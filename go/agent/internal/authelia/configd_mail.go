package authelia

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyyaml"
)

var (
	dnsLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	emailRE    = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
	timeoutRE  = regexp.MustCompile(`^[1-9][0-9]{0,5}(?:ms|s|m|h)$`)
	envKeyRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	mailFields = []string{"mode", "host", "port", "username", "password_action", "password", "sender", "recipient",
		"subject", "timeout", "tls_mode", "tls_skip_verify"}
	tlsUnverifiedRE = regexp.MustCompile(`\bdsn=4\.7\.5\b.*\bstatus=deferred \(Server certificate not verified\)`)
)

func mailErr(format string, args ...any) error { return newErr("MailSettingsError", format, args...) }

func loadYAMLMappingBytes(data []byte, path string) (*pyyaml.Map, error) {
	if utf8Error(data) != nil {
		return nil, mailErr("managed file is not UTF-8: %s", path)
	}
	v, aliased, err := pyyaml.LoadAliases(data)
	if err != nil {
		return nil, mailErr("invalid YAML in managed file: %s", path)
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, mailErr("YAML root must be a mapping: %s", path)
	}
	if aliased {
		return nil, newErr("ValueError", "YAML aliases and recursive structures are not allowed")
	}
	if err := rejectUnsafeValues(m, false); err != nil {
		return nil, err
	}
	return m, nil
}

func decodeEnvValue(raw string) string {
	value := pyStrip(raw)
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			decoded = value[1 : len(value)-1]
		}
		if s, ok := decoded.(string); ok {
			return strings.ReplaceAll(s, "$$", "$")
		}
	}
	if len(value) >= 2 && strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		return strings.ReplaceAll(strings.ReplaceAll(value[1:len(value)-1], `\'`, "'"), `\\`, `\`)
	}
	return value
}

func splitLines(text string) []string {
	out := []string{}
	start := 0
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i]))
			if rs[i] == '\r' && i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

type envMap struct {
	keys []string
	vals map[string]string
}

func (e *envMap) get(k string) any {
	if v, ok := e.vals[k]; ok {
		return v
	}
	return nil
}

func parseEnv(text string) *envMap {
	e := &envMap{vals: map[string]string{}}
	for _, line := range splitLines(text) {
		stripped := pyStrip(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key = pyStrip(key)
		if envKeyRE.MatchString(key) {
			if _, seen := e.vals[key]; !seen {
				e.keys = append(e.keys, key)
			}
			e.vals[key] = decodeEnvValue(value)
		}
	}
	return e
}

func encodeEnvValue(value string) string {
	s, _ := pyyaml.JSONDumps(strings.ReplaceAll(value, "$", "$$"), false, false)
	return s
}

type kv struct{ k, v string }

func renderEnvWithUpdates(text string, updates []kv) string {
	want := map[string]string{}
	for _, u := range updates {
		want[u.k] = u.v
	}
	emitted := map[string]bool{}
	rendered := []string{}
	for _, line := range splitLines(text) {
		if !strings.Contains(line, "=") || strings.HasPrefix(strings.TrimLeft(line, " \t\n\r\v\f"), "#") {
			rendered = append(rendered, line)
			continue
		}
		key := pyStrip(strings.SplitN(line, "=", 2)[0])
		v, ok := want[key]
		if !ok {
			rendered = append(rendered, line)
			continue
		}
		if !emitted[key] {
			rendered = append(rendered, key+"="+encodeEnvValue(v))
			emitted[key] = true
		}
	}
	for _, u := range updates {
		if !emitted[u.k] {
			rendered = append(rendered, u.k+"="+encodeEnvValue(u.v))
		}
	}
	return strings.TrimRight(strings.Join(rendered, "\n"), "\n") + "\n"
}

func yamlBytes(m *pyyaml.Map) ([]byte, error) {
	s, err := pyyaml.Dump(m, pyyaml.Options{AllowUnicode: true})
	return []byte(s), err
}

func stageFile(path string, data []byte, prev *syscall.Stat_t, forceMode int) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".mail-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	mode := uint32(prev.Mode & 0o7777)
	if forceMode >= 0 {
		mode = uint32(forceMode)
	}
	if err := syscall.Fchmod(int(tmp.Fd()), mode); err != nil {
		return fail(err)
	}
	if err := syscall.Fchown(int(tmp.Fd()), int(prev.Uid), int(prev.Gid)); err != nil {
		if !(err == syscall.EPERM && os.Geteuid() != 0) {
			return fail(err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	tmp.Close()
	return name, nil
}

func fsyncDirectories(paths []string) {
	dirs := map[string]bool{}
	for _, p := range paths {
		dirs[filepath.Dir(p)] = true
	}
	keys := make([]string, 0, len(dirs))
	for d := range dirs {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		if f, err := os.Open(d); err == nil {
			_ = f.Sync()
			f.Close()
		}
	}
}

type snapshot struct {
	data []byte
	st   *syscall.Stat_t
}

func (c *Configd) forcedMode(path string) int {
	if path == c.managedSecretsFile() || path == c.mailNotifyStatePath() {
		return 0o600
	}
	return -1
}

func (c *Configd) restoreFiles(snaps map[string]snapshot, paths []string) error {
	if len(paths) == 0 {
		for p := range snaps {
			paths = append(paths, p)
		}
	}
	staged := map[string]string{}
	defer func() {
		for _, t := range staged {
			_ = os.Remove(t)
		}
	}()
	for _, p := range paths {
		s := snaps[p]
		t, err := stageFile(p, s.data, s.st, c.forcedMode(p))
		if err != nil {
			return err
		}
		staged[p] = t
	}
	for _, p := range paths {
		if err := os.Rename(staged[p], p); err != nil {
			return err
		}
		delete(staged, p)
	}
	fsyncDirectories(paths)
	return nil
}

func (c *Configd) commitMailFiles(order []string, updates map[string][]byte, snaps map[string]snapshot) (err error) {
	staged := map[string]string{}
	replaced := []string{}
	defer func() {
		if err != nil && len(replaced) > 0 {
			_ = c.restoreFiles(snaps, replaced)
		}
		for _, t := range staged {
			_ = os.Remove(t)
		}
	}()
	for _, p := range order {
		t, serr := stageFile(p, updates[p], snaps[p].st, c.forcedMode(p))
		if serr != nil {
			return serr
		}
		staged[p] = t
	}
	if err := c.validateConfigViaAuthelia(staged[c.Opts.ConfigFile]); err != nil {
		return err
	}
	for _, p := range sortedSnapshotKeys(snaps) {
		current, _, rerr := safeReadFile(p)
		if rerr != nil {
			return rerr
		}
		if string(current) != string(snaps[p].data) {
			return newErr("MailSettingsConflictError", "managed mail source changed during validation: %s", p)
		}
	}
	c.backupConfigFile()
	for _, p := range order {
		if rerr := os.Rename(staged[p], p); rerr != nil {
			return rerr
		}
		delete(staged, p)
		replaced = append(replaced, p)
	}
	fsyncDirectories(order)
	return nil
}

func sortedSnapshotKeys(snaps map[string]snapshot) []string {
	keys := make([]string, 0, len(snaps))
	for k := range snaps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *Configd) mailLock() (func(), error) {
	path := c.Opts.MailLockFile
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(fd)
		return nil, mailErr("mail settings lock is not a regular file")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		syscall.Close(fd)
	}, nil
}

func (c *Configd) ensureMailNotifyStateFile() (string, error) {
	path := c.mailNotifyStatePath()
	if _, err := os.Lstat(path); err == nil {
		return path, nil
	}
	varsData, _, err := safeReadFile(c.managedVarsFile())
	if err != nil {
		return "", err
	}
	vars, err := loadYAMLMappingBytes(varsData, c.managedVarsFile())
	if err != nil {
		return "", err
	}
	onlyFor, ok := pyyaml.DeepCopy(getDefault(vars, "mail_notify_only_for", []any{})).([]any)
	if !ok {
		onlyFor = []any{}
	}
	state := pyyaml.NewMap()
	state.Set("enabled", truthy(getDefault(vars, "mail_notify_enabled", false)))
	state.Set("from", pyStrOr(vars.Value("mail_notify_from")))
	state.Set("only_for", onlyFor)
	state.Set("to", pyStrOr(vars.Value("mail_notify_to")))
	text, err := pyyaml.JSONDumps(state.Sorted(), false, true)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mail-notify.*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(0o600)
	_, werr := tmp.WriteString(text + "\n")
	if werr == nil {
		werr = tmp.Sync()
	}
	tmp.Close()
	if werr != nil {
		return "", werr
	}
	if err := os.Link(name, path); err != nil && !os.IsExist(err) {
		return "", err
	}
	fsyncDirectories([]string{path})
	return path, nil
}

func getDefault(m *pyyaml.Map, key string, def any) any {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

type mailState struct {
	snapshots               map[string]snapshot
	config, compose         *pyyaml.Map
	vars, authelia, secrets *pyyaml.Map
	envText                 string
	env                     *envMap
	notifyState             any
}

func (c *Configd) loadMailState() (*mailState, error) {
	notifyPath, err := c.ensureMailNotifyStateFile()
	if err != nil {
		return nil, err
	}
	paths := []string{c.Opts.ConfigFile, c.Opts.EnvFile, c.Opts.ComposeFile, c.managedVarsFile(), c.managedAutheliaFile(),
		c.managedSecretsFile(), notifyPath}
	s := &mailState{snapshots: map[string]snapshot{}}
	for _, p := range paths {
		data, st, err := safeReadFile(p)
		if err != nil {
			return nil, err
		}
		s.snapshots[p] = snapshot{data, st}
	}
	if s.config, err = loadYAMLMappingBytes(s.snapshots[c.Opts.ConfigFile].data, c.Opts.ConfigFile); err != nil {
		return nil, err
	}
	envData := s.snapshots[c.Opts.EnvFile].data
	if utf8Error(envData) != nil {
		return nil, mailErr("managed file is not UTF-8: %s", c.Opts.EnvFile)
	}
	s.envText = string(envData)
	s.env = parseEnv(s.envText)
	if s.compose, err = loadYAMLMappingBytes(s.snapshots[c.Opts.ComposeFile].data, c.Opts.ComposeFile); err != nil {
		return nil, err
	}
	if s.vars, err = loadYAMLMappingBytes(s.snapshots[c.managedVarsFile()].data, c.managedVarsFile()); err != nil {
		return nil, err
	}
	if s.authelia, err = loadYAMLMappingBytes(s.snapshots[c.managedAutheliaFile()].data, c.managedAutheliaFile()); err != nil {
		return nil, err
	}
	if s.secrets, err = loadYAMLMappingBytes(s.snapshots[c.managedSecretsFile()].data, c.managedSecretsFile()); err != nil {
		return nil, err
	}
	notifyData := s.snapshots[notifyPath].data
	if utf8Error(notifyData) != nil {
		return nil, mailErr("managed file is not UTF-8: %s", notifyPath)
	}
	if s.notifyState, err = pyyaml.JSONLoads(notifyData); err != nil {
		return nil, newErr("JSONDecodeError", "%s", err.Error())
	}
	return s, nil
}

func (c *Configd) mailRevision(s *mailState) string {
	parts := [][]byte{}
	for _, p := range sortedSnapshotKeys(s.snapshots) {
		parts = append(parts, []byte(p), []byte{0}, s.snapshots[p].data, []byte{0})
	}
	return hmacHex(c.mailRevisionKey, parts...)
}

func relayAvailable(s *mailState) bool {
	services := asMap(s.compose.Value("services"))
	return services != nil && asMap(services.Value("mail_relay")) != nil
}

func smtpAddressParts(address any) (string, int, string) {
	text := pyStrip(pyStrOr(address))
	u, err := url.Parse(text)
	if err != nil {
		return "", 25, "starttls"
	}
	host := strings.ToLower(u.Hostname())
	port := 0
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n > 65535 {
			return "", 25, "starttls"
		}
		port = n
	}
	scheme := strings.ToLower(u.Scheme)
	tls := "starttls"
	if scheme == "smtps" || scheme == "submissions" {
		tls = "smtps"
	}
	if port == 0 {
		port = 25
		if tls == "smtps" {
			port = 465
		}
	}
	return host, port, tls
}

func mailMode(config *pyyaml.Map) string {
	notifier := asMap(config.Value("notifier"))
	if notifier == nil || asMap(notifier.Value("filesystem")) != nil {
		return "filesystem"
	}
	smtp := asMap(notifier.Value("smtp"))
	if smtp == nil {
		return "filesystem"
	}
	host, _, _ := smtpAddressParts(smtp.Value("address"))
	if host == "mail_relay" {
		return "relay"
	}
	return "direct"
}

func firstText(def string, values ...any) string {
	for _, v := range values {
		if v != nil && pyStrip(pyStr(v)) != "" {
			return pyStrip(pyStr(v))
		}
	}
	return def
}

func currentPassword(s *mailState) string {
	var smtpPassword any = ""
	if notifier := asMap(s.config.Value("notifier")); notifier != nil {
		if smtp := asMap(notifier.Value("smtp")); smtp != nil {
			smtpPassword = smtp.Value("password")
		}
	}
	return firstText("", s.env.get("SMTP_PASSWORD"), s.env.get("MAIL_SMTP_PASSWORD"), s.secrets.Value("mail_smtp_pass"), smtpPassword)
}

func (c *Configd) mailSettingsModel(s *mailState) map[string]any {
	notifier := asMap(s.config.Value("notifier"))
	if notifier == nil {
		notifier = pyyaml.NewMap()
	}
	smtp := asMap(notifier.Value("smtp"))
	if smtp == nil {
		smtp = pyyaml.NewMap()
	}
	runtimeMode := mailMode(s.config)
	mode := "relay"
	if runtimeMode == "filesystem" {
		mode = "filesystem"
	}
	host := firstText("", s.env.get("SMTP_SERVER"), s.env.get("MAIL_SMTP_SERVER"), s.vars.Value("mail_smtp_host"))
	rawPort := firstText("587", s.env.get("SMTP_PORT"), s.env.get("MAIL_SMTP_PORT"), s.vars.Value("mail_smtp_port"))
	port, ok := pyInt(rawPort)
	if !ok {
		port = 587
	}
	username := firstText("", s.env.get("SMTP_USERNAME"), s.env.get("MAIL_SMTP_USERNAME"), s.vars.Value("mail_smtp_user"))
	defTLS := "starttls"
	if port == 465 {
		defTLS = "smtps"
	}
	tlsMode := strings.ToLower(firstText(defTLS, s.env.get("EASY_HA_PROXY_SMTP_TLS_MODE"), s.vars.Value("mail_smtp_ssl_mode")))
	if tlsMode != "smtps" && tlsMode != "starttls" && tlsMode != "plain" {
		tlsMode = defTLS
	}
	tlsCfg := asMap(smtp.Value("tls"))
	if tlsCfg == nil {
		tlsCfg = pyyaml.NewMap()
	}
	skip := getDefault(tlsCfg, "skip_verify", getDefault(s.vars, "mail_smtp_tls_skip_verify", getDefault(s.authelia, "mail_smtp_tls_skip_verify", false)))
	settings := map[string]any{
		"mode": mode, "host": host, "port": port, "username": username,
		"password_configured": currentPassword(s) != "",
		"sender":              firstText("", smtp.Value("sender"), s.vars.Value("mail_notify_from")),
		"recipient":           firstText("", smtp.Value("startup_check_address"), s.vars.Value("mail_notify_to")),
		"subject":             firstText("", smtp.Value("subject"), s.authelia.Value("mail_subject")),
		"timeout":             firstText("10s", smtp.Value("timeout"), s.authelia.Value("mail_smtp_timeout")),
		"tls_mode":            tlsMode,
		"tls_skip_verify":     truthy(skip),
	}
	return map[string]any{"ok": true, "settings": settings,
		"capabilities": map[string]any{"relay_available": relayAvailable(s), "legacy_direct": runtimeMode == "direct"},
		"revision":     c.mailRevision(s)}
}

// pyInt is int(text) for a str.
func pyInt(text string) (int, bool) {
	t := strings.ReplaceAll(pyStrip(text), "_", "")
	if t == "" || strings.HasPrefix(pyStrip(text), "_") || strings.HasSuffix(pyStrip(text), "_") || strings.Contains(text, "__") {
		return 0, false
	}
	n, err := strconv.Atoi(t)
	return n, err == nil
}

func validateMailText(value any, label string, maximum int, required bool) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", mailErr("%s must be a string", label)
	}
	text := pyStrip(s)
	if required && text == "" {
		return "", mailErr("%s is required", label)
	}
	if utf8.RuneCountInString(text) > maximum || controlRE.MatchString(text) {
		return "", mailErr("%s contains invalid characters or is too long", label)
	}
	return text, nil
}

func validateMailHost(value any) (string, error) {
	host, err := validateMailText(value, "SMTP host", 253, true)
	if err != nil {
		return "", err
	}
	cand := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		cand = host[1 : len(host)-1]
	}
	if a, err := netip.ParseAddr(cand); err == nil {
		return a.String(), nil
	}
	for _, label := range strings.Split(strings.TrimRight(host, "."), ".") {
		if !dnsLabelRE.MatchString(label) {
			return "", mailErr("SMTP host must be a valid IP address or DNS name")
		}
	}
	return strings.TrimRight(host, "."), nil
}

func validateMailEmail(value any, label string) (string, error) {
	email, err := validateMailText(value, label, 254, true)
	if err != nil {
		return "", err
	}
	if !emailRE.MatchString(email) {
		return "", mailErr("%s must be a valid email address", label)
	}
	return email, nil
}

type mailSettings struct {
	mode, host, username, passwordAction, password, sender, recipient, subject, timeout, tlsMode string
	port                                                                                         int
	tlsSkipVerify                                                                                bool
}

func (m mailSettings) get(key string) any {
	switch key {
	case "host":
		return m.host
	case "port":
		return m.port
	case "username":
		return m.username
	case "timeout":
		return m.timeout
	case "tls_mode":
		return m.tlsMode
	case "tls_skip_verify":
		return m.tlsSkipVerify
	}
	return nil
}

func validateMailPayload(value any) (*mailSettings, error) {
	v, ok := value.(*pyyaml.Map)
	if !ok {
		return nil, mailErr("settings must be an object")
	}
	known := map[string]bool{}
	for _, f := range mailFields {
		known[f] = true
	}
	missing, unexpected := []string{}, []string{}
	for _, f := range mailFields {
		if _, ok := v.Get(f); !ok {
			missing = append(missing, f)
		}
	}
	for _, k := range v.Keys() {
		if !known[pyStr(k)] {
			unexpected = append(unexpected, pyStr(k))
		}
	}
	if len(missing) > 0 || len(unexpected) > 0 {
		sort.Strings(missing)
		sort.Strings(unexpected)
		details := []string{}
		if len(missing) > 0 {
			details = append(details, "missing: "+strings.Join(missing, ", "))
		}
		if len(unexpected) > 0 {
			details = append(details, "unsupported: "+strings.Join(unexpected, ", "))
		}
		return nil, mailErr("invalid mail settings fields (%s)", strings.Join(details, "; "))
	}
	mode := strings.ToLower(pyStrip(pyStrOr(v.Value("mode"))))
	if mode != "filesystem" && mode != "relay" {
		return nil, mailErr("mode must be filesystem or relay")
	}
	tlsMode := strings.ToLower(pyStrip(pyStrOr(v.Value("tls_mode"))))
	if tlsMode != "smtps" && tlsMode != "starttls" && tlsMode != "plain" {
		return nil, mailErr("tls_mode must be smtps, starttls, or plain")
	}
	action := strings.ToLower(pyStrip(pyStrOr(v.Value("password_action"))))
	if action != "keep" && action != "replace" && action != "clear" {
		return nil, mailErr("password_action must be keep, replace, or clear")
	}
	s := &mailSettings{mode: mode, tlsMode: tlsMode, passwordAction: action}
	rawHost := v.Value("host")
	if hs, ok := rawHost.(string); mode == "filesystem" && ok && pyStrip(hs) == "" {
		s.host = ""
	} else {
		h, err := validateMailHost(rawHost)
		if err != nil {
			return nil, err
		}
		s.host = h
	}
	rawPort := v.Value("port")
	if mode == "filesystem" && (rawPort == nil || rawPort == "") {
		rawPort = int64(25)
	}
	switch p := rawPort.(type) {
	case bool:
		return nil, mailErr("SMTP port must be an integer")
	case int64:
		s.port = int(p)
	case float64:
		s.port = int(p)
	case string:
		n, ok := pyInt(p)
		if !ok {
			return nil, mailErr("SMTP port must be an integer")
		}
		s.port = n
	default:
		return nil, mailErr("SMTP port must be an integer")
	}
	if s.port < 1 || s.port > 65535 {
		return nil, mailErr("SMTP port must be between 1 and 65535")
	}
	password, ok := v.Value("password").(string)
	if !ok {
		return nil, mailErr("password must be a string")
	}
	if utf8.RuneCountInString(password) > 1024 || controlRE.MatchString(password) {
		return nil, mailErr("password contains invalid characters or is too long")
	}
	if action == "replace" && password == "" {
		return nil, mailErr("a non-empty password is required when replacing it")
	}
	if action != "replace" && password != "" {
		return nil, mailErr("password must be empty unless password_action is replace")
	}
	s.password = password
	skip, ok := v.Value("tls_skip_verify").(bool)
	if !ok {
		return nil, mailErr("tls_skip_verify must be true or false")
	}
	s.tlsSkipVerify = skip
	timeout, err := validateMailText(v.Value("timeout"), "Timeout", 16, true)
	if err != nil {
		return nil, err
	}
	if !timeoutRE.MatchString(timeout) {
		return nil, mailErr("Timeout must look like 10s, 2m, 1h, or 500ms")
	}
	s.timeout = timeout
	rawSender, rawRecipient := v.Value("sender"), v.Value("recipient")
	if mode == "filesystem" {
		if str, ok := rawSender.(string); ok && pyStrip(str) != "" {
			if s.sender, err = validateMailEmail(rawSender, "Sender"); err != nil {
				return nil, err
			}
		}
		if str, ok := rawRecipient.(string); ok && pyStrip(str) != "" {
			if s.recipient, err = validateMailEmail(rawRecipient, "Recipient"); err != nil {
				return nil, err
			}
		}
		if s.subject, err = validateMailText(v.Value("subject"), "Subject", 255, false); err != nil {
			return nil, err
		}
	} else {
		if s.sender, err = validateMailEmail(rawSender, "Sender"); err != nil {
			return nil, err
		}
		if s.recipient, err = validateMailEmail(rawRecipient, "Recipient"); err != nil {
			return nil, err
		}
		if s.subject, err = validateMailText(v.Value("subject"), "Subject", 255, true); err != nil {
			return nil, err
		}
	}
	if s.username, err = validateMailText(v.Value("username"), "SMTP username", 320, false); err != nil {
		return nil, err
	}
	return s, nil
}

func mailRelayHostname(st *mailState, s *mailSettings) (string, error) {
	domains := []string{}
	if root, ok := st.vars.Value("root_domain").(string); ok && pyStrip(root) != "" {
		domains = append(domains, strings.Trim(pyStrip(root), "."))
	}
	for _, sender := range []any{s.sender, st.vars.Value("mail_notify_from")} {
		if str, ok := sender.(string); ok && strings.Contains(str, "@") {
			domains = append(domains, strings.Trim(pyStrip(str[strings.LastIndex(str, "@")+1:]), "."))
		}
	}
	for _, d := range domains {
		hostname := strings.ToLower("mail-relay." + d)
		if utf8.RuneCountInString(hostname) <= 253 {
			valid := true
			for _, label := range strings.Split(hostname, ".") {
				if !dnsLabelRE.MatchString(label) {
					valid = false
				}
			}
			if valid {
				return hostname, nil
			}
		}
	}
	return "", mailErr("cannot derive a valid mail relay hostname from root_domain or sender")
}

// prepareMailUpdates is _prepare_mail_updates; order is the dict order.
func (c *Configd) prepareMailUpdates(st *mailState, s *mailSettings) ([]string, map[string][]byte, error) {
	password := currentPassword(st)
	if s.mode == "relay" && s.passwordAction == "replace" {
		password = s.password
	} else if s.mode == "relay" && s.passwordAction == "clear" {
		password = ""
	}
	config := pyyaml.DeepCopy(st.config).(*pyyaml.Map)
	old := asMap(config.Value("notifier"))
	if old == nil {
		old = pyyaml.NewMap()
	}
	notifier := pyyaml.NewMap()
	notifier.Set("disable_startup_check", truthy(getDefault(old, "disable_startup_check", false)))
	tp := pyStrOr(old.Value("template_path"))
	if tp == "" {
		tp = "/config/email_templates"
	}
	notifier.Set("template_path", tp)
	if s.mode == "filesystem" {
		oldFS := asMap(old.Value("filesystem"))
		if oldFS == nil {
			oldFS = pyyaml.NewMap()
		}
		fn := pyStrOr(oldFS.Value("filename"))
		if fn == "" {
			fn = "/config/notification.log"
		}
		fs := pyyaml.NewMap()
		fs.Set("filename", fn)
		notifier.Set("filesystem", fs)
	} else {
		smtp := pyyaml.NewMap()
		for _, p := range []struct {
			k string
			v any
		}{{"timeout", s.timeout}, {"sender", s.sender}, {"subject", s.subject}, {"startup_check_address", s.recipient},
			{"address", "smtp://mail_relay:25"}, {"username", ""}, {"password", ""}, {"disable_require_tls", true},
			{"disable_starttls", true}} {
			smtp.Set(p.k, p.v)
		}
		notifier.Set("smtp", smtp)
	}
	config.Set("notifier", notifier)
	envUpdates := []kv{}
	if s.mode == "relay" {
		level, useTLS := "none", "no"
		if s.tlsMode != "plain" {
			level, useTLS = "verify", "yes"
			if s.tlsSkipVerify {
				level = "encrypt"
			}
		}
		wrapper := "no"
		if s.tlsMode == "smtps" {
			wrapper = "yes"
		}
		hostname, err := mailRelayHostname(st, s)
		if err != nil {
			return nil, nil, err
		}
		port := strconv.Itoa(s.port)
		envUpdates = []kv{{"MAIL_SMTP_SERVER", s.host}, {"MAIL_SMTP_PORT", port}, {"MAIL_SMTP_USERNAME", s.username},
			{"MAIL_SMTP_PASSWORD", password}, {"SERVER_HOSTNAME", hostname}, {"SMTP_SERVER", s.host}, {"SMTP_PORT", port},
			{"SMTP_USERNAME", s.username}, {"SMTP_PASSWORD", password}, {"EASY_HA_PROXY_SMTP_TLS_MODE", s.tlsMode},
			{"POSTFIX_smtp_tls_security_level", level}, {"POSTFIX_smtp_tls_wrappermode", wrapper},
			{"POSTFIX_smtp_use_tls", useTLS}, {"POSTFIX_smtp_connect_timeout", s.timeout}}
	}
	vars := pyyaml.DeepCopy(st.vars).(*pyyaml.Map)
	vars.Set("mail_notify_enabled", s.mode == "relay")
	if s.mode == "relay" {
		auth := "off"
		if s.username != "" {
			auth = "on"
		}
		for _, p := range []struct {
			k string
			v any
		}{{"mail_notify_to", s.recipient}, {"mail_notify_from", s.sender}, {"mail_smtp_host", s.host},
			{"mail_smtp_port", int64(s.port)}, {"mail_smtp_user", s.username}, {"mail_smtp_auth", auth},
			{"mail_smtp_ssl_mode", s.tlsMode}, {"mail_smtp_tls_skip_verify", s.tlsSkipVerify}} {
			vars.Set(p.k, p.v)
		}
	}
	authelia := pyyaml.DeepCopy(st.authelia).(*pyyaml.Map)
	ntype := "smtp"
	if s.mode == "filesystem" {
		ntype = "filesystem"
	}
	authelia.Set("mail_relay_server", s.mode == "relay")
	authelia.Set("authelia_notifier_type", ntype)
	authelia.Set("mail_subject", s.subject)
	authelia.Set("mail_smtp_timeout", s.timeout)
	secrets := pyyaml.DeepCopy(st.secrets).(*pyyaml.Map)
	if s.mode == "relay" {
		secrets.Set("mail_smtp_pass", password)
	}
	notify := asMap(st.notifyState)
	if notify == nil {
		notify = pyyaml.NewMap()
	}
	onlyFor, ok := notify.Value("only_for").([]any)
	if !ok {
		onlyFor = []any{}
	}
	from, to := pyStrOr(notify.Value("from")), pyStrOr(notify.Value("to"))
	if s.mode == "relay" {
		from, to = s.sender, s.recipient
	}
	ns := pyyaml.NewMap()
	ns.Set("enabled", s.mode == "relay")
	ns.Set("from", from)
	ns.Set("only_for", onlyFor)
	ns.Set("to", to)
	nsText, err := pyyaml.JSONDumps(ns, false, true)
	if err != nil {
		return nil, nil, err
	}
	updates := map[string][]byte{}
	order := []string{c.Opts.ConfigFile, c.Opts.EnvFile, c.managedVarsFile(), c.managedAutheliaFile(), c.managedSecretsFile(), c.mailNotifyStatePath()}
	var yerr error
	put := func(path string, m *pyyaml.Map) {
		if yerr != nil {
			return
		}
		var b []byte
		b, yerr = yamlBytes(m)
		updates[path] = b
	}
	put(c.Opts.ConfigFile, config)
	updates[c.Opts.EnvFile] = []byte(renderEnvWithUpdates(st.envText, envUpdates))
	put(c.managedVarsFile(), vars)
	put(c.managedAutheliaFile(), authelia)
	put(c.managedSecretsFile(), secrets)
	updates[c.mailNotifyStatePath()] = []byte(nsText + "\n")
	return order, updates, yerr
}

// ---------------------------------------------------------------------------
// the relay stack
// ---------------------------------------------------------------------------

func (c *Configd) containerHealth(container string, timeout int) bool {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	tmpl := "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
	for time.Now().Before(deadline) {
		rc, out, _, err := c.docker(5*time.Second, nil, "inspect", "--format", tmpl, container)
		if err != nil && errKind(err) == "TimeoutExpired" {
			time.Sleep(time.Second)
			continue
		}
		if err == nil && rc == 0 {
			status, health, _ := strings.Cut(pyStrip(out), "|")
			if status == "running" && (health == "healthy" || health == "none") {
				return true
			}
			if status == "dead" || status == "exited" || health == "unhealthy" {
				return false
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

func (c *Configd) relayQueueStatus() string {
	rc, out, _, err := c.docker(5*time.Second, nil, "inspect", "--format", "{{.State.Running}}", "mail_relay")
	if err != nil {
		return "unknown"
	}
	if rc != 0 {
		return "absent"
	}
	if strings.ToLower(pyStrip(out)) != "true" {
		rc, _, _, err := c.docker(30*time.Second, nil, "start", "mail_relay")
		if err != nil || rc != 0 || !c.containerHealth("mail_relay", c.Opts.RestartTimeout) {
			return "unknown"
		}
	}
	for i, args := range [][]string{{"exec", "mail_relay", "postqueue", "-j"}, {"exec", "mail_relay", "postqueue", "-p"}} {
		rc, out, _, err := c.docker(10*time.Second, nil, args...)
		if err != nil || rc != 0 {
			continue
		}
		output := pyStrip(out)
		if i == 0 {
			if output == "" {
				return "empty"
			}
			return "nonempty"
		}
		if output == "" || strings.Contains(output, "Mail queue is empty") {
			return "empty"
		}
		return "nonempty"
	}
	return "unknown"
}

func (c *Configd) relaySpoolStatus() string {
	rc, out, _, err := c.docker(5*time.Second, nil, "inspect", "--format", "{{json .Mounts}}", "mail_relay")
	if err != nil {
		return "unknown"
	}
	if rc != 0 {
		rc, listed, _, err := c.docker(5*time.Second, nil, "ps", "-a", "--filter", "name=^/mail_relay$", "--format", "{{.Names}}")
		if err != nil {
			return "unknown"
		}
		if rc == 0 && pyStrip(listed) == "" {
			return "absent"
		}
		return "unknown"
	}
	mounts, err := pyyaml.JSONLoads([]byte(out))
	if err != nil {
		return "unknown"
	}
	list, ok := mounts.([]any)
	if !ok {
		return "unknown"
	}
	for _, m := range list {
		mount, ok := m.(*pyyaml.Map)
		if !ok {
			return "unknown"
		}
		if mount.Value("Destination") != "/var/spool/postfix" {
			continue
		}
		if mount.Value("Type") == "volume" && mount.Value("Name") == "easy-ha-proxy-mail-relay-spool" {
			return "managed"
		}
		return "legacy"
	}
	return "legacy"
}

func (c *Configd) mailTransportChanged(st *mailState, s *mailSettings) bool {
	current := c.mailSettingsModel(st)["settings"].(map[string]any)
	for _, key := range []string{"host", "port", "username", "timeout", "tls_mode", "tls_skip_verify"} {
		if fmt.Sprint(s.get(key)) != fmt.Sprint(current[key]) {
			return true
		}
	}
	switch s.passwordAction {
	case "clear":
		return currentPassword(st) != ""
	case "replace":
		return true
	}
	return false
}

type queueSafetyErr struct {
	msg             string
	autheliaStopped bool
}

func (e *queueSafetyErr) Error() string { return e.msg }

func (c *Configd) restartOrErr() error {
	r := c.handleRestart()
	if r["ok"] != true {
		msg, _ := r["error"].(string)
		if msg == "" {
			msg = "Authelia restart failed"
		}
		return newErr("RuntimeError", "%s", msg)
	}
	return nil
}

func (c *Configd) applyMailStack(mode string, recreate bool) (map[string]any, error) {
	if mode != "relay" {
		if err := c.restartOrErr(); err != nil {
			return nil, err
		}
		status := c.relayQueueStatus()
		switch status {
		case "empty":
			rc, _, _, err := c.docker(30*time.Second, nil, "stop", "mail_relay")
			if err == nil && rc == 0 {
				return map[string]any{"relay_state": "stopped"}, nil
			}
			return map[string]any{"relay_state": "left_running",
				"warning": "Email notifications are disabled, but the empty relay container could not be stopped."}, nil
		case "nonempty", "unknown":
			return map[string]any{"relay_state": "left_running",
				"warning": "Email notifications are disabled. The relay container was left running because its queue is not empty or could not be verified; let it drain before stopping it."}, nil
		}
		return map[string]any{"relay_state": status}, nil
	}
	if !recreate {
		if err := c.restartOrErr(); err != nil {
			return nil, err
		}
		return map[string]any{"relay_state": "unchanged"}, nil
	}
	spool := c.relaySpoolStatus()
	if spool == "unknown" {
		return nil, &queueSafetyErr{msg: "mail_relay spool safety could not be verified; inspect the existing container before applying new transport settings"}
	}
	if spool == "legacy" {
		switch c.relayQueueStatus() {
		case "nonempty":
			return nil, &queueSafetyErr{msg: "the legacy mail_relay has queued messages in its container layer; wait for the queue to drain before migrating it"}
		case "unknown":
			return nil, &queueSafetyErr{msg: "the legacy mail_relay queue could not be inspected; its container-layer spool will not be replaced"}
		}
	}
	log.Printf("Stopping Authelia before mail relay recreation")
	rc, _, _, err := c.docker(30*time.Second, nil, "stop", c.Opts.AutheliaContainer)
	if err != nil {
		return nil, newErr("RuntimeError", "could not stop Authelia for safe relay apply")
	}
	if rc != 0 {
		return nil, newErr("RuntimeError", "could not stop Authelia for safe relay apply (rc=%d)", rc)
	}
	if spool == "legacy" {
		switch c.relayQueueStatus() {
		case "nonempty":
			return nil, &queueSafetyErr{msg: "the legacy mail_relay received queued messages during the migration barrier; the old container will be preserved", autheliaStopped: true}
		case "unknown":
			return nil, &queueSafetyErr{msg: "the legacy mail_relay queue could not be verified after stopping Authelia; the old container will be preserved", autheliaStopped: true}
		}
	}
	log.Printf("Recreating Authelia mail relay stack")
	rc, _, _, err = c.dockerIn(filepath.Dir(c.Opts.ComposeFile), 120*time.Second, "compose", "-f", c.Opts.ComposeFile,
		"--profile", "mail-relay", "up", "-d", "--force-recreate", "mail_relay")
	if err != nil {
		return nil, newErr("RuntimeError", "docker compose mail apply failed: %s", err.Error())
	}
	if rc != 0 {
		log.Printf("docker compose mail apply failed with rc=%d", rc)
		return nil, newErr("RuntimeError", "docker compose mail apply failed (rc=%d)", rc)
	}
	if !c.containerHealth("mail_relay", c.Opts.RestartTimeout) {
		return nil, newErr("RuntimeError", "mail_relay did not become healthy")
	}
	if err := c.restartOrErr(); err != nil {
		return nil, err
	}
	return map[string]any{"relay_state": "running"}, nil
}

// ---------------------------------------------------------------------------
// test message
// ---------------------------------------------------------------------------

// mailTestMessage is EmailMessage.as_bytes() for the test message: the
// Message-ID (always 88 characters with its name) is folded onto its own
// line, and the body, one line longer than 78 characters, is sent
// quoted-printable, exactly as the email package writes them.
func mailTestMessage(sender, recipient, messageID string) []byte {
	body := "This is a test message sent from the easy-ha-proxy Authelia mail settings pag=\n" +
		"e. The result shown by easy-ha-proxy can confirm whether the configured exter=\n" +
		"nal SMTP relay accepted this message, but not whether it reached the final in=\n" +
		"box.\n"
	idLine := "Message-ID: " + messageID
	if len(idLine) > 78 {
		idLine = "Message-ID:\n " + messageID
	}
	return []byte("From: " + sender + "\nTo: " + recipient + "\nSubject: easy-ha-proxy email test\n" + idLine +
		"\nContent-Type: text/plain; charset=\"utf-8\"\nContent-Transfer-Encoding: quoted-printable\nMIME-Version: 1.0\n\n" + body)
}

func parseMailTestDelivery(output, messageID string) (string, string) {
	idRE := regexp.MustCompile(`(?i)(?:^|\s)([A-Za-z0-9]+):\s+.*message-id=` + regexp.QuoteMeta(messageID) + `(?:\s|$)`)
	queueID := ""
	lines := splitLines(output)
	for _, line := range lines {
		if m := idRE.FindStringSubmatch(line); m != nil {
			queueID = m[1]
			break
		}
	}
	if queueID == "" {
		return "", "queued"
	}
	state := "queued"
	qre := regexp.MustCompile(`(?i)(?:^|\s)` + regexp.QuoteMeta(queueID) + `:\s+.*\bstatus=(sent|deferred|bounced|expired)\b`)
	for _, line := range lines {
		m := qre.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch strings.ToLower(m[1]) {
		case "sent":
			return queueID, "relay_accepted"
		case "bounced", "expired":
			return queueID, "rejected"
		case "deferred":
			if tlsUnverifiedRE.MatchString(line) {
				return queueID, "tls_unverified"
			}
			state = "deferred"
		}
	}
	return queueID, state
}

func (c *Configd) waitForMailTestDelivery(messageID string, submittedAt time.Time, timeout int) string {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	last := "queued"
	since := submittedAt.Unix() - 2
	if since < 0 {
		since = 0
	}
	for time.Now().Before(deadline) {
		rc, out, errOut, err := c.docker(5*time.Second, nil, "logs", "--since", strconv.FormatInt(since, 10), "--tail", "2000", "mail_relay")
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if rc == 0 {
			_, state := parseMailTestDelivery(out+"\n"+errOut, messageID)
			if state == "relay_accepted" || state == "rejected" || state == "tls_unverified" {
				return state
			}
			if state == "deferred" {
				last = state
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

func (c *Configd) sendRelayMailTest(settings map[string]any, recipient string) (string, error) {
	if !c.containerHealth("mail_relay", 10) {
		return "", newErr("RuntimeError", "mail_relay is not healthy")
	}
	sender, err := validateMailEmail(settings["sender"], "Sender")
	if err != nil {
		return "", err
	}
	b := make([]byte, 16)
	_, _ = randRead(b)
	messageID := fmt.Sprintf("<easy-ha-proxy-test-%x@easy-ha-proxy.invalid>", b)
	submitted := time.Now()
	rc, _, _, err := c.docker(30*time.Second, mailTestMessage(sender, recipient, messageID), "exec", "-i", "mail_relay",
		"/usr/sbin/sendmail", "-i", "-f", sender, "--", recipient)
	if err != nil {
		return "", err
	}
	if rc != 0 {
		return "", newErr("RuntimeError", "mail_relay rejected the test message")
	}
	return c.waitForMailTestDelivery(messageID, submitted, c.Opts.MailTestResultTimeout), nil
}

func (c *Configd) claimMailTestSlot() int {
	c.mailTestMu.Lock()
	defer c.mailTestMu.Unlock()
	now := time.Now()
	if !c.mailTestLast.IsZero() {
		elapsed := now.Sub(c.mailTestLast).Seconds()
		if elapsed < float64(c.Opts.MailTestCooldown) {
			r := int(float64(c.Opts.MailTestCooldown)-elapsed) + 1
			if r < 1 {
				r = 1
			}
			return r
		}
	}
	c.mailTestLast = now
	return 0
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

func keySet(req *pyyaml.Map) map[string]bool {
	out := map[string]bool{}
	for _, k := range req.Keys() {
		out[pyStr(k)] = true
	}
	return out
}

func sameKeys(req *pyyaml.Map, want ...string) bool {
	ks := keySet(req)
	if len(ks) != len(want) || req.Len() != len(want) {
		return false
	}
	for _, w := range want {
		if !ks[w] {
			return false
		}
	}
	return true
}

func (c *Configd) handleMailView() map[string]any {
	unlock, err := c.mailLock()
	if err != nil {
		return c.mailViewError(err)
	}
	defer unlock()
	st, err := c.loadMailState()
	if err != nil {
		return c.mailViewError(err)
	}
	return c.mailSettingsModel(st)
}

func (c *Configd) mailViewError(err error) map[string]any {
	if isMailSettingsError(err) {
		log.Printf("Failed to load mail settings: managed configuration is invalid")
		return map[string]any{"ok": false, "error": "failed to load mail settings: " + errText(err)}
	}
	log.Printf("Failed to load mail settings: %v", err)
	return map[string]any{"ok": false, "error": "failed to load mail settings"}
}

func (c *Configd) handleMailTest(req *pyyaml.Map) map[string]any {
	if !sameKeys(req, "action", "revision", "recipient") {
		return map[string]any{"ok": false, "validation_error": true, "error": "revision and recipient are required"}
	}
	revision, ok := req.Value("revision").(string)
	if !ok || !isHex64(revision) {
		return map[string]any{"ok": false, "validation_error": true, "error": "revision must be the current 64-character SHA-256 value"}
	}
	recipient, err := validateMailEmail(req.Value("recipient"), "Recipient")
	if err != nil {
		return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
	}
	fail := func(err error) map[string]any {
		if isMailSettingsError(err) {
			return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
		}
		log.Printf("Mail test setup failed")
		return map[string]any{"ok": false, "error": "Failed to prepare the mail test."}
	}
	unlock, err := c.mailLock()
	if err != nil {
		return fail(err)
	}
	defer unlock()
	st, err := c.loadMailState()
	if err != nil {
		return fail(err)
	}
	current := c.mailRevision(st)
	if revision != current {
		return map[string]any{"ok": false, "conflict": true,
			"error":    "Mail settings changed after this page was loaded. Reload them before sending a test message.",
			"revision": current}
	}
	mode := mailMode(st.config)
	if mode != "relay" {
		return map[string]any{"ok": false, "unsupported": true, "error": "Enable the internal mail relay first.", "revision": current}
	}
	if retry := c.claimMailTestSlot(); retry > 0 {
		return map[string]any{"ok": false, "rate_limited": true, "retry_after": retry,
			"error": "Please wait before sending another test message.", "revision": current}
	}
	settings := c.mailSettingsModel(st)["settings"].(map[string]any)
	status, err := c.sendRelayMailTest(settings, recipient)
	if err != nil {
		log.Printf("Mail test failed in %s mode", mode)
		return map[string]any{"ok": false, "revision": current,
			"error": "The test message was not accepted. Check the SMTP settings and the Authelia/mail_relay logs."}
	}
	switch status {
	case "rejected":
		return map[string]any{"ok": false, "accepted": true, "rejected": true, "delivery_status": status, "delivery_guaranteed": false,
			"error":    "The internal relay accepted the test message, but the configured external SMTP relay rejected it. Check the SMTP credentials, sender policy, and mail_relay logs.",
			"revision": current}
	case "tls_unverified":
		return map[string]any{"ok": false, "accepted": true, "tls_unverified": true, "delivery_status": status, "delivery_guaranteed": false,
			"error":    "The internal relay could not verify the certificate of the external SMTP server and keeps the message queued. Check the server name, its certificate, or the relay's trusted certificates.",
			"revision": current}
	}
	message := "The internal relay queued the test message, but no definitive external delivery result was available within the bounded check window."
	switch status {
	case "relay_accepted":
		message = "The configured external SMTP relay accepted the test message. Final inbox delivery still cannot be guaranteed."
	case "deferred":
		message = "The internal relay queued the test message after a temporary external delivery failure and will retry it."
	}
	return map[string]any{"ok": true, "message": message, "mode": mode, "recipient": recipient, "accepted": true,
		"upstream_accepted": status == "relay_accepted", "delivery_status": status, "delivery_guaranteed": false, "revision": current}
}

func (c *Configd) handleMailUpdate(req *pyyaml.Map) map[string]any {
	if req.Value("apply") != true {
		return map[string]any{"ok": false, "validation_error": true, "error": "apply must be true"}
	}
	revision, ok := req.Value("revision").(string)
	if !ok || !isHex64(revision) {
		return map[string]any{"ok": false, "validation_error": true, "error": "revision must be the current 64-character SHA-256 value"}
	}
	settings, err := validateMailPayload(req.Value("settings"))
	if err != nil {
		return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
	}
	outer := func(err error) map[string]any {
		if isMailSettingsError(err) {
			return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
		}
		log.Printf("Unexpected mail settings update failure: %v", err)
		return map[string]any{"ok": false, "error": "mail settings update failed: " + errText(err)}
	}
	unlock, err := c.mailLock()
	if err != nil {
		return outer(err)
	}
	defer unlock()
	st, err := c.loadMailState()
	if err != nil {
		return outer(err)
	}
	current := c.mailRevision(st)
	if revision != current {
		return map[string]any{"ok": false, "conflict": true,
			"error": "Mail settings changed after this page was loaded. Reload them and review your changes.", "revision": current}
	}
	oldMode := mailMode(st.config)
	recreate := settings.mode == "relay" && (oldMode != "relay" || c.mailTransportChanged(st, settings))
	if settings.mode == "relay" && !relayAvailable(st) {
		return map[string]any{"ok": false, "conflict": true, "relay_unavailable": true,
			"error":    "mail relay is not installed in the current Compose stack; run a full easy-ha-proxy update, then retry",
			"revision": current}
	}
	order, updates, err := c.prepareMailUpdates(st, settings)
	if err != nil {
		return outer(err)
	}
	unchanged := true
	for _, p := range order {
		if string(updates[p]) != string(st.snapshots[p].data) {
			unchanged = false
		}
	}
	if unchanged {
		r := c.mailSettingsModel(st)
		r["applied"], r["message"] = true, "Mail settings are already active."
		return r
	}
	if err := c.commitMailFiles(order, updates, st.snapshots); err != nil {
		if errKind(err) == "MailSettingsConflictError" {
			changed := current
			if s2, err2 := c.loadMailState(); err2 == nil {
				changed = c.mailRevision(s2)
			}
			return map[string]any{"ok": false, "conflict": true, "error": errText(err), "revision": changed}
		}
		log.Printf("Failed to commit mail settings: %v", err)
		return map[string]any{"ok": false, "error": "failed to save mail settings: " + errText(err), "revision": current}
	}
	applyInfo, applyErr := c.applyMailStack(settings.mode, recreate)
	if applyErr != nil {
		log.Printf("Mail apply failed; restoring previous settings")
		rollbackErrors := []string{}
		recover := func(f func() error, label string) {
			if err := f(); err != nil {
				rollbackErrors = append(rollbackErrors, label+": "+errText(err))
			}
		}
		if err := c.restoreFiles(st.snapshots, order); err != nil {
			rollbackErrors = append(rollbackErrors, "file rollback failed: "+errText(err))
		} else if settings.mode != "relay" {
			recover(c.restartOrErr, "previous Authelia recovery failed")
		} else if qe, ok := applyErr.(*queueSafetyErr); ok {
			if qe.autheliaStopped {
				recover(c.restartOrErr, "previous Authelia recovery failed")
			}
		} else if !recreate {
			recover(c.restartOrErr, "previous Authelia recovery failed")
		} else {
			recover(func() error { _, err := c.applyMailStack(oldMode, true); return err }, "previous stack recovery failed")
		}
		restored := current
		if s2, err2 := c.loadMailState(); err2 == nil {
			restored = c.mailRevision(s2)
		}
		msg := "mail settings apply failed and changes were rolled back: " + errText(applyErr)
		if len(rollbackErrors) > 0 {
			msg += "; " + strings.Join(rollbackErrors, "; ")
		}
		return map[string]any{"ok": false, "rolled_back": len(rollbackErrors) == 0, "error": msg, "revision": restored}
	}
	st2, err := c.loadMailState()
	if err != nil {
		return outer(err)
	}
	r := c.mailSettingsModel(st2)
	r["applied"], r["message"] = true, "Mail settings saved and applied safely."
	if w, ok := applyInfo["warning"]; ok && truthy(w) {
		r["warning"] = w
		r["relay_state"] = applyInfo["relay_state"]
	}
	return r
}
