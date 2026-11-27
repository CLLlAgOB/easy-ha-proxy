package authelia

// The Go port of authelia-configd.py. The Python daemon is the
// specification: one JSON line per request on a Unix socket, served one at
// a time, the same replies, files (configuration.yml and its backups, the
// managed mail files, the notification tombstone) and fixed docker
// commands. YAML goes through go/panel/shared/pyyaml so files and rules_yaml
// stay byte-identical with PyYAML's output.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

// ConfigdOptions holds what authelia-configd.py reads from the environment.
type ConfigdOptions struct {
	ConfigFile, SocketPath, AutheliaContainer, AutheliaConfigPath string
	ValidateConfig                                                bool
	RestartHost                                                   string
	RestartPort, RestartTimeout                                   int
	HAProxyRuntimeSocket                                          string
	EnvFile, ComposeFile, ManagedConfigDir, MailLockFile          string
	MailTestCooldown, MailTestResultTimeout                       int
	NotificationStateFile, NotificationRootDir                    string
	NotificationStateDir, NotificationClientUser                  string
	NotificationExpectedUID, NotificationRevealCooldown           int
	ProtectedDomains                                              string
	DockerBin                                                     string
}

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envIntDefault(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ConfigdOptionsFromEnv reads the environment as authelia-configd.py does.
func ConfigdOptionsFromEnv() ConfigdOptions {
	validate := strings.ToLower(envDefault("AUTHELIA_VALIDATE_CONFIG", "false"))
	return ConfigdOptions{
		ConfigFile:                 envDefault("AUTHELIA_CONFIG_FILE", "/opt/authelia/configuration.yml"),
		SocketPath:                 envDefault("AUTHELIA_CONFIG_SOCKET", "/run/easy-ha-proxy/authelia-configd.sock"),
		AutheliaContainer:          envDefault("AUTHELIA_CONTAINER_NAME", "authelia"),
		AutheliaConfigPath:         envDefault("AUTHELIA_CONFIG_PATH", "/config/configuration.yml"),
		ValidateConfig:             validate == "1" || validate == "true" || validate == "yes",
		RestartHost:                envDefault("AUTHELIA_RESTART_HOST", "127.0.0.1"),
		RestartPort:                envIntDefault("AUTHELIA_RESTART_PORT", 9091),
		RestartTimeout:             envIntDefault("AUTHELIA_RESTART_TIMEOUT", 30),
		HAProxyRuntimeSocket:       envDefault("AUTHELIA_HAPROXY_SOCKET", "/run/haproxy/admin.sock"),
		EnvFile:                    envDefault("AUTHELIA_ENV_FILE", "/opt/authelia/.env"),
		ComposeFile:                envDefault("AUTHELIA_COMPOSE_FILE", "/opt/authelia/docker-compose.yml"),
		ManagedConfigDir:           envDefault("EASY_HA_PROXY_CONFIG_DIR", "/etc/easy-ha-proxy"),
		MailLockFile:               envDefault("AUTHELIA_MAIL_LOCK_FILE", "/run/easy-ha-proxy/authelia-mail.lock"),
		MailTestCooldown:           clampInt(envIntDefault("AUTHELIA_MAIL_TEST_COOLDOWN", 15), 5, 300),
		MailTestResultTimeout:      clampInt(envIntDefault("AUTHELIA_MAIL_TEST_RESULT_TIMEOUT", 12), 3, 30),
		NotificationStateFile:      strings.TrimSpace(envDefault("AUTHELIA_NOTIFICATION_STATE_FILE", "")),
		NotificationRootDir:        envDefault("AUTHELIA_NOTIFICATION_ROOT", "/opt/authelia"),
		NotificationStateDir:       envDefault("AUTHELIA_NOTIFICATION_STATE_DIR", "/var/lib/easy-ha-proxy"),
		NotificationClientUser:     strings.TrimSpace(envDefault("AUTHELIA_NOTIFICATION_CLIENT_USER", "haproxyadmin")),
		NotificationExpectedUID:    envIntDefault("AUTHELIA_NOTIFICATION_UID", -1),
		NotificationRevealCooldown: clampInt(envIntDefault("AUTHELIA_NOTIFICATION_REVEAL_COOLDOWN", 3), 1, 60),
		ProtectedDomains:           os.Getenv("EASY_HA_PROXY_PROTECTED_DOMAINS"),
		DockerBin:                  "docker",
	}
}

const (
	maxHAProxyStatsBytes = 4 * 1024 * 1024
	maxRequestBytes      = 2 * 1024 * 1024
	maxConfigBytes       = 2 * 1024 * 1024
	notificationMaxBytes = 256 * 1024
	notificationStateMax = 8 * 1024
	autheliaHealthPath   = "/api/health"
	autheliaBackend      = "authelia_backend"
	autheliaServer       = "authelia"
)

// Configd is the daemon state.
type Configd struct {
	Opts              ConfigdOptions
	mailRevisionKey   []byte
	notifyRevisionKey []byte
	mailTestMu        sync.Mutex
	mailTestLast      time.Time
	revealMu          sync.Mutex
	revealedAt        map[string]time.Time
	// Protected domains are read at call time in Python (os.environ).
	protectedDomains func() string
}

// NewConfigd builds the daemon with fresh per-process revision keys.
func NewConfigd(opts ConfigdOptions) *Configd {
	key := func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
	if opts.DockerBin == "" {
		opts.DockerBin = "docker"
	}
	return &Configd{Opts: opts, mailRevisionKey: key(), notifyRevisionKey: key(), revealedAt: map[string]time.Time{},
		protectedDomains: func() string { return opts.ProtectedDomains }}
}

func (c *Configd) managedVarsFile() string { return filepath.Join(c.Opts.ManagedConfigDir, "vars.yml") }
func (c *Configd) managedAutheliaFile() string {
	return filepath.Join(c.Opts.ManagedConfigDir, "authelia.yml")
}
func (c *Configd) managedSecretsFile() string {
	return filepath.Join(c.Opts.ManagedConfigDir, "secrets.yml")
}
func (c *Configd) mailNotifyStatePath() string {
	return filepath.Join(c.Opts.ManagedConfigDir, "mail-notify.json")
}

// ---------------------------------------------------------------------------
// Python value helpers
// ---------------------------------------------------------------------------

type pyError struct {
	kind string // "ValueError", "RuntimeError", "MailSettingsError", ...
	msg  string
}

func (e *pyError) Error() string { return e.msg }

func newErr(kind, format string, args ...any) error {
	if len(args) == 0 {
		return &pyError{kind, format}
	}
	return &pyError{kind, fmt.Sprintf(format, args...)}
}

func errKind(err error) string {
	var pe *pyError
	if errors.As(err, &pe) {
		return pe.kind
	}
	return ""
}

func isMailSettingsError(err error) bool {
	k := errKind(err)
	return k == "MailSettingsError" || k == "MailSettingsConflictError"
}

// pyRepr is repr() of a str.
func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

// pyStr is str(value) for decoded values.
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return pyyaml.FloatRepr(x)
	case pyyaml.Timestamp:
		return strings.Replace(string(x), "T", " ", 1)
	case *pyyaml.Map, []any:
		s, _ := pyyaml.JSONDumps(x, false, false)
		return s
	}
	return fmt.Sprint(v)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int64:
		return x != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case *pyyaml.Map:
		return x.Len() > 0
	case []any:
		return len(x) > 0
	}
	return true
}

func asMap(v any) *pyyaml.Map {
	m, _ := v.(*pyyaml.Map)
	return m
}

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case string:
		return "str"
	case bool:
		return "bool"
	case int64, int:
		return "int"
	case float64:
		return "float"
	case []any:
		return "list"
	case *pyyaml.Map:
		return "dict"
	case pyyaml.Timestamp:
		return "datetime"
	}
	return "object"
}

// osErr is str(OSError).
func osErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		var errno syscall.Errno
		if errors.As(pe.Err, &errno) {
			msg := errno.Error()
			if msg != "" {
				msg = strings.ToUpper(msg[:1]) + msg[1:]
			}
			return fmt.Sprintf("[Errno %d] %s: %s", int(errno), msg, pyRepr(pe.Path))
		}
	}
	return err.Error()
}

func utf8Error(raw []byte) error {
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size <= 1 {
			return newErr("ValueError", "'utf-8' codec can't decode byte 0x%02x in position %d: invalid start byte", raw[i], i)
		}
		i += size
	}
	return nil
}

func hmacHex(key []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

func sha256Hex(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' || (r >= 0x1c && r <= 0x1f) || r == 0x85 ||
			r == 0xa0 || r == 0x1680 || (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
	})
}

var controlRE = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// ---------------------------------------------------------------------------
// configuration.yml
// ---------------------------------------------------------------------------

func (c *Configd) backupConfigFile() {
	cfg := c.Opts.ConfigFile
	if _, err := os.Stat(cfg); err != nil {
		return
	}
	now := time.Now()
	ts := now.Format("20060102-150405") + fmt.Sprintf("-%06d", now.Nanosecond()/1000)
	backup := cfg + ".bak-" + ts
	if err := os.Link(cfg, backup); err != nil {
		log.Printf("Backup failed (%s): %s", backup, osErr(err))
	} else {
		log.Printf("Backup created: %s", backup)
	}
	dir := filepath.Dir(cfg)
	prefix := filepath.Base(cfg) + ".bak-"
	ents, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Backup rotation list failed: %s", osErr(err))
		return
	}
	type cand struct {
		p string
		t float64
	}
	cands := []cand{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			p := filepath.Join(dir, e.Name())
			t := 0.0
			if fi, err := os.Stat(p); err == nil {
				t = float64(fi.ModTime().UnixNano())
			}
			cands = append(cands, cand{p, t})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].t > cands[j].t })
	for i := 14; i < len(cands); i++ {
		if err := os.Remove(cands[i].p); err != nil {
			log.Printf("Failed to remove old backup %s: %s", cands[i].p, osErr(err))
		} else {
			log.Printf("Old backup removed: %s", cands[i].p)
		}
	}
}

// safeReadFile is _safe_read_file.
func safeReadFile(path string) ([]byte, *syscall.Stat_t, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, newErr("MailSettingsError", "cannot safely open %s: %s", path, osErr(&os.PathError{Op: "open", Path: path, Err: err}))
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, nil, newErr("MailSettingsError", "managed path is not a regular file: %s", path)
	}
	if st.Size < 0 || st.Size > maxConfigBytes {
		return nil, nil, newErr("MailSettingsError", "managed file has an unsafe size: %s", path)
	}
	data := []byte{}
	buf := make([]byte, 65536)
	for len(data) <= maxConfigBytes {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, nil, &os.PathError{Op: "read", Path: path, Err: err}
		}
		if n <= 0 {
			break
		}
		data = append(data, buf[:n]...)
	}
	if len(data) > maxConfigBytes {
		return nil, nil, newErr("MailSettingsError", "managed file is too large: %s", path)
	}
	return data, &st, nil
}

// loadConfigData is _load_config_data: the root mapping and its rules list.
func (c *Configd) loadConfigData() (*pyyaml.Map, []any, error) {
	cfg := c.Opts.ConfigFile
	if _, err := os.Lstat(cfg); err != nil {
		return nil, nil, newErr("FileNotFoundError", "Authelia config file not found: %s", cfg)
	}
	raw, _, err := safeReadFile(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := utf8Error(raw); err != nil {
		return nil, nil, err
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		return nil, nil, err
	}
	if !truthy(v) {
		v = pyyaml.NewMap()
	}
	data, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, nil, newErr("ValueError", "configuration.yml: root is not a dict")
	}
	ac, present := data.Get("access_control")
	if !present || ac == nil {
		ac = pyyaml.NewMap()
		data.Set("access_control", ac)
	}
	acm, ok := ac.(*pyyaml.Map)
	if !ok {
		return nil, nil, newErr("ValueError", "configuration.yml: 'access_control' is not a dict")
	}
	rules, present := acm.Get("rules")
	if !present || rules == nil {
		rules = []any{}
		acm.Set("rules", rules)
	}
	list, ok := rules.([]any)
	if !ok {
		return nil, nil, newErr("ValueError", "configuration.yml: 'access_control.rules' is not a list")
	}
	return data, list, nil
}

func deepUpdate(dst, src *pyyaml.Map) {
	src.Each(func(k, v any) {
		if vm, ok := v.(*pyyaml.Map); ok {
			if dm, ok := dst.Value(k).(*pyyaml.Map); ok {
				deepUpdate(dm, vm)
				return
			}
		}
		dst.Set(k, v)
	})
}

var sensitiveKeys = map[string]bool{"secret": true, "password": true, "token": true, "api_key": true, "private_key": true,
	"encryption_key": true, "jwt_secret": true, "client_secret": true}

func maskSensitiveFields(node any) {
	switch x := node.(type) {
	case *pyyaml.Map:
		for _, k := range x.Keys() {
			v := x.Value(k)
			_, isMap := v.(*pyyaml.Map)
			_, isList := v.([]any)
			if sensitiveKeys[strings.ToLower(pyStr(k))] && !isMap && !isList {
				x.Set(k, "*****")
			} else {
				maskSensitiveFields(v)
			}
		}
	case []any:
		for _, v := range x {
			maskSensitiveFields(v)
		}
	}
}

// rejectUnsafeValues is _reject_unsafe_values; aliased reports that the
// YAML held one collection twice (Python sees the same id()).
func rejectUnsafeValues(node any, aliased bool) error {
	if aliased {
		if err := rejectAliasedFirst(node, 0); err != nil {
			return err
		}
	}
	_, err := rejectUnsafe(node, 0, aliased)
	return err
}

func rejectAliasedFirst(node any, depth int) error { return nil }

func rejectUnsafe(node any, depth int, aliased bool) (int, error) {
	if depth > 20 {
		return 0, newErr("ValueError", "configuration fragment is too deeply nested")
	}
	switch x := node.(type) {
	case string:
		if utf8.RuneCountInString(x) > 16384 {
			return 0, newErr("ValueError", "configuration contains an unsafe string")
		}
		for _, r := range x {
			if r < 32 {
				return 0, newErr("ValueError", "configuration contains an unsafe string")
			}
		}
		return 1, nil
	case *pyyaml.Map:
		count := 1
		var ferr error
		for _, k := range x.Keys() {
			ks, ok := k.(string)
			if !ok || utf8.RuneCountInString(ks) > 128 {
				return 0, newErr("ValueError", "configuration contains an invalid key")
			}
			n, err := rejectUnsafe(x.Value(k), depth+1, aliased)
			if err != nil {
				ferr = err
				break
			}
			count += n
		}
		if ferr != nil {
			return 0, ferr
		}
		if count > 5000 {
			return 0, newErr("ValueError", "configuration fragment is too large")
		}
		return count, nil
	case []any:
		count := 1
		for _, v := range x {
			n, err := rejectUnsafe(v, depth+1, aliased)
			if err != nil {
				return 0, err
			}
			count += n
		}
		if count > 5000 {
			return 0, newErr("ValueError", "configuration fragment is too large")
		}
		return count, nil
	case nil, bool, int64, int, float64:
		return 1, nil
	}
	return 0, newErr("ValueError", "configuration contains an unsupported value")
}

func (c *Configd) docker(timeout time.Duration, stdin []byte, args ...string) (int, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Opts.DockerBin, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 0, "", "", newErr("TimeoutExpired", "Command '%s' timed out after %d seconds", pyArgv(append([]string{"docker"}, args...)), int(timeout.Seconds()))
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String(), errb.String(), nil
		}
		return 0, "", "", newErr("FileNotFoundError", "[Errno 2] No such file or directory: 'docker'")
	}
	return 0, out.String(), errb.String(), nil
}

func pyArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = pyRepr(a)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (c *Configd) validateConfigViaAuthelia(tmpHostPath string) error {
	if !c.Opts.ValidateConfig {
		log.Printf("AUTHELIA_VALIDATE_CONFIG=false, skipping authelia config validate")
		return nil
	}
	if c.Opts.AutheliaContainer == "" || c.Opts.AutheliaConfigPath == "" {
		log.Printf("AUTHELIA_CONTAINER_NAME or AUTHELIA_CONFIG_PATH not set; skipping Authelia config validation")
		return nil
	}
	cfgDir, cfgBase := filepath.Split(c.Opts.AutheliaConfigPath)
	if cfgBase == "" {
		log.Printf("AUTHELIA_CONFIG_PATH has no filename, skipping validation: %s", c.Opts.AutheliaConfigPath)
		return nil
	}
	cfgDir = strings.TrimRight(cfgDir, "/")
	if cfgDir == "" {
		cfgDir = "/"
	}
	containerTmp := filepath.Join(cfgDir, filepath.Base(tmpHostPath))
	args := []string{"exec", "-i", c.Opts.AutheliaContainer, "authelia", "config", "validate", "--config", containerTmp}
	log.Printf("Running Authelia config validate: docker %s", strings.Join(args, " "))
	rc, _, _, err := c.docker(60*time.Second, nil, args...)
	if err != nil {
		return newErr("RuntimeError", "Could not run docker exec for Authelia: %s", err.Error())
	}
	if rc != 0 {
		log.Printf("Authelia config validation failed with rc=%d", rc)
		return newErr("RuntimeError", "Authelia configuration validation failed (rc=%d)", rc)
	}
	log.Printf("Authelia config validate OK for %s", containerTmp)
	return nil
}

var (
	syncTempFile  = func(f *os.File) error { return f.Sync() }
	closeTempFile = func(f *os.File) error { return f.Close() }
)

func (c *Configd) saveConfigData(root *pyyaml.Map) error {
	cfg := c.Opts.ConfigFile
	var prev *syscall.Stat_t
	var st syscall.Stat_t
	if err := syscall.Lstat(cfg, &st); err == nil {
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return newErr("ValueError", "config file is not a regular file: %s", cfg)
		}
		prev = &st
	} else if err != syscall.ENOENT {
		log.Printf("Failed to stat %s before save: %v", cfg, err)
	}
	c.backupConfigFile()
	uid, gid := -1, -1
	if prev != nil {
		uid, gid = int(prev.Uid), int(prev.Gid)
	} else if u, err := user.Lookup("authelia"); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	text, err := pyyaml.Dump(root, pyyaml.Options{AllowUnicode: true})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cfg), ".configuration.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := syncTempFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if uid != -1 {
		if err := tmp.Chown(uid, gid); err != nil {
			if os.Geteuid() == 0 || !errors.Is(err, syscall.EPERM) {
				_ = tmp.Close()
				return err
			}
			log.Printf("Failed to set owner/group on temp config file: %v", err)
		}
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := closeTempFile(tmp); err != nil {
		return err
	}
	if err := c.validateConfigViaAuthelia(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, cfg); err != nil {
		return err
	}
	keep = true
	log.Printf("Config file updated: %s", cfg)
	return nil
}

// ---------------------------------------------------------------------------
// restart
// ---------------------------------------------------------------------------

func (c *Configd) autheliaHealthReady() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", net.JoinHostPort(c.Opts.RestartHost, strconv.Itoa(c.Opts.RestartPort)), autheliaHealthPath), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "easy-ha-proxy-configd")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func haproxyStatsReportBackendUp(stats string) bool {
	r := csv.NewReader(strings.NewReader(stats))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil || len(header) == 0 {
		return false
	}
	header[0] = strings.TrimLeft(header[0], "# ")
	idx := func(name string) int {
		for i, h := range header {
			if h == name {
				return i
			}
		}
		return -1
	}
	px, sv, stIdx := idx("pxname"), idx("svname"), idx("status")
	if px < 0 || sv < 0 || stIdx < 0 {
		return false
	}
	need := px
	if sv > need {
		need = sv
	}
	if stIdx > need {
		need = stIdx
	}
	for {
		row, err := r.Read()
		if err == io.EOF {
			return false
		}
		if err != nil {
			continue
		}
		if len(row) <= need {
			continue
		}
		if row[px] == autheliaBackend && row[sv] == autheliaServer {
			status := strings.ToUpper(pyStrip(row[stIdx]))
			return status == "UP" || strings.HasPrefix(status, "UP ")
		}
	}
}

func (c *Configd) haproxyAutheliaBackendUp() bool {
	conn, err := net.DialTimeout("unix", c.Opts.HAProxyRuntimeSocket, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("show stat\n")); err != nil {
		return false
	}
	data := []byte{}
	buf := make([]byte, 65536)
	for len(data) <= maxHAProxyStatsBytes {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil {
			break
		}
	}
	if len(data) == 0 || len(data) > maxHAProxyStatsBytes {
		return false
	}
	return haproxyStatsReportBackendUp(strings.ToValidUTF8(string(data), "�"))
}

func (c *Configd) waitForAutheliaReady(timeout int) bool {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		if c.autheliaHealthReady() && c.haproxyAutheliaBackendUp() {
			return true
		}
		remaining := time.Until(deadline)
		if remaining > 0 {
			if remaining > 500*time.Millisecond {
				remaining = 500 * time.Millisecond
			}
			time.Sleep(remaining)
		}
	}
	return false
}

func (c *Configd) handleRestart() map[string]any {
	log.Printf("Restarting Authelia via: docker restart %s", c.Opts.AutheliaContainer)
	rc, _, _, err := c.docker(30*time.Second, nil, "restart", c.Opts.AutheliaContainer)
	if err != nil {
		return map[string]any{"ok": false, "error": "docker restart failed: " + err.Error()}
	}
	if rc != 0 {
		log.Printf("docker restart failed with rc=%d", rc)
		return map[string]any{"ok": false, "error": fmt.Sprintf("docker restart failed (rc=%d)", rc)}
	}
	if c.waitForAutheliaReady(c.Opts.RestartTimeout) {
		log.Printf("Authelia restarted, healthy on %s:%d, and available through HAProxy", c.Opts.RestartHost, c.Opts.RestartPort)
		return map[string]any{"ok": true, "message": "Authelia restarted and ForwardAuth routing is available"}
	}
	log.Printf("Authelia restart timeout: health or HAProxy backend %s/%s is not ready after %d seconds", autheliaBackend, autheliaServer, c.Opts.RestartTimeout)
	return map[string]any{"ok": false, "error": "Authelia restart timed out: HTTP health or HAProxy ForwardAuth routing did not recover"}
}

// ---------------------------------------------------------------------------
// rules / config / settings
// ---------------------------------------------------------------------------

func rulesRevision(rules []any) string {
	data, err := pyyaml.Dump(rules, pyyaml.Options{AllowUnicode: true, SortKeys: true})
	if err != nil {
		return ""
	}
	return sha256Hex([]byte(data))
}

func (c *Configd) handleRulesGet() map[string]any {
	_, rules, err := c.loadConfigData()
	if err != nil {
		log.Printf("rules_get: failed to load config: %v", err)
		return map[string]any{"ok": false, "error": "Could not read configuration.yml: " + errText(err)}
	}
	text, err := pyyaml.Dump(rules, pyyaml.Options{AllowUnicode: true})
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not build the rules YAML: " + err.Error()}
	}
	return map[string]any{"ok": true, "rules_yaml": text, "revision": rulesRevision(rules)}
}

func (c *Configd) rejectUnprotectedControlPlane(rules []any) error {
	protected := map[string]bool{}
	for _, item := range strings.Split(c.protectedDomains(), ",") {
		if s := pyStrip(item); s != "" {
			protected[strings.TrimRight(strings.ToLower(s), ".")] = true
		}
	}
	if len(protected) == 0 {
		return nil
	}
	for i, r := range rules {
		rule := asMap(r)
		policy := strings.ToLower(pyStrip(pyStrOr(rule.Value("policy"))))
		if policy != "bypass" {
			continue
		}
		for _, domain := range ruleStrings(rule.Value("domain")) {
			name := strings.TrimRight(strings.ToLower(pyStrip(domain)), ".")
			for host := range protected {
				if host == name || strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:]) {
					return newErr("ValueError", "rules[%d]: policy 'bypass' is not allowed for the protected domain %s", i, host)
				}
			}
		}
		for _, pattern := range ruleStrings(rule.Value("domain_regex")) {
			expression, err := regexp.Compile(pattern)
			if err != nil {
				return newErr("ValueError", "rules[%d]: invalid domain_regex", i)
			}
			for host := range protected {
				if expression.MatchString(host) {
					return newErr("ValueError", "rules[%d]: policy 'bypass' is not allowed for the protected domain %s", i, host)
				}
			}
		}
	}
	return nil
}

func ruleStrings(value any) []string {
	switch value := value.(type) {
	case string:
		return []string{value}
	case []any:
		items := make([]string, 0, len(value))
		for _, item := range value {
			items = append(items, pyStr(item))
		}
		return items
	default:
		return nil
	}
}

// pyStrOr is str(value or "").
func pyStrOr(v any) string {
	if !truthy(v) {
		return ""
	}
	return pyStr(v)
}

func errText(err error) string {
	var pe *pyError
	if errors.As(err, &pe) {
		return pe.msg
	}
	return osErr(err)
}

func (c *Configd) handleRulesSet(req *pyyaml.Map) map[string]any {
	rulesYAML, ok := req.Value("rules_yaml").(string)
	if !ok {
		return map[string]any{"ok": false, "error": "field 'rules_yaml' must be a string"}
	}
	parsed, aliased, err := pyyaml.LoadAliases([]byte(rulesYAML))
	if err != nil {
		return map[string]any{"ok": false, "error": "Invalid YAML in rules_yaml: " + err.Error()}
	}
	if !truthy(parsed) {
		parsed = []any{}
	}
	list, ok := parsed.([]any)
	if !ok {
		return map[string]any{"ok": false, "error": "rules_yaml must be a YAML list"}
	}
	if len(list) > 500 {
		return map[string]any{"ok": false, "error": "At most 500 rules are allowed"}
	}
	if aliased {
		return map[string]any{"ok": false, "error": "YAML aliases and recursive structures are not allowed"}
	}
	if err := rejectUnsafeValues(list, false); err != nil {
		return map[string]any{"ok": false, "error": errText(err)}
	}
	for i, r := range list {
		if _, ok := r.(*pyyaml.Map); !ok {
			return map[string]any{"ok": false, "error": fmt.Sprintf("rules[%d] must be a dict, got %s", i, pyTypeName(r))}
		}
	}
	if err := c.rejectUnprotectedControlPlane(list); err != nil {
		return map[string]any{"ok": false, "error": errText(err)}
	}
	root, oldRules, err := c.loadConfigData()
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not read configuration.yml: " + errText(err)}
	}
	if raw, present := req.Get("expected_revision"); present {
		s, ok := raw.(string)
		if !ok || !isHex64(s) || !hmac.Equal([]byte(s), []byte(rulesRevision(oldRules))) {
			return map[string]any{"ok": false, "conflict": true,
				"error": "Access rules changed since this page was loaded. Reload before editing."}
		}
	}
	ac, ok := root.Value("access_control").(*pyyaml.Map)
	if !ok {
		ac = pyyaml.NewMap()
		root.Set("access_control", ac)
	}
	ac.Set("rules", list)
	if err := c.saveConfigData(root); err != nil {
		log.Printf("rules_set: failed to save configuration: %v", err)
		return map[string]any{"ok": false, "error": "Failed to save configuration.yml: " + errText(err)}
	}
	return map[string]any{"ok": true, "message": "access_control rules updated"}
}

func (c *Configd) handleConfigView() (map[string]any, error) {
	root, _, err := c.loadConfigData()
	if err != nil {
		return nil, err
	}
	data := pyyaml.DeepCopy(root).(*pyyaml.Map)
	if ac, ok := data.Value("access_control").(*pyyaml.Map); ok {
		ac.Delete("rules")
	}
	maskSensitiveFields(data)
	return map[string]any{"ok": true, "config": data}, nil
}

func (c *Configd) handleSettingsUpdate(req *pyyaml.Map) (map[string]any, error) {
	in, ok := req.Value("config").(*pyyaml.Map)
	if !ok {
		return map[string]any{"ok": false, "error": "field 'config' must be a dict"}, nil
	}
	cfg := pyyaml.DeepCopy(in).(*pyyaml.Map)
	unexpected := []string{}
	for _, k := range cfg.Keys() {
		ks := pyStr(k)
		if ks != "log" && ks != "session" && ks != "regulation" && ks != "totp" {
			unexpected = append(unexpected, ks)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return map[string]any{"ok": false, "error": "unsupported configuration sections: " + strings.Join(unexpected, ", ")}, nil
	}
	if err := rejectUnsafeValues(cfg, false); err != nil {
		return map[string]any{"ok": false, "error": errText(err)}, nil
	}
	if session, present := cfg.Get("session"); present {
		settings, ok := session.(*pyyaml.Map)
		if !ok {
			return map[string]any{"ok": false, "error": "session settings must be a mapping"}, nil
		}
		settings.Delete("secret")
		settings.Delete("redis")
	}
	root, _, err := c.loadConfigData()
	if err != nil {
		return nil, err
	}
	deepUpdate(root, cfg)
	if err := c.saveConfigData(root); err != nil {
		log.Printf("Failed to save configuration (settings_update): %v", err)
		return map[string]any{"ok": false, "error": "Failed to save configuration.yml: " + errText(err)}, nil
	}
	return map[string]any{"ok": true}, nil
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

func (c *Configd) notificationPeerAllowed(peerUID int) bool {
	if peerUID == 0 {
		return true
	}
	if peerUID < 0 || c.Opts.NotificationClientUser == "" {
		return false
	}
	u, err := user.Lookup(c.Opts.NotificationClientUser)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(strconv.Itoa(peerUID)), []byte(u.Uid))
}

// HandleRequest is handle_request; it returns the reply or an error that
// the server turns into "internal error: ...".
func (c *Configd) HandleRequest(reqAny any, peerUID int) (map[string]any, error) {
	req, ok := reqAny.(*pyyaml.Map)
	if !ok {
		return nil, fmt.Errorf("'%s' object has no attribute 'get'", pyTypeName(reqAny))
	}
	actionRaw := req.Value("action")
	if !truthy(actionRaw) {
		actionRaw = ""
	}
	actionStr, ok := actionRaw.(string)
	if !ok {
		return nil, fmt.Errorf("'%s' object has no attribute 'strip'", pyTypeName(actionRaw))
	}
	action := pyStrip(actionStr)
	if (action == "notification_reveal" || action == "notification_handle") && !c.notificationPeerAllowed(peerUID) {
		log.Printf("Denied sensitive local notification action=%s for peer_uid=%d", pyRepr(action), peerUID)
		return map[string]any{"ok": false, "forbidden": true,
			"error": "the local notification action is not available to this client"}, nil
	}
	switch action {
	case "rules_get":
		return c.handleRulesGet(), nil
	case "rules_set":
		return c.handleRulesSet(req), nil
	case "config_view":
		return c.handleConfigView()
	case "mail_view":
		return c.handleMailView(), nil
	case "mail_test":
		return c.handleMailTest(req), nil
	case "mail_update":
		return c.handleMailUpdate(req), nil
	case "notification_latest":
		return c.handleNotificationLatest(req), nil
	case "notification_reveal":
		return c.handleNotificationReveal(req), nil
	case "notification_handle":
		return c.handleNotificationHandle(req), nil
	case "restart":
		return c.handleRestart(), nil
	case "settings_update":
		return c.handleSettingsUpdate(req)
	}
	return map[string]any{"ok": false, "error": "unknown action: " + pyRepr(action)}, nil
}

func replyJSON(resp map[string]any) []byte {
	keys := make([]string, 0, len(resp))
	for k := range resp {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m := pyyaml.NewMap()
	for _, k := range keys {
		m.Set(k, resp[k])
	}
	s, err := pyyaml.JSONDumps(m, false, false)
	if err != nil {
		s, _ = pyyaml.JSONDumps(map[string]any{"ok": false, "error": "internal error: " + err.Error()}, false, false)
	}
	return []byte(s + "\n")
}

func (c *Configd) serveConn(conn net.Conn) {
	defer conn.Close()
	peerUID, err := unixrpc.PeerUID(conn)
	if err != nil {
		peerUID = -1
	}
	var resp map[string]any
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("request handling failed: %v", r)
				resp = map[string]any{"ok": false, "error": fmt.Sprintf("internal error: %v", r)}
			}
		}()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		data := []byte{}
		buf := make([]byte, 4096)
		for !bytes.Contains(data, []byte("\n")) {
			n, err := conn.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				if len(data) > maxRequestBytes {
					resp = map[string]any{"ok": false, "error": "internal error: request is too large"}
					return
				}
			}
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					resp = map[string]any{"ok": false, "error": "internal error: timed out"}
					return
				}
				break
			}
		}
		if len(data) == 0 {
			return
		}
		line := data
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		text := pyStrip(strings.ToValidUTF8(string(line), "�"))
		if text == "" {
			return
		}
		req, err := pyyaml.JSONLoads([]byte(text))
		if err != nil {
			resp = map[string]any{"ok": false, "error": "invalid json: " + jsonErrText(err)}
			return
		}
		_ = conn.SetDeadline(time.Time{})
		r, err := c.HandleRequest(req, peerUID)
		if err != nil {
			log.Printf("request handling failed: %v", err)
			resp = map[string]any{"ok": false, "error": "internal error: " + errText(err)}
			return
		}
		resp = r
	}()
	if resp == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, _ = conn.Write(replyJSON(resp))
}

func jsonErrText(err error) string {
	return "Expecting value: line 1 column 1 (char 0)"
}

// Serve accepts connections on ln one at a time until ctx is canceled or ln fails.
func (c *Configd) Serve(ctx context.Context, ln net.Listener) error {
	ln = unixrpc.PanelListener(ln)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		c.serveConn(conn)
	}
}

// RunConfigd is main(): serve the socket one request at a time.
func RunConfigd(opts ConfigdOptions) error {
	c := NewConfigd(opts)
	if _, err := os.Stat(opts.SocketPath); err == nil {
		_ = os.Remove(opts.SocketPath)
	}
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(opts.SocketPath, 0o660); err != nil {
		_ = ln.Close()
		_ = os.Remove(opts.SocketPath)
		return err
	}
	log.Printf("authelia-configd listening on %s", opts.SocketPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			log.Printf("Got signal, shutting down")
		}
		_ = ln.Close()
		if _, err := os.Stat(opts.SocketPath); err == nil {
			_ = os.Remove(opts.SocketPath)
		}
	}()
	return c.Serve(ctx, ln)
}

var _ = bufio.NewReader
