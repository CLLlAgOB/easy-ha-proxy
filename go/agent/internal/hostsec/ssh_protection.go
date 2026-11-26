package hostsec

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Constants matching installer/ssh_protection.py.
const (
	sshDefaultClient      = "/usr/bin/fail2ban-client"
	sshDefaultSystemctl   = "/usr/bin/systemctl"
	sshUnit               = "fail2ban.service"
	sshDefaultConfigDir   = "/etc/fail2ban"
	sshHeader             = "# Managed by Easy HA Proxy for SSH protection.\n"
	sshJournalMatch       = "_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session + _COMM=sshd-auth"
	sshMaxBans            = 200
	sshMaxConfigSize      = 256 * 1024
	sshReviewMessage      = "An existing Fail2ban configuration requires administrator review"
	sshDefaultAuthLog     = "/var/log/auth.log"
	sshDefaultProcIfInet6 = "/proc/net/if_inet6"
)

// Package-level injectable paths & helpers for unit tests.
var (
	sshClientPath    = sshDefaultClient
	sshSystemctlPath = sshDefaultSystemctl
	sshConfigDir     = sshDefaultConfigDir
	sshDropInPath    = filepath.Join(sshDefaultConfigDir, "jail.d", "99-easy-ha-proxy-sshd.local")
	sshAuthLogPath   = sshDefaultAuthLog
	sshProcIfInet6   = sshDefaultProcIfInet6
	sshQuickFunc     = defaultSSHQuick
	sshLookPathFunc  = sshLookPathIn
	sshSleepFunc     = time.Sleep
)

var (
	sshCounters = [][2]string{
		{"Currently failed", "currently_failed"},
		{"Total failed", "total_failed"},
		{"Currently banned", "currently_banned"},
		{"Total banned", "total_banned"},
	}
	sshOpenSSHFields = map[string]bool{
		"passwordauthentication":       true,
		"kbdinteractiveauthentication": true,
		"permitrootlogin":              true,
		"persourcepenalties":           true,
		"pubkeyauthentication":         true,
		"authenticationmethods":        true,
		"allowusers":                   true,
		"allowgroups":                  true,
		"denyusers":                    true,
		"denygroups":                   true,
	}
	sshHarmlessInputRules = map[string]bool{
		"-A INPUT -j HP_BAN": true,
	}
	sshBanTimeRe      = regexp.MustCompile(`^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$`)
	sshUserRe         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\$?$`)
	sshHostnameRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$`)
	sshPortRe         = regexp.MustCompile(`^[0-9]{1,5}$`)
	sshStreamSocketRe = regexp.MustCompile(`(\S+)\s+\(Stream\)`)
	sshEndpointRe     = regexp.MustCompile(`^[\w.:%*\[\]-]+:\d{1,5}$`)
	sshFilterSSHDRe   = regexp.MustCompile(`(?i)^sshd(?:\s|\[|$)`)
	sshStatusLineRe   = regexp.MustCompile("[\x60|]- ([^:\\n]+):([^\\n]*)")
	sshIgnoreIPItemRe = regexp.MustCompile("(?m)^[`|]- (\\S{1,253})$")
	sshSignedIntRe    = regexp.MustCompile(`^-?\d{1,12}$`)
	sshDigitsRe       = regexp.MustCompile(`^\d+$`)
)

// SSHPolicy holds Fail2ban sshd jail thresholds.
type SSHPolicy struct {
	MaxRetry int `json:"maxretry"`
	FindTime int `json:"findtime"`
	BanTime  int `json:"bantime"`
}

func defaultSSHPolicy() SSHPolicy {
	return SSHPolicy{MaxRetry: 5, FindTime: 600, BanTime: 3600}
}

func defaultSSHQuick(argv ...string) (int, string) {
	if len(argv) == 0 {
		return 1, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LC_ALL=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "LC_ALL=C")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return 1, ""
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		return 1, ""
	}
	return 0, string(out)
}

func sshAddress(value string, network bool) (string, error) {
	errMsg := "Invalid IP address"
	if network {
		errMsg = "Enter a valid IPv4 or IPv6 address or subnet"
	}
	if len(value) < 1 || len(value) > 64 || strings.Contains(value, "%") {
		return "", errors.New(errMsg)
	}
	if network && strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Zone() != "" {
			return "", errors.New(errMsg)
		}
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return "", errors.New(errMsg)
	}
	return addr.String(), nil
}

func sshTrustedAddresses(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, errors.New("Enter up to 32 trusted addresses or subnets")
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		norm, err := sshAddress(v, true)
		if err != nil {
			return nil, err
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

func sshValidatePolicyMap(raw map[string]any) (SSHPolicy, error) {
	if raw == nil || len(raw) != 3 {
		return SSHPolicy{}, errors.New("Invalid SSH blocking thresholds")
	}
	vals := make(map[string]int, 3)
	for _, k := range []string{"maxretry", "findtime", "bantime"} {
		v, ok := raw[k]
		if !ok {
			return SSHPolicy{}, errors.New("Invalid SSH blocking thresholds")
		}
		n, ok := strictIntVal(v)
		if !ok {
			return SSHPolicy{}, errors.New("Invalid SSH blocking thresholds")
		}
		vals[k] = n
	}
	return sshValidatePolicy(SSHPolicy{
		MaxRetry: vals["maxretry"],
		FindTime: vals["findtime"],
		BanTime:  vals["bantime"],
	})
}

func sshValidatePolicy(p SSHPolicy) (SSHPolicy, error) {
	if p.MaxRetry < 2 || p.MaxRetry > 50 ||
		p.FindTime < 60 || p.FindTime > 86400 || p.FindTime%60 != 0 ||
		p.BanTime < 60 || p.BanTime > 604800 || p.BanTime%60 != 0 {
		return SSHPolicy{}, errors.New("Invalid SSH blocking thresholds")
	}
	return p, nil
}

func sshOpenSSHSettings(options ...string) map[string]string {
	argv := append([]string{"/usr/sbin/sshd", "-T"}, options...)
	code, output := sshQuickFunc(argv...)
	if code != 0 {
		return map[string]string{}
	}
	settings := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		key, val, ok := strings.Cut(line, " ")
		if !ok || val == "" || !sshOpenSSHFields[key] {
			continue
		}
		combined := strings.TrimSpace(settings[key] + " " + val)
		if len(combined) > 2048 {
			combined = combined[:2048]
		}
		settings[key] = combined
	}
	return settings
}

func sshCheckConnection(user, source, hostname, localAddress, port string) (map[string]string, error) {
	if !sshUserRe.MatchString(user) {
		return nil, errors.New("Enter a valid SSH username")
	}
	normSource, err := sshAddress(source, false)
	if err != nil {
		return nil, err
	}
	if hostname != "" && !sshHostnameRe.MatchString(hostname) {
		return nil, errors.New("Enter a valid client hostname")
	}
	host := hostname
	if host == "" {
		host = normSource
	}
	fields := []string{"user=" + user, "addr=" + normSource, "host=" + host}
	if localAddress != "" {
		normLocal, err := sshAddress(localAddress, false)
		if err != nil {
			return nil, err
		}
		fields = append(fields, "laddr="+normLocal)
	}
	if port != "" {
		if !sshPortRe.MatchString(port) {
			return nil, errors.New("Enter a valid local SSH port")
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("Enter a valid local SSH port")
		}
		fields = append(fields, "lport="+port)
	}
	settings := sshOpenSSHSettings("-C", strings.Join(fields, ","))
	if len(settings) == 0 {
		return nil, secErr("OpenSSH settings could not be evaluated for this connection")
	}
	return settings, nil
}

func sshLookPathIn(name, pathList string) string {
	for _, dir := range strings.Split(pathList, ":") {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		fi, err := os.Stat(candidate)
		if err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

func sshListeningEndpoints() []string {
	ss := sshLookPathFunc("ss", "/usr/sbin:/usr/bin:/sbin:/bin")
	if ss == "" {
		return []string{}
	}
	code, output := sshQuickFunc(ss, "-H", "-lntp")
	if code != 0 {
		return []string{}
	}
	var endpoints []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.Contains(line, `("sshd",`) {
			endpoints = append(endpoints, fields[3])
		}
	}
	code, state := sshQuickFunc(sshSystemctlPath, "is-active", "ssh.socket")
	if code == 0 && strings.TrimSpace(state) == "active" {
		code, sockets := sshQuickFunc(sshSystemctlPath, "show", "--property=Listen", "--value", "ssh.socket")
		if code != 0 {
			return []string{}
		}
		for _, m := range sshStreamSocketRe.FindAllStringSubmatch(sockets, -1) {
			endpoints = append(endpoints, m[1])
		}
	}
	seen := map[string]bool{}
	filtered := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		if sshEndpointRe.MatchString(ep) && !seen[ep] {
			seen[ep] = true
			filtered = append(filtered, ep)
		}
	}
	sort.Strings(filtered)
	if len(filtered) > 32 {
		filtered = filtered[:32]
	}
	return filtered
}

func sshListeningPorts(endpoints []string) []int {
	if endpoints == nil {
		endpoints = sshListeningEndpoints()
	}
	seen := map[int]bool{}
	var ports []int
	for _, ep := range endpoints {
		idx := strings.LastIndexByte(ep, ':')
		if idx < 0 {
			continue
		}
		p, err := strconv.Atoi(ep[idx+1:])
		if err == nil && p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports
}

func sshConfigText(enabled bool, ports []int, backend string, trusted []string, policy *SSHPolicy) string {
	en := "false"
	if enabled {
		en = "true"
	}
	var b strings.Builder
	b.WriteString(sshHeader)
	b.WriteString("[sshd]\nenabled = ")
	b.WriteString(en)
	b.WriteByte('\n')
	if backend != "" {
		p := defaultSSHPolicy()
		if policy != nil {
			p = *policy
		}
		portStrs := make([]string, len(ports))
		for i, port := range ports {
			portStrs[i] = strconv.Itoa(port)
		}
		b.WriteString("port = ")
		b.WriteString(strings.Join(portStrs, ","))
		b.WriteByte('\n')
		b.WriteString("backend = ")
		b.WriteString(backend)
		b.WriteByte('\n')
		b.WriteString("action = iptables-multiport[name=sshd, port=\"%(port)s\", protocol=tcp]\n")
		fmt.Fprintf(&b, "findtime = %d\nmaxretry = %d\nbantime = %d\n", p.FindTime, p.MaxRetry, p.BanTime)
		ignoreParts := make([]string, 0, 2+len(trusted))
		ignoreParts = append(ignoreParts, "127.0.0.0/8", "::1")
		ignoreParts = append(ignoreParts, trusted...)
		b.WriteString("ignoreip = ")
		b.WriteString(strings.Join(ignoreParts, " "))
		b.WriteByte('\n')
		filterArgs := `_daemon="sshd(?:-session|-auth)?"`
		if backend == "systemd" {
			filterArgs += fmt.Sprintf(`, journalmatch="%s"`, sshJournalMatch)
		}
		b.WriteString("filter = sshd[")
		b.WriteString(filterArgs)
		b.WriteString("]\n")
		if backend == "polling" {
			b.WriteString("logpath = /var/log/auth.log\n")
		}
	}
	return b.String()
}

func sshReadConfig(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || (requireRootOwner && st.Uid != 0) || info.Mode().Perm()&0o022 != 0 || info.Size() > sshMaxConfigSize {
		return "", secErr("%s", sshReviewMessage)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", secErr("%s", sshReviewMessage)
	}
	return string(raw), nil
}

// iniDoc is a lightweight ConfigParser(interpolation=None) equivalent.
type iniDoc struct {
	defaults map[string]string
	sections map[string]map[string]string
	order    []string
}

func parseINI(text string, strict bool) (*iniDoc, error) {
	doc := &iniDoc{
		defaults: map[string]string{},
		sections: map[string]map[string]string{},
	}
	var curName string
	var curMap map[string]string
	var curKey string
	seenSections := map[string]bool{}
	seenKeys := map[string]map[string]bool{}

	lines := strings.Split(text, "\n")
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		// Continuation line (indented)
		if (line[0] == ' ' || line[0] == '\t') && curMap != nil && curKey != "" {
			curMap[curKey] = curMap[curKey] + "\n" + trimmed
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := trimmed[1 : len(trimmed)-1]
			if name == "" {
				return nil, errors.New("empty INI section header")
			}
			curKey = ""
			if name == "DEFAULT" {
				curName = "DEFAULT"
				curMap = doc.defaults
				if seenKeys["DEFAULT"] == nil {
					seenKeys["DEFAULT"] = map[string]bool{}
				}
				continue
			}
			if strict && seenSections[name] {
				return nil, fmt.Errorf("duplicate section %q", name)
			}
			seenSections[name] = true
			if doc.sections[name] == nil {
				doc.sections[name] = map[string]string{}
				doc.order = append(doc.order, name)
			}
			if seenKeys[name] == nil {
				seenKeys[name] = map[string]bool{}
			}
			curName = name
			curMap = doc.sections[name]
			continue
		}
		if curMap == nil {
			return nil, errors.New("INI option outside section")
		}
		sep := strings.IndexAny(line, "=:")
		if sep < 0 {
			return nil, errors.New("invalid INI line")
		}
		key := strings.ToLower(strings.TrimSpace(line[:sep]))
		val := strings.TrimSpace(line[sep+1:])
		if key == "" {
			return nil, errors.New("empty INI key")
		}
		if strict && seenKeys[curName][key] {
			return nil, fmt.Errorf("duplicate option %q in section %q", key, curName)
		}
		seenKeys[curName][key] = true
		curMap[key] = val
		curKey = key
	}
	return doc, nil
}

func (d *iniDoc) get(section, key, fallback string) string {
	k := strings.ToLower(key)
	if sec, ok := d.sections[section]; ok {
		if v, ok := sec[k]; ok {
			return v
		}
	}
	if v, ok := d.defaults[k]; ok {
		return v
	}
	return fallback
}

func (d *iniDoc) getBool(section, key string) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(d.get(section, key, "")))
	switch v {
	case "1", "yes", "true", "on":
		return true, nil
	case "0", "no", "false", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
}

func (d *iniDoc) getInt(section, key string, fallback int) (int, error) {
	sec, ok := d.sections[section]
	if ok {
		if v, exists := sec[strings.ToLower(key)]; exists {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if v, exists := d.defaults[strings.ToLower(key)]; exists {
		return strconv.Atoi(strings.TrimSpace(v))
	}
	return fallback, nil
}

type sshManagedConfigData struct {
	Text    string
	Enabled bool
	Ports   []int
	Backend string
	Trusted []string
	Policy  SSHPolicy
}

func sshManagedConfig() (*sshManagedConfigData, error) {
	text, err := sshReadConfig(sshDropInPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !strings.HasPrefix(text, sshHeader+"[sshd]\nenabled = ") {
		return nil, secErr("%s", sshReviewMessage)
	}
	doc, err := parseINI(text, true)
	if err != nil {
		return nil, err
	}
	if _, ok := doc.sections["sshd"]; !ok {
		return nil, secErr("%s", sshReviewMessage)
	}
	enabled, err := doc.getBool("sshd", "enabled")
	if err != nil {
		return nil, err
	}
	var ports []int
	portRaw := doc.get("sshd", "port", "")
	if portRaw != "" {
		for _, part := range strings.Split(portRaw, ",") {
			if part == "" {
				continue
			}
			p, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	backend := doc.get("sshd", "backend", "")
	ignoreFields := strings.Fields(doc.get("sshd", "ignoreip", ""))
	var rawTrusted []string
	if len(ignoreFields) > 2 {
		rawTrusted = ignoreFields[2:]
	}
	trusted, err := sshTrustedAddresses(rawTrusted)
	if err != nil {
		return nil, err
	}
	def := defaultSSHPolicy()
	maxRetry, err := doc.getInt("sshd", "maxretry", def.MaxRetry)
	if err != nil {
		return nil, err
	}
	findTime, err := doc.getInt("sshd", "findtime", def.FindTime)
	if err != nil {
		return nil, err
	}
	banTime, err := doc.getInt("sshd", "bantime", def.BanTime)
	if err != nil {
		return nil, err
	}
	policy, err := sshValidatePolicy(SSHPolicy{MaxRetry: maxRetry, FindTime: findTime, BanTime: banTime})
	if err != nil {
		return nil, err
	}
	if backend != "" && backend != "systemd" && backend != "polling" {
		return nil, secErr("%s", sshReviewMessage)
	}
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			return nil, secErr("%s", sshReviewMessage)
		}
	}
	if text != sshConfigText(enabled, ports, backend, trusted, &policy) {
		return nil, secErr("%s", sshReviewMessage)
	}
	if ports == nil {
		ports = []int{}
	}
	return &sshManagedConfigData{
		Text:    text,
		Enabled: enabled,
		Ports:   ports,
		Backend: backend,
		Trusted: trusted,
		Policy:  policy,
	}, nil
}

func sshUnmodifiedPackageDefaults(path, text string) bool {
	code, conffiles := sshQuickFunc("/usr/bin/dpkg-query", "--show", "--showformat=${Conffiles}", "fail2ban")
	if code != 0 {
		return false
	}
	sum := md5.Sum([]byte(text))
	checksum := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(conffiles, "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		// rsplit(maxsplit=1)
		idx := strings.LastIndexAny(s, " \t")
		if idx < 0 {
			continue
		}
		filePart := strings.TrimSpace(s[:idx])
		hashPart := strings.TrimSpace(s[idx+1:])
		if filePart == path && hashPart == checksum {
			return true
		}
	}
	return false
}

func sshExternalConfig() (bool, error) {
	dropInDir := filepath.Dir(sshDropInPath)
	paths := []string{filepath.Join(sshConfigDir, "jail.local")}
	if confs, err := filepath.Glob(filepath.Join(dropInDir, "*.conf")); err == nil {
		sort.Strings(confs)
		paths = append(paths, confs...)
	}
	if locals, err := filepath.Glob(filepath.Join(dropInDir, "*.local")); err == nil {
		sort.Strings(locals)
		paths = append(paths, locals...)
	}
	defaultsDebian := filepath.Join(dropInDir, "defaults-debian.conf")
	for _, p := range paths {
		if p == sshDropInPath {
			continue
		}
		if _, err := os.Lstat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, err
		}
		text, err := sshReadConfig(p)
		if err != nil {
			return false, err
		}
		if p == defaultsDebian {
			if sshUnmodifiedPackageDefaults(p, text) {
				continue
			}
			return true, nil
		}
		doc, err := parseINI(text, false)
		if err != nil {
			return false, err
		}
		if _, hasIgnoreIP := doc.defaults["ignoreip"]; hasIgnoreIP {
			return true, nil
		}
		if _, hasIgnoreCmd := doc.defaults["ignorecommand"]; hasIgnoreCmd {
			return true, nil
		}
		if _, hasIncludes := doc.sections["INCLUDES"]; hasIncludes {
			return true, nil
		}
		for _, name := range doc.order {
			low := strings.ToLower(name)
			if strings.HasPrefix(low, "sshd") || strings.HasPrefix(low, "openssh") {
				return true, nil
			}
			filterVal := strings.TrimSpace(doc.get(name, "filter", ""))
			if sshFilterSSHDRe.MatchString(filterVal) {
				return true, nil
			}
		}
	}
	return false, nil
}

type sshJailStatusData struct {
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
	Banned          []string
}

func sshJailStatus() (*sshJailStatusData, error) {
	code, output := sshQuickFunc(sshClientPath, "status", "sshd")
	if code != 0 {
		return nil, nil
	}
	values := map[string]string{}
	for _, m := range sshStatusLineRe.FindAllStringSubmatch(output, -1) {
		values[m[1]] = strings.TrimSpace(m[2])
	}
	parsed := map[string]int{}
	for _, kv := range sshCounters {
		raw := values[kv[0]]
		if !sshDigitsRe.MatchString(raw) {
			return nil, secErr("The Fail2ban SSH rule returned an unreadable status")
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, secErr("The Fail2ban SSH rule returned an unreadable status")
		}
		parsed[kv[1]] = n
	}
	bans := []string{}
	fields := strings.Fields(values["Banned IP list"])
	if len(fields) > sshMaxBans {
		fields = fields[:sshMaxBans]
	}
	for _, v := range fields {
		norm, err := sshAddress(v, false)
		if err != nil {
			continue
		}
		bans = append(bans, norm)
	}
	return &sshJailStatusData{
		CurrentlyFailed: parsed["currently_failed"],
		TotalFailed:     parsed["total_failed"],
		CurrentlyBanned: parsed["currently_banned"],
		TotalBanned:     parsed["total_banned"],
		Banned:          bans,
	}, nil
}

func sshBanTimes(addresses []string) map[string]map[string]any {
	if len(addresses) == 0 {
		return map[string]map[string]any{}
	}
	code, output := sshQuickFunc(sshClientPath, "get", "sshd", "banip", "--with-time")
	if code != 0 {
		return map[string]map[string]any{}
	}
	active := make(map[string]bool, len(addresses))
	for _, a := range addresses {
		active[a] = true
	}
	result := map[string]map[string]any{}
	for _, line := range strings.Split(output, "\n") {
		m := sshBanTimeRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		ip, err := sshAddress(m[1], false)
		if err != nil || !active[ip] {
			continue
		}
		permanent := m[3] == "-1"
		var expires any = m[4]
		if permanent {
			expires = nil
		}
		result[ip] = map[string]any{
			"started":   m[2],
			"expires":   expires,
			"permanent": permanent,
		}
	}
	return result
}

func sshEffectiveJailPolicy() map[string]any {
	keys := []string{"maxretry", "findtime", "bantime", "ignoreip"}
	type queryRes struct {
		code int
		out  string
	}
	results := make([]queryRes, len(keys))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Add(1)
		go func(idx int, key string) {
			defer wg.Done()
			code, out := sshQuickFunc(sshClientPath, "get", "sshd", key)
			results[idx] = queryRes{code: code, out: out}
		}(i, k)
	}
	wg.Wait()

	out := map[string]any{}
	for i, key := range keys {
		res := results[i]
		if res.code != 0 {
			continue
		}
		val := strings.TrimSpace(res.out)
		if key == "ignoreip" {
			if strings.HasPrefix(val, "These IP addresses/networks are ignored:") ||
				strings.HasPrefix(val, "No IP address/network is ignored") {
				matches := sshIgnoreIPItemRe.FindAllStringSubmatch(val, -1)
				trusted := make([]string, 0, len(matches))
				for _, m := range matches {
					trusted = append(trusted, m[1])
					if len(trusted) >= 50 {
						break
					}
				}
				out["trusted"] = trusted
			}
		} else if sshSignedIntRe.MatchString(val) {
			if n, err := strconv.Atoi(val); err == nil {
				out[key] = n
			}
		}
	}
	return out
}

func sshEqualSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sshIsBlockTarget(tail []string) bool {
	return sshEqualSlice(tail, []string{"-j", "DROP"}) ||
		sshEqualSlice(tail, []string{"-j", "REJECT"}) ||
		sshEqualSlice(tail, []string{"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}) ||
		sshEqualSlice(tail, []string{"-j", "REJECT", "--reject-with", "icmp6-port-unreachable"})
}

func shlexSplitStrict(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unclosed single quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			closed := false
			for i++; i < len(s); i++ {
				if s[i] == '"' {
					closed = true
					break
				}
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\\\"$`\n", rune(s[i+1])) {
					i++
				}
				cur.WriteByte(s[i])
			}
			if !closed {
				return nil, errors.New("unclosed double quote")
			}
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing escape")
			}
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}

func sshFirewallFamily(family int, ports []int, banned map[string]bool) string {
	tool := "/usr/sbin/iptables-save"
	if family == 6 {
		tool = "/usr/sbin/ip6tables-save"
	}
	code, rules := sshQuickFunc(tool, "-t", "filter")
	if code != 0 {
		return "unknown"
	}
	portSet := make(map[string]bool, len(ports))
	for _, p := range ports {
		portSet[strconv.Itoa(p)] = true
	}
	hook := false
	earlierInput := false
	priorityUncertain := false
	earlierJailRule := false
	blocked := map[string]bool{}
	reachedReturn := false

	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "-A INPUT ") && !sshHarmlessInputRules[strings.TrimSpace(line)] {
			args, err := shlexSplitStrict(line)
			if err != nil {
				return "unknown"
			}
			if !hook && len(args) == 10 &&
				sshEqualSlice(args[2:7], []string{"-p", "tcp", "-m", "multiport", "--dports"}) &&
				sshEqualSlice(args[8:], []string{"-j", "f2b-sshd"}) {
				dports := strings.Split(args[7], ",")
				dset := make(map[string]bool, len(dports))
				for _, dp := range dports {
					dset[dp] = true
				}
				samePorts := len(dset) == len(portSet)
				if samePorts {
					for k := range portSet {
						if !dset[k] {
							samePorts = false
							break
						}
					}
				}
				if samePorts {
					hook = true
					priorityUncertain = earlierInput
				}
			}
			earlierInput = true
		} else if !reachedReturn && strings.HasPrefix(line, "-A f2b-sshd ") {
			args, err := shlexSplitStrict(line)
			if err != nil {
				return "unknown"
			}
			if len(args) >= 2 && sshEqualSlice(args[2:], []string{"-j", "RETURN"}) {
				reachedReturn = true
			}
			if len(args) >= 5 && args[2] == "-s" && sshIsBlockTarget(args[4:]) {
				var addr netip.Addr
				if strings.Contains(args[3], "/") {
					p, err := netip.ParsePrefix(args[3])
					if err != nil {
						return "unknown"
					}
					if p.Bits() == p.Addr().BitLen() {
						addr = p.Addr()
					}
				} else {
					a, err := netip.ParseAddr(args[3])
					if err != nil {
						return "unknown"
					}
					addr = a
				}
				if addr.IsValid() {
					ip := addr.String()
					blocked[ip] = true
					if banned[ip] && earlierJailRule {
						priorityUncertain = true
					}
				}
			} else if !reachedReturn {
				earlierJailRule = true
			}
		}
	}
	if len(banned) > 0 {
		if !hook {
			return "missing"
		}
		for ip := range banned {
			if !blocked[ip] {
				return "missing"
			}
		}
		if priorityUncertain {
			return "order_unknown"
		}
		return "verified"
	}
	return "idle"
}

func sshFirewallStatus(configured, live []int, status *sshJailStatusData) map[string]any {
	if len(live) == 0 {
		return map[string]any{"state": "unknown"}
	}
	if len(live) != len(configured) {
		return map[string]any{"state": "ports_changed"}
	}
	cset := make(map[int]bool, len(configured))
	for _, p := range configured {
		cset[p] = true
	}
	for _, p := range live {
		if !cset[p] {
			return map[string]any{"state": "ports_changed"}
		}
	}
	addrs := map[int]map[string]bool{4: {}, 6: {}}
	for _, v := range status.Banned {
		a, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		if a.Is4() {
			addrs[4][v] = true
		} else {
			addrs[6][v] = true
		}
	}
	families := map[string]string{}
	observed := map[string]bool{}
	for _, fam := range []int{4, 6} {
		st := "idle"
		if len(addrs[fam]) > 0 {
			st = sshFirewallFamily(fam, configured, addrs[fam])
		}
		families[strconv.Itoa(fam)] = st
		observed[st] = true
	}
	var state string
	switch {
	case observed["missing"]:
		state = "missing"
	case observed["unknown"]:
		state = "unknown"
	case observed["order_unknown"]:
		state = "order_unknown"
	case status.CurrentlyBanned > len(status.Banned):
		state = "partial"
	case observed["verified"]:
		state = "verified"
	default:
		state = "idle"
	}
	return map[string]any{"state": state, "families": families}
}

func sshIsRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// SSHSnapshot inspects Fail2ban and OpenSSH protection status.
func SSHSnapshot(monitor bool) map[string]any {
	result := map[string]any{
		"state":   "not_installed",
		"managed": false,
		"trusted": []string{},
		"policy":  defaultSSHPolicy(),
	}
	if !monitor {
		result["openssh"] = sshOpenSSHSettings()
	}
	err := func() error {
		installed := sshIsRegularFile(sshClientPath)
		var status *sshJailStatusData
		if installed {
			_, unit := sshQuickFunc(sshSystemctlPath, "show", "--property=ActiveState", "--value", sshUnit)
			var err error
			status, err = sshJailStatus()
			if err != nil {
				return err
			}
			if status != nil {
				result["state"] = "active"
				result["currently_failed"] = status.CurrentlyFailed
				result["total_failed"] = status.TotalFailed
				result["currently_banned"] = status.CurrentlyBanned
				result["total_banned"] = status.TotalBanned
				result["banned"] = status.Banned
			} else if strings.TrimSpace(unit) == "active" {
				code, _ := sshQuickFunc(sshClientPath, "ping")
				if code == 0 {
					result["state"] = "jail_disabled"
				} else {
					result["state"] = "unavailable"
				}
			} else {
				switch strings.TrimSpace(unit) {
				case "failed":
					result["state"] = "service_failed"
				case "inactive":
					result["state"] = "service_stopped"
				default:
					result["state"] = "unavailable"
				}
			}
		}
		local, err := sshManagedConfig()
		if err != nil {
			return err
		}
		if local != nil {
			result["managed"] = true
			result["managed_enabled"] = local.Enabled
			result["trusted"] = local.Trusted
			result["ports"] = local.Ports
			if local.Backend != "" {
				result["backend"] = local.Backend
			} else {
				result["backend"] = nil
			}
			result["policy"] = local.Policy
		}
		ext, err := sshExternalConfig()
		if err != nil {
			return err
		}
		result["external_config"] = ext
		var listeners []string
		if !monitor || (status != nil && local != nil && local.Enabled && !ext) {
			listeners = sshListeningEndpoints()
			result["listeners"] = listeners
		}
		if status != nil {
			if !monitor {
				result["ban_times"] = sshBanTimes(status.Banned)
				result["effective_policy"] = sshEffectiveJailPolicy()
			}
			if local != nil && local.Enabled && !ext {
				result["firewall"] = sshFirewallStatus(local.Ports, sshListeningPorts(listeners), status)
			} else {
				result["firewall"] = map[string]any{"state": "external"}
			}
		}
		return nil
	}()
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}

func sshLogBackend() (string, error) {
	argv := append([]string{"/usr/bin/journalctl", "--quiet", "-n", "1", "-o", "json", "--output-fields=_COMM", "--"},
		strings.Fields(sshJournalMatch)...)
	code, output := sshQuickFunc(argv...)
	if code == 0 && strings.HasPrefix(strings.TrimLeft(output, " \t\r\n"), "{") {
		return "systemd", nil
	}
	if sshIsRegularFile(sshAuthLogPath) {
		return "polling", nil
	}
	if code == 0 {
		return "systemd", nil
	}
	return "", secErr("No readable SSH log source was found")
}

func sshReloadJail(running, enabled bool) error {
	if running {
		_, _, err := runCommand([]string{sshClientPath, "reload", "--if-exists", "sshd"}, cmdOpts{check: true})
		return err
	}
	if enabled {
		_, _, err := runCommand([]string{sshSystemctlPath, "start", sshUnit}, cmdOpts{check: true})
		return err
	}
	return nil
}

func sshVerifyJail(running, enabled bool) error {
	attempts := 1
	if enabled && !running {
		attempts = 20
	}
	for i := 0; i < attempts; i++ {
		st, err := sshJailStatus()
		if err != nil {
			return err
		}
		if enabled == (st != nil) {
			if running {
				code, _ := sshQuickFunc(sshClientPath, "ping")
				if code != 0 {
					return secErr("The Fail2ban service did not become ready")
				}
			}
			return nil
		}
		if attempts > 1 {
			sshSleepFunc(250 * time.Millisecond)
		}
	}
	return secErr("The Fail2ban SSH rule could not be verified")
}

// SSHSetProtection installs, enables, or disables panel-managed Fail2ban SSH protection.
func SSHSetProtection(action string, trusted []string, policy *SSHPolicy) (string, error) {
	if _, _, err := checkPlatform(); err != nil {
		return "", err
	}
	local, err := sshManagedConfig()
	if err != nil {
		return "", err
	}
	ext, err := sshExternalConfig()
	if err != nil {
		return "", err
	}
	if ext {
		return "", secErr("SSH protection is configured outside the panel")
	}
	installed := sshIsRegularFile(sshClientPath)
	if action == "install" && installed {
		return "", secErr("Fail2ban is already installed. Refresh its status before continuing.")
	}
	if action != "install" && !installed {
		return "", secErr("Install Fail2ban before changing SSH protection")
	}
	enabled := action != "disable"
	if !enabled && local == nil {
		return "", secErr("Only panel-managed SSH protection can be disabled here")
	}
	var active *sshJailStatusData
	if installed {
		active, err = sshJailStatus()
		if err != nil {
			return "", err
		}
	}
	if active != nil && (local == nil || !local.Enabled) {
		return "", secErr("SSH protection is configured outside the panel")
	}

	var (
		ports   []int
		backend string
		pol     SSHPolicy
	)
	if enabled {
		if policy != nil {
			pol, err = sshValidatePolicy(*policy)
			if err != nil {
				return "", err
			}
		} else if local != nil {
			pol = local.Policy
		} else {
			pol = defaultSSHPolicy()
		}
		ports = sshListeningPorts(nil)
		if len(ports) == 0 {
			return "", secErr("No active OpenSSH listening port was found")
		}
		if len(ports) > 15 {
			return "", secErr("The firewall action supports up to 15 SSH ports")
		}
		backend, err = sshLogBackend()
		if err != nil {
			return "", err
		}
	} else {
		ports = local.Ports
		backend = local.Backend
		trusted = local.Trusted
		pol = local.Policy
	}

	if action == "install" {
		if err := maintenanceGuard(false); err != nil {
			return "", err
		}
		if err := AtomicWrite(sshDropInPath, []byte(sshConfigText(false, nil, "", nil, nil)), 0o644); err != nil {
			return "", err
		}
		if _, _, err := runCommand([]string{
			"/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=10", "--assume-yes", "--no-remove",
			"--no-upgrade", "--no-install-recommends", "install", "fail2ban", "python3-systemd", "iptables",
		}, cmdOpts{timeout: 600 * time.Second, check: true}); err != nil {
			return "", err
		}
		local, err = sshManagedConfig()
		if err != nil {
			return "", err
		}
		ext, err = sshExternalConfig()
		if err != nil {
			return "", err
		}
		if ext {
			return "", secErr("SSH protection is configured outside the panel")
		}
	}

	var previous *string
	if local != nil {
		prev := local.Text
		previous = &prev
	}
	pingCode, _ := sshQuickFunc(sshClientPath, "ping")
	running := pingCode == 0

	applyErr := func() error {
		if enabled {
			iptables := sshLookPathIn("iptables", "/usr/sbin:/sbin:/usr/bin:/bin")
			if iptables == "" {
				iptables = "/usr/sbin/iptables"
			}
			firewalls := []string{iptables}
			if _, err := os.Stat(sshProcIfInet6); err == nil {
				ip6tables := sshLookPathIn("ip6tables", "/usr/sbin:/sbin:/usr/bin:/bin")
				if ip6tables == "" {
					ip6tables = "/usr/sbin/ip6tables"
				}
				firewalls = append(firewalls, ip6tables)
			}
			for _, fw := range firewalls {
				if code, _ := sshQuickFunc(fw, "-w", "2", "-S", "INPUT"); code != 0 {
					return secErr("The server firewall could not be checked for SSH blocking")
				}
			}
		}
		if err := AtomicWrite(sshDropInPath, []byte(sshConfigText(enabled, ports, backend, trusted, &pol)), 0o644); err != nil {
			return err
		}
		if _, _, err := runCommand([]string{sshClientPath, "-t"}, cmdOpts{check: true}); err != nil {
			return err
		}
		if err := sshReloadJail(running, enabled); err != nil {
			return err
		}
		if err := sshVerifyJail(running, enabled); err != nil {
			return err
		}
		if enabled {
			if _, _, err := runCommand([]string{sshSystemctlPath, "enable", sshUnit}, cmdOpts{check: true}); err != nil {
				return err
			}
		}
		return nil
	}()
	if applyErr != nil {
		if previous == nil {
			_ = os.Remove(sshDropInPath)
		} else {
			_ = AtomicWrite(sshDropInPath, []byte(*previous), 0o644)
		}
		if running {
			_, _, _ = runCommand([]string{sshClientPath, "reload", "--if-exists", "sshd"}, cmdOpts{check: false})
		} else if enabled {
			_, _, _ = runCommand([]string{sshSystemctlPath, "stop", sshUnit}, cmdOpts{check: false})
		}
		return "", applyErr
	}
	if enabled {
		return "SSH protection is enabled.", nil
	}
	return "SSH protection is disabled.", nil
}

type sshCLIArgs struct {
	action          string
	trusted         []string
	ip              string
	policyRaw       string
	hasPolicy       bool
	user            string
	hostname        string
	localAddress    string
	port            string
	maintenanceLock string
	requestID       *string
}

func parseSSHCLIArgs(args []string) (sshCLIArgs, error) {
	var parsed sshCLIArgs
	validActions := map[string]bool{
		"status":           true,
		"monitor":          true,
		"check-connection": true,
		"install":          true,
		"enable":           true,
		"disable":          true,
		"unban":            true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			if parsed.action != "" {
				return parsed, fmt.Errorf("unexpected positional argument: %s", arg)
			}
			if !validActions[arg] {
				return parsed, fmt.Errorf("invalid action: %s", arg)
			}
			parsed.action = arg
			continue
		}
		name, eqVal, hasEq := strings.Cut(arg, "=")
		nextVal := func() (string, error) {
			if hasEq {
				return eqVal, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("option %s requires a value", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--trusted":
			if hasEq {
				if eqVal != "" {
					parsed.trusted = append(parsed.trusted, eqVal)
				}
			} else {
				for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					parsed.trusted = append(parsed.trusted, args[i])
				}
			}
		case "--ip":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.ip = v
		case "--policy":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.policyRaw = v
			parsed.hasPolicy = true
		case "--user":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.user = v
		case "--hostname":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.hostname = v
		case "--local-address":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.localAddress = v
		case "--port":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.port = v
		case "--maintenance-lock":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.maintenanceLock = v
		case "--request-id":
			v, err := nextVal()
			if err != nil {
				return parsed, err
			}
			parsed.requestID = &v
		default:
			return parsed, fmt.Errorf("unknown option: %s", name)
		}
	}
	if parsed.action == "" {
		return parsed, errors.New("action is required")
	}
	return parsed, nil
}

// RunSSHProtectionCLI implements "easy-ha-proxy-agent ssh-protection <action> [flags]".
func RunSSHProtectionCLI(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseSSHCLIArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "easy-ha-proxy-agent ssh-protection: %v\n", err)
		return 2
	}
	var reqID any
	if parsed.requestID != nil {
		reqID = *parsed.requestID
	}
	emit := func(payload map[string]any) {
		raw, _ := json.Marshal(payload)
		_, _ = stdout.Write(append(raw, '\n'))
	}
	fail := func(err error) int {
		emit(map[string]any{"ok": false, "request_id": reqID, "error": err.Error()})
		return 1
	}

	var policy *SSHPolicy
	if parsed.hasPolicy {
		var rawMap map[string]any
		dec := json.NewDecoder(strings.NewReader(parsed.policyRaw))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			return fail(err)
		}
		p, err := sshValidatePolicyMap(rawMap)
		if err != nil {
			return fail(err)
		}
		policy = &p
	}

	var result map[string]any
	switch parsed.action {
	case "status", "monitor":
		result = SSHSnapshot(parsed.action == "monitor")
	case "check-connection":
		settings, err := sshCheckConnection(parsed.user, parsed.ip, parsed.hostname, parsed.localAddress, parsed.port)
		if err != nil {
			return fail(err)
		}
		result = map[string]any{"openssh": settings}
	case "unban":
		ip, err := sshAddress(parsed.ip, false)
		if err != nil {
			return fail(err)
		}
		if code, _ := sshQuickFunc(sshClientPath, "set", "sshd", "unbanip", ip); code != 0 {
			return fail(secErr("The IP could not be unblocked in the Fail2ban SSH rule"))
		}
		result = map[string]any{"message": "IP removed from SSH blocks."}
	default:
		if parsed.maintenanceLock == "" {
			return fail(secErr("--maintenance-lock is required"))
		}
		fd, err := unix.Open(parsed.maintenanceLock, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return fail(err)
		}
		defer unix.Close(fd)
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
				return fail(secErr("Another maintenance operation is active"))
			}
			return fail(err)
		}
		trusted, err := sshTrustedAddresses(parsed.trusted)
		if err != nil {
			return fail(err)
		}
		msg, err := SSHSetProtection(parsed.action, trusted, policy)
		if err != nil {
			return fail(err)
		}
		result = map[string]any{"message": msg}
	}

	out := map[string]any{"ok": true, "request_id": reqID}
	for k, v := range result {
		out[k] = v
	}
	emit(out)
	return 0
}
