package tools

// The Go port of haproxy-udp-forward.py: the same udp.yml validation, the
// same HP_UDP_* chains and iptables-restore transaction, the same state
// file (/run/easy-ha-proxy/udp-forward-state.json, version 1) and the same
// --check, --dry-run and --health-targets output.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// UDPForwardOptions holds what haproxy-udp-forward.py reads from the environment.
type UDPForwardOptions struct {
	ConfigPath      string
	IptablesBin     string
	IptablesRestore string
	BanSet          string
	AuthSet         string
	StatePath       string
	FailoverPath    string
	ResolveIPv4     func(host string) (string, error)
	SysctlRoot      string
	Now             func() time.Time
}

func envOrDefault(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

// UDPForwardOptionsFromEnv reads HP_UDP_* as the Python generator does.
func UDPForwardOptionsFromEnv() UDPForwardOptions {
	return UDPForwardOptions{
		ConfigPath:      envOrDefault("HP_UDP_CONFIG", "/opt/haproxy-admin/config/udp.yml"),
		IptablesBin:     envOrDefault("HP_UDP_IPTABLES", "iptables-legacy"),
		IptablesRestore: envOrDefault("HP_UDP_IPTABLES_RESTORE", "iptables-legacy-restore"),
		BanSet:          envOrDefault("HP_UDP_BAN_SET", "haproxy_ban"),
		AuthSet:         envOrDefault("HP_UDP_AUTH_SET", "haproxy_ip_auth"),
		StatePath:       envOrDefault("HP_UDP_STATE", "/run/easy-ha-proxy/udp-forward-state.json"),
		FailoverPath:    envOrDefault("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"),
	}
}

const (
	udpRawChain        = "HP_UDP_RAW"
	udpNatPre          = "HP_UDP_PRE"
	udpNatPost         = "HP_UDP_POST"
	udpFwdChain        = "HP_UDP_FWD"
	udpLegacyInput     = "HP_UDP_IN"
	udpMaxPorts        = 1024
	udpFailoverMaxSize = 64 * 1024
)

var (
	udpWiring = [][3]string{{"raw", "PREROUTING", udpRawChain}, {"nat", "PREROUTING", udpNatPre},
		{"nat", "POSTROUTING", udpNatPost}, {"filter", "FORWARD", udpFwdChain}}
	udpPortRangeRE = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)
)

// UDPBackup is a forward's backup backend.
type UDPBackup struct {
	Host       string
	IP         string // "" when it did not resolve
	Start, End int
	Check      string
	HealthPort int // 0 for none
}

// UDPForward is one validated udp.yml entry.
type UDPForward struct {
	Name                     string
	ListenStart, ListenEnd   int
	BackendIP                string
	BackendStart, BackendEnd int
	BanCheck, ZeroTrust      bool
	Backup                   *UDPBackup
	Active, TargetIP         string
	TargetStart              int
}

type udpConfigError struct{ msg string }

func (e *udpConfigError) Error() string { return e.msg }

func cfgErr(format string, args ...any) error { return &udpConfigError{fmt.Sprintf(format, args...)} }

// systemExit is SystemExit(message): printed on stderr, exit status 1.
type systemExit struct{ msg string }

func (e *systemExit) Error() string { return e.msg }

func udpLog(w io.Writer, msg string) { fmt.Fprintf(w, "[easy-ha-proxy-udp] %s\n", msg) }

func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

// pyStrValue is str(value) for decoded YAML.
func pyStrValue(v any) string {
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
	case float64:
		return pyyaml.FloatRepr(x)
	case pyyaml.Timestamp:
		return strings.Replace(string(x), "T", " ", 1)
	}
	s, _ := pyyaml.JSONDumps(v, false, false)
	return s
}

func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int64:
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

func strOr(v any) string {
	if !pyTruthy(v) {
		return ""
	}
	return pyStrValue(v)
}

func pyStripSpace(s string) string { return strings.TrimFunc(s, unicode.IsSpace) }

func (o UDPForwardOptions) resolveIPv4(host string) (string, error) {
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		return a.String(), nil
	}
	if o.ResolveIPv4 != nil {
		return o.ResolveIPv4(host)
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil {
		reason := "[Errno -2] Name or service not known"
		var de *net.DNSError
		if errors.As(err, &de) && de.IsTemporary {
			reason = "[Errno -3] Temporary failure in name resolution"
		}
		return "", cfgErr("cannot resolve backend host %s: %s", pyRepr(host), reason)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", cfgErr("backend host %s has no IPv4 address", pyRepr(host))
}

func isLoopback(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsLoopback()
}

func udpPortRange(value any, field string) (int, int, error) {
	text := ""
	if value != nil {
		text = pyStripSpace(pyStrValue(value))
	}
	m := udpPortRangeRE.FindStringSubmatch(text)
	if m == nil {
		return 0, 0, cfgErr("%s must be a port or inclusive range such as 51820-51830", field)
	}
	start, _ := strconv.Atoi(m[1])
	end := start
	if m[2] != "" {
		end, _ = strconv.Atoi(m[2])
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return 0, 0, cfgErr("%s must be within 1-65535, got %s", field, pyRepr(text))
	}
	if end < start {
		return 0, 0, cfgErr("%s range end must not be lower than its start", field)
	}
	if end-start+1 > udpMaxPorts {
		return 0, 0, cfgErr("%s range may contain at most %d ports", field, udpMaxPorts)
	}
	return start, end, nil
}

func formatPortRange(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func dportTokens(start, end int) []string {
	if start == end {
		return []string{"--dport", strconv.Itoa(start)}
	}
	return []string{"--dport", fmt.Sprintf("%d:%d", start, end)}
}

func getOr(m *pyyaml.Map, key string, def any) any {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

func (o UDPForwardOptions) normalizeForward(raw any, logw io.Writer) (*UDPForward, error) {
	m, ok := raw.(*pyyaml.Map)
	if !ok {
		return nil, cfgErr("each UDP forward must be a mapping")
	}
	name := pyStripSpace(strOr(m.Value("name")))
	ls, le, err := udpPortRange(m.Value("listen_port"), "listen_port")
	if err != nil {
		return nil, err
	}
	backendHost := pyStripSpace(strOr(m.Value("backend_host")))
	if backendHost == "" {
		label := pyRepr(name)
		if name == "" {
			// _format_port_range gives an int for one port: its repr has no quotes.
			label = pyRepr(formatPortRange(ls, le))
			if ls == le {
				label = formatPortRange(ls, le)
			}
		}
		return nil, cfgErr("forward %s is missing backend_host", label)
	}
	backendIP, err := o.resolveIPv4(backendHost)
	if err != nil {
		return nil, err
	}
	if isLoopback(backendIP) {
		return nil, cfgErr("backend_host must not resolve to a loopback address; use a container or LAN backend")
	}
	bs, be, err := udpPortRange(m.Value("backend_port"), "backend_port")
	if err != nil {
		return nil, err
	}
	if le-ls != be-bs {
		return nil, cfgErr("listen_port and backend_port ranges must contain the same number of ports")
	}
	backup, err := o.normalizeBackup(m, backendIP, bs, be, logw)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = fmt.Sprintf("udp%d", ls)
	}
	return &UDPForward{Name: name, ListenStart: ls, ListenEnd: le, BackendIP: backendIP, BackendStart: bs, BackendEnd: be,
		BanCheck: pyTruthy(getOr(m, "ban_check", true)), ZeroTrust: pyTruthy(getOr(m, "zero_trust", false)), Backup: backup,
		Active: "primary", TargetIP: backendIP, TargetStart: bs}, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func (o UDPForwardOptions) normalizeBackup(m *pyyaml.Map, backendIP string, bs, be int, logw io.Writer) (*UDPBackup, error) {
	host := pyStripSpace(strOr(m.Value("backup_host")))
	if host == "" {
		return nil, nil
	}
	ip, err := o.resolveIPv4(host)
	if err != nil {
		label := "None"
		if v, ok := m.Get("name"); ok {
			label = pyStrValue(v)
			if s, isStr := v.(string); isStr {
				label = pyRepr(s)
			}
		}
		udpLog(logw, fmt.Sprintf("backup of forward %s is unavailable: %s", label, err.Error()))
		ip = ""
	}
	if ip != "" && isLoopback(ip) {
		return nil, cfgErr("backup_host must not resolve to a loopback address")
	}
	if ip != "" && ip == backendIP {
		return nil, cfgErr("backup_host must be a different address from backend_host")
	}
	portValue := m.Value("backup_port")
	if portValue == nil || portValue == "" {
		portValue = m.Value("backend_port")
	}
	start, end, err := udpPortRange(portValue, "backup_port")
	if err != nil {
		return nil, err
	}
	if end-start != be-bs {
		return nil, cfgErr("backup_port must contain as many ports as backend_port")
	}
	check := strings.ToLower(pyStripSpace(strOr(m.Value("health_check"))))
	if check == "" {
		check = "ping"
	}
	if check != "ping" && check != "tcp" {
		return nil, cfgErr("health_check must be ping or tcp")
	}
	healthPort := 0
	if check == "tcp" {
		text := pyStripSpace(strOr(m.Value("health_port")))
		n, convErr := strconv.Atoi(text)
		if !isDigits(text) || convErr != nil || n < 1 || n > 65535 {
			return nil, cfgErr("health_port must be a TCP port (1-65535) for the tcp check")
		}
		healthPort = n
	}
	return &UDPBackup{Host: host, IP: ip, Start: start, End: end, Check: check, HealthPort: healthPort}, nil
}

// LoadUDPForwards is load_forwards; logw receives the generator's log lines.
func LoadUDPForwards(opts UDPForwardOptions) ([]UDPForward, error) {
	return opts.loadForwards(io.Discard)
}

func (o UDPForwardOptions) loadForwards(logw io.Writer) ([]UDPForward, error) {
	path := o.ConfigPath
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, nil
		}
		return nil, &systemExit{fmt.Sprintf("cannot read %s: %s", path, osErrorText(path, err))}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, &systemExit{fmt.Sprintf("cannot read %s: %v", path, err)}
	}
	if !fi.Mode().IsRegular() {
		return nil, &systemExit{fmt.Sprintf("cannot read %s: not a regular file", path)}
	}
	if fi.Size() > 1024*1024 {
		return nil, &systemExit{fmt.Sprintf("cannot read %s: file is too large", path)}
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, &systemExit{fmt.Sprintf("cannot read %s: %v", path, err)}
	}
	data, err := pyyaml.Load(raw)
	if err != nil {
		return nil, err
	}
	if !pyTruthy(data) {
		data = pyyaml.NewMap()
	}
	root, ok := data.(*pyyaml.Map)
	if !ok {
		return nil, &systemExit{fmt.Sprintf("%s: root must be a mapping", path)}
	}
	entries := root.Value("udp_forwards")
	if entries == nil {
		entries = root.Value("udp")
	}
	list, ok := entries.([]any)
	if !ok {
		return nil, nil
	}
	forwards := []UDPForward{}
	seen := map[int]bool{}
	for i, entry := range list {
		if em, ok := entry.(*pyyaml.Map); ok && em.Value("enabled") == false {
			continue
		}
		fwd, err := o.normalizeForward(entry, logw)
		if err != nil {
			return nil, &systemExit{fmt.Sprintf("%s: udp_forwards[%d]: %s", path, i, err.Error())}
		}
		first := -1
		for p := fwd.ListenStart; p <= fwd.ListenEnd; p++ {
			if seen[p] && (first < 0 || p < first) {
				first = p
			}
		}
		if first >= 0 {
			return nil, &systemExit{fmt.Sprintf("%s: udp_forwards[%d]: listen port %d is configured more than once", path, i, first)}
		}
		for p := fwd.ListenStart; p <= fwd.ListenEnd; p++ {
			seen[p] = true
		}
		forwards = append(forwards, *fwd)
	}
	return forwards, nil
}

func osErrorText(path string, err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("[Errno %d] %s: %s", int(errno), msg, pyRepr(path))
	}
	return err.Error()
}

func (o UDPForwardOptions) loadFailover() map[string]bool {
	path := o.FailoverPath
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() > udpFailoverMaxSize {
		return map[string]bool{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]bool{}
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return map[string]bool{}
	}
	m, ok := v.(*pyyaml.Map)
	if !ok {
		return map[string]bool{}
	}
	version, isInt := m.Value("version").(int64)
	active, isMap := m.Value("active").(*pyyaml.Map)
	if !isInt || version != 1 || !isMap {
		return map[string]bool{}
	}
	out := map[string]bool{}
	active.Each(func(k, side any) {
		if side == "backup" {
			out[pyStrValue(k)] = true
		}
	})
	return out
}

func setActive(forwards []UDPForward, failover map[string]bool) {
	for i := range forwards {
		f := &forwards[i]
		if failover[f.Name] && f.Backup != nil && f.Backup.IP != "" {
			f.Active, f.TargetIP, f.TargetStart = "backup", f.Backup.IP, f.Backup.Start
		}
	}
}

func healthTargetsJSON(forwards []UDPForward) string {
	items := []any{}
	for _, f := range forwards {
		if f.Backup == nil {
			continue
		}
		m := pyyaml.NewMap()
		var backup, port any
		if f.Backup.IP != "" {
			backup = f.Backup.IP
		}
		if f.Backup.HealthPort != 0 {
			port = int64(f.Backup.HealthPort)
		}
		m.Set("backup", backup)
		m.Set("check", f.Backup.Check)
		m.Set("health_port", port)
		m.Set("name", f.Name)
		m.Set("primary", f.BackendIP)
		items = append(items, m)
	}
	s, _ := pyyaml.JSONDumps(items, true, false)
	return s
}

// BuildUDPRuleCommands is build_rule_commands (argument lists without the binary).
func BuildUDPRuleCommands(forwards []UDPForward, banSet, authSet string) [][]string {
	commands := [][]string{}
	for _, f := range forwards {
		backendIP := f.TargetIP
		if backendIP == "" {
			backendIP = f.BackendIP
		}
		backendStart := f.TargetStart
		if backendStart == 0 {
			backendStart = f.BackendStart
		}
		listen := dportTokens(f.ListenStart, f.ListenEnd)
		if f.BanCheck {
			commands = append(commands, append(append([]string{"-t", "raw", "-A", udpRawChain, "-p", "udp"}, listen...),
				"-m", "set", "--match-set", banSet, "src", "-j", "DROP"))
		}
		if f.ZeroTrust {
			commands = append(commands, append(append([]string{"-t", "raw", "-A", udpRawChain, "-p", "udp"}, listen...),
				"-m", "set", "!", "--match-set", authSet, "src", "-j", "DROP"))
		}
		for offset := 0; offset <= f.ListenEnd-f.ListenStart; offset++ {
			lp, bp := strconv.Itoa(f.ListenStart+offset), strconv.Itoa(backendStart+offset)
			commands = append(commands,
				[]string{"-t", "nat", "-A", udpNatPre, "-p", "udp", "--dport", lp, "-j", "DNAT", "--to-destination", backendIP + ":" + bp},
				[]string{"-t", "nat", "-A", udpNatPost, "-p", "udp", "-d", backendIP, "--dport", bp, "-j", "MASQUERADE"},
				[]string{"-t", "filter", "-A", udpFwdChain, "-p", "udp", "-d", backendIP, "--dport", bp, "-m", "conntrack",
					"--ctstate", "DNAT", "--ctdir", "ORIGINAL", "--ctorigdstport", lp, "-j", "ACCEPT"},
				[]string{"-t", "filter", "-A", udpFwdChain, "-p", "udp", "-s", backendIP, "--sport", bp, "-m", "conntrack",
					"--ctstate", "DNAT", "--ctdir", "REPLY", "--ctorigdstport", lp, "-j", "ACCEPT"})
		}
	}
	return commands
}

type udpRunner struct{ o UDPForwardOptions }

func (r udpRunner) run(binary string, check bool, args ...string) (int, string, error) {
	if binary == "" {
		binary = r.o.IptablesBin
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, append([]string{"-w", "10"}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	rc := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return 0, "", err
		}
		rc = ee.ExitCode()
	}
	if check && rc != 0 {
		return rc, "", fmt.Errorf("Command '%s' returned non-zero exit status %d.", pyArgList(append([]string{binary, "-w", "10"}, args...)), rc)
	}
	return rc, out.String(), nil
}

func pyArgList(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = pyRepr(a)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (r udpRunner) restore(commands [][]string, binary string, tables []string) error {
	if binary == "" {
		binary = r.o.IptablesRestore
	}
	lines := []string{}
	for _, table := range tables {
		lines = append(lines, "*"+table)
		for _, w := range udpWiring {
			if w[0] == table {
				lines = append(lines, "-F "+w[2])
			}
		}
		for _, c := range commands {
			if len(c) >= 3 && c[0] == "-t" && c[1] == table {
				lines = append(lines, strings.Join(c[2:], " "))
			}
		}
		lines = append(lines, "COMMIT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--wait", "10", "--noflush")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return err
		}
		detail := errb.String()
		if detail == "" {
			detail = out.String()
		}
		if detail == "" {
			detail = "unknown error"
		}
		return fmt.Errorf("iptables-restore failed: %s", pyStripSpace(detail))
	}
	return nil
}

func (r udpRunner) dockerUserHook(binary string) error {
	if rc, _, err := r.run(binary, false, "-t", "filter", "-S", "DOCKER-USER"); err == nil && rc == 0 {
		if rc, _, _ := r.run(binary, false, "-t", "filter", "-C", "DOCKER-USER", "-j", udpFwdChain); rc != 0 {
			if _, _, err := r.run(binary, true, "-t", "filter", "-I", "DOCKER-USER", "1", "-j", udpFwdChain); err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (r udpRunner) ensureScaffolding() error {
	for _, w := range udpWiring {
		if _, _, err := r.run("", false, "-t", w[0], "-N", w[2]); err != nil {
			return err
		}
		rc, _, err := r.run("", false, "-t", w[0], "-C", w[1], "-j", w[2])
		if err != nil {
			return err
		}
		if rc != 0 {
			if _, _, err := r.run("", true, "-t", w[0], "-I", w[1], "1", "-j", w[2]); err != nil {
				return err
			}
		}
	}
	return r.dockerUserHook(r.o.IptablesBin)
}

func realpathWhich(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		p = name
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		if a, err := filepath.Abs(r); err == nil {
			return a
		}
		return r
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func (r udpRunner) syncOtherForwardFilters(commands [][]string) error {
	primary := realpathWhich(r.o.IptablesBin)
	for _, name := range []string{"iptables-legacy", "iptables-nft"} {
		binary, err := exec.LookPath(name)
		if err != nil || realpathWhich(binary) == primary {
			continue
		}
		restore, err := exec.LookPath(name + "-restore")
		if err != nil {
			return fmt.Errorf("%s-restore is required for UDP forwarding", name)
		}
		if _, _, err := r.run(binary, false, "-t", "filter", "-N", udpFwdChain); err != nil {
			return err
		}
		if rc, _, _ := r.run(binary, false, "-t", "filter", "-C", "FORWARD", "-j", udpFwdChain); rc != 0 {
			if _, _, err := r.run(binary, true, "-t", "filter", "-I", "FORWARD", "1", "-j", udpFwdChain); err != nil {
				return err
			}
		}
		if err := r.dockerUserHook(binary); err != nil {
			return err
		}
		if err := r.restore(commands, restore, []string{"filter"}); err != nil {
			return err
		}
	}
	return nil
}

func (r udpRunner) removeLegacyLoopbackScaffolding() error {
	for {
		rc, _, err := r.run("", false, "-t", "filter", "-C", "INPUT", "-j", udpLegacyInput)
		if err != nil {
			return err
		}
		if rc != 0 {
			break
		}
		if _, _, err := r.run("", true, "-t", "filter", "-D", "INPUT", "-j", udpLegacyInput); err != nil {
			return err
		}
	}
	_, _, _ = r.run("", false, "-t", "filter", "-F", udpLegacyInput)
	_, _, _ = r.run("", false, "-t", "filter", "-X", udpLegacyInput)
	return nil
}

func (o UDPForwardOptions) writeSysctl(path, value string) error {
	full := filepath.Join(o.SysctlRoot, path)
	raw, err := os.ReadFile(full)
	if err == nil && pyStripSpace(string(raw)) == value {
		return nil
	}
	if err == nil {
		f, ferr := os.OpenFile(full, os.O_WRONLY|os.O_TRUNC, 0)
		if ferr == nil {
			_, ferr = f.WriteString(value + "\n")
			f.Close()
		}
		err = ferr
	}
	if err != nil {
		return fmt.Errorf("could not set %s=%s: %s", path, value, osErrorText(path, unwrapErrno(err)))
	}
	return nil
}

func unwrapErrno(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func udpStatePayload(forwards []UDPForward, now time.Time) *pyyaml.Map {
	ports := 0
	for _, f := range forwards {
		ports += f.ListenEnd - f.ListenStart + 1
	}
	m := pyyaml.NewMap()
	m.Set("applied_at", pyISO(now.UTC()))
	m.Set("forwards", int64(len(forwards)))
	m.Set("local_backends", int64(0))
	m.Set("ports", int64(ports))
	m.Set("version", int64(1))
	return m
}

func pyISO(t time.Time) string {
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

func (o UDPForwardOptions) writeState(state *pyyaml.Map) error {
	dir := filepath.Dir(o.StatePath)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	text, err := pyyaml.JSONDumps(state, true, true)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(o.StatePath)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(text + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, o.StatePath)
}

func (o UDPForwardOptions) applyForwards(forwards []UDPForward, stdout io.Writer) error {
	for _, s := range [][2]string{{"/proc/sys/net/ipv4/ip_forward", "1"}, {"/proc/sys/net/ipv4/conf/all/route_localnet", "0"},
		{"/proc/sys/net/ipv4/conf/default/route_localnet", "0"}} {
		if err := o.writeSysctl(s[0], s[1]); err != nil {
			return err
		}
	}
	r := udpRunner{o}
	if err := r.removeLegacyLoopbackScaffolding(); err != nil {
		return err
	}
	if err := r.ensureScaffolding(); err != nil {
		return err
	}
	commands := BuildUDPRuleCommands(forwards, o.BanSet, o.AuthSet)
	if err := r.restore(commands, "", []string{"raw", "nat", "filter"}); err != nil {
		return err
	}
	if err := r.syncOtherForwardFilters(commands); err != nil {
		return err
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	state := udpStatePayload(forwards, now())
	if err := o.writeState(state); err != nil {
		return err
	}
	switched := []string{}
	for _, f := range forwards {
		if f.Active == "backup" {
			switched = append(switched, f.Name)
		}
	}
	msg := fmt.Sprintf("applied %d UDP forward(s), %d port(s)", state.Value("forwards"), state.Value("ports"))
	if len(switched) > 0 {
		msg += "; on their backup: " + strings.Join(switched, ", ")
	}
	udpLog(stdout, msg)
	return nil
}

// RunUDPForward is main(): it returns the exit status.
func RunUDPForward(args []string, stdout, stderr io.Writer) int {
	opts := UDPForwardOptionsFromEnv()
	dryRun, check, health := false, false, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--dry-run":
			dryRun = true
		case a == "--check":
			check = true
		case a == "--health-targets":
			health = true
		case a == "--config" && i+1 < len(args):
			opts.ConfigPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--config="):
			opts.ConfigPath = strings.TrimPrefix(a, "--config=")
		default:
			fmt.Fprintf(stderr, "usage: haproxy-udp-forward.py [-h] [--config CONFIG] [--dry-run] [--check] [--health-targets]\nhaproxy-udp-forward.py: error: unrecognized arguments: %s\n", a)
			return 2
		}
	}
	return opts.Main(dryRun, check, health, stdout, stderr)
}

// Main runs one generator invocation with these options.
func (o UDPForwardOptions) Main(dryRun, check, health bool, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		var se *systemExit
		if errors.As(err, &se) {
			fmt.Fprintln(stderr, se.msg)
			return 1
		}
		fmt.Fprintf(stderr, "Traceback (most recent call last):\n%s\n", err.Error())
		return 1
	}
	forwards, err := o.loadForwards(stdout)
	if err != nil {
		return fail(err)
	}
	if health {
		fmt.Fprintln(stdout, healthTargetsJSON(forwards))
		return 0
	}
	setActive(forwards, o.loadFailover())
	if check {
		state := udpStatePayload(forwards, time.Now())
		udpLog(stdout, fmt.Sprintf("%d valid UDP forward(s), %d port(s)", state.Value("forwards"), state.Value("ports")))
		return 0
	}
	if dryRun {
		ipt := o.IptablesBin
		for _, w := range udpWiring {
			fmt.Fprintf(stdout, "%s -t %s -N %s\n", ipt, w[0], w[2])
			fmt.Fprintf(stdout, "%s -t %s -C %s -j %s || %s -t %s -I %s 1 -j %s\n", ipt, w[0], w[1], w[2], ipt, w[0], w[1], w[2])
			fmt.Fprintf(stdout, "%s -t %s -F %s\n", ipt, w[0], w[2])
		}
		for _, c := range BuildUDPRuleCommands(forwards, o.BanSet, o.AuthSet) {
			fmt.Fprintln(stdout, ipt+" "+strings.Join(c, " "))
		}
		return 0
	}
	if err := o.applyForwards(forwards, stdout); err != nil {
		return fail(err)
	}
	return 0
}

// ApplyUDPForwards keeps the older call shape: the output as a string.
func ApplyUDPForwards(_ context.Context, opts UDPForwardOptions, dryRun, checkOnly, healthTargets bool) (string, error) {
	var out, errb bytes.Buffer
	if rc := opts.Main(dryRun, checkOnly, healthTargets, &out, &errb); rc != 0 {
		return out.String(), errors.New(strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

var _ = json.Marshal
var _ = sort.Strings
