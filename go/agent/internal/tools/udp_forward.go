package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MaxPortsPerForward = 1024
	RawUDPChain        = "HP_UDP_RAW"
	NatPreUDPChain     = "HP_UDP_PRE"
	NatPostUDPChain    = "HP_UDP_POST"
	FwdUDPChain        = "HP_UDP_FWD"
)

var portRangeRe = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)

// UDPForwardOptions holds paths and commands for the udp-forward generator.
type UDPForwardOptions struct {
	ConfigPath      string
	IptablesBin     string
	IptablesRestore string
	BanSet          string
	AuthSet         string
	StatePath       string
	FailoverPath    string
	ResolveIPv4     func(host string) (string, error)
}

// UDPForwardOptionsFromEnv reads HP_UDP_* env vars matching haproxy-udp-forward.py.
func UDPForwardOptionsFromEnv() UDPForwardOptions {
	envOr := func(k, fb string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return fb
	}
	return UDPForwardOptions{
		ConfigPath:      envOr("HP_UDP_CONFIG", "/opt/haproxy-admin/config/udp.yml"),
		IptablesBin:     envOr("HP_UDP_IPTABLES", "iptables-legacy"),
		IptablesRestore: envOr("HP_UDP_IPTABLES_RESTORE", "iptables-legacy-restore"),
		BanSet:          envOr("HP_UDP_BAN_SET", "haproxy_ban"),
		AuthSet:         envOr("HP_UDP_AUTH_SET", "haproxy_ip_auth"),
		StatePath:       envOr("HP_UDP_STATE", "/run/easy-ha-proxy/udp-forward-state.json"),
		FailoverPath:    envOr("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"),
	}
}

// UDPBackup describes a validated backup target for one UDP forward.
type UDPBackup struct {
	Host       string `json:"host"`
	IP         string `json:"ip,omitempty"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Port       string `json:"port"`
	Check      string `json:"check"`
	HealthPort int    `json:"health_port,omitempty"`
}

// UDPForward represents one normalized, injection-safe UDP forward entry.
type UDPForward struct {
	Name         string     `json:"name"`
	ListenPort   string     `json:"listen_port"`
	ListenStart  int        `json:"listen_start"`
	ListenEnd    int        `json:"listen_end"`
	BackendIP    string     `json:"backend_ip"`
	BackendPort  string     `json:"backend_port"`
	BackendStart int        `json:"backend_start"`
	BackendEnd   int        `json:"backend_end"`
	BanCheck     bool       `json:"ban_check"`
	ZeroTrust    bool       `json:"zero_trust"`
	Backup       *UDPBackup `json:"backup,omitempty"`
	Active       string     `json:"active"`
	TargetIP     string     `json:"target_ip"`
	TargetStart  int        `json:"target_start"`
	TargetEnd    int        `json:"target_end"`
}

func defaultResolveIPv4(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		return addr.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("cannot resolve backend host %q: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("backend host %q has no IPv4 address", host)
}

func parsePortRange(raw, field string) (int, int, error) {
	text := strings.TrimSpace(raw)
	m := portRangeRe.FindStringSubmatch(text)
	if m == nil {
		return 0, 0, fmt.Errorf("%s must be a port or inclusive range such as 51820-51830", field)
	}
	start, _ := strconv.Atoi(m[1])
	end := start
	if m[2] != "" {
		end, _ = strconv.Atoi(m[2])
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return 0, 0, fmt.Errorf("%s must be within 1-65535, got %q", field, text)
	}
	if end < start {
		return 0, 0, fmt.Errorf("%s range end must not be lower than its start", field)
	}
	if end-start+1 > MaxPortsPerForward {
		return 0, 0, fmt.Errorf("%s range may contain at most %d ports", field, MaxPortsPerForward)
	}
	return start, end, nil
}

func formatPortRange(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func dportArg(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d:%d", start, end)
}

// ParseUDPConfigYAML parses udp.yml (`udp_forwards:` list) without external YAML dependencies.
func ParseUDPConfigYAML(content string) []map[string]string {
	var items []map[string]string
	inList := false
	var cur map[string]string

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inList = trimmed == "udp_forwards:"
			cur = nil
			continue
		}
		if !inList {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			cur = make(map[string]string)
			items = append(items, cur)
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if k, v, ok := strings.Cut(rest, ":"); ok {
				cur[strings.TrimSpace(k)] = unquoteSimple(strings.TrimSpace(v))
			}
			continue
		}
		if cur != nil {
			if k, v, ok := strings.Cut(trimmed, ":"); ok {
				cur[strings.TrimSpace(k)] = unquoteSimple(strings.TrimSpace(v))
			}
		}
	}
	return items
}

func unquoteSimple(s string) string {
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return s[1 : len(s)-1]
	}
	return s
}

func parseBoolDefault(raw string, def bool) bool {
	if raw == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "1", "on":
		return true
	case "false", "no", "0", "off":
		return false
	default:
		return def
	}
}

// LoadUDPForwards reads, normalizes, and applies failover selection to udp.yml entries.
func LoadUDPForwards(opts UDPForwardOptions) ([]UDPForward, error) {
	resolve := opts.ResolveIPv4
	if resolve == nil {
		resolve = defaultResolveIPv4
	}
	raw, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []UDPForward{}, nil
		}
		return nil, err
	}
	rawItems := ParseUDPConfigYAML(string(raw))
	failover := loadUDPFailoverActive(opts.FailoverPath)

	forwards := make([]UDPForward, 0, len(rawItems))
	for _, m := range rawItems {
		if !parseBoolDefault(m["enabled"], true) {
			continue
		}
		lStart, lEnd, err := parsePortRange(m["listen_port"], "listen_port")
		if err != nil {
			return nil, err
		}
		bHost := strings.TrimSpace(m["backend_host"])
		if bHost == "" {
			return nil, fmt.Errorf("forward %q is missing backend_host", m["name"])
		}
		bIP, err := resolve(bHost)
		if err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(bIP); err != nil || !addr.Is4() || addr.IsLoopback() {
			return nil, errors.New("backend_host must not resolve to a loopback address")
		}
		bStart, bEnd, err := parsePortRange(m["backend_port"], "backend_port")
		if err != nil {
			return nil, err
		}
		if lEnd-lStart != bEnd-bStart {
			return nil, errors.New("listen_port and backend_port ranges must contain the same number of ports")
		}

		name := strings.TrimSpace(m["name"])
		if name == "" {
			name = fmt.Sprintf("udp%d", lStart)
		}
		fwd := UDPForward{
			Name:         name,
			ListenPort:   formatPortRange(lStart, lEnd),
			ListenStart:  lStart,
			ListenEnd:    lEnd,
			BackendIP:    bIP,
			BackendPort:  formatPortRange(bStart, bEnd),
			BackendStart: bStart,
			BackendEnd:   bEnd,
			BanCheck:     parseBoolDefault(m["ban_check"], true),
			ZeroTrust:    parseBoolDefault(m["zero_trust"], false),
			Active:       "primary",
			TargetIP:     bIP,
			TargetStart:  bStart,
			TargetEnd:    bEnd,
		}

		if bkHost := strings.TrimSpace(m["backup_host"]); bkHost != "" {
			bkPortStr := strings.TrimSpace(m["backup_port"])
			if bkPortStr == "" {
				bkPortStr = m["backend_port"]
			}
			bkStart, bkEnd, err := parsePortRange(bkPortStr, "backup_port")
			if err != nil {
				return nil, err
			}
			if bkEnd-bkStart != bEnd-bStart {
				return nil, errors.New("backup_port must contain as many ports as backend_port")
			}
			bkIP, _ := resolve(bkHost)
			if bkIP != "" {
				if addr, err := netip.ParseAddr(bkIP); err != nil || !addr.Is4() || addr.IsLoopback() {
					return nil, errors.New("backup_host must not resolve to a loopback address")
				}
				if bkIP == bIP {
					return nil, errors.New("backup_host must be a different address from backend_host")
				}
			}
			chk := strings.ToLower(strings.TrimSpace(m["health_check"]))
			if chk == "" {
				chk = "ping"
			}
			if chk != "ping" && chk != "tcp" {
				return nil, errors.New("health_check must be ping or tcp")
			}
			var hPort int
			if chk == "tcp" {
				p, err := strconv.Atoi(strings.TrimSpace(m["health_port"]))
				if err != nil || p < 1 || p > 65535 {
					return nil, errors.New("health_port must be a TCP port (1-65535) for the tcp check")
				}
				hPort = p
			}
			fwd.Backup = &UDPBackup{
				Host:       bkHost,
				IP:         bkIP,
				Start:      bkStart,
				End:        bkEnd,
				Port:       formatPortRange(bkStart, bkEnd),
				Check:      chk,
				HealthPort: hPort,
			}
			if failover[name] == "backup" && bkIP != "" {
				fwd.Active = "backup"
				fwd.TargetIP = bkIP
				fwd.TargetStart = bkStart
				fwd.TargetEnd = bkEnd
			}
		}
		forwards = append(forwards, fwd)
	}
	return forwards, nil
}

func loadUDPFailoverActive(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var doc struct {
		Version int               `json:"version"`
		Active  map[string]string `json:"active"`
	}
	if json.Unmarshal(raw, &doc) == nil && doc.Version == 1 && doc.Active != nil {
		return doc.Active
	}
	return out
}

// BuildUDPIptablesRestore generates the complete idempotent iptables-legacy-restore script.
func BuildUDPIptablesRestore(forwards []UDPForward, banSet, authSet string) string {
	var rawRules, natPreRules, natPostRules, fwdRules strings.Builder

	for _, f := range forwards {
		ldport := dportArg(f.ListenStart, f.ListenEnd)
		tdport := dportArg(f.TargetStart, f.TargetEnd)
		if f.BanCheck && banSet != "" {
			fmt.Fprintf(&rawRules, "-A %s -p udp --dport %s -m set --match-set %s src -j DROP\n",
				RawUDPChain, ldport, banSet)
		}
		if f.ZeroTrust && authSet != "" {
			fmt.Fprintf(&rawRules, "-A %s -p udp --dport %s -m set ! --match-set %s src -j DROP\n",
				RawUDPChain, ldport, authSet)
		}
		dest := fmt.Sprintf("%s:%s", f.TargetIP, formatPortRange(f.TargetStart, f.TargetEnd))
		fmt.Fprintf(&natPreRules, "-A %s -p udp --dport %s -j DNAT --to-destination %s\n",
			NatPreUDPChain, ldport, dest)
		fmt.Fprintf(&natPostRules, "-A %s -p udp -d %s --dport %s -j MASQUERADE\n",
			NatPostUDPChain, f.TargetIP, tdport)
		fmt.Fprintf(&fwdRules, "-A %s -p udp -d %s --dport %s -j ACCEPT\n",
			FwdUDPChain, f.TargetIP, tdport)
		fmt.Fprintf(&fwdRules, "-A %s -p udp -s %s --sport %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
			FwdUDPChain, f.TargetIP, tdport)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "*raw\n:%s - [0:0]\n-F %s\n%sCOMMIT\n", RawUDPChain, RawUDPChain, rawRules.String())
	fmt.Fprintf(&b, "*nat\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n%s%sCOMMIT\n",
		NatPreUDPChain, NatPostUDPChain, NatPreUDPChain, NatPostUDPChain, natPreRules.String(), natPostRules.String())
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n-F %s\n%sCOMMIT\n", FwdUDPChain, FwdUDPChain, fwdRules.String())
	return b.String()
}

// ApplyUDPForwards installs the iptables chains & rules and writes udp-forward-state.json.
func ApplyUDPForwards(ctx context.Context, opts UDPForwardOptions, dryRun, checkOnly, healthTargets bool) (string, error) {
	forwards, err := LoadUDPForwards(opts)
	if err != nil {
		return "", err
	}
	if healthTargets {
		targets := make([]map[string]any, 0)
		for _, f := range forwards {
			if f.Backup != nil && f.Backup.IP != "" {
				targets = append(targets, map[string]any{
					"name":        f.Name,
					"primary":     f.BackendIP,
					"backup":      f.Backup.IP,
					"check":       f.Backup.Check,
					"health_port": f.Backup.HealthPort,
				})
			}
		}
		raw, _ := json.MarshalIndent(targets, "", "  ")
		return string(raw) + "\n", nil
	}
	script := BuildUDPIptablesRestore(forwards, opts.BanSet, opts.AuthSet)
	if checkOnly {
		return fmt.Sprintf("validated %d UDP forward(s)\n", len(forwards)), nil
	}
	if dryRun {
		return script, nil
	}

	// Ensure ip_forward is enabled when forwards exist.
	if len(forwards) > 0 {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	}

	// Apply rules via iptables-legacy-restore --noflush.
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, opts.IptablesRestore, "--noflush")
	cmd.Stdin = strings.NewReader(script)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("iptables-restore failed: %s", strings.TrimSpace(errBuf.String()))
	}

	// Ensure top-level jumps exist once per built-in chain.
	wiring := [][3]string{
		{"raw", "PREROUTING", RawUDPChain},
		{"nat", "PREROUTING", NatPreUDPChain},
		{"nat", "POSTROUTING", NatPostUDPChain},
		{"filter", "FORWARD", FwdUDPChain},
	}
	for _, w := range wiring {
		chk := exec.CommandContext(cmdCtx, opts.IptablesBin, "-t", w[0], "-C", w[1], "-j", w[2])
		if chk.Run() != nil {
			_ = exec.CommandContext(cmdCtx, opts.IptablesBin, "-t", w[0], "-I", w[1], "1", "-j", w[2]).Run()
		}
	}

	if opts.StatePath != "" {
		state := map[string]any{
			"applied_at": time.Now().UTC().Format(time.RFC3339),
			"count":      len(forwards),
			"forwards":   forwards,
		}
		if raw, err := json.MarshalIndent(state, "", "  "); err == nil {
			_ = os.MkdirAll(filepath.Dir(opts.StatePath), 0o750)
			_ = writeFileAtomic(opts.StatePath, append(raw, '\n'), 0o644)
		}
	}
	return fmt.Sprintf("applied %d UDP forward(s)\n", len(forwards)), nil
}

func writeFileAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	_ = tmp.Chmod(mode)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return err
	}
	return nil
}
