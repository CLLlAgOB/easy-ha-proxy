package controld

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

func (d *Daemon) udpPortsInUse(start, end int) map[int]bool {
	result := map[int]bool{}
	for _, path := range d.Opts.ProcNetUDP {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || !strings.Contains(fields[1], ":") {
				continue
			}
			portHex := fields[1][strings.LastIndex(fields[1], ":")+1:]
			port, err := strconv.ParseInt(portHex, 16, 32)
			if err != nil {
				continue
			}
			if int(port) >= start && int(port) <= end {
				result[int(port)] = true
			}
		}
		_ = f.Close()
	}
	return result
}

func (d *Daemon) readUDPForwardState() (map[string]any, error) {
	fi, err := os.Lstat(d.Opts.UDPForwardState)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, rErr("UDP forwarding has not been applied yet")
		}
		return nil, rErr("UDP forwarding state is unreadable")
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > udpForwardStateMaxBytes {
		return nil, rErr("UDP forwarding state has an unsafe file type or size")
	}
	raw, err := os.ReadFile(d.Opts.UDPForwardState)
	if err != nil {
		return nil, rErr("UDP forwarding state is unreadable")
	}
	v, err := pyx.Decode(raw)
	if err != nil {
		return nil, rErr("UDP forwarding state is unreadable")
	}
	state, ok := v.(map[string]any)
	if !ok || len(state) != 5 {
		return nil, rErr("UDP forwarding state has an invalid format")
	}
	for _, k := range []string{"version", "applied_at", "forwards", "ports", "local_backends"} {
		if _, ok := state[k]; !ok {
			return nil, rErr("UDP forwarding state has an invalid format")
		}
	}
	if n, ok := pyx.Int(state["version"]); !ok || n != 1 {
		return nil, rErr("UDP forwarding state version is unsupported")
	}
	if s, ok := state["applied_at"].(string); !ok || len([]rune(s)) < 1 || len([]rune(s)) > 128 {
		return nil, rErr("UDP forwarding state timestamp is invalid")
	}
	for _, f := range []string{"forwards", "ports", "local_backends"} {
		n, ok := pyx.Int(state[f])
		if _, isNum := state[f].(json.Number); !ok || !isNum || n < 0 {
			return nil, rErr("UDP forwarding state field %s is invalid", f)
		}
	}
	return state, nil
}

// ---------------------------------------------------------------------------
// UDP failover (UdpFailover)
// ---------------------------------------------------------------------------

type failoverEntry struct {
	Active              string
	Since               float64
	Fails, Oks          int
	PrimaryOK, BackupOK *bool
	CheckedAt           *float64
	Primary, Backup     any
}

type pendingSwitch struct {
	side   string
	target map[string]any
}

type udpFailover struct {
	d                *Daemon
	mu               sync.Mutex
	targets          []map[string]any
	configKey        string
	state            map[string]*failoverEntry
	order            []string
	errText          string
	reported         map[string]float64
	conntrackMissing bool
	pending          map[string]pendingSwitch
	applyError       string
	retryAt          float64
	initialized      bool
	reconcilePending bool
	probe            func(ip any, check string, port any) bool
}

func newUDPFailover(d *Daemon) *udpFailover {
	f := &udpFailover{d: d, state: map[string]*failoverEntry{}, reported: map[string]float64{}, pending: map[string]pendingSwitch{}}
	f.probe = f.defaultProbe
	return f
}

func (f *udpFailover) startupState() (map[string]string, bool) {
	raw, err := os.ReadFile(f.d.Opts.UDPFailoverState)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, false
		}
		log.Printf("UDP failover state could not be recovered; reconciling the current configuration: %v", err)
		return map[string]string{}, true
	}
	bad := func(msg string) (map[string]string, bool) {
		log.Printf("UDP failover state could not be recovered; reconciling the current configuration: %s", msg)
		return map[string]string{}, true
	}
	if len(raw) > udpFailoverStateMaxBytes {
		return bad("state exceeds the size limit")
	}
	v, err := pyx.Decode(raw)
	data, _ := v.(map[string]any)
	if err != nil || data == nil {
		return bad("invalid state schema")
	}
	active, ok := data["active"].(map[string]any)
	if n, okV := pyx.Int(data["version"]); !okV || n != 1 || !ok {
		return bad("invalid state schema")
	}
	out := map[string]string{}
	for name, side := range active {
		s, _ := side.(string)
		if s != "primary" && s != "backup" {
			return bad("invalid saved backend side")
		}
		if s == "backup" {
			out[name] = s
		}
	}
	return out, true
}

// healthTargetsCommand asks the UDP generator, the agent's own udp-forward,
// which forwards have a backup.
func (f *udpFailover) healthTargetsCommand() []string {
	exe, err := os.Executable()
	if err != nil {
		exe = "/usr/local/sbin/easy-ha-proxy-agent"
	}
	return []string{exe, "udp-forward", "--config", f.d.Opts.UDPConfig, "--health-targets"}
}

func (f *udpFailover) loadTargets() []map[string]any {
	fi, err := os.Stat(f.d.Opts.UDPConfig)
	if err != nil {
		f.targets, f.configKey = nil, ""
		return f.targets
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	key := fmt.Sprintf("%d:%d:%d", ino, fi.ModTime().UnixNano(), fi.Size())
	if key == f.configKey {
		return f.targets
	}
	res, err := runCmd(f.healthTargetsCommand(), nil, 30*time.Second)
	var targets []map[string]any
	if err == nil {
		out := strings.TrimSpace(res.stdout)
		last := "[]"
		if out != "" {
			lines := strings.Split(out, "\n")
			last = lines[len(lines)-1]
		}
		var raw []any
		if jerr := json.Unmarshal([]byte(last), &raw); jerr != nil {
			err = fmt.Errorf("%s", pyJSONError(jerr))
		} else {
			for _, t := range raw {
				if m, ok := t.(map[string]any); ok {
					targets = append(targets, m)
				}
			}
		}
	}
	if err != nil {
		f.errText = "udp.yml could not be read for failover: " + pyx.TruncRunes(pyErr(err), 300)
		log.Printf("%s", f.errText)
		return f.targets
	}
	f.targets, f.configKey, f.errText = targets, key, ""
	return f.targets
}

func (f *udpFailover) defaultProbe(ip any, check string, port any) bool {
	host, _ := ip.(string)
	if host == "" {
		return false
	}
	if check == "tcp" {
		p, _ := pyx.Int(port)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.FormatInt(p, 10)), 2*time.Second)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	_, err := runCmd([]string{"ping", "-n", "-q", "-c", "1", "-W", "1", host}, nil, 4*time.Second)
	return err == nil
}

func boolPtr(b bool) *bool        { return &b }
func floatPtr(v float64) *float64 { return &v }

type switchRec struct {
	name, old, new string
	target         map[string]any
}

func (f *udpFailover) tick(now float64) []switchRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	targets := f.loadTargets()
	startupActive := map[string]string{}
	startupSync := false
	if !f.initialized {
		if f.errText != "" {
			return nil
		}
		startupActive, startupSync = f.startupState()
		f.reconcilePending = startupSync
		f.initialized = true
	}
	switches := []switchRec{}
	names := map[string]bool{}
	for _, target := range targets {
		name := pyx.StrOr(target["name"])
		if name == "" {
			continue
		}
		names[name] = true
		entry, ok := f.state[name]
		if !ok {
			active := startupActive[name]
			if active == "" {
				active = "primary"
			}
			entry = &failoverEntry{Active: active, Since: now}
			f.state[name] = entry
			f.order = append(f.order, name)
		}
		if f.reconcilePending {
			f.pending[name] = pendingSwitch{entry.Active, target}
		}
		check := pyx.StrOr(pyx.Get(target, "check", "ping"))
		primaryOK := f.probe(target["primary"], check, target["health_port"])
		backupOK := f.probe(target["backup"], check, target["health_port"])
		entry.PrimaryOK, entry.BackupOK, entry.CheckedAt = boolPtr(primaryOK), boolPtr(backupOK), floatPtr(now)
		entry.Primary, entry.Backup = target["primary"], target["backup"]
		if entry.Active == "primary" {
			if primaryOK {
				entry.Fails = 0
			} else {
				entry.Fails++
			}
			if entry.Fails >= udpFailAfter && backupOK {
				switches = append(switches, switchRec{name, "primary", "backup", target})
			}
		} else {
			if primaryOK {
				entry.Oks++
			} else {
				entry.Oks = 0
			}
			if entry.Oks >= udpRecoverAfter || (primaryOK && !backupOK) {
				switches = append(switches, switchRec{name, "backup", "primary", target})
			}
		}
	}
	for _, gone := range append([]string{}, f.order...) {
		if !names[gone] {
			delete(f.state, gone)
			delete(f.pending, gone)
			f.removeOrder(gone)
			f.report(gone, false, "", now, true)
		}
	}
	if len(switches) > 0 || startupSync || f.fileOutOfStep() {
		for _, s := range switches {
			e := f.state[s.name]
			e.Active, e.Since, e.Fails, e.Oks = s.new, now, 0, 0
			f.pending[s.name] = pendingSwitch{s.new, s.target}
		}
		f.writeState()
	}
	if (len(f.pending) > 0 || f.reconcilePending) && (len(switches) > 0 || now >= f.retryAt) {
		f.apply(now)
	}
	for _, name := range f.order {
		entry := f.state[name]
		forced := false
		for _, s := range switches {
			if s.name == name {
				forced = true
			}
		}
		f.report(name, entry.Active == "backup", f.detail(name, entry), now, forced)
	}
	return switches
}

func (f *udpFailover) removeOrder(name string) {
	out := f.order[:0]
	for _, n := range f.order {
		if n != name {
			out = append(out, n)
		}
	}
	f.order = out
}

func (f *udpFailover) wanted() map[string]any {
	w := map[string]any{}
	for name, e := range f.state {
		if e.Active == "backup" {
			w[name] = "backup"
		}
	}
	return w
}

func (f *udpFailover) fileOutOfStep() bool {
	raw, err := os.ReadFile(f.d.Opts.UDPFailoverState)
	var current map[string]any
	if err == nil {
		var data map[string]any
		if json.Unmarshal(raw, &data) == nil {
			current, _ = data["active"].(map[string]any)
		}
	}
	if current == nil {
		current = map[string]any{}
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(f.wanted())
	return string(a) != string(b)
}

func (f *udpFailover) writeState() {
	payload := map[string]any{"version": 1, "active": f.wanted()}
	dir := filepath.Dir(f.d.Opts.UDPFailoverState)
	_ = os.MkdirAll(dir, 0o755)
	tmp, err := os.CreateTemp(dir, ".udp-failover.")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	raw, _ := json.Marshal(payload)
	text := strings.ReplaceAll(strings.ReplaceAll(string(raw), `":`, `": `), `,"`, `, "`)
	_, _ = tmp.WriteString(text + "\n")
	_ = tmp.Sync()
	_ = tmp.Close()
	_ = os.Chmod(name, 0o644)
	_ = os.Rename(name, f.d.Opts.UDPFailoverState)
}

func (f *udpFailover) apply(now float64) {
	names := make([]string, 0, len(f.pending))
	for n := range f.pending {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		log.Printf("UDP forward %s: sending to its %s backend", n, f.pending[n].side)
	}
	if _, err := runCmd([]string{"systemctl", "restart", "iptables-haproxy-udp.service"}, nil, 60*time.Second); err != nil {
		log.Printf("UDP failover could not apply the rules: %v", err)
		f.applyError = "the switch could not be applied: " + pyx.TruncRunes(pyErr(err), 300)
		f.retryAt = now + udpApplyRetrySeconds
		return
	}
	done := f.pending
	f.pending, f.applyError, f.reconcilePending = map[string]pendingSwitch{}, "", false
	for _, p := range done {
		leftKey := "primary"
		if p.side == "primary" {
			leftKey = "backup"
		}
		left := p.target[leftKey]
		if !pyx.Truthy(left) {
			continue
		}
		if _, err := runCmd([]string{"conntrack", "-D", "-p", "udp", "--reply-src", pyx.Str(left)}, nil, 10*time.Second); err != nil {
			if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.ENOENT {
				if !f.conntrackMissing {
					log.Printf("conntrack is not installed: existing UDP flows move after their timeout")
				}
				f.conntrackMissing = true
			}
		}
	}
}

func (f *udpFailover) detail(name string, e *failoverEntry) string {
	if e.Active == "backup" {
		return fmt.Sprintf("The main backend %s of UDP forward %s stopped answering; traffic goes to the backup %s until the main one answers again.",
			pyx.Str(e.Primary), name, pyx.Str(e.Backup))
	}
	return ""
}

func (f *udpFailover) report(name string, active bool, detail string, now float64, force bool) {
	if f.d.alerts == nil || !f.d.alerts.Enabled() {
		return
	}
	if !force && now-f.reported[name] < udpFailoverReportSeconds {
		return
	}
	f.reported[name] = now
	f.d.observe(alerts.Observation{Rule: udpFailoverRule, Subject: name, Active: alerts.BoolPtr(active),
		Summary: fmt.Sprintf("UDP forward %s runs on its backup backend", name), Detail: detail})
}

func optBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func optFloat(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

func (f *udpFailover) publicState() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	forwards := map[string]any{}
	for name, e := range f.state {
		_, pending := f.pending[name]
		forwards[name] = map[string]any{"active": e.Active, "since": e.Since, "primary_ok": optBool(e.PrimaryOK),
			"backup_ok": optBool(e.BackupOK), "checked_at": optFloat(e.CheckedAt), "primary": e.Primary, "backup": e.Backup,
			"apply_pending": pending}
	}
	var errText any
	if f.errText != "" {
		errText = f.errText
	} else if f.applyError != "" {
		errText = f.applyError
	}
	return map[string]any{"error": errText, "forwards": forwards}
}

func (d *Daemon) udpFailoverLoop() {
	log.Printf("UDP failover loop started: interval=%ds", d.Opts.UDPHealthInterval)
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("UDP failover check failed: %v", r)
				}
			}()
			d.failover.tick(nowEpoch())
		}()
		time.Sleep(time.Duration(d.Opts.UDPHealthInterval) * time.Second)
	}
}
