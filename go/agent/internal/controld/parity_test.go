package controld

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/haproxy"
)

type fakeIpset struct {
	mu       sync.Mutex
	sets     map[string]map[string]struct{}
	timeouts map[string]bool
	scripts  []string
}

func newFakeIpset() *fakeIpset {
	return &fakeIpset{
		sets:     map[string]map[string]struct{}{},
		timeouts: map[string]bool{},
	}
}

func (f *fakeIpset) List(_ context.Context, name string) (map[string]struct{}, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.sets[name]
	if !ok {
		return nil, false, os.ErrNotExist
	}
	cp := make(map[string]struct{}, len(m))
	for k := range m {
		cp[k] = struct{}{}
	}
	return cp, f.timeouts[name], nil
}

func (f *fakeIpset) Create(_ context.Context, name string, withTimeout bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sets[name]; !ok {
		f.sets[name] = map[string]struct{}{}
	}
	f.timeouts[name] = withTimeout
	return nil
}

func (f *fakeIpset) Restore(_ context.Context, script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, script)
	for _, line := range strings.Split(script, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		op, setName, ip := parts[0], parts[1], parts[2]
		if _, ok := f.sets[setName]; !ok {
			f.sets[setName] = map[string]struct{}{}
		}
		if op == "add" {
			f.sets[setName][ip] = struct{}{}
		} else if op == "del" {
			delete(f.sets[setName], ip)
		}
	}
	return nil
}

func (f *fakeIpset) SwapAndDestroy(_ context.Context, liveName, tempName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets[liveName] = f.sets[tempName]
	f.timeouts[liveName] = f.timeouts[tempName]
	delete(f.sets, tempName)
	delete(f.timeouts, tempName)
	return nil
}

func TestIpsetSyncFirstStepOrderingRestartGraceAndAuthTimeout(t *testing.T) {
	dir := t.TempDir()
	haSock := filepath.Join(dir, "haproxy-admin.sock")
	ln, err := net.Listen("unix", haSock)
	if err != nil {
		t.Fatalf("listen haproxy sock: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	uptimeSec := "10" // inside 60s restart grace window
	banTableReply := "# table: tbl_ban, type: ip, size:1024, used:2\n" +
		"0x1: key=198.51.100.10 use=0 exp=600000 gpt0=41 gpc0=1\n" +
		"0x2: key=198.51.100.20 use=0 exp=600000 gpt0=20 gpc0=1\n"
	authTableReply := "# table: tbl_ip_auth, type: ip, size:1024, used:1\n" +
		"0x3: key=203.0.113.5 use=0 exp=450000 gpc0=1\n"

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				cmd := strings.TrimSpace(line)
				mu.Lock()
				up, ban, auth := uptimeSec, banTableReply, authTableReply
				mu.Unlock()
				switch cmd {
				case "show info":
					_, _ = c.Write([]byte("Uptime_sec: " + up + "\n"))
				case "show table tbl_ban":
					_, _ = c.Write([]byte(ban))
				case "show table tbl_ip_auth":
					_, _ = c.Write([]byte(auth))
				}
			}(conn)
		}
	}()

	fake := newFakeIpset()
	// Pre-populate stale firewall ban that must be PRESERVED during HAProxy restart grace.
	_ = fake.Create(context.Background(), "haproxy_ban", false)
	_ = fake.Create(context.Background(), "haproxy_ban_page", false)
	_ = fake.Restore(context.Background(), "add haproxy_ban 198.51.100.99\n")
	// Legacy auth set without timeout must be swapped cleanly.
	_ = fake.Create(context.Background(), "haproxy_ip_auth", false)

	opts := OptionsFromEnv()
	opts.HAProxyAdminSocket = haSock
	opts.BanRestartGraceSec = 60
	opts.AuthIpsetTTLSec = 900

	ctrl := NewController(opts)
	ctrl.Ipset = fake
	ctrl.HAProxy = haproxy.NewClient(haSock)

	if err := ctrl.EnsureIpsets(context.Background()); err != nil {
		t.Fatalf("EnsureIpsets: %v", err)
	}
	if !fake.timeouts["haproxy_ip_auth"] {
		t.Fatal("expected legacy haproxy_ip_auth to be upgraded to timeout-enabled via swap")
	}

	// Pass 1 (uptime=10s < 60s grace): adds .10 (first-step page BEFORE ban) & .20, keeps .99!
	fake.scripts = nil
	if err := ctrl.SyncBansOnce(context.Background()); err != nil {
		t.Fatalf("SyncBansOnce pass1: %v", err)
	}
	if len(fake.scripts) < 2 || !strings.Contains(fake.scripts[0], "add haproxy_ban_page 198.51.100.10") {
		t.Fatalf("expected page_ipset add BEFORE ban_ipset, got scripts: %+v", fake.scripts)
	}
	if _, kept := fake.sets["haproxy_ban"]["198.51.100.99"]; !kept {
		t.Fatal("expected existing ban 198.51.100.99 preserved during restart grace window")
	}

	// Pass 2 (uptime=120s > grace): stale .99 is removed!
	mu.Lock()
	uptimeSec = "120"
	mu.Unlock()
	if err := ctrl.SyncBansOnce(context.Background()); err != nil {
		t.Fatalf("SyncBansOnce pass2: %v", err)
	}
	if _, kept := fake.sets["haproxy_ban"]["198.51.100.99"]; kept {
		t.Fatal("expected stale ban 198.51.100.99 removed after grace window")
	}

	// Auth sync adds 203.0.113.5 with timeout 450 (450000ms / 1000).
	fake.scripts = nil
	if err := ctrl.SyncAuthOnce(context.Background()); err != nil {
		t.Fatalf("SyncAuthOnce: %v", err)
	}
	if len(fake.scripts) == 0 || !strings.Contains(fake.scripts[0], "add haproxy_ip_auth 203.0.113.5 timeout 450") {
		t.Fatalf("expected auth ipset timeout 450, got: %+v", fake.scripts)
	}
}

func TestConfigTransactionLifecycleConfirmAndRollback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "haproxy.cfg")
	fakeHaproxy := filepath.Join(dir, "fake-haproxy.sh")
	fakeSystemctl := filepath.Join(dir, "fake-systemctl.sh")
	_ = os.WriteFile(fakeHaproxy, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(fakeSystemctl, []byte("#!/bin/sh\necho reloaded\nexit 0\n"), 0o755)
	_ = os.WriteFile(cfgPath, []byte(validHAProxyCfg), 0o644)

	opts := OptionsFromEnv()
	opts.HAProxyBin = fakeHaproxy
	opts.HAProxyCfgPath = cfgPath
	opts.SystemctlBin = fakeSystemctl
	opts.ConfigTransactionDir = filepath.Join(dir, "tx")
	opts.ConfigHistoryDir = filepath.Join(dir, "history")
	opts.ConfigSourceDir = filepath.Join(dir, "config")
	opts.ServerStatePath = ""

	ctrl := NewController(opts)
	ctrl.CheckRunner = func(_ context.Context, _ []ControlPlaneCheck) (bool, []CheckResult) {
		return true, []CheckResult{{Name: "admin", OK: true, Status: 200}}
	}

	candidateCfg := validHAProxyCfg + "\n# candidate v2\n"
	candB64 := base64.StdEncoding.EncodeToString([]byte(candidateCfg))
	checksB64 := base64.StdEncoding.EncodeToString([]byte(`[{"name":"admin","kind":"tcp","port":80}]`))

	// 1. Begin transaction -> pending_confirmation, then rollback -> restores original config.
	res, err := ctrl.BeginConfigTransaction(context.Background(), candB64, checksB64, "", "60")
	if err != nil || res["state"] != "pending_confirmation" || res["pending"] != true {
		t.Fatalf("begin tx: %+v err=%v", res, err)
	}
	txID := res["transaction_id"].(string)
	rb, err := ctrl.RollbackConfigTransaction(context.Background(), txID)
	if err != nil || rb["state"] != "rolled_back" {
		t.Fatalf("rollback tx: %+v err=%v", rb, err)
	}
	restored, _ := os.ReadFile(cfgPath)
	if string(restored) != validHAProxyCfg {
		t.Fatalf("expected original config restored after rollback")
	}

	// 2. Begin again and confirm -> records history version.
	res2, err := ctrl.BeginConfigTransaction(context.Background(), candB64, checksB64, "", "60")
	if err != nil || res2["state"] != "pending_confirmation" {
		t.Fatalf("begin tx 2: %+v err=%v", res2, err)
	}
	conf, err := ctrl.ConfirmConfigTransaction(context.Background(), res2["transaction_id"].(string), res2["candidate_sha256"].(string))
	if err != nil || conf["state"] != "confirmed" {
		t.Fatalf("confirm tx: %+v err=%v", conf, err)
	}
	versions, err := ctrl.ListConfigVersions(10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("expected 1 confirmed config history version, got %+v err=%v", versions, err)
	}

	// 3. Guarded apply rolls back automatically when control-plane checks fail.
	ctrl.CheckRunner = func(_ context.Context, _ []ControlPlaneCheck) (bool, []CheckResult) {
		return false, []CheckResult{{Name: "admin", OK: false, Error: "connection refused"}}
	}
	badCandB64 := base64.StdEncoding.EncodeToString([]byte(validHAProxyCfg + "\n# broken v3\n"))
	ga := ctrl.ApplyConfigGuarded(context.Background(), badCandB64, checksB64)
	if ga["ok"] != false || ga["rolled_back"] != true || ga["rollback_ok"] != true {
		t.Fatalf("expected automatic rollback on check failure, got %+v", ga)
	}
	afterGA, _ := os.ReadFile(cfgPath)
	if string(afterGA) != candidateCfg {
		t.Fatalf("expected v2 config preserved after guarded apply rollback")
	}
}

func TestUDPFailoverHysteresis(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "udp-failover.json")
	applyCount := 0
	healthy := false

	mgr := NewUDPFailoverManager(stateFile, func(context.Context) error {
		applyCount++
		return nil
	}, nil)
	mgr.probeFn = func(context.Context, string, string) bool { return healthy }
	targets := []UDPForwardTarget{{Name: "wg0", Primary: "10.0.0.1:51820", Backup: "10.0.0.2:51820", ProbeProto: "tcp"}}

	// 2 failures -> stays on primary; 3rd failure -> switches to backup.
	for i := 0; i < UDPFailAfter-1; i++ {
		if mgr.Step(context.Background(), targets, 100+int64(i)) {
			t.Fatalf("switched too early on miss %d", i+1)
		}
	}
	if !mgr.Step(context.Background(), targets, 105) || applyCount != 1 {
		t.Fatalf("expected failover on 3rd miss, applyCount=%d", applyCount)
	}

	// Requires UDPRecoverAfter (6) consecutive successes to return to primary.
	healthy = true
	for i := 0; i < UDPRecoverAfter-1; i++ {
		if mgr.Step(context.Background(), targets, 200+int64(i)) {
			t.Fatalf("recovered too early on pass %d", i+1)
		}
	}
	if !mgr.Step(context.Background(), targets, 210) || applyCount != 2 {
		t.Fatalf("expected recovery on 6th success, applyCount=%d", applyCount)
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("state file missing: %v", err)
	}
	var parsed map[string]any
	if json.Unmarshal(raw, &parsed) != nil || parsed["wg0"] == nil {
		t.Fatalf("unexpected persisted failover state: %s", string(raw))
	}
}
