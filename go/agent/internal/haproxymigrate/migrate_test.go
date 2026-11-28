package haproxymigrate

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const testConfig = `global
    localpeer ha-local
peers bancluster
    peer ha-local 127.0.0.1:10240
backend tbl_ban
    stick-table type ip size 200k expire 168h store gpc0,gpt0 peers bancluster
backend tbl_ip_auth
    stick-table type ip size 200k expire 9h store gpc0 peers bancluster
`

type fakeHost struct {
	cmdFn     func(args []string, opts CmdOpts) (CmdResult, error)
	activeFn  func(unit string) bool
	serviceFn func(action, unit string) error
	pkgsFn    func() (map[string]string, error)
	machineID string
	workerDig string
	mainPID   int
	cancelled bool
	cmdCalls  [][]string
	svcCalls  [][2]string
	guardDB   string
	ctrlJour  string
}

func (f *fakeHost) SetLog(string) {}
func (f *fakeHost) Command(args []string, opts CmdOpts) (CmdResult, error) {
	f.cmdCalls = append(f.cmdCalls, args)
	if f.cmdFn != nil {
		return f.cmdFn(args, opts)
	}
	return CmdResult{}, nil
}
func (f *fakeHost) Active(unit string) bool {
	if f.activeFn != nil {
		return f.activeFn(unit)
	}
	return false
}
func (f *fakeHost) Service(action, unit string) error {
	f.svcCalls = append(f.svcCalls, [2]string{action, unit})
	if f.serviceFn != nil {
		return f.serviceFn(action, unit)
	}
	return nil
}
func (f *fakeHost) MainPID() (int, error) { return f.mainPID, nil }
func (f *fakeHost) Packages() (map[string]string, error) {
	if f.pkgsFn != nil {
		return f.pkgsFn()
	}
	return map[string]string{}, nil
}
func (f *fakeHost) Machine() (string, error) {
	if f.machineID != "" {
		return f.machineID, nil
	}
	return strings.Repeat("m", 64), nil
}
func (f *fakeHost) WorkerDigest(string) (string, error) { return f.workerDig, nil }
func (f *fakeHost) StartSeed(string, string) error      { return nil }
func (f *fakeHost) Watchdog(string, string) error       { return nil }
func (f *fakeHost) CancelWatchdog(string)               { f.cancelled = true }
func (f *fakeHost) ControlJournal(def string) (string, error) {
	if f.ctrlJour != "" {
		return f.ctrlJour, nil
	}
	return def, nil
}
func (f *fakeHost) GuardDatabase() (string, error) { return f.guardDB, nil }

func saveMigGlobals(t *testing.T) {
	t.Helper()
	oLines := linesFromSocketFunc
	oRun := runtimeCmdFunc
	oInfo := runtimeInfoFunc
	oRows := tableRowsFunc
	oProbe := localProbeFunc
	oRefresh := refreshAptFunc
	oRoot := requireRootOwner
	oNow := nowFunc
	oSleep := sleepFunc
	oBin := engineBinaryFunc
	oDropins := serviceDropinDirs
	oEUID := cliGetEUID
	oNew := cliNewEngine
	oUmask := cliUmask
	t.Cleanup(func() {
		linesFromSocketFunc = oLines
		runtimeCmdFunc = oRun
		runtimeInfoFunc = oInfo
		tableRowsFunc = oRows
		localProbeFunc = oProbe
		refreshAptFunc = oRefresh
		requireRootOwner = oRoot
		nowFunc = oNow
		sleepFunc = oSleep
		engineBinaryFunc = oBin
		serviceDropinDirs = oDropins
		cliGetEUID = oEUID
		cliNewEngine = oNew
		cliUmask = oUmask
	})
}

func TestHealthAcceptsRedirectForSameHostOnly(t *testing.T) {
	saveMigGlobals(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "haproxy.cfg")
	p := DefaultPaths()
	p.Config = cfg
	e := NewEngine(&p, &fakeHost{})

	https := "frontend fe_https\n    acl host_admin hdr(host) -i admin.example.test\n"
	httpLine := "frontend fe_http80\n    acl host_admin hdr(host) -i "
	_ = os.WriteFile(cfg, []byte(https+httpLine+"ADMIN.example.test\n"), 0o600)

	var probes [][2]string
	codes := []int{200, 302}
	localProbeFunc = func(domain, path string) (int, error) {
		probes = append(probes, [2]string{domain, path})
		c := codes[0]
		codes = codes[1:]
		return c, nil
	}
	runtimeCmdFunc = func(string, string) (string, error) {
		return "# pxname,svname\nbe_admin,BACKEND\n", nil
	}
	if err := e.Health(); err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"admin.example.test", "/api/control-plane-health"}, {"admin.example.test", "/"}}
	if !reflect.DeepEqual(probes, want) {
		t.Fatalf("probes=%v want=%v", probes, want)
	}

	for _, bad := range []string{"frontend fe_https\n", https + httpLine + "another.example.test\n"} {
		_ = os.WriteFile(cfg, []byte(bad), 0o600)
		called := false
		localProbeFunc = func(string, string) (int, error) { called = true; return 200, nil }
		if err := e.Health(); err == nil || !strings.Contains(err.Error(), "No unique administration hostname") || called {
			t.Fatalf("bad=%q: err=%v called=%v", bad, err, called)
		}
	}
}

func TestInternalCAPathDefaultAndEnv(t *testing.T) {
	orig, had := os.LookupEnv("HAPROXY_CA_ROOT_DIR")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HAPROXY_CA_ROOT_DIR", orig)
		} else {
			_ = os.Unsetenv("HAPROXY_CA_ROOT_DIR")
		}
	})
	_ = os.Unsetenv("HAPROXY_CA_ROOT_DIR")
	if got := InternalCAPath(); got != "/etc/haproxy/certificate-authorities/internal/ca.crt" {
		t.Fatalf("default CA path = %q", got)
	}
	_ = os.Setenv("HAPROXY_CA_ROOT_DIR", "/custom/ca")
	if got := InternalCAPath(); got != "/custom/ca/internal/ca.crt" {
		t.Fatalf("env CA path = %q", got)
	}
}

func TestMigrateHoldsLockAndRefusesFailedMetadataRefresh(t *testing.T) {
	saveMigGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "maintenance.lock")
	p := DefaultPaths()
	p.Lock = lockPath
	e := NewEngine(&p, &fakeHost{})

	refreshAptFunc = func() (map[string]any, error) {
		// Verify lock is currently held by attempting non-blocking flock from another fd.
		fd, err := unix.Open(lockPath, unix.O_RDWR, 0)
		if err != nil {
			t.Fatalf("open lock: %v", err)
		}
		defer unix.Close(fd)
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			t.Fatal("expected lock to be held during metadata refresh")
		}
		return map[string]any{"fresh": false}, nil
	}
	if _, err := e.Migrate(false); err == nil || !strings.Contains(err.Error(), "metadata refresh failed") {
		t.Fatalf("expected metadata refresh failed error, got %v", err)
	}
}

func TestQualifiedServiceDropin(t *testing.T) {
	cfg := "/etc/haproxy/haproxy.cfg"
	cmd := "/usr/sbin/haproxy -Ws -S /run/haproxy/master.sock,mode,660,user,root,group,haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid"
	text := "[Service]\nExecStart=\nExecStart=" + cmd + "\n"
	if !QualifiedServiceDropin(text, cfg) {
		t.Fatal("valid master-socket dropin rejected")
	}
	if !QualifiedServiceDropin(strings.ReplaceAll(text, " -S ", " \\\n    -S "), cfg) {
		t.Fatal("continued master-socket dropin rejected")
	}
	badCases := []string{
		strings.ReplaceAll(text, "660", "666"),
		strings.ReplaceAll(text, "-Ws", "-W"),
		strings.ReplaceAll(text, "/usr/sbin/haproxy", "/bin/sh"),
		strings.ReplaceAll(text, "/etc/haproxy/haproxy.cfg", "$CONFIG"),
		text + "ExecStartPre=/bin/true\n",
		text + "User=another-user\n",
		strings.ReplaceAll(text, "[Service]", "[Unit]"),
		strings.ReplaceAll(text, "ExecStart=\n", ""),
	}
	for _, bad := range badCases {
		if QualifiedServiceDropin(bad, cfg) {
			t.Errorf("invalid dropin accepted:\n%s", bad)
		}
	}

	dump := "[Service]\nExecStartPre=-/usr/local/sbin/haproxy-state-dump\n"
	if !QualifiedServiceDropin(dump, cfg) {
		t.Fatal("valid state-dump dropin rejected")
	}
	for _, bad := range []string{
		strings.ReplaceAll(dump, "haproxy-state-dump", "another-script"),
		dump + "User=other\n",
		strings.ReplaceAll(dump, "[Service]", "[Unit]"),
		strings.ReplaceAll(dump, "dump\n", "dump --other\n"),
	} {
		if QualifiedServiceDropin(bad, cfg) {
			t.Errorf("invalid dump dropin accepted:\n%s", bad)
		}
	}
}

func TestServiceOverrideDriftRefused(t *testing.T) {
	saveMigGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	serviceDropinDirs = []string{dir}
	dropin := filepath.Join(dir, "server-state.conf")
	_ = os.WriteFile(dropin, []byte("[Service]\nExecStartPre=-/usr/local/sbin/haproxy-state-dump\n"), 0o644)
	e := NewEngine(nil, &fakeHost{})
	e.State = map[string]any{"service_dropins": map[string]any{dropin: "original-hash"}}
	if err := e.unchangedServiceDropins(); err == nil || !strings.Contains(err.Error(), "changed after preparation") {
		t.Fatalf("expected override drift error, got %v", err)
	}
}

func TestStoreServersNormalizesLegacySnapshot(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "haproxy.cfg")
	st := filepath.Join(dir, "server-state")
	_ = os.WriteFile(cfg, []byte("backend target\n server main new.example.test:1026 check\n"), 0o644)
	p := DefaultPaths()
	p.Config = cfg
	p.ServerState = st
	e := NewEngine(&p, &fakeHost{})
	header := "be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port"
	row := "36 target 1 main 127.0.0.1 2 8 17 100 10 15 3 4 6 0 0 0 old.example.test 1025 - 0 0 - - 0"
	e.State = map[string]any{
		"files":        map[string]any{st: map[string]any{}},
		"server_state": "1\n# " + header + "\n" + row + "\n",
	}
	if err := e.storeServers(); err != nil {
		t.Fatal(err)
	}
	outRaw, err := os.ReadFile(st)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(outRaw)), "\n")
	fields := strings.Fields(lines[1][2:])
	vals := strings.Fields(lines[2])
	m := map[string]string{}
	for i, f := range fields {
		m[f] = vals[i]
	}
	if m["srv_addr"] != "-" || m["srv_fqdn"] != "new.example.test" || m["srv_port"] != "1026" || m["srv_admin_state"] != "8" || m["srv_uweight"] != "17" {
		t.Fatalf("unexpected normalized row: %v", m)
	}
}

func TestSavedRecoveryCommandAndArtifactIntegrity(t *testing.T) {
	saveMigGlobals(t)
	dir := t.TempDir()
	fakeExe := filepath.Join(dir, "agent-bin")
	_ = os.WriteFile(fakeExe, []byte("binary-v1"), 0o755)
	engineBinaryFunc = func() (string, error) { return fakeExe, nil }
	dig, _ := fileDigest(fakeExe)

	txDir := filepath.Join(dir, "tx")
	_ = os.MkdirAll(txDir, 0o700)
	oldDeb := filepath.Join(txDir, "haproxy-old.deb")
	baseBin := filepath.Join(txDir, "baseline-haproxy")
	_ = os.WriteFile(oldDeb, []byte("old-deb"), 0o600)
	_ = os.WriteFile(baseBin, []byte("base-bin"), 0o700)
	oldDebDig, _ := fileDigest(oldDeb)
	baseBinDig, _ := fileDigest(baseBin)

	e := NewEngine(nil, &fakeHost{})
	e.Directory = txDir
	e.State = map[string]any{
		"engine_digest":     dig,
		"created_at":        unixNowFloat(),
		"phase":             "prepared",
		"old_digest":        oldDebDig,
		"old_binary_digest": baseBinDig,
		"target_packages":   []any{},
		"extra_packages":    []any{},
	}
	if err := e.storeRecoveryCommands(); err != nil {
		t.Fatal(err)
	}
	if err := e.checkArtifacts(); err != nil {
		t.Fatalf("expected valid artifacts: %v", err)
	}
	// Tampering saved recovery binary fails check
	_ = os.WriteFile(filepath.Join(txDir, "recover-agent"), []byte("tampered"), 0o700)
	if err := e.checkArtifacts(); err == nil || !strings.Contains(err.Error(), "recovery command integrity") {
		t.Fatalf("expected recovery integrity failure, got %v", err)
	}
	// Changed current binary fails check
	_ = os.WriteFile(fakeExe, []byte("binary-v2"), 0o755)
	if err := e.checkArtifacts(); err == nil || !strings.Contains(err.Error(), "implementation changed") {
		t.Fatalf("expected implementation changed failure, got %v", err)
	}
}

func TestWebSummaryDurableWithoutPrivateConfig(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPaths()
	p.Root = dir
	e := NewEngine(&p, &fakeHost{})
	e.Directory = filepath.Join(dir, strings.Repeat("a", 32))
	_ = os.MkdirAll(e.Directory, 0o700)
	e.State = map[string]any{
		"id":                     strings.Repeat("a", 32),
		"kind":                   "migration",
		"created_at":             unixNowFloat(),
		"old_version":            "2.8.30-1",
		"target_runtime_version": "3.4.7",
		"files":                  map[string]any{"private-config": map[string]any{"data": "PRIVATE_CONFIGURATION_VALUE"}},
	}
	if err := e.save("prepared"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "last-migration.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE_CONFIGURATION_VALUE") {
		t.Fatal("private config leaked into last-migration.json")
	}
	var pub map[string]any
	_ = json.Unmarshal(raw, &pub)
	if pub["phase"] != "prepared" || pub["target_runtime_version"] != "3.4.7" {
		t.Fatalf("unexpected published summary: %v", pub)
	}
	e.State["target_verified"] = true
	if err := e.save("committed"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "last-migration.json"))
	_ = json.Unmarshal(raw, &pub)
	if pub["target_verified"] != true {
		t.Fatalf("expected target_verified=true: %v", pub)
	}
}

func TestCommittedUnchangedRejectsLaterPackageRevision(t *testing.T) {
	h := &fakeHost{pkgsFn: func() (map[string]string, error) {
		return map[string]string{"haproxy-awslc": "3.4.8-2"}, nil
	}}
	e := NewEngine(nil, h)
	e.State = map[string]any{
		"target_packages": []any{map[string]any{"Package": "haproxy-awslc", "Version": "3.4.8-1"}},
	}
	if err := e.committedUnchanged(); err == nil || !strings.Contains(err.Error(), "target packages changed") {
		t.Fatalf("expected target packages changed, got %v", err)
	}
	if len(h.cmdCalls) != 0 {
		t.Fatalf("unexpected commands: %v", h.cmdCalls)
	}
}

func TestPreviousUnfinishedOperationBlocksNewPrepare(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"last-update.json", "last-migration.json"} {
		prev := filepath.Join(dir, name)
		_ = os.WriteFile(prev, []byte(`{"id":"`+strings.Repeat("a", 32)+`","phase":"rollback_failed"}`), 0o600)
		p := DefaultPaths()
		p.Root = dir
		e := NewEngine(&p, &fakeHost{})
		if err := e.checkPreviousOperations(); err == nil || !strings.Contains(err.Error(), "unfinished HAProxy update") {
			t.Fatalf("%s: expected unfinished update error, got %v", name, err)
		}
		_ = os.Remove(prev)
	}
}

func TestPeerLayoutAndSeedConfig(t *testing.T) {
	layout, err := ParsePeerLayout(testConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.Tables) != 2 || layout.Tables["tbl_ban"] == "" || layout.Tables["tbl_ip_auth"] == "" {
		t.Fatalf("unexpected layout: %+v", layout)
	}
	for _, bad := range []string{
		strings.ReplaceAll(testConfig, "127.0.0.1", "192.0.2.1"),
		strings.ReplaceAll(testConfig, "backend tbl_ban", "    peer other 127.0.0.1:10241\nbackend tbl_ban"),
		strings.ReplaceAll(testConfig, "store gpc0,gpt0", "store gpc0"),
		strings.ReplaceAll(testConfig, "type ip", "type ipv6"),
		strings.ReplaceAll(testConfig, "localpeer ha-local", "localpeer other"),
	} {
		if _, err := ParsePeerLayout(bad); err == nil {
			t.Errorf("invalid layout accepted:\n%s", bad)
		}
	}
	cand, err := AddSeed(testConfig, layout, "migration-test", 12345)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(cand, "    peer migration-test 127.0.0.1:12345\n", "") != testConfig {
		t.Fatalf("AddSeed modified original config:\n%s", cand)
	}
	seed := SeedConfig(layout, "migration-test", 12345, "/private/seed.sock")
	for _, decl := range layout.Tables {
		if !strings.Contains(seed, decl) {
			t.Errorf("seed config missing %q", decl)
		}
	}
}

func TestParseAptPlan(t *testing.T) {
	for _, prefix := range []string{"Inst", "Remv", "Conf"} {
		if _, err := ParseAptPlan(prefix+" libc6:arm64 (2.40)", map[string]bool{"haproxy": true}); err == nil {
			t.Errorf("expected refusal for %s libc6", prefix)
		}
	}
	got, err := ParseAptPlan("Remv haproxy [2.8]\nInst haproxy-awslc:arm64 (3.4)", map[string]bool{"haproxy": true, "haproxy-awslc": true})
	if err != nil || !got["haproxy"] || !got["haproxy-awslc"] {
		t.Fatalf("unexpected plan: %v %v", got, err)
	}
}

func TestTableRowsAndVerifyTables(t *testing.T) {
	saveMigGlobals(t)
	for _, bad := range [][]string{
		{},
		{"Unknown table"},
		{"# table: tbl_ban, type: ipv6, size:10"},
		{"# table: tbl_ban, type: ip, size:10", "key=198.51.100.22 exp=1000 gpc0=1"},
	} {
		linesFromSocketFunc = func(string, string) ([]string, error) { return bad, nil }
		if _, err := defaultTableRows("/unused", "tbl_ban"); err == nil {
			t.Errorf("expected error for response %v", bad)
		}
	}

	compare := func(oldMap, newMap map[string][]TableRow, elapsed int64) error {
		tables := map[string]string{"tbl_ban": "", "tbl_ip_auth": ""}
		snap := filepath.Join(t.TempDir(), "tables.sqlite")
		nowFunc = func() time.Time { return time.Unix(100, 0) }
		tableRowsFunc = func(_, tab string) ([]TableRow, error) { return oldMap[tab], nil }
		if _, err := SnapshotTables("/unused", snap, tables); err != nil {
			t.Fatal(err)
		}
		nowFunc = func() time.Time { return time.Unix(100+elapsed, 0) }
		tableRowsFunc = func(_, tab string) ([]TableRow, error) { return newMap[tab], nil }
		_, err := VerifyTables("/unused", snap, tables)
		return err
	}

	ban := TableRow{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 1, HasGPT0: true, GPT0: 40}
	banAfter := TableRow{Address: "198.51.100.22", ExpiryMS: 25000, GPC0: 1, HasGPT0: true, GPT0: 40}
	if err := compare(map[string][]TableRow{"tbl_ban": {ban}}, map[string][]TableRow{"tbl_ban": {banAfter}}, 5); err != nil {
		t.Fatalf("preserved expiry rejected: %v", err)
	}
	if err := compare(map[string][]TableRow{"tbl_ban": {ban}}, map[string][]TableRow{"tbl_ban": {ban}}, 5); err == nil || !strings.Contains(err.Error(), "extended=1") {
		t.Fatalf("expected extended=1, got %v", err)
	}

	// Missing ban, changed reason, lost counter
	oldBan := map[string][]TableRow{"tbl_ban": {{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 3, HasGPT0: true, GPT0: 40}}}
	for _, badNew := range []map[string][]TableRow{
		{},
		{"tbl_ban": {{Address: "198.51.100.22", ExpiryMS: 25000, GPC0: 3, HasGPT0: true, GPT0: 41}}},
		{"tbl_ban": {{Address: "198.51.100.22", ExpiryMS: 25000, GPC0: 2, HasGPT0: true, GPT0: 40}}},
	} {
		if err := compare(oldBan, badNew, 5); err == nil {
			t.Errorf("expected mismatch for %+v", badNew)
		}
	}

	// Natural expiry and legitimate auth renewal allowed
	if err := compare(map[string][]TableRow{"tbl_ban": {{Address: "198.51.100.22", ExpiryMS: 3000, GPC0: 1, HasGPT0: true, GPT0: 40}}}, nil, 5); err != nil {
		t.Fatalf("natural expiry rejected: %v", err)
	}
	if err := compare(
		map[string][]TableRow{"tbl_ip_auth": {{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 7}}},
		map[string][]TableRow{"tbl_ip_auth": {{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 8}}},
		5,
	); err != nil {
		t.Fatalf("auth renewal rejected: %v", err)
	}
	if err := compare(
		map[string][]TableRow{"tbl_ip_auth": {{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 7}}},
		map[string][]TableRow{"tbl_ip_auth": {{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 7}}},
		5,
	); err == nil || !strings.Contains(err.Error(), "extended=1") {
		t.Fatalf("expected extended=1 for unchanged auth counter, got %v", err)
	}
}

func TestAtomicRestoreRefusesExternalChanges(t *testing.T) {
	saveMigGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	e := NewEngine(nil, &fakeHost{})
	e.Directory = dir
	e.State = map[string]any{"files": map[string]any{}}
	target := filepath.Join(dir, "managed")
	if err := atomicWrite(target, []byte("original"), 0o640, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.backup(target); err != nil {
		t.Fatal(err)
	}
	if err := e.put(target, []byte("owned replacement"), 0o600, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.restore(target); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(target)
	fi, _ := os.Stat(target)
	if string(raw) != "original" || fi.Mode().Perm() != 0o640 {
		t.Fatalf("restored=%q mode=%o", string(raw), fi.Mode().Perm())
	}
	_ = os.WriteFile(target, []byte("foreign edit"), 0o640)
	if err := e.restore(target); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("expected external edit refusal, got %v", err)
	}
}

func TestWatchdogRecoveryAndWorkerReload(t *testing.T) {
	saveMigGlobals(t)
	requireRootOwner = false
	dir := t.TempDir()
	id := strings.Repeat("a", 32)
	txDir := filepath.Join(dir, id)
	_ = os.MkdirAll(txDir, 0o700)
	mach := strings.Repeat("m", 64)
	h := &fakeHost{machineID: mach}
	p := DefaultPaths()
	p.Root = dir
	p.Lock = filepath.Join(dir, "lock")
	e := NewEngine(&p, h)
	e.Directory = txDir
	e.State = map[string]any{"format": 1, "id": id, "machine": mach, "phase": "committed"}
	_ = e.save("committed")

	// Watchdog recovery does not undo committed migration
	sum, err := e.Recover(id)
	if err != nil || sum["phase"] != "committed" || !h.cancelled {
		t.Fatalf("recover committed: sum=%v cancelled=%v err=%v", sum, h.cancelled, err)
	}

	// Interrupted rollback without ready peer keeps committed target
	e.State["phase"] = "bootstrapping_peer"
	e.State["operation"] = "rollback"
	e.State["seed_ready"] = false
	e.State["config_modified"] = false
	_ = e.save("")
	e.HealthHook = func() error { return nil }
	sum, err = e.Recover(id)
	if err != nil || sum["phase"] != "committed" {
		t.Fatalf("interrupted rollback recover: sum=%v err=%v", sum, err)
	}

	// Reloading same version waits for different worker pid
	sleepFunc = func(time.Duration) {}
	bin := filepath.Join(dir, "haproxy")
	_ = os.WriteFile(bin, []byte("bin"), 0o755)
	dig, _ := fileDigest(bin)
	h.workerDig = dig
	p.Binary = bin
	e2 := NewEngine(&p, h)
	infos := []map[string]string{{"Version": "2.8.30", "Pid": "10"}, {"Version": "2.8.30", "Pid": "11"}}
	calls := 0
	runtimeInfoFunc = func(string) (map[string]string, error) {
		res := infos[calls]
		calls++
		return res, nil
	}
	got, err := e2.waitWorker("2.8.30", "10")
	if err != nil || got["Pid"] != "11" || calls != 2 {
		t.Fatalf("waitWorker: got=%v calls=%d err=%v", got, calls, err)
	}
}

func TestCheckGuardAdaptiveFirstStepAndManualBans(t *testing.T) {
	saveMigGlobals(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.sqlite")
	e := NewEngine(nil, &fakeHost{})
	e.Directory = dir
	e.State = map[string]any{"guard_database": dbPath}

	// 1. Legacy schema without ban_code column defaults to 40
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`CREATE TABLE ip_state(ip TEXT, banned_until INTEGER)`)
	_, _ = db.Exec(`CREATE TABLE manual_bans(ip TEXT, expires_at INTEGER)`)
	_, _ = db.Exec(`INSERT INTO ip_state VALUES(?,?)`, "198.51.100.22", time.Now().Unix()+60)
	_ = db.Close()

	for _, tc := range []struct {
		rows []TableRow
		ok   bool
	}{
		{nil, false},
		{[]TableRow{{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 1, HasGPT0: true, GPT0: 50}}, false},
		{[]TableRow{{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 1, HasGPT0: true, GPT0: 40}}, true},
	} {
		tableRowsFunc = func(string, string) ([]TableRow, error) { return tc.rows, nil }
		_, _ = SnapshotTables("/unused", filepath.Join(dir, "tables.sqlite"), map[string]string{"tbl_ban": ""})
		err := e.CheckGuard()
		if (err == nil) != tc.ok {
			t.Fatalf("legacy rows=%v ok=%v got err=%v", tc.rows, tc.ok, err)
		}
	}

	// 2. Schema with ban_code matches 40 vs 41 strictly
	_ = os.Remove(dbPath)
	db, _ = sql.Open("sqlite", dbPath)
	_, _ = db.Exec(`CREATE TABLE ip_state(ip TEXT, banned_until INTEGER, ban_code INTEGER)`)
	_, _ = db.Exec(`CREATE TABLE manual_bans(ip TEXT, expires_at INTEGER)`)
	_ = db.Close()

	for _, tc := range []struct {
		persisted any
		runtime   int64
		ok        bool
	}{
		{41, 41, true}, {41, 40, false}, {40, 41, false},
		{40, 40, true}, {0, 40, true}, {0, 41, false},
		{nil, 40, true}, {50, 50, false}, {99, 99, false},
	} {
		db, _ = sql.Open("sqlite", dbPath)
		_, _ = db.Exec(`DELETE FROM ip_state`)
		_, _ = db.Exec(`INSERT INTO ip_state VALUES(?,?,?)`, "198.51.100.22", time.Now().Unix()+3600, tc.persisted)
		_ = db.Close()
		tableRowsFunc = func(string, string) ([]TableRow, error) {
			return []TableRow{{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 1, HasGPT0: true, GPT0: tc.runtime}}, nil
		}
		_, _ = SnapshotTables("/unused", filepath.Join(dir, "tables.sqlite"), map[string]string{"tbl_ban": ""})
		err := e.CheckGuard()
		if (err == nil) != tc.ok {
			t.Fatalf("ban_code persisted=%v runtime=%d ok=%v got err=%v", tc.persisted, tc.runtime, tc.ok, err)
		}
	}

	// 3. Manual bans only accept code 50
	db, _ = sql.Open("sqlite", dbPath)
	_, _ = db.Exec(`DELETE FROM ip_state`)
	_, _ = db.Exec(`INSERT INTO manual_bans VALUES(?,?)`, "198.51.100.22", time.Now().Unix()+3600)
	_ = db.Close()
	for _, rt := range []int64{40, 41, 50} {
		tableRowsFunc = func(string, string) ([]TableRow, error) {
			return []TableRow{{Address: "198.51.100.22", ExpiryMS: 30000, GPC0: 1, HasGPT0: true, GPT0: rt}}, nil
		}
		_, _ = SnapshotTables("/unused", filepath.Join(dir, "tables.sqlite"), map[string]string{"tbl_ban": ""})
		err := e.CheckGuard()
		if (err == nil) != (rt == 50) {
			t.Fatalf("manual ban runtime=%d got err=%v", rt, err)
		}
	}
}

func TestCLIReportsOriginalFailureWithAbortSummary(t *testing.T) {
	saveMigGlobals(t)
	requireRootOwner = false
	cliGetEUID = func() int { return 0 }
	cliUmask = func(int) int { return 0 }
	dir := t.TempDir()
	p := DefaultPaths()
	p.Lock = filepath.Join(dir, "lock")
	e := NewEngine(&p, &fakeHost{})
	e.State = map[string]any{"id": strings.Repeat("a", 32), "phase": "aborted", "failure": "Persisted guard decisions differ"}
	cliNewEngine = func() *Engine { return e }
	refreshAptFunc = func() (map[string]any, error) {
		return map[string]any{"fresh": false}, nil
	}
	var out, errBuf bytes.Buffer
	code := RunCLI([]string{"migrate"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	var payload map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(errBuf.Bytes()), &payload); err != nil {
		t.Fatalf("stderr json: %v (%s)", err, errBuf.String())
	}
	if payload["failure"] != "Persisted guard decisions differ" || payload["phase"] != "aborted" {
		t.Fatalf("unexpected CLI error payload: %v", payload)
	}
}
