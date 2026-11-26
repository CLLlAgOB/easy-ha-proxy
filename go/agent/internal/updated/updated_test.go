package updated

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestDaemon(t testing.TB) *Daemon {
	t.Helper()
	root := t.TempDir()
	opts := Options{
		SocketPath: filepath.Join(root, "run", "u.sock"), StateRoot: filepath.Join(root, "state"),
		SourceDir: filepath.Join(root, "src"), ConfigDir: filepath.Join(root, "etc"),
		CLIPath: "/bin/true", ActiveMarker: filepath.Join(root, "run", "active"),
		RestartRequestMarker: filepath.Join(root, "run", "restart"), RebootMarker: filepath.Join(root, "run", "reboot.json"),
		AssistantRebootMarker: filepath.Join(root, "run", "assistant"), MaintenanceLockPath: filepath.Join(root, "run", "op.lock"),
		HAProxyTransactionMarker: filepath.Join(root, "run", "tx"), HAProxyTransactionState: filepath.Join(root, "run", "tx.json"),
		BackupdRestoreMarker: filepath.Join(root, "run", "restore"), BootIDPath: filepath.Join(root, "boot_id"),
		RebootRequiredPath: filepath.Join(root, "reboot-required"), ProcStatPath: filepath.Join(root, "stat"),
		HAProxyUpdateState: filepath.Join(root, "hp", "last-update.json"), HAProxyMigrationState: filepath.Join(root, "hp", "last-migration.json"),
		MaxRequestBytes: 32768, MaxResponseBytes: 2 << 20, MaxCaptureBytes: 256 * 1024, MaxStateBytes: 1 << 20,
		JobTimeoutSeconds: 60, CheckTimeoutSeconds: 60, PlanTTLSeconds: 900, ListLimit: 30, AutoCheckHours: 24,
		MaxConnections: 4, RebootDelaySeconds: 60, AppUID: os.Getuid(), AppPrimaryGID: -1, AppGroupGID: -1,
	}
	for _, dir := range []string{opts.JobsDir(), filepath.Dir(opts.SocketPath), opts.ConfigDir, filepath.Join(opts.SourceDir, "installer")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(opts.BootIDPath, []byte("58eacc1c-f8a0-4c2f-86f4-45f4aaaaaaaa\n"), 0o644)
	d := NewDaemon(opts)
	d.Alerts = nil
	d.rootUID = os.Geteuid()
	d.transient = func() bool { return false }
	return d
}

func TestDispatchValidation(t *testing.T) {
	d := newTestDaemon(t)
	cases := []struct {
		req  map[string]any
		want string
	}{
		{map[string]any{"action": "nope"}, "unknown update broker action"},
		{map[string]any{"action": "summary", "z": 1, "a": 1}, "unexpected request fields: a, z"},
		{map[string]any{"action": "set_settings", "auto_check_hours": 5.0}, "auto_check_hours must be one of 0, 6, 12, 24, 72, 168"},
		{map[string]any{"action": "set_auto_install", "enabled": true, "start": 4.0, "end": 4.0}, "the window must not start and end at the same hour"},
		{map[string]any{"action": "start_apply", "confirmation": "no"}, "type UPDATE to confirm component updates"},
		{map[string]any{"action": "reboot", "confirmation": "REBOOT", "expected_boot_id": "x", "actor": "a"}, "a valid expected boot id is required"},
		{map[string]any{"action": "reboot", "confirmation": "REBOOT", "expected_boot_id": "00000000-0000-0000-0000-000000000000", "actor": "a"},
			"the server boot changed; reload the page and try again"},
		{map[string]any{"action": "set_channels"}, "select a channel to persist"},
	}
	for _, c := range cases {
		_, err := d.Dispatch(context.Background(), c.req)
		if err == nil || err.Error() != c.want {
			t.Errorf("%v: got %v, want %q", c.req["action"], err, c.want)
		}
	}
	out, err := d.Dispatch(context.Background(), map[string]any{"action": "set_settings", "auto_check_hours": 6.0})
	if err != nil || out["settings"].(map[string]any)["auto_check_hours"] != int64(6) {
		t.Fatalf("set_settings: %v %v", out, err)
	}
}

func TestSelectedComponentsOrderAndCollapse(t *testing.T) {
	got, err := selectedComponents([]any{"os", "admin-container", "all", "daemons"})
	if err != nil || strings.Join(got, ",") != "all,os" {
		t.Fatalf("all collapses source and containers: %v %v", got, err)
	}
	got, _ = selectedComponents([]any{"haproxy", "services", "changes", "authelia-container"})
	if strings.Join(got, ",") != "changes,authelia-container,haproxy" {
		t.Fatalf("changes replaces services: %v", got)
	}
	if _, err := selectedComponents([]any{"all", "all"}); err == nil || err.Error() != "duplicate update component" {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestProgressAndLog(t *testing.T) {
	text := "EHP-PROGRESS phase=source\n=== Applying component: daemons ===\nEHP-PROGRESS 3/9 Copy\x07 files\n"
	p := parseProgress(text)
	if p["phase"] != "playbook" || p["done"] != 3 || p["total"] != 9 || p["task"] != "Copy files" {
		t.Fatalf("progress: %v", p)
	}
	if parseProgress("=== Applying component: x ===\nnothing") != nil {
		t.Fatal("progress before the heading must not count")
	}
	d := newTestDaemon(t)
	d.Opts.MaxCaptureBytes = 30
	got := d.sanitizeLog(strings.Repeat("é", 40))
	if !strings.HasPrefix(got, "[output truncated]\n") || len(got) > 30 {
		t.Fatalf("truncation: %q (%d)", got, len(got))
	}
}

func TestMaintenanceWindow(t *testing.T) {
	loc := time.FixedZone("X", 3600)
	value := map[string]any{"enabled": true, "start": int64(23), "end": int64(2), "updated_at": 1.0}
	at := time.Date(2026, 11, 23, 1, 30, 0, 0, loc)
	w := mwCurrent(value, at)
	if w == nil || w["key"] != "2026-11-22" {
		t.Fatalf("window spanning midnight: %v", w)
	}
	if mwCurrent(value, time.Date(2026, 11, 23, 2, 0, 0, 0, loc)) != nil {
		t.Fatal("window end is exclusive")
	}
	if !inInstallWindow(at, 23, 2) || installNight(at, 23, 2) != "2026-11-22" {
		t.Fatal("install window helpers")
	}
	if _, err := mwPolicy(map[string]any{"auto_install_unified": true, "auto_install_start": 1.0, "auto_install_end": 1.0}); err == nil {
		t.Fatal("invalid unified policy accepted")
	}
}

func TestAvailabilityReport(t *testing.T) {
	plan := map[string]any{"components": []any{
		map[string]any{"id": "os", "state": "available", "actionable": true, "details": map[string]any{"package_count": 4.0}},
		map[string]any{"id": "haproxy", "state": "available", "actionable": true, "installed": "2.8.5", "available": "2.8.6"},
	}}
	active, summary, detail, ok := availabilityReport(plan)
	if !ok || !active || summary != "Software updates are available: operating-system packages (4), HAProxy 2.8.5 → 2.8.6" ||
		detail != "Install them from Software updates in HAProxy Admin." {
		t.Fatalf("report: %v %q %q", active, summary, detail)
	}
	_, _, _, ok = availabilityReport(map[string]any{"components": []any{map[string]any{"id": "os", "state": "unknown"}}})
	if ok {
		t.Fatal("unknown must say nothing")
	}
}

// listJobs keeps parsed job files between calls; a write must show at once,
// and a caller changing what it got must not change what the next one gets.
func TestListJobsCache(t *testing.T) {
	d := newTestDaemon(t)
	job, err := d.newJob("check", map[string]any{"components": []any{"host"}})
	if err != nil {
		t.Fatal(err)
	}
	id := job["id"].(string)
	first := d.listJobs()
	if len(first) != 1 || first[0]["status"] != "queued" {
		t.Fatalf("first listing: %v", first)
	}
	first[0]["status"] = "tampered"
	first[0]["components"].([]any)[0] = "tampered"
	again := d.listJobs()
	if again[0]["status"] != "queued" || again[0]["components"].([]any)[0] != "host" {
		t.Fatalf("cache changed by a caller: %v", again[0])
	}
	if _, err := d.updateJob(id, map[string]any{"status": "running"}); err != nil {
		t.Fatal(err)
	}
	if got := d.listJobs(); got[0]["status"] != "running" {
		t.Fatalf("a written job was not read again: %v", got[0])
	}
	if err := os.Remove(filepath.Join(d.Opts.JobsDir(), id+".json")); err != nil {
		t.Fatal(err)
	}
	if got := d.listJobs(); len(got) != 0 || len(d.jobCache) != 0 {
		t.Fatalf("a removed job is still listed: %v %v", got, d.jobCache)
	}
}

// A broker whose binary was replaced under it restarts itself once no job of
// its own runs, with or without the installer's restart marker.
func TestBrokerRestartsWhenItsBinaryWasReplaced(t *testing.T) {
	d := newTestDaemon(t)
	var calls []string
	d.commandRunner = func(_ time.Duration, _ []string, argv ...string) (int, string, string, error) {
		calls = append(calls, strings.Join(argv, " "))
		return 0, "", "", nil
	}
	replaced := false
	old := runningReplacedBinary
	runningReplacedBinary = func() bool { return replaced }
	defer func() { runningReplacedBinary = old }()

	d.requestSelfRestartIfNeeded()
	if len(calls) != 0 {
		t.Fatalf("restarted without a reason: %v", calls)
	}
	replaced = true
	d.autoMu.Lock()
	d.cycleRunning = true
	d.autoMu.Unlock()
	d.requestSelfRestartIfNeeded()
	if len(calls) != 0 {
		t.Fatalf("restarted while its own cycle runs: %v", calls)
	}
	d.autoMu.Lock()
	d.cycleRunning = false
	d.autoMu.Unlock()
	d.requestSelfRestartIfNeeded()
	if len(calls) != 1 || !strings.Contains(calls[0], "try-restart --no-block") {
		t.Fatalf("expected one deferred self-restart, got %v", calls)
	}
}
