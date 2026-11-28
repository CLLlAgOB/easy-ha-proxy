package hostsec

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOSPolicyAndWindows(t *testing.T) {
	p, err := validateOSPolicy(map[string]any{"mode": "daily", "interval": 4, "start": 3, "end": 5})
	if err != nil || p.Mode != "daily" || p.Interval != 4 {
		t.Fatalf("valid policy failed: %+v %v", p, err)
	}
	for _, bad := range []map[string]any{
		{"mode": "bogus", "interval": 4, "start": 3, "end": 5},
		{"mode": "auto", "interval": 5, "start": 3, "end": 5},
		{"mode": "window", "interval": 4, "start": 3, "end": 3},
		{"mode": "window", "interval": 4, "start": -1, "end": 5},
	} {
		if _, err := validateOSPolicy(bad); err == nil {
			t.Errorf("expected invalid policy error for %v", bad)
		}
	}

	at3 := time.Date(2026, 11, 20, 3, 30, 0, 0, time.UTC)
	at4 := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	if !osWindowOpen(p, at3) || osWindowOpen(p, at4) {
		t.Fatal("daily window open/close mismatch")
	}
	if !osScheduledInstall(p, map[string]any{}, at3) {
		t.Fatal("daily install should be due before first install")
	}
	if osScheduledInstall(p, map[string]any{"last_install_at": float64(at3.Unix())}, at3) {
		t.Fatal("daily install should not repeat on same day")
	}

	cross := osPolicy{Mode: "window", Interval: 4, Start: 23, End: 2}
	if !osWindowOpen(cross, time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)) ||
		osWindowOpen(cross, time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC)) {
		t.Fatal("cross-midnight window mismatch")
	}
}

func TestBuildAptEnvironment(t *testing.T) {
	dir := t.TempDir()
	env, err := buildAptEnvironment(dir, "ubuntu", "noble")
	if err != nil {
		t.Fatal(err)
	}
	if env["NEEDRESTART_MODE"] != "a" {
		t.Fatalf("expected NEEDRESTART_MODE=a, got %q", env["NEEDRESTART_MODE"])
	}
	mainRaw, err := os.ReadFile(filepath.Join(dir, "main.conf"))
	if err != nil {
		t.Fatal(err)
	}
	mainStr := string(mainRaw)
	for _, want := range []string{
		"origin=Ubuntu,archive=noble-security",
		"origin=UbuntuESM,archive=noble-infra-security",
		"Unattended-Upgrade::Automatic-Reboot \"false\"",
		"Unattended-Upgrade::InstallOnShutdown \"false\"",
		"^haproxy(:[a-z0-9]+)?$",
		"^docker[.]io(:[a-z0-9]+)?$",
	} {
		if !strings.Contains(mainStr, want) {
			t.Errorf("main.conf missing %q", want)
		}
	}
}

func TestServiceRestartClassificationAndWindow(t *testing.T) {
	origRun := runCommand
	origConf := needrestartConfPath
	origPerl := perlBin
	t.Cleanup(func() {
		runCommand = origRun
		needrestartConfPath = origConf
		perlBin = origPerl
	})
	needrestartConfPath = filepath.Join(t.TempDir(), "missing.conf")
	perlBin = filepath.Join(t.TempDir(), "missing-perl")

	if got := classifyService("haproxy.service", nil); got != "protected" {
		t.Fatalf("haproxy.service = %q, want protected", got)
	}
	if got := classifyService("dbus.service", nil); got != "deferred" {
		t.Fatalf("dbus.service = %q, want deferred", got)
	}
	if got := classifyService("cron.service", nil); got != "automatic" {
		t.Fatalf("cron.service = %q, want automatic", got)
	}
	if got := classifyService("cron.service", map[string]bool{"cron.service": true}); got != "deferred" {
		t.Fatalf("excluded cron.service = %q, want deferred", got)
	}
	if got := classifyService("bad;unit", nil); got != "unknown" {
		t.Fatalf("bad;unit = %q, want unknown", got)
	}

	local := time.Date(2026, 11, 20, 2, 30, 0, 0, time.UTC)
	pol := restartPolicyData{Enabled: true, Time: "02:15", ID: strings.Repeat("a", 32), UpdatedAt: 1}
	due, key := restartDue(pol, map[string]any{}, local, "boot-1", 100)
	if !due || key != "2026-11-20 02:15" {
		t.Fatalf("expected restart due, got due=%v key=%q", due, key)
	}
	doneStatus := map[string]any{
		"policy_id": pol.ID, "boot_id": "boot-1", "window": key, "state": "ready",
		"applied": true, "completed_at": float64(200), "last_attempt": float64(local.Unix()),
	}
	if due, _ := restartDue(pol, doneStatus, local, "boot-1", 100); due {
		t.Fatal("already-completed window should not be due again")
	}
}

func TestAutoRebootFireOutcomes(t *testing.T) {
	origRoot := requireRootOwner
	origBoot := bootIDPath
	origRun := runCommand
	origNow := nowFunc
	origLocal := localTimeFunc
	origLocks := aptLockPaths
	origGuardDir := runGuardDir
	origMigDir := haproxyMigrationDir
	origUI := haproxyPendingUIFile
	origTx := haproxyGuardTxFile
	origDropin := osRestartDropin
	origAptGuard := osAptGuard
	t.Cleanup(func() {
		requireRootOwner = origRoot
		bootIDPath = origBoot
		runCommand = origRun
		nowFunc = origNow
		localTimeFunc = origLocal
		aptLockPaths = origLocks
		runGuardDir = origGuardDir
		haproxyMigrationDir = origMigDir
		haproxyPendingUIFile = origUI
		haproxyGuardTxFile = origTx
		osRestartDropin = origDropin
		osAptGuard = origAptGuard
	})
	requireRootOwner = false
	dir := t.TempDir()
	root := filepath.Join(dir, "os-security")
	bootFile := filepath.Join(dir, "boot_id")
	_ = os.WriteFile(bootFile, []byte("58eacc1c-f8a0-4c2f-86f4-45f4aaaaaaaa\n"), 0o644)
	bootIDPath = bootFile
	runGuardDir = filepath.Join(dir, "run")
	haproxyMigrationDir = filepath.Join(dir, "mig")
	haproxyPendingUIFile = filepath.Join(dir, "ui")
	haproxyGuardTxFile = filepath.Join(dir, "tx")
	osRestartDropin = filepath.Join(dir, "easy-ha-proxy-os-security.conf")
	osAptGuard = filepath.Join(dir, "99-easy-ha-proxy-os-security")
	_ = os.WriteFile(osRestartDropin, []byte(osRestartConfig), 0o644)
	_ = os.WriteFile(osAptGuard, []byte(osAptGuardConfig), 0o644)
	_ = AtomicWrite(filepath.Join(root, "policy.json"), map[string]any{
		"phase": "ready", "policy": map[string]any{"mode": "notify", "interval": 4, "start": 3, "end": 5},
		"baseline": map[string]any{"enabled": "enabled", "active": true}, "updated_at": 1,
	}, 0o600)
	aptLockPaths = nil

	now := time.Date(2026, 11, 20, 3, 10, 0, 0, time.UTC)
	nowFunc = func() time.Time { return now }
	localTimeFunc = func() time.Time { return now }

	unit := "easy-ha-proxy-web-reboot-0123456789ab"
	rev := strings.Repeat("d", 32)
	lockPath := filepath.Join(dir, "maint.lock")
	markerPath := filepath.Join(dir, "reboot.json")
	reqPath := filepath.Join(dir, "reboot-required")

	reset := func() {
		_ = os.WriteFile(reqPath, []byte("reboot\n"), 0o644)
		_ = AtomicWrite(filepath.Join(root, "reboot-policy.json"), map[string]any{
			"enabled": true, "time": "03:00", "id": rev, "updated_at": float64(now.Add(-time.Hour).Unix()),
			"attempt": map[string]any{"window": "2026-11-20 03:00", "state": "scheduled", "at": float64(now.Unix())},
		}, 0o600)
		_ = AtomicWrite(markerPath, map[string]any{
			"unit": unit, "boot_id": "58eacc1c-f8a0-4c2f-86f4-45f4aaaaaaaa",
			"automatic": map[string]any{"policy_revision": rev, "window": "2026-11-20 03:00"},
		}, 0o600)
	}

	// 1. Triggered (with reboot intercepted!)
	reset()
	reboots := 0
	runCommand = func(argv []string, _ cmdOpts) (int, string, error) {
		if reflect.DeepEqual(argv, []string{"/usr/bin/systemctl", "reboot"}) {
			reboots++
			return 0, "", nil
		}
		if len(argv) >= 2 && argv[0] == "/usr/bin/apt-config" {
			return 0, "PERIODIC='0'\nSHUTDOWN='false'\nREBOOT='false'\n", nil
		}
		if len(argv) >= 3 && argv[0] == "/usr/bin/systemctl" && argv[1] == "show" && argv[2] == NativeTimerUnit {
			return 0, "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n", nil
		}
		if len(argv) >= 2 && argv[0] == "/usr/bin/systemctl" {
			return 0, "inactive\n", nil
		}
		return 0, "", nil
	}
	res, err := FireAutoReboot(root, lockPath, markerPath, reqPath, unit, &now, io.Discard)
	if err != nil || res != "triggered" || reboots != 1 {
		t.Fatalf("triggered: res=%q reboots=%d err=%v", res, reboots, err)
	}

	// 2. Not required when reboot-required disappears
	reset()
	_ = os.Remove(reqPath)
	reboots = 0
	res, err = FireAutoReboot(root, lockPath, markerPath, reqPath, unit, &now, io.Discard)
	if err != nil || res != "not_required" || reboots != 0 || lexists(markerPath) {
		t.Fatalf("not_required: res=%q reboots=%d marker=%v err=%v", res, reboots, lexists(markerPath), err)
	}

	// 3. Canceled when marker disappears
	reset()
	_ = os.Remove(markerPath)
	res, err = FireAutoReboot(root, lockPath, markerPath, reqPath, unit, &now, io.Discard)
	if err != nil || res != "canceled" || reboots != 0 {
		t.Fatalf("canceled: res=%q reboots=%d err=%v", res, reboots, err)
	}

	// 3. Missed window (after 04:00)
	reset()
	late := time.Date(2026, 11, 20, 4, 5, 0, 0, time.UTC)
	res, err = FireAutoReboot(root, lockPath, markerPath, reqPath, unit, &late, io.Discard)
	if err != nil || res != "missed" || reboots != 0 {
		t.Fatalf("missed: res=%q reboots=%d err=%v", res, reboots, err)
	}
}

func TestTimerMetadataHelpers(t *testing.T) {
	if got := parseDurationSeconds("0"); got != 0 {
		t.Fatalf("0: got %#v", got)
	}
	if got := parseDurationSeconds("1h 30min 5s"); got != float64(5405) {
		t.Fatalf("1h 30min 5s: got %#v", got)
	}
	if got := parseDurationSeconds("bogus"); got != nil {
		t.Fatalf("bogus: got %#v", got)
	}
	if got := dbusEscapeUnit("apt-daily-upgrade.timer"); got != "apt_2ddaily_2dupgrade_2etimer" {
		t.Fatalf("escape: got %q", got)
	}
}
