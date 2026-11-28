package hostsec

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func saveGuardGlobals(t *testing.T) {
	t.Helper()
	origRun := guardRun
	origUp := guardRunUpgrade
	origConsent := checkRuntimeConsent
	origFiles := guardRuntimeFiles
	origList := listRunningContainers
	origInspect := inspectContainerState
	origRestore := restoreContainers
	origSleep := guardSleep
	origNow := nowFunc
	origDpkgLock := guardDpkgLockPath
	origMaintLock := guardMaintLockPath
	origRoot := requireRootOwner
	t.Cleanup(func() {
		guardRun = origRun
		guardRunUpgrade = origUp
		checkRuntimeConsent = origConsent
		guardRuntimeFiles = origFiles
		listRunningContainers = origList
		inspectContainerState = origInspect
		restoreContainers = origRestore
		guardSleep = origSleep
		nowFunc = origNow
		guardDpkgLockPath = origDpkgLock
		guardMaintLockPath = origMaintLock
		requireRootOwner = origRoot
	})
}

func instLine(pkg, oldVer, newVer string) string {
	if oldVer != "" {
		return "Inst " + pkg + " [" + oldVer + "] (" + newVer + " repository [amd64])\n"
	}
	return "Inst " + pkg + " (" + newVer + " repository [amd64])\n"
}

func TestOSUpgradeGuardPackageSafety(t *testing.T) {
	// Unheld haproxy refused even if not upgraded
	for pkg := range guardHAProxyPkgs {
		_, err := ValidateOSUpgrade(pkg+"\tinstall\n", instLine("libc6", "2.36", "2.36.1"), false, false)
		if err == nil || !strings.Contains(err.Error(), "protection") {
			t.Errorf("unheld %s: got %v, want protection error", pkg, err)
		}
	}
	// No haproxy candidate can escape through OS component
	for _, auto := range []bool{false, true} {
		for pkg := range guardHAProxyPkgs {
			_, err := ValidateOSUpgrade(pkg+"\thold\n", instLine(pkg, "2.6.12", "2.6.13"), auto, false)
			if err == nil || !strings.Contains(err.Error(), "separately") {
				t.Errorf("pkg=%s auto=%v: got %v, want separately error", pkg, auto, err)
			}
		}
	}
	// Runtime patches accepted including epochs and distro suffixes
	patchCases := [][3]string{
		{"docker-ce", "5:28.5.1-1~ubuntu.24.04~noble", "5:28.5.2-1~ubuntu.24.04~noble"},
		{"docker.io:amd64", "26.1.3+dfsg1-1", "26.1.4+dfsg1-1"},
		{"containerd.io", "1.7.28-1", "1.7.29-1"},
		{"runc", "1.2.1-1", "1.2.2-1"},
	}
	for _, c := range patchCases {
		got, err := ValidateOSUpgrade("", instLine(c[0], c[1], c[2]), true, false)
		if err != nil || !reflect.DeepEqual(got, []string{c[0]}) {
			t.Errorf("patch %v: got %v %v", c, got, err)
		}
	}
	// New release lines, unknown versions, prereleases, and new installs need manual review
	badPairs := [][2]string{
		{"5:28.5.1", "5:29.0.0"}, {"1.7.1", "1.8.0"}, {"1.7.1", "2.0.0"},
		{"1.7.1", "1:1.7.2"}, {"unreadable", "1.7.2"}, {"1.7.1", "1.7.2~rc1"},
		{"1.7.1", "1.7.2-rc.1"}, {"", "1.7.2"},
	}
	for pkg := range guardRuntimePkgs {
		for _, pair := range badPairs {
			sim := instLine(pkg, pair[0], pair[1])
			if _, err := ValidateOSUpgrade("", sim, true, false); err == nil || !strings.Contains(err.Error(), "manual review") {
				t.Errorf("%s %v automatic: got %v, want manual review", pkg, pair, err)
			}
			if got, err := ValidateOSUpgrade("", sim, false, false); err != nil || len(got) != 0 {
				t.Errorf("%s %v manual: got %v %v", pkg, pair, got, err)
			}
		}
	}
	// Removals and malformed lines fail closed
	for _, sim := range []string{"Remv openssh-server [1.0]\n", "Inst docker-ce unreadable\n"} {
		if _, err := ValidateOSUpgrade("", sim, true, false); err == nil {
			t.Errorf("expected refusal for %q", sim)
		}
	}
}

func TestOSUpgradeGuardPreflight(t *testing.T) {
	saveGuardGlobals(t)
	root := filepath.Join(t.TempDir(), "os-security")
	record := filepath.Join(root, "package-install.json")

	// Refusal never writes package-install.json or runs mutating commands
	var calls [][]string
	outputs := []string{"haproxy\thold\n", instLine("docker-ce", "28.5.1", "29.0.0")}
	guardRun = func(argv []string) (string, error) {
		calls = append(calls, argv)
		out := outputs[0]
		outputs = outputs[1:]
		return out, nil
	}
	if err := prepareOSUpgrade(true, root); err == nil || !strings.Contains(err.Error(), "manual review") {
		t.Fatalf("expected manual review error, got %v", err)
	}
	if lexists(record) {
		t.Fatal("refusal must not write package-install.json")
	}
	wantCalls := [][]string{
		{"/usr/bin/dpkg", "--get-selections"},
		{"/usr/bin/apt-get", "-s", "--with-new-pkgs", "upgrade"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls %#v, want %#v", calls, wantCalls)
	}

	// Live-restore required for automatic runtime patch updates
	for _, ans := range []string{"false\n", "unreadable\n"} {
		outputs = []string{"", instLine("containerd.io", "1.7.1", "1.7.2"), ans}
		if err := prepareOSUpgrade(true, root); err == nil || !strings.Contains(err.Error(), "live-restore") {
			t.Fatalf("ans=%q: expected live-restore error, got %v", ans, err)
		}
		if lexists(record) {
			t.Fatal("record written despite live-restore failure")
		}
	}

	// Patches record before apt and do not overwrite status.json
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(root, "status.json")
	if err := os.WriteFile(status, []byte(`{"last_install_at":10}`), 0o600); err != nil {
		t.Fatal(err)
	}
	nowFunc = func() time.Time { return time.Unix(1234, 0) }
	outputs = []string{"", instLine("docker-ce", "28.5.1", "28.5.2"), "true\n"}
	if err := prepareOSUpgrade(true, root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]float64
	if err := json.Unmarshal(raw, &rec); err != nil || rec["last_install_attempt"] != 1234 {
		t.Fatalf("unexpected package-install.json: %s", string(raw))
	}
	fi, _ := os.Stat(record)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	if sraw, _ := os.ReadFile(status); string(sraw) != `{"last_install_at":10}` {
		t.Fatalf("status.json modified: %s", string(sraw))
	}

	// Manual upgrade does not require docker daemon
	root2 := filepath.Join(t.TempDir(), "os-security")
	calls = nil
	outputs = []string{"", instLine("docker-ce", "28.5.1", "29.0.0")}
	if err := prepareOSUpgrade(false, root2); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !lexists(filepath.Join(root2, "package-install.json")) {
		t.Fatalf("manual upgrade calls=%d record=%v", len(calls), lexists(filepath.Join(root2, "package-install.json")))
	}
}

func TestMaintenanceWindowSemantics(t *testing.T) {
	saveGuardGlobals(t)
	requireRootOwner = false
	rev := strings.Repeat("a", 32)
	mkSettings := func(overrides map[string]any) map[string]any {
		m := map[string]any{
			"auto_install": true, "auto_install_unified": true, "auto_install_runtime": true,
			"auto_install_os": true, "auto_install_start": 1, "auto_install_end": 2,
			"maintenance_revision": rev, "maintenance_updated_at": 1,
		}
		for k, v := range overrides {
			m[k] = v
		}
		return m
	}

	// Executor lease cannot extend saved window or revive revoked consent
	dir := t.TempDir()
	root := filepath.Join(dir, "os-security")
	settingsFile := filepath.Join(dir, "settings.json")
	writeSettings := func(m map[string]any) {
		b, _ := json.Marshal(m)
		if err := os.WriteFile(settingsFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSettings(mkSettings(nil))
	local := time.Date(2026, 11, 15, 1, 30, 0, 0, time.UTC)
	deadline := float64(time.Date(2026, 11, 15, 2, 0, 0, 0, time.UTC).Unix())
	nowFunc = func() time.Time { return local }

	if err := checkRuntimeConsent(root, rev, deadline, 0, true, &local); err != nil {
		t.Fatalf("expected valid consent: %v", err)
	}
	if err := checkRuntimeConsent(root, rev, deadline+3600, 0, true, &local); err == nil {
		t.Fatal("expected extended deadline refused")
	}
	if err := checkRuntimeConsent(root, rev, deadline, 3600, true, &local); err == nil {
		t.Fatal("expected excessive reserve refused")
	}
	writeSettings(mkSettings(map[string]any{"auto_install_runtime": false}))
	if err := checkRuntimeConsent(root, rev, deadline, 0, false, &local); err != nil {
		t.Fatalf("expected non-runtime consent accepted: %v", err)
	}
	if err := checkRuntimeConsent(root, rev, deadline, 0, true, &local); err == nil {
		t.Fatal("expected revoked runtime consent refused")
	}
	writeSettings(mkSettings(map[string]any{"auto_install": false}))
	if err := checkRuntimeConsent(root, rev, deadline, 0, true, &local); err == nil {
		t.Fatal("expected disabled auto_install refused")
	}

	// Exact end is closed and cross-midnight is one window
	pol, err := parseMWPolicy(mkSettings(nil))
	if err != nil {
		t.Fatal(err)
	}
	if currentMWWindow(pol, local) == nil {
		t.Fatal("expected window open at 01:30")
	}
	if currentMWWindow(pol, time.Date(2026, 11, 15, 2, 0, 0, 0, time.UTC)) != nil {
		t.Fatal("expected exact end 02:00 closed")
	}
	pol.Start, pol.End = 23, 2
	if w := currentMWWindow(pol, local); w == nil || w.Key != "2026-11-14" {
		t.Fatalf("cross-midnight 01:30: got %+v", w)
	}
	if w := currentMWWindow(pol, time.Date(2026, 11, 14, 23, 0, 0, 0, time.UTC)); w == nil || w.Key != "2026-11-14" {
		t.Fatalf("cross-midnight 23:00: got %+v", w)
	}

	// New consent waits for next full window
	pol2, _ := parseMWPolicy(mkSettings(map[string]any{"maintenance_updated_at": float64(local.Unix())}))
	if currentMWWindow(pol2, local) != nil {
		t.Fatal("new consent should not open already-started window")
	}
	if currentMWWindow(pol2, local.Add(24*time.Hour)) == nil {
		t.Fatal("next day window should open")
	}
	pol2.Enabled = false
	if currentMWWindow(pol2, local.Add(24*time.Hour)) != nil {
		t.Fatal("disabled policy should never open")
	}

	// Native stage rejects revoked or replaced policy
	writeSettings(mkSettings(nil))
	if err := requireMWWindow(root, rev, local); err != nil {
		t.Fatalf("expected requireMWWindow to pass: %v", err)
	}
	for _, raw := range []map[string]any{
		mkSettings(map[string]any{"auto_install": false}),
		mkSettings(map[string]any{"maintenance_revision": strings.Repeat("c", 32)}),
		mkSettings(map[string]any{"auto_install_unified": false}),
	} {
		writeSettings(raw)
		if err := requireMWWindow(root, rev, local); err == nil || !strings.Contains(err.Error(), "window has closed") {
			t.Fatalf("expected window has closed error, got %v", err)
		}
	}
}

func TestRuntimeMaintenanceFlows(t *testing.T) {
	saveGuardGlobals(t)
	requireRootOwner = false
	rev := strings.Repeat("a", 32)
	id := strings.Repeat("b", 64)
	healthy := "healthy"
	baseContainers := []containerInfo{{ID: id, Name: "/app", Status: "running", Paused: false, Health: &healthy}}

	newEnv := func(t *testing.T) (string, *[]string, *string) {
		t.Helper()
		root := filepath.Join(t.TempDir(), "os-security")
		events := &[]string{}
		sim := "Inst docker-ce [5:28.5.1] (5:29.0.0 repository [amd64])\n"
		guardRuntimeFiles = nil
		checkRuntimeConsent = func(string, string, float64, float64, bool, *time.Time) error { return nil }
		listRunningContainers = func() ([]containerInfo, error) { return baseContainers, nil }
		restoreContainers = func(items []containerInfo) error {
			*events = append(*events, "restore")
			return nil
		}
		guardRun = func(argv []string) (string, error) {
			if strings.HasSuffix(argv[0], "dpkg") {
				return "haproxy\thold\n", nil
			}
			if strings.HasSuffix(argv[0], "apt-get") {
				return sim, nil
			}
			for _, a := range argv {
				if a == "info" {
					for _, f := range argv {
						if strings.Contains(f, "LiveRestoreEnabled") {
							return "true\n", nil
						}
					}
					return "inactive\n", nil
				}
				if a == "stop" {
					*events = append(*events, "stop")
				}
			}
			return "", nil
		}
		guardRunUpgrade = func(argv []string, _ io.Writer) error {
			for _, a := range argv {
				if a == "--download-only" {
					*events = append(*events, "download")
					return nil
				}
			}
			*events = append(*events, "install")
			return nil
		}
		return root, events, &sim
	}

	// 1. Release upgrade downloads before downtime and restores original set
	root, events, _ := newEnv(t)
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*events, []string{"download", "stop", "install", "restore"}) {
		t.Fatalf("events=%v", *events)
	}
	rec, err := ReadJSON(filepath.Join(root, "runtime-maintenance.json"))
	if err != nil || rec["phase"] != "completed" || rec["restored"] != true {
		t.Fatalf("unexpected journal: %v %v", rec, err)
	}

	// 2. Window without runtime consent keeps patch-only policy
	root, events, sim := newEnv(t)
	if err := performRuntimeMaintenance(root, rev, 123456, false, io.Discard); err == nil || !strings.Contains(err.Error(), "manual review") {
		t.Fatalf("expected manual review error, got %v", err)
	}
	if len(*events) != 0 {
		t.Fatalf("expected no apt calls, got %v", *events)
	}
	*sim = strings.ReplaceAll(*sim, "29.0.0", "28.5.2")
	if err := performRuntimeMaintenance(root, rev, 123456, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*events, []string{"download", "install", "restore"}) {
		t.Fatalf("patch-only events=%v", *events)
	}

	// 3. Install failure still restores and requires recovery before retry
	root, events, _ = newEnv(t)
	guardRunUpgrade = func(argv []string, _ io.Writer) error {
		for _, a := range argv {
			if a == "--download-only" {
				*events = append(*events, "download")
				return nil
			}
		}
		*events = append(*events, "install")
		return refusef("package failure")
	}
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil || !strings.Contains(err.Error(), "package failure") {
		t.Fatalf("expected package failure, got %v", err)
	}
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("expected requires recovery on retry, got %v", err)
	}

	// 4. Closed window before installation restores without installing
	root, events, _ = newEnv(t)
	consentCalls := 0
	checkRuntimeConsent = func(string, string, float64, float64, bool, *time.Time) error {
		consentCalls++
		if consentCalls == 3 {
			return refusef("window closed")
		}
		return nil
	}
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil || !strings.Contains(err.Error(), "window closed") {
		t.Fatalf("expected window closed, got %v", err)
	}
	if !reflect.DeepEqual(*events, []string{"download", "stop", "restore"}) {
		t.Fatalf("closed window events=%v", *events)
	}
	rec, _ = ReadJSON(filepath.Join(root, "runtime-maintenance.json"))
	if rec["phase"] != "recovered" || rec["installation_started"] != false || rec["restored"] != true {
		t.Fatalf("unexpected closed-window journal: %v", rec)
	}

	// 5. Download failure or changed candidates never stops containers
	root, events, _ = newEnv(t)
	guardRunUpgrade = func([]string, io.Writer) error { return refusef("download failed") }
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil {
		t.Fatal("expected download error")
	}
	for _, ev := range *events {
		if ev == "stop" {
			t.Fatal("containers stopped on download failure")
		}
	}
	root, events, sim = newEnv(t)
	origRun := guardRun
	aptCalls := 0
	guardRun = func(argv []string) (string, error) {
		if strings.HasSuffix(argv[0], "apt-get") {
			aptCalls++
			if aptCalls == 2 {
				return strings.ReplaceAll(*sim, "29.0.0", "29.0.1"), nil
			}
		}
		return origRun(argv)
	}
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil || !strings.Contains(err.Error(), "candidates changed") {
		t.Fatalf("expected candidates changed, got %v", err)
	}

	// 6. Failed restoration is durable
	root, _, _ = newEnv(t)
	restoreContainers = func([]containerInfo) error { return errors.New("Docker did not return") }
	if err := performRuntimeMaintenance(root, rev, 123456, true, io.Discard); err == nil || !strings.Contains(err.Error(), "Docker did not return") {
		t.Fatalf("expected restore error, got %v", err)
	}
	rec, _ = ReadJSON(filepath.Join(root, "runtime-maintenance.json"))
	if rec["phase"] != "recovery_required" {
		t.Fatalf("expected recovery_required, got %v", rec["phase"])
	}

	// 7. Manual recovery respects shared custody lock and never installs packages
	root, events, _ = newEnv(t)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, "runtime-maintenance.json")
	if err := AtomicWrite(journal, map[string]any{"phase": "recovery_required", "containers": baseContainers}, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "maintenance.lock")
	dpkgLock := filepath.Join(root, "dpkg.lock")
	if err := os.WriteFile(dpkgLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	guardMaintLockPath = lockPath
	guardDpkgLockPath = dpkgLock
	held, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := recoverRuntimeMaintenance(root); err == nil || !strings.Contains(err.Error(), "Another maintenance") {
		t.Fatalf("expected busy lock refusal, got %v", err)
	}
	_ = held.Close()
	if err := recoverRuntimeMaintenance(root); err != nil {
		t.Fatalf("recovery after unlock failed: %v", err)
	}
	rec, _ = ReadJSON(journal)
	if rec["phase"] != "recovered" || !reflect.DeepEqual(*events, []string{"restore"}) {
		t.Fatalf("unexpected recovery result: phase=%v events=%v", rec["phase"], *events)
	}
}

func TestRestoreContainersStartsExitedAndWaitsForHealth(t *testing.T) {
	saveGuardGlobals(t)
	guardSleep = func(time.Duration) {}
	id := strings.Repeat("b", 64)
	healthy := "healthy"
	baseContainers := []containerInfo{{ID: id, Name: "/app", Status: "running", Paused: false, Health: &healthy}}
	exited := containerInfo{ID: id, Name: "/app", Status: "exited", Health: &healthy}
	startingHealth := "starting"
	starting := containerInfo{ID: id, Name: "/app", Status: "running", Health: &startingHealth}
	states := []containerInfo{exited, starting, baseContainers[0]}
	inspectContainerState = func(string) (containerInfo, error) {
		s := states[0]
		states = states[1:]
		return s, nil
	}
	var restoreCmds [][]string
	guardRun = func(argv []string) (string, error) {
		restoreCmds = append(restoreCmds, argv)
		return "", nil
	}
	if err := restoreContainers(baseContainers); err != nil {
		t.Fatal(err)
	}
	wantRestoreCmds := [][]string{
		{"/usr/bin/systemctl", "start", "docker.service"},
		{"/usr/bin/docker", "start", id},
	}
	if !reflect.DeepEqual(restoreCmds, wantRestoreCmds) {
		t.Fatalf("restore cmds=%#v, want %#v", restoreCmds, wantRestoreCmds)
	}
}

func TestContainerStateInspectionWithoutAndWithHealth(t *testing.T) {
	saveGuardGlobals(t)
	id := strings.Repeat("a", 64)
	inspect := func(state map[string]any) containerInfo {
		rec := []map[string]any{{"Id": id, "Name": "/nextcloud", "State": state}}
		raw, _ := json.Marshal(rec)
		var gotArgv []string
		guardRun = func(argv []string) (string, error) {
			gotArgv = argv
			return string(raw), nil
		}
		ci, err := inspectContainerState(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range gotArgv {
			if a == "--format" {
				t.Fatalf("must inspect full JSON, never --format template: %v", gotArgv)
			}
		}
		return ci
	}
	noHealth := inspect(map[string]any{"Status": "running", "Paused": false})
	if noHealth.ID != id || noHealth.Name != "/nextcloud" || noHealth.Status != "running" || noHealth.Paused || noHealth.Health != nil {
		t.Fatalf("unexpected container without health: %+v", noHealth)
	}
	withHealth := inspect(map[string]any{"Status": "running", "Paused": false, "Health": map[string]any{"Status": "starting"}})
	if withHealth.Health == nil || *withHealth.Health != "starting" {
		t.Fatalf("unexpected container with health: %+v", withHealth)
	}
	guardRun = func([]string) (string, error) { return "[]", nil }
	if _, err := inspectContainerState(id); err == nil {
		t.Fatal("expected unverifiable empty record refused")
	}
}

func TestRuntimeRecoveryEdgeCases(t *testing.T) {
	mkState := func(ch, name, status, health string) containerInfo {
		var hp *string
		if health != "" {
			h := health
			hp = &h
		}
		return containerInfo{ID: strings.Repeat(ch, 64), Name: "/" + name, Status: status, Health: hp}
	}

	// 1. Missing original does not prevent starting later dependencies
	t.Run("missing_original_starts_later_deps", func(t *testing.T) {
		saveGuardGlobals(t)
		guardSleep = func(time.Duration) {}
		missing := mkState("a", "app", "running", "healthy")
		redis := mkState("b", "redis", "running", "healthy")
		cur := map[string]containerInfo{redis.ID: mkState("b", "redis", "exited", "healthy")}
		inspectContainerState = func(id string) (containerInfo, error) {
			if c, ok := cur[id]; ok {
				return c, nil
			}
			return containerInfo{}, refusef("No such container: %s", id)
		}
		var cmds [][]string
		guardRun = func(argv []string) (string, error) {
			cmds = append(cmds, argv)
			for _, a := range argv {
				if a == "ps" {
					return redis.ID + "\n", nil
				}
			}
			if len(argv) >= 2 && argv[0] == "/usr/bin/docker" && argv[1] == "start" {
				cur[redis.ID] = redis
			}
			return "", nil
		}
		ticks := 0
		base := time.Unix(1000, 0)
		nowFunc = func() time.Time {
			ticks++
			if ticks == 1 {
				return base
			}
			return base.Add(200 * time.Second)
		}
		err := restoreContainers([]containerInfo{missing, redis})
		if err == nil || !strings.Contains(err.Error(), "/app:") || !strings.Contains(err.Error(), "No such container") {
			t.Fatalf("expected /app missing error, got %v", err)
		}
		if cur[redis.ID].Status != "running" {
			t.Fatal("redis was not started")
		}
	})

	// 2. Running replacement satisfies recovery without mutating it
	t.Run("running_replacement_accepted", func(t *testing.T) {
		saveGuardGlobals(t)
		orig := mkState("a", "app", "running", "healthy")
		repl := mkState("c", "app", "running", "healthy")
		calls := 0
		inspectContainerState = func(string) (containerInfo, error) {
			calls++
			if calls == 1 {
				return containerInfo{}, refusef("gone")
			}
			return repl, nil
		}
		var cmds [][]string
		guardRun = func(argv []string) (string, error) {
			cmds = append(cmds, argv)
			return repl.ID + "\n", nil
		}
		if err := restoreContainers([]containerInfo{orig}); err != nil {
			t.Fatal(err)
		}
		for _, c := range cmds {
			if len(c) >= 2 && c[0] == "/usr/bin/docker" && c[1] == "start" {
				t.Fatalf("must not start running replacement: %v", c)
			}
		}
	})

	// 3. Replacement must be running, exact name, not paused; existing ID never falls back; malformed names rejected
	t.Run("replacement_validation_and_malformed_names", func(t *testing.T) {
		saveGuardGlobals(t)
		orig := mkState("a", "app", "running", "healthy")
		paused := mkState("c", "app", "running", "healthy")
		paused.Paused = true
		for _, bad := range []containerInfo{
			mkState("c", "other", "running", "healthy"),
			mkState("c", "app", "exited", "healthy"),
			paused,
		} {
			calls := 0
			inspectContainerState = func(string) (containerInfo, error) {
				calls++
				if calls == 1 {
					return containerInfo{}, refusef("gone")
				}
				return bad, nil
			}
			guardRun = func([]string) (string, error) { return bad.ID + "\n", nil }
			if _, err := recoveryContainerState(orig); err == nil {
				t.Fatalf("expected invalid replacement %+v refused", bad)
			}
		}

		// Inspect failure for existing ID never falls back to name
		inspectCalls := 0
		inspectContainerState = func(string) (containerInfo, error) {
			inspectCalls++
			return containerInfo{}, refusef("temporary")
		}
		guardRun = func([]string) (string, error) { return orig.ID + "\n", nil }
		if _, err := recoveryContainerState(orig); err == nil || !strings.Contains(err.Error(), "temporary") || inspectCalls != 1 {
			t.Fatalf("existing ID fell back or wrong err: calls=%d err=%v", inspectCalls, err)
		}

		// Malformed names never trigger docker ps lookup
		for _, badName := range []string{"--help", "/", "/app/other", ""} {
			called := false
			guardRun = func([]string) (string, error) { called = true; return "", nil }
			item := orig
			item.Name = badName
			if _, err := recoveryContainerState(item); err == nil || called {
				t.Fatalf("malformed name %q: called=%v err=%v", badName, called, err)
			}
		}
	})

	// 4. Bounded retries (3), unhealthy/restarting never started, daemon start error non-fatal, last error preserved
	t.Run("bounded_retries_and_errors", func(t *testing.T) {
		saveGuardGlobals(t)
		guardSleep = func(time.Duration) {}
		orig := mkState("a", "app", "exited", "healthy")
		inspectContainerState = func(string) (containerInfo, error) { return orig, nil }
		starts := 0
		guardRun = func(argv []string) (string, error) {
			if len(argv) >= 2 && argv[0] == "/usr/bin/docker" && argv[1] == "start" {
				starts++
				return "", refusef("address already in use")
			}
			return "", nil
		}
		ticks := 0
		base := time.Unix(1000, 0)
		nowFunc = func() time.Time {
			ticks++
			if ticks <= 4 {
				return base.Add(time.Duration(ticks) * time.Second)
			}
			return base.Add(200 * time.Second)
		}
		err := restoreContainers([]containerInfo{orig})
		if err == nil || starts != 3 || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("retries=%d err=%v", starts, err)
		}

		// Service start error does not mask healthy running container
		running := mkState("a", "app", "running", "healthy")
		inspectContainerState = func(string) (containerInfo, error) { return running, nil }
		guardRun = func([]string) (string, error) { return "", refusef("unit restarting") }
		if err := restoreContainers([]containerInfo{running}); err != nil {
			t.Fatalf("daemon start error masked running container: %v", err)
		}
	})
}
