package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func resetLockHooks(t *testing.T) {
	t.Helper()
	origLockPath := maintenanceLockPath
	origBrokerFn := startedByUpdateBrokerFn
	origReqRoot := requireRootFn
	origRebootReq := rebootRequiredFn
	origRebootMarker := rebootScheduleMarker
	origWebMarker := webRebootScheduleMarker
	origSchedFn := scheduleServerRebootFn
	origOfferFn := offerPendingRebootFn
	origLookPath := lookPath
	origSubproc := runSubprocessFn
	origRunCmd := runCommandFn
	origPlaybook := runPlaybookFn
	origConfigDir := configDirOverride
	origRuntimeHA := runtimeHAProxyConfigDir
	origDNSPreflight := dnsPreflightFn
	origRecordApplied := recordAppliedSourceFn
	origConfigureInt := configureIntFn

	t.Cleanup(func() {
		ReleaseMaintenanceLock()
		maintenanceLockPath = origLockPath
		startedByUpdateBrokerFn = origBrokerFn
		requireRootFn = origReqRoot
		rebootRequiredFn = origRebootReq
		rebootScheduleMarker = origRebootMarker
		webRebootScheduleMarker = origWebMarker
		scheduleServerRebootFn = origSchedFn
		offerPendingRebootFn = origOfferFn
		lookPath = origLookPath
		runSubprocessFn = origSubproc
		runCommandFn = origRunCmd
		runPlaybookFn = origPlaybook
		configDirOverride = origConfigDir
		runtimeHAProxyConfigDir = origRuntimeHA
		dnsPreflightFn = origDNSPreflight
		recordAppliedSourceFn = origRecordApplied
		configureIntFn = origConfigureInt
	})
}

func assertFlockBusy(t *testing.T, lockFile string) {
	t.Helper()
	fd, err := unix.Open(lockFile, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatalf("expected flock on %s to be held, but acquired it", lockFile)
	}
}

func TestMaintenanceLockAcquireContendAndInherit(t *testing.T) {
	resetLockHooks(t)
	lockPath := filepath.Join(t.TempDir(), "run", "operation.lock")
	startedByUpdateBrokerFn = func() bool { return false }
	t.Setenv(MaintenanceLockHeldEnv, "")
	_ = os.Unsetenv(MaintenanceLockHeldEnv)

	if err := HoldMaintenanceLock(lockPath); err != nil {
		t.Fatalf("HoldMaintenanceLock failed: %v", err)
	}
	if os.Getenv(MaintenanceLockHeldEnv) != "cli" {
		t.Fatalf("expected env cli, got %q", os.Getenv(MaintenanceLockHeldEnv))
	}
	assertFlockBusy(t, lockPath)
	ReleaseMaintenanceLock()

	// Contended by another holder.
	holder, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(holder)
	if err := unix.Flock(holder, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := HoldMaintenanceLock(lockPath); err == nil || !strings.Contains(err.Error(), "Another maintenance operation") {
		t.Fatalf("expected contention error, got %v", err)
	}
	if os.Getenv(MaintenanceLockHeldEnv) != "" {
		t.Fatalf("env should not be set on failure")
	}

	// Already held via env or update broker cgroup.
	for _, val := range []string{"updated", "cli"} {
		t.Setenv(MaintenanceLockHeldEnv, val)
		if err := HoldMaintenanceLock(lockPath); err != nil {
			t.Fatalf("expected inherited lock (%s) to pass: %v", val, err)
		}
		if maintenanceLockFD != -1 {
			t.Fatalf("should not open a new fd when inherited")
		}
	}
	_ = os.Unsetenv(MaintenanceLockHeldEnv)
	startedByUpdateBrokerFn = func() bool { return true }
	if err := HoldMaintenanceLock(lockPath); err != nil {
		t.Fatalf("expected broker job to pass: %v", err)
	}
}

func TestStartedByUpdateBrokerCgroup(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if !StartedByUpdateBroker(write("job", "0::/system.slice/easy-ha-proxy-updated-job-e4ea21b3f3d3.service\n")) {
		t.Fatal("expected v2 job cgroup to match")
	}
	if !StartedByUpdateBroker(write("legacy", "12:pids:/system.slice/easy-ha-proxy-updated-job-0123456789ab.service\n0::/system.slice/easy-ha-proxy-updated-job-0123456789ab.service\n")) {
		t.Fatal("expected legacy job cgroup to match")
	}
	for _, tc := range []string{
		"0::/user.slice/user-0.slice/session-3.scope\n",
		"0::/system.slice/ehp-test-update.service\n",
		"0::/system.slice/easy-ha-proxy-updated.service\n",
	} {
		if StartedByUpdateBroker(write("other", tc)) {
			t.Fatalf("did not expect %q to match", tc)
		}
	}
	if StartedByUpdateBroker("/nonexistent/cgroup") {
		t.Fatal("nonexistent cgroup must return false")
	}
}

func TestMutatingCommandsRefuseWhenLockHeldAndDisplayChannelsDoesNot(t *testing.T) {
	resetLockHooks(t)
	root := t.TempDir()
	lockPath := filepath.Join(root, "operation.lock")
	cfgDir := filepath.Join(root, "config")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = WriteText(filepath.Join(cfgDir, "metadata.yml"), "source_channel: github\nimage_channel: latest\n", 0o600)

	maintenanceLockPath = lockPath
	configDirOverride = cfgDir
	startedByUpdateBrokerFn = func() bool { return false }
	requireRootFn = func() error { return nil }
	_ = os.Unsetenv(MaintenanceLockHeldEnv)

	holder, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(holder)
	if err := unix.Flock(holder, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	playbookCalled := false
	runPlaybookFn = func(_ *Context, _ string, _ PlaybookOptions) error {
		playbookCalled = true
		return nil
	}

	for _, argv := range [][]string{
		{"configure"},
		{"configure", "--apply"},
		{"install"},
		{"install", "--reconfigure"},
		{"language", "--language", "ru", "--apply"},
		{"migrate-domain", "--new-domain", "new.example.test"},
		{"promote-production", "--new-domain", "new.example.test"},
		{"set-channels", "--release-channel", "alpha"},
	} {
		var out, errOut bytes.Buffer
		rc := RunCLI(argv, strings.NewReader(""), &out, &errOut)
		if rc != 2 {
			t.Fatalf("expected exit 2 for %v under held lock, got %d (%s)", argv, rc, errOut.String())
		}
	}
	if playbookCalled {
		t.Fatal("playbook must not run when maintenance lock is contended")
	}

	// Displaying channels needs no mutation lock.
	var out, errOut bytes.Buffer
	if rc := RunCLI([]string{"set-channels"}, strings.NewReader(""), &out, &errOut); rc != 0 {
		t.Fatalf("expected exit 0 for read-only set-channels, got %d (%s)", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "release_channel=stable") {
		t.Fatalf("unexpected set-channels output: %s", out.String())
	}

	// apply-restored runs under backupd's existing lock without reacquiring.
	_ = WriteText(filepath.Join(cfgDir, "secrets.yml"), "haproxy_admin_proxy_secret: present\n", 0o600)
	for _, scope := range []string{"full", "config"} {
		out.Reset()
		errOut.Reset()
		rc := RunCLI([]string{"apply-restored", "--scope", scope}, strings.NewReader(""), &out, &errOut)
		if rc != 0 {
			t.Fatalf("expected apply-restored --scope %s to succeed under parent lock, got %d (%s)", scope, rc, errOut.String())
		}
	}
}

func TestRebootFlowScheduleAndMarkerCleanup(t *testing.T) {
	resetLockHooks(t)
	root := t.TempDir()
	marker := filepath.Join(root, "run/easy-ha-proxy/reboot-scheduled")
	rebootScheduleMarker = marker
	webRebootScheduleMarker = filepath.Join(root, "no-web-reboot.json")
	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	var ran [][]string
	runCommandFn = func(_ ioWriter, command []string, _ []string) error {
		ran = append(ran, command)
		return nil
	}
	var out bytes.Buffer
	if err := ScheduleServerReboot(&out); err != nil {
		t.Fatalf("ScheduleServerReboot failed: %v", err)
	}
	if len(ran) != 1 || ran[0][0] != "/usr/bin/systemd-run" {
		t.Fatalf("unexpected command: %v", ran)
	}
	unitRe := regexp.MustCompile(`^--unit=easy-ha-proxy-reboot-[0-9]{14}-[0-9]+-[0-9a-f]{8}$`)
	if !unitRe.MatchString(ran[0][1]) {
		t.Fatalf("unexpected unit flag: %s", ran[0][1])
	}
	if !strings.Contains(strings.Join(ran[0], " "), "--on-active=30s") {
		t.Fatalf("missing --on-active=30s in %v", ran[0])
	}
	if !fileExists(marker) || !strings.Contains(out.String(), "EASY_HA_PROXY_REBOOT_SCHEDULED=1") {
		t.Fatalf("marker or scheduled token missing: %s", out.String())
	}

	// Stale marker is removed when systemctl is-active returns 3.
	runSubprocessFn = func(name string, args ...string) subprocessResult {
		return subprocessResult{ExitCode: 3}
	}
	if RebootScheduleIsActive() {
		t.Fatal("expected inactive schedule for exit code 3")
	}
	if fileExists(marker) {
		t.Fatal("stale marker should have been removed")
	}

	// Failed systemd-run removes marker.
	runCommandFn = func(_ ioWriter, _ []string, _ []string) error {
		if !fileExists(marker) {
			t.Fatal("marker should exist before systemd-run runs")
		}
		return errors.New("systemd-run failed")
	}
	if err := ScheduleServerReboot(&out); err == nil {
		t.Fatal("expected error from failed systemd-run")
	}
	if fileExists(marker) {
		t.Fatal("marker must be cleaned up on failure")
	}
}

type ioWriter = io.Writer

func TestOfferPendingRebootDeferAndAccept(t *testing.T) {
	resetLockHooks(t)
	rebootRequiredFn = func() bool { return true }
	scheduled := 0
	scheduleServerRebootFn = func(_ ioWriter) error {
		scheduled++
		return nil
	}
	t.Setenv("EASY_HA_PROXY_REBOOT_DECISION", "")
	_ = os.Unsetenv("EASY_HA_PROXY_REBOOT_DECISION")

	var out bytes.Buffer
	ctx := NewContext(strings.NewReader(""), &out, &out)
	ctx.isTTYFn = func() bool { return false }
	accepted, err := OfferPendingReboot(ctx, false)
	if err != nil || accepted || scheduled != 0 {
		t.Fatalf("non-interactive reboot should defer: accepted=%v scheduled=%d err=%v", accepted, scheduled, err)
	}
	if !strings.Contains(out.String(), "Reboot deferred") {
		t.Fatalf("expected deferred notice: %s", out.String())
	}

	t.Setenv("EASY_HA_PROXY_REBOOT_DECISION", "yes")
	accepted, err = OfferPendingReboot(ctx, false)
	if err != nil || !accepted || scheduled != 1 {
		t.Fatalf("explicit yes env should schedule reboot: accepted=%v scheduled=%d err=%v", accepted, scheduled, err)
	}
}
