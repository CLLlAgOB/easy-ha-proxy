package fullbackup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func restoreArgs(archive string) restoreOptions {
	return restoreOptions{archive: archive, mode: "overlay", scope: "full", skipSSH: true, passphraseStdin: true, yes: true}
}

func noInput(t *testing.T) {
	t.Helper()
	withStdin(t, passphrase+"\n")
}

func TestRestoreYesSkipsTheConfirmation(t *testing.T) {
	root := t.TempDir()
	encrypted, _ := createTestArchive(t, root, archiveSpec{})
	installedHost(t, root)
	noInput(t)
	record(t, nil)
	quietQuiesce(t)
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { return "", nil })
	swap(t, &managedStatePaths, func(bool) []string { return nil })
	extracted := 0
	swap(t, &extractPayload, func(string, []string) error { extracted++; return nil })
	swap(t, &disableRestoredRuntimeFirewallState, func() ([]string, error) { return nil, nil })
	output := captureStdout(t, func() {
		if err := restoreBackup(restoreArgs(encrypted)); err != nil {
			t.Error(err)
		}
	})
	if extracted != 1 || strings.Contains(output, "Type RESTORE") {
		t.Fatalf("extracted %d output %q", extracted, output)
	}
}

// fakeArchive stands an opened archive in for the decryption.
func fakeArchive(t *testing.T, root string) string {
	t.Helper()
	archive := filepath.Join(root, "backup.enc")
	writeText(t, archive, "encrypted")
	payload := filepath.Join(root, "payload.tar.gz")
	writeText(t, payload, "payload")
	manifest := map[string]any{"hostname": "proxy.example.test", "created_at": "20260718T120000Z",
		"payload_expanded_bytes": jsonInt(1), "ssh_payload_expanded_bytes": nil}
	swap(t, &openBackupArchive, func(string, string, bool) (*openedArchive, error) {
		return &openedArchive{manifest: manifest, payload: payload}, nil
	})
	return payload
}

func jsonInt(n int) any { return json.Number(fmt.Sprint(n)) }

func TestTheControlPlaneIsCheckedBeforeAnythingStops(t *testing.T) {
	root := t.TempDir()
	installedHost(t, root)
	fakeArchive(t, root)
	record(t, nil)
	var events []string
	add := func(event string) { events = append(events, event) }
	swap(t, &newQuiesce, func(bool, bool) quiescer { add("quiesce-created"); return fakeQuiesce{&events} })
	swap(t, &preflightRestoreControlPlane, func() error { add("control-plane-preflight"); return nil })
	swap(t, &managedStatePaths, func(bool) []string { add("managed-paths"); return []string{"/trusted/current-state"} })
	swap(t, &preflightRestoreSpace, func(map[string]any, []string, bool, bool) error { add("space-preflight"); return nil })
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { add("rollback-snapshot"); return "", nil })
	swap(t, &removePaths, func([]string) error { add("remove-managed"); return nil })
	swap(t, &extractPayload, func(string, []string) error { add("extract-candidate"); return nil })
	swap(t, &installRestoredMetrics, func() (bool, error) { return false, nil })
	swap(t, &disableRestoredRuntimeFirewallState, func() ([]string, error) { return nil, nil })
	swap(t, &normalizeRestoredConfigPermissions, func() error { return nil })
	swap(t, &reconcileRestoredHost, func(bool) error { add("reconcile-candidate"); return nil })
	o := restoreArgs(filepath.Join(root, "backup.enc"))
	o.apply, o.replaceManaged = true, true
	captureStdout(t, func() {
		if err := restoreBackup(o); err != nil {
			t.Error(err)
		}
	})
	index := func(event string) int {
		for i, e := range events {
			if e == event {
				return i
			}
		}
		t.Fatalf("no %s in %v", event, events)
		return -1
	}
	for _, later := range []string{"quiesce-created", "rollback-snapshot", "remove-managed", "extract-candidate"} {
		if index("control-plane-preflight") >= index(later) {
			t.Fatalf("%s before the control-plane check: %v", later, events)
		}
	}
	// Reconciliation ends with a status check that needs the quiesced timers
	// active again.
	if index("quiesce-units-resumed") >= index("reconcile-candidate") || index("reconcile-candidate") >= index("quiesce-exited") {
		t.Fatalf("order %v", events)
	}
}

func TestAFailedControlPlaneCheckLeavesTheHostUntouched(t *testing.T) {
	root := t.TempDir()
	installedHost(t, root)
	fakeArchive(t, root)
	touched := []string{}
	swap(t, &preflightRestoreControlPlane, func() error {
		return backupErrorf("Restore control-plane Python dependency check failed with exit code 100: _apt setresuid EPERM")
	})
	swap(t, &newQuiesce, func(bool, bool) quiescer { touched = append(touched, "quiesce"); return fakeQuiesce{&touched} })
	swap(t, &managedStatePaths, func(bool) []string { touched = append(touched, "paths"); return nil })
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { touched = append(touched, "snapshot"); return "", nil })
	swap(t, &removePaths, func([]string) error { touched = append(touched, "remove"); return nil })
	swap(t, &extractPayload, func(string, []string) error { touched = append(touched, "extract"); return nil })
	o := restoreArgs(filepath.Join(root, "backup.enc"))
	o.apply, o.replaceManaged = true, true
	var err error
	captureStdout(t, func() { err = restoreBackup(o) })
	if err == nil || !strings.Contains(err.Error(), "exit code 100: _apt setresuid EPERM") || len(touched) != 0 {
		t.Fatalf("err %v touched %v", err, touched)
	}
}

func TestARestoreStageKeepsItsExitCodeAndStderrTail(t *testing.T) {
	record(t, func(argv []string) (runResult, error) {
		return runResult{Code: 100}, &CommandError{argv, 100, "ordinary output", "E: setresuid 42 failed: Operation not permitted"}
	})
	err := restoreStage("Restore dependency check", []string{"apt-get", "update"}, nil, true)
	if err == nil || err.Error() != "Restore dependency check failed with exit code 100: E: setresuid 42 failed: Operation not permitted" {
		t.Fatalf("err %v", err)
	}
}

func stages(t *testing.T) *[][]string {
	t.Helper()
	calls := &[][]string{}
	swap(t, &restoreStage, func(_ string, argv []string, _ []string, _ bool) error {
		*calls = append(*calls, argv)
		return nil
	})
	return calls
}

func TestTheRollbackReusesThePreparedControlPlane(t *testing.T) {
	source := t.TempDir()
	writeText(t, filepath.Join(source, "install-local.sh"), "#!/usr/bin/env bash\n")
	swap(t, &activateRecoverySource, func() (string, error) { return source, nil })
	os.Unsetenv(offlineRestoreEnv)
	calls := stages(t)
	if err := reconcileRestoredHost(true); err != nil {
		t.Fatal(err)
	}
	candidate := *calls
	*calls = nil
	if err := reconcileRestoredHost(false); err != nil {
		t.Fatal(err)
	}
	if len(candidate) != 2 || !reflect.DeepEqual(candidate[0][len(candidate[0])-2:], []string{"--prepare-only", "--skip-bootstrap-dependencies"}) ||
		has(candidate[0], "apt-get") {
		t.Fatalf("candidate %q", candidate)
	}
	if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], []string{"/usr/local/bin/easy-ha-proxy", "apply-restored"}) {
		t.Fatalf("rollback %q", *calls)
	}
}

func has(list []string, value string) bool { return contains(list, value) }

func TestTheBrokersOfflineModeReachesBothReconciles(t *testing.T) {
	source := t.TempDir()
	writeText(t, filepath.Join(source, "install-local.sh"), "#!/usr/bin/env bash\n")
	swap(t, &activateRecoverySource, func() (string, error) { return source, nil })
	t.Setenv(offlineRestoreEnv, "1")
	calls := stages(t)
	want := []string{"/usr/local/bin/easy-ha-proxy", "apply-restored", "--offline"}
	for _, prepare := range []bool{true, false} {
		*calls = nil
		if err := reconcileRestoredHost(prepare); err != nil {
			t.Fatal(err)
		}
		if last := (*calls)[len(*calls)-1]; !reflect.DeepEqual(last, want) {
			t.Fatalf("prepare=%v: %q", prepare, last)
		}
	}
}

func TestTheRecoverySourceArchivePathAvoidsCollisions(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "source")
	first, _ := recoverySourceArchivePath(managed, "20260719T080000000000Z", 123)
	_ = os.Mkdir(first, 0o700)
	second, _ := recoverySourceArchivePath(managed, "20260719T080000000000Z", 123)
	if second != first+".1" {
		t.Fatalf("second %s", second)
	}
}

func candidateFailure(t *testing.T, root string, reconcile func(bool) error) (*[]string, *[]bool, *[]string, error) {
	t.Helper()
	installedHost(t, root)
	payload := fakeArchive(t, root)
	rollback := filepath.Join(root, "previous-state.tar.gz")
	writeText(t, rollback, "rollback")
	record(t, nil)
	quietQuiesce(t)
	swap(t, &preflightRestoreControlPlane, func() error { return nil })
	swap(t, &managedStatePaths, func(bool) []string { return nil })
	swap(t, &preflightRestoreSpace, func(map[string]any, []string, bool, bool) error { return nil })
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { return rollback, nil })
	swap(t, &removePaths, func([]string) error { return nil })
	extracted := &[]string{}
	swap(t, &extractPayload, func(p string, _ []string) error { *extracted = append(*extracted, p); return nil })
	swap(t, &installRestoredMetrics, func() (bool, error) { return false, nil })
	swap(t, &disableRestoredRuntimeFirewallState, func() ([]string, error) { return nil, nil })
	swap(t, &normalizeRestoredConfigPermissions, func() error { return nil })
	swap(t, &validateRollbackPayload, func(string, bool) error { return nil })
	swap(t, &removeManagedState, func(bool) error { return nil })
	reconciles := &[]bool{}
	swap(t, &reconcileRestoredHost, func(prepare bool) error { *reconciles = append(*reconciles, prepare); return reconcile(prepare) })
	cleaned := &[]string{}
	swap(t, &cleanupPreRestoreBackup, func(p string) { *cleaned = append(*cleaned, p) })
	o := restoreArgs(filepath.Join(root, "backup.enc"))
	o.apply, o.replaceManaged = true, true
	var err error
	captureStdout(t, func() { err = restoreBackup(o) })
	_ = payload
	return extracted, reconciles, cleaned, err
}

func TestACandidateFailureRollsBackWithoutRepeatingTheBootstrap(t *testing.T) {
	root := t.TempDir()
	extracted, reconciles, cleaned, err := candidateFailure(t, root, func(prepare bool) error {
		if prepare {
			return backupErrorf("candidate apply failed")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "previous managed state was restored automatically") ||
		strings.Contains(err.Error(), "automatic rollback also failed") {
		t.Fatalf("err %v", err)
	}
	payload, rollback := filepath.Join(root, "payload.tar.gz"), filepath.Join(root, "previous-state.tar.gz")
	if !reflect.DeepEqual(*reconciles, []bool{true, false}) || !reflect.DeepEqual(*extracted, []string{payload, rollback}) ||
		!reflect.DeepEqual(*cleaned, []string{rollback}) {
		t.Fatalf("reconciles %v extracted %v cleaned %v", *reconciles, *extracted, *cleaned)
	}
}

func TestReplaceRestoreUsesTrustedPathsAndRollsBack(t *testing.T) {
	root := t.TempDir()
	encrypted, _ := createTestArchive(t, root, archiveSpec{})
	installedHost(t, root)
	noInput(t)
	record(t, nil)
	quietQuiesce(t)
	rollback := filepath.Join(root, "previous-state.tar.gz")
	writeText(t, rollback, "rollback")
	swap(t, &managedStatePaths, func(bool) []string { return []string{"/trusted/current-state"} })
	swap(t, &preflightRestoreSpace, func(map[string]any, []string, bool, bool) error { return nil })
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { return rollback, nil })
	swap(t, &preflightRestoreControlPlane, func() error { return nil })
	var removed [][]string
	swap(t, &removePaths, func(p []string) error { removed = append(removed, p); return nil })
	swap(t, &extractPayload, func(string, []string) error { return nil })
	swap(t, &installRestoredMetrics, func() (bool, error) { return false, nil })
	swap(t, &disableRestoredRuntimeFirewallState, func() ([]string, error) { return nil, nil })
	swap(t, &normalizeRestoredConfigPermissions, func() error { return nil })
	swap(t, &reconcileRestoredHost, func(bool) error { return errors.New("candidate apply failed") })
	type previous struct {
		rollback   string
		ssh, apply bool
	}
	var restored []previous
	swap(t, &restorePreviousState, func(r string, ssh, apply bool) error {
		restored = append(restored, previous{r, ssh, apply})
		return nil
	})
	var cleaned []string
	swap(t, &cleanupPreRestoreBackup, func(p string) { cleaned = append(cleaned, p) })
	o := restoreArgs(encrypted)
	o.apply, o.replaceManaged = true, true
	var err error
	captureStdout(t, func() { err = restoreBackup(o) })
	if err == nil || !strings.Contains(err.Error(), "restored automatically") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(removed, [][]string{{"/trusted/current-state"}}) || !reflect.DeepEqual(restored, []previous{{rollback, false, true}}) ||
		!reflect.DeepEqual(cleaned, []string{rollback}) {
		t.Fatalf("removed %v restored %v cleaned %v", removed, restored, cleaned)
	}
}

func TestAFailedRollbackKeepsTheSafetyArchive(t *testing.T) {
	root := t.TempDir()
	encrypted, _ := createTestArchive(t, root, archiveSpec{})
	installedHost(t, root)
	noInput(t)
	record(t, nil)
	quietQuiesce(t)
	rollback := filepath.Join(root, "previous-state.tar.gz")
	writeText(t, rollback, "rollback")
	swap(t, &managedStatePaths, func(bool) []string { return nil })
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { return rollback, nil })
	swap(t, &removePaths, func([]string) error { return nil })
	swap(t, &extractPayload, func(string, []string) error { return errors.New("candidate extraction failed") })
	swap(t, &restorePreviousState, func(string, bool, bool) error { return errors.New("rollback extraction failed") })
	cleaned := 0
	swap(t, &cleanupPreRestoreBackup, func(string) { cleaned++ })
	o := restoreArgs(encrypted)
	o.replaceManaged = true
	var err error
	captureStdout(t, func() { err = restoreBackup(o) })
	if err == nil || !strings.Contains(err.Error(), "automatic rollback also failed") || !strings.Contains(err.Error(), rollback) || cleaned != 0 {
		t.Fatalf("err %v cleaned %d", err, cleaned)
	}
}

func TestRestoreModesAndScopes(t *testing.T) {
	root := t.TempDir()
	config := installedHost(t, root)
	fakeArchive(t, root)
	for _, tc := range []struct {
		mode, scope string
		ssh         bool
		installed   bool
		message     string
	}{
		{"fresh", "full", false, true, "Fresh restore refuses"},
		{"overlay", "full", false, false, "requires an existing managed installation"},
		{"auto", "config", false, false, "requires an installed server"},
		{"overlay", "config", true, true, "SSH keys are not part"},
	} {
		if tc.installed {
			writeText(t, filepath.Join(config, "metadata.yml"), "x\n")
		} else {
			_ = os.Remove(filepath.Join(config, "metadata.yml"))
		}
		o := restoreArgs(filepath.Join(root, "backup.enc"))
		o.mode, o.scope, o.restoreSSH = tc.mode, tc.scope, tc.ssh
		if err := restoreBackup(o); err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestATypedNoCancelsTheRestore(t *testing.T) {
	root := t.TempDir()
	installedHost(t, root)
	fakeArchive(t, root)
	withStdin(t, "nope\n")
	o := restoreArgs(filepath.Join(root, "backup.enc"))
	o.yes = false
	var err error
	captureStdout(t, func() { err = restoreBackup(o) })
	if err == nil || err.Error() != "Restore cancelled." {
		t.Fatalf("err %v", err)
	}
}

func TestThePreflightRefusesTooLittleRollbackSpace(t *testing.T) {
	swap(t, &managedPathsApparentUsage, func([]string) (int64, int64, map[uint64]bool, error) {
		return 50, 2, map[uint64]bool{7: true}, nil
	})
	swap(t, &existingAncestor, func(p string) (string, error) { return p, nil })
	swap(t, &deviceOf, func(string) (uint64, error) { return 7, nil })
	swap(t, &diskUsage, func(string) (usage, error) { return usage{free: 199}, nil })
	saved := limit
	t.Cleanup(func() { limit = saved })
	limit.restoreMinFree, limit.rollbackBase, limit.rollbackPerMember = 100, 20, 5
	manifest := map[string]any{"payload_expanded_bytes": jsonInt(100), "ssh_payload_expanded_bytes": nil}
	// Exact replacement reclaims 50 bytes, but the rollback (80), the growth
	// (50) and the reserve (100) still need 230.
	if err := preflightRestoreSpace(manifest, []string{"/managed"}, true, false); err == nil || !strings.Contains(err.Error(), "Not enough free space") {
		t.Fatalf("err %v", err)
	}
	swap(t, &diskUsage, func(string) (usage, error) { return usage{free: 230}, nil })
	if err := preflightRestoreSpace(manifest, []string{"/managed"}, true, false); err != nil {
		t.Fatalf("enough space refused: %v", err)
	}
}

func TestActivatingTheRecoverySourceKeepsTheArchivedOne(t *testing.T) {
	root := t.TempDir()
	recovery, managed := filepath.Join(root, "recovery"), filepath.Join(root, "managed-source")
	for _, rel := range []string{"install-local.sh", "installer/easy-ha-proxy", "installer/agent-fetch.sh", "ansible/easy-ha-proxy.yml"} {
		writeText(t, filepath.Join(recovery, rel), "recovery: "+rel+"\n")
	}
	if err := os.Symlink("installer/easy-ha-proxy", filepath.Join(recovery, "link")); err != nil {
		t.Fatal(err)
	}
	writeText(t, filepath.Join(managed, "archived.txt"), "from backup\n")
	swap(t, &managedSource, managed)
	t.Setenv("EASY_HA_PROXY_SOURCE_DIR", recovery)
	r := record(t, nil)
	var result string
	captureStdout(t, func() {
		var err error
		if result, err = activateRecoverySource(); err != nil {
			t.Error(err)
		}
	})
	if result != managed || !isFile(filepath.Join(managed, "installer/easy-ha-proxy")) || !isSymlink(filepath.Join(managed, "link")) {
		t.Fatal("the recovery source is not in place")
	}
	preserved, _ := filepath.Glob(filepath.Join(root, "source.from-backup.*"))
	if len(preserved) != 1 || readText(t, filepath.Join(preserved[0], "archived.txt")) != "from backup\n" {
		t.Fatalf("preserved %v", preserved)
	}
	if len(r.calls) != 1 || r.calls[0][0] != "chown" || os.Getenv("EASY_HA_PROXY_SOURCE_DIR") != managed {
		t.Fatalf("calls %v", r.calls)
	}
}

func TestTheRestoredRuntimeFirewallStateIsKeptButDisabled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/iptables")
	writeText(t, filepath.Join(dir, "rules.v4"), "*nat\n:DOCKER - [0:0]\nCOMMIT\n")
	writeText(t, filepath.Join(dir, "rules.v6"), "*filter\nCOMMIT\n")
	writeText(t, filepath.Join(dir, "haproxy_ban.rules"), "*filter\n:HP_BAN - [0:0]\nCOMMIT\n")
	swap(t, &iptablesDir, dir)
	var disabled []string
	captureStdout(t, func() { disabled, _ = disableRestoredRuntimeFirewallState() })
	v4, _ := filepath.Glob(filepath.Join(dir, "rules.v4.restored-disabled.*"))
	v6, _ := filepath.Glob(filepath.Join(dir, "rules.v6.restored-disabled.*"))
	if len(disabled) != 2 || lexists(filepath.Join(dir, "rules.v4")) || lexists(filepath.Join(dir, "rules.v6")) ||
		!lexists(filepath.Join(dir, "haproxy_ban.rules")) || len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("disabled %v", disabled)
	}
}

func TestTheKeysThatCouldLogInBeforeAreKept(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "root/.ssh/authorized_keys")
	writeText(t, keys, "ssh-ed25519 operator\n\nssh-ed25519 shared\n")
	swap(t, &rootAuthorizedKeys, keys)
	swap(t, &authorizedKeysGlob, filepath.Join(root, "home/*/.ssh/authorized_keys"))
	saved := currentAuthorizedKeys()
	writeText(t, keys, "ssh-ed25519 shared\nssh-ed25519 from-backup\n")
	if err := mergeAuthorizedKeys(saved); err != nil {
		t.Fatal(err)
	}
	if got := readText(t, keys); got != "ssh-ed25519 shared\nssh-ed25519 from-backup\nssh-ed25519 operator\n" {
		t.Fatalf("keys %q", got)
	}
	if fi, _ := os.Stat(keys); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	link := filepath.Join(root, "link_keys")
	_ = os.Symlink(keys, link)
	if err := mergeAuthorizedKeys(map[string]keyFile{link: {}}); err == nil {
		t.Fatal("merged through a symbolic link")
	}
}

// A failed configuration-scope restore leaves the fixed roots as they were,
// including one the attempt created.

type configRestore struct {
	existing, absent string
}

func newConfigRestore(t *testing.T) configRestore {
	base := t.TempDir()
	c := configRestore{existing: filepath.Join(base, "haproxy"), absent: filepath.Join(base, "letsencrypt")}
	swap(t, &configScopePaths, []string{c.existing, c.absent})
	swap(t, &configScopeMembers, func(string) ([]string, error) { return []string{"haproxy", "letsencrypt"}, nil })
	swap(t, &preflightRestoreControlPlane, func() error { return nil })
	swap(t, &normalizeRestoredConfigPermissions, func() error { return nil })
	swap(t, &validateRollbackPayload, func(string, bool) error { return nil })
	swap(t, &cleanupPreRestoreBackup, func(string) {})
	swap(t, &DefaultBackupRoot, filepath.Join(base, "backups"))
	calls := 0
	swap(t, &reconcileRestoredConfiguration, func() error {
		calls++
		if calls == 1 {
			return errors.New("apply failed")
		}
		return nil
	})
	swap(t, &extractPayload, func(_ string, members []string) error {
		_ = os.MkdirAll(c.existing, 0o755)
		if members != nil {
			// The candidate changes one root and creates the other.
			writeText(t, filepath.Join(c.existing, "haproxy.cfg"), "from the archive\n")
			writeText(t, filepath.Join(c.absent, "privkey.pem"), "archive key\n")
		} else {
			// The rollback archive holds what existed: the first root only.
			writeText(t, filepath.Join(c.existing, "haproxy.cfg"), "original\n")
		}
		return nil
	})
	return c
}

func (c configRestore) restore(t *testing.T) string {
	var err error
	captureStdout(t, func() {
		err = restoreConfigScope(restoreOptions{yes: true, apply: true}, map[string]any{}, "candidate.tar.gz")
	})
	if err == nil {
		t.Fatal("the restore did not fail")
	}
	return err.Error()
}

func TestARootTheAttemptCreatedIsGoneAfterTheRollback(t *testing.T) {
	c := newConfigRestore(t)
	writeText(t, filepath.Join(c.existing, "haproxy.cfg"), "original\n")
	swap(t, &createPreRestoreBackup, func([]string) (string, error) { return "previous-state.tar.gz", nil })
	message := c.restore(t)
	if !strings.Contains(message, "restored automatically") || readText(t, filepath.Join(c.existing, "haproxy.cfg")) != "original\n" ||
		lexists(c.absent) {
		t.Fatalf("message %q", message)
	}
}

func TestWithNoRootBeforeEverythingWrittenIsRemoved(t *testing.T) {
	c := newConfigRestore(t)
	message := c.restore(t) // the real snapshot: nothing to keep, no archive
	if !strings.Contains(message, "removed again") || lexists(c.existing) || lexists(c.absent) {
		t.Fatalf("message %q", message)
	}
}

func TestTheQuiesceUnwindsAfterAPartialEntryFailure(t *testing.T) {
	swap(t, &quiesceUnits, []string{"first.service", "second.service"})
	swap(t, &which, func(name string) bool { return name == "systemctl" })
	r := record(t, func(argv []string) (runResult, error) {
		if reflect.DeepEqual(argv, []string{"systemctl", "stop", "second.service"}) {
			return runResult{}, errors.New("simulated stop failure")
		}
		return runResult{}, nil
	})
	q := &quiesce{enabled: true}
	if err := q.enter(); err == nil || !strings.Contains(err.Error(), "simulated stop failure") {
		t.Fatalf("err %v", err)
	}
	if !r.ran("systemctl", "start", "first.service") || len(q.units) != 0 || len(q.containers) != 0 {
		t.Fatalf("calls %v", r.calls)
	}
}

func TestReplaceManagedPreservesBrokerSpoolAndRecoverySource(t *testing.T) {
	root := t.TempDir()
	varLib := filepath.Join(root, "var/lib/easy-ha-proxy")
	auditFile := filepath.Join(varLib, "audit/audit.db")
	strayFile := filepath.Join(varLib, "stray.tmp")
	localBackup := filepath.Join(varLib, "backup-web/backups/existing.tar.gz.enc")
	jobStderr := filepath.Join(varLib, "backup-web/jobs/.job-abc.stderr")
	recoveryFile := filepath.Join(varLib, "backup-web/jobs/.0123.recovery-source/install-local.sh")
	updatePlan := filepath.Join(varLib, "update-web/latest-plan.json")
	migrationState := filepath.Join(varLib, "haproxy-package-migration/last-migration.json")
	nativeStage := filepath.Join(varLib, "native-staging/image.json")
	writeText(t, auditFile, "old-audit")
	writeText(t, strayFile, "remove-me")
	writeText(t, localBackup, "keep-backup")
	writeText(t, jobStderr, "live-stderr")
	writeText(t, recoveryFile, "#!/bin/sh\n")
	writeText(t, updatePlan, "{}")
	writeText(t, migrationState, "{}")
	writeText(t, nativeStage, "{}")

	preserved := []string{
		filepath.Join(varLib, "backup-web"),
		filepath.Join(varLib, "update-web"),
		filepath.Join(varLib, "haproxy-package-migration"),
		filepath.Join(varLib, "native-staging"),
	}
	swap(t, &restorePreservedPaths, preserved)

	// Apparent usage must skip preserved subtrees (like gigabytes of local backups).
	usedBytes, _, _, err := managedPathsApparentUsage([]string{varLib})
	if err != nil {
		t.Fatalf("apparent usage: %v", err)
	}
	wantBytes := int64(len("old-audit") + len("remove-me"))
	if usedBytes != wantBytes {
		t.Fatalf("apparent usage included preserved files: got %d, want %d", usedBytes, wantBytes)
	}

	// removePaths on /var/lib/easy-ha-proxy must delete managed data while keeping broker state.
	if err := removePaths([]string{varLib}); err != nil {
		t.Fatalf("removePaths: %v", err)
	}
	for _, gone := range []string{auditFile, filepath.Dir(auditFile), strayFile} {
		if lexists(gone) {
			t.Fatalf("managed path should have been removed: %s", gone)
		}
	}
	for _, kept := range []string{localBackup, jobStderr, recoveryFile, updatePlan, migrationState, nativeStage} {
		if !lexists(kept) {
			t.Fatalf("preserved host path was deleted: %s", kept)
		}
	}

	// Full extractPayload must exclude preserved subtrees so an archive cannot clobber live jobs.
	r := record(t, nil)
	if err := extractPayload("/tmp/payload.tar.gz", nil); err != nil {
		t.Fatalf("extractPayload: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected 1 tar call, got %v", r.calls)
	}
	wantExclude := "--exclude=" + strings.TrimLeft(filepath.Join(varLib, "backup-web"), "/")
	if !contains(r.calls[0], wantExclude) {
		t.Fatalf("extractPayload argv missing %q: %v", wantExclude, r.calls[0])
	}
}
