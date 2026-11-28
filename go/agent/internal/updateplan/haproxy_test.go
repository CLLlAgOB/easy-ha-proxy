package updateplan

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Version truth and package-update isolation for HAProxy.

type versionFixture struct {
	t                                   *testing.T
	root, binary, protection, osRelease string
	pkg, installed, candidate           string
	held, remote, qualifiedHost         bool
	runtime, metadata                   M
	runtimeErr                          error
	lastUpdate, lastMigration           string
	calls                               [][]string
}

func newVersionFixture(t *testing.T) *versionFixture {
	f := &versionFixture{t: t, root: t.TempDir(), pkg: "haproxy-awslc", installed: "3.4.7-0+ha34+ubuntu24.04u2",
		held: true, remote: true, qualifiedHost: true, metadata: M{"fresh": true}}
	f.candidate = f.installed
	f.binary = filepath.Join(f.root, "haproxy")
	writeFile(t, f.binary, "fixture")
	f.protection = filepath.Join(f.root, "needrestart.conf")
	writeFile(t, f.protection, guardedRestartLine)
	f.runtime = M{"running_version": f.installed, "binary_matches": true, "replaced_libraries": []any{}}
	f.lastUpdate = filepath.Join(f.root, "absent")
	f.osRelease = filepath.Join(f.root, "os-release")
	savedRelease, savedMachine, savedReader := osReleasePath, machine, runtimeReader
	t.Cleanup(func() { osReleasePath, machine, runtimeReader = savedRelease, savedMachine, savedReader })
	return f
}

func (f *versionFixture) Run(argv []string, _ time.Duration) CommandResult {
	f.calls = append(f.calls, argv)
	switch {
	case argv[0] == "dpkg-query":
		if last(argv) == f.pkg {
			return ok("installed\t" + f.installed)
		}
		return failed(1, "")
	case hasPrefix(argv, "apt-cache", "policy"):
		remote := ""
		if f.remote {
			remote = " 990 https://example.test noble/main amd64 Packages\n"
		}
		return ok("  Installed: " + f.installed + "\n  Candidate: " + f.candidate + "\n" + remote)
	case is(argv, "dpkg", "--get-selections"):
		if f.held {
			return ok(f.pkg + "\thold\nlibssl-awslc\thold")
		}
		return ok("")
	case hasPrefix(argv, "dpkg", "--compare-versions"):
		if f.candidate > f.installed {
			return ok("")
		}
		return failed(1, "")
	}
	return unexpected(argv)
}

func (f *versionFixture) probe() M {
	release := "ID=ubuntu\nVERSION_ID=\"24.04\"\n"
	if !f.qualifiedHost {
		release = "ID=debian\nVERSION_ID=\"13\"\n"
	}
	writeFile(f.t, f.osRelease, release)
	osReleasePath = f.osRelease
	machine = func() string { return "aarch64" }
	runtimeReader = func(string) (M, error) {
		if f.runtimeErr != nil {
			return nil, f.runtimeErr
		}
		out := M{}
		for k, v := range f.runtime {
			out[k] = v
		}
		return out, nil
	}
	return probeHAProxy(f, haproxyPaths{binary: f.binary, lastUpdate: f.lastUpdate, lastMigration: f.lastMigration,
		protection: f.protection}, f.metadata)
}

func TestInstalledRunningAndCandidateAreDistinctFields(t *testing.T) {
	f := newVersionFixture(t)
	result := f.probe()
	d := details(result)
	if result["state"] != "current" || d["installed_version"] != f.installed || d["running_version"] != f.installed ||
		d["candidate_version"] != f.candidate {
		t.Fatalf("result %v", result)
	}
	if _, found := result["candidate"]; found {
		t.Fatal("the HAProxy component has no candidate alias")
	}
}

func TestAPatchIsOfferedButABranchJumpAndDowngradeAreBlocked(t *testing.T) {
	f := newVersionFixture(t)
	for version, want := range map[string]string{"3.4.8-1": "available", "3.5.0-1": "blocked", "3.4.6-1": "blocked"} {
		f.candidate = version
		if got := f.probe()["state"]; got != want {
			t.Fatalf("%s: %v", version, got)
		}
	}
}

func TestFailedMetadataDoesNotClaimNoUpdates(t *testing.T) {
	f := newVersionFixture(t)
	f.metadata = M{"fresh": false}
	if got := f.probe()["state"]; got != "unknown" {
		t.Fatalf("state %v", got)
	}
}

func TestADiskRuntimeMismatchIsNeverASuccessfulUpdate(t *testing.T) {
	f := newVersionFixture(t)
	f.runtime["binary_matches"] = false
	if got := f.probe()["state"]; got != "blocked" {
		t.Fatalf("state %v", got)
	}
	// Manual upgrade guidance is not offered when runtime recovery is required.
	f.qualifiedHost = false
	if _, found := details(f.probe())["manual_update"]; found {
		t.Fatal("manual update offered")
	}
}

func TestAnUnreadableRuntimeIsUnknown(t *testing.T) {
	f := newVersionFixture(t)
	f.runtimeErr = errors.New("no socket")
	if got := f.probe()["state"]; got != "unknown" {
		t.Fatalf("state %v", got)
	}
}

func TestReplacedLibrariesOfferAStatePreservingReloadAtTheSameVersion(t *testing.T) {
	f := newVersionFixture(t)
	f.runtime["replaced_libraries"] = []any{"libc.so.6"}
	result := f.probe()
	if result["state"] != "available" || details(result)["needs_reload"] != true || result["current_version"] != result["available_version"] {
		t.Fatalf("result %v", result)
	}
}

func TestAMissingHoldOrRestartGuardBlocksTheControlledAction(t *testing.T) {
	f := newVersionFixture(t)
	f.held = false
	if got := f.probe()["state"]; got != "blocked" {
		t.Fatalf("without hold: %v", got)
	}
	f.held = true
	f.protection = filepath.Join(f.root, "absent.conf")
	if got := f.probe()["state"]; got != "blocked" {
		t.Fatalf("without guard: %v", got)
	}
}

func TestTheDistributionPackageIsDetected(t *testing.T) {
	f := newVersionFixture(t)
	f.pkg = "haproxy"
	f.installed, f.candidate = "2.8.30-0ubuntu0.24.04.2", "2.8.30-0ubuntu0.24.04.2"
	f.runtime["running_version"] = f.installed
	result := f.probe()
	if details(result)["branch"] != "2.8" || result["state"] != "current" {
		t.Fatalf("result %v", result)
	}
}

func TestAnInstalledPackageWithoutARepositoryIsNotCurrent(t *testing.T) {
	f := newVersionFixture(t)
	f.remote = false
	if got := f.probe()["state"]; got != "unknown" {
		t.Fatalf("state %v", got)
	}
}

func TestAnUnsupportedPlatformGetsNoControlledInstall(t *testing.T) {
	f := newVersionFixture(t)
	f.qualifiedHost = false
	result := f.probe()
	if result["state"] != "blocked" || details(result)["manual_update"] != "vendor" ||
		!strings.Contains(result["summary"].(string), "including manual installation") {
		t.Fatalf("result %v", result)
	}
}

func TestAnUnqualifiedDistributionPackageHasAManualPathAndItsBranch(t *testing.T) {
	f := newVersionFixture(t)
	f.pkg = "haproxy"
	f.qualifiedHost = false
	for version, branch := range map[string]string{"2.4.30-0ubuntu0.22.04.1": "2.4", "3.0.11-1+deb13u1": "3.0", "1:3.2.0-1": "3.2"} {
		f.installed, f.candidate = version, version
		f.runtime["running_version"] = version
		result := f.probe()
		d := details(result)
		if result["state"] != "blocked" || result["actionable"] != false || d["manual_update"] != "distribution" ||
			d["branch"] != branch || d["source"] != "APT" {
			t.Fatalf("%s: %v", version, result)
		}
	}
	for _, argv := range f.calls {
		if argv[0] == "apt-get" || argv[0] == "apt-mark" {
			t.Fatalf("changed packages: %q", argv)
		}
	}
}

func TestTheLastOperationPrefersANewerMigrationAndKeepsUnsettledFirst(t *testing.T) {
	f := newVersionFixture(t)
	dir := filepath.Join(f.root, "haproxy-package-migration")
	f.lastUpdate, f.lastMigration = filepath.Join(dir, "last-update.json"), filepath.Join(dir, "last-migration.json")
	oldID, migrationID := strings.Repeat("1", 32), strings.Repeat("2", 32)
	writeFile(t, f.lastUpdate, mustJSON(M{"id": oldID, "kind": "patch", "phase": "prepared",
		"old_version": "2.8.30-0ubuntu0.24.04.2", "updated_at": 1000.0}))
	writeFile(t, f.lastMigration, mustJSON(M{"id": migrationID, "kind": "migration", "phase": "committed",
		"old_version": "2.8.30-0ubuntu0.24.04.2", "updated_at": 2000.0, "target_verified": true}))
	op := details(f.probe())["last_operation"].(M)
	if op["id"] != migrationID || op["kind"] != "migration" || op["phase"] != "committed" {
		t.Fatalf("operation %v", op)
	}
	// An unsettled operation still wins over a newer settled record.
	writeFile(t, f.lastUpdate, mustJSON(M{"id": oldID, "kind": "patch", "phase": "rollback_failed",
		"old_version": "2.8.30-0ubuntu0.24.04.2", "updated_at": 1000.0}))
	op = details(f.probe())["last_operation"].(M)
	if op["id"] != oldID || op["phase"] != "rollback_failed" {
		t.Fatalf("operation %v", op)
	}
}

func TestSplitFieldsIsPythonsSplit(t *testing.T) {
	line := "7f00-7f01 r-xp 00000000 08:01 1234       /usr/lib/libc.so.6 (deleted)"
	got := splitFields(line, 6)
	if len(got) != 6 || got[1] != "r-xp" || got[5] != "/usr/lib/libc.so.6 (deleted)" {
		t.Fatalf("fields %q", got)
	}
}

// The OS component leaves the managed HAProxy packages to their own update.

func aptSimulation(stdout string) Runner {
	return runnerFunc(func([]string) CommandResult { return ok(stdout) })
}

func TestManagedHAProxyAndTLSAreNotOSUpdates(t *testing.T) {
	result := probeOS(aptSimulation("Inst haproxy-awslc [3.4.7] (3.4.8 repo)\nInst libssl-awslc [4.2] (4.3 repo)\nInst libc6 [2.39] (2.39.1 repo)"),
		M{"fresh": true}, haproxyPackages)
	d := details(result)
	if !reflect.DeepEqual(d["packages"], []any{"libc6"}) ||
		!reflect.DeepEqual(d["candidates"], []any{M{"name": "libc6", "version": "2.39.1", "installed_version": "2.39"}}) {
		t.Fatalf("details %v", d)
	}
}

func TestOSPackageVersionsKeepTheArchitectureAndNewDependencies(t *testing.T) {
	result := probeOS(aptSimulation("Inst containerd.io:arm64 [1:2.1.5-1] (1:2.2.0-1 repo [arm64])\n"+
		"Inst docker-buildx-plugin [0.38.0-1] (0.39.0-1 repo)\nInst new-dependency (1.0 repo)\n"+
		"Inst docker-buildx-plugin [0.38.0-1] (0.39.0-1 repo)\n"), M{"fresh": true}, nil)
	d := details(result)
	want := []any{
		M{"name": "containerd.io:arm64", "version": "1:2.2.0-1", "installed_version": "1:2.1.5-1"},
		M{"name": "docker-buildx-plugin", "version": "0.39.0-1", "installed_version": "0.38.0-1"},
		M{"name": "new-dependency", "version": "1.0", "installed_version": nil},
	}
	if d["package_count"] != 3 || !reflect.DeepEqual(d["candidates"], want) {
		t.Fatalf("details %v", d)
	}
}

func TestAFailedRefreshMarksOSUnknownEvenWhenTheSimulationIsEmpty(t *testing.T) {
	if got := probeOS(aptSimulation(""), M{"fresh": false}, nil)["state"]; got != "unknown" {
		t.Fatalf("state %v", got)
	}
}
