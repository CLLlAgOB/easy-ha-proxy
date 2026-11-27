package stages

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	_ "modernc.org/sqlite"
)

// pick returns the named steps, in the part's order.
func pick(t *testing.T, steps []engine.Step, names ...string) []engine.Step {
	t.Helper()
	var out []engine.Step
	for _, name := range names {
		out = append(out, steps[stepAt(t, steps, name)])
	}
	return out
}

// ---------------------------------------------------------------------------
// Certificates: the PEM a renewal builds for HAProxy. The handler's own
// script runs here, with the Let's Encrypt directory moved into a temporary
// one and chown/stat standing in for a root run.

const fakeStat = `#!/bin/sh
# Report the real mode, and the owner the handler expects, as a root run would.
mode="$(/usr/bin/stat -c %a "$3")"
echo "$mode root:root"
`

type pemFixture struct {
	t    *testing.T
	root string
	b    *Builder
	path string
}

func newPEMFixture(t *testing.T) *pemFixture {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := t.TempDir()
	f := &pemFixture{t: t, root: root}
	for _, dir := range []string{"certs", "bin"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "bin/chown"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(root, "bin/stat"), []byte(fakeStat), 0o755)
	f.path = filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH")
	part := Part{Name: "cert/renew", Role: "cert", File: "renew"}
	f.b = &Builder{Set: mustSetWith(t, repoRoot(t), part, map[string]any{
		"haproxy_certs_dir": filepath.Join(root, "certs"), "haproxy_certs_available_dir": filepath.Join(root, "available")})}
	return f
}

func (f *pemFixture) issue(text string) {
	live := filepath.Join(f.root, "live", "shop.example.com")
	os.MkdirAll(live, 0o755)
	os.WriteFile(filepath.Join(live, "fullchain.pem"), []byte("CERT "+text+"\n"), 0o644)
	os.WriteFile(filepath.Join(live, "privkey.pem"), []byte("KEY "+text+"\n"), 0o600)
}

// build runs the script for one lineage and destination: whether it said
// it wrote the PEM (the handler's changed_when).
func (f *pemFixture) build(lineage, dest string) bool {
	f.t.Helper()
	script, err := f.b.Set.RenderLocal(pemSingle, map[string]any{"lineage": lineage, "dest": dest})
	if err != nil {
		f.t.Fatal(err)
	}
	script = strings.ReplaceAll(script, "/etc/letsencrypt/live/", f.root+"/live/")
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+f.path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("the script failed: %v\n%s", err, out)
	}
	return strings.Contains(string(out), "PEM written:")
}

func (f *pemFixture) dest() string { return filepath.Join(f.root, "certs", "shop.example.com.pem") }

func TestThePEMBuildWritesANewCertificateAndSaysSo(t *testing.T) {
	f := newPEMFixture(t)
	f.issue("one")
	if !f.build("shop.example.com", f.dest()) {
		t.Fatal("not reported")
	}
	raw, _ := os.ReadFile(f.dest())
	fi, _ := os.Stat(f.dest())
	if string(raw) != "CERT one\nKEY one\n" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("PEM %q mode %o", raw, fi.Mode().Perm())
	}
}

func TestThePEMBuildLeavesTheSameCertificateAlone(t *testing.T) {
	f := newPEMFixture(t)
	f.issue("one")
	f.build("shop.example.com", f.dest())
	before, _ := os.Stat(f.dest())
	if f.build("shop.example.com", f.dest()) {
		t.Fatal("an unchanged PEM was reported written")
	}
	after, _ := os.Stat(f.dest())
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an unchanged PEM was rewritten")
	}
	if names := entries(t, filepath.Join(f.root, "certs")); strings.Join(names, ",") != "shop.example.com.pem" {
		t.Fatalf("certs dir %q", names)
	}
}

func TestThePEMBuildRewritesARenewalOrLoosePermissions(t *testing.T) {
	f := newPEMFixture(t)
	f.issue("one")
	f.build("shop.example.com", f.dest())
	f.issue("two")
	if !f.build("shop.example.com", f.dest()) {
		t.Fatal("a renewal was not written")
	}
	if raw, _ := os.ReadFile(f.dest()); string(raw) != "CERT two\nKEY two\n" {
		t.Fatalf("PEM %q", raw)
	}
	os.Chmod(f.dest(), 0o644)
	if !f.build("shop.example.com", f.dest()) {
		t.Fatal("loose permissions were left")
	}
	if fi, _ := os.Stat(f.dest()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func TestThePEMBuildChangesNothingForAHeldNameOrAMissingCertificate(t *testing.T) {
	f := newPEMFixture(t)
	if f.build("shop.example.com", f.dest()) {
		t.Fatal("no certificate, yet written")
	}
	f.issue("one")
	pin := filepath.Join(f.root, "available", "shop.example.com", ".pinned")
	os.MkdirAll(filepath.Dir(pin), 0o755)
	os.WriteFile(pin, []byte("standby"), 0o644)
	if f.build("shop.example.com", f.dest()) {
		t.Fatal("a held name was written")
	}
	if _, err := os.Stat(f.dest()); err == nil {
		t.Fatal("a held name has a PEM")
	}
}

// websites.yml is written by the panel; this script runs as root.
func TestThePEMBuildRunsNoShellSyntaxFromASiteName(t *testing.T) {
	f := newPEMFixture(t)
	marker := filepath.Join(f.root, "ran")
	f.build("shop.example.com$(touch "+marker+")", f.root+`/certs/x.pem"; touch `+marker+`; echo "`)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a site name ran a command")
	}
}

// cert_path is the site's own; as root it could name any file.
func TestThePEMBuildRefusesADestinationOutsideTheCertificateDirectory(t *testing.T) {
	f := newPEMFixture(t)
	f.issue("one")
	for _, dest := range []string{filepath.Join(f.root, "elsewhere", "x.pem"), filepath.Join(f.root, "certs") + "/../escape.pem",
		filepath.Join(f.root, "certs", "notes.txt")} {
		os.MkdirAll(filepath.Dir(dest), 0o755)
		if f.build("shop.example.com", dest) {
			t.Errorf("%s was written", dest)
		}
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("%s exists", dest)
		}
	}
	if _, err := os.Stat(filepath.Join(f.root, "escape.pem")); err == nil {
		t.Fatal("escaped the certificate directory")
	}
}

// ---------------------------------------------------------------------------
// native-cleanup: the former Python daemons go last, and only when no
// installed unit names them. The step's own script runs on files and units in
// a temporary directory.

func runNativeCleanup(t *testing.T, root string, legacy []string) string {
	t.Helper()
	quoted := make([]string, len(legacy))
	for i, p := range legacy {
		q, _ := jinja.AnsibleQuote(nil, p, nil, nil)
		quoted[i] = q.(string)
	}
	script := strings.Replace(nativeCleanup, "{{ native_legacy_paths | map('quote') | join(' ') }}", strings.Join(quoted, " "), 1)
	dirs := "/etc/systemd/system /run/systemd/system /usr/lib/systemd/system"
	if !strings.Contains(script, dirs) {
		t.Fatalf("the script no longer looks in %s", dirs)
	}
	script = strings.Replace(script, dirs, filepath.Join(root, "units"), 1)
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("cleanup failed: %v\n%s", err, out)
	}
	return string(out)
}

func nativeCleanupFixture(t *testing.T) (string, []string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "units"), 0o755)
	legacy := []string{filepath.Join(root, "easy-ha-proxy-guardd.py"), filepath.Join(root, "easy_ha_proxy_alert_client.py"),
		filepath.Join(root, "updated")}
	return root, legacy
}

func placeLegacy(legacy []string) {
	os.WriteFile(legacy[0], []byte("daemon\n"), 0o755)
	os.WriteFile(legacy[1], []byte("client\n"), 0o644)
	os.Mkdir(legacy[2], 0o755)
}

func TestNativeCleanupKeepsEverythingWhileAUnitStartsAFormerDaemon(t *testing.T) {
	root, legacy := nativeCleanupFixture(t)
	placeLegacy(legacy)
	os.WriteFile(filepath.Join(root, "units", "easy-ha-proxy-guardd.service"),
		[]byte("[Service]\nExecStart=/usr/bin/python3 "+legacy[0]+"\n"), 0o644)
	if out := runNativeCleanup(t, root, legacy); strings.Contains(out, "removed:") {
		t.Fatalf("removed while named: %s", out)
	}
	// The daemon a unit starts keeps the client it imports, which no unit names.
	for _, p := range legacy {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s is gone", p)
		}
	}
}

func TestNativeCleanupRemovesEverythingOnceNoUnitNamesIt(t *testing.T) {
	root, legacy := nativeCleanupFixture(t)
	placeLegacy(legacy)
	os.WriteFile(filepath.Join(root, "units", "easy-ha-proxy-guardd.service"),
		[]byte("[Service]\nExecStart=/usr/local/sbin/guardd-core serve\n"), 0o644)
	if out := runNativeCleanup(t, root, legacy); !strings.Contains(out, "removed:") {
		t.Fatalf("nothing removed: %s", out)
	}
	for _, p := range legacy {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
}

func TestNativeCleanupOnACleanGatewayReportsNothing(t *testing.T) {
	root, legacy := nativeCleanupFixture(t)
	if out := runNativeCleanup(t, root, legacy); out != "" {
		t.Fatalf("output %q", out)
	}
}

// The native stage itself removes no Python daemon (the cleanup does, last),
// and the cleanup's list names the update broker.
func TestTheNativeStageLeavesThePythonDaemonsToTheCleanup(t *testing.T) {
	for _, step := range buildPart(t, "native", nil, nil) {
		if step.Resource != nil && strings.Contains(step.Resource.Describe(), ".py") {
			t.Errorf("%s touches a Python daemon: %s", step.Name, step.Resource.Describe())
		}
	}
	if strings.Contains(nativeOCIPull, "easy-ha-proxy-updated.py") || strings.Contains(nativeOCIPull, "libguardd_core.so") {
		t.Error("the bundle pull names a former daemon")
	}
	found := false
	for _, p := range nativeLegacyPaths {
		found = found || p == "/usr/local/sbin/easy-ha-proxy-updated.py"
	}
	if !found {
		t.Error("the cleanup list does not name the update broker")
	}
}

// The native bundle is verified wherever it comes from.
func TestTheNativeBundleIsVerified(t *testing.T) {
	if !strings.Contains(nativeOCIPull, "sha256sum -c SHA256SUMS") {
		t.Error("the OCI bundle is not checked against SHA256SUMS")
	}
	checksums := map[string]any{"amd64": strings.Repeat("a", 64), "arm64": strings.Repeat("b", 64)}
	steps := buildPart(t, "native", &engine.System{}, map[string]any{"native_release_base_url": "http://example.test/native",
		"native_release_checksums": checksums, "native_release_image": ""})
	err := engine.NewRun(engine.Plan, &engine.System{}, nil).Do("native",
		pick(t, steps, "native-daemons | Map host architecture to release arch", "native-daemons | Select delivery mode",
			"native-daemons | Validate configured delivery source"))
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("a plain-http release was accepted: %v", err)
	}
}

// The HTTPS checksum is read for the host arch at build time, not from the
// _native_arch fact (which a later step sets): otherwise it is always empty
// and a correctly configured HTTPS release is rejected.
func TestTheNativeHTTPSChecksumIsReadForTheHostArch(t *testing.T) {
	checksums := map[string]any{"amd64": strings.Repeat("a", 64), "arm64": strings.Repeat("b", 64)}
	steps := buildPart(t, "native", &engine.System{}, map[string]any{
		"ansible_architecture":     "x86_64",
		"native_release_base_url":  "https://example.test/native",
		"native_release_checksums": checksums, "native_release_image": ""})
	err := engine.NewRun(engine.Plan, &engine.System{}, nil).Do("native",
		pick(t, steps, "native-daemons | Map host architecture to release arch", "native-daemons | Select delivery mode",
			"native-daemons | Validate configured delivery source"))
	if err != nil {
		t.Fatalf("a valid https release with a per-arch checksum was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Authelia: the host clock is checked before Authelia is deployed (it refuses
// to start on a clock that is off), and forced into sync where it drifted.

type clockFake struct {
	synced, provider bool
	calls            []string
}

func (c *clockFake) exec(name string, args ...string) (string, int, error) {
	call := name + " " + strings.Join(args, " ")
	c.calls = append(c.calls, call)
	switch {
	case call == "timedatectl show --property=NTPSynchronized --value":
		if c.synced {
			return "yes\n", 0, nil
		}
		return "no\n", 0, nil
	case call == "systemctl show systemd-timesyncd.service --property=LoadState --value":
		if c.provider {
			return "loaded\n", 0, nil
		}
		return "not-found\n", 0, nil
	case call == "timedatectl set-ntp true":
		c.synced = c.provider
		return "", 0, nil
	case name == "systemctl" && args[0] == "is-enabled":
		return "enabled\n", 0, nil
	case name == "systemctl" && args[0] == "show":
		return "active\n", 0, nil
	}
	return "", 0, nil
}

func clockSteps(t *testing.T, c *clockFake) []engine.Step {
	t.Helper()
	steps := buildPart(t, "authelia/install", &engine.System{Exec: c.exec},
		map[string]any{"authelia_enabled": true, "authelia_test_time_sync_retries": 1, "authelia_test_time_sync_delay": 0})
	return steps[:stepAt(t, steps, "Stop before deploying Authelia with an inaccurate clock")+1]
}

func TestASynchronizedClockIsLeftAloneEvenInAPlan(t *testing.T) {
	for _, mode := range []engine.Mode{engine.Plan, engine.Apply} {
		c := &clockFake{synced: true, provider: true}
		if err := engine.NewRun(mode, &engine.System{Exec: c.exec}, nil).Do("authelia/install", clockSteps(t, c)); err != nil {
			t.Fatalf("mode %v: %v", mode, err)
		}
		for _, call := range c.calls {
			if strings.Contains(call, "set-ntp") || strings.Contains(call, "restart") {
				t.Fatalf("mode %v: %s on a synchronized clock", mode, call)
			}
		}
	}
}

func TestADriftedClockIsForcedIntoSyncThroughTimesyncd(t *testing.T) {
	c := &clockFake{synced: false, provider: true}
	if err := engine.NewRun(engine.Apply, &engine.System{Exec: c.exec}, nil).Do("authelia/install", clockSteps(t, c)); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(c.calls, "\n")
	for _, want := range []string{"timedatectl set-ntp true", "systemctl restart systemd-timesyncd.service"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no %q in:\n%s", want, joined)
		}
	}
}

func TestADriftedClockWithoutAProviderStopsWithTheWayOut(t *testing.T) {
	c := &clockFake{synced: false, provider: false}
	err := engine.NewRun(engine.Apply, &engine.System{Exec: c.exec}, nil).Do("authelia/install", clockSteps(t, c))
	if err == nil || !strings.Contains(err.Error(), "systemd-timesyncd is not available") {
		t.Fatalf("err %v", err)
	}
}

// A failed start explains itself without leaking what the logs may hold.
func TestAFailedAutheliaStartReportsLogsAndTheClock(t *testing.T) {
	steps := buildPart(t, "authelia/install", nil, nil)
	logs := steps[stepAt(t, steps, "Collect recent Authelia logs when startup fails")]
	if !strings.Contains(logs.Resource.Describe(), "--tail 80") {
		t.Errorf("logs read with %s", logs.Resource.Describe())
	}
	stepAt(t, steps, "Collect host time status when Authelia startup fails")
	for _, word := range []string{"authorization", "password", "secret", "token"} {
		if !authCredential.MatchString(word) {
			t.Errorf("a log line with %q would be shown", word)
		}
	}
}

// ---------------------------------------------------------------------------
// HAProxy package provider: a change of provider fails before an ordinary
// update can replace HAProxy.

func providerCheck(t *testing.T, installed map[string]string, extra map[string]any) error {
	t.Helper()
	vars := map[string]any{"haproxy_package_provider": "haproxy-technologies", "haproxy_package_branch": "3.4",
		"ansible_distribution": "Ubuntu", "ansible_distribution_release": "noble", "ansible_architecture": "x86_64"}
	for k, v := range extra {
		vars[k] = v
	}
	sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
		if name != "dpkg-query" {
			t.Fatalf("ran %s %v", name, args)
		}
		var lines []string
		for pkg, version := range installed {
			lines = append(lines, "ii \t"+pkg+"\t"+version+"\tamd64")
		}
		return strings.Join(lines, "\n") + "\n", 0, nil
	}}
	steps := buildPart(t, "haproxy/install", sys, vars)
	return engine.NewRun(engine.Plan, sys, nil).Do("haproxy/install", pick(t, steps,
		"HAProxy package | Validate the provider", "HAProxy package | Read installed packages",
		"HAProxy package | Require a separate provider migration", "HAProxy package | Validate the platform before changing APT"))
}

func TestOnlyTheTwoExplicitProvidersAreAccepted(t *testing.T) {
	for provider, ok := range map[string]bool{"distribution": true, "haproxy-technologies": true, "latest": false, "": false} {
		if err := providerCheck(t, nil, map[string]any{"haproxy_package_provider": provider}); (err == nil) != ok {
			t.Errorf("provider %q: %v", provider, err)
		}
	}
}

func TestAnInstalledPackageIsNotSilentlyReplacedByTheOtherProvider(t *testing.T) {
	if err := providerCheck(t, map[string]string{"haproxy": "2.8.30"}, nil); err == nil || !strings.Contains(err.Error(), "Refusing to replace") {
		t.Errorf("the vendor provider replaced the distribution package: %v", err)
	}
	if err := providerCheck(t, map[string]string{"haproxy": "2.8.30"}, map[string]any{"haproxy_package_provider": "distribution"}); err != nil {
		t.Errorf("the distribution package under its own provider: %v", err)
	}
	if err := providerCheck(t, map[string]string{"haproxy-awslc": "3.4.7"}, map[string]any{"haproxy_package_provider": "distribution"}); err == nil {
		t.Error("a missing provider setting downgraded the vendor package")
	}
}

func TestTheVendorProviderOnlyRunsWhereItIsQualified(t *testing.T) {
	for _, arch := range []string{"aarch64", "x86_64"} {
		if err := providerCheck(t, nil, map[string]any{"ansible_architecture": arch}); err != nil {
			t.Errorf("%s: %v", arch, err)
		}
	}
	for _, bad := range []map[string]any{{"ansible_architecture": "armv7l"}, {"ansible_distribution": "Debian"},
		{"ansible_distribution_release": "jammy"}, {"ansible_distribution_release": "resolute"}, {"haproxy_package_branch": "3.5"}} {
		if err := providerCheck(t, nil, bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	if err := providerCheck(t, map[string]string{"haproxy-awslc": "3.2.26"}, nil); err == nil {
		t.Error("another installed branch was accepted")
	}
	if err := providerCheck(t, map[string]string{"haproxy-awslc": "3.4.6-0+ha34+ubuntu24.04u1"}, nil); err != nil {
		t.Errorf("a patch update within the branch: %v", err)
	}
}

// The status check asks for the package actually installed, whatever an
// older inventory says.
func TestTheStatusCheckQueriesTheInstalledHAProxyPackage(t *testing.T) {
	for _, c := range []struct {
		out  string
		code int
		want string
	}{{"installed", 0, "haproxy-awslc"}, {"config-files", 0, "haproxy"}, {"", 1, "haproxy"}} {
		sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) { return c.out, c.code, nil }}
		p := parts["healthcheck/status"]
		root := repoRoot(t)
		b := &Builder{Set: mustSet(t, root, p), Sys: sys, RoleDir: filepath.Join(root, "ansible", "roles", p.Role)}
		steps := p.Build(b)
		if err := engine.NewRun(engine.Plan, sys, nil).Do("status", pick(t, steps,
			"Status check | detect the installed HAProxy package provider", "Status check | select the actual HAProxy package name")); err != nil {
			t.Fatal(err)
		}
		if got := b.S("{{ status_check_haproxy_apt_package }}"); got != c.want {
			t.Errorf("dpkg %q rc %d: %s, want %s", c.out, c.code, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// The OS upgrade guard gets its flag and state path as separate arguments.

func guardArgv(t *testing.T, extra map[string]any) []string {
	t.Helper()
	steps := buildPart(t, "update_packages/upgrade", nil, extra)
	step := steps[stepAt(t, steps, "Verify package upgrade safety and record the installation attempt")]
	res, err := step.Build(engine.NewRun(engine.Apply, &engine.System{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return res.(*engine.Command).Argv
}

func TestTheUpgradeGuardGetsItsArgumentsWithoutShellSplitting(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		argv := guardArgv(t, map[string]any{"updated_state_root": "/state with spaces", "easy_ha_proxy_automatic_os_upgrade": automatic})
		if argv[0] != "/usr/local/sbin/easy-ha-proxy-agent" || argv[1] != "os-upgrade-guard" {
			t.Fatalf("argv %q", argv)
		}
		if strings.Contains(strings.Join(argv, "\x00"), "--automatic") != automatic {
			t.Errorf("automatic %v: %q", automatic, argv)
		}
		if tail := argv[len(argv)-2:]; tail[0] != "--state-root" || tail[1] != "/state with spaces/os-security" {
			t.Errorf("state root %q", tail)
		}
	}
	for _, runtime := range []bool{false, true} {
		extra := map[string]any{"easy_ha_proxy_automatic_os_upgrade": true, "easy_ha_proxy_maintenance_revision": strings.Repeat("a", 32),
			"easy_ha_proxy_runtime_maintenance_until": 123456, "easy_ha_proxy_runtime_maintenance_revision": ""}
		if runtime {
			extra["easy_ha_proxy_runtime_maintenance_revision"] = strings.Repeat("a", 32)
		}
		argv := guardArgv(t, extra)
		want := "--maintenance-revision"
		if runtime {
			want = "--runtime-maintenance"
		}
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, want) || !strings.HasSuffix(joined, "--maintenance-until 123456") {
			t.Errorf("runtime %v: %q", runtime, argv)
		}
	}
}

// ---------------------------------------------------------------------------
// A changed HAProxy environment or secret drop-in needs a restart: a reload
// keeps the old environment.

func TestAChangedHAProxyEnvironmentRestartsInsteadOfReloading(t *testing.T) {
	for _, changed := range []string{"", "haproxy_runtime_environment", "haproxy_secret_dropin"} {
		var calls []string
		sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "systemctl" && len(args) > 0 && args[0] == "show" {
				return "active\n", 0, nil
			}
			return "", 0, nil
		}, ExecEnv: func(_ []string, name string, args ...string) (string, int, error) { return "", 0, nil }}
		part := Part{Name: "haproxy/handlers", Role: "haproxy", File: "handlers"}
		b := &Builder{Set: mustSet(t, repoRoot(t), part), Sys: sys, Shared: map[string]any{}}
		steps := append(handlerValidateHaproxy(b), handlerApplyHaproxy(b)...)
		r := engine.NewRun(engine.Apply, sys, nil)
		if changed != "" {
			r.MarkChanged(changed)
		}
		if err := r.Do("handlers", steps); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(calls, "\n")
		restarted := strings.Contains(joined, "systemctl restart haproxy")
		if restarted != (changed != "") {
			t.Errorf("changed %q: calls\n%s", changed, joined)
		}
	}
}

// ---------------------------------------------------------------------------
// Authelia's notification templates follow the configured language.

func TestAutheliaNotificationTemplatesFollowTheLanguage(t *testing.T) {
	for _, lang := range []string{"en", "ru"} {
		n := 0
		for _, step := range buildPart(t, "authelia/install", nil, map[string]any{"authelia_enabled": true, "authelia_notification_language": lang}) {
			if strings.HasPrefix(step.Name, "Deploy ") && strings.HasSuffix(step.Name, "template ("+strings.ToUpper(lang)+")") {
				n++
			}
		}
		if n != 6 {
			t.Errorf("%s: %d templates", lang, n)
		}
	}
	steps := buildPart(t, "authelia/install", nil, map[string]any{"authelia_enabled": true, "authelia_notification_language": "de"})
	err := engine.NewRun(engine.Plan, &engine.System{}, nil).Do("authelia/install", pick(t, steps, "Validate Authelia notification language"))
	if err == nil {
		t.Fatal("an unsupported language was accepted")
	}
}

// Mail leaves through the relay container: nothing installs msmtp or a host
// SMTP listener any more.
func TestCertificateMailNeedsNoHostMailer(t *testing.T) {
	for _, part := range []string{"cert/install", "cert/notify"} {
		for _, step := range buildPart(t, part, nil, nil) {
			desc := ""
			if step.Resource != nil {
				desc = step.Resource.Describe()
			}
			if strings.Contains(step.Name+desc, "msmtp") || strings.Contains(desc, "2525") {
				t.Errorf("%s: %s %s", part, step.Name, desc)
			}
		}
	}
}

// The legacy relay spool is migrated under a lock, with the queue checked
// and Authelia stopped, and anything that goes wrong puts it back.
func TestTheSpoolMigrationIsLockedQuiescedAndFailsClosed(t *testing.T) {
	for _, want := range []string{"flock --exclusive --wait 30", `docker stop "{{ authelia_container_name }}"`, "trap recover EXIT",
		"easy-ha-proxy-mail-relay-spool"} {
		if !strings.Contains(autheliaSpoolMigration, want) {
			t.Errorf("the spool migration lacks %q", want)
		}
	}
	if strings.Count(autheliaSpoolMigration, "postqueue -p") < 2 {
		t.Error("the queue is not checked before and after")
	}
}

// ---------------------------------------------------------------------------
// Authelia's database is copied before a different Authelia image runs on it,
// and only then; a failed copy stops the update before the migration.

func autheliaCopyRun(t *testing.T, running string, runningCode int, target string, database []byte) (string, error) {
	t.Helper()
	root := t.TempDir()
	if database != nil {
		os.WriteFile(filepath.Join(root, "db.sqlite3"), database, 0o600)
	}
	sys := &engine.System{Exec: func(name string, args ...string) (string, int, error) {
		if name == "docker" && args[0] == "inspect" {
			return running, runningCode, nil
		}
		if name == "docker" && args[0] == "image" {
			return target, 0, nil
		}
		t.Fatalf("ran %s %v", name, args)
		return "", 0, nil
	}}
	copies := filepath.Join(root, "copies")
	b := &Builder{Set: mustSetWith(t, repoRoot(t), parts["authelia/install"], map[string]any{
		"authelia_root_dir": root, "authelia_db_backup_dir": copies, "authelia_db_backup_keep": 3}), Sys: sys}
	err := engine.NewRun(engine.Apply, sys, nil).Do("authelia", autheliaDBBackup(b))
	names, _ := filepath.Glob(filepath.Join(copies, "authelia-db-*.sqlite3"))
	return strings.Join(names, ","), err
}

func TestTheAutheliaDatabaseIsCopiedOnlyForADifferentImage(t *testing.T) {
	database := freshSQLite(t)
	copied, err := autheliaCopyRun(t, "sha256:old authelia/authelia:4.39.27", 0, "sha256:new", database)
	if err != nil || !strings.Contains(copied, "authelia_authelia_4.39.27") {
		t.Fatalf("a different image: copied %q, %v", copied, err)
	}
	if copied, err := autheliaCopyRun(t, "sha256:same authelia/authelia:4.39.28", 0, "sha256:same", database); err != nil || copied != "" {
		t.Fatalf("the same image: copied %q, %v", copied, err)
	}
	if copied, err := autheliaCopyRun(t, "", 1, "sha256:new", database); err != nil || copied != "" {
		t.Fatalf("no running container: copied %q, %v", copied, err)
	}
	if copied, err := autheliaCopyRun(t, "sha256:old authelia/authelia:4.39.27", 0, "sha256:new", nil); err != nil || copied != "" {
		t.Fatalf("no database: copied %q, %v", copied, err)
	}
	if _, err := autheliaCopyRun(t, "sha256:old authelia/authelia:4.39.27", 0, "sha256:new", []byte("not a database")); err == nil {
		t.Fatal("a failed copy let the update go on")
	}
}

// freshSQLite is the bytes of a small valid SQLite database.
func freshSQLite(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("create table migrations (id integer primary key, version_after int); insert into migrations (version_after) values (29)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Where the copies go, and that at least one is kept.
func TestAutheliaCopiesGoWhereTheRestoreLooks(t *testing.T) {
	b := &Builder{Set: mustSet(t, repoRoot(t), parts["authelia/install"])}
	if dir := b.S("{{ authelia_db_backup_dir }}"); dir != "/var/backups/easy-ha-proxy/authelia-db" {
		t.Errorf("dir %s", dir)
	}
	if keep, _ := strconv.Atoi(b.S("{{ authelia_db_backup_keep | string }}")); keep < 1 {
		t.Errorf("keep %d", keep)
	}
}
