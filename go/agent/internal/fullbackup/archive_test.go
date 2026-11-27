package fullbackup

import (
	"archive/tar"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func member(name string, typ byte, link string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: typ, Linkname: link, Mode: 0o644}
}

func TestASafeLetsEncryptRelativeSymlinkIsAllowed(t *testing.T) {
	if err := validateBundleMember(member("etc/letsencrypt/live/example/cert.pem", tar.TypeSymlink, "../../archive/example/cert1.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeMembersAreRejected(t *testing.T) {
	for _, h := range []*tar.Header{
		member("etc/easy-ha-proxy/escape", tar.TypeSymlink, "../../../../etc/shadow"),
		member("etc/easy-ha-proxy/absolute", tar.TypeSymlink, "/etc/shadow"),
		member("etc/easy-ha-proxy/hardlink", tar.TypeLink, "../etc/shadow"),
		member("etc/easy-ha-proxy/special", tar.TypeChar, ""),
		member("etc/easy-ha-proxy/special", tar.TypeBlock, ""),
		member("etc/easy-ha-proxy/special", tar.TypeFifo, ""),
		member("../etc/shadow", tar.TypeReg, ""),
		member("/etc/shadow", tar.TypeReg, ""),
		member("./", tar.TypeDir, ""),
	} {
		var be *BackupError
		if err := validateBundleMember(h); err == nil || !asBackupError(err, &be) {
			t.Errorf("%s (%c -> %s) accepted: %v", h.Name, h.Typeflag, h.Linkname, err)
		}
	}
}

func asBackupError(err error, target **BackupError) bool {
	if be, ok := err.(*BackupError); ok {
		*target = be
		return true
	}
	return false
}

func TestPythonPathHelpers(t *testing.T) {
	for in, want := range map[string]string{"": ".", "a/../b": "b", "//a/b": "//a/b", "///a": "/a", "./a/": "a", "../a": "../a",
		"/../a": "/a", "a/b/../../..": ".."} {
		if got := pyNormpath(in); got != want {
			t.Errorf("pyNormpath(%q) = %q, want %q", in, got, want)
		}
	}
	if pyDirname("a/b/c") != "a/b" || pyDirname("c") != "" || pyDirname("/c") != "/" {
		t.Fatal("pyDirname")
	}
	if !reflect.DeepEqual(parents("/etc/systemd/system/x"), []string{"/etc/systemd/system", "/etc/systemd", "/etc", "/"}) {
		t.Fatalf("parents %v", parents("/etc/systemd/system/x"))
	}
	if staticPatternPrefix("/etc/systemd/system/haproxy*") != "/etc/systemd/system" || staticPatternPrefix("*") != "/" {
		t.Fatal("staticPatternPrefix")
	}
}

func TestTheCorePayloadEnforcesItsLimits(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeTar(t, payload, []tarEntry{file("etc/easy-ha-proxy/one", "1"), file("etc/easy-ha-proxy/two", "22")})
	saved := limit
	t.Cleanup(func() { limit = saved })
	limit.coreMembers = 1
	if _, err := validatePayload(payload, false); err == nil || !strings.Contains(err.Error(), "member-count limit") {
		t.Fatalf("members: %v", err)
	}
	limit = saved
	limit.coreBytes = 2
	if _, err := validatePayload(payload, false); err == nil || !strings.Contains(err.Error(), "expanded-size limit") {
		t.Fatalf("bytes: %v", err)
	}
}

func TestTheOuterAndSSHArchivesUseTheirOwnLimits(t *testing.T) {
	root := t.TempDir()
	saved := limit
	t.Cleanup(func() { limit = saved })
	if _, err := exec.LookPath("openssl"); err == nil {
		createTestArchive(t, root, archiveSpec{})
		destination := filepath.Join(root, "extract")
		_ = os.Mkdir(destination, 0o700)
		limit.outerMembers = 2
		if err := extractBundle(filepath.Join(root, "bundle.tar.gz"), destination); err == nil || !strings.Contains(err.Error(), "member-count limit") {
			t.Fatalf("outer members: %v", err)
		}
		limit = saved
		limit.outerBytes = 1
		if err := extractBundle(filepath.Join(root, "bundle.tar.gz"), destination); err == nil || !strings.Contains(err.Error(), "expanded-size limit") {
			t.Fatalf("outer bytes: %v", err)
		}
		limit = saved
	}
	ssh := filepath.Join(root, "ssh.tar.gz")
	writeTar(t, ssh, []tarEntry{file("root/.ssh/authorized_keys", "one"), file("home/operator/.ssh/authorized_keys", "two")})
	if _, err := validatePayload(ssh, true); err != nil {
		t.Fatal(err)
	}
	limit.sshMembers = 1
	if _, err := validatePayload(ssh, true); err == nil || !strings.Contains(err.Error(), "member-count limit") {
		t.Fatalf("ssh members: %v", err)
	}
	limit = saved
	limit.sshBytes = 5
	if _, err := validatePayload(ssh, true); err == nil || !strings.Contains(err.Error(), "expanded-size limit") {
		t.Fatalf("ssh bytes: %v", err)
	}
}

func TestTheOuterBundleChecksTemporarySpaceBeforeExtraction(t *testing.T) {
	root := t.TempDir()
	createTestArchive(t, root, archiveSpec{})
	destination := filepath.Join(root, "extract-low-space")
	_ = os.Mkdir(destination, 0o700)
	swap(t, &diskUsage, func(string) (usage, error) { return usage{free: 0}, nil })
	if err := extractBundle(filepath.Join(root, "bundle.tar.gz"), destination); err == nil || !strings.Contains(err.Error(), "temporary disk space") {
		t.Fatalf("err %v", err)
	}
	if entries, _ := os.ReadDir(destination); len(entries) != 0 {
		t.Fatalf("extracted %v", entries)
	}
}

func TestSetuidAndWorldWriteBitsDoNotSurviveTheBundle(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle.tar.gz")
	var entries []tarEntry
	for _, name := range outerRequired {
		content := "x"
		if name == "manifest.json" {
			content = "{}"
		}
		entries = append(entries, tarEntry{name: name, content: content, typ: tar.TypeReg, mode: 0o4777})
	}
	writeTar(t, bundle, entries)
	destination := filepath.Join(root, "work")
	_ = os.Mkdir(destination, 0o700)
	saved := limit
	t.Cleanup(func() { limit = saved })
	limit.restoreMinFree = 0
	if err := extractBundle(bundle, destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range outerRequired {
		fi, err := os.Stat(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSetuid != 0 || fi.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s: %v", name, fi.Mode())
		}
	}
}

func TestTheCorePayloadAllowsAncestorsLinksAndManagedFiles(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeTar(t, payload, []tarEntry{
		{name: "etc", typ: tar.TypeDir}, {name: "etc/letsencrypt", typ: tar.TypeDir},
		file("etc/letsencrypt/archive/example/cert1.pem", "cert"),
		{name: "etc/letsencrypt/live/example/cert.pem", typ: tar.TypeSymlink, link: "../../archive/example/cert1.pem"},
		file("etc/systemd/system/haproxy-certd.service", "x"),
		file("usr/local/sbin/haproxy-healthd.py", "x"),
		file("etc/rsyslog.d/49-haproxy.conf", "x"),
	})
	if _, err := validatePayload(payload, false); err != nil {
		t.Fatal(err)
	}
}

func TestTheCorePayloadAllowsChildrenOfAManagedGlobDirectory(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeTar(t, payload, []tarEntry{file("etc/systemd/system/haproxy.service.d/override.conf", "[Service]\nEnvironment=TEST=1\n")})
	if size, err := validatePayload(payload, false); err != nil || size <= 0 {
		t.Fatalf("size %d err %v", size, err)
	}
}

func TestTheCorePayloadRefusesWhatIsNotManaged(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"outside":        {file("etc/shadow", "root:*:0:0\n")},
		"file as a tree": {file("etc/msmtprc/child", "x")},
		"setuid":         {{name: "etc/easy-ha-proxy/tool", content: "x", typ: tar.TypeReg, mode: 0o4755}},
		"security xattr": {{name: "etc/easy-ha-proxy/x", content: "x", typ: tar.TypeReg, pax: map[string]string{"SCHILY.xattr.security.capability": "x"}}},
		"link out":       {{name: "etc/haproxy/x", typ: tar.TypeSymlink, link: "../shadow"}},
		"duplicate":      {file("etc/haproxy/a", "1"), file("etc/haproxy/./a", "2")},
	} {
		payload := filepath.Join(t.TempDir(), "payload.tar.gz")
		writeTar(t, payload, entries)
		if _, err := validatePayload(payload, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPayloadPreservesHostPaths(t *testing.T) {
	t.Setenv("EASY_HA_PROXY_SOURCE_DIR", "/etc/easy-ha-proxy/recovery[1]")
	payload := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeTar(t, payload, []tarEntry{file("./var/lib/easy-ha-proxy/backup-web/history", "legacy")})
	if _, err := validatePayload(payload, false); err != nil {
		t.Fatalf("legacy member covered by extraction exclusions: %v", err)
	}
	for _, name := range []string{"var/lib/easy-ha-proxy/backup-web//history", "etc/easy-ha-proxy/./recovery[1]/state"} {
		writeTar(t, payload, []tarEntry{file(name, "state")})
		if _, err := validatePayload(payload, false); err == nil {
			t.Errorf("accepted noncanonical protected member %q", name)
		}
		if err := validateRollbackPayload(payload, true); err == nil {
			t.Errorf("accepted noncanonical protected rollback member %q", name)
		}
	}
	writeTar(t, payload, []tarEntry{{name: "etc/easy-ha-proxy/copy", typ: tar.TypeLink, link: "etc/easy-ha-proxy/recovery[1]/state"}})
	if _, err := validatePayload(payload, false); err == nil {
		t.Fatal("accepted a link to a protected file")
	}
	r := record(t, func([]string) (runResult, error) { return runResult{}, nil })
	if err := extractPayload(payload, []string{"etc/easy-ha-proxy"}); err != nil {
		t.Fatal(err)
	}
	for _, option := range []string{"--no-overwrite-dir", "--anchored", "--no-wildcards", "--exclude=etc/easy-ha-proxy/recovery[1]"} {
		if !contains(r.calls[0], option) {
			t.Errorf("scoped extraction omitted %q", option)
		}
	}
}

func TestPayloadAncestorMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy memberPolicy
	}{{"usr/local/sbin", coreMemberPolicy}, {"root", sshMemberPolicy}, {"home/operator", sshMemberPolicy}} {
		h := member(tc.name, tar.TypeDir, "")
		h.Mode = 0o755
		if err := tc.policy(h, tc.name, nil); err != nil {
			t.Fatal(err)
		}
		if err := tc.policy(h, tc.name, map[string]string{"SCHILY.acl.access": "example"}); err == nil {
			t.Errorf("accepted an ACL on %s", tc.name)
		}
		h.Uid = 1000
		if err := tc.policy(h, tc.name, nil); err == nil {
			t.Errorf("accepted non-root ownership on %s", tc.name)
		}
		h.Uid, h.Mode = 0, 0o775
		if err := tc.policy(h, tc.name, nil); err == nil {
			t.Errorf("accepted group write access on %s", tc.name)
		}
	}
}

func TestTheRollbackPayloadCanHoldCoreAndOptedInSSHState(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "rollback.tar.gz")
	writeTar(t, payload, []tarEntry{file("etc/easy-ha-proxy/vars.yml", "root_domain: example.test\n"),
		file("root/.ssh/authorized_keys", "ssh-ed25519 test-key\n")})
	if err := validateRollbackPayload(payload, true); err != nil {
		t.Fatal(err)
	}
	if err := validateRollbackPayload(payload, false); err == nil || !strings.Contains(err.Error(), "outside managed paths") {
		t.Fatalf("without SSH: %v", err)
	}
}

func TestRemovePathsDeletesOnlyTheTargetsWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	managed, unrelated := filepath.Join(root, "managed"), filepath.Join(root, "unrelated")
	writeText(t, filepath.Join(managed, "stale.txt"), "stale\n")
	writeText(t, filepath.Join(unrelated, "keep.txt"), "keep\n")
	link := filepath.Join(root, "managed-link")
	if err := os.Symlink(unrelated, link); err != nil {
		t.Fatal(err)
	}
	if err := removePaths([]string{managed, link}); err != nil {
		t.Fatal(err)
	}
	if lexists(managed) || lexists(link) || readText(t, filepath.Join(unrelated, "keep.txt")) != "keep\n" {
		t.Fatal("removed the wrong things")
	}
}

func TestTheCapacityScanDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	writeText(t, filepath.Join(root, "unrelated", "large.bin"), strings.Repeat("x", 4096))
	link := filepath.Join(root, "managed-link")
	if err := os.Symlink(filepath.Join(root, "unrelated"), link); err != nil {
		t.Fatal(err)
	}
	bytes, members, _, err := managedPathsApparentUsage([]string{link})
	if err != nil || members != 1 || bytes >= 4096 {
		t.Fatalf("bytes %d members %d err %v", bytes, members, err)
	}
}

// What tar says, and when it is fatal.

const (
	tarChanged = "tar: var/log/haproxy.log: file changed as we read it\n"
	tarSocket  = "tar: var/lib/haproxy/dev/log: socket ignored\n"
	tarFatal   = "tar: etc/haproxy: Cannot open: Permission denied\n"
)

func fakeTar(t *testing.T, code int, stderr string) (*recorder, string) {
	t.Helper()
	r := record(t, func([]string) (runResult, error) { return runResult{Code: code, Stderr: stderr}, nil })
	destination := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeText(t, destination, "")
	_ = os.Chmod(destination, 0o644)
	return r, destination
}

func TestTarWarningsAreKeptAndOnlyAFatalExitFails(t *testing.T) {
	for _, tc := range []struct {
		code   int
		stderr string
		want   []string
	}{
		{0, "", []string{}},
		{0, tarSocket, []string{strings.TrimSpace(tarSocket)}},
		{1, tarChanged, []string{strings.TrimSpace(tarChanged)}},
		{1, tarSocket + tarChanged, []string{strings.TrimSpace(tarSocket), strings.TrimSpace(tarChanged)}},
	} {
		_, destination := fakeTar(t, tc.code, tc.stderr)
		warnings, err := createPayload(destination, []string{"etc/haproxy"}, backupExcludes)
		if err != nil || !reflect.DeepEqual(warnings, tc.want) {
			t.Fatalf("code %d: %v %v", tc.code, warnings, err)
		}
		// Even on the warning path: a readable payload is a leak.
		if fi, _ := os.Stat(destination); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}
	_, destination := fakeTar(t, 2, tarFatal)
	if _, err := createPayload(destination, []string{"etc/haproxy"}, nil); err == nil ||
		!strings.Contains(err.Error(), "exit code 2") || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("fatal: %v", err)
	}
	// A run that did not finish is not made root-only.
	if fi, _ := os.Stat(destination); fi.Mode().Perm() != 0o644 {
		t.Fatalf("chmodded a failed payload: %v", fi.Mode())
	}
	_, destination = fakeTar(t, 2, "")
	if _, err := createPayload(destination, []string{"etc/haproxy"}, nil); err == nil || !strings.Contains(err.Error(), "no reason") {
		t.Fatalf("silent fatal: %v", err)
	}
	r, _ := fakeTar(t, 0, "")
	if _, err := createPayload("/tmp/x.tar.gz", nil, nil); err == nil || len(r.calls) != 0 {
		t.Fatalf("an empty list ran tar: %v", err)
	}
}

func TestTheTarCommandLine(t *testing.T) {
	r, destination := fakeTar(t, 0, "")
	if _, err := createPayload(destination, []string{"/etc/haproxy", "/var/log/haproxy.log"}, []string{"var/x"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"tar", "--acls", "--xattrs", "--numeric-owner", "-czpf", destination, "-C", "/", "--exclude=var/x",
		"etc/haproxy", "var/log/haproxy.log"}
	if !reflect.DeepEqual(r.calls[0], want) {
		t.Fatalf("argv %q", r.calls[0])
	}
}

func TestNotificationSecretsAreExcludedFromThePayload(t *testing.T) {
	requireTools(t, "tar")
	root := t.TempDir()
	authelia := filepath.Join(root, "opt/authelia")
	state := filepath.Join(root, "var/lib/easy-ha-proxy/authelia-notification-state.json")
	writeText(t, filepath.Join(authelia, "configuration.yml"), "notifier: {}\n")
	writeText(t, filepath.Join(authelia, "notification.log"), "one-time reset link\n")
	writeText(t, state, `{"content":"one-time code"}`+"\n")
	payload := filepath.Join(root, "payload.tar.gz")
	excludes := []string{strings.TrimLeft(filepath.Join(authelia, "notification.log"), "/"), strings.TrimLeft(state, "/")}
	if _, err := createPayload(payload, []string{authelia, filepath.Dir(state)}, excludes); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	_ = eachMember(payload, func(h *tar.Header, _ map[string]string, _ io.Reader) error {
		names[strings.TrimSuffix(h.Name, "/")] = true
		return nil
	})
	if !names[strings.TrimLeft(filepath.Join(authelia, "configuration.yml"), "/")] ||
		names[strings.TrimLeft(filepath.Join(authelia, "notification.log"), "/")] || names[strings.TrimLeft(state, "/")] {
		t.Fatalf("names %v", names)
	}
}

func TestBackupExcludesTheHAProxyMigrationWorkTree(t *testing.T) {
	requireTools(t, "tar")
	root := t.TempDir()
	const state = "var/lib/easy-ha-proxy"
	const migration = state + "/haproxy-package-migration"
	const managed = state + "/managed.json"
	const content = "managed state\n"
	packageDir := filepath.Join(root, migration, "transaction/target/usr/lib")
	writeText(t, filepath.Join(packageDir, "library.so.1.0"), "staged library\n")
	if err := os.Symlink("library.so.1.0", filepath.Join(packageDir, "library.so.1")); err != nil {
		t.Fatal(err)
	}
	writeText(t, filepath.Join(root, managed), content)

	runTar := runCommand
	swap(t, &runCommand, func(argv []string, opts runOptions) (runResult, error) {
		argv = slices.Clone(argv)
		argv[slices.Index(argv, "-C")+1] = root
		return runTar(argv, opts)
	})
	payload := filepath.Join(root, "payload.tar.gz")
	if _, err := createPayload(payload, []string{"/" + state}, backupExcludes); err != nil {
		t.Fatal(err)
	}
	if expanded, err := validatePayload(payload, false); err != nil || expanded != int64(len(content)) {
		t.Fatalf("backup payload: expanded = %d, error = %v", expanded, err)
	}
	found := false
	if err := eachMember(payload, func(h *tar.Header, _ map[string]string, _ io.Reader) error {
		name := strings.TrimSuffix(h.Name, "/")
		if name == migration || strings.HasPrefix(name, migration+"/") {
			t.Errorf("migration entry was archived: %s", name)
		}
		found = found || name == managed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("backup omitted the managed file next to the migration work tree")
	}
}

func TestTheExcludesAreSurgical(t *testing.T) {
	for _, required := range []string{"var/lib/easy-ha-proxy/backup-web/backups", "var/lib/easy-ha-proxy/backup-web/uploads",
		"var/lib/easy-ha-proxy/update-web"} {
		if !contains(backupExcludes, required) {
			t.Errorf("%s is archived", required)
		}
	}
	// The job history beside them is kept, and the tree around them archived.
	if contains(backupExcludes, "var/lib/easy-ha-proxy/backup-web") || !contains(corePaths, "/var/lib/easy-ha-proxy") {
		t.Fatal("the exclusions swallow what is wanted")
	}
	for _, value := range backupExcludes {
		// tar runs with -C /: a leading slash would match nothing.
		if strings.HasPrefix(value, "/") {
			t.Errorf("%s is absolute", value)
		}
		reachable := false
		for _, root := range corePaths {
			root = strings.TrimLeft(root, "/")
			reachable = reachable || value == root || strings.HasPrefix(value, root+"/")
		}
		if !reachable {
			t.Errorf("%s is under nothing that gets collected", value)
		}
	}
	// The snapshot of the history is archived, the live database is not.
	if !strings.HasPrefix(metricsSnapshot, "/var/lib/easy-ha-proxy/") || !contains(backupExcludes, "var/lib/easy-ha-proxy/metrics") {
		t.Fatal("the monitoring history")
	}
}

func TestTheLiveDatabaseWritersAreStoppedAndTheTimerFirst(t *testing.T) {
	for _, unit := range []string{"easy-ha-proxy-guardd.service", "easy-ha-proxy-alertd.service"} {
		if !contains(quiesceUnits, unit) {
			t.Errorf("%s keeps writing during the archive", unit)
		}
	}
	index := func(v string) int {
		for i, u := range quiesceUnits {
			if u == v {
				return i
			}
		}
		return -1
	}
	if index("easy-ha-proxy-geoip-update.timer") >= index("easy-ha-proxy-geoip-update.service") {
		t.Fatal("the GeoIP timer must stop before its service")
	}
}

func TestConfigScopeSelectsExactArchiveNames(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload.tar.gz")
	writeTar(t, payload, []tarEntry{file("etc/haproxy/haproxy.cfg", "config"), file("./opt/haproxy-admin/config/websites.yml", "sites"), file("etc/easy-ha-proxy/vars.yml", "vars")})
	got, err := configScopeMembers(payload)
	if err != nil || !reflect.DeepEqual(got, []string{"etc/haproxy/haproxy.cfg", "./opt/haproxy-admin/config/websites.yml"}) {
		t.Fatalf("members %v err %v", got, err)
	}
	requireTools(t, "tar")
	dest := t.TempDir()
	oldRun := runCommand
	swap(t, &runCommand, func(argv []string, opts runOptions) (runResult, error) {
		for i, arg := range argv {
			if arg == "-C" {
				argv[i+1] = dest
				break
			}
		}
		return oldRun(argv, opts)
	})
	if err := extractPayload(payload, got); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "opt/haproxy-admin/config/websites.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "etc/easy-ha-proxy/vars.yml")); !os.IsNotExist(err) {
		t.Fatalf("out-of-scope file was extracted: %v", err)
	}
	writeTar(t, payload, []tarEntry{{name: "etc/haproxy/copy", typ: tar.TypeLink, link: "etc/easy-ha-proxy/vars.yml"}})
	if _, err := configScopeMembers(payload); err == nil {
		t.Fatal("accepted a link outside the configuration scope")
	}
}
