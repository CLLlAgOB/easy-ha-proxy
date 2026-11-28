//go:build haproxymigrate_smoke

// Real package/reload/rollback/patch qualification on disposable Ubuntu 24.04 only.
//
// Never run on a production gateway. Requires root and EHP_MIGRATION_DISPOSABLE=1.
package haproxymigrate

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/tools"
	_ "modernc.org/sqlite"
)

func smokeExec(t *testing.T, cwd string, argv ...string) string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %v failed: %v\n%s", argv, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func setupMigrationFixture(t *testing.T, repoRoot string) {
	t.Helper()
	varsFile := "/etc/easy-ha-proxy/vars.yml"
	marker := "/etc/easy-ha-proxy/migration-fixture/owned"
	if lexists(varsFile) && !lexists(marker) {
		t.Fatal("Refusing to replace an existing managed installation")
	}
	for _, name := range []string{"haproxy-controld", "easy-ha-proxy-guardd", "haproxy-certd"} {
		p := filepath.Join("/etc/systemd/system", name+".service")
		if lexists(p) && !lexists(marker) {
			t.Fatalf("Refusing to replace an existing host service: %s", p)
		}
	}
	base := filepath.Dir(marker)
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(marker, []byte("disposable migration qualification\n"), 0o600)
	_ = os.WriteFile(varsFile, []byte("admin_domain: admin.example.test\nkeep_this_setting: preserved\n"), 0o600)
	_ = os.Chmod(varsFile, 0o600)

	dbPath := "/var/lib/easy-ha-proxy/security/security.db"
	_ = os.MkdirAll(filepath.Dir(dbPath), 0o755)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS ip_state (ip TEXT PRIMARY KEY, banned_until INTEGER)`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS manual_bans (ip TEXT PRIMARY KEY, expires_at INTEGER)`)
	_ = db.Close()

	smokeExec(t, "", "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
		"-subj", "/CN=admin.example.test",
		"-addext", "subjectAltName=DNS:admin.example.test,DNS:auth.example.test",
		"-keyout", filepath.Join(base, "key.pem"), "-out", filepath.Join(base, "cert.pem"))
	certBytes, _ := os.ReadFile(filepath.Join(base, "cert.pem"))
	keyBytes, _ := os.ReadFile(filepath.Join(base, "key.pem"))
	_ = os.WriteFile(filepath.Join(base, "combined.pem"), append(certBytes, keyBytes...), 0o600)
	_ = os.WriteFile("/usr/local/share/ca-certificates/ehp-migration-fixture.crt", certBytes, 0o644)
	smokeExec(t, "", "update-ca-certificates")

	_ = os.MkdirAll("/var/lib/haproxy", 0o755)
	_ = os.WriteFile("/var/lib/haproxy/server-state", []byte("1\n"), 0o600)
	_ = os.MkdirAll("/run/haproxy", 0o755)

	cfg := fmt.Sprintf(`global
    localpeer ha-local
    nbthread 1
    user haproxy
    group haproxy
    stats socket /run/haproxy/admin.sock mode 600 user root group root level admin
    server-state-file /var/lib/haproxy/server-state
    .if !feature(OPENSSL_AWSLC)
    tune.ssl.default-dh-param 2048
    .endif
    .if version_atleast(3.1)
    tune.lua.bool-sample-conversion normal
    .endif
defaults
    mode http
    timeout connect 1s
    timeout client 5s
    timeout server 5s
    load-server-state-from-file global
peers migration
    peer ha-local 127.0.0.1:19240
backend tbl_ban
    stick-table type ip size 1k expire 30m store gpc0,gpt0 peers migration
backend tbl_ip_auth
    stick-table type ip size 1k expire 30m store gpc0 peers migration
frontend fe_https
    bind 127.0.0.1:443 ssl crt %s/combined.pem
    acl host_admin hdr(host) -i admin.example.test
    acl host_authelia hdr(host) -i auth.example.test
    http-request return status 200 if host_admin { path /api/control-plane-health }
    http-request redirect location https://auth.example.test/ if host_admin
    http-request return status 200 if host_authelia { path /api/health }
    default_backend be_admin
backend be_admin
    server fixture 127.0.0.1:19999
`, base)
	_ = os.WriteFile("/etc/haproxy/haproxy.cfg", []byte(cfg), 0o644)

	dropins := "/etc/systemd/system/haproxy.service.d"
	_ = os.MkdirAll(dropins, 0o755)
	tmplRaw, err := os.ReadFile(filepath.Join(repoRoot, "ansible/roles/haproxy/templates/haproxy-state-dump.sh.j2"))
	if err != nil {
		t.Fatal(err)
	}
	dumperTxt := strings.ReplaceAll(string(tmplRaw), "{{ haproxy_socket | default('/run/haproxy/admin.sock') }}", "/run/haproxy/admin.sock")
	dumperTxt = strings.ReplaceAll(dumperTxt, "{{ haproxy_server_state_file | default('/var/lib/haproxy/server-state') }}", "/var/lib/haproxy/server-state")
	dumperTxt = strings.ReplaceAll(dumperTxt, "{{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }}", os.Getenv("EHP_AGENT"))
	_ = os.WriteFile("/usr/local/sbin/haproxy-state-dump", []byte(dumperTxt), 0o755)
	_ = os.WriteFile(filepath.Join(dropins, "server-state.conf"), []byte("[Service]\nExecStartPre=-/usr/local/sbin/haproxy-state-dump\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dropins, "override.conf"), []byte("[Service]\nExecStart=\nExecStart=/usr/sbin/haproxy -Ws \\\n    -S /run/haproxy/master.sock,mode,660,user,root,group,haproxy \\\n    -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid\n"), 0o644)
	for _, name := range []string{"haproxy-controld", "easy-ha-proxy-guardd", "haproxy-certd"} {
		_ = os.WriteFile(filepath.Join("/etc/systemd/system", name+".service"),
			[]byte("[Unit]\nDescription=Disposable migration qualification fixture\n[Service]\nExecStart=/bin/sleep infinity\n"), 0o644)
	}
	smokeExec(t, "", "systemctl", "daemon-reload")
	smokeExec(t, "", "systemctl", "start", "haproxy-controld", "easy-ha-proxy-guardd", "haproxy-certd")
}

func dumpSmokeDiagnostics(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	matches, _ := filepath.Glob("/var/lib/easy-ha-proxy/haproxy-package-migration/*/transaction.json")
	for _, m := range matches {
		if b, err := os.ReadFile(m); err == nil {
			t.Logf("transaction %s: %s", m, string(b))
		}
		logPath := filepath.Join(filepath.Dir(m), "commands.jsonl")
		if b, err := os.ReadFile(logPath); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, `"rc":0`) || strings.TrimSpace(line) == "" {
					continue
				}
				t.Logf("failed cmd: %s", line)
			}
		}
	}
}

func TestDisposableHAProxyMigration(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("EHP_MIGRATION_DISPOSABLE") != "1" {
		t.Fatal("Requires root and EHP_MIGRATION_DISPOSABLE=1 on a disposable system")
	}
	defer dumpSmokeDiagnostics(t)
	repoRoot := os.Getenv("EHP_REPO_ROOT")
	if repoRoot == "" {
		repoRoot, _ = filepath.Abs("../../..")
	}
	if agent := os.Getenv("EHP_AGENT"); agent != "" {
		origBin := engineBinaryFunc
		engineBinaryFunc = func() (string, error) { return agent, nil }
		defer func() { engineBinaryFunc = origBin }()
	}
	setupMigrationFixture(t, repoRoot)

	host := &SystemHost{}
	if err := host.Service("restart", "haproxy.service"); err != nil {
		t.Fatal(err)
	}
	paths := DefaultPaths()
	paths.Source = repoRoot
	e := NewEngine(&paths, host)
	baselinePkgs, err := host.Packages()
	if err != nil {
		t.Fatal(err)
	}
	oldVer := baselinePkgs["haproxy"]
	if _, err := e.waitWorker(oldVer, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Health(); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"set table tbl_ban key 198.51.100.22 data.gpc0 1 data.gpt0 40",
		"set table tbl_ip_auth key 198.51.100.22 data.gpc0 7",
		"set server be_admin/fixture state maint",
		"set server be_admin/fixture weight 17",
	} {
		if _, err := runtimeCmdFunc(paths.Socket, cmd); err != nil {
			t.Fatal(err)
		}
	}
	baselineCfg, _ := os.ReadFile(paths.Config)
	origVars, _ := os.ReadFile(paths.Variables)

	// 1. Exercise post-switch rollback
	ex, err := e.Migrate(true)
	if err != nil {
		t.Fatalf("exercise rollback failed: %v", err)
	}
	if ex["target_verified"] != true || ex["rollback_verified"] != true {
		t.Fatalf("unexpected exercise summary: %v", ex)
	}
	if info, _ := runtimeInfoFunc(paths.Socket); info["Version"] != oldVer {
		t.Fatalf("version after exercise=%q want %q", info["Version"], oldVer)
	}

	// 2. Cold failure rollback
	cold := NewEngine(&paths, host)
	fired := false
	cold.HealthHook = func() error {
		if err := cold.DefaultHealth(); err != nil {
			return err
		}
		if info, _ := runtimeInfoFunc(paths.Socket); !fired && strings.HasPrefix(info["Version"], "3.4.") {
			fired = true
			_ = host.Service("stop", "haproxy.service")
			return migErr("Injected failed candidate service")
		}
		return nil
	}
	prep, err := cold.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cold.Apply(strVal(prep["id"]), false); err == nil {
		t.Fatal("Injected failure unexpectedly succeeded")
	}
	if !fired || cold.State["rollback_verified"] != true || cold.State["phase"] != "rolled_back" {
		t.Fatalf("cold rollback state: fired=%v phase=%v rb=%v", fired, cold.State["phase"], cold.State["rollback_verified"])
	}

	// 3. Full commit + manual rollback
	e2 := NewEngine(&paths, host)
	applied, err := e2.Migrate(false)
	if err != nil || applied["phase"] != "committed" {
		t.Fatalf("full migrate: %v %v", applied, err)
	}
	if info, _ := runtimeInfoFunc(paths.Socket); !strings.HasPrefix(info["Version"], "3.4.") {
		t.Fatalf("expected 3.4 after commit, got %q", info["Version"])
	}
	rb, err := e2.Rollback(strVal(applied["id"]))
	if err != nil || rb["rollback_verified"] != true {
		t.Fatalf("manual rollback: %v %v", rb, err)
	}
	if info, _ := runtimeInfoFunc(paths.Socket); info["Version"] != oldVer {
		t.Fatalf("version after manual rollback=%q want %q", info["Version"], oldVer)
	}
	if curCfg, _ := os.ReadFile(paths.Config); !bytes.Equal(curCfg, baselineCfg) {
		t.Fatal("config mismatch after rollback")
	}
	if curVars, _ := os.ReadFile(paths.Variables); !bytes.Equal(curVars, origVars) {
		t.Fatal("vars mismatch after rollback")
	}
	for _, tab := range []string{"tbl_ban", "tbl_ip_auth"} {
		rows, err := tableRowsFunc(paths.Socket, tab)
		if err != nil || len(rows) != 1 {
			t.Fatalf("table %s rows=%d err=%v", tab, len(rows), err)
		}
	}
}

func TestDisposableHAProxyPatch(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("EHP_MIGRATION_DISPOSABLE") != "1" {
		t.Fatal("Requires root and EHP_MIGRATION_DISPOSABLE=1 on a disposable system")
	}
	defer dumpSmokeDiagnostics(t)
	repoRoot := os.Getenv("EHP_REPO_ROOT")
	if repoRoot == "" {
		repoRoot, _ = filepath.Abs("../../..")
	}
	if agent := os.Getenv("EHP_AGENT"); agent != "" {
		origBin := engineBinaryFunc
		engineBinaryFunc = func() (string, error) { return agent, nil }
		defer func() { engineBinaryFunc = origBin }()
	}
	setupMigrationFixture(t, repoRoot)

	host := &SystemHost{}
	pkgs, err := host.Packages()
	if err != nil {
		t.Fatal(err)
	}
	name := "haproxy"
	if pkgs["haproxy-awslc"] != "" {
		name = "haproxy-awslc"
	}
	wanted := map[string]string{name: pkgs[name]}
	if name == "haproxy-awslc" {
		wanted["libssl-awslc"] = pkgs["libssl-awslc"]
		_ = os.WriteFile("/etc/easy-ha-proxy/vars.yml", []byte("haproxy_package_provider: haproxy-technologies\nhaproxy_package_branch: \"3.4\"\n"), 0o600)
	}
	for pkg := range wanted {
		smokeExec(t, "", "apt-mark", "hold", pkg)
	}
	if err := host.Service("restart", "haproxy.service"); err != nil {
		t.Fatal(err)
	}
	paths := DefaultPaths()
	paths.Source = repoRoot
	e := NewEngine(&paths, host)
	vOut := smokeExec(t, "", "haproxy", "-v")
	m := haproxyVerRe.FindStringSubmatch(vOut)
	if m == nil {
		t.Fatalf("unparseable haproxy -v: %s", vOut)
	}
	if _, err := e.waitWorker(m[1], ""); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"set table tbl_ban key 198.51.100.22 data.gpc0 1 data.gpt0 40",
		"set table tbl_ip_auth key 198.51.100.22 data.gpc0 7",
		"set server be_admin/fixture state maint",
		"set server be_admin/fixture weight 17",
	} {
		if _, err := runtimeCmdFunc(paths.Socket, cmd); err != nil {
			t.Fatal(err)
		}
	}

	base, err := os.MkdirTemp("", "ehp-disposable-patch-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	_ = os.Chmod(base, 0o755)
	sourceList := "/etc/apt/sources.list.d/ehp-disposable-patch.list"
	defer os.Remove(sourceList)

	arch := smokeExec(t, "", "dpkg", "--print-architecture")
	repo := filepath.Join(base, "repo")
	pool := filepath.Join(repo, "pool")
	_ = os.MkdirAll(pool, 0o755)
	var records strings.Builder
	targets := map[string]string{}
	verLineRe := regexp.MustCompile(`(?m)^Version: .*$`)
	for pkgName, ver := range wanted {
		smokeExec(t, base, "apt-get", "-o", "APT::Get::AllowUnauthenticated=false", "download", pkgName+"="+ver)
		debs, _ := filepath.Glob(filepath.Join(base, "*.deb"))
		var archDeb string
		for _, d := range debs {
			if smokeExec(t, "", "dpkg-deb", "-f", d, "Package") == pkgName {
				archDeb = d
				break
			}
		}
		unpack := filepath.Join(base, "unpack-"+pkgName)
		smokeExec(t, "", "dpkg-deb", "-R", archDeb, unpack)
		ctrlPath := filepath.Join(unpack, "DEBIAN/control")
		ctrlRaw, _ := os.ReadFile(ctrlPath)
		targetVer := ver + "+fixture1"
		ctrlTxt := verLineRe.ReplaceAllString(string(ctrlRaw), "Version: "+targetVer)
		if pkgName == "haproxy-awslc" {
			ctrlTxt = strings.ReplaceAll(ctrlTxt, "libssl-awslc (= "+wanted["libssl-awslc"]+")", "libssl-awslc (= "+wanted["libssl-awslc"]+"+fixture1)")
		}
		_ = os.WriteFile(ctrlPath, []byte(ctrlTxt), 0o644)
		outDeb := filepath.Join(pool, pkgName+".deb")
		smokeExec(t, "", "dpkg-deb", "--build", unpack, outDeb)
		fi, _ := os.Stat(outDeb)
		dig, _ := fileDigest(outDeb)
		fmt.Fprintf(&records, "%s\nFilename: pool/%s\nSize: %d\nSHA256: %s\n\n",
			smokeExec(t, "", "dpkg-deb", "-f", outDeb), filepath.Base(outDeb), fi.Size(), dig)
		targets[pkgName] = targetVer
	}
	distDir := filepath.Join(repo, "dists/noble")
	idxDir := filepath.Join(distDir, "main/binary-"+arch)
	_ = os.MkdirAll(idxDir, 0o755)
	pkgBytes := []byte(records.String())
	_ = os.WriteFile(filepath.Join(idxDir, "Packages"), pkgBytes, 0o644)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(pkgBytes)
	_ = gz.Close()
	_ = os.WriteFile(filepath.Join(idxDir, "Packages.gz"), gzBuf.Bytes(), 0o644)
	var rel strings.Builder
	fmt.Fprintf(&rel, "Origin: EHP-Disposable-Fixture\nLabel: EHP-Disposable-Fixture\nSuite: noble\nCodename: noble\nDate: %s\nArchitectures: %s\nComponents: main\nSHA256:\n",
		time.Now().UTC().Format(time.RFC1123), arch)
	for _, item := range []struct {
		rel  string
		data []byte
	}{
		{"main/binary-" + arch + "/Packages", pkgBytes},
		{"main/binary-" + arch + "/Packages.gz", gzBuf.Bytes()},
	} {
		s := sha256.Sum256(item.data)
		fmt.Fprintf(&rel, " %s %d %s\n", hex.EncodeToString(s[:]), len(item.data), item.rel)
	}
	_ = os.WriteFile(filepath.Join(distDir, "Release"), []byte(rel.String()), 0o644)
	gpgHome := filepath.Join(base, "gnupg")
	_ = os.MkdirAll(gpgHome, 0o700)
	gpgBase := []string{"gpg", "--homedir", gpgHome, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""}
	smokeExec(t, "", append(gpgBase, "--quick-generate-key", "EHP disposable test <fixture@example.test>", "rsa2048", "sign", "0")...)
	keyPath := filepath.Join(base, "fixture.asc")
	keyOut := smokeExec(t, "", append(gpgBase, "--armor", "--export")...)
	_ = os.WriteFile(keyPath, []byte(keyOut+"\n"), 0o644)
	smokeExec(t, "", append(gpgBase, "--yes", "--clearsign", "--output", filepath.Join(distDir, "InRelease"), filepath.Join(distDir, "Release"))...)

	_ = os.WriteFile(sourceList, []byte(fmt.Sprintf("deb [signed-by=%s] file://%s noble main\n", keyPath, repo)), 0o644)
	meta, err := tools.RefreshAptMetadata(tools.AptMetadataState, "/etc/apt", 100*time.Second)
	if err != nil || meta["fresh"] != true {
		t.Fatalf("metadata refresh failed: %v %v", meta, err)
	}

	defaultsDir := filepath.Join(base, "source/ansible/roles/haproxy/defaults")
	_ = os.MkdirAll(defaultsDir, 0o755)
	keyDig, _ := fileDigest(keyPath)
	_ = os.WriteFile(filepath.Join(defaultsDir, "main.yml"), []byte("haproxy_community_key_sha256: "+keyDig+"\n"), 0o644)
	patchPaths := DefaultPaths()
	patchPaths.Source = filepath.Join(base, "source")

	newPatcher := func() *Engine {
		pe := NewEngine(&patchPaths, host)
		pe.Vendor = "file://" + repo + "/"
		pe.KeyURL = "file://" + keyPath
		return pe
	}

	// Ordinary apt-get upgrade must leave held packages untouched
	sim := smokeExec(t, "", "apt-get", "-s", "upgrade")
	for pkg := range wanted {
		if regexp.MustCompile(`(?m)^Inst ` + regexp.QuoteMeta(pkg) + `(?:\s|:)`).MatchString(sim) {
			t.Fatalf("ordinary upgrade touched held package %s:\n%s", pkg, sim)
		}
	}

	// 1. Exercise rollback
	p1 := newPatcher()
	prep1, err := p1.PreparePatch(targets[name], false)
	if err != nil {
		t.Fatal(err)
	}
	ex1, err := p1.Apply(strVal(prep1["id"]), true)
	if err != nil || ex1["rollback_verified"] != true {
		t.Fatalf("patch exercise rollback: %v %v", ex1, err)
	}
	if cur, _ := host.Packages(); cur[name] != wanted[name] {
		t.Fatalf("package not restored: %q vs %q", cur[name], wanted[name])
	}

	// 2. Cold failure rollback
	cold := newPatcher()
	fired := false
	cold.HealthHook = func() error {
		if err := cold.DefaultHealth(); err != nil {
			return err
		}
		if cur, _ := host.Packages(); !fired && strVal(cold.State["phase"]) == "installing_target" && cur[name] == targets[name] {
			fired = true
			_ = host.Service("stop", "haproxy.service")
			return migErr("Injected unavailable patched worker")
		}
		return nil
	}
	prepCold, err := cold.PreparePatch(targets[name], false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cold.Apply(strVal(prepCold["id"]), false); err == nil {
		t.Fatal("cold failure unexpectedly succeeded")
	}
	if !fired || cold.State["rollback_verified"] != true {
		t.Fatalf("cold patch rollback failed: fired=%v rb=%v", fired, cold.State["rollback_verified"])
	}

	// 3. Apply + manual rollback
	p2 := newPatcher()
	prep2, err := p2.PreparePatch(targets[name], false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Apply(strVal(prep2["id"]), false); err != nil {
		t.Fatal(err)
	}
	if cur, _ := host.Packages(); cur[name] != targets[name] {
		t.Fatalf("patched version mismatch: %q vs %q", cur[name], targets[name])
	}
	rb, err := p2.Rollback(strVal(prep2["id"]))
	if err != nil || rb["rollback_verified"] != true {
		t.Fatalf("patch manual rollback: %v %v", rb, err)
	}
	if cur, _ := host.Packages(); cur[name] != wanted[name] {
		t.Fatalf("post-rollback version mismatch: %q vs %q", cur[name], wanted[name])
	}
	out, _ := json.MarshalIndent(map[string]any{"ok": true, "package": name, "target": targets[name]}, "", "  ")
	t.Log(string(out))
}
