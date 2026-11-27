package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func TestReplaceDomainTextAndData(t *testing.T) {
	got := ReplaceDomainText("https://app.old.example.com/ old.example.com notold.example.com", "old.example.com", "new.example.net")
	want := "https://app.new.example.net/ new.example.net notold.example.com"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	src, _ := pyyaml.Load([]byte(`
root_domain: old.example.com
url: https://aut.old.example.com/access_granted
sites:
  - domain: app.old.example.com
    backend: 127.0.0.1
  - domain: www.example.org
`))
	var changes []DomainChange
	migrated := ReplaceDomainInData(src, "old.example.com", "new.example.net", "vars.yml", &changes).(*pyyaml.Map)
	if migrated.Value("root_domain") != "new.example.net" ||
		migrated.Value("url") != "https://aut.new.example.net/access_granted" ||
		len(changes) != 3 {
		t.Fatalf("unexpected migration result: %v changes=%v", mapToGoMap(migrated), changes)
	}

	vars, _ := pyyaml.Load([]byte("admin_domain: ha.new.example.net\n"))
	aut, _ := pyyaml.Load([]byte("aut_domain: aut.new.example.net\n"))
	web, _ := pyyaml.Load([]byte("sites:\n  - domain: app.new.example.net\n    alt_names: [data.new.example.net, external.example.org]\n  - domain: www.example.org\n"))
	names := DomainMigrationDNSNames(vars.(*pyyaml.Map), aut.(*pyyaml.Map), web.(*pyyaml.Map), "new.example.net")
	if strings.Join(names, ",") != "app.new.example.net,aut.new.example.net,data.new.example.net,ha.new.example.net" {
		t.Fatalf("unexpected DNS names: %v", names)
	}
}

func TestMigrateDomainAndPromoteProductionPlanOnly(t *testing.T) {
	origCfg := configDirOverride
	origRuntime := runtimeHAProxyConfigDir
	origReqRoot := requireRootFn
	origPlaybook := runPlaybookFn
	t.Cleanup(func() {
		configDirOverride = origCfg
		runtimeHAProxyConfigDir = origRuntime
		requireRootFn = origReqRoot
		runPlaybookFn = origPlaybook
	})

	dir := t.TempDir()
	configDirOverride = dir
	runtimeHAProxyConfigDir = filepath.Join(dir, "no-runtime")
	requireRootFn = func() error { return nil }

	_ = WriteText(filepath.Join(dir, "vars.yml"),
		"root_domain: easy-ha-proxy.test\nadmin_domain: ha.easy-ha-proxy.test\n"+
			"easy_ha_proxy_test_mode: true\neasy_ha_proxy_test_ip: 192.168.56.10\n"+
			"easy_ha_proxy_certificate_source: internal\nhaproxy_admin_image: clllagob/haproxy-admin-ui:alpha\n"+
			"site_defaults:\n  certificate_source: internal\n  le_managed: false\n", 0o600)
	_ = WriteText(filepath.Join(dir, "authelia.yml"), "aut_domain: aut.easy-ha-proxy.test\nauthelia_cookie_domain: easy-ha-proxy.test\n", 0o600)
	_ = WriteText(filepath.Join(dir, "websites.yml"), "sites:\n  - name: app\n    domain: app.easy-ha-proxy.test\n    backend_ip: 192.168.56.20\n", 0o600)
	_ = WriteText(filepath.Join(dir, "tcp.yml"), "tcp_proxies: []\n", 0o600)
	_ = WriteText(filepath.Join(dir, "metadata.yml"),
		"test_mode: true\ntest_server_ip: 192.168.56.10\ncertificate_source: internal\nimage_channel: alpha\n"+
			"admin_domain: ha.easy-ha-proxy.test\nauthelia_domain: aut.easy-ha-proxy.test\ninstallation_complete: true\nconfiguration_pending: false\n", 0o600)
	_ = WriteText(filepath.Join(dir, "secrets.yml"), "secret: unchanged\n", 0o600)
	_ = WriteText(filepath.Join(dir, "authelia_users_initial.yml"), "authelia_users:\n  admin:\n    password: hash\n", 0o600)
	_ = WriteText(filepath.Join(dir, "inventory.ini"), "[easy_ha_proxy]\nlocalhost ansible_connection=local\n", 0o600)

	origVarsBytes, _ := os.ReadFile(filepath.Join(dir, "vars.yml"))

	var capturedTags string
	var capturedCheck bool
	var previewVars, previewMeta *pyyaml.Map
	runPlaybookFn = func(_ *Context, tags string, opts PlaybookOptions) error {
		capturedTags = tags
		capturedCheck = opts.CheckMode
		previewVars, _ = LoadYAMLMapping(filepath.Join(opts.Directory, "vars.yml"))
		previewMeta, _ = LoadYAMLMapping(filepath.Join(opts.Directory, "metadata.yml"))
		return nil
	}

	var out, errOut bytes.Buffer
	rc := RunCLI([]string{
		"promote-production",
		"--new-domain", "example.com",
		"--certificate-source", "internal",
		"--image-channel", "latest",
		"--skip-dns-check",
		"--plan-only",
	}, strings.NewReader(""), &out, &errOut)
	if rc != 0 {
		t.Fatalf("promote-production --plan-only failed: %d %s", rc, errOut.String())
	}
	if !capturedCheck || capturedTags != InternalCAInstallTags {
		t.Fatalf("expected check=true tags=%s, got check=%v tags=%s", InternalCAInstallTags, capturedCheck, capturedTags)
	}
	if previewVars.Value("easy_ha_proxy_test_mode") != false ||
		previewVars.Value("haproxy_admin_image") != "clllagob/haproxy-admin-ui:latest" ||
		previewMeta.Value("test_mode") != false ||
		previewMeta.Value("configuration_pending") != true {
		t.Fatalf("unexpected preview values: vars=%v meta=%v", mapToGoMap(previewVars), mapToGoMap(previewMeta))
	}

	afterVarsBytes, _ := os.ReadFile(filepath.Join(dir, "vars.yml"))
	if !bytes.Equal(origVarsBytes, afterVarsBytes) {
		t.Fatal("plan-only modified original vars.yml")
	}
}

func TestBackupRuntimeUIConfigRefusesSymlink(t *testing.T) {
	// The runtime config is container-writable: a symlink to a root secret
	// must not be copied into the migration backup (and restored as root).
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secrets.yml")
	if err := os.WriteFile(secret, []byte("token: root-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(runtime, "websites.yml")); err != nil {
		t.Fatal(err)
	}
	old := runtimeHAProxyConfigDir
	runtimeHAProxyConfigDir = runtime
	t.Cleanup(func() { runtimeHAProxyConfigDir = old })
	if err := backupRuntimeUIConfig(filepath.Join(root, "backup")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked runtime config was copied: %v", err)
	}
}
