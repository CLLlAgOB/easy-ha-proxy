package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func TestReleaseChannelsAndPersistence(t *testing.T) {
	origBackup := backupConfigurationFn
	t.Cleanup(func() { backupConfigurationFn = origBackup })
	backupCount := 0
	backupConfigurationFn = func(_ ioWriter, _ string) (string, error) {
		backupCount++
		return "", nil
	}

	dir := t.TempDir()
	_ = WriteText(filepath.Join(dir, "vars.yml"), "root_domain: example.test\nhaproxy_admin_image: repo:latest\n", 0o600)
	_ = WriteText(filepath.Join(dir, "metadata.yml"), "product: easy-ha-proxy\n", 0o600)

	var out bytes.Buffer
	if err := PersistDeploymentChannels(&out, ChannelOptions{ReleaseChannel: "alpha", Directory: dir}); err != nil {
		t.Fatal(err)
	}
	meta, _ := LoadYAMLMapping(filepath.Join(dir, "metadata.yml"))
	vars, _ := LoadYAMLMapping(filepath.Join(dir, "vars.yml"))
	if meta.Value("source_channel") != "github" || meta.Value("branch") != "alpha" || meta.Value("image_channel") != "alpha" {
		t.Fatalf("unexpected alpha metadata: %v", mapToGoMap(meta))
	}
	if !strings.HasSuffix(strVal(vars.Value("haproxy_admin_image")), ":alpha") {
		t.Fatalf("unexpected alpha image: %v", vars.Value("haproxy_admin_image"))
	}

	// Local channel only changes source_channel, leaving branch/image untouched.
	if err := PersistDeploymentChannels(&out, ChannelOptions{ReleaseChannel: "local", Directory: dir}); err != nil {
		t.Fatal(err)
	}
	meta, _ = LoadYAMLMapping(filepath.Join(dir, "metadata.yml"))
	if meta.Value("source_channel") != "local" || meta.Value("branch") != "alpha" || meta.Value("image_channel") != "alpha" {
		t.Fatalf("unexpected local metadata: %v", mapToGoMap(meta))
	}

	// Switch to stable.
	if err := PersistDeploymentChannels(&out, ChannelOptions{ReleaseChannel: "stable", Directory: dir}); err != nil {
		t.Fatal(err)
	}
	meta, _ = LoadYAMLMapping(filepath.Join(dir, "metadata.yml"))
	if meta.Value("branch") != "main" || meta.Value("image_channel") != "latest" {
		t.Fatalf("unexpected stable metadata: %v", mapToGoMap(meta))
	}

	if err := PersistDeploymentChannels(&out, ChannelOptions{ReleaseChannel: "nightly", Directory: dir}); err == nil {
		t.Fatal("expected invalid release channel error")
	}

	if ReleaseChannelFromSettings("github", "main", "alpha") != "alpha" ||
		ReleaseChannelFromSettings("github", "main", "latest") != "stable" ||
		ReleaseChannelFromSettings("local", "main", "latest") != "local" {
		t.Fatal("unexpected ReleaseChannelFromSettings derivation")
	}
	if backupCount != 3 {
		t.Fatalf("expected 3 backups, got %d", backupCount)
	}
}

func TestSyncRuntimeHAProxyConfig(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	runtime := filepath.Join(root, "runtime")
	_ = os.MkdirAll(managed, 0o700)
	_ = os.MkdirAll(runtime, 0o700)

	_ = WriteText(filepath.Join(managed, "metadata.yml"), "configuration_pending: false\n", 0o600)
	_ = WriteText(filepath.Join(managed, "vars.yml"),
		"admin_domain: ha.managed.example.test\n"+
			"admin_authelia_enabled: true\n"+
			"haproxy_admin_image: example/admin:alpha\n"+
			"enable_http80: false\n"+
			"export_prometheus: true\n", 0o600)
	_ = WriteText(filepath.Join(managed, "websites.yml"), "sites: []\n", 0o600)
	_ = WriteText(filepath.Join(managed, "tcp.yml"), "tcp_proxies: []\n", 0o600)

	_ = WriteText(filepath.Join(runtime, "vars.yml"),
		"admin_domain: ha.stale.example.test\n"+
			"admin_authelia_enabled: false\n"+
			"haproxy_admin_image: example/admin:latest\n"+
			"enable_http80: true\n"+
			"geoip_country_codes: [PL, RU]\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "websites.yml"),
		"sites:\n  - name: app\n    domain: app.example.test\n    geo_countries: [PL]\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "tcp.yml"),
		"tcp_proxies:\n  - name: ssh\n    bind_port: 2222\n", 0o600)

	var out bytes.Buffer
	changed, err := SyncRuntimeHAProxyConfigToManaged(&out, managed, runtime)
	if err != nil || !changed {
		t.Fatalf("expected sync to succeed and change: changed=%v err=%v", changed, err)
	}
	vars, _ := LoadYAMLMapping(filepath.Join(managed, "vars.yml"))
	if vars.Value("enable_http80") != true {
		t.Fatalf("expected enable_http80=true, got %v", vars.Value("enable_http80"))
	}
	if vars.Value("admin_domain") != "ha.managed.example.test" || vars.Value("haproxy_admin_image") != "example/admin:alpha" {
		t.Fatalf("installer-owned keys were overwritten: %v", mapToGoMap(vars))
	}
	if _, exists := vars.Get("export_prometheus"); exists {
		t.Fatal("removed runtime key export_prometheus should be deleted")
	}

	// Unknown top-level key rejected without modifying managed files.
	_ = WriteText(filepath.Join(runtime, "websites.yml"), "sites: []\nfuture_ansible_override: blocked\n", 0o600)
	if _, err := SyncRuntimeHAProxyConfigToManaged(&out, managed, runtime); err == nil || !strings.Contains(err.Error(), "Unsupported top-level key") {
		t.Fatalf("expected unknown root key rejection, got %v", err)
	}

	// Pending configuration blocks runtime override.
	_ = WriteText(filepath.Join(managed, "metadata.yml"), "configuration_pending: true\n", 0o600)
	_ = WriteText(filepath.Join(runtime, "websites.yml"), "sites: []\n", 0o600)
	changed, err = SyncRuntimeHAProxyConfigToManaged(&out, managed, runtime)
	if err != nil || changed {
		t.Fatalf("pending configuration must ignore runtime: changed=%v err=%v", changed, err)
	}
}

func TestSyncRuntimeAutheliaRules(t *testing.T) {
	root := t.TempDir()
	managedDir := filepath.Join(root, "etc")
	_ = os.MkdirAll(managedDir, 0o700)
	managedPath := filepath.Join(managedDir, "authelia.yml")
	runtimePath := filepath.Join(root, "configuration.yml")
	_ = WriteText(filepath.Join(managedDir, "metadata.yml"), "{}\n", 0o600)

	writeManaged := func(rules string) {
		_ = WriteText(managedPath, "authelia_enabled: true\nauthelia_totp_issuer: example\nauthelia_access_control_rules:\n"+rules, 0o600)
	}
	writeManaged("  - domain: ha.example.test\n    policy: one_factor\n")
	_ = WriteText(runtimePath, "access_control:\n  default_policy: deny\n  rules:\n    - domain: ha.example.test\n      policy: one_factor\n    - domain: docker.example.test\n      policy: two_factor\n", 0o600)

	var out bytes.Buffer
	changed, err := SyncRuntimeAutheliaRulesToManaged(&out, managedDir, runtimePath)
	if err != nil || !changed {
		t.Fatalf("expected rules sync: changed=%v err=%v", changed, err)
	}
	loaded, _ := LoadYAMLMapping(managedPath)
	rules, _ := loaded.Value("authelia_access_control_rules").([]any)
	if len(rules) != 2 || loaded.Value("authelia_totp_issuer") != "example" {
		t.Fatalf("unexpected synced authelia.yml: %v", mapToGoMap(loaded))
	}

	// Idempotent when equal.
	changed, err = SyncRuntimeAutheliaRulesToManaged(&out, managedDir, runtimePath)
	if err != nil || changed {
		t.Fatalf("expected no-op when equal: changed=%v err=%v", changed, err)
	}

	// Empty list never wipes existing managed rules.
	_ = WriteText(runtimePath, "access_control:\n  default_policy: deny\n  rules: []\n", 0o600)
	changed, err = SyncRuntimeAutheliaRulesToManaged(&out, managedDir, runtimePath)
	if err != nil || changed {
		t.Fatalf("empty rule list must not wipe managed rules")
	}

	// Broken YAML is ignored safely.
	for _, bad := range []string{
		"access_control: [not, a, mapping]\n",
		"access_control:\n  rules: nope\n",
		"access_control:\n  rules:\n    - just a string\n",
		"{{ not yaml",
		"- top list\n",
	} {
		_ = WriteText(runtimePath, bad, 0o600)
		if changed, err := SyncRuntimeAutheliaRulesToManaged(&out, managedDir, runtimePath); err != nil || changed {
			t.Fatalf("broken runtime YAML %q should be ignored: changed=%v err=%v", bad, changed, err)
		}
	}
}

func TestOfflineRestoreRequiredImages(t *testing.T) {
	origSubproc := runSubprocessFn
	origDockerExists := dockerContainerExistsFn
	t.Cleanup(func() {
		runSubprocessFn = origSubproc
		dockerContainerExistsFn = origDockerExists
	})

	repoRoot := resolvePath(filepath.Join("..", "..", "..", ".."))
	if !fileExists(filepath.Join(repoRoot, "ansible/roles/haproxy-admin/defaults/main.yml")) {
		t.Skip("repo root not found relative to package")
	}
	cfg := t.TempDir()
	_ = WriteText(filepath.Join(cfg, "vars.yml"),
		"haproxy_admin_image_channel: alpha\n"+
			"haproxy_admin_use_docker: true\n"+
			"authelia_enabled: true\n"+
			"authelia_session_redis_enabled: true\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "authelia.yml"),
		"mail_notify_enabled: false\n"+
			"mail_relay_server: false\n", 0o600)

	runSubprocessFn = func(name string, args ...string) subprocessResult {
		return subprocessResult{ExitCode: 0, Stdout: "1d91160cd370abcdef0123456789\n"}
	}
	dockerContainerExistsFn = func(string) bool { return false }

	images, err := OfflineRestoreRequiredImages(cfg, repoRoot)
	if err != nil {
		t.Fatalf("OfflineRestoreRequiredImages failed: %v", err)
	}
	if !images["clllagob/haproxy-admin-ui:go-alpha"] {
		t.Fatalf("missing go-alpha image in %v", images)
	}
	if !images["clllagob/haproxy-admin-ui:native-alpha-1d91160cd370"] {
		t.Fatalf("missing native-alpha pinned image in %v", images)
	}
	for img := range images {
		if strings.Contains(img, "postfix") {
			t.Fatalf("unused mail relay image should be omitted: %v", images)
		}
	}

	// Mail relay included when container exists or enabled.
	dockerContainerExistsFn = func(string) bool { return true }
	images, err = OfflineRestoreRequiredImages(cfg, repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	foundPostfix := false
	for img := range images {
		if strings.Contains(img, "postfix") {
			foundPostfix = true
		}
	}
	if !foundPostfix {
		t.Fatalf("expected mail relay image when container exists: %v", images)
	}
}

func TestUpdateManagedSourceAndReexec(t *testing.T) {
	origHome := installHomeOverride
	origSrc := sourceDirOverride
	origGitRev := gitRevisionFn
	origRunCmd := runCommandFn
	origExec := execveFn
	t.Cleanup(func() {
		installHomeOverride = origHome
		sourceDirOverride = origSrc
		gitRevisionFn = origGitRev
		runCommandFn = origRunCmd
		execveFn = origExec
	})

	home := t.TempDir()
	src := filepath.Join(home, "source")
	_ = os.MkdirAll(filepath.Join(src, ".git"), 0o755)
	installHomeOverride = home
	sourceDirOverride = src

	expected := strings.Repeat("a", 40)
	gitRevisionFn = func(dir, ref string) (string, error) { return expected, nil }
	var cmds [][]string
	runCommandFn = func(_ ioWriter, cmd []string, _ []string) error {
		cmds = append(cmds, cmd)
		return nil
	}
	var out bytes.Buffer
	replaced, err := UpdateManagedSource(&out, expected)
	if err != nil || !replaced {
		t.Fatalf("UpdateManagedSource failed: replaced=%v err=%v", replaced, err)
	}
	if len(cmds) != 2 || cmds[0][3] != "fetch" || cmds[1][3] != "reset" {
		t.Fatalf("unexpected git commands: %v", cmds)
	}

	// Mismatched fetched revision is rejected before reset.
	cmds = nil
	gitRevisionFn = func(dir, ref string) (string, error) { return strings.Repeat("b", 40), nil }
	if _, err := UpdateManagedSource(&out, expected); err == nil || !strings.Contains(err.Error(), "changed after the update check") {
		t.Fatalf("expected revision mismatch error, got %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("reset must not run on revision mismatch: %v", cmds)
	}

	// Reexec preserves args and sets one-shot env marker.
	entry := filepath.Join(src, "installer/easy-ha-proxy")
	_ = os.MkdirAll(filepath.Dir(entry), 0o755)
	_ = os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o755)
	var execPath string
	var execArgv, execEnv []string
	execveFn = func(argv0 string, argv []string, envv []string) error {
		execPath = argv0
		execArgv = argv
		execEnv = envv
		return errors.New("stop-exec")
	}
	_ = ReexecAfterSourceUpdate(&out, []string{"update", "--source-channel", "github"})
	if execPath != entry || len(execArgv) != 4 || execArgv[1] != "update" {
		t.Fatalf("unexpected exec args: %s %v", execPath, execArgv)
	}
	hasMarker := false
	for _, e := range execEnv {
		if e == UpdateSourceRefreshedEnv+"=1" {
			hasMarker = true
		}
	}
	if !hasMarker {
		t.Fatal("reexec env missing UPDATE_SOURCE_REFRESHED marker")
	}
}

func TestMarkInstallationCompleteAndDNSPreflight(t *testing.T) {
	origLookup := lookupHostFn
	t.Cleanup(func() { lookupHostFn = origLookup })

	dir := t.TempDir()
	_ = WriteText(filepath.Join(dir, "metadata.yml"), "product: easy-ha-proxy\ninstallation_complete: false\nconfiguration_pending: true\n", 0o600)
	if err := MarkInstallationComplete(dir); err != nil {
		t.Fatal(err)
	}
	meta, _ := LoadYAMLMapping(filepath.Join(dir, "metadata.yml"))
	if meta.Value("installation_complete") != true || meta.Value("configuration_pending") != false || strVal(meta.Value("installation_completed_at")) == "" {
		t.Fatalf("unexpected completed metadata: %v", mapToGoMap(meta))
	}

	_ = WriteText(filepath.Join(dir, "vars.yml"), "admin_domain: ha.private.example\n", 0o600)
	_ = WriteText(filepath.Join(dir, "authelia.yml"), "aut_domain: aut.private.example\n", 0o600)
	lookupHostFn = func(string) ([]string, error) { return nil, errors.New("not found") }
	var out bytes.Buffer
	ready, err := DNSPreflight(&out, dir)
	if err != nil || ready {
		t.Fatalf("unresolved DNS should return ready=false without error: ready=%v err=%v", ready, err)
	}
	_ = pyyaml.NewMap()
}
