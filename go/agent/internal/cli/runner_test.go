package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetRunnerHooks(t *testing.T) {
	t.Helper()
	origAgent := agentBinary
	origStaged := stagedAgent
	origSrc := sourceDirOverride
	origCfg := configDirOverride
	origHome := installHomeOverride
	origSubproc := runSubprocessFn
	origRunCmd := runCommandFn
	origOffer := offerPendingRebootFn
	origFetch := fetchRunnerFn
	origPlaybook := runPlaybookFn
	origReqRoot := requireRootFn
	origUpdateSrc := updateManagedSourceFn
	origReexec := reexecAfterSourceFn
	origSyncDeps := syncRuntimeDepsFn
	origChanges := changesScopeFn
	origRecord := recordAppliedSourceFn
	origBackup := backupConfigurationFn
	origLockPath := maintenanceLockPath
	origBroker := startedByUpdateBrokerFn

	t.Cleanup(func() {
		ReleaseMaintenanceLock()
		agentBinary = origAgent
		stagedAgent = origStaged
		sourceDirOverride = origSrc
		configDirOverride = origCfg
		installHomeOverride = origHome
		runSubprocessFn = origSubproc
		runCommandFn = origRunCmd
		offerPendingRebootFn = origOffer
		fetchRunnerFn = origFetch
		runPlaybookFn = origPlaybook
		requireRootFn = origReqRoot
		updateManagedSourceFn = origUpdateSrc
		reexecAfterSourceFn = origReexec
		syncRuntimeDepsFn = origSyncDeps
		changesScopeFn = origChanges
		recordAppliedSourceFn = origRecord
		backupConfigurationFn = origBackup
		maintenanceLockPath = origLockPath
		startedByUpdateBrokerFn = origBroker
	})
}

func TestRunPlaybookBootstrapAndFallback(t *testing.T) {
	resetRunnerHooks(t)
	root := t.TempDir()
	agent := filepath.Join(root, "easy-ha-proxy-agent")
	fetched := filepath.Join(root, "staged-agent")
	_ = os.WriteFile(agent, []byte("#!/bin/sh\n"), 0o755)
	_ = os.WriteFile(fetched, []byte("#!/bin/sh\n"), 0o755)
	cfg := filepath.Join(root, "config")
	_ = os.MkdirAll(cfg, 0o700)
	for _, name := range ConfigurationFiles {
		_ = os.WriteFile(filepath.Join(cfg, name), []byte("{}\n"), 0o600)
	}
	src := filepath.Join(root, "source")
	_ = os.MkdirAll(filepath.Join(src, "ansible"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "ansible/easy-ha-proxy.yml"), []byte("[]\n"), 0o600)

	agentBinary = agent
	sourceDirOverride = src
	offerCount := 0
	offerPendingRebootFn = func(_ *Context, _ bool) (bool, error) {
		offerCount++
		return false, nil
	}
	fetchRunnerFn = func(_ ioWriter, _ string) (string, error) { return fetched, nil }

	supportedRC := 0
	partsOut := `{"parts":{"native":{}}}`
	runSubprocessFn = func(name string, args ...string) subprocessResult {
		if len(args) >= 2 && args[1] == "parts" {
			return subprocessResult{ExitCode: 0, Stdout: partsOut}
		}
		return subprocessResult{ExitCode: supportedRC}
	}

	var runs [][]string
	runCommandFn = func(_ ioWriter, cmd []string, _ []string) error {
		runs = append(runs, cmd)
		return nil
	}

	ctx := NewContext(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := RunPlaybook(ctx, "ha-adm-native,ha-cfg,status", PlaybookOptions{Directory: cfg}); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0][1] != "apply" || runs[0][2] != "run" || runs[0][4] != "native" {
		t.Fatalf("expected bootstrap native then playbook, got %v", runs)
	}
	if !strings.Contains(strings.Join(runs[1], " "), "status_check_fail_on_error=true") {
		t.Fatalf("missing status_check_fail_on_error=true in %v", runs[1])
	}

	// Plan (check mode) does not run bootstrap native.
	runs = nil
	if err := RunPlaybook(ctx, "ha-adm-native,status", PlaybookOptions{Directory: cfg, CheckMode: true}); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || !containsString(runs[0], "--check") {
		t.Fatalf("expected single --check run, got %v", runs)
	}

	// Older agent without "apply playbook" falls back to fetched runner.
	runs = nil
	supportedRC = 2
	if err := RunPlaybook(ctx, "status", PlaybookOptions{Directory: cfg}); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0][0] != fetched {
		t.Fatalf("expected fetched runner, got %v", runs)
	}

	// Upgrade tag triggers OfferPendingReboot only on real apply.
	supportedRC = 0
	offerCount = 0
	_ = RunPlaybook(ctx, "upgrade,status", PlaybookOptions{Directory: cfg})
	if offerCount != 1 {
		t.Fatalf("expected offerPendingReboot once after upgrade, got %d", offerCount)
	}
	_ = RunPlaybook(ctx, "upgrade,status", PlaybookOptions{Directory: cfg, CheckMode: true})
	if offerCount != 1 {
		t.Fatalf("check mode must not offer reboot, got %d", offerCount)
	}

	// Missing config file fails before running anything.
	_ = os.Remove(filepath.Join(cfg, "secrets.yml"))
	if err := RunPlaybook(ctx, "status", PlaybookOptions{Directory: cfg}); err == nil || !strings.Contains(err.Error(), "Configuration is incomplete") {
		t.Fatalf("expected incomplete config error, got %v", err)
	}
}

// fakeProc points procRoot at a directory holding one process with the given
// command line and memory map; @HOME@ stands for home.
func fakeProc(t *testing.T, home, cmdline, maps string) {
	t.Helper()
	proc := t.TempDir()
	orig := procRoot
	procRoot = proc
	t.Cleanup(func() { procRoot = orig })
	_ = os.MkdirAll(filepath.Join(proc, "42"), 0o755)
	_ = os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	_ = os.WriteFile(filepath.Join(proc, "42/cmdline"), []byte(strings.ReplaceAll(cmdline, "@HOME@", home)), 0o600)
	_ = os.WriteFile(filepath.Join(proc, "42/maps"), []byte(strings.ReplaceAll(maps, "@HOME@", home)), 0o600)
}

func TestSyncRuntimeDependenciesRemovesTheUnusedVenv(t *testing.T) {
	resetRunnerHooks(t)
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, "venv/bin"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "venv/bin/python"), []byte("#!/bin/sh\n"), 0o755)
	_ = os.MkdirAll(filepath.Join(home, "tmp/ansible/leftover"), 0o755)
	installHomeOverride = home
	fakeProc(t, home, "/usr/bin/sleep\x0060\x00", "7f00-7f01 r-xp 0 08:01 1 /usr/lib/libc.so.6\n")
	runCommandFn = func(_ ioWriter, cmd []string, _ []string) error {
		t.Fatalf("no command expected, got %v", cmd)
		return nil
	}
	var out bytes.Buffer
	if err := SyncRuntimeDependencies(&out); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(home, "venv")) || fileExists(filepath.Join(home, "tmp/ansible")) {
		t.Fatalf("venv and tmp/ansible should be gone: %s", out.String())
	}
}

func TestSyncRuntimeDependenciesKeepsAVenvInUse(t *testing.T) {
	for name, proc := range map[string][2]string{
		// The pre-1.2.0 broker runs as venv/bin/python ...
		"argument": {"@HOME@/venv/bin/python\x00-m\x00broker\x00", ""},
		// ... and the venv python is a symlink, so the command line may name
		// the system interpreter while the venv's modules are mapped.
		"mapping": {"/usr/bin/python3\x00broker\x00", "7f00-7f01 r--p 0 08:01 1 @HOME@/venv/lib/python3.12/site-packages/yaml/_yaml.so\n"},
	} {
		t.Run(name, func(t *testing.T) {
			resetRunnerHooks(t)
			home := t.TempDir()
			installHomeOverride = home
			_ = os.MkdirAll(filepath.Join(home, "venv/bin"), 0o755)
			fakeProc(t, home, proc[0], proc[1])
			var out bytes.Buffer
			if err := SyncRuntimeDependencies(&out); err != nil {
				t.Fatal(err)
			}
			if !fileExists(filepath.Join(home, "venv")) || !strings.Contains(out.String(), "still in use") {
				t.Fatalf("a venv in use was touched: %s", out.String())
			}
		})
	}
}

func TestUpdateScopeAndChangesComponent(t *testing.T) {
	resetRunnerHooks(t)
	root := t.TempDir()
	cfg := filepath.Join(root, "config")
	_ = os.MkdirAll(cfg, 0o700)
	_ = WriteText(filepath.Join(cfg, "vars.yml"), "haproxy_admin_image: repo:latest\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "metadata.yml"), "source_channel: github\nconfiguration_pending: false\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "secrets.yml"), "haproxy_admin_proxy_secret: x\n", 0o600)

	configDirOverride = cfg
	requireRootFn = func() error { return nil }
	maintenanceLockPath = filepath.Join(root, "op.lock")
	startedByUpdateBrokerFn = func() bool { return false }
	syncDepsCalled := 0
	syncRuntimeDepsFn = func(_ ioWriter) error { syncDepsCalled++; return nil }
	recordCalled := 0
	recordAppliedSourceFn = func(_ ioWriter, _ string) { recordCalled++ }
	var appliedTags string
	var appliedExtra map[string]any
	runPlaybookFn = func(_ *Context, tags string, opts PlaybookOptions) error {
		appliedTags = tags
		appliedExtra = opts.ExtraVars
		return nil
	}

	// Narrow changes scope runs only needed tags without syncRuntimeDeps.
	t.Setenv(UpdateSourceRefreshedEnv, "1")
	changesScopeFn = func(_ ioWriter, _ string) map[string]any {
		return map[string]any{"full": false, "ready": true, "tags": []string{"ha-adm-guardd", "status"}, "changed": 2}
	}
	ctx := NewContext(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := CommandUpdate(ctx, UpdateArgs{Component: "changes", SourceChannel: "github"}); err != nil {
		t.Fatal(err)
	}
	if appliedTags != "ha-adm-guardd,status" || recordCalled != 1 || syncDepsCalled != 0 {
		t.Fatalf("unexpected narrow update: tags=%s record=%d deps=%d", appliedTags, recordCalled, syncDepsCalled)
	}

	// Full fallback refused when NoFullFallback is set.
	ReleaseMaintenanceLock()
	t.Setenv(UpdateSourceRefreshedEnv, "1")
	changesScopeFn = func(_ ioWriter, _ string) map[string]any {
		return map[string]any{"full": true, "ready": false, "tags": []string{}, "changed": 1}
	}
	if err := CommandUpdate(ctx, UpdateArgs{Component: "changes", SourceChannel: "github", NoFullFallback: true}); err == nil {
		t.Fatal("expected error when full fallback is forbidden")
	}

	// Automatic OS passes easy_ha_proxy_automatic_os_upgrade=true and rejects non-os.
	ReleaseMaintenanceLock()
	if err := CommandUpdate(ctx, UpdateArgs{Component: "all", AutomaticOS: true}); err == nil {
		t.Fatal("expected error for --automatic-os with non-os component")
	}
	ReleaseMaintenanceLock()
	if err := CommandUpdate(ctx, UpdateArgs{Component: "os", NoFetch: true, AutomaticOS: true}); err != nil {
		t.Fatal(err)
	}
	if appliedTags != "upgrade,status" || appliedExtra["easy_ha_proxy_automatic_os_upgrade"] != true {
		t.Fatalf("expected automatic os extra var, got tags=%s extra=%v", appliedTags, appliedExtra)
	}
}

func TestFullBackupSelectionAndRestoreCommand(t *testing.T) {
	resetRunnerHooks(t)
	root := t.TempDir()
	agent := filepath.Join(root, "agent")
	staged := filepath.Join(root, "staged")
	_ = os.WriteFile(agent, []byte(""), 0o755)
	_ = os.WriteFile(staged, []byte(""), 0o755)

	agentBinary = agent
	fetchCalls := 0
	fetchRunnerFn = func(_ ioWriter, _ string) (string, error) {
		fetchCalls++
		return staged, nil
	}

	runSubprocessFn = func(name string, args ...string) subprocessResult {
		return subprocessResult{ExitCode: 2, Stderr: "usage: easy-ha-proxy-agent full-backup backup ...\n"}
	}
	cmd, err := FullBackupCommand(&bytes.Buffer{})
	if err != nil || cmd[0] != agent || fetchCalls != 0 {
		t.Fatalf("expected installed agent, got %v (fetch=%d, err=%v)", cmd, fetchCalls, err)
	}

	runSubprocessFn = func(name string, args ...string) subprocessResult {
		return subprocessResult{ExitCode: 2, Stderr: "usage: easy-ha-proxy-agent <healthd|apply|version> [flags]\n"}
	}
	cmd, err = FullBackupCommand(&bytes.Buffer{})
	if err != nil || cmd[0] != staged || fetchCalls != 1 {
		t.Fatalf("expected fetched staged agent, got %v (fetch=%d, err=%v)", cmd, fetchCalls, err)
	}

	// restore-full forwards exact flags.
	requireRootFn = func() error { return nil }
	maintenanceLockPath = filepath.Join(root, "op.lock")
	startedByUpdateBrokerFn = func() bool { return false }
	var ranCmd []string
	runCommandFn = func(_ ioWriter, c []string, _ []string) error {
		ranCmd = c
		return nil
	}
	var out, errOut bytes.Buffer
	rc := RunCLI([]string{"restore-full", "/root/backup.enc", "--mode", "auto", "--skip-ssh", "--apply"}, strings.NewReader(""), &out, &errOut)
	if rc != 0 {
		t.Fatalf("restore-full failed: rc=%d err=%s", rc, errOut.String())
	}
	want := strings.Join([]string{staged, "full-backup", "restore", "/root/backup.enc", "--mode", "auto", "--replace-managed", "--skip-ssh", "--apply"}, " ")
	if strings.Join(ranCmd, " ") != want {
		t.Fatalf("got %q, want %q", strings.Join(ranCmd, " "), want)
	}
}

func TestCommandLanguageAndCLIHelp(t *testing.T) {
	resetRunnerHooks(t)
	root := t.TempDir()
	cfg := filepath.Join(root, "config")
	_ = os.MkdirAll(cfg, 0o700)
	_ = WriteText(filepath.Join(cfg, "vars.yml"), "root_domain: example.test\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "authelia.yml"), "authelia_notification_language: en\n", 0o600)
	_ = WriteText(filepath.Join(cfg, "metadata.yml"), "installer_language: en\n", 0o600)

	configDirOverride = cfg
	requireRootFn = func() error { return nil }
	maintenanceLockPath = filepath.Join(root, "op.lock")
	startedByUpdateBrokerFn = func() bool { return false }
	backupConfigurationFn = func(_ ioWriter, _ string) (string, error) { return "", nil }
	var playedTags string
	runPlaybookFn = func(_ *Context, tags string, _ PlaybookOptions) error {
		playedTags = tags
		return nil
	}

	var out, errOut bytes.Buffer
	if rc := RunCLI([]string{"language", "--language", "ru", "--apply"}, strings.NewReader(""), &out, &errOut); rc != 0 {
		t.Fatalf("language failed: %d %s", rc, errOut.String())
	}
	vars, _ := LoadYAMLMapping(filepath.Join(cfg, "vars.yml"))
	aut, _ := LoadYAMLMapping(filepath.Join(cfg, "authelia.yml"))
	meta, _ := LoadYAMLMapping(filepath.Join(cfg, "metadata.yml"))
	if vars.Value("haproxy_admin_default_language") != "ru" ||
		aut.Value("authelia_notification_language") != "ru" ||
		!strings.Contains(strVal(aut.Value("mail_subject")), "Уведомление безопасности") ||
		meta.Value("installer_language") != "ru" ||
		playedTags != LanguageTags {
		t.Fatalf("unexpected language update: vars=%v aut=%v meta=%v tags=%s", mapToGoMap(vars), mapToGoMap(aut), mapToGoMap(meta), playedTags)
	}

	// Helper capability probes.
	for _, argv := range [][]string{{"--probe"}, {"--help"}, {"update", "--help"}, {"language", "--help"}} {
		out.Reset()
		errOut.Reset()
		if rc := RunCLI(argv, strings.NewReader(""), &out, &errOut); rc != 0 {
			t.Fatalf("%v exited %d: %s", argv, rc, errOut.String())
		}
	}
	out.Reset()
	_ = RunCLI([]string{"update", "--help"}, strings.NewReader(""), &out, &errOut)
	for _, token := range []string{"--component", "daemons", "services"} {
		if !strings.Contains(out.String(), token) {
			t.Fatalf("update --help missing %q: %s", token, out.String())
		}
	}
}
