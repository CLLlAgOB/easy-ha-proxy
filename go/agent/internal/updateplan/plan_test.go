package updateplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/updatescope"
)

func aptOnly(argv []string) CommandResult {
	if is(argv, "apt-get", "-s", "upgrade", "--with-new-pkgs") {
		return ok("")
	}
	return unexpected(argv)
}

func missingStacks(root string) (string, string) {
	return filepath.Join(root, "missing-authelia.yml"), filepath.Join(root, "missing-admin.yml")
}

func TestNormalizerOnlyChangeIsAHostServiceUpdate(t *testing.T) {
	// The agent normalizes the state: a change to its port is a host service change.
	root := t.TempDir()
	installed := prepareSource(t, filepath.Join(root, "installed"))
	candidate := prepareSource(t, filepath.Join(root, "candidate"))
	writeFile(t, filepath.Join(installed, "go/agent/internal/tools/server_state.go"), "old\n")
	writeFile(t, filepath.Join(candidate, "go/agent/internal/tools/server_state.go"), "new\n")
	result := probeServices(M{"state": "available"}, "alpha", installed, candidate, "")
	if result["state"] != "available" {
		t.Fatalf("state %v", result["state"])
	}
}

func TestLocalSourceChannelNeverContactsGit(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	runner := newFakeRunner(aptOnly)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "local", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	c := byID(plan)
	if c["all"]["state"] != "blocked" || details(c["all"])["reason"] != "local-source-channel" {
		t.Fatalf("all: %v", c["all"])
	}
	if c["services"]["state"] != "blocked" || c["daemons"]["state"] != "current" {
		t.Fatalf("services %v daemons %v", c["services"]["state"], c["daemons"]["state"])
	}
	for _, argv := range runner.commands() {
		if argv[0] == "git" {
			t.Fatalf("ran git: %q", argv)
		}
	}
}

func TestAvailableDaemonsSummaryNamesTheOutdatedDaemon(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	first := nativeDaemonArtifacts[0]
	// Exactly one native binary is not installed.
	installed := prepareInstalledDaemons(t, root, "", first.id)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "local", Runner: newFakeRunner(aptOnly), ArtifactPath: installed})
	daemons := byID(plan)["daemons"]
	if daemons["state"] != "available" {
		t.Fatalf("state %v", daemons["state"])
	}
	summary := daemons["summary"].(string)
	// The summary names the candidate rather than dumping every digest.
	if !strings.Contains(summary, first.label) || strings.Contains(strings.ToLower(summary), "digest") {
		t.Fatalf("summary %q", summary)
	}
	outdated := []string{}
	for _, item := range details(daemons)["artifacts"].([]any) {
		if a := item.(M); a["state"] == "available" {
			outdated = append(outdated, a["id"].(string))
		}
	}
	if !reflect.DeepEqual(outdated, []string{first.id}) {
		t.Fatalf("outdated %v", outdated)
	}
}

func TestGitCheckIgnoresFileModeOnlyDrift(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	runner := newFakeRunner(gitHandler)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	all := byID(plan)["all"]
	// gitHandler refuses the candidate, and that is named first: without it
	// nothing can say what the complete update would install.
	if all["state"] != "blocked" || details(all)["reason"] != "candidate-unavailable" || all["available_version"] != remoteRevision {
		t.Fatalf("all: %v", all)
	}
	var status [][]string
	for _, argv := range runner.commands() {
		if has(argv, "status") {
			status = append(status, argv)
		}
	}
	if len(status) != 1 || !has(status[0], "core.fileMode=false") || has(status[0], "--ignore-submodules=dirty") {
		t.Fatalf("status commands %q", status)
	}
}

func markerSource(t *testing.T, root, revision string, dirty bool) string {
	source := prepareSource(t, root)
	if err := os.RemoveAll(filepath.Join(source, ".git")); err != nil { // tarball install: no checkout
		t.Fatal(err)
	}
	flag := "false"
	if dirty {
		flag = "true"
	}
	writeFile(t, filepath.Join(source, ".easy-ha-proxy-source-revision"), "revision="+revision+"\ndirty="+flag+"\n")
	return source
}

func TestRecordedRevisionDetectsRemoteUpdateWithoutGitCheckout(t *testing.T) {
	// A synced tarball has no .git; the recorded marker lets the github
	// channel still compare against the remote branch.
	root := t.TempDir()
	source := markerSource(t, root, localRevision, false)
	runner := newFakeRunner(func(argv []string) CommandResult {
		switch {
		case hasPrefix(argv, "git", "ls-remote", "--heads"):
			return ok(remoteRevision + "\trefs/heads/main\n")
		case hasPrefix(argv, "git", "clone"):
			copyTree(t, source, last(argv))
			return ok("")
		case hasSuffix(argv, "rev-parse", "HEAD"):
			return ok(remoteRevision + "\n")
		}
		return aptOnly(argv)
	})
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	all := byID(plan)["all"]
	if all["available_version"] != remoteRevision || all["state"] == "unknown" {
		t.Fatalf("all: %v", all)
	}
	// No working-tree git commands ran against the source (there is no
	// checkout); rev-parse on the temporary candidate clone is fine.
	lsRemote := false
	for _, argv := range runner.commands() {
		if argv[0] == "git" && has(argv, source) && (has(argv, "rev-parse") || has(argv, "status") || has(argv, "remote")) {
			t.Fatalf("source git command %q", argv)
		}
		lsRemote = lsRemote || hasPrefix(argv, "git", "ls-remote", "--heads")
	}
	if !lsRemote {
		t.Fatal("the remote branch was not asked")
	}
}

func TestRecordedRevisionIsCurrentWhenMatchingRemote(t *testing.T) {
	root := t.TempDir()
	source := markerSource(t, root, remoteRevision, false)
	runner := newFakeRunner(func(argv []string) CommandResult {
		if hasPrefix(argv, "git", "ls-remote", "--heads") {
			return ok(remoteRevision + "\trefs/heads/main\n")
		}
		return aptOnly(argv)
	})
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: runner,
		ArtifactPath: prepareInstalledDaemons(t, root, remoteRevision)})
	c := byID(plan)
	// The native binaries were built from the recorded revision.
	if c["all"]["state"] != "current" || c["daemons"]["state"] != "current" {
		t.Fatalf("all %v daemons %v", c["all"]["state"], c["daemons"]["state"])
	}
}

func TestRecordedDirtySourceIsBlockedBeforeNetwork(t *testing.T) {
	root := t.TempDir()
	source := markerSource(t, root, localRevision, true)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: newFakeRunner(aptOnly),
		ArtifactPath: prepareInstalledDaemons(t, root, "")})
	all := byID(plan)["all"]
	if all["state"] != "blocked" || details(all)["reason"] != "recorded-source-dirty" {
		t.Fatalf("all: %v", all)
	}
}

func TestMissingMarkerAndGitIsUnknown(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	if err := os.RemoveAll(filepath.Join(source, ".git")); err != nil { // neither checkout nor marker
		t.Fatal(err)
	}
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: newFakeRunner(aptOnly),
		ArtifactPath: prepareInstalledDaemons(t, root, "")})
	all := byID(plan)["all"]
	if all["state"] != "unknown" || details(all)["reason"] != "not-a-git-checkout" {
		t.Fatalf("all: %v", all)
	}
}

func TestContentChangesBlockAutomaticSourceReplacement(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	runner := newFakeRunner(func(argv []string) CommandResult {
		if has(argv, "status") {
			return ok(" M installer/easy_ha_proxy.py\n")
		}
		return gitHandler(argv)
	})
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	all := byID(plan)["all"]
	if all["state"] != "blocked" || all["actionable"] != false || details(all)["reason"] != "local-source-changes" {
		t.Fatalf("all: %v", all)
	}
}

// candidateHandler clones the installed source as the candidate (changed by
// edit) and says the candidate is the remote revision.
func candidateHandler(t *testing.T, source string, edit func(candidate string), next func([]string) CommandResult) func([]string) CommandResult {
	return func(argv []string) CommandResult {
		if hasPrefix(argv, "git", "clone") {
			copyTree(t, source, last(argv))
			if edit != nil {
				edit(last(argv))
			}
			return ok("")
		}
		if hasSuffix(argv, "rev-parse", "HEAD") && argv[2] != source {
			return ok(remoteRevision + "\n")
		}
		return next(argv)
	}
}

func TestRemoteSourceChangeDoesNotCreateComponentFalsePositives(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, Runner: newFakeRunner(candidateHandler(t, source, nil, gitHandler)),
		ArtifactPath: prepareInstalledDaemons(t, root, localRevision)})
	c := byID(plan)
	if c["all"]["state"] != "blocked" || details(c["all"])["reason"] != "container-candidate-unavailable" ||
		c["all"]["available_version"] != remoteRevision {
		t.Fatalf("all: %v", c["all"])
	}
	if c["services"]["state"] != "current" || has(anyStrings(plan["actionable_components"]), "services") {
		t.Fatalf("services: %v", c["services"])
	}
	// The native binaries are pinned to the commit they were built from, so
	// a moving source brings the candidate's build.
	if c["daemons"]["state"] != "available" {
		t.Fatalf("daemons: %v", c["daemons"])
	}
	for _, item := range details(c["daemons"])["artifacts"].([]any) {
		if a := item.(M); a["id"] == "easy-ha-proxy-agent" && a["reason"] != "revision-mismatch" {
			t.Fatalf("agent: %v", a)
		}
	}
}

func anyStrings(v any) []string {
	out := []string{}
	for _, item := range v.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestPlanReportsOnlyManagedComposeStacksWithoutPulling(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	config := filepath.Join(root, "config")
	writeFile(t, filepath.Join(config, "metadata.yml"), "source_channel: github\nimage_channel: alpha\n")
	autheliaCompose := filepath.Join(root, "opt/authelia/docker-compose.yml")
	adminCompose := filepath.Join(root, "opt/haproxy-admin/docker-compose.yml")
	writeFile(t, autheliaCompose, "services: {}\n")
	writeFile(t, adminCompose, "services: {}\n")
	edit := func(candidate string) {
		writeFile(t, filepath.Join(candidate, "ansible/easy-ha-proxy.yml"), "---\n- hosts: easy_ha_proxy\n  gather_facts: true\n")
	}
	runner := newFakeRunner(candidateHandler(t, source, edit, func(argv []string) CommandResult {
		if argv[0] == "git" {
			return gitHandler(argv)
		}
		switch {
		case is(argv, "apt-get", "-s", "upgrade", "--with-new-pkgs"):
			return ok("Inst openssl [3.0.0] (3.0.1 Debian:stable)\nInst docker-ce [1] (2 Docker)\n")
		case is(argv, "docker", "compose", "-f", autheliaCompose, "config", "--images"):
			return ok("authelia/authelia:4.39.20\nredis@" + digestA + "\nauthelia/authelia:4.39.20\n")
		case is(argv, "docker", "compose", "-f", adminCompose, "config", "--images"):
			return ok("example/haproxy-admin:go-alpha\n")
		}
		if answer, found := panelImageAnswer(argv); found {
			return answer
		}
		switch {
		case hasPrefix(argv, "docker", "image", "inspect"):
			image := argv[3]
			return ok(mustJSON([]string{strings.SplitN(image, ":", 2)[0] + "@" + digestA}))
		case hasPrefix(argv, "docker", "buildx", "imagetools", "inspect"):
			image := argv[4]
			digest := digestB
			if strings.HasPrefix(image, "authelia/") {
				digest = digestA
			}
			return ok("Name: " + image + "\nDigest: " + digest + "\n")
		case hasPrefix(argv, "docker", "compose") && hasSuffix(argv, "ps", "-q"):
			// Which containers run: a read, never a pull.
			return ok("")
		}
		return unexpected(argv)
	}))
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: config, AutheliaCompose: autheliaCompose,
		AdminCompose: adminCompose, Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, localRevision),
		Now: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)})
	c := byID(plan)
	if c["authelia-container"]["state"] != "current" || c["admin-container"]["state"] != "available" {
		t.Fatalf("authelia %v admin %v", c["authelia-container"], c["admin-container"])
	}
	osc := c["os"]
	if osc["available_version"] != 2 || osc["installed"] != nil || osc["available"] != 2 || osc["candidate"] != 2 {
		t.Fatalf("os: %v", osc)
	}
	if plan["source_channel"] != "github" || plan["image_channel"] != "alpha" || plan["generated_at"] != "2026-07-19T12:00:00Z" {
		t.Fatalf("plan: %v %v %v", plan["source_channel"], plan["image_channel"], plan["generated_at"])
	}
	// The source moves, so the native binaries of the candidate commit too.
	actionable := anyStrings(plan["actionable_components"])
	sort.Strings(actionable)
	if !reflect.DeepEqual(actionable, []string{"admin-container", "all", "daemons", "os", "services"}) {
		t.Fatalf("actionable %v", actionable)
	}
	if _, err := json.Marshal(plan); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, argv := range runner.commands() {
		if hasPrefix(argv, "docker", "compose", "-f") {
			paths[argv[3]] = true
		}
		if has(argv, "pull") {
			t.Fatalf("pulled: %q", argv)
		}
	}
	if !reflect.DeepEqual(paths, map[string]bool{autheliaCompose: true, adminCompose: true}) {
		t.Fatalf("compose files %v", paths)
	}
}

func TestProbeTimeoutIsReportedWithoutFailingThePlan(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	timeout := CommandResult{Returncode: 124, Error: "timeout"}
	runner := newFakeRunner(func(argv []string) CommandResult {
		switch {
		case hasSuffix(argv, "rev-parse", "HEAD"):
			return ok(localRevision + "\n")
		case has(argv, "status"):
			return ok("")
		case hasSuffix(argv, "remote", "get-url", "origin"):
			return ok("https://example.test/repository.git\n")
		case hasPrefix(argv, "git", "ls-remote", "--heads"), is(argv, "apt-get", "-s", "upgrade", "--with-new-pkgs"):
			return timeout
		}
		return unexpected(argv)
	})
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	c := byID(plan)
	if c["all"]["state"] != "unknown" || c["os"]["state"] != "unknown" || plan["has_updates"] != false {
		t.Fatalf("all %v os %v has_updates %v", c["all"]["state"], c["os"]["state"], plan["has_updates"])
	}
}

func TestRequestedAdminChannelChecksTargetTagWithoutPull(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	config := filepath.Join(root, "config")
	writeFile(t, filepath.Join(config, "metadata.yml"), "source_channel: local\nimage_channel: latest\n")
	writeFile(t, filepath.Join(config, "vars.yml"), "haproxy_admin_image: registry.example/admin:latest\n")
	adminCompose := filepath.Join(root, "admin/docker-compose.yml")
	writeFile(t, adminCompose, "services: {}\n")
	runner := newFakeRunner(func(argv []string) CommandResult {
		switch {
		case is(argv, "apt-get", "-s", "upgrade", "--with-new-pkgs"):
			return ok("")
		case is(argv, "docker", "compose", "-f", adminCompose, "config", "--images"):
			return ok("registry.example/admin:latest\n")
		case hasSuffix(argv, "ps", "-q"):
			return ok("")
		}
		if answer, found := panelImageAnswer(argv); found {
			return answer
		}
		switch {
		case hasPrefix(argv, "docker", "image", "inspect"):
			if argv[3] != "registry.example/admin:latest" {
				t.Errorf("inspected %q", argv[3])
			}
			return ok(mustJSON([]string{"registry.example/admin@" + digestA}))
		case hasPrefix(argv, "docker", "buildx", "imagetools", "inspect"):
			if argv[4] != "registry.example/admin:go-alpha" {
				t.Errorf("asked the registry for %q", argv[4])
			}
			return ok("Digest: " + digestB + "\n")
		}
		return unexpected(argv)
	})
	authelia, _ := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: config, AutheliaCompose: authelia, AdminCompose: adminCompose,
		SourceChannel: "local", ImageChannel: "alpha", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")})
	admin := byID(plan)["admin-container"]
	d := details(admin)
	// Every deployment runs the Go panel: the channel's go- tag.
	target := d["images"].([]any)[0].(M)["target_image"]
	if admin["state"] != "available" || d["configured_channel"] != "latest" || d["target_channel"] != "alpha" ||
		target != "registry.example/admin:go-alpha" {
		t.Fatalf("admin: %v", admin)
	}
	for _, argv := range runner.commands() {
		if has(argv, "pull") {
			t.Fatalf("pulled: %q", argv)
		}
	}
}

func TestSubprocessErrorsRedactURICredentialsAndTokens(t *testing.T) {
	message := shortError(failed(1, "fatal: https://alice:private-token@example.test/repository?access_token=also-private could not be read"))
	if strings.Contains(message, "private-token") || strings.Contains(message, "also-private") ||
		!strings.Contains(message, "https://***@example.test") || !strings.Contains(message, "access_token=***") {
		t.Fatalf("message %q", message)
	}
}

func TestTheSourceComponentSaysWhatAChangesOnlyUpdateWouldRun(t *testing.T) {
	root := t.TempDir()
	source := prepareSource(t, root)
	config := filepath.Join(root, "config")
	if _, err := updatescope.WriteApplied(config, source, localRevision); err != nil {
		t.Fatal(err)
	}
	edit := func(candidate string) {
		writeFile(t, filepath.Join(candidate, "ansible/roles/haproxy-admin/files/scanner-signatures.json"), "{}")
	}
	authelia, admin := missingStacks(root)
	plan := buildPlanForTest(t, Options{SourceDir: source, ConfigDir: config, AutheliaCompose: authelia, AdminCompose: admin,
		Runner: newFakeRunner(candidateHandler(t, source, edit, gitHandler)), ArtifactPath: prepareInstalledDaemons(t, root, "")})
	scope := details(byID(plan)["all"])["scope"].(M)
	if scope["ready"] != true || !reflect.DeepEqual(scope["tags"], []string{"ha-adm-guardd", "status"}) || scope["changed"] != 1 {
		t.Fatalf("scope: %v", scope)
	}
}

// The native binaries follow their own sources (MED-31).

const (
	revOld = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revNew = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func seedTree(t *testing.T, root, goPanel, goAgent, rustGuardd string) {
	t.Helper()
	writeFile(t, filepath.Join(root, ".git", "HEAD"), "")
	writeFile(t, filepath.Join(root, "ansible/roles/haproxy-admin/defaults/main.yml"), "app_group: hadmin\n")
	writeFile(t, filepath.Join(root, "go/panel/cmd/easy-ha-proxy-panel/main.go"), "// "+goPanel+"\n")
	writeFile(t, filepath.Join(root, "go/agent/cmd/easy-ha-proxy-agent/main.go"), "// "+goAgent+"\n")
	writeFile(t, filepath.Join(root, "rust/guardd/src/main.rs"), "// "+rustGuardd+"\n")
}

type nativeCase struct {
	goPanel, goAgent, rustGuardd string
	remote, installed            string
	missingAgent                 bool
}

func runNativePlan(t *testing.T, c nativeCase) map[string]M {
	t.Helper()
	root := t.TempDir()
	source, candidate := filepath.Join(root, "source"), filepath.Join(root, "candidate")
	seedTree(t, source, "v1", "v1", "v1")
	seedTree(t, candidate, or(c.goPanel, "v1"), or(c.goAgent, "v1"), or(c.rustGuardd, "v1"))
	var skip []string
	if c.missingAgent {
		skip = []string{"easy-ha-proxy-agent"}
	}
	resolve := prepareInstalledDaemons(t, root, c.installed, skip...)
	runner := newFakeRunner(func(argv []string) CommandResult {
		switch {
		case hasSuffix(argv, "rev-parse", "HEAD"):
			if has(argv, source) {
				return ok(revOld + "\n")
			}
			return ok(c.remote + "\n")
		case has(argv, "status"):
			return ok("")
		case has(argv, "remote") && has(argv, "get-url"):
			return ok(defaultRepository + "\n")
		case hasPrefix(argv, "git", "ls-remote", "--heads"):
			return ok(c.remote + "\trefs/heads/alpha\n")
		case hasPrefix(argv, "git", "clone"):
			copyTree(t, candidate, last(argv))
			return ok("")
		case is(argv, "apt-get", "-s", "upgrade", "--with-new-pkgs"):
			return ok("")
		}
		return failed(1, "unexpected")
	})
	authelia, admin := missingStacks(root)
	return byID(buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Branch: "alpha", Runner: runner, ArtifactPath: resolve}))
}

func artifact(c M, id string) M {
	for _, item := range details(c)["artifacts"].([]any) {
		if a := item.(M); a["id"] == id {
			return a
		}
	}
	return nil
}

func TestOnlyPanelChangedDoesNotMarkServicesAvailable(t *testing.T) {
	c := runNativePlan(t, nativeCase{goPanel: "v2", remote: revNew, installed: revOld})
	if c["services"]["state"] != "current" {
		t.Fatalf("services %v", c["services"])
	}
}

func TestNativeSourceChangesMarkServicesAndDaemonsAvailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    nativeCase
		id   string
	}{
		{"agent", nativeCase{goAgent: "v2", remote: revNew, installed: revOld}, "easy-ha-proxy-agent"},
		{"guardd", nativeCase{rustGuardd: "v2", remote: revNew, installed: revOld}, "guardd-core"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := runNativePlan(t, tc.c)
			a := artifact(c["daemons"], tc.id)
			if c["services"]["state"] != "available" || c["daemons"]["state"] != "available" ||
				a["state"] != "available" || a["reason"] != "native-source-changed" {
				t.Fatalf("services %v daemons %v artifact %v", c["services"]["state"], c["daemons"]["state"], a)
			}
		})
	}
}

func TestFreshSourcesWithAStaleBinaryMarkDaemonsAvailable(t *testing.T) {
	// The source matches the remote, but the installed native metadata has
	// another revision.
	c := runNativePlan(t, nativeCase{remote: revOld, installed: strings.Repeat("c", 40)})
	if c["all"]["state"] != "current" || c["services"]["state"] != "current" || c["daemons"]["state"] != "available" ||
		artifact(c["daemons"], "easy-ha-proxy-agent")["reason"] != "revision-mismatch" {
		t.Fatalf("all %v services %v daemons %v", c["all"]["state"], c["services"]["state"], c["daemons"])
	}
	// Also when the native binary itself is missing on disk.
	c = runNativePlan(t, nativeCase{remote: revOld, installed: revOld, missingAgent: true})
	if c["daemons"]["state"] != "available" || artifact(c["daemons"], "easy-ha-proxy-agent")["reason"] != "installed-file-missing" {
		t.Fatalf("daemons %v", c["daemons"])
	}
}

// A plan without the candidate offers nothing to install.

func planWithoutCandidate(t *testing.T) M {
	root := t.TempDir()
	source := prepareSource(t, root)
	authelia, admin := missingStacks(root)
	return buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: newFakeRunner(gitHandler),
		ArtifactPath: prepareInstalledDaemons(t, root, "")})
}

func TestAPlanWithoutTheCandidateOffersNothingAndSaysWhy(t *testing.T) {
	plan := planWithoutCandidate(t)
	c := byID(plan)
	all := c["all"]
	d := details(all)
	if all["state"] != "blocked" || all["actionable"] != false || d["reason"] != "candidate-unavailable" ||
		!strings.Contains(d["candidate_error"].(string), "candidate unavailable") {
		t.Fatalf("all: %v", all)
	}
	// Still says there is something newer, and which revision.
	if all["available_version"] != remoteRevision || has(anyStrings(plan["actionable_components"]), "all") {
		t.Fatalf("all: %v", all)
	}
	if c["services"]["actionable"] != false || c["daemons"]["actionable"] != false {
		t.Fatal("services or daemons offered without the candidate")
	}
}

func TestAPlanWithoutTheCandidateSaysSoInRussian(t *testing.T) {
	summary := planWithoutCandidate(t)["components"].([]any)[0].(M)["summary"].(string)
	russian, found := russianMessages(t)[summary]
	if !found || !strings.Contains(russian, "скачать новую версию") {
		t.Fatalf("%q -> %q", summary, russian)
	}
}

// Local changes the next revision already holds do not block the update.

func localChangesPlan(t *testing.T, upstream bool) map[string]M {
	t.Helper()
	root := t.TempDir()
	source := prepareSource(t, root)
	writeFile(t, filepath.Join(source, "installer/guard.py"), "fixed\n")
	candidate := filepath.Join(root, "candidate")
	copyTree(t, source, candidate)
	if !upstream {
		writeFile(t, filepath.Join(candidate, "installer/guard.py"), "upstream\n")
	}
	runner := newFakeRunner(func(argv []string) CommandResult {
		switch {
		case has(argv, "status"):
			return ok(" M installer/guard.py\x00")
		case hasPrefix(argv, "git", "clone"):
			copyTree(t, candidate, last(argv))
			return ok("")
		case hasSuffix(argv, "rev-parse", "HEAD") && argv[2] != source:
			return ok(remoteRevision + "\n")
		}
		return gitHandler(argv)
	})
	authelia, admin := missingStacks(root)
	return byID(buildPlanForTest(t, Options{SourceDir: source, ConfigDir: filepath.Join(root, "config"), AutheliaCompose: authelia,
		AdminCompose: admin, SourceChannel: "github", Runner: runner, ArtifactPath: prepareInstalledDaemons(t, root, "")}))
}

func TestChangesAlreadyUpstreamMakeItAnOrdinaryUpdate(t *testing.T) {
	all := localChangesPlan(t, true)["all"]
	d := details(all)
	// Past the local changes: what holds it now is only that this test has
	// no container stacks to verify.
	if d["reason"] != "container-candidate-unavailable" || d["local_changes"] != "in-candidate" ||
		all["available_version"] != remoteRevision {
		t.Fatalf("all: %v", all)
	}
	if _, found := d["scope"]; !found {
		t.Fatal("no scope")
	}
	if _, found := all["_local_changes"]; found {
		t.Fatal("the local change entries leaked into the plan")
	}
}

func TestOtherChangesKeepTheBlockAndNameTheFiles(t *testing.T) {
	all := localChangesPlan(t, false)["all"]
	if all["state"] != "blocked" || all["actionable"] != false ||
		!reflect.DeepEqual(details(all)["changed_files"], []any{"installer/guard.py"}) {
		t.Fatalf("all: %v", all)
	}
	if _, found := all["_local_changes"]; found {
		t.Fatal("the local change entries leaked into the plan")
	}
}

func TestTheHealedSourceIsTheUsualAvailableUpdate(t *testing.T) {
	// The services are judged against the healed source: an available update
	// whose candidate leaves their files as they are.
	services := localChangesPlan(t, true)["services"]
	if services["state"] != "current" || services["summary"] != "The remote source does not change host-service files." {
		t.Fatalf("services: %v", services)
	}
}
