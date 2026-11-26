package updatescope

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Updates that run only the stages their changed files need. "Only what
// changed" compares the source an update would install with the record of
// the last complete update and maps each changed file to the stage that
// deploys it. A file the map does not know means the full stack, never a
// skipped step. The map is only worth anything if it is right, so every rule
// that names a stage is checked against the stages themselves.

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

type playbookEntry struct {
	role, stage string
	tags        map[string]bool
}

// playbookEntries is (role, task_stage, tags) for every role entry of the
// main playbook.
func playbookEntries(t *testing.T) []playbookEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "ansible/easy-ha-proxy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := pyyaml.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	var entries []playbookEntry
	for _, play := range loaded.([]any) {
		roles, _ := play.(*pyyaml.Map).Value("roles").([]any)
		for _, item := range roles {
			role, isMap := item.(*pyyaml.Map)
			if !isMap {
				continue
			}
			entry := playbookEntry{role: role.Value("role").(string), stage: "main", tags: map[string]bool{}}
			if stage, found := role.Get("task_stage"); found && stage != nil {
				entry.stage = stage.(string)
			}
			switch tags := role.Value("tags").(type) {
			case string:
				entry.tags[tags] = true
			case []any:
				for _, tag := range tags {
					entry.tags[tag.(string)] = true
				}
			}
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		t.Fatal("no role entries in the playbook")
	}
	return entries
}

func isPattern(pattern string) bool { return strings.ContainsAny(pattern, "*?[") }

func TestEveryTagTheMapUsesExistsInThePlaybook(t *testing.T) {
	all := map[string]bool{}
	for _, entry := range playbookEntries(t) {
		for tag := range entry.tags {
			all[tag] = true
		}
	}
	for _, rule := range Rules {
		for _, tag := range rule.Tags {
			if tag != Full && !all[tag] {
				t.Errorf("%s: tag %q is not in the playbook", rule.Pattern, tag)
			}
		}
	}
}

func TestEveryNamedFileExists(t *testing.T) {
	// A rule for a file that is gone is a rule nobody will notice is wrong.
	root := repoRoot()
	files := trackedFiles(root)
	if len(files) == 0 {
		// Not a Git checkout (or no Git): every file there is.
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}
			if err == nil && info.Mode().IsRegular() {
				rel, _ := filepath.Rel(root, path)
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	known := map[string]bool{}
	for _, f := range files {
		known[f] = true
	}
	for _, rule := range Rules {
		if !isPattern(rule.Pattern) {
			if !known[rule.Pattern] {
				t.Errorf("%s does not exist", rule.Pattern)
			}
			continue
		}
		matched := false
		for _, f := range files {
			if FnmatchCase(f, rule.Pattern) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s matches nothing", rule.Pattern)
		}
	}
}

func TestEachMappedFileIsOneTheAgentDeploys(t *testing.T) {
	// A rule for a template or file no stage reads any more maps a change to
	// a step that does not pick it up.
	paths, _ := filepath.Glob(filepath.Join(repoRoot(), "go/agent/internal/apply/stages/*.go"))
	var sources strings.Builder
	for _, path := range paths {
		if !strings.HasSuffix(path, "_test.go") {
			raw, _ := os.ReadFile(path)
			sources.Write(raw)
		}
	}
	stageCode := sources.String()
	roleFile := regexp.MustCompile(`^ansible/roles/([^/]+)/(files|templates)/(.+)$`)
	for _, rule := range Rules {
		if len(rule.Tags) == 0 || contains(rule.Tags, Full) || isPattern(rule.Pattern) {
			continue
		}
		if m := roleFile.FindStringSubmatch(rule.Pattern); m != nil {
			name := filepath.Base(m[3])
			// A daemon's unit template is named after the daemon there.
			named := strings.TrimSuffix(name, ".service.j2")
			if !strings.Contains(stageCode, name) && !strings.Contains(stageCode, `"`+named+`"`) {
				t.Errorf("no stage deploys %s", rule.Pattern)
			}
		}
	}
}

func TestTheWholeRolesMappedToOneStageHaveOnlyThatStage(t *testing.T) {
	entries := playbookEntries(t)
	for role, tag := range map[string]string{"geoip_acl": "geo", "docker": "docker"} {
		roles := map[string]bool{}
		for _, entry := range entries {
			if entry.tags[tag] {
				roles[entry.role] = true
			}
		}
		if !reflect.DeepEqual(roles, map[string]bool{role: true}) {
			t.Errorf("tag %s: roles %v", tag, roles)
		}
	}
}

func scopeTags(scope map[string]any) []string { return scope["tags"].([]string) }

func TestThePythonStateNormalizerDeploysNothing(t *testing.T) {
	scope := ScopeFor([]string{"installer/haproxy_server_state.py"})
	if scope["full"] != false || len(scopeTags(scope)) != 0 {
		t.Fatalf("scope %v", scope)
	}
}

func TestADaemonChangeRunsItsStage(t *testing.T) {
	scope := ScopeFor([]string{
		"ansible/roles/haproxy-admin/templates/guardd.json.j2",
		"ansible/roles/haproxy-admin/templates/easy-ha-proxy-guardd.service.j2",
		"ansible/roles/haproxy-admin/files/scanner-signatures.json",
		".tests/test_rust_guardd.py",
		"README.md",
	})
	if scope["full"] != false || !reflect.DeepEqual(scopeTags(scope), []string{"ha-adm-guardd", "status"}) ||
		!reflect.DeepEqual(scope["steps"], []string{"Adaptive protection"}) || scope["changed"] != 5 {
		t.Fatalf("scope %v", scope)
	}
}

func TestTheTemplateRefreshesHAProxyAndTheWebApplicationsCopy(t *testing.T) {
	scope := ScopeFor([]string{"ansible/roles/haproxy/templates/haproxy.cfg.j2"})
	if !reflect.DeepEqual(scopeTags(scope), []string{"ha-adm-cfg", "ha-cfg", "status"}) {
		t.Fatalf("scope %v", scope)
	}
}

var goInstallerTags = []string{"apparmor", "authelia", "crt-hooks", "crt-install", "crt-notify", "docker", "geo", "ha-adm-cfg",
	"ha-adm-daemons", "ha-adm-install", "ha-adm-journald", "ha-adm-native", "ha-adm-start", "ha-cfg", "ha-install", "status"}

func TestTheSharedGoPackagesRefreshTheNativeBinaries(t *testing.T) {
	// The agent compiles go/panel/shared too, and renders the templates with
	// it: a new agent and its stages.
	scope := ScopeFor([]string{"go/panel/shared/jinja/render.go", "go/panel/internal/app/app.go"})
	if scope["full"] != false || !reflect.DeepEqual(scopeTags(scope), goInstallerTags) {
		t.Fatalf("scope %v", scope)
	}
}

func TestAGoInstallerChangeRunsTheStagesItTakesOver(t *testing.T) {
	if got := scopeTags(ScopeFor([]string{"go/agent/internal/apply/stages/daemons.go"})); !reflect.DeepEqual(got, goInstallerTags) {
		t.Fatalf("tags %v", got)
	}
	if got := scopeTags(ScopeFor([]string{"go/agent/internal/healthd/healthd.go"})); !reflect.DeepEqual(got, []string{"ha-adm-native", "status"}) {
		t.Fatalf("tags %v", got)
	}
}

func TestNativeSourcesTargetTheNativeStage(t *testing.T) {
	// Only the panel changed: nothing on the host.
	if scope := ScopeFor([]string{"go/panel/internal/app/app.go"}); scope["full"] != false || len(scopeTags(scope)) != 0 ||
		len(scope["steps"].([]string)) != 0 {
		t.Fatalf("scope %v", scope)
	}
	for _, path := range []string{"go/agent/internal/alertd/engine.go", "rust/guardd/src/engine.rs"} {
		scope := ScopeFor([]string{path})
		if scope["full"] != false || !reflect.DeepEqual(scopeTags(scope), []string{"ha-adm-native", "status"}) ||
			!reflect.DeepEqual(scope["steps"], []string{"Native host binaries"}) {
			t.Fatalf("%s: %v", path, scope)
		}
	}
}

func TestDocumentationTestsAndTheWebApplicationDeployNothing(t *testing.T) {
	scope := ScopeFor([]string{"README.ru.md", "docs/screenshots/en/dashboard.webp", ".tests/test_x.py", ".github/workflows/ci.yml",
		"go/panel/web/static/js/live_activity.js", "go/panel/internal/app/app.go", "installer/easy_ha_proxy.py"})
	if scope["full"] != false || len(scopeTags(scope)) != 0 {
		t.Fatalf("scope %v", scope)
	}
}

func TestAnythingUnknownOrStructuralMeansTheFullStack(t *testing.T) {
	for _, path := range []string{
		"ansible/easy-ha-proxy.yml",
		"ansible/requirements.yml",
		"installer/requirements.txt",
		"ansible/roles/haproxy-admin/defaults/main.yml",
		"ansible/roles/haproxy-admin/templates/docker-compose.yml.j2",
		"ansible/roles/authelia/templates/configuration.yml.j2",
		"ansible/roles/cert/defaults/main.yml",
		"some/new/thing.py",
	} {
		scope := ScopeFor([]string{path, "README.md"})
		if scope["full"] != true || len(scopeTags(scope)) != 0 || !contains(scope["unmapped"].([]string), path) {
			t.Errorf("%s: %v", path, scope)
		}
	}
}

func TestFnmatchCrossesSlashes(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		want          bool
	}{
		{"go/panel/web/x.js", "go/panel/*", true},
		{"README.md", "*.md", true},
		{"docs/a/b.md", "*.md", true},
		{"VERSION", "VERSION", true},
		{"VERSIONS", "VERSION", false},
		{"a.pyc", "*.py[co]", true},
		{"a.pyx", "*.py[!co]", true},
		{"a.py", "a.p?", true},
		{"a+b", "a+b", true},
	} {
		if got := FnmatchCase(tc.name, tc.pattern); got != tc.want {
			t.Errorf("FnmatchCase(%q, %q) = %v", tc.name, tc.pattern, got)
		}
	}
}

// The record of the last complete update.

type recordFixture struct {
	root, source, config string
}

func newRecordFixture(t *testing.T) recordFixture {
	root := t.TempDir()
	f := recordFixture{root: root, source: filepath.Join(root, "source"), config: filepath.Join(root, "config")}
	write(t, filepath.Join(f.source, "ansible/roles/haproxy-admin/files/scanner-signatures.json"), "v1\n")
	write(t, filepath.Join(f.source, "README.md"), "docs\n")
	return f
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWithoutARecordTheFullStackIsNeeded(t *testing.T) {
	f := newRecordFixture(t)
	scope := PlanScope(f.config, f.source)
	if scope["ready"] != false || scope["reason"] != "no-applied-record" {
		t.Fatalf("scope %v", scope)
	}
}

func TestARecordThenAChange(t *testing.T) {
	f := newRecordFixture(t)
	if _, err := WriteApplied(f.config, f.source, strings.Repeat("a", 40)); err != nil {
		t.Fatal(err)
	}
	if applied := ReadApplied(f.config); applied == nil || applied.Revision != strings.Repeat("a", 40) {
		t.Fatalf("applied %+v", applied)
	}
	if tags := scopeTags(PlanScope(f.config, f.source)); len(tags) != 0 {
		t.Fatalf("tags %v", tags)
	}
	write(t, filepath.Join(f.source, "ansible/roles/haproxy-admin/files/scanner-signatures.json"), "v2\n")
	scope := PlanScope(f.config, f.source)
	if scope["ready"] != true || !reflect.DeepEqual(scopeTags(scope), []string{"ha-adm-guardd", "status"}) {
		t.Fatalf("scope %v", scope)
	}
}

func TestTheRecordIsPrivateAndSorted(t *testing.T) {
	f := newRecordFixture(t)
	path, err := WriteApplied(f.config, f.source, strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	var record map[string]any
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"files", "recorded_at", "revision", "schema"}) {
		t.Fatalf("keys %v", keys)
	}
}

func TestARemovedFileIsNotAChange(t *testing.T) {
	f := newRecordFixture(t)
	if _, err := WriteApplied(f.config, f.source, ""); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(f.source, "README.md"))
	if changed := PlanScope(f.config, f.source)["changed"]; changed != 0 {
		t.Fatalf("changed %v", changed)
	}
}

func TestFilesTheInstallationWritesIntoItsSourceNeverCount(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	f := newRecordFixture(t)
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"commit", "-q", "-m", "x"}} {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-C", f.source}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if _, err := WriteApplied(f.config, f.source, ""); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.source, "ansible/cache/facts"), "{}")
	write(t, filepath.Join(f.source, "ansible/new-untracked.yml"), "x")
	if changed := PlanScope(f.config, f.source)["changed"]; changed != 0 {
		t.Fatalf("changed %v", changed)
	}
}

func TestAStagedBundleSkipsKnownRuntimeFiles(t *testing.T) {
	f := newRecordFixture(t)
	before := SourceManifest(f.source)
	write(t, filepath.Join(f.source, "ansible/roles/cert/files/site.pem"), "secret")
	write(t, filepath.Join(f.source, "ansible/tcp.yml"), "x")
	if after := SourceManifest(f.source); !reflect.DeepEqual(after, before) {
		t.Fatalf("manifest %v", after)
	}
}

func TestADamagedRecordIsNoRecord(t *testing.T) {
	f := newRecordFixture(t)
	write(t, filepath.Join(f.config, AppliedSourceFile), "{not json")
	if ReadApplied(f.config) != nil || PlanScope(f.config, f.source)["ready"] != false {
		t.Fatal("a damaged record was used")
	}
}

func TestTheCommandPlansAndRecords(t *testing.T) {
	f := newRecordFixture(t)
	var stdout, stderr strings.Builder
	if code := RunCLI([]string{"record", "--config", f.config, "--source", f.source, "--revision", strings.Repeat("c", 40)},
		&stdout, &stderr); code != 0 {
		t.Fatalf("record: %d %s", code, stderr.String())
	}
	if code := RunCLI([]string{"plan", "--config", f.config, "--source", f.source}, &stdout, &stderr); code != 0 {
		t.Fatalf("plan: %d %s", code, stderr.String())
	}
	var scope map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &scope); err != nil || scope["applied_revision"] != strings.Repeat("c", 40) ||
		scope["ready"] != true || scope["changed"] != 0.0 {
		t.Fatalf("scope %v (%v)", scope, err)
	}
	if code := RunCLI([]string{"apply"}, &stdout, &stderr); code != 2 {
		t.Fatalf("an unknown action ran: %d", code)
	}
}

func TestThePageTranslatesTheScope(t *testing.T) {
	web := filepath.Join(repoRoot(), "go/panel/web/translations")
	read := func(path string) map[string]any {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var loaded map[string]any
		if err := json.Unmarshal(raw, &loaded); err != nil {
			t.Fatal(err)
		}
		if messages, isMap := loaded["messages"].(map[string]any); isMap {
			return messages
		}
		return loaded
	}
	updates := read(filepath.Join(web, "ru/updates.json"))
	for _, key := range []string{"Only what changed", "{count} changed file(s). Steps to run: {steps}",
		"These changes need the complete stack: {paths}",
		"Available after the next complete update: there is no record of the last one yet."} {
		if _, found := updates[key]; !found {
			t.Errorf("%q has no Russian", key)
		}
	}
	merged := map[string]any{}
	_ = filepath.Walk(web, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".json") &&
			(strings.Contains(filepath.ToSlash(path), "/ru/") || filepath.Base(path) == "ru.json") {
			for k, v := range read(path) {
				merged[k] = v
			}
		}
		return nil
	})
	for _, label := range TagLabels {
		if _, found := merged[label]; !found {
			t.Errorf("step %q has no Russian", label)
		}
	}
}
