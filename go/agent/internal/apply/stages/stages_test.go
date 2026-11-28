package stages

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..")
}

// mustSet loads a part's variables over the repository's roles and an empty
// configuration (the checkout may hold an ignored group_vars, which the loader
// refuses, so the roles are linked into a clean source dir).
func mustSet(t *testing.T, root string, part Part) *vars.Set {
	t.Helper()
	return mustSetWith(t, root, part, nil)
}

// testFacts are a supported gateway's facts (Ubuntu 24.04 on amd64), for the
// tasks that read them; an extra variable overrides any of them.
var testFacts = map[string]any{"os_family": "Debian", "distribution": "Ubuntu", "distribution_version": "24.04",
	"distribution_release": "noble", "distribution_major_version": "24", "architecture": "x86_64",
	"hostname": "gateway", "fqdn": "gateway.example.test"}

// mustSetWith is mustSet with extra variables (--extra-vars).
func mustSetWith(t *testing.T, root string, part Part, extra map[string]any) *vars.Set {
	t.Helper()
	source, config := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "ansible"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "ansible", "roles"), filepath.Join(source, "ansible", "roles")); err != nil {
		t.Fatal(err)
	}
	playbook, err := os.ReadFile(filepath.Join(root, vars.Playbook))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"inventory.ini": "[easy_ha_proxy]\nlocalhost ansible_connection=local\n"}
	for _, name := range []string{"vars.yml", "authelia.yml", "authelia_users_initial.yml", "websites.yml", "tcp.yml", "secrets.yml"} {
		files[name] = "{}\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(config, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, vars.Playbook), playbook, 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := vars.Load(vars.Options{SourceDir: source, ConfigDir: config, Play: part.Play, Role: part.Role,
		Params: map[string]any{"task_stage": part.TaskFile()}, Extra: extra, Facts: testFacts})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// Every topic a part notifies has a Go handler.
func TestEveryNotifiedTopicHasAHandler(t *testing.T) {
	topics := map[string]bool{}
	for _, name := range HandlerTopics() {
		topics[name] = true
	}
	for _, name := range []string{validateHaproxy, applyHaproxy, apparmorRsyslog, buildPEMs, "Restart Docker"} {
		if !topics[name] {
			t.Errorf("no handler for %q", name)
		}
	}
}
