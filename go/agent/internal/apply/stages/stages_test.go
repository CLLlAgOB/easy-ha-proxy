package stages

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/vars"
)

// Tasks a stage folds into the conditions of later steps instead of running.
var folded = map[string]bool{
	"haproxy-controld | Check runtime environment":          true, // stat, read in the conditions
	"easy-ha-proxy-backupd | Inspect active restore marker": true, // stat, read in the conditions
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..")
}

// Each part lists the same tasks, in the same order, as the Ansible task file
// it transcribes: editing a task file without its stage fails here.
func TestStagesFollowTheirTaskFiles(t *testing.T) {
	root := repoRoot(t)
	for _, name := range Names() {
		for _, part := range registry[name].Parts {
			path := filepath.Join(root, "ansible", "roles", part.Role, "tasks", part.TaskStage+".yml")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := pyyaml.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, task := range doc.([]any) {
				taskName, _ := task.(*pyyaml.Map).Value("name").(string)
				if !folded[taskName] {
					want = append(want, taskName)
				}
			}
			b := &Builder{Set: nil, Sys: &engine.System{}, RoleDir: ""}
			b.Set = mustSet(t, root, part)
			var got []string
			for _, step := range part.Build(b) {
				if len(got) == 0 || got[len(got)-1] != step.Name {
					got = append(got, step.Name) // a loop is one task
				}
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("%s/%s:\n  stage: %q\n  tasks: %q", part.Role, part.TaskStage, got, want)
			}
		}
	}
}

// mustSet loads a part's variables over the repository's roles and an empty
// configuration (the checkout may hold an ignored group_vars, which the loader
// refuses, so the roles are linked into a clean source dir).
func mustSet(t *testing.T, root string, part Part) *vars.Set {
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
	set, err := vars.Load(vars.Options{SourceDir: source, ConfigDir: config, Role: part.Role,
		Params: map[string]any{"task_stage": part.TaskStage}})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// Inline content: of copy tasks is kept in Go word for word; hold it to the
// task file (a transcription that dropped its comment lines was caught on a
// host by "apply plan").
func TestInlineContentMatchesTheTaskFile(t *testing.T) {
	root := repoRoot(t)
	for _, c := range []struct{ file, task, content string }{
		{"haproxy-admin/tasks/journald-retention.yml", "journald | Configure retention (MaxRetentionSec/MaxFileSec)", journaldRetention},
	} {
		raw, err := os.ReadFile(filepath.Join(root, "ansible", "roles", c.file))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := pyyaml.Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, task := range doc.([]any) {
			m := task.(*pyyaml.Map)
			if m.Value("name") != c.task {
				continue
			}
			found = true
			args, _ := m.Value("ansible.builtin.copy").(*pyyaml.Map)
			if args == nil || args.Value("content") != c.content {
				t.Errorf("%s: the Go content differs from the task's", c.task)
			}
		}
		if !found {
			t.Errorf("%s: no task %q", c.file, c.task)
		}
	}
}
