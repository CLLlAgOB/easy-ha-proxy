package stages

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	"easy-ha-proxy-updated | Inspect active update marker":  true, // stat, read in the conditions
	"Check if HAProxy was initialized before":               true, // stat, read in the conditions
	"AppArmor | info if disabled":                           true, // stat, read in the conditions
}

// taskNames lists a task file's task names in order, its import_tasks
// expanded in place, folded tasks left out.
func taskNames(t *testing.T, dir, file string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pyyaml.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var walk func(list []any)
	walk = func(list []any) {
		for _, task := range list {
			m := task.(*pyyaml.Map)
			imported, ok := m.Value("import_tasks").(string)
			if !ok {
				imported, ok = m.Value("ansible.builtin.import_tasks").(string)
			}
			if ok {
				names = append(names, taskNames(t, dir, imported)...)
				continue
			}
			if block, ok := m.Value("block").([]any); ok {
				walk(block) // a block's own name is not a task
				continue
			}
			if name, _ := m.Value("name").(string); !folded[name] {
				names = append(names, name)
			}
		}
	}
	walk(doc.([]any))
	return names
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
			want := taskNames(t, filepath.Join(root, "ansible", "roles", part.Role, "tasks"), part.TaskFile()+".yml")
			b := &Builder{Set: nil, Sys: &engine.System{}, RoleDir: ""}
			b.Set = mustSet(t, root, part)
			var got []string
			for _, step := range part.Build(b) {
				if len(got) == 0 || got[len(got)-1] != step.Name {
					got = append(got, step.Name) // a loop is one task
				}
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("%s/%s:\n  stage: %q\n  tasks: %q", part.Role, part.Name, got, want)
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
		Params: map[string]any{"task_stage": part.TaskFile()}})
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
		{"haproxy-admin/tasks/certd.yml", "Install the certificate delivery worker", certDeliver},
		{"haproxy-admin/tasks/iptables-udp.yml", "iptables-udp | Ensure a managed udp.yml exists (empty by default)", udpForwards},
		{"haproxy/tasks/protection.yml", "HAProxy updates | defer core restart to the controlled update", needrestartHaproxy},
		{"haproxy/tasks/apparmor.yml", "AppArmor | deploy local rules for rsyslogd (HAProxy chroot socket)", apparmorRsyslogd},
		{"haproxy/tasks/package.yml", "HAProxy package | Keep package updates within the selected branch", haproxyPin},
		{"haproxy/tasks/install.yml", "Ensure admin IPs file exists with static admin_allowed_ips", adminIPs},
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
		var tasks []any
		for _, task := range doc.([]any) {
			if block, ok := task.(*pyyaml.Map).Value("block").([]any); ok {
				tasks = append(tasks, block...)
			} else {
				tasks = append(tasks, task)
			}
		}
		for _, task := range tasks {
			m := task.(*pyyaml.Map)
			if m.Value("name") != c.task {
				continue
			}
			found = true
			args, _ := m.Value("ansible.builtin.copy").(*pyyaml.Map)
			if args == nil {
				args, _ = m.Value("copy").(*pyyaml.Map)
			}
			if args == nil || args.Value("content") != c.content {
				t.Errorf("%s: the Go content differs from the task's", c.task)
			}
		}
		if !found {
			t.Errorf("%s: no task %q", c.file, c.task)
		}
	}
}

// The role's go_installer_parts names exactly the parts the agent has, so
// Ansible asks about every one and about nothing else.
func TestTheRoleListsTheAgentsParts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "ansible", "roles", "haproxy-admin", "defaults", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pyyaml.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, name := range doc.(*pyyaml.Map).Value("go_installer_parts").([]any) {
		listed[name.(string)] = true
	}
	for name := range Parts() {
		if !listed[name] {
			t.Errorf("part %s is missing from go_installer_parts", name)
		}
		delete(listed, name)
	}
	for name := range listed {
		t.Errorf("go_installer_parts lists %s, which the agent does not have", name)
	}
}

// Each role's main.yml writes its parts out (a static import's name is
// templated from the role parameters alone); they must be that role's parts,
// the pre-task ones aside.
func TestMainYmlSendsTheSamePartsToTheFallback(t *testing.T) {
	for _, role := range []string{"haproxy-admin", "haproxy"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), "ansible", "roles", role, "tasks", "main.yml"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		start := strings.Index(text, "task_stage in [")
		end := strings.Index(text[start:], "]") + start
		if start < 0 || end < start {
			t.Fatalf("%s main.yml has no inline part list:\n%s", role, text)
		}
		var listed []string
		for _, item := range strings.Split(text[start+len("task_stage in ["):end], ",") {
			listed = append(listed, strings.Trim(strings.TrimSpace(item), "'"))
		}
		sort.Strings(listed)
		var files []string
		for _, p := range Parts() {
			if p.Role == role && !p.PreTask {
				files = append(files, p.TaskFile())
			}
		}
		sort.Strings(files)
		if strings.Join(listed, ",") != strings.Join(files, ",") {
			t.Errorf("%s main.yml lists %v, the agent has %v", role, listed, files)
		}
	}
}
