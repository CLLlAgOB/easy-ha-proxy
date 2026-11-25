package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystem is a temp root, every name owned by the current user, and a
// systemctl that remembers what it was told.
type fakeSystem struct {
	*System
	enabled map[string]bool
	active  map[string]bool
	calls   []string
}

func newFake(t *testing.T) *fakeSystem {
	t.Helper()
	f := &fakeSystem{enabled: map[string]bool{}, active: map[string]bool{}}
	uid, gid := os.Getuid(), os.Getgid()
	f.System = &System{
		Root:        t.TempDir(),
		LookupUser:  func(string) (int, error) { return uid, nil },
		LookupGroup: func(string) (int, error) { return gid, nil },
		Exec: func(name string, args ...string) (string, int, error) {
			f.calls = append(f.calls, name+" "+strings.Join(args, " "))
			if name != "systemctl" {
				return "", 0, nil
			}
			switch args[0] {
			case "is-enabled":
				if f.enabled[args[1]] {
					return "enabled\n", 0, nil
				}
				return "disabled\n", 1, nil
			case "show":
				if f.active[args[1]] {
					return "active\n", 0, nil
				}
				return "inactive\n", 0, nil
			case "enable":
				f.enabled[args[1]] = true
			case "start", "restart":
				f.active[args[1]] = true
			case "stop":
				f.active[args[1]] = false
			}
			return "", 0, nil
		},
	}
	return f
}

func (f *fakeSystem) write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	full := f.Path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

func check(t *testing.T, sys *System, r Resource) Change {
	t.Helper()
	c, err := r.Check(sys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFileWritesOnlyWhatDiffers(t *testing.T) {
	f := newFake(t)
	if err := os.MkdirAll(f.Path("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := &File{Path: "/etc/x.conf", Content: []byte("a=1\n"), Owner: "root", Group: "root", Mode: 0o640}
	c := check(t, f.System, file)
	if !c.Needed || c.Summary != "create, 4 bytes" {
		t.Fatalf("missing file: %+v", c)
	}
	if err := file.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f.Path("/etc/x.conf"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("written mode: %v %v", fi, err)
	}
	if c := check(t, f.System, file); c.Needed {
		t.Fatalf("same content and mode: %+v", c)
	}
	if err := os.Chmod(f.Path("/etc/x.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	c = check(t, f.System, file)
	if !c.Needed || c.Summary != "mode 0644 -> 0640" {
		t.Fatalf("mode only: %+v", c)
	}
	if err := file.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	file.Content = []byte("a=2\n")
	c = check(t, f.System, file)
	if !c.Needed || c.Summary != "content 4 -> 4 bytes" {
		t.Fatalf("content: %+v", c)
	}
	if err := file.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Path("/etc/x.conf"))
	if string(got) != "a=2\n" {
		t.Fatalf("content after apply: %q", got)
	}
	entries, _ := os.ReadDir(f.Path("/etc"))
	if len(entries) != 1 {
		t.Fatalf("a temporary file was left behind: %v", entries)
	}
	seed := &File{Path: "/etc/x.conf", Content: []byte("other\n"), OnlyIfMissing: true}
	if c := check(t, f.System, seed); c.Needed {
		t.Fatalf("force: false never rewrites an existing file: %+v", c)
	}
}

func TestDirAbsentAndTouch(t *testing.T) {
	f := newFake(t)
	dir := &Dir{Path: "/var/lib/x/y", Mode: 0o750}
	c := check(t, f.System, dir)
	if !c.Needed {
		t.Fatal("missing directory")
	}
	if err := dir.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(f.Path("/var/lib/x/y")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
		t.Fatalf("directory: %v %v", fi, err)
	}
	if c := check(t, f.System, dir); c.Needed {
		t.Fatalf("existing directory: %+v", c)
	}
	f.write(t, "/var/lib/x/file", "x", 0o644)
	if _, err := (&Dir{Path: "/var/lib/x/file"}).Check(f.System); err == nil {
		t.Fatal("a file where a directory belongs must fail, as in Ansible")
	}
	gone := &Absent{Path: "/var/lib/x/file"}
	if c := check(t, f.System, gone); !c.Needed {
		t.Fatal("present file")
	}
	if err := gone.Apply(f.System, Change{}); err != nil {
		t.Fatal(err)
	}
	if c := check(t, f.System, gone); c.Needed {
		t.Fatal("removed file")
	}
	touch := &Touch{Path: "/var/lib/x/marker", Mode: 0o600}
	if c := check(t, f.System, touch); !c.Needed {
		t.Fatal("touch always changes")
	}
	if err := touch.Apply(f.System, Change{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(f.Path("/var/lib/x/marker")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("touched: %v %v", fi, err)
	}
}

func TestUnitEnablesStartsAndRestarts(t *testing.T) {
	f := newFake(t)
	u := &Unit{Name: "x.service", Enabled: Bool(true), State: "started"}
	c := check(t, f.System, u)
	if c.Summary != "enable; start" {
		t.Fatalf("new unit: %+v", c)
	}
	if err := u.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	if c := check(t, f.System, u); c.Needed {
		t.Fatalf("enabled and running: %+v", c)
	}
	if c := check(t, f.System, &Unit{Name: "x.service", State: "restarted"}); c.Summary != "restart" {
		t.Fatalf("restarted always acts: %+v", c)
	}
	if c := check(t, f.System, &Unit{Name: "x.service", State: "stopped"}); c.Summary != "stop" {
		t.Fatalf("stop a running unit: %+v", c)
	}
}

// A plan changes nothing yet shows the restarts an apply would do: later
// conditions see the would-be changes of registered steps.
func TestPlanPredictsAndApplyDoes(t *testing.T) {
	steps := func() []Step {
		return []Step{
			{Name: "Install unit", Register: "unit", Resource: &File{Path: "/u.service", Content: []byte("[Unit]\n"), Mode: 0o644}},
			{Name: "Reload if unit changed", When: func(r *Run) bool { return r.Changed("unit") }, Resource: DaemonReload{}},
			{Name: "Restart if changed", When: func(r *Run) bool { return r.ChangedAny("unit", "env") },
				Resource: &Unit{Name: "u.service", State: "restarted"}},
			{Name: "Ensure started", Resource: &Unit{Name: "u.service", State: "started"}},
		}
	}
	f := newFake(t)
	var journal bytes.Buffer
	plan := NewRun(Plan, f.System, &journal)
	if err := plan.Do("demo", steps()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.Path("/u.service")); !os.IsNotExist(err) {
		t.Fatal("a plan must not write")
	}
	for _, call := range f.calls {
		if !strings.HasPrefix(call, "systemctl show") && !strings.HasPrefix(call, "systemctl is-enabled") {
			t.Fatalf("a plan ran %q", call)
		}
	}
	if got := plan.Counts(); got["would_change"] != 4 {
		t.Fatalf("plan counts: %v", got)
	}
	lines := strings.Split(strings.TrimSpace(journal.String()), "\n")
	var first Result
	if len(lines) != 4 || json.Unmarshal([]byte(lines[0]), &first) != nil || first.Status != "would_change" || first.Stage != "demo" {
		t.Fatalf("journal: %v", lines)
	}

	apply := NewRun(Apply, f.System, nil)
	if err := apply.Do("demo", steps()); err != nil {
		t.Fatal(err)
	}
	if got := apply.Counts(); got["changed"] != 3 || got["ok"] != 1 {
		t.Fatalf("first apply: %v (restart makes it running, so start is ok)", got)
	}
	again := NewRun(Apply, f.System, nil)
	if err := again.Do("demo", steps()); err != nil {
		t.Fatal(err)
	}
	if got := again.Counts(); got["ok"] != 2 || got["skipped"] != 2 {
		t.Fatalf("a converged host: %v", got)
	}
	seeded := NewRun(Plan, f.System, nil, "env")
	if err := seeded.Do("demo", steps()); err != nil {
		t.Fatal(err)
	}
	if seeded.Results[2].Status != "would_change" {
		t.Fatalf("a change seeded from an earlier stage still restarts: %+v", seeded.Results[2])
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]os.FileMode{"0640": 0o640, "755": 0o755, "2750": 0o750 | os.ModeSetgid, "0o600": 0o600} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseMode("rw-r--r--"); err == nil {
		t.Error("symbolic modes are not supported")
	}
}
