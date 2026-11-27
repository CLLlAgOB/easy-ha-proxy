package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

// A symlink planted in a container-writable directory must not let a
// primitive read, chmod or write the host file it points at.
func TestPrimitivesRefuseSymlinks(t *testing.T) {
	f := newFake(t)
	f.write(t, "/etc/easy-ha-proxy/daemons.env", "TOKEN=secret\n", 0o600)
	if err := os.MkdirAll(f.Path("/opt/haproxy-admin/config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.Path("/etc/easy-ha-proxy/daemons.env"), f.Path("/opt/haproxy-admin/config/vars.yml")); err != nil {
		t.Fatal(err)
	}
	lif := &LineInFile{Path: "/opt/haproxy-admin/config/vars.yml", Regexp: regexp.MustCompile(`^TOKEN=`), Line: "TOKEN=x", Mode: 0o644}
	if _, err := lif.Check(f.System); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("LineInFile followed a symlink: %v", err)
	}
	if err := (&Touch{Path: "/opt/haproxy-admin/config/vars.yml", Mode: 0o644}).Apply(f.System, Change{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Touch followed a symlink: %v", err)
	}
	if err := (&ACL{Path: "/opt/haproxy-admin/config/vars.yml", User: "haproxyadmin", Perms: "r"}).Apply(f.System, Change{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ACL followed a symlink: %v", err)
	}
	if err := os.Symlink(f.Path("/etc"), f.Path("/opt/authelia-logs")); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Dir{Path: "/opt/authelia-logs", Mode: 0o750}).Check(f.System); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Dir followed a symlink: %v", err)
	}
	if raw, _ := os.ReadFile(f.Path("/etc/easy-ha-proxy/daemons.env")); string(raw) != "TOKEN=secret\n" {
		t.Fatalf("the host secret was modified: %q", raw)
	}
}

// validate: checks the new content in a temporary file, with the
// environment the task gives it; a refusal leaves the old file and no
// temporary one behind.
func TestFileValidateKeepsTheOldContentWhenRefused(t *testing.T) {
	f := newFake(t)
	f.write(t, "/etc/haproxy/haproxy.cfg", "old\n", 0o644)
	var seen []string
	f.ExecEnv = func(env []string, name string, args ...string) (string, int, error) {
		tmp := args[len(args)-1]
		raw, err := os.ReadFile(tmp)
		if err != nil {
			t.Fatalf("the check could not read the temporary file: %v", err)
		}
		seen = append(seen, strings.Join(env, ",")+" "+string(raw))
		if strings.Contains(string(raw), "bad") {
			return "[ALERT] parsing\n", 1, nil
		}
		return "", 0, nil
	}
	check := func(sys *System, tmp string) error {
		_, code, err := sys.RunEnv([]string{"SECRET=s"}, "haproxy", "-c", "-f", tmp)
		if err == nil && code != 0 {
			err = os.ErrInvalid
		}
		return err
	}
	file := &File{Path: "/etc/haproxy/haproxy.cfg", Content: []byte("bad\n"), Validate: check}
	c, err := file.Check(f.System)
	if err != nil || !c.Needed {
		t.Fatalf("check: %+v %v", c, err)
	}
	if err := file.Apply(f.System, c); err == nil {
		t.Fatal("a refused configuration was applied")
	}
	if got, _ := os.ReadFile(f.Path("/etc/haproxy/haproxy.cfg")); string(got) != "old\n" {
		t.Fatalf("the old file was replaced: %q", got)
	}
	if entries, _ := os.ReadDir(f.Path("/etc/haproxy")); len(entries) != 1 {
		t.Fatalf("a temporary file was left behind: %v", entries)
	}
	file.Content = []byte("good\n")
	c, _ = file.Check(f.System)
	if err := file.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(f.Path("/etc/haproxy/haproxy.cfg")); string(got) != "good\n" {
		t.Fatalf("an accepted configuration was not written: %q", got)
	}
	if strings.Join(seen, "|") != "SECRET=s bad\n|SECRET=s good\n" {
		t.Fatalf("the check saw %q", seen)
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

func TestCommandsSysctlLoopsAndTags(t *testing.T) {
	f := newFake(t)
	run := NewRun(Apply, f.System, nil)
	run.SkipTags["restore-network"] = true
	probe := &Command{Argv: []string{"certbot", "plugins"}, Probe: true}
	steps := []Step{
		{Name: "install", Tags: []string{"restore-network"}, Resource: &Packages{Names: []string{"x"}}},
		{Name: "ipset", Resource: &Command{Argv: []string{"ipset", "create", "a"}}},
		{Name: "probe", Resource: probe},
		{Name: "sysctl", Register: "fwd", Resource: &Sysctl{Name: "net.ipv4.ip_forward", Value: "1", File: "/s.conf", Reload: true}},
		{Name: "loop", Register: "loop", Resource: &Multi{Desc: "dirs", Items: []Resource{&Dir{Path: "/a"}, &Dir{Path: "/b"}}}},
		{Name: "skipped", Register: "never", When: func(*Run) bool { return false }},
	}
	f.write(t, "/s.conf", "# keep\nnet.ipv4.ip_forward = 0\nnet.core.x=5\nnet.core.x=6\n", 0o644)
	if err := run.Do("demo", steps); err != nil {
		t.Fatal(err)
	}
	statuses := []string{}
	for _, r := range run.Results {
		statuses = append(statuses, r.Status)
	}
	if strings.Join(statuses, ",") != "skipped,ok,ok,changed,changed,skipped" {
		t.Fatalf("statuses: %v", statuses)
	}
	joined := strings.Join(f.calls, "\n")
	if strings.Contains(joined, "dpkg-query") || !strings.Contains(joined, "ipset create a") ||
		!strings.Contains(joined, "certbot plugins") || !strings.Contains(joined, "sysctl -p /s.conf") {
		t.Fatalf("calls: %v", f.calls)
	}
	got, _ := os.ReadFile(f.Path("/s.conf"))
	if string(got) != "# keep\nnet.ipv4.ip_forward=1\nnet.core.x=5\n" {
		t.Fatalf("sysctl file, rewritten as the module does: %q", got)
	}
	if regs := run.Registers(); !regs["fwd"] || !regs["loop"] || regs["never"] {
		t.Fatalf("registers: %v", regs)
	}
	if _, ok := run.Registers()["never"]; !ok {
		t.Fatal("a skipped step's register is reported too, as unchanged")
	}

	// A plan runs probes but no other command.
	f.calls = nil
	plan := NewRun(Plan, f.System, nil)
	if err := plan.Do("demo", steps[1:3]); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "certbot") {
		t.Fatalf("a plan ran: %v", f.calls)
	}
}

// As in the apt module, a stale package list is refreshed when a task that
// names packages runs, but only an install counts as a change.
func TestAptInstallRefreshesWithoutCallingItAChange(t *testing.T) {
	f := newFake(t)
	installed := ""
	f.System.Exec = func(name string, args ...string) (string, int, error) {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		if name == "dpkg-query" {
			return installed, 0, nil
		}
		return "", 0, nil
	}
	apt := &AptInstall{Names: []string{"socat"}, UpdateCache: true, CacheValid: time.Hour}
	installed = "socat\tii \t1.8\n"
	c := check(t, f.System, apt)
	if c.Needed || !c.Run {
		t.Fatalf("installed package, stale lists: %+v", c)
	}
	if err := apt.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "apt-get update") || strings.Contains(strings.Join(f.calls, "\n"), "apt-get install") {
		t.Fatalf("calls: %v", f.calls)
	}
	pinned := &AptInstall{Names: []string{"haproxy-awslc=3.4.*"}}
	installed = "haproxy-awslc\tii \t3.2.1-1\n"
	if c := check(t, f.System, pinned); !c.Needed {
		t.Fatal("an installed version outside the pin is a change")
	}
	installed = "haproxy-awslc\tii \t3.4.2-1\n"
	if c := check(t, f.System, pinned); c.Needed {
		t.Fatal("a version inside the pin is not")
	}
}

// lineinfile: the last line the expression finds is replaced, else the line
// goes at the end (after a newline the file lacked); no change when it is
// already there.
func TestLineInFileFollowsAnsible(t *testing.T) {
	f := newFake(t)
	f.write(t, "/c/vars.yml", "a: 1\nhaproxy_nbthread: 1\nb: 2\n  haproxy_nbthread : 3\nc: 3", 0o644)
	line := &LineInFile{Path: "/c/vars.yml", Regexp: regexp.MustCompile(`^\s*haproxy_nbthread\s*:`), Line: "haproxy_nbthread: 2"}
	c := check(t, f.System, line)
	if !c.Needed || c.Summary != "line replaced" {
		t.Fatalf("replace: %+v", c)
	}
	if err := line.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Path("/c/vars.yml"))
	if string(got) != "a: 1\nhaproxy_nbthread: 1\nb: 2\nhaproxy_nbthread: 2\nc: 3" {
		t.Fatalf("only the last match is replaced: %q", got)
	}
	if c := check(t, f.System, line); c.Needed {
		t.Fatalf("already there: %+v", c)
	}
	add := &LineInFile{Path: "/c/vars.yml", Regexp: regexp.MustCompile(`^\s*haproxy_socket\s*:`), Line: `haproxy_socket: "/run/x"`}
	c = check(t, f.System, add)
	if err := add.Apply(f.System, c); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(f.Path("/c/vars.yml"))
	if !strings.HasSuffix(string(got), "c: 3\nhaproxy_socket: \"/run/x\"\n") {
		t.Fatalf("added at the end after a newline: %q", got)
	}
	missing := &LineInFile{Path: "/c/none.yml", Regexp: regexp.MustCompile(`x`), Line: "x"}
	if _, err := missing.Check(f.System); err == nil {
		t.Fatal("a missing file is an error without create:")
	}
}

// changed_when over the output: the command runs on apply only, and the
// step is changed only when the output says so.
func TestCommandOutcomeDecidesTheChange(t *testing.T) {
	f := newFake(t)
	out := "Container x Started\n"
	f.Exec = func(name string, args ...string) (string, int, error) {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		return out, 0, nil
	}
	cmd := func() *Command {
		return &Command{Argv: []string{"docker", "compose", "up"}, Dir: "/opt/x", Env: []string{"A=b"}, MergeStderr: true,
			ChangedWhen: func(o string, _ int) bool { return strings.Contains(o, "Started") }}
	}
	plan := NewRun(Plan, f.System, nil)
	if err := plan.Do("s", []Step{{Name: "up", Register: "up", Resource: cmd()}}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || plan.Changed("up") {
		t.Fatalf("plan ran it or called it changed: %v", f.calls)
	}
	apply := NewRun(Apply, f.System, nil)
	if err := apply.Do("s", []Step{{Name: "up", Register: "up", Notify: []string{"h"}, Resource: cmd()}}); err != nil {
		t.Fatal(err)
	}
	if !apply.Changed("up") || apply.Results[0].Status != "changed" || len(apply.Notified()) != 1 {
		t.Fatalf("outcome: %+v %v", apply.Results, apply.Notified())
	}
	if f.calls[0] != `/bin/sh -c exec "$@" 2>&1 sh env -C /opt/x A=b docker compose up` {
		t.Fatalf("argv: %q", f.calls[0])
	}
	out = "up to date\n"
	again := NewRun(Apply, f.System, nil)
	if err := again.Do("s", []Step{{Name: "up", Register: "up", Resource: cmd()}}); err != nil {
		t.Fatal(err)
	}
	if again.Changed("up") || again.Results[0].Status != "ok" {
		t.Fatalf("no change in the output: %+v", again.Results)
	}
}

// recurse: every entry below the directory that is not the owner's.
func TestTreeAndAttrs(t *testing.T) {
	f := newFake(t)
	f.write(t, "/d/a/b.txt", "x", 0o640)
	tree := &Tree{Path: "/d", Owner: "u", Group: "g"}
	if c := check(t, f.System, tree); c.Needed {
		t.Fatalf("everything is the current user's already: %+v", c)
	}
	f.LookupUser = func(string) (int, error) { return os.Getuid() + 1, nil }
	if c := check(t, f.System, tree); !c.Needed || c.Summary != "owner of 3 entries" {
		t.Fatalf("another owner: %+v", c)
	}
	attrs := &Attrs{Path: "/d/missing"}
	if _, err := attrs.Check(f.System); err == nil {
		t.Fatal("state: file on a missing file is an error")
	}
	attrs = &Attrs{Path: "/d/a/b.txt", Mode: 0o644}
	c := check(t, f.System, attrs)
	if !c.Needed || c.Summary != "mode 0640 -> 0644" {
		t.Fatalf("mode: %+v", c)
	}
}
