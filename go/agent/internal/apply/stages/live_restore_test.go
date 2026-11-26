package stages

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// Docker live-restore keeps the containers running while apt restarts the
// daemon during a system upgrade. The stage merges it into daemon.json (the
// other settings and the file's mode kept), lets dockerd validate the result,
// reloads Docker -- never restarts or starts it -- verifies the running
// daemon took it, and puts the previous file back when anything fails.
//
// The stage runs for real here, in a temporary root, against a docker,
// dockerd and systemctl stand-in that keeps its state like the real ones.

type dockerFake struct {
	Active     bool   `json:"active"`
	Live       bool   `json:"live"`
	Reject     bool   `json:"reject"`
	FailReload bool   `json:"fail_reload"`
	Flags      string `json:"flags"`
	Swarm      string `json:"swarm"`
	calls      []string
}

const liveOriginal = `{"registry-mirrors":["https://registry.example.test"],"log-driver":"local"}` + "\n"

type liveFixture struct {
	t      *testing.T
	root   string
	config string // daemon.json inside the root
	docker *dockerFake
	sys    *engine.System
}

func newLiveFixture(t *testing.T) *liveFixture {
	t.Helper()
	f := &liveFixture{t: t, root: t.TempDir(), docker: &dockerFake{Active: true}}
	f.config = filepath.Join(f.root, "etc/docker/daemon.json")
	for _, dir := range []string{"usr/bin", "etc/docker"} {
		if err := os.MkdirAll(filepath.Join(f.root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.root, "usr/bin/dockerd"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, []byte(liveOriginal), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	f.sys = &engine.System{Root: f.root,
		LookupUser:  func(string) (int, error) { return uid, nil },
		LookupGroup: func(string) (int, error) { return gid, nil },
		Exec:        f.exec}
	return f
}

// configLive reads live-restore from a daemon.json, false when absent.
func configLive(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	live, _ := v["live-restore"].(bool)
	return live
}

func (f *liveFixture) exec(name string, args ...string) (string, int, error) {
	d := f.docker
	d.calls = append(d.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "/bin/sh" && strings.Contains(strings.Join(args, " "), "dockerd --validate"):
		if d.Reject && configLive(args[len(args)-1]) {
			return "unable to configure the Docker daemon", 1, nil
		}
		return "configuration OK", 0, nil
	case name == "systemctl" && args[0] == "show":
		state := "inactive"
		if d.Active {
			state = "active"
		}
		return "ActiveState=" + state + "\nExecStart={ argv[]=/usr/bin/dockerd " + d.Flags + " ; }\n", 0, nil
	case name == "systemctl" && args[0] == "reload":
		if d.FailReload {
			d.FailReload = false
			return "", 1, nil
		}
		if !d.Active {
			return "", 1, nil
		}
		d.Live = configLive(f.config)
		return "", 0, nil
	case name == "systemctl":
		f.t.Errorf("only reload is allowed: systemctl %v", args)
		return "", 1, nil
	case name == "/usr/bin/docker":
		if !d.Active {
			return "Docker is stopped", 1, nil
		}
		if args[len(args)-1] == "{{json .}}" {
			swarm := d.Swarm
			if swarm == "" {
				swarm = "inactive"
			}
			raw, _ := json.Marshal(map[string]any{"LiveRestoreEnabled": d.Live, "Swarm": map[string]any{"LocalNodeState": swarm}})
			return string(raw), 0, nil
		}
		if d.Live {
			return "true\n", 0, nil
		}
		return "false\n", 0, nil
	}
	f.t.Errorf("unexpected command %s %v", name, args)
	return "", 127, nil
}

func (f *liveFixture) apply(enabled, succeed bool, mode engine.Mode) {
	f.t.Helper()
	part := Part{Name: "docker/docker", Role: "docker", File: "docker"}
	b := &Builder{Set: mustSetWith(f.t, repoRoot(f.t), part, map[string]any{"docker_live_restore_enabled": enabled}), Sys: f.sys}
	steps := dockerLiveRestore(b)
	if b.err != nil {
		f.t.Fatal(b.err)
	}
	err := engine.NewRun(mode, f.sys, nil).Do("docker/docker", steps)
	if succeed && err != nil {
		f.t.Fatalf("the stage failed: %v", err)
	}
	if !succeed && err == nil {
		f.t.Fatal("the stage succeeded")
	}
	for _, call := range f.docker.calls {
		if strings.HasPrefix(call, "systemctl start") || strings.HasPrefix(call, "systemctl restart") {
			f.t.Fatalf("Docker was (re)started: %q", call)
		}
	}
}

func (f *liveFixture) reloads() int {
	n := 0
	for _, call := range f.docker.calls {
		if strings.HasPrefix(call, "systemctl reload") {
			n++
		}
	}
	return n
}

func (f *liveFixture) read() string {
	raw, err := os.ReadFile(f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func (f *liveFixture) mode() os.FileMode {
	fi, err := os.Stat(f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestLiveRestoreMergesReloadsAndASecondApplyChangesNothing(t *testing.T) {
	f := newLiveFixture(t)
	f.apply(true, true, engine.Apply)
	var config map[string]any
	if err := json.Unmarshal([]byte(f.read()), &config); err != nil {
		t.Fatal(err)
	}
	if config["live-restore"] != true {
		t.Fatalf("live-restore not written: %v", config)
	}
	delete(config, "live-restore")
	var original map[string]any
	json.Unmarshal([]byte(liveOriginal), &original)
	if raw, raw2 := mustJSON(config), mustJSON(original); raw != raw2 {
		t.Fatalf("other settings changed: %s, was %s", raw, raw2)
	}
	if f.mode() != 0o600 {
		t.Fatalf("mode %o", f.mode())
	}
	if !f.docker.Live {
		t.Fatal("the running daemon did not take it")
	}
	before, _ := os.Stat(f.config)
	f.apply(true, true, engine.Apply)
	after, _ := os.Stat(f.config)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the second apply rewrote the file")
	}
	if f.reloads() != 1 {
		t.Fatalf("%d reloads", f.reloads())
	}
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func TestLiveRestoreReloadsAStaleRuntimeWhenTheFileMatches(t *testing.T) {
	f := newLiveFixture(t)
	os.WriteFile(f.config, []byte(`{"live-restore": true}`+"\n"), 0o600)
	f.apply(true, true, engine.Apply)
	if !f.docker.Live {
		t.Fatal("not reloaded")
	}
}

func TestLiveRestoreRejectedByDockerdKeepsTheOriginal(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.Reject = true
	f.apply(true, false, engine.Apply)
	if f.read() != liveOriginal || f.mode() != 0o600 || f.docker.Live {
		t.Fatalf("file %q mode %o live %v", f.read(), f.mode(), f.docker.Live)
	}
}

func TestLiveRestoreFailedReloadRollsBack(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.FailReload = true
	f.apply(true, false, engine.Apply)
	if f.read() != liveOriginal || f.docker.Live {
		t.Fatalf("file %q live %v", f.read(), f.docker.Live)
	}
}

func TestLiveRestoreDoesNotStartAStoppedOrFreshDocker(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.Active = false
	os.Remove(f.config)
	f.apply(true, true, engine.Apply)
	if !configLive(f.config) || f.docker.Active || f.reloads() != 0 {
		t.Fatalf("file %q active %v reloads %d", f.read(), f.docker.Active, f.reloads())
	}
}

func TestLiveRestoreRefusesSwarmAndCanBeTurnedOff(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.Swarm, f.docker.Live = "active", true
	f.apply(true, false, engine.Apply)
	if f.read() != liveOriginal {
		t.Fatalf("file changed under Swarm: %q", f.read())
	}
	f.apply(false, true, engine.Apply)
	if configLive(f.config) || f.docker.Live {
		t.Fatalf("not turned off: %q live %v", f.read(), f.docker.Live)
	}
	if !strings.Contains(f.read(), `"live-restore": false`) {
		t.Fatalf("the off switch is not written: %q", f.read())
	}
}

func TestLiveRestoreOnTheCommandLineIsVerifiedNotDuplicated(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.Flags, f.docker.Live = "--live-restore=true", true
	f.apply(true, true, engine.Apply)
	if f.read() != liveOriginal || f.reloads() != 0 {
		t.Fatalf("file %q reloads %d", f.read(), f.reloads())
	}
	f.apply(false, false, engine.Apply)
	if f.read() != liveOriginal {
		t.Fatalf("file %q", f.read())
	}
}

func TestLiveRestoreLeavesACustomConfigPathAndASymlinkAlone(t *testing.T) {
	f := newLiveFixture(t)
	f.docker.Flags = "--config-file=/custom/docker.json"
	f.apply(true, false, engine.Apply)
	if f.read() != liveOriginal {
		t.Fatalf("file %q", f.read())
	}
	f.docker.Flags = ""
	target := filepath.Join(f.root, "original.json")
	if err := os.Rename(f.config, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.config); err != nil {
		t.Fatal(err)
	}
	f.apply(true, false, engine.Apply)
	if fi, err := os.Lstat(f.config); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
	if raw, _ := os.ReadFile(target); string(raw) != liveOriginal {
		t.Fatalf("the target changed: %q", raw)
	}
}

func TestLiveRestorePlanChangesNothing(t *testing.T) {
	f := newLiveFixture(t)
	f.apply(true, true, engine.Plan)
	if f.read() != liveOriginal || f.reloads() != 0 {
		t.Fatalf("file %q reloads %d", f.read(), f.reloads())
	}
}
