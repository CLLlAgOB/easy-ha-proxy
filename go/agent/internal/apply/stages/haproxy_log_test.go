package stages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// The access log rsyslog writes and the panel compose bind-mounts must be a
// regular file. On images where /var/log is root-owned 0755, rsyslog cannot
// create it, and Docker creates a directory at the missing mount source,
// leaving guardd and the Log Explorer without data. The fs stage keeps the
// file syslog:adm 0640 and replaces an empty directory left at the path; a
// filled one is refused. The steps run here in a temporary root, the owner
// lookups standing in for syslog and adm as a root run would resolve them.

type accessLogFixture struct {
	t    *testing.T
	root string
	sys  *engine.System
}

func newAccessLogFixture(t *testing.T) *accessLogFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/log"), 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	sys := &engine.System{Root: root,
		LookupUser:  func(string) (int, error) { return uid, nil },
		LookupGroup: func(string) (int, error) { return gid, nil },
		Exec:        func(string, ...string) (string, int, error) { return "", 0, nil }}
	return &accessLogFixture{t: t, root: root, sys: sys}
}

func (f *accessLogFixture) path() string { return filepath.Join(f.root, "var/log/haproxy.log") }

func (f *accessLogFixture) run(mode engine.Mode) ([]engine.Result, error) {
	f.t.Helper()
	steps := buildPart(f.t, "haproxy/install", f.sys, nil)
	r := engine.NewRun(mode, f.sys, nil)
	err := r.Do("haproxy/install", pick(f.t, steps,
		"Replace an empty directory at the HAProxy access log path",
		"Ensure the HAProxy access log exists for rsyslog and the panel"))
	return r.Results, err
}

func (f *accessLogFixture) mkdirAtLogPath() {
	f.t.Helper()
	if err := os.MkdirAll(f.path(), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *accessLogFixture) writeLog(content string, mode os.FileMode) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.path()), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.path(), []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.path(), mode); err != nil {
		f.t.Fatal(err)
	}
}

func TestAccessLogIsCreatedBeforeAnythingMountsIt(t *testing.T) {
	f := newAccessLogFixture(t)
	results, err := f.run(engine.Apply)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(f.path())
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the access log is not a regular file: %v", err)
	}
	if fi.Mode().Perm() != 0o640 || fi.Size() != 0 {
		t.Fatalf("access log mode %o size %d", fi.Mode().Perm(), fi.Size())
	}
	if results[1].Status != "changed" {
		t.Fatalf("the create was not reported: %+v", results)
	}
}

func TestAccessLogPlanChangesNothing(t *testing.T) {
	f := newAccessLogFixture(t)
	results, err := f.run(engine.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.path()); !os.IsNotExist(err) {
		t.Fatalf("a plan created the log: %v", err)
	}
	if results[1].Status != "would_change" {
		t.Fatalf("the plan does not report the create: %+v", results)
	}
}

func TestAccessLogReplacesAnEmptyDirectory(t *testing.T) {
	f := newAccessLogFixture(t)
	f.mkdirAtLogPath()
	results, err := f.run(engine.Apply)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(f.path())
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
		t.Fatalf("the empty directory was not replaced with the log file: %v", err)
	}
	if results[0].Status != "changed" || results[1].Status != "changed" {
		t.Fatalf("the replacement was not reported: %+v", results)
	}
}

func TestAccessLogRefusesAFilledDirectory(t *testing.T) {
	f := newAccessLogFixture(t)
	f.mkdirAtLogPath()
	kept := filepath.Join(f.path(), "kept")
	if err := os.WriteFile(kept, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.run(engine.Apply)
	if err == nil || !strings.Contains(err.Error(), "directory with contents") {
		t.Fatalf("a filled directory was not refused: %v", err)
	}
	if raw, readErr := os.ReadFile(kept); readErr != nil || string(raw) != "data" {
		t.Fatalf("the directory contents were touched: %v", readErr)
	}
}

func TestAccessLogFixesLoosePermissionsWithoutRewriting(t *testing.T) {
	f := newAccessLogFixture(t)
	f.writeLog("lines rsyslog wrote\n", 0o644)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(f.path(), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(engine.Apply); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(f.path())
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("the mode was not tightened: %v", err)
	}
	if raw, _ := os.ReadFile(f.path()); string(raw) != "lines rsyslog wrote\n" {
		t.Fatalf("the log was rewritten: %q", raw)
	}
	if !fi.ModTime().Equal(old) {
		t.Fatalf("the log's times were not preserved: %s", fi.ModTime())
	}
}

func TestAccessLogLeavesACorrectFileAlone(t *testing.T) {
	f := newAccessLogFixture(t)
	f.writeLog("lines rsyslog wrote\n", 0o640)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(f.path(), old, old); err != nil {
		t.Fatal(err)
	}
	results, err := f.run(engine.Apply)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		if res.Status != "ok" {
			t.Fatalf("a correct log was changed: %+v", results)
		}
	}
	fi, _ := os.Lstat(f.path())
	if !fi.ModTime().Equal(old) {
		t.Fatalf("the log's times were not preserved: %s", fi.ModTime())
	}
}
