package contract

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Bootstrap must apply the fetched branch even in a single-branch clone:
// the checkout-update block of install-local.sh runs here against a
// disposable origin and a depth-1 clone of main. Nothing outside the block
// (APT, venv setup, entrypoints or services) runs.

type bootstrapFixture struct {
	t      *testing.T
	origin string
	source string
	alpha  string
}

func (f *bootstrapFixture) git(dir string, args ...string) (string, int) {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			f.t.Fatalf("git %v: %v", args, err)
		}
	}
	return stdout.String(), code
}

func (f *bootstrapFixture) gitOut(dir string, args ...string) string {
	f.t.Helper()
	out, code := f.git(dir, args...)
	if code != 0 {
		f.t.Fatalf("git %v: exit %d", args, code)
	}
	return out
}

func (f *bootstrapFixture) commit(content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.origin, "payload"), []byte(content+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
	f.gitOut(f.origin, "add", "payload")
	f.gitOut(f.origin, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
		"commit", "--quiet", "-m", content)
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := t.TempDir()
	f := &bootstrapFixture{t: t, origin: filepath.Join(root, "origin"), source: filepath.Join(root, "installed")}
	if err := os.MkdirAll(f.origin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.gitOut(f.origin, "init", "--quiet", "-b", "main")
	f.commit("main")
	f.gitOut(f.origin, "checkout", "--quiet", "-b", "alpha")
	f.commit("alpha")
	f.alpha = strings.TrimSpace(f.gitOut(f.origin, "rev-parse", "HEAD"))
	f.gitOut(root, "clone", "--quiet", "--depth=1", "--branch", "main", "file://"+f.origin, f.source)
	return f
}

// update executes the checkout-update block from the real bootstrap.
func (f *bootstrapFixture) update(branch string) (string, int) {
	f.t.Helper()
	source := read(f.t, "install-local.sh")
	parts := strings.SplitN(source, "elif [[ -d \"${source_dir}/.git\" ]]; then\n", 2)
	if len(parts) != 2 {
		f.t.Fatal("the checkout-update block is not in install-local.sh")
	}
	block := strings.SplitN(parts[1], "elif [[ -e \"${source_dir}\" ]]; then", 2)[0]
	cmd := exec.Command("bash", "-c", "set -Eeuo pipefail\nlog() { :; }\n"+block)
	cmd.Env = append(os.Environ(), "source_dir="+f.source, "branch="+branch)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			f.t.Fatal(err)
		}
	}
	return stderr.String(), code
}

func TestBootstrapSwitchesToABranchAbsentFromTheCloneRefspec(t *testing.T) {
	f := newBootstrapFixture(t)
	mustContain(t, f.gitOut(f.source, "config", "--get", "remote.origin.fetch"), "refs/heads/main", "clone refspec")
	if _, code := f.git(f.source, "rev-parse", "--verify", "refs/remotes/origin/alpha"); code == 0 {
		t.Fatal("origin/alpha is already in the clone")
	}
	stderr, code := f.update("alpha")
	if code != 0 {
		t.Fatalf("rc %d: %s", code, stderr)
	}
	if got := strings.TrimSpace(f.gitOut(f.source, "rev-parse", "HEAD")); got != f.alpha {
		t.Fatalf("HEAD %s, want %s", got, f.alpha)
	}
	if raw, _ := os.ReadFile(filepath.Join(f.source, "payload")); string(raw) != "alpha\n" {
		t.Fatalf("payload %q", raw)
	}
}

func TestBootstrapDoesNotResetToAStaleRemoteTrackingRef(t *testing.T) {
	f := newBootstrapFixture(t)
	f.gitOut(f.source, "fetch", "origin", "alpha:refs/remotes/origin/alpha")
	oldAlpha := strings.TrimSpace(f.gitOut(f.source, "rev-parse", "origin/alpha"))
	f.commit("new alpha")
	currentAlpha := strings.TrimSpace(f.gitOut(f.origin, "rev-parse", "HEAD"))
	stderr, code := f.update("alpha")
	if code != 0 {
		t.Fatalf("rc %d: %s", code, stderr)
	}
	if oldAlpha == currentAlpha {
		t.Fatal("the origin did not move")
	}
	if got := strings.TrimSpace(f.gitOut(f.source, "rev-parse", "HEAD")); got != currentAlpha {
		t.Fatalf("HEAD %s, want %s", got, currentAlpha)
	}
}

func TestBootstrapFailedFetchLeavesTheCurrentCheckoutUntouched(t *testing.T) {
	f := newBootstrapFixture(t)
	before := f.gitOut(f.source, "rev-parse", "HEAD")
	if _, code := f.update("missing"); code == 0 {
		t.Fatal("the update of a missing branch succeeded")
	}
	if got := f.gitOut(f.source, "rev-parse", "HEAD"); got != before {
		t.Fatalf("HEAD moved: %s -> %s", before, got)
	}
	if raw, _ := os.ReadFile(filepath.Join(f.source, "payload")); string(raw) != "main\n" {
		t.Fatalf("payload %q", raw)
	}
}