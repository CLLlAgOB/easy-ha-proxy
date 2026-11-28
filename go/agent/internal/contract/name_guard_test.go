package contract

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/nameguard"
)

// The name guard finds a guarded word in the tree and in pushed messages,
// and never repeats the word it found.

const guardWord = "zebracorp" // a made-up name standing in for a real one

type guardFixture struct {
	t    *testing.T
	root string
	base string
}

func (f *guardFixture) git(args ...string) string {
	f.t.Helper()
	full := append([]string{"-C", f.root, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
		"-c", "commit.gpgsign=false"}, args...)
	out, err := exec.Command("git", full...).Output()
	if err != nil {
		f.t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

func (f *guardFixture) commit(message string) {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "-q", "-m", message)
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	root := t.TempDir()
	f := &guardFixture{t: t, root: root}
	f.git("init", "-q")
	if err := os.WriteFile(filepath.Join(root, "clean.txt"), []byte("nothing to see\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.commit("first")
	f.base = strings.TrimSpace(f.git("rev-parse", "HEAD"))
	return f
}

func (f *guardFixture) runGuard(words, base, head string) (int, string) {
	f.t.Helper()
	var printed bytes.Buffer
	code := nameguard.Run(words, f.root, base, head, &printed)
	return code, printed.String()
}

func TestAGuardedCleanTreePasses(t *testing.T) {
	f := newGuardFixture(t)
	if code, _ := f.runGuard(guardWord, "", ""); code != 0 {
		t.Fatalf("rc %d, want 0", code)
	}
}

func TestANameInAFileIsReportedByPlaceNotByWord(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "notes.md"),
		[]byte("line one\nthanks to ZebraCorp ops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.commit("add notes")
	code, printed := f.runGuard("\n  "+strings.ToUpper(guardWord)+"  \nother\n", "", "")
	if code != 1 {
		t.Fatalf("rc %d, want 1", code)
	}
	mustContain(t, printed, "notes.md:2", "guard output")
	if strings.Contains(strings.ToLower(printed), guardWord) {
		t.Fatal("the output repeats the guarded word")
	}
}

func TestAnUntrackedFileIsNotTheRepository(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "inventory.ini"),
		[]byte(guardWord+".example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.runGuard(guardWord, "", ""); code != 0 {
		t.Fatalf("rc %d, want 0", code)
	}
}

func TestANameInAPushedMessageIsReportedByCommit(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "clean.txt"), []byte("still nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.commit("Fix the gateway for " + guardWord)
	head := strings.TrimSpace(f.git("rev-parse", "HEAD"))
	code, printed := f.runGuard(guardWord, f.base, head)
	if code != 1 {
		t.Fatalf("rc %d, want 1", code)
	}
	mustContain(t, printed, "commit "+head[:12], "guard output")
	if strings.Contains(strings.ToLower(printed), guardWord) {
		t.Fatal("the output repeats the guarded word")
	}
	// A new branch has no "before": only the tree is checked.
	if code, _ := f.runGuard(guardWord, strings.Repeat("0", 40), head); code != 0 {
		t.Fatalf("a new branch rc %d, want 0", code)
	}
}

func TestAForcedPushReadsEveryMessageOfTheNewHistory(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "clean.txt"), []byte("still nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.commit("Fix the gateway for " + guardWord)
	head := strings.TrimSpace(f.git("rev-parse", "HEAD"))
	gone := strings.Repeat("1", 40) // the "before" of a rewritten branch, absent here
	code, printed := f.runGuard(guardWord, gone, head)
	if code != 1 {
		t.Fatalf("rc %d, want 1", code)
	}
	mustContain(t, printed, "commit "+head[:12], "guard output")
	if code, _ := f.runGuard(guardWord, gone, f.base); code != 0 {
		t.Fatalf("the old history rc %d, want 0", code)
	}
}

func TestWithoutTheSecretItSaysSoAndPasses(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "notes.md"), []byte(guardWord+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.commit("add notes")
	code, printed := f.runGuard("", "", "")
	if code != 0 {
		t.Fatalf("rc %d, want 0", code)
	}
	mustContain(t, printed, "NAME_GUARD_WORDS is not set", "guard output")
}
