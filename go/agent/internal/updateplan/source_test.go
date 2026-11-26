package updateplan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// How the checker gets the candidate source. A gateway with a slow route to
// GitHub could not clone the next revision within the minute it was given;
// the candidate is now fetched on top of the installed checkout, which
// already holds almost all of it.

type fetchFixture struct {
	root, remote, url, installed, newRevision, destination string
}

func newFetchFixture(t *testing.T) *fetchFixture {
	requireGit(t)
	f := &fetchFixture{root: t.TempDir()}
	f.remote = filepath.Join(f.root, "remote")
	if err := os.MkdirAll(f.remote, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, f.remote, "init", "--quiet")
	gitRun(t, f.remote, "symbolic-ref", "HEAD", "refs/heads/main")
	// History before the installed revision, which a depth-1 checkout does
	// not have: Git must be told where the installed history stops.
	commitFiles(t, f.remote, map[string]string{"README.md": "older\n"}, "older revision")
	// Enough unchanged files that borrowing them is visible.
	base := map[string]string{}
	for i := 0; i < 30; i++ {
		base[fmt.Sprintf("ansible/roles/role%d/tasks/main.yml", i)] = strings.Repeat(fmt.Sprintf("- name: task %d\n", i), 40)
	}
	base["ansible/roles/authelia/defaults/main.yml"] = "authelia_redis_image: \"redis:7.4.12-alpine\"\n"
	commitFiles(t, f.remote, base, "installed revision")
	f.url = fileURL(f.remote)
	// What the update leaves on a gateway: a depth-1 checkout.
	f.installed = filepath.Join(f.root, "installed")
	gitRun(t, f.root, "clone", "--quiet", "--depth=1", "--branch", "main", f.url, f.installed)
	f.newRevision = commitFiles(t, f.remote, map[string]string{
		"ansible/roles/authelia/defaults/main.yml": "authelia_redis_image: \"redis:8.10.3-alpine\"\n",
		"installer/new_file.py":                    "print('new')\n",
	}, "next revision")
	f.destination = filepath.Join(f.root, "scratch", "source")
	if err := os.MkdirAll(filepath.Dir(f.destination), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fetchFixture) fetch() (string, string) {
	return remoteCandidate(f.installed, f.url, "main", f.newRevision, f.destination, SubprocessRunner{})
}

func treeContents(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			files[filepath.ToSlash(rel)] = readFile(t, path)
		}
		return nil
	})
	return files
}

func TestTheCandidateIsTheNewRevisionFileForFile(t *testing.T) {
	f := newFetchFixture(t)
	candidate, problem := f.fetch()
	if problem != "" || candidate != f.destination {
		t.Fatalf("candidate %q problem %q", candidate, problem)
	}
	expected := filepath.Join(f.root, "expected")
	gitRun(t, f.root, "clone", "--quiet", "--depth=1", "--branch", "main", f.url, expected)
	if !reflect.DeepEqual(treeContents(t, candidate), treeContents(t, expected)) {
		t.Fatal("the candidate differs from the new revision")
	}
	if !strings.Contains(readFile(t, filepath.Join(candidate, "ansible/roles/authelia/defaults/main.yml")), "redis:8.10.3-alpine") {
		t.Fatal("not the new pin")
	}
}

func TestOnlyWhatChangedIsTransferred(t *testing.T) {
	f := newFetchFixture(t)
	candidate, problem := f.fetch()
	if problem != "" {
		t.Fatal(problem)
	}
	alternates := strings.TrimSpace(readFile(t, filepath.Join(candidate, ".git/objects/info/alternates")))
	want, _ := filepath.EvalSymlinks(filepath.Join(f.installed, ".git/objects"))
	if alternates != want {
		t.Fatalf("alternates %q want %q", alternates, want)
	}
	stored := map[string]int{}
	for _, line := range strings.Split(gitRun(t, candidate, "count-objects", "-v"), "\n") {
		if k, v, found := strings.Cut(line, ": "); found && (k == "count" || k == "in-pack") {
			stored[k], _ = strconv.Atoi(v)
		}
	}
	total := len(strings.Split(gitRun(t, candidate, "rev-list", "--objects", "HEAD"), "\n"))
	// The new commit, its changed trees and two files -- not the 31 others.
	if held := stored["count"] + stored["in-pack"]; held >= 12 || total <= 30 {
		t.Fatalf("held %v of %d", stored, total)
	}
}

func TestTheInstalledCheckoutIsOnlyRead(t *testing.T) {
	f := newFetchFixture(t)
	snapshot := func() []string {
		gitDir := filepath.Join(f.installed, ".git")
		paths := []string{gitRun(t, f.installed, "rev-parse", "HEAD"), gitRun(t, f.installed, "for-each-ref"),
			readFile(t, filepath.Join(gitDir, "shallow"))}
		_ = filepath.WalkDir(gitDir, func(path string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(gitDir, path)
			paths = append(paths, filepath.ToSlash(rel))
			return nil
		})
		sort.Strings(paths[3:])
		return paths
	}
	before := snapshot()
	if _, problem := f.fetch(); problem != "" {
		t.Fatal(problem)
	}
	if !reflect.DeepEqual(snapshot(), before) || gitRun(t, f.installed, "status", "--porcelain") != "" {
		t.Fatal("the installed checkout changed")
	}
}

func TestAMovedBranchIsStillRefused(t *testing.T) {
	f := newFetchFixture(t)
	commitFiles(t, f.remote, map[string]string{"README.md": "moved\n"}, "pushed during the check")
	candidate, problem := f.fetch()
	if candidate != "" || problem != "candidate-revision-changed-during-check" {
		t.Fatalf("candidate %q problem %q", candidate, problem)
	}
}

// When the fetch does not work: the order of attempts, with the network scripted.

func scriptedFetch(t *testing.T, tarball bool, handler func(argv []string) CommandResult) (string, string, [][]string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, ".git/objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if tarball {
		_ = os.RemoveAll(filepath.Join(source, ".git"))
	}
	runner := newFakeRunner(func(argv []string) CommandResult {
		if hasSuffix(argv, "remote", "get-url", "origin") {
			return ok("https://example.test/r.git\n")
		}
		return handler(argv)
	})
	candidate, problem := remoteCandidate(source, "https://example.test/r.git", "main", remoteRevision,
		filepath.Join(root, "candidate"), runner)
	return candidate, problem, runner.commands()
}

func mkdir(path string) CommandResult {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return failed(1, err.Error())
	}
	return ok("")
}

func TestATimedOutFetchIsNotFollowedByALargerClone(t *testing.T) {
	candidate, problem, commands := scriptedFetch(t, false, func(argv []string) CommandResult {
		switch {
		case hasPrefix(argv, "git", "init"):
			return mkdir(last(argv))
		case has(argv, "fetch"):
			return CommandResult{Returncode: 124, Error: "timeout"}
		}
		return unexpected(argv)
	})
	if candidate != "" || !strings.HasPrefix(problem, "candidate-fetch-timed-out") {
		t.Fatalf("candidate %q problem %q", candidate, problem)
	}
	for _, argv := range commands {
		if hasPrefix(argv, "git", "clone") {
			t.Fatalf("cloned: %q", argv)
		}
	}
}

func TestAnyOtherFailureFallsBackToACleanFullClone(t *testing.T) {
	existed := true
	candidate, problem, commands := scriptedFetch(t, false, func(argv []string) CommandResult {
		switch {
		case hasPrefix(argv, "git", "init"):
			return mkdir(last(argv))
		case has(argv, "fetch"):
			return failed(128, "fatal: shallow file has changed")
		case hasPrefix(argv, "git", "clone"):
			// The half-made scratch repository is gone before the clone.
			existed = exists(last(argv))
			return mkdir(last(argv))
		case hasSuffix(argv, "rev-parse", "HEAD"):
			return ok(remoteRevision + "\n")
		}
		return unexpected(argv)
	})
	if problem != "" || candidate == "" || existed {
		t.Fatalf("candidate %q problem %q existed %v", candidate, problem, existed)
	}
	for _, argv := range commands {
		if hasPrefix(argv, "git", "clone") && !has(argv, "--depth=1") {
			t.Fatalf("clone %q", argv)
		}
	}
}

func TestATarballInstallGoesStraightToTheClone(t *testing.T) {
	_, problem, commands := scriptedFetch(t, true, func(argv []string) CommandResult {
		switch {
		case hasPrefix(argv, "git", "clone"):
			return mkdir(last(argv))
		case hasSuffix(argv, "rev-parse", "HEAD"):
			return ok(remoteRevision + "\n")
		}
		return unexpected(argv)
	})
	if problem != "" {
		t.Fatal(problem)
	}
	for _, argv := range commands {
		if hasPrefix(argv, "git", "init") {
			t.Fatalf("init: %q", argv)
		}
	}
}

func TestATimedOutCloneSaysSo(t *testing.T) {
	candidate, problem, _ := scriptedFetch(t, true, func(argv []string) CommandResult {
		if hasPrefix(argv, "git", "clone") {
			return CommandResult{Returncode: 124, Error: "timeout"}
		}
		return unexpected(argv)
	})
	if candidate != "" || !strings.HasPrefix(problem, "candidate-clone-timed-out") {
		t.Fatalf("candidate %q problem %q", candidate, problem)
	}
}

func TestTheCandidateHasLongerThanTheChangelog(t *testing.T) {
	if candidateTimeout <= cloneTimeout || candidateTimeout >= 10*60*1e9 {
		t.Fatalf("candidate %v changelog %v", candidateTimeout, cloneTimeout)
	}
}

// Files changed by hand on a gateway block its update only when they matter:
// files the next revision already holds byte for byte lose nothing.

const (
	guardFix = "def restore():\n    return 'all services'\n"
	redirect = "acl host_admin hdr(host) -i admin.example.test\n"
)

type localFixture struct {
	t                                            *testing.T
	root, remote, url, installed                 string
	installedRevision, nextRevision, destination string
}

func newLocalFixture(t *testing.T) *localFixture {
	requireGit(t)
	f := &localFixture{t: t, root: t.TempDir()}
	f.remote = filepath.Join(f.root, "remote")
	if err := os.MkdirAll(f.remote, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, f.remote, "init", "--quiet")
	gitRun(t, f.remote, "symbolic-ref", "HEAD", "refs/heads/main")
	commitFiles(t, f.remote, map[string]string{"installer/guard.py": "def restore():\n    return 'some'\n",
		"ansible/haproxy.cfg.j2": "frontend fe_http80\n", "README.md": "readme\n"}, "installed")
	f.url = fileURL(f.remote)
	f.installed = filepath.Join(f.root, "installed")
	gitRun(t, f.root, "clone", "--quiet", "--depth=1", "--branch", "main", f.url, f.installed)
	f.installedRevision = gitRun(t, f.installed, "rev-parse", "HEAD")
	f.nextRevision = commitFiles(t, f.remote, map[string]string{"installer/guard.py": guardFix, "ansible/haproxy.cfg.j2": redirect},
		"two fixes")
	return f
}

func (f *localFixture) edit(files map[string]string) {
	for name, text := range files {
		writeFile(f.t, filepath.Join(f.installed, name), text)
	}
}

func (f *localFixture) probe() M {
	return probeSource(f.installed, "github", "main", f.url, SubprocessRunner{})
}

func (f *localFixture) candidate() string {
	destination := filepath.Join(f.root, "scratch", "source")
	_ = os.MkdirAll(filepath.Dir(destination), 0o755)
	found, problem := remoteCandidate(f.installed, f.url, "main", f.nextRevision, destination, SubprocessRunner{})
	if problem != "" {
		f.t.Fatal(problem)
	}
	return found
}

func entries(c M) []localChange {
	list, _ := c["_local_changes"].([]localChange)
	return list
}

func TestABlockedSourceNamesItsFilesAndStillLearnsTheNextRevision(t *testing.T) {
	f := newLocalFixture(t)
	f.edit(map[string]string{"installer/guard.py": guardFix, "ansible/haproxy.cfg.j2": redirect})
	c := f.probe()
	if c["state"] != "blocked" || !reflect.DeepEqual(details(c)["changed_files"], []any{"ansible/haproxy.cfg.j2", "installer/guard.py"}) ||
		c["current_version"] != f.installedRevision || c["available_version"] != f.nextRevision {
		t.Fatalf("component: %v", c)
	}
	paths := []string{}
	for _, e := range entries(c) {
		paths = append(paths, e.path)
	}
	sort.Strings(paths)
	if !reflect.DeepEqual(paths, []string{"ansible/haproxy.cfg.j2", "installer/guard.py"}) {
		t.Fatalf("entries %v", paths)
	}
}

func TestChangesTheNextRevisionHoldsAreUpstream(t *testing.T) {
	f := newLocalFixture(t)
	f.edit(map[string]string{"installer/guard.py": guardFix, "ansible/haproxy.cfg.j2": redirect})
	if !localChangesUpstream(f.installed, f.candidate(), entries(f.probe())) {
		t.Fatal("not upstream")
	}
}

func TestChangesTheNextRevisionLacksKeepTheBlock(t *testing.T) {
	for name, setup := range map[string]func(f *localFixture){
		"one file differs": func(f *localFixture) {
			f.edit(map[string]string{"installer/guard.py": guardFix, "ansible/haproxy.cfg.j2": redirect + "# mine\n"})
		},
		"a new file": func(f *localFixture) {
			f.edit(map[string]string{"installer/guard.py": guardFix, "ansible/haproxy.cfg.j2": redirect, "notes/todo.txt": "x\n"})
		},
		"a deleted file the next revision keeps": func(f *localFixture) {
			_ = os.Remove(filepath.Join(f.installed, "README.md"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLocalFixture(t)
			setup(f)
			list := entries(f.probe())
			if name == "a new file" && !containsChange(list, localChange{"??", "notes/todo.txt"}) {
				t.Fatalf("entries %v", list)
			}
			if localChangesUpstream(f.installed, f.candidate(), list) {
				t.Fatal("taken as upstream")
			}
		})
	}
}

func containsChange(list []localChange, want localChange) bool {
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}

func TestChangesOnTopOfTheNewestRevisionStayBlockedWithoutAFetch(t *testing.T) {
	f := newLocalFixture(t)
	// What the update itself does: fetch the branch and reset to it.
	gitRun(t, f.installed, "fetch", "--quiet", "--depth=1", "origin", "main")
	gitRun(t, f.installed, "reset", "--quiet", "--hard", "FETCH_HEAD")
	f.edit(map[string]string{"installer/guard.py": "mine\n"})
	c := f.probe()
	if _, found := c["_local_changes"]; c["state"] != "blocked" || found || c["available_version"] != nil {
		t.Fatalf("component: %v", c)
	}
}

func TestStagedOrRenamedChangesAreNeverTakenAsUpstream(t *testing.T) {
	for name, setup := range map[string]func(f *localFixture){
		"a rename": func(f *localFixture) { gitRun(t, f.installed, "mv", "README.md", "README.txt") },
		"staged content under an upstream worktree": func(f *localFixture) {
			f.edit(map[string]string{"installer/guard.py": "private staged change\n"})
			gitRun(t, f.installed, "add", "installer/guard.py")
			f.edit(map[string]string{"installer/guard.py": guardFix})
		},
		"a staged deletion with a recreated file": func(f *localFixture) {
			gitRun(t, f.installed, "rm", "--quiet", "installer/guard.py")
			f.edit(map[string]string{"installer/guard.py": guardFix})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLocalFixture(t)
			setup(f)
			c := f.probe()
			if _, found := c["_local_changes"]; c["state"] != "blocked" || found {
				t.Fatalf("component: %v", c)
			}
			if name == "staged content under an upstream worktree" &&
				gitRun(t, f.installed, "show", ":installer/guard.py") != "private staged change" {
				t.Fatal("the staged content was discarded")
			}
		})
	}
}

func TestStatusEntriesAreReadFromNulSeparatedOutput(t *testing.T) {
	got := statusEntries(" M a.py\x00?? new dir/b.txt\x00 D c.py\x00")
	want := []localChange{{" M", "a.py"}, {"??", "new dir/b.txt"}, {" D", "c.py"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries %v", got)
	}
}

func TestRenamesCopiesOddPathsAndStagedChangesAreRefused(t *testing.T) {
	for _, stdout := range []string{"R  new.py\x00old.py\x00", "C  new.py\x00old.py\x00", " M ../outside\x00", " M /etc/passwd\x00", "bad\x00"} {
		if statusEntries(stdout) != nil {
			t.Fatalf("%q accepted", stdout)
		}
	}
	for _, status := range []string{"MM", "M ", "AM", "D ", "UU", "AA", "UD"} {
		if statusEntries(status+" a.py\x00") != nil {
			t.Fatalf("%q accepted", status)
		}
	}
}
