package updateplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	localRevision  = "1111111111111111111111111111111111111111"
	remoteRevision = "2222222222222222222222222222222222222222"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

type runCall struct {
	argv    []string
	timeout time.Duration
}

// fakeRunner answers commands from a handler and records them. A handler
// panics on a command it does not expect, as the checker's own error
// handling would see an exception.
type fakeRunner struct {
	mu      sync.Mutex
	handler func(argv []string) CommandResult
	calls   []runCall
}

func newFakeRunner(handler func(argv []string) CommandResult) *fakeRunner {
	return &fakeRunner{handler: handler}
}

func (f *fakeRunner) Run(argv []string, timeout time.Duration) CommandResult {
	f.mu.Lock()
	f.calls = append(f.calls, runCall{append([]string(nil), argv...), timeout})
	f.mu.Unlock()
	return f.handler(argv)
}

func (f *fakeRunner) commands() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.argv
	}
	return out
}

// runnerFunc is a Runner from a function.
type runnerFunc func(argv []string) CommandResult

func (r runnerFunc) Run(argv []string, _ time.Duration) CommandResult { return r(argv) }

func unexpected(argv []string) CommandResult {
	panic(fmt.Sprintf("unexpected command: %q", argv))
}

func ok(stdout string) CommandResult { return CommandResult{Returncode: 0, Stdout: stdout} }

func failed(code int, stderr string) CommandResult {
	return CommandResult{Returncode: code, Stderr: stderr}
}

func has(argv []string, value string) bool {
	for _, item := range argv {
		if item == value {
			return true
		}
	}
	return false
}

func hasPrefix(argv []string, prefix ...string) bool {
	return len(argv) >= len(prefix) && reflect.DeepEqual(argv[:len(prefix)], prefix)
}

func hasSuffix(argv []string, suffix ...string) bool {
	return len(argv) >= len(suffix) && reflect.DeepEqual(argv[len(argv)-len(suffix):], suffix)
}

func is(argv []string, want ...string) bool { return reflect.DeepEqual(argv, want) }

func last(argv []string) string { return argv[len(argv)-1] }

// What `git ls-tree` over the panel's inputs answers in these fakes, and the
// fingerprint a published panel image built from it is labelled with.
var (
	panelListing = "100644 blob " + strings.Repeat("c", 40) + "\tgo/panel/web/templates/base.html\n"
	panelTree    = func() string { s := sha256.Sum256([]byte(panelListing)); return hex.EncodeToString(s[:]) }()
)

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// panelImageAnswer is the panel fingerprint label, for the label reads of an image.
func panelImageAnswer(argv []string) (CommandResult, bool) {
	switch {
	case hasPrefix(argv, "docker", "image", "inspect") && has(argv, "{{json .Config.Labels}}"):
		return ok(mustJSON(M{goWebTreeLabelName: panelTree})), true
	case hasPrefix(argv, "docker", "buildx", "imagetools", "inspect") && has(argv, "{{json .Image}}"):
		return ok(mustJSON(M{"config": M{"Labels": M{goWebTreeLabelName: panelTree}}})), true
	case hasPrefix(argv, "git", "-C") && has(argv, "ls-tree"):
		return ok(panelListing), true
	}
	return CommandResult{}, false
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func prepareSource(t *testing.T, root string) string {
	t.Helper()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "ansible/easy-ha-proxy.yml"), "---\n- hosts: easy_ha_proxy\n")
	return source
}

// prepareInstalledDaemons installs the native host binaries as the native
// stage does, with the revision they were built from when one is given, and
// returns the artifact path mapper.
func prepareInstalledDaemons(t *testing.T, root, revision string, skip ...string) func(string) string {
	t.Helper()
	installed := filepath.Join(root, "installed")
	resolve := func(path string) string { return filepath.Join(installed, strings.TrimPrefix(path, "/")) }
	for _, a := range nativeDaemonArtifacts {
		if has(skip, a.id) {
			continue
		}
		writeFile(t, resolve(a.installed), "ELF native binary")
	}
	if revision != "" {
		writeFile(t, resolve(nativeStagingMetadata), mustJSON(M{"revision": revision})+"\n")
	}
	return resolve
}

func gitHandler(argv []string) CommandResult {
	switch {
	case has(argv, "ls-tree"):
		return ok(panelListing)
	case hasSuffix(argv, "rev-parse", "HEAD"):
		return ok(localRevision + "\n")
	case has(argv, "status"):
		return ok("")
	case hasSuffix(argv, "remote", "get-url", "origin"):
		return ok("https://example.test/easy-ha-proxy.git\n")
	case hasPrefix(argv, "git", "ls-remote", "--heads"):
		return ok(remoteRevision + "\trefs/heads/main\n")
	case hasPrefix(argv, "git", "clone"):
		return failed(1, "candidate unavailable")
	case is(argv, "apt-get", "-s", "upgrade"):
		return ok("")
	}
	return unexpected(argv)
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		target := filepath.Join(destination, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// buildPlanForTest checks with the host's environment and APT sources kept out.
func buildPlanForTest(t *testing.T, o Options) M {
	t.Helper()
	if o.Getenv == nil {
		o.Getenv = func(string) string { return "" }
	}
	if o.AptRoot == "" {
		o.AptRoot = t.TempDir()
	}
	plan, err := BuildUpdatePlan(o)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func byID(plan M) map[string]M {
	out := map[string]M{}
	for _, item := range plan["components"].([]any) {
		c := item.(M)
		out[c["id"].(string)] = c
	}
	return out
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
}

// gitRun runs real Git with a fixed identity and no system configuration.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	argv := append([]string{"-c", "user.name=Test", "-c", "user.email=test@example.test"}, args...)
	cmd := exec.Command("git", argv...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitFiles(t *testing.T, repository string, files map[string]string, message string) string {
	t.Helper()
	for name, text := range files {
		writeFile(t, filepath.Join(repository, name), text)
	}
	gitRun(t, repository, "add", "--all")
	gitRun(t, repository, "commit", "--quiet", "-m", message)
	return gitRun(t, repository, "rev-parse", "HEAD")
}

func fileURL(path string) string {
	abs, _ := filepath.Abs(path)
	return "file://" + filepath.ToSlash(abs)
}

func russianMessages(t *testing.T) map[string]string {
	t.Helper()
	catalogs := filepath.Join(repoRoot(), "go/panel/web/translations")
	paths := []string{filepath.Join(catalogs, "ru.json")}
	more, _ := filepath.Glob(filepath.Join(catalogs, "ru", "*.json"))
	paths = append(paths, more...)
	messages := map[string]string{}
	for _, path := range paths {
		var loaded struct {
			Messages map[string]string `json:"messages"`
		}
		if err := json.Unmarshal([]byte(readFile(t, path)), &loaded); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for k, v := range loaded.Messages {
			messages[k] = v
		}
	}
	return messages
}
