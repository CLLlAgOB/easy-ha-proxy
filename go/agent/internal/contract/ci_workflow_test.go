package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// The CI workflow: linters, and the panel and native images published from
// the commit CI has just tested. The fingerprint step cannot run outside
// GitHub, so its script is taken out of the workflow and run here: the
// fingerprint must be the one gateways compute, or they would never pair
// the panel image with its source.

func ciJobs(t *testing.T) *pyyaml.Map {
	t.Helper()
	v, err := pyyaml.Load([]byte(read(t, ".github/workflows/ci.yml")))
	if err != nil {
		t.Fatal(err)
	}
	jobs, ok := v.(*pyyaml.Map).Value("jobs").(*pyyaml.Map)
	if !ok {
		t.Fatal("ci.yml has no jobs")
	}
	return jobs
}

func ciJob(t *testing.T, jobs *pyyaml.Map, name string) *pyyaml.Map {
	t.Helper()
	job, ok := jobs.Value(name).(*pyyaml.Map)
	if !ok {
		t.Fatalf("no job %s", name)
	}
	return job
}

func ciStep(t *testing.T, job *pyyaml.Map, name string) *pyyaml.Map {
	t.Helper()
	steps, _ := job.Value("steps").([]any)
	for _, s := range steps {
		step, ok := s.(*pyyaml.Map)
		if ok && step.Value("name") == name {
			return step
		}
	}
	t.Fatalf("no step %q", name)
	return nil
}

func runOf(step *pyyaml.Map) string {
	run, _ := step.Value("run").(string)
	return run
}

func jobRuns(job *pyyaml.Map) string {
	var runs []string
	steps, _ := job.Value("steps").([]any)
	for _, s := range steps {
		if step, ok := s.(*pyyaml.Map); ok {
			runs = append(runs, runOf(step))
		}
	}
	return strings.Join(runs, "\n")
}

func needsOf(job *pyyaml.Map) map[string]bool {
	out := map[string]bool{}
	needs, _ := job.Value("needs").([]any)
	for _, n := range needs {
		out[n.(string)] = true
	}
	return out
}

// goWebTreeInputs reads the panel's build inputs as a Go file lists them.
func goWebTreeInputs(t *testing.T, rel string) []string {
	t.Helper()
	source := read(t, rel)
	parts := strings.SplitN(source, "goWebTreeInputs = []string{", 2)
	if len(parts) != 2 {
		t.Fatalf("%s: no goWebTreeInputs", rel)
	}
	listed := strings.SplitN(parts[1], "}", 2)[0]
	var out []string
	for _, item := range strings.Split(listed, ",") {
		out = append(out, strings.Trim(strings.TrimSpace(item), `"`))
	}
	return out
}

func TestRuffAndShellcheckRun(t *testing.T) {
	jobs := ciJobs(t)
	mustContain(t, runOf(ciStep(t, ciJob(t, jobs, "lint"), "Ruff")), "ruff check", "lint/Ruff")
	mustContain(t, runOf(ciStep(t, ciJob(t, jobs, "shell"), "ShellCheck")), "shellcheck -S warning", "shell/ShellCheck")
	mustContain(t, read(t, "ruff.toml"), `select = ["F", "E9", "B"]`, "ruff.toml")
}

func TestEveryScriptIsParsedAndTheJsTestsRun(t *testing.T) {
	jobs := ciJobs(t)
	js := ciJob(t, jobs, "javascript")
	mustContain(t, runOf(ciStep(t, js, "Parse every script")), "node --check", "javascript/Parse")
	mustContain(t, runOf(ciStep(t, js, "Behaviour tests")), "node --test .tests/js/", "javascript/Behaviour")
	matches, _ := filepath.Glob(filepath.Join(repoRoot(t), ".tests", "js", "*.test.js"))
	if len(matches) == 0 {
		t.Fatal("no behaviour tests in .tests/js")
	}
}

func TestEslintRunsPinnedOverThePanelAndItsTests(t *testing.T) {
	run := runOf(ciStep(t, ciJob(t, ciJobs(t), "javascript"), "ESLint"))
	for _, pin := range []string{"eslint@9.39.1", "@eslint/js@9.39.1", "globals@16.4.0"} {
		mustContain(t, run, pin, "javascript/ESLint")
	}
	mustContain(t, run, "--no-save", "javascript/ESLint")
	mustContain(t, run, "eslint go/panel/web/static/js .tests/js", "javascript/ESLint")
	if fi, err := os.Stat(filepath.Join(repoRoot(t), "eslint.config.mjs")); err != nil || fi.IsDir() {
		t.Fatal("eslint.config.mjs is missing")
	}
}

func TestTheWholeHistoryIsSearchedForSecrets(t *testing.T) {
	jobs := ciJobs(t)
	secrets := ciJob(t, jobs, "secrets")
	steps, _ := secrets.Value("steps").([]any)
	checkout := steps[0].(*pyyaml.Map)
	if depth := checkout.Value("with").(*pyyaml.Map).Value("fetch-depth"); depth != int64(0) {
		t.Fatalf("checkout fetch-depth %v, want 0", depth)
	}
	run := runOf(ciStep(t, secrets, "gitleaks"))
	for _, want := range []string{
		"ghcr.io/gitleaks/gitleaks:v8.28.0",
		"gitleaks git /repo",
		"--gitleaks-ignore-path /repo/.gitleaksignore",
		"--redact",
	} {
		mustContain(t, run, want, "secrets/gitleaks")
	}
	var acknowledged []string
	for _, line := range strings.Split(read(t, ".gitleaksignore"), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			acknowledged = append(acknowledged, line)
		}
	}
	// Six fixture lines and one exact public checksum; additions require
	// review. Each is file:rule:line with no commit, so it holds in every
	// commit -- which is why a fixture that moved keeps its old line too.
	publicChecksum := "ansible/roles/haproxy/defaults/main.yml:generic-api-key:12"
	if len(acknowledged) != 7 {
		t.Fatalf("%d acknowledged lines, want 7", len(acknowledged))
	}
	found := false
	fixtures := 0
	for _, line := range acknowledged {
		if len(strings.Split(line, ":")) != 3 {
			t.Errorf("acknowledged line %q is not file:rule:line", line)
		}
		if line == publicChecksum {
			found = true
		} else {
			fixtures++
			if !strings.HasPrefix(line, ".tests/") {
				t.Errorf("fixture %q is not under .tests/", line)
			}
		}
	}
	if !found {
		t.Errorf("the public checksum %q is not acknowledged", publicChecksum)
	}
	if fixtures != 6 {
		t.Fatalf("%d fixtures, want 6", fixtures)
	}
}

func TestTheNamesComeFromASecret(t *testing.T) {
	guard := ciStep(t, ciJob(t, ciJobs(t), "secrets"), "Names of installations")
	if got := guard.Value("env").(*pyyaml.Map).Value("NAME_GUARD_WORDS"); got != "${{ secrets.NAME_GUARD_WORDS }}" {
		t.Fatalf("NAME_GUARD_WORDS %v", got)
	}
	if got := guard.Value("env").(*pyyaml.Map).Value("NAME_GUARD_ROOT"); got != "${{ github.workspace }}" {
		t.Fatalf("NAME_GUARD_ROOT %v", got)
	}
	if got := guard.Value("working-directory"); got != "go/agent" {
		t.Fatalf("the name guard runs in %v", got)
	}
	if got := runOf(guard); got != "go run ./cmd/name-guard" {
		t.Fatalf("the name guard runs %q", got)
	}
}

func TestPythonCoversOnlyTheCompatibilityShims(t *testing.T) {
	// The contract suite is Go now; Python stays only for the shims the
	// update broker of releases before 1.2.0 loads mid-update.
	python := ciJob(t, ciJobs(t), "python")
	if python.Value("strategy") != nil {
		t.Fatal("the python job still has a version matrix")
	}
	steps := jobRuns(python)
	mustContain(t, steps, "test_unified_maintenance test_haproxy_package_migration", "python job")
	if strings.Contains(steps, "unittest discover") {
		t.Fatal("the python job still discovers the whole suite")
	}
	if strings.Contains(steps, "pip install") {
		t.Fatal("the python job still installs dependencies")
	}
}

func TestTheServerStateSmokeRunsTheAgentBuiltHere(t *testing.T) {
	jobs := ciJobs(t)
	serverState := ciJob(t, jobs, "server-state")
	mustContain(t, runOf(ciStep(t, serverState, "Build the agent and the server-state smoke")), "go build", "server-state/Build")
	mustContain(t, jobRuns(serverState), "--normalizer /usr/local/sbin/easy-ha-proxy-agent", "server-state job")
}

func TestAPullRequestBuildsThePanelImageWithoutPublishingIt(t *testing.T) {
	build := runOf(ciStep(t, ciJob(t, ciJobs(t), "go-panel"), "Build Go panel container image (smoke + live healthcheck + size)"))
	mustContain(t, build, "docker build -f go/panel/Dockerfile", "go-panel build")
	if strings.Contains(build, "push") {
		t.Fatal("the go-panel check pushes")
	}
}

func TestOnlyATestedPushToAReleaseBranchPublishes(t *testing.T) {
	jobs := ciJobs(t)
	everyCheck := map[string]bool{"python": true, "shell": true, "lint": true, "javascript": true,
		"udp-forwarding": true, "server-state": true, "secrets": true}
	for _, name := range []string{"go-panel-image", "native-release-image"} {
		job := ciJob(t, jobs, name)
		needs := needsOf(job)
		for check := range everyCheck {
			if check != "javascript" && !needs[check] {
				t.Errorf("%s does not need %s", name, check)
			}
		}
		if cond, _ := job.Value("if").(string); !strings.Contains(cond, "github.event_name == 'push'") ||
			!strings.Contains(cond, "refs/heads/alpha") || !strings.Contains(cond, "refs/heads/main") {
			t.Errorf("%s publishes outside a tested push: %q", name, cond)
		}
	}
	if !needsOf(ciJob(t, jobs, "go-panel-image"))["javascript"] {
		t.Fatal("go-panel-image does not need javascript")
	}
}

func TestTheAgentReleaseHoldsWhatInstallersFetch(t *testing.T) {
	jobs := ciJobs(t)
	release := ciJob(t, jobs, "agent-release-assets")
	image := ciJob(t, jobs, "native-release-image")
	// Published only from what the image is published from.
	a, b := needsOf(release), needsOf(image)
	if len(a) != len(b) {
		t.Fatalf("needs differ: %v vs %v", a, b)
	}
	for n := range a {
		if !b[n] {
			t.Fatalf("needs differ at %s", n)
		}
	}
	if release.Value("if") != image.Value("if") {
		t.Fatal("the release and the image publish under different conditions")
	}
	perms := release.Value("permissions").(*pyyaml.Map)
	if perms.Len() != 1 || perms.Value("contents") != "write" {
		t.Fatalf("permissions %v", perms)
	}
	if got := release.Value("env").(*pyyaml.Map).Value("RELEASE_TAG"); got != "agent-builds" {
		t.Fatalf("RELEASE_TAG %v", got)
	}
	upload := runOf(ciStep(t, release, "Upload this commit's agent"))
	// The names installer/agent-fetch.sh asks for.
	mustContain(t, upload, `name="easy-ha-proxy-agent-${GITHUB_SHA}-linux-${arch}"`, "upload")
	mustContain(t, upload, `sha256sum "${name}" > "${name}.sha256"`, "upload")
	fetch := read(t, "installer/agent-fetch.sh")
	mustContain(t, fetch, "releases/download/agent-builds", "agent-fetch.sh")
	mustContain(t, fetch, `name="easy-ha-proxy-agent-${revision}-linux-${arch}"`, "agent-fetch.sh")
	prune := ciStep(t, release, "Keep the newest builds")
	if prune.Value("continue-on-error") != true {
		t.Fatal("the prune step is not continue-on-error")
	}
	mustContain(t, runOf(prune), "grep -vxF -f tagged", "prune")
}

func TestTheFingerprintIsTheOneGatewaysCompute(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := t.TempDir()
	for _, dir := range []string{"go/panel/web/templates", "installer"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"VERSION":                          "1.2.0\n",
		"go/panel/main.go":                 "package main\n",
		"go/panel/web/templates/base.html": "<html></html>\n",
		"installer/other.py":               "VALUE = 1\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return string(out)
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "x")
	output := filepath.Join(root, "output")
	script := runOf(ciStep(t, ciJob(t, ciJobs(t), "go-panel-image"), "Fingerprint the Go web panel"))
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = root
	cmd.Env = append(env, "GITHUB_OUTPUT="+output, "GITHUB_REF_NAME=alpha")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the fingerprint step: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = v
		}
	}
	// What the update checker on a gateway computes (updateplan.webTree).
	inputs := goWebTreeInputs(t, "go/agent/internal/updateplan/source.go")
	listing := git(append([]string{"ls-tree", "-r", "--full-tree", "HEAD", "--"}, inputs...)...)
	sum := sha256.Sum256([]byte(listing))
	expected := hex.EncodeToString(sum[:])
	if values["tree"] != expected {
		t.Fatalf("tree %s, want %s", values["tree"], expected)
	}
	if values["key"] != "go-alpha-"+expected {
		t.Fatalf("key %s", values["key"])
	}
	if values["channel"] != "go-alpha" {
		t.Fatalf("channel %s", values["channel"])
	}
}

func TestTheBrokerFingerprintsTheSameInputs(t *testing.T) {
	// The footer (the broker) and the update checker read the same paths.
	broker := goWebTreeInputs(t, "go/agent/internal/updated/config.go")
	checker := goWebTreeInputs(t, "go/agent/internal/updateplan/source.go")
	if strings.Join(broker, ",") != strings.Join(checker, ",") {
		t.Fatalf("broker %v vs checker %v", broker, checker)
	}
	if strings.Join(checker, ",") != "VERSION,go/panel" {
		t.Fatalf("checker inputs %v", checker)
	}
}

// Every job names the runner image it was written for: ubuntu-latest moves
// on GitHub's schedule, not this project's, and the gateways run Ubuntu
// 24.04. A move is a decision made in the workflow file.

func workflowFiles(t *testing.T) []string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	sort.Strings(matches)
	return matches
}

func workflowJobs(t *testing.T, path string) *pyyaml.Map {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyyaml.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := v.(*pyyaml.Map)
	jobs, _ := root.Value("jobs").(*pyyaml.Map)
	if jobs == nil {
		jobs = pyyaml.NewMap()
	}
	return jobs
}

func TestNoJobFollowsUbuntuLatest(t *testing.T) {
	for _, path := range workflowFiles(t) {
		jobs := workflowJobs(t, path)
		jobs.Each(func(name, job any) {
			runner, _ := job.(*pyyaml.Map).Value("runs-on").(string)
			if strings.Contains(runner, "latest") {
				t.Errorf("%s: job %v runs on %q", filepath.Base(path), name, runner)
			}
		})
	}
}

func TestAllActionsArePinnedToFullCommitShas(t *testing.T) {
	shaPin := regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
	for _, path := range workflowFiles(t) {
		jobs := workflowJobs(t, path)
		jobs.Each(func(jobName, job any) {
			steps, _ := job.(*pyyaml.Map).Value("steps").([]any)
			for _, s := range steps {
				step, ok := s.(*pyyaml.Map)
				if !ok {
					continue
				}
				uses, _ := step.Value("uses").(string)
				if uses == "" || strings.HasPrefix(uses, "./") {
					continue
				}
				if !shaPin.MatchString(uses) {
					t.Errorf("%s: job %v uses %q, not a full commit sha", filepath.Base(path), jobName, uses)
				}
			}
		})
	}
}
