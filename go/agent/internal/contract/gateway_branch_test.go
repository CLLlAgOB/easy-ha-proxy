package contract

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The helper and the bootstrap follow the branch the gateway was set up on.
// An alpha gateway records branch: alpha in metadata.yml; the helper used to
// compare such a host with main, and install-local.sh fetched main into its
// source checkout.

var gatewayScripts = []string{"easy-ha-proxy-helper.sh", "install-local.sh"}

var gatewayBranchRe = regexp.MustCompile(`(?ms)^gateway_branch\(\) \{\n.*?^\}\n`)

func gatewayBranchFunction(t *testing.T, name string) string {
	t.Helper()
	m := gatewayBranchRe.FindString(read(t, name))
	if m == "" {
		t.Fatalf("%s has no gateway_branch function", name)
	}
	return m
}

// resolve runs the function with a metadata.yml and an optional override.
func resolveBranch(t *testing.T, config, name, metadata string, write bool, override string) string {
	t.Helper()
	if write {
		if err := os.WriteFile(filepath.Join(config, "metadata.yml"), []byte(metadata), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "EASY_HA_PROXY_BRANCH=") {
			env = append(env, kv)
		}
	}
	if override != "" {
		env = append(env, "EASY_HA_PROXY_BRANCH="+override)
	}
	env = append(env, "config_dir="+config)
	script := "set -Eeuo pipefail\n" + gatewayBranchFunction(t, name) + "gateway_branch\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

func TestBothScriptsResolveTheBranchTheSameWay(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	if gatewayBranchFunction(t, gatewayScripts[0]) != gatewayBranchFunction(t, gatewayScripts[1]) {
		t.Fatal("the gateway_branch functions differ")
	}
}

func TestRecordedBranchWinsOverTheMainDefault(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	cases := []struct {
		metadata string
		write    bool
		expected string
	}{
		{"", false, "main"},
		{"product: easy-ha-proxy\n", true, "main"},
		{"product: easy-ha-proxy\nbranch: alpha\nimage_channel: alpha\n", true, "alpha"},
		{"branch: 'alpha'\n", true, "alpha"},
		{`branch: "release/2.0"` + "\n", true, "release/2.0"},
		{"nested:\n  branch: alpha\n", true, "main"},
		{"branch: --upload-pack=touch\n", true, "main"},
		{"branch: a..b\n", true, "main"},
		{"branch: alpha.lock\n", true, "main"},
		{"branch:\n", true, "main"},
	}
	for _, name := range gatewayScripts {
		config := t.TempDir()
		for _, c := range cases {
			if got := resolveBranch(t, config, name, c.metadata, c.write, ""); got != c.expected {
				t.Errorf("%s with %q: %q, want %q", name, c.metadata, got, c.expected)
			}
		}
	}
}

func TestAnExplicitBranchStillOverridesTheRecordedOne(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	for _, name := range gatewayScripts {
		config := t.TempDir()
		if got := resolveBranch(t, config, name, "branch: alpha\n", true, "feature"); got != "feature" {
			t.Errorf("%s: %q, want feature", name, got)
		}
	}
}

func TestBothScriptsUseTheResolvedBranch(t *testing.T) {
	helper := read(t, "easy-ha-proxy-helper.sh")
	bootstrap := read(t, "install-local.sh")
	for name, text := range map[string]string{"helper": helper, "bootstrap": bootstrap} {
		if strings.Contains(text, `branch="${EASY_HA_PROXY_BRANCH:-main}"`) {
			t.Errorf("%s forces the main default", name)
		}
	}
	// The helper resolves it as root, after the sudo re-run.
	if strings.Index(helper, `exec sudo env "${sudo_environment[@]}"`) >= strings.Index(helper, `branch="$(gateway_branch)"`) {
		t.Error("the helper resolves the branch before the sudo re-run")
	}
	if strings.Index(bootstrap, `branch="$(gateway_branch)"`) >= strings.Index(bootstrap, `fetch --depth=1 origin "${branch}"`) {
		t.Error("the bootstrap fetches before it resolves the branch")
	}
}

// A non-root user may not read metadata.yml: the sudo re-run must let root
// resolve it, without forcing a branch nobody gave.

type sudoFixture struct {
	t      *testing.T
	root   string
	record string
	path   string
}

func newSudoFixture(t *testing.T) *sudoFixture {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	if os.Geteuid() == 0 {
		t.Skip("the sudo re-run happens only for non-root users")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, "sudo-args")
	fake := "#!/bin/sh\nprintf \"%s\\n\" \"$@\" > \"$SUDO_RECORD\"\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	return &sudoFixture{t: t, root: root, record: record, path: bin + string(os.PathListSeparator) + os.Getenv("PATH")}
}

func (f *sudoFixture) rerunArguments(extra map[string]string) []string {
	f.t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "EASY_HA_PROXY_") {
			env = append(env, kv)
		}
	}
	env = append(env, "PATH="+f.path, "SUDO_RECORD="+f.record,
		"EASY_HA_PROXY_CONFIG_DIR="+filepath.Join(f.root, "config"))
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(repoRoot(f.t), "easy-ha-proxy-helper.sh"), "--action", "status")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		f.t.Fatalf("the helper: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(f.record)
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func TestNoBranchIsForcedWhenNoneWasGiven(t *testing.T) {
	f := newSudoFixture(t)
	arguments := f.rerunArguments(nil)
	if arguments[0] != "env" {
		t.Fatalf("the re-run starts with %q", arguments[0])
	}
	for _, a := range arguments {
		if strings.HasPrefix(a, "EASY_HA_PROXY_BRANCH=") || strings.HasPrefix(a, "EASY_HA_PROXY_RAW_BASE=") {
			t.Errorf("the re-run forces %q", a)
		}
	}
	if len(arguments) < 2 || arguments[len(arguments)-2] != "--action" || arguments[len(arguments)-1] != "status" {
		t.Fatalf("the re-run ends with %v", arguments)
	}
}

func TestAGivenBranchReachesRoot(t *testing.T) {
	f := newSudoFixture(t)
	arguments := f.rerunArguments(map[string]string{"EASY_HA_PROXY_BRANCH": "feature"})
	for _, a := range arguments {
		if a == "EASY_HA_PROXY_BRANCH=feature" {
			return
		}
	}
	t.Fatalf("the branch did not reach root: %v", arguments)
}
