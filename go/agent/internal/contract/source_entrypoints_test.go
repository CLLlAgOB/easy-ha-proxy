package contract

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A fresh private checkout must still start the privileged CLI wrapper:
// checkout-index keeps the launchers executable, and installer/easy-ha-proxy
// reaches the agent it is pointed at.

var entrypoints = []string{"install.sh", "install-local.sh", "install-remote.sh",
	"easy-ha-proxy-helper.sh", "installer/easy-ha-proxy"}

func TestPrivateCheckoutKeepsLaunchersExecutableAndCliCanStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX host")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("needs a git checkout")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	previous := setUmask(0o077)
	defer setUmask(previous)
	args := []string{"-c", "core.autocrlf=false", "-C", root, "checkout-index", "--prefix=" + source + "/", "--"}
	args = append(args, entrypoints...)
	cmd := exec.Command("git", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checkout-index: %v\n%s", err, out)
	}
	for _, rel := range entrypoints {
		path := filepath.Join(source, filepath.FromSlash(rel))
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if fi.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", rel)
		}
	}
	home := filepath.Join(directory, "home")
	agent := filepath.Join(directory, "easy-ha-proxy-agent")
	agentScript := "#!/bin/sh\nif [ \"$1\" = \"cli\" ] && [ \"$2\" = \"--probe\" ]; then exit 0; fi\nprintf 'entrypoint-started\\n'\n"
	if err := os.WriteFile(agent, []byte(agentScript), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	launch := exec.CommandContext(ctx, filepath.Join(source, "installer", "easy-ha-proxy"), "--help")
	launch.Env = append(os.Environ(), "EASY_HA_PROXY_HOME="+home, "EASY_HA_PROXY_SOURCE_DIR="+source,
		"EASY_HA_PROXY_AGENT_BIN="+agent)
	var stdout, stderr bytes.Buffer
	launch.Stdout, launch.Stderr = &stdout, &stderr
	if err := launch.Run(); err != nil {
		t.Fatalf("the launcher: %v\n%s", err, stderr.String())
	}
	if stdout.String() != "entrypoint-started\n" {
		t.Fatalf("stdout %q", stdout.String())
	}
}
