package contract

import (
	"os/exec"
	"strings"
	"testing"
)

// A fresh image upgrades git and libraries in the bootstrap APT step;
// needrestart then restarted systemd-resolved and the clone right after it
// failed with "Could not resolve host" in two of three clean installs.

func TestBootstrapAptStepDoesNotRestartServices(t *testing.T) {
	text := read(t, "install-local.sh")
	install := strings.Index(text, "apt-get install -y --no-install-recommends ca-certificates curl git openssl")
	if install < 0 {
		t.Fatal("the bootstrap APT install is not in install-local.sh")
	}
	// The variables prefix the same command, possibly across a continuation line.
	start := strings.LastIndex(text[:install], "\n  NEEDRESTART")
	if start < 0 || strings.Contains(text[start:install], "\n  apt-get") {
		t.Fatal("the bootstrap APT install must run with needrestart suspended")
	}
	prefix := text[start:install]
	mustContain(t, prefix, "NEEDRESTART_SUSPEND=1", "bootstrap APT environment")
	mustContain(t, prefix, "NEEDRESTART_MODE=l", "bootstrap APT environment")
}

func TestBootstrapWaitsForTheRepositoryHostBeforeTheFirstNetworkCall(t *testing.T) {
	text := read(t, "install-local.sh")
	wait := strings.Index(text, `getent hosts "${repository_host}"`)
	if wait < 0 {
		t.Fatal("install-local.sh does not wait for the repository host")
	}
	for _, call := range []string{"git -C \"${source_dir}\" fetch", "git clone"} {
		at := strings.Index(text, call)
		if at < 0 {
			t.Fatalf("%q is not in install-local.sh", call)
		}
		if at < wait {
			t.Fatalf("%q runs before the wait for the repository host", call)
		}
	}
}

func TestBootstrapRepositoryHostParsing(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	var line string
	for _, l := range strings.Split(read(t, "install-local.sh"), "\n") {
		if strings.HasPrefix(l, "repository_host=") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("repository_host is not set in install-local.sh")
	}
	for repository, want := range map[string]string{
		"https://github.com/CLLlAgOB/easy-ha-proxy.git":       "github.com",
		"https://token@git.example.com:8443/team/project.git": "git.example.com",
		"http://192.0.2.10/repo.git":                          "192.0.2.10",
		"file:///srv/easy-ha-proxy":                           "",
		"/srv/easy-ha-proxy":                                  "",
	} {
		cmd := exec.Command("bash", "-c", line+"\nprintf '%s' \"${repository_host}\"")
		cmd.Env = []string{"repository=" + repository, "PATH=/usr/bin:/bin"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", repository, err)
		}
		if string(out) != want {
			t.Errorf("%s: host %q, want %q", repository, out, want)
		}
	}
}
