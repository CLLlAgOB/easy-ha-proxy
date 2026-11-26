package contract

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Regression tests for shell/Ansible deployment channel contracts. The CLI
// unit tests for release channels, runtime HAProxy sync, git source updates
// and re-exec live in go/agent/internal/cli.

func TestRemoteDryRunReportsLocalAlphaWorkflow(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "install-remote.sh"),
		"--host", "192.0.2.10", "--user", "admin", "--sync-source", root,
		"--apply", "--image", "alpha", "--dry-run")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the dry run: %v\n%s", err, stderr.String())
	}
	for _, want := range []string{
		"Action: sync-source",
		"Source channel: local",
		"Image channel: alpha",
		"Apply after sync: yes",
	} {
		mustContain(t, stdout.String(), want, "dry run stdout")
	}
}

func TestLocalSourceBundleExcludesMachineConfiguration(t *testing.T) {
	remote := read(t, "install-remote.sh")
	parts := strings.SplitN(remote, "build_source_archive() {", 2)
	if len(parts) != 2 {
		t.Fatal("no build_source_archive in install-remote.sh")
	}
	archiveBlock := strings.SplitN(parts[1], "installer_fingerprint()", 2)[0]
	for _, path := range []string{
		"ansible/inventory.ini",
		"ansible/vars.yml",
		"ansible/websites.yml",
		"ansible/tcp.yml",
		"ansible/authelia_users_initial.yml",
		"ansible/roles/cert/files/*.pem",
	} {
		mustContain(t, archiveBlock, "--exclude='"+path+"'", "source archive")
	}
}

func TestGeoipFilteringIsOptInForLegacyConfiguration(t *testing.T) {
	for _, rel := range []string{
		"ansible/roles/haproxy/defaults/main.yml",
		"ansible/roles/geoip_acl/defaults/main.yml",
	} {
		v, err := pyyaml.Load([]byte(read(t, rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := v.(*pyyaml.Map).Value("enable_geoip"); got != false {
			t.Errorf("%s: enable_geoip %v, want false", rel, got)
		}
	}
	v, err := pyyaml.Load([]byte(read(t, "ansible/roles/geoip_acl/defaults/main.yml")))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(*pyyaml.Map).Value("geoip_database_enabled"); got != true {
		t.Errorf("geoip_database_enabled %v, want true", got)
	}
}

func TestRemoteInstallerFingerprintPreflightIsNounsetSafe(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash")
	}
	root := repoRoot(t)
	temporary := t.TempDir()
	fakeBin := filepath.Join(temporary, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeSSH := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *'/opt/easy-ha-proxy/source'*'sha256sum'*)\n" +
		"    printf '%064d\\n' 0\n" +
		"    ;;\n" +
		"  *'mktemp -d /tmp/easy-ha-proxy-stage'*)\n" +
		"    printf '/tmp/easy-ha-proxy-stage.test01\\n'\n" +
		"    ;;\n" +
		"esac\n"
	for name, body := range map[string]string{"ssh": fakeSSH, "scp": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", filepath.Join(root, "install-remote.sh"),
		"--host", "192.0.2.10", "--user", "admin", "--action", "repair")
	cmd.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if code != 0 {
		t.Fatalf("rc %d: %s", code, stderr.String())
	}
	mustContain(t, stderr.String(), "installer source on the server differs", "repair stderr")
	if strings.Contains(stderr.String(), "unbound variable") {
		t.Fatal("the preflight tripped over an unbound variable")
	}
}
