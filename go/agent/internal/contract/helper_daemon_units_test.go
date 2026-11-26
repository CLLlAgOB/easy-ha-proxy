package contract

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The helper does not count a switched-off Authelia's daemons as a pending
// update: Authelia's daemons are installed only where Authelia (and that
// daemon) is on, but the helper treated every missing unit as "an update is
// available", so a gateway without Authelia was told so after every update.
// The checks run the helper's own bash functions against a scratch config.

// helperDaemonFunction extracts one shell function body from the helper,
// from its "name() {" line to the first line that is just "}".
func helperDaemonFunction(t *testing.T, name string) string {
	t.Helper()
	helper := read(t, "easy-ha-proxy-helper.sh")
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{\n.*?^\}\n`)
	body := re.FindString(helper)
	if body == "" {
		t.Fatalf("helper has no %s", name)
	}
	return body
}

// helperDaemonUnitExpected runs unit_expected in bash with a scratch config
// directory; an empty vars or authelia text leaves that file unwritten.
func helperDaemonUnitExpected(t *testing.T, unit, varsText, autheliaText string) bool {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}
	config := t.TempDir()
	if varsText != "" {
		if err := os.WriteFile(filepath.Join(config, "vars.yml"), []byte(varsText), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if autheliaText != "" {
		if err := os.WriteFile(filepath.Join(config, "authelia.yml"), []byte(autheliaText), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.Join([]string{
		helperDaemonFunction(t, "yaml_scalar"),
		helperDaemonFunction(t, "config_switch"),
		helperDaemonFunction(t, "unit_expected"),
		fmt.Sprintf("config_dir=%q", config),
		fmt.Sprintf("unit_expected %q", unit),
	}, "\n")
	return exec.Command("bash", "-c", script).Run() == nil
}

func TestAutheliaDaemonsFollowTheirSwitches(t *testing.T) {
	on := "authelia_enabled: true\n"
	cases := []struct {
		unit     string
		vars     string
		authelia string
		want     bool
	}{
		{"authelia-usersd.service", on, "", true},
		{"authelia-bansd.service", on, "", true},
		{"authelia-usersd.service", "authelia_enabled: false\n", "", false},
		{"authelia-usersd.service", "", "", false},
		{"authelia-usersd.service", "root_domain: example.com\n", on, true},
		// authelia.yml is read after vars.yml and wins, as in the playbook.
		{"authelia-usersd.service", on, "authelia_enabled: false\n", false},
		{"authelia-usersd.service", "authelia_enabled: false\n", on, true},
		{"authelia-bansd.service", on + "authelia_bans_daemon_enabled: false\n", "", false},
		{"authelia-configd.service", on + "authelia_configd_enabled: false\n", "", false},
		{"authelia-configd.service", on + "authelia_bans_daemon_enabled: false\n", "", true},
	}
	for _, c := range cases {
		if got := helperDaemonUnitExpected(t, c.unit, c.vars, c.authelia); got != c.want {
			t.Errorf("unit_expected %q (vars=%q, authelia=%q) = %v, want %v",
				c.unit, c.vars, c.authelia, got, c.want)
		}
	}
}

func TestOtherDaemonsAreAlwaysExpected(t *testing.T) {
	if !helperDaemonUnitExpected(t, "haproxy-controld.service", "", "") {
		t.Error("haproxy-controld.service is not always expected")
	}
	if !helperDaemonUnitExpected(t, "easy-ha-proxy-guardd.service", "authelia_enabled: false\n", "") {
		t.Error("easy-ha-proxy-guardd.service depends on the Authelia switch")
	}
}
