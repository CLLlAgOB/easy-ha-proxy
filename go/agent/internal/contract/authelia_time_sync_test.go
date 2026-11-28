package contract

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Regression checks for the Authelia host-time deployment guard: the
// Vagrant guest keeps its own NTP without the VirtualBox time provider,
// the timesyncd recovery window stays at two minutes, and the healthcheck
// role tracks no VirtualBox machinery.

// timeSyncInt is int(v) for a YAML scalar that may parse as an int or as a
// string.
func timeSyncInt(t *testing.T, v any, name string) int64 {
	t.Helper()
	switch x := v.(type) {
	case int64:
		return x
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			t.Fatalf("%s: %q is not an integer", name, x)
		}
		return n
	}
	t.Fatalf("%s: %v is not an integer", name, v)
	return 0
}

func TestVagrantUsesGuestNtpWithoutStoppingGuestAdditions(t *testing.T) {
	path := filepath.Join(repoRoot(t), ".Vagrant", "Vagrantfile")
	if _, err := os.Stat(path); err != nil {
		t.Skip("the intentionally local .Vagrant/Vagrantfile is absent")
	}
	vagrantfile := read(t, ".Vagrant/Vagrantfile")
	for _, want := range []string{
		`"setextradata", :id`,
		"VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled",
		`"/EasyHAProxy/GuestNTP", "systemd-timesyncd-v1"`,
		`"--flags", "RDONLYGUEST"`,
		"vboxadd-service.service.d/easy-ha-proxy-timesync.conf",
		"'Conflicts='",
		"'Conflicts=shutdown.target'",
		"systemctl restart vboxadd-service.service",
		"systemctl restart systemd-timesyncd.service",
		"timedatectl show --property=NTPSynchronized --value",
	} {
		mustContain(t, vagrantfile, want, "Vagrantfile")
	}
	if strings.Contains(vagrantfile, "disable --now vboxadd-service") {
		t.Error("Vagrantfile must not disable vboxadd-service")
	}
}

func TestDefaultTimesyncdRecoveryWindowIsTwoMinutes(t *testing.T) {
	v, err := pyyaml.Load([]byte(read(t, "ansible/roles/authelia/defaults/main.yml")))
	if err != nil {
		t.Fatal(err)
	}
	defaults, ok := v.(*pyyaml.Map)
	if !ok {
		t.Fatal("authelia defaults are not a mapping")
	}
	retries := timeSyncInt(t, defaults.Value("authelia_test_time_sync_retries"), "authelia_test_time_sync_retries")
	delay := timeSyncInt(t, defaults.Value("authelia_test_time_sync_delay"), "authelia_test_time_sync_delay")
	if retries*delay != 120 {
		t.Errorf("retries %d x delay %ds = %ds, want 120s", retries, delay, retries*delay)
	}
}

func TestHealthcheckHasNoVirtualboxTracking(t *testing.T) {
	// Time synchronization is still monitored, but nothing VirtualBox.
	healthcheckDefaults := read(t, "ansible/roles/healthcheck/defaults/main.yml")
	mustContain(t, healthcheckDefaults, `- name: "systemd-timesyncd.service"`, "healthcheck defaults")
	for _, needle := range []string{
		"vboxadd-service",
		"VirtualBox",
		"status_check_virtualbox",
		"authelia_vbox_time_provider",
	} {
		if strings.Contains(healthcheckDefaults, needle) {
			t.Errorf("healthcheck defaults still mention %q", needle)
		}
	}
}
