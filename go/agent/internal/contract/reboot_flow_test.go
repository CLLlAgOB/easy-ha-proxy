package contract

import "testing"

// Regression tests for shell launcher reboot handling: the helper schedules
// a reboot through a marker file and offers the full OS action, and the
// remote launcher watches the boot id so it waits for the machine to come
// back instead of reporting failure mid-reboot. Unit tests for CLI reboot
// scheduling and markers live in go/agent/internal/cli/lock_reboot_test.go.

func TestHelperExitsCleanlyAndRemoteLauncherWaitsForReboot(t *testing.T) {
	helper := read(t, "easy-ha-proxy-helper.sh")
	remote := read(t, "install-remote.sh")
	launcher := read(t, "install.sh")

	for _, want := range []string{
		`reboot_schedule_marker="/run/easy-ha-proxy/reboot-scheduled"`,
		"8) perform_action reboot",
		`if [[ "${status}" -eq 0 && -f "${reboot_schedule_marker}" ]]`,
		`if [[ "${action_name}" == "os" ]]`,
		`if [[ "${has_full}" == true ]]`,
		"run_smart_managed_action os",
	} {
		mustContain(t, helper, want, "easy-ha-proxy-helper.sh")
	}
	for _, want := range []string{
		"wait_for_remote_reboot()",
		"prepare_remote_reboot_monitoring()",
		// The call site, not only the definition: monitoring must actually
		// be prepared before the remote reboot runs.
		"prepare_remote_reboot_monitoring\n",
		"/proc/sys/kernel/random/boot_id",
		`"${current_boot_id}" != "${reboot_monitor_boot_id}"`,
		"EASY_HA_PROXY_REBOOT_SCHEDULED",
		"reboot|configure|language",
	} {
		mustContain(t, remote, want, "install-remote.sh")
	}
	mustContain(t, launcher, "update-containers|reboot|configure", "install.sh")
}
