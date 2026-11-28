package contract

import "testing"

// The restart notice page wording after a night that rebooted: the finding
// and the restart run both predate the reboot, and the page says so in
// English source with a Russian catalog entry. Container inspection tests
// (without health check, with health check, unverifiable record) moved to
// go/agent/internal/hostsec/os_upgrade_guard_test.go.

func TestThePageSaysTheFindingAndTheRunPredateTheReboot(t *testing.T) {
	script := read(t, webDir+"/static/js/os_security.js")
	mustContain(t, script, "restart.before_boot ?", "os_security.js")
	mustContain(t, script, "const earlierBoot =", "os_security.js")
	catalog := loadCatalog(t, catalogDir+"/ru/maintenance_window.json")
	for _, sentence := range []string{
		"The last check was made before the server rebooted, and the reboot restarted every service. " +
			"A new check runs shortly after startup.",
		"The last service restart run was before the server rebooted, and the reboot restarted every service.",
	} {
		mustContain(t, script, sentence, "os_security.js")
		if _, ok := catalog.messages[sentence]; !ok {
			t.Errorf("maintenance_window.json has no Russian for %q", sentence)
		}
	}
}
