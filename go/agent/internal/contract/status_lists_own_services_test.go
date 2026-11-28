package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// Status lists the alert engine and the backup schedule (F26, 30 October
// review): the default inventory had backupd, updated, metricsd and guardd
// but not easy-ha-proxy-alertd.service nor the backup schedule, and the
// haproxy-* / authelia-* globs do not reach them. The alerts badge could
// say the engine was down while Status had no row, journal or restart for
// it. The Python daemon loader this suite also defined was never used by a
// test and the daemon is Go now; the inventory contract is the template's.

// statusOwnServicesInventory renders healthd.json.j2 and returns the
// systemd units it lists.
func statusOwnServicesInventory(t *testing.T, vars map[string]any) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "ansible", "roles", "haproxy-admin", "templates")
	env := jinja.NewEnvironment(func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		return string(raw), err
	})
	env.Autoescape = false
	env.Filters["bool"] = jinja.AnsibleBool
	rendered, err := env.Render("healthd.json.j2", vars)
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Systemd struct {
			Units []string `json:"units"`
		} `json:"systemd"`
	}
	if err := json.Unmarshal([]byte(rendered), &inventory); err != nil {
		t.Fatalf("healthd.json.j2 did not render valid JSON: %v", err)
	}
	return inventory.Systemd.Units
}

func statusOwnServicesHas(units []string, unit string) bool {
	for _, u := range units {
		if u == unit {
			return true
		}
	}
	return false
}

func TestStatusListsTheAlertEngineAndTheBackupSchedule(t *testing.T) {
	units := statusOwnServicesInventory(t, nil)
	for _, unit := range []string{
		"easy-ha-proxy-alertd.service",
		"easy-ha-proxy-backup.service",
		"easy-ha-proxy-backup.timer",
	} {
		if !statusOwnServicesHas(units, unit) {
			t.Errorf("the default inventory does not list %s", unit)
		}
	}
}

func TestDisabledBackupScheduleIsNotShownAsAFailure(t *testing.T) {
	units := statusOwnServicesInventory(t, map[string]any{"backup_schedule_enabled": false})
	if statusOwnServicesHas(units, "easy-ha-proxy-backup.timer") {
		t.Error("a disabled backup schedule is listed as a unit to watch")
	}
	if !statusOwnServicesHas(units, "easy-ha-proxy-alertd.service") {
		t.Error("the alert engine dropped out of the inventory")
	}
}
