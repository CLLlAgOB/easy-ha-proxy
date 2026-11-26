package contract

import "testing"

// Regression tests for the local GeoIP database and derived HAProxy ACL:
// the update timer and its oneshot service keep their monitoring semantics
// in healthd's config, the healthcheck defaults and the panel's health
// page, including the never-run and failed-result detection.

func TestGeoipTimerAndOneshotHaveCorrectMonitoringSemantics(t *testing.T) {
	healthdConfig := read(t, "ansible/roles/haproxy-admin/templates/healthd.json.j2")
	healthcheckDefaults := read(t, "ansible/roles/healthcheck/defaults/main.yml")
	healthJavascript := read(t, "go/panel/web/static/js/health.js")
	healthcheckTasks := read(t, "go/agent/internal/apply/stages/healthcheck.go")

	for _, unit := range []string{
		"easy-ha-proxy-geoip-update.service",
		"easy-ha-proxy-geoip-update.timer",
	} {
		mustContain(t, healthdConfig, unit, "healthd.json.j2")
	}
	mustContain(t, healthcheckDefaults, `timer: "easy-ha-proxy-geoip-update.timer"`, "healthcheck defaults")
	mustContain(t, healthcheckDefaults, `service: "easy-ha-proxy-geoip-update.service"`, "healthcheck defaults")
	mustContain(t, healthJavascript, "unit.healthy", "health.js")
	mustContain(t, healthcheckTasks, "^ActiveState=failed$", "healthcheck.go")
	// The Python-era look-around pattern, kept verbatim in the Go source as
	// the comment documenting its hand-written RE2 equivalent; the check is
	// on the literal text, not on a regex Go could compile.
	mustContain(t, healthcheckTasks, "^Result=(?!(?:success)?$).+$", "healthcheck.go")
	mustContain(t, healthcheckTasks, "status_check_systemd_jobs_never_run", "healthcheck.go")
}
