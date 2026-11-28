package contract

import (
	"strings"
	"testing"
)

// Regression tests for the privileged GeoIP management API boundary: the
// page exposes status, country management and async updates, and a confirm
// click pauses status polling while the commit is in flight. (The Python
// module's maxminddb stubs were never exercised by its assertions; every
// check here reads the shipped files.)

func TestGeoipPageExposesStatusCountryManagementAndAsyncUpdates(t *testing.T) {
	template := read(t, "go/panel/web/templates/haproxy_geoip.html")
	javascript := read(t, "go/panel/web/static/js/geoip.js")
	navigation := read(t, "go/panel/web/templates/_haproxy_nav.html")

	for _, want := range []string{
		`id="geoip-db-records"`,
		`id="geoip-allowed-networks"`,
		`id="geoip-save-countries"`,
		`id="geoip-next-run"`,
		`id="geoip-journal"`,
	} {
		mustContain(t, template, want, "haproxy_geoip.html")
	}
	for _, want := range []string{
		"/haproxy/geoip/status",
		"/haproxy/geoip/update",
		"/haproxy/geoip/countries",
		"revision: selectionRevision",
		"UPDATE_POLL_INTERVAL_MS",
		"payload.update_running",
	} {
		mustContain(t, javascript, want, "geoip.js")
	}
	mustContain(t, navigation, "routes.haproxy_geoip_page", "_haproxy_nav.html")
}

// geoipFunctionBody is the source between two function markers, as the
// Python split pair isolated it.
func geoipFunctionBody(t *testing.T, javascript, start, end string) string {
	t.Helper()
	parts := strings.SplitN(javascript, start, 2)
	if len(parts) != 2 {
		t.Fatalf("%s not found in haproxy_config.js", start)
	}
	return strings.SplitN(parts[1], end, 2)[0]
}

func TestConfirmationPausesStatusPollingWhileCommitIsInFlight(t *testing.T) {
	javascript := read(t, "go/panel/web/static/js/haproxy_config.js")
	confirmSource := geoipFunctionBody(t, javascript,
		"async function confirmPendingConfiguration()",
		"async function rollbackPendingConfiguration()")
	pollSource := geoipFunctionBody(t, javascript,
		"async function pollTransactionStatus()",
		"async function confirmPendingConfiguration()")

	confirmRequest := strings.Index(confirmSource, `requestJson("/haproxy/config/confirm"`)
	if confirmRequest < 0 {
		t.Fatal("the confirm request is missing from confirmPendingConfiguration")
	}
	if got := strings.Index(confirmSource, "transactionActionInFlight = true"); got < 0 || got >= confirmRequest {
		t.Error("transactionActionInFlight must be set before the confirm request")
	}
	if got := strings.Index(confirmSource, "pauseTransactionPolling()"); got < 0 || got >= confirmRequest {
		t.Error("polling must be paused before the confirm request")
	}
	mustContain(t, pollSource, "if (!pendingTransaction || transactionActionInFlight) return", "pollTransactionStatus")
	mustContain(t, pollSource, "pollGeneration !== transactionPollGeneration", "pollTransactionStatus")
	mustContain(t, javascript, `return ["rollback_failed", "failed"].includes(state)`, "haproxy_config.js")
	mustContain(t, javascript, "setButtonLoading(rollbackButton, false)", "haproxy_config.js")
	mustContain(t, confirmSource, "scheduleTransactionPoll(0)", "confirmPendingConfiguration")
}
