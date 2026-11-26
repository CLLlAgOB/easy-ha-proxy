package contract

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Regression checks for the Alerts page and its routes: every element the
// script writes to must exist, stored payloads stay out of DOM translation,
// secrets are never prefilled with the daemon's mask nor sent back untouched,
// writes carry the CSRF token, and a stopped daemon is shown rather than a
// blank page.

func TestAlertsPageEveryElementTheScriptWritesToExists(t *testing.T) {
	javascript := read(t, webDir+"/static/js/alerts.js")
	template := read(t, webDir+"/templates/alerts.html")
	referenced := map[string]bool{}
	for _, m := range regexp.MustCompile(`byId\("([a-z0-9-]+)"\)`).FindAllStringSubmatch(javascript, -1) {
		referenced[m[1]] = true
	}
	templateIDs := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([a-z0-9-]+)"`).FindAllStringSubmatch(template, -1) {
		templateIDs[m[1]] = true
	}
	var missing []string
	for id := range referenced {
		if !templateIDs[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Errorf("elements the script writes to are missing from the template: %v", missing)
	}
}

func TestAlertsPageStoredPayloadsAreExcludedFromDomTranslation(t *testing.T) {
	template := read(t, webDir+"/templates/alerts.html")
	for _, elementID := range []string{"al-active-body", "al-history-body", "al-status", "al-channels"} {
		tag := regexp.MustCompile(`<[^>]+id="` + regexp.QuoteMeta(elementID) + `"[^>]*>`).FindString(template)
		if tag == "" {
			t.Errorf("no element %s", elementID)
			continue
		}
		mustContain(t, tag, "data-i18n-skip", elementID)
	}
}

func TestAlertsPageSecretFieldsStartEmptyRatherThanPrefilled(t *testing.T) {
	// The daemon returns them shortened; putting that mask in the value
	// would let a save write the mask back as the real setting.
	javascript := read(t, webDir+"/static/js/alerts.js")
	mustContain(t, javascript, `url.value = "";`, "alerts.js")
	mustContain(t, javascript, `secret.value = "";`, "alerts.js")
	mustContain(t, javascript, "url.placeholder = config.webhook_url", "alerts.js")
}

func TestAlertsPageAnUntouchedSecretIsNotSentBack(t *testing.T) {
	javascript := read(t, webDir+"/static/js/alerts.js")
	parts := strings.SplitN(javascript, "function deliveryPayload", 2)
	if len(parts) < 2 {
		t.Fatal("no deliveryPayload function in alerts.js")
	}
	block := strings.SplitN(parts[1], "function ", 2)[0]
	mustContain(t, block, "if (url) payload.webhook_url = url;", "deliveryPayload")
	mustContain(t, block, "if (secret) payload.webhook_header_value = secret;", "deliveryPayload")
}

func TestAlertsPageWritesCarryTheCsrfToken(t *testing.T) {
	javascript := read(t, webDir+"/static/js/alerts.js")
	mustContain(t, javascript, `"X-CSRFToken": csrfToken()`, "alerts.js")
}

func TestAlertsPageAnEventCannotBeGivenADelayInTheForm(t *testing.T) {
	javascript := read(t, webDir+"/static/js/alerts.js")
	mustContain(t, javascript, `delay.disabled = rule.kind === "event";`, "alerts.js")
}

func TestAlertsPageAStoppedDaemonIsShownRatherThanABlankPage(t *testing.T) {
	template := read(t, webDir+"/templates/alerts.html")
	javascript := read(t, webDir+"/static/js/alerts.js")
	mustContain(t, template, `id="al-unavailable"`, "alerts.html")
	mustContain(t, javascript, "setUnavailable(Boolean(error.unavailable))", "alerts.js")
}

func TestAlertsPageIsReachableFromTheNavigation(t *testing.T) {
	nav := read(t, webDir+"/templates/_haproxy_nav.html")
	mustContain(t, nav, "routes.alerts_page", "_haproxy_nav.html")
}

func TestAlertsPageContainerIsGivenTheSocketAndTheToken(t *testing.T) {
	env := read(t, "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2")
	mustContain(t, env, "ALERTD_SOCKET_PATH=", "haproxy-admin.env.j2")
	mustContain(t, env, "ALERTD_TOKEN=", "haproxy-admin.env.j2")
}
