package contract

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Regression checks for the Log Explorer page and its routes: stored request
// data stays out of DOM translation, every planned filter is offered, the two
// failure modes are shown apart, "show more" carries on by cursor rather than
// offset, the panel's own requests are hidden unless asked for, and the search
// on screen lives in the address bar.

func TestRequestLogEveryElementTheScriptWritesToExists(t *testing.T) {
	javascript := read(t, webDir+"/static/js/request_log.js")
	template := read(t, webDir+"/templates/request_log.html")
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

func TestRequestLogStoredRequestDataIsExcludedFromDomTranslation(t *testing.T) {
	// Paths and hostnames are data, not interface language.
	template := read(t, webDir+"/templates/request_log.html")
	tag := regexp.MustCompile(`<[^>]+id="rq-body"[^>]*>`).FindString(template)
	if tag == "" {
		t.Fatal("no rq-body element")
	}
	mustContain(t, tag, "data-i18n-skip", "rq-body")
}

func TestRequestLogPageOffersEveryFilterThePlanAsksFor(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	for _, elementID := range []string{
		"rq-range", "rq-status", "rq-client", "rq-host", "rq-backend",
		"rq-path", "rq-request-id",
	} {
		mustContain(t, template, `id="`+elementID+`"`, "request_log.html")
	}
}

func TestRequestLogTwoFailureModesAreShownApart(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, `id="rq-disabled"`, "request_log.html")
	mustContain(t, template, `id="rq-unavailable"`, "request_log.html")
	mustContain(t, javascript, `setNotice("rq-disabled", true)`, "request_log.js")
	mustContain(t, javascript, `setNotice("rq-unavailable", true)`, "request_log.js")
}

func TestRequestLogPageSaysWhatTheStoreCosts(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, `id="rq-store"`, "request_log.html")
	mustContain(t, javascript, "database_bytes", "request_log.js")
	mustContain(t, javascript, "max_bytes", "request_log.js")
}

func TestRequestLogPrivacyRuleIsStatedOnThePage(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	mustContain(t, template, "query string is dropped", "request_log.html")
	// The one header kept is said by name.
	mustContain(t, template, "only the User-Agent is kept", "request_log.html")
	mustContain(t, template, "no cookie or body", "request_log.html")
}

func TestRequestLogShowMoreCarriesOnWhereTheSearchOnScreenStopped(t *testing.T) {
	// Not by offset: new requests would repeat rows, and filters typed
	// since the search would mix two searches in one table.
	javascript := read(t, webDir+"/static/js/request_log.js")
	for _, unwanted := range []string{`"offset"`, "offset +="} {
		if strings.Contains(javascript, unwanted) {
			t.Errorf("request_log.js holds %q", unwanted)
		}
	}
	mustContain(t, javascript, `params.set("before", String(next))`, "request_log.js")
	mustContain(t, javascript, "const params = new URLSearchParams(query);", "request_log.js")
	mustContain(t, javascript, "if (mine !== sequence) return;", "request_log.js")
}

func TestRequestLogPanelsOwnRequestsAreHiddenUnlessAskedFor(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, `id="rq-admin"`, "request_log.html")
	mustContain(t, javascript, `byId("rq-admin").checked`, "request_log.js")
	core := read(t, webDir+"/static/js/request_log_core.js")
	mustContain(t, core, `if (!view.admin) params.hide_admin = "1";`, "request_log_core.js")
}

func TestRequestLogTimeShownIsTheServersAnswer(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, "Server answer", "request_log.html")
	mustContain(t, javascript, "entry.response_ms", "request_log.js")
	mustContain(t, javascript, "The whole request", "request_log.js")
}

func TestRequestLogSearchThatRanOutOfTimeSaysSo(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, `id="rq-stopped"`, "request_log.html")
	mustContain(t, javascript, "payload.timed_out", "request_log.js")
	mustContain(t, javascript, "payload.searched_to", "request_log.js")
	mustContain(t, javascript, "payload.total_exact === false", "request_log.js")
}

func TestRequestLogSearchOnScreenIsInTheAddress(t *testing.T) {
	// A reload, a bookmark or a link opens the same search; Back returns
	// to the one before.
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, javascript, "window.history.pushState", "request_log.js")
	mustContain(t, javascript, `window.addEventListener("popstate"`, "request_log.js")
	mustContain(t, javascript, "core.viewFromQuery(window.location.search)", "request_log.js")
	mustContain(t, javascript, "run(false)", "request_log.js")
}

func TestRequestLogCoresLoadBeforeThePage(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	var order []int
	for _, name := range []string{"live_activity_core.js", "request_log_core.js", "request_log.js"} {
		idx := strings.Index(template, "js/"+name)
		if idx < 0 {
			t.Fatalf("js/%s is not loaded", name)
		}
		order = append(order, idx)
	}
	if !sort.IntsAreSorted(order) {
		t.Errorf("scripts load out of order: %v", order)
	}
}

func TestRequestLogValueInTheTableNarrowsTheSearchToItself(t *testing.T) {
	javascript := read(t, webDir+"/static/js/request_log.js")
	for _, name := range []string{"status", "method", "host", "path", "backend", "client"} {
		mustContain(t, javascript, `filterButton("`+name+`"`, "request_log.js")
	}
	mustContain(t, javascript, `event.target.closest("[data-filter]")`, "request_log.js")
}

func TestRequestLogRowOpensWhatTheLivePageShowsOfARequest(t *testing.T) {
	javascript := read(t, webDir+"/static/js/request_log.js")
	parts := strings.SplitN(javascript, "  function detailsRow(entry) {", 2)
	if len(parts) < 2 {
		t.Fatal("no detailsRow function in request_log.js")
	}
	details := strings.SplitN(parts[1], "\n  }\n", 2)[0]
	for _, part := range []string{
		"live.termination(entry.term)", "live.timers(entry.times)", "entry.user_agent",
		"entry.ban_reason", "/monitoring/live?ip=",
	} {
		mustContain(t, details, part, "detailsRow")
	}
}

func TestRequestLogNewFiltersAreOffered(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	for _, elementID := range []string{"rq-method", "rq-agent", "rq-slower", "rq-refused"} {
		mustContain(t, template, `id="`+elementID+`"`, "request_log.html")
	}
}

func TestRequestLogSwitchedOffShowsNoStopButtonAndNoEmptyStore(t *testing.T) {
	// The status route answers "off" with a 200 and enabled: false; read by
	// its status alone, the page offered to stop a record that was not
	// running and showed an empty store summary.
	javascript := read(t, webDir+"/static/js/request_log.js")
	parts := strings.SplitN(javascript, "async function refreshStore()", 2)
	if len(parts) < 2 {
		t.Fatal("no refreshStore function in request_log.js")
	}
	block := strings.SplitN(parts[1], "\n  }\n", 2)[0]
	mustContain(t, block, "payload.enabled !== false", "refreshStore")
	mustContain(t, block, `byId("rq-disable").hidden = !recording;`, "refreshStore")
}

func TestRequestLogMemoryIsSaidToBeMemory(t *testing.T) {
	template := read(t, webDir+"/templates/request_log.html")
	javascript := read(t, webDir+"/static/js/request_log.js")
	mustContain(t, template, `id="rq-memory"`, "request_log.html")
	mustContain(t, javascript, `payload.source === "memory"`, "request_log.js")
	mustContain(t, javascript, "payload.reaches_back_to", "request_log.js")
}

func TestRequestLogIsReachableFromTheNavigation(t *testing.T) {
	nav := read(t, webDir+"/templates/_haproxy_nav.html")
	mustContain(t, nav, "routes.request_log_page", "_haproxy_nav.html")
}
