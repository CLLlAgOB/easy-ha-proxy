package contract

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The panel's side of alerts in the header: every page carries the header's
// indicator, its script does not cry wolf on a single failed answer, a refresh
// keeps the history the operator is looking at, and every word is in Russian.
// The route tests ran against the Flask panel and went with it.

func TestAlertsHeaderCarriesTheIndicatorAndItsScript(t *testing.T) {
	base := read(t, webDir+"/templates/base.html")
	mustContain(t, base, `id="global-alerts"`, "base.html")
	mustContain(t, base, "url_for('routes.api_alerts_portal')", "base.html")
	mustContain(t, base, "js/alerts_badge.js", "base.html")
	// Shown to every operator, not only to a superadmin: the indicator must
	// not sit inside an unbalanced superadmin-only conditional.
	indicator := strings.SplitN(base, `<a id="global-alerts"`, 2)[0]
	if got, want := strings.Count(indicator, "{% if g.is_superadmin %}"), strings.Count(indicator, "{% endif %}"); got != want {
		t.Errorf("superadmin conditionals unbalanced before the indicator: %d if vs %d endif", got, want)
	}
}

func TestAlertsBadgeScriptDoesNotCryWolf(t *testing.T) {
	// The alert service restarts with every update: one failed answer is
	// not shown, two in a row are.
	script := read(t, webDir+"/static/js/alerts_badge.js")
	mustContain(t, script, "if (failures >= 2) renderSilent(badge);", "alerts_badge.js")
	mustContain(t, script, "badge.hidden = total === 0;", "alerts_badge.js")
	mustContain(t, script, `"easy-ha-proxy:alerts-changed"`, "alerts_badge.js")
	page := read(t, webDir+"/static/js/alerts.js")
	mustContain(t, page, `new CustomEvent("easy-ha-proxy:alerts-changed")`, "alerts.js")
}

func TestAlertsRefreshKeepsTheHistoryTheOperatorIsLookingAt(t *testing.T) {
	page := read(t, webDir+"/static/js/alerts.js")
	refreshParts := strings.SplitN(page, "async function refresh(", 2)
	if len(refreshParts) < 2 {
		t.Fatal("no refresh function in alerts.js")
	}
	refresh := strings.SplitN(refreshParts[1], "\n  }\n", 2)[0]
	mustContain(t, refresh, "if (!historyBusy()) await loadHistory(false);", "refresh")

	busyParts := strings.SplitN(page, "function historyBusy(", 2)
	if len(busyParts) < 2 {
		t.Fatal("no historyBusy function in alerts.js")
	}
	busy := strings.SplitN(busyParts[1], "\n  }\n", 2)[0]
	mustContain(t, busy, "historyRows.length > HISTORY_PAGE", "historyBusy")
	mustContain(t, busy, "selectedHistory().length > 0", "historyBusy")
}

func TestAlertsEveryWordIsInRussian(t *testing.T) {
	// The merged Russian catalogue, which is what the browser actually gets.
	root := filepath.Join(repoRoot(t), catalogDir)
	catalog := map[string]string{}
	for _, path := range catalogFiles(t) {
		rel, _ := filepath.Rel(root, path)
		c := loadCatalog(t, catalogDir+"/"+filepath.ToSlash(rel))
		if c.code != "ru" {
			continue
		}
		for key, value := range c.messages {
			catalog[key] = value
		}
	}
	words := []string{
		"Acknowledge", "Mute", "Unmute", "Undo", "Dismiss", "Muted until", "Acknowledged",
		"1 hour", "8 hours", "1 day", "7 days", "Delete selected", "Clear history",
		"Show more", "All severities", "All conditions", "Delete the selected entries?",
		"Delete the whole alert history?", "The action failed", "Show in the panel from",
		"Alerts: {count}", "The alert service is not answering", "Open alerts",
		"Mail cannot be delivered", "critical", "warning", "info", "fired", "recovered",
		"dismissed", "Actions",
	}
	var missing []string
	for _, word := range words {
		if _, ok := catalog[word]; !ok {
			missing = append(missing, word)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Errorf("words missing from the Russian catalogue: %v", missing)
	}
}
