package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The header must not cost three rows, and must not lose a page doing it.
// Grouping the buttons into menus is only worth doing if every destination
// survives the move: the same set of pages, each in exactly one place, and
// the machinery that makes a <details> behave like a menu actually wired up.

const navTemplate = webDir + "/templates/_haproxy_nav.html"
const navBase = webDir + "/templates/base.html"
const navScript = webDir + "/static/js/nav.js"
const navStyles = webDir + "/static/css/styles.css"

const navInclude = `{% include "_haproxy_nav.html" %}`

// navExpectedEndpoints is every destination the header offers.
var navExpectedEndpoints = map[string]bool{
	"access_portal.sites":             true,
	"routes.haproxy_sites_page":       true,
	"routes.haproxy_tcp_page":         true,
	"routes.haproxy_udp_page":         true,
	"routes.haproxy_config_page":      true,
	"routes.config_history_page":      true,
	"routes.trash_page":               true,
	"routes.haproxy_geoip_page":       true,
	"routes.haproxy_certs_page":       true,
	"routes.dns_providers_page":       true,
	"routes.cert_delivery_page":       true,
	"routes.mail_settings_page":       true,
	"routes.haproxy_backends_page":    true,
	"routes.backend_presets_page":     true,
	"routes.live_activity_page":       true,
	"routes.monitoring_page":          true,
	"routes.adaptive_protection_page": true,
	"routes.adaptive_bans_page":       true,
	"routes.detection_rules_page":     true,
	"routes.request_log_page":         true,
	"ssh_security.page":               true,
	"routes.alerts_page":              true,
	"routes.audit_page":               true,
	"routes.system_health_page":       true,
	"system_updates.page":             true,
	"schedule.page":                   true,
	"os_security.page":                true,
	"system_backups.page":             true,
	"routes.haproxy_stats_page":       true,
	"authelia_acl.edit_rules":         true,
	"routes.authelia_users":           true,
	"routes.authelia_bans":            true,
	"authelia_settings.edit_settings": true,
	// Only rendered when debug routes are switched on.
	"routes.debug": true,
	"routes.index": true,
}

var navURLFor = regexp.MustCompile(`url_for\('([^']+)'\)`)
var navGroupedEndpoint = regexp.MustCompile(`\("([a-z_]+\.[a-z_]+)"`)
var navGroupLabel = regexp.MustCompile(`"label": "([^"]+)"`)

func navSource(t *testing.T) string {
	t.Helper()
	return read(t, navTemplate)
}

// navGroupedEndpoints are the endpoints named inside the group definitions,
// in order.
func navGroupedEndpoints(t *testing.T) []string {
	t.Helper()
	source := navSource(t)
	parts := strings.SplitN(source, "set nav_groups", 2)
	if len(parts) != 2 {
		t.Fatal("no nav_groups definition")
	}
	block := strings.SplitN(parts[1], "%}", 2)[0]
	var out []string
	for _, m := range navGroupedEndpoint.FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

// navAfter is source.split(marker)[1]; a missing marker is the IndexError
// the Python split would raise.
func navAfter(t *testing.T, source, marker string) string {
	t.Helper()
	parts := strings.SplitN(source, marker, 2)
	if len(parts) != 2 {
		t.Fatalf("marker %q not found", marker)
	}
	return parts[1]
}

// navCatalog merges the base Russian catalog with the fragment catalogs.
func navCatalog(t *testing.T) map[string]string {
	t.Helper()
	messages := map[string]string{}
	base := loadCatalog(t, catalogDir+"/ru.json")
	for k, v := range base.messages {
		messages[k] = v
	}
	frags, _ := filepath.Glob(filepath.Join(repoRoot(t), filepath.FromSlash(catalogDir), "ru", "*.json"))
	sort.Strings(frags)
	for _, path := range frags {
		rel, _ := filepath.Rel(repoRoot(t), path)
		c := loadCatalog(t, filepath.ToSlash(rel))
		for k, v := range c.messages {
			messages[k] = v
		}
	}
	return messages
}

// navFirstRunes is s[:n] by code point, as Python slices.
func navFirstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func TestNoPageWasLostInTheRegrouping(t *testing.T) {
	source := navSource(t)
	present := map[string]bool{}
	for _, m := range navURLFor.FindAllStringSubmatch(source, -1) {
		present[m[1]] = true
	}
	for _, e := range navGroupedEndpoints(t) {
		present[e] = true
	}
	for e := range navExpectedEndpoints {
		if !present[e] {
			t.Errorf("endpoint %s was lost in the regrouping", e)
		}
	}
	for e := range present {
		if !navExpectedEndpoints[e] {
			t.Errorf("unexpected endpoint %s", e)
		}
	}
}

func TestEachDestinationAppearsOnce(t *testing.T) {
	// Twice in two menus is a menu nobody trusts.
	endpoints := navGroupedEndpoints(t)
	counts := map[string]int{}
	for _, e := range endpoints {
		counts[e]++
	}
	for e, n := range counts {
		if n > 1 {
			t.Errorf("endpoint %s appears %d times", e, n)
		}
	}
}

func TestTheDashboardStaysALinkRatherThanHidingInAMenu(t *testing.T) {
	// It is where people go when they are lost; burying it in a menu is the
	// opposite of that.
	for _, e := range navGroupedEndpoints(t) {
		if e == "routes.index" {
			t.Error("routes.index is hidden in a menu")
		}
	}
	mustContain(t, navSource(t), "url_for('routes.index')", "nav")
}

func TestTheGeoipDatabaseSitsWithTheProtectionItServes(t *testing.T) {
	// A country list is not a naming concern; it exists so requests from
	// somewhere can be refused.
	source := navSource(t)
	protection := strings.SplitN(navAfter(t, source, `"label": "Protection"`), "},", 2)[0]
	mustContain(t, protection, "routes.haproxy_geoip_page", "Protection group")
}

func TestTheAutheliaItemsDoNotRepeatTheMenuName(t *testing.T) {
	source := navSource(t)
	block := strings.SplitN(navAfter(t, source, `"label": "Authelia"`), "},", 2)[0]
	labels := regexp.MustCompile(`"([A-Z][^"]*)"\)`).FindAllStringSubmatch(block, -1)
	if len(labels) == 0 {
		t.Fatal("no Authelia item labels")
	}
	for _, m := range labels {
		label := m[1]
		t.Run(label, func(t *testing.T) {
			if strings.Contains(label, "Authelia") {
				t.Errorf("label %q repeats the menu name", label)
			}
		})
	}
}

func TestAutheliaIsReachableFromEveryPage(t *testing.T) {
	// It used to be one button on the dashboard, so arriving on any HAProxy
	// page meant going Home before you could reach it.
	for _, e := range navGroupedEndpoints(t) {
		if e == "authelia_acl.edit_rules" {
			return
		}
	}
	t.Error("authelia_acl.edit_rules is not in the navigation")
}

func TestOneNavServesTheWholeApplication(t *testing.T) {
	base := read(t, navBase)
	if n := strings.Count(base, navInclude); n != 1 {
		t.Errorf("base.html includes the nav %d times, want 1", n)
	}
	pages, _ := filepath.Glob(filepath.Join(repoRoot(t), filepath.FromSlash(webDir), "templates", "*.html"))
	for _, path := range pages {
		name := filepath.Base(path)
		if name == "base.html" || name == "_haproxy_nav.html" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), navInclude) {
				t.Errorf("%s includes the nav a second time", name)
			}
		})
	}
}

func TestTheRowIsShortEnoughToBeWorthIt(t *testing.T) {
	// Six menus plus Home. More than about eight and the header wraps again,
	// which is the problem this replaced.
	source := navSource(t)
	groups := strings.Count(source, `"label":`)
	if groups+1 > 9 {
		t.Errorf("the header will wrap again (%d groups)", groups)
	}
	if groups <= 1 {
		t.Errorf("grouping that groups nothing (%d groups)", groups)
	}
}

func TestItWorksWithoutTheScript(t *testing.T) {
	// <details> opens and closes on its own; anything that made opening
	// depend on JS would leave the section unreachable when it fails to load.
	source := navSource(t)
	mustContain(t, source, "<details", "nav")
	mustContain(t, source, "<summary", "nav")
}

func TestTheScriptIsLoadedForEveryPage(t *testing.T) {
	mustContain(t, read(t, navBase), "js/nav.js", "base.html")
}

func TestSectionsRememberTheirOwnState(t *testing.T) {
	script := read(t, navScript)
	mustContain(t, script, `addEventListener("toggle"`, "nav.js")
	mustContain(t, script, `localStorage.setItem("ehp-nav-sections"`, "nav.js")
}

func TestEscapeClosesAndReturnsFocus(t *testing.T) {
	script := read(t, navScript)
	mustContain(t, script, `event.key === "Escape"`, "nav.js")
	mustContain(t, script, "trigger.focus()", "nav.js")
}

func TestClickingAwayClosesIt(t *testing.T) {
	mustContain(t, read(t, navScript), `backdrop.addEventListener("click"`, "nav.js")
}

func TestTheCurrentPageIsMarked(t *testing.T) {
	// A menu that hides its contents has to tell you where you are.
	source := navSource(t)
	styles := read(t, navStyles)
	mustContain(t, source, "nav-item-current", "nav")
	mustContain(t, source, `aria-current="page"`, "nav")
	mustContain(t, styles, ".nav-item-current", "styles.css")
}

func TestTheMenusAndTheDashboardShareOneClass(t *testing.T) {
	// They were two rules obliged to stay identical and did not. One class
	// cannot drift from itself.
	source := navSource(t)
	styles := read(t, navStyles)
	if n := strings.Count(source, `class="nav-item nav-item-menu`); n != 1 {
		t.Errorf("nav-item-menu class appears %d times, want 1", n)
	}
	mustContain(t, source, `<a class="nav-item nav-dashboard`, "nav")
	// And exactly one rule defines the shared look.
	if n := len(regexp.MustCompile(`\n\s*\.nav-item \{`).FindAllString(styles, -1)); n != 1 {
		t.Errorf(".nav-item rule defined %d times, want 1", n)
	}
}

func TestTheDashboardIsSetApartDeliberately(t *testing.T) {
	// It is a destination among menus; a rule before it says so without
	// making it a different shape.
	source := navSource(t)
	styles := read(t, navStyles)
	mustContain(t, source, `class="nav-separator"`, "nav")
	mustContain(t, styles, ".nav-separator", "styles.css")
}

func TestTheSectionIsNamedForAScreenReader(t *testing.T) {
	mustContain(t, navSource(t), `aria-label="Administration sections"`, "nav")
}

func TestTheSidebarIsPositionedAndItsContentsScroll(t *testing.T) {
	styles := read(t, navStyles)
	for _, rule := range []string{".sidebar", "position: fixed", "overflow-y: auto", "z-index"} {
		t.Run(rule, func(t *testing.T) {
			mustContain(t, styles, rule, "styles.css")
		})
	}
}

func TestMobileNavigationDisablesTheBackground(t *testing.T) {
	script := read(t, navScript)
	mustContain(t, script, "workspace.inert = opened", "nav.js")
	mustContain(t, script, `sidebar.setAttribute("aria-modal", "true")`, "nav.js")
}

func TestNavigationIsQuieterThanAnActionButton(t *testing.T) {
	// Seven solid accent pills read as seven competing calls to action. The
	// summary deliberately does not carry .btn.
	source := navSource(t)
	styles := read(t, navStyles)
	if strings.Contains(source, `class="btn nav-item`) {
		t.Error("a nav summary carries the .btn action class")
	}
	mustContain(t, styles, ".nav-item {", "styles.css")
}

func TestALinkShapedLikeAButtonIsNotUnderlined(t *testing.T) {
	// Mixing <a class="btn"> and <button class="btn"> in one row showed the
	// browser default underline on half of them.
	styles := read(t, navStyles)
	block := navFirstRunes(navAfter(t, styles, "a.btn,"), 400)
	mustContain(t, block, "text-decoration: none", "a.btn block")
}

func TestANarrowScreenGetsAStackedMenu(t *testing.T) {
	styles := read(t, navStyles)
	mustContain(t, styles, "@media (max-width: 1023px)", "styles.css")
	narrow := navFirstRunes(navAfter(t, styles, "@media (max-width: 1023px)"), 900)
	mustContain(t, narrow, "position: static", "narrow block")
}

func TestEveryGroupLabelHasRussian(t *testing.T) {
	messages := navCatalog(t)
	labels := navGroupLabel.FindAllStringSubmatch(navSource(t), -1)
	if len(labels) == 0 {
		t.Fatal("no group labels")
	}
	// A product keeps its name in every language; translating "Authelia"
	// would leave nobody able to find Authelia.
	productNames := map[string]bool{"Authelia": true}
	var missing []string
	for _, m := range labels {
		label := m[1]
		if _, ok := messages[label]; !ok && !productNames[label] {
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		t.Errorf("group labels with no Russian: %s", strings.Join(missing, ", "))
	}
}
