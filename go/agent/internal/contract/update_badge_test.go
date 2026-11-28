package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// A dot in the navigation when updates are waiting: beside "Maintenance" and
// beside "Software updates", for a superadmin. It glows for easy-ha-proxy's
// own updates; operating-system packages get a quiet dot. The page renders it
// on the server, so it never pops in after load, and the updates page keeps it
// current while it polls.

// updateBadgeRenderNav mirrors render_nav: autoescape on, the template's own
// whitespace control, a url_for stub, a request on the dashboard, and the
// badge level (nil for no updates).
func updateBadgeRenderNav(t *testing.T, level any) string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), filepath.FromSlash(webDir), "templates")
	env := jinja.NewEnvironment(func(n string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		return string(raw), err
	})
	env.Autoescape = true
	env.TrimBlocks = false
	env.LstripBlocks = false
	out, err := env.Render("_haproxy_nav.html", map[string]any{
		"url_for": jinja.Func(func(args []any, kwargs *jinja.Map) (any, error) {
			return "/" + jinja.Str(args[0]), nil
		}),
		"request":              jinja.Obj{"endpoint": "routes.index"},
		"updates_badge":        level,
		"debug_routes_enabled": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// updateBadgeAfter is source.split(marker)[1]; a missing marker is the
// IndexError the Python split would raise.
func updateBadgeAfter(t *testing.T, source, marker string) string {
	t.Helper()
	parts := strings.SplitN(source, marker, 2)
	if len(parts) != 2 {
		t.Fatalf("marker %q not found", marker)
	}
	return parts[1]
}

func TestTheDotSitsBesideMaintenanceAndSoftwareUpdates(t *testing.T) {
	html := updateBadgeRenderNav(t, "product")
	if n := strings.Count(html, `class="nav-update-dot nav-update-dot--product"`); n != 2 {
		t.Errorf("product dot rendered %d times, want 2", n)
	}
	maintenance := strings.SplitN(updateBadgeAfter(t, html, `data-nav-group="maintenance"`), "</summary>", 2)[0]
	mustContain(t, maintenance, "nav-update-dot--product", "maintenance summary")
	item := strings.SplitN(updateBadgeAfter(t, html, `data-nav-endpoint="system_updates.page"`), "</a>", 2)[0]
	mustContain(t, item, "nav-update-dot--product", "system_updates item")
	mustContain(t, html, `title="Software updates are available"`, "nav")
}

func TestOsPackagesGetTheQuietDotAndNothingGetsNone(t *testing.T) {
	osHTML := updateBadgeRenderNav(t, "os")
	if n := strings.Count(osHTML, "nav-update-dot--os"); n != 2 {
		t.Errorf("os dot rendered %d times, want 2", n)
	}
	mustContain(t, osHTML, "Operating-system package updates are available", "nav (os)")
	if strings.Contains(updateBadgeRenderNav(t, nil), "nav-update-dot") {
		t.Error("a dot rendered with no updates waiting")
	}
}

func TestTheUpdateDotIsStillAndMotionCanBeReduced(t *testing.T) {
	css := read(t, webDir+"/static/css/styles.css")
	for _, selector := range []string{".nav-update-dot {", ".nav-update-dot--product {"} {
		block := strings.SplitN(updateBadgeAfter(t, css, selector), "}", 2)[0]
		if strings.Contains(block, "animation") {
			t.Errorf("%s animates", selector)
		}
	}
	reduced := updateBadgeAfter(t, css, "@media (prefers-reduced-motion: reduce)")
	mustContain(t, reduced, "animation-iteration-count: 1 !important", "reduced-motion block")
}

func TestTheUpdatesPageMovesTheDotWithItsPolls(t *testing.T) {
	script := read(t, webDir+"/static/js/system_updates.js")
	mustContain(t, script, "syncNavDot(payload.summary)", "system_updates.js")
	mustContain(t, script, `[data-nav-group="maintenance"] > summary`, "system_updates.js")
	mustContain(t, script, `[data-nav-endpoint="system_updates.page"]`, "system_updates.js")
}

func TestTheTitlesAreTranslated(t *testing.T) {
	catalogue := loadCatalog(t, catalogDir+"/ru/updates.json")
	for _, key := range []string{
		"Software updates are available",
		"Operating-system package updates are available",
	} {
		if _, ok := catalogue.messages[key]; !ok {
			t.Errorf("no Russian for %q", key)
		}
	}
}
