package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every page's header is the same height and the same shape. The dashboard
// was the exception: Refresh and Auto-refresh in the header pushed the
// navigation onto a second row, and the site counters hung off the far
// right. Actions on a page belong to the page; the header is for moving
// between pages, and the counters stay at the head of the row.

const headerShapeTemplates = webDir + "/templates"
const headerShapeStyles = webDir + "/static/css/styles.css"

// headerShapeBlock is the body of one {% block %} in a template: from the
// block tag up to the first endblock, as the Python header_block().
func headerShapeBlock(t *testing.T, markup, name string) string {
	t.Helper()
	start := strings.Index(markup, "{% block "+name+" %}")
	if start < 0 {
		t.Fatalf("no {%% block %s %%} in the template", name)
	}
	end := strings.Index(markup[start:], "{% endblock %}")
	if end < 0 {
		t.Fatalf("no endblock for %s", name)
	}
	return markup[start : start+end]
}

// headerShapePages is every panel template, sorted as the Python glob loop.
func headerShapePages(t *testing.T) []string {
	t.Helper()
	pages, err := filepath.Glob(filepath.Join(repoRoot(t), filepath.FromSlash(headerShapeTemplates), "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

// Two buttons in the header were what made this page's header taller than
// every other page's; they must stay out of it.
func TestThePageActionsLeftTheHeader(t *testing.T) {
	buttons := headerShapeBlock(t, read(t, headerShapeTemplates+"/index.html"), "header_buttons")
	for _, control := range []string{`id="refresh-btn"`, `id="auto-btn"`} {
		if strings.Contains(buttons, control) {
			t.Errorf("header_buttons still holds %s", control)
		}
	}
}

// Moved, not deleted: dashboard.js binds both buttons by id.
func TestThePageActionsAreStillOnThePage(t *testing.T) {
	content := headerShapeBlock(t, read(t, headerShapeTemplates+"/index.html"), "content")
	mustContain(t, content, `id="refresh-btn"`, "content block")
	mustContain(t, content, `id="auto-btn"`, "content block")
	mustContain(t, content, `class="page-toolbar"`, "content block")
}

// The shell supplies navigation once; the dashboard header adds neither a
// second include nor buttons of its own.
func TestTheShellSuppliesNavigationOnce(t *testing.T) {
	buttons := headerShapeBlock(t, read(t, headerShapeTemplates+"/index.html"), "header_buttons")
	base := read(t, headerShapeTemplates+"/base.html")
	if strings.Contains(buttons, "_haproxy_nav.html") {
		t.Error("header_buttons includes the navigation")
	}
	if n := strings.Count(base, `{% include "_haproxy_nav.html" %}`); n != 1 {
		t.Errorf("base.html includes _haproxy_nav.html %d times, want 1", n)
	}
	if strings.Contains(buttons, "<button") {
		t.Error("header_buttons holds a button")
	}
}

// The counters sit at the head of the row, not trailing off the edge.
func TestTheCountersSitAtTheHeadOfTheRow(t *testing.T) {
	lead := headerShapeBlock(t, read(t, headerShapeTemplates+"/index.html"), "header_lead")
	mustContain(t, lead, `id="sites-meta"`, "header_lead")
	mustContain(t, lead, `id="toggle-compact"`, "header_lead")
}

// Otherwise "at the head of the row" is only true by accident of source
// order in one template: the slot must precede the language switcher in
// the shell itself.
func TestTheSlotComesBeforeTheLanguageSwitcher(t *testing.T) {
	controls := updateBadgeAfter(t, read(t, headerShapeTemplates+"/base.html"), `<div class="controls">`)
	lead := strings.Index(controls, "{% block header_lead %}")
	language := strings.Index(controls, `class="language-switcher"`)
	if lead < 0 || language < 0 {
		t.Fatal("the controls lack the header_lead slot or the language switcher")
	}
	if lead >= language {
		t.Errorf("header_lead at %d comes after the language switcher at %d", lead, language)
	}
}

// A block nothing fills renders nothing, so the rest of the application
// keeps the header it has: no other page may define the slot.
func TestTheSlotIsEmptyForEveryOtherPage(t *testing.T) {
	for _, path := range headerShapePages(t) {
		name := filepath.Base(path)
		if name == "base.html" || name == "index.html" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "{% block header_lead %}") {
			t.Errorf("%s fills the header_lead slot", name)
		}
	}
}

// The centring machinery the old arrangement needed is gone: the spacer
// existed only to push that group into the middle of the header.
func TestTheSpacerIsGone(t *testing.T) {
	if strings.Contains(read(t, headerShapeStyles), "controls-spacer") {
		t.Error("styles.css still holds controls-spacer")
	}
	for _, path := range headerShapePages(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "controls-spacer") {
			t.Errorf("%s still holds controls-spacer", filepath.Base(path))
		}
	}
}

// A card header is no longer a header concern.
func TestACardHeaderIsNoLongerAHeaderConcern(t *testing.T) {
	if strings.Contains(read(t, headerShapeStyles), "header .controls .card-header") {
		t.Error("styles.css still styles header .controls .card-header")
	}
}

// The page toolbar the actions moved into is styled.
func TestThePageToolbarIsStyled(t *testing.T) {
	mustContain(t, read(t, headerShapeStyles), ".page-toolbar", "styles.css")
}
