package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// Rendered shell: role boundaries, current location and safe account text.

// uiShellRender mirrors the Python render(): autoescape on, a url_for stub
// that serves endpoints and static files, g/request objects and the page
// globals base.html reads. An empty source renders base.html itself.
func uiShellRender(t *testing.T, endpoint string, administrator bool, username, source string) string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), filepath.FromSlash(webDir), "templates")
	env := jinja.NewEnvironment(func(n string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		return string(raw), err
	})
	env.Autoescape = true
	env.TrimBlocks = false
	env.LstripBlocks = false
	env.Globals["url_for"] = jinja.Func(func(args []any, kwargs *jinja.Map) (any, error) {
		out := "/" + jinja.Str(args[0])
		if filename, ok := kwargs.Get("filename"); ok {
			out += "/" + jinja.Str(filename)
		}
		return out, nil
	})
	vars := map[string]any{
		"g":                    jinja.Obj{"is_superadmin": administrator, "remote_user": username},
		"request":              jinja.Obj{"endpoint": endpoint, "full_path": "/"},
		"current_language":     "en",
		"supported_languages":  []any{map[string]any{"code": "en", "label": "English"}},
		"i18n_config":          map[string]any{"language": "en", "languages": []any{}},
		"i18n_messages_url":    "/messages.js",
		"csrf_token":           jinja.Func(func([]any, *jinja.Map) (any, error) { return "test-csrf", nil }),
		"csp_nonce":            "test-nonce",
		"build":                nil,
		"updates_badge":        nil,
		"debug_routes_enabled": false,
	}
	if source != "" {
		tmpl, err := env.FromString("shell-test", source)
		if err != nil {
			t.Fatal(err)
		}
		out, err := env.RenderTemplate(tmpl, vars)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out, err := env.Render("base.html", vars)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An ordinary user gets the dashboard without administration links: the
// admin navigation and the configuration chip stay superadmin-only.
func TestAnOrdinaryUserGetsTheDashboardWithoutAdministrationLinks(t *testing.T) {
	html := uiShellRender(t, "routes.index", false, "operator", "")
	mustContain(t, html, `href="/routes.index"`, "shell (ordinary user)")
	for _, unwanted := range []string{
		`data-nav-endpoint="routes.haproxy_config_page"`,
		`data-nav-endpoint="routes.authelia_users"`,
		`id="global-config-state"`,
	} {
		if strings.Contains(html, unwanted) {
			t.Errorf("shell (ordinary user) holds %q", unwanted)
		}
	}
}

// The current section is open and marked for nested editors: a site edit
// page lights up its parent HTTP-sites entry.
func TestTheCurrentSectionIsOpenAndMarkedForNestedEditors(t *testing.T) {
	html := uiShellRender(t, "routes.haproxy_site_edit", true, "operator", "")
	mustContain(t, html, `data-nav-group="routing" open`, "shell (site edit)")
	if !regexp.MustCompile(`data-nav-endpoint="routes\.haproxy_sites_page"\s+aria-current="page"`).MatchString(html) {
		t.Error("the parent HTTP-sites entry is not marked aria-current=\"page\"")
	}
}

// Account text is escaped: a hostile remote_user must not inject markup.
func TestAccountTextIsEscaped(t *testing.T) {
	html := uiShellRender(t, "routes.index", true, `<img src=x onerror="bad()">`, "")
	if strings.Contains(html, "<img src=x") {
		t.Error("the account name injected raw markup")
	}
	mustContain(t, html, "&lt;img", "shell (hostile account name)")
}

// Mobile controls and the skip target are present exactly once.
func TestMobileControlsAndSkipTargetArePresentOnce(t *testing.T) {
	html := uiShellRender(t, "routes.index", true, "operator", "")
	for _, target := range []string{"app-sidebar", "nav-toggle", "nav-close", "nav-backdrop", "main-content", "theme-toggle"} {
		if n := strings.Count(html, `id="`+target+`"`); n != 1 {
			t.Errorf("id=%q rendered %d times, want 1", target, n)
		}
	}
	mustContain(t, html, `href="#main-content"`, "shell")
	mustContain(t, html, `aria-controls="app-sidebar"`, "shell")
}

// Page actions render inside the main content, not in the header.
func TestPageActionsRenderInsideTheMainContent(t *testing.T) {
	html := uiShellRender(t, "routes.index", true, "operator", `{% extends "base.html" %}
            {% block header_buttons %}<a href="/new">Create entry</a>{% endblock %}`)
	main := strings.SplitN(updateBadgeAfter(t, html, "<main "), "</main>", 2)[0]
	mustContain(t, main, `class="page-actions"`, "main content")
	mustContain(t, main, `href="/new"`, "main content")
	header := strings.SplitN(updateBadgeAfter(t, html, "<header "), "</header>", 2)[0]
	if strings.Contains(header, `href="/new"`) {
		t.Error("the page action leaked into the header")
	}
}
