package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
)

// An exclusion the page offers has to reach the configuration. A real user
// was banned for a week: their mail client asked for a dozen inline images
// that were not on the server, retried each four times, and produced 71
// errors in ten seconds against a limit of 50. The site edit page has an
// err_exclude editor (exact, prefix and regular-expression matching) and
// the tracking rule has always consulted the variable named for it, but
// nothing ever set that variable: a rule could be written, saved,
// redisplayed and rendered into websites.yml while changing nothing.

const errExcludeTemplateDir = "ansible/roles/haproxy/templates"

// errExcludeVars is the Python harness's render context: one mail site,
// with the exclusion rules under test when there are any.
func errExcludeVars(errExclude any) map[string]any {
	site := map[string]any{
		"name":         "mail.example.com",
		"domain":       "mail.example.com",
		"backend_ip":   "10.0.0.1",
		"backend_port": 5010,
		"err_limit":    250,
	}
	if errExclude != nil {
		site["err_exclude"] = errExclude
	}
	return map[string]any{
		"sites":                          []any{site},
		"tcp_proxies":                    []any{},
		"tcp":                            []any{},
		"site_defaults":                  map[string]any{},
		"admin_domain":                   "admin.example.test",
		"aut_domain":                     "auth.example.test",
		"authelia_enabled":               true,
		"enable_geoip":                   true,
		"easy_ha_proxy_runtime_vars":     map[string]any{},
		"easy_ha_proxy_runtime_websites": map[string]any{},
		"easy_ha_proxy_runtime_tcp":      map[string]any{},
	}
}

// errExcludeRender renders the real template and reads what HAProxy would
// be given. As the Python setUp did, a baseline that cannot render alone
// skips the test instead of failing it.
func errExcludeRender(t *testing.T, errExclude any) string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), filepath.FromSlash(errExcludeTemplateDir))
	env := jinja.NewEnvironment(func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		return string(raw), err
	})
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = true
	env.Filters["regex_replace"] = jinja.RegexReplaceFilter
	env.Filters["combine"] = jinja.CombineFilter
	if _, err := env.Render("haproxy.cfg.j2", errExcludeVars(nil)); err != nil {
		t.Skipf("cannot render the template alone: %v", err)
	}
	rendered, err := env.Render("haproxy.cfg.j2", errExcludeVars(errExclude))
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func errExcludeAbsent(t *testing.T, text, unwanted, where string) {
	t.Helper()
	if strings.Contains(text, unwanted) {
		t.Errorf("%s holds %q", where, unwanted)
	}
}

// errExcludeSetLine is the line that sets the site variable true for the
// configured rule (the asset line sets the same variable but is a separate,
// deliberately not host-scoped line).
func errExcludeSetLine(t *testing.T, rendered string) string {
	t.Helper()
	for _, row := range strings.Split(rendered, "\n") {
		if strings.Contains(row, "site_mail_example_com_excl) bool(true)") && strings.Contains(row, "_ex1_path") {
			return row
		}
	}
	t.Fatal("no line sets site_mail_example_com_excl for the configured rule")
	return ""
}

func TestSiteWithoutExclusionsDeclaresNone(t *testing.T) {
	baseline := errExcludeRender(t, nil)
	mustContain(t, baseline, "set-var(txn.site_mail_example_com_excl) bool(false)", "baseline")
	errExcludeAbsent(t, baseline, "site_mail_example_com_ex1_path", "baseline")
}

func TestExactPathRuleIsRendered(t *testing.T) {
	rendered := errExcludeRender(t, []any{map[string]any{"path": "/", "methods": []any{"GET"}}})
	mustContain(t, rendered, "acl site_mail_example_com_ex1_path path -i /", "rendered config")
	mustContain(t, rendered, "acl site_mail_example_com_ex1_meth method GET", "rendered config")
}

func TestPrefixRuleUsesPathBeg(t *testing.T) {
	// The shape the banned user needed: every attachment under one path.
	rendered := errExcludeRender(t, []any{map[string]any{"path_beg": "/webapi/entry.cgi"}})
	mustContain(t, rendered,
		"acl site_mail_example_com_ex1_path path_beg -i /webapi/entry.cgi",
		"rendered config")
}

func TestRegularExpressionRuleUsesPathReg(t *testing.T) {
	rendered := errExcludeRender(t, []any{map[string]any{"path_reg": "^/static/"}})
	mustContain(t, rendered,
		"acl site_mail_example_com_ex1_path path_reg -i ^/static/",
		"rendered config")
}

func TestExclusionVariableIsActuallySet(t *testing.T) {
	// The whole defect: the rule existed and nothing ever set it true.
	rendered := errExcludeRender(t, []any{map[string]any{"path_beg": "/webapi/entry.cgi"}})
	mustContain(t, rendered, "set-var(txn.site_mail_example_com_excl) bool(true)", "rendered config")
}

func TestExclusionRuleIsScopedToItsOwnSite(t *testing.T) {
	// Without the host guard one site's exclusion would silence errors for
	// every other site sharing the frontend.
	rendered := errExcludeRender(t, []any{map[string]any{"path_beg": "/webapi/entry.cgi"}})
	mustContain(t, errExcludeSetLine(t, rendered), "host_mail_example_com", "configured-rule line")
}

func TestMethodsAreOptional(t *testing.T) {
	rendered := errExcludeRender(t, []any{map[string]any{"path_beg": "/webapi/"}})
	errExcludeAbsent(t, rendered, "site_mail_example_com_ex1_meth", "rendered config")
	line := errExcludeSetLine(t, rendered)
	if !strings.HasSuffix(strings.TrimRight(line, " \t\r\n"), "_ex1_path") {
		t.Errorf("the rule line does not end with the path acl: %s", line)
	}
}

func TestSeveralRulesGetDistinctNames(t *testing.T) {
	rendered := errExcludeRender(t, []any{
		map[string]any{"path": "/", "methods": []any{"GET"}},
		map[string]any{"path_beg": "/webapi/entry.cgi"},
	})
	mustContain(t, rendered, "site_mail_example_com_ex1_path", "rendered config")
	mustContain(t, rendered, "site_mail_example_com_ex2_path", "rendered config")
}

func TestEmptyRuleRendersNothing(t *testing.T) {
	// A row left blank on the page must not produce an acl matching all.
	rendered := errExcludeRender(t, []any{
		map[string]any{"path": "", "methods": []any{"GET"}},
		map[string]any{},
	})
	errExcludeAbsent(t, rendered, "site_mail_example_com_ex1_path", "rendered config")
	errExcludeAbsent(t, rendered, "site_mail_example_com_ex2_path", "rendered config")
}

func TestExclusionStillGatesTheTrackingRule(t *testing.T) {
	rendered := errExcludeRender(t, []any{map[string]any{"path_beg": "/webapi/entry.cgi"}})
	var tracking []string
	for _, row := range strings.Split(rendered, "\n") {
		if strings.Contains(row, "track-sc1 src table tbl_err_mail_example_com") {
			tracking = append(tracking, row)
		}
	}
	if len(tracking) == 0 {
		t.Fatal("no tracking rule for the site")
	}
	mustContain(t, tracking[0], "site_mail_example_com_excl", "tracking rule")
}

func TestTemplateKnowsTheThreeShapesThePageOffers(t *testing.T) {
	source := read(t, errExcludeTemplateDir+"/haproxy.cfg.j2")
	for _, key := range []string{"ex.path", "ex.path_beg", "ex.path_reg"} {
		mustContain(t, source, key, "haproxy.cfg.j2")
	}
}

func TestPageAndTemplateAgreeOnTheShapes(t *testing.T) {
	page := read(t, webDir+"/templates/haproxy_site_edit.html")
	offered := map[string]bool{}
	for _, m := range regexp.MustCompile(`<option value="(path[a-z_]*)"`).FindAllStringSubmatch(page, -1) {
		offered[m[1]] = true
	}
	want := map[string]bool{"path": true, "path_beg": true, "path_reg": true}
	for key := range want {
		if !offered[key] {
			t.Errorf("the page does not offer %q", key)
		}
	}
	for key := range offered {
		if !want[key] {
			t.Errorf("the page offers unexpected shape %q", key)
		}
	}
	source := read(t, errExcludeTemplateDir+"/haproxy.cfg.j2")
	for key := range offered {
		mustContain(t, source, "ex."+key, "haproxy.cfg.j2")
	}
}
