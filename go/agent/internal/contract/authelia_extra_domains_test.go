package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

// Extra Authelia sign-in domains (vars.yml authelia_extra_domains): each is a
// session cookie domain with a portal of its own. HAProxy has to route every
// portal to Authelia exactly as it routes aut_domain, and the agent's Authelia
// template has to give each a cookie and its portal's /access_granted rule.
// Without the list both files must come out as before, so an update changes
// nothing on a gateway that has none.

func extraDomainsHAProxy(t *testing.T, extras any) string {
	t.Helper()
	override := map[string]any{"enable_http80": true}
	if extras != nil {
		override["authelia_extra_domains"] = extras
	}
	return extraDomainsHAProxyWith(t, override)
}

func TestEveryPortalIsRoutedToAutheliaLikeTheMainOne(t *testing.T) {
	out := extraDomainsHAProxy(t, []any{
		map[string]any{"domain": "other.test", "portal": "aut.other.test"},
		map[string]any{"domain": "third.test", "portal": "login.third.test"},
	})
	for _, want := range []string{
		// The main portal keeps its ACL to itself: the panel and controld
		// refuse any change to it outside migrate-domain.
		"acl host_authelia hdr(host) -i auth.example.test\n",
		"acl host_authelia_extra hdr(host) -i aut.other.test login.third.test\n",
		"use_backend authelia_backend if authelia_up host_authelia_extra !path_access_granted",
		"use_backend be_access_granted if host_authelia_extra path_access_granted",
		"remote-user,remote-groups,remote-name,remote-email - if host_authelia_extra path_access_granted\n",
		"src_inc_gpc0(tbl_ip_auth) if host_authelia_extra path_access_granted",
		"http-request redirect scheme https code 301 if host_authelia_extra !acme_challenge_http",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, prefix := range []string{"    acl valid_sni ssl_fc_sni -i ", "    acl valid_host hdr(host) -i "} {
		line := lineWithPrefix(out, prefix)
		for _, portal := range []string{"aut.other.test", "login.third.test"} {
			if !strings.Contains(" "+line+" ", " "+portal+" ") {
				t.Errorf("%s lacks %s: %s", strings.TrimSpace(prefix), portal, line)
			}
		}
	}
	if strings.Count(out, "acl host_authelia_extra hdr(host) -i aut.other.test login.third.test\n") != 2 {
		t.Error("the :80 frontend does not know the portals")
	}
}

func TestWithoutExtraDomainsHAProxyIsRenderedAsBefore(t *testing.T) {
	none := extraDomainsHAProxy(t, nil)
	if empty := extraDomainsHAProxy(t, []any{}); empty != none {
		t.Fatal("an empty list changes haproxy.cfg")
	}
	if !strings.Contains(none, "acl host_authelia hdr(host) -i auth.example.test\n") || strings.Contains(none, "host_authelia_extra") {
		t.Fatal("the main portal's ACL changed")
	}
}

func TestPortalsNeedAutheliaOn(t *testing.T) {
	out := extraDomainsHAProxyWith(t, map[string]any{"authelia_enabled": false,
		"authelia_extra_domains": []any{map[string]any{"domain": "other.test", "portal": "aut.other.test"}}})
	if strings.Contains(out, "aut.other.test") {
		t.Fatal("a portal is routed with Authelia off")
	}
}

func extraDomainsHAProxyWith(t *testing.T, override map[string]any) string {
	t.Helper()
	vars := errExcludeVars(nil)
	for k, v := range override {
		vars[k] = v
	}
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
	out, err := env.Render("haproxy.cfg.j2", vars)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func lineWithPrefix(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// autheliaSessionCookies renders the template's session.cookies part.
func autheliaSessionCookies(t *testing.T, extras any) string {
	t.Helper()
	src := read(t, autheliaConfigTemplate)
	start := strings.Index(src, "  cookies:\n")
	end := strings.Index(src, "{% if authelia_session_redis_enabled")
	if start < 0 || end < start {
		t.Fatal("the session part of configuration.yml.j2 changed shape; update this test")
	}
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.TrimBlocks = true
	env.StrictUndefined = true
	jinja.AddAnsibleFilters(env)
	tmpl, err := env.FromString("cookies", src[start:end]+"# end\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx := map[string]any{
		"authelia_cookie_domain":           "example.test",
		"authelia_portal_url":              "https://aut.example.test",
		"authelia_default_redirection_url": "https://aut.example.test/access_granted",
	}
	if extras != nil {
		ctx["authelia_extra_domains"] = extras
	}
	out, err := env.RenderTemplate(tmpl, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEachExtraDomainBecomesAnAutheliaCookie(t *testing.T) {
	out := autheliaSessionCookies(t, []any{map[string]any{"domain": "other.test", "portal": "aut.other.test"}})
	v, err := pyyaml.Load([]byte(out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cookies, _ := v.(*pyyaml.Map).Value("cookies").([]any)
	if len(cookies) != 2 {
		t.Fatalf("%d cookies:\n%s", len(cookies), out)
	}
	second := cookies[1].(*pyyaml.Map)
	if second.Value("domain") != "other.test" || second.Value("authelia_url") != "https://aut.other.test" ||
		second.Value("default_redirection_url") != "https://aut.other.test/access_granted" {
		t.Fatalf("second cookie:\n%s", out)
	}
	if none := autheliaSessionCookies(t, nil); none != autheliaSessionCookies(t, []any{}) || strings.Count(none, "- domain:") != 1 {
		t.Fatalf("without extra domains:\n%s", none)
	}
}

func TestEachPortalGetsItsAccessGrantedRuleUnlessOneNamesIt(t *testing.T) {
	src := read(t, autheliaConfigTemplate)
	start := strings.Index(src, "{# Access-gate sites need a login rule")
	marker := "| to_nice_yaml(indent=2) | indent(4) }}\n"
	end := strings.Index(src, marker)
	part := src[start:end+len(marker)] + "# end of access_control\n"
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	env.TrimBlocks = true
	env.StrictUndefined = true
	jinja.AddAnsibleFilters(env)
	tmpl, err := env.FromString("access_control", part)
	if err != nil {
		t.Fatal(err)
	}
	render := func(rules []any) []any {
		out, err := env.RenderTemplate(tmpl, map[string]any{
			"authelia_default_policy":       "deny",
			"authelia_access_control_rules": rules,
			"sites":                         []any{},
			"authelia_extra_domains":        []any{map[string]any{"domain": "other.test", "portal": "aut.other.test"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		list, _ := gateTestYAML(t, out).(*pyyaml.Map).Value("access_control").(*pyyaml.Map).Value("rules").([]any)
		return list
	}
	got := render(gateTestYAML(t, "- {domain: ha.example.test, policy: one_factor}\n").([]any))
	if len(got) != 2 {
		t.Fatalf("%d rules", len(got))
	}
	rule := got[1].(*pyyaml.Map)
	res, _ := rule.Value("resources").([]any)
	if rule.Value("domain") != "aut.other.test" || rule.Value("policy") != "one_factor" || len(res) != 1 || res[0] != "^/access_granted/?$" {
		t.Fatalf("portal rule: %v", rule)
	}
	// Once an update has copied the live rule into the managed list, the
	// template adds none: the file renders the same before and after.
	copied := render(gateTestYAML(t, "- {domain: ha.example.test, policy: one_factor}\n"+
		"- {domain: aut.other.test, policy: one_factor, resources: ['^/access_granted/?$']}\n").([]any))
	if len(copied) != 2 {
		t.Fatalf("%d rules after the copy", len(copied))
	}
}
