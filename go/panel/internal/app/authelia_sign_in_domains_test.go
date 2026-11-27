package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const signInVars = `root_domain: example.test
admin_domain: ha.example.test
aut_domain: aut.example.test
authelia_enabled: true
site_defaults:
  certificate_source: internal
`

// signInFixture is a panel config directory plus configd (rules, cookies,
// restarts) and certd stand-ins.
type signInFixture struct {
	*loginFixture
	dir     string
	issued  []string
	setFail string
}

func newSignInFixture(t *testing.T, vars, sites string) *signInFixture {
	t.Helper()
	dir := t.TempDir()
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("vars.yml", vars)
	write("websites.yml", sites)
	f := &signInFixture{loginFixture: newLoginFixture(t, adminRules), dir: dir}
	f.cookies = []any{newMap("domain", "example.test", "authelia_url", "https://aut.example.test",
		"default_redirection_url", "https://aut.example.test/access_granted")}
	base, cfg, web := BaseDir, ConfigYAML, WebsitesYAML
	pending, setCookies, issue, profile := signInPending, autheliaSetCookies, issueSignInPortalCert, signInDNSProfileKnown
	BaseDir, ConfigYAML, WebsitesYAML = dir, filepath.Join(dir, "vars.yml"), filepath.Join(dir, "websites.yml")
	signInPending = func(*Op) (bool, string) { return false, "" }
	autheliaSetCookies = func(cookies []*Map) (bool, string) {
		if f.setFail != "" {
			return false, f.setFail
		}
		f.cookies = nil
		for _, c := range cookies {
			f.cookies = append(f.cookies, c)
		}
		return true, ""
	}
	issueSignInPortalCert = func(d signInDomain, _ *Map, _ bool) *Map {
		f.issued = append(f.issued, d.Portal)
		return newMap("ok", true)
	}
	signInDNSProfileKnown = func(name string) bool { return name == "hetzner" }
	t.Cleanup(func() {
		BaseDir, ConfigYAML, WebsitesYAML = base, cfg, web
		signInPending, autheliaSetCookies, issueSignInPortalCert, signInDNSProfileKnown = pending, setCookies, issue, profile
	})
	return f
}

func (f *signInFixture) vars(t *testing.T) *Map {
	t.Helper()
	m, err := loadYAML(ConfigYAML)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *signInFixture) cookieDomains() []string {
	var out []string
	for _, c := range f.cookies {
		out = append(out, strOrEmpty(get(c, "domain"))+"="+strOrEmpty(get(c, "authelia_url")))
	}
	return out
}

func TestAddingASignInDomainWritesAutheliaTheListAndThePortalRule(t *testing.T) {
	f := newSignInFixture(t, signInVars, "sites: []\n")
	ok, msg, notes := AddSignInDomain(NewOp(), signInRequest{Domain: "Other.Test"})
	if !ok || msg != signInMsgAdded {
		t.Fatalf("ok %v msg %q notes %v", ok, msg, notes)
	}
	if got := strings.Join(f.cookieDomains(), " "); got != "example.test=https://aut.example.test other.test=https://aut.other.test" {
		t.Fatalf("cookies: %s", got)
	}
	extras := signInDomainsFromVars(f.vars(t))
	if len(extras) != 1 || extras[0].Domain != "other.test" || extras[0].Portal != "aut.other.test" || extras[0].CertificateSource != "" {
		t.Fatalf("vars: %+v", extras)
	}
	rules := f.ruleList(t)
	last, _ := asMap(rules[len(rules)-1])
	if !isPortalRule(last, "aut.other.test") || f.restarts != 1 {
		t.Fatalf("rules:\n%s\nrestarts %d", f.rules, f.restarts)
	}
	if len(f.issued) != 1 || f.issued[0] != "aut.other.test" || len(notes) != 1 || notes[0] != signInMsgCertIssued {
		t.Fatalf("internal certificate: issued %v notes %v", f.issued, notes)
	}
	// The site editor's coverage follows the live cookies at once.
	cookies, _ := AutheliaCookieDomains()
	if len(UncoveredNames([]string{"app.other.test"}, cookies)) != 0 {
		t.Fatalf("app.other.test is still uncovered: %v", cookies)
	}
}

func TestTheAddFormsChoicesAreKeptAndChecked(t *testing.T) {
	f := newSignInFixture(t, signInVars, "sites: []\n")
	ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test", Prefix: "login", CertificateSource: "letsencrypt", DNSProfile: "hetzner"})
	if !ok {
		t.Fatal(msg)
	}
	extras := signInDomainsFromVars(f.vars(t))
	if extras[0].Portal != "login.other.test" || extras[0].CertificateSource != "letsencrypt" || extras[0].DNSProfile != "hetzner" {
		t.Fatalf("%+v", extras)
	}
	if len(f.issued) != 0 {
		t.Fatalf("a Let's Encrypt portal is issued on apply, not on add: %v", f.issued)
	}
	for _, req := range []signInRequest{
		{Domain: "third.test", Prefix: "bad_prefix"},
		{Domain: "third.test", CertificateSource: "self"},
		{Domain: "third.test", CertificateSource: "letsencrypt", DNSProfile: "nope"},
		{Domain: "localhost"},
	} {
		if ok, msg, _ := AddSignInDomain(NewOp(), req); ok {
			t.Errorf("%+v was accepted: %s", req, msg)
		}
	}
}

func TestOneSignInDomainCannotContainAnother(t *testing.T) {
	f := newSignInFixture(t, signInVars, "sites: []\n")
	if ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"}); !ok {
		t.Fatal(msg)
	}
	for _, d := range []string{"app.example.test", "app.other.test", "test"} {
		if ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: d}); ok {
			t.Errorf("%s was accepted", d)
		} else if d != "test" && msg != signInErrOverlap {
			t.Errorf("%s: %q", d, msg)
		}
	}
	if len(f.cookies) != 2 {
		t.Fatalf("cookies changed: %v", f.cookieDomains())
	}
}

func TestAPortalNameASiteUsesIsRefused(t *testing.T) {
	f := newSignInFixture(t, signInVars, "sites:\n- {name: shop, domain: aut.other.test, backend_ip: 10.0.0.1}\n")
	ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"})
	if ok || msg != signInErrPortalUsed || len(f.cookies) != 1 {
		t.Fatalf("ok %v msg %q cookies %v", ok, msg, f.cookieDomains())
	}
}

func TestAutheliaRefusingTheCookieSavesNothing(t *testing.T) {
	f := newSignInFixture(t, signInVars, "sites: []\n")
	f.setFail = "Authelia configuration validation failed (rc=1)"
	ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"})
	if ok || !strings.HasPrefix(msg, signInErrAuthelia) {
		t.Fatalf("ok %v msg %q", ok, msg)
	}
	if f.vars(t).Value("authelia_extra_domains") != nil || f.restarts != 0 || len(f.saved) != 0 {
		t.Fatalf("something was saved: restarts %d rules %v", f.restarts, f.saved)
	}
}

func TestNothingIsAddedWhileAutheliaIsOff(t *testing.T) {
	newSignInFixture(t, strings.Replace(signInVars, "authelia_enabled: true", "authelia_enabled: false", 1), "sites: []\n")
	if ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"}); ok || msg != signInErrDisabled {
		t.Fatalf("ok %v msg %q", ok, msg)
	}
}

const signInVarsWithOther = signInVars + `authelia_extra_domains:
- domain: other.test
  portal: aut.other.test
`

func TestADomainMissingFromAutheliaIsWrittenBack(t *testing.T) {
	// A configuration-scope restore brings vars.yml back but not Authelia.
	f := newSignInFixture(t, signInVarsWithOther, "sites: []\n")
	ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"})
	if !ok || msg != signInMsgRepaired || len(f.cookies) != 2 || f.restarts != 1 {
		t.Fatalf("ok %v msg %q cookies %v restarts %d", ok, msg, f.cookieDomains(), f.restarts)
	}
	if n := len(signInDomainsFromVars(f.vars(t))); n != 1 {
		t.Fatalf("%d entries", n)
	}
	// Everything in place: nothing changes, nothing restarts.
	ok, msg, _ = AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"})
	if !ok || msg != signInMsgUnchanged || f.restarts != 1 {
		t.Fatalf("ok %v msg %q restarts %d", ok, msg, f.restarts)
	}
	if ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test", Prefix: "login"}); ok || msg != signInErrOtherPortal {
		t.Fatalf("another portal: ok %v msg %q", ok, msg)
	}
}

func TestADomainWithProtectedSitesIsNotRemoved(t *testing.T) {
	f := newSignInFixture(t, signInVarsWithOther,
		"sites:\n- {name: app, domain: app.other.test, backend_ip: 10.0.0.1, authelia_enabled: true}\n")
	if _, _, _ = AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"}); len(f.cookies) != 2 {
		t.Fatal("setup")
	}
	ok, msg, _ := RemoveSignInDomain(NewOp(), "other.test")
	if ok || !strings.HasPrefix(msg, signInErrInUse) || !strings.Contains(msg, "app.other.test") || len(f.cookies) != 2 {
		t.Fatalf("ok %v msg %q", ok, msg)
	}
}

func TestRemovingASignInDomainTakesItsCookieEntryAndRuleAway(t *testing.T) {
	f := newSignInFixture(t, signInVarsWithOther,
		"sites:\n- {name: app, domain: app.other.test, backend_ip: 10.0.0.1, authelia_enabled: false}\n")
	if ok, msg, _ := AddSignInDomain(NewOp(), signInRequest{Domain: "other.test"}); !ok {
		t.Fatal(msg)
	}
	before := f.restarts
	ok, msg, _ := RemoveSignInDomain(NewOp(), "other.test")
	if !ok || msg != signInMsgRemoved {
		t.Fatalf("ok %v msg %q", ok, msg)
	}
	if len(f.cookies) != 1 || f.vars(t).Value("authelia_extra_domains") != nil || f.restarts != before+1 {
		t.Fatalf("cookies %v vars %v restarts %d", f.cookieDomains(), f.vars(t).Value("authelia_extra_domains"), f.restarts)
	}
	for _, r := range f.ruleList(t) {
		if m, _ := asMap(r); ruleNamesHost(m, "aut.other.test") {
			t.Fatalf("the portal rule stayed:\n%s", f.rules)
		}
	}
	if ok, msg, _ := RemoveSignInDomain(NewOp(), "other.test"); ok || msg != signInErrNotFound {
		t.Fatalf("second removal: ok %v msg %q", ok, msg)
	}
}

func TestARuleEditedByHandIsNotAPortalRule(t *testing.T) {
	portal := newMap("domain", "aut.other.test", "policy", "one_factor", "resources", []any{signInPortalResource})
	if !isPortalRule(portal, "aut.other.test") {
		t.Fatal("the page's own rule")
	}
	for _, r := range []*Map{
		newMap("domain", "aut.other.test", "policy", "two_factor", "resources", []any{signInPortalResource}),
		newMap("domain", []any{"aut.other.test", "x.other.test"}, "policy", "one_factor", "resources", []any{signInPortalResource}),
		newMap("domain", "aut.other.test", "policy", "one_factor", "resources", []any{signInPortalResource}, "subject", []any{"group:a"}),
	} {
		if isPortalRule(r, "aut.other.test") {
			t.Errorf("%v counted as the page's own rule", r)
		}
	}
}

func TestNoSiteMayTakeASignInPortal(t *testing.T) {
	newSignInFixture(t, signInVarsWithOther, "sites: []\n")
	site := newMap("name", "portal", "domain", "x.other.test", "alt_names", []any{"aut.other.test"})
	if got := SiteIdentityConflict(site, nil); got != signInPortalTaken {
		t.Fatalf("%q", got)
	}
	site.Set("paused", true)
	if got := SiteIdentityConflict(site, nil); got != "" {
		t.Fatalf("a paused site serves nothing: %q", got)
	}
}

func TestTheGatewayDefaultDecidesThePortalCertificate(t *testing.T) {
	for _, c := range []struct {
		vars, want string
	}{
		{"site_defaults: {certificate_source: internal}\n", "internal"},
		{"site_defaults: {le_managed: false}\n", "external"},
		{"{}\n", "letsencrypt"},
	} {
		v, _ := loadYAMLText(c.vars)
		if got := signInEffectiveSource(signInDomain{}, v); got != c.want {
			t.Errorf("%s: %s, want %s", c.vars, got, c.want)
		}
		if got := signInEffectiveSource(signInDomain{CertificateSource: "external"}, v); got != "external" {
			t.Errorf("the entry's own choice wins: %s", got)
		}
	}
}

func loadYAMLText(text string) (*Map, error) {
	dir, err := os.MkdirTemp("", "vars")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "vars.yml")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		return nil, err
	}
	return loadYAML(p)
}

// Adding a portal must not look like a change of the protected Authelia
// domain: the template gives the extra portals an ACL of their own.
func TestAnExtraPortalIsNotAChangeOfTheProtectedDomain(t *testing.T) {
	before := "    acl host_admin hdr(host) -i ha.example.test\n    acl host_authelia hdr(host) -i aut.example.test\n"
	after := before + "    acl host_authelia_extra hdr(host) -i aut.other.test\n"
	if err := ValidateControlPlaneTransition(before, after); err != nil {
		t.Fatal(err)
	}
	if checks, err := criticalControlPlaneChecks(after); err != nil || len(checks) != 2 {
		t.Fatalf("%v %v", checks, err)
	}
}
