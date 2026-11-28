package app

import (
	"strings"
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// loginFixture stands in for configd: the live rules, what was saved, and
// whether Authelia was restarted.
type loginFixture struct {
	rules    string
	saved    []string
	restarts int
	cookies  []any
}

func newLoginFixture(t *testing.T, rules string, cookies ...string) *loginFixture {
	t.Helper()
	f := &loginFixture{rules: rules}
	for _, c := range cookies {
		f.cookies = append(f.cookies, newMap("domain", c))
	}
	load, save, configd, view := autheliaLoadRulesYAML, autheliaSaveRulesFromYAML, autheliaConfigdRequest, autheliaConfigView
	autheliaLoadRulesYAML = func() (string, error) { return f.rules, nil }
	autheliaSaveRulesFromYAML = func(op *Op, text string) (bool, string) {
		f.saved = append(f.saved, text)
		f.rules = text
		return true, "saved"
	}
	autheliaConfigdRequest = func(p *Map) (*Map, error) {
		if p.Value("action") == "restart" {
			f.restarts++
		}
		return newMap("ok", true), nil
	}
	autheliaConfigView = func() *Map {
		if f.cookies == nil {
			return newMap("ok", false, "error", "configd is down")
		}
		return newMap("ok", true, "config", newMap("session", newMap("cookies", f.cookies)))
	}
	t.Cleanup(func() {
		autheliaLoadRulesYAML, autheliaSaveRulesFromYAML, autheliaConfigdRequest, autheliaConfigView = load, save, configd, view
	})
	return f
}

func (f *loginFixture) ruleList(t *testing.T) []any {
	t.Helper()
	v, err := pyyaml.Load([]byte(f.rules))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := asList(v)
	return list
}

func loginRules(t *testing.T, text string) []any {
	t.Helper()
	v, err := pyyaml.Load([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := asList(v)
	return list
}

const adminRules = `
- domain: ha.example.test
  policy: one_factor
  subject: ['group:admins']
- domain: aut.example.test
  policy: one_factor
  resources: ['^/access_granted/?$']
`

func siteEff(domain string, on bool, alts ...string) *Map {
	m := newMap("name", domain, "domain", domain, "authelia_enabled", on)
	if len(alts) > 0 {
		list := make([]any, len(alts))
		for i, a := range alts {
			list[i] = a
		}
		m.Set("alt_names", list)
	}
	return m
}

func TestTheSessionCookieCoversItsDomainAndEveryNameUnderIt(t *testing.T) {
	cookies := []string{"example.test"}
	for host, want := range map[string]bool{
		"example.test": true, "app.example.test": true, "a.b.example.test": true, "*.example.test": true,
		"APP.Example.Test.": true, "xexample.test": false, "example.test.evil": false, "other.test": false,
	} {
		if got := hostCovered(host, cookies); got != want {
			t.Errorf("%s covered = %v, want %v", host, got, want)
		}
	}
	if got := UncoveredNames([]string{"app.example.test", "app.other.test"}, cookies); len(got) != 1 || got[0] != "app.other.test" {
		t.Fatalf("uncovered %v", got)
	}
}

func TestTheCookieDomainsComeFromTheLiveAutheliaSettings(t *testing.T) {
	newLoginFixture(t, adminRules, ".Example.Test", "second.test")
	got, ok := AutheliaCookieDomains()
	if !ok || strings.Join(got, ",") != "example.test,second.test" {
		t.Fatalf("cookie domains %v %v", got, ok)
	}
	newLoginFixture(t, adminRules)
	if _, ok := AutheliaCookieDomains(); ok {
		t.Fatal("a configd failure must read as unknown, not as no domains")
	}
}

func TestASiteWithoutARuleIsNoneAndEditable(t *testing.T) {
	got := analyzeSiteLogin(loginRules(t, adminRules), []string{"app.example.test"})
	if got.State != loginStateNone {
		t.Fatalf("state %s", got.State)
	}
}

func TestTheEditorReadsARuleOfItsOwnShape(t *testing.T) {
	rules := loginRules(t, adminRules+`
- domain: [www.example.test, app.example.test]
  policy: two_factor
  subject: ['group:staff', 'group:admins']
`)
	got := analyzeSiteLogin(rules, []string{"app.example.test", "www.example.test"})
	if got.State != loginStateSimple || got.Policy != "two_factor" || strings.Join(got.Groups, ",") != "staff,admins" || got.Index != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestTheEditorLeavesOtherRulesToTheAccessRulesPage(t *testing.T) {
	names := []string{"app.example.test"}
	for name, tc := range map[string]struct{ rules, reason string }{
		"paths":       {"- {domain: app.example.test, policy: one_factor, resources: ['^/x']}", loginReasonOptions},
		"users":       {"- {domain: app.example.test, policy: one_factor, subject: ['user:bob']}", loginReasonOptions},
		"and-groups":  {"- {domain: app.example.test, policy: one_factor, subject: [['group:a', 'group:b']]}", loginReasonOptions},
		"bypass":      {"- {domain: app.example.test, policy: bypass}", loginReasonOptions},
		"deny":        {"- {domain: app.example.test, policy: deny}", loginReasonOptions},
		"other names": {"- {domain: [app.example.test, b.example.test], policy: one_factor}", loginReasonNames},
		"wildcard first": {"- {domain: '*.example.test', policy: one_factor}\n- {domain: app.example.test, policy: two_factor}",
			loginReasonNames},
		"second rule": {"- {domain: app.example.test, policy: one_factor}\n- {domain: '*.example.test', policy: one_factor}",
			loginReasonMultiple},
		"regex": {"- {domain_regex: '^app\\.', policy: one_factor}", loginReasonOptions},
	} {
		got := analyzeSiteLogin(loginRules(t, tc.rules), names)
		if got.State != loginStateManaged || got.Reason != tc.reason {
			t.Errorf("%s: %+v, want managed with %q", name, got, tc.reason)
		}
	}
}

func TestTheLoginRequestIsChecked(t *testing.T) {
	req, msg := parseSiteLoginRequest(newMap("policy", "two_factor", "groups", " admins, staff ,admins,"))
	if msg != "" || req.Policy != "two_factor" || strings.Join(req.Groups, ",") != "admins,staff" {
		t.Fatalf("%+v %q", req, msg)
	}
	if req, msg := parseSiteLoginRequest(nil); req != nil || msg != "" {
		t.Fatal("an absent authelia_login is no request")
	}
	for _, bad := range []*Map{newMap("policy", "bypass"), newMap("policy", "one_factor", "groups", []any{"a b"}),
		newMap("policy", "one_factor", "groups", []any{"a:b"}), newMap("policy", "one_factor", "groups", []any{int64(3)})} {
		if _, msg := parseSiteLoginRequest(bad); msg == "" {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestSavingASiteWithAutheliaAddsAOneFactorRuleForEveryone(t *testing.T) {
	f := newLoginFixture(t, adminRules, "example.test")
	note := SyncSiteLoginAfterSave(nil, nil, siteEff("app.example.test", true), nil)
	if note != loginRuleAdded || f.restarts != 1 {
		t.Fatalf("note %q restarts %d", note, f.restarts)
	}
	rules := f.ruleList(t)
	last, _ := asMap(rules[len(rules)-1])
	if len(rules) != 3 || last.Value("domain") != "app.example.test" || last.Value("policy") != "one_factor" || last.Value("subject") != nil {
		t.Fatalf("rules:\n%s", f.rules)
	}
}

func TestTheEditorsLevelAndGroupsBecomeTheRule(t *testing.T) {
	f := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: one_factor}\n", "example.test")
	req := &siteLoginRequest{Policy: "two_factor", Groups: []string{"staff"}}
	before, after := siteEff("app.example.test", true), siteEff("app.example.test", true)
	if note := SyncSiteLoginAfterSave(nil, before, after, req); note != loginRuleUpdated {
		t.Fatalf("note %q", note)
	}
	got := analyzeSiteLogin(f.ruleList(t), []string{"app.example.test"})
	if got.State != loginStateSimple || got.Policy != "two_factor" || strings.Join(got.Groups, ",") != "staff" || got.Index != 2 {
		t.Fatalf("got %+v\n%s", got, f.rules)
	}
	// Saving the same again changes nothing and restarts nothing.
	if note := SyncSiteLoginAfterSave(nil, before, after, req); note != "" || f.restarts != 1 || len(f.saved) != 1 {
		t.Fatalf("second save: %q, %d restarts, %d saves", note, f.restarts, len(f.saved))
	}
}

func TestASaveWithoutTheLoginFieldsKeepsTheRule(t *testing.T) {
	f := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: two_factor, subject: ['group:staff']}\n", "example.test")
	if note := SyncSiteLoginAfterSave(nil, siteEff("app.example.test", true), siteEff("app.example.test", true), nil); note != "" || len(f.saved) != 0 {
		t.Fatalf("note %q, saves %d", note, len(f.saved))
	}
}

func TestTheEditorNeverRewritesAManagedRule(t *testing.T) {
	rules := adminRules + "- {domain: app.example.test, policy: one_factor, resources: ['^/api']}\n"
	f := newLoginFixture(t, rules, "example.test")
	req := &siteLoginRequest{Policy: "two_factor"}
	if note := SyncSiteLoginAfterSave(nil, siteEff("app.example.test", true), siteEff("app.example.test", true), req); note != loginRuleManaged {
		t.Fatalf("note %q", note)
	}
	if len(f.saved) != 0 || f.restarts != 0 {
		t.Fatal("a managed rule was rewritten")
	}
}

func TestTurningAutheliaOffRemovesTheSitesOwnRuleOnly(t *testing.T) {
	f := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: one_factor}\n", "example.test")
	if note := SyncSiteLoginAfterSave(nil, siteEff("app.example.test", true), siteEff("app.example.test", false), nil); note != loginRuleRemoved {
		t.Fatalf("note %q", note)
	}
	if got := len(f.ruleList(t)); got != 2 {
		t.Fatalf("%d rules left:\n%s", got, f.rules)
	}
	g := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: one_factor, resources: ['^/x']}\n", "example.test")
	if note := SyncSiteLoginAfterSave(nil, siteEff("app.example.test", true), siteEff("app.example.test", false), nil); note != "" || len(g.saved) != 0 {
		t.Fatalf("a managed rule was removed: %q", note)
	}
}

func TestAPassthroughSiteIsNotAnAutheliaSite(t *testing.T) {
	f := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: one_factor}\n", "example.test")
	after := siteEff("app.example.test", true)
	after.Set("tcp_passthrough", true)
	if note := SyncSiteLoginAfterSave(nil, siteEff("app.example.test", true), after, nil); note != loginRuleRemoved || len(f.ruleList(t)) != 2 {
		t.Fatalf("note %q\n%s", note, f.rules)
	}
}

func TestARenamedSiteTakesItsRuleAlongInPlace(t *testing.T) {
	f := newLoginFixture(t, adminRules+"- {domain: app.example.test, policy: two_factor, subject: ['group:staff']}\n- {domain: z.example.test, policy: one_factor}\n", "example.test")
	before, after := siteEff("app.example.test", true), siteEff("app.example.test", true, "www.example.test")
	if note := SyncSiteLoginAfterSave(nil, before, after, nil); note != loginRuleUpdated || f.restarts != 1 {
		t.Fatalf("note %q restarts %d", note, f.restarts)
	}
	got := analyzeSiteLogin(f.ruleList(t), []string{"app.example.test", "www.example.test"})
	if got.State != loginStateSimple || got.Index != 2 || got.Policy != "two_factor" || strings.Join(got.Groups, ",") != "staff" {
		t.Fatalf("got %+v\n%s", got, f.rules)
	}
}

func TestAutheliaCannotBeTurnedOnForANameItCannotCheck(t *testing.T) {
	newLoginFixture(t, adminRules, "example.test")
	if got := loginRefusal(nil, siteEff("app.other.test", true)); got != loginUncoveredError {
		t.Fatalf("refusal %q", got)
	}
	if got := loginRefusal(siteEff("app.example.test", true), siteEff("app.example.test", true, "www.other.test")); got != loginUncoveredError {
		t.Fatal("adding an uncovered alias must be refused")
	}
	if got := loginRefusal(nil, siteEff("app.example.test", true)); got != "" {
		t.Fatalf("a covered name was refused: %q", got)
	}
	if got := loginRefusal(nil, siteEff("app.other.test", false)); got != "" {
		t.Fatal("a site without Authelia was refused")
	}
	// An unrelated edit of a site already in that state goes through.
	if got := loginRefusal(siteEff("app.other.test", true), siteEff("app.other.test", true)); got != "" {
		t.Fatalf("an existing site was held hostage: %q", got)
	}
	// configd cannot say: no refusal on a guess.
	newLoginFixture(t, adminRules)
	if got := loginRefusal(nil, siteEff("app.other.test", true)); got != "" {
		t.Fatalf("refused without knowing the cookie domains: %q", got)
	}
}

func TestTheSiteListMarksSitesNobodyCanEnter(t *testing.T) {
	newLoginFixture(t, adminRules+"- {domain: ok.example.test, policy: one_factor}\n", "example.test")
	items := []any{
		newMap("effective", siteEff("ok.example.test", true)),
		newMap("effective", siteEff("norule.example.test", true)),
		newMap("effective", siteEff("app.other.test", true)),
		newMap("effective", siteEff("off.example.test", false)),
	}
	annotateSiteLoginIssues(items)
	want := []any{nil, "no_rule", "uncovered", nil}
	for i, it := range items {
		if got := it.(*Map).Value("login_issue"); got != want[i] {
			t.Errorf("site %d: login_issue %v, want %v", i, got, want[i])
		}
	}
}
