package app

// Authelia sign-in for an ordinary site. authelia_enabled sends a site's
// visitors to Authelia, but with default_policy: deny nobody gets in until an
// access rule names the site, and Authelia can only check a site whose name
// lies under one of its session cookie domains. The level (one or two
// factors) and the groups live in that access rule alone: the site editor
// reads the rule and writes it, so a change on the access rules page shows in
// the editor and there is no second copy to keep in step.

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/jinja"
	"easy-ha-proxy/panel/shared/pyyaml"
)

const (
	loginStateNone        = "none"        // no rule names the site: it refuses everyone
	loginStateSimple      = "simple"      // one rule of the editor's own shape: editable
	loginStateManaged     = "managed"     // anything else: left to the access rules page
	loginStateUnavailable = "unavailable" // the rules could not be read
)

// Sentences the editor shows for a rule it leaves alone (translated whole).
const (
	loginReasonOptions  = "This site's access rule uses options the site editor does not offer (users, paths, networks, or a bypass or deny policy), so it is managed on the Authelia access rules page."
	loginReasonNames    = "This site's access rule also names other domains, or not all of the site's names, so it is managed on the Authelia access rules page."
	loginReasonMultiple = "More than one access rule covers this site, so its sign-in is managed on the Authelia access rules page."
)

// autheliaConfigView is configd's config_view; a variable for tests.
var autheliaConfigView = func() *Map { return ConfigClient(newMap("action", "config_view"), 5*time.Second) }

// siteLogin is what the editor knows about a site's Authelia sign-in.
type siteLogin struct {
	Names         []string // the site's domain and alternative names, lower case
	State         string
	Policy        string // one_factor or two_factor for a simple rule; the first rule's policy otherwise
	Groups        []string
	Reason        string // why a managed rule is left alone
	Index         int    // the simple rule's position
	CookieDomains []string
	CookiesKnown  bool
	Uncovered     []string // names no session cookie domain covers
}

// AutheliaCookieDomains are the domains Authelia's session cookies are set
// for. ok is false when configd could not say.
func AutheliaCookieDomains() ([]string, bool) {
	resp := autheliaConfigView()
	if resp == nil || !truthy(resp.Value("ok")) {
		return nil, false
	}
	cookies, ok := asList(getNested(resp.Value("config"), "session", "cookies"))
	if !ok {
		return nil, false
	}
	var out []string
	for _, c := range cookies {
		d := strings.Trim(strings.ToLower(strings.TrimSpace(strOrEmpty(get(c, "domain")))), ".")
		if d != "" {
			out = append(out, d)
		}
	}
	return out, len(out) > 0
}

// hostCovered: a cookie for example.com reaches example.com and every name
// under it, at any depth, and nothing else (xexample.com is another domain).
func hostCovered(host string, cookieDomains []string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimPrefix(host, "*.")
	for _, d := range cookieDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// UncoveredNames are the names outside every cookie domain.
func UncoveredNames(names, cookieDomains []string) []string {
	var out []string
	for _, n := range names {
		if !hostCovered(n, cookieDomains) {
			out = append(out, n)
		}
	}
	return out
}

// siteLoginNames are the names a site answers to: its domain and alt_names.
func siteLoginNames(eff *Map) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v any) {
		n := strings.ToLower(strings.TrimSpace(strOrEmpty(v)))
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	add(eff.Value("domain"))
	if alts, ok := asList(eff.Value("alt_names")); ok {
		for _, a := range alts {
			add(a)
		}
	}
	return out
}

// siteLoginApplies: Authelia is consulted for this site.
func siteLoginApplies(eff *Map) bool {
	return eff != nil && truthy(eff.Value("authelia_enabled")) && !truthy(eff.Value("tcp_passthrough")) &&
		eff.Value("access_gate") != true
}

func ruleDomainList(rule *Map) []string {
	v := rule.Value("domain")
	list, ok := asList(v)
	if !ok {
		list = []any{v}
	}
	var out []string
	for _, d := range list {
		if s := strings.ToLower(strings.TrimSpace(strOrEmpty(d))); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ruleCoversHost: the rule's domains name host, by name or wildcard, or its
// domain_regex could match it (a regex that does not compile counts as a
// match: the editor then leaves the site alone rather than guess).
func ruleCoversHost(rule *Map, host string) bool {
	for _, d := range ruleDomainList(rule) {
		if d == host {
			return true
		}
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:]) {
			return true
		}
	}
	if v, has := rule.Get("domain_regex"); has {
		list, ok := asList(v)
		if !ok {
			list = []any{v}
		}
		for _, p := range list {
			re, err := regexp.Compile(strOrEmpty(p))
			if err != nil || re.MatchString(host) {
				return true
			}
		}
	}
	return false
}

// simpleLoginRule reads a rule of the editor's shape: domain, a one or two
// factor policy and, optionally, a flat list of groups.
func simpleLoginRule(rule *Map) (policy string, groups []string, ok bool) {
	for _, k := range rule.Keys() {
		if k != "domain" && k != "policy" && k != "subject" {
			return "", nil, false
		}
	}
	policy = strOrEmpty(rule.Value("policy"))
	if policy != "one_factor" && policy != "two_factor" {
		return "", nil, false
	}
	if subj, has := rule.Get("subject"); has && subj != nil {
		list, isList := asList(subj)
		if !isList {
			list = []any{subj}
		}
		for _, s := range list {
			str, isStr := s.(string)
			if !isStr || !strings.HasPrefix(str, "group:") || strings.TrimPrefix(str, "group:") == "" {
				return "", nil, false
			}
			groups = append(groups, strings.TrimPrefix(str, "group:"))
		}
	}
	return policy, groups, true
}

func sameNameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// analyzeSiteLogin finds the rules that cover any of names. The editor takes a
// site's sign-in over only when exactly one rule covers it and that rule has
// its own shape and names exactly the site's names: with groups, a user
// outside them falls through to later rules, so a second covering rule would
// make the editor's setting a promise it cannot keep.
func analyzeSiteLogin(rules []any, names []string) siteLogin {
	res := siteLogin{Names: names, Index: -1}
	var covering []int
	for i, r := range rules {
		rule, ok := asMap(r)
		if !ok {
			continue
		}
		for _, n := range names {
			if ruleCoversHost(rule, n) {
				covering = append(covering, i)
				break
			}
		}
	}
	if len(covering) == 0 {
		res.State = loginStateNone
		return res
	}
	first, _ := asMap(rules[covering[0]])
	res.Policy = strOrEmpty(first.Value("policy"))
	policy, groups, simple := simpleLoginRule(first)
	switch {
	case !simple:
		res.State, res.Reason = loginStateManaged, loginReasonOptions
	case !sameNameSet(ruleDomainList(first), names):
		res.State, res.Reason = loginStateManaged, loginReasonNames
	case len(covering) > 1:
		res.State, res.Reason = loginStateManaged, loginReasonMultiple
	default:
		res.State, res.Policy, res.Groups, res.Index = loginStateSimple, policy, groups, covering[0]
	}
	return res
}

func loadAutheliaRuleList() ([]any, error) {
	if autheliaLoadRulesYAML == nil {
		return nil, &ValueError{"authelia rules helper unavailable"}
	}
	text, err := autheliaLoadRulesYAML()
	if err != nil {
		return nil, err
	}
	v, err := pyyaml.Load([]byte(text))
	if err != nil {
		return nil, &ValueError{pyYAMLErrorText(err)}
	}
	rules, ok := asList(v)
	if !ok || !truthy(v) {
		rules = []any{}
	}
	return rules, nil
}

// LoadSiteLogin is the editor's view of a site's sign-in.
func LoadSiteLogin(eff *Map) siteLogin {
	names := siteLoginNames(eff)
	res := siteLogin{Names: names, Index: -1}
	rules, err := loadAutheliaRuleList()
	if err != nil {
		res.State = loginStateUnavailable
	} else {
		res = analyzeSiteLogin(rules, names)
	}
	res.CookieDomains, res.CookiesKnown = AutheliaCookieDomains()
	if res.CookiesKnown {
		res.Uncovered = UncoveredNames(names, res.CookieDomains)
	}
	return res
}

// siteLoginRequest is the editor's authelia_login: the level and the groups.
type siteLoginRequest struct {
	Policy string
	Groups []string
}

var loginGroupName = regexp.MustCompile(`^[^\s,:]{1,128}$`)

// parseSiteLoginRequest reads authelia_login from a save; nil when absent.
func parseSiteLoginRequest(v any) (*siteLoginRequest, string) {
	if v == nil {
		return nil, ""
	}
	m, ok := asMap(v)
	if !ok {
		return nil, "authelia_login must be an object"
	}
	req := &siteLoginRequest{Policy: strOrEmpty(m.Value("policy"))}
	if req.Policy != "one_factor" && req.Policy != "two_factor" {
		return nil, "The Authelia sign-in level must be one_factor or two_factor"
	}
	var raw []any
	switch g := m.Value("groups").(type) {
	case nil:
	case string:
		for _, part := range strings.Split(g, ",") {
			raw = append(raw, part)
		}
	default:
		list, isList := asList(g)
		if !isList {
			return nil, "Authelia groups must be a list of names"
		}
		raw = list
	}
	seen := map[string]bool{}
	for _, item := range raw {
		s, isStr := item.(string)
		if !isStr {
			return nil, "Authelia groups must be a list of names"
		}
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if !loginGroupName.MatchString(s) {
			return nil, "An Authelia group name cannot contain spaces, commas or colons and is at most 128 characters long"
		}
		seen[s] = true
		req.Groups = append(req.Groups, s)
	}
	if len(req.Groups) > 50 {
		return nil, "At most 50 Authelia groups can be named for a site"
	}
	return req, ""
}

func buildSiteLoginRule(names []string, req siteLoginRequest) *Map {
	var domain any = names[0]
	if len(names) > 1 {
		list := make([]any, len(names))
		for i, n := range names {
			list[i] = n
		}
		domain = list
	}
	rule := newMap("domain", domain, "policy", req.Policy)
	if len(req.Groups) > 0 {
		subj := make([]any, len(req.Groups))
		for i, g := range req.Groups {
			subj[i] = "group:" + g
		}
		rule.Set("subject", subj)
	}
	return rule
}

// Outcomes of a rule change, shown after the save message (each translated whole).
const (
	loginRuleAdded     = "An Authelia access rule now lets this site's users sign in; Authelia was restarted to load it."
	loginRuleUpdated   = "The site's Authelia access rule was updated; Authelia was restarted to load it."
	loginRuleRemoved   = "The site's Authelia access rule was removed; Authelia was restarted to load the change."
	loginRuleManaged   = "The site's Authelia access rule is managed on the Authelia access rules page and was left as it is."
	loginRuleNoRestart = "The site's Authelia access rule was saved, but Authelia could not be restarted to load it; restart it on the Authelia settings page."
)

func saveAutheliaRulesAndRestart(op *Op, rules []any, done string) string {
	if autheliaSaveRulesFromYAML == nil || autheliaConfigdRequest == nil {
		return "The site's Authelia access rule could not be changed: the Authelia rules helper is unavailable."
	}
	if ok, msg := autheliaSaveRulesFromYAML(op, dumpYAML(rules)); !ok {
		return "The site's Authelia access rule could not be changed: " + msg
	}
	restart, err := autheliaConfigdRequest(newMap("action", "restart"))
	if err != nil || !truthy(restart.Value("ok")) {
		return loginRuleNoRestart
	}
	return done
}

// EnsureSiteLoginRule gives the site the rule req asks for; with req nil it
// keeps a rule the site already has and otherwise adds one_factor for every
// user. A managed rule is never touched. "" means nothing had to change.
func EnsureSiteLoginRule(op *Op, names []string, req *siteLoginRequest) string {
	if len(names) == 0 {
		return ""
	}
	rules, err := loadAutheliaRuleList()
	if err != nil {
		return "The site's Authelia access rule could not be read: " + err.Error()
	}
	state := analyzeSiteLogin(rules, names)
	switch state.State {
	case loginStateManaged:
		if req != nil && (req.Policy != state.Policy || len(req.Groups) > 0) {
			return loginRuleManaged
		}
		return ""
	case loginStateSimple:
		if req == nil || (req.Policy == state.Policy && sameNameSet(req.Groups, state.Groups)) {
			return ""
		}
		rules = append([]any{}, rules...)
		rules[state.Index] = buildSiteLoginRule(names, *req)
		return saveAutheliaRulesAndRestart(op, rules, loginRuleUpdated)
	default:
		want := siteLoginRequest{Policy: "one_factor"}
		if req != nil {
			want = *req
		}
		rules = append(append([]any{}, rules...), buildSiteLoginRule(names, want))
		return saveAutheliaRulesAndRestart(op, rules, loginRuleAdded)
	}
}

// RemoveSiteLoginRule drops the site's rule when it is of the editor's own
// shape; a rule edited into anything else stays.
func RemoveSiteLoginRule(op *Op, names []string) string {
	if len(names) == 0 {
		return ""
	}
	rules, err := loadAutheliaRuleList()
	if err != nil {
		return "The site's Authelia access rule could not be read: " + err.Error()
	}
	state := analyzeSiteLogin(rules, names)
	if state.State != loginStateSimple {
		return ""
	}
	rules = append(append([]any{}, rules[:state.Index]...), rules[state.Index+1:]...)
	return saveAutheliaRulesAndRestart(op, rules, loginRuleRemoved)
}

// loginRefusal is the save's answer when Authelia would be turned on for a
// name it cannot check; "" when the save may go ahead. A site already in that
// state with the same names may still be saved (an unrelated edit must not
// be held hostage by it); the editor and the site list say what is wrong.
const loginUncoveredError = "Authelia cannot protect this site: its sign-in covers only the domains in the Authelia settings, and at least one of the site's names is outside them. Turn Authelia off for this site, or serve it under a domain Authelia covers."

func loginRefusal(before, after *Map) string {
	if !siteLoginApplies(after) {
		return ""
	}
	cookies, known := AutheliaCookieDomains()
	if !known {
		return ""
	}
	names := siteLoginNames(after)
	if len(UncoveredNames(names, cookies)) == 0 {
		return ""
	}
	if siteLoginApplies(before) && sameNameSet(siteLoginNames(before), names) {
		return ""
	}
	return loginUncoveredError
}

// SyncSiteLoginAfterSave changes the access rule to match a saved site:
// before and after are the site's effective settings (before nil for a new
// site), req the editor's authelia_login. The result is a sentence for the
// answer's detail, "" when no rule changed.
func SyncSiteLoginAfterSave(op *Op, before, after *Map, req *siteLoginRequest) string {
	wasOn, isOn := siteLoginApplies(before), siteLoginApplies(after)
	switch {
	case !wasOn && !isOn:
		return ""
	case !isOn:
		return RemoveSiteLoginRule(op, siteLoginNames(before))
	}
	oldNames, newNames := siteLoginNames(before), siteLoginNames(after)
	if wasOn && !sameNameSet(oldNames, newNames) {
		// Renamed: carry the site's own rule over to the new names where it
		// stands, keeping its level and groups unless the editor sent others.
		rules, err := loadAutheliaRuleList()
		if err != nil {
			return "The site's Authelia access rule could not be read: " + err.Error()
		}
		if old := analyzeSiteLogin(rules, oldNames); old.State == loginStateSimple {
			want := siteLoginRequest{Policy: old.Policy, Groups: old.Groups}
			if req != nil {
				want = *req
			}
			rules = append([]any{}, rules...)
			rules[old.Index] = buildSiteLoginRule(newNames, want)
			return saveAutheliaRulesAndRestart(op, rules, loginRuleUpdated)
		}
	}
	return EnsureSiteLoginRule(op, newNames, req)
}

// siteLoginView is what templates get.
func (s siteLogin) view(mailRelay bool, knownGroups []any) map[string]any {
	groups := make([]any, len(s.Groups))
	for i, g := range s.Groups {
		groups[i] = g
	}
	cookies := make([]any, len(s.CookieDomains))
	for i, d := range s.CookieDomains {
		cookies[i] = d
	}
	uncovered := make([]any, len(s.Uncovered))
	for i, d := range s.Uncovered {
		uncovered[i] = d
	}
	policy := s.Policy
	if policy != "two_factor" {
		policy = "one_factor"
	}
	return map[string]any{
		"state": s.State, "editable": s.State == loginStateNone || s.State == loginStateSimple,
		"policy": policy, "groups": groups, "reason": s.Reason, "cookie_domains": cookies,
		"uncovered": uncovered, "mail_relay": mailRelay, "known_groups": knownGroups,
	}
}

// autheliaMailRelay: Authelia sends mail out (relay mode), rather than
// writing it to a file nobody reads.
func autheliaMailRelay() bool {
	settings, err := loadMailSettings()
	if err != nil {
		return false
	}
	return strOrEmpty(getNested(settings, "settings", "mode")) == "relay"
}

// EffectiveSiteSettings is a site merged over site_defaults, as the editor
// and HAProxy see it.
func EffectiveSiteSettings(site *Map) (*Map, error) {
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, err
	}
	defaults, ok := asMap(orValue(cv.Value("site_defaults"), pyyaml.NewMap()))
	if !ok {
		defaults = pyyaml.NewMap()
	}
	effV, err := jinja.CombineFilter(nil, defaults, []any{site}, newMap("recursive", true))
	if err != nil {
		return nil, err
	}
	eff, ok := effV.(*Map)
	if !ok {
		return nil, &ValueError{"the site's effective settings are not a mapping"}
	}
	return eff, nil
}

// loginNoteOK: the note reports a rule change that went through.
func loginNoteOK(note string) bool {
	return note == loginRuleAdded || note == loginRuleUpdated || note == loginRuleRemoved
}

// siteLoginForEditor is the editor's sign-in block: the rule, the cookie
// domains, whether mail goes out, and the groups Authelia knows.
func siteLoginForEditor(eff *Map) map[string]any {
	_, groups, _ := GetAutheliaUsers()
	if groups == nil {
		groups = []any{}
	}
	return LoadSiteLogin(eff).view(autheliaMailRelay(), groups)
}

// splitRuleDomains reads the access rules page's domain field: names
// separated by commas.
func splitRuleDomains(text string) []string {
	var out []string
	for _, part := range strings.Split(text, ",") {
		if d := strings.ToLower(strings.TrimSpace(part)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// annotateSiteLoginIssues marks, for the site list, each site that sends
// visitors to Authelia but cannot let anyone in: login_issue is "uncovered"
// (no session cookie domain covers it) or "no_rule" (no access rule names
// it). configd is asked only when some site uses Authelia.
func annotateSiteLoginIssues(items []any) {
	var rules []any
	var rulesErr error
	var cookies []string
	var cookiesKnown, asked bool
	for _, it := range items {
		item, ok := asMap(it)
		if !ok {
			continue
		}
		eff, _ := asMap(item.Value("effective"))
		if !siteLoginApplies(eff) {
			continue
		}
		if !asked {
			asked = true
			rules, rulesErr = loadAutheliaRuleList()
			cookies, cookiesKnown = AutheliaCookieDomains()
		}
		names := siteLoginNames(eff)
		switch {
		case cookiesKnown && len(UncoveredNames(names, cookies)) > 0:
			item.Set("login_issue", "uncovered")
		case rulesErr == nil && analyzeSiteLogin(rules, names).State == loginStateNone:
			item.Set("login_issue", "no_rule")
		}
	}
}
