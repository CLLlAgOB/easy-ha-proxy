package app

// Extra Authelia sign-in domains. A browser sends a cookie only to the
// registrable domain it was set for, so Authelia, whose one session cookie is
// for the root domain, can check no site under any other domain. Each extra
// sign-in domain is one more session cookie domain with a portal of its own
// (aut.<domain> by default): its sites sign in there. Users, passwords and
// second factors are the same; the sign-in is not shared across domains.
//
// vars.yml authelia_extra_domains is the list: the HAProxy template routes
// the portals from it, the agent renders the Authelia cookies and issues the
// certificate names from it, and an update carries it into the managed
// configuration. Adding or removing a domain here also writes Authelia's live
// session cookies and the portal's /access_granted rule through configd, so
// the change takes effect without waiting for an update.

import (
	"context"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const signInPortalResource = "^/access_granted/?$"

var signInPrefixRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// signInDomain is one entry of authelia_extra_domains.
type signInDomain struct {
	Domain            string
	Portal            string
	CertificateSource string // "" follows the gateway's default
	DNSProfile        string
}

func (d signInDomain) entry() *Map {
	m := newMap("domain", d.Domain, "portal", d.Portal)
	if d.CertificateSource != "" {
		m.Set("certificate_source", d.CertificateSource)
	}
	if d.DNSProfile != "" {
		m.Set("dns_profile", d.DNSProfile)
	}
	return m
}

func (d signInDomain) cookie() *Map {
	return newMap("domain", d.Domain, "authelia_url", "https://"+d.Portal,
		"default_redirection_url", "https://"+d.Portal+"/access_granted")
}

func signInDomainsFromVars(vars *Map) []signInDomain {
	var out []signInDomain
	list, _ := asList(vars.Value("authelia_extra_domains"))
	for _, it := range list {
		m, ok := asMap(it)
		if !ok {
			continue
		}
		d := signInDomain{Domain: strings.ToLower(strOrEmpty(m.Value("domain"))), Portal: strings.ToLower(strOrEmpty(m.Value("portal"))),
			CertificateSource: strOrEmpty(m.Value("certificate_source")), DNSProfile: strOrEmpty(m.Value("dns_profile"))}
		if d.Domain != "" && d.Portal != "" {
			out = append(out, d)
		}
	}
	return out
}

// signInPortals are the portal names of the extra sign-in domains, which no
// site may take; a variable for tests.
var signInPortals = func() map[string]bool {
	out := map[string]bool{}
	vars, err := loadYAML(ConfigYAML)
	if err != nil || vars == nil {
		return out
	}
	for _, d := range signInDomainsFromVars(vars) {
		out[d.Portal] = true
	}
	return out
}

// signInPortalConflict is the site save's answer when one of a site's names
// is a sign-in portal ("" when none is).
const signInPortalTaken = "This name is the Authelia sign-in portal of an extra sign-in domain, so no site can use it."

func signInPortalConflict(site *Map) string {
	if site.Value("paused") == true {
		return ""
	}
	portals := signInPortals()
	for n := range routingNames(site) {
		if portals[n] {
			return signInPortalTaken
		}
	}
	return ""
}

func domainsOverlap(a, b string) bool {
	a, b = strings.Trim(strings.ToLower(a), "."), strings.Trim(strings.ToLower(b), ".")
	return a != "" && b != "" && (a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a))
}

// liveCookies are Authelia's session cookies as configd reads them now.
func liveCookies() ([]*Map, bool) {
	resp := autheliaConfigView()
	if resp == nil || !truthy(resp.Value("ok")) {
		return nil, false
	}
	list, ok := asList(getNested(resp.Value("config"), "session", "cookies"))
	if !ok {
		return nil, false
	}
	var out []*Map
	for _, it := range list {
		if m, ok := asMap(it); ok {
			out = append(out, copyMap(m))
		}
	}
	return out, len(out) > 0
}

func cookieDomain(c *Map) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(strOrEmpty(c.Value("domain")))), ".")
}

// cookieMatches: Authelia has the cookie this entry asks for.
func cookieMatches(cookies []*Map, d signInDomain) bool {
	for _, c := range cookies {
		if cookieDomain(c) == d.Domain {
			return strings.TrimRight(strOrEmpty(c.Value("authelia_url")), "/") == "https://"+d.Portal
		}
	}
	return false
}

// autheliaSetCookies writes Authelia's session cookie list.
var autheliaSetCookies = func(cookies []*Map) (bool, string) {
	list := make([]any, len(cookies))
	for i, c := range cookies {
		list[i] = c
	}
	resp := ConfigClient(newMap("action", "settings_update", "config", newMap("session", newMap("cookies", list))), 90*time.Second)
	if !truthy(resp.Value("ok")) {
		return false, pyStr(orValue(resp.Value("error"), "unknown error"))
	}
	return true, ""
}

// isPortalRule: the rule this page adds for a portal, and nothing more.
func isPortalRule(rule *Map, portal string) bool {
	if rule == nil || rule.Len() != 3 || strOrEmpty(rule.Value("policy")) != "one_factor" {
		return false
	}
	names := ruleDomainList(rule)
	if len(names) != 1 || names[0] != portal {
		return false
	}
	res, ok := asList(rule.Value("resources"))
	return ok && len(res) == 1 && strOrEmpty(res[0]) == signInPortalResource
}

func ruleNamesHost(rule *Map, host string) bool {
	for _, n := range ruleDomainList(rule) {
		if n == host {
			return true
		}
	}
	return false
}

// Sentences of this page, each translated whole.
const (
	signInMsgAdded        = "The sign-in domain was added to Authelia, and Authelia was restarted. Create the DNS record shown for its portal, then apply the HAProxy configuration: that routes the portal and issues its certificate."
	signInMsgRepaired     = "The sign-in domain was written to Authelia again, and Authelia was restarted."
	signInMsgUnchanged    = "This sign-in domain is already in place; nothing had to change."
	signInMsgRemoved      = "The sign-in domain was removed from Authelia, and Authelia was restarted. Apply the HAProxy configuration to stop routing its portal."
	signInMsgNoRestart    = "The change was saved, but Authelia could not be restarted to load it; restart it with the button above."
	signInMsgRuleFailed   = "The portal's access rule could not be written; add a one_factor rule for its /access_granted page on the Authelia access rules page."
	signInMsgCertIssued   = "The portal's certificate was issued."
	signInMsgCertFailed   = "The portal's certificate could not be issued yet; it is issued when the HAProxy configuration is applied, or with the Issue certificate button."
	signInErrDisabled     = "Authelia is turned off on this gateway, so there is nothing to sign in to."
	signInErrNoPortal     = "This gateway has no Authelia portal (aut_domain), so no sign-in domain can be added."
	signInErrCookies      = "Authelia's session cookies could not be read, so nothing was changed."
	signInErrDomain       = "Enter a domain with at least two labels, for example example.org."
	signInErrPrefix       = "The portal name prefix must be one DNS label: letters, digits and hyphens."
	signInErrOverlap      = "Authelia already covers this domain, or one of its domains lies under it: one sign-in domain cannot contain another."
	signInErrOtherPortal  = "This domain is already a sign-in domain with another portal name; remove it first to change the portal."
	signInErrPortalUsed   = "The portal name is already used by a site, the panel or the main Authelia portal."
	signInErrSource       = "The certificate source must be Let's Encrypt, the internal CA or an external certificate."
	signInErrProfile      = "The DNS profile does not exist."
	signInErrTooMany      = "At most 50 extra sign-in domains can be added."
	signInErrNotFound     = "This sign-in domain is not in the list."
	signInErrInUse        = "Sites on this domain still send their visitors to Authelia; turn Authelia off for them, or move them, before removing the sign-in domain:"
	signInErrAuthelia     = "Authelia refused the change, so nothing was saved:"
	signInErrVarsWrite    = "The sign-in domain list could not be saved, so Authelia was put back as it was:"
	signInErrPortalSource = "The portal uses an external certificate: upload it on the certificates page."
)

func signInEffectiveSource(d signInDomain, vars *Map) string {
	if d.CertificateSource != "" {
		return d.CertificateSource
	}
	sd, _ := asMap(vars.Value("site_defaults"))
	if sd != nil {
		if s := strOrEmpty(sd.Value("certificate_source")); s == "letsencrypt" || s == "internal" || s == "external" {
			return s
		}
		if le, has := sd.Get("le_managed"); has && !truthy(le) {
			return "external"
		}
	}
	return "letsencrypt"
}

// issueSignInPortalCert issues the portal's certificate when it is missing
// or expired (or an internal one is close to its end).
var issueSignInPortalCert = func(d signInDomain, vars *Map, force bool) *Map {
	source := signInEffectiveSource(d, vars)
	state := CertStatusForSite(newMap("domain", d.Portal)).Value("state")
	if !force && state != "missing" && state != "expired" && !(source == "internal" && state == "warning") {
		return nil
	}
	switch source {
	case "internal":
		return CertdIssueInternal(d.Portal, nil)
	case "letsencrypt":
		return CertdIssue(d.Portal, nil, nil, d.DNSProfile, nil)
	}
	return newMap("ok", false, "error", signInErrPortalSource)
}

// signInPortalCertsBeforeApply issues the portals' missing certificates
// before an apply. A failure never stops the apply: a portal whose DNS is not
// there yet must not hold every other change back; the settings page shows
// the certificate's state.
func signInPortalCertsBeforeApply() []any {
	vars, err := loadYAML(ConfigYAML)
	if err != nil || vars == nil || !autheliaOn(vars) {
		return nil
	}
	var actions []any
	for _, d := range signInDomainsFromVars(vars) {
		if res := issueSignInPortalCert(d, vars, false); res != nil {
			actions = append(actions, newMap("domain", d.Portal, "result", res, "blocking", false))
		}
	}
	return actions
}

func autheliaOn(vars *Map) bool {
	v, has := vars.Get("authelia_enabled")
	return !has || truthy(v)
}

// signInRequest is the add form.
type signInRequest struct {
	Domain, Prefix, CertificateSource, DNSProfile string
}

func dnsProfileKnown(name string) bool {
	for _, p := range availableDNSProfiles() {
		if strings.EqualFold(strOrEmpty(get(p, "name")), name) {
			return true
		}
	}
	return false
}

var signInDNSProfileKnown = dnsProfileKnown

// AddSignInDomain adds an extra sign-in domain, or writes one already in the
// list back into Authelia. It answers ok, the message and further notes.
func AddSignInDomain(op *Op, req signInRequest) (bool, string, []string) {
	if pending, msg := signInPending(op); pending {
		return false, msg, nil
	}
	release, err := op.Lock("vars")
	if err != nil {
		return false, err.Error(), nil
	}
	defer release()
	vars, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, err.Error(), nil
	}
	if !autheliaOn(vars) {
		return false, signInErrDisabled, nil
	}
	autDomain := strings.ToLower(strOrEmpty(vars.Value("aut_domain")))
	if autDomain == "" {
		return false, signInErrNoPortal, nil
	}
	domain, err := validateDomain(strings.TrimSpace(req.Domain), "domain", false)
	if err != nil || !strings.Contains(domain, ".") {
		return false, signInErrDomain, nil
	}
	prefix := strings.ToLower(strings.TrimSpace(req.Prefix))
	if prefix == "" {
		prefix = "aut"
	}
	if !signInPrefixRe.MatchString(prefix) {
		return false, signInErrPrefix, nil
	}
	want := signInDomain{Domain: domain, Portal: prefix + "." + domain,
		CertificateSource: strings.TrimSpace(req.CertificateSource), DNSProfile: strings.ToLower(strings.TrimSpace(req.DNSProfile))}
	if want.CertificateSource != "" && want.CertificateSource != "letsencrypt" && want.CertificateSource != "internal" && want.CertificateSource != "external" {
		return false, signInErrSource, nil
	}
	if want.DNSProfile != "" {
		if signInEffectiveSource(want, vars) != "letsencrypt" {
			want.DNSProfile = ""
		} else if !signInDNSProfileKnown(want.DNSProfile) {
			return false, signInErrProfile, nil
		}
	}

	extras := signInDomainsFromVars(vars)
	existing := -1
	for i, d := range extras {
		if d.Domain == domain {
			existing = i
			if d.Portal != want.Portal {
				return false, signInErrOtherPortal, nil
			}
			want = d // a repair keeps the stored choices
		} else if domainsOverlap(d.Domain, domain) {
			return false, signInErrOverlap, nil
		}
	}
	if existing < 0 && len(extras) >= 50 {
		return false, signInErrTooMany, nil
	}
	cookies, known := liveCookies()
	if !known {
		return false, signInErrCookies, nil
	}
	for _, c := range cookies {
		if cd := cookieDomain(c); cd != domain && domainsOverlap(cd, domain) {
			return false, signInErrOverlap, nil
		}
	}
	if domainsOverlap(strOrEmpty(vars.Value("root_domain")), domain) {
		return false, signInErrOverlap, nil
	}
	taken := map[string]bool{autDomain: true, strings.ToLower(strOrEmpty(vars.Value("admin_domain"))): true}
	sites, _ := GetWebsitesList()
	for _, s := range sites {
		if m, ok := asMap(s); ok {
			for n := range routingNames(m) {
				taken[n] = true
			}
		}
	}
	if taken[want.Portal] {
		return false, signInErrPortalUsed, nil
	}

	// Authelia first: it validates the cookie (configd runs Authelia's own
	// config check before replacing the file), and a refusal leaves
	// nothing to undo.
	changedAuthelia := false
	previous := cookies
	if !cookieMatches(cookies, want) {
		next := []*Map{}
		for _, c := range cookies {
			if cookieDomain(c) != domain {
				next = append(next, c)
			}
		}
		next = append(next, want.cookie())
		if ok, msg := autheliaSetCookies(next); !ok {
			return false, signInErrAuthelia + " " + msg, nil
		}
		changedAuthelia = true
	}
	if existing < 0 {
		list, _ := asList(vars.Value("authelia_extra_domains"))
		list = append(append([]any{}, list...), want.entry())
		vars.Set("authelia_extra_domains", list)
		if ok, msg := replaceYAMLSource("vars", ConfigYAML, dumpYAMLWide(vars), "authelia_extra_domains"); !ok {
			if changedAuthelia {
				autheliaSetCookies(previous)
			}
			return false, signInErrVarsWrite + " " + msg, nil
		}
	}
	var notes []string
	if rules, err := loadAutheliaRuleList(); err != nil {
		notes = append(notes, signInMsgRuleFailed)
	} else {
		found := false
		for _, r := range rules {
			if m, ok := asMap(r); ok && ruleNamesHost(m, want.Portal) {
				found = true
			}
		}
		if !found {
			rules = append(append([]any{}, rules...), newMap("domain", want.Portal, "policy", "one_factor", "resources", []any{signInPortalResource}))
			if ok, _ := autheliaSaveRulesFromYAML(op, dumpYAML(rules)); ok {
				changedAuthelia = true
			} else {
				notes = append(notes, signInMsgRuleFailed)
			}
		}
	}
	if signInEffectiveSource(want, vars) == "internal" {
		if res := issueSignInPortalCert(want, vars, false); res != nil {
			if truthy(res.Value("ok")) {
				notes = append(notes, signInMsgCertIssued)
			} else {
				notes = append(notes, signInMsgCertFailed)
			}
		}
	}
	if !changedAuthelia {
		if existing >= 0 {
			return true, signInMsgUnchanged, notes
		}
		return true, signInMsgAdded, notes
	}
	if restart, err := autheliaConfigdRequest(newMap("action", "restart")); err != nil || !truthy(restart.Value("ok")) {
		return true, signInMsgNoRestart, notes
	}
	if existing >= 0 {
		return true, signInMsgRepaired, notes
	}
	return true, signInMsgAdded, notes
}

// signInDomainUsers are the names of serving sites under domain that send
// their visitors to Authelia (access gates included).
func signInDomainUsers(domain string) []string {
	sites, _ := GetWebsitesList()
	var out []string
	for _, s := range sites {
		m, ok := asMap(s)
		if !ok || m.Value("paused") == true {
			continue
		}
		eff, err := EffectiveSiteSettings(m)
		if err != nil || eff == nil {
			continue
		}
		if !siteLoginApplies(eff) && eff.Value("access_gate") != true {
			continue
		}
		for _, n := range siteLoginNames(eff) {
			if hostCovered(n, []string{domain}) {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// RemoveSignInDomain takes an extra sign-in domain away.
func RemoveSignInDomain(op *Op, domain string) (bool, string, []string) {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if pending, msg := signInPending(op); pending {
		return false, msg, nil
	}
	release, err := op.Lock("vars")
	if err != nil {
		return false, err.Error(), nil
	}
	defer release()
	vars, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, err.Error(), nil
	}
	var target *signInDomain
	for _, d := range signInDomainsFromVars(vars) {
		if d.Domain == domain {
			d := d
			target = &d
		}
	}
	if target == nil {
		return false, signInErrNotFound, nil
	}
	if users := signInDomainUsers(domain); len(users) > 0 {
		return false, signInErrInUse + " " + strings.Join(users, ", "), nil
	}
	cookies, known := liveCookies()
	if !known {
		return false, signInErrCookies, nil
	}
	changedAuthelia := false
	next := []*Map{}
	for _, c := range cookies {
		if cookieDomain(c) != domain {
			next = append(next, c)
		}
	}
	if len(next) != len(cookies) {
		if ok, msg := autheliaSetCookies(next); !ok {
			return false, signInErrAuthelia + " " + msg, nil
		}
		changedAuthelia = true
	}
	list, _ := asList(vars.Value("authelia_extra_domains"))
	kept := []any{}
	for _, it := range list {
		if strings.ToLower(strOrEmpty(get(it, "domain"))) != domain {
			kept = append(kept, it)
		}
	}
	if len(kept) == 0 {
		vars.Delete("authelia_extra_domains")
	} else {
		vars.Set("authelia_extra_domains", kept)
	}
	if ok, msg := replaceYAMLSource("vars", ConfigYAML, dumpYAMLWide(vars), "authelia_extra_domains"); !ok {
		if changedAuthelia {
			autheliaSetCookies(cookies)
		}
		return false, signInErrVarsWrite + " " + msg, nil
	}
	var notes []string
	if rules, err := loadAutheliaRuleList(); err == nil {
		keptRules := []any{}
		for _, r := range rules {
			if m, ok := asMap(r); ok && isPortalRule(m, target.Portal) {
				continue
			}
			keptRules = append(keptRules, r)
		}
		if len(keptRules) != len(rules) {
			if ok, _ := autheliaSaveRulesFromYAML(op, dumpYAML(keptRules)); ok {
				changedAuthelia = true
			}
		}
	}
	if changedAuthelia {
		if restart, err := autheliaConfigdRequest(newMap("action", "restart")); err != nil || !truthy(restart.Value("ok")) {
			return true, signInMsgNoRestart, notes
		}
	}
	return true, signInMsgRemoved, notes
}

// IssueSignInPortalCertificate is the page's Issue certificate button.
func IssueSignInPortalCertificate(domain string) (bool, string) {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	vars, err := loadYAML(ConfigYAML)
	if err != nil {
		return false, err.Error()
	}
	for _, d := range signInDomainsFromVars(vars) {
		if d.Domain == domain {
			res := issueSignInPortalCert(d, vars, true)
			if res != nil && truthy(res.Value("ok")) {
				return true, signInMsgCertIssued
			}
			detail := ""
			if res != nil {
				detail = strOrEmpty(orValue(res.Value("error"), res.Value("message")))
			}
			return false, strings.TrimSpace("The portal's certificate could not be issued: " + detail)
		}
	}
	return false, signInErrNotFound
}

// lookupHost resolves a name for the page's DNS hint; a variable for tests.
var lookupHost = func(name string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		return nil
	}
	sort.Strings(addrs)
	return addrs
}

// SignInDomainsView is what the settings page shows.
func SignInDomainsView() map[string]any {
	view := map[string]any{"items": []any{}, "available": false}
	vars, err := loadYAML(ConfigYAML)
	if err != nil || vars == nil {
		return view
	}
	autDomain := strings.ToLower(strOrEmpty(vars.Value("aut_domain")))
	view["aut_domain"] = autDomain
	view["enabled"] = autheliaOn(vars)
	view["available"] = autheliaOn(vars) && autDomain != ""
	view["default_source"] = signInEffectiveSource(signInDomain{}, vars)
	extras := signInDomainsFromVars(vars)
	cookies, known := liveCookies()
	view["cookies_known"] = known

	names := []string{autDomain}
	for _, d := range extras {
		names = append(names, d.Portal)
	}
	resolved := make([][]string, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		if n == "" {
			continue
		}
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			resolved[i] = lookupHost(n)
		}(i, n)
	}
	wg.Wait()
	reference := resolved[0]
	view["aut_addresses"] = strings.Join(reference, ", ")

	items := []any{}
	for i, d := range extras {
		addrs := resolved[i+1]
		dnsState := "missing"
		if len(addrs) > 0 {
			dnsState = "elsewhere"
			for _, a := range addrs {
				for _, r := range reference {
					if a == r {
						dnsState = "ok"
					}
				}
			}
			if len(reference) == 0 {
				dnsState = "resolves"
			}
		}
		cert := CertStatusForSite(newMap("domain", d.Portal))
		items = append(items, map[string]any{
			"domain": d.Domain, "portal": d.Portal, "prefix": strings.TrimSuffix(d.Portal, "."+d.Domain),
			"in_authelia":        known && cookieMatches(cookies, d),
			"certificate_source": signInEffectiveSource(d, vars),
			"dns_profile":        d.DNSProfile,
			"dns_state":          dnsState,
			"addresses":          strings.Join(addrs, ", "),
			"cert_state":         cert.Value("state"),
			"cert_short":         cert.Value("short"),
		})
	}
	view["items"] = items
	view["dns_profiles"] = availableDNSProfiles()
	return view
}

// signInPending is ConfigTransactionIsPending; a variable for tests.
var signInPending = ConfigTransactionIsPending
