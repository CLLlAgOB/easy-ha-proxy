package app

// The parts of services_live.py the address page shares with the live
// activity page: what an address is (allowed, banned), why it was banned,
// and Authelia's own sign-in ban. Also services_security._site_limits.

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy-ha-proxy/panel/shared/jinja"
)

// What each ban code in tbl_ban (gpt0) means.
var banCodeLabels = map[string]string{
	"10": "Too many 4xx errors on a site (ERR_LIMIT_SITE)",
	"20": "Too many 4xx errors on unknown names (ERR_LIMIT_OTHER)",
	"30": "Site request rate exceeded (RATE_LIMIT_SITE)",
	"40": "Adaptive protection: scored as hostile",
	"41": "Adaptive protection: first step, shown a page",
	"50": "Banned by hand from the live activity page",
}

func banCodeLabelsMap() *Map {
	m := newMap()
	for _, k := range []string{"10", "20", "30", "40", "41", "50"} {
		m.Set(k, banCodeLabels[k])
	}
	return m
}

func banLabel(code string) string {
	if l, ok := banCodeLabels[code]; ok {
		return l
	}
	return "Ban code " + code
}

var decisionLabels = map[[2]string]string{
	{"applied", "adaptive"}: "Banned by adaptive protection",
	{"applied", "operator"}: "Banned by hand",
	{"restored", "restart"}: "Ban put back after HAProxy restarted",
	{"lifted", "expiry"}:    "The ban ran out",
	{"lifted", "mode"}:      "Lifted: enforcement was turned off",
	{"lifted", "operator"}:  "Lifted by hand",
	{"lifted", "policy"}:    "An old HAProxy ban, lifted by the new ban policy",
	{"observed", "haproxy"}: "Banned by HAProxy's own rule (first seen)",
	{"ended", "haproxy"}:    "HAProxy's own ban is no longer in force",
}

var readingCounters = map[string]string{"http_req_rate": "Request rate", "http_err_rate": "Error rate (4xx)"}

var decisionOutcomes = map[string]string{"failed": "HAProxy refused it", "abandoned": "Not applied", "pending": "Being applied"}

func decisionLabel(action, source string) string {
	if l, ok := decisionLabels[[2]string{action, source}]; ok {
		return l
	}
	return fmt.Sprintf("%s (%s)", action, source)
}

func counterLabel(counter string) string {
	if l, ok := readingCounters[counter]; ok {
		return l
	}
	return counter
}

// networksIn is _networks: the networks a list file names, comments dropped.
func networksIn(path string) []netip.Prefix {
	text, err := readTextUniversal(path)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, line := range strings.SplitAfter(text, "\n") {
		t, _, _ := strings.Cut(line, "#")
		t = pyStripSpace(t)
		if t == "" {
			continue
		}
		if p, ok := pyIPNetwork(t); ok {
			out = append(out, p)
		}
	}
	return out
}

func listedIn(ip string, nets []netip.Prefix) bool {
	a, ok := pyIPAddress(ip)
	if !ok {
		return false
	}
	for _, n := range nets {
		if n.Contains(a.WithZone("")) {
			return true
		}
	}
	return false
}

// allowEntry is allow_entry: "host", "range", or "" for none.
func allowEntry(ip string, nets []netip.Prefix) string {
	a, ok := pyIPAddress(ip)
	if !ok {
		return ""
	}
	found, host := false, false
	for _, n := range nets {
		if n.Contains(a.WithZone("")) {
			found = true
			host = host || n.Bits() == n.Addr().BitLen()
		}
	}
	switch {
	case !found:
		return ""
	case host:
		return "host"
	}
	return "range"
}

func strOrNone(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// currentBans is current_bans: addresses HAProxy refuses right now.
func currentBans() *Map {
	bans := newMap()
	table := orValue(getTables(true).Value("ban"), newMap())
	for _, row := range tableRows(table) {
		if rowLen(row) < 4 || pyStr(rowAt(row, 1)) != "Blocked" {
			continue
		}
		code := pyStr(rowAt(row, 2))
		expires, err := parsePyIntString(pyStr(rowAt(row, 3)))
		if err != nil {
			expires = 0
		}
		bans.Set(pyStr(rowAt(row, 0)), newMap("code", code, "label", banLabel(code), "expires_in", expires))
	}
	return bans
}

func addressStatus(ip string) *Map {
	entry := allowEntry(ip, networksIn(WhitelistGlobalFile))
	return newMap("ipv4", ipv4DottedRe.MatchString(ip), "allow_entry", strOrNone(entry),
		"ban", currentBans().Value(ip), "ban_known", true, "allow_listed", entry != "")
}

// when is _when: a stored timestamp in the gateway's zone.
func when(ts any) string {
	value, err := intOr0(ts)
	if err != nil || value <= 0 {
		return ""
	}
	loc, _ := ServerLocation()
	return time.Unix(value, 0).In(loc).Format("2006-01-02 15:04")
}

var siteNameSanitize = regexp.MustCompile(`[^A-Za-z0-9_]`)

// siteLimits is services_security._site_limits.
func siteLimits() (map[string]*Map, error) {
	cv, err := loadYAML(ConfigYAML)
	if err != nil {
		return nil, err
	}
	defaults, _ := asMap(orValue(cv.Value("site_defaults"), newMap()))
	if defaults == nil {
		defaults = newMap()
	}
	sites, err := GetWebsitesList()
	if err != nil {
		return nil, err
	}
	table := map[string]*Map{}
	for _, s := range sites {
		name := strOrEmpty(get(s, "name"))
		if name == "" {
			continue
		}
		effV, err := jinja.CombineFilter(nil, defaults, []any{s}, newMap("recursive", true))
		if err != nil {
			return nil, err
		}
		eff := effV.(*Map)
		domain := strOrEmpty(eff.Value("domain"))
		if domain == "" {
			domain = name
		}
		table[siteNameSanitize.ReplaceAllString(name, "_")] = newMap("site", name, "domain", domain,
			"max_req_rate", eff.Value("max_req_rate"),
			"rate_window", orValue(eff.Value("rate_window"), defaults.Value("rate_window")),
			"err_limit", orValue(eff.Value("err_limit"), defaults.Value("err_limit")),
			"err_window", orValue(eff.Value("err_window"), defaults.Value("err_window")))
	}
	return table, nil
}

func siteDomain(sites map[string]*Map, site string) string {
	if known := sites[site]; known != nil {
		if d := strOrEmpty(known.Value("domain")); d != "" {
			return d
		}
	}
	return site
}

func observedBan(decision *Map) (*Map, error) {
	recorded := orValue(decision.Value("reason"), newMap())
	sites, err := siteLimits()
	if err != nil {
		sites = map[string]*Map{}
	}
	codeN, err := intOr0(decision.Value("code"))
	if err != nil {
		return nil, err
	}
	code := strconv.FormatInt(codeN, 10)
	readings := []any{}
	for _, entry := range listOf(asMapOr(recorded), "readings") {
		site := strOrEmpty(get(entry, "site"))
		value, err := intOr0(get(entry, "value"))
		if err != nil {
			return nil, err
		}
		readings = append(readings, newMap("unknown", site == "other", "site", siteDomain(sites, site),
			"counter", counterLabel(strOrEmpty(get(entry, "counter"))), "value", value,
			"limit", get(entry, "limit"), "over", truthy(get(entry, "over"))))
	}
	return newMap("when", when(decision.Value("ts")), "until", when(decision.Value("until")), "code", code,
		"rule", banLabel(code), "readings", readings), nil
}

func asMapOr(v any) *Map {
	if m, ok := asMap(v); ok {
		return m
	}
	return newMap()
}

// banHistory is ban_history: nil when the engine does not answer.
func banHistory(ip string) (*Map, error) {
	payload, err := guarddDecisions(ip)
	if err != nil {
		return nil, nil
	}
	decisions := listOf(payload, "decisions")
	rows := []any{}
	for _, item := range decisions {
		if _, ok := asMap(item); !ok {
			return nil, noAttr(item, "get")
		}
		action, source := strOrEmpty(get(item, "action")), strOrEmpty(get(item, "source"))
		code, err := intOr0(get(item, "code"))
		if err != nil {
			return nil, err
		}
		strike, err := intOr0(get(item, "strike"))
		if err != nil {
			return nil, err
		}
		score, err := intOr0(get(item, "score"))
		if err != nil {
			return nil, err
		}
		until := ""
		if action != "lifted" {
			until = when(get(item, "until"))
		}
		rows = append(rows, newMap("when", when(get(item, "ts")), "label", decisionLabel(action, source),
			"outcome", decisionOutcomes[strOrEmpty(get(item, "outcome"))], "code", code, "until", until,
			"strike", strike, "score", score))
	}
	var latest *Map
	for _, item := range decisions {
		m := item.(*Map)
		if (m.Value("action") == "applied" && m.Value("source") == "adaptive" && m.Value("outcome") == "applied") ||
			(m.Value("action") == "observed" && m.Value("source") == "haproxy") {
			latest = m
			break
		}
	}
	var reason, observed any
	if latest != nil && latest.Value("source") == "haproxy" {
		o, err := observedBan(latest)
		if err != nil {
			return nil, err
		}
		observed = o
		latest = nil
	}
	if latest != nil {
		recorded := asMapOr(orValue(latest.Value("reason"), newMap()))
		evidence := []any{}
		for _, entry := range listOf(recorded, "evidence") {
			finding := strOrEmpty(get(entry, "event_type"))
			if truthy(get(entry, "category")) {
				finding = fmt.Sprintf("%s (%s)", pyStr(get(entry, "event_type")), pyStr(get(entry, "category")))
			}
			evidence = append(evidence, newMap("when", when(get(entry, "ts")), "finding", finding,
				"site", strOrEmpty(get(entry, "site")), "detail", strOrEmpty(get(entry, "detail")), "points", get(entry, "points")))
		}
		score, err := intOr0(latest.Value("score"))
		if err != nil {
			return nil, err
		}
		strike, err := intOr0(latest.Value("strike"))
		if err != nil {
			return nil, err
		}
		total, err := intOr0(recorded.Value("evidence_total"))
		if err != nil {
			return nil, err
		}
		reason = newMap("when", when(latest.Value("ts")), "until", when(latest.Value("until")), "score", score,
			"strike", strike, "policy", strOrEmpty(latest.Value("policy")), "evidence", evidence, "evidence_total", total)
	}
	return newMap("decisions", rows, "reason", reason, "observed", observed), nil
}

// Authelia's list of banned addresses, kept 30 s between address pages.
var (
	autheliaBansMu    sync.Mutex
	autheliaBansAt    time.Time
	autheliaBansValue *Map
)

// autheliaSignInBan is authelia_sign_in_ban: Authelia's own ban on signing
// in from this address, or nil.
func autheliaSignInBan(ip string) *Map {
	a, ok := pyIPAddress(ip)
	if !ok {
		return nil
	}
	autheliaBansMu.Lock()
	if autheliaBansValue == nil || time.Since(autheliaBansAt) > 30*time.Second {
		autheliaBansValue = GetAutheliaBans()
		autheliaBansAt = time.Now()
	}
	bans := autheliaBansValue
	autheliaBansMu.Unlock()
	if truthy(bans.Value("error")) {
		return nil
	}
	for _, entry := range listOf(bans, "ips") {
		subject := strOrEmpty(get(entry, "subject"))
		network, ok := pyIPNetwork(subject)
		if !ok {
			continue
		}
		addr := a.WithZone("")
		if addr.Is4() == network.Addr().Is4() && network.Contains(addr) {
			return newMap("subject", subject, "network", network.Bits() < network.Addr().BitLen(),
				"expires", strOrEmpty(get(entry, "expires")), "source", strOrEmpty(get(entry, "source")),
				"reason", strOrEmpty(get(entry, "reason")))
		}
	}
	return nil
}
