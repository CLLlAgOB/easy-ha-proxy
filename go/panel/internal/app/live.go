package app

// Port of services_live.py's live activity snapshot, decision feed and
// manual ban, with their routes from routes_monitoring.py.

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	liveMaxWindow   = 3600
	manualBanCode   = 50
	decisionFeedLen = 50
)

var (
	liveStatusClasses = []string{"1xx", "2xx", "3xx", "4xx", "5xx"}
	liveIPRe          = regexp.MustCompile(`^[0-9A-Fa-f:.]{1,45}$`)
	liveHostRe        = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
	liveCountryRe     = regexp.MustCompile(`^[A-Z]{2}$`)
	connRowRe         = regexp.MustCompile(`key=(?P<ip>\S+)\s.*?conn_rate\(\d+\)=(?P<rate>\d+)\s+conn_cur=(?P<cur>\d+)`)
	decisionFeedKinds = []string{"all", "bans", "lifts"}
	refusalLabelKeys  = []string{"banned", "rate-limited", "geo", "zero-trust", "denied", "invalid-request", "refused"}
	refusalLabels     = map[string]string{"banned": "Banned", "rate-limited": "Request rate limit", "geo": "GeoIP",
		"zero-trust": "Zero trust: not signed in", "denied": "Address not allowed",
		"invalid-request": "Unknown name or bad request", "refused": "Refused by the gateway"}
)

// LiveUnavailable is services_live.LiveUnavailable.
type LiveUnavailable struct{ Msg string }

func (e *LiveUnavailable) Error() string { return e.Msg }

func flagOn(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// normalizeLiveRequest is normalize_request: the query string, checked.
func (c *Ctx) normalizeLiveRequest() *Map {
	arg := func(k string) string { v, _ := c.queryOpt(k); return v }
	window := int64(60)
	if raw := arg("window"); raw != "" {
		if n, err := parsePyIntString(raw); err == nil {
			window = n
		}
	}
	req := newMap("window", max(5, min(liveMaxWindow, window)))
	if ip := pyStripSpace(arg("ip")); ip != "" && liveIPRe.MatchString(ip) {
		req.Set("ip", ip)
	}
	if host := strings.ToLower(pyStripSpace(arg("host"))); host != "" && liveHostRe.MatchString(host) {
		req.Set("host", host)
	}
	if q := pyStripSpace(arg("q")); q != "" {
		req.Set("q", truncRunes(q, 120))
	}
	if status := pyStripSpace(arg("status")); pick(liveStatusClasses, status, "") != "" {
		req.Set("status", status)
	}
	if flagOn(arg("blocked")) {
		req.Set("blocked", true)
	}
	if flagOn(arg("banned")) {
		req.Set("banned", true)
	}
	if country := strings.ToUpper(pyStripSpace(arg("country"))); liveCountryRe.MatchString(country) {
		req.Set("country", country)
	}
	// The admin panel's own polling is most of a quiet gateway's traffic.
	if flagOn(arg("hide_admin")) {
		req.Set("hide_admin", true)
	}
	var agent strings.Builder
	for _, r := range arg("agent") {
		if unicode.IsPrint(r) {
			agent.WriteRune(r)
		}
	}
	if a := pyStripSpace(agent.String()); a != "" {
		req.Set("agent", truncRunes(a, 120))
	}
	return req
}

func fetchSnapshot(req *Map) (*Map, error) {
	var params []QueryValue
	req.Each(func(k, v any) {
		key := k.(string)
		if key == "country" {
			return
		}
		if b, ok := v.(bool); ok && b {
			params = append(params, QueryValue{key, "1"})
			return
		}
		params = append(params, QueryValue{key, pyStr(v)})
	})
	data, err := guarddLive(params)
	if err != nil {
		if isUnavailable(err) {
			return nil, &LiveUnavailable{"Adaptive protection is not answering. Live activity is read from its memory, " +
				"so it needs adaptive protection running in monitor or enforce mode (" + err.Error() + ")"}
		}
		return nil, err
	}
	if !truthy(data.Value("ok")) {
		return nil, &LiveUnavailable{pyStr(orValue(data.Value("error"), "guardd refused the request"))}
	}
	return data, nil
}

type connEntry struct{ rate, cur int64 }

// connectionTable is connection_table: new-connection rate and open
// connections per address.
func connectionTable() ([]string, map[string]connEntry) {
	raw := ""
	for _, table := range []string{"tbl_conn_edge", "fe_https"} {
		out, err := runtimeCmd("show table " + table)
		if err != nil {
			continue
		}
		raw = out
		if strings.HasPrefix(strings.TrimLeftFunc(raw, pyIsSpace), "# table:") {
			break
		}
		raw = ""
	}
	var order []string
	rows := map[string]connEntry{}
	for _, line := range pySplitlines(raw) {
		m := connRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rate, _ := parsePyIntString(m[2])
		cur, _ := parsePyIntString(m[3])
		if _, seen := rows[m[1]]; !seen {
			order = append(order, m[1])
		}
		rows[m[1]] = connEntry{rate, cur}
	}
	return order, rows
}

func connectionLimits() *Map {
	cv, _ := loadYAML(ConfigYAML)
	defaults := newMap()
	if cv != nil {
		if d, ok := asMap(orValue(cv.Value("site_defaults"), newMap())); ok {
			defaults = d
		}
	}
	number := func(key string, fallback int64) int64 {
		v, has := defaults.Get(key)
		if !has {
			return fallback
		}
		n, err := pyInt(v)
		if err != nil {
			return fallback
		}
		return n
	}
	return newMap("burst", number("conn_rate_burst", 200), "concurrent", number("conn_cur_limit", 500))
}

func authorizedAddresses(table *Map) map[string]bool {
	out := map[string]bool{}
	if table == nil {
		return out
	}
	for _, row := range tableRows(table) {
		n, err := pyInt(rowAt(row, 1))
		if err == nil && n > 0 {
			out[pyStr(rowAt(row, 0))] = true
		}
	}
	return out
}

func liveCountry(ip string, cache map[string]string) string {
	if code, ok := cache[ip]; ok {
		return code
	}
	code := getCountryCode(ip)
	if !liveCountryRe.MatchString(code) {
		code = ""
	}
	cache[ip] = code
	return code
}

func mergeInto(dst, src *Map) {
	src.Each(func(k, v any) { dst.Set(k, v) })
}

// liveView is live_view.
func (c *Ctx) liveView() (*Map, error) {
	req := c.normalizeLiveRequest()
	snapshot, err := fetchSnapshot(req)
	if err != nil {
		return nil, err
	}
	bans := currentBans()
	connOrder, connections := connectionTable()
	limits := connectionLimits()
	burst, concurrent := limits.Value("burst").(int64), limits.Value("concurrent").(int64)
	allowed := networksIn(WhitelistGlobalFile)
	authTable, err := getIPAuthTable()
	if err != nil {
		authTable = newMap()
	}
	authorized := authorizedAddresses(authTable)
	identities := asMapOr(orValue(authTable.Value("users_by_ip"), newMap()))
	countries := map[string]string{}

	state := func(ip string) *Map {
		conn, hasConn := connections[ip]
		over := hasConn && (conn.rate > burst || conn.cur > concurrent)
		entry := allowEntry(ip, allowed)
		var users any = []any{}
		if authorized[ip] {
			if u, found := identities.Get(ip); found {
				users = u
			}
		}
		var connections any
		if hasConn {
			connections = newMap("rate", conn.rate, "cur", conn.cur)
		}
		return newMap("country", liveCountry(ip, countries), "ban", bans.Value(ip), "allow_listed", entry != "",
			"allow_entry", strOrNone(entry), "authorized", authorized[ip], "authenticated_users", users,
			// The allow list is exempt from the connection limit.
			"connection_limited", over && entry == "", "connections", connections)
	}

	ipOf := func(row any) (string, error) {
		m, ok := asMap(row)
		if !ok {
			return "", noAttr(row, "update")
		}
		v, found := m.Get("ip")
		if !found {
			return "", fmt.Errorf("KeyError: 'ip'")
		}
		return pyStr(v), nil
	}
	for _, row := range listOf(snapshot, "addresses") {
		ip, err := ipOf(row)
		if err != nil {
			return nil, err
		}
		mergeInto(row.(*Map), state(ip))
	}
	for _, key := range []string{"events", "slow"} {
		for _, event := range listOf(snapshot, key) {
			ip, err := ipOf(event)
			if err != nil {
				return nil, err
			}
			event.(*Map).Set("country", liveCountry(ip, countries))
		}
	}
	if wanted := strOrEmpty(req.Value("country")); wanted != "" {
		keep := func(key string) {
			kept := []any{}
			for _, e := range listOf(snapshot, key) {
				if get(e, "country") == wanted {
					kept = append(kept, e)
				}
			}
			snapshot.Set(key, kept)
		}
		keep("addresses")
		keep("events")
		keep("slow")
	}
	seen := map[string]*Map{}
	for _, row := range listOf(snapshot, "addresses") {
		if m, ok := asMap(row); ok {
			seen[pyStr(m.Value("ip"))] = m
		}
	}
	type banRow struct {
		m       *Map
		expires int64
	}
	var banned []banRow
	bans.Each(func(k, v any) {
		ip := k.(string)
		row := newMap("ip", ip, "country", liveCountry(ip, countries))
		mergeInto(row, v.(*Map))
		var requests any = int64(0)
		if s := seen[ip]; s != nil {
			if r, found := s.Get("requests"); found {
				requests = r
			}
		}
		row.Set("requests_in_window", requests)
		banned = append(banned, banRow{row, v.(*Map).Value("expires_in").(int64)})
	})
	sort.SliceStable(banned, func(i, j int) bool { return banned[i].expires > banned[j].expires })
	type limRow struct {
		m    *Map
		rate int64
	}
	var limited []limRow
	var currentConns int64
	for _, ip := range connOrder {
		conn := connections[ip]
		currentConns += conn.cur
		if listedIn(ip, allowed) {
			continue
		}
		if conn.rate > burst || conn.cur > concurrent {
			limited = append(limited, limRow{newMap("ip", ip, "country", liveCountry(ip, countries), "rate", conn.rate, "cur", conn.cur), conn.rate})
		}
	}
	sort.SliceStable(limited, func(i, j int) bool { return limited[i].rate > limited[j].rate })
	bannedList, limitedList := []any{}, []any{}
	for _, b := range banned {
		bannedList = append(bannedList, b.m)
	}
	for _, l := range limited {
		limitedList = append(limitedList, l.m)
	}
	codes := map[string]bool{}
	for _, code := range countries {
		if code != "" {
			codes[code] = true
		}
	}
	refusals := newMap()
	for _, k := range refusalLabelKeys {
		refusals.Set(k, refusalLabels[k])
	}
	snapshot.Set("request", req)
	snapshot.Set("banned", bannedList)
	snapshot.Set("connection_limited", limitedList)
	snapshot.Set("connection_limits", limits)
	snapshot.Set("ban_labels", banCodeLabelsMap())
	snapshot.Set("refusal_labels", refusals)
	snapshot.Set("countries", strList(sortedKeys(codes)...))
	snapshot.Set("current_connections", currentConns)
	totals, ok := asMap(snapshot.Value("totals"))
	if !ok {
		if _, found := snapshot.Get("totals"); !found {
			return nil, fmt.Errorf("KeyError: 'totals'")
		}
		return nil, fmt.Errorf("TypeError: object does not support item assignment")
	}
	totals.Set("banned_now", int64(len(bannedList)))
	totals.Set("connection_limited_now", int64(len(limitedList)))
	return snapshot, nil
}

// decisionFeed is decision_feed: every address's ban decisions, newest first.
func (c *Ctx) decisionFeed() (*Map, error) {
	kind, _ := c.queryOpt("kind")
	if kind == "" {
		kind = "all"
	}
	if pick(decisionFeedKinds, kind, "") == "" {
		kind = "all"
	}
	var before int64
	if raw, _ := c.queryOpt("before"); raw != "" {
		if n, err := parsePyIntString(raw); err == nil {
			before = max(0, n)
		}
	}
	payload, err := guarddDecisionFeed([]QueryValue{{"kind", kind}, intParam("before", before), intParam("limit", decisionFeedLen)})
	if err != nil {
		return nil, err
	}
	sites, err := siteLimits()
	if err != nil {
		sites = map[string]*Map{}
	}
	rows := []any{}
	for _, item := range listOf(payload, "decisions") {
		m, ok := asMap(item)
		if !ok {
			return nil, noAttr(item, "get")
		}
		action, source := strOrEmpty(m.Value("action")), strOrEmpty(m.Value("source"))
		ip := strOrEmpty(m.Value("ip"))
		summary := asMapOr(orValue(m.Value("summary"), newMap()))
		over := []any{}
		for _, entry := range listOf(summary, "over") {
			site := strOrEmpty(get(entry, "site"))
			value, err := intOr0(get(entry, "value"))
			if err != nil {
				return nil, err
			}
			over = append(over, newMap("unknown", site == "other", "site", siteDomain(sites, site),
				"counter", counterLabel(strOrEmpty(get(entry, "counter"))), "value", value, "limit", get(entry, "limit")))
		}
		ints := map[string]int64{}
		for _, key := range []string{"id", "ts", "code", "score", "strike"} {
			n, err := intOr0(m.Value(key))
			if err != nil {
				return nil, err
			}
			ints[key] = n
		}
		until := ""
		if action != "lifted" && action != "ended" {
			until = when(m.Value("until"))
		}
		categories := []any{}
		for _, name := range listOf(summary, "categories") {
			if len(categories) < 4 {
				categories = append(categories, pyStr(name))
			}
		}
		country := getCountryCode(ip)
		rows = append(rows, newMap("id", ints["id"], "ts", ints["ts"], "when", when(m.Value("ts")), "ip", ip,
			"country", country, "label", decisionLabel(action, source),
			"outcome", decisionOutcomes[strOrEmpty(m.Value("outcome"))], "code", ints["code"], "until", until,
			"score", ints["score"], "strike", ints["strike"], "categories", categories, "over", over))
	}
	next, err := intOr0(payload.Value("next"))
	if err != nil {
		return nil, err
	}
	sources := []any{}
	for _, name := range listOf(payload, "sources") {
		sources = append(sources, pyStr(name))
	}
	return newMap("ok", true, "kind", kind, "decisions", rows, "next", next, "sources", sources), nil
}

// banAddress is ban_address: one address banned by hand.
func banAddress(ip, clientIP string, dropAllowlist bool) (*Map, error) {
	if !ipv4DottedRe.MatchString(ip) {
		return newMap("ok", false, "error", "Only an IPv4 address can be banned"), nil
	}
	if a, ok := pyIPAddress(ip); !ok || !a.Is4() {
		return newMap("ok", false, "error", "Invalid IP"), nil
	}
	if clientIP != "" && ip == clientIP {
		return newMap("ok", false, "error", "That is your own address; banning it would lock you out"), nil
	}
	if listedIn(ip, networksIn(WhitelistGlobalFile)) {
		if !dropAllowlist {
			return newMap("ok", false, "allow_listed", true, "error", "The address is on the global allow list, so a ban would not apply"), nil
		}
		removed, errText := removeHostFromGlobalWhitelist(ip)
		if errText != "" {
			return newMap("ok", false, "error", "Could not update the allow list: "+errText), nil
		}
		if listedIn(ip, networksIn(WhitelistGlobalFile)) {
			return newMap("ok", false, "error", "The address is allowed by a network range, not its own entry. Remove or narrow that range first, then ban."), nil
		}
		if !removed {
			return newMap("ok", false, "error", "The address was not found as a single allow-list entry"), nil
		}
	}
	note := ""
	answer, err := guarddManualBan(ip)
	if err != nil && !isUnavailable(err) {
		return nil, err
	}
	if err == nil {
		if answer.Value("ok") == false {
			return newMap("ok", false, "error", truncRunes(pyStr(orValue(answer.Value("error"), "The ban was not placed")), 300)), nil
		}
		if answer.Value("remembered") == false {
			note = "Banned, but the security engine could not remember it: it will not come back after HAProxy restarts."
		}
	} else {
		log.Printf("security engine not reachable while banning %s by hand: %v", ip, err)
		// The engine is down: HAProxy alone, as before, and said so.
		reply, err := runtimeCmd(fmt.Sprintf("set table tbl_ban key %s data.gpc0 1 data.gpt0 %d", ip, manualBanCode))
		if err != nil {
			return nil, err
		}
		if r := pyStripSpace(reply); r != "" {
			return newMap("ok", false, "error", "HAProxy refused: "+truncRunes(r, 200)), nil
		}
		note = "Banned in HAProxy, but the security engine did not answer: the ban will not come back after HAProxy restarts."
	}
	invalidateTableCache()
	result := newMap("ok", true, "ip", ip, "code", int64(manualBanCode), "dropped_from_allowlist", dropAllowlist)
	if note != "" {
		result.Set("note", note)
	}
	return result, nil
}

func (a *App) registerLive() {
	a.Handle("routes.api_live_activity", func(c *Ctx) error {
		out, err := c.liveView()
		if err != nil {
			if lu, ok := err.(*LiveUnavailable); ok {
				log.Printf("live activity unavailable: %s", lu.Msg)
				return c.JSON(503, newMap("ok", false, "unavailable", true, "error", lu.Msg))
			}
			return err
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_live_decisions", func(c *Ctx) error {
		out, err := c.decisionFeed()
		if err != nil {
			if isUnavailable(err) {
				log.Printf("ban decisions unavailable: %v", err)
				return c.JSON(503, newMap("ok", false, "unavailable", true, "error", err.Error()))
			}
			return err
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_live_ban", func(c *Ctx) error {
		raw := c.silentJSONMap()
		payload, ok := asMap(raw)
		if !ok {
			return noAttr(raw, "get")
		}
		ip := pyStripSpace(strOrEmpty(payload.Value("ip")))
		drop := truthy(payload.Value("drop_allowlist"))
		result, err := banAddress(ip, c.trustedClientIP(), drop)
		if err != nil {
			return err
		}
		done := truthy(result.Value("ok"))
		summary := "by hand from the live activity page"
		if drop {
			summary = "dropped from the allow list and banned by hand from the live activity page"
		}
		detail := ""
		if !done {
			detail = truncRunes(pyStr(result.Value("error")), 300)
		}
		c.RecordRequest("ban.place", AuditEntry{ObjectType: "ip", ObjectID: truncRunes(ip, 64), Result: recordResult(done),
			Summary: summary, Detail: detail})
		return c.JSON(okStatus(done, 400), result)
	})
}
