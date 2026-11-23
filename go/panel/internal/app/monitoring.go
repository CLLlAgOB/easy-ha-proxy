package app

// Port of routes_monitoring.py (the historical monitoring page's API),
// services_monitoring.py and metricsd_client.py.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kept in step with RANGES/CHART_SERIES in easy-ha-proxy-metricsd.py.
var (
	monitoringRangeKeys = []string{"1h", "6h", "24h", "7d", "30d", "90d", "1y"}
	monitoringRangeSec  = map[string]int64{"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400,
		"30d": 30 * 86400, "90d": 90 * 86400, "1y": 365 * 86400}
	monitoringCharts = []string{"requests", "traffic", "responses", "latency", "connections", "cpu", "memory",
		"disk", "diskio", "network", "temperature", "percentiles", "refusals"}
	// The monitors the page can switch, as the daemon names them.
	monitoringMonitors = []string{"machine", "components", "disk", "network", "temperature", "percentiles", "refusals",
		"requests", "traffic", "responses", "latency", "connections", "uplinks", "availability"}
	componentPrefixes = []string{"easy-ha-proxy-", "haproxy-"}
)

const (
	monitoringDefaultRange = "24h"
	maxWindowSeconds       = 366 * 86400
	minWindowSeconds       = 60
	maxMonitoringEvents    = 200
	maxAttention           = 8
)

func metricsdTransport() *UnixHTTP {
	return &UnixHTTP{Service: "metricsd",
		SocketPath: strings.TrimSpace(envOr("METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"))}
}

// metricsdGet is metricsd_client._get_json; a non-object answer is the
// AttributeError the service layer's payload.get raised.
func metricsdGet(path string, params []QueryValue, timeout time.Duration) (*Map, error) {
	v, err := metricsdTransport().Get(path, HTTPOptions{Params: params, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	m, ok := asMap(v)
	if !ok {
		return nil, noAttr(v, "get")
	}
	return m, nil
}

// metricsdSave is a settings POST: a refused value comes back as a Rejected.
func metricsdSave(path string, body *Map) (*Map, error) {
	v, err := metricsdTransport().Post(path, body, HTTPOptions{Timeout: 10 * time.Second, RejectedStatus: 400, RequireObject: true})
	if err != nil {
		return nil, err
	}
	m, _ := asMap(v)
	return m, nil
}

// monitoringWindow is normalize_window: a since/until pair, or nil for the preset.
type monitoringWindow struct{ since, until int64 }

func normalizeWindow(since, until string, hasSince, hasUntil bool) *monitoringWindow {
	if !hasSince || !hasUntil {
		return nil
	}
	start, err1 := parsePyIntString(since)
	end, err2 := parsePyIntString(until)
	if err1 != nil || err2 != nil || start <= 0 || end <= 0 || end-start < minWindowSeconds {
		return nil
	}
	if end-start > maxWindowSeconds {
		start = end - maxWindowSeconds
	}
	return &monitoringWindow{start, end}
}

func (c *Ctx) monitoringWindow() *monitoringWindow {
	since, hasSince := c.queryOpt("since")
	until, hasUntil := c.queryOpt("until")
	return normalizeWindow(since, until, hasSince, hasUntil)
}

func pick(list []string, value string, def string) string {
	for _, v := range list {
		if v == value {
			return v
		}
	}
	return def
}

func (c *Ctx) monitoringRange() string {
	raw, _ := c.queryOpt("range")
	return pick(monitoringRangeKeys, strings.ToLower(pyStripSpace(raw)), monitoringDefaultRange)
}

// windowParams is _window_params.
func windowParams(rangeKey, site string, w *monitoringWindow) []QueryValue {
	params := []QueryValue{{"range", rangeKey}}
	if site != "" {
		params = append(params, QueryValue{"site", site})
	}
	if w != nil {
		params = append(params, QueryValue{"since", fmt.Sprint(w.since)}, QueryValue{"until", fmt.Sprint(w.until)})
	}
	return params
}

// ---- display names (services._load_display_map_from_cfg) ----

var (
	displayMu        sync.Mutex
	displayMtime     = time.Time{}
	displayMapCached map[string]string
	displayLoaded    bool
	cfgBackendRe     = regexp.MustCompile(`^\s*backend\s+(\S+)`)
	cfgDisplayTagRe  = regexp.MustCompile(`^\s*#\s*display-name:\s*(.+)\s*$`)
)

func haproxyCfgForDisplay() string {
	return strings.TrimSpace(envOr("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"))
}

// cfgLines reads a text file the way Python's text mode iterates it:
// UTF-8 with errors="ignore" and universal newlines.
func cfgLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ToValidUTF8(string(raw), "")
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

func loadDisplayMap() map[string]string {
	path := haproxyCfgForDisplay()
	var mtime time.Time
	if fi, err := os.Stat(path); err == nil {
		mtime = fi.ModTime()
	}
	displayMu.Lock()
	defer displayMu.Unlock()
	if displayLoaded && mtime.Equal(displayMtime) {
		return displayMapCached
	}
	mapping := map[string]string{}
	if lines, err := cfgLines(path); err == nil {
		current := ""
		for _, line := range lines {
			if m := cfgBackendRe.FindStringSubmatch(line); m != nil {
				current = pyStripSpace(m[1])
				continue
			}
			if m := cfgDisplayTagRe.FindStringSubmatch(line); m != nil && current != "" {
				if _, taken := mapping[current]; !taken {
					mapping[current] = pyStripSpace(m[1])
				}
			}
		}
	}
	displayMtime, displayMapCached, displayLoaded = mtime, mapping, true
	return mapping
}

// monitoringDisplayName is display_name: a backend's readable name.
func monitoringDisplayName(proxy string) string {
	if tagged := loadDisplayMap()[proxy]; tagged != "" {
		return tagged
	}
	return strings.ReplaceAll(strings.TrimPrefix(proxy, "be_"), "_", ".")
}

func componentLabel(name, group string) string {
	if group == "service" {
		for _, prefix := range componentPrefixes {
			if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
				return name[len(prefix):]
			}
		}
	}
	return name
}

// listOf is (payload.get(key) or []) iterated as entries.
func listOf(m *Map, key string) []any {
	l, _ := asList(orValue(m.Value(key), []any{}))
	return l
}

// intOr0 is int(value or 0); a value int() refuses is the 500 it was.
func intOr0(v any) (int64, error) {
	if !truthy(v) {
		return 0, nil
	}
	return pyInt(v)
}

func listSites() ([]any, error) {
	payload, err := metricsdGet("/api/v1/metrics/sites", nil, 10*time.Second)
	if err != nil {
		return nil, err
	}
	sites := []*Map{}
	for _, entry := range listOf(payload, "sites") {
		proxy := orStr(get(entry, "proxy"))
		if proxy == "" {
			continue
		}
		sites = append(sites, newMap("proxy", proxy, "label", monitoringDisplayName(proxy)))
	}
	sort.SliceStable(sites, func(i, j int) bool {
		return strings.ToLower(sites[i].Value("label").(string)) < strings.ToLower(sites[j].Value("label").(string))
	})
	out := make([]any, len(sites))
	for i, s := range sites {
		out[i] = s
	}
	return out, nil
}

func (c *Ctx) monitoringSite(sites []any) string {
	raw, _ := c.queryOpt("site")
	candidate := pyStripSpace(raw)
	if candidate == "" || strings.ToLower(candidate) == "all" {
		return ""
	}
	for _, s := range sites {
		if get(s, "proxy") == candidate {
			return candidate
		}
	}
	return ""
}

func labelEntries(list []any, label func(entry *Map) string) {
	for _, e := range list {
		if m, ok := asMap(e); ok {
			m.Set("label", label(m))
		}
	}
}

func monitoringStates(payload *Map) {
	objects := listOf(payload, "objects")
	serversPerProxy := map[string]int{}
	hasBackendRow := map[string]bool{}
	for _, entry := range objects {
		proxy := strOrEmpty(get(entry, "proxy"))
		if truthy(get(entry, "server")) {
			serversPerProxy[proxy]++
		} else {
			hasBackendRow[proxy] = true
		}
	}
	kept := []any{}
	for _, entry := range objects {
		proxy := strOrEmpty(get(entry, "proxy"))
		// Only ever collapse into a row that exists.
		if !truthy(get(entry, "server")) || !hasBackendRow[proxy] || serversPerProxy[proxy] > 1 {
			kept = append(kept, entry)
		}
	}
	labelEntries(kept, func(m *Map) string { return monitoringDisplayName(strOrEmpty(m.Value("proxy"))) })
	payload.Set("objects", kept)
	payload.Set("collapsed", int64(len(objects)-len(kept)))
}

// ---- uplinks ----

var (
	cfgServerRe = regexp.MustCompile(`^\s+server\s+(?P<name>\S+)\s+(?P<host>[^\s:]+|\[[^\]]+\]):(?P<port>\d+)(?P<rest>.*)$`)
)

type backendServer struct {
	proxy, server, host string
	backup              bool
}

func backendServers() []backendServer {
	path := haproxyCfgForDisplay()
	lines, err := cfgLines(path)
	if err != nil {
		log.Printf("cannot read %s for uplinks: %s", path, pyFileError(err, path))
		return nil
	}
	var found []backendServer
	current := ""
	for _, line := range lines {
		if m := cfgBackendRe.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if current == "" {
			continue
		}
		m := cfgServerRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		found = append(found, backendServer{proxy: current, server: m[1], host: strings.Trim(m[2], "[]"),
			backup: strings.Contains(m[4], " backup")})
	}
	return found
}

func isLocalHost(host string) bool {
	text := strings.Trim(host, "[]")
	if text == "localhost" || text == "" {
		return true
	}
	// ipaddress.ip_address(text).is_loopback: Python 3.12 does not unmap
	// ::ffff:127.0.0.1, so neither does this.
	a, ok := pyIPAddress(text)
	return ok && a.IsLoopback() && !a.Is4In6()
}

func share(part, total int64) float64 {
	if total == 0 {
		return 0.0
	}
	return pyRound(100.0*float64(part)/float64(total), 1)
}

func rangeOf(payload *Map, rangeKey string) (any, any, any) {
	r, has := payload.Get("range")
	if !has {
		r = rangeKey
	}
	since, has := payload.Get("since")
	if !has {
		since = int64(0)
	}
	until, has := payload.Get("until")
	if !has {
		until = int64(0)
	}
	return r, since, until
}

func monitoringChannels(rangeKey string, w *monitoringWindow) (*Map, error) {
	servers := backendServers()
	payload, err := metricsdGet("/api/v1/metrics/servers", windowParams(rangeKey, "", w), 10*time.Second)
	if err != nil {
		return nil, err
	}
	labels, _ := asMap(orValue(payload.Value("labels"), newMap()))
	if labels == nil {
		labels = newMap()
	}
	hidden := map[string]bool{}
	for _, h := range listOf(payload, "hidden") {
		if hs, ok := h.(string); ok {
			hidden[hs] = true
		}
	}
	measured := map[[2]string]*Map{}
	for _, row := range listOf(payload, "servers") {
		if m, ok := asMap(row); ok {
			measured[[2]string{pyStr(m.Value("proxy")), pyStr(m.Value("server"))}] = m
		}
	}
	type channel struct {
		host                        string
		label                       any
		names, backends             []string
		backup                      bool
		bytesIn, bytesOut, sessions int64
		hidden                      bool
	}
	var order []*channel
	grouped := map[string]*channel{}
	for _, entry := range servers {
		if isLocalHost(entry.host) {
			continue
		}
		ch := grouped[entry.host]
		if ch == nil {
			label, found := labels.Get(entry.host)
			if !found {
				label = ""
			}
			ch = &channel{host: entry.host, label: label, backup: true}
			grouped[entry.host] = ch
			order = append(order, ch)
		}
		ch.names = append(ch.names, entry.server)
		ch.backends = append(ch.backends, entry.proxy)
		// A link is only a reserve if every server on it is one.
		if !entry.backup {
			ch.backup = false
		}
		if row := measured[[2]string{entry.proxy, entry.server}]; row != nil {
			for _, col := range []struct {
				key string
				dst *int64
			}{{"bytes_in", &ch.bytesIn}, {"bytes_out", &ch.bytesOut}, {"sessions", &ch.sessions}} {
				n, err := intOr0(row.Value(col.key))
				if err != nil {
					return nil, err
				}
				*col.dst += n
			}
		}
	}
	for _, ch := range order {
		ch.hidden = hidden[ch.host]
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.hidden != b.hidden {
			return !a.hidden
		}
		if a.backup != b.backup {
			return !a.backup
		}
		ta, tb := a.bytesIn+a.bytesOut, b.bytesIn+b.bytesOut
		if ta != tb {
			return ta > tb
		}
		return a.host < b.host
	})
	var total int64
	for _, ch := range order {
		if !ch.hidden {
			total += ch.bytesIn + ch.bytesOut
		}
	}
	shown, put := []any{}, []any{}
	for _, ch := range order {
		// The name HAProxy was given is the best default label there is.
		counts := map[string]int{}
		common, best := "", 0
		for _, n := range ch.names {
			counts[n]++
		}
		for _, n := range ch.names {
			if counts[n] > best {
				common, best = n, counts[n]
			}
		}
		uniq := map[string]bool{}
		var backends []string
		for _, b := range ch.backends {
			if !uniq[b] {
				uniq[b] = true
				backends = append(backends, b)
			}
		}
		sort.Strings(backends)
		bytesTotal := ch.bytesIn + ch.bytesOut
		sh := 0.0
		if !ch.hidden {
			sh = share(bytesTotal, total)
		}
		item := newMap("host", ch.host, "label", ch.label, "backends", strList(backends...), "backup", ch.backup,
			"bytes_in", ch.bytesIn, "bytes_out", ch.bytesOut, "sessions", ch.sessions, "hidden", ch.hidden,
			"default_label", common, "backend_count", int64(len(backends)), "bytes_total", bytesTotal, "share", sh)
		if ch.hidden {
			put = append(put, item)
		} else {
			shown = append(shown, item)
		}
	}
	r, since, until := rangeOf(payload, rangeKey)
	return newMap("ok", true, "range", r, "since", since, "until", until, "channels", shown, "hidden", put, "bytes_total", total), nil
}

func monitoringBackendTraffic(rangeKey string, w *monitoringWindow) (*Map, error) {
	payload, err := metricsdGet("/api/v1/metrics/servers", windowParams(rangeKey, "", w), 10*time.Second)
	if err != nil {
		return nil, err
	}
	type entry struct {
		proxy, label                string
		bytesIn, bytesOut, sessions int64
	}
	var order []*entry
	grouped := map[string]*entry{}
	for _, row := range listOf(payload, "servers") {
		proxy := strOrEmpty(get(row, "proxy"))
		if proxy == "" {
			continue
		}
		e := grouped[proxy]
		if e == nil {
			e = &entry{proxy: proxy}
			grouped[proxy] = e
			order = append(order, e)
		}
		for _, col := range []struct {
			key string
			dst *int64
		}{{"bytes_in", &e.bytesIn}, {"bytes_out", &e.bytesOut}, {"sessions", &e.sessions}} {
			n, err := intOr0(get(row, col.key))
			if err != nil {
				return nil, err
			}
			*col.dst += n
		}
	}
	var total int64
	for _, e := range order {
		e.label = monitoringDisplayName(e.proxy)
		total += e.bytesIn + e.bytesOut
	}
	sort.SliceStable(order, func(i, j int) bool {
		ti, tj := order[i].bytesIn+order[i].bytesOut, order[j].bytesIn+order[j].bytesOut
		if ti != tj {
			return ti > tj
		}
		return strings.ToLower(order[i].label) < strings.ToLower(order[j].label)
	})
	items := []any{}
	for _, e := range order {
		bt := e.bytesIn + e.bytesOut
		items = append(items, newMap("proxy", e.proxy, "bytes_in", e.bytesIn, "bytes_out", e.bytesOut, "sessions", e.sessions,
			"label", e.label, "bytes_total", bt, "share", share(bt, total)))
	}
	r, since, until := rangeOf(payload, rangeKey)
	return newMap("ok", true, "range", r, "since", since, "until", until, "backends", items, "bytes_total", total), nil
}

func monitoringBackendRequests(rangeKey string, w *monitoringWindow) (*Map, error) {
	payload, err := metricsdGet("/api/v1/metrics/backends", windowParams(rangeKey, "", w), 15*time.Second)
	if err != nil {
		return nil, err
	}
	type item struct {
		m        *Map
		label    string
		requests int64
	}
	var items []item
	for _, entry := range listOf(payload, "backends") {
		proxy := strOrEmpty(get(entry, "proxy"))
		requests, err := intOr0(get(entry, "requests"))
		if err != nil {
			return nil, err
		}
		if proxy == "" || requests <= 0 {
			continue
		}
		classes := map[string]int64{}
		var answered int64
		for _, col := range []string{"resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx"} {
			n, err := intOr0(get(entry, col))
			if err != nil {
				return nil, err
			}
			classes[col] = n
			answered += n
		}
		msValue := func(key string) (any, error) {
			v := get(entry, key)
			if v == nil {
				return nil, nil
			}
			return pyInt(v)
		}
		avg, err := msValue("response_ms_avg")
		if err != nil {
			return nil, err
		}
		peak, err := msValue("response_ms_max")
		if err != nil {
			return nil, err
		}
		bin, err := intOr0(get(entry, "bytes_in"))
		if err != nil {
			return nil, err
		}
		bout, err := intOr0(get(entry, "bytes_out"))
		if err != nil {
			return nil, err
		}
		label := monitoringDisplayName(proxy)
		items = append(items, item{m: newMap("proxy", proxy, "label", label, "requests", requests, "answered", answered,
			"resp_4xx", classes["resp_4xx"], "resp_5xx", classes["resp_5xx"],
			"share_4xx", share(classes["resp_4xx"], answered), "share_5xx", share(classes["resp_5xx"], answered),
			"response_ms_avg", avg, "response_ms_max", peak, "bytes_total", bin+bout), label: label, requests: requests})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].requests != items[j].requests {
			return items[i].requests > items[j].requests
		}
		return strings.ToLower(items[i].label) < strings.ToLower(items[j].label)
	})
	out := []any{}
	var total int64
	for _, it := range items {
		out = append(out, it.m)
		total += it.requests
	}
	r, since, until := rangeOf(payload, rangeKey)
	return newMap("ok", true, "range", r, "since", since, "until", until, "backends", out, "requests_total", total), nil
}

// ---- events and attention ----

var eventActions = []struct{ action, label string }{
	{"config.apply", "Configuration applied"}, {"config.rollback", "Configuration rolled back"},
	{"config.revert", "Configuration reverted"}, {"config.restore", "Configuration restored"},
	{"config.upload", "Configuration uploaded"}, {"site.create", "Site added"}, {"site.update", "Site changed"},
	{"site.delete", "Site removed"}, {"tcp_proxy.create", "TCP proxy added"}, {"tcp_proxy.update", "TCP proxy changed"},
	{"tcp_proxy.delete", "TCP proxy removed"}, {"udp_forward.create", "UDP forward added"},
	{"udp_forward.update", "UDP forward changed"}, {"udp_forward.delete", "UDP forward removed"},
	{"vars.update", "Variables changed"}, {"backend.state", "Server state changed"},
	{"backend.weight", "Server weight changed"}, {"service.control", "Service action"},
	{"update.apply", "Update started"}, {"restore.start", "Restore from a backup started"},
	{"system.reboot", "Reboot"}, {"geoip.countries", "Country rules changed"},
	{"adaptive.mode", "Adaptive protection mode changed"}, {"certificate.issue", "Certificate issued"},
	{"certificate.restore", "Certificate restored"}, {"certificate.standby_activate", "Standby certificate activated"},
}

var eventTransitions = map[string]string{"fired": "alert", "escalated": "alert", "recovered": "recovered"}

func ruleTitles(catalogue []any, needName bool) map[string]string {
	titles := map[string]string{}
	for _, rule := range catalogue {
		m, ok := asMap(rule)
		if !ok || (needName && !truthy(m.Value("name"))) {
			continue
		}
		titles[strOrEmpty(m.Value("name"))] = strOrEmpty(m.Value("title"))
	}
	return titles
}

func alertdStateMap(limit int) (*Map, error) {
	v, err := alertdGet("/api/v1/alerts/state", []QueryValue{{"limit", fmt.Sprint(limit)}}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	m, ok := asMap(v)
	if !ok {
		return nil, noAttr(v, "get")
	}
	return m, nil
}

func isUnavailable(err error) bool {
	var down *Unavailable
	return errors.As(err, &down)
}

func monitoringEvents(rangeKey string, w *monitoringWindow) (*Map, error) {
	now := time.Now().Unix()
	since, until := now-monitoringRangeSec[rangeKey], now
	if w != nil {
		since, until = w.since, w.until
	}
	labels := map[string]string{}
	actions := make([]string, 0, len(eventActions))
	for _, ea := range eventActions {
		labels[ea.action] = ea.label
		actions = append(actions, ea.action)
	}
	type event struct {
		ts int64
		m  *Map
	}
	var found []event
	changes := Audit().Query(AuditQuery{Actions: actions, Result: auditResultSuccess, Since: since, Until: until, Limit: maxMonitoringEvents})
	totalChanges, err := intOr0(changes.Value("total"))
	if err != nil {
		return nil, err
	}
	truncated := totalChanges > maxMonitoringEvents
	for _, row := range listOf(changes, "events") {
		action := strOrEmpty(get(row, "action"))
		ts, err := intOr0(get(row, "ts"))
		if err != nil {
			return nil, err
		}
		label := labels[action]
		if label == "" {
			label = action
		}
		found = append(found, event{ts, newMap("ts", ts, "kind", "change", "label", label,
			"object", truncRunes(strOrEmpty(get(row, "object_id")), 120), "actor", truncRunes(strOrEmpty(get(row, "actor")), 60),
			"summary", truncRunes(strOrEmpty(get(row, "summary")), 160))})
	}
	available := true
	var history *Map
	hv, err := alertdGet("/api/v1/alerts/history", []QueryValue{{"since", fmt.Sprint(since)}, {"until", fmt.Sprint(until)}, {"limit", "500"}}, 15*time.Second)
	if err != nil {
		if !isUnavailable(err) {
			return nil, err
		}
		available = false
		history = newMap()
	} else if history, _ = asMap(hv); history == nil {
		return nil, noAttr(hv, "get")
	}
	titles := map[string]string{}
	if available {
		state, err := alertdStateMap(1)
		if err != nil && !isUnavailable(err) {
			return nil, err
		}
		if err == nil {
			titles = ruleTitles(listOf(state, "catalogue"), true)
		}
	}
	var alertRows []event
	for _, row := range listOf(history, "events") {
		kind := eventTransitions[strOrEmpty(get(row, "transition"))]
		ts, err := intOr0(get(row, "ts"))
		if err != nil {
			return nil, err
		}
		// An engine older than the `until` filter answers with everything after `since`.
		if kind == "" || ts < since || ts > until {
			continue
		}
		rule := truncRunes(strOrEmpty(get(row, "rule")), 80)
		label := "Recovered"
		if kind == "alert" {
			label = "Alert"
		}
		title := titles[rule]
		if title == "" {
			title = rule
		}
		alertRows = append(alertRows, event{ts, newMap("ts", ts, "kind", kind, "label", label,
			"object", truncRunes(strOrEmpty(get(row, "subject")), 120), "actor", "",
			"summary", truncRunes(strOrEmpty(get(row, "summary")), 160), "severity", strOrEmpty(get(row, "severity")),
			"rule", rule, "title", title)})
	}
	sort.SliceStable(alertRows, func(i, j int) bool { return alertRows[i].ts < alertRows[j].ts })
	if len(alertRows) > maxMonitoringEvents {
		alertRows = alertRows[len(alertRows)-maxMonitoringEvents:]
		truncated = true
	}
	found = append(found, alertRows...)
	sort.SliceStable(found, func(i, j int) bool { return found[i].ts < found[j].ts })
	out := []any{}
	for _, e := range found {
		out = append(out, e.m)
	}
	return newMap("ok", true, "since", since, "until", until, "events", out, "truncated", truncated, "alerts_available", available), nil
}

var attentionSeverities = []string{"critical", "warning"}

func monitoringAttention() (*Map, error) {
	state, err := alertdStateMap(1)
	if err != nil {
		if isUnavailable(err) {
			return newMap("ok", true, "available", false, "items", []any{}, "more", int64(0)), nil
		}
		return nil, err
	}
	titles := ruleTitles(listOf(state, "catalogue"), false)
	type item struct {
		m        *Map
		pending  bool
		severity int
		since    int64
	}
	var items []item
	for _, group := range []struct {
		key     string
		pending bool
	}{{"active", false}, {"pending", true}} {
		for _, row := range listOf(state, group.key) {
			severity := strOrEmpty(get(row, "severity"))
			sev := -1
			for i, s := range attentionSeverities {
				if s == severity {
					sev = i
				}
			}
			if sev < 0 {
				continue
			}
			rule := strOrEmpty(get(row, "rule"))
			since, err := intOr0(get(row, "since_ts"))
			if err != nil {
				return nil, err
			}
			title := titles[rule]
			if title == "" {
				title = rule
			}
			items = append(items, item{newMap("rule", rule, "title", title, "subject", truncRunes(strOrEmpty(get(row, "subject")), 120),
				"severity", severity, "pending", group.pending, "since", since,
				"summary", truncRunes(strOrEmpty(get(row, "summary")), 200)), group.pending, sev, since})
		}
	}
	// Firing before pending, critical before warning, the newest first.
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.pending != b.pending {
			return !a.pending
		}
		if a.severity != b.severity {
			return a.severity < b.severity
		}
		return a.since > b.since
	})
	out := []any{}
	for i, it := range items {
		if i < maxAttention {
			out = append(out, it.m)
		}
	}
	return newMap("ok", true, "available", true, "items", out, "more", int64(max(0, len(items)-maxAttention))), nil
}

// ---- the routes ----

func (c *Ctx) metricsdFailure(err error) error {
	if !isUnavailable(err) {
		return err
	}
	log.Printf("metricsd unavailable: %v", err)
	return c.JSON(503, newMap("ok", false, "unavailable", true, "error", err.Error()))
}

func (a *App) registerMonitoring() {
	a.Handle("routes.api_monitoring_sites", func(c *Ctx) error {
		sites, err := listSites()
		if err != nil {
			return c.metricsdFailure(err)
		}
		return c.JSON(200, newMap("ok", true, "sites", sites))
	})

	windowed := func(f func(string, *monitoringWindow) (*Map, error)) HandlerFunc {
		return func(c *Ctx) error {
			out, err := f(c.monitoringRange(), c.monitoringWindow())
			if err != nil {
				return c.metricsdFailure(err)
			}
			return c.JSON(200, out)
		}
	}
	a.Handle("routes.api_monitoring_channels", windowed(monitoringChannels))
	a.Handle("routes.api_monitoring_backends", windowed(monitoringBackendTraffic))
	a.Handle("routes.api_monitoring_backend_requests", windowed(monitoringBackendRequests))
	a.Handle("routes.api_monitoring_events", func(c *Ctx) error {
		out, err := monitoringEvents(c.monitoringRange(), c.monitoringWindow())
		if err != nil {
			return err
		}
		return c.JSON(200, out)
	})
	a.Handle("routes.api_monitoring_attention", func(c *Ctx) error {
		out, err := monitoringAttention()
		if err != nil {
			return err
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_monitoring_channel_labels", func(c *Ctx) error {
		raw := c.silentJSONMap()
		entry := AuditEntry{ObjectType: "monitoring"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("monitoring.channel_labels", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		payload, ok := asMap(raw)
		if !ok {
			return noAttr(raw, "get")
		}
		labels, isMap := asMap(payload.Value("labels"))
		hiddenV := payload.Value("hidden")
		hidden, isList := hiddenV.([]any)
		var result *Map
		var err error
		switch {
		case !isMap:
			err = &ValueError{"labels must be an object"}
		case hiddenV != nil && !isList:
			err = &ValueError{"hidden must be a list"}
		default:
			body := newMap("labels", labels)
			// Omitted rather than empty when unchanged: "absent" means "leave it".
			if hiddenV != nil {
				body.Set("hidden", hidden)
			}
			result, err = metricsdSave("/api/v1/metrics/channel-labels", body)
		}
		if err != nil {
			if msg, refused := refusal(err); refused {
				entry.Result, entry.Detail = auditResultFailure, msg
				c.RecordRequest("monitoring.channel_labels", entry)
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.metricsdFailure(err)
		}
		entry.After, entry.Detail = result.Value("labels"), "uplink names changed"
		c.RecordRequest("monitoring.channel_labels", entry)
		return c.JSON(200, result)
	})

	a.Handle("routes.api_monitoring_monitors", func(c *Ctx) error {
		raw := c.silentJSONMap()
		entry := AuditEntry{ObjectType: "monitoring"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("monitoring.monitors", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		payload, ok := asMap(raw)
		if !ok {
			return noAttr(raw, "get")
		}
		changesV := payload.Value("monitors")
		var result *Map
		var err error
		changes, isMap := asMap(changesV)
		if !isMap || changes.Len() == 0 {
			err = &ValueError{"monitors must be a non-empty object"}
		} else {
			cleaned := newMap()
			changes.Each(func(k, v any) {
				if err != nil {
					return
				}
				name := pyStr(k)
				if pick(monitoringMonitors, name, "") == "" {
					err = &ValueError{"unknown monitor: " + truncRunes(name, 40)}
					return
				}
				if _, isB := v.(bool); !isB {
					err = &ValueError{name + " must be true or false"}
					return
				}
				cleaned.Set(name, v)
			})
			if err == nil {
				result, err = metricsdSave("/api/v1/metrics/monitors", newMap("monitors", cleaned))
			}
		}
		if err != nil {
			if msg, refused := refusal(err); refused {
				entry.Result, entry.Detail = auditResultFailure, msg
				c.RecordRequest("monitoring.monitors", entry)
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.metricsdFailure(err)
		}
		entry.After, entry.Detail = changesV, "monitors switched"
		c.RecordRequest("monitoring.monitors", entry)
		return c.JSON(200, result)
	})

	sited := func(path string, chart bool) HandlerFunc {
		return func(c *Ctx) error {
			chartName := ""
			if chart {
				raw, _ := c.queryOpt("chart")
				chartName = pick(monitoringCharts, strings.ToLower(pyStripSpace(raw)), "")
				if chartName == "" {
					return c.JSON(400, newMap("ok", false, "error", "unknown chart", "available", strList(monitoringCharts...)))
				}
			}
			rangeKey := c.monitoringRange()
			sites, err := listSites()
			if err != nil {
				return c.metricsdFailure(err)
			}
			site := c.monitoringSite(sites)
			w := c.monitoringWindow()
			params := windowParams(rangeKey, site, w)
			if chart {
				// The processor and memory charts' line per component, only when the page shows them.
				raw, _ := c.queryOpt("components")
				components := strings.ToLower(pyStripSpace(pyStr(orValue(raw, "1"))))
				on := "1"
				if components == "0" || components == "false" || components == "no" {
					on = "0"
				}
				params = append(params, QueryValue{"chart", chartName}, QueryValue{"components", on})
			}
			payload, err := metricsdGet(path, params, 15*time.Second)
			if err != nil {
				return c.metricsdFailure(err)
			}
			switch path {
			case "/api/v1/metrics/summary":
				health, _ := asMap(orValue(payload.Value("health"), newMap()))
				if health != nil {
					for _, group := range []string{"backends", "servers"} {
						labelEntries(listOf(health, group), func(m *Map) string { return monitoringDisplayName(strOrEmpty(m.Value("proxy"))) })
					}
				}
				label := ""
				if site != "" {
					label = monitoringDisplayName(site)
				}
				payload.Set("site_label", label)
			case "/api/v1/metrics/series":
				labelEntries(listOf(payload, "components"), func(m *Map) string {
					return componentLabel(strOrEmpty(m.Value("name")), strOrEmpty(m.Value("group")))
				})
			case "/api/v1/metrics/states":
				monitoringStates(payload)
			}
			return c.JSON(200, payload)
		}
	}
	a.Handle("routes.api_monitoring_summary", sited("/api/v1/metrics/summary", false))
	a.Handle("routes.api_monitoring_series", sited("/api/v1/metrics/series", true))
	a.Handle("routes.api_monitoring_states", sited("/api/v1/metrics/states", false))

	a.Handle("routes.api_monitoring_storage", func(c *Ctx) error {
		v, err := metricsdTransport().Get("/api/v1/metrics/storage", HTTPOptions{Timeout: 10 * time.Second})
		if err != nil {
			return c.metricsdFailure(err)
		}
		return c.JSON(200, v)
	})
}

// refusal reports a ValueError the view turns into a 400: a local check or
// the daemon's own refusal.
func refusal(err error) (string, bool) {
	var verr *ValueError
	var rej *Rejected
	switch {
	case errors.As(err, &verr):
		return verr.Msg, true
	case errors.As(err, &rej):
		return rej.Msg, true
	}
	return "", false
}
