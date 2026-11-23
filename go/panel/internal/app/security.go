package app

// Port of routes_security.py and services_security.py: the Adaptive
// protection section, the detection rules and the Log Explorer, all read
// from and written to guardd.

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	securityModes      = []string{"off", "monitor", "enforce"}
	adaptiveEventTypes = []string{"SCANNER_PATH", "SCANNER_PATH_DECISIVE", "QUERY_INJECTION", "SCANNER_MULTI_CATEGORY",
		"LOW_AND_SLOW_SCANNER", "NOT_FOUND_ENUMERATION", "WIDE_ENUMERATION", "MASS_ENUMERATION", "RECURRING_SCANNER",
		"INVALID_HOST_ACTIVITY", "NOSNI_PROBING", "RATE_EXCEEDED", "ERROR_RATE_EXCEEDED", "LEGACY_HAPROXY_BAN",
		"HARD_FLOOR_EPISODE", "SUBNET_CAMPAIGN"}
	limitForEvent = map[string][3]string{
		"RATE_EXCEEDED":       {"max_req_rate", "rate_window", "requests"},
		"ERROR_RATE_EXCEEDED": {"err_limit", "err_window", "errors"},
	}
	hostileMarkers = []string{"SCANNER", "QUERY_INJECTION", "SUBNET_CAMPAIGN", "INVALID_HOST", "NOSNI",
		"LEGACY_HAPROXY_BAN", "WIDE_ENUMERATION", "MASS_ENUMERATION"}
	requestFilters = []string{"since", "until", "client", "status", "host", "backend", "request_id", "method", "path",
		"limit", "before", "count", "hide_admin", "refused", "slower", "agent"}
	observedRateRe = regexp.MustCompile(`(?:req|err)_rate=(\d+)`)
	limitInRe      = regexp.MustCompile(`limit=(\d+)`)
	csvNumberRe    = regexp.MustCompile(`^(?:-?\d+|-+)$`)
	exportColumns  = [][2]string{{"time_utc", ""}, {"status", "status"}, {"refused", "refusal"}, {"method", "method"},
		{"host", "host"}, {"path", "path"}, {"backend", "backend"}, {"server", "server"}, {"client", "client"},
		{"server_answer_ms", "response_ms"}, {"whole_request_ms", "duration_ms"}, {"bytes", "bytes_out"},
		{"ended", "term"}, {"timers", "times"}, {"ban_rule", "ban_reason"}, {"user_agent", "user_agent"},
		{"request_id", "request_id"}}
)

const exportRows = 10000

func summaryFilters() []string {
	var out []string
	for _, k := range requestFilters {
		if k != "limit" && k != "before" && k != "count" {
			out = append(out, k)
		}
	}
	return out
}

// guarddFailure is unavailable_payload with its 503.
func (c *Ctx) guarddFailure(err error) error {
	if !isUnavailable(err) {
		return err
	}
	log.Printf("guardd unavailable: %v", err)
	return c.JSON(503, newMap("ok", false, "unavailable", true, "error", err.Error()))
}

func (c *Ctx) argInt(name string) (int64, bool, bool) {
	raw, has := c.queryOpt(name)
	if !has || pyStripSpace(raw) == "" {
		return 0, false, has
	}
	n, err := parsePyIntString(raw)
	return n, err == nil, has
}

// simulatorParams is simulator_params: the what-if weights and knobs.
func (c *Ctx) simulatorParams() []QueryValue {
	var params []QueryValue
	for _, et := range adaptiveEventTypes {
		if n, ok, _ := c.argInt("w." + et); ok {
			params = append(params, intParam("w."+et, max(0, min(100, n))))
		}
	}
	for _, knob := range []struct {
		name      string
		low, high int64
	}{{"cap", 1, 100}, {"window", 3600, 30 * 86400}, {"decay", 0, 30 * 86400}} {
		if n, ok, _ := c.argInt(knob.name); ok {
			params = append(params, intParam(knob.name, max(knob.low, min(knob.high, n))))
		}
	}
	return params
}

func annotate(entry any) error {
	m, ok := asMap(entry)
	if !ok {
		return noAttr(entry, "get")
	}
	if addr := strOrEmpty(m.Value("ip")); addr != "" {
		m.Set("country", getCountryCode(addr))
	}
	return nil
}

// explain is _explain: what was measured, against what, and which setting moves it.
func explain(contribution *Map, limits map[string]*Map) {
	known := limits[strOrEmpty(contribution.Value("site"))]
	if known != nil {
		contribution.Set("site_name", known.Value("site"))
		contribution.Set("site_domain", known.Value("domain"))
	}
	mapping, hasMapping := limitForEvent[strOrEmpty(contribution.Value("event_type"))]
	detail := strOrEmpty(contribution.Value("detail"))
	m := observedRateRe.FindStringSubmatch(detail)
	if !hasMapping || m == nil {
		return
	}
	observed, _ := parsePyIntString(m[1])
	contribution.Set("observed", observed)
	contribution.Set("unit", mapping[2])
	contribution.Set("setting", mapping[0])
	var limit int64
	if lm := limitInRe.FindStringSubmatch(detail); lm != nil {
		limit, _ = parsePyIntString(lm[1])
	} else if known != nil {
		switch v := known.Value(mapping[0]).(type) {
		case int64:
			limit = v
		case bool:
			if v {
				limit = 1
			}
		default:
			return
		}
	} else {
		return
	}
	if limit <= 0 {
		return
	}
	contribution.Set("limit", limit)
	if known != nil {
		contribution.Set("window", known.Value(mapping[1]))
	}
	contribution.Set("over_by", max(0, observed-limit))
	contribution.Set("suggested", max(limit+1, int64(float64(observed)*1.5)))
}

func withholdAdviceFromAttackers(contributions []any) {
	hostile := false
	for _, c := range contributions {
		et := strOrEmpty(get(c, "event_type"))
		for _, marker := range hostileMarkers {
			if strings.Contains(et, marker) {
				hostile = true
			}
		}
	}
	if !hostile {
		return
	}
	for _, c := range contributions {
		if m, ok := asMap(c); ok && has(m, "suggested") {
			m.Delete("suggested")
			m.Set("advice_withheld", "the address is probing the gateway")
		}
	}
}

// requestParams is _request_params: the closed set of Log Explorer filters.
func (c *Ctx) requestParams(keys []string) []QueryValue {
	var params []QueryValue
	for _, k := range keys {
		raw, _ := c.queryOpt(k)
		if v := pyStripSpace(raw); v != "" {
			params = append(params, QueryValue{k, truncRunes(v, 200)})
		}
	}
	return params
}

// csvCell is _csv_cell: a cell a spreadsheet would read as a formula stays text.
func csvCell(v any) string {
	text := ""
	if v != nil {
		text = pyStr(v)
	}
	if text != "" && strings.ContainsAny(text[:1], "=+-@\t\r") && !csvNumberRe.MatchString(text) {
		text = "'" + text
	}
	return text
}

// csvRow is csv.writer(lineterminator="\r\n").writerow with QUOTE_MINIMAL.
func csvRow(cells []string) string {
	out := make([]string, len(cells))
	for i, cell := range cells {
		if strings.ContainsAny(cell, ",\"\r\n") {
			cell = `"` + strings.ReplaceAll(cell, `"`, `""`) + `"`
		}
		out[i] = cell
	}
	return strings.Join(out, ",") + "\r\n"
}

func pyUTCStamp(ts float64) string {
	micro := math.RoundToEven(ts * 1e6)
	return time.UnixMicro(int64(micro)).UTC().Format("2006-01-02T15:04:05Z")
}

func lenOf(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case *Map:
		return x.Len()
	case string:
		return pyLen(x)
	}
	return 0
}

func (a *App) registerSecurity() {
	getter := func(f func(c *Ctx) (any, error)) HandlerFunc {
		return func(c *Ctx) error {
			out, err := f(c)
			if err != nil {
				return c.guarddFailure(err)
			}
			return c.JSON(200, out)
		}
	}
	a.Handle("routes.api_detection_rules", getter(func(*Ctx) (any, error) {
		return guarddGetAny("/api/v1/guard/signatures", nil, 15*time.Second)
	}))
	a.Handle("routes.api_traps", getter(func(*Ctx) (any, error) {
		return guarddGetAny("/api/v1/guard/traps", nil, 15*time.Second)
	}))
	a.Handle("routes.api_detection_context", getter(func(*Ctx) (any, error) {
		return guarddGetAny("/api/v1/guard/detection-context", nil, 15*time.Second)
	}))
	a.Handle("routes.api_detection_rule_candidates", getter(func(*Ctx) (any, error) {
		return guarddGetAny("/api/v1/guard/signatures/candidates", nil, 15*time.Second)
	}))
	a.Handle("routes.api_adaptive_health", getter(func(*Ctx) (any, error) {
		return guarddGetAny("/api/v1/guard/health", nil, 15*time.Second)
	}))
	a.Handle("routes.api_adaptive_quality", getter(func(c *Ctx) (any, error) {
		days := int64(7)
		if raw, has := c.queryOpt("days"); has {
			if n, err := parsePyIntString(raw); err == nil {
				days = n
			}
		}
		return guarddGetAny("/api/v1/guard/quality", []QueryValue{intParam("days", max(1, min(days, 30)))}, 15*time.Second)
	}))
	a.Handle("routes.api_adaptive_shadow", getter(func(c *Ctx) (any, error) {
		payload, err := guarddGet("/api/v1/guard/shadow", c.simulatorParams(), 15*time.Second)
		if err != nil {
			return nil, err
		}
		for _, e := range listOf(payload, "addresses") {
			if err := annotate(e); err != nil {
				return nil, err
			}
		}
		return payload, nil
	}))
	a.Handle("routes.api_adaptive_rate_warnings", getter(func(c *Ctx) (any, error) {
		limit := int64(100)
		if raw, _ := c.queryOpt("limit"); raw != "" {
			if n, err := parsePyIntString(raw); err == nil {
				limit = n
			}
		}
		limit = max(1, min(500, limit))
		payload, err := guarddGet("/api/v1/guard/rate-warnings", []QueryValue{intParam("limit", limit)}, 15*time.Second)
		if err != nil {
			return nil, err
		}
		limits, err := siteLimits()
		if err != nil {
			log.Printf("cannot read site limits for the rate warnings: %v", err)
			limits = map[string]*Map{}
		}
		for _, row := range append(append([]any{}, listOf(payload, "open")...), listOf(payload, "recent")...) {
			if err := annotate(row); err != nil {
				return nil, err
			}
			if known := limits[strOrEmpty(get(row, "site"))]; known != nil {
				row.(*Map).Set("site_name", known.Value("site"))
				row.(*Map).Set("site_domain", known.Value("domain"))
			}
		}
		return payload, nil
	}))
	a.Handle("routes.api_adaptive_ip", func(c *Ctx) error {
		addr := validIP(c.Query("ip"))
		if addr == "" {
			return c.JSON(400, newMap("ok", false, "error", "invalid ip"))
		}
		payload, err := guarddGet("/api/v1/guard/ip", append([]QueryValue{{"ip", addr}}, c.simulatorParams()...), 15*time.Second)
		if err != nil {
			return c.guarddFailure(err)
		}
		if err := annotate(payload); err != nil {
			return err
		}
		limits, err := siteLimits()
		if err != nil {
			log.Printf("cannot read site limits for the findings: %v", err)
			limits = map[string]*Map{}
		}
		contributions := listOf(payload, "contributions")
		for _, contribution := range contributions {
			m, ok := asMap(contribution)
			if !ok {
				return noAttr(contribution, "get")
			}
			explain(m, limits)
		}
		withholdAdviceFromAttackers(contributions)
		return c.JSON(200, payload)
	})

	a.Handle("routes.api_adaptive_bans", func(c *Ctx) error {
		detail := strings.HasSuffix(c.R.URL.Path, "/ban")
		keys := []string{"q", "terms", "since", "sort", "direction", "offset", "snapshot"}
		if detail {
			keys = []string{"id", "ip", "at"}
		}
		var params []QueryValue
		for _, k := range keys {
			if v, has := c.queryOpt(k); has {
				limit := 100
				if k == "terms" {
					limit = 2048
				}
				params = append(params, QueryValue{k, truncRunes(v, limit)})
			}
		}
		payload, err := guarddAdaptiveBans(params, detail)
		if err != nil {
			return c.guarddFailure(err)
		}
		status := 200
		if !truthy(payload.Value("ok")) {
			status = 400
			if detail {
				status = 404
			}
		}
		return c.JSON(status, payload)
	})

	a.Handle("routes.api_set_detection_context", func(c *Ctx) error {
		entry := AuditEntry{ObjectType: "detection_context"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("adaptive.rules", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		if c.R.ContentLength > 131072 {
			return c.JSON(413, newMap("ok", false, "error", "settings too large"))
		}
		current, err := guarddGet("/api/v1/guard/detection-context", nil, 15*time.Second)
		if err != nil {
			return c.guarddFailure(err)
		}
		before, found := current.Get("config")
		if !found {
			return fmt.Errorf("KeyError: 'config'")
		}
		payload := c.SilentJSON()
		body, isMap := asMap(payload)
		if !isMap {
			return c.JSON(400, newMap("ok", false, "error", "expected an object"))
		}
		resultV, err := guarddChangeAny("/api/v1/guard/detection-context", body, 15*time.Second)
		if err != nil {
			if msg, refused := refusal(err); refused {
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.guarddFailure(err)
		}
		result, err := asObject(resultV, nil)
		if err != nil {
			return err
		}
		after, found := result.Get("config")
		if !found {
			return fmt.Errorf("KeyError: 'config'")
		}
		entry.Before, entry.After, entry.Result, entry.Detail = before, after, auditResultSuccess, "contextual detection settings"
		c.RecordRequest("adaptive.rules", entry)
		return c.JSON(200, result)
	})

	a.Handle("routes.api_detection_preview", func(c *Ctx) error {
		// Never audited, even on failure: its query can carry a password-reset token.
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		if c.R.ContentLength > 8192 {
			return c.JSON(413, newMap("ok", false, "error", "request too large"))
		}
		body, isMap := asMap(c.SilentJSON())
		if !isMap {
			return c.JSON(400, newMap("ok", false, "error", "invalid request fields"))
		}
		out, err := guarddChangeAny("/api/v1/guard/detection-preview", body, 15*time.Second)
		if err != nil {
			if _, refused := refusal(err); refused {
				return c.JSON(400, newMap("ok", false, "error", "invalid request fields"))
			}
			if isUnavailable(err) {
				return c.JSON(503, newMap("ok", false, "unavailable", true, "error", "detection engine unavailable"))
			}
			return err
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_set_traps", func(c *Ctx) error {
		raw := c.silentJSONMap()
		entry := AuditEntry{ObjectType: "detection_rules"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("adaptive.rules", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		current, err := guarddGet("/api/v1/guard/traps", nil, 15*time.Second)
		if err != nil {
			return c.guarddFailure(err)
		}
		before := orValue(current.Value("trap_hosts"), []any{})
		payload, isMap := asMap(raw)
		var hosts []any
		ok := false
		if isMap {
			hosts, ok = payload.Value("hosts").([]any)
		}
		var resultV any
		if !ok {
			err = &ValueError{"expected a list of names"}
		} else {
			resultV, err = guarddChangeAny("/api/v1/guard/traps", newMap("hosts", hosts), 15*time.Second)
		}
		if err != nil {
			if msg, refused := refusal(err); refused {
				entry.Result, entry.Detail = auditResultFailure, truncRunes(msg, 300)
				c.RecordRequest("adaptive.rules", entry)
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.guarddFailure(err)
		}
		result, err := asObject(resultV, nil)
		if err != nil {
			return err
		}
		entry.Before = newMap("trap_hosts", before)
		entry.After = newMap("trap_hosts", result.Value("trap_hosts"))
		entry.Detail = "trap names changed"
		c.RecordRequest("adaptive.rules", entry)
		return c.JSON(200, result)
	})

	a.Handle("routes.api_dismiss_detection_rule_candidate", func(c *Ctx) error {
		raw := c.silentJSONMap()
		entry := AuditEntry{ObjectType: "detection_rules"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("adaptive.rules", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		payload, isMap := asMap(raw)
		if !isMap {
			return c.JSON(400, newMap("ok", false, "error", "expected an object"))
		}
		path := pyStripSpace(strOrEmpty(payload.Value("path")))
		if !strings.HasPrefix(path, "/") {
			return c.JSON(400, newMap("ok", false, "error", "expected a path"))
		}
		result, err := guarddChangeAny("/api/v1/guard/signatures/candidates/dismiss",
			newMap("path", path, "restore", truthy(payload.Value("restore")), "host", strOrEmpty(payload.Value("host"))), 15*time.Second)
		if err != nil {
			if msg, refused := refusal(err); refused {
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.guarddFailure(err)
		}
		entry.ObjectID = truncRunes(strOrEmpty(payload.Value("path")), 200)
		entry.Detail = "suggestion hidden"
		if truthy(payload.Value("restore")) {
			entry.Detail = "suggestion restored"
		}
		c.RecordRequest("adaptive.rules", entry)
		return c.JSON(200, result)
	})

	a.Handle("routes.api_set_detection_rules", func(c *Ctx) error {
		raw := c.silentJSONMap()
		entry := AuditEntry{ObjectType: "detection_rules"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("adaptive.rules", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		beforeV, err := guarddGetAny("/api/v1/guard/signatures", nil, 15*time.Second)
		if err != nil {
			return c.guarddFailure(err)
		}
		payload, isMap := asMap(raw)
		var resultV any
		if !isMap {
			err = &ValueError{"expected an object"}
		} else {
			resultV, err = guarddChangeAny("/api/v1/guard/signatures", newMap(
				"added", orValue(payload.Value("added"), newMap()), "disabled", orValue(payload.Value("disabled"), []any{})), 30*time.Second)
		}
		if err != nil {
			if msg, refused := refusal(err); refused {
				entry.Result, entry.Detail = auditResultFailure, msg
				c.RecordRequest("adaptive.rules", entry)
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			if isUnavailable(err) {
				entry.Result, entry.Detail = auditResultFailure, err.Error()
				c.RecordRequest("adaptive.rules", entry)
			}
			return c.guarddFailure(err)
		}
		before, err := asObject(beforeV, nil)
		if err != nil {
			return err
		}
		result, err := asObject(resultV, nil)
		if err != nil {
			return err
		}
		entry.Before = newMap("added", before.Value("added"), "disabled", before.Value("disabled"))
		entry.After = newMap("added", result.Value("added"), "disabled", result.Value("disabled"))
		entry.Detail = fmt.Sprintf("%d added, %d suppressed", lenOf(orValue(result.Value("added"), newMap())),
			lenOf(orValue(result.Value("disabled"), []any{})))
		c.RecordRequest("adaptive.rules", entry)
		log.Printf("Detection rules changed by %s", c.User())
		return c.JSON(200, result)
	})

	// The four settings that answer with the engine's new state.
	setting := func(action string, check func(payload *Map) (any, error), path string, timeout time.Duration,
		audit func(result *Map, entry *AuditEntry)) HandlerFunc {
		return func(c *Ctx) error {
			raw := c.silentJSONMap()
			payload, isMap := asMap(raw)
			if !isMap {
				return noAttr(raw, "get")
			}
			entry := AuditEntry{ObjectType: "adaptive_protection"}
			if !c.Superadmin() {
				entry.Result, entry.Detail = auditResultDenied, "superadmin required"
				c.RecordRequest(action, entry)
				return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
			}
			body, err := check(payload)
			var resultV any
			if err == nil {
				resultV, err = guarddChangeAny(path, body, timeout)
			}
			if err != nil {
				msg, refused := refusal(err)
				if refused || isUnavailable(err) {
					if !refused {
						msg = err.Error()
					}
					entry.Result, entry.Detail = auditResultFailure, msg
					c.RecordRequest(action, entry)
				}
				if refused {
					return c.JSON(400, newMap("ok", false, "error", msg))
				}
				return c.guarddFailure(err)
			}
			result, err := asObject(resultV, nil)
			if err != nil {
				return err
			}
			audit(result, &entry)
			c.RecordRequest(action, entry)
			return c.JSON(200, result)
		}
	}
	boolField := func(payload *Map) (bool, error) {
		v, isBool := payload.Value("enabled").(bool)
		if !isBool {
			return false, &ValueError{"enabled must be true or false"}
		}
		return v, nil
	}
	a.Handle("routes.api_adaptive_ban_durations", setting("adaptive.ban_durations", func(payload *Map) (any, error) {
		list, ok := payload.Value("durations").([]any)
		if !ok || len(list) == 0 {
			return nil, &ValueError{"ban durations must be a non-empty list"}
		}
		if len(list) > 6 {
			return nil, &ValueError{"at most 6 steps"}
		}
		steps := []any{}
		for _, v := range list {
			if _, isBool := v.(bool); isBool {
				return nil, &ValueError{"each step must be a whole number of seconds"}
			}
			n, err := pyInt(v)
			if err != nil {
				return nil, &ValueError{"each step must be a whole number of seconds"}
			}
			if n < 60 || n > 365*86400 {
				return nil, &ValueError{"each step must be between 60 seconds and 365 days"}
			}
			steps = append(steps, n)
		}
		for i := 1; i < len(steps); i++ {
			if steps[i].(int64) < steps[i-1].(int64) {
				return nil, &ValueError{"each step must be at least as long as the one before"}
			}
		}
		return newMap("durations", steps), nil
	}, "/api/v1/guard/ban-durations", 15*time.Second, func(result *Map, entry *AuditEntry) {
		entry.After = newMap("durations", result.Value("ban_durations_seconds"))
		log.Printf("Adaptive ban durations set by %s", entry.Actor)
	}))
	a.Handle("routes.api_adaptive_first_step_page", setting("adaptive.first_step_page", func(payload *Map) (any, error) {
		v, err := boolField(payload)
		if err != nil {
			return nil, err
		}
		return newMap("enabled", v), nil
	}, "/api/v1/guard/first-step-page", 15*time.Second, func(result *Map, entry *AuditEntry) {
		state := asMapOr(orValue(result.Value("first_step_page"), newMap()))
		changed, found := state.Get("changed")
		if !found {
			changed = int64(0)
		}
		entry.After = newMap("enabled", state.Value("enabled"))
		entry.Detail = "first steps turned into cut-offs: " + pyStr(changed)
	}))
	a.Handle("routes.api_adaptive_shield", setting("adaptive.shield", func(payload *Map) (any, error) {
		v, err := boolField(payload)
		if err != nil {
			return nil, err
		}
		return newMap("enabled", v), nil
	}, "/api/v1/guard/shield", 15*time.Second, func(result *Map, entry *AuditEntry) {
		state := asMapOr(orValue(result.Value("path_shield"), newMap()))
		value := func(k string) string {
			v, found := state.Get(k)
			if !found {
				return "0"
			}
			return pyStr(v)
		}
		entry.After = newMap("enabled", state.Value("enabled"))
		entry.Detail = fmt.Sprintf("segments %s, paths %s", value("segments"), value("paths"))
	}))

	a.Handle("routes.api_adaptive_mode", func(c *Ctx) error {
		raw := c.silentJSONMap()
		payload, isMap := asMap(raw)
		if !isMap {
			return noAttr(raw, "get")
		}
		requested := strOrEmpty(payload.Value("mode"))
		entry := AuditEntry{ObjectType: "adaptive_protection", ObjectID: requested}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("adaptive.mode", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		mode := strings.ToLower(pyStripSpace(requested))
		var resultV any
		var err error
		if pick(securityModes, mode, "") == "" {
			err = &ValueError{"mode must be one of " + strings.Join(securityModes, ", ")}
		} else {
			resultV, err = guarddSetMode(mode)
		}
		if err != nil {
			msg, refused := refusal(err)
			if refused || isUnavailable(err) {
				if !refused {
					msg = err.Error()
				}
				entry.Result, entry.Detail = auditResultFailure, msg
				c.RecordRequest("adaptive.mode", entry)
			}
			if refused {
				return c.JSON(400, newMap("ok", false, "error", msg))
			}
			return c.guarddFailure(err)
		}
		result, err := asObject(resultV, nil)
		if err != nil {
			return err
		}
		objectID, found := result.Get("mode")
		if !found {
			objectID = ""
		}
		c.RecordRequest("adaptive.mode", AuditEntry{ObjectType: "adaptive_protection", ObjectID: pyStr(objectID),
			Before: newMap("mode", result.Value("previous")), After: newMap("mode", result.Value("mode")),
			Detail: fmt.Sprintf("banned %d, lifted %d", lenOf(orValue(result.Value("applied"), []any{})),
				lenOf(orValue(result.Value("lifted"), []any{})))})
		log.Printf("Adaptive protection mode set to %s by %s", pyStr(result.Value("mode")), c.User())
		return c.JSON(200, result)
	})

	// ---- Log Explorer ----
	a.Handle("routes.api_request_log", getter(func(c *Ctx) (any, error) {
		return guarddRequestLog("/api/v1/guard/requests", c.requestParams(requestFilters))
	}))
	a.Handle("routes.api_request_log_summary", getter(func(c *Ctx) (any, error) {
		return guarddRequestLog("/api/v1/guard/requests/summary", c.requestParams(summaryFilters()))
	}))
	a.Handle("routes.api_request_log_status", getter(func(*Ctx) (any, error) {
		return guarddRequestLog("/api/v1/guard/requests/status", nil)
	}))
	a.Handle("routes.api_live_memory", getter(func(*Ctx) (any, error) {
		return guarddRequestLog("/api/v1/guard/live/memory", nil)
	}))

	a.Handle("routes.api_request_log_export", func(c *Ctx) error {
		filename := time.Now().UTC().Format("requests-20060102-1504.csv")
		c.W.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		c.W.Header().Set("Cache-Control", "no-store")
		c.writeHead(200, "text/csv; charset=utf-8")
		flusher, _ := c.W.(http.Flusher)
		write := func(s string) {
			_, _ = c.W.Write([]byte(s))
			if flusher != nil {
				flusher.Flush()
			}
		}
		header := make([]string, len(exportColumns))
		for i, col := range exportColumns {
			header[i] = col[0]
		}
		write(csvRow(header))
		params := c.requestParams(summaryFilters())
		written, before := 0, ""
		for written < exportRows {
			page := append(append([]QueryValue{}, params...), QueryValue{"limit", "500"}, QueryValue{"count", "0"})
			if before != "" {
				page = append(page, QueryValue{"before", before})
			}
			found, err := guarddRequestLog("/api/v1/guard/requests", page)
			if err != nil {
				log.Printf("request log export stopped: %v", err)
				break
			}
			rows := listOf(found, "requests")
			if len(rows) > exportRows-written {
				rows = rows[:exportRows-written]
			}
			var chunk strings.Builder
			for _, row := range rows {
				m, ok := asMap(row)
				if !ok {
					return nil // the AttributeError ended the stream where it got to
				}
				ts, err := pyFloatStrict(orValue(m.Value("ts"), int64(0)))
				if err != nil {
					return nil
				}
				cells := make([]string, len(exportColumns))
				for i, col := range exportColumns {
					if col[1] == "" {
						cells[i] = pyUTCStamp(ts)
					} else {
						cells[i] = csvCell(m.Value(col[1]))
					}
				}
				chunk.WriteString(csvRow(cells))
			}
			written += len(rows)
			write(chunk.String())
			before = strOrEmpty(found.Value("next"))
			if before == "" || found.Value("ok") == false {
				break
			}
		}
		return nil
	})

	a.Handle("routes.api_request_log_enabled", func(c *Ctx) error {
		raw := c.silentJSONMap()
		payload, isMap := asMap(raw)
		if !isMap {
			return noAttr(raw, "get")
		}
		wanted := truthy(payload.Value("enabled"))
		objectID := strings.ToLower(pyStr(wanted))
		entry := AuditEntry{ObjectType: "request_log", ObjectID: objectID}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("request_log.enabled", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		result, err := guarddPostObject("/api/v1/guard/requests/enabled", newMap("enabled", wanted), 30*time.Second)
		if err != nil {
			if isUnavailable(err) {
				entry.Result, entry.Detail = auditResultFailure, err.Error()
				c.RecordRequest("request_log.enabled", entry)
			}
			return c.guarddFailure(err)
		}
		entry.After, entry.Result = newMap("enabled", result.Value("enabled")), auditResultSuccess
		entry.Summary = "recording stopped"
		if truthy(result.Value("enabled")) {
			entry.Summary = "recording requests"
		}
		c.RecordRequest("request_log.enabled", entry)
		return c.JSON(200, result)
	})

	a.Handle("routes.api_live_memory_set", func(c *Ctx) error {
		payloadV := c.SilentJSON()
		payload, isMap := asMap(payloadV)
		var wanted any
		if isMap {
			wanted = payload.Value("budget_mib")
		}
		entry := AuditEntry{ObjectType: "request_log", ObjectID: pyStr(wanted)}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("request_log.memory", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		status, result := 0, (*Map)(nil)
		if !isMap {
			status, result = 400, newMap("ok", false, "error", "expected an object")
		} else {
			budget, okB := payload.Value("budget_mib").(int64)
			revision, okR := payload.Value("revision").(int64)
			if !okB || !okR {
				status, result = 400, newMap("ok", false, "error", "budget_mib and revision must be whole numbers")
			} else {
				answer, err := guarddPostObject("/api/v1/guard/live/memory", newMap("budget_mib", budget, "revision", revision), 15*time.Second)
				if err != nil {
					if isUnavailable(err) {
						entry.Result, entry.Detail = auditResultFailure, err.Error()
						c.RecordRequest("request_log.memory", entry)
					}
					return c.guarddFailure(err)
				}
				switch {
				case answer.Value("ok") != false:
					status = 200
				case truthy(answer.Value("conflict")):
					status = 409
				default:
					status = 400
				}
				result = answer
			}
		}
		if status != 200 {
			entry.Result = auditResultFailure
			entry.Detail = pyStr(orValue(result.Value("error"), "refused"))
			c.RecordRequest("request_log.memory", entry)
			return c.JSON(status, result)
		}
		dropped, found := result.Get("dropped")
		if !found {
			dropped = int64(0)
		}
		summary := "latest requests in memory: configured profile"
		if truthy(result.Value("budget_mib")) {
			summary = fmt.Sprintf("latest requests in memory: %s MiB", pyStr(result.Value("budget_mib")))
		}
		c.RecordRequest("request_log.memory", AuditEntry{ObjectType: "request_log", ObjectID: pyStr(result.Value("budget_mib")),
			After: newMap("budget_mib", result.Value("budget_mib")), Result: auditResultSuccess, Summary: summary,
			Detail: "dropped " + pyStr(dropped)})
		return c.JSON(200, result)
	})
}
