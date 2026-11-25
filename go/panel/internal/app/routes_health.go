package app

// Port of routes_health.py with healthd_client.py: the health page's API,
// a proxy to the root haproxy-healthd over its Unix socket.

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"
)

func healthdTransport() *UnixHTTP {
	return &UnixHTTP{
		Service:     "haproxy-healthd",
		SocketPath:  strings.TrimSpace(envOr("HEALTHD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-healthd.sock")),
		TokenHeader: "X-Healthd-Token",
		Token:       strings.TrimSpace(os.Getenv("HEALTHD_TOKEN")),
	}
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// healthdCall is _get_json / _post_json: requests' raise_for_status unless the
// status is accepted, and a non-JSON body as {"ok": False, "error": ...}.
func healthdCall(method, path string, params []QueryValue, body any, timeout time.Duration, accepted ...int) (any, error) {
	u := healthdTransport()
	target := "http://localhost" + path
	if len(params) > 0 {
		vals := make([]string, 0, len(params))
		for _, p := range params {
			vals = append(vals, url.QueryEscape(p.Key)+"="+url.QueryEscape(p.Value))
		}
		target += "?" + strings.Join(vals, "&")
	}
	var reader io.Reader
	if method == http.MethodPost {
		text, err := pyyaml.JSONDumps(body, true, false)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(text)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if u.Token != "" {
		req.Header.Set(u.TokenHeader, u.Token)
	}
	resp, err := u.client(timeout).Do(req)
	if err != nil {
		return nil, &Unavailable{pyOSError(err)}
	}
	defer resp.Body.Close()
	raw, err := readBoundedBody(resp, maxDaemonResponseBytes)
	if err != nil {
		return nil, &Unavailable{pyOSError(err)}
	}
	ok := false
	for _, code := range accepted {
		ok = ok || code == resp.StatusCode
	}
	if !ok && resp.StatusCode >= 400 {
		kind := "Client Error"
		if resp.StatusCode >= 500 {
			kind = "Server Error"
		}
		return nil, &Unavailable{fmt.Sprintf("%d %s: %s for url: %s", resp.StatusCode, kind, httpReason(resp.StatusCode), u.displayURL(path, params))}
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return newMap("ok", false, "error", "non-json response", "text", truncRunes(strings.ToValidUTF8(string(raw), "�"), 2000)), nil
	}
	return v, nil
}

// noAttr is the AttributeError a view hits calling a dict method on a non-dict.
func noAttr(v any, attr string) error {
	return fmt.Errorf("'%s' object has no attribute '%s'", pyTypeName(v), attr)
}

// healthJSONError is the broad "except Exception" of each view: 502 with str(e).
func (c *Ctx) healthJSONError(what string, err error) error {
	log.Printf("healthd %s error: %v", what, err)
	return c.JSON(502, newMap("ok", false, "error", err.Error()))
}

// queryInt is int(request.args.get(name, def)), ok=false on a ValueError.
func (c *Ctx) queryInt(name, def string) (int64, bool) {
	raw := def
	if vals, has := c.R.URL.Query()[name]; has && len(vals) > 0 {
		raw = vals[0]
	}
	n, err := parsePyIntString(raw)
	return n, err == nil
}

// fnmatchRe is fnmatch.translate (POSIX: case-sensitive, '*' crosses '/').
func fnmatchRe(pat string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	rs := []rune(pat)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(rs) && rs[j] == '!' {
				j++
			}
			if j < len(rs) && rs[j] == ']' {
				j++
			}
			for j < len(rs) && rs[j] != ']' {
				j++
			}
			if j >= len(rs) {
				b.WriteString(`\[`)
				continue
			}
			stuff := string(rs[i+1 : j])
			i = j
			neg := strings.HasPrefix(stuff, "!")
			if neg {
				stuff = stuff[1:]
			}
			stuff = strings.ReplaceAll(stuff, `\`, `\\`)
			if neg {
				b.WriteString("[^" + stuff + "]")
			} else {
				b.WriteString("[" + stuff + "]")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(`\A\b\B`) // matches nothing, as a bad pattern raised and was skipped
	}
	return re
}

// strField is (payload.get(key) or "") for a value the view then calls
// .strip() on: a truthy non-string is the AttributeError a 500 came from.
func strField(payload *Map, key string) (string, error) {
	v := payload.Value(key)
	if !truthy(v) {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", noAttr(v, "strip")
	}
	return s, nil
}

func (a *App) registerHealth() {
	a.Handle("routes.api_control_plane_health", func(c *Ctx) error {
		return c.JSON(200, newMap("ok", true, "service", "haproxy-admin"))
	})

	a.Handle("routes.api_health_status", func(c *Ctx) error {
		var params []QueryValue
		if c.queryDefault("refresh", "0") == "1" {
			params = []QueryValue{{"refresh", "1"}}
		}
		data, err := healthdCall(http.MethodGet, "/api/v1/health/status", params, nil, 12*time.Second)
		if err != nil {
			return c.healthJSONError("status", err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_health_events", func(c *Ctx) error {
		limit, ok := c.queryInt("limit", "50")
		if !ok {
			limit = 50
		}
		limit = max(1, min(limit, 500))
		data, err := healthdCall(http.MethodGet, "/api/v1/health/events", []QueryValue{{"limit", fmt.Sprint(limit)}}, nil, 10*time.Second)
		if err != nil {
			return c.healthJSONError("events", err)
		}
		return c.JSON(200, data)
	})

	logs := func(what, param, path string) HandlerFunc {
		return func(c *Ctx) error {
			name := pyStripSpace(c.queryDefault(param, ""))
			if name == "" {
				return c.JSON(400, newMap("ok", false, "error", param+" is required"))
			}
			tail, ok1 := c.queryInt("tail", "200")
			since, ok2 := c.queryInt("since", "3600")
			if !ok1 || !ok2 {
				tail, since = 200, 3600
			}
			data, err := healthdCall(http.MethodGet, path, []QueryValue{{param, name}, {"tail", fmt.Sprint(tail)},
				{"since", fmt.Sprint(since)}}, nil, 20*time.Second)
			if err != nil {
				return c.healthJSONError(what, err)
			}
			return c.JSON(200, data)
		}
	}
	a.Handle("routes.api_health_logs_systemd", logs("logs systemd", "unit", "/api/v1/health/logs/systemd"))
	a.Handle("routes.api_health_logs_docker", logs("logs docker", "container", "/api/v1/health/logs/docker"))

	a.Handle("routes.api_health_recent_systemd", func(c *Ctx) error {
		limit, ok := c.queryInt("limit", "50")
		if !ok {
			limit = 50
		}
		limit = max(1, min(limit, 500))
		params := []QueryValue{{"limit", fmt.Sprint(limit)}}
		q := c.R.URL.Query()
		_, hasUnit := q["unit"]
		_, hasUnits := q["units"]
		if hasUnit || hasUnits {
			var units []string
			seen := map[string]bool{}
			for _, raw := range append(append([]string{}, q["unit"]...), q["units"]...) {
				for _, part := range strings.Split(raw, ",") {
					unit := strings.TrimFunc(part, pyIsSpace)
					if unit == "" || seen[unit] {
						continue
					}
					seen[unit] = true
					units = append(units, unit)
				}
			}
			if len(units) > 0 {
				for _, unit := range units {
					params = append(params, QueryValue{"unit", unit})
				}
			} else {
				// Preserve the distinction between omitted and explicitly empty.
				params = append(params, QueryValue{"units", ""})
			}
		}
		data, err := healthdCall(http.MethodGet, "/api/v1/health/recent-systemd", params, nil, 20*time.Second, 400)
		if err != nil {
			return c.healthJSONError("recent systemd logs", err)
		}
		m, isMap := asMap(data)
		if !isMap {
			return c.healthJSONError("recent systemd logs", noAttr(data, "get"))
		}
		status := 200
		if m.Value("ok") == false && truthy(m.Value("invalid_units")) {
			status = 400
		}
		return c.JSON(status, m)
	})

	a.Handle("routes.api_health_capabilities", func(c *Ctx) error {
		data, err := healthdCall(http.MethodGet, "/api/v1/control/capabilities", nil, nil, 10*time.Second)
		if err != nil {
			return c.healthJSONError("capabilities", err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_health_control", func(c *Ctx) error {
		payload, err := c.jsonPayload()
		if err != nil {
			return err
		}
		kindRaw, err := strField(payload, "kind")
		if err != nil {
			return err
		}
		nameRaw, err := strField(payload, "name")
		if err != nil {
			return err
		}
		actionRaw, err := strField(payload, "action")
		if err != nil {
			return err
		}
		kind := strings.ToLower(pyStripSpace(kindRaw))
		name := pyStripSpace(nameRaw)
		action := strings.ToLower(pyStripSpace(actionRaw))
		summary := "action: " + action
		if !c.Superadmin() {
			objectType := kind
			if objectType == "" {
				objectType = "service"
			}
			c.RecordRequest("service.control", AuditEntry{ObjectType: objectType, ObjectID: name, Result: auditResultDenied,
				Summary: summary, Detail: "superadmin required"})
			return c.JSON(403, newMap("ok", false, "error", "forbidden"))
		}
		if kind != "systemd" && kind != "docker" {
			return c.JSON(400, newMap("ok", false, "error", "kind must be systemd|docker"))
		}
		if name == "" {
			return c.JSON(400, newMap("ok", false, "error", "name is required"))
		}
		switch action {
		case "start", "stop", "restart", "reload":
		default:
			return c.JSON(400, newMap("ok", false, "error", "action must be start|stop|restart|reload"))
		}

		// The action must be one healthd offers for this unit or container.
		capsV, err := healthdCall(http.MethodGet, "/api/v1/control/capabilities", nil, nil, 10*time.Second)
		if err != nil {
			return c.healthJSONError("capabilities validate", err)
		}
		caps, isMap := asMap(capsV)
		if !isMap {
			return c.healthJSONError("capabilities validate", noAttr(capsV, "get"))
		}
		if caps.Value("ok") != true {
			return c.JSON(502, newMap("ok", false, "error", "healthd capabilities not ok"))
		}
		allowedV := caps.Value(kind)
		allowed := map[string]bool{}
		if truthy(allowedV) {
			allowedMap, isMap := asMap(allowedV)
			if !isMap {
				return c.healthJSONError("capabilities validate", noAttr(allowedV, "items"))
			}
			if list, ok := allowedMap.Value(name).([]any); ok {
				for _, x := range list {
					allowed[pyStr(x)] = true
				}
			}
			allowedMap.Each(func(k, v any) {
				ks, isStr := k.(string)
				if !isStr || ks == name || !strings.ContainsAny(ks, "*?") {
					return
				}
				if list, ok := v.([]any); ok && fnmatchRe(ks).MatchString(name) {
					for _, x := range list {
						allowed[pyStr(x)] = true
					}
				}
			})
		}
		if !allowed[action] {
			c.RecordRequest("service.control", AuditEntry{ObjectType: kind, ObjectID: name, Result: auditResultDenied,
				Summary: summary, Detail: "action is not in the healthd capability list"})
			names := make([]string, 0, len(allowed))
			for k := range allowed {
				names = append(names, k)
			}
			sort.Strings(names)
			return c.JSON(403, newMap("ok", false, "error", "action not allowed", "allowed", strList(names...)))
		}

		failed := func(err error) error {
			log.Printf("healthd control error: %v", err)
			c.RecordRequest("service.control", AuditEntry{ObjectType: kind, ObjectID: name, Result: auditResultFailure,
				Summary: summary, Detail: truncRunes(err.Error(), 500)})
			return c.JSON(502, newMap("ok", false, "error", err.Error()))
		}
		dataV, err := healthdCall(http.MethodPost, "/api/v1/control", nil, newMap("kind", kind, "name", name, "action", action), 30*time.Second)
		if err != nil {
			return failed(err)
		}
		data, isMap := asMap(dataV)
		if !isMap {
			return failed(noAttr(dataV, "get"))
		}
		if !has(data, "text") {
			out := pyStr(orValue(data.Value("stdout"), ""))
			errText := pyStr(orValue(data.Value("stderr"), ""))
			sep := ""
			if out != "" && errText != "" {
				sep = "\n"
			}
			data.Set("text", pyStripSpace(out+sep+errText))
		}
		ok := truthy(data.Value("ok")) || truthy(data.Value("scheduled"))
		if truthy(data.Value("scheduled")) {
			summary += ", scheduled"
		}
		detail := ""
		if !ok {
			detail = truncRunes(pyStr(orValue(data.Value("error"), data.Value("text"), "")), 500)
		}
		c.RecordRequest("service.control", AuditEntry{ObjectType: kind, ObjectID: name, Result: recordResult(ok), Summary: summary, Detail: detail})
		status := 500
		switch {
		case truthy(data.Value("scheduled")):
			status = 202
		case truthy(data.Value("ok")):
			status = 200
		}
		return c.JSON(status, data)
	})
}

// queryDefault is request.args.get(name, def).
func (c *Ctx) queryDefault(name, def string) string {
	if vals, has := c.R.URL.Query()[name]; has && len(vals) > 0 {
		return vals[0]
	}
	return def
}
