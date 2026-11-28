package app

// Port of routes_alerts.py with alertd_client.py. The conditions and the
// notification policy live in easy-ha-proxy-alertd; here its state is only
// read and its settings written.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

const alertsMaxLimit = 500

func alertdTransport() *UnixHTTP {
	return &UnixHTTP{
		Service:     "alertd",
		SocketPath:  strings.TrimSpace(envOr("ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock")),
		TokenHeader: "X-Alertd-Token",
		// Changing the rules silences alerts, so the daemon requires this token.
		Token: strings.TrimSpace(os.Getenv("ALERTD_TOKEN")),
	}
}

func alertdGet(path string, params []QueryValue, timeout time.Duration) (any, error) {
	return alertdTransport().Get(path, HTTPOptions{Params: params, Timeout: timeout})
}

// alertdPost is _post_json: a rejected setting comes back as 400 with a
// message worth showing, so the status is not raised on.
func alertdPost(path string, payload any, timeout time.Duration) (*Map, error) {
	v, err := alertdTransport().Post(path, payload, HTTPOptions{Timeout: timeout, WithToken: true, NoCheckStatus: true, RequireObject: true})
	if err != nil {
		return nil, err
	}
	m, _ := asMap(v)
	return m, nil
}

// alertsUnavailable is _unavailable: a degraded page, not an error page.
func (c *Ctx) alertsUnavailable(err error) error {
	var down *Unavailable
	if !errors.As(err, &down) {
		return err
	}
	log.Printf("alertd unavailable: %s", down.Msg)
	return c.JSON(503, newMap("ok", false, "unavailable", true, "error", down.Msg))
}

// pyIntArgOr is int(value) for a query value (None when absent).
func pyIntArgOr(raw string, present bool) (int64, bool) {
	if !present {
		return 0, false
	}
	n, err := parsePyIntString(raw)
	return n, err == nil
}

func (c *Ctx) queryOpt(name string) (string, bool) {
	vals, has := c.R.URL.Query()[name]
	if !has || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func (c *Ctx) alertsLimit() int64 {
	n, ok := pyIntArgOr(c.queryOpt("limit"))
	if !ok {
		return 100
	}
	return max(1, min(alertsMaxLimit, n))
}

func (c *Ctx) alertsOffset() int64 {
	n, ok := pyIntArgOr(c.queryOpt("offset"))
	if !ok {
		return 0
	}
	return max(0, min(1_000_000, n))
}

// alertKey is _alert_key.
func alertKey(payload *Map) (string, string) {
	rule := truncRunes(pyStripSpace(strOrEmpty(payload.Value("rule"))), 80)
	subject := truncRunes(pyStripSpace(strOrEmpty(payload.Value("subject"))), 200)
	return rule, subject
}

// alertsObject is "request.get_json(silent=True) or {}" followed by the
// isinstance(payload, dict) check.
func (c *Ctx) alertsObject() (*Map, bool) {
	v := c.SilentJSON()
	if !truthy(v) {
		return newMap(), true
	}
	m, ok := asMap(v)
	return m, ok
}

func okStatus(ok bool, failed int) int {
	if ok {
		return 200
	}
	return failed
}

// joinStrings is ", ".join(list): a non-string item is the TypeError a 500 came from.
func joinStrings(v any, sep string) (string, error) {
	list, _ := asList(orValue(v, []any{}))
	parts := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return "", fmt.Errorf("sequence item %d: expected str instance, %s found", i, pyTypeName(item))
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, sep), nil
}

func (a *App) registerAlerts() {
	a.Handle("routes.api_alerts_state", func(c *Ctx) error {
		data, err := alertdGet("/api/v1/alerts/state", []QueryValue{{"limit", fmt.Sprint(c.alertsLimit())}}, 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_alerts_health", func(c *Ctx) error {
		data, err := alertdGet("/api/v1/alerts/health", nil, 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_alerts_history", func(c *Ctx) error {
		// A page offset starts at 0; the limit's floor of 1 hid the newest entry.
		params := []QueryValue{{"limit", fmt.Sprint(c.alertsLimit())}, {"offset", fmt.Sprint(c.alertsOffset())}}
		for _, key := range []string{"rule", "severity"} {
			raw, _ := c.queryOpt(key)
			if v := pyStripSpace(raw); v != "" {
				params = append(params, QueryValue{key, v})
			}
		}
		data, err := alertdGet("/api/v1/alerts/history", params, 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_alerts_portal", func(c *Ctx) error {
		// What the header of every page shows; short, it is asked for often.
		data, err := alertdGet("/api/v1/alerts/portal", nil, 5*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		return c.JSON(200, data)
	})

	a.Handle("routes.api_alerts_config", func(c *Ctx) error {
		payload, ok := c.alertsObject()
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "a JSON object is required"))
		}
		entry := AuditEntry{ObjectType: "alerts", ObjectID: "settings"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("alerts.config", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		result, err := alertdPost("/api/v1/alerts/config", payload, 15*time.Second)
		if err != nil {
			var down *Unavailable
			if errors.As(err, &down) {
				entry.Result, entry.Detail = auditResultFailure, down.Msg
				c.RecordRequest("alerts.config", entry)
			}
			return c.alertsUnavailable(err)
		}
		saved := truthy(result.Value("ok"))
		// The webhook URL and the header value are secrets: the record names
		// the fields that were touched and never their values.
		var keys []string
		payload.Each(func(k, _ any) { keys = append(keys, pyStr(k)) })
		sort.Strings(keys)
		entry.Result = recordResult(saved)
		entry.Summary = "fields: " + strings.Join(keys, ", ")
		if !saved {
			entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 500)
		}
		c.RecordRequest("alerts.config", entry)
		return c.JSON(okStatus(saved, 400), result)
	})

	a.Handle("routes.api_alerts_quieten", func(c *Ctx) error {
		payload, ok := c.alertsObject()
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "a JSON object is required"))
		}
		rule, subject := alertKey(payload)
		mode := strOrEmpty(payload.Value("mode"))
		body := newMap("rule", rule, "subject", subject, "mode", mode, "by", c.User())
		summary := "mode: " + mode
		if seconds, has := payload.Get("seconds"); has {
			body.Set("seconds", seconds)
			summary += ", seconds: " + pyStr(seconds)
		}
		result, err := alertdPost("/api/v1/alerts/quieten", body, 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		done := truthy(result.Value("ok"))
		entry := AuditEntry{ObjectType: "alert", ObjectID: rule + ":" + subject, Result: recordResult(done), Summary: summary}
		if !done {
			entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 300)
		}
		c.RecordRequest("alerts.quieten", entry)
		return c.JSON(okStatus(done, 400), result)
	})

	a.Handle("routes.api_alerts_dismiss", func(c *Ctx) error {
		payload, ok := c.alertsObject()
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "a JSON object is required"))
		}
		rule, subject := alertKey(payload)
		result, err := alertdPost("/api/v1/alerts/dismiss", newMap("rule", rule, "subject", subject, "by", c.User()), 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		done := truthy(result.Value("ok"))
		entry := AuditEntry{ObjectType: "alert", ObjectID: rule + ":" + subject, Result: recordResult(done)}
		if !done {
			entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 300)
		}
		c.RecordRequest("alerts.dismiss", entry)
		return c.JSON(okStatus(done, 400), result)
	})

	a.Handle("routes.api_alerts_mail_retry", func(c *Ctx) error {
		result, err := alertdPost("/api/v1/alerts/mail/retry", newMap(), 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		done := truthy(result.Value("ok"))
		entry := AuditEntry{ObjectType: "alert", ObjectID: "mail.delivery_failed:relay", Result: recordResult(done)}
		if !done {
			entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 300)
		}
		c.RecordRequest("alerts.mail_retry", entry)
		return c.JSON(okStatus(done, 400), result)
	})

	a.Handle("routes.api_alerts_history_delete", func(c *Ctx) error {
		payload, isObject := c.alertsObject()
		entry := AuditEntry{ObjectType: "alerts", ObjectID: "history"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("alerts.history_delete", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		if !isObject {
			return c.JSON(400, newMap("ok", false, "error", "a JSON object is required"))
		}
		body := newMap()
		summary := ""
		if payload.Value("all") == true {
			body.Set("all", true)
			summary = "all"
		} else {
			rows := 0
			if ids, ok := payload.Value("ids").([]any); ok {
				if len(ids) > 1000 {
					ids = ids[:1000]
				}
				body.Set("ids", ids)
				rows = len(ids)
			}
			summary = fmt.Sprintf("rows: %d", rows)
		}
		result, err := alertdPost("/api/v1/alerts/history/delete", body, 15*time.Second)
		if err != nil {
			return c.alertsUnavailable(err)
		}
		done := truthy(result.Value("ok"))
		if done {
			summary += ", deleted: " + pyStr(result.Value("deleted"))
		}
		entry.Result, entry.Summary = recordResult(done), summary
		if !done {
			entry.Detail = truncRunes(strOrEmpty(result.Value("error")), 300)
		}
		c.RecordRequest("alerts.history_delete", entry)
		return c.JSON(okStatus(done, 400), result)
	})

	a.Handle("routes.api_alerts_test", func(c *Ctx) error {
		entry := AuditEntry{ObjectType: "alerts", ObjectID: "channels"}
		if !c.Superadmin() {
			entry.Result, entry.Detail = auditResultDenied, "superadmin required"
			c.RecordRequest("alerts.test", entry)
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		// The webhook can take as long as its own timeout: a longer budget.
		result, err := alertdPost("/api/v1/alerts/test", newMap(), 60*time.Second)
		if err != nil {
			var down *Unavailable
			if errors.As(err, &down) {
				entry.Result, entry.Detail = auditResultFailure, down.Msg
				c.RecordRequest("alerts.test", entry)
			}
			return c.alertsUnavailable(err)
		}
		done := truthy(result.Value("ok"))
		delivered, err := joinStrings(result.Value("delivered"), ", ")
		if err != nil {
			return err
		}
		if delivered == "" {
			delivered = "none"
		}
		entry.Result, entry.Summary = recordResult(done), "delivered: "+delivered
		if !done {
			errs, err := joinStrings(result.Value("errors"), "; ")
			if err != nil {
				return err
			}
			entry.Detail = truncRunes(errs, 500)
		}
		c.RecordRequest("alerts.test", entry)
		return c.JSON(okStatus(done, 502), result)
	})
}
