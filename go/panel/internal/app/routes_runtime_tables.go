package app

// Port of the runtime routes of routes.py (tables, unban, allow lists,
// attackers, connections, the address page, country batch, backends, IP
// authorization) and routes_runtime.py (server state and weight).

import (
	"errors"
	"fmt"
	"log"
)

func (c *Ctx) textResponse(text string, code int) error {
	return c.Text(code, "text/plain; charset=utf-8", text)
}

// recordOutcome is _record_outcome: a refusal from HAProxy is a failure even
// though no exception was raised.
func (c *Ctx) recordOutcome(action, ip, text string, code int, summary string) {
	detail := ""
	if !(code < 300 && (text == "OK" || text == "")) {
		detail = truncRunes(text, 300)
	}
	result := auditResultSuccess
	if code >= 300 {
		result = auditResultFailure
	}
	c.RecordRequest(action, AuditEntry{ObjectType: "ip", ObjectID: ip, Result: result, Summary: summary, Detail: detail})
}

func (c *Ctx) serverTarget(payload *Map) string {
	return pyStr(payload.Value("backend")) + "/" + pyStr(payload.Value("server"))
}

func (a *App) registerRuntimeTables() {
	a.Handle("routes.api_whitelists", func(c *Ctx) error {
		return c.JSON(200, getWhitelists())
	})

	a.Handle("routes.api_tables", func(c *Ctx) error {
		if c.queryDefault("view", "") == "bans" {
			return c.JSON(200, getTables(false))
		}
		return c.JSON(200, getTables(true))
	})

	a.Handle("routes.api_tables_raw", func(c *Ctx) error {
		out, err := getTablesRaw()
		if err != nil {
			log.Printf("Failed to read raw HAProxy tables: %v", err)
			return c.JSON(500, newMap("error", "Failed to read HAProxy tables"))
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_unban", func(c *Ctx) error {
		ip := pyStripSpace(c.FormStr("ip"))
		if ip == "" {
			return c.textResponse("IP is required", 400)
		}
		text, code, err := unbanIP(ip)
		if err != nil {
			c.RecordRequest("ban.lift", AuditEntry{ObjectType: "ip", ObjectID: ip, Result: auditResultFailure, Detail: err.Error()})
			return err
		}
		c.recordOutcome("ban.lift", ip, text, code, "")
		return c.textResponse(text, code)
	})

	whitelist := func(global bool) HandlerFunc {
		scope := "geo"
		if global {
			scope = "global"
		}
		return func(c *Ctx) error {
			ip := pyStripSpace(c.FormStr("ip"))
			if ip == "" {
				return c.textResponse("IP is required", 400)
			}
			text, code := toggleWhitelist(ip, global)
			c.recordOutcome("whitelist.add", ip, text, code, "scope: "+scope)
			return c.textResponse(text, code)
		}
	}
	a.Handle("routes.api_whitelist", whitelist(false))
	a.Handle("routes.api_whitelist_global", whitelist(true))

	a.Handle("routes.api_attackers", func(c *Ctx) error {
		return c.JSON(200, getAttackers())
	})

	a.Handle("routes.api_connections", func(c *Ctx) error {
		out, err := getConnections()
		if err != nil {
			log.Printf("Failed to read HAProxy connections: %v", err)
			return c.JSON(500, newMap("error", "Failed to load HAProxy connections"))
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.view_ip_logs", func(c *Ctx) error {
		ip := c.Args["ip"]
		if _, ok := pyIPAddress(ip); !ok {
			return c.textResponse("Invalid IP", 400)
		}
		lines := GrepLastLogsForIP(ip, 30)
		status := addressStatus(ip)
		var history any
		if h, err := banHistory(ip); err != nil {
			log.Printf("Failed to read the ban history of %s: %v", ip, err)
		} else if h != nil {
			history = h
		}
		var autheliaBan any
		if b := autheliaSignInBan(ip); b != nil {
			autheliaBan = b
		}
		lineList := make([]any, len(lines))
		for i, l := range lines {
			lineList[i] = l
		}
		return c.Render("ip_logs.html", map[string]any{"ip": ip, "lines": lineList, "status": status,
			"history": history, "authelia_ban": autheliaBan})
	})

	a.Handle("routes.api_country_batch", func(c *Ctx) error {
		data := c.silentJSONMap()
		dm, ok := asMap(data)
		if !ok {
			return noAttr(data, "get")
		}
		ipsV, has := dm.Get("ips")
		if !has {
			ipsV = []any{}
		}
		ips, isList := ipsV.([]any)
		if !isList {
			return c.JSON(400, newMap("error", "ips must be a list"))
		}
		if len(ips) > 512 {
			return c.JSON(413, newMap("error", "at most 512 IP addresses are allowed"))
		}
		result := newMap()
		for _, v := range ips {
			x := pyStripSpace(pyStr(v))
			if _, seen := result.Get(x); seen {
				continue
			}
			if _, ok := pyIPAddress(x); ok {
				result.Set(x, getCountryCode(x))
			} else {
				result.Set(x, "")
			}
		}
		return c.JSON(200, result)
	})

	a.Handle("routes.api_backends", func(c *Ctx) error {
		return c.JSON(200, getBackendsStatus())
	})

	a.Handle("routes.api_ip_auth", func(c *Ctx) error {
		out, err := getIPAuthTable()
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			return c.JSON(500, newMap("error", err.Error()))
		}
		return c.JSON(200, out)
	})

	a.Handle("routes.api_haproxy_backends", func(c *Ctx) error {
		if !c.Superadmin() {
			return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
		}
		return c.JSON(200, newMap("ok", true, "backends", listRuntimeBackends()))
	})

	change := func(action, field string, apply func(backend, server, value any) (*Map, error)) HandlerFunc {
		return func(c *Ctx) error {
			raw := c.silentJSONMap()
			payload, ok := asMap(raw)
			if !ok {
				return noAttr(raw, "get")
			}
			entry := AuditEntry{ObjectType: "server", ObjectID: c.serverTarget(payload)}
			if !c.Superadmin() {
				entry.Result, entry.Detail = auditResultDenied, "superadmin required"
				c.RecordRequest(action, entry)
				return c.JSON(403, newMap("ok", false, "error", "superadmin required"))
			}
			result, err := apply(payload.Value("backend"), payload.Value("server"), payload.Value(field))
			if err != nil {
				entry.Result, entry.Detail = auditResultFailure, err.Error()
				c.RecordRequest(action, entry)
				var refusal *RuntimeRefusal
				if errors.As(err, &refusal) {
					return c.JSON(400, newMap("ok", false, "error", refusal.Msg))
				}
				log.Printf("runtime %s change failed: %v", field, err)
				return c.JSON(502, newMap("ok", false, "error", err.Error()))
			}
			c.RecordRequest(action, AuditEntry{ObjectType: "server",
				ObjectID: fmt.Sprintf("%s/%s", pyStr(result.Value("backend")), pyStr(result.Value("server"))),
				Summary:  fmt.Sprintf("%s: %s", field, pyStr(result.Value(field)))})
			return c.JSON(200, result)
		}
	}
	a.Handle("routes.api_haproxy_backend_state", change("backend.state", "state", setServerState))
	a.Handle("routes.api_haproxy_backend_weight", change("backend.weight", "weight", setServerWeight))

}
