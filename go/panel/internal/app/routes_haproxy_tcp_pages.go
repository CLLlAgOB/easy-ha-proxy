package app

// Port of routes_haproxy_config.py: the TCP proxy list and editor pages.

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *App) registerTCPPages() {
	a.Handle("routes.haproxy_tcp_page", func(c *Ctx) error {
		var errMsg, message any
		op := c.op()
		if c.R.Method == http.MethodPost {
			action := strings.TrimSpace(orStr(orValue(c.FormStr("action"), "add")))
			if action == "delete" {
				name := c.FormStrip("name")
				if name == "" {
					errMsg = "TCP proxy name is required for deletion"
				} else {
					ok, msg := DeleteTCPProxy(op, name)
					c.RecordRequest("tcp_proxy.delete", AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
					if ok {
						message = msg
					} else {
						errMsg = msg
					}
				}
			} else {
				name := c.FormStrip("name")
				bindIP := c.FormStrip("bind_ip")
				if bindIP == "" {
					bindIP = "0.0.0.0"
				}
				bindPortStr := c.FormStrip("bind_port")
				backendHost := c.FormStrip("backend_host")
				backendPortStr := c.FormStrip("backend_port")
				setName := c.FormStrip("servers_preset")
				balance := c.FormStrip("balance")
				if balance == "" {
					balance = "source"
				}
				var bindPort, backendPort int64
				switch {
				case name == "":
					errMsg = "The TCP proxy Name field is required"
				case bindPortStr == "":
					errMsg = "The Bind port field is required"
				case (backendHost == "" && setName == "") || backendPortStr == "":
					errMsg = "The backend_host and backend_port fields are required"
				default:
					var e1, e2 error
					bindPort, e1 = parsePyIntString(bindPortStr)
					if e1 == nil {
						backendPort, e2 = parsePyIntString(backendPortStr)
					}
					if e1 != nil || e2 != nil {
						errMsg = "bind_port and backend_port must be numbers"
					} else if !(1 <= bindPort && bindPort <= 65535 && 1 <= backendPort && backendPort <= 65535) {
						errMsg = "Ports must be between 1 and 65535"
					}
				}
				if errMsg == nil {
					obj := newMap("name", name, "bind_ip", bindIP, "bind_port", bindPort, "backend_host", backendHost,
						"backend_port", backendPort, "balance", balance, "zero_trust", c.FormBool("zero_trust"), "ban_check", c.FormBool("ban_check"))
					if setName != "" {
						obj.Set(presetField, setName)
						obj.Set(portField, backendPort)
					}
					ok, msg, err := SaveTCPFromJSON(op, obj, "", nil)
					if err != nil {
						return err
					}
					c.RecordRequest("tcp_proxy.create", AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: recordResult(ok),
						Summary: fmt.Sprintf("bind: %s:%d, backend: %s:%d", bindIP, bindPort, backendHost, backendPort), Detail: detailIfFailed(ok, msg)})
					if ok {
						return c.Redirect(c.URLFor("routes.haproxy_tcp_edit", "name", name), 302)
					}
					errMsg = msg
				}
			}
		}
		list, err := GetTCPProxiesList()
		if err != nil {
			return err
		}
		return c.Render("haproxy_tcp.html", map[string]any{"tcp_proxies": list, "error": errMsg, "message": message})
	})
	a.Handle("routes.haproxy_tcp_edit", func(c *Ctx) error {
		name := c.Args["name"]
		var errMsg, message any
		list, err := GetTCPProxiesList()
		if err != nil {
			return err
		}
		var obj any
		for _, t := range list {
			if pyEqual(get(t, "name"), name) {
				obj = t
				break
			}
		}
		if obj == nil {
			html, err := c.RenderString("haproxy_tcp_edit.html", map[string]any{"tcp": newMap("name", name),
				"error": fmt.Sprintf("TCP proxy with name=%s not found", pyRepr(name)), "message": nil})
			if err != nil {
				return err
			}
			return c.HTML(404, html)
		}
		if c.R.Method == http.MethodPost {
			action := strings.TrimSpace(orStr(orValue(c.FormStr("action"), "save")))
			if action == "delete" {
				ok, msg := DeleteTCPProxy(c.op(), name)
				c.RecordRequest("tcp_proxy.delete", AuditEntry{ObjectType: "tcp_proxy", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
				if ok {
					return c.Redirect(c.URLFor("routes.haproxy_tcp_page"), 302)
				}
				errMsg = msg
			}
		}
		return c.Render("haproxy_tcp_edit.html", map[string]any{"tcp": obj, "tcp_revision": EntryRevision(obj), "error": errMsg, "message": message})
	})
}
