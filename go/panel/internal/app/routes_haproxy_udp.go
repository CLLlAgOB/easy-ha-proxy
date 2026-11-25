package app

// Port of routes_haproxy_udp.py.

import (
	"io"
	"log"
	"net/http"
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// Form is request.form.get(name): the first body value, or ok=false.
func (c *Ctx) Form(name string) (string, bool) {
	if c.R.PostForm == nil {
		ct := strings.ToLower(c.R.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "multipart/form-data") {
			_ = c.R.ParseMultipartForm(2 * 1024 * 1024)
		} else {
			_ = c.R.ParseForm()
		}
	}
	vals, ok := c.R.PostForm[name]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// FormStr is (request.form.get(name) or "").
func (c *Ctx) FormStr(name string) string {
	v, _ := c.Form(name)
	return v
}

// FormStrip is (request.form.get(name) or "").strip().
func (c *Ctx) FormStrip(name string) string { return strings.TrimSpace(c.FormStr(name)) }

// FormBool is bool(request.form.get(name)).
func (c *Ctx) FormBool(name string) bool { return c.FormStr(name) != "" }

// JSONBody is request.get_json(force=True, silent=False).
func (c *Ctx) JSONBody() (any, error) {
	raw, err := io.ReadAll(c.R.Body)
	if err != nil {
		return nil, err
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, &ValueError{"400 Bad Request: Failed to decode JSON object: Expecting value: line 1 column 1 (char 0)"}
	}
	return v, nil
}

func noneIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (c *Ctx) op() *Op {
	op := NewOp()
	op.Actor = c.User()
	return op
}

func storedUDP(name string) any {
	if name == "" {
		return pyyaml.NewMap()
	}
	list, _ := GetUDPForwardsList()
	for _, f := range list {
		if m, ok := asMap(f); ok && strOrEmpty(m.Value("name")) == name {
			return m
		}
	}
	return pyyaml.NewMap()
}

func (c *Ctx) recordUDPDelete(name string, ok bool, message string) {
	res := auditResultFailure
	detail := truncRunes(message, 500)
	if ok {
		res, detail = auditResultSuccess, ""
	}
	c.RecordRequest("udp_forward.delete", AuditEntry{ObjectType: "udp_forward", ObjectID: name, Result: res, Detail: detail})
}

func okKey(ok bool) string {
	if ok {
		return "message"
	}
	return "error"
}

func (a *App) registerUDPRoutes() {
	a.Handle("routes.haproxy_udp_page", func(c *Ctx) error {
		var errMsg, editForward, originalName, revision any
		op := c.op()
		if c.R.Method == http.MethodPost {
			action := strings.TrimSpace(orStr(orValue(c.FormStr("action"), "save")))
			if action == "delete" {
				name := c.FormStrip("name")
				if name == "" {
					errMsg = "A UDP forward name is required for deletion"
				} else {
					ok, msg := DeleteUDPForward(op, name)
					c.recordUDPDelete(name, ok, msg)
					if ok {
						c.Flash(msg, "success")
						return c.Redirect(c.URLFor("routes.haproxy_udp_page"), 302)
					}
					errMsg = msg
				}
			} else {
				orig := c.FormStrip("original_name")
				originalName = noneIfEmpty(orig)
				healthCheck := strings.TrimSpace(orStr(orValue(c.FormStr("health_check"), "ping")))
				udpObj := newMap("name", c.FormStrip("name"), "listen_port", c.FormStrip("listen_port"),
					"backend_host", c.FormStrip("backend_host"), "backend_port", c.FormStrip("backend_port"),
					"ban_check", c.FormBool("ban_check"), "zero_trust", c.FormBool("zero_trust"), "enabled", c.FormBool("enabled"),
					"backup_host", c.FormStrip("backup_host"), "backup_port", c.FormStrip("backup_port"),
					"health_check", healthCheck, "health_port", c.FormStrip("health_port"),
					"servers_preset", c.FormStrip("servers_preset"))
				before := storedUDP(orig)
				ok, msg := func() (ok bool, msg string) {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Unhandled exception in route: %v", r)
							ok, msg = false, "Internal error while saving the UDP forward"
						}
					}()
					return SaveUDPFromJSON(op, udpObj, orig, c.FormStrip("revision"))
				}()
				res, summary, detail := auditResultFailure, "", truncRunes(msg, 500)
				if ok {
					res, summary, detail = auditResultSuccess, AuditSummarize(before, udpObj), ""
				}
				act := "udp_forward.create"
				if truthy(before) {
					act = "udp_forward.update"
				}
				c.RecordRequest(act, AuditEntry{ObjectType: "udp_forward", ObjectID: pyStr(udpObj.Value("name")), Result: res, Summary: summary, Detail: detail})
				if ok {
					c.Flash(msg, "success")
					return c.Redirect(c.URLFor("routes.haproxy_udp_page"), 302)
				}
				errMsg = msg
				editForward = udpObj
				revision = noneIfEmpty(c.FormStrip("revision"))
			}
		}
		if c.R.Method == http.MethodGet {
			orig := strings.TrimSpace(c.QueryStr("edit"))
			originalName = noneIfEmpty(orig)
			if orig != "" {
				list, err := GetUDPForwardsList()
				if err != nil {
					return err
				}
				for _, it := range list {
					if strOrEmpty(get(it, "name")) == orig {
						editForward = it
						break
					}
				}
				if editForward == nil {
					errMsg = "UDP forward with name=" + pyRepr(orig) + " not found"
				} else {
					revision = UDPRevision(editForward)
				}
			}
		}
		list, err := GetUDPForwardsList()
		if err != nil {
			return err
		}
		return c.Render("haproxy_udp.html", map[string]any{
			"udp_forwards": list, "udp_status": GetUDPRuntimeStatus(), "error": errMsg,
			"edit_forward": editForward, "original_name": originalName, "revision": revision,
			"udp_follow_error": FollowUDPError(),
		})
	})
	a.Handle("routes.haproxy_udp_save", func(c *Ctx) error {
		payloadV, err := c.JSONBody()
		if err != nil {
			return c.JSON(400, newMap("ok", false, "error", "Invalid JSON: "+err.Error()))
		}
		payload, ok := asMap(payloadV)
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "Expected a JSON object"))
		}
		udp := payload.Value("udp")
		orig := orStr(payload.Value("original_name"))
		if _, ok := asMap(udp); !ok {
			return c.JSON(400, newMap("ok", false, "error", "The 'udp' field must be an object"))
		}
		name := orStr(orValue(get(udp, "name"), noneIfEmpty(orig)))
		before := storedUDP(orig)
		act := "udp_forward.create"
		if truthy(before) {
			act = "udp_forward.update"
		}
		okSave, msg := SaveUDPFromJSON(c.op(), udp, orig, orStr(payload.Value("revision")))
		res, summary, detail := auditResultFailure, "", truncRunes(msg, 500)
		if okSave {
			res, summary, detail = auditResultSuccess, AuditSummarize(before, udp), ""
		}
		c.RecordRequest(act, AuditEntry{ObjectType: "udp_forward", ObjectID: name, Result: res, Summary: summary, Detail: detail})
		return c.JSON(200, newMap("ok", okSave, okKey(okSave), msg))
	})
	a.Handle("routes.haproxy_udp_delete", func(c *Ctx) error {
		name := c.Args["name"]
		ok, msg := DeleteUDPForward(c.op(), name)
		c.recordUDPDelete(name, ok, msg)
		return c.JSON(200, newMap("ok", ok, okKey(ok), msg))
	})
}
