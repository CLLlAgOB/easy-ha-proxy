package app

// Port of routes_haproxy_config.py: the site list page, the mail page and
// the Let's Encrypt account email.

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"easy-ha-proxy/panel/shared/pyyaml"
)

var pauseActions = map[string]struct {
	key    string
	paused bool
}{
	"pause":          {"paused", true},
	"resume":         {"paused", false},
	"pause_renewal":  {"cert_renewal_paused", true},
	"resume_renewal": {"cert_renewal_paused", false},
}

func (a *App) registerSitesPage() {
	a.Handle("routes.haproxy_sites_page", func(c *Ctx) error {
		var errMsg, message any
		op := c.op()
		if c.R.Method == http.MethodPost {
			action := strings.TrimSpace(orStr(orValue(c.FormStr("action"), "add")))
			if pa, isPause := pauseActions[action]; isPause {
				name := c.FormStrip("name")
				ok, msg := false, "Site name is required"
				if name != "" {
					ok, msg = SetSitePause(op, name, pa.key, pa.paused)
				}
				c.RecordRequest("site."+action, AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
				switch {
				case !ok:
					errMsg = msg
				case pa.key == "paused":
					if pa.paused {
						message = "Publication paused. Apply the configuration to take the site off HAProxy."
					} else {
						message = "Publication resumed. Apply the configuration to serve the site again."
					}
				default:
					synced := SyncRenewalPauses()
					m := "Certificate renewal resumed."
					if pa.paused {
						m = "Certificate renewal paused."
					}
					if !truthy(synced.Value("ok")) {
						m += " The certificate service could not be told yet: " + pyStr(orValue(synced.Value("error"), "unknown error")) + ". It will be told on the next apply."
					} else if pa.paused && truthy(synced.Value("without_lineage")) {
						m += " No certificate of its own was found for it here, so there is nothing for certbot to skip."
					}
					message = m
				}
			} else if action == "delete" {
				name := c.FormStrip("name")
				if name == "" {
					errMsg = "Site name is required for deletion"
				} else {
					ok, msg := DeleteSiteByName(op, name)
					c.RecordRequest("site.delete", AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
					if ok {
						message = msg
					} else {
						errMsg = msg
					}
				}
			} else {
				domain := c.FormStrip("domain")
				siteType := strings.TrimSpace(orStr(orValue(c.FormStr("site_type"), "normal")))
				backendIP := c.FormStrip("backend_ip")
				portStr := c.FormStrip("backend_port")
				setName := c.FormStrip("servers_preset")
				var setExtra *Map
				if setName != "" && siteType != "gate" {
					setExtra = newMap(presetField, setName, portField, portStr)
					presets, err := loadPresets()
					if err != nil {
						return err
					}
					if err := ApplyPresetToSite(setExtra, presets); err != nil {
						errMsg = err.Error()
					} else {
						servers := setExtra.Value("servers").([]any)
						backendIP = pyStr(servers[0].(*Map).Value("host"))
					}
				}
				isGate := siteType == "gate"
				if isGate {
					backendIP, portStr = "", ""
				}
				switch {
				case errMsg != nil:
				case domain == "":
					errMsg = "The Domain field is required"
				case isGate:
				case backendIP == "" || portStr == "":
					errMsg = "Backend IP and port are required for a proxy site. Use Service sites for a login page."
				default:
					if p, err := parsePyIntString(portStr); err != nil {
						errMsg = "Port must be a number"
					} else if p < 1 || p > 65535 {
						errMsg = "Port must be between 1 and 65535"
					}
				}
				if errMsg == nil {
					ok, msg := AddSiteMinimal(op, domain, domain, backendIP, portStr, setExtra)
					summary := fmt.Sprintf("backend: %s:%s", backendIP, portStr)
					if isGate {
						summary = "access gate"
					}
					c.RecordRequest("site.create", AuditEntry{ObjectType: "site", ObjectID: domain, Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, msg)})
					if ok {
						return c.Redirect(c.URLFor("routes.haproxy_site_edit", "name", domain), 302)
					}
					errMsg = msg
				}
			}
		}
		cv, err := loadYAML(ConfigYAML)
		if err != nil {
			return err
		}
		defaults, sites, err := SitesAndDefaultsForUI()
		if err != nil {
			return err
		}
		shown := []any{}
		for _, s := range sites {
			if get(s.(*Map).Value("effective"), "access_gate") != true {
				shown = append(shown, s)
			}
		}
		return c.Render("haproxy_sites.html", map[string]any{"sites": shown, "site_defaults": defaults, "config_vars": cv, "error": errMsg, "message": message})
	})
	a.Handle("routes.mail_settings_page", staticPage("mail_settings.html", nil))
	a.Handle("routes.acme_email_view", func(c *Ctx) error {
		res, err := GetACMEEmail()
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			return c.JSON(500, newMap("ok", false, "error", err.Error()))
		}
		return c.JSON(200, res)
	})
	a.Handle("routes.acme_email_save", func(c *Ctx) error {
		payload, ok := asMap(c.SilentJSON())
		valid := ok && payload.Len() == 2 && has(payload, "email") && has(payload, "revision")
		if !valid {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "email and revision are required"))
		}
		res, err := SaveACMEEmail(c.op(), payload.Value("email"), payload.Value("revision"))
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			c.RecordRequest("acme_email.update", AuditEntry{ObjectType: "haproxy", ObjectID: "acme_email", Result: auditResultFailure, Detail: truncRunes(err.Error(), 500)})
			return c.JSON(500, newMap("ok", false, "error", err.Error()))
		}
		okRes := truthy(res.Value("ok"))
		summary := ""
		if okRes {
			summary = "address: changed"
		}
		c.RecordRequest("acme_email.update", AuditEntry{ObjectType: "haproxy", ObjectID: "acme_email", Result: recordResult(okRes), Summary: summary, Detail: detailIfFailed(okRes, strOrEmpty(res.Value("error")))})
		status := 500
		switch {
		case okRes:
			status = 200
		case truthy(res.Value("conflict")) || truthy(res.Value("pending")):
			status = 409
		case truthy(res.Value("validation_error")):
			status = 400
		}
		return c.JSON(status, res)
	})
}

var _ = pyyaml.NewMap
