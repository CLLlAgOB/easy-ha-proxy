package app

// Port of routes_haproxy_config.py: the site editor page and certificate issue.

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var (
	formTextFields     = []string{"backend_host", "health_uri", "hsts"}
	formNumberFields   = []string{"max_req_rate", "health_status"}
	formTristateFields = []string{"redirect_to_https", "authelia_enabled", "zero_trust", "backend_ssl", "backend_ssl_verify", "maintenance", "rate_ban", "compress"}
	allowFormSplit     = regexp.MustCompile(`[,;\s]+`)
)

// mergeSiteFromEditForm is merge_site_from_edit_form.
func mergeSiteFromEditForm(c *Ctx, name string, existing *Map) (*Map, string) {
	domain := c.FormStrip("domain")
	backendIP := c.FormStrip("backend_ip")
	portStr := c.FormStrip("backend_port")
	if domain == "" || backendIP == "" || portStr == "" {
		return nil, "The domain, backend_ip, and backend_port fields are required"
	}
	port, err := parsePyIntString(portStr)
	if err != nil {
		return nil, "backend_port must be a number"
	}
	if port < 1 || port > 65535 {
		return nil, "backend_port must be between 1 and 65535"
	}
	site := copyMap(existing)
	site.Set("name", name)
	site.Set("domain", domain)
	site.Set("backend_ip", backendIP)
	site.Set("backend_port", port)
	inForm := func(k string) bool { _, ok := c.Form(k); return ok }
	lines := func(k string) []any {
		var out []any
		for _, l := range pySplitlines(c.FormStr(k)) {
			if strings.TrimSpace(l) != "" {
				out = append(out, strings.TrimSpace(l))
			}
		}
		return out
	}
	if inForm("alt_names") {
		if alt := lines("alt_names"); len(alt) > 0 {
			site.Set("alt_names", alt)
		} else {
			site.Delete("alt_names")
		}
	}
	if inForm("acme_challenge") {
		profile := ""
		if c.FormStrip("acme_challenge") == "dns-01" {
			profile = c.FormStrip("dns_profile")
		}
		if profile != "" {
			site.Set("dns_profile", profile)
			if extra := lines("cert_alt_names"); len(extra) > 0 {
				site.Set("cert_alt_names", extra)
			} else {
				site.Delete("cert_alt_names")
			}
		} else {
			site.Delete("dns_profile")
			site.Delete("cert_alt_names")
		}
	}
	if inForm("allow_ips") {
		var entries []any
		for _, v := range allowFormSplit.Split(c.FormStr("allow_ips"), -1) {
			if strings.TrimSpace(v) != "" {
				entries = append(entries, strings.TrimSpace(v))
			}
		}
		if len(entries) > 0 {
			site.Set("allow_ips", entries)
		} else {
			site.Delete("allow_ips")
		}
	}
	if inForm("mtls_mode") {
		mode := c.FormStrip("mtls_mode")
		if mode == "optional" || mode == "required" {
			site.Set("mtls_mode", mode)
			site.Set("mtls_ca_id", strings.ToLower(c.FormStrip("mtls_ca_id")))
		} else {
			site.Delete("mtls_mode")
			site.Delete("mtls_ca_id")
		}
	}
	for _, f := range []string{"paused", "cert_renewal_paused"} {
		if !inForm(f) {
			continue
		}
		if c.FormStrip(f) == "true" {
			site.Set(f, true)
		} else {
			site.Delete(f)
		}
	}
	for _, f := range formTristateFields {
		if !inForm(f) {
			continue
		}
		switch c.FormStrip(f) {
		case "true":
			site.Set(f, true)
		case "false":
			site.Set(f, false)
		default:
			site.Delete(f)
		}
	}
	for _, f := range formNumberFields {
		if !inForm(f) {
			continue
		}
		v := c.FormStrip(f)
		if v == "" {
			site.Delete(f)
			continue
		}
		n, err := parsePyIntString(v)
		if err != nil {
			return nil, f + " must be a number"
		}
		site.Set(f, n)
	}
	for _, f := range formTextFields {
		if !inForm(f) {
			continue
		}
		if v := c.FormStrip(f); v != "" {
			site.Set(f, v)
		} else {
			site.Delete(f)
		}
	}
	return site, ""
}

// availableDNSProfiles is _available_dns_profiles.
func availableDNSProfiles() []any {
	data, err := CertdDNS("dns-providers", newMap())
	if err != nil {
		return []any{}
	}
	profiles, ok := asList(data.Value("profiles"))
	if !ok {
		return []any{}
	}
	out := []any{}
	for _, p := range profiles {
		if m, ok := asMap(p); ok && truthy(m.Value("name")) {
			out = append(out, m)
		}
	}
	return out
}

func (a *App) registerSiteEdit() {
	a.Handle("routes.haproxy_site_edit", func(c *Ctx) error {
		name := c.Args["name"]
		var errMsg, message any
		defaults, raw, eff, err := SiteRawAndEffective(name)
		if err != nil {
			return err
		}
		if raw == nil {
			return Abort(404, "")
		}
		if eff.Value("access_gate") == true {
			if c.R.Method == http.MethodPost {
				return Abort(400, "Use the service-site editor")
			}
			return c.Redirect(c.URLFor("access_portal.edit", "name", name), 302)
		}
		op := c.op()
		if c.R.Method == http.MethodPost {
			action := c.FormStr("action")
			if _, has := c.Form("action"); !has {
				action = "save"
			}
			switch action {
			case "delete":
				ok, msg := DeleteSiteByName(op, name)
				c.RecordRequest("site.delete", AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, msg)})
				if ok {
					return c.Redirect(c.URLFor("routes.haproxy_sites_page"), 302)
				}
				errMsg = msg
			case "save":
				if _, has := c.Form("access_gate"); has {
					return Abort(400, "Use the service-site editor")
				}
				release, err := op.Lock("websites")
				if err != nil {
					return err
				}
				var newSite *Map
				var ok bool
				var msg string
				var abortErr error
				var beforeEff *Map
				var loginReq *siteLoginRequest
				if _, has := c.Form("authelia_policy"); has {
					var lerr string
					loginReq, lerr = parseSiteLoginRequest(newMap("policy", c.FormStrip("authelia_policy"), "groups", c.FormStr("authelia_groups")))
					if lerr != "" {
						errMsg = lerr
					}
				}
				func() {
					defer release()
					if errMsg != nil {
						return
					}
					defaults, raw, eff, err = SiteRawAndEffective(name)
					if err != nil {
						abortErr = err
						return
					}
					if raw == nil {
						abortErr = Abort(404, "")
						return
					}
					if serr := CheckEntryRevision(raw, c.FormStr("revision"), "This site"); serr != nil {
						errMsg = serr.Error()
						return
					}
					var e string
					newSite, e = mergeSiteFromEditForm(c, name, raw)
					if e != "" {
						errMsg = e
						return
					}
					beforeEff = eff
					afterEff, err := EffectiveSiteSettings(newSite)
					if err != nil {
						abortErr = err
						return
					}
					if refusal := loginRefusal(beforeEff, afterEff); refusal != "" {
						errMsg = refusal
						return
					}
					ok, msg = saveSiteRaw(op, name, newSite)
				}()
				if abortErr == nil && errMsg == nil && ok {
					if _, _, savedEff, err := SiteRawAndEffective(name); err == nil && savedEff != nil {
						if note := SyncSiteLoginAfterSave(op, beforeEff, savedEff, loginReq); note != "" {
							msg += " " + note
						}
					}
				}
				if abortErr != nil {
					return abortErr
				}
				if errMsg == nil {
					if ok && !pyEqual(raw.Value("cert_renewal_paused"), newSite.Value("cert_renewal_paused")) {
						SyncRenewalPauses()
					}
					summary := ""
					if ok {
						summary = AuditSummarize(raw, newSite)
					}
					c.RecordRequest("site.update", AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, msg)})
					if ok {
						message = msg + " JavaScript was unavailable, so only the fields this form carries were saved; the backend servers, certificate source, key types and error-exclusion rules were kept as they were."
						if defaults, raw, eff, err = SiteRawAndEffective(name); err != nil {
							return err
						}
					} else {
						errMsg = msg
					}
				}
			}
		}
		certData := CertdListAll()
		authorities, _ := asMap(orValue(certData.Value("certificate_authorities"), newMap()))
		if authorities == nil {
			authorities = newMap()
		}
		return c.Render("haproxy_site_edit.html", map[string]any{
			"site": raw, "eff": eff, "site_defaults": defaults, "error": errMsg, "message": message,
			"original_name": name, "site_revision": EntryRevision(raw), "is_new": false,
			"internal_ca": authorities.Value("internal"), "external_cas": orValue(authorities.Value("external"), []any{}),
			"dns_profiles": availableDNSProfiles(), "geoip_country_codes": strList(ConfiguredGeoIPCountries()...),
			"site_login": siteLoginForEditor(eff),
		})
	})
	a.Handle("routes.haproxy_site_issue_cert", func(c *Ctx) error {
		name := c.Args["name"]
		res, err := func() (*Map, error) {
			_, raw, eff, err := SiteRawAndEffective(name)
			if err != nil {
				return nil, err
			}
			if raw == nil {
				return newMap("ok", false, "status", "ERROR", "message", fmt.Sprintf("Site %s not found", pyRepr(name))), nil
			}
			domain := orValue(eff.Value("domain"), eff.Value("name"))
			if !truthy(domain) {
				return newMap("ok", false, "status", "ERROR", "message", "The site has no domain"), nil
			}
			alts, _ := asList(orValue(eff.Value("alt_names"), []any{}))
			keyTypes := orValue(eff.Value("key_types"), []any{})
			payload := c.silentJSONMap()
			requested := strings.ToLower(orStr(get(payload, "source")))
			source := any(requested)
			if requested == "" {
				source = raw.Value("certificate_source")
			}
			if source != "letsencrypt" && source != "external" && source != "internal" {
				le, has := raw.Get("le_managed")
				if !has {
					le = true
				}
				source = "external"
				if truthy(le) {
					source = "letsencrypt"
				}
			}
			var rawRes *Map
			switch source {
			case "external":
				rawRes = newMap("ok", false, "error", "External CA certificates must be uploaded with their private key.")
			case "internal":
				rawRes = CertdIssueInternal(pyStr(domain), alts)
			default:
				certAlts, _ := asList(orValue(eff.Value("cert_alt_names"), []any{}))
				rawRes = CertdIssue(pyStr(domain), append(append([]any{}, alts...), certAlts...), keyTypes, strOrEmpty(eff.Value("dns_profile")), nil)
			}
			res := copyMap(rawRes)
			if _, has := res.Get("source"); !has {
				res.Set("source", source)
			}
			if v, has := res.Get("ok"); has {
				if truthy(v) {
					res.Set("status", "OK")
				} else {
					res.Set("status", "ERROR")
				}
			} else if _, has := res.Get("status"); !has {
				res.Set("status", "UNKNOWN")
			}
			if !truthy(res.Value("message")) {
				msg := orValue(res.Value("error"), res.Value("details"), res.Value("detail"), res.Value("stderr"), res.Value("stdout"))
				if truthy(msg) {
					res.Set("message", pyStr(msg))
				} else {
					res.Set("message", "no details")
				}
			}
			challenge := "http-01"
			if truthy(eff.Value("dns_profile")) {
				challenge = "dns-01"
			}
			summary := fmt.Sprintf("source: %s, challenge: %s", pyStr(source), challenge)
			if truthy(eff.Value("dns_profile")) {
				summary += ", profile: " + pyStr(eff.Value("dns_profile"))
			}
			ok := truthy(res.Value("ok"))
			c.RecordRequest("certificate.issue", AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, strOrEmpty(res.Value("message")))})
			return res, nil
		}()
		if err != nil {
			log.Printf("Unhandled exception in route: %v", err)
			return c.JSON(500, newMap("ok", false, "status", "ERROR", "message", "Certificate issuance error: "+err.Error()))
		}
		return c.JSON(200, res)
	})
}
