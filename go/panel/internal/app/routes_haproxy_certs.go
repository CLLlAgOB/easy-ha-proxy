package app

// Port of routes_haproxy_config.py: the certificates page and its uploads,
// downloads, backup and restore.

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxCertUploadBytes = 4 * 1024 * 1024

var certAuditActions = map[string][2]string{
	"delete_haproxy":           {"certificate.delete", "certificate"},
	"delete_le":                {"certificate.delete", "letsencrypt"},
	"create_internal_ca":       {"ca.create", "internal_ca"},
	"issue_internal_cert":      {"certificate.issue", "certificate"},
	"rotate_internal_ca":       {"ca.rotate", "internal_ca"},
	"delete_internal_ca":       {"ca.delete", "internal_ca"},
	"import_external_ca":       {"ca.import", "external_ca"},
	"delete_external_ca":       {"ca.delete", "external_ca"},
	"set_client_auth_cas":      {"ca.client_auth", "client_auth"},
	"set_revoked_client_certs": {"ca.revoke_client", "client_certificate"},
	"store_standby":            {"certificate.standby_store", "certificate"},
	"activate_standby":         {"certificate.standby_activate", "certificate"},
	"delete_standby":           {"certificate.standby_delete", "certificate"},
	"release_standby":          {"certificate.standby_release", "certificate"},
	"adopt_standby":            {"certificate.standby_adopt", "certificate"},
}

var (
	commaSpaceSplit   = regexp.MustCompile(`[,\s]+`)
	commaSemiSpaceSpl = regexp.MustCompile(`[,;\s]+`)
)

func clientTrustSites(res *Map) string {
	sites, _ := asList(orValue(get(orValue(res.Value("client_trust"), newMap()), "sites"), []any{}))
	if len(sites) == 0 {
		return ""
	}
	parts := make([]string, len(sites))
	for i, s := range sites {
		parts[i] = pyRepr(pyStr(s))
	}
	return " Sites that ask for its client certificates: " + strings.Join(parts, ", ") + "."
}

func splitNonEmpty(re *regexp.Regexp, text string) []string {
	var out []string
	for _, v := range re.Split(text, -1) {
		if strings.TrimSpace(v) != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

func firstText(res *Map, keys ...string) string {
	for _, k := range keys {
		if truthy(res.Value(k)) {
			return pyStr(res.Value(k))
		}
	}
	return ""
}

func (a *App) registerCertRoutes() {
	a.Handle("routes.haproxy_certs_page", func(c *Ctx) error {
		var message, errMsg string
		actor := c.User()
		if c.R.Method == http.MethodPost {
			action := c.FormStrip("action")
			target := ""
			okOr := func(res *Map, okMsg string, fail ...string) {
				if truthy(res.Value("ok")) {
					message = okMsg
				} else {
					errMsg = firstText(res, fail[:len(fail)-1]...)
					if errMsg == "" {
						errMsg = fail[len(fail)-1]
					}
				}
			}
			switch action {
			case "delete_haproxy":
				target = c.FormStrip("path")
				res := CertdDeleteHAProxy(target, actor)
				okOr(res, pyStr(orValue(res.Value("message"), "HAProxy certificate deleted: "+target)), "message", "error", "Failed to delete the HAProxy certificate")
			case "delete_le":
				target = c.FormStrip("lineage")
				res := CertdDeleteLE(target, actor)
				okOr(res, pyStr(orValue(res.Value("message"), "Let's Encrypt certificate deleted: "+target)), "message", "error", "Failed to delete the Let's Encrypt certificate")
			case "create_internal_ca":
				res := CertdEnsureInternalCA()
				okOr(res, pyStr(orValue(res.Value("message"), "Internal certificate authority is ready.")), "error", "Failed to create the internal certificate authority")
			case "issue_internal_cert":
				domain := c.FormStrip("domain")
				var alts []any
				for _, v := range splitNonEmpty(commaSpaceSplit, c.FormStr("alt_names")) {
					alts = append(alts, v)
				}
				target = domain
				res := CertdIssueInternal(domain, alts)
				okOr(res, pyStr(orValue(res.Value("message"), "Internal certificate issued successfully.")), "error", "Failed to issue the internal certificate")
			case "rotate_internal_ca":
				res := CertdRotateInternalCA(c.FormStr("confirmation"))
				if truthy(res.Value("ok")) {
					reissued, _ := asList(orValue(res.Value("reissued"), []any{}))
					message = pyStr(orValue(res.Value("message"), fmt.Sprintf("Internal certificate authority rotated; certificates reissued: %d.", len(reissued))))
				} else {
					errMsg = pyStr(orValue(res.Value("error"), "Failed to rotate the internal certificate authority")) + clientTrustSites(res)
				}
			case "delete_internal_ca":
				res := CertdDeleteInternalCA(c.FormStr("confirmation"), actor)
				if truthy(res.Value("ok")) {
					message = pyStr(orValue(res.Value("message"), "Internal certificate authority deleted."))
				} else {
					errMsg = pyStr(orValue(res.Value("error"), "Failed to delete the internal certificate authority")) + clientTrustSites(res)
					blockers, _ := asList(orValue(res.Value("blocking_certificates"), []any{}))
					if len(blockers) > 0 {
						parts := make([]string, len(blockers))
						for i, b := range blockers {
							doms, _ := asList(orValue(get(b, "domains"), []any{}))
							var ds []string
							for _, d := range doms {
								ds = append(ds, pyStr(d))
							}
							parts[i] = strings.Join(ds, ", ")
							if parts[i] == "" {
								parts[i] = strOrEmpty(get(b, "path"))
							}
						}
						errMsg += ": " + strings.Join(parts, ", ")
					}
				}
			case "import_external_ca":
				filename, raw, ok, _ := c.File("ca_file")
				if !ok || filename == "" {
					errMsg = "Select a root or intermediate CA certificate bundle"
				} else {
					target = c.FormStrip("ca_name")
					res := CertdUploadExternalCA(target, raw, filename)
					okOr(res, pyStr(orValue(res.Value("message"), "External certificate authority imported.")), "error", "Failed to import the certificate authority")
				}
			case "store_standby":
				domain := c.FormStrip("standby_domain")
				slot := c.FormStrip("standby_slot")
				target = domain + "/" + slot
				certName, certRaw, ok, _ := c.File("standby_cert")
				if !ok || certName == "" {
					errMsg = "Select the certificate file"
				} else {
					pieces := []string{strings.ToValidUTF8(string(certRaw), "�")}
					if keyName, keyRaw, ok, _ := c.File("standby_key"); ok && keyName != "" {
						pieces = append(pieces, strings.ToValidUTF8(string(keyRaw), "�"))
					}
					for i := range pieces {
						pieces[i] = strings.TrimSpace(pieces[i])
					}
					blob := strings.Join(pieces, "\n") + "\n"
					var res *Map
					var covered []string
					if domain == "*" {
						res = CertdStandbyStoreAll(slot, blob)
						doms, _ := asList(orValue(res.Value("domains"), []any{}))
						for _, d := range doms {
							covered = append(covered, pyStr(d))
						}
						target = "*/" + slot
					} else {
						res = CertdStandbyStore(domain, slot, blob)
						if truthy(res.Value("ok")) {
							covered = []string{domain}
						}
					}
					okOr(res, "Standby certificate kept for "+strings.Join(covered, ", "), "error", "Failed to keep the standby certificate")
				}
			case "activate_standby":
				domain, slot := c.FormStrip("standby_domain"), c.FormStrip("standby_slot")
				target = domain + "/" + slot
				res := CertdStandbyActivate(domain, slot)
				issuer := ""
				if v, has := res.Get("issuer"); has {
					issuer = pyStr(v)
				}
				okOr(res, fmt.Sprintf("%s is now served by the standby certificate from %s", domain, issuer), "reload_error", "error", "Failed to put the standby certificate into service")
			case "adopt_standby":
				domain := c.FormStrip("standby_domain")
				slot := c.FormStrip("standby_slot")
				if slot == "" {
					slot = "imported"
				}
				target = domain + "/" + slot
				res := CertdStandbyAdopt(domain, slot)
				doms, _ := asList(orValue(res.Value("domains"), []any{}))
				var ds []string
				for _, d := range doms {
					ds = append(ds, pyStr(d))
				}
				okOr(res, fmt.Sprintf("%s taken out of service and kept as the standby '%s' for ", domain, slot)+strings.Join(ds, ", "), "reload_error", "error", "Failed to take the certificate out of service")
			case "release_standby":
				domain := c.FormStrip("standby_domain")
				target = domain
				res := CertdReleaseToLE(domain)
				var okMsg string
				if truthy(res.Value("restored")) {
					okMsg = domain + " is back on Let's Encrypt"
				} else {
					okMsg = pyStr(orValue(res.Value("message"), domain+" released; no Let's Encrypt certificate on disk yet"))
				}
				okOr(res, okMsg, "reload_error", "error", "Failed to hand the name back to Let's Encrypt")
			case "delete_standby":
				domain, slot := c.FormStrip("standby_domain"), c.FormStrip("standby_slot")
				target = domain + "/" + slot
				res := CertdStandbyDelete(domain, slot, actor)
				okOr(res, "Standby certificate removed for "+domain, "error", "Failed to remove the standby certificate")
			case "delete_external_ca":
				target = c.FormStrip("ca_id")
				res := CertdDeleteExternalCA(target, actor)
				okOr(res, pyStr(orValue(res.Value("message"), "External certificate authority deleted.")), "error", "Failed to delete the certificate authority")
			case "set_client_auth_cas":
				var ids []any
				var sorted []string
				for _, v := range c.FormList("client_auth_ca") {
					if t := strings.ToLower(strings.TrimSpace(v)); t != "" {
						ids = append(ids, t)
						sorted = append(sorted, t)
					}
				}
				if ids == nil {
					ids = []any{}
				}
				sort.Strings(sorted)
				target = strings.Join(sorted, ",")
				res := CertdSetClientAuthCAs(ids)
				if truthy(res.Value("ok")) {
					message = pyStr(orValue(res.Value("message"), "Client authentication updated."))
					if truthy(res.Value("reload_error")) {
						errMsg = "The trust list was saved but HAProxy did not reload: " + pyStr(res.Value("reload_error"))
					}
				} else {
					errMsg = pyStr(orValue(res.Value("error"), "Failed to update client authentication"))
				}
			case "set_revoked_client_certs":
				fps := []any{}
				for _, v := range splitNonEmpty(commaSemiSpaceSpl, c.FormStr("fingerprints")) {
					fps = append(fps, v)
				}
				target = fmt.Sprint(len(fps))
				res := CertdSetRevoked(fps)
				if truthy(res.Value("ok")) {
					message = pyStr(orValue(res.Value("message"), "The revocation list was saved."))
					if truthy(res.Value("reload_error")) {
						errMsg = "The list was saved but HAProxy did not reload, so it is not in force yet: " + pyStr(res.Value("reload_error"))
					}
				} else {
					errMsg = pyStr(orValue(res.Value("error"), "Failed to save the revocation list"))
				}
			default:
				errMsg = "Unknown action"
			}
			if aa, ok := certAuditActions[action]; ok {
				res := auditResultSuccess
				if errMsg != "" {
					res = auditResultFailure
				}
				c.RecordRequest(aa[0], AuditEntry{ObjectType: aa[1], ObjectID: target, Result: res, Summary: "action: " + action, Detail: truncRunes(errMsg, 500)})
			}
		}
		if errMsg != "" {
			errMsg = c.T(errMsg)
		}
		if message != "" {
			message = c.T(message)
		}
		standby := CertdStandbyList()
		data := CertdListAll()
		auth, _ := asMap(orValue(data.Value("certificate_authorities"), newMap()))
		if auth == nil {
			auth = newMap()
		}
		if errMsg == "" && !truthy(data.Value("ok")) {
			errMsg = pyStr(orValue(data.Value("error"), "Failed to get the certificate list from haproxy-certd"))
		}
		standbyErr := ""
		if !truthy(standby.Value("ok")) {
			standbyErr = strOrEmpty(standby.Value("error"))
		}
		return c.Render("haproxy_certs.html", map[string]any{
			"haproxy_certs": orValue(data.Value("haproxy"), []any{}), "le_certs": orValue(data.Value("letsencrypt"), []any{}),
			"internal_ca": auth.Value("internal"), "external_cas": orValue(auth.Value("external"), []any{}),
			"revoked_client_certs": orValue(auth.Value("revoked_client_certificates"), []any{}),
			"standby_domains":      orValue(standby.Value("domains"), []any{}), "standby_error": standbyErr,
			"message": noneIfEmpty(message), "error": noneIfEmpty(errMsg),
		})
	})
	material := func(action string) HandlerFunc {
		return func(c *Ctx) error {
			filename, raw, ok, _ := c.File("file")
			if !ok || filename == "" {
				return c.JSON(400, newMap("ok", false, "error", "Select a file"))
			}
			if len(raw) > maxCertUploadBytes {
				return c.JSON(413, newMap("ok", false, "error", "The file is too large"))
			}
			password, name, domain := c.FormStr("password"), c.FormStrip("name"), c.FormStrip("domain")
			if action == "inspect" {
				return c.JSON(200, CertdMaterial("inspect", raw, filename, password, name, domain, false))
			}
			replace := strings.ToLower(c.FormStr("replace"))
			res := CertdMaterial("import", raw, filename, password, name, domain, replace == "1" || replace == "true" || replace == "on")
			done, _ := asList(orValue(res.Value("completed"), []any{}))
			var parts []string
			for _, d := range done {
				parts = append(parts, pyStr(d))
			}
			summary := strings.Join(parts, "; ")
			if summary == "" {
				summary = "nothing was installed"
			}
			obj := domain
			if obj == "" {
				obj = name
			}
			if obj == "" {
				obj = filename
			}
			okRes := truthy(res.Value("ok"))
			c.RecordRequest("certificate.import", AuditEntry{ObjectType: "certificate", ObjectID: obj, Result: recordResult(okRes), Summary: summary, Detail: truncRunes(strOrEmpty(res.Value("error")), 500)})
			return c.JSON(200, res)
		}
	}
	a.Handle("routes.haproxy_certs_inspect", material("inspect"))
	a.Handle("routes.haproxy_certs_import", material("import"))
	a.Handle("routes.haproxy_ca_download", func(c *Ctx) error {
		caID := c.Args["ca_id"]
		res := CertdExportCA(caID)
		if !truthy(res.Value("ok")) {
			return Abort(404, "")
		}
		content, err := pyB64DecodeStrict(strOrEmpty(res.Value("certificate_b64")))
		if err != nil {
			return Abort(502, "")
		}
		name := strOrEmpty(res.Value("filename"))
		if name == "" {
			name = caID + ".pem"
		}
		return c.sendBytes(content, "application/x-pem-file", name)
	})
	a.Handle("routes.haproxy_certs_backup", func(c *Ctx) error {
		res := CertdBackup()
		if !truthy(res.Value("ok")) {
			msg := firstText(res, "message", "error")
			if msg == "" {
				msg = "Unknown backup error."
			}
			log.Printf("Backup certs returned error: %s", msg)
			return c.Text(500, "text/plain; charset=utf-8", "Certificate backup error:\n"+msg)
		}
		c.RecordRequest("certificate.export", AuditEntry{ObjectType: "certificate", ObjectID: "all"})
		archive := strOrEmpty(res.Value("archive_b64"))
		if archive == "" {
			return c.Text(500, "text/plain; charset=utf-8", "The backup service did not return an archive (archive_b64 is empty).")
		}
		binary, err := pyB64Decode(archive)
		if err != nil {
			return c.Text(500, "text/plain; charset=utf-8", "Failed to decode the archive (base64 error).")
		}
		c.W.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="haproxy_certs_backup_%s.zip"`, time.Now().UTC().Format("20060102_150405")))
		return c.Text(200, "application/zip", string(binary))
	})
	a.Handle("routes.haproxy_certs_restore", func(c *Ctx) error {
		filename, raw, ok, _ := c.File("archive")
		if !ok || filename == "" || len(raw) == 0 {
			return c.Redirect(c.URLFor("routes.haproxy_certs_page"), 302)
		}
		res := CertdRestore(raw)
		okRes := truthy(res.Value("ok"))
		detail := ""
		if !okRes {
			detail = truncRunes(firstText(res, "message", "error"), 500)
			log.Printf("haproxy_certs_restore: restore failed: %s", truncRunes(strings.TrimSpace(firstText(res, "message", "error")), 300))
		}
		c.RecordRequest("certificate.restore", AuditEntry{ObjectType: "certificate", ObjectID: "all", Result: recordResult(okRes), Summary: fmt.Sprintf("bytes: %d", len(raw)), Detail: detail})
		return c.Redirect(c.URLFor("routes.haproxy_certs_page"), 302)
	})
}

var _ = base64.StdEncoding
