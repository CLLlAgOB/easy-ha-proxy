package app

// Port of routes_haproxy_sites.py.

import (
	"fmt"
	"io"
	"strings"

	"easy-ha-proxy/panel/internal/pyyaml"
)

// File is request.files.get(name): its name and bytes, ok=false when absent.
func (c *Ctx) File(name string) (string, []byte, bool, error) {
	if c.R.MultipartForm == nil {
		if err := c.R.ParseMultipartForm(32 * 1024 * 1024); err != nil {
			return "", nil, false, nil
		}
	}
	f, h, err := c.R.FormFile(name)
	if err != nil {
		return "", nil, false, nil
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	return h.Filename, raw, true, err
}

func (a *App) registerSiteRoutes() {
	trashRestorers["site"] = RestoreSite
	a.Handle("routes.haproxy_site_save", func(c *Ctx) error {
		payloadV, err := c.JSONBody()
		if err != nil {
			return c.JSON(400, newMap("ok", false, "error", "Invalid JSON in request"))
		}
		payload, ok := asMap(payloadV)
		if !ok {
			return c.JSON(400, newMap("ok", false, "error", "Invalid request format"))
		}
		site, ok := asMap(orValue(payload.Value("site"), pyyaml.NewMap()))
		if !ok {
			return fmt.Errorf("site is not a dict")
		}
		origV := orValue(payload.Value("original_name"), nil)
		orig := ""
		if origV != nil {
			orig = pyStr(origV)
		}
		expected := orValue(payload.Value("revision"), nil)
		name := orStr(orValue(site.Value("name"), origV))
		before := pyyaml.NewMap()
		revision := ""
		op := c.op()
		release, err := op.Lock("websites")
		if err != nil {
			return err
		}
		var okSave bool
		var msg string
		var serr error
		var early error
		func() {
			defer release()
			if orig != "" {
				_, previous, eff, err := SiteRawAndEffective(orig)
				if err != nil {
					serr = err
					return
				}
				if previous != nil {
					before = previous
				}
				if eff != nil && eff.Value("access_gate") == true {
					early = c.JSON(400, newMap("ok", false, "error", "Use the service-site editor"))
					return
				}
			}
			if site.Value("access_gate") == true {
				early = c.JSON(400, newMap("ok", false, "error", "Use the service-site editor"))
				return
			}
			okSave, msg, serr = SaveSiteFromJSON(op, site, orig, expected)
			if serr == nil && okSave {
				revision = SiteRevision(name)
			}
		}()
		if c.written {
			return early
		}
		if serr != nil {
			if se, stale := serr.(*StaleEntry); stale {
				c.RecordRequest("site.update", AuditEntry{ObjectType: "site", ObjectID: name, Result: auditResultFailure, Detail: truncRunes(se.Msg, 500)})
				return c.JSON(409, newMap("ok", false, "conflict", true, "error", se.Msg))
			}
			return serr
		}
		act := "site.create"
		if before.Len() > 0 {
			act = "site.update"
		}
		res, summary, detail := auditResultFailure, "", truncRunes(msg, 500)
		if okSave {
			res, summary, detail = auditResultSuccess, AuditSummarize(before, site), ""
		}
		c.RecordRequest(act, AuditEntry{ObjectType: "site", ObjectID: name, Result: res, Summary: summary, Detail: detail})
		if okSave {
			now, has := site.Get("cert_renewal_paused")
			if !has {
				now = before.Value("cert_renewal_paused")
			}
			if (before.Value("cert_renewal_paused") == true) != (now == true) {
				synced := SyncRenewalPauses()
				if !truthy(synced.Value("ok")) {
					msg = fmt.Sprintf("%s The certificate service could not be told about the renewal pause yet (%s); it will be told on the next apply.", msg, pyStr(orValue(synced.Value("error"), "unknown error")))
				}
			}
		}
		status := 400
		if okSave {
			status = 200
		}
		answer := newMap("ok", okSave, okKey(okSave), msg)
		if revision != "" {
			answer.Set("revision", revision)
		}
		return c.JSON(status, answer)
	})
	a.Handle("routes.haproxy_site_upload_cert", func(c *Ctx) error {
		siteName := c.Args["site_name"]
		filename, pem, ok, rerr := c.File("cert_file")
		if !ok || filename == "" {
			return c.JSON(400, newMap("ok", false, "error", "No file supplied"))
		}
		_, raw, eff, err := SiteRawAndEffective(siteName)
		if err != nil {
			return err
		}
		if raw == nil {
			return c.JSON(404, newMap("ok", false, "error", "Site was not found"))
		}
		domain := orStr(orValue(eff.Value("domain"), eff.Value("name")))
		source, _ := raw.Value("certificate_source").(string)
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
		if source != "external" {
			return c.JSON(400, newMap("ok", false, "error", "Select the external certificate authority mode before uploading a certificate."))
		}
		ext := orStr(raw.Value("external_ca_id"))
		if ext == "" {
			return c.JSON(400, newMap("ok", false, "error", "Select an imported external certificate authority."))
		}
		if rerr != nil {
			return c.JSON(400, newMap("ok", false, "error", "Failed to read uploaded file: "+rerr.Error()))
		}
		if len(pem) == 0 {
			return c.JSON(400, newMap("ok", false, "error", "The file is empty"))
		}
		res := CertdUpload(siteName, domain, pem, filename, ext)
		result, detail := auditResultFailure, truncRunes(strOrEmpty(res.Value("error")), 500)
		if truthy(res.Value("ok")) {
			result, detail = auditResultSuccess, ""
		}
		c.RecordRequest("certificate.upload", AuditEntry{ObjectType: "site", ObjectID: siteName, Result: result,
			Summary: fmt.Sprintf("authority: %s, bytes: %d", ext, len(pem)), Detail: detail})
		return c.JSON(200, res)
	})
	a.Handle("routes.haproxy_site_delete", func(c *Ctx) error {
		name := c.Args["name"]
		ok, msg := DeleteSiteByName(c.op(), name)
		res, detail := auditResultFailure, truncRunes(msg, 500)
		if ok {
			res, detail = auditResultSuccess, ""
		}
		c.RecordRequest("site.delete", AuditEntry{ObjectType: "site", ObjectID: name, Result: res, Detail: detail})
		return c.JSON(200, newMap("ok", ok, okKey(ok), msg))
	})
}

var _ = strings.TrimSpace
