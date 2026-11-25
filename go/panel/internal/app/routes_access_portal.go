package app

// Port of routes_access_portal.py: administration is superadmin-only;
// downloads require a verified gate login.

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/jinja"
)

// Four transfers at once is all the Flask panel gave to downloads (two in
// each of its two workers). A transfer has an hour, a block the visitor does
// not take within a minute ends it, and one visitor has one transfer at a time.
const (
	portalDownloadSeconds      = 3600
	portalDownloadStallSeconds = 60
	portalHostHeader           = "X-Easy-HA-Proxy-Portal-Host"
)

var portalDownloadSlots = make(chan struct{}, 4)

// portalSite is _site: the raw site, or 404 unless it is an access gate.
func portalSite(name string) (*Map, error) {
	_, raw, eff, err := SiteRawAndEffective(name)
	if err != nil {
		return nil, err
	}
	if raw == nil || eff.Value("access_gate") != true {
		return nil, Abort(404, "")
	}
	return raw, nil
}

// portalSetRouting is set_routing: opt in this site only; apply remains in
// the normal guarded workflow.
func portalSetRouting(op *Op, name string, enabled bool) (bool, error) {
	release, err := op.Lock("websites")
	if err != nil {
		return false, err
	}
	defer release()
	data, err := loadYAML(WebsitesYAML)
	if err != nil {
		return false, err
	}
	sites, _ := data.Value("sites").([]any)
	var site *Map
	for _, s := range sites {
		if m, ok := asMap(s); ok && pyEqual(m.Value("name"), name) {
			site = m
			break
		}
	}
	if site == nil {
		return false, &ValueError{"Access page not found"}
	}
	if truthy(site.Value("access_portal_enabled")) == enabled {
		return false, nil
	}
	site.Set("access_portal_enabled", enabled)
	if ok, message := UpdateYAMLFile(op, "websites", dumpYAML(data)); !ok {
		return false, &ValueError{message}
	}
	return true, nil
}

// portalJSONError answers the FileExistsError/ValueError of the JSON routes.
func (c *Ctx) portalJSONError(err error) error {
	var conflict *portalConflict
	var verr *ValueError
	switch {
	case errors.As(err, &conflict):
		return c.JSON(409, newMap("ok", false, "error", conflict.msg))
	case errors.As(err, &verr):
		return c.JSON(400, newMap("ok", false, "error", verr.Msg))
	}
	return err
}

// publicPortal is _public_portal.
func (c *Ctx) publicPortal() (*Map, *Map, error) {
	if !c.ID.AccessPortal {
		return nil, nil, Abort(403, "")
	}
	site, err := portalSiteByHost(c.R.Header.Get(portalHostHeader))
	var value *Map
	if err == nil {
		value, err = PortalSettings(strOrEmpty(site.Value("name")))
	}
	if err != nil {
		var verr *ValueError
		var missing *portalNotFound
		if errors.As(err, &verr) || errors.As(err, &missing) {
			return nil, nil, Abort(404, "")
		}
		return nil, nil, err
	}
	if lang := strOrEmpty(value.Value("language")); lang != "auto" {
		c.Lang = lang
	}
	return site, value, nil
}

func (c *Ctx) portalFileSize(size int64) string {
	if size < 1024 {
		return strings.ReplaceAll(c.T("{size} B"), "{size}", strconv.FormatInt(size, 10))
	}
	if size < 1024*1024 {
		return strings.ReplaceAll(c.T("{size} KiB"), "{size}", strconv.FormatFloat(float64(size)/1024, 'f', 1, 64))
	}
	return strings.ReplaceAll(c.T("{size} MiB"), "{size}", strconv.FormatFloat(float64(size)/(1024*1024), 'f', 1, 64))
}

// portalRefused is the 429 a download is turned away with.
func (c *Ctx) portalRefused(message string) error {
	c.W.Header().Set("Retry-After", "10")
	return c.Text(429, "text/plain; charset=utf-8", c.T(message))
}

// httpDate is werkzeug's http_date.
func httpDate(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

func (c *Ctx) portalSend(f *os.File, item *Map, done func()) error {
	defer done()
	size := pyIntOr0(item.Value("size"))
	h := c.W.Header()
	h.Set("Content-Disposition", contentDisposition(strOrEmpty(item.Value("filename"))))
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("Cache-Control", "private, no-store")
	h.Set("Expires", httpDate(time.Now()))
	c.writeHead(200, "application/octet-stream")
	if c.R.Method == http.MethodHead {
		return nil
	}
	rc := http.NewResponseController(c.W)
	// The server sets no write timeout of its own, so a deadline left on the
	// connection would cut short the next request that reuses it.
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	deadline := time.Now().Add(portalDownloadSeconds * time.Second)
	buf := make([]byte, 64*1024)
	for {
		if time.Now().After(deadline) {
			return nil // the download took longer than it is allowed
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(portalDownloadStallSeconds * time.Second))
			if _, err := c.W.Write(buf[:n]); err != nil {
				return nil
			}
		}
		if rerr != nil {
			return nil
		}
	}
}

func (a *App) registerAccessPortal() {
	a.Handle("access_portal.health", func(c *Ctx) error {
		return c.JSON(200, newMap("ok", true))
	})

	a.Handle("access_portal.sites", func(c *Ctx) error {
		var errMsg any
		if c.R.Method == http.MethodPost {
			domain, err := validateDomain(c.FormStr("domain"), "domain", false)
			if err != nil {
				errMsg = err.Error()
			} else {
				ok, message := AddSiteMinimal(c.op(), domain, domain, "", "", nil)
				detail := "Service access site"
				if !ok {
					detail = truncRunes(message, 500)
				}
				c.RecordRequest("site.create", AuditEntry{ObjectType: "site", ObjectID: domain, Result: recordResult(ok), Detail: detail})
				if ok {
					c.Flash(message, "message")
					return c.Redirect(c.URLFor("access_portal.edit", "name", domain), 302)
				}
				errMsg = message
			}
		}
		_, items, err := SitesAndDefaultsForUI()
		if err != nil {
			return err
		}
		gates := []any{}
		for _, item := range items {
			if get(get(item, "effective"), "access_gate") == true {
				gates = append(gates, item)
			}
		}
		return c.Render("access_sites.html", map[string]any{"sites": gates, "error": errMsg})
	})

	a.Handle("access_portal.edit", func(c *Ctx) error {
		name := c.Args["name"]
		site, err := portalSite(name)
		if err != nil {
			return err
		}
		var errMsg any
		if c.R.Method == http.MethodPost {
			action, hasAction := c.Form("action")
			// The short form takes no proxy fields: a service site has no
			// backend, unless a gate from before the split proxies to a
			// single backend of its own.
			allowed := map[string]bool{"action": true, "domain": true, "paused": true, "revision": true, "csrf_token": true}
			if truthy(site.Value("backend_ip")) && !truthy(site.Value("servers")) {
				allowed["backend_ip"], allowed["backend_port"] = true, true
			}
			extra := false
			for k := range c.R.PostForm {
				if !allowed[k] {
					extra = true
				}
			}
			paused, hasPaused := c.Form("paused")
			if !hasPaused {
				paused = "false"
			}
			if extra || !hasAction || (action != "save_identity" && action != "delete") || (paused != "true" && paused != "false") {
				return Abort(400, "")
			}
			var backend []any
			_, hasIP := c.Form("backend_ip")
			_, hasPort := c.Form("backend_port")
			if action == "save_identity" && (hasIP || hasPort) {
				backend = []any{c.FormStr("backend_ip"), c.FormStr("backend_port")}
			}
			var revision any
			if v, ok := c.Form("revision"); ok {
				revision = v
			}
			del := action == "delete"
			ok, message, serr := SaveAccessSiteIdentity(c.op(), name, c.FormStr("domain"), paused == "true", revision, del, backend)
			if serr != nil {
				var stale *StaleEntry
				if !errors.As(serr, &stale) {
					return serr
				}
				errMsg = stale.Msg
			} else {
				auditAction := "site.update"
				if del {
					auditAction = "site.delete"
				}
				c.RecordRequest(auditAction, AuditEntry{ObjectType: "site", ObjectID: name, Result: recordResult(ok), Detail: detailIfFailed(ok, message)})
				if ok {
					c.Flash(message, "message")
					if del {
						return c.Redirect(c.URLFor("access_portal.sites"), 302)
					}
					return c.Redirect(c.URLFor("access_portal.edit", "name", name), 302)
				}
				errMsg = message
			}
			if site, err = portalSite(name); err != nil {
				return err
			}
		}
		messages := []any{}
		for _, f := range c.popFlashes() {
			messages = append(messages, f.Message)
		}
		return c.Render("access_portal_settings.html", map[string]any{
			"site": site, "error": errMsg, "messages": messages,
			"site_revision": EntryRevision(site), "cert": CertStatusForSite(site),
		})
	})

	a.Handle("access_portal.settings", func(c *Ctx) error {
		name := c.Args["name"]
		if _, err := portalSite(name); err != nil {
			return err
		}
		var value *Map
		var err error
		if c.R.Method == http.MethodPost {
			changed := false
			op := c.op()
			value, err = PortalConfigure(name, c.SilentJSON(), func(enabled bool) error {
				ch, err := portalSetRouting(op, name, enabled)
				changed = changed || ch
				return err
			})
			if err == nil {
				value.Set("routing_changed", changed)
				c.RecordRequest("access_portal.settings", AuditEntry{ObjectType: "site", ObjectID: name,
					Detail: "Access page instructions and attachment labels updated"})
			}
		} else {
			value, err = PortalSettings(name)
		}
		if err != nil {
			return c.portalJSONError(err)
		}
		return c.JSON(200, newMap("ok", true, "settings", value))
	})

	a.Handle("access_portal.upload", func(c *Ctx) error {
		name := c.Args["name"]
		if _, err := portalSite(name); err != nil {
			return err
		}
		mt, _, _ := mime.ParseMediaType(c.R.Header.Get("Content-Type"))
		if mt != "application/octet-stream" {
			return Abort(415, "")
		}
		if c.R.ContentLength > portalMaxFileBytes {
			return Abort(413, "")
		}
		value, err := PortalUpload(name, c.QueryStr("filename"), c.R.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return Abort(413, "")
			}
			return c.portalJSONError(err)
		}
		c.RecordRequest("access_portal.upload", AuditEntry{ObjectType: "site", ObjectID: name, Detail: "Access page attachment uploaded"})
		return c.JSON(200, newMap("ok", true, "settings", value))
	})

	a.Handle("access_portal.delete", func(c *Ctx) error {
		name := c.Args["name"]
		if _, err := portalSite(name); err != nil {
			return err
		}
		value, err := PortalDelete(name, c.Args["identifier"])
		if err != nil {
			return c.portalJSONError(err)
		}
		c.RecordRequest("access_portal.delete", AuditEntry{ObjectType: "site", ObjectID: name, Detail: "Access page attachment removed"})
		return c.JSON(200, newMap("ok", true, "settings", value))
	})

	a.Handle("access_portal.page", func(c *Ctx) error {
		_, value, err := c.publicPortal()
		if err != nil {
			return err
		}
		// This small landing page needs no admin badges or daemon status calls.
		html, err := c.App.Env.Render("access_portal.html", map[string]any{
			"current_language": c.Lang,
			"portal":           value,
			"_": jinja.Func(func(args []any, _ *jinja.Map) (any, error) {
				if len(args) == 0 {
					return "", nil
				}
				return c.T(jinja.Str(args[0])), nil
			}),
			"file_size": jinja.Func(func(args []any, _ *jinja.Map) (any, error) {
				if len(args) == 0 {
					return nil, fmt.Errorf("file_size needs a size")
				}
				n, err := pyInt(args[0])
				if err != nil {
					return nil, err
				}
				return c.portalFileSize(n), nil
			}),
		})
		if err != nil {
			return err
		}
		c.W.Header().Set("Content-Language", c.Lang)
		return c.HTML(200, html)
	})

	a.Handle("access_portal.download", func(c *Ctx) error {
		site, _, err := c.publicPortal()
		if err != nil {
			return err
		}
		turn, err := portalDownloadTurn(c.User())
		if err != nil {
			return err
		}
		if turn == nil {
			return c.portalRefused("You already have a download in progress. Please wait for it to finish.")
		}
		select {
		case portalDownloadSlots <- struct{}{}:
		default:
			turn.Close()
			return c.portalRefused("Downloads are busy. Please try again in 10 seconds.")
		}
		release := func() {
			turn.Close()
			<-portalDownloadSlots
		}
		// Given back however this returns, a panic included, until the
		// download itself takes it over.
		handedOver := false
		defer func() {
			if !handedOver {
				release()
			}
		}()
		f, item, err := portalOpenDownload(strOrEmpty(site.Value("name")), c.Args["identifier"])
		if err != nil {
			var missing *portalNotFound
			if errors.As(err, &missing) {
				return Abort(404, "")
			}
			return err
		}
		handedOver = true
		return c.portalSend(f, item, func() {
			f.Close()
			release()
		})
	})
}
