package app

// Ports of services_authelia_settings.py and routes_authelia_settings.py.

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"easy-ha-proxy/panel/internal/pyyaml"
)

var (
	mailFields      = []string{"host", "mode", "password", "password_action", "port", "recipient", "sender", "subject", "timeout", "tls_mode", "tls_skip_verify", "username"}
	dnsLabelRe      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	mailEmailRe     = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
	mailTimeoutRe   = regexp.MustCompile(`^[1-9][0-9]{0,5}(?:ms|s|m|h)$`)
	notifMetaFields = []string{"handled", "handled_at", "id", "received_at", "recipient_masked", "revision", "size"}
	latestFields    = []string{"conflict", "error", "latest", "mode", "ok", "status", "validation_error"}
	handleFields    = []string{"conflict", "error", "forbidden", "latest", "ok", "status", "validation_error"}
)

func getNested(d any, path ...any) any {
	cur := d
	for _, p := range path {
		switch k := p.(type) {
		case int:
			l, ok := asList(cur)
			if !ok || len(l) <= k {
				return nil
			}
			cur = l[k]
		case string:
			m, ok := asMap(cur)
			if !ok {
				return nil
			}
			cur = m.Value(k)
		}
		if cur == nil {
			return nil
		}
	}
	return cur
}

func nested(d any, def any, path ...any) any {
	if v := getNested(d, path...); v != nil {
		return v
	}
	return def
}

// loadSettingsFormData is load_settings_form_data.
func loadSettingsFormData() (*Map, error) {
	resp := ConfigClient(newMap("action", "config_view"), 5*time.Second)
	if !truthy(resp.Value("ok")) {
		e, has := resp.Get("error")
		if !has {
			e = "authelia-configd config_view failed"
		}
		return nil, fmt.Errorf("%s", pyStr(e))
	}
	cfg := orValue(resp.Value("config"), newMap())
	f := pyyaml.NewMap()
	f.Set("server_address", nested(cfg, "", "server", "address"))
	f.Set("log_level", nested(cfg, "warn", "log", "level"))
	f.Set("log_format", nested(cfg, "json", "log", "format"))
	f.Set("log_file_path", nested(cfg, "", "log", "file_path"))
	f.Set("log_keep_stdout", truthy(nested(cfg, true, "log", "keep_stdout")))
	f.Set("session_name", nested(cfg, "authelia_session", "session", "name"))
	f.Set("session_same_site", nested(cfg, "lax", "session", "same_site"))
	f.Set("session_expiration", nested(cfg, "12h", "session", "expiration"))
	f.Set("session_inactivity", nested(cfg, "30m", "session", "inactivity"))
	f.Set("session_remember_me", nested(cfg, "3M", "session", "remember_me"))
	f.Set("cookie_domain", nested(cfg, "", "session", "cookies", 0, "domain"))
	f.Set("cookie_authelia_url", nested(cfg, "", "session", "cookies", 0, "authelia_url"))
	f.Set("cookie_default_redirection_url", nested(cfg, "", "session", "cookies", 0, "default_redirection_url"))
	f.Set("storage_local_path", nested(cfg, "/config/db.sqlite3", "storage", "local", "path"))
	f.Set("auth_refresh_interval", nested(cfg, "always", "authentication_backend", "refresh_interval"))
	f.Set("auth_file_path", nested(cfg, "/config/users_database.yml", "authentication_backend", "file", "path"))
	f.Set("auth_file_watch", truthy(nested(cfg, true, "authentication_backend", "file", "watch")))
	f.Set("auth_password_algorithm", nested(cfg, "argon2id", "authentication_backend", "file", "password", "algorithm"))
	modes := nested(cfg, []any{"ip"}, "regulation", "modes")
	if l, ok := asList(modes); ok {
		parts := make([]string, len(l))
		for i, m := range l {
			parts[i] = pyStr(m)
		}
		f.Set("reg_modes", strings.Join(parts, ", "))
	} else {
		f.Set("reg_modes", pyStr(modes))
	}
	f.Set("reg_max_retries", nested(cfg, int64(5), "regulation", "max_retries"))
	f.Set("reg_find_time", nested(cfg, "2m", "regulation", "find_time"))
	f.Set("reg_ban_time", nested(cfg, "1h", "regulation", "ban_time"))
	f.Set("totp_issuer", nested(cfg, "", "totp", "issuer"))
	f.Set("totp_period", nested(cfg, int64(30), "totp", "period"))
	f.Set("totp_skew", nested(cfg, int64(1), "totp", "skew"))
	return f, nil
}

func loadMailSettings() (*Map, error) {
	resp := ConfigClient(newMap("action", "mail_view"), 5*time.Second)
	if !truthy(resp.Value("ok")) {
		return nil, fmt.Errorf("%s", pyStr(orValue(resp.Value("error"), "authelia-configd mail_view failed")))
	}
	settings, ok := asMap(resp.Value("settings"))
	if !ok {
		return nil, fmt.Errorf("authelia-configd returned invalid mail settings")
	}
	settings.Delete("password")
	return newMap("ok", true, "settings", settings, "capabilities", orValue(resp.Value("capabilities"), newMap()), "revision", strOrEmpty(resp.Value("revision"))), nil
}

func mailText(v any, label string, maximum int, required bool) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", valueErr("%s must be a string", label)
	}
	t := strings.TrimSpace(s)
	if required && t == "" {
		return "", valueErr("%s is required", label)
	}
	if pyLen(t) > maximum || controlRe.MatchString(t) {
		return "", valueErr("%s contains invalid characters or is too long", label)
	}
	return t, nil
}

func mailHost(v any) (string, error) {
	host, err := mailText(v, "SMTP host", 253, true)
	if err != nil {
		return "", err
	}
	cand := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		cand = host[1 : len(host)-1]
	}
	if a, ok := pyIPAddress(cand); ok {
		return a.String(), nil
	}
	for _, l := range strings.Split(strings.TrimRight(host, "."), ".") {
		if !dnsLabelRe.MatchString(l) {
			return "", &ValueError{"SMTP host must be a valid IP address or DNS name"}
		}
	}
	return strings.TrimRight(host, "."), nil
}

func mailEmail(v any, label string) (string, error) {
	e, err := mailText(v, label, 254, true)
	if err != nil {
		return "", err
	}
	if !mailEmailRe.MatchString(e) {
		return "", valueErr("%s must be a valid email address", label)
	}
	return e, nil
}

func validateMailSettingsPayload(v any) (*Map, error) {
	p, ok := asMap(v)
	if !ok {
		return nil, &ValueError{"settings must be an object"}
	}
	allowed := map[string]bool{}
	for _, f := range mailFields {
		allowed[f] = true
	}
	var unexpected, missing []string
	for _, k := range p.Keys() {
		if !allowed[pyStr(k)] {
			unexpected = append(unexpected, pyStr(k))
		}
	}
	for _, f := range mailFields {
		if !has(p, f) {
			missing = append(missing, f)
		}
	}
	if len(unexpected) > 0 || len(missing) > 0 {
		sort.Strings(unexpected)
		var details []string
		if len(missing) > 0 {
			details = append(details, "missing: "+strings.Join(missing, ", "))
		}
		if len(unexpected) > 0 {
			details = append(details, "unsupported: "+strings.Join(unexpected, ", "))
		}
		return nil, &ValueError{"invalid mail settings fields (" + strings.Join(details, "; ") + ")"}
	}
	mode := strings.ToLower(orStr(p.Value("mode")))
	if mode != "filesystem" && mode != "relay" {
		return nil, &ValueError{"mode must be filesystem or relay"}
	}
	tls := strings.ToLower(orStr(p.Value("tls_mode")))
	if tls != "smtps" && tls != "starttls" && tls != "plain" {
		return nil, &ValueError{"tls_mode must be smtps, starttls, or plain"}
	}
	pa := strings.ToLower(orStr(p.Value("password_action")))
	if pa != "keep" && pa != "replace" && pa != "clear" {
		return nil, &ValueError{"password_action must be keep, replace, or clear"}
	}
	var host string
	rawHost := p.Value("host")
	if hs, ok := rawHost.(string); mode == "filesystem" && ok && strings.TrimSpace(hs) == "" {
		host = ""
	} else {
		h, err := mailHost(rawHost)
		if err != nil {
			return nil, err
		}
		host = h
	}
	portV := p.Value("port")
	if mode == "filesystem" && (portV == nil || portV == "") {
		portV = int64(25)
	}
	if isBool(portV) {
		return nil, &ValueError{"SMTP port must be an integer"}
	}
	port, err := pyInt(portV)
	if err != nil {
		return nil, &ValueError{"SMTP port must be an integer"}
	}
	if port < 1 || port > 65535 {
		return nil, &ValueError{"SMTP port must be between 1 and 65535"}
	}
	password, ok := p.Value("password").(string)
	if !ok {
		return nil, &ValueError{"password must be a string"}
	}
	if pyLen(password) > 1024 || controlRe.MatchString(password) {
		return nil, &ValueError{"password contains invalid characters or is too long"}
	}
	if pa == "replace" && password == "" {
		return nil, &ValueError{"a non-empty password is required when replacing it"}
	}
	if pa != "replace" && password != "" {
		return nil, &ValueError{"password must be empty unless password_action is replace"}
	}
	skip, ok := p.Value("tls_skip_verify").(bool)
	if !ok {
		return nil, &ValueError{"tls_skip_verify must be true or false"}
	}
	var sender, recipient, subject string
	if mode == "filesystem" {
		if s, ok := p.Value("sender").(string); ok && strings.TrimSpace(s) != "" {
			if sender, err = mailEmail(s, "Sender"); err != nil {
				return nil, err
			}
		}
		if s, ok := p.Value("recipient").(string); ok && strings.TrimSpace(s) != "" {
			if recipient, err = mailEmail(s, "Recipient"); err != nil {
				return nil, err
			}
		}
		if subject, err = mailText(p.Value("subject"), "Subject", 255, false); err != nil {
			return nil, err
		}
	} else {
		if sender, err = mailEmail(p.Value("sender"), "Sender"); err != nil {
			return nil, err
		}
		if recipient, err = mailEmail(p.Value("recipient"), "Recipient"); err != nil {
			return nil, err
		}
		if subject, err = mailText(p.Value("subject"), "Subject", 255, true); err != nil {
			return nil, err
		}
	}
	username, err := mailText(p.Value("username"), "SMTP username", 320, false)
	if err != nil {
		return nil, err
	}
	timeout, err := mailText(p.Value("timeout"), "Timeout", 16, true)
	if err != nil {
		return nil, err
	}
	return newMap("mode", mode, "host", host, "port", port, "username", username, "password_action", pa, "password", password,
		"sender", sender, "recipient", recipient, "subject", subject, "timeout", timeout, "tls_mode", tls, "tls_skip_verify", skip), nil
}

func validRevision(v any) bool {
	s, ok := v.(string)
	return ok && hex64Re.MatchString(s)
}

func saveMailSettings(payload any, revision any) *Map {
	settings, err := validateMailSettingsPayload(payload)
	if err == nil && !mailTimeoutRe.MatchString(pyStr(settings.Value("timeout"))) {
		err = &ValueError{"Timeout must look like 10s, 2m, 1h, or 500ms"}
	}
	if err != nil {
		return newMap("ok", false, "validation_error", true, "error", err.Error())
	}
	if !validRevision(revision) {
		return newMap("ok", false, "validation_error", true, "error", "revision must be the current 64-character SHA-256 value")
	}
	resp := ConfigClient(newMap("action", "mail_update", "settings", settings, "apply", true, "revision", revision), 840*time.Second)
	if s, ok := asMap(resp.Value("settings")); ok {
		s.Delete("password")
	}
	return resp
}

func testMailSettings(revision, recipient any) *Map {
	if !validRevision(revision) {
		return newMap("ok", false, "validation_error", true, "error", "revision must be the current 64-character SHA-256 value")
	}
	r, err := mailEmail(recipient, "Recipient")
	if err != nil {
		return newMap("ok", false, "validation_error", true, "error", err.Error())
	}
	return ConfigClient(newMap("action", "mail_test", "revision", revision, "recipient", r), 180*time.Second)
}

func allowlistNotification(resp *Map, allowed []string) *Map {
	out := pyyaml.NewMap()
	for _, k := range allowed {
		if k == "latest" {
			continue
		}
		if v, ok := resp.Get(k); ok {
			out.Set(k, v)
		}
	}
	isAllowed := false
	for _, k := range allowed {
		if k == "latest" {
			isAllowed = true
		}
	}
	if v, ok := resp.Get("latest"); ok && isAllowed {
		if lm, ok := asMap(v); ok {
			f := pyyaml.NewMap()
			for _, k := range notifMetaFields {
				if x, ok := lm.Get(k); ok {
					f.Set(k, x)
				}
			}
			out.Set("latest", f)
		} else {
			out.Set("latest", nil)
		}
	}
	return out
}

func notificationRef(id, rev any) error {
	if !validRevision(id) || !validRevision(rev) {
		return &ValueError{"id and revision must be current 64-character values"}
	}
	return nil
}

func notificationCall(action string, id, rev any, actor string, extra *Map) (*Map, bool) {
	if err := notificationRef(id, rev); err != nil {
		return newMap("ok", false, "validation_error", true, "error", err.Error()), false
	}
	a, err := mailText(actor, "Actor", 128, true)
	if err != nil {
		return newMap("ok", false, "validation_error", true, "error", err.Error()), false
	}
	p := newMap("action", action, "id", id, "revision", rev)
	if extra != nil {
		extra.Each(func(k, v any) { p.Set(k, v) })
	}
	p.Set("actor", a)
	return ConfigClient(p, 5*time.Second), true
}

func parseIntField(c *Ctx, name string, def int64) (int64, error) {
	v := c.FormStrip(name)
	if v == "" {
		return def, nil
	}
	n, err := parsePyIntString(v)
	if err != nil {
		return 0, valueErr("Field '%s' must be an integer, not '%s'", name, v)
	}
	return n, nil
}

func cookiesWithFirstUpdated(cookie *Map) ([]any, error) {
	resp := ConfigClient(newMap("action", "config_view"), 5*time.Second)
	if !truthy(resp.Value("ok")) {
		return nil, fmt.Errorf("The session cookies stored now cannot be read, so the settings were not saved: saving would replace them.")
	}
	current, ok := asList(get(get(orValue(resp.Value("config"), newMap()), "session"), "cookies"))
	if !ok || len(current) == 0 {
		return []any{cookie}, nil
	}
	first := newMap()
	if m, ok := asMap(current[0]); ok {
		first = copyMap(m)
	}
	cookie.Each(func(k, v any) { first.Set(k, v) })
	out := []any{first}
	for _, it := range current[1:] {
		if m, ok := asMap(it); ok {
			out = append(out, copyMap(m))
		}
	}
	return out, nil
}

func saveSettingsFromForm(c *Ctx) (bool, string) {
	or := func(name, def string) string {
		if v := c.FormStrip(name); v != "" {
			return v
		}
		return def
	}
	cfg := pyyaml.NewMap()
	cfg.Set("log", newMap("level", or("log_level", "warn")))
	session := newMap("name", or("session_name", "authelia_session"), "same_site", or("session_same_site", "lax"),
		"expiration", or("session_expiration", "12h"), "inactivity", or("session_inactivity", "30m"), "remember_me", or("session_remember_me", "3M"))
	cookie := newMap("domain", c.FormStrip("cookie_domain"), "authelia_url", c.FormStrip("cookie_authelia_url"), "default_redirection_url", c.FormStrip("cookie_default_redirection_url"))
	cookies, err := cookiesWithFirstUpdated(cookie)
	if err != nil {
		return false, err.Error()
	}
	session.Set("cookies", cookies)
	cfg.Set("session", session)
	var modes []any
	for _, m := range strings.Split(or("reg_modes", "ip"), ",") {
		if t := strings.TrimSpace(m); t != "" {
			modes = append(modes, t)
		}
	}
	if modes == nil {
		modes = []any{}
	}
	maxRetries, err := parseIntField(c, "reg_max_retries", 5)
	if err != nil {
		return false, err.Error()
	}
	cfg.Set("regulation", newMap("modes", modes, "max_retries", maxRetries, "find_time", or("reg_find_time", "2m"), "ban_time", or("reg_ban_time", "1h")))
	period, err := parseIntField(c, "totp_period", 30)
	if err != nil {
		return false, err.Error()
	}
	skew, err := parseIntField(c, "totp_skew", 1)
	if err != nil {
		return false, err.Error()
	}
	cfg.Set("totp", newMap("issuer", c.FormStrip("totp_issuer"), "period", period, "skew", skew))
	resp := ConfigClient(newMap("action", "settings_update", "config", cfg), 5*time.Second)
	if !truthy(resp.Value("ok")) {
		return false, "Failed to save settings via authelia-configd: " + pyStr(resp.Value("error"))
	}
	return true, "Authelia settings saved successfully."
}

func statusFor(res *Map, keys ...any) int {
	if truthy(res.Value("ok")) {
		return 200
	}
	for i := 0; i+1 < len(keys); i += 2 {
		for _, k := range strings.Split(keys[i].(string), "|") {
			if truthy(res.Value(k)) {
				return keys[i+1].(int)
			}
		}
	}
	return 502
}

func exactKeys(p *Map, keys ...string) bool {
	if p == nil || p.Len() != len(keys) {
		return false
	}
	for _, k := range keys {
		if !has(p, k) {
			return false
		}
	}
	return true
}

func (a *App) registerAutheliaSettings() {
	a.Handle("authelia_settings.get_mail_configuration", func(c *Ctx) error {
		res, err := loadMailSettings()
		if err != nil {
			log.Printf("Failed to load Authelia mail settings: %v", err)
			return c.JSON(502, newMap("ok", false, "error", err.Error()))
		}
		return c.JSON(200, res)
	})
	a.Handle("authelia_settings.update_mail_configuration", func(c *Ctx) error {
		p, _ := asMap(c.SilentJSON())
		if !exactKeys(p, "settings", "apply", "revision") {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "settings, apply, and revision are required"))
		}
		if p.Value("apply") != true {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "apply must be true"))
		}
		res := saveMailSettings(p.Value("settings"), p.Value("revision"))
		summary := ""
		if sm, ok := asMap(p.Value("settings")); ok {
			var keys []string
			for _, k := range sm.Keys() {
				keys = append(keys, pyStr(k))
			}
			sort.Strings(keys)
			summary = "fields: " + strings.Join(keys, ", ")
		}
		ok := truthy(res.Value("ok"))
		c.RecordRequest("authelia_mail.update", AuditEntry{ObjectType: "authelia", ObjectID: "mail", Result: recordResult(ok), Summary: summary, Detail: detailIfFailed(ok, strOrEmpty(res.Value("error")))})
		return c.JSON(statusFor(res, "conflict|relay_unavailable", 409, "validation_error", 400), res)
	})
	a.Handle("authelia_settings.send_mail_test_message", func(c *Ctx) error {
		p, _ := asMap(c.SilentJSON())
		if !exactKeys(p, "revision", "recipient") {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "revision and recipient are required"))
		}
		res := testMailSettings(p.Value("revision"), p.Value("recipient"))
		ok := truthy(res.Value("ok"))
		c.RecordRequest("authelia_mail.test", AuditEntry{ObjectType: "authelia", ObjectID: "mail", Result: recordResult(ok), Detail: detailIfFailed(ok, strOrEmpty(res.Value("error")))})
		return c.JSON(statusFor(res, "rate_limited", 429, "conflict|unsupported", 409, "validation_error", 400), res)
	})
	a.Handle("authelia_settings.get_latest_local_notification", func(c *Ctx) error {
		res := allowlistNotification(ConfigClient(newMap("action", "notification_latest"), 5*time.Second), latestFields)
		return c.JSON(statusFor(res, "conflict", 409, "validation_error", 400), res)
	})
	a.Handle("authelia_settings.reveal_current_local_notification", func(c *Ctx) error {
		p, _ := asMap(c.SilentJSON())
		if !exactKeys(p, "id", "revision") {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "id and revision are required"))
		}
		res, _ := notificationCall("notification_reveal", p.Value("id"), p.Value("revision"), c.User(), nil)
		return c.JSON(statusFor(res, "rate_limited", 429, "conflict", 409, "validation_error", 400), res)
	})
	a.Handle("authelia_settings.update_current_local_notification_status", func(c *Ctx) error {
		p, _ := asMap(c.SilentJSON())
		if !exactKeys(p, "id", "revision") {
			return c.JSON(400, newMap("ok", false, "validation_error", true, "error", "id and revision are required"))
		}
		res, called := notificationCall("notification_handle", p.Value("id"), p.Value("revision"), c.User(), newMap("handled", true))
		if called {
			res = allowlistNotification(res, handleFields)
		}
		return c.JSON(statusFor(res, "conflict", 409, "validation_error", 400), res)
	})
	a.Handle("authelia_settings.edit_settings", func(c *Ctx) error {
		if c.R.Method == http.MethodPost {
			submit, has := c.Form("submit_action")
			if !has {
				submit = "save"
			}
			ok, msg := saveSettingsFromForm(c)
			cat := "danger"
			if ok {
				cat = "success"
			}
			c.RecordRequest("authelia_settings.update", AuditEntry{ObjectType: "authelia", ObjectID: "configuration", Result: recordResult(ok), Summary: "action: " + submit, Detail: detailIfFailed(ok, msg)})
			if ok && submit == "apply" {
				base := msg
				if base == "" {
					base = "Settings saved."
				}
				resp := ConfigdRequest(newMap("action", "restart"))
				switch {
				case !truthy(resp.Value("ok")):
					msg = base + " But Authelia did not restart: " + pyStr(orValue(resp.Value("error"), "unknown error"))
					cat = "warning"
				case !waitForAutheliaHealthy(30 * time.Second):
					msg = base + " Authelia was restarted, but did not become ready before the health-check timed out. If the page does not open, refresh it in a few seconds."
					cat = "warning"
				default:
					msg = base + " Authelia restarted successfully."
					cat = "success"
				}
			}
			if msg == "" {
				msg = "Authelia settings update failed."
			}
			c.Flash(msg, cat)
			return c.Redirect(c.URLFor("authelia_settings.edit_settings"), 303)
		}
		var loadErr any
		form, err := loadSettingsFormData()
		if err != nil {
			log.Printf("Failed to load Authelia settings from configd: %v", err)
			loadErr = "Failed to read Authelia configuration: " + err.Error()
			form = pyyaml.NewMap()
			for _, k := range []string{"server", "log", "session", "identity_validation", "totp", "webauthn", "authentication_backend", "access_control", "storage", "regulation", "notifier"} {
				form.Set(k, pyyaml.NewMap())
			}
		}
		vars := map[string]any{"msg": nil, "msg_category": "info", "settings_load_error": loadErr, "form": form}
		form.Each(func(k, v any) { vars[pyStr(k)] = v })
		return c.Render("authelia_settings.html", vars)
	})
}
