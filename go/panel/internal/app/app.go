package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/jinja"
	"easy-ha-proxy/panel/internal/pyyaml"
	"easy-ha-proxy/panel/internal/security"
)

// HandlerFunc serves one Flask endpoint.
type HandlerFunc func(c *Ctx) error

// App is the ported Flask application.
type App struct {
	Cfg     *config.Config
	Catalog *i18n.Catalog
	Router  *Router
	Env     *jinja.Environment

	handlers map[string]HandlerFunc
	secret   []byte

	staticMu       sync.Mutex
	staticVersions map[string]string
}

// New builds the application; templatesDir holds the Flask templates.
func New(cfg *config.Config, cat *i18n.Catalog, templatesDir string) *App {
	a := &App{
		Cfg:            cfg,
		Catalog:        cat,
		Router:         NewRouter(flaskRules),
		handlers:       map[string]HandlerFunc{},
		secret:         []byte(cfg.SecretKey),
		staticVersions: map[string]string{},
	}
	a.Env = jinja.NewEnvironment(func(name string) (string, error) {
		clean := filepath.Clean(filepath.FromSlash(name))
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return "", fmt.Errorf("template %s not found", name)
		}
		raw, err := os.ReadFile(filepath.Join(templatesDir, clean))
		if err != nil {
			return "", fmt.Errorf("template %s not found", name)
		}
		return string(raw), nil
	})
	a.Env.JSONDumps = jinja.FlaskJSONDumps
	a.registerAll()
	return a
}

// Handle registers the handler for a Flask endpoint.
func (a *App) Handle(endpoint string, h HandlerFunc) {
	if _, ok := a.Router.byEndpoint[endpoint]; !ok {
		panic("app: no Flask rule for endpoint " + endpoint)
	}
	a.handlers[endpoint] = h
}

// Endpoints lists the Flask endpoints that have a Go handler.
func (a *App) Endpoints() []string {
	out := make([]string, 0, len(a.handlers))
	for e := range a.handlers {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ServeHTTP dispatches to the endpoints; anything else is a 404/405 as in Flask.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m := a.Router.Match(r.Method, r.URL.Path)
	if m.Rule != nil {
		if h, ok := a.handlers[m.Rule.endpoint]; ok {
			c := a.newCtx(w, r, m)
			if m.Redirect != "" {
				// werkzeug's RequestRedirect names the absolute URL in the
				// body; keep_redirects_on_this_origin turns the header back
				// into a path.
				target := m.Redirect
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				c.redirectBody(target, "http://"+r.Host+target, http.StatusPermanentRedirect)
				return
			}
			a.serve(c, h)
			return
		}
	}
	c := a.newCtx(w, r, m)
	if len(m.Allowed) > 0 {
		w.Header().Set("Allow", strings.Join(m.Allowed, ", "))
		if r.Method == http.MethodOptions {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			return
		}
		c.abortPage(http.StatusMethodNotAllowed, "")
		return
	}
	c.abortPage(http.StatusNotFound, "")
}

func (a *App) serve(c *Ctx, h HandlerFunc) {
	defer func() {
		if rec := recover(); rec != nil {
			if ab, ok := rec.(abortSignal); ok {
				c.abortPage(ab.code, ab.description)
				return
			}
			log.Printf("Exception on %s [%s]: %v", c.R.URL.Path, c.R.Method, rec)
			if !c.written {
				c.abortPage(http.StatusInternalServerError, "")
			}
		}
	}()
	if err := h(c); err != nil {
		if ab, ok := err.(abortSignal); ok {
			c.abortPage(ab.code, ab.description)
			return
		}
		log.Printf("Exception on %s [%s]: %v", c.R.URL.Path, c.R.Method, err)
		if !c.written {
			c.abortPage(http.StatusInternalServerError, "")
		}
	}
}

// Ctx is one request: Flask's request, g and response helpers.
type Ctx struct {
	App      *App
	W        http.ResponseWriter
	R        *http.Request
	Endpoint string
	Args     map[string]string
	ID       *security.Identity
	Lang     string

	flashLoaded  bool
	session      map[string]any
	flashes      []flashMessage
	flashDirty   bool
	flashUsed    []flashMessage
	flashUsedSet bool
	written      bool
}

type flashMessage struct {
	Category string
	Message  string
}

func (a *App) newCtx(w http.ResponseWriter, r *http.Request, m MatchResult) *Ctx {
	c := &Ctx{App: a, W: w, R: r, Args: m.Args, ID: security.FromContext(r.Context())}
	if m.Rule != nil {
		c.Endpoint = m.Rule.endpoint
	}
	if c.ID == nil {
		c.ID = &security.Identity{Groups: map[string]struct{}{}}
	}
	if a.Catalog != nil {
		c.Lang = a.Catalog.SelectLanguage(r)
	} else {
		c.Lang = "en"
	}
	return c
}

// Superadmin is g.is_superadmin.
func (c *Ctx) Superadmin() bool { return c.ID.IsSuperadmin }

// User is g.remote_user.
func (c *Ctx) User() string { return c.ID.User }

// T is translate(message) in the request language.
func (c *Ctx) T(msg string) string {
	if c.App.Catalog == nil {
		return msg
	}
	return c.App.Catalog.Translate(c.Lang, msg)
}

// abortSignal is werkzeug's abort(code, description).
type abortSignal struct {
	code        int
	description string
}

func (a abortSignal) Error() string { return fmt.Sprintf("%d %s", a.code, a.description) }

// Abort stops the handler with an HTTP error, like flask.abort.
func Abort(code int, description string) error {
	return abortSignal{code: code, description: description}
}

// ---- the session (Flask's signed cookie session: flashes and form nonces) ----

const sessionCookie = "easy_ha_proxy_flask_session"

func (c *Ctx) sign(payload string) string {
	user := ""
	if c.ID != nil {
		user = c.ID.User
	}
	mac := hmac.New(sha256.New, c.App.secret)
	mac.Write([]byte("session|" + user + "\x00" + payload))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (c *Ctx) loadSession() {
	if c.flashLoaded {
		return
	}
	c.flashLoaded = true
	c.session = map[string]any{}
	ck, err := c.R.Cookie(sessionCookie)
	if err != nil {
		return
	}
	payload, sig, ok := strings.Cut(ck.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(c.sign(payload))) {
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil {
		return
	}
	c.session = data
	if items, ok := data["_flashes"].([]any); ok {
		for _, it := range items {
			pair, ok := it.([]any)
			if ok && len(pair) == 2 {
				cat, _ := pair[0].(string)
				msg, _ := pair[1].(string)
				c.flashes = append(c.flashes, flashMessage{Category: cat, Message: msg})
			}
		}
	}
}

// SessionGet is session.get(key) (string values).
func (c *Ctx) SessionGet(key string) string {
	c.loadSession()
	s, _ := c.session[key].(string)
	return s
}

// SessionSetDefault is session.setdefault(key, value).
func (c *Ctx) SessionSetDefault(key, value string) string {
	c.loadSession()
	if s, ok := c.session[key].(string); ok {
		return s
	}
	c.session[key] = value
	c.flashDirty = true
	return value
}

// Flash is flask.flash(message, category).
func (c *Ctx) Flash(message, category string) {
	c.loadSession()
	if category == "" {
		category = "message"
	}
	c.flashes = append(c.flashes, flashMessage{Category: category, Message: message})
	c.flashDirty = true
}

// popFlashes is get_flashed_messages: the first call in a request takes them
// out of the session; later calls see the same list.
func (c *Ctx) popFlashes() []flashMessage {
	if c.flashUsedSet {
		return c.flashUsed
	}
	c.loadSession()
	c.flashUsed = c.flashes
	c.flashUsedSet = true
	if len(c.flashes) > 0 {
		c.flashes = nil
		c.flashDirty = true
	}
	return c.flashUsed
}

func (c *Ctx) commitCookies() {
	if !c.flashDirty {
		return
	}
	data := map[string]any{}
	for k, v := range c.session {
		if k != "_flashes" {
			data[k] = v
		}
	}
	if len(c.flashes) > 0 {
		items := make([][2]string, len(c.flashes))
		for i, f := range c.flashes {
			items[i] = [2]string{f.Category, f.Message}
		}
		data["_flashes"] = items
	}
	cookie := &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, Secure: c.App.Cfg.SessionSecure, SameSite: http.SameSiteStrictMode}
	if len(data) == 0 {
		cookie.MaxAge = -1
	} else {
		raw, _ := json.Marshal(data)
		payload := base64.RawURLEncoding.EncodeToString(raw)
		cookie.Value = payload + "." + c.sign(payload)
	}
	http.SetCookie(c.W, cookie)
	c.flashDirty = false
}

// ---- responses ----

func (c *Ctx) writeHead(status int, contentType string) {
	c.commitCookies()
	if contentType != "" {
		c.W.Header().Set("Content-Type", contentType)
	}
	c.W.WriteHeader(status)
	c.written = true
}

// HTML writes an HTML body.
func (c *Ctx) HTML(status int, body string) error {
	c.writeHead(status, "text/html; charset=utf-8")
	_, err := c.W.Write([]byte(body))
	return err
}

// Text writes a plain body with the given content type.
func (c *Ctx) Text(status int, contentType, body string) error {
	c.writeHead(status, contentType)
	_, err := c.W.Write([]byte(body))
	return err
}

// JSON is flask.jsonify followed by the localize_json_response hook, which
// translates message fields and re-dumps with app.json.dumps: sorted keys,
// ASCII, default separators, no trailing newline.
func (c *Ctx) JSON(status int, payload any) error {
	sorted := jinja.SortKeysDeep(payload)
	if c.App.Catalog != nil {
		sorted = c.localize(sorted, "")
	}
	text, err := pyyaml.JSONDumps(sorted, true, false)
	if err != nil {
		return err
	}
	c.writeHead(status, "application/json")
	_, err = c.W.Write([]byte(text))
	return err
}

func (c *Ctx) localize(v any, key string) any {
	switch x := v.(type) {
	case *pyyaml.Map:
		out := pyyaml.NewMap()
		x.Each(func(k, item any) {
			ks, _ := k.(string)
			out.Set(k, c.localize(item, ks))
		})
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = c.localize(item, key)
		}
		return out
	case string:
		switch key {
		case "error", "message", "warning", "detail":
			return c.T(x)
		}
	}
	return v
}

// Redirect is flask.redirect(location, code).
func (c *Ctx) Redirect(location string, code int) error {
	c.redirect(location, code)
	return nil
}

func (c *Ctx) redirect(location string, code int) { c.redirectBody(location, location, code) }

func (c *Ctx) redirectBody(location, shown string, code int) {
	if code == 0 {
		code = http.StatusFound
	}
	esc := string(jinja.Escape(shown))
	body := "<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n<h1>Redirecting...</h1>\n" +
		"<p>You should be redirected automatically to the target URL: <a href=\"" + esc + "\">" + esc + "</a>. If not, click the link.\n"
	c.W.Header().Set("Location", location)
	c.writeHead(code, "text/html; charset=utf-8")
	_, _ = c.W.Write([]byte(body))
}

var statusDescriptions = map[int]string{
	400: "The browser (or proxy) sent a request that this server could not understand.",
	403: "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server.",
	404: "The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.",
	405: "The method is not allowed for the requested URL.",
	409: "A conflict happened while processing the request. The resource might have been modified while the request was being processed.",
	413: "The data value transmitted exceeds the capacity limit.",
	415: "The server does not support the media type transmitted in the request.",
	500: "The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.",
	502: "The proxy server received an invalid response from an upstream server.",
	503: "The server is temporarily unable to service your request due to maintenance downtime or capacity problems. Please try again later.",
}

// abortPage answers like Flask's HTTPException handling: JSON for callers
// that parse JSON (handle_api_error), werkzeug's HTML page otherwise.
func (c *Ctx) abortPage(code int, description string) {
	if c.written {
		return
	}
	name := http.StatusText(code)
	if code == http.StatusRequestEntityTooLarge {
		name = "Request Entity Too Large"
	}
	if security.CallerParsesJSON(c.R) {
		// error_reason(exc.description, exc.name): a bare abort(404) or an
		// unhandled error still carries werkzeug's default description.
		reason := strings.Join(strings.Fields(description), " ")
		if reason == "" {
			reason = strings.Join(strings.Fields(statusDescriptions[code]), " ")
		}
		if reason == "" {
			reason = name
		}
		_ = c.JSON(code, map[string]any{"ok": false, "error": c.T(reason)})
		return
	}
	if description == "" {
		description = statusDescriptions[code]
	}
	body := fmt.Sprintf("<!doctype html>\n<html lang=en>\n<title>%d %s</title>\n<h1>%s</h1>\n<p>%s</p>\n",
		code, name, name, string(jinja.Escape(description)))
	_ = c.HTML(code, body)
}

// EnsureWhitelistFile is utils.ensure_whitelist_file, run at start-up.
func EnsureWhitelistFile() {
	dir := filepath.Dir(WhitelistFile)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		log.Printf("ensure_whitelist_file: cannot create dir %q: %v", dir, err)
		return
	}
	if _, err := os.Stat(WhitelistFile); err == nil {
		return
	}
	if err := os.WriteFile(WhitelistFile, []byte("# HAProxy whitelist\n"), 0o644); err != nil {
		log.Printf("ensure_whitelist_file: cannot create file %q: %v", WhitelistFile, err)
		return
	}
	_ = os.Chmod(WhitelistFile, 0o644)
	log.Printf("Created whitelist file %s", WhitelistFile)
}
