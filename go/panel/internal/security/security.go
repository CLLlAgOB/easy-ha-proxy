// Package security enforces the trusted-proxy authentication boundary, RBAC,
// session-bound CSRF protection, security headers, same-origin redirects, and
// response compression with full parity to docker/app/haproxy_admin/security.py.
package security

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"easy-ha-proxy/panel/internal/pyyaml"
)

const (
	ProxySecretHeader       = "X-Easy-HA-Proxy-Secret"
	PortalHostHeader        = "X-Easy-HA-Proxy-Portal-Host"
	StaticCacheSeconds      = 31536000
	ControlPlaneHealthPath  = "/api/control-plane-health"
	AccessPortalHealthPath  = "/api/access-portal-health"
	ControlPlaneHealthUser  = "easy-ha-proxy-healthcheck"
	ControlPlaneHealthGroup = "healthcheck"
	MetricsScrapePath       = "/metrics"
	MetricsScrapeUser       = "easy-ha-proxy-metrics"
	MetricsScrapeGroup      = "metrics"
	SessionCookieName       = "easy_ha_proxy_session"
	CSRFHeaderPrimary       = "X-CSRFToken"
	CSRFHeaderAlternate     = "X-CSRF-Token"
	CSRFFormField           = "csrf_token"
	CompressMinBytes        = 512
)

var superadminPrefixes = []string{
	"/haproxy",
	"/api/haproxy/",
	"/authelia",
	"/system/backups",
	"/system/updates",
	"/system/os-security",
	"/system/ssh-security",
	"/system/schedule",
}

var superadminExact = map[string]struct{}{
	"/api/health/control": {},
}

var jsonAPIPrefixes = []string{
	"/api/",
	"/system/backups/api/",
	"/system/updates/api/",
	"/system/os-security/api/",
	"/system/ssh-security/api/",
}

// Identity holds the verified caller context extracted from HAProxy headers.
type Identity struct {
	User         string
	Groups       map[string]struct{}
	IsSuperadmin bool
	AccessPortal bool
	CSPNonce     string
	SessionID    string
	CSRFToken    string
}

type ctxKey struct{}

// FromContext returns the verified Identity for a request, if present.
func FromContext(ctx context.Context) *Identity {
	if id, ok := ctx.Value(ctxKey{}).(*Identity); ok {
		return id
	}
	return nil
}

// WithIdentity attaches an Identity to a context (useful in tests).
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// NormalizedGroups parses Remote-Groups header values separated by "," or ";"
// and strips optional "group:" prefixes.
func NormalizedGroups(value string) map[string]struct{} {
	groups := make(map[string]struct{})
	replaced := strings.ReplaceAll(value, ";", ",")
	for _, raw := range strings.Split(replaced, ",") {
		g := strings.TrimSpace(raw)
		if g == "" {
			continue
		}
		if strings.HasPrefix(g, "group:") {
			g = strings.TrimPrefix(g, "group:")
		}
		if g != "" {
			groups[g] = struct{}{}
		}
	}
	return groups
}

func hasGroup(groups map[string]struct{}, name string) bool {
	_, ok := groups[name]
	return ok
}

func isExactSingleGroup(groups map[string]struct{}, name string) bool {
	if len(groups) != 1 {
		return false
	}
	_, ok := groups[name]
	return ok
}

// CallerParsesJSON reports whether an error response for r should be JSON.
func CallerParsesJSON(r *http.Request) bool {
	for _, prefix := range jsonAPIPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(ct, "application/json")
}

// TranslateFunc optionally localizes error strings returned by middleware.
type TranslateFunc func(r *http.Request, msg string) string

// Boundary configures the HTTP security middleware chain.
type Boundary struct {
	ProxySecret   string
	SecretKey     string
	SessionSecure bool
	Translate     TranslateFunc
}

// NewBoundary constructs a Boundary middleware.
func NewBoundary(proxySecret, secretKey string, sessionSecure bool, translate TranslateFunc) *Boundary {
	return &Boundary{
		ProxySecret:   strings.TrimSpace(proxySecret),
		SecretKey:     secretKey,
		SessionSecure: sessionSecure,
		Translate:     translate,
	}
}

func (b *Boundary) tr(r *http.Request, msg string) string {
	if b.Translate != nil {
		return b.Translate(r, msg)
	}
	return msg
}

func (b *Boundary) writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	translated := b.tr(r, msg)
	if CallerParsesJSON(r) {
		// jsonify, re-dumped by localize_json_response: sorted, ASCII.
		m := pyyaml.NewMap()
		m.Set("error", translated)
		m.Set("ok", false)
		text, _ := pyyaml.JSONDumps(m, true, false)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(text))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(WerkzeugErrorPage(status, translated)))
}

// WerkzeugErrorPage is the HTML body werkzeug's abort(status, description) renders.
func WerkzeugErrorPage(status int, description string) string {
	name := http.StatusText(status)
	if status == http.StatusRequestEntityTooLarge {
		name = "Request Entity Too Large"
	}
	return fmt.Sprintf("<!doctype html>\n<html lang=en>\n<title>%d %s</title>\n<h1>%s</h1>\n<p>%s</p>\n",
		status, name, name, html.EscapeString(description))
}

// Wrap applies CSP nonce generation, security headers, same-origin redirect
// rewriting, proxy+RBAC enforcement, and session-bound CSRF validation.
func (b *Boundary) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := randomNonce()
		id := &Identity{
			Groups:   make(map[string]struct{}),
			CSPNonce: nonce,
		}

		// Wrap ResponseWriter so headers and redirects are normalized before
		// the status line is sent.
		sw := &securityResponseWriter{
			ResponseWriter: w,
			req:            r,
			nonce:          nonce,
		}

		// 1. Validate shared proxy secret in constant time (fail closed).
		supplied := r.Header.Get(ProxySecretHeader)
		if b.ProxySecret == "" || supplied == "" ||
			subtle.ConstantTimeCompare([]byte(b.ProxySecret), []byte(supplied)) != 1 {
			b.writeError(sw, r, http.StatusForbidden, "trusted proxy authentication required")
			return
		}

		username := strings.TrimSpace(r.Header.Get("Remote-User"))
		groups := NormalizedGroups(r.Header.Get("Remote-Groups"))
		id.User = username
		id.Groups = groups

		// 2. Dedicated least-privilege control-plane healthcheck identity.
		if r.Method == http.MethodGet &&
			(r.URL.Path == ControlPlaneHealthPath || r.URL.Path == AccessPortalHealthPath) &&
			username == ControlPlaneHealthUser &&
			isExactSingleGroup(groups, ControlPlaneHealthGroup) {
			next.ServeHTTP(sw, r.WithContext(WithIdentity(r.Context(), id)))
			return
		}

		// 3. Dedicated least-privilege Prometheus scrape identity.
		if r.Method == http.MethodGet &&
			r.URL.Path == MetricsScrapePath &&
			username == MetricsScrapeUser &&
			isExactSingleGroup(groups, MetricsScrapeGroup) {
			next.ServeHTTP(sw, r.WithContext(WithIdentity(r.Context(), id)))
			return
		}

		// 4. Reject forged healthcheck/metrics identities on any other path.
		if username == ControlPlaneHealthUser ||
			hasGroup(groups, ControlPlaneHealthGroup) ||
			username == MetricsScrapeUser ||
			hasGroup(groups, MetricsScrapeGroup) {
			b.writeError(sw, r, http.StatusForbidden, "authenticated administrator required")
			return
		}

		// 5. Isolated access-portal boundary (read-only + HAProxy portal marker).
		if strings.HasPrefix(r.URL.Path, "/access-portal/") {
			if (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
				username == "" ||
				strings.TrimSpace(r.Header.Get(PortalHostHeader)) == "" {
				b.writeError(sw, r, http.StatusForbidden, "authenticated access-page user required")
				return
			}
			id.AccessPortal = true
			next.ServeHTTP(sw, r.WithContext(WithIdentity(r.Context(), id)))
			return
		}

		// 6. Standard admin/superadmin check.
		isAdmin := hasGroup(groups, "admins") || hasGroup(groups, "superadmin")
		if username == "" || !isAdmin {
			b.writeError(sw, r, http.StatusForbidden, "authenticated administrator required")
			return
		}

		needsSuperadmin := false
		if _, ok := superadminExact[r.URL.Path]; ok {
			needsSuperadmin = true
		} else {
			for _, prefix := range superadminPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					needsSuperadmin = true
					break
				}
			}
		}
		if needsSuperadmin && !hasGroup(groups, "superadmin") {
			b.writeError(sw, r, http.StatusForbidden, "superadmin role required")
			return
		}
		id.IsSuperadmin = hasGroup(groups, "superadmin")

		// 7. Session-bound CSRF token management.
		sid, validCookie := b.readSessionCookie(r)
		if !validCookie {
			sid = randomHex(24)
			b.setSessionCookie(sw, sid)
		}
		id.SessionID = sid
		id.CSRFToken = b.CSRFTokenForSession(sid)

		if isMutatingMethod(r.Method) {
			if !validCookie || !b.verifyCSRF(r, id.CSRFToken) {
				b.writeError(sw, r, http.StatusBadRequest, "CSRF validation failed")
				return
			}
		}

		next.ServeHTTP(sw, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// CSRFTokenForSession derives a deterministic HMAC-SHA256 CSRF token bound to
// the session identifier and the panel secret key.
func (b *Boundary) CSRFTokenForSession(sessionID string) string {
	mac := hmac.New(sha256.New, []byte(b.SecretKey))
	mac.Write([]byte("csrf:"))
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (b *Boundary) signSession(sessionID string) string {
	mac := hmac.New(sha256.New, []byte(b.SecretKey))
	mac.Write([]byte("sid:"))
	mac.Write([]byte(sessionID))
	return sessionID + "." + hex.EncodeToString(mac.Sum(nil))
}

func (b *Boundary) readSessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c == nil || c.Value == "" {
		return "", false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	expected := b.signSession(parts[0])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(c.Value)) != 1 {
		return "", false
	}
	return parts[0], true
}

func (b *Boundary) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    b.signSession(sessionID),
		Path:     "/",
		HttpOnly: true,
		Secure:   b.SessionSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

// MakeSessionCookie builds a signed session cookie (for tests and clients).
func (b *Boundary) MakeSessionCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    b.signSession(sessionID),
		Path:     "/",
		HttpOnly: true,
		Secure:   b.SessionSecure,
		SameSite: http.SameSiteStrictMode,
	}
}

func (b *Boundary) verifyCSRF(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	candidates := []string{
		strings.TrimSpace(r.Header.Get(CSRFHeaderPrimary)),
		strings.TrimSpace(r.Header.Get(CSRFHeaderAlternate)),
	}
	for _, tok := range candidates {
		if tok != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(tok)) == 1 {
			return true
		}
	}
	// Check form field for standard HTML form POSTs without disturbing JSON bodies.
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
		tok := strings.TrimSpace(r.FormValue(CSRFFormField))
		if tok != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(tok)) == 1 {
			return true
		}
	}
	return false
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

type securityResponseWriter struct {
	http.ResponseWriter
	req         *http.Request
	nonce       string
	wroteHeader bool
}

func (w *securityResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *securityResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.applyHeaders(code)
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *securityResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *securityResponseWriter) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *securityResponseWriter) Flush() { _ = w.FlushError() }

func (w *securityResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *securityResponseWriter) applyHeaders(status int) {
	h := w.Header()

	// Static files carry a version query param and are cached immutably.
	if strings.HasPrefix(w.req.URL.Path, "/static/") &&
		(status == http.StatusOK || status == http.StatusNotModified) {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	setDefault(h, "Cache-Control", "no-store")
	setDefault(h, "Pragma", "no-cache")
	setDefault(h, "Strict-Transport-Security", "max-age=31536000")
	setDefault(h, "X-Content-Type-Options", "nosniff")
	setDefault(h, "X-Frame-Options", "DENY")
	setDefault(h, "Referrer-Policy", "same-origin")
	setDefault(h, "Permissions-Policy", "camera=(), microphone=(), geolocation=()")

	scriptSrc := "'self'"
	if w.nonce != "" {
		scriptSrc = "'self' 'nonce-" + w.nonce + "'"
	}
	setDefault(
		h,
		"Content-Security-Policy",
		"default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "+
			"form-action 'self'; object-src 'none'; "+
			"script-src "+scriptSrc+"; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'",
	)

	// Keep same-origin redirects relative so TLS termination at HAProxy never
	// leaks http:// URLs into Location headers.
	if status >= 300 && status < 400 {
		if loc := h.Get("Location"); loc != "" {
			if u, err := url.Parse(loc); err == nil {
				if (u.Scheme == "http" || u.Scheme == "https") && u.Host == w.req.Host {
					cleanPath := "/" + strings.TrimLeft(u.Path, "/")
					rel := url.URL{
						Path:     cleanPath,
						RawQuery: u.RawQuery,
						Fragment: u.Fragment,
					}
					h.Set("Location", rel.String())
				}
			}
		}
	}
}

func setDefault(h http.Header, key, val string) {
	if h.Get(key) == "" {
		h.Set(key, val)
	}
}

// GzipJSONMiddleware compresses JSON responses >= CompressMinBytes when the
// client accepts gzip encoding.
func GzipJSONMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &gzipResponseWriter{
			ResponseWriter: w,
			compress:       r.Method != http.MethodHead && acceptsGzip(r.Header.Values("Accept-Encoding")),
		}
		next.ServeHTTP(writer, r)
		if writer.gzip != nil {
			_ = writer.gzip.Close()
		} else if writer.status != 0 && !writer.started {
			_ = writer.start(false)
		}
	})
}

func acceptsGzip(values []string) bool {
	wildcard := false
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			coding, params, _ := strings.Cut(item, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "gzip" && coding != "*" {
				continue
			}
			allowed := true
			for _, param := range strings.Split(params, ";") {
				key, raw, _ := strings.Cut(param, "=")
				if strings.EqualFold(strings.TrimSpace(key), "q") {
					q, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
					allowed = err == nil && q > 0 && q <= 1
				}
			}
			if coding == "gzip" {
				return allowed
			}
			wildcard = allowed
		}
	}
	return wildcard
}

type gzipResponseWriter struct {
	http.ResponseWriter
	prefix   []byte
	gzip     *gzip.Writer
	status   int
	compress bool
	started  bool
}

func (w *gzipResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status < 200 && status != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.status = status
	h := w.Header()
	contentType, _, _ := strings.Cut(h.Get("Content-Type"), ";")
	isJSON := strings.EqualFold(strings.TrimSpace(contentType), "application/json")
	if !isJSON || status < 200 || status == http.StatusNoContent || status == http.StatusResetContent ||
		status == http.StatusPartialContent || status == http.StatusNotModified || h.Get("Content-Encoding") != "" ||
		h.Get("Content-Disposition") != "" || h.Get("Content-Range") != "" {
		w.compress = false
	} else {
		h.Add("Vary", "Accept-Encoding")
	}
	if !w.compress {
		_ = w.start(false)
	}
}

func (w *gzipResponseWriter) start(compress bool) error {
	w.started = true
	if compress {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		w.gzip = gzip.NewWriter(w.ResponseWriter)
	}
	w.ResponseWriter.WriteHeader(w.status)
	if len(w.prefix) == 0 {
		return nil
	}
	prefix := w.prefix
	w.prefix = nil
	_, err := w.Write(prefix)
	return err
}

func (w *gzipResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.started {
		if len(p) < CompressMinBytes-len(w.prefix) {
			w.prefix = append(w.prefix, p...)
			return len(p), nil
		}
		if err := w.start(true); err != nil {
			return 0, err
		}
	}
	if w.gzip != nil {
		return w.gzip.Write(p)
	}
	return w.ResponseWriter.Write(p)
}

func (w *gzipResponseWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.started {
		if err := w.start(false); err != nil {
			return err
		}
	}
	if w.gzip != nil {
		if err := w.gzip.Flush(); err != nil {
			return err
		}
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *gzipResponseWriter) Flush() { _ = w.FlushError() }

func randomNonce() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func randomHex(nBytes int) string {
	buf := make([]byte, nBytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
