package security

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBoundaryProxySecretAndRBAC(t *testing.T) {
	b := NewBoundary("top-secret", "session-signing-key", true, nil)
	okHandler := b.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":            true,
			"user":          id.User,
			"superadmin":    id.IsSuperadmin,
			"access_portal": id.AccessPortal,
		})
	}))

	// Missing proxy secret fails closed with 403 JSON on /api/.
	req := httptest.NewRequest(http.MethodGet, "/api/health/status", nil)
	rec := httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without secret, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON error for /api/, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers on 403 response")
	}

	// Dedicated healthcheck identity allowed ONLY on control-plane-health.
	req = httptest.NewRequest(http.MethodGet, ControlPlaneHealthPath, nil)
	req.Header.Set(ProxySecretHeader, "top-secret")
	req.Header.Set("Remote-User", ControlPlaneHealthUser)
	req.Header.Set("Remote-Groups", ControlPlaneHealthGroup)
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for control-plane-health, got %d", rec.Code)
	}

	// Forged healthcheck identity rejected everywhere else.
	req = httptest.NewRequest(http.MethodGet, "/api/health/status", nil)
	req.Header.Set(ProxySecretHeader, "top-secret")
	req.Header.Set("Remote-User", ControlPlaneHealthUser)
	req.Header.Set("Remote-Groups", "healthcheck,superadmin")
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for forged healthcheck user on /api/health/status, got %d", rec.Code)
	}

	// Dedicated metrics scrape identity allowed ONLY on GET /metrics.
	req = httptest.NewRequest(http.MethodGet, MetricsScrapePath, nil)
	req.Header.Set(ProxySecretHeader, "top-secret")
	req.Header.Set("Remote-User", MetricsScrapeUser)
	req.Header.Set("Remote-Groups", MetricsScrapeGroup)
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for metrics scrape identity on /metrics, got %d", rec.Code)
	}

	// Regular admin blocked from superadmin prefix /api/haproxy/ and exact /api/health/control.
	for _, path := range []string{"/api/haproxy/backends", "/api/health/control", "/system/backups/api/list"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(ProxySecretHeader, "top-secret")
		req.Header.Set("Remote-User", "alice")
		req.Header.Set("Remote-Groups", "group:admins")
		rec = httptest.NewRecorder()
		okHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for non-superadmin on %s, got %d", path, rec.Code)
		}
	}

	// Superadmin allowed on /api/haproxy/backends and receives signed session cookie.
	req = httptest.NewRequest(http.MethodGet, "/api/haproxy/backends", nil)
	req.Header.Set(ProxySecretHeader, "top-secret")
	req.Header.Set("Remote-User", "rootadmin")
	req.Header.Set("Remote-Groups", "group:superadmin;admins")
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for superadmin, got %d", rec.Code)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatalf("expected session cookie to be issued")
	}

	// Access portal requires GET/HEAD + Remote-User + X-Easy-HA-Proxy-Portal-Host.
	req = httptest.NewRequest(http.MethodGet, "/access-portal/index", nil)
	req.Header.Set(ProxySecretHeader, "top-secret")
	req.Header.Set("Remote-User", "guest1")
	req.Header.Set("Remote-Groups", "portal_users")
	req.Header.Set(PortalHostHeader, "portal.example.com")
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for access portal user, got %d", rec.Code)
	}
}

func TestBoundaryCSRFAndRedirectNormalization(t *testing.T) {
	b := NewBoundary("proxy-sec", "signing-secret", true, nil)
	h := b.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://admin.example.com/system/updates/?a=1", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	// POST without CSRF token fails with 400.
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/quieten", strings.NewReader(`{}`))
	req.Header.Set(ProxySecretHeader, "proxy-sec")
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Groups", "admins")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing CSRF, got %d", rec.Code)
	}

	// POST with valid signed session cookie + matching X-CSRFToken succeeds.
	sid := "test-session-123"
	req = httptest.NewRequest(http.MethodPost, "/api/alerts/quieten", strings.NewReader(`{}`))
	req.Header.Set(ProxySecretHeader, "proxy-sec")
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Groups", "admins")
	req.AddCookie(b.MakeSessionCookie(sid))
	req.Header.Set(CSRFHeaderPrimary, b.CSRFTokenForSession(sid))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid CSRF, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Same-origin http:// redirect is normalized to relative path.
	req = httptest.NewRequest(http.MethodGet, "http://admin.example.com/redirect", nil)
	req.Header.Set(ProxySecretHeader, "proxy-sec")
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Groups", "admins")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/system/updates/?a=1" {
		t.Fatalf("expected relative Location, got %q", loc)
	}
}

func TestGzipJSONMiddleware(t *testing.T) {
	big := `{"ok":true,"data":"` + strings.Repeat("a", 2048) + `"}`
	h := GzipJSONMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(big[:100]))
		_, _ = w.Write([]byte(big[100:]))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip Content-Encoding")
	}
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	decoded, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if string(decoded) != big {
		t.Fatalf("decoded payload mismatch")
	}
}

func TestGzipLeavesDownloadsStreaming(t *testing.T) {
	for _, contentType := range []string{"application/octet-stream", "application/json"} {
		t.Run(contentType, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h := GzipJSONMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentType)
				w.Header().Set("Content-Disposition", "attachment")
				_, _ = io.WriteString(w, "first chunk")
				if rec.Body.String() != "first chunk" {
					t.Fatal("download was buffered")
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Fatal(err)
				}
				_, _ = io.WriteString(w, " and the rest")
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			h.ServeHTTP(rec, req)
			if !rec.Flushed || rec.Body.String() != "first chunk and the rest" || rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("unexpected download response: %s, headers %v", rec.Body, rec.Header())
			}
		})
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"br, gzip;q=0.5": true,
		"gzip;q=0, *":    false,
		"not-gzip":       false,
		"br":             false,
		"*;q=0.5":        true,
	} {
		if got := acceptsGzip([]string{header}); got != want {
			t.Errorf("%q: got %t, want %t", header, got, want)
		}
	}
}

func TestFormCSRFUsesBodyAndReportsSize(t *testing.T) {
	b := NewBoundary("proxy", "session", false, nil)
	h := b.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	token := b.CSRFTokenForSession("test")
	for _, tc := range []struct {
		query, body string
		limit       int64
		want        int
	}{
		{"?csrf_token=" + token, "", 256, 400},
		{"", "csrf_token=" + token, 256, 204},
		{"", "csrf_token=" + token, 4, 413},
	} {
		r := httptest.NewRequest("POST", "/form"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(ProxySecretHeader, "proxy")
		r.Header.Set("Remote-User", "admin")
		r.Header.Set("Remote-Groups", "superadmin")
		r.AddCookie(b.MakeSessionCookie("test"))
		w := httptest.NewRecorder()
		r.Body = http.MaxBytesReader(w, r.Body, tc.limit)
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("got HTTP %d, want %d", w.Code, tc.want)
		}
	}
}

func TestRequestCopyRemovesMultipartFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(part, strings.NewReader(strings.Repeat("a", (2<<20)+1))); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	b := NewBoundary("proxy", "session", false, nil)
	h := b.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			t.Fatal(err)
		}
		if files, err := os.ReadDir(dir); err != nil || len(files) != 1 {
			t.Fatalf("expected a spooled file: %v, %v", files, err)
		}
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest("POST", "/form", &body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r.Header.Set(ProxySecretHeader, "proxy")
	r.Header.Set("Remote-User", "admin")
	r.Header.Set("Remote-Groups", "superadmin")
	r.AddCookie(b.MakeSessionCookie("test"))
	r.Header.Set(CSRFHeaderPrimary, b.CSRFTokenForSession("test"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if files, err := os.ReadDir(dir); err != nil || len(files) != 0 || w.Code != 204 {
		t.Fatalf("after request: %v, %v, HTTP %d", files, err, w.Code)
	}
}
