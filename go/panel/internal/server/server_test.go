package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
	"easy-ha-proxy/panel/internal/server"
)

// The endpoints themselves are checked against Flask by the differential
// harness; this covers what the server adds around them.
func TestServerChain(t *testing.T) {
	trDir := filepath.Join(t.TempDir(), "translations")
	if err := os.MkdirAll(trDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(trDir, "en.json"), []byte(`{"meta":{"code":"en","label":"English"},"messages":{}}`), 0o600)
	_ = os.WriteFile(filepath.Join(trDir, "ru.json"), []byte(`{"meta":{"code":"ru","label":"Русский"},"messages":{"<b>x</b>":"<b>х</b>"}}`), 0o600)
	cat, err := i18n.LoadDir(trDir, "en")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	cfg := &config.Config{ProxySecret: "proxy-secret-xyz", SecretKey: "panel-hmac-secret", DefaultLanguage: "en",
		TranslationsDir: trDir, MaxBodyBytes: 1024, SessionSecure: true}
	h := server.New(cfg, cat).Handler()

	probe := func(secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, security.ControlPlaneHealthPath, nil)
		if secret != "" {
			req.Header.Set(security.ProxySecretHeader, secret)
		}
		req.Header.Set("Remote-User", security.ControlPlaneHealthUser)
		req.Header.Set("Remote-Groups", security.ControlPlaneHealthGroup)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// The control-plane probe is answered by the app behind the boundary.
	if rec := probe(cfg.ProxySecret); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok": true`) {
		t.Fatalf("control-plane-health: %d %s", rec.Code, rec.Body.String())
	}
	// Without the proxy secret the boundary refuses before the app.
	if rec := probe(""); rec.Code != http.StatusForbidden {
		t.Fatalf("missing proxy secret: expected 403, got %d", rec.Code)
	}

	// The catalogue script keeps <, > and & as json.dumps does.
	req := httptest.NewRequest(http.MethodGet, "/i18n/messages.js?lang=ru", nil)
	req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
	req.Header.Set("Remote-User", "admin")
	req.Header.Set("Remote-Groups", "superadmin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"<b>x</b>":"<b>х</b>"`) {
		t.Fatalf("messages.js: %d %s", rec.Code, rec.Body.String())
	}

	// A route Flask does not have is a 404, not an older handler.
	req = httptest.NewRequest(http.MethodGet, "/api/panel-info", nil)
	req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
	req.Header.Set("Remote-User", "admin")
	req.Header.Set("Remote-Groups", "superadmin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route: expected 404, got %d", rec.Code)
	}
}

func TestSecretKeyIsCreatedOnceAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret_key")
	k1, err := config.LoadOrCreateSecretKey("", path)
	if err != nil || len(k1) != 64 {
		t.Fatalf("first call: err=%v len=%d", err, len(k1))
	}
	k2, err := config.LoadOrCreateSecretKey("", path)
	if err != nil || k1 != k2 {
		t.Fatalf("second call: %v", err)
	}
}
