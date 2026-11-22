package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/audit"
	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/haproxy"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
	"easy-ha-proxy/panel/internal/server"
)

func TestStageD3AuditConfigStoreAndHTMLPages(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "config")
	bakDir := filepath.Join(tmp, "backups")
	liveCfg := filepath.Join(tmp, "haproxy.cfg")
	auditDB := filepath.Join(tmp, "audit.db")
	_ = os.MkdirAll(cfgDir, 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "vars.yml"), []byte("enable_geoip: true\n"), 0o644)
	_ = os.WriteFile(liveCfg, []byte("global\n  maxconn 4096\n"), 0o644)

	controldSock := startFakeHAProxyAdmin(t, func(cmd string) string {
		switch {
		case cmd == "config-transaction-status":
			return controldOK(`{"ok":true,"pending":false}`)
		case strings.HasPrefix(cmd, "check-config"):
			return "OK configuration is valid\n"
		case strings.HasPrefix(cmd, "begin-config-transaction"):
			return controldOK(`{"ok":true,"state":"pending_confirmation","token":"tx-99"}`)
		default:
			return controldOK(`{"ok":true}`)
		}
	})

	cfg := &config.Config{
		ProxySecret:     "d3-secret",
		SecretKey:       "d3-hmac",
		DefaultLanguage: "en",
		AuditDatabase:   auditDB,
		ConfigDir:       cfgDir,
		ConfigBackupDir: bakDir,
		HAProxyCfg:      liveCfg,
		ControldSocket:  controldSock,
		MaxBodyBytes:    config.DefaultMaxBodyBytes,
		SessionSecure:   true,
	}

	cat, _ := i18n.LoadDir("", "en")
	srv := server.New(cfg, daemons.NewPool(cfg), haproxy.NewRuntime("", liveCfg, nil, nil), cat)
	h := srv.Handler()

	// Seed an SSH unban event to verify /system/ssh-security/api/unblock-history.
	srv.Audit.Record("rootadmin", "10.0.0.5", "ssh.unban", "ip", "203.0.113.9", audit.ResultSuccess, "unbanned 203.0.113.9", "", nil, nil)

	sid := "s-d3"
	superReq := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
		req.Header.Set("Remote-User", "rootadmin")
		req.Header.Set("Remote-Groups", "superadmin")
		req.AddCookie(srv.Boundary.MakeSessionCookie(sid))
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(security.CSRFHeaderPrimary, srv.Boundary.CSRFTokenForSession(sid))
		}
		return req
	}

	// 1. Config store state, preview, download, save (audited), check, and apply (audited).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/haproxy/config/state", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"clean"`) {
		t.Fatalf("config state failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/haproxy/config/download/vars", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_geoip: true") {
		t.Fatalf("config download vars failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/api/haproxy/config/files/vars", `{"content":"enable_geoip: false\n"}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sha256"`) {
		t.Fatalf("config save vars failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/haproxy/config/check", `{"config":"global\n"}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("config check failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/haproxy/config/apply", `{"reason":"test"}`))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"pending_confirmation"`) {
		t.Fatalf("config apply failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Audit events, filters, status, and SSH unblock history.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/audit/events?range=7d", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"config.apply"`) {
		t.Fatalf("audit events failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/audit/filters", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"rootadmin"`) {
		t.Fatalf("audit filters failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/system/ssh-security/api/unblock-history", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "203.0.113.9") {
		t.Fatalf("ssh unblock history failed: %d %s", rec.Code, rec.Body.String())
	}

	// 3. HTML pages render with CSP nonce, CSRF meta tag, i18n, and navigation.
	for _, path := range []string{
		"/",
		"/system/health",
		"/monitoring",
		"/system/alerts",
		"/system/audit",
		"/haproxy/config",
		"/haproxy/backends",
		"/system/backups/",
		"/system/updates/",
	} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, superReq(http.MethodGet, path, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("HTML page %s returned %d", path, rec.Code)
		}
		html := rec.Body.String()
		if !strings.Contains(html, `<meta name="csrf-token"`) || !strings.Contains(html, "window.HAPROXY_ADMIN_I18N") {
			t.Fatalf("HTML page %s missing CSRF/i18n bootstrap", path)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "nonce-") {
			t.Fatalf("HTML page %s missing CSP nonce header: %q", path, csp)
		}
	}
}
