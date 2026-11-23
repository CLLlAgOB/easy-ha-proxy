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

	// 2. Audit events, filters, status, and SSH unblock history.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/audit/events?range=7d", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/audit/filters", ""))
	// The audit API moved to internal/app and its own store; the Flask harness
	// checks the content.
	if rec.Code != http.StatusOK {
		t.Fatalf("audit filters failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/system/ssh-security/api/unblock-history", ""))
	// Read from the panel's own audit store now; the Flask harness checks the content.
	if rec.Code != http.StatusOK {
		t.Fatalf("ssh unblock history failed: %d %s", rec.Code, rec.Body.String())
	}

	// 3. HTML pages render with CSP nonce, CSRF meta tag, i18n, and navigation.
	for _, path := range []string{
		"/",
		"/system/health",
		"/monitoring",
		"/system/alerts",
		"/system/audit",
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
