package server_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/daemons"
	"easy-ha-proxy/panel/internal/haproxy"
	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
	"easy-ha-proxy/panel/internal/server"
)

func startUnixHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "daemon.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(sock)
	})
	return sock
}

func startFakeHAProxyAdmin(t *testing.T, onCmd func(cmd string) string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "haproxy.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen haproxy unix: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				cmd := strings.TrimSpace(string(buf[:n]))
				_, _ = c.Write([]byte(onCmd(cmd)))
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	return sock
}

func TestServerEndToEndAPIsAndPrometheus(t *testing.T) {
	// Fake healthd over AF_UNIX.
	healthSock := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/health/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "host": "nanopi"})
		case "/api/v1/control/capabilities":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"systemd": map[string]any{
					"haproxy.service": []string{"reload", "restart"},
					"easy-ha-proxy-*": []string{"restart"},
				},
			})
		case "/api/v1/control":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stdout": "reloaded"})
		default:
			http.NotFound(w, r)
		}
	}))

	// Fake metricsd over AF_UNIX.
	metricsSock := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/metrics/storage":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":                    true,
				"state":                 "NORMAL",
				"writes_paused":         false,
				"total_bytes":           1048576,
				"filesystem_free_bytes": 536870912,
			})
		case "/api/v1/metrics/sites":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    true,
				"sites": []map[string]any{{"proxy": "be_app_example_com"}},
			})
		case "/api/v1/metrics/series":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    true,
				"chart": r.URL.Query().Get("chart"),
				"range": r.URL.Query().Get("range"),
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// Fake alertd over AF_UNIX.
	alertSock := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/alerts/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":       true,
				"firing":   1,
				"pending":  2,
				"channels": map[string]bool{"webhook": true, "mail": false},
			})
		case "/api/v1/alerts/portal":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "alerts": []any{}})
		case "/api/v1/alerts/quieten":
			if r.Header.Get("X-Alertd-Token") != "alert-tok" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "bad token"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))

	// Fake guardd over AF_UNIX.
	guardSock := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/guard/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":          true,
				"mode":        "enforce",
				"bans_active": 3,
				"states":      map[string]int{"banned": 3, "clean": 40},
				"database":    map[string]int{"events": 99},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// Fake HAProxy admin socket + config file with display-name comment.
	var lastHAProxyCmd string
	haproxySock := startFakeHAProxyAdmin(t, func(cmd string) string {
		lastHAProxyCmd = cmd
		if cmd == "show stat" {
			return "# pxname,svname,scur,status,weight,check_status,addr\n" +
				"be_app_example_com,srv1,5,UP,100,L7OK,10.0.0.10:8080\n" +
				"authelia_backend,authelia,1,UP,100,L7OK,127.0.0.1:9091\n"
		}
		return ""
	})
	cfgFile := filepath.Join(t.TempDir(), "haproxy.cfg")
	if err := os.WriteFile(cfgFile, []byte("backend be_app_example_com\n  # display-name: App Example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a minimal real translation catalog.
	trDir := filepath.Join(t.TempDir(), "translations")
	if err := os.MkdirAll(trDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(trDir, "en.json"), []byte(`{"meta":{"code":"en","label":"English"},"messages":{"unknown chart":"unknown chart"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(trDir, "ru.json"), []byte(`{"meta":{"code":"ru","label":"Русский"},"messages":{"unknown chart":"неизвестный график"}}`), 0o600)

	cfg := &config.Config{
		ProxySecret:          "proxy-secret-xyz",
		SecretKey:            "panel-hmac-secret",
		DefaultLanguage:      "en",
		TranslationsDir:      trDir,
		HAProxySocket:        haproxySock,
		HAProxyCfg:           cfgFile,
		HealthdSocket:        healthSock,
		HealthdToken:         "health-tok",
		MetricsdSocket:       metricsSock,
		AlertdSocket:         alertSock,
		AlertdToken:          "alert-tok",
		GuarddSocket:         guardSock,
		GuarddToken:          "guard-tok",
		MetricsExportEnabled: true,
		MetricsExportToken:   "prom-bearer-123",
		MaxBodyBytes:         config.DefaultMaxBodyBytes,
		SessionSecure:        true,
	}

	cat, err := i18n.LoadDir(trDir, "en")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	srv := server.New(cfg, daemons.NewPool(cfg), haproxy.NewRuntime(haproxySock, cfgFile, nil, nil), cat)
	h := srv.Handler()

	// Helper to build an authenticated superadmin request.
	sid := "s-admin-1"
	adminReq := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
		req.Header.Set("Remote-User", "admin")
		req.Header.Set("Remote-Groups", "superadmin")
		req.AddCookie(srv.Boundary.MakeSessionCookie(sid))
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(security.CSRFHeaderPrimary, srv.Boundary.CSRFTokenForSession(sid))
		}
		return req
	}

	// 1. Control-plane healthcheck probe.
	req := httptest.NewRequest(http.MethodGet, security.ControlPlaneHealthPath, nil)
	req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
	req.Header.Set("Remote-User", security.ControlPlaneHealthUser)
	req.Header.Set("Remote-Groups", security.ControlPlaneHealthGroup)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok": true`) {
		t.Fatalf("control-plane-health failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Health API moved to internal/app; the Flask harness covers it.

	// 3. HAProxy runtime backends listing (excludes authelia_backend!) + set weight.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminReq(http.MethodGet, "/api/haproxy/backends", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("backends list failed: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "authelia_backend") {
		t.Fatalf("protected backend authelia_backend leaked into operable list")
	}
	if !strings.Contains(rec.Body.String(), "App Example") {
		t.Fatalf("expected display-name 'App Example', got %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminReq(http.MethodPost, "/api/haproxy/backends/weight", `{"backend":"be_app_example_com","server":"srv1","weight":50}`))
	if rec.Code != http.StatusOK || lastHAProxyCmd != "set server be_app_example_com/srv1 weight 50" {
		t.Fatalf("set weight failed: %d cmd=%q body=%s", rec.Code, lastHAProxyCmd, rec.Body.String())
	}

	// 4. Alerts API moved to internal/app; the Flask harness covers it.

	// 5. Monitoring series validates chart and localizes Russian error.
	req = adminReq(http.MethodGet, "/api/monitoring/series?chart=bogus", "")
	req.AddCookie(&http.Cookie{Name: i18n.LanguageCookie, Value: "ru"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Flask answers in ASCII-escaped JSON (json.dumps' default), so the text is decoded.
	var seriesErr struct{ Error string }
	_ = json.Unmarshal(rec.Body.Bytes(), &seriesErr)
	if rec.Code != http.StatusBadRequest || !strings.Contains(seriesErr.Error, "неизвестный график") {
		t.Fatalf("expected localized RU 400 error, got %d %s", rec.Code, rec.Body.String())
	}

	// 6. /i18n/messages.js serves immutable JS with ETag and 304 support.
	req = adminReq(http.MethodGet, "/i18n/messages.js?lang=ru", "")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("messages.js failed: %d cc=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	etag := rec.Header().Get("ETag")
	req = adminReq(http.MethodGet, "/i18n/messages.js?lang=ru", "")
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("expected 304 for matching ETag, got %d", rec.Code)
	}

	// 7. Prometheus /metrics dual-gate (401 without bearer, 200 with bearer).
	promReq := func(bearer string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
		r.Header.Set("Remote-User", security.MetricsScrapeUser)
		r.Header.Set("Remote-Groups", security.MetricsScrapeGroup)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		return r
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, promReq("wrong-token"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong bearer token, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, promReq(cfg.MetricsExportToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid /metrics scrape, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"easy_ha_proxy_build_info 1",
		`easy_ha_proxy_backend_servers_up{backend="be_app_example_com"} 1`,
		`easy_ha_proxy_monitoring_storage_state{state="NORMAL"} 1`,
		"easy_ha_proxy_guard_bans_active 3",
		"easy_ha_proxy_guard_enforcing 1",
		"easy_ha_proxy_alerts_firing 1",
		`easy_ha_proxy_source_up{source="haproxy"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing metric %q in /metrics output:\n%s", want, body)
		}
	}

	// 8. Secret key atomic file creation & reuse test.
	secretPath := filepath.Join(t.TempDir(), "secret_key")
	k1, err := config.LoadOrCreateSecretKey("", secretPath)
	if err != nil || len(k1) != 64 {
		t.Fatalf("LoadOrCreateSecretKey first call: err=%v len=%d", err, len(k1))
	}
	k2, err := config.LoadOrCreateSecretKey("", secretPath)
	if err != nil || k1 != k2 {
		t.Fatalf("LoadOrCreateSecretKey second call mismatch: %v", err)
	}

	// 9. JSON-line client test (backupd/updated/authelia).
	jlSock := filepath.Join(t.TempDir(), "jl.sock")
	ln, err := net.Listen("unix", jlSock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(`{"ok":true,"pong":1}` + "\n"))
	}()
	jl := &daemons.JSONLineClient{Service: "test", SocketPath: jlSock}
	resp, err := jl.Call(context.Background(), map[string]any{"action": "ping"}, 0)
	if err != nil || resp["ok"] != true {
		t.Fatalf("JSONLineClient.Call failed: err=%v resp=%v", err, resp)
	}
}
