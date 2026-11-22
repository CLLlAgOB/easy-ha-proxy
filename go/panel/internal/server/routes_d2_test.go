package server_test

import (
	"bufio"
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

func startJSONLineServer(t *testing.T, onReq func(req map[string]any) map[string]any) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "rpc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req map[string]any
				_ = json.Unmarshal(line, &req)
				resp := onReq(req)
				out, _ := json.Marshal(resp)
				_, _ = c.Write(append(out, '\n'))
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	return sock
}

func TestStageD2DashboardCertsConfigBackupsUpdatesAuthelia(t *testing.T) {
	tmp := t.TempDir()
	geoWL := filepath.Join(tmp, "whitelist_geo.lst")
	globalWL := filepath.Join(tmp, "whitelist_global.lst")
	uploadsDir := filepath.Join(tmp, "uploads")
	downloadsDir := filepath.Join(tmp, "backups")
	_ = os.MkdirAll(uploadsDir, 0o755)
	_ = os.MkdirAll(downloadsDir, 0o755)
	_ = os.WriteFile(geoWL, []byte("203.0.113.10\n"), 0o644)
	_ = os.WriteFile(globalWL, []byte("198.51.100.1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(downloadsDir, "bk001.tar.gz.enc"), []byte("ENCRYPTED-ARCHIVE"), 0o600)

	// Fake HAProxy socket.
	var clearedKey string
	haproxySock := startFakeHAProxyAdmin(t, func(cmd string) string {
		switch {
		case cmd == "show table abuse_ban":
			return "# table: abuse_ban, type: ip, size:1024, used:1\n0x1: key=192.0.2.55 use=0 exp=60000 gpt0=41\n"
		case cmd == "show table":
			return "# table: abuse_ban, type: ip\n# table: ip_auth, type: ip\n"
		case strings.HasPrefix(cmd, "clear table abuse_ban key "):
			clearedKey = strings.TrimPrefix(cmd, "clear table abuse_ban key ")
			return ""
		case cmd == "show stat":
			return "# pxname,svname,scur,smax,rate,status,weight,check_status,addr\nfe_https,FRONTEND,12,20,3,OPEN,,,\nbe_site,BACKEND,4,10,1,UP,,,\nbe_site,s1,4,10,1,UP,100,L7OK,10.0.0.5:80\n"
		default:
			return ""
		}
	})

	// Fake certd HTTP-over-Unix.
	certdSock := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/dns-providers/save":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "saved": true})
		case "/api/v1/cert-delivery/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "targets": []any{}})
		case "/api/v1/certs/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":          true,
				"letsencrypt": []map[string]any{{"lineage": "example.com", "not_after": "2027-01-01"}},
			})
		case "/api/v1/ca/export":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n", "filename": "internal-ca.crt"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	}))

	// Fake controld line-based socket.
	controldSock := startFakeHAProxyAdmin(t, func(cmd string) string {
		switch {
		case strings.HasPrefix(cmd, "config-versions"):
			return `{"versions":[{"id":"v1"}],"unapplied":false}` + "\n"
		case cmd == "config-transaction-status":
			return `{"ok":true,"pending":false}` + "\n"
		case cmd == "geoip-status":
			return `{"ok":true,"available":true}` + "\n"
		case strings.HasPrefix(cmd, "geoip-schedule "):
			return `{"ok":true,"schedule":"weekly"}` + "\n"
		default:
			return `{"ok":true}` + "\n"
		}
	})

	// Fake backupd JSON-line RPC.
	backupdSock := startJSONLineServer(t, func(req map[string]any) map[string]any {
		switch req["action"] {
		case "status":
			return map[string]any{
				"ok": true,
				"backups": []map[string]any{
					{"id": "bk001", "archive_name": "bk001.tar.gz.enc"},
				},
			}
		case "start_backup":
			return map[string]any{"ok": true, "job_id": "job123"}
		case "schedule_save":
			return map[string]any{"ok": true, "saved": true}
		default:
			return map[string]any{"ok": true}
		}
	})

	// Fake updated JSON-line RPC.
	var lastUpdateAction string
	updatedSock := startJSONLineServer(t, func(req map[string]any) map[string]any {
		lastUpdateAction, _ = req["action"].(string)
		return map[string]any{"ok": true, "action": lastUpdateAction}
	})

	// Fake authelia-usersd & authelia-bansd JSON-line RPC.
	usersSock := startJSONLineServer(t, func(req map[string]any) map[string]any {
		return map[string]any{"ok": true, "users": []string{"admin"}}
	})
	bansSock := startJSONLineServer(t, func(req map[string]any) map[string]any {
		return map[string]any{"ok": true, "bans": []any{}}
	})

	cfg := &config.Config{
		ProxySecret:         "secret-d2",
		SecretKey:           "hmac-key-d2",
		DefaultLanguage:     "en",
		HAProxySocket:       haproxySock,
		WhitelistGeo:        geoWL,
		WhitelistGlobal:     globalWL,
		BanTable:            "abuse_ban",
		BackupUploadsDir:    uploadsDir,
		BackupDownloadsDir:  downloadsDir,
		CertdSocket:         certdSock,
		ControldSocket:      controldSock,
		BackupdSocket:       backupdSock,
		UpdatedSocket:       updatedSock,
		AutheliaUsersSocket: usersSock,
		AutheliaBansSocket:  bansSock,
		MaxBodyBytes:        config.DefaultMaxBodyBytes,
		MaxUploadBytes:      10 * 1024 * 1024,
		SessionSecure:       true,
	}

	cat, _ := i18n.LoadDir("", "en")
	srv := server.New(cfg, daemons.NewPool(cfg), haproxy.NewRuntime(haproxySock, "", nil, nil), cat)
	h := srv.Handler()

	sid := "s-d2"
	superReq := func(method, target, body, ct string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set(security.ProxySecretHeader, cfg.ProxySecret)
		req.Header.Set("Remote-User", "rootadmin")
		req.Header.Set("Remote-Groups", "superadmin")
		req.AddCookie(srv.Boundary.MakeSessionCookie(sid))
		if method != http.MethodGet {
			if ct == "" {
				ct = "application/json"
			}
			req.Header.Set("Content-Type", ct)
			req.Header.Set(security.CSRFHeaderPrimary, srv.Boundary.CSRFTokenForSession(sid))
		}
		return req
	}

	// 1. Dashboard: whitelists, add whitelist, tables, unban, connections, country-batch.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/whitelists", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "203.0.113.10") {
		t.Fatalf("whitelists failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/api/whitelist", `{"ip":"198.51.100.42"}`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("whitelist add failed: %d %s", rec.Code, rec.Body.String())
	}
	rawGeo, _ := os.ReadFile(geoWL)
	if !strings.Contains(string(rawGeo), "198.51.100.42") {
		t.Fatalf("expected IP written to geo whitelist, got %q", string(rawGeo))
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/tables?view=bans", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "192.0.2.55") {
		t.Fatalf("tables failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/api/unban", `{"ip":"192.0.2.55"}`, ""))
	if rec.Code != http.StatusOK || clearedKey != "192.0.2.55" {
		t.Fatalf("unban failed: %d cleared=%q", rec.Code, clearedKey)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/api/country-batch", `{"ips":["8.8.8.8","not-an-ip"]}`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("country-batch failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Certs: DNS provider validation + save, cert delivery with available lineages, CA download.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/api/haproxy/dns-providers/save", `{"name":"cf-main","provider":"cloudflare","credentials":{"api_token":"tok123"}}`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("dns-provider save failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/haproxy/cert-delivery", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "example.com") {
		t.Fatalf("cert-delivery list failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/haproxy/certs/ca/internal/download", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("CA download failed: %d %s", rec.Code, rec.Body.String())
	}

	// 3. Config history, transactions, and GeoIP via controld.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/api/haproxy/config/versions", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"v1"`) {
		t.Fatalf("config versions failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/haproxy/geoip/schedule", `{"schedule":"weekly"}`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("geoip schedule failed: %d %s", rec.Code, rec.Body.String())
	}

	// 4. Backups: start backup (202), streaming upload (201), safe download (200), restore validation.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/system/backups/api/jobs/backup", `{"passphrase":"very-strong-pass","include_ssh":false,"quiesce":true}`, ""))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("backup start expected 202, got %d %s", rec.Code, rec.Body.String())
	}

	uploadReq := superReq(http.MethodPost, "/system/backups/api/uploads", "ARCHIVE-BYTES-PAYLOAD", "application/octet-stream")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, uploadReq)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"upload_id"`) {
		t.Fatalf("backup upload failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/system/backups/download/bk001", "", ""))
	if rec.Code != http.StatusOK || rec.Body.String() != "ENCRYPTED-ARCHIVE" {
		t.Fatalf("backup download failed: %d %q", rec.Code, rec.Body.String())
	}

	// 5. Updates, OS Security, SSH Security via updated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/system/updates/api/check", `{"release_channel":"alpha"}`, ""))
	if rec.Code != http.StatusAccepted || lastUpdateAction != "start_check" {
		t.Fatalf("updates check failed: %d action=%q", rec.Code, lastUpdateAction)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/system/os-security/api/policy", `{"mode":"window","interval":6,"start":2,"end":5,"confirmation":"SECURITY"}`, ""))
	if rec.Code != http.StatusAccepted || lastUpdateAction != "os_security_configure" {
		t.Fatalf("os-security policy failed: %d action=%q %s", rec.Code, lastUpdateAction, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodPost, "/system/ssh-security/api/unban", `{"ip":"203.0.113.9"}`, ""))
	if rec.Code != http.StatusOK || lastUpdateAction != "ssh_protection_unban" {
		t.Fatalf("ssh unban failed: %d action=%q", rec.Code, lastUpdateAction)
	}

	// 6. Authelia users & bans daemons.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/authelia/api/users", "", ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"admin"`) {
		t.Fatalf("authelia users list failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, superReq(http.MethodGet, "/authelia/api/bans", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("authelia bans list failed: %d %s", rec.Code, rec.Body.String())
	}
}
