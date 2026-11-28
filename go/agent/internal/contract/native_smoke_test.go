package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Smoke tests of the built panel and agent binaries on synthetic data, the
// port of .tests/integration/native_smoke.py. The panel: the healthcheck
// identities, static files and the i18n catalogue script, the RBAC boundary,
// and session-bound CSRF on mutating routes. The agent: its server-state
// normalizer must answer exactly as the installer's Python normalizer, which
// the HAProxy package migration also uses. Needs PANEL_BIN and AGENT_BIN (the
// linux binaries CI built); without them the tests skip.

const nativeSmokeProxySecret = "smoke-ci-local-proxy"

var nativeSmokeMetaCSRF = regexp.MustCompile(`name="csrf-token"\s+content="([^"]+)"`)

// nativeSmokeBinaries skips unless both CI-built binaries are present as
// regular executable files, and returns their paths.
func nativeSmokeBinaries(t *testing.T) (panel, agent string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the native smoke tests run the linux binaries")
	}
	for _, name := range []string{"PANEL_BIN", "AGENT_BIN"} {
		path := os.Getenv(name)
		if path == "" {
			t.Skipf("%s is not set", name)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			t.Skipf("%s (%q) is not a regular executable file", name, path)
		}
	}
	return os.Getenv("PANEL_BIN"), os.Getenv("AGENT_BIN")
}

// nativeSmokeIdentity is the proxy secret plus the identity the gateway's
// auth proxy forwards for a user.
func nativeSmokeIdentity(user, groups string) map[string]string {
	return map[string]string{
		"X-Easy-HA-Proxy-Secret": nativeSmokeProxySecret,
		"Remote-User":            user,
		"Remote-Groups":          groups,
	}
}

// nativeSmokeClient mirrors http.client.HTTPConnection: a 3s timeout, no
// redirect following and no transparent compression.
func nativeSmokeClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableCompression: true},
	}
}

// nativeSmokeRequest performs one panel request and returns the status, the
// body and the response headers.
func nativeSmokeRequest(client *http.Client, port int, method, path string, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), reader)
	if err != nil {
		return 0, nil, nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, raw, resp.Header, nil
}

// nativeSmokeDo is nativeSmokeRequest for the checks: a transport error
// fails the test instead of being retried.
func nativeSmokeDo(t *testing.T, client *http.Client, port int, method, path string, headers map[string]string, body []byte) (int, []byte, http.Header) {
	t.Helper()
	status, raw, header, err := nativeSmokeRequest(client, port, method, path, headers, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return status, raw, header
}

// nativeSmokeRead is a GET whose status and body the caller checks.
func nativeSmokeRead(t *testing.T, client *http.Client, port int, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	status, raw, _ := nativeSmokeDo(t, client, port, http.MethodGet, path, headers, nil)
	return status, raw
}

// nativeSmokeCookieHeader joins the Set-Cookie name=value pairs the way the
// Python suite's SimpleCookie extraction does.
func nativeSmokeCookieHeader(header http.Header) string {
	var parts []string
	for _, cookie := range (&http.Response{Header: header}).Cookies() {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

// nativeSmokeEnv is the inherited environment with the panel overrides the
// Python suite sets.
func nativeSmokeEnv(overrides map[string]string) []string {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			env[key] = value
		}
	}
	for key, value := range overrides {
		env[key] = value
	}
	var out []string
	for key, value := range env {
		out = append(out, key+"="+value)
	}
	return out
}

// nativeSmokePort reserves a free loopback port the way the Python suite
// does: bind, read the port, close.
func nativeSmokePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// nativeSmokeLog reads the panel log for failure messages.
func nativeSmokeLog(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(no panel log: %v)", err)
	}
	return string(raw)
}

func TestNativeSmokePanel(t *testing.T) {
	panelBin, _ := nativeSmokeBinaries(t)
	web := filepath.Join(repoRoot(t), "go", "panel", "web")
	tmp := t.TempDir()
	port := nativeSmokePort(t)

	logPath := filepath.Join(tmp, "panel.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	panel := exec.Command(panelBin, "serve")
	panel.Env = nativeSmokeEnv(map[string]string{
		"HAPROXY_ADMIN_LISTEN_ADDR":      fmt.Sprintf("127.0.0.1:%d", port),
		"HAPROXY_ADMIN_PROXY_SECRET":     nativeSmokeProxySecret,
		"HAPROXY_ADMIN_SECRET_KEY":       "smoke-ci-local-session",
		"HAPROXY_ADMIN_STATIC_DIR":       filepath.Join(web, "static"),
		"HAPROXY_ADMIN_TRANSLATIONS_DIR": filepath.Join(web, "translations"),
		"HAPROXY_ADMIN_TEMPLATES_DIR":    filepath.Join(web, "templates"),
		"HAPROXY_ADMIN_TRASH_DIR":        filepath.Join(tmp, "trash"),
		"WHITELIST_GLOBAL_FILE":          filepath.Join(tmp, "whitelist"),
		"WHITELIST_FILE":                 filepath.Join(tmp, "whitelist-site"),
		"AUDIT_DATABASE":                 filepath.Join(tmp, "audit.db"),
	})
	panel.Stdout = log
	panel.Stderr = log
	if err := panel.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = panel.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = panel.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = panel.Process.Kill()
			<-exited
		}
		log.Close()
	})

	client := nativeSmokeClient()
	health := nativeSmokeIdentity("easy-ha-proxy-healthcheck", "healthcheck")
	admin := nativeSmokeIdentity("smoke-admin", "superadmin")
	operator := nativeSmokeIdentity("smoke-op", "admins")

	// Readiness: the health endpoint answers 200 within 10s.
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("panel exited before becoming ready\n%s", nativeSmokeLog(t, logPath))
		default:
		}
		status, _, _, err := nativeSmokeRequest(client, port, http.MethodGet, "/api/control-plane-health", health, nil)
		if err == nil && status == http.StatusOK {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("panel did not become ready\n%s", nativeSmokeLog(t, logPath))
	}

	for _, path := range []string{"/api/control-plane-health", "/api/access-portal-health"} {
		t.Run(strings.TrimPrefix(path, "/api/"), func(t *testing.T) {
			status, body := nativeSmokeRead(t, client, port, path, health)
			if status != http.StatusOK {
				t.Fatalf("%s: status %d, want 200", path, status)
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("%s: body is not JSON: %v", path, err)
			}
			if payload["ok"] != true {
				t.Errorf("%s: ok is %v, want true", path, payload["ok"])
			}
		})
	}

	t.Run("static file served as it is on disk", func(t *testing.T) {
		status, body := nativeSmokeRead(t, client, port, "/static/js/acme_email.js", admin)
		if status != http.StatusOK {
			t.Fatalf("status %d, want 200", status)
		}
		want, err := os.ReadFile(filepath.Join(web, "static", "js", "acme_email.js"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, want) {
			t.Errorf("the served acme_email.js differs from the file on disk")
		}
	})

	t.Run("i18n catalogue script", func(t *testing.T) {
		status, body := nativeSmokeRead(t, client, port, "/i18n/messages.js?lang=ru", admin)
		if status != http.StatusOK {
			t.Fatalf("status %d, want 200", status)
		}
		if len(body) <= 1000 {
			t.Errorf("the catalogue script is %d bytes, want more than 1000", len(body))
		}
	})

	t.Run("rbac-missing-proxy-secret", func(t *testing.T) {
		status, _ := nativeSmokeRead(t, client, port, "/api/control-plane-health", map[string]string{
			"Remote-User":   "nobody",
			"Remote-Groups": "superadmin",
		})
		if status != http.StatusForbidden {
			t.Errorf("status %d, want 403", status)
		}
	})

	t.Run("rbac-admins-blocked-on-superadmin-route", func(t *testing.T) {
		status, _ := nativeSmokeRead(t, client, port, "/haproxy", operator)
		if status != http.StatusForbidden {
			t.Errorf("status %d, want 403", status)
		}
	})

	form := []byte("language=ru&next=/")
	formType := "application/x-www-form-urlencoded"

	t.Run("csrf-missing-token-rejected", func(t *testing.T) {
		headers := nativeSmokeIdentity("smoke-admin", "superadmin")
		headers["Content-Type"] = formType
		status, _, _ := nativeSmokeDo(t, client, port, http.MethodPost, "/language", headers, form)
		if status != http.StatusBadRequest {
			t.Errorf("status %d, want 400", status)
		}
	})

	// The session page issues the CSRF token and the session cookie every
	// mutating check below needs.
	status, html, header := nativeSmokeDo(t, client, port, http.MethodGet, "/", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /: status %d, want 200", status)
	}
	match := nativeSmokeMetaCSRF.FindSubmatch(html)
	if match == nil {
		t.Fatalf("no csrf-token meta on the home page\n%s", html)
	}
	csrf := string(match[1])
	cookie := nativeSmokeCookieHeader(header)
	if !strings.Contains(cookie, "easy_ha_proxy_session=") {
		t.Fatalf("no session cookie in %q", cookie)
	}
	formHeaders := nativeSmokeIdentity("smoke-admin", "superadmin")
	formHeaders["Content-Type"] = formType
	formHeaders["Cookie"] = cookie

	t.Run("csrf-query-string-token-rejected", func(t *testing.T) {
		// A token in the query string is not accepted.
		status, _, _ := nativeSmokeDo(t, client, port, http.MethodPost, "/language?csrf_token="+csrf, formHeaders, form)
		if status != http.StatusBadRequest {
			t.Errorf("status %d, want 400", status)
		}
	})

	t.Run("csrf-valid-mutating-language", func(t *testing.T) {
		// The header token with the session cookie is 303 + the language cookie.
		headers := nativeSmokeIdentity("smoke-admin", "superadmin")
		for key, value := range formHeaders {
			headers[key] = value
		}
		headers["X-CSRF-Token"] = csrf
		status, _, okHeader := nativeSmokeDo(t, client, port, http.MethodPost, "/language", headers, form)
		if status != http.StatusSeeOther {
			t.Fatalf("status %d, want 303", status)
		}
		if got := nativeSmokeCookieHeader(okHeader); !strings.Contains(got, "easy_ha_proxy_language=ru") {
			t.Errorf("no language cookie in %q", got)
		}
	})

	t.Run("csrf-valid-mutating-whitelist-global", func(t *testing.T) {
		// A mutating API route passes CSRF; with no HAProxy runtime socket
		// in the smoke container it answers 502 with a body.
		headers := nativeSmokeIdentity("smoke-admin", "superadmin")
		for key, value := range formHeaders {
			headers[key] = value
		}
		headers["X-CSRF-Token"] = csrf
		status, body, _ := nativeSmokeDo(t, client, port, http.MethodPost, "/api/whitelist-global", headers, []byte("ip=203.0.113.55"))
		if status != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", status)
		}
		if len(body) == 0 {
			t.Error("the 502 answer has no body")
		}
	})

	t.Run("csrf-token-of-one-user-rejected-for-another", func(t *testing.T) {
		// A token issued to one user does not authorize another user's
		// request on the same session cookie.
		headers := nativeSmokeIdentity("smoke-admin", "superadmin")
		for key, value := range formHeaders {
			headers[key] = value
		}
		headers["Remote-User"] = "smoke-other"
		headers["X-CSRF-Token"] = csrf
		status, _, _ := nativeSmokeDo(t, client, port, http.MethodPost, "/language", headers, form)
		if status != http.StatusBadRequest {
			t.Errorf("status %d, want 400", status)
		}
	})
}

func TestNativeSmokeServerState(t *testing.T) {
	_, agentBin := nativeSmokeBinaries(t)
	root := t.TempDir()
	config := filepath.Join(root, "haproxy.cfg")
	state := filepath.Join(root, "server.state")
	if err := os.WriteFile(config, []byte("defaults\n  default-server check\nbackend app\n  server web 192.0.2.10:80\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateText := "1\n" +
		"# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight " +
		"srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health " +
		"srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord\n" +
		"3 app 1 web 192.0.2.10 2 0 1 1 100 6 3 4 6 0 0 0 - 80 -\n"
	if err := os.WriteFile(state, []byte(stateText), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, agentBin, "server-state", "--config", config, "--state", state)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agent server-state failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("3 app 1 web")) {
		t.Errorf("stdout lacks %q: %s", "3 app 1 web", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr is not empty: %s", stderr.String())
	}
}
