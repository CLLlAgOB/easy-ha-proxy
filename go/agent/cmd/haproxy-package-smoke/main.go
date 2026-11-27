// Command haproxy-package-smoke exercises the real generated configuration,
// Lua, TLS and Runtime API of the selected HAProxy package.
//
// Run as root on a disposable system with that HAProxy package installed:
//
//	haproxy-package-smoke [--expected-branch 3.4]
//
// All listeners use loopback and temporary ports; no service is started or
// reloaded. Authentication responses come from a fixture, not a real account.
// It prints {"version": ..., "checks": [...]} as JSON on success.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy-ha-proxy/panel/shared/jinja"
)

func main() {
	expectedBranch := flag.String("expected-branch", "3.4", "HAProxy branch the package must report")
	flag.Parse()
	result, err := qualify(*expectedBranch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

// findRoot locates the repository root by walking up from the working
// directory until the HAProxy template is present (Python used __file__).
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	marker := filepath.Join("ansible", "roles", "haproxy", "templates", "haproxy.cfg.j2")
	for {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("cannot locate repository root (haproxy.cfg.j2) from the working directory")
		}
		dir = parent
	}
}

// run captures stdout and stderr separately; env overrides the environment.
func run(env []string, args ...string) (string, string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			err = copyDir(s, d)
		} else {
			err = copyFile(s, d)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// renderPlain renders an error-page template with a default Jinja environment
// (no trim/lstrip, no autoescape), as Python's Environment().from_string().
func renderPlain(path string) (string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	env := jinja.NewEnvironment(nil)
	env.Autoescape = false
	t, err := env.FromString(filepath.Base(path), string(src))
	if err != nil {
		return "", err
	}
	return env.RenderTemplate(t, map[string]any{})
}

func unusedPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// runtime sends one command to the HAProxy Runtime API unix socket, closes the
// write side and reads the whole reply (Python's socket + shutdown(SHUT_WR)).
func runtime(path, command string) (string, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return "", err
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := uc.CloseWrite(); err != nil {
			return "", err
		}
	}
	data, err := io.ReadAll(conn)
	return string(data), err
}

func hasField(line, token string) bool {
	for _, f := range strings.Fields(line) {
		if f == token {
			return true
		}
	}
	return false
}

// fixtureBackend is the auth/content backend: HEAD answers the forward-auth
// subrequest, GET serves the site body.
type fixtureBackend struct {
	mu           sync.Mutex
	authFailure  bool
	authRequests []map[string]string
}

func (b *fixtureBackend) setAuthFailure(v bool) {
	b.mu.Lock()
	b.authFailure = v
	b.mu.Unlock()
}

func (b *fixtureBackend) snapshot() []map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]map[string]string(nil), b.authRequests...)
}

func (b *fixtureBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		cookie := r.Header.Get("Cookie")
		b.mu.Lock()
		b.authRequests = append(b.authRequests, map[string]string{"path": r.URL.Path, "cookie": cookie})
		fail := b.authFailure
		b.mu.Unlock()
		w.Header().Set("Content-Length", "0")
		switch {
		case fail:
			w.WriteHeader(http.StatusServiceUnavailable)
		case cookie == "session=allowed":
			w.Header().Set("Remote-User", "test-user")
			w.WriteHeader(http.StatusOK)
		case cookie == "session=redirect":
			w.Header().Set("Location", "https://auth.example.test/")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}
	payload := []byte("fixture backend\n")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func qualify(expected string) (map[string]any, error) {
	stdout, _, err := run(nil, "haproxy", "-v")
	if err != nil {
		return nil, fmt.Errorf("haproxy -v: %w", err)
	}
	version := strings.SplitN(stdout, "\n", 2)[0]
	wantVersion := regexp.MustCompile(`HAProxy version ` + regexp.QuoteMeta(expected) + `\.`)
	if !wantVersion.MatchString(version) {
		return nil, fmt.Errorf("unexpected HAProxy version: %s", version)
	}

	root, err := findRoot()
	if err != nil {
		return nil, err
	}
	var checks []string

	base, err := os.MkdirTemp("/tmp", "ehp-haproxy-smoke-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o755); err != nil {
		return nil, err
	}

	backend := &fixtureBackend{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	backendPort := listener.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: backend}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	tlsPort, err := unusedPort()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(base, "etc")
	certsDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(base, "state"), 0o755); err != nil {
		return nil, err
	}
	errorsDir := filepath.Join(configDir, "errors")
	if err := copyDir("/etc/haproxy/errors", errorsDir); err != nil {
		return nil, err
	}
	templates := filepath.Join(root, "ansible", "roles", "haproxy", "templates")
	for _, name := range []string{"maintenance.http", "access_granted.http"} {
		rendered, err := renderPlain(filepath.Join(templates, name+".j2"))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(errorsDir, name), []byte(rendered), 0o644); err != nil {
			return nil, err
		}
	}
	if err := copyFile(filepath.Join(root, "ansible/roles/haproxy/files/default-favicon.ico"),
		filepath.Join(errorsDir, "default-favicon.ico")); err != nil {
		return nil, err
	}
	banPage, err := renderPlain(filepath.Join(templates, "ban_first_step.html.j2"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(errorsDir, "ban-first-step.html"), []byte(banPage), 0o644); err != nil {
		return nil, err
	}

	luaDir := filepath.Join(configDir, "lua")
	if err := os.MkdirAll(filepath.Join(luaDir, "haproxy-lua-http"), 0o755); err != nil {
		return nil, err
	}
	sourceLua := filepath.Join(root, "ansible", "roles", "authelia", "files", "lua")
	for _, c := range [][2]string{
		{"auth-request.lua", filepath.Join(luaDir, "auth-request.lua")},
		{"http.lua", filepath.Join(luaDir, "haproxy-lua-http", "http.lua")},
		{"json.lua", filepath.Join(luaDir, "json.lua")},
	} {
		if err := copyFile(filepath.Join(sourceLua, c[0]), c[1]); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"admin.allow", "whitelist.ip", "guardd-shield-segments.lst", "guardd-shield-paths.lst", "guardd-shield-exempt.lst"} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte(""), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "admin.allow"), []byte("127.0.0.1\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(configDir, "geoip"), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(configDir, "geoip", "whitelist.geo"), []byte(""), 0o644); err != nil {
		return nil, err
	}

	keyPath, certPath := filepath.Join(base, "key.pem"), filepath.Join(base, "cert.pem")
	if _, _, err := run(nil, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
		"-subj", "/CN=shop.example.test", "-addext",
		"subjectAltName=DNS:shop.example.test,DNS:admin.example.test,IP:127.0.0.1",
		"-keyout", keyPath, "-out", certPath); err != nil {
		return nil, fmt.Errorf("openssl: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(certsDir, "test.pem"), append(append([]byte{}, certPEM...), keyPEM...), 0o644); err != nil {
		return nil, err
	}

	env := jinja.NewEnvironment(func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(templates, name))
		return string(b), err
	})
	env.Autoescape = false
	env.TrimBlocks = true
	env.LstripBlocks = true
	jinja.AddAnsibleFilters(env)
	env.Filters["regex_replace"] = jinja.RegexReplaceFilter
	env.Filters["combine"] = jinja.CombineFilter

	shopSite := map[string]any{
		"name": "shop", "domain": "shop.example.test",
		"backend_ip": "127.0.0.1", "backend_port": backendPort,
		"authelia_enabled": true,
	}
	config, err := env.Render("haproxy.cfg.j2", map[string]any{
		"sites":                        []map[string]any{shopSite},
		"site_defaults":                map[string]any{"ban_policy": "u02"},
		"tcp_proxies":                  []map[string]any{},
		"tcp":                          []map[string]any{},
		"admin_domain":                 "admin.example.test",
		"aut_domain":                   "auth.example.test",
		"authelia_enabled":             true,
		"admin_password":               false,
		"enable_geoip":                 false,
		"peers_enabled":                false,
		"haproxy_server_state_enabled": false,
		"haproxy_socket_group":         "root",
		"haproxy_certs_dir":            certsDir + "/",
	})
	if err != nil {
		return nil, fmt.Errorf("render haproxy.cfg.j2: %w", err)
	}
	stateDir := filepath.Join(base, "state")
	config = strings.ReplaceAll(config, "/etc/haproxy", configDir)
	config = strings.ReplaceAll(config, "/var/lib/haproxy", stateDir)
	config = strings.ReplaceAll(config, "/run/haproxy/admin.sock", filepath.Join(base, "admin.sock"))
	config = strings.ReplaceAll(config, "ipv4@*:443", "127.0.0.1:"+strconv.Itoa(tlsPort))
	config = strings.ReplaceAll(config, "127.0.0.1:9091", "127.0.0.1:"+strconv.Itoa(backendPort))
	config = strings.ReplaceAll(config, "127.0.0.1:5000", "127.0.0.1:"+strconv.Itoa(backendPort))
	confPath := filepath.Join(base, "haproxy.cfg")
	if err := os.WriteFile(confPath, []byte(config), 0o644); err != nil {
		return nil, err
	}

	processEnv := append(os.Environ(), "HAPROXY_ADMIN_PROXY_SECRET=smoke-test-secret-"+strings.Repeat("a", 40))
	parsedOut, parsedErr, err := run(processEnv, "haproxy", "-c", "-f", confPath)
	if err != nil {
		return nil, fmt.Errorf("haproxy -c failed: %s%s", parsedOut, parsedErr)
	}
	for _, warning := range []string{"bool-sample-conversion", "not supported by AWS-LC", "will still be processed before"} {
		if strings.Contains(parsedErr, warning) {
			return nil, fmt.Errorf("haproxy -c warned %q: %s", warning, parsedErr)
		}
	}
	checks = append(checks, "generated configuration and Lua load")

	// Every kind of backend the template writes, checked by this HAProxy (not
	// started): a passthrough site, a service site with its access page, a TCP
	// proxy and a paused site. A passthrough backend's ban rule once joined the
	// next directive -- trim_blocks ate its newline -- and only a gateway with
	// such a site found out.
	everyKind, err := env.Render("haproxy.cfg.j2", map[string]any{
		"sites": []map[string]any{
			shopSite,
			{"name": "files", "domain": "files.example.test", "tcp_passthrough": true,
				"backend_ip": "127.0.0.1", "backend_port": backendPort},
			{"name": "help", "domain": "help.example.test", "access_gate": true,
				"authelia_enabled": true, "access_portal_enabled": true},
			{"name": "old", "domain": "old.example.test", "paused": true,
				"backend_ip": "127.0.0.1", "backend_port": backendPort},
		},
		"site_defaults": map[string]any{"ban_policy": "u02"},
		"tcp_proxies": []map[string]any{
			{"name": "db", "bind_port": 15432, "backend_host": "127.0.0.1", "backend_port": backendPort},
		},
		"tcp": []map[string]any{
			{"name": "db", "bind_port": 15432, "backend_host": "127.0.0.1", "backend_port": backendPort},
		},
		"admin_domain":                 "admin.example.test",
		"aut_domain":                   "auth.example.test",
		"admin_ips_enabled":            true,
		"authelia_enabled":             true,
		"admin_password":               false,
		"enable_geoip":                 false,
		"peers_enabled":                false,
		"haproxy_server_state_enabled": false,
		"haproxy_socket_group":         "root",
		"haproxy_certs_dir":            certsDir + "/",
	})
	if err != nil {
		return nil, fmt.Errorf("render every-kind haproxy.cfg.j2: %w", err)
	}
	everyKind = strings.ReplaceAll(everyKind, "/etc/haproxy", configDir)
	everyKind = strings.ReplaceAll(everyKind, "/var/lib/haproxy", stateDir)
	everyKind = strings.ReplaceAll(everyKind, "/run/haproxy/admin.sock", filepath.Join(base, "admin-every-kind.sock"))
	everyKindPath := filepath.Join(base, "every-kind.cfg")
	if err := os.WriteFile(everyKindPath, []byte(everyKind), 0o644); err != nil {
		return nil, err
	}
	parsedOut, parsedErr, err = run(processEnv, "haproxy", "-c", "-f", everyKindPath)
	if err != nil {
		return nil, fmt.Errorf("haproxy -c every-kind failed: %s%s", parsedOut, parsedErr)
	}
	checks = append(checks, "a configuration with every kind of backend")

	logPath := filepath.Join(base, "process.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	proc := exec.Command("haproxy", "-db", "-f", confPath)
	proc.Env = processEnv
	proc.Stdout = logFile
	proc.Stderr = logFile
	if err := proc.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	exited := make(chan struct{})
	go func() { _ = proc.Wait(); close(exited) }()
	defer func() {
		_ = proc.Process.Kill()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
		}
		logFile.Close()
	}()
	readLog := func() string { b, _ := os.ReadFile(logPath); return string(b) }

	sockPath := filepath.Join(base, "admin.sock")
	ready := false
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			ready = true
			break
		}
		select {
		case <-exited:
			return nil, fmt.Errorf("haproxy exited before the Runtime socket appeared: %s", readLog())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return nil, fmt.Errorf("Runtime socket did not appear: %s", readLog())
	}

	// request dials 127.0.0.1:tlsPort but verifies the certificate against
	// `host` (SNI + Host header), as Python's LocalTLSConnection does.
	request := func(cookie, host string, tlsVersion uint16) (int, string, []byte, error) {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certPEM) {
			return 0, "", nil, fmt.Errorf("cannot load the smoke certificate")
		}
		cfg := &tls.Config{RootCAs: pool, ServerName: host}
		if tlsVersion != 0 {
			cfg.MinVersion = tlsVersion
			cfg.MaxVersion = tlsVersion
		}
		client := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: cfg,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tlsPort)), 5*time.Second)
				},
			},
		}
		req, err := http.NewRequest("GET", "https://"+host+"/", nil)
		if err != nil {
			return 0, "", nil, err
		}
		req.Host = host
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, "", nil, err
		}
		return resp.StatusCode, resp.Header.Get("Location"), body, nil
	}

	for _, host := range []string{"admin.example.test", "shop.example.test"} {
		status, _, _, err := request("", host, 0)
		if err != nil {
			return nil, err
		}
		if status != http.StatusForbidden {
			return nil, fmt.Errorf("%s: anonymous must be refused, got %d", host, status)
		}
		status, _, _, err = request("session=allowed", host, 0)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("%s: authorized must be allowed, got %d (auth requests %v, log %s)",
				host, status, backend.snapshot(), readLog())
		}
		status, location, _, err := request("session=redirect", host, 0)
		if err != nil {
			return nil, err
		}
		if status != http.StatusFound || location != "https://auth.example.test/" {
			return nil, fmt.Errorf("%s: login redirect got (%d, %q)", host, status, location)
		}
	}
	checks = append(checks, "Lua forward-auth: anonymous deny, authorized allow, login redirect")

	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		status, _, _, err := request("session=allowed", "admin.example.test", v)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("TLS version %d: got %d", v, status)
		}
	}
	checks = append(checks, "TLS 1.2 and 1.3 with certificate verification")

	backend.setAuthFailure(true)
	status, _, _, err := request("session=allowed", "admin.example.test", 0)
	if err != nil {
		return nil, err
	}
	if status != http.StatusServiceUnavailable {
		return nil, fmt.Errorf("Auth failure must fail closed, got %d", status)
	}
	backend.setAuthFailure(false)
	checks = append(checks, "authentication outage fails closed")

	reply, err := runtime(sockPath, "set table tbl_ban key 198.51.100.20 data.gpc0 1 data.gpt0 900")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(reply) != "" {
		return nil, fmt.Errorf("set table reply: %q", reply)
	}
	table, err := runtime(sockPath, "show table tbl_ban")
	if err != nil {
		return nil, err
	}
	entry := ""
	for _, line := range strings.Split(table, "\n") {
		if hasField(line, "key=198.51.100.20") {
			entry = line
			break
		}
	}
	if !hasField(entry, "gpc0=1") || !hasField(entry, "gpt0=900") {
		return nil, fmt.Errorf("ban table entry missing counters: %s", table)
	}
	if _, err := runtime(sockPath, "clear table tbl_ban key 198.51.100.20"); err != nil {
		return nil, err
	}
	after, err := runtime(sockPath, "show table tbl_ban")
	if err != nil {
		return nil, err
	}
	if strings.Contains(after, "198.51.100.20") {
		return nil, fmt.Errorf("ban table not cleared: %s", after)
	}
	checks = append(checks, "Runtime API ban table write/read/clear")

	raw, err := runtime(sockPath, "show stat")
	if err != nil {
		return nil, err
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimLeft(raw, "# "))).ReadAll()
	if err != nil {
		return nil, err
	}
	found := false
	if len(rows) > 0 {
		px, sv := -1, -1
		for i, h := range rows[0] {
			if h == "pxname" {
				px = i
			}
			if h == "svname" {
				sv = i
			}
		}
		if px >= 0 && sv >= 0 {
			for _, row := range rows[1:] {
				if px < len(row) && sv < len(row) && row[px] == "be_shop" && row[sv] == "BACKEND" {
					found = true
					break
				}
			}
		}
	}
	if !found {
		preview := raw
		if len(preview) > 500 {
			preview = preview[:500]
		}
		return nil, fmt.Errorf("show stat lacks be_shop/BACKEND: %s", preview)
	}
	checks = append(checks, "Runtime API statistics retain named CSV fields")

	return map[string]any{"version": version, "checks": checks}, nil
}
