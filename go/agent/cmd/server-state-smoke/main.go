// Command server-state-smoke audits HAProxy server-state restoration against
// real, isolated HAProxy workers and backends. It is the Go port of
// .tests/integration/server_state_tls_smoke.py and
// .tests/integration/server_state_settings_smoke.py: the settings smoke calls
// the TLS smoke first, so this program runs the TLS/port cases and then the
// settings cases, printing the TLS results line followed by the settings JSON.
//
// Usage: server-state-smoke --template haproxy-state-dump.sh.j2 [--normalizer AGENT]
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// nativeAgent is the dumper's native-agent placeholder, rendered empty: these
// runs exercise the agent they name (--normalizer), which the dumper then uses.
const nativeAgent = "{{ native_agent_bin | default('/usr/local/sbin/easy-ha-proxy-agent') }}"

// rpc sends one command to a HAProxy admin unix socket and reads the reply
// until EOF, with a 3s timeout.
func rpc(path, command string) (string, error) {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return "", err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// state reads "show servers state" and zips the header row with the target
// server row into a map, returning the raw text as well.
func state(path string) (string, map[string]string, error) {
	text, err := rpc(path, "show servers state")
	if err != nil {
		return "", nil, err
	}
	var header, row []string
	for _, line := range strings.Split(text, "\n") {
		if header == nil && strings.HasPrefix(line, "# ") {
			header = strings.Fields(line[2:])
		}
		if row == nil && strings.Contains(line, " target ") {
			row = strings.Fields(line)
		}
	}
	if header == nil {
		return "", nil, errors.New("no state header in show servers state reply")
	}
	if row == nil {
		return "", nil, errors.New("no target row in show servers state reply")
	}
	if len(header) != len(row) {
		return "", nil, fmt.Errorf("state header/row length mismatch: %d vs %d", len(header), len(row))
	}
	fields := make(map[string]string, len(header))
	for i, key := range header {
		fields[key] = row[i]
	}
	return text, fields, nil
}

// runOpts mirrors the keyword arguments of the Python running() helper.
type runOpts struct {
	tls            bool
	load           bool
	backendPort    int
	backendHost    string
	serverOptions  string
	backendOptions string
	weight         int
}

func defaultRunOpts() runOpts {
	return runOpts{backendPort: 9, backendHost: "127.0.0.1", weight: 100}
}

// running starts an isolated HAProxy worker with the generated config on
// stdin, waits for the control socket to answer, invokes body with the control
// socket path, and finally SIGTERMs the worker (5s wait).
func running(root string, o runOpts, body func(control string) error) error {
	control := filepath.Join(root, "admin.sock")
	if err := os.Remove(control); err != nil && !os.IsNotExist(err) {
		return err
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "global\n stats socket %s level admin\n", control)
	if o.load {
		fmt.Fprintf(&cfg, " server-state-file %s\n", filepath.Join(root, "state"))
	}
	cfg.WriteString("defaults\n mode http\n timeout connect 1s\n timeout client 1s\n timeout server 1s\n")
	if o.load {
		cfg.WriteString(" load-server-state-from-file global\n")
	}
	fmt.Fprintf(&cfg, "frontend probe\n bind 127.0.0.1:%d\n default_backend target\n", port)
	cfg.WriteString("backend target\n default-server check-ssl verify none\n")
	cfg.WriteString(o.backendOptions)
	fmt.Fprintf(&cfg, " server main %s:%d weight %d %s", o.backendHost, o.backendPort, o.weight, o.serverOptions)
	if o.tls {
		cfg.WriteString(" ssl")
	}
	cfg.WriteString("\n")
	config := cfg.String()
	if err := os.WriteFile(filepath.Join(root, "haproxy.cfg"), []byte(config), 0o644); err != nil {
		return err
	}

	cmd := exec.Command("haproxy", "-db", "-f", "/dev/stdin")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var stderrBuf bytes.Buffer
	stderrDone := make(chan struct{})
	go func() {
		io.Copy(&stderrBuf, stderr)
		close(stderrDone)
	}()
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	if _, err := io.WriteString(stdin, config); err != nil {
		stdin.Close()
		<-waitCh
		<-stderrDone
		return fmt.Errorf("writing haproxy config to stdin: %w", err)
	}
	if err := stdin.Close(); err != nil {
		<-waitCh
		<-stderrDone
		return err
	}

	stop := func() error {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitCh:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-waitCh
			<-stderrDone
			return errors.New("HAProxy did not exit within 5s after SIGTERM")
		}
		<-stderrDone
		return nil
	}

	for i := 0; i < 100; i++ {
		select {
		case werr := <-waitCh:
			<-stderrDone
			return fmt.Errorf("HAProxy exited during startup: %v\n%s", werr, stderrBuf.String())
		default:
		}
		if _, err := os.Stat(control); err == nil {
			if _, _, serr := state(control); serr == nil {
				bodyErr := body(control)
				if stopErr := stop(); bodyErr == nil {
					bodyErr = stopErr
				}
				return bodyErr
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	notReady := errors.New("HAProxy socket not ready")
	if stopErr := stop(); stopErr != nil {
		return errors.Join(notReady, stopErr)
	}
	return notReady
}

// renderDump renders the dump template for an isolated run root.
func renderDump(templatePath, root string) (string, error) {
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		return "", err
	}
	script := string(raw)
	script = strings.ReplaceAll(script,
		"{{ haproxy_socket | default('/run/haproxy/admin.sock') }}", filepath.Join(root, "admin.sock"))
	script = strings.ReplaceAll(script,
		"{{ haproxy_server_state_file | default('/var/lib/haproxy/server-state') }}", filepath.Join(root, "state"))
	script = strings.ReplaceAll(script, nativeAgent, "")
	if strings.Contains(script, "{{") {
		return "", errors.New("unrendered placeholder remains in the dump script")
	}
	return script, nil
}

func writeDump(templatePath, root string) error {
	script, err := renderDump(templatePath, root)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "dump.sh"), []byte(script), 0o755)
}

// runDump executes the rendered dumper against the run's config, as the
// installer would, with a 5s timeout.
func runDump(root, normalizer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", filepath.Join(root, "dump.sh"),
		filepath.Join(root, "haproxy.cfg"), normalizer)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dump.sh failed: %w\n%s", err, out)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tlsResult mirrors one result dict of the Python TLS smoke.
type tlsResult struct {
	TLSBefore           bool    `json:"tls_before"`
	TLSAfter            bool    `json:"tls_after"`
	PortBefore          int     `json:"port_before"`
	PortAfter           int     `json:"port_after"`
	UnfilteredTLS       *string `json:"unfiltered_tls"`
	UnfilteredPort      string  `json:"unfiltered_port"`
	AdminStatePreserved string  `json:"admin_state_preserved"`
	WeightPreserved     int     `json:"weight_preserved"`
}

// tlsCases ports server_state_tls_smoke.main: four TLS/port transitions driven
// through the real dumper, printing {"passed": [...]} as the Python smoke does.
func tlsCases(templatePath, normalizer string) error {
	cases := []struct {
		oldTLS, wantedTLS bool
		admin             string
		oldPort           int
		wantedPort        int
	}{
		{false, true, "maint", 1025, 1025},
		{true, false, "drain", 1025, 1025},
		{true, true, "drain", 1025, 1026},
		{false, true, "maint", 1026, 1025},
	}
	results := make([]tlsResult, 0, len(cases))
	for _, c := range cases {
		result, err := tlsCase(templatePath, normalizer, c.oldTLS, c.wantedTLS, c.admin, c.oldPort, c.wantedPort)
		if err != nil {
			return fmt.Errorf("tls case %+v: %w", c, err)
		}
		results = append(results, result)
	}
	out, err := json.Marshal(map[string]any{"passed": results})
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func tlsCase(templatePath, normalizer string, oldTLS, wantedTLS bool, admin string, oldPort, wantedPort int) (tlsResult, error) {
	var result tlsResult
	root, err := os.MkdirTemp("", "ehp-state-tls-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(root)
	if err := writeDump(templatePath, root); err != nil {
		return result, err
	}
	statePath := filepath.Join(root, "state")
	configPath := filepath.Join(root, "haproxy.cfg")

	var original string
	var expected map[string]string
	var filtered string
	before := defaultRunOpts()
	before.tls = oldTLS
	before.backendPort = oldPort
	err = running(root, before, func(control string) error {
		if _, err := rpc(control, "set server target/main weight 17"); err != nil {
			return err
		}
		if _, err := rpc(control, "set server target/main state "+admin); err != nil {
			return err
		}
		var fields map[string]string
		original, fields, err = state(control)
		if err != nil {
			return err
		}
		expected = fields
		if err := os.WriteFile(statePath, []byte(original), 0o644); err != nil {
			return err
		}
		// A save writes the new config before asking the old worker to dump.
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}
		rewritten := strings.ReplaceAll(string(raw),
			fmt.Sprintf(":%d weight", oldPort), fmt.Sprintf(":%d weight", wantedPort))
		if err := os.WriteFile(configPath, []byte(rewritten), 0o644); err != nil {
			return err
		}
		if err := runDump(root, normalizer); err != nil {
			return err
		}
		data, err := os.ReadFile(statePath)
		if err != nil {
			return err
		}
		filtered = string(data)
		return nil
	})
	if err != nil {
		return result, err
	}

	// Observe the raw behavior for diagnostics. Upstream versions can fix this
	// behavior too; only the normalized postconditions below are requirements,
	// not the presence of a bug in an upstream build.
	if err := os.WriteFile(statePath, []byte(original), 0o644); err != nil {
		return result, err
	}
	after := defaultRunOpts()
	after.tls = wantedTLS
	after.load = true
	after.backendPort = wantedPort
	var unfiltered map[string]string
	err = running(root, after, func(control string) error {
		var fields map[string]string
		_, fields, err = state(control)
		unfiltered = fields
		return err
	})
	if err != nil {
		return result, err
	}

	// Then exercise the real updated dumper's output.
	if err := os.WriteFile(statePath, []byte(filtered), 0o644); err != nil {
		return result, err
	}
	err = running(root, after, func(control string) error {
		_, restored, err := state(control)
		if err != nil {
			return err
		}
		if value, ok := restored["srv_use_ssl"]; ok {
			if value != strconv.Itoa(boolInt(wantedTLS)) {
				return fmt.Errorf("srv_use_ssl: want %d got %q (%v)", boolInt(wantedTLS), value, restored)
			}
		}
		if restored["srv_port"] != strconv.Itoa(wantedPort) {
			return fmt.Errorf("srv_port: want %d got %q (%v)", wantedPort, restored["srv_port"], restored)
		}
		for _, key := range []string{"srv_admin_state", "srv_uweight", "srv_iweight"} {
			if restored[key] != expected[key] {
				return fmt.Errorf("%s: want %q got %q (expected %v, restored %v)", key, expected[key], restored[key], expected, restored)
			}
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	result = tlsResult{
		TLSBefore:           oldTLS,
		TLSAfter:            wantedTLS,
		PortBefore:          oldPort,
		PortAfter:           wantedPort,
		UnfilteredPort:      unfiltered["srv_port"],
		AdminStatePreserved: admin,
		WeightPreserved:     17,
	}
	if value, ok := unfiltered["srv_use_ssl"]; ok {
		result.UnfilteredTLS = &value
	}
	return result, nil
}

// endpoint mirrors one before/after dict of the Python settings smoke. A nil
// weight means "unset" (default 100); an explicit zero weight is meaningful.
type endpoint struct {
	backendHost    string
	backendPort    int
	weight         *int
	serverOptions  string
	backendOptions string
	tls            bool
}

func intPtr(v int) *int { return &v }

func (e endpoint) host() string {
	if e.backendHost != "" {
		return e.backendHost
	}
	return "127.0.0.1"
}

func (e endpoint) port() int {
	if e.backendPort != 0 {
		return e.backendPort
	}
	return 9
}

func (e endpoint) weightValue() int {
	if e.weight != nil {
		return *e.weight
	}
	return 100
}

func (e endpoint) runOpts(load bool) runOpts {
	return runOpts{
		tls:            e.tls,
		load:           load,
		backendPort:    e.port(),
		backendHost:    e.host(),
		serverOptions:  e.serverOptions,
		backendOptions: e.backendOptions,
		weight:         e.weightValue(),
	}
}

var serverMainLine = regexp.MustCompile(`(?m)^ server main .+$`)

// transition ports the settings smoke's transition(): run the before config,
// apply runtime commands, rewrite the server line to the desired after config,
// dump through the real dumper, then reload with the after config and check
// the restored state (plus CSV stats) against expected.
func transition(templatePath, normalizer string, before, after endpoint, commands []string,
	expected map[string]any, probe func(root, control string) error, snapshotExpected map[string]string) error {
	root, err := os.MkdirTemp("", "ehp-state-settings-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err := writeDump(templatePath, root); err != nil {
		return err
	}
	configPath := filepath.Join(root, "haproxy.cfg")
	statePath := filepath.Join(root, "state")

	err = running(root, before.runOpts(false), func(control string) error {
		for _, command := range commands {
			answer, err := rpc(control, command)
			if err != nil {
				return err
			}
			if strings.TrimSpace(answer) != "" && !strings.Contains(answer, "IP changed") {
				return fmt.Errorf("command %q: unexpected answer %q", command, answer)
			}
		}
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}
		sslSuffix := ""
		if after.tls {
			sslSuffix = " ssl"
		}
		desired := fmt.Sprintf(" server main %s:%d weight %d %s%s",
			after.host(), after.port(), after.weightValue(), after.serverOptions, sslSuffix)
		config := serverMainLine.ReplaceAllString(string(raw), desired)
		if before.backendOptions != "" {
			config = strings.Replace(config, before.backendOptions, "", 1)
		}
		config = strings.Replace(config, "backend target\n", "backend target\n"+after.backendOptions, 1)
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			return err
		}
		if err := runDump(root, normalizer); err != nil {
			return err
		}
		info, err := os.Stat(statePath)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("The dumper did not create a server-state snapshot")
		}
		if snapshotExpected != nil {
			data, err := os.ReadFile(statePath)
			if err != nil {
				return err
			}
			lines := strings.Split(string(data), "\n")
			if len(lines) < 3 || len(lines[1]) < 2 {
				return fmt.Errorf("short server-state snapshot: %q", string(data))
			}
			header := strings.Fields(lines[1][2:])
			row := strings.Fields(lines[2])
			if len(header) != len(row) {
				return fmt.Errorf("snapshot header/row length mismatch: %d vs %d", len(header), len(row))
			}
			saved := make(map[string]string, len(header))
			for i, key := range header {
				saved[key] = row[i]
			}
			for key, value := range snapshotExpected {
				if saved[key] != value {
					return fmt.Errorf("snapshot %s: want %q got %q (%v)", key, value, saved[key], saved)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return running(root, after.runOpts(true), func(control string) error {
		if probe != nil {
			if err := probe(root, control); err != nil {
				return err
			}
		}
		_, fields, err := state(control)
		if err != nil {
			return err
		}
		statText, err := rpc(control, "show stat")
		if err != nil {
			return err
		}
		stats, err := statRow(statText, "target", "main")
		if err != nil {
			return err
		}
		actual := make(map[string]any, len(fields)+3)
		for key, value := range fields {
			actual[key] = value
		}
		actual["bck"] = stats["bck"]
		actual["slim"] = stats["slim"]
		checkState, err := strconv.Atoi(fields["srv_check_state"])
		if err != nil {
			return fmt.Errorf("srv_check_state %q: %w", fields["srv_check_state"], err)
		}
		actual["check_enabled"] = checkState&4 != 0
		for key, value := range expected {
			got, ok := actual[key]
			if !ok || !reflect.DeepEqual(got, value) {
				return fmt.Errorf("%s: want %#v got %#v (actual %v)", key, value, got, actual)
			}
		}
		return nil
	})
}

// statRow parses the CSV of "show stat" and returns the row for pxname/svname.
func statRow(text, pxname, svname string) (map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(text))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("empty show stat reply")
	}
	header := records[0]
	for _, record := range records[1:] {
		row := make(map[string]string, len(header))
		for i, key := range header {
			if i < len(record) {
				row[key] = record[i]
			}
		}
		if row["# pxname"] == pxname && row["svname"] == svname {
			return row, nil
		}
	}
	return nil, fmt.Errorf("no show stat row for %s/%s", pxname, svname)
}

var bindPort = regexp.MustCompile(`bind 127\.0\.0\.1:(\d+)`)

// request issues GET / through the run's frontend with the client Host header,
// returning the status and body.
func request(root string) (int, string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "haproxy.cfg"))
	if err != nil {
		return 0, "", err
	}
	match := bindPort.FindSubmatch(raw)
	if match == nil {
		return 0, "", errors.New("no frontend bind port in haproxy.cfg")
	}
	port, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return 0, "", err
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = "client.example.test"
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

// observation records one backend request: the Host header and, for TLS
// connections, the negotiated ALPN protocol.
type observation struct {
	host string
	alpn string
}

// backend is the plain or TLS test backend: it records requests, answers 404
// for /healthz and 200 otherwise, and echoes the Host header as the body.
type backend struct {
	mu       sync.Mutex
	observed []observation
	names    []string
	srv      *http.Server
	port     int
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	alpn := ""
	if r.TLS != nil {
		alpn = r.TLS.NegotiatedProtocol
	}
	b.mu.Lock()
	b.observed = append(b.observed, observation{host: r.Host, alpn: alpn})
	b.mu.Unlock()
	status := http.StatusOK
	if r.URL.Path == "/healthz" {
		status = http.StatusNotFound
	}
	w.WriteHeader(status)
	io.WriteString(w, r.Host)
}

func (b *backend) lastObservation() (observation, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.observed) == 0 {
		return observation{}, false
	}
	return b.observed[len(b.observed)-1], true
}

func (b *backend) lastName() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.names) == 0 {
		return "", false
	}
	return b.names[len(b.names)-1], true
}

func startPlainBackend() (*backend, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &backend{port: listener.Addr().(*net.TCPAddr).Port}
	// Silence request logging, as the Python handler's log_message override does.
	b.srv = &http.Server{Handler: b, ErrorLog: log.New(io.Discard, "", 0)}
	go b.srv.Serve(listener)
	return b, nil
}

func startTLSBackend(certFile, keyFile string) (*backend, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &backend{port: listener.Addr().(*net.TCPAddr).Port}
	b.srv = &http.Server{
		Handler:  b,
		ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			NextProtos: []string{"http/1.1", "h2"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				b.mu.Lock()
				b.names = append(b.names, hello.ServerName)
				b.mu.Unlock()
				return &cert, nil
			},
		},
		// Advertise h2 but keep serving HTTP/1.1, exactly like the Python
		// ThreadingHTTPServer wrapped in an ALPN-enabled SSL socket.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go b.srv.ServeTLS(listener, "", "")
	return b, nil
}

func (b *backend) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b.srv.Shutdown(ctx)
}

// generateCert creates the self-signed backend certificate with openssl, as
// the Python smoke does.
func generateCert(root string) (string, string, error) {
	certPath := filepath.Join(root, "cert.pem")
	keyPath := filepath.Join(root, "key.pem")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
		"-subj", "/CN=backend.example.test", "-addext", "subjectAltName=DNS:backend.example.test",
		"-keyout", keyPath, "-out", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("openssl req failed: %w\n%s", err, out)
	}
	return certPath, keyPath, nil
}

// settingsCases ports server_state_settings_smoke.main: the TLS cases first,
// then the settings transitions, printing the final settings JSON.
func settingsCases(templatePath, normalizer string) error {
	for _, command := range []string{"haproxy", "socat", "openssl"} {
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("Missing runtime audit dependency: %s", command)
		}
	}
	if info, err := os.Stat(normalizer); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("Missing state normalizer: %s", normalizer)
	}
	if err := tlsCases(templatePath, normalizer); err != nil {
		return err
	}

	cases := []struct {
		label    string
		before   endpoint
		after    endpoint
		commands []string
		expected map[string]any
	}{
		{"IPv4", endpoint{}, endpoint{backendHost: "127.0.0.2"}, nil,
			map[string]any{"srv_addr": "127.0.0.2"}},
		{"IPv6", endpoint{}, endpoint{backendHost: "[::1]"}, nil,
			map[string]any{"srv_addr": "::1"}},
		{"IP to DNS", endpoint{}, endpoint{backendHost: "ip6-localhost"}, nil,
			map[string]any{"srv_addr": "::1", "srv_fqdn": "ip6-localhost"}},
		{"DNS rename", endpoint{backendHost: "localhost"}, endpoint{backendHost: "ip6-localhost"},
			[]string{"set server target/main addr 127.0.0.2"}, map[string]any{"srv_addr": "::1"}},
		{"same DNS cache", endpoint{backendHost: "localhost"}, endpoint{backendHost: "localhost"},
			[]string{"set server target/main addr 127.0.0.2"}, map[string]any{"srv_fqdn": "localhost"}},
		{"configured weight", endpoint{}, endpoint{weight: intPtr(55)},
			[]string{"set server target/main weight 17"}, map[string]any{"srv_uweight": "55"}},
		{"zero weight to enabled", endpoint{weight: intPtr(0)}, endpoint{weight: intPtr(100)}, nil,
			map[string]any{"srv_uweight": "100", "srv_admin_state": "0"}},
		{"manual drain with new weight", endpoint{}, endpoint{weight: intPtr(55)},
			[]string{"set server target/main state drain"}, map[string]any{"srv_uweight": "55", "srv_admin_state": "8"}},
		{"configured disabled to enabled", endpoint{serverOptions: "disabled"}, endpoint{}, nil,
			map[string]any{"srv_admin_state": "0"}},
		{"enabled to configured disabled", endpoint{}, endpoint{serverOptions: "disabled"}, nil,
			map[string]any{"srv_admin_state": "5"}},
		{"add health check", endpoint{}, endpoint{serverOptions: "check inter 10s"}, nil,
			map[string]any{"check_enabled": true}},
		{"remove failed health check", endpoint{serverOptions: "check inter 10s"}, endpoint{},
			[]string{"set server target/main health down"}, map[string]any{"srv_op_state": "2"}},
		{"keep explicit health disable", endpoint{serverOptions: "check inter 10s"}, endpoint{serverOptions: "check inter 10s"},
			[]string{"disable health target/main"}, map[string]any{"check_enabled": false}},
		{"backup and maxconn", endpoint{}, endpoint{serverOptions: "backup maxconn 11"}, nil,
			map[string]any{"bck": "1", "slim": "11"}},
		{"backup to main", endpoint{serverOptions: "backup"}, endpoint{}, nil,
			map[string]any{"bck": "0"}},
	}
	passed := make([]string, 0, 20)
	for _, c := range cases {
		// Preserve our cache in the snapshot. HAProxy can legitimately choose
		// a fresh DNS result if the saved IP has a different address family.
		var snapshotExpected map[string]string
		if c.label == "same DNS cache" {
			snapshotExpected = map[string]string{"srv_addr": "127.0.0.2"}
		}
		if err := transition(templatePath, normalizer, c.before, c.after, c.commands, c.expected, nil, snapshotExpected); err != nil {
			return fmt.Errorf("case %q: %w", c.label, err)
		}
		passed = append(passed, c.label)
	}

	plain, err := startPlainBackend()
	if err != nil {
		return err
	}
	endpointPort := endpoint{backendPort: plain.port}
	after := endpointPort
	after.backendOptions = " http-request set-header Host new.example.test\n"
	hostProbe := func(root, _ string) error {
		status, body, err := request(root)
		if err != nil {
			return err
		}
		if status != 200 || body != "new.example.test" {
			return fmt.Errorf("backend Host header: want (200, %q) got (%d, %q)", "new.example.test", status, body)
		}
		return nil
	}
	if err := transition(templatePath, normalizer, endpointPort, after, nil, nil, hostProbe, nil); err != nil {
		plain.shutdown()
		return fmt.Errorf("case %q: %w", "backend Host header", err)
	}
	passed = append(passed, "backend Host header")

	after = endpointPort
	after.serverOptions = "check inter 100ms rise 1 fall 1"
	after.backendOptions = " option httpchk\n http-check send meth GET uri /healthz\n http-check expect status 404\n"
	healthProbe := func(_, control string) error {
		deadline := time.Now().Add(3 * time.Second)
		var stats map[string]string
		for time.Now().Before(deadline) {
			text, err := rpc(control, "show stat")
			if err != nil {
				return err
			}
			stats, err = statRow(text, "target", "main")
			if err != nil {
				return err
			}
			if stats["status"] == "UP" && stats["check_code"] == "404" {
				return nil
			}
			time.Sleep(25 * time.Millisecond)
		}
		return fmt.Errorf("health probe timed out: %v", stats)
	}
	before := endpointPort
	before.serverOptions = "check inter 10s"
	// The helper defaults check-ssl; explicitly disable it for this plain backend.
	after.serverOptions += " no-check-ssl"
	if err := transition(templatePath, normalizer, before, after,
		[]string{"set server target/main health down"}, nil, healthProbe, nil); err != nil {
		plain.shutdown()
		return fmt.Errorf("case %q: %w", "new HTTP health URI and expected status", err)
	}
	passed = append(passed, "new HTTP health URI and expected status")
	plain.shutdown()

	root, err := os.MkdirTemp("", "ehp-state-tls-backend-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	certPath, keyPath, err := generateCert(root)
	if err != nil {
		return err
	}
	secure, err := startTLSBackend(certPath, keyPath)
	if err != nil {
		return err
	}
	before = endpoint{tls: true, backendPort: secure.port, serverOptions: "sni str(old.example.test) alpn h2"}
	after = before
	after.serverOptions = "sni str(new.example.test) alpn http/1.1"
	tlsProbe := func(root, _ string) error {
		status, _, err := request(root)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("backend SNI and ALPN: want status 200 got %d", status)
		}
		name, ok := secure.lastName()
		if !ok || name != "new.example.test" {
			return fmt.Errorf("backend SNI and ALPN: last SNI name %q (ok=%v), want new.example.test", name, ok)
		}
		last, ok := secure.lastObservation()
		if !ok || last.alpn != "http/1.1" {
			return fmt.Errorf("backend SNI and ALPN: last observation %+v (ok=%v), want ALPN http/1.1", last, ok)
		}
		return nil
	}
	if err := transition(templatePath, normalizer, before, after, nil, nil, tlsProbe, nil); err != nil {
		secure.shutdown()
		return fmt.Errorf("case %q: %w", "backend SNI and ALPN", err)
	}
	passed = append(passed, "backend SNI and ALPN")

	for _, verifyCase := range []struct {
		hostname string
		status   int
	}{
		{"backend.example.test", 200},
		{"wrong.example.test", 503},
	} {
		hostname, expectedStatus := verifyCase.hostname, verifyCase.status
		after := before
		after.serverOptions = fmt.Sprintf("verify required ca-file %s verifyhost %s sni str(%s) alpn http/1.1",
			certPath, hostname, hostname)
		verifyProbe := func(root, _ string) error {
			status, body, err := request(root)
			if err != nil {
				return err
			}
			if status != expectedStatus {
				return fmt.Errorf("certificate verification %s: want status %d got (%d, %q)",
					hostname, expectedStatus, status, body)
			}
			return nil
		}
		label := "certificate verification " + hostname
		if err := transition(templatePath, normalizer, before, after, nil, nil, verifyProbe, nil); err != nil {
			secure.shutdown()
			return fmt.Errorf("case %q: %w", label, err)
		}
		passed = append(passed, label)
	}
	secure.shutdown()

	out, err := json.Marshal(struct {
		SettingsPassed        []string `json:"settings_passed"`
		TotalWithTLSPortCases int      `json:"total_with_tls_port_cases"`
	}{SettingsPassed: passed, TotalWithTLSPortCases: len(passed) + 4})
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func main() {
	templatePath := flag.String("template", "", "path to haproxy-state-dump.sh.j2 (required)")
	defaultNormalizer := os.Getenv("AGENT_BIN")
	if defaultNormalizer == "" {
		defaultNormalizer = "/usr/local/sbin/easy-ha-proxy-agent"
	}
	normalizer := flag.String("normalizer", defaultNormalizer, "path to the state normalizer agent")
	flag.Parse()
	if *templatePath == "" {
		fmt.Fprintln(os.Stderr, "server-state-smoke: --template is required")
		os.Exit(2)
	}
	if err := settingsCases(*templatePath, *normalizer); err != nil {
		fmt.Fprintln(os.Stderr, "server-state-smoke:", err)
		os.Exit(1)
	}
}
