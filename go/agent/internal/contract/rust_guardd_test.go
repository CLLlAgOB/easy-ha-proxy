package contract

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The Rust guardd-core daemon and parser, driven from outside. The daemon
// tests start the real binary against fake HAProxy and alert sockets: it
// must drain an active request on SIGTERM and keep answering its API while
// HAProxy or the alert engine block. The parser test replays access lines
// whose expected fields the Python guardd, the reference the Rust port
// matched field for field, recorded before it was removed.

const guarddSignatures = "ansible/roles/haproxy-admin/files/scanner-signatures.json"
const guarddVectors = ".tests/fixtures/guardd_parse_vectors.json"

func guarddBinary(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("GUARDD_RUST_BIN"); env != "" {
		if fi, err := os.Stat(env); err == nil && !fi.IsDir() {
			return env
		}
	}
	root := repoRoot(t)
	for _, rel := range []string{"rust/guardd/target/release/guardd-core", "rust/guardd/target/debug/guardd-core"} {
		p := filepath.Join(root, rel)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	t.Skip("guardd-core binary was not built")
	return ""
}

func guarddSocketGroup(t *testing.T) string {
	t.Helper()
	g, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Skipf("no group entry for gid %d: %v", os.Getegid(), err)
	}
	return g.Name
}

// daemonProc is the running daemon; done closes when it exits, so both the
// wait and the cleanup can read the outcome.
type daemonProc struct {
	cmd  *exec.Cmd
	err  error
	done chan struct{}
}

// startGuardd runs the daemon against a config file.
func startGuardd(t *testing.T, root, config string, extraEnv ...string) *daemonProc {
	t.Helper()
	bin := guarddBinary(t)
	configPath := filepath.Join(root, "guard.json")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve", "--config", configPath,
		"--socket", filepath.Join(root, "api.sock"),
		"--database", filepath.Join(root, "security.db"),
		"--signatures", filepath.Join(repoRoot(t), guarddSignatures))
	cmd.Env = append(os.Environ(), "GUARDD_SOCKET_GROUP="+guarddSocketGroup(t),
		"GUARDD_TOKEN=local-test-token", "ALERTD_TOKEN=")
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &daemonProc{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p
}

func killIfRunning(p *daemonProc) {
	select {
	case <-p.done:
	default:
		p.cmd.Process.Kill()
		<-p.done
	}
}

func waitExit(t *testing.T, p *daemonProc, timeout time.Duration) {
	t.Helper()
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("the daemon exited with %v", p.err)
		}
		if code := p.cmd.ProcessState.ExitCode(); code != 0 {
			t.Fatalf("the daemon exited %d", code)
		}
	case <-time.After(timeout):
		p.cmd.Process.Kill()
		<-p.done
		t.Fatal("the daemon did not exit in time")
	}
}

func stillRunning(t *testing.T, p *daemonProc) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatalf("the daemon exited early: %v", p.err)
	default:
	}
}

func unixListener(t *testing.T, path string, timeout time.Duration) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetDeadline(time.Now().Add(timeout))
	t.Cleanup(func() { ln.Close() })
	return ln
}

func accept(t *testing.T, ln net.Listener, timeout time.Duration) net.Conn {
	t.Helper()
	ln.(*net.UnixListener).SetDeadline(time.Now().Add(timeout))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(timeout))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func dial(t *testing.T, path string, timeout time.Duration) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(timeout))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func recv(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	read, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return buf[:read]
}

func send(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
}

func waitForPath(t *testing.T, path string, exists bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		if (err == nil) == exists {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s did not become present=%v in time", path, exists)
}

const guarddTable = "# table: tbl_ban, type: ip, size:1024, used:0\n"

func TestGuarddDrainsAnActiveRequestOnSigterm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux Unix sockets")
	}
	root := t.TempDir()
	runtimeSock := filepath.Join(root, "runtime.sock")
	api := filepath.Join(root, "api.sock")
	if err := os.WriteFile(filepath.Join(root, "access.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	config := `{"mode":"monitor","sources":{"haproxy_socket":"` + runtimeSock +
		`","log_file":"` + filepath.Join(root, "access.log") + `"}}`
	ln := unixListener(t, runtimeSock, 6*time.Second)
	p := startGuardd(t, root, config)
	defer killIfRunning(p)

	poll := accept(t, ln, 3*time.Second)
	if got := strings.TrimSpace(string(recv(t, poll, 256))); got != "show table" {
		t.Fatalf("first poll %q", got)
	}
	waitForPath(t, api, true, 6*time.Second)
	fi, err := os.Stat(api)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("api socket mode %v", fi.Mode())
	}

	health := dial(t, api, 2*time.Second)
	send(t, health, "GET /api/v1/guard/health HTTP/1.0\r\n\r\n")
	if got := recv(t, health, 256); !strings.Contains(string(got), "200 OK") {
		t.Fatalf("health: %q", got)
	}
	bad := dial(t, api, 2*time.Second)
	send(t, bad, "POST /api/v1/guard/mode HTTP/1.0\r\nContent-Length: 5\r\n\r\n")
	if got := recv(t, bad, 256); !strings.Contains(string(got), "403 Forbidden") {
		t.Fatalf("mode without token: %q", got)
	}
	idle := dial(t, api, 2*time.Second)
	send(t, idle, "GET ")
	active := dial(t, api, 2*time.Second)
	send(t, active, "GET /api/v1/guard/live?banned=1 HTTP/1.0\r\n\r\n")
	reply := accept(t, ln, 3*time.Second)
	if got := strings.TrimSpace(string(recv(t, reply, 256))); got != "show table tbl_ban" {
		t.Fatalf("live poll %q", got)
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitForPath(t, api, false, 3*time.Second)
	poll.Close()
	stillRunning(t, p)
	send(t, reply, guarddTable)
	reply.Close()
	active.SetDeadline(time.Now().Add(2 * time.Second))
	if got := recv(t, active, 256); !strings.Contains(string(got), "200 OK") {
		t.Fatalf("the active request was not drained: %q", got)
	}
	idle.SetDeadline(time.Now().Add(2 * time.Second))
	if got := recv(t, idle, 16); len(got) != 0 {
		t.Fatalf("the idle connection got %q", got)
	}
	waitExit(t, p, 3*time.Second)
}

func TestGuarddAPIRespondsWhileEnforcementIOIsBlocked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux Unix sockets")
	}
	root := t.TempDir()
	runtimeSock := filepath.Join(root, "runtime.sock")
	api := filepath.Join(root, "api.sock")
	if err := os.WriteFile(filepath.Join(root, "access.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	config := `{"mode":"enforce","poll_interval_seconds":1,"sources":{"haproxy_socket":"` + runtimeSock +
		`","log_file":"` + filepath.Join(root, "access.log") + `"}}`
	ln := unixListener(t, runtimeSock, 6*time.Second)
	p := startGuardd(t, root, config)
	defer killIfRunning(p)

	// 1. read_tables: "show table"
	c1 := accept(t, ln, 3*time.Second)
	if got := strings.TrimSpace(string(recv(t, c1, 256))); got != "show table" {
		t.Fatalf("c1 %q", got)
	}
	send(t, c1, guarddTable)
	c1.Close()
	// 2. read_tables: "show table tbl_ban"
	c2 := accept(t, ln, 3*time.Second)
	if got := strings.TrimSpace(string(recv(t, c2, 256))); got != "show table tbl_ban" {
		t.Fatalf("c2 %q", got)
	}
	send(t, c2, guarddTable)
	c2.Close()
	// 3. apply_enforcement: "show table tbl_ban" (active_bans) -- hold open.
	blocked := accept(t, ln, 3*time.Second)
	if got := strings.TrimSpace(string(recv(t, blocked, 256))); got != "show table tbl_ban" {
		t.Fatalf("blocked %q", got)
	}
	waitForPath(t, api, true, 6*time.Second)

	// While enforcement HAProxy I/O is blocked, API read endpoints must
	// answer immediately without waiting for enforcement.
	for _, path := range []string{"/api/v1/guard/health", "/api/v1/guard/reputation", "/api/v1/guard/bans/schedule"} {
		started := time.Now()
		stream := dial(t, api, time.Second)
		send(t, stream, "GET "+path+" HTTP/1.0\r\n\r\n")
		reply := recv(t, stream, 512)
		elapsed := time.Since(started)
		if !strings.Contains(string(reply), "200 OK") {
			t.Errorf("%s failed: %q", path, reply)
		}
		if elapsed >= time.Second {
			t.Errorf("%s took %s while enforcement blocked", path, elapsed)
		}
	}
	send(t, blocked, guarddTable)
	blocked.Close()
	p.cmd.Process.Signal(syscall.SIGTERM)
	waitExit(t, p, 5*time.Second)
}

func TestGuarddAPIRespondsWhileAlertdIOIsBlocked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux Unix sockets")
	}
	root := t.TempDir()
	missingRuntime := filepath.Join(root, "missing-runtime.sock")
	alertSock := filepath.Join(root, "alertd.sock")
	api := filepath.Join(root, "api.sock")
	if err := os.WriteFile(filepath.Join(root, "access.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	config := `{"mode":"monitor","poll_interval_seconds":1,"sources":{"haproxy_socket":"` + missingRuntime +
		`","log_file":"` + filepath.Join(root, "access.log") + `"}}`
	alertLn := unixListener(t, alertSock, 20*time.Second)
	p := startGuardd(t, root, config,
		"ALERTD_SOCKET_PATH="+alertSock, "ALERTD_TOKEN=alert-test-token")
	defer killIfRunning(p)

	// Wait for the engine_failing alert after consecutive poll failures,
	// then hold the connection open.
	stalled := accept(t, alertLn, 20*time.Second)
	stalled.SetDeadline(time.Now().Add(3 * time.Second))
	req := recv(t, stalled, 4096)
	if !strings.Contains(string(req), "security.engine_failing") {
		t.Fatalf("no engine_failing alert: %q", req)
	}
	started := time.Now()
	stream := dial(t, api, time.Second)
	send(t, stream, "GET /api/v1/guard/health HTTP/1.0\r\n\r\n")
	reply := recv(t, stream, 512)
	elapsed := time.Since(started)
	if !strings.Contains(string(reply), "200 OK") {
		t.Fatalf("health while alertd blocked: %q", reply)
	}
	if elapsed >= time.Second {
		t.Fatalf("health took %s while alertd blocked", elapsed)
	}
	send(t, stalled, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
	stalled.Close()
	p.cmd.Process.Signal(syscall.SIGTERM)
	waitExit(t, p, 5*time.Second)
}

func TestGuarddAPIAnswersWithoutWaitingOutANap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux Unix sockets")
	}
	// The accept loop slept 25 ms whenever no connection was waiting, so a
	// request that came after the previous answer waited out a whole nap.
	root := t.TempDir()
	api := filepath.Join(root, "api.sock")
	if err := os.WriteFile(filepath.Join(root, "access.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	config := `{"mode":"monitor","poll_interval_seconds":60,"sources":{"haproxy_socket":"` +
		filepath.Join(root, "missing.sock") + `","log_file":"` + filepath.Join(root, "access.log") + `"}}`
	p := startGuardd(t, root, config)
	defer killIfRunning(p)
	waitForPath(t, api, true, 20*time.Second)

	ask := func() time.Duration {
		started := time.Now()
		stream := dial(t, api, 2*time.Second)
		send(t, stream, "GET /api/v1/guard/health HTTP/1.0\r\n\r\n")
		reply, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(reply), "200 OK") {
			t.Fatalf("health: %q", reply)
		}
		return time.Since(started)
	}
	ask()
	var times []time.Duration
	for i := 0; i < 20; i++ {
		times = append(times, ask())
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := times[len(times)/2]
	if median >= 10*time.Millisecond {
		t.Fatalf("median ask %s: %v", median, times)
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	waitExit(t, p, 5*time.Second)
}

func TestGuarddParserMatchesTheRecordedReference(t *testing.T) {
	bin := guarddBinary(t)
	var fixture struct {
		Cases []struct {
			Line         string         `json:"line"`
			Parsed       map[string]any `json:"parsed"`
			PathCategory any            `json:"path_category"`
			UAToken      any            `json:"ua_token"`
			UACategory   any            `json:"ua_category"`
		} `json:"cases"`
	}
	if err := json.Unmarshal([]byte(read(t, guarddVectors)), &fixture); err != nil {
		t.Fatal(err)
	}
	var input strings.Builder
	for _, c := range fixture.Cases {
		input.WriteString(c.Line)
		input.WriteString("\n")
	}
	cmd := exec.Command(bin, "parse", "--signatures", filepath.Join(repoRoot(t), guarddSignatures))
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if len(rows) != len(fixture.Cases) {
		t.Fatalf("%d rows for %d cases", len(rows), len(fixture.Cases))
	}
	for i, c := range fixture.Cases {
		row := rows[i]
		rowParsed, _ := row["parsed"].(map[string]any)
		if !reflect.DeepEqual(rowParsed, c.Parsed) {
			label := c.Line
			if len(label) > 80 {
				label = label[:80]
			}
			t.Errorf("case %d (%s): parsed %v, want %v", i, label, rowParsed, c.Parsed)
			continue
		}
		if c.Parsed != nil {
			if !reflect.DeepEqual(row["path_category"], c.PathCategory) {
				t.Errorf("case %d: path_category %v, want %v", i, row["path_category"], c.PathCategory)
			}
			if !reflect.DeepEqual(row["ua_token"], c.UAToken) {
				t.Errorf("case %d: ua_token %v, want %v", i, row["ua_token"], c.UAToken)
			}
			if !reflect.DeepEqual(row["ua_category"], c.UACategory) {
				t.Errorf("case %d: ua_category %v, want %v", i, row["ua_category"], c.UACategory)
			}
		}
	}
}
