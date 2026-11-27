package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// Alert history survives the update from the Python alertd to the agent.
// Gateways on 1.1.x run the Python alertd; the update moves them to the
// agent on the same alerts.db. The fixture is a real alerts.db the Python
// alertd of release 1.1.3 wrote (two alerts, one acknowledged, one muted);
// the agent must show both as they were, add an event of its own, and keep
// all of it across a restart. The fixture is generated once by
// dev-tools/gen_alertd_fixture.sh, so CI needs no Python.

const alertdToken = "upgrade-rollback-token"

func alertdClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
		Timeout: 10 * time.Second,
	}
}

func alertdCall(t *testing.T, sock, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, "http://unix"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Alertd-Token", alertdToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := alertdClient(sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	data := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			t.Fatalf("%s %s: %v (%s)", method, path, err, raw)
		}
	}
	return resp.StatusCode, data
}

func alertdAlerts(t *testing.T, sock string) map[string]map[string]any {
	t.Helper()
	status, state := alertdCall(t, sock, "GET", "/api/v1/alerts/state?limit=100", nil)
	if status != 200 {
		t.Fatalf("state: %d %v", status, state)
	}
	found := map[string]map[string]any{}
	for _, key := range []string{"open", "active"} {
		rows, _ := state[key].([]any)
		for _, r := range rows {
			row, ok := r.(map[string]any)
			if !ok {
				continue
			}
			found[row["rule"].(string)+"|"+row["subject"].(string)] = row
		}
	}
	return found
}

func alertdHistory(t *testing.T, sock string) []any {
	t.Helper()
	status, data := alertdCall(t, sock, "GET", "/api/v1/alerts/history?limit=500", nil)
	if status != 200 {
		t.Fatalf("history: %d %v", status, data)
	}
	if events, ok := data["events"].([]any); ok {
		return events
	}
	events, _ := data["history"].([]any)
	return events
}

// startAlertd runs the agent's alertd and waits for its health endpoint.
func startAlertd(t *testing.T, root, sock, bin string, env []string) *daemonProc {
	t.Helper()
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "alertd")
	cmd.Env = append(os.Environ(), env...)
	log, err := os.Create(filepath.Join(root, "alertd.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &daemonProc{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); log.Close(); close(p.done) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			raw, _ := os.ReadFile(filepath.Join(root, "alertd.log"))
			t.Fatalf("alertd did not start:\n%s", raw)
		default:
		}
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write([]byte("GET /api/v1/alerts/health HTTP/1.0\r\nX-Alertd-Token: " + alertdToken + "\r\n\r\n"))
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			conn.Close()
			if bytes.Contains(buf[:n], []byte("200")) {
				return p
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	killIfRunning(p)
	raw, _ := os.ReadFile(filepath.Join(root, "alertd.log"))
	t.Fatalf("alertd health not ready:\n%s", raw)
	return nil
}

func alertdStop(t *testing.T, p *daemonProc) {
	t.Helper()
	p.cmd.Process.Signal(syscall.SIGTERM)
	waitExit(t, p, 10*time.Second)
}

func TestAlertdUpgradeKeepsPythonHistory(t *testing.T) {
	bin := os.Getenv("AGENT_BIN")
	if bin == "" {
		t.Skip("AGENT_BIN not set")
	}
	if fi, err := os.Stat(bin); err != nil || fi.IsDir() {
		t.Skip("AGENT_BIN is not a binary")
	}
	var expected struct {
		Alerts       map[string]map[string]any `json:"alerts"`
		EventsBefore int                       `json:"events_before"`
		MutedUntil   any                       `json:"muted_until"`
	}
	if err := json.Unmarshal([]byte(read(t, "go/agent/internal/contract/testdata/alertd_python_expected.json")), &expected); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "alerts"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join(repoRoot(t), "go", "agent", "internal", "contract", "testdata", "alertd_python_1_1_3.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "alerts", "alerts.db"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(root, "alertd.sock")
	env := []string{
		"ALERTD_SOCKET_PATH=" + sock,
		"ALERTD_SOCKET_GROUP=" + guarddSocketGroup(t),
		"ALERTD_DATABASE=" + filepath.Join(root, "alerts", "alerts.db"),
		"ALERTD_CONFIG=" + filepath.Join(root, "alertd.json"),
		"ALERTD_TOKEN=" + alertdToken,
		"ALERTD_MAIL_STATE=" + filepath.Join(root, "mail-notify.json"),
		"ALERTD_MAIL_LOCK=" + filepath.Join(root, "mail.lock"),
		"ALERTD_GATEWAY_NAME=gw.example.test",
	}

	// The Go agent sees both alerts exactly as Python left them.
	p := startAlertd(t, root, sock, bin, env)
	seen := alertdAlerts(t, sock)
	for _, key := range []string{"backup.failed|nightly", "site.down|app.example.test"} {
		row, ok := seen[key]
		if !ok {
			t.Fatalf("%s missing from %v", key, seen)
		}
		for _, field := range []string{"state", "acknowledged_ts", "acknowledged_by", "muted_until", "first_seen_ts"} {
			if !reflect.DeepEqual(row[field], expected.Alerts[key][field]) {
				t.Errorf("%s %s: %v, want %v", key, field, row[field], expected.Alerts[key][field])
			}
		}
	}
	if seen["backup.failed|nightly"]["acknowledged_by"] != "ops" {
		t.Error("the acknowledgement was lost")
	}
	if !reflect.DeepEqual(seen["site.down|app.example.test"]["muted_until"], expected.MutedUntil) {
		t.Error("the mute was lost")
	}
	if got := len(alertdHistory(t, sock)); got != expected.EventsBefore {
		t.Fatalf("the Go agent does not show the Python history: %d, want %d", got, expected.EventsBefore)
	}
	if status, _ := alertdCall(t, sock, "POST", "/api/v1/alerts/notify",
		map[string]any{"rule": "backup.failed", "subject": "weekly"}); status != 200 {
		t.Fatalf("notify: %d", status)
	}
	eventsGo := len(alertdHistory(t, sock))
	alertdStop(t, p)

	// Restarted, the agent keeps everything, including its own event.
	p = startAlertd(t, root, sock, bin, env)
	defer killIfRunning(p)
	again := alertdAlerts(t, sock)
	if _, ok := again["backup.failed|weekly"]; !ok {
		t.Fatalf("the agent's own event was lost: %v", again)
	}
	if again["backup.failed|nightly"]["acknowledged_by"] != "ops" {
		t.Error("the acknowledgement was lost on restart")
	}
	if !reflect.DeepEqual(again["site.down|app.example.test"]["muted_until"], expected.MutedUntil) {
		t.Error("the mute was lost on restart")
	}
	if got := len(alertdHistory(t, sock)); got != eventsGo {
		t.Fatalf("a restarted agent lost history: %d, want %d", got, eventsGo)
	}
	alertdStop(t, p)
}
