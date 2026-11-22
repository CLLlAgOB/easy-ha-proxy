package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/alerts"
)

func TestNormalizeServerStateParity(t *testing.T) {
	header := "# " + strings.Join(serverStateFields, " ")
	// srv_admin_state=65 (0x40 FQDN_CHANGED | 0x01 MAINT), srv_op_state=0 (down)
	row := "1 be_app 1 srv1 10.0.0.5 0 65 1 1 12 6 2 0 14 0 0 0 old.local 8080 -"
	state := "1\n" + header + "\n" + row + "\n"
	cfg := "backend be_app\n  server srv1 10.0.0.99:9090\n"

	out, err := NormalizeServerState(state, cfg, true)
	if err != nil {
		t.Fatalf("NormalizeServerState: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %s", len(lines), out)
	}
	cols := strings.Fields(lines[2])
	// IP updated to 10.0.0.99, port updated to 9090, 0x40 cleared -> admin_state=1 (MAINT kept!),
	// op_state reset to 2 because no check/agent-check in config.
	if cols[4] != "10.0.0.99" || cols[18] != "9090" || cols[6] != "1" || cols[5] != "2" || cols[17] != "-" {
		t.Fatalf("unexpected normalized row: %v", cols)
	}

	// Reject malformed numeric field.
	badRow := "1 be_app 1 srv1 10.0.0.5 NOTNUM 0 1 1 12 6 2 0 14 0 0 0 - 80 -"
	if _, err := NormalizeServerState("1\n"+header+"\n"+badRow+"\n", "", false); err == nil {
		t.Fatal("expected error for non-decimal field")
	}
}

func TestRunBackupScheduledExitCodes(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "backupd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	reply := `{"ok":true,"backup_id":"abc","uploads":["nas"]}`
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte(reply + "\n"))
			}(c)
		}
	}()

	var out, errBuf bytes.Buffer
	rc := RunBackupScheduled(context.Background(), sock, 5*time.Second, &out, &errBuf)
	if rc != 0 || !strings.Contains(out.String(), "backup abc copied to 1 destination(s)") {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errBuf.String())
	}
}

func TestUnitFailedJournalFilteringAndAlertDelivery(t *testing.T) {
	journal := strings.Join([]string{
		`{"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Failed with result exit-code"}`,
		`{"SYSLOG_IDENTIFIER":"backup-run","MESSAGE":[1,2,3]}`,
		`{"SYSLOG_IDENTIFIER":"backup-run","MESSAGE":"disk full on target"}`,
	}, "\n")
	words := ParseJournalLastWords(journal)
	if words != "disk full on target" {
		t.Fatalf("unexpected journal words: %q", words)
	}

	// Unknown unit exits 0 without touching alertd.
	if rc := RunUnitFailed(context.Background(), "cups.service", UnitFailedOptions{}); rc != 0 {
		t.Fatalf("expected exit 0 for unknown unit, got %d", rc)
	}

	// Known unit delivers backup.failed event to alertd.
	sock := filepath.Join(t.TempDir(), "alertd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var got alerts.Observation
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	rc := RunUnitFailed(context.Background(), "easy-ha-proxy-backup.service", UnitFailedOptions{
		Alerts:       alerts.NewClient(sock, "tok-1"),
		SystemctlBin: "/nonexistent/systemctl",
		Journalctl:   "/nonexistent/journalctl",
	})
	if rc != 0 || got.Rule != "backup.failed" || got.Subject != "easy-ha-proxy-backup.service" {
		t.Fatalf("rc=%d got=%+v", rc, got)
	}
}
