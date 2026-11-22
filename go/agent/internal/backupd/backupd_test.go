package backupd

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/unixrpc"
)

func TestBackupdProtocolWhitelistStorageAndStaleRecovery(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		SocketPath:      filepath.Join(dir, "backupd.sock"),
		SpoolRoot:       filepath.Join(dir, "spool"),
		RebootMarker:    filepath.Join(dir, "reboot.json"),
		AppUID:          os.Getuid(),
		MaxRequestBytes: 64 * 1024,
		MinFreeBytes:    1024,
		LowSpaceBytes:   2048,
		ListLimit:       50,
		MaxConnections:  8,
	}

	// Seed a stale running job before NewService starts.
	jobsDir := filepath.Join(opts.SpoolRoot, "jobs")
	_ = os.MkdirAll(jobsDir, 0o750)
	staleID := strings.Repeat("a", 32)
	_ = os.WriteFile(filepath.Join(jobsDir, staleID+".json"), []byte(`{"id":"`+staleID+`","status":"running"}`), 0o600)

	// Seed a local backup archive.
	backupsDir := filepath.Join(opts.SpoolRoot, "backups")
	_ = os.MkdirAll(backupsDir, 0o750)
	bid := strings.Repeat("b", 32)
	_ = os.WriteFile(filepath.Join(backupsDir, bid+ArchiveSuffix), []byte("encrypted-data"), 0o600)

	svc, err := NewService(opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	srv := unixrpc.NewServer(opts.AppUID, opts.MaxRequestBytes, 1024*1024, opts.MaxConnections, svc.Dispatch)
	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	call := func(payload map[string]any) map[string]any {
		t.Helper()
		conn, err := net.Dial("unix", opts.SocketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		b, _ := json.Marshal(payload)
		_, _ = conn.Write(append(b, '\n'))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(line), &out)
		return out
	}

	// Unexpected field rejected.
	if res := call(map[string]any{"action": "status", "evil": 1}); res["ok"] != false {
		t.Fatalf("expected unexpected field rejection, got %+v", res)
	}

	// Status shows stale job recovered to interrupted and local backup present.
	st := call(map[string]any{"action": "status", "job_id": staleID})
	if st["ok"] != true {
		t.Fatalf("status failed: %+v", st)
	}
	job := st["job"].(map[string]any)
	if job["status"] != "interrupted" {
		t.Fatalf("expected stale job recovered to interrupted, got %+v", job)
	}
	if len(st["backups"].([]any)) != 1 {
		t.Fatalf("expected 1 backup, got %+v", st["backups"])
	}

	// Save destination redacts secrets and preserves them on "***".
	saved := call(map[string]any{
		"action": "destination_save", "name": "nas", "type": "sftp",
		"host": "10.0.0.2", "private_key": "SECRET-KEY",
	})
	if saved["ok"] != true || saved["destination"].(map[string]any)["private_key"] != "***" {
		t.Fatalf("destination_save: %+v", saved)
	}

	// Delete local backup succeeds, then second delete returns not_found.
	if res := call(map[string]any{"action": "delete", "kind": "backup", "id": bid}); res["ok"] != true {
		t.Fatalf("delete backup failed: %+v", res)
	}
	if res := call(map[string]any{"action": "delete", "kind": "backup", "id": bid}); res["error_code"] != "not_found" {
		t.Fatalf("expected not_found on second delete, got %+v", res)
	}
}
