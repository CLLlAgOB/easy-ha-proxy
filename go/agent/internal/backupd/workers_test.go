package backupd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBackupEncryptInspectAndScheduledRun(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary not available")
	}
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "sample-etc")
	_ = os.MkdirAll(srcDir, 0o755)
	_ = os.WriteFile(filepath.Join(srcDir, "haproxy.cfg"), []byte("global\n  daemon\n"), 0o644)

	opts := Options{
		SpoolRoot:         filepath.Join(dir, "spool"),
		OperationLockPath: filepath.Join(dir, "op.lock"),
		MinFreeBytes:      1024,
		LowSpaceBytes:     2048,
		ListLimit:         50,
	}
	svc, err := NewService(opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.BackupRoots = []string{srcDir}

	// Scheduled run skips cleanly when disabled.
	res, err := svc.Dispatch(context.Background(), map[string]any{"action": "run_scheduled"})
	if err != nil || res["skipped"] == "" {
		t.Fatalf("expected skipped scheduled run, got %+v err=%v", res, err)
	}

	// Create encrypted backup archive.
	res, err = svc.Dispatch(context.Background(), map[string]any{
		"action": "start_backup", "passphrase": "strong-test-passphrase", "include_ssh": false, "quiesce": false,
	})
	if err != nil || res["ok"] != true {
		t.Fatalf("start_backup failed: %+v err=%v", res, err)
	}

	// List local backups and inspect the created archive with the same passphrase.
	st, _ := svc.Dispatch(context.Background(), map[string]any{"action": "status"})
	backups := st["backups"].([]map[string]any)
	if len(backups) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(backups))
	}
	bid := backups[0]["id"].(string)

	insp, err := svc.Dispatch(context.Background(), map[string]any{
		"action": "start_inspect", "upload_id": bid, "passphrase": "strong-test-passphrase",
	})
	if err != nil || insp["ok"] != true {
		t.Fatalf("start_inspect failed: %+v err=%v", insp, err)
	}
	job := insp["job"].(map[string]any)
	if job["files"].(int) != 1 {
		t.Fatalf("expected 1 inspected file, got %+v", job)
	}

	// Wrong passphrase fails cleanly.
	if _, err := svc.Dispatch(context.Background(), map[string]any{
		"action": "start_inspect", "upload_id": bid, "passphrase": "wrong-passphrase",
	}); err == nil {
		t.Fatal("expected inspect with wrong passphrase to fail")
	}
}
