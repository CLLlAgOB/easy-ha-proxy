package updated

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStartCheckAndStartApplyWithProgressAndLock(t *testing.T) {
	dir := t.TempDir()
	fakeCLI := filepath.Join(dir, "fake-cli.sh")
	_ = os.WriteFile(fakeCLI, []byte(`#!/bin/sh
if [ "$2" = "--check" ]; then
  echo '{"updates_available":true,"components":["daemons"]}'
  exit 0
fi
echo "=== Applying component: daemons ==="
echo "EHP-PROGRESS phase=playbook"
echo "EHP-PROGRESS 4/4 Restart services"
exit 0
`), 0o755)

	txState := filepath.Join(dir, "tx.json")
	opts := Options{
		StateRoot:               filepath.Join(dir, "state"),
		CLIPath:                 fakeCLI,
		MaintenanceLockPath:     filepath.Join(dir, "maint.lock"),
		HAProxyTransactionState: txState,
		RebootMarker:            filepath.Join(dir, "reboot.json"),
		ListLimit:               30,
	}
	svc, err := NewService(opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Active HAProxy transaction blocks update checks.
	_ = os.WriteFile(txState, []byte(`{"state":"pending_confirmation"}`), 0o600)
	if _, err := svc.Dispatch(context.Background(), map[string]any{"action": "start_check"}); err == nil {
		t.Fatal("active HAProxy transaction must block start_check")
	}
	_ = os.Remove(txState)

	// start_check succeeds and produces a plan_id.
	chk, err := svc.Dispatch(context.Background(), map[string]any{"action": "start_check"})
	if err != nil || chk["ok"] != true {
		t.Fatalf("start_check failed: %+v err=%v", chk, err)
	}
	planID := chk["plan"].(map[string]any)["plan_id"].(string)

	// start_apply validates plan_id & components, runs CLI, and parses EHP-PROGRESS.
	app, err := svc.Dispatch(context.Background(), map[string]any{
		"action": "start_apply", "plan_id": planID, "components": []any{"daemons"},
	})
	if err != nil || app["ok"] != true {
		t.Fatalf("start_apply failed: %+v err=%v", app, err)
	}
	job := app["job"].(map[string]any)
	prog := job["progress"].(Progress)
	if prog.Phase != "playbook" || prog.Done != 4 || prog.Total != 4 {
		t.Fatalf("unexpected apply progress: %+v", prog)
	}
}
