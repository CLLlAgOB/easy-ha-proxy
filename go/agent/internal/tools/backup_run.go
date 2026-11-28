package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBackupdSocket  = "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock"
	maxBackupRunRespBytes = 1024 * 1024
)

// RunBackupScheduled asks backupd to run the scheduled copy and returns exact exit codes (0/1/2).
func RunBackupScheduled(ctx context.Context, socketPath string, timeout time.Duration, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = strings.TrimSpace(os.Getenv("BACKUPD_SOCKET_PATH"))
	}
	if socketPath == "" {
		socketPath = defaultBackupdSocket
	}
	if timeout <= 0 {
		secs := 8 * 3600
		if raw := strings.TrimSpace(os.Getenv("BACKUPD_SCHEDULED_TIMEOUT")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				secs = n
			}
		}
		timeout = time.Duration(secs) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	answer, err := backupRunRequest(ctx, socketPath, map[string]string{"action": "run_scheduled"})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if answer["ok"] == true && answer["status"] == "queued" {
		id, _ := answer["job_id"].(string)
		answer, err = waitBackupRun(ctx, socketPath, id)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	if skipped, ok := answer["skipped"].(string); ok && skipped != "" {
		fmt.Fprintln(stdout, skipped)
		return 0
	}
	if okVal, _ := answer["ok"].(bool); okVal {
		bid, _ := answer["backup_id"].(string)
		uploads, _ := answer["uploads"].([]any)
		fmt.Fprintf(stdout, "backup %s copied to %d destination(s)\n", bid, len(uploads))
		return 0
	}
	if errs, ok := answer["errors"].([]any); ok && len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(stderr, e)
		}
	} else {
		msg, _ := answer["error"].(string)
		if msg == "" {
			msg = "unknown"
		}
		fmt.Fprintln(stderr, msg)
	}
	return 1
}

func backupRunRequest(ctx context.Context, socketPath string, request map[string]string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("the backup daemon is unreachable: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, fmt.Errorf("the backup daemon is unreachable: %w", err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		return nil, fmt.Errorf("the backup daemon is unreachable: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, maxBackupRunRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("the backup daemon is unreachable: %w", err)
	}
	if len(raw) > maxBackupRunRespBytes {
		return nil, fmt.Errorf("the backup daemon returned an oversized answer")
	}
	var answer map[string]any
	if err := json.Unmarshal(raw, &answer); err != nil || answer == nil {
		return nil, fmt.Errorf("the backup daemon returned an unreadable answer")
	}
	return answer, nil
}

func waitBackupRun(ctx context.Context, socketPath, id string) (map[string]any, error) {
	if id == "" {
		return nil, fmt.Errorf("the backup daemon did not return a job ID")
	}
	request := map[string]string{"action": "job_status", "job_id": id}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		answer, err := backupRunRequest(ctx, socketPath, request)
		if err != nil {
			return nil, err
		}
		if answer["ok"] != true {
			return answer, nil
		}
		job, _ := answer["job"].(map[string]any)
		switch job["status"] {
		case "completed", "failed", "interrupted":
			outcome, _ := job["output"].(map[string]any)
			if outcome == nil {
				outcome = map[string]any{}
			}
			outcome["ok"] = job["status"] == "completed"
			outcome["error"] = job["error"]
			return outcome, nil
		case "queued", "running":
		default:
			return nil, fmt.Errorf("the backup daemon returned an unknown job status")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for backup job %s: %w", id, ctx.Err())
		case <-ticker.C:
		}
	}
}
