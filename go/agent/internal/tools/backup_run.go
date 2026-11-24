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

	var d net.Dialer
	d.Timeout = 10 * time.Second
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		fmt.Fprintf(stderr, "the backup daemon is unreachable: %v\n", err)
		return 2
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, `{"action":"run_scheduled"}`+"\n"); err != nil {
		fmt.Fprintf(stderr, "the backup daemon is unreachable: %v\n", err)
		return 2
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	raw, err := io.ReadAll(io.LimitReader(conn, maxBackupRunRespBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "the backup daemon is unreachable: %v\n", err)
		return 2
	}
	if len(raw) > maxBackupRunRespBytes {
		fmt.Fprintln(stderr, "the backup daemon returned an oversized answer")
		return 2
	}

	var answer map[string]any
	if err := json.Unmarshal(raw, &answer); err != nil || answer == nil {
		fmt.Fprintln(stderr, "the backup daemon returned an unreadable answer")
		return 2
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
