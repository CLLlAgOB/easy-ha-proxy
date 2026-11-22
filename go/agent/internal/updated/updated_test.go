package updated

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

func TestParseProgressScopedToLatestComponent(t *testing.T) {
	logText := strings.Join([]string{
		"=== Applying component: daemons ===",
		"EHP-PROGRESS phase=playbook",
		"EHP-PROGRESS 9/10 Old daemon task",
		"=== Applying component: os ===",
		"EHP-PROGRESS phase=prepare",
		"EHP-PROGRESS 2/5 Install security upgrades",
	}, "\n")
	p := ParseProgress(logText)
	if p.Phase != "prepare" || p.Done != 2 || p.Total != 5 || p.Task != "Install security upgrades" {
		t.Fatalf("unexpected progress: %+v", p)
	}
}

func TestUpdatedBrokerSettingsRebootAndSSHValidation(t *testing.T) {
	dir := t.TempDir()
	fakeShutdown := filepath.Join(dir, "fake-shutdown.sh")
	_ = os.WriteFile(fakeShutdown, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	bootFile := filepath.Join(dir, "boot_id")
	bootUUID := "11111111-2222-3333-4444-555555555555"
	_ = os.WriteFile(bootFile, []byte(bootUUID+"\n"), 0o644)
	srcDir := filepath.Join(dir, "source")
	_ = os.MkdirAll(srcDir, 0o755)
	_ = os.WriteFile(filepath.Join(srcDir, "VERSION"), []byte("2.5.0-alpha\n"), 0o644)

	opts := Options{
		SocketPath:               filepath.Join(dir, "updated.sock"),
		StateRoot:                filepath.Join(dir, "state"),
		SourceDir:                srcDir,
		RebootMarker:             filepath.Join(dir, "reboot.json"),
		SSHProtectionMonitorPath: filepath.Join(dir, "state", "ssh-monitor.json"),
		BootIDPath:               bootFile,
		ShutdownBin:              fakeShutdown,
		AppUID:                   os.Getuid(),
		MaxRequestBytes:          32 * 1024,
		MaxResponseBytes:         1024 * 1024,
		ListLimit:                30,
		AutoCheckHours:           24,
		MaxConnections:           8,
	}

	svc, err := NewService(opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	srv := unixrpc.NewServer(opts.AppUID, opts.MaxRequestBytes, opts.MaxResponseBytes, opts.MaxConnections, svc.Dispatch)
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

	// Summary reports protocol_version=2 and VERSION.
	sum := call(map[string]any{"action": "summary"})
	if sum["ok"] != true || sum["version"] != "2.5.0-alpha" || int(sum["protocol_version"].(float64)) != 2 {
		t.Fatalf("unexpected summary: %+v", sum)
	}

	// set_settings rejects invalid interval and accepts 12.
	if res := call(map[string]any{"action": "set_settings", "auto_check_hours": 5}); res["ok"] != false {
		t.Fatalf("expected invalid auto_check_hours rejection: %+v", res)
	}
	if res := call(map[string]any{"action": "set_settings", "auto_check_hours": 12}); res["ok"] != true {
		t.Fatalf("expected auto_check_hours=12 accepted: %+v", res)
	}

	// Reboot requires confirmation=REBOOT and matching boot_id; then cancel_reboot clears marker.
	if res := call(map[string]any{"action": "reboot", "confirmation": "NO"}); res["ok"] != false {
		t.Fatalf("expected invalid confirmation rejected: %+v", res)
	}
	if res := call(map[string]any{"action": "reboot", "confirmation": "REBOOT", "expected_boot_id": bootUUID, "actor": "admin"}); res["ok"] != true {
		t.Fatalf("expected reboot scheduled: %+v", res)
	}
	if _, err := os.Stat(opts.RebootMarker); err != nil {
		t.Fatalf("expected reboot marker written: %v", err)
	}
	if res := call(map[string]any{"action": "cancel_reboot"}); res["ok"] != true {
		t.Fatalf("cancel_reboot failed: %+v", res)
	}
	if _, err := os.Stat(opts.RebootMarker); !os.IsNotExist(err) {
		t.Fatalf("expected reboot marker removed after cancel")
	}

	// ssh_protection_unban rejects zone-ID IPv6 and accepts valid IPv4.
	if res := call(map[string]any{"action": "ssh_protection_unban", "ip": "fe80::1%eth0"}); res["ok"] != false {
		t.Fatalf("expected zone-ID IP rejected: %+v", res)
	}
	if res := call(map[string]any{"action": "ssh_protection_unban", "ip": "203.0.113.42"}); res["ok"] != true {
		t.Fatalf("expected valid IP accepted: %+v", res)
	}
}
