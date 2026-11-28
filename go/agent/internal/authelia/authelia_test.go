package authelia

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBansdProtocolAndValidation(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "bans.sh")
	_ = os.WriteFile(script, []byte("#!/bin/sh\necho \"ok:$1:$2\"\n"), 0o755)
	sock := filepath.Join(dir, "bansd.sock")

	srv := NewBansdServer(BansdOptions{
		SocketPath:      sock,
		ScriptPath:      script,
		CommandTimeout:  5 * time.Second,
		MaxRequestBytes: 8192,
		MaxWorkers:      2,
	})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	call := func(req map[string]any) map[string]any {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		b, _ := json.Marshal(req)
		_, _ = c.Write(append(b, '\n'))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(line), &out)
		return out
	}

	if res := call(map[string]any{"action": "ping"}); res["ok"] != true || res["pong"] != true {
		t.Fatalf("ping failed: %+v", res)
	}
	if res := call(map[string]any{"action": "list"}); res["ok"] != true {
		t.Fatalf("list failed: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-user", "username": "../root"}); res["ok"] != false {
		t.Fatalf("invalid username must be rejected: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-ip", "ip": "203.0.113.0/24"}); res["ok"] != true {
		t.Fatalf("valid CIDR revoke-ip failed: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-ip", "ip": "not-an-ip"}); res["ok"] != false {
		t.Fatalf("invalid IP must be rejected: %+v", res)
	}
}
