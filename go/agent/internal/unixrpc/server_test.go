package unixrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixRPCFramingAndPeerAuth(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rpc.sock")
	srv := NewServer(os.Getuid(), 1024, 4096, 4, func(_ context.Context, req map[string]any) (map[string]any, error) {
		if req["action"] == "ping" {
			return map[string]any{"ok": true, "pong": true}, nil
		}
		return nil, NewError("invalid", "unknown action")
	})

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	call := func(raw string) map[string]any {
		t.Helper()
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(raw))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		return out
	}

	// Valid request succeeds.
	if res := call(`{"action":"ping"}` + "\n"); res["ok"] != true || res["pong"] != true {
		t.Fatalf("unexpected ping reply: %+v", res)
	}
	// Oversized request returns too_large.
	if res := call(`{"action":"` + strings.Repeat("a", 2048) + `"}` + "\n"); res["ok"] != false || res["error_code"] != "too_large" {
		t.Fatalf("expected too_large, got %+v", res)
	}
	// Multi-line framing rejected.
	if res := call("{\"action\":\"ping\"}\n{\"action\":\"ping\"}\n"); res["ok"] != false || res["error_code"] != "invalid" {
		t.Fatalf("expected invalid framing, got %+v", res)
	}
}
