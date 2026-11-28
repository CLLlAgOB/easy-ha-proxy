package app

import (
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Each call to a daemon builds its own Transport, so a connection it keeps
// alive is never reused: it must be closed with the answer, or every panel
// request leaves a socket open in the panel and a goroutine in the daemon.
func TestUnixSocketClientClosesEachConnection(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var opened, closed atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok": true}`))
		}),
		ConnState: func(_ net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				opened.Add(1)
			case http.StateClosed, http.StateHijacked:
				closed.Add(1)
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &UnixHTTP{Service: "test", SocketPath: sock}
	const calls = 5
	for i := 0; i < calls; i++ {
		if _, err := client.Get("/x", HTTPOptions{Timeout: 5 * time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := unixSocketClient(sock, 5*time.Second).Get("http://localhost/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for closed.Load() < calls+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if o, c := opened.Load(), closed.Load(); o != calls+1 || c != calls+1 {
		t.Fatalf("connections opened %d, closed %d; want %d each", o, c, calls+1)
	}
}
