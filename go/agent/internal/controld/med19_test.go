package controld

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type errListener struct{ err error }

func (l errListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errListener) Close() error              { return nil }
func (l errListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestControldServeDrainsActiveClientAndReportsAcceptError(t *testing.T) {
	d := NewDaemon(Options{MaxCommandBytes: 4096})

	acceptErr := errors.New("accept boom")
	if err := d.Serve(context.Background(), errListener{err: acceptErr}); !errors.Is(err, acceptErr) {
		t.Fatalf("expected accept error, got %v", err)
	}

	sock := filepath.Join(t.TempDir(), "controld.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Hold an accepted connection open with a partial line, then cancel ctx.
	_, _ = conn.Write([]byte("udp-port-check "))
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Serve must not return while the client handler is still active.
	select {
	case err := <-served:
		t.Fatalf("Serve returned before active handler drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Finish the command; client gets its reply and Serve exits cleanly with nil.
	_, _ = conn.Write([]byte("0\n"))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("expected reply from drained client: %v", err)
	}
	if !strings.HasPrefix(line, "ERROR udp-port-check:") {
		t.Fatalf("unexpected reply: %q", line)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("expected nil on graceful shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit after active client completed")
	}
}
