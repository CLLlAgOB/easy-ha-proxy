package unixrpc

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerListenerRejectsUnlistedUID(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always authorized")
	}
	path := filepath.Join(t.TempDir(), "peer.sock")
	raw, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener := &peerListener{Listener: raw, panelUID: -1, daemonUID: 0}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	defer raw.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("unlisted peer read = %d, %v", n, err)
	}
	_ = raw.Close()
	if err := <-result; err == nil {
		t.Fatal("unlisted peer reached listener consumer")
	}
}
