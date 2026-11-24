package unixrpc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChownSocketReportsErrorsAndListenUnixPublishesMode(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.sock")
	if err := ChownSocket(missing, "", "", 0o600); err == nil {
		t.Fatal("expected ChownSocket to return error for missing socket path")
	}

	sock := filepath.Join(dir, "published.sock")
	ln, err := ListenUnix(sock, "", "", 0o600)
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	}()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat published socket: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("expected published mode 0600, got %04o", fi.Mode().Perm())
	}
}
