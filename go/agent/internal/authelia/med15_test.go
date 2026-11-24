package authelia

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyyaml"
)

type failingAcceptListener struct {
	err error
}

func (l failingAcceptListener) Accept() (net.Conn, error) { return nil, l.err }
func (l failingAcceptListener) Close() error              { return nil }
func (l failingAcceptListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestSaveConfigDataFailurePreservesFileAndMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "configuration.yml")
	orig := "theme: dark\n"
	if err := os.WriteFile(cfgPath, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewConfigd(ConfigdOptions{ConfigFile: cfgPath, ValidateConfig: false})
	root := pyyaml.NewMap()
	root.Set("theme", "light")

	t.Run("sync failure preserves original", func(t *testing.T) {
		origSync := syncTempFile
		defer func() { syncTempFile = origSync }()
		syncTempFile = func(f *os.File) error { return errors.New("injected sync error") }

		err := c.saveConfigData(root)
		if err == nil || !strings.Contains(err.Error(), "injected sync error") {
			t.Fatalf("expected sync error, got %v", err)
		}
		got, err := os.ReadFile(cfgPath)
		if err != nil || string(got) != orig {
			t.Fatalf("original file altered: %q err=%v", string(got), err)
		}
		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("original mode altered: %o err=%v", fi.Mode().Perm(), err)
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".configuration.") {
				t.Fatalf("stale temp file left behind: %s", e.Name())
			}
		}
	})

	t.Run("close failure preserves original", func(t *testing.T) {
		origClose := closeTempFile
		defer func() { closeTempFile = origClose }()
		closeTempFile = func(f *os.File) error {
			_ = f.Close()
			return errors.New("injected close error")
		}

		err := c.saveConfigData(root)
		if err == nil || !strings.Contains(err.Error(), "injected close error") {
			t.Fatalf("expected close error, got %v", err)
		}
		got, err := os.ReadFile(cfgPath)
		if err != nil || string(got) != orig {
			t.Fatalf("original file altered: %q err=%v", string(got), err)
		}
		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("original mode altered: %o err=%v", fi.Mode().Perm(), err)
		}
	})

	t.Run("symlink target is rejected via lstat", func(t *testing.T) {
		target := filepath.Join(dir, "real.yml")
		link := filepath.Join(dir, "link.yml")
		if err := os.WriteFile(target, []byte("keep: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		cLink := NewConfigd(ConfigdOptions{ConfigFile: link, ValidateConfig: false})
		if err := cLink.saveConfigData(root); err == nil {
			t.Fatal("expected symlink saveConfigData to fail")
		}
		got, _ := os.ReadFile(target)
		if string(got) != "keep: true\n" {
			t.Fatalf("symlink target was modified: %q", string(got))
		}
	})
}

func TestSaveUsersDataCloseFailurePreservesFileAndMode(t *testing.T) {
	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users_database.yml")
	orig := "users:\n  alice:\n    displayname: Alice\n"
	if err := os.WriteFile(usersPath, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	u := NewUsersd(UsersdOptions{UsersFile: usersPath})
	root := pyyaml.NewMap()
	root.Set("users", pyyaml.NewMap())

	origClose := closeTempFile
	defer func() { closeTempFile = origClose }()
	closeTempFile = func(f *os.File) error {
		_ = f.Close()
		return errors.New("injected users close error")
	}

	err := u.saveUsersData(root)
	if err == nil || !strings.Contains(err.Error(), "injected users close error") {
		t.Fatalf("expected close error, got %v", err)
	}
	got, err := os.ReadFile(usersPath)
	if err != nil || string(got) != orig {
		t.Fatalf("original users file altered: %q err=%v", string(got), err)
	}
	fi, err := os.Stat(usersPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("original users mode altered: %o err=%v", fi.Mode().Perm(), err)
	}
}

func TestStageFileAndNotificationStateCloseFailure(t *testing.T) {
	dir := t.TempDir()
	mailFile := filepath.Join(dir, "mail.env")
	if err := os.WriteFile(mailFile, []byte("SMTP_PORT=587\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(mailFile, &st); err != nil {
		t.Fatal(err)
	}

	origClose := closeTempFile
	defer func() { closeTempFile = origClose }()
	closeTempFile = func(f *os.File) error {
		_ = f.Close()
		return errors.New("injected close error")
	}

	if staged, err := stageFile(mailFile, []byte("SMTP_PORT=465\n"), &st, 0o600); err == nil {
		t.Fatalf("expected stageFile error on close failure, got staged=%s", staged)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".mail.env.mail-") {
			t.Fatalf("stale staged mail file left behind: %s", e.Name())
		}
	}

	stateDir := filepath.Join(dir, "notify-state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(stateDir, "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewConfigd(ConfigdOptions{NotificationStateFile: stateFile})
	m := pyyaml.NewMap()
	m.Set("version", int64(2))
	if err := c.writeNotificationState(m); err == nil {
		t.Fatal("expected writeNotificationState to fail on close error")
	}
	got, _ := os.ReadFile(stateFile)
	if string(got) != `{"version":1}` {
		t.Fatalf("notification state altered: %q", string(got))
	}
}

func TestConfigdAndUsersdServeDistinguishShutdownFromAcceptError(t *testing.T) {
	c := NewConfigd(ConfigdOptions{})
	u := NewUsersd(UsersdOptions{})

	acceptErr := errors.New("listener broken")
	if err := c.Serve(context.Background(), failingAcceptListener{err: acceptErr}); !errors.Is(err, acceptErr) {
		t.Fatalf("Configd.Serve expected accept error, got %v", err)
	}
	if err := u.Serve(context.Background(), failingAcceptListener{err: acceptErr}); !errors.Is(err, acceptErr) {
		t.Fatalf("Usersd.Serve expected accept error, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Serve(ctx, failingAcceptListener{err: net.ErrClosed}); err != nil {
		t.Fatalf("Configd.Serve expected nil on canceled context, got %v", err)
	}
	if err := u.Serve(ctx, failingAcceptListener{err: net.ErrClosed}); err != nil {
		t.Fatalf("Usersd.Serve expected nil on canceled context, got %v", err)
	}
}
