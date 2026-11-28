package controld

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A guarded apply copies the live haproxy.cfg into the panel's backup tree.
// controld made the copy root-owned, the installer gives that tree to the
// panel's user, and so every update after an apply changed one owner back
// and `easy-ha-proxy plan` reported it as drift.

type fchownCall struct{ uid, gid int }

func recordBackupFchown(t *testing.T) *[]fchownCall {
	t.Helper()
	calls := &[]fchownCall{}
	saved := backupFchown
	backupFchown = func(f *os.File, uid, gid int) error {
		*calls = append(*calls, fchownCall{uid, gid})
		return nil
	}
	t.Cleanup(func() { backupFchown = saved })
	return calls
}

func backupDaemon(dir string) *Daemon {
	return &Daemon{Opts: Options{ConfigBackupDir: dir, MaxConfigBytes: 1 << 20, GuardedConfigBackups: 3}}
}

func TestTheConfigBackupTakesTheOwnerOfItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "haproxy")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	calls := recordBackupFchown(t)
	backup, err := backupDaemon(dir).createGuardedConfigBackup([]byte("global\n"), strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := directoryOwner(dir)
	if !ok {
		t.Fatal("the test directory has no owner")
	}
	if len(*calls) != 1 || (*calls)[0] != (fchownCall{uid, gid}) {
		t.Fatalf("fchown calls %v, want one to the directory's %d:%d", *calls, uid, gid)
	}
	fi, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %o, want 600", fi.Mode().Perm())
	}
	if raw, _ := os.ReadFile(backup); string(raw) != "global\n" {
		t.Fatalf("backup content %q", raw)
	}
	if !strings.HasPrefix(filepath.Base(backup), "haproxy.cfg.pre-apply.") {
		t.Fatalf("backup name %s", backup)
	}
}

func TestTheConfigBackupTakesNoOwnerFromALinkedDirectory(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "haproxy")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	if _, _, ok := directoryOwner(link); ok {
		t.Fatal("directoryOwner followed a link")
	}
	calls := recordBackupFchown(t)
	if _, err := backupDaemon(link).createGuardedConfigBackup([]byte("global\n"), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("fchown was asked %v for a linked directory", *calls)
	}
}

func TestAFailedChownDoesNotFailTheBackup(t *testing.T) {
	dir := t.TempDir()
	saved := backupFchown
	backupFchown = func(*os.File, int, int) error { return os.ErrPermission }
	t.Cleanup(func() { backupFchown = saved })
	if _, err := backupDaemon(dir).createGuardedConfigBackup([]byte("global\n"), strings.Repeat("c", 64)); err != nil {
		t.Fatalf("the apply's backup failed on its owner: %v", err)
	}
}
