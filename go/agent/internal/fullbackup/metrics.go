package fullbackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"modernc.org/sqlite"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostfile"
)

type onlineBackup interface {
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

// snapshotMetrics copies the monitoring history consistently, or says why
// it did not. A missing history, a disk too full for a second copy, or a
// database that cannot be read leaves the backup without the history rather
// than without a backup.
func snapshotMetrics(database, snapshot string) map[string]any {
	discardMetricsSnapshot(snapshot)
	fi, err := os.Stat(database)
	if err != nil || !fi.Mode().IsRegular() {
		return map[string]any{"included": false, "reason": "no monitoring history on this gateway"}
	}
	size := fi.Size()
	if wal, err := os.Stat(database + "-wal"); err == nil && wal.Mode().IsRegular() {
		size += wal.Size()
	}
	ancestor, err := existingAncestor(filepath.Dir(snapshot))
	if err != nil {
		return map[string]any{"included": false, "reason": "the monitoring history could not be read: " + err.Error()}
	}
	free, err := diskUsage(ancestor)
	if err != nil {
		return map[string]any{"included": false, "reason": "the monitoring history could not be read: " + err.Error()}
	}
	if free.free < size+metricsSnapshotReserve {
		return map[string]any{"included": false, "reason": "not enough free space for a copy of the monitoring history",
			"database_bytes": size, "free_bytes": free.free}
	}
	if err := os.MkdirAll(filepath.Dir(snapshot), 0o700); err == nil {
		err = os.Chmod(filepath.Dir(snapshot), 0o700)
	}
	partial := snapshot + ".partial"
	defer os.Remove(partial)
	err = onlineCopy(database, partial)
	if err == nil {
		err = os.Chmod(partial, 0o600)
	}
	if err == nil {
		err = os.Rename(partial, snapshot)
	}
	if err != nil {
		discardMetricsSnapshot(snapshot)
		return map[string]any{"included": false, "reason": "the monitoring history could not be read: " + err.Error()}
	}
	copied, err := os.Stat(snapshot)
	if err != nil {
		return map[string]any{"included": false, "reason": "the monitoring history could not be read: " + err.Error()}
	}
	return map[string]any{"included": true, "snapshot_bytes": copied.Size()}
}

// onlineCopy is SQLite's online backup of a database opened read-only.
func onlineCopy(database, target string) error {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: database}).EscapedPath()+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 30000"); err != nil {
		return err
	}
	return conn.Raw(func(driverConn any) error {
		b, ok := driverConn.(onlineBackup)
		if !ok {
			return errors.New("the SQLite driver has no online backup")
		}
		backup, err := b.NewBackup(target)
		if err != nil {
			return err
		}
		for {
			more, err := backup.Step(4096)
			if err != nil {
				backup.Finish()
				return err
			}
			if !more {
				break
			}
		}
		destination, err := backup.Commit()
		if err != nil {
			return err
		}
		return destination.Close()
	})
}

func discardMetricsSnapshot(snapshot string) {
	_ = os.Remove(snapshot)
	_ = os.Remove(snapshot + ".partial")
	_ = os.Remove(filepath.Dir(snapshot))
}

// installRestoredMetrics puts a restored history where the collector reads
// it. The collector holds its database open, so it is stopped for the swap
// and started again only if it ran. The old write-ahead log goes with the
// old database; left in place SQLite would replay it into the restored one.
var installRestoredMetrics = func() (bool, error) {
	snapshot, database := metricsSnapshot, metricsDatabase
	sourceDir, err := hostfile.OpenDirectory(filepath.Dir(snapshot), 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer sourceDir.Close()
	sourceName := filepath.Base(snapshot)
	fd, err := unix.Openat(int(sourceDir.Fd()), sourceName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(fd), snapshot)
	defer file.Close()
	var expected unix.Stat_t
	if err := unix.Fstat(fd, &expected); err != nil {
		return false, err
	}
	if expected.Mode&unix.S_IFMT != unix.S_IFREG || expected.Nlink != 1 {
		return false, backupErrorf("Monitoring history must be a regular file with a single link: %s", snapshot)
	}
	if err := file.Chmod(0o640); err != nil {
		return false, err
	}
	running := false
	if which("systemctl") {
		r, err := run([]string{"systemctl", "is-active", "--quiet", metricsUnit}, runOptions{})
		running = err == nil && r.Code == 0
	}
	if running {
		_, _ = run([]string{"systemctl", "stop", metricsUnit}, runOptions{})
	}
	defer func() {
		discardMetricsSnapshot(snapshot)
		if running {
			_, _ = run([]string{"systemctl", "start", metricsUnit}, runOptions{})
		}
	}()
	destDir, err := hostfile.OpenDirectory(filepath.Dir(database), 0o755)
	if err != nil {
		return false, err
	}
	defer destDir.Close()
	destFD, destName := int(destDir.Fd()), filepath.Base(database)
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := unix.Unlinkat(destFD, destName+suffix, 0); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	if err := unix.Renameat(int(sourceDir.Fd()), sourceName, destFD, destName); err != nil {
		return false, err
	}
	var actual unix.Stat_t
	if err := unix.Fstatat(destFD, destName, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	if actual.Dev != expected.Dev || actual.Ino != expected.Ino {
		_ = unix.Unlinkat(destFD, destName, 0)
		return false, backupErrorf("Monitoring history was replaced during restore")
	}
	fmt.Printf("Restored the monitoring history: %s\n", database)
	return true, nil
}
