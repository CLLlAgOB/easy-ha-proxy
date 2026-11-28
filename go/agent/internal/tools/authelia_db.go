package tools

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"modernc.org/sqlite"
)

// Authelia's SQLite database is copied before a different Authelia image runs
// on it. A new Authelia version migrates its storage schema on first start,
// and there is no way back: the old version refuses a newer schema. The only
// rollback is the database as it was, so the installer takes this copy just
// before the stack is recreated on a different image.
//
// The copy is taken through SQLite's online backup API, so Authelia keeps
// running and the copy is consistent even mid-write. It is integrity-checked,
// written under a temporary name and renamed into place, readable by root
// only. Only the newest keep copies made here are kept.

const (
	autheliaDBPrefix = "authelia-db-"
	autheliaDBSuffix = ".sqlite3"
)

var autheliaDBLabel = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// backupper is the modernc driver connection's online backup.
type backupper interface {
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

func readOnlyURI(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro"
}

// CopyAutheliaDB copies source into directory and returns the copy's path,
// or "" when there is no database to copy. An error means no verified copy
// exists and the caller must not let the new image start.
func CopyAutheliaDB(source, directory, label string, keep int) (string, error) {
	if fi, err := os.Stat(source); err != nil || !fi.Mode().IsRegular() {
		return "", nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102T150405") + fmt.Sprintf("%06dZ", now.Nanosecond()/1000)
	safe := autheliaDBLabel.ReplaceAllString(label, "_")
	if len(safe) > 80 {
		safe = safe[:80]
	}
	if safe == "" {
		safe = "unknown"
	}
	target := filepath.Join(directory, autheliaDBPrefix+stamp+"-"+safe+autheliaDBSuffix)
	partial := target + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	f.Close()
	if err := copyThenVerify(source, partial); err != nil {
		os.Remove(partial)
		return "", err
	}
	if err := os.Chmod(partial, 0o600); err != nil {
		os.Remove(partial)
		return "", err
	}
	if err := syncFile(partial); err != nil {
		os.Remove(partial)
		return "", err
	}
	if err := os.Rename(partial, target); err != nil {
		os.Remove(partial)
		return "", err
	}
	_ = syncFile(directory)
	pruneAutheliaDB(directory, keep)
	return target, nil
}

func copyThenVerify(source, partial string) error {
	ctx := context.Background()
	origin, err := sql.Open("sqlite", readOnlyURI(source))
	if err != nil {
		return err
	}
	defer origin.Close()
	conn, err := origin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 30000"); err != nil {
		return err
	}
	err = conn.Raw(func(driverConn any) error {
		b, ok := driverConn.(backupper)
		if !ok {
			return errors.New("the SQLite driver has no online backup")
		}
		backup, err := b.NewBackup(partial)
		if err != nil {
			return err
		}
		for {
			more, err := backup.Step(256)
			if err != nil {
				backup.Finish()
				return err
			}
			if !more {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		return backup.Finish()
	})
	if err != nil {
		return err
	}
	check, err := sql.Open("sqlite", readOnlyURI(partial))
	if err != nil {
		return err
	}
	defer check.Close()
	var result string
	if err := check.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("the copy failed its integrity check: %q", result)
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func pruneAutheliaDB(directory string, keep int) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	var copies []string
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(name, autheliaDBPrefix) && strings.HasSuffix(name, autheliaDBSuffix) {
			copies = append(copies, name)
		}
	}
	sort.Strings(copies)
	for len(copies) > keep {
		os.Remove(filepath.Join(directory, copies[0]))
		copies = copies[1:]
	}
}
