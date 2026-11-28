package tools

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A gateway moved from Authelia 4.39.20 to 4.39.28 through a complete update.
// The new version migrated the storage schema on first start, and 4.39.20
// refuses a newer schema -- with no copy taken beforehand there was no way
// back. The copy is taken just before the stack runs a different image.

func makeAutheliaDB(t *testing.T, path string, rows int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("create table migrations (id integer primary key, version_after int)"); err != nil {
		t.Fatal(err)
	}
	for v := 20; v < 20+rows; v++ {
		if _, err := db.Exec("insert into migrations (version_after) values (?)", v); err != nil {
			t.Fatal(err)
		}
	}
}

func versions(t *testing.T, path string) []int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("select version_after from migrations order by id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

func TestTheAutheliaCopyHoldsTheSameRowsAndOnlyRootReadsIt(t *testing.T) {
	root := t.TempDir()
	source, dir := filepath.Join(root, "db.sqlite3"), filepath.Join(root, "copies")
	makeAutheliaDB(t, source, 3)
	copied, err := CopyAutheliaDB(source, dir, "authelia/authelia:4.39.20", 5)
	if err != nil {
		t.Fatal(err)
	}
	if got := versions(t, copied); len(got) != 3 || got[0] != 20 || got[2] != 22 {
		t.Fatalf("rows %v", got)
	}
	fi, _ := os.Stat(copied)
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes %o %o", fi.Mode().Perm(), di.Mode().Perm())
	}
	// The label says which version the copy can be restored under.
	if !strings.Contains(filepath.Base(copied), "authelia_authelia_4.39.20") {
		t.Fatalf("name %s", copied)
	}
}

// Authelia keeps running while the copy is taken.
func TestTheAutheliaCopyIsConsistentWhileAWriterHoldsTheDatabase(t *testing.T) {
	root := t.TempDir()
	source, dir := filepath.Join(root, "db.sqlite3"), filepath.Join(root, "copies")
	makeAutheliaDB(t, source, 3)
	writer, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	for _, q := range []string{"pragma journal_mode=wal", "insert into migrations (version_after) values (99)"} {
		if _, err := writer.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("insert into migrations (version_after) values (100)"); err != nil {
		t.Fatal(err)
	}
	copied, err := CopyAutheliaDB(source, dir, "x", 5)
	if err != nil {
		t.Fatal(err)
	}
	got := versions(t, copied)
	has := func(v int) bool {
		for _, x := range got {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(99) || has(100) {
		t.Fatalf("rows %v", got)
	}
}

func TestOnlyTheNewestAutheliaCopiesAreKept(t *testing.T) {
	root := t.TempDir()
	source, dir := filepath.Join(root, "db.sqlite3"), filepath.Join(root, "copies")
	makeAutheliaDB(t, source, 3)
	for i := 0; i < 4; i++ {
		if _, err := CopyAutheliaDB(source, dir, "x", 2); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(dir, "keep-me.txt")
	os.WriteFile(unrelated, []byte("not ours"), 0o600)
	if _, err := CopyAutheliaDB(source, dir, "x", 2); err != nil {
		t.Fatal(err)
	}
	copies, _ := filepath.Glob(filepath.Join(dir, "authelia-db-*.sqlite3"))
	if len(copies) != 2 {
		t.Fatalf("copies %v", copies)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("an unrelated file was removed")
	}
}

func TestNoAutheliaDatabaseIsNothingToCopy(t *testing.T) {
	root := t.TempDir()
	copied, err := CopyAutheliaDB(filepath.Join(root, "absent.sqlite3"), filepath.Join(root, "copies"), "x", 5)
	if err != nil || copied != "" {
		t.Fatalf("%q %v", copied, err)
	}
}

func TestADamagedAutheliaDatabaseFailsAndLeavesNothingHalfWritten(t *testing.T) {
	root := t.TempDir()
	source, dir := filepath.Join(root, "db.sqlite3"), filepath.Join(root, "copies")
	os.WriteFile(source, []byte(strings.Repeat("this is not a database", 100)), 0o600)
	if _, err := CopyAutheliaDB(source, dir, "x", 5); err == nil {
		t.Fatal("a damaged database was copied")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left behind %v", entries)
	}
}
