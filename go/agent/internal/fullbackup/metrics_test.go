package fullbackup

import (
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type gateway struct {
	root, database, snapshot string
}

func newGateway(t *testing.T) gateway {
	root := t.TempDir()
	g := gateway{root: root, database: filepath.Join(root, "metrics", "metrics.db"),
		snapshot: filepath.Join(root, "monitoring-history", "metrics.db")}
	if err := os.MkdirAll(filepath.Dir(g.database), 0o755); err != nil {
		t.Fatal(err)
	}
	return g
}

// collector is a database in WAL mode with committed rows not yet
// checkpointed, its connection kept open.
func (g gateway) collector(t *testing.T, rows int) {
	t.Helper()
	db, err := sql.Open("sqlite", g.database)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE metric_1m (bucket_ts INTEGER, value REAL)"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	tx, _ := db.Begin()
	for i := 0; i < rows; i++ {
		if _, err := tx.Exec("INSERT INTO metric_1m VALUES (?, ?)", i, float64(i)*1.5); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func rows(t *testing.T, p string) int {
	t.Helper()
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM metric_1m").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheSnapshotHoldsWhatTheCollectorWrote(t *testing.T) {
	g := newGateway(t)
	g.collector(t, 50)
	if fi, err := os.Stat(g.database + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatal("the rows are not in the write-ahead log")
	}
	result := snapshotMetrics(g.database, g.snapshot)
	fi, _ := os.Stat(g.snapshot)
	if result["included"] != true || rows(t, g.snapshot) != 50 || result["snapshot_bytes"] != fi.Size() {
		t.Fatalf("result %v", result)
	}
	// One self-contained file, root only.
	entries, _ := os.ReadDir(filepath.Dir(g.snapshot))
	if len(entries) != 1 || entries[0].Name() != "metrics.db" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot directory %v mode %v", entries, fi.Mode())
	}
}

func TestNoHistoryIsNotAnError(t *testing.T) {
	g := newGateway(t)
	if result := snapshotMetrics(g.database, g.snapshot); result["included"] != false || lexists(filepath.Dir(g.snapshot)) {
		t.Fatalf("result %v", result)
	}
}

func TestADiskTooFullCostsTheHistoryNotTheBackup(t *testing.T) {
	g := newGateway(t)
	g.collector(t, 5)
	swap(t, &diskUsage, func(string) (usage, error) { return usage{free: 1024}, nil })
	result := snapshotMetrics(g.database, g.snapshot)
	if result["included"] != false || !strings.Contains(result["reason"].(string), "free space") || lexists(filepath.Dir(g.snapshot)) {
		t.Fatalf("result %v", result)
	}
}

func TestAnUnreadableDatabaseLeavesNothingBehind(t *testing.T) {
	g := newGateway(t)
	writeText(t, g.database, strings.Repeat("not a database at all", 100))
	result := snapshotMetrics(g.database, g.snapshot)
	if result["included"] != false || !strings.Contains(result["reason"].(string), "could not be read") || lexists(filepath.Dir(g.snapshot)) {
		t.Fatalf("result %v", result)
	}
}

func TestALeftoverFromAnInterruptedRunIsReplaced(t *testing.T) {
	g := newGateway(t)
	g.collector(t, 7)
	writeText(t, g.snapshot, "stale")
	snapshotMetrics(g.database, g.snapshot)
	if rows(t, g.snapshot) != 7 {
		t.Fatal("the stale snapshot stayed")
	}
}

func (g gateway) restored(t *testing.T, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(g.snapshot), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", g.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE metric_1m (bucket_ts INTEGER, value REAL)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		_, _ = db.Exec("INSERT INTO metric_1m VALUES (?, 0)", i)
	}
}

func systemd(t *testing.T, g gateway, running bool) *recorder {
	t.Helper()
	swap(t, &metricsSnapshot, g.snapshot)
	swap(t, &metricsDatabase, g.database)
	swap(t, &which, func(string) bool { return true })
	return record(t, func(argv []string) (runResult, error) {
		if argv[1] == "is-active" && !running {
			return runResult{Code: 3}, nil
		}
		return runResult{}, nil
	})
}

func systemctlVerbs(r *recorder) [][]string {
	var out [][]string
	for _, call := range r.calls {
		out = append(out, call[1:])
	}
	return out
}

func TestTheRestoredHistoryReplacesTheFreshOne(t *testing.T) {
	g := newGateway(t)
	writeText(t, g.database, "")
	for _, suffix := range []string{"-wal", "-shm"} {
		writeText(t, g.database+suffix, "belongs to the old database")
	}
	g.restored(t, 12)
	r := systemd(t, g, true)
	var installed bool
	captureStdout(t, func() {
		var err error
		if installed, err = installRestoredMetrics(); err != nil {
			t.Error(err)
		}
	})
	if !installed || rows(t, g.database) != 12 || lexists(g.database+"-wal") || lexists(g.database+"-shm") || lexists(filepath.Dir(g.snapshot)) {
		t.Fatal("not swapped in cleanly")
	}
	// Stopped for the swap, started again afterwards.
	want := [][]string{{"is-active", "--quiet", metricsUnit}, {"stop", metricsUnit}, {"start", metricsUnit}}
	if !reflect.DeepEqual(systemctlVerbs(r), want) {
		t.Fatalf("systemctl %v", systemctlVerbs(r))
	}
}

func TestACollectorThatWasNotRunningIsNotStarted(t *testing.T) {
	g := newGateway(t)
	g.restored(t, 3)
	r := systemd(t, g, false)
	captureStdout(t, func() { _, _ = installRestoredMetrics() })
	if !reflect.DeepEqual(systemctlVerbs(r), [][]string{{"is-active", "--quiet", metricsUnit}}) || rows(t, g.database) != 3 {
		t.Fatalf("systemctl %v", systemctlVerbs(r))
	}
}

func TestAnArchiveWithoutAHistoryChangesNothing(t *testing.T) {
	g := newGateway(t)
	g.collector(t, 5)
	systemd(t, g, true)
	if installed, _ := installRestoredMetrics(); installed || rows(t, g.database) != 5 {
		t.Fatal("changed a history the archive did not have")
	}
}

func TestThePageSaysWhetherTheHistoryIsThere(t *testing.T) {
	page := readText(t, filepath.Join(repoRoot(), "go/panel/web/templates/system_backups.html"))
	script := readText(t, filepath.Join(repoRoot(), "go/panel/web/static/js/system_backups.js"))
	if !strings.Contains(page, `id="backup-metrics-state"`) ||
		!strings.Contains(script, `byId("backup-metrics-state").textContent = manifest.metrics_included ? t("Yes") : t("No");`) {
		t.Fatal("the backup details do not show the history")
	}
}
