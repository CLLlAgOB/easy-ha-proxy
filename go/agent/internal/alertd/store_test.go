package alertd

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// A database the Python daemon wrote (schema version 1 columns, then the
// version 2 migration) is read and continued by the Go store, and what the
// Go store writes stays readable with the Python schema.
func TestStoreSharesThePythonDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// As a Python daemon of schema version 1 left it: no quiet columns yet.
	for _, stmt := range []string{
		"CREATE TABLE schema_version (version INTEGER NOT NULL)",
		"INSERT INTO schema_version (version) VALUES (1)",
		schemaStatements[1],
		schemaStatements[3],
		"INSERT INTO alert_state (rule, subject, state, severity, since_ts, first_seen_ts, last_seen_ts, summary) " +
			"VALUES ('site.down', 'app.example.com', 'firing', 'critical', 100, 90, 120, 'App down')",
		"INSERT INTO alert_events (ts, rule, subject, transition, severity, summary) " +
			"VALUES (100, 'site.down', 'app.example.com', 'fired', 'critical', 'App down')",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	db.Close()

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	row, ok := store.GetState("site.down", "app.example.com")
	if !ok || row.State != StateFiring || row.FirstSeenTS != 90 || row.AcknowledgedTS != 0 {
		t.Fatalf("Python row not read: %+v %v", row, ok)
	}
	if found, err := store.SetQuiet("site.down", "app.example.com", 130, "operator", 0); !found || err != nil {
		t.Fatalf("SetQuiet: %v %v", found, err)
	}
	// An observation keeps the acknowledgement and first_seen_ts.
	store.PutState(AlertState{Rule: "site.down", Subject: "app.example.com", State: StateFiring, Severity: "critical",
		SinceTS: 100, FirstSeenTS: 999, LastSeenTS: 140, Summary: "App down"})
	store.AddEvent(AlertEvent{TS: 140, Rule: "site.down", Subject: "app.example.com", Transition: TransitionRepeated, Severity: "critical"})
	if err := store.TakeErr(); err != nil {
		t.Fatal(err)
	}
	store.Close()

	db, _ = sql.Open("sqlite", path)
	defer db.Close()
	var version, ackTS, firstSeen, events int
	var ackBy string
	_ = db.QueryRow("SELECT version FROM schema_version").Scan(&version)
	_ = db.QueryRow("SELECT acknowledged_ts, acknowledged_by, first_seen_ts FROM alert_state").Scan(&ackTS, &ackBy, &firstSeen)
	_ = db.QueryRow("SELECT COUNT(*) FROM alert_events").Scan(&events)
	if version != SchemaVersion || ackTS != 130 || ackBy != "operator" || firstSeen != 90 || events != 2 {
		t.Fatalf("database after Go: version=%d ack=%d/%q first_seen=%d events=%d", version, ackTS, ackBy, firstSeen, events)
	}
}

// A write that fails must reach the API as an error, never as ok.
func TestQuietenReportsAFailedWrite(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(DaemonOptions{GatewayName: "gw"}, DefaultConfig(), store, nil)
	eng.nowFn = func() int64 { return 1700000000 }
	if _, err := eng.Observe(context.Background(), map[string]any{"rule": "backup.failed", "subject": "nightly"}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	store.Close() // every later statement fails, as a full or read-only disk would
	_, err = eng.Quieten(map[string]any{"rule": "backup.failed", "subject": "nightly", "mode": "acknowledge", "by": "ops"})
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
		t.Fatalf("expected a storage error (HTTP 500), got %v", err)
	}
	if _, err := eng.DeleteHistory(map[string]any{"all": true}); err == nil {
		t.Fatal("a failed history deletion must be an error")
	}
	if _, err := eng.Observe(context.Background(), map[string]any{"rule": "backup.failed", "subject": "other"}); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Fatalf("a failed observation must be an error, got %v", err)
	}
}

func TestStoreErrorsStayWithTheirOperation(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	failed := store.operation()
	ok := store.operation()
	if _, err := failed.exec("UPDATE missing_table SET id=0"); err == nil {
		t.Fatal("expected database failure")
	}
	ok.OpenStates()
	if err := ok.TakeErr(); err != nil {
		t.Fatalf("unrelated operation failed: %v", err)
	}
	if err := failed.TakeErr(); err == nil {
		t.Fatal("original operation lost its error")
	}
}
