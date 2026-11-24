package alertd

import (
	"context"
	"database/sql"
	"errors"
	"os"
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

// The JSON state an earlier Go daemon kept beside the database is imported
// once, then set aside.
func TestStoreImportsTheEarlierGoState(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "alerts-state.json")
	_ = os.WriteFile(legacy, []byte(`{"schema_version":2,"next_event_id":3,
		"states":[{"rule":"backup.failed","subject":"nightly","state":"firing","severity":"warning","since_ts":50,
		"first_seen_ts":50,"last_seen_ts":60,"acknowledged_ts":55,"acknowledged_by":"ops","muted_until":0}],
		"events":[{"id":1,"ts":50,"rule":"backup.failed","subject":"nightly","transition":"fired","severity":"warning"},
		{"id":2,"ts":55,"rule":"backup.failed","subject":"nightly","transition":"acknowledged","severity":"warning"}]}`), 0o640)
	// The database already holds the Python daemon's history: an older row
	// for the same alert, and an event.
	old, err := NewStore(filepath.Join(dir, "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	old.PutState(AlertState{Rule: "backup.failed", Subject: "nightly", State: StateFiring, Severity: "warning",
		SinceTS: 10, FirstSeenTS: 10, LastSeenTS: 20})
	old.PutState(AlertState{Rule: "site.down", Subject: "kept", State: StateFiring, Severity: "critical",
		SinceTS: 10, FirstSeenTS: 10, LastSeenTS: 999})
	old.AddEvent(AlertEvent{TS: 10, Rule: "backup.failed", Subject: "nightly", Transition: TransitionFired, Severity: "warning"})
	old.Close()

	store, err := NewStore(filepath.Join(dir, "alerts.db"), legacy)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	row, ok := store.GetState("backup.failed", "nightly")
	if !ok || row.AcknowledgedBy != "ops" || row.LastSeenTS != 60 || row.FirstSeenTS != 10 {
		t.Fatalf("the newer JSON row must replace the older one (keeping the earliest first sight): %+v", row)
	}
	if kept, _ := store.GetState("site.down", "kept"); kept.LastSeenTS != 999 {
		t.Fatalf("a database row the JSON does not hold must stay: %+v", kept)
	}
	if total, _ := store.Events(EventFilter{}); total != 3 {
		t.Fatalf("events not imported beside the database's own: %d", total)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("the JSON state must be set aside after the import")
	}
	matches, _ := filepath.Glob(legacy + ".imported-*")
	if len(matches) != 1 {
		t.Fatalf("expected one imported copy, got %v", matches)
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
