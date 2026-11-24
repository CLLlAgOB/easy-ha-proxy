package alertd

// The alert store: the same SQLite database (alerts.db), schema, migration
// and SQL as AlertDatabase in easy-ha-proxy-alertd.py, so the Python and the
// Go daemon read and continue each other's history, acknowledgements and
// mutes in either direction of an update or a rollback.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is SCHEMA_VERSION of the Python daemon.
const SchemaVersion = 2

// AlertState represents one (rule, subject) row of alert_state.
type AlertState struct {
	Rule           string `json:"rule"`
	Subject        string `json:"subject"`
	State          string `json:"state"`
	Severity       string `json:"severity"`
	SinceTS        int64  `json:"since_ts"`
	FirstSeenTS    int64  `json:"first_seen_ts"`
	LastSeenTS     int64  `json:"last_seen_ts"`
	LastNotifiedTS int64  `json:"last_notified_ts"`
	NotifyCount    int    `json:"notify_count"`
	Summary        string `json:"summary"`
	Detail         string `json:"detail"`
	TriggerDelay   *int   `json:"trigger_delay"`
	Recipient      string `json:"recipient"`
	AcknowledgedTS int64  `json:"acknowledged_ts"`
	AcknowledgedBy string `json:"acknowledged_by"`
	MutedUntil     int64  `json:"muted_until"`
	StaleSinceTS   int64  `json:"stale_since_ts"`
}

// AlertEvent represents one row of alert_events.
type AlertEvent struct {
	ID            int64  `json:"id"`
	TS            int64  `json:"ts"`
	Rule          string `json:"rule"`
	Subject       string `json:"subject"`
	Transition    string `json:"transition"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	Detail        string `json:"detail"`
	Delivered     string `json:"delivered"`
	DeliveryError string `json:"delivery_error"`
}

// EventFilter filters alert history queries.
type EventFilter struct {
	Rule     string
	Severity string
	Since    int64
	Until    int64
	Limit    int
	Offset   int
}

// StoreStats summarizes persisted alert state counts and file size.
type StoreStats struct {
	Firing        int   `json:"firing"`
	Pending       int   `json:"pending"`
	Events        int   `json:"events"`
	DatabaseBytes int64 `json:"database_bytes"`
}

var schemaStatements = []string{
	"CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
	`CREATE TABLE IF NOT EXISTS alert_state (
        rule            TEXT    NOT NULL,
        subject         TEXT    NOT NULL,
        state           TEXT    NOT NULL,
        severity        TEXT    NOT NULL DEFAULT 'warning',
        since_ts        INTEGER NOT NULL,
        first_seen_ts   INTEGER NOT NULL,
        last_seen_ts    INTEGER NOT NULL,
        last_notified_ts INTEGER NOT NULL DEFAULT 0,
        notify_count    INTEGER NOT NULL DEFAULT 0,
        summary         TEXT    NOT NULL DEFAULT '',
        detail          TEXT    NOT NULL DEFAULT '',
        trigger_delay   INTEGER,
        recipient       TEXT    NOT NULL DEFAULT '',
        PRIMARY KEY (rule, subject)
    )`,
	"CREATE INDEX IF NOT EXISTS ix_state_state ON alert_state(state, since_ts)",
	`CREATE TABLE IF NOT EXISTS alert_events (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        rule        TEXT    NOT NULL,
        subject     TEXT    NOT NULL,
        transition  TEXT    NOT NULL,
        severity    TEXT    NOT NULL,
        summary     TEXT    NOT NULL DEFAULT '',
        detail      TEXT    NOT NULL DEFAULT '',
        delivered   TEXT    NOT NULL DEFAULT '',
        delivery_error TEXT NOT NULL DEFAULT ''
    )`,
	"CREATE INDEX IF NOT EXISTS ix_events_ts ON alert_events(ts)",
	"CREATE INDEX IF NOT EXISTS ix_events_rule ON alert_events(rule, ts)",
}

// Columns added by schema version 2, as the Python migration adds them.
var addedColumns = [][2]string{
	{"acknowledged_ts", "INTEGER NOT NULL DEFAULT 0"},
	{"acknowledged_by", "TEXT NOT NULL DEFAULT ''"},
	{"muted_until", "INTEGER NOT NULL DEFAULT 0"},
	{"stale_since_ts", "INTEGER NOT NULL DEFAULT 0"},
}

const stateColumns = "rule, subject, state, severity, since_ts, first_seen_ts, last_seen_ts, last_notified_ts, " +
	"notify_count, summary, detail, trigger_delay, recipient, acknowledged_ts, acknowledged_by, muted_until, stale_since_ts"

const eventColumns = "id, ts, rule, subject, transition, severity, summary, detail, delivered, delivery_error"

// Store is the alert database. Every method is safe for concurrent use.
//
// A failed read or write is kept as the store's pending error (TakeErr), so
// the engine can answer the request that caused it with a 500, as the Python
// daemon does when sqlite3 raises, instead of reporting success.
type Store struct {
	mu   sync.Mutex
	db   *sql.DB
	path string
	err  error
}

// NewStore opens or creates the alert database at path; "" keeps it in
// memory (tests). legacyJSON, if it names an existing file, is the state an
// earlier Go daemon kept outside the database: it is imported once and set
// aside, so nothing recorded during that period is lost.
func NewStore(path string, legacyJSON ...string) (*Store, error) {
	dsn := "file::memory:"
	fresh := true
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		_, statErr := os.Stat(path)
		fresh = os.IsNotExist(statErr)
		dsn = path + "?_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection, as the Python daemon's one sqlite3 connection: an
	// in-memory database exists only on its connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	pragmas := []string{}
	if fresh {
		pragmas = append(pragmas, "PRAGMA auto_vacuum=INCREMENTAL")
	}
	if path != "" {
		pragmas = append(pragmas, "PRAGMA journal_mode=WAL")
	}
	pragmas = append(pragmas, "PRAGMA synchronous=NORMAL", "PRAGMA busy_timeout=5000")
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, legacy := range legacyJSON {
		if legacy != "" {
			if err := s.importLegacyJSON(legacy); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("importing %s: %w", legacy, err)
			}
		}
	}
	return s, nil
}

func (s *Store) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range schemaStatements {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	existing := map[string]bool{}
	rows, err := tx.Query("PRAGMA table_info(alert_state)")
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	for _, col := range addedColumns {
		if !existing[col[0]] {
			if _, err := tx.Exec("ALTER TABLE alert_state ADD COLUMN " + col[0] + " " + col[1]); err != nil {
				return err
			}
		}
	}
	var version int
	switch err := tx.QueryRow("SELECT version FROM schema_version").Scan(&version); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", SchemaVersion); err != nil {
			return err
		}
	case err != nil:
		return err
	case version < SchemaVersion:
		if _, err := tx.Exec("UPDATE schema_version SET version = ?", SchemaVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type legacySnapshot struct {
	States []AlertState `json:"states"`
	Events []AlertEvent `json:"events"`
}

// importLegacyJSON brings the JSON state of an earlier Go daemon into the
// database: rows the database does not hold yet, and every event (renumbered,
// keeping its time). The file is then renamed, never read again.
func (s *Store) importLegacyJSON(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var snap legacySnapshot
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &snap); err != nil {
			return err
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, st := range snap.States {
		var trigger any
		if st.TriggerDelay != nil {
			trigger = *st.TriggerDelay
		}
		// The same alert in both: the row seen last is the current one (the
		// JSON was written after the database stopped being used, but a row
		// the JSON never touched again may be older than the database's).
		if _, err := tx.Exec("INSERT INTO alert_state ("+stateColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "+
			"ON CONFLICT(rule, subject) DO UPDATE SET state = excluded.state, severity = excluded.severity, "+
			"since_ts = excluded.since_ts, first_seen_ts = MIN(alert_state.first_seen_ts, excluded.first_seen_ts), "+
			"last_seen_ts = excluded.last_seen_ts, last_notified_ts = excluded.last_notified_ts, "+
			"notify_count = excluded.notify_count, summary = excluded.summary, detail = excluded.detail, "+
			"trigger_delay = excluded.trigger_delay, recipient = excluded.recipient, "+
			"acknowledged_ts = excluded.acknowledged_ts, acknowledged_by = excluded.acknowledged_by, "+
			"muted_until = excluded.muted_until, stale_since_ts = excluded.stale_since_ts "+
			"WHERE excluded.last_seen_ts > alert_state.last_seen_ts",
			st.Rule, st.Subject, st.State, st.Severity, st.SinceTS, st.FirstSeenTS, st.LastSeenTS, st.LastNotifiedTS,
			st.NotifyCount, st.Summary, st.Detail, trigger, st.Recipient, st.AcknowledgedTS, st.AcknowledgedBy,
			st.MutedUntil, st.StaleSinceTS); err != nil {
			return err
		}
	}
	for _, ev := range snap.Events {
		if _, err := tx.Exec("INSERT INTO alert_events (ts, rule, subject, transition, severity, summary, detail, delivered, delivery_error) "+
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ev.TS, ev.Rule, ev.Subject, ev.Transition, ev.Severity, ev.Summary,
			ev.Detail, ev.Delivered, ev.DeliveryError); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return os.Rename(path, fmt.Sprintf("%s.imported-%d", path, time.Now().Unix()))
}

// Close closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// TakeErr returns the first error since the last call and clears it.
func (s *Store) TakeErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.err
	s.err = nil
	return err
}

func (s *Store) keep(err error) error {
	if err != nil && s.err == nil {
		s.err = err
	}
	return err
}

// exec runs one statement in its own transaction, as `with self._conn:`.
func (s *Store) exec(query string, args ...any) (sql.Result, error) {
	res, err := s.db.Exec(query, args...)
	return res, s.keep(err)
}

type rowScanner interface{ Scan(...any) error }

func scanState(r rowScanner) (AlertState, error) {
	var st AlertState
	var trigger sql.NullInt64
	err := r.Scan(&st.Rule, &st.Subject, &st.State, &st.Severity, &st.SinceTS, &st.FirstSeenTS, &st.LastSeenTS,
		&st.LastNotifiedTS, &st.NotifyCount, &st.Summary, &st.Detail, &trigger, &st.Recipient, &st.AcknowledgedTS,
		&st.AcknowledgedBy, &st.MutedUntil, &st.StaleSinceTS)
	if trigger.Valid {
		v := int(trigger.Int64)
		st.TriggerDelay = &v
	}
	return st, err
}

func (s *Store) states(query string, args ...any) []AlertState {
	rows, err := s.db.Query("SELECT "+stateColumns+" FROM alert_state "+query, args...)
	if s.keep(err) != nil {
		return []AlertState{}
	}
	defer rows.Close()
	out := []AlertState{}
	for rows.Next() {
		st, err := scanState(rows)
		if s.keep(err) != nil {
			return out
		}
		out = append(out, st)
	}
	s.keep(rows.Err())
	return out
}

func (s *Store) GetState(rule, subject string) (AlertState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := scanState(s.db.QueryRow("SELECT "+stateColumns+" FROM alert_state WHERE rule = ? AND subject = ?", rule, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertState{}, false
	}
	if s.keep(err) != nil {
		return AlertState{}, false
	}
	return st, true
}

// PutState is put_state: an observation never overwrites the operator's
// acknowledgement or mute, nor first_seen_ts, and clears stale_since_ts.
func (s *Store) PutState(st AlertState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var trigger any
	if st.TriggerDelay != nil {
		trigger = *st.TriggerDelay
	}
	_, _ = s.exec(`INSERT INTO alert_state (
            rule, subject, state, severity, since_ts, first_seen_ts,
            last_seen_ts, last_notified_ts, notify_count, summary,
            detail, trigger_delay, recipient
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(rule, subject) DO UPDATE SET
            state = excluded.state,
            stale_since_ts = 0,
            severity = excluded.severity,
            since_ts = excluded.since_ts,
            last_seen_ts = excluded.last_seen_ts,
            last_notified_ts = excluded.last_notified_ts,
            notify_count = excluded.notify_count,
            summary = excluded.summary,
            detail = excluded.detail,
            trigger_delay = excluded.trigger_delay,
            recipient = excluded.recipient`,
		st.Rule, st.Subject, st.State, st.Severity, st.SinceTS, st.FirstSeenTS, st.LastSeenTS, st.LastNotifiedTS,
		st.NotifyCount, st.Summary, st.Detail, trigger, st.Recipient)
}

// SetQuiet is set_quiet. It reports whether the alert exists, and an error
// when the change could not be written, which the API must not call a success.
func (s *Store) SetQuiet(rule, subject string, ackTS int64, ackBy string, mutedUntil int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := []rune(ackBy); len(r) > 120 {
		ackBy = string(r[:120])
	}
	res, err := s.db.Exec("UPDATE alert_state SET acknowledged_ts = ?, acknowledged_by = ?, muted_until = ? WHERE rule = ? AND subject = ?",
		ackTS, ackBy, mutedUntil, rule, subject)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) ClearAcknowledgement(rule, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.exec("UPDATE alert_state SET acknowledged_ts = 0, acknowledged_by = '' WHERE rule = ? AND subject = ?", rule, subject)
}

func (s *Store) DropState(rule, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.exec("DELETE FROM alert_state WHERE rule = ? AND subject = ?", rule, subject)
}

func (s *Store) MarkStale(rule, subject string, since int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.exec("UPDATE alert_state SET stale_since_ts = ? WHERE rule = ? AND subject = ?", since, rule, subject)
}

func (s *Store) OpenStates() []AlertState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states("WHERE state != ? ORDER BY since_ts DESC", StateOK)
}

func (s *Store) ActiveAlerts() []AlertState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states("WHERE state = ? ORDER BY since_ts DESC", StateFiring)
}

func (s *Store) AddEvent(ev AlertEvent) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.exec("INSERT INTO alert_events (ts, rule, subject, transition, severity, summary, detail, delivered, delivery_error) "+
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ev.TS, ev.Rule, ev.Subject, ev.Transition, ev.Severity, ev.Summary,
		ev.Detail, ev.Delivered, ev.DeliveryError)
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func (s *Store) SetDelivery(eventID int64, delivered, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := []rune(errMsg); len(r) > MaxTextChars {
		errMsg = string(r[:MaxTextChars])
	}
	_, _ = s.exec("UPDATE alert_events SET delivered = ?, delivery_error = ? WHERE id = ?", delivered, errMsg, eventID)
}

func (s *Store) Events(f EventFilter) (int, []AlertEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var clauses []string
	var params []any
	if f.Rule != "" {
		clauses = append(clauses, "rule = ?")
		params = append(params, f.Rule)
	}
	if ValidSeverity(f.Severity) {
		clauses = append(clauses, "severity = ?")
		params = append(params, f.Severity)
	}
	if f.Since != 0 {
		clauses = append(clauses, "ts >= ?")
		params = append(params, f.Since)
	}
	if f.Until != 0 {
		clauses = append(clauses, "ts <= ?")
		params = append(params, f.Until)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	limit := 100
	if f.Limit != 0 {
		limit = clampInt(f.Limit, 1, 500)
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	var total int
	if s.keep(s.db.QueryRow("SELECT COUNT(*) FROM alert_events"+where, params...).Scan(&total)) != nil {
		return 0, []AlertEvent{}
	}
	rows, err := s.db.Query("SELECT "+eventColumns+" FROM alert_events"+where+" ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
		append(params, limit, offset)...)
	if s.keep(err) != nil {
		return total, []AlertEvent{}
	}
	defer rows.Close()
	out := []AlertEvent{}
	for rows.Next() {
		var ev AlertEvent
		if s.keep(rows.Scan(&ev.ID, &ev.TS, &ev.Rule, &ev.Subject, &ev.Transition, &ev.Severity, &ev.Summary,
			&ev.Detail, &ev.Delivered, &ev.DeliveryError)) != nil {
			break
		}
		out = append(out, ev)
	}
	s.keep(rows.Err())
	return total, out
}

// DeleteEvents is delete_events: everything, everything before a time, or
// up to 1000 ids. It returns the rows removed.
func (s *Store) DeleteEvents(ids []int64, everything bool, before int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res sql.Result
	var err error
	switch {
	case everything:
		res, err = s.db.Exec("DELETE FROM alert_events")
	case before != 0:
		res, err = s.db.Exec("DELETE FROM alert_events WHERE ts < ?", before)
	default:
		if len(ids) > 1000 {
			ids = ids[:1000]
		}
		if len(ids) == 0 {
			return 0, nil
		}
		marks := make([]string, len(ids))
		args := make([]any, len(ids))
		for i, id := range ids {
			marks[i], args[i] = "?", id
		}
		res, err = s.db.Exec("DELETE FROM alert_events WHERE id IN ("+strings.Join(marks, ", ")+")", args...)
	}
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *Store) NotificationsSince(since int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	s.keep(s.db.QueryRow("SELECT COUNT(*) FROM alert_events WHERE ts >= ? AND transition IN (?, ?)",
		since, TransitionFired, TransitionRepeated).Scan(&n))
	return n
}

// Prune is prune: history and resolved state past the retention period, the
// row caps, then an incremental vacuum.
func (s *Store) Prune(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now - int64(RetentionDays)*86400
	tx, err := s.db.Begin()
	if s.keep(err) != nil {
		return
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"DELETE FROM alert_events WHERE ts < ?", []any{cutoff}},
		{"DELETE FROM alert_events WHERE id NOT IN (SELECT id FROM alert_events ORDER BY id DESC LIMIT ?)", []any{MaxEventRows}},
		{"DELETE FROM alert_state WHERE state = ? AND last_seen_ts < ?", []any{StateOK, cutoff}},
		{"DELETE FROM alert_state WHERE rowid NOT IN (SELECT rowid FROM alert_state ORDER BY last_seen_ts DESC LIMIT ?)", []any{MaxStateRows}},
	} {
		if _, err := tx.Exec(q.sql, q.args...); s.keep(err) != nil {
			_ = tx.Rollback()
			return
		}
	}
	if s.keep(tx.Commit()) != nil {
		return
	}
	_, _ = s.db.Exec("PRAGMA incremental_vacuum")
}

func (s *Store) Stats() StoreStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st StoreStats
	s.keep(s.db.QueryRow("SELECT COUNT(*) FROM alert_state WHERE state = ?", StateFiring).Scan(&st.Firing))
	s.keep(s.db.QueryRow("SELECT COUNT(*) FROM alert_state WHERE state = ?", StatePending).Scan(&st.Pending))
	s.keep(s.db.QueryRow("SELECT COUNT(*) FROM alert_events").Scan(&st.Events))
	if s.path != "" {
		if info, err := os.Stat(s.path); err == nil {
			st.DatabaseBytes = info.Size()
		}
	}
	return st
}
