package app

// Port of audit.py: the change log in the SQLite file the Flask panel uses.

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"easy-ha-proxy/panel/shared/pyyaml"

	_ "modernc.org/sqlite"
)

const (
	auditResultSuccess = "success"
	auditResultFailure = "failure"
	auditResultDenied  = "denied"
	auditMaxSummary    = 500
	auditMaxJSON       = 8192
	auditSchemaVersion = 1
	auditDefaultDays   = 365
	auditMaxRows       = 200000
)

var auditSensitiveKey = regexp.MustCompile(`(?i)pass|secret|token|credential|private|passphrase|cookie|authorization|session|salt|hash|_key$|^key$|apikey|api_key`)

var auditSchema = []string{
	"CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
	`CREATE TABLE IF NOT EXISTS audit_events (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        actor_type  TEXT    NOT NULL,
        actor       TEXT    NOT NULL DEFAULT '',
        source_ip   TEXT    NOT NULL DEFAULT '',
        action      TEXT    NOT NULL,
        object_type TEXT    NOT NULL DEFAULT '',
        object_id   TEXT    NOT NULL DEFAULT '',
        result      TEXT    NOT NULL,
        summary     TEXT    NOT NULL DEFAULT '',
        before_json TEXT    NOT NULL DEFAULT '',
        after_json  TEXT    NOT NULL DEFAULT '',
        detail      TEXT    NOT NULL DEFAULT ''
    )`,
	"CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events (ts DESC)",
	"CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events (actor, ts DESC)",
	"CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, ts DESC)",
	`CREATE INDEX IF NOT EXISTS idx_audit_object
        ON audit_events (object_type, object_id, ts DESC)`,
}

// AuditRedact is redact().
func AuditRedact(v any) any { return auditRedact(v, 0) }

func auditRedact(v any, depth int) any {
	if depth > 6 {
		return "..."
	}
	switch x := v.(type) {
	case *Map:
		clean := pyyaml.NewMap()
		x.Each(func(k, item any) {
			name := pyStr(k)
			if auditSensitiveKey.MatchString(name) {
				if item == nil || item == "" {
					clean.Set(name, nil)
				} else {
					clean.Set(name, "***")
				}
			} else {
				clean.Set(name, auditRedact(item, depth+1))
			}
		})
		return clean
	case []any:
		n := len(x)
		if n > 100 {
			n = 100
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = auditRedact(x[i], depth+1)
		}
		return out
	case string:
		if pyLen(x) > 1000 {
			return truncRunes(x, 1000) + "…"
		}
	}
	return v
}

func auditDump(v any) string {
	if v == nil {
		return ""
	}
	text, err := PyJSON(AuditRedact(v), JSONOpts{SortKeys: true})
	if err != nil {
		text = MustJSON(newMap("unserializable", fmt.Sprintf("<class '%s'>", pyTypeName(v))), JSONOpts{})
	}
	return truncRunes(text, auditMaxJSON)
}

// AuditSummarize is summarize().
func AuditSummarize(before, after any) string {
	b, ok1 := asMap(before)
	a, ok2 := asMap(after)
	if !ok1 || !ok2 {
		return ""
	}
	bc := AuditRedact(b).(*Map)
	ac := AuditRedact(a).(*Map)
	keys := map[string]any{}
	for _, k := range b.Keys() {
		keys[pyStr(k)] = k
	}
	for _, k := range a.Keys() {
		keys[pyStr(k)] = k
	}
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		k := keys[name]
		oldRaw, newRaw := b.Value(k), a.Value(k)
		if pyEqual(oldRaw, newRaw) {
			continue
		}
		old, nw := bc.Value(name), ac.Value(name)
		_, inBefore := b.Get(k)
		_, inAfter := a.Get(k)
		switch {
		case !inBefore:
			parts = append(parts, "+"+name)
		case !inAfter:
			parts = append(parts, "-"+name)
		case auditSensitiveKey.MatchString(name) || pyEqual(old, nw):
			parts = append(parts, name+": changed")
		default:
			parts = append(parts, fmt.Sprintf("%s: %s → %s", name, pyRepr(old), pyRepr(nw)))
		}
	}
	return truncRunes(strings.Join(parts, ", "), auditMaxSummary)
}

// AuditLog is AuditLog.
type AuditLog struct {
	path            string
	mu              sync.Mutex
	db              *sql.DB
	writeFailures   int
	lastError       string
	lastWriteOK     float64
	lastWriteFailed float64
}

var (
	auditOnce sync.Once
	auditInst *AuditLog
)

// Audit is audit_log(): the process-wide store.
func Audit() *AuditLog {
	auditOnce.Do(func() {
		path := os.Getenv("AUDIT_DATABASE")
		if path == "" {
			path = "/var/lib/easy-ha-proxy/audit/audit.db"
		}
		auditInst = &AuditLog{path: path}
	})
	return auditInst
}

func (l *AuditLog) dropConnection() {
	if l.db != nil {
		_ = l.db.Close()
		l.db = nil
	}
}

func (l *AuditLog) noteFailure(err error) {
	l.writeFailures++
	l.lastError = err.Error()
	if l.writeFailures == 1 || l.writeFailures == 10 || l.writeFailures%100 == 0 {
		log.Printf("Audit write failed (%d so far): %v", l.writeFailures, err)
	}
}

func (l *AuditLog) connect() *sql.DB {
	if l.db != nil {
		return l.db
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o777); err != nil {
		l.noteFailure(err)
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+l.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		l.noteFailure(err)
		return nil
	}
	db.SetMaxOpenConns(1)
	setup := func() error {
		for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA busy_timeout=5000"} {
			if _, err := db.Exec(p); err != nil {
				return err
			}
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, s := range auditSchema {
			if _, err := tx.Exec(s); err != nil {
				tx.Rollback()
				return err
			}
		}
		var v int
		if err := tx.QueryRow("SELECT version FROM schema_version").Scan(&v); err == sql.ErrNoRows {
			if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", auditSchemaVersion); err != nil {
				tx.Rollback()
				return err
			}
		} else if err != nil {
			tx.Rollback()
			return err
		}
		return tx.Commit()
	}
	if err := setup(); err != nil {
		db.Close()
		l.noteFailure(err)
		return nil
	}
	l.db = db
	return db
}

// AuditEntry is the keyword arguments of record().
type AuditEntry struct {
	Actor      string
	ActorType  string
	SourceIP   string
	ObjectType string
	ObjectID   string
	Result     string
	Before     any
	After      any
	Summary    string
	Detail     string
}

// Record is AuditLog.record.
func (l *AuditLog) Record(action string, e AuditEntry) bool {
	if e.Result != auditResultSuccess && e.Result != auditResultFailure && e.Result != auditResultDenied {
		e.Result = auditResultSuccess
	}
	if e.ActorType != "user" && e.ActorType != "system" {
		e.ActorType = "system"
	}
	summary := e.Summary
	if summary == "" {
		summary = AuditSummarize(e.Before, e.After)
	}
	args := []any{time.Now().Unix(), e.ActorType, truncRunes(e.Actor, 120), truncRunes(e.SourceIP, 64),
		truncRunes(action, 120), truncRunes(e.ObjectType, 60), truncRunes(e.ObjectID, 200), e.Result,
		truncRunes(summary, auditMaxSummary), auditDump(e.Before), auditDump(e.After), truncRunes(e.Detail, auditMaxSummary)}
	l.mu.Lock()
	defer l.mu.Unlock()
	for attempt := 1; attempt <= 2; attempt++ {
		db := l.connect()
		if db == nil {
			l.lastWriteFailed = nowFloat()
			return false
		}
		_, err := db.Exec("INSERT INTO audit_events (ts, actor_type, actor, source_ip, action, object_type, object_id, result, summary, before_json, after_json, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", args...)
		if err == nil {
			l.lastWriteOK = nowFloat()
			return true
		}
		l.dropConnection()
		if attempt == 1 && strings.Contains(strings.ToLower(err.Error()), "readonly") {
			continue
		}
		l.noteFailure(err)
		l.lastWriteFailed = nowFloat()
		return false
	}
	return false
}

// WriteProblem is write_problem.
func (l *AuditLog) WriteProblem() string {
	checks := []struct {
		path string
		mode uint32
	}{{filepath.Dir(l.path), 2 | 1}, {l.path, 2}, {l.path + "-wal", 2}, {l.path + "-shm", 2}}
	for _, c := range checks {
		info, err := os.Stat(c.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Sprintf("%s: %s", c.path, pyStrerrorOf(err))
		}
		if syscall.Access(c.path, c.mode) != nil {
			st := info.Sys().(*syscall.Stat_t)
			return fmt.Sprintf("%s: owner uid %d, group %d, mode %o; the panel runs as uid %d", c.path, st.Uid, st.Gid, info.Mode().Perm(), os.Getuid())
		}
	}
	if l.lastWriteFailed != 0 && l.lastWriteFailed >= l.lastWriteOK {
		if l.lastError != "" {
			return l.lastError
		}
		return "the last entry could not be written"
	}
	return ""
}

func pyStrerrorOf(err error) string {
	var errno syscall.Errno
	if pe, ok := err.(*os.PathError); ok {
		if e, ok := pe.Err.(syscall.Errno); ok {
			errno = e
			return pyStrerror(errno)
		}
	}
	return err.Error()
}

// AuditQuery are the keyword arguments of query().
type AuditQuery struct {
	Actor, Action, ObjectType, Result string
	Actions                           []string
	Since, Until                      int64
	Limit, Offset                     int64
}

// Query is AuditLog.query.
func (l *AuditLog) Query(q AuditQuery) *Map {
	var clauses []string
	var params []any
	if q.Actor != "" {
		clauses = append(clauses, "actor = ?")
		params = append(params, q.Actor)
	}
	if q.Action != "" {
		clauses = append(clauses, "action = ?")
		params = append(params, q.Action)
	}
	var wanted []string
	for _, a := range q.Actions {
		if a != "" {
			wanted = append(wanted, a)
		}
	}
	if len(wanted) > 100 {
		wanted = wanted[:100]
	}
	if len(wanted) > 0 {
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(wanted)), ", ")
		clauses = append(clauses, "action IN ("+marks+")")
		for _, a := range wanted {
			params = append(params, a)
		}
	}
	if q.ObjectType != "" {
		clauses = append(clauses, "object_type = ?")
		params = append(params, q.ObjectType)
	}
	if q.Result == auditResultSuccess || q.Result == auditResultFailure || q.Result == auditResultDenied {
		clauses = append(clauses, "result = ?")
		params = append(params, q.Result)
	}
	if q.Since != 0 {
		clauses = append(clauses, "ts >= ?")
		params = append(params, q.Since)
	}
	if q.Until != 0 {
		clauses = append(clauses, "ts <= ?")
		params = append(params, q.Until)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	limit = max(1, min(limit, 500))
	offset := max(0, q.Offset)
	l.mu.Lock()
	defer l.mu.Unlock()
	db := l.connect()
	if db == nil {
		return newMap("total", int64(0), "events", []any{}, "available", false, "error", "the change log cannot be opened")
	}
	var total int64
	if err := db.QueryRow("SELECT COUNT(*) AS value FROM audit_events"+where, params...).Scan(&total); err != nil {
		l.noteFailure(err)
		return newMap("total", int64(0), "events", []any{}, "available", false, "error", orValue(truncRunes(err.Error(), 200), "the change log cannot be read"))
	}
	rows, err := db.Query("SELECT id, ts, actor_type, actor, source_ip, action, object_type, object_id, result, summary, before_json, after_json, detail FROM audit_events"+where+" ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", append(params, limit, offset)...)
	if err != nil {
		l.noteFailure(err)
		return newMap("total", int64(0), "events", []any{}, "available", false, "error", orValue(truncRunes(err.Error(), 200), "the change log cannot be read"))
	}
	defer rows.Close()
	events := []any{}
	for rows.Next() {
		var id, ts int64
		var at, actor, ip, action, ot, oid, res, sum, bj, aj, det string
		if err := rows.Scan(&id, &ts, &at, &actor, &ip, &action, &ot, &oid, &res, &sum, &bj, &aj, &det); err != nil {
			continue
		}
		events = append(events, newMap("id", id, "ts", ts, "actor_type", at, "actor", actor, "source_ip", ip, "action", action,
			"object_type", ot, "object_id", oid, "result", res, "summary", sum, "before_json", bj, "after_json", aj, "detail", det))
	}
	return newMap("total", total, "events", events, "available", true)
}

// Distinct is AuditLog.distinct.
func (l *AuditLog) Distinct(column string, limit int64) []any {
	if column != "actor" && column != "action" && column != "object_type" {
		return []any{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	db := l.connect()
	if db == nil {
		return []any{}
	}
	rows, err := db.Query(fmt.Sprintf("SELECT DISTINCT %s AS value FROM audit_events WHERE %s != '' ORDER BY value LIMIT ?", column, column), max(1, min(limit, 500)))
	if err != nil {
		l.noteFailure(err)
		return []any{}
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// Stats is AuditLog.stats.
func (l *AuditLog) Stats() *Map {
	l.mu.Lock()
	defer l.mu.Unlock()
	problem := l.WriteProblem()
	var lastErr any
	if l.lastError != "" {
		lastErr = l.lastError
	}
	writing := func(m *Map) *Map {
		m.Set("writable", problem == "")
		m.Set("write_problem", problem)
		m.Set("write_failures", int64(l.writeFailures))
		m.Set("last_error", lastErr)
		return m
	}
	db := l.connect()
	if db == nil {
		return writing(newMap("available", false))
	}
	var rowsN int64
	var oldest, newest sql.NullInt64
	if err := db.QueryRow("SELECT COUNT(*) AS rows, MIN(ts) AS oldest, MAX(ts) AS newest FROM audit_events").Scan(&rowsN, &oldest, &newest); err != nil {
		l.noteFailure(err)
		return writing(newMap("available", false))
	}
	size := int64(0)
	for _, p := range []string{l.path, l.path + "-wal"} {
		if info, err := os.Stat(p); err == nil {
			size += info.Size()
		}
	}
	var o, n any
	if oldest.Valid {
		o = oldest.Int64
	}
	if newest.Valid {
		n = newest.Int64
	}
	return writing(newMap("available", true, "rows", rowsN, "oldest_ts", o, "newest_ts", n, "bytes", size))
}

// ApplyRetention is apply_retention.
func (l *AuditLog) ApplyRetention(now int64, days, maxRows int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	db := l.connect()
	if db == nil {
		return 0
	}
	tx, err := db.Begin()
	if err != nil {
		l.dropConnection()
		l.noteFailure(err)
		return 0
	}
	r1, err := tx.Exec("DELETE FROM audit_events WHERE ts < ?", now-max(1, days)*86400)
	if err != nil {
		tx.Rollback()
		l.dropConnection()
		l.noteFailure(err)
		return 0
	}
	r2, err := tx.Exec("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)", max(1000, maxRows))
	if err != nil {
		tx.Rollback()
		l.dropConnection()
		l.noteFailure(err)
		return 0
	}
	if err := tx.Commit(); err != nil {
		l.dropConnection()
		l.noteFailure(err)
		return 0
	}
	a, _ := r1.RowsAffected()
	b, _ := r2.RowsAffected()
	return a + b
}

// RecordRequest is record_request: the actor and address from this request.
func (c *Ctx) RecordRequest(action string, e AuditEntry) bool {
	if e.Actor == "" {
		e.Actor = c.User()
	}
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	if e.SourceIP == "" {
		forwarded := strings.Split(c.R.Header.Get("X-Forwarded-For"), ",")
		ip := strings.TrimSpace(forwarded[0])
		if ip == "" {
			ip = remoteHost(c.R.RemoteAddr)
		}
		e.SourceIP = ip
	}
	return Audit().Record(action, e)
}

func remoteHost(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return strings.Trim(addr[:i], "[]")
	}
	return addr
}
