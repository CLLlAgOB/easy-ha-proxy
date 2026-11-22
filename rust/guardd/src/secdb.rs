//! Persistent SQLite `security.db`, a line-for-line port of Python
//! `guardd.storage.SecurityDatabase`. Same schema (v3), same queries, same
//! ordering -- the score depends on the order events are read in.

use crate::constants::{
    utc_now, DECISION_REASON_MAX_BYTES, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED, EVENT_LEGACY_BAN,
    EVENT_LEGACY_BAN_LIFTED, EVENT_QUERY_INJECTION, EVENT_SCANNER_DECISIVE, EVENT_SCANNER_PATH,
    QUALITY_AT_ONCE_SECONDS, QUALITY_NETWORKS_SHOWN, QUALITY_NETWORK_MIN,
};
use crate::haconfig::decision_summary;
use crate::scoring::{enforceable, StoredEvent, Verdict};
use crate::watchers::{Episode, RATE_WARNING};
use regex::Regex;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

pub const SCHEMA_VERSION: i64 = 3;
pub const MAX_PATH_LENGTH: usize = 200;
pub const MANUAL_BAN_REPLACED_MARGIN: i64 = 120;
const OWN_BAN_DETAILS: [&str; 3] = ["code=40", "code=41", "code=50"];
const SIGNATURE_EVENTS_SORTED: [&str; 3] = [EVENT_QUERY_INJECTION, EVENT_SCANNER_PATH, EVENT_SCANNER_DECISIVE];

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS ip_state (
        ip               TEXT PRIMARY KEY,
        family           INTEGER NOT NULL,
        enforceable      INTEGER NOT NULL,
        first_seen       INTEGER NOT NULL,
        last_seen        INTEGER NOT NULL,
        excluded         INTEGER NOT NULL DEFAULT 0,
        exclusion_reason TEXT    NOT NULL DEFAULT '',
        banned_until     INTEGER NOT NULL DEFAULT 0,
        ban_code         INTEGER NOT NULL DEFAULT 0,
        authenticated_at INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS idx_ip_state_banned ON ip_state (banned_until) WHERE banned_until > 0",
    "CREATE INDEX IF NOT EXISTS idx_ip_state_first_seen ON ip_state (first_seen, ip)",
    "CREATE TABLE IF NOT EXISTS security_events (
        id         INTEGER PRIMARY KEY,
        ts         INTEGER NOT NULL,
        ip         TEXT    NOT NULL,
        event_type TEXT    NOT NULL,
        source     TEXT    NOT NULL,
        site       TEXT    NOT NULL DEFAULT '',
        category   TEXT    NOT NULL DEFAULT '',
        detail     TEXT    NOT NULL DEFAULT '',
        handled    INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON security_events (ip, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events (ts)",
    "CREATE TABLE IF NOT EXISTS event_cooldowns (
        fingerprint TEXT PRIMARY KEY,
        last_ts     INTEGER NOT NULL
    ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS guard_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS rate_warnings (
        id           INTEGER PRIMARY KEY,
        ip           TEXT    NOT NULL,
        site         TEXT    NOT NULL,
        trust        TEXT    NOT NULL,
        rate_limit   INTEGER NOT NULL,
        window_s     INTEGER NOT NULL,
        enforced     INTEGER NOT NULL DEFAULT 1,
        started      INTEGER NOT NULL,
        ended        INTEGER NOT NULL,
        peak         INTEGER NOT NULL,
        over_limit   INTEGER NOT NULL,
        requests     INTEGER NOT NULL,
        rate_limited INTEGER NOT NULL DEFAULT 0,
        banned       INTEGER NOT NULL DEFAULT 0,
        rate_ban     INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS idx_rate_warnings_ended ON rate_warnings (ended)",
    "CREATE TABLE IF NOT EXISTS manual_bans (
        ip          TEXT    PRIMARY KEY,
        placed_at   INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        seen_at     INTEGER NOT NULL,
        reasserted  INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE TABLE IF NOT EXISTS ban_decisions (
        id       INTEGER PRIMARY KEY,
        ts       INTEGER NOT NULL,
        ip       TEXT    NOT NULL,
        action   TEXT    NOT NULL,
        source   TEXT    NOT NULL,
        code     INTEGER NOT NULL DEFAULT 0,
        until    INTEGER NOT NULL DEFAULT 0,
        strike   INTEGER NOT NULL DEFAULT 0,
        score    INTEGER NOT NULL DEFAULT 0,
        policy   TEXT    NOT NULL DEFAULT '',
        outcome  TEXT    NOT NULL,
        reason   TEXT    NOT NULL DEFAULT '{}'
    )",
    "CREATE INDEX IF NOT EXISTS idx_ban_decisions_ip ON ban_decisions (ip, ts)",
];

const RATE_WARNING_COLUMNS: [&str; 14] = [
    "ip", "site", "trust", "rate_limit", "window_s", "enforced", "started", "ended", "peak",
    "over_limit", "requests", "rate_limited", "banned", "rate_ban",
];

pub type DbResult<T> = Result<T, String>;

fn e(err: rusqlite::Error) -> String {
    err.to_string()
}

/// A manual ban as remembered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualBan {
    pub placed_at: i64,
    pub expires_at: i64,
    pub seen_at: i64,
    pub reasserted: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Decision<'a> {
    pub code: i64,
    pub until: i64,
    pub strike: i64,
    pub score: i64,
    pub policy: &'a str,
    pub reason: Option<Value>,
}

/// A JSON object row from named columns.
fn row_object(row: &Row<'_>, names: &[&str]) -> rusqlite::Result<Value> {
    let mut m = Map::new();
    for (i, name) in names.iter().enumerate() {
        let v: SqlValue = row.get(i)?;
        m.insert((*name).to_string(), sql_to_json(v));
    }
    Ok(Value::Object(m))
}

fn sql_to_json(v: SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(i) => json!(i),
        SqlValue::Real(f) => json!(f),
        SqlValue::Text(s) => json!(s),
        SqlValue::Blob(b) => json!(String::from_utf8_lossy(&b)),
    }
}

fn parse_reason(text: &str) -> Value {
    match serde_json::from_str::<Value>(text) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

/// Python's `json.dumps(obj, sort_keys=True, ensure_ascii=False)`, compact
/// separators aside: keys sorted at every level.
pub fn sorted_json(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let ordered: BTreeMap<&String, Value> = m.iter().map(|(k, v)| (k, sort(v))).collect();
                let mut out = Map::new();
                for (k, v) in ordered {
                    out.insert(k.clone(), v);
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    python_json(&sort(v))
}

/// Serialise like Python's default `json.dumps` (", " and ": " separators),
/// so stored text matches what the Python daemon wrote.
pub fn python_json(v: &Value) -> String {
    let mut out = String::new();
    write_py(v, &mut out);
    out
}

fn write_py(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push_str(": ");
                write_py(val, out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, val) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py(val, out);
            }
            out.push(']');
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64().filter(|_| n.is_f64()) {
                if f.fract() == 0.0 && f.is_finite() && f.abs() < 1e16 {
                    out.push_str(&format!("{f:.1}"));
                } else {
                    out.push_str(&n.to_string());
                }
            } else {
                out.push_str(&n.to_string());
            }
        }
        other => out.push_str(&other.to_string()),
    }
}

pub struct SecurityDatabase {
    conn: Mutex<Connection>,
    pub path: PathBuf,
}

impl SecurityDatabase {
    pub fn open(path: impl AsRef<Path>) -> DbResult<Self> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("mkdir failed: {err}"))?;
        }
        let fresh = !p.exists();
        let conn = Connection::open(&p).map_err(|err| format!("sqlite open failed: {err}"))?;
        if fresh {
            conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;").map_err(e)?;
        }
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
            .map_err(e)?;
        let db = Self { conn: Mutex::new(conn), path: p };
        db.migrate()?;
        Ok(db)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> DbResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        for stmt in SCHEMA {
            tx.execute(stmt, []).map_err(e)?;
        }
        let current: Option<i64> = tx
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()
            .map_err(e)?;
        match current {
            None => {
                tx.execute("INSERT INTO schema_version (version) VALUES (?1)", params![SCHEMA_VERSION])
                    .map_err(e)?;
            }
            Some(v) if v > SCHEMA_VERSION => {
                return Err(format!(
                    "security database schema v{v} is newer than the supported v{SCHEMA_VERSION}"
                ));
            }
            Some(mut v) => {
                while v < SCHEMA_VERSION {
                    match v + 1 {
                        2 => add_column(&tx, "security_events", "handled", "INTEGER NOT NULL DEFAULT 0")?,
                        3 => add_column(&tx, "ip_state", "authenticated_at", "INTEGER NOT NULL DEFAULT 0")?,
                        _ => {}
                    }
                    v += 1;
                }
                tx.execute("UPDATE schema_version SET version = ?1", params![v]).map_err(e)?;
            }
        }
        tx.commit().map_err(e)
    }

    pub fn get_state(&self, key: &str, default: &str) -> String {
        self.lock()
            .query_row("SELECT value FROM guard_state WHERE key = ?1", params![key], |r| r.get::<_, String>(0))
            .optional()
            .ok()
            .flatten()
            .unwrap_or_else(|| default.to_string())
    }

    pub fn set_state(&self, key: &str, value: &str) -> DbResult<()> {
        self.lock()
            .execute(
                "INSERT INTO guard_state (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(e)
    }

    pub fn set_states(&self, values: &[(String, String)]) -> DbResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        for (k, v) in values {
            tx.execute(
                "INSERT INTO guard_state (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![k, v],
            )
            .map_err(e)?;
        }
        tx.commit().map_err(e)
    }

    pub fn observe_ip(&self, ip: &str, ts: i64, verdict: &Verdict) -> DbResult<()> {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            return Ok(());
        };
        let family = if addr.is_ipv4() { 4 } else { 6 };
        self.lock()
            .execute(
                "INSERT INTO ip_state \
                 (ip, family, enforceable, first_seen, last_seen, excluded, exclusion_reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT (ip) DO UPDATE SET last_seen = excluded.last_seen, \
                 excluded = excluded.excluded, exclusion_reason = excluded.exclusion_reason",
                params![
                    ip,
                    family,
                    i64::from(enforceable(ip)),
                    ts,
                    ts,
                    i64::from(verdict.excluded),
                    verdict.reason
                ],
            )
            .map(|_| ())
            .map_err(e)
    }

    /// Write events; `detail` is cut to the path limit like Python.
    pub fn record_events(&self, events: &[NewEvent]) -> DbResult<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        for ev in events {
            tx.execute(
                "INSERT INTO security_events (ts, ip, event_type, source, site, category, detail, handled) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    ev.ts,
                    ev.ip,
                    ev.event_type,
                    ev.source,
                    ev.site,
                    ev.category,
                    truncate(&ev.detail, MAX_PATH_LENGTH),
                    i64::from(ev.handled)
                ],
            )
            .map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(events.len())
    }

    pub fn record_authenticated(&self, ips: &[String], ts: i64) -> DbResult<usize> {
        if ips.is_empty() {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let mut updated = 0;
        for ip in ips {
            updated += tx
                .execute("UPDATE ip_state SET authenticated_at = ?1 WHERE ip = ?2", params![ts, ip])
                .map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(updated)
    }

    pub fn set_ban(&self, ip: &str, until: i64, code: i64, now: i64) -> DbResult<()> {
        self.exec(
            "UPDATE ip_state SET banned_until = ?1, ban_code = ?2, last_seen = ?3 WHERE ip = ?4",
            params![until, code, now, ip],
        )
    }

    pub fn clear_ban(&self, ip: &str) -> DbResult<()> {
        self.exec("UPDATE ip_state SET banned_until = 0, ban_code = 0 WHERE ip = ?1", params![ip])
    }

    fn exec(&self, sql: &str, p: impl rusqlite::Params) -> DbResult<()> {
        self.lock().execute(sql, p).map(|_| ()).map_err(e)
    }

    // -- ban decisions ------------------------------------------------------

    pub fn record_decision(&self, ip: &str, ts: i64, action: &str, source: &str, outcome: &str, d: Decision<'_>) -> DbResult<i64> {
        let reason = d.reason.unwrap_or_else(|| json!({}));
        let mut text = sorted_json(&reason);
        if text.len() > DECISION_REASON_MAX_BYTES {
            text = sorted_json(&json!({"truncated": true}));
        }
        let conn = self.lock();
        conn.execute(
            "INSERT INTO ban_decisions \
             (ts, ip, action, source, code, until, strike, score, policy, outcome, reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![ts, ip, action, source, d.code, d.until, d.strike, d.score, d.policy, outcome, text],
        )
        .map_err(e)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn settle_decision(&self, id: i64, outcome: &str) -> DbResult<()> {
        self.exec(
            "UPDATE ban_decisions SET outcome = ?1 WHERE id = ?2 AND outcome = 'pending'",
            params![outcome, id],
        )
    }

    pub fn commit_ban(&self, decision_id: i64, ip: &str, until: i64, code: i64, now: i64, detail: &str) -> DbResult<()> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        tx.execute(
            "UPDATE ip_state SET banned_until = ?1, ban_code = ?2, last_seen = ?3 WHERE ip = ?4",
            params![until, code, now, ip],
        )
        .map_err(e)?;
        tx.execute(
            "INSERT INTO security_events (ts, ip, event_type, source, site, category, detail, handled) \
             VALUES (?1, ?2, ?3, 'guardd', '', '', ?4, 0)",
            params![now, ip, EVENT_BAN_APPLIED, truncate(detail, MAX_PATH_LENGTH)],
        )
        .map_err(e)?;
        tx.execute(
            "UPDATE ban_decisions SET outcome = 'applied' WHERE id = ?1 AND outcome = 'pending'",
            params![decision_id],
        )
        .map_err(e)?;
        tx.commit().map_err(e)
    }

    pub fn pending_decisions(&self, before: i64) -> DbResult<Vec<Value>> {
        self.rows(
            "SELECT id, ts, ip, code, until, strike, score FROM ban_decisions \
             WHERE outcome = 'pending' AND ts < ?1 ORDER BY ts",
            &[SqlValue::Integer(before)],
            &["id", "ts", "ip", "code", "until", "strike", "score"],
        )
    }

    fn rows(&self, sql: &str, args: &[SqlValue], names: &[&str]) -> DbResult<Vec<Value>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(sql).map_err(e)?;
        let mapped = stmt.query_map(params_from_iter(args.iter()), |r| row_object(r, names)).map_err(e)?;
        mapped.collect::<Result<Vec<_>, _>>().map_err(e)
    }

    fn scalar_i64(&self, sql: &str, args: &[SqlValue]) -> i64 {
        self.lock()
            .query_row(sql, params_from_iter(args.iter()), |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    const DECISION_COLUMNS: [&'static str; 12] =
        ["id", "ts", "ip", "action", "source", "code", "until", "strike", "score", "policy", "outcome", "reason"];

    pub fn ban_decisions(&self, ip: &str, limit: i64) -> DbResult<Vec<Value>> {
        let mut rows = self.rows(
            "SELECT id, ts, ip, action, source, code, until, strike, score, policy, outcome, reason \
             FROM ban_decisions WHERE ip = ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
            &[SqlValue::Text(ip.into()), SqlValue::Integer(limit)],
            &Self::DECISION_COLUMNS,
        )?;
        for row in rows.iter_mut() {
            let text = row["reason"].as_str().unwrap_or("{}").to_string();
            row["reason"] = parse_reason(if text.is_empty() { "{}" } else { &text });
        }
        Ok(rows)
    }

    pub fn decision_feed(&self, before: i64, limit: i64, actions: &[&str]) -> DbResult<Vec<Value>> {
        let mut clauses = Vec::new();
        let mut values: Vec<SqlValue> = Vec::new();
        if before > 0 {
            clauses.push("id < ?".to_string());
            values.push(SqlValue::Integer(before));
        }
        if !actions.is_empty() {
            clauses.push(format!("action IN ({})", vec!["?"; actions.len()].join(", ")));
            values.extend(actions.iter().map(|a| SqlValue::Text((*a).into())));
        }
        let where_ = if clauses.is_empty() { String::new() } else { format!("WHERE {} ", clauses.join(" AND ")) };
        values.push(SqlValue::Integer(limit + 1));
        let sql = format!(
            "SELECT id, ts, ip, action, source, code, until, strike, score, policy, outcome, reason \
             FROM ban_decisions {where_}ORDER BY id DESC LIMIT ?"
        );
        let mut rows = self.rows(&sql, &values, &Self::DECISION_COLUMNS)?;
        for row in rows.iter_mut() {
            let obj = row.as_object_mut().expect("row object");
            let reason = obj.remove("reason").and_then(|v| v.as_str().map(parse_reason)).unwrap_or_else(|| json!({}));
            obj.insert("summary".into(), decision_summary(&reason));
        }
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn adaptive_ban_history(
        &self,
        query: &str,
        since: i64,
        sort: &str,
        direction: &str,
        offset: i64,
        snapshot: i64,
        limit: i64,
        terms: &[String],
    ) -> DbResult<Value> {
        let column = match sort {
            "ts" | "ip" | "score" | "strike" | "until" => sort,
            _ => return Err("Invalid ban history sort".into()),
        };
        if direction != "asc" && direction != "desc" {
            return Err("Invalid ban history sort".into());
        }
        let snapshot = if snapshot != 0 {
            snapshot
        } else {
            self.scalar_i64("SELECT COALESCE(MAX(id), 0) FROM ban_decisions", &[])
        };
        let mut where_ = "source = 'adaptive' AND action = 'applied' AND outcome = 'applied' AND id <= ? AND ts >= ?".to_string();
        let mut values = vec![SqlValue::Integer(snapshot), SqlValue::Integer(since)];
        if !query.is_empty() {
            static TERM: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
            let term_re = TERM.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("regex"));
            where_.push_str(" AND (instr(ip, ?) > 0 OR instr(lower(reason), lower(?)) > 0");
            values.push(SqlValue::Text(query.into()));
            values.push(SqlValue::Text(query.into()));
            for term in terms.iter().take(32).filter(|t| term_re.is_match(t)) {
                where_.push_str(" OR instr(lower(reason), lower(?)) > 0");
                values.push(SqlValue::Text(term.clone()));
            }
            where_.push(')');
        }
        let total = self.scalar_i64(&format!("SELECT COUNT(*) FROM ban_decisions WHERE {where_}"), &values);
        let mut page = values.clone();
        page.push(SqlValue::Integer(limit));
        page.push(SqlValue::Integer(offset));
        let sql = format!(
            "SELECT id, ts, ip, until, strike, score, reason FROM ban_decisions \
             WHERE {where_} ORDER BY {column} {direction}, id {direction} LIMIT ? OFFSET ?"
        );
        let mut rows = self.rows(&sql, &page, &["id", "ts", "ip", "until", "strike", "score", "reason"])?;
        for row in rows.iter_mut() {
            let obj = row.as_object_mut().expect("row object");
            let reason = obj.remove("reason").and_then(|v| v.as_str().map(parse_reason)).unwrap_or_else(|| json!({}));
            let cats = decision_summary(&reason).get("categories").cloned().unwrap_or_else(|| json!([]));
            obj.insert("categories".into(), cats);
        }
        Ok(json!({"bans": rows, "total": total, "snapshot": snapshot, "offset": offset, "limit": limit}))
    }

    pub fn adaptive_ban_detail(&self, decision_id: i64, ip: &str, at: i64, until: i64) -> DbResult<Option<Value>> {
        let (where_, values) = if decision_id != 0 {
            ("id = ?", vec![SqlValue::Integer(decision_id)])
        } else if until != 0 {
            ("ip = ? AND until = ?", vec![SqlValue::Text(ip.into()), SqlValue::Integer(until)])
        } else {
            ("ip = ? AND ts = ?", vec![SqlValue::Text(ip.into()), SqlValue::Integer(at)])
        };
        let sql = format!(
            "SELECT id, ts, ip, until, strike, score, reason FROM ban_decisions \
             WHERE {where_} AND source = 'adaptive' AND action = 'applied' AND outcome = 'applied' \
             ORDER BY id DESC LIMIT 1"
        );
        let mut rows = self.rows(&sql, &values, &["id", "ts", "ip", "until", "strike", "score", "reason"])?;
        let Some(mut row) = rows.pop() else {
            return Ok(None);
        };
        let text = row["reason"].as_str().unwrap_or("{}").to_string();
        row["reason"] = parse_reason(if text.is_empty() { "{}" } else { &text });
        Ok(Some(row))
    }

    pub fn prune_decisions(&self, before: i64, keep: i64, now: i64) -> DbResult<i64> {
        let now = if now != 0 { now } else { utc_now() };
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let mut deleted = tx
            .execute("DELETE FROM ban_decisions WHERE ts < ?1 AND until <= ?2", params![before, now])
            .map_err(e)?;
        deleted += tx
            .execute(
                "DELETE FROM ban_decisions WHERE until <= ?1 AND id NOT IN \
                 (SELECT id FROM ban_decisions ORDER BY ts DESC, id DESC LIMIT ?2)",
                params![now, keep],
            )
            .map_err(e)?;
        tx.commit().map_err(e)?;
        Ok(deleted as i64)
    }

    // -- the operator's bans -------------------------------------------------

    pub fn manual_bans(&self) -> DbResult<BTreeMap<String, ManualBan>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT ip, placed_at, expires_at, seen_at, reasserted FROM manual_bans")
            .map_err(e)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    ManualBan { placed_at: r.get(1)?, expires_at: r.get(2)?, seen_at: r.get(3)?, reasserted: r.get(4)? },
                ))
            })
            .map_err(e)?;
        rows.collect::<Result<BTreeMap<_, _>, _>>().map_err(e)
    }

    pub fn note_manual_ban(&self, ip: &str, now: i64, expires_at: i64) -> DbResult<()> {
        self.exec(
            "INSERT INTO manual_bans (ip, placed_at, expires_at, seen_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (ip) DO UPDATE SET seen_at = excluded.seen_at, \
             expires_at = CASE WHEN manual_bans.reasserted = 0 \
             AND excluded.expires_at > manual_bans.expires_at + ?5 \
             THEN excluded.expires_at ELSE manual_bans.expires_at END",
            params![ip, now, expires_at, now, MANUAL_BAN_REPLACED_MARGIN],
        )
    }

    pub fn write_manual_ban(&self, ip: &str, placed_at: i64, expires_at: i64, seen_at: i64, reasserted: i64) -> DbResult<()> {
        self.exec(
            "INSERT INTO manual_bans (ip, placed_at, expires_at, seen_at, reasserted) \
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (ip) DO UPDATE SET \
             placed_at = excluded.placed_at, expires_at = excluded.expires_at, \
             seen_at = excluded.seen_at, reasserted = excluded.reasserted",
            params![ip, placed_at, expires_at, seen_at, reasserted],
        )
    }

    pub fn mark_manual_reasserted(&self, ip: &str) -> DbResult<()> {
        self.exec("UPDATE manual_bans SET reasserted = 1 WHERE ip = ?1", params![ip])
    }

    pub fn forget_manual_ban(&self, ip: &str) -> DbResult<bool> {
        self.lock()
            .execute("DELETE FROM manual_bans WHERE ip = ?1", params![ip])
            .map(|n| n > 0)
            .map_err(e)
    }

    pub fn scheduled_bans(&self) -> DbResult<BTreeMap<String, i64>> {
        self.ip_pairs("SELECT ip, banned_until FROM ip_state WHERE banned_until > 0")
    }

    pub fn scheduled_ban_codes(&self) -> DbResult<BTreeMap<String, i64>> {
        self.ip_pairs("SELECT ip, COALESCE(ban_code, 0) FROM ip_state WHERE banned_until > 0")
    }

    fn ip_pairs(&self, sql: &str) -> DbResult<BTreeMap<String, i64>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(sql).map_err(e)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(e)?;
        rows.collect::<Result<BTreeMap<_, _>, _>>().map_err(e)
    }

    pub fn set_ban_code(&self, ip: &str, code: i64) -> DbResult<()> {
        self.exec("UPDATE ip_state SET ban_code = ?1 WHERE ip = ?2", params![code, ip])
    }

    pub fn last_ban_ts(&self, ip: &str) -> i64 {
        self.scalar_i64(
            "SELECT MAX(ts) FROM security_events WHERE ip = ?1 AND event_type = ?2",
            &[SqlValue::Text(ip.into()), SqlValue::Text(EVENT_BAN_APPLIED.into())],
        )
    }

    pub fn last_ban_detail(&self, ip: &str) -> String {
        self.lock()
            .query_row(
                "SELECT detail FROM security_events WHERE ip = ?1 AND event_type = ?2 ORDER BY ts DESC LIMIT 1",
                params![ip, EVENT_BAN_APPLIED],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten()
            .unwrap_or_default()
    }

    pub fn newest_finding_ts(&self, ip: &str) -> i64 {
        let mut args = vec![
            SqlValue::Text(ip.into()),
            SqlValue::Text(EVENT_BAN_APPLIED.into()),
            SqlValue::Text(EVENT_BAN_LIFTED.into()),
            SqlValue::Text(EVENT_LEGACY_BAN.into()),
        ];
        args.extend(OWN_BAN_DETAILS.iter().map(|d| SqlValue::Text((*d).into())));
        self.scalar_i64(
            "SELECT MAX(ts) FROM security_events WHERE ip = ? AND event_type NOT IN (?, ?) \
             AND NOT (event_type = ? AND detail IN (?,?,?))",
            &args,
        )
    }

    pub fn ban_timestamps(&self, ip: &str, limit: i64) -> DbResult<Vec<i64>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT ts FROM security_events WHERE ip = ?1 AND event_type = ?2 ORDER BY ts DESC LIMIT ?3")
            .map_err(e)?;
        let mut out: Vec<i64> = stmt
            .query_map(params![ip, EVENT_BAN_APPLIED, limit], |r| r.get(0))
            .map_err(e)?
            .collect::<Result<_, _>>()
            .map_err(e)?;
        out.sort_unstable();
        Ok(out)
    }

    pub fn strike_count(&self, ip: &str, since: i64) -> i64 {
        self.scalar_i64(
            "SELECT COUNT(*) FROM security_events WHERE ip = ?1 AND event_type = ?2 AND ts >= ?3",
            &[SqlValue::Text(ip.into()), SqlValue::Text(EVENT_BAN_APPLIED.into()), SqlValue::Integer(since)],
        )
    }

    pub fn ip_facts(&self, ip: &str) -> Value {
        self.rows(
            "SELECT first_seen, last_seen, excluded, exclusion_reason, authenticated_at FROM ip_state WHERE ip = ?1",
            &[SqlValue::Text(ip.into())],
            &["first_seen", "last_seen", "excluded", "exclusion_reason", "authenticated_at"],
        )
        .ok()
        .and_then(|mut r| r.pop())
        .unwrap_or_else(|| json!({}))
    }

    pub fn last_applied_ban(&self, ip: &str) -> Option<(i64, i64)> {
        self.lock()
            .query_row(
                "SELECT code, until FROM ban_decisions WHERE ip = ?1 AND action = 'applied' \
                 AND outcome = 'applied' ORDER BY ts DESC, id DESC LIMIT 1",
                params![ip],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn signature_paths_since(&self, ip: &str, since: i64) -> i64 {
        let mut args = vec![SqlValue::Text(ip.into()), SqlValue::Integer(since)];
        args.extend(SIGNATURE_EVENTS_SORTED.iter().map(|s| SqlValue::Text((*s).into())));
        self.scalar_i64(
            "SELECT COUNT(DISTINCT detail) FROM security_events WHERE ip = ? AND ts > ? AND event_type IN (?,?,?)",
            &args,
        )
    }

    pub fn last_signature(&self, ip: &str, since: i64, until: i64) -> i64 {
        let mut args = vec![SqlValue::Text(ip.into()), SqlValue::Integer(since), SqlValue::Integer(until)];
        args.extend(SIGNATURE_EVENTS_SORTED.iter().map(|s| SqlValue::Text((*s).into())));
        self.scalar_i64(
            "SELECT MAX(ts) FROM security_events WHERE ip = ? AND ts BETWEEN ? AND ? AND event_type IN (?,?,?)",
            &args,
        )
    }

    /// Newest first, at most `limit`: the order the score is computed in.
    pub fn events_for(&self, ip: &str, since: i64, limit: i64) -> DbResult<Vec<StoredEvent>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT ts, event_type, source, site, category, detail, handled \
                 FROM security_events WHERE ip = ?1 AND ts >= ?2 ORDER BY ts DESC, id DESC LIMIT ?3",
            )
            .map_err(e)?;
        let rows = stmt
            .query_map(params![ip, since, limit], |r| {
                Ok(StoredEvent {
                    ts: r.get(0)?,
                    event_type: r.get(1)?,
                    site: r.get(3)?,
                    category: r.get(4)?,
                    detail: r.get(5)?,
                    handled: r.get::<_, i64>(6)? != 0,
                })
            })
            .map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)
    }

    /// The same rows with `source`, as the API shows them.
    pub fn events_for_json(&self, ip: &str, since: i64, limit: i64) -> DbResult<Vec<Value>> {
        self.rows(
            "SELECT ts, event_type, source, site, category, detail, handled \
             FROM security_events WHERE ip = ?1 AND ts >= ?2 ORDER BY ts DESC, id DESC LIMIT ?3",
            &[SqlValue::Text(ip.into()), SqlValue::Integer(since), SqlValue::Integer(limit)],
            &["ts", "event_type", "source", "site", "category", "detail", "handled"],
        )
    }

    pub fn active_addresses(&self, since: i64, limit: i64) -> DbResult<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT ip, COUNT(*) AS hits FROM security_events WHERE ts >= ?1 GROUP BY ip ORDER BY hits DESC LIMIT ?2")
            .map_err(e)?;
        let rows = stmt.query_map(params![since, limit], |r| r.get::<_, String>(0)).map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)
    }

    pub fn enforcement_addresses(&self, after: (i64, &str), before: i64, limit: i64) -> DbResult<Vec<(i64, String)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT first_seen, ip FROM ip_state WHERE (first_seen, ip) > (?1, ?2) AND first_seen <= ?3 \
                 ORDER BY first_seen, ip LIMIT ?4",
            )
            .map_err(e)?;
        let rows = stmt
            .query_map(params![after.0, after.1, before, limit], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)
    }

    pub fn recent_findings(&self, limit: i64) -> DbResult<Vec<(String, i64, String, bool)>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT ip, ts, event_type, handled FROM security_events ORDER BY id DESC LIMIT ?1")
            .map_err(e)?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0))
            })
            .map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)
    }

    pub fn cooldown_passed(&self, fingerprint: &str, ts: i64, window: i64) -> DbResult<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let last: Option<i64> = tx
            .query_row("SELECT last_ts FROM event_cooldowns WHERE fingerprint = ?1", params![fingerprint], |r| r.get(0))
            .optional()
            .map_err(e)?;
        if let Some(last) = last {
            if ts - last < window {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO event_cooldowns (fingerprint, last_ts) VALUES (?1, ?2) \
             ON CONFLICT (fingerprint) DO UPDATE SET last_ts = excluded.last_ts",
            params![fingerprint, ts],
        )
        .map_err(e)?;
        tx.commit().map_err(e)?;
        Ok(true)
    }

    pub fn apply_retention(&self, events_before: i64, bans_before: i64) -> DbResult<BTreeMap<String, i64>> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let mut events = tx
            .execute(
                "DELETE FROM security_events WHERE ts < ?1 AND event_type NOT IN (?2, ?3)",
                params![events_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED],
            )
            .map_err(e)?;
        events += tx
            .execute(
                "DELETE FROM security_events WHERE ts < ?1 AND event_type IN (?2, ?3)",
                params![bans_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED],
            )
            .map_err(e)?;
        let cooldowns = tx
            .execute("DELETE FROM event_cooldowns WHERE last_ts < ?1", params![events_before])
            .map_err(e)?;
        let addresses = tx
            .execute("DELETE FROM ip_state WHERE last_seen < ?1 AND banned_until = 0", params![events_before])
            .map_err(e)?;
        tx.commit().map_err(e)?;
        let mut out = BTreeMap::new();
        out.insert("events".to_string(), events as i64);
        out.insert("cooldowns".to_string(), cooldowns as i64);
        out.insert("addresses".to_string(), addresses as i64);
        Ok(out)
    }

    // -- rate warnings --------------------------------------------------------

    pub fn record_rate_warnings(&self, episodes: &[Episode]) -> DbResult<usize> {
        if episodes.is_empty() {
            return Ok(0);
        }
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let sql = format!(
            "INSERT INTO rate_warnings ({}) VALUES ({})",
            RATE_WARNING_COLUMNS.join(", "),
            vec!["?"; RATE_WARNING_COLUMNS.len()].join(", ")
        );
        for ep in episodes {
            tx.execute(
                &sql,
                params![
                    ep.ip,
                    ep.site,
                    ep.trust,
                    ep.limit,
                    ep.window,
                    i64::from(ep.enforced),
                    ep.started,
                    ep.ended,
                    ep.peak,
                    ep.over_limit,
                    ep.requests,
                    ep.rate_limited,
                    ep.banned,
                    i64::from(ep.rate_ban)
                ],
            )
            .map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(episodes.len())
    }

    pub fn rate_warnings(&self, limit: i64) -> DbResult<Vec<Value>> {
        let sql = format!(
            "SELECT {} FROM rate_warnings ORDER BY ended DESC, id DESC LIMIT ?1",
            RATE_WARNING_COLUMNS.join(", ")
        );
        let mut rows = self.rows(&sql, &[SqlValue::Integer(limit.max(1))], &RATE_WARNING_COLUMNS)?;
        for row in rows.iter_mut() {
            let obj = row.as_object_mut().expect("row object");
            obj.insert("kind".into(), json!(RATE_WARNING));
            let limit = obj.remove("rate_limit").unwrap_or(Value::Null);
            obj.insert("limit".into(), limit);
            let window = obj.remove("window_s").unwrap_or(Value::Null);
            obj.insert("window".into(), window);
            let enforced = obj.get("enforced").and_then(Value::as_i64).unwrap_or(0) != 0;
            obj.insert("enforced".into(), json!(enforced));
            let rate_ban = obj.get("rate_ban").and_then(Value::as_i64).unwrap_or(0) != 0;
            obj.insert("rate_ban".into(), json!(rate_ban));
            obj.insert("open".into(), json!(false));
        }
        Ok(rows)
    }

    pub fn rate_warning_count(&self, since: i64) -> i64 {
        self.scalar_i64("SELECT COUNT(*) FROM rate_warnings WHERE ended >= ?1", &[SqlValue::Integer(since)])
    }

    pub fn prune_rate_warnings(&self, before: i64, keep: i64) -> DbResult<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(e)?;
        let mut deleted = tx.execute("DELETE FROM rate_warnings WHERE ended < ?1", params![before]).map_err(e)?;
        deleted += tx
            .execute(
                "DELETE FROM rate_warnings WHERE id NOT IN (SELECT id FROM rate_warnings ORDER BY id DESC LIMIT ?1)",
                params![keep.max(0)],
            )
            .map_err(e)?;
        tx.commit().map_err(e)?;
        Ok(deleted as i64)
    }

    pub fn incremental_vacuum(&self, pages: i64) {
        let _ = self.lock().execute_batch(&format!("PRAGMA incremental_vacuum({pages});"));
    }

    // -- reporting --------------------------------------------------------------

    pub fn quality(&self, since: i64, now: i64) -> DbResult<Value> {
        let bans = self.rows(
            "SELECT ip, ts, until, strike, score, reason FROM ban_decisions \
             WHERE action = 'applied' AND source = 'adaptive' AND ts >= ?1 ORDER BY ts",
            &[SqlValue::Integer(since)],
            &["ip", "ts", "until", "strike", "score", "reason"],
        )?;
        let first = self.lock()
            .query_row("SELECT MIN(ts) FROM ban_decisions", [], |r| r.get::<_, Option<i64>>(0))
            .map_err(e)?;
        let operator_lifts = self.rows(
            "SELECT ip, ts FROM ban_decisions WHERE action = 'lifted' AND source = 'operator' AND ts >= ?1",
            &[SqlValue::Integer(since)],
            &["ip", "ts"],
        )?;
        let lifted_by_operator = operator_lifts.len();
        let mut lifted_ts_by_ip: HashMap<String, Vec<i64>> = HashMap::new();
        for row in &operator_lifts {
            lifted_ts_by_ip
                .entry(row["ip"].as_str().unwrap_or("").to_string())
                .or_default()
                .push(row["ts"].as_i64().unwrap_or(0));
        }
        let auth_at_by_ip: HashMap<String, i64> = self
            .rows(
                "SELECT ip, authenticated_at FROM ip_state WHERE authenticated_at > 0",
                &[],
                &["ip", "authenticated_at"],
            )?
            .into_iter()
            .map(|r| (r["ip"].as_str().unwrap_or("").to_string(), r["authenticated_at"].as_i64().unwrap_or(0)))
            .collect();
        let quiet = [EVENT_BAN_APPLIED, EVENT_BAN_LIFTED, EVENT_LEGACY_BAN, EVENT_LEGACY_BAN_LIFTED];
        let mut at_once = 0i64;
        let mut single = 0i64;
        {
            let conn = self.lock();
            for ban in &bans {
                let ip = ban["ip"].as_str().unwrap_or("");
                let ts = ban["ts"].as_i64().unwrap_or(0);
                let (first_ts, findings): (Option<i64>, i64) = conn
                    .query_row(
                        "SELECT MIN(ts), COUNT(*) FROM security_events \
                         WHERE ip = ?1 AND ts BETWEEN ?2 AND ?3 AND event_type NOT IN (?4,?5,?6,?7)",
                        params![ip, ts - 86400, ts + 5, quiet[0], quiet[1], quiet[2], quiet[3]],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(e)?;
                if let Some(f) = first_ts {
                    at_once += i64::from(ts - f <= QUALITY_AT_ONCE_SECONDS);
                    single += i64::from(findings == 1);
                }
            }
        }
        let mut ended = 0i64;
        let mut came_back = 0i64;
        let mut seen: HashSet<String> = HashSet::new();
        {
            let conn = self.lock();
            for ban in &bans {
                let ip = ban["ip"].as_str().unwrap_or("").to_string();
                let until = ban["until"].as_i64().unwrap_or(0);
                if seen.contains(&ip) || !(0 < until && until < now) {
                    continue;
                }
                seen.insert(ip.clone());
                ended += 1;
                let again: Option<i64> = conn
                    .query_row(
                        "SELECT 1 FROM security_events WHERE ip = ?1 AND ts > ?2 \
                         AND event_type NOT IN (?3,?4,?5,?6) LIMIT 1",
                        params![ip, until, quiet[0], quiet[1], quiet[2], quiet[3]],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(e)?;
                came_back += i64::from(again.is_some());
            }
        }
        let mut sig_args = vec![SqlValue::Integer(since)];
        sig_args.extend(SIGNATURE_EVENTS_SORTED.iter().map(|s| SqlValue::Text((*s).into())));
        let unbanned = self.scalar_i64(
            "SELECT COUNT(DISTINCT e.ip) FROM security_events e \
             WHERE e.ts >= ? AND e.handled = 0 AND e.event_type IN (?,?,?) \
             AND NOT EXISTS (SELECT 1 FROM ban_decisions d WHERE d.ip = e.ip AND d.action = 'applied')",
            &sig_args,
        );
        let addresses: HashSet<String> = bans.iter().map(|b| b["ip"].as_str().unwrap_or("").to_string()).collect();
        let mut networks: HashMap<String, i64> = HashMap::new();
        for ip in &addresses {
            if let Some((head, _)) = ip.rsplit_once('.') {
                *networks.entry(format!("{head}.0/24")).or_insert(0) += 1;
            }
        }
        let mut crowded: Vec<(i64, String)> = networks
            .into_iter()
            .filter(|(_, c)| *c >= QUALITY_NETWORK_MIN)
            .map(|(n, c)| (c, n))
            .collect();
        crowded.sort_by(|a, b| b.cmp(a));
        let mut steps: BTreeMap<String, i64> = BTreeMap::new();
        let mut signal_stats: BTreeMap<String, [i64; 4]> = BTreeMap::new();
        for ban in &bans {
            *steps.entry(ban["strike"].as_i64().unwrap_or(0).to_string()).or_insert(0) += 1;
            let ip = ban["ip"].as_str().unwrap_or("");
            let ts = ban["ts"].as_i64().unwrap_or(0);
            let until = ban["until"].as_i64().unwrap_or(0).max(ts + 86400);
            let was_lifted = lifted_ts_by_ip.get(ip).is_some_and(|l| l.iter().any(|t| ts <= *t && *t <= until));
            let auth_after = auth_at_by_ip.get(ip).copied().unwrap_or(0) > ts;
            let disputed = was_lifted || auth_after;
            let reason = parse_reason(ban["reason"].as_str().unwrap_or("{}"));
            let mut seen_signals: HashSet<String> = HashSet::new();
            if let Some(evidence) = reason.get("evidence").and_then(Value::as_array) {
                for item in evidence {
                    let Some(obj) = item.as_object() else { continue };
                    let ev = obj.get("event_type").and_then(Value::as_str).unwrap_or("");
                    if ev.is_empty() {
                        continue;
                    }
                    let cat = obj.get("category").and_then(Value::as_str).unwrap_or("");
                    seen_signals.insert(if cat.is_empty() { ev.to_string() } else { format!("{ev}:{cat}") });
                }
            }
            for sig in seen_signals {
                let entry = signal_stats.entry(sig).or_insert([0; 4]);
                entry[0] += 1;
                entry[1] += i64::from(was_lifted);
                entry[2] += i64::from(auth_after);
                entry[3] += i64::from(disputed);
            }
        }
        let mut by_signal: Vec<Value> = signal_stats
            .iter()
            .map(|(sig, st)| {
                let rate = if st[0] > 0 { ((st[3] as f64 / st[0] as f64) * 1000.0).round() / 1000.0 } else { 0.0 };
                json!({
                    "signal": sig,
                    "bans": st[0],
                    "lifted_by_operator": st[1],
                    "authenticated_after": st[2],
                    "disputed": st[3],
                    "fp_rate": rate,
                })
            })
            .collect();
        by_signal.sort_by(|a, b| {
            let key = |v: &Value| {
                (
                    -v["disputed"].as_i64().unwrap_or(0),
                    -v["bans"].as_i64().unwrap_or(0),
                    v["signal"].as_str().unwrap_or("").to_string(),
                )
            };
            key(a).cmp(&key(b))
        });
        by_signal.truncate(25);
        let covered = (now - since.max(first.unwrap_or(now))).max(0);
        let bans_per_day = if covered >= 3600 {
            json!(((bans.len() as f64 * 86400.0 / covered as f64) * 10.0).round() / 10.0)
        } else {
            Value::Null
        };
        Ok(json!({
            "since": since,
            "until": now,
            "covered_seconds": covered,
            "bans": bans.len(),
            "banned_addresses": addresses.len(),
            "bans_per_day": bans_per_day,
            "decided_at_once": at_once,
            "on_a_single_finding": single,
            "steps": steps,
            "first_bans_ended": ended,
            "came_back_after_a_ban": came_back,
            "lifted_by_operator": lifted_by_operator,
            "probers_never_banned": unbanned,
            "networks": crowded.iter().take(QUALITY_NETWORKS_SHOWN)
                .map(|(c, n)| json!({"network": n, "addresses": c})).collect::<Vec<_>>(),
            "addresses_in_networks": crowded.iter().map(|(c, _)| c).sum::<i64>(),
            "by_signal": by_signal,
        }))
    }

    pub fn stats(&self) -> DbResult<Value> {
        let conn = self.lock();
        let version: Option<i64> = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()
            .map_err(e)?;
        let (rows, oldest, newest): (i64, Option<i64>, Option<i64>) = conn
            .query_row("SELECT COUNT(*), MIN(ts), MAX(ts) FROM security_events", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(e)?;
        let (arows, excluded, unenf): (i64, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT COUNT(*), SUM(CASE WHEN excluded = 1 THEN 1 ELSE 0 END), \
                 SUM(CASE WHEN enforceable = 0 THEN 1 ELSE 0 END) FROM ip_state",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(e)?;
        let mut stmt = conn
            .prepare("SELECT event_type, COUNT(*) AS value FROM security_events GROUP BY event_type ORDER BY value DESC LIMIT 20")
            .map_err(e)?;
        let mut by_type = Map::new();
        let rows_iter = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(e)?;
        for item in rows_iter {
            let (k, v) = item.map_err(e)?;
            by_type.insert(k, json!(v));
        }
        Ok(json!({
            "schema_version": version.unwrap_or(0),
            "events": {"rows": rows, "oldest_ts": oldest, "newest_ts": newest, "by_type": by_type},
            "addresses": {"rows": arows, "excluded": excluded.unwrap_or(0), "unenforceable": unenf.unwrap_or(0)},
        }))
    }

    pub fn storage(&self) -> Value {
        let size = |p: &Path| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let name = self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let database = size(&self.path);
        let wal = size(&self.path.with_file_name(format!("{name}-wal")));
        let shm = size(&self.path.with_file_name(format!("{name}-shm")));
        json!({
            "database_bytes": database,
            "wal_bytes": wal,
            "shm_bytes": shm,
            "total_bytes": database + wal + shm,
        })
    }
}

fn add_column(tx: &rusqlite::Transaction<'_>, table: &str, column: &str, definition: &str) -> DbResult<()> {
    let mut stmt = tx.prepare(&format!("PRAGMA table_info({table})")).map_err(e)?;
    let existing: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(e)?
        .collect::<Result<_, _>>()
        .map_err(e)?;
    if existing.iter().any(|c| c == column) {
        return Ok(());
    }
    tx.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"), []).map_err(e)?;
    Ok(())
}

pub fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// One event to write.
#[derive(Debug, Clone, Default)]
pub struct NewEvent {
    pub ts: i64,
    pub ip: String,
    pub event_type: String,
    pub source: String,
    pub site: String,
    pub category: String,
    pub detail: String,
    pub handled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> SecurityDatabase {
        let dir = std::env::temp_dir().join(format!("guardd-secdb-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        SecurityDatabase::open(dir.join("security.db")).expect("open")
    }

    #[test]
    fn events_come_back_newest_first() {
        let db = temp_db("order");
        let v = Verdict { excluded: false, reason: String::new(), source: String::new() };
        db.observe_ip("203.0.113.5", 100, &v).unwrap();
        for ts in [100, 300, 200] {
            db.record_events(&[NewEvent { ts, ip: "203.0.113.5".into(), event_type: "SCANNER_PATH".into(), source: "t".into(), ..Default::default() }]).unwrap();
        }
        let ev = db.events_for("203.0.113.5", 0, 500).unwrap();
        assert_eq!(ev.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![300, 200, 100]);
    }

    #[test]
    fn cooldown_and_decisions() {
        let db = temp_db("cool");
        assert!(db.cooldown_passed("k", 100, 60).unwrap());
        assert!(!db.cooldown_passed("k", 120, 60).unwrap());
        assert!(db.cooldown_passed("k", 161, 60).unwrap());
        let id = db
            .record_decision("1.2.3.4", 10, "applied", "adaptive", "pending", Decision { code: 41, until: 3610, strike: 1, score: 60, policy: "legacy", reason: Some(json!({"b": 1, "a": [1, 2]})) })
            .unwrap();
        assert_eq!(db.pending_decisions(100).unwrap().len(), 1);
        db.settle_decision(id, "failed").unwrap();
        assert!(db.pending_decisions(100).unwrap().is_empty());
        let rows = db.ban_decisions("1.2.3.4", 5).unwrap();
        assert_eq!(rows[0]["reason"]["a"], json!([1, 2]));
    }

    #[test]
    fn python_json_format() {
        assert_eq!(sorted_json(&json!({"b": 1, "a": {"d": 2.5, "c": 3.0}})), r#"{"a": {"c": 3.0, "d": 2.5}, "b": 1}"#);
    }
}
