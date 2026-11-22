//! Schema-compatible SQLite storage for `security.db` and `requests.db`.

use crate::parser::ParsedRequest;
use crate::scoring::{enforceable, ip_family, StoredEvent};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const SECURITY_SCHEMA_VERSION: i64 = 3;
pub const REQUEST_LOG_SCHEMA_VERSION: i64 = 3;

const SECURITY_SCHEMA_STATEMENTS: &[&str] = &[
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

const REQUEST_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS requests (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        request_id  TEXT    NOT NULL DEFAULT '',
        client      TEXT    NOT NULL DEFAULT '',
        status      INTEGER NOT NULL DEFAULT 0,
        frontend    TEXT    NOT NULL DEFAULT '',
        backend     TEXT    NOT NULL DEFAULT '',
        server      TEXT    NOT NULL DEFAULT '',
        method      TEXT    NOT NULL DEFAULT '',
        host        TEXT    NOT NULL DEFAULT '',
        path        TEXT    NOT NULL DEFAULT '',
        bytes_out   INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        bad_request INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS ix_requests_ts ON requests(ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_rid ON requests(request_id)",
    "CREATE INDEX IF NOT EXISTS ix_requests_client ON requests(client, ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status, ts)",
    "CREATE TABLE IF NOT EXISTS agents (
        id      INTEGER PRIMARY KEY,
        agent   TEXT    NOT NULL UNIQUE,
        last_ts INTEGER NOT NULL DEFAULT 0
    )",
];

const REQUEST_ADDED_COLUMNS: &[(&str, &str)] = &[
    ("response_ms", "INTEGER NOT NULL DEFAULT -1"),
    ("times", "TEXT NOT NULL DEFAULT ''"),
    ("term", "TEXT NOT NULL DEFAULT ''"),
    ("ban_reason", "TEXT NOT NULL DEFAULT ''"),
    ("agent_id", "INTEGER NOT NULL DEFAULT 0"),
    ("authenticated_user", "TEXT NOT NULL DEFAULT ''"),
];

/// Persistent SQLite `security.db` compatible with Python `guardd.storage.SecurityDatabase`.
pub struct SecurityDatabase {
    conn: Connection,
}

impl SecurityDatabase {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
        }
        let fresh = !p.exists();
        let conn = Connection::open(p).map_err(|e| format!("sqlite open failed: {e}"))?;
        if fresh {
            conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
                .map_err(|e| e.to_string())?;
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| e.to_string())?;

        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&mut self) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        for stmt in SECURITY_SCHEMA_STATEMENTS {
            tx.execute(stmt, []).map_err(|e| e.to_string())?;
        }
        let current: Option<i64> = tx
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        match current {
            None => {
                tx.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![SECURITY_SCHEMA_VERSION],
                )
                .map_err(|e| e.to_string())?;
            }
            Some(v) if v > SECURITY_SCHEMA_VERSION => {
                return Err(format!(
                    "security database schema v{v} is newer than supported v{SECURITY_SCHEMA_VERSION}"
                ));
            }
            Some(v) if v < SECURITY_SCHEMA_VERSION => {
                if v < 2 {
                    add_column_if_missing(&tx, "security_events", "handled", "INTEGER NOT NULL DEFAULT 0")?;
                }
                if v < 3 {
                    add_column_if_missing(&tx, "ip_state", "authenticated_at", "INTEGER NOT NULL DEFAULT 0")?;
                }
                tx.execute(
                    "UPDATE schema_version SET version = ?1",
                    params![SECURITY_SCHEMA_VERSION],
                )
                .map_err(|e| e.to_string())?;
            }
            Some(_) => {}
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn get_state(&self, key: &str, default: &str) -> String {
        self.conn
            .query_row(
                "SELECT value FROM guard_state WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or_else(|| default.to_string())
    }

    pub fn set_state(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO guard_state (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn upsert_ip_state(
        &self,
        ip: &str,
        ts: i64,
        excluded: bool,
        exclusion_reason: &str,
    ) -> Result<(), String> {
        let family = ip_family(ip);
        let enf = if enforceable(ip) { 1i64 } else { 0i64 };
        let excl = if excluded { 1i64 } else { 0i64 };
        self.conn
            .execute(
                "INSERT INTO ip_state (ip, family, enforceable, first_seen, last_seen, excluded, exclusion_reason) \
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6) \
                 ON CONFLICT(ip) DO UPDATE SET \
                   last_seen = MAX(ip_state.last_seen, excluded.last_seen), \
                   excluded = excluded.excluded, \
                   exclusion_reason = excluded.exclusion_reason",
                params![ip, family, enf, ts, excl, exclusion_reason],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        ts: i64,
        ip: &str,
        event_type: &str,
        source: &str,
        site: &str,
        category: &str,
        detail: &str,
        handled: bool,
    ) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO security_events (ts, ip, event_type, source, site, category, detail, handled) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    ts,
                    ip,
                    event_type,
                    source,
                    site,
                    category,
                    detail,
                    if handled { 1i64 } else { 0i64 }
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn events_for_ip(&self, ip: &str, since: i64) -> Result<Vec<StoredEvent>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, event_type, category, site, detail, handled \
                 FROM security_events WHERE ip = ?1 AND ts >= ?2 ORDER BY ts ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![ip, since], |r| {
                Ok(StoredEvent {
                    ts: r.get(0)?,
                    event_type: r.get(1)?,
                    category: r.get(2)?,
                    site: r.get(3)?,
                    detail: r.get(4)?,
                    handled: r.get::<_, i64>(5)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for item in rows {
            out.push(item.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

/// Persistent SQLite `requests.db` compatible with Python `guardd.request_log.RequestLog`.
pub struct RequestLogDb {
    conn: Connection,
    agent_cache: HashMap<String, i64>,
}

impl RequestLogDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
        }
        let fresh = !p.exists();
        let conn = Connection::open(p).map_err(|e| format!("sqlite open failed: {e}"))?;
        if fresh {
            conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
                .map_err(|e| e.to_string())?;
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| e.to_string())?;

        let mut db = Self {
            conn,
            agent_cache: HashMap::new(),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&mut self) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        for stmt in REQUEST_SCHEMA_STATEMENTS {
            tx.execute(stmt, []).map_err(|e| e.to_string())?;
        }
        for &(col, def) in REQUEST_ADDED_COLUMNS {
            add_column_if_missing(&tx, "requests", col, def)?;
        }
        let current: Option<i64> = tx
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        match current {
            None => {
                tx.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![REQUEST_LOG_SCHEMA_VERSION],
                )
                .map_err(|e| e.to_string())?;
            }
            Some(v) if v < REQUEST_LOG_SCHEMA_VERSION => {
                tx.execute(
                    "UPDATE schema_version SET version = ?1",
                    params![REQUEST_LOG_SCHEMA_VERSION],
                )
                .map_err(|e| e.to_string())?;
            }
            Some(_) => {}
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Insert a batch of parsed requests in a single WAL transaction.
    pub fn insert_batch(&mut self, rows: &[ParsedRequest]) -> Result<usize, String> {
        if rows.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        {
            let mut insert_agent = tx
                .prepare_cached(
                    "INSERT INTO agents (agent, last_ts) VALUES (?1, ?2) \
                     ON CONFLICT(agent) DO UPDATE SET last_ts = MAX(agents.last_ts, excluded.last_ts)",
                )
                .map_err(|e| e.to_string())?;
            let mut find_agent = tx
                .prepare_cached("SELECT id FROM agents WHERE agent = ?1")
                .map_err(|e| e.to_string())?;
            let mut insert_req = tx
                .prepare_cached(
                    "INSERT INTO requests (
                        ts, request_id, client, status, frontend, backend, server,
                        method, host, path, bytes_out, duration_ms, bad_request,
                        response_ms, times, term, ban_reason, agent_id, authenticated_user
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                        ?8, ?9, ?10, ?11, ?12, ?13,
                        ?14, ?15, ?16, ?17, ?18, ?19
                    )",
                )
                .map_err(|e| e.to_string())?;

            for req in rows {
                let agent_id = if req.user_agent.is_empty() {
                    0i64
                } else if let Some(&id) = self.agent_cache.get(&req.user_agent) {
                    id
                } else {
                    insert_agent
                        .execute(params![req.user_agent, req.ts])
                        .map_err(|e| e.to_string())?;
                    let id: i64 = find_agent
                        .query_row(params![req.user_agent], |r| r.get(0))
                        .map_err(|e| e.to_string())?;
                    if self.agent_cache.len() < 4096 {
                        self.agent_cache.insert(req.user_agent.clone(), id);
                    }
                    id
                };
                let (backend, server) = match req.backend.split_once('/') {
                    Some((b, s)) => (b, s),
                    None => (req.backend.as_str(), ""),
                };
                insert_req
                    .execute(params![
                        req.ts,
                        req.request_id,
                        req.client_ip,
                        req.status as i64,
                        req.frontend,
                        backend,
                        server,
                        req.method,
                        req.host,
                        req.path,
                        req.bytes_out as i64,
                        req.duration_ms,
                        if req.bad_request { 1i64 } else { 0i64 },
                        req.response_ms,
                        req.times,
                        req.term,
                        req.ban_reason,
                        agent_id,
                        req.authenticated_user,
                    ])
                    .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(rows.len())
    }
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| e.to_string())?;
    let existing: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();
    if existing.iter().any(|c| c == column) {
        return Ok(());
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_access_line;
    use crate::signatures::SignatureEngine;

    #[test]
    fn creates_and_queries_security_and_request_dbs() {
        let dir = std::env::temp_dir().join(format!("guardd_db_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let sec_path = dir.join("security.db");
        let req_path = dir.join("requests.db");
        let _ = fs::remove_file(&sec_path);
        let _ = fs::remove_file(&req_path);

        let sec = SecurityDatabase::open(&sec_path).expect("open security.db");
        sec.set_state("mode_override", "enforce").expect("set_state");
        assert_eq!(sec.get_state("mode_override", "monitor"), "enforce");
        sec.upsert_ip_state("198.51.100.1", 1000, false, "")
            .expect("upsert ip");
        sec.record_event(
            1000,
            "198.51.100.1",
            "SCANNER_PATH_DECISIVE",
            "log",
            "app.example.com",
            "secrets",
            "/.env",
            false,
        )
        .expect("record event");
        let evs = sec.events_for_ip("198.51.100.1", 0).expect("events_for_ip");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].category, "secrets");

        let sigs = SignatureEngine::builtin();
        let line = "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: \
            198.51.100.1:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 \
            0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=app.example.com ua=sqlmap/1.7 \
            GET /.env HTTP/1.1";
        let req = parse_access_line(line, &sigs).expect("parse");
        let mut rdb = RequestLogDb::open(&req_path).expect("open requests.db");
        assert_eq!(rdb.insert_batch(&[req]).expect("insert_batch"), 1);

        let _ = fs::remove_file(&sec_path);
        let _ = fs::remove_file(&req_path);
        let _ = fs::remove_dir(&dir);
    }
}
