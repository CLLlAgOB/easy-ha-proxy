//! The optional SQLite request log (`requests.db`) and the query/summary types
//! shared with the live buffer (Python `guardd.request_log`).

use crate::constants::utc_now;
use crate::live::live_refusal;
use crate::livebuf::{logged_agent, LiveRecord, LIVE_ADMIN_BACKENDS};
use crate::parser::ParsedRequest;
use crate::runtime::GuardConfig;
use regex::Regex;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

pub const REQUEST_LOG_SCHEMA_VERSION: i64 = 3;
pub const REQUEST_SEARCH_SECONDS: f64 = 4.0;
pub const REQUEST_COUNT_CAP: i64 = 10000;
pub const REQUEST_SCAN_STEP: i64 = 20000;
pub const REQUEST_SEARCHES_AT_ONCE: usize = 2;
pub const REQUEST_INDEXED_ROWS: i64 = 5000;
pub const REQUEST_SUMMARY_SECONDS: f64 = 3.0;
pub const REQUEST_SUMMARY_TOP: usize = 10;
const SUMMARY_BARS: i64 = 72;
const SUMMARY_STEPS: [i64; 12] = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];
const MAX_PATH_LENGTH: usize = 200;
const MAX_HOST_LENGTH: usize = 128;
const MAX_USER_AGENT_LENGTH: usize = 128;

const REFUSED_SQL: &str =
    "(status IN (423, 429) OR ban_reason != '' OR (server = '' AND (status IN (451, 401, 403, 400) OR term LIKE 'PR%')))";

const SCHEMA: &[&str] = &[
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

const ADDED_COLUMNS: [(&str, &str); 6] = [
    ("response_ms", "INTEGER NOT NULL DEFAULT -1"),
    ("times", "TEXT NOT NULL DEFAULT ''"),
    ("term", "TEXT NOT NULL DEFAULT ''"),
    ("ban_reason", "TEXT NOT NULL DEFAULT ''"),
    ("agent_id", "INTEGER NOT NULL DEFAULT 0"),
    ("authenticated_user", "TEXT NOT NULL DEFAULT ''"),
];

const COLUMNS: [&str; 20] = [
    "id", "ts", "request_id", "client", "status", "frontend", "backend", "server", "method", "host", "path",
    "bytes_out", "duration_ms", "bad_request", "response_ms", "times", "term", "ban_reason", "agent_id",
    "authenticated_user",
];

pub fn request_log_path() -> String {
    std::env::var("GUARDD_REQUEST_LOG").unwrap_or_else(|_| "/var/lib/easy-ha-proxy/requests/requests.db".into())
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// "404", "5xx", or several: "4xx, 500". Ranges as [low, high).
pub fn parse_statuses(text: &str) -> Vec<(i64, i64)> {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    static SPLIT: OnceLock<Regex> = OnceLock::new();
    let token_re = TOKEN.get_or_init(|| Regex::new(r"^([1-5])(\d\d|xx)$").expect("regex"));
    let split_re = SPLIT.get_or_init(|| Regex::new(r"[\s,;]+").expect("regex"));
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    let lowered = text.trim().to_lowercase();
    for token in split_re.split(&lowered).take(8) {
        let Some(c) = token_re.captures(token) else { continue };
        let range = if &c[2] == "xx" {
            let low: i64 = c[1].parse::<i64>().unwrap_or(0) * 100;
            (low, low + 100)
        } else {
            let code: i64 = token.parse().unwrap_or(0);
            (code, code + 1)
        };
        if !ranges.contains(&range) {
            ranges.push(range);
        }
    }
    ranges
}

/// What a search of the request log asks for, answered the same way by the
/// store (as SQL) and by the live buffer (as a test of each record).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RequestQuery {
    pub since: f64,
    pub until: f64,
    pub client: String,
    pub statuses: Vec<(i64, i64)>,
    pub host: String,
    pub backend: String,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub hide_admin: bool,
    pub refused: bool,
    pub slower_ms: i64,
    pub agent: String,
}

impl RequestQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        since: f64,
        until: f64,
        client: &str,
        status: &str,
        host: &str,
        backend: &str,
        request_id: &str,
        method: &str,
        path: &str,
        hide_admin: bool,
        refused: bool,
        slower: i64,
        agent: &str,
    ) -> Self {
        let agent: String = agent.trim().to_lowercase().chars().take(120).collect();
        let backend = truncate(backend, 200);
        let request_id = truncate(request_id, 200);
        Self {
            since,
            until,
            client: truncate(client, 200),
            statuses: parse_statuses(status),
            host: truncate(host, 200),
            hide_admin: hide_admin && request_id.is_empty() && !LIVE_ADMIN_BACKENDS.contains(&backend.as_str()),
            backend,
            request_id,
            method: truncate(&method.to_uppercase(), 10),
            path: truncate(path, MAX_PATH_LENGTH),
            refused,
            slower_ms: slower.clamp(0, 86_400_000),
            agent: if agent.is_empty() { String::new() } else { logged_agent(&agent) },
        }
    }

    /// Build from string parameters as the API receives them.
    pub fn from_params(p: &HashMap<String, String>) -> Self {
        let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
        let num = |k: &str| get(k).trim().parse::<f64>().unwrap_or(0.0);
        let flag = |k: &str| crate::livebuf::truthy(p.get(k));
        Self::build(
            num("since"),
            num("until"),
            get("client"),
            get("status"),
            get("host"),
            get("backend"),
            get("request_id"),
            get("method"),
            get("path"),
            flag("hide_admin"),
            flag("refused"),
            get("slower").trim().parse::<i64>().unwrap_or(0),
            get("agent"),
        )
    }

    pub fn clauses(&self) -> (Vec<String>, Vec<SqlValue>) {
        let mut clauses = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if self.since != 0.0 {
            clauses.push("ts >= ?".to_string());
            params.push(SqlValue::Integer(self.since as i64));
        }
        if self.until != 0.0 {
            clauses.push("ts <= ?".to_string());
            params.push(SqlValue::Integer(self.until as i64));
        }
        for (column, value) in [
            ("client", &self.client),
            ("host", &self.host),
            ("backend", &self.backend),
            ("request_id", &self.request_id),
            ("method", &self.method),
        ] {
            if !value.is_empty() {
                clauses.push(format!("{column} = ?"));
                params.push(SqlValue::Text(value.clone()));
            }
        }
        if self.hide_admin {
            clauses.push(format!("backend NOT IN ({})", vec!["?"; LIVE_ADMIN_BACKENDS.len()].join(",")));
            params.extend(LIVE_ADMIN_BACKENDS.iter().map(|b| SqlValue::Text((*b).into())));
        }
        if !self.path.is_empty() {
            clauses.push("path LIKE ? ESCAPE ?".to_string());
            params.push(SqlValue::Text(format!("{}%", like_literal(&self.path))));
            params.push(SqlValue::Text("\\".into()));
        }
        if !self.statuses.is_empty() {
            clauses.push(format!(
                "({})",
                vec!["(status >= ? AND status < ?)"; self.statuses.len()].join(" OR ")
            ));
            for (low, high) in &self.statuses {
                params.push(SqlValue::Integer(*low));
                params.push(SqlValue::Integer(*high));
            }
        }
        if self.refused {
            clauses.push(REFUSED_SQL.to_string());
        }
        if self.slower_ms != 0 {
            clauses.push("response_ms >= ?".to_string());
            params.push(SqlValue::Integer(self.slower_ms));
        }
        if !self.agent.is_empty() {
            clauses.push("agent_id IN (SELECT id FROM agents WHERE agent LIKE ? ESCAPE ?)".to_string());
            params.push(SqlValue::Text(format!("%{}%", like_literal(&self.agent))));
            params.push(SqlValue::Text("\\".into()));
        }
        (clauses, params)
    }

    pub fn matches(&self, r: &LiveRecord) -> bool {
        if self.since != 0.0 && r.ts < self.since {
            return false;
        }
        if self.until != 0.0 && r.ts > self.until {
            return false;
        }
        if !self.client.is_empty() && r.ip != self.client {
            return false;
        }
        if !self.host.is_empty() && r.host != self.host {
            return false;
        }
        let backend = r.backend_name();
        if !self.backend.is_empty() && backend != self.backend {
            return false;
        }
        if !self.request_id.is_empty() && r.request_id != self.request_id {
            return false;
        }
        if !self.method.is_empty() && r.method != self.method {
            return false;
        }
        if self.hide_admin && LIVE_ADMIN_BACKENDS.contains(&backend) {
            return false;
        }
        if !self.path.is_empty() && !r.path.starts_with(&self.path) {
            return false;
        }
        let status = i64::from(r.status);
        if !self.statuses.is_empty() && !self.statuses.iter().any(|(l, h)| *l <= status && status < *h) {
            return false;
        }
        if self.refused && r.refusal.is_empty() {
            return false;
        }
        if self.slower_ms != 0 && r.response_ms < self.slower_ms {
            return false;
        }
        if !self.agent.is_empty() && !r.user_agent.to_lowercase().contains(&self.agent) {
            return false;
        }
        true
    }
}

fn like_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// (first bar's start, seconds per bar, bars) for a period.
pub fn summary_layout(start: f64, end: f64) -> (i64, i64, i64) {
    let start = start as i64;
    let end = (end as i64).max(start + 60);
    let step = SUMMARY_STEPS
        .iter()
        .copied()
        .find(|s| (end - start) as f64 / *s as f64 <= SUMMARY_BARS as f64)
        .unwrap_or(SUMMARY_STEPS[SUMMARY_STEPS.len() - 1]);
    let first = start - start.rem_euclid(step);
    let bars = (-((-(end - first)).div_euclid(step))).max(1);
    (first, step, bars)
}

/// Counts folded in a part at a time, then read out.
#[derive(Debug, Clone)]
pub struct RequestSummary {
    pub first: i64,
    pub step: i64,
    pub bars: i64,
    pub histogram: Vec<[i64; 4]>,
    statuses: HashMap<i64, i64>,
    clients: HashMap<String, i64>,
    paths: HashMap<(String, String), i64>,
    pub counted: i64,
}

impl RequestSummary {
    pub fn new(first: i64, step: i64, bars: i64) -> Self {
        Self {
            first,
            step,
            bars,
            histogram: vec![[0; 4]; bars.max(1) as usize],
            statuses: HashMap::new(),
            clients: HashMap::new(),
            paths: HashMap::new(),
            counted: 0,
        }
    }

    pub fn add(&mut self, bar: i64, status: u16, refused: bool, count: i64) {
        let bar = bar.clamp(0, self.bars - 1) as usize;
        let kind = if refused { 3 } else if status >= 500 { 2 } else if status >= 400 { 1 } else { 0 };
        self.histogram[bar][kind] += count;
        *self.statuses.entry(i64::from(status)).or_insert(0) += count;
        self.counted += count;
    }

    pub fn add_client(&mut self, client: &str, count: i64) {
        *self.clients.entry(client.to_string()).or_insert(0) += count;
    }

    pub fn add_path(&mut self, host: &str, path: &str, count: i64) {
        *self.paths.entry((host.to_string(), path.to_string())).or_insert(0) += count;
    }

    fn most<K: Clone, F: Fn(&K) -> String>(counter: &HashMap<K, i64>, top: usize, text: F) -> Vec<(K, i64)> {
        let mut items: Vec<(K, i64)> = counter.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| text(&a.0).cmp(&text(&b.0))));
        items.truncate(top);
        items
    }

    pub fn read(&self) -> Value {
        json!({
            "start": self.first,
            "bucket_seconds": self.step,
            "buckets": self.histogram,
            "counted": self.counted,
            "statuses": Self::most(&self.statuses, 12, |k| k.to_string()).into_iter()
                .map(|(s, c)| json!({"status": s, "count": c})).collect::<Vec<_>>(),
            "clients": Self::most(&self.clients, REQUEST_SUMMARY_TOP, |k| k.clone()).into_iter()
                .map(|(s, c)| json!({"client": s, "count": c})).collect::<Vec<_>>(),
            "paths": Self::most(&self.paths, REQUEST_SUMMARY_TOP, |k| format!("('{}', '{}')", k.0, k.1)).into_iter()
                .map(|(k, c)| json!({"host": k.0, "path": k.1, "count": c})).collect::<Vec<_>>(),
        })
    }
}

/// A bounded, searchable window over recent requests.
pub struct RequestLog {
    pub path: PathBuf,
    conn: Mutex<Connection>,
    state: Mutex<LogState>,
    searching: AtomicUsize,
    pub config: GuardConfig,
}

struct LogState {
    pending: Vec<PendingRow>,
    agents: HashMap<String, i64>,
    paused: bool,
    pause_reason: String,
    last_maintenance: i64,
}

#[derive(Debug, Clone)]
struct PendingRow {
    ts: i64,
    request_id: String,
    client: String,
    status: i64,
    frontend: String,
    backend: String,
    server: String,
    method: String,
    host: String,
    path: String,
    bytes_out: i64,
    duration_ms: i64,
    bad_request: i64,
    response_ms: i64,
    times: String,
    term: String,
    ban_reason: String,
    authenticated_user: String,
    agent: String,
}

struct SearchSlot<'a>(&'a AtomicUsize);

impl Drop for SearchSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn e(err: rusqlite::Error) -> String {
    err.to_string()
}

impl RequestLog {
    pub fn open(path: impl AsRef<Path>, config: &GuardConfig) -> Result<Self, String> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("mkdir failed: {err}"))?;
        }
        let fresh = !p.exists();
        let mut conn = Connection::open(&p).map_err(e)?;
        if fresh {
            conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;").map_err(e)?;
        }
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
            .map_err(e)?;
        for stmt in SCHEMA {
            conn.execute(stmt, []).map_err(e)?;
        }
        let found: Option<i64> = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .optional()
            .map_err(e)?;
        if found.is_none() {
            conn.execute("INSERT INTO schema_version (version) VALUES (?1)", params![REQUEST_LOG_SCHEMA_VERSION])
                .map_err(e)?;
        }
        let version = found.unwrap_or(REQUEST_LOG_SCHEMA_VERSION);
        // One transaction for the new columns, the move to UTC and the new
        // version, as the Python migration's: interrupted between the move
        // and the version, the next start would move every stamp again.
        let tx = conn.transaction().map_err(e)?;
        let present: Vec<String> = {
            let mut stmt = tx.prepare("PRAGMA table_info(requests)").map_err(e)?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(1)).map_err(e)?;
            rows.collect::<Result<_, _>>().map_err(e)?
        };
        for (name, kind) in ADDED_COLUMNS {
            if !present.iter().any(|c| c == name) {
                tx.execute(&format!("ALTER TABLE requests ADD COLUMN {name} {kind}"), []).map_err(e)?;
            }
        }
        if version < 2 {
            local_stamps_to_utc(&tx)?;
        }
        if version < REQUEST_LOG_SCHEMA_VERSION {
            tx.execute("UPDATE schema_version SET version = ?1", params![REQUEST_LOG_SCHEMA_VERSION])
                .map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(Self {
            path: p,
            conn: Mutex::new(conn),
            state: Mutex::new(LogState {
                pending: Vec::new(),
                agents: HashMap::new(),
                paused: false,
                pause_reason: String::new(),
                last_maintenance: 0,
            }),
            searching: AtomicUsize::new(0),
            config: config.clone(),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn state(&self) -> MutexGuard<'_, LogState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queue one record; written once per cycle.
    pub fn add(&self, record: &ParsedRequest, ts: Option<f64>) {
        let (backend, server) = match record.backend.split_once('/') {
            Some((b, s)) => (b, s),
            None => (record.backend.as_str(), ""),
        };
        let row = PendingRow {
            ts: match ts {
                Some(t) if t != 0.0 => t as i64,
                _ => {
                    if record.ts != 0 {
                        record.ts
                    } else {
                        utc_now()
                    }
                }
            },
            request_id: truncate(&record.request_id, 64),
            client: truncate(&record.client_ip, 45),
            status: i64::from(record.status),
            frontend: truncate(&record.frontend, 64),
            backend: truncate(backend, 64),
            server: if server.is_empty() || server == "<NOSRV>" { String::new() } else { truncate(server, 64) },
            method: truncate(&record.method, 10),
            host: truncate(&record.host, MAX_HOST_LENGTH),
            path: truncate(&record.path, MAX_PATH_LENGTH),
            bytes_out: record.bytes_out as i64,
            duration_ms: record.duration_ms,
            bad_request: i64::from(record.bad_request),
            response_ms: if record.response_ms >= 0 { record.response_ms } else { -1 },
            times: truncate(&record.times, 40),
            term: truncate(&record.term, 8),
            ban_reason: truncate(&record.ban_reason, 160),
            authenticated_user: record.authenticated_user.clone(),
            agent: truncate(&record.user_agent, MAX_USER_AGENT_LENGTH),
        };
        self.state().pending.push(row);
    }

    /// Write the queued records, then keep the store inside its budget.
    pub fn flush(&self, now: i64) -> usize {
        let mut state = self.state();
        let pending = std::mem::take(&mut state.pending);
        let mut written = 0;
        if !pending.is_empty() && !state.paused {
            let outcome = {
                let mut conn = self.conn();
                write_batch(&mut conn, &pending, &mut state.agents)
            };
            match outcome {
                Ok(n) => written = n,
                Err(err) => {
                    eprintln!("request log write failed: {err}");
                    state.agents.clear();
                }
            }
        }
        if now - state.last_maintenance >= 60 {
            state.last_maintenance = now;
            self.maintain(now, &mut state);
        }
        written
    }

    fn size(&self) -> u64 {
        let name = self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        ["", "-wal", "-shm"]
            .iter()
            .map(|s| fs::metadata(self.path.with_file_name(format!("{name}{s}"))).map(|m| m.len()).unwrap_or(0))
            .sum()
    }

    fn free_bytes(&self) -> u64 {
        free_bytes(self.path.parent().unwrap_or(Path::new("/")))
    }

    fn maintain(&self, now: i64, state: &mut LogState) {
        let cutoff = now - self.config.request_log_retention_days * 86400;
        {
            let conn = self.conn();
            let _ = conn.execute("DELETE FROM requests WHERE ts < ?1", params![cutoff]);
        }
        for _ in 0..8 {
            if self.size() <= self.config.request_log_max_bytes {
                break;
            }
            let conn = self.conn();
            let _ = conn.execute(
                "DELETE FROM requests WHERE id IN (SELECT id FROM requests ORDER BY id LIMIT \
                 (SELECT MAX(1, COUNT(*) / 10) FROM requests))",
                [],
            );
            let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
        }
        {
            let conn = self.conn();
            if let Ok(gone) =
                conn.execute("DELETE FROM agents WHERE last_ts < (SELECT ts FROM requests ORDER BY id LIMIT 1)", [])
            {
                if gone > 0 {
                    state.agents.clear();
                }
            }
        }
        let free = self.free_bytes();
        let reserve = self.config.request_log_reserved_free_bytes;
        if free != 0 && free < reserve {
            if !state.paused {
                state.paused = true;
                state.pause_reason = "the filesystem is below its free-space reserve".into();
                eprintln!("Request log paused: {}. HAProxy traffic is not affected.", state.pause_reason);
            }
        } else if state.paused && free as f64 > reserve as f64 * 1.2 {
            state.paused = false;
            state.pause_reason.clear();
        }
    }

    fn reader(&self) -> Result<Connection, String> {
        let conn = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(e)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(e)?;
        conn.execute_batch("PRAGMA query_only=1;").map_err(e)?;
        Ok(conn)
    }

    fn acquire(&self) -> Result<SearchSlot<'_>, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let current = self.searching.load(Ordering::SeqCst);
            if current < REQUEST_SEARCHES_AT_ONCE
                && self
                    .searching
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return Ok(SearchSlot(&self.searching));
            }
            if Instant::now() > deadline {
                return Err("other searches of the request log are still running".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The newest matching requests, a page at a time.
    pub fn search(&self, query: &RequestQuery, before: i64, count: bool, limit: i64, seconds: f64) -> Result<Value, String> {
        let (clauses, parameters) = query.clauses();
        let (since, until) = (query.since as i64, query.until as i64);
        let limit = limit.clamp(1, 500);
        let before = before.clamp(0, 1i64 << 62);
        let deadline = Instant::now() + Duration::from_secs_f64(seconds.max(0.0));
        let _slot = self.acquire()?;
        let conn = self.reader()?;
        let index = if !query.request_id.is_empty() {
            "ix_requests_rid"
        } else if !query.client.is_empty() && few(&conn, &clauses, &parameters)? {
            "ix_requests_client"
        } else {
            ""
        };
        let mut found = if index.is_empty() {
            search_scan(&conn, &clauses, &parameters, since, until, before, limit, count, deadline)?
        } else {
            search_indexed(&conn, index, &clauses, &parameters, before, limit, count)?
        };
        let stopped_at = found.stopped_at;
        let searched_to = if stopped_at != 0 { ts_at(&conn, stopped_at) } else { 0 };
        let rows = present(&conn, &found.rows)?;
        let mut out = json!({
            "requests": rows,
            "next": found.next,
            "complete": found.complete,
            "timed_out": found.timed_out,
            "searched_to": searched_to,
        });
        if let Some((total, exact)) = found.total.take() {
            out["total"] = json!(total);
            out["total_exact"] = json!(exact);
        }
        Ok(out)
    }

    pub fn summary(&self, query: &RequestQuery, seconds: f64) -> Result<Value, String> {
        let (clauses, parameters) = query.clauses();
        let where_ = where_clause(&clauses);
        let deadline = Instant::now() + Duration::from_secs_f64(seconds.max(0.0));
        let _slot = self.acquire()?;
        let conn = self.reader()?;
        let (low, high) = id_bounds(&conn, query.since as i64, query.until as i64)?;
        let oldest = if high >= low { ts_at(&conn, low) } else { 0 };
        let now = crate::constants::utc_now_f();
        let start = if query.since != 0.0 { query.since } else if oldest != 0 { oldest as f64 } else { now };
        let end = if query.until != 0.0 { query.until } else { now };
        let (first, step, bars) = summary_layout(start, end);
        let mut summary = RequestSummary::new(first, step, bars);
        let refused = format!("CASE WHEN {REFUSED_SQL} THEN 1 ELSE 0 END");
        let mut position = high;
        while position >= low {
            let floor = low.max(position - REQUEST_SCAN_STEP + 1);
            let part = format!("FROM requests NOT INDEXED WHERE id BETWEEN ? AND ?{where_}");
            let mut values = vec![SqlValue::Integer(floor), SqlValue::Integer(position)];
            values.extend(parameters.iter().cloned());
            {
                let mut args = vec![SqlValue::Integer(summary.first), SqlValue::Integer(summary.step)];
                args.extend(values.iter().cloned());
                let mut stmt = conn
                    .prepare(&format!("SELECT (ts - ?) / ?, status, {refused}, COUNT(*) {part} GROUP BY 1, 2, 3"))
                    .map_err(e)?;
                let rows = stmt
                    .query_map(params_from_iter(args.iter()), |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
                    })
                    .map_err(e)?;
                for row in rows {
                    let (bar, status, gateway, count) = row.map_err(e)?;
                    summary.add(bar, status as u16, gateway != 0, count);
                }
            }
            {
                let mut stmt = conn.prepare(&format!("SELECT client, COUNT(*) {part} GROUP BY client")).map_err(e)?;
                let rows = stmt
                    .query_map(params_from_iter(values.iter()), |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                    .map_err(e)?;
                for row in rows {
                    let (client, count) = row.map_err(e)?;
                    summary.add_client(&client, count);
                }
            }
            {
                let mut stmt = conn.prepare(&format!("SELECT host, path, COUNT(*) {part} GROUP BY host, path")).map_err(e)?;
                let rows = stmt
                    .query_map(params_from_iter(values.iter()), |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
                    })
                    .map_err(e)?;
                for row in rows {
                    let (host, path, count) = row.map_err(e)?;
                    summary.add_path(&host, &path, count);
                }
            }
            position = floor - 1;
            if Instant::now() > deadline {
                break;
            }
        }
        let mut result = summary.read();
        let complete = position < low;
        result["complete"] = json!(complete);
        result["reached_to"] = json!(if complete { 0 } else { ts_at(&conn, position + 1) });
        Ok(result)
    }

    pub fn status(&self) -> Value {
        let (newest, oldest) = match self.reader() {
            Ok(conn) => {
                let q = |sql: &str| -> Option<(i64, i64)> {
                    conn.query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?))).optional().ok().flatten()
                };
                (
                    q("SELECT id, ts FROM requests ORDER BY id DESC LIMIT 1"),
                    q("SELECT id, ts FROM requests ORDER BY id LIMIT 1"),
                )
            }
            Err(_) => (None, None),
        };
        let rows = match (newest, oldest) {
            (Some(n), Some(o)) => n.0 - o.0 + 1,
            _ => 0,
        };
        let state = self.state();
        json!({
            "enabled": true,
            "configured": self.config.request_log_enabled,
            "rows": rows,
            "oldest_ts": oldest.map(|o| o.1).unwrap_or(0),
            "newest_ts": newest.map(|n| n.1).unwrap_or(0),
            "database_bytes": self.size(),
            "max_bytes": self.config.request_log_max_bytes,
            "retention_days": self.config.request_log_retention_days,
            "free_bytes": self.free_bytes(),
            "paused": state.paused,
            "pause_reason": state.pause_reason,
        })
    }
}

fn write_batch(conn: &mut Connection, pending: &[PendingRow], agents: &mut HashMap<String, i64>) -> Result<usize, String> {
    let tx = conn.transaction().map_err(e)?;
    // Each agent of the batch once, in the order it first appears (new ids
    // are handed out in that order, as by the Python daemon), with its newest
    // time; the index keeps a batch of many lines from scanning the list.
    let mut newest: Vec<(String, i64)> = Vec::new();
    let mut position: HashMap<&str, usize> = HashMap::new();
    for row in pending {
        if row.agent.is_empty() {
            continue;
        }
        match position.get(row.agent.as_str()) {
            Some(&i) => newest[i].1 = newest[i].1.max(row.ts),
            None => {
                position.insert(row.agent.as_str(), newest.len());
                newest.push((row.agent.clone(), row.ts));
            }
        }
    }
    let mut unknown: Vec<&(String, i64)> = newest.iter().filter(|(a, _)| !agents.contains_key(a)).collect();
    if !unknown.is_empty() {
        if agents.len() > 20000 {
            agents.clear();
            // The known agents of this batch were just forgotten too: resolve
            // them again, or their lines would be stored without an agent.
            unknown = newest.iter().collect();
        }
        for (agent, ts) in &unknown {
            tx.execute("INSERT OR IGNORE INTO agents (agent, last_ts) VALUES (?1, ?2)", params![agent, ts])
                .map_err(e)?;
        }
        for (agent, _) in &unknown {
            if let Some(id) = tx
                .query_row("SELECT id FROM agents WHERE agent = ?1", params![agent], |r| r.get::<_, i64>(0))
                .optional()
                .map_err(e)?
            {
                agents.insert(agent.clone(), id);
            }
        }
    }
    for (agent, stamp) in &newest {
        if let Some(id) = agents.get(agent) {
            tx.execute("UPDATE agents SET last_ts = ?1 WHERE id = ?2 AND last_ts < ?1", params![stamp, id])
                .map_err(e)?;
        }
    }
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO requests (ts, request_id, client, status, frontend, backend, server, method, host, path, \
                 bytes_out, duration_ms, bad_request, response_ms, times, term, ban_reason, authenticated_user, agent_id) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .map_err(e)?;
        for r in pending {
            let agent_id = if r.agent.is_empty() { 0 } else { agents.get(&r.agent).copied().unwrap_or(0) };
            stmt.execute(params![
                r.ts, r.request_id, r.client, r.status, r.frontend, r.backend, r.server, r.method, r.host, r.path,
                r.bytes_out, r.duration_ms, r.bad_request, r.response_ms, r.times, r.term, r.ban_reason,
                r.authenticated_user, agent_id
            ])
            .map_err(e)?;
        }
    }
    tx.commit().map_err(e)?;
    Ok(pending.len())
}

/// Version 1 stored HAProxy's %t (local wall clock read as UTC); move every
/// row by the offset its hour had.
fn local_stamps_to_utc(conn: &Connection) -> Result<i64, String> {
    let (low, high): (Option<i64>, Option<i64>) =
        conn.query_row("SELECT MIN(ts), MAX(ts) FROM requests", [], |r| Ok((r.get(0)?, r.get(1)?))).map_err(e)?;
    let (Some(low), Some(high)) = (low, high) else {
        return Ok(0);
    };
    let mut shifts = Vec::new();
    let mut hour = low - low.rem_euclid(3600);
    while hour <= high {
        // A wall clock written as UTC: its offset is that of the true time.
        let offset = crate::localtime::offset_at(hour - crate::localtime::offset_at(hour));
        if offset != 0 {
            shifts.push((hour, offset));
        }
        hour += 3600;
    }
    if shifts.is_empty() {
        return Ok(0);
    }
    conn.execute_batch("CREATE TEMP TABLE request_shift (hour INTEGER PRIMARY KEY, offset INTEGER);").map_err(e)?;
    for (h, o) in &shifts {
        conn.execute("INSERT INTO request_shift VALUES (?1, ?2)", params![h, o]).map_err(e)?;
    }
    for name in ["ix_requests_ts", "ix_requests_client", "ix_requests_status"] {
        conn.execute_batch(&format!("DROP INDEX IF EXISTS {name};")).map_err(e)?;
    }
    let moved = conn
        .execute(
            "UPDATE requests SET ts = ts - (SELECT offset FROM request_shift WHERE hour = requests.ts - requests.ts % 3600) \
             WHERE ts - ts % 3600 IN (SELECT hour FROM request_shift)",
            [],
        )
        .map_err(e)?;
    conn.execute_batch("DROP TABLE request_shift;").map_err(e)?;
    for stmt in SCHEMA.iter().filter(|s| s.starts_with("CREATE INDEX")) {
        conn.execute(stmt, []).map_err(e)?;
    }
    Ok(moved as i64)
}

#[cfg(unix)]
fn free_bytes(dir: &Path) -> u64 {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
        return 0;
    };
    // SAFETY: statvfs writes only into the zeroed struct we own.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    st.f_bavail as u64 * st.f_frsize as u64
}

#[cfg(not(unix))]
fn free_bytes(_dir: &Path) -> u64 {
    0
}

fn where_clause(clauses: &[String]) -> String {
    clauses.iter().map(|c| format!(" AND {c}")).collect()
}

fn few(conn: &Connection, clauses: &[String], parameters: &[SqlValue]) -> Result<bool, String> {
    let mut args = parameters.to_vec();
    args.push(SqlValue::Integer(REQUEST_INDEXED_ROWS + 1));
    let found: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM requests INDEXED BY ix_requests_client WHERE 1{} LIMIT ?)",
                where_clause(clauses)
            ),
            params_from_iter(args.iter()),
            |r| r.get(0),
        )
        .map_err(e)?;
    Ok(found <= REQUEST_INDEXED_ROWS)
}

struct Found {
    rows: Vec<HashMap<String, SqlValue>>,
    next: i64,
    complete: bool,
    timed_out: bool,
    stopped_at: i64,
    total: Option<(i64, bool)>,
}

fn fetch_rows(conn: &Connection, sql: &str, args: &[SqlValue]) -> Result<Vec<HashMap<String, SqlValue>>, rusqlite::Error> {
    let mut stmt = conn.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
        let mut m = HashMap::new();
        for (i, n) in names.iter().enumerate() {
            m.insert(n.clone(), r.get::<_, SqlValue>(i)?);
        }
        Ok(m)
    })?;
    rows.collect()
}

fn row_id(row: &HashMap<String, SqlValue>) -> i64 {
    match row.get("id") {
        Some(SqlValue::Integer(i)) => *i,
        _ => 0,
    }
}

fn search_indexed(
    conn: &Connection,
    index: &str,
    clauses: &[String],
    parameters: &[SqlValue],
    before: i64,
    limit: i64,
    count: bool,
) -> Result<Found, String> {
    let mut where_ = format!(" WHERE 1{}", where_clause(clauses));
    let mut params = parameters.to_vec();
    if before != 0 {
        where_.push_str(" AND id < ?");
        params.push(SqlValue::Integer(before));
    }
    let mut args = params.clone();
    args.push(SqlValue::Integer(limit + 1));
    let mut rows = fetch_rows(
        conn,
        &format!("SELECT * FROM requests INDEXED BY {index}{where_} ORDER BY id DESC LIMIT ?"),
        &args,
    )
    .map_err(e)?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more { rows.last().map(row_id).unwrap_or(0) } else { 0 };
    let total = if count {
        let mut cargs = params.clone();
        cargs.push(SqlValue::Integer(REQUEST_COUNT_CAP + 1));
        let counted: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM (SELECT 1 FROM requests INDEXED BY {index}{where_} LIMIT ?)"),
                params_from_iter(cargs.iter()),
                |r| r.get(0),
            )
            .map_err(e)?;
        Some((counted.min(REQUEST_COUNT_CAP), counted <= REQUEST_COUNT_CAP))
    } else {
        None
    };
    Ok(Found { rows, next, complete: true, timed_out: false, stopped_at: 0, total })
}

#[allow(clippy::too_many_arguments)]
fn search_scan(
    conn: &Connection,
    clauses: &[String],
    parameters: &[SqlValue],
    since: i64,
    until: i64,
    before: i64,
    limit: i64,
    count: bool,
    deadline: Instant,
) -> Result<Found, String> {
    let (low, mut high) = id_bounds(conn, since, until)?;
    if before != 0 {
        high = high.min(before - 1);
    }
    let where_ = where_clause(clauses);
    let mut rows: Vec<HashMap<String, SqlValue>> = Vec::new();
    let mut counted = 0i64;
    let mut position = high;
    let mut counting_from = 0i64;
    let mut timed_out = false;
    let mut first_step = true;
    while position >= low && rows.len() as i64 <= limit {
        let floor = low.max(position - REQUEST_SCAN_STEP + 1);
        let need = limit + 1 - rows.len() as i64;
        let mut args = vec![SqlValue::Integer(floor), SqlValue::Integer(position)];
        args.extend(parameters.iter().cloned());
        args.push(SqlValue::Integer(need));
        if !first_step {
            let d = deadline;
            conn.progress_handler(2000, Some(move || Instant::now() > d));
        }
        let step = match fetch_rows(
            conn,
            &format!("SELECT * FROM requests NOT INDEXED WHERE id BETWEEN ? AND ?{where_} ORDER BY id DESC LIMIT ?"),
            &args,
        ) {
            Ok(s) => s,
            Err(err) if err.to_string().contains("interrupt") => {
                timed_out = true;
                break;
            }
            Err(err) => return Err(err.to_string()),
        };
        first_step = false;
        let got = step.len() as i64;
        rows.extend(step);
        if got < need {
            counted += got;
            position = floor - 1;
        } else {
            counting_from = position;
            position = floor - 1;
            break;
        }
        if Instant::now() > deadline {
            timed_out = position >= low;
            break;
        }
    }
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let following = if more {
        rows.last().map(row_id).unwrap_or(0)
    } else if timed_out {
        position + 1
    } else {
        0
    };
    let mut found = Found {
        rows,
        next: following,
        complete: !timed_out,
        timed_out,
        stopped_at: if timed_out { position + 1 } else { 0 },
        total: None,
    };
    if !count {
        conn.progress_handler(0, None::<fn() -> bool>);
        return Ok(found);
    }
    let mut exact = !timed_out;
    if counting_from != 0 {
        let d = deadline;
        conn.progress_handler(2000, Some(move || Instant::now() > d));
        position = counting_from;
        while position >= low && counted <= REQUEST_COUNT_CAP {
            if Instant::now() > deadline {
                exact = false;
                break;
            }
            let floor = low.max(position - REQUEST_SCAN_STEP + 1);
            let mut args = vec![SqlValue::Integer(floor), SqlValue::Integer(position)];
            args.extend(parameters.iter().cloned());
            args.push(SqlValue::Integer(REQUEST_COUNT_CAP + 1 - counted));
            match conn.query_row(
                &format!("SELECT COUNT(*) FROM (SELECT 1 FROM requests NOT INDEXED WHERE id BETWEEN ? AND ?{where_} LIMIT ?)"),
                params_from_iter(args.iter()),
                |r| r.get::<_, i64>(0),
            ) {
                Ok(n) => counted += n,
                Err(err) if err.to_string().contains("interrupt") => {
                    exact = false;
                    break;
                }
                Err(err) => return Err(err.to_string()),
            }
            position = floor - 1;
        }
    }
    conn.progress_handler(0, None::<fn() -> bool>);
    if counted > REQUEST_COUNT_CAP {
        counted = REQUEST_COUNT_CAP;
        exact = false;
    }
    found.total = Some((counted.max(found.rows.len() as i64), exact));
    Ok(found)
}

fn id_bounds(conn: &Connection, since: i64, until: i64) -> Result<(i64, i64), String> {
    let one = |sql: &str, args: &[SqlValue]| -> Result<Option<i64>, String> {
        conn.query_row(sql, params_from_iter(args.iter()), |r| r.get::<_, Option<i64>>(0))
            .optional()
            .map(|v| v.flatten())
            .map_err(e)
    };
    let top = if until != 0 {
        one(
            "SELECT id FROM requests INDEXED BY ix_requests_ts WHERE ts <= ? ORDER BY ts DESC LIMIT 1",
            &[SqlValue::Integer(until)],
        )?
    } else {
        one("SELECT MAX(id) FROM requests", &[])?
    };
    let bottom = if since != 0 {
        one(
            "SELECT id FROM requests INDEXED BY ix_requests_ts WHERE ts >= ? ORDER BY ts LIMIT 1",
            &[SqlValue::Integer(since)],
        )?
    } else {
        one("SELECT MIN(id) FROM requests", &[])?
    };
    Ok((bottom.unwrap_or(1), top.unwrap_or(0)))
}

fn ts_at(conn: &Connection, id: i64) -> i64 {
    conn.query_row("SELECT ts FROM requests WHERE id >= ?1 ORDER BY id LIMIT 1", params![id], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
        .unwrap_or(0)
}

fn sql_json(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(i) => json!(i),
        SqlValue::Real(f) => json!(f),
        SqlValue::Text(s) => json!(s),
        SqlValue::Blob(b) => json!(String::from_utf8_lossy(b)),
    }
}

fn present(conn: &Connection, rows: &[HashMap<String, SqlValue>]) -> Result<Vec<Value>, String> {
    let mut wanted: Vec<i64> = rows
        .iter()
        .filter_map(|r| match r.get("agent_id") {
            Some(SqlValue::Integer(i)) if *i != 0 => Some(*i),
            _ => None,
        })
        .collect();
    wanted.sort_unstable();
    wanted.dedup();
    let mut names: HashMap<i64, String> = HashMap::new();
    if !wanted.is_empty() {
        let marks = vec!["?"; wanted.len()].join(",");
        let args: Vec<SqlValue> = wanted.iter().map(|i| SqlValue::Integer(*i)).collect();
        let mut stmt = conn.prepare(&format!("SELECT id, agent FROM agents WHERE id IN ({marks})")).map_err(e)?;
        let it = stmt
            .query_map(params_from_iter(args.iter()), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(e)?;
        for item in it {
            let (id, agent) = item.map_err(e)?;
            names.insert(id, agent);
        }
    }
    let text = |row: &HashMap<String, SqlValue>, k: &str| match row.get(k) {
        Some(SqlValue::Text(s)) => s.clone(),
        _ => String::new(),
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut m = Map::new();
        for c in COLUMNS {
            if c == "agent_id" {
                continue;
            }
            if let Some(v) = row.get(c) {
                m.insert(c.to_string(), sql_json(v));
            }
        }
        let agent_id = match row.get("agent_id") {
            Some(SqlValue::Integer(i)) => *i,
            _ => 0,
        };
        m.insert("user_agent".into(), json!(names.get(&agent_id).cloned().unwrap_or_default()));
        let status = match row.get("status") {
            Some(SqlValue::Integer(i)) => *i as u16,
            _ => 0,
        };
        let server = text(row, "server");
        let backend = format!("{}/{}", text(row, "backend"), if server.is_empty() { "<NOSRV>" } else { server.as_str() });
        m.insert(
            "refusal".into(),
            json!(live_refusal(status, &backend, &text(row, "term"), &text(row, "ban_reason"))),
        );
        out.push(Value::Object(m));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_layout() {
        assert_eq!(parse_statuses("4xx, 500"), vec![(400, 500), (500, 501)]);
        assert_eq!(parse_statuses("bogus 404 404"), vec![(404, 405)]);
        let (first, step, bars) = summary_layout(1000.0, 1000.0 + 3600.0);
        assert_eq!(step, 60);
        assert_eq!(first, 960);
        assert_eq!(bars, 61);
    }

    #[test]
    fn store_search_round_trip() {
        let dir = std::env::temp_dir().join(format!("guardd-reqlog-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = GuardConfig::default();
        let log = RequestLog::open(dir.join("requests.db"), &cfg).unwrap();
        let mut req = ParsedRequest {
            client_ip: "203.0.113.9".into(),
            status: 404,
            frontend: "fe".into(),
            backend: "be_site/srv1".into(),
            method: "GET".into(),
            path: "/x".into(),
            host: "a.example".into(),
            bad_request: false,
            query_flag: String::new(),
            path_flag: String::new(),
            observation_flags: Vec::new(),
            ts: 0,
            request_id: "rid1".into(),
            bytes_out: 5,
            duration_ms: 3,
            response_ms: 2,
            times: String::new(),
            term: "----".into(),
            ban_reason: String::new(),
            user_agent: "curl/8".into(),
            authenticated_user: String::new(),
            protocol: "HTTP/1.1".into(),
        };
        log.add(&req, Some(1000.0));
        req.status = 200;
        req.request_id = "rid2".into();
        log.add(&req, Some(1001.0));
        assert_eq!(log.flush(1001), 2);
        let q = RequestQuery::build(0.0, 0.0, "", "4xx", "", "", "", "", "", false, false, 0, "");
        let out = log.search(&q, 0, true, 10, 4.0).unwrap();
        assert_eq!(out["requests"].as_array().unwrap().len(), 1);
        assert_eq!(out["requests"][0]["user_agent"], "curl/8");
        assert_eq!(out["total"], 1);
        let by_id = RequestQuery::build(0.0, 0.0, "", "", "", "", "rid2", "", "", false, false, 0, "");
        assert_eq!(log.search(&by_id, 0, true, 10, 4.0).unwrap()["requests"][0]["status"], 200);
        let summary = log.summary(&RequestQuery::default(), 3.0).unwrap();
        assert_eq!(summary["counted"], 2);
    }

    fn pending(ts: i64, agent: &str) -> PendingRow {
        PendingRow {
            ts,
            request_id: String::new(),
            client: "203.0.113.1".into(),
            status: 200,
            frontend: String::new(),
            backend: String::new(),
            server: String::new(),
            method: "GET".into(),
            host: String::new(),
            path: "/".into(),
            bytes_out: 0,
            duration_ms: 0,
            bad_request: 0,
            response_ms: -1,
            times: String::new(),
            term: String::new(),
            ban_reason: String::new(),
            authenticated_user: String::new(),
            agent: agent.into(),
        }
    }

    // The new columns, the move to UTC and the new version are one
    // transaction: a migration stopped before the version is written leaves
    // nothing half done for the next start to apply a second time.
    #[test]
    fn version_one_migration_is_all_or_nothing() {
        let dir = std::env::temp_dir().join(format!("guardd-reqlog-mig-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requests.db");
        {
            let conn = Connection::open(&path).unwrap();
            for stmt in SCHEMA {
                conn.execute(stmt, []).unwrap();
            }
            conn.execute_batch(
                "INSERT INTO schema_version (version) VALUES (1);
                 INSERT INTO requests (ts, client) VALUES (1700000000, '203.0.113.1');
                 CREATE TRIGGER stop_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT, 'stopped'); END;",
            )
            .unwrap();
        }
        let cfg = GuardConfig::default();
        assert!(RequestLog::open(&path, &cfg).is_err());
        let columns = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn.prepare("PRAGMA table_info(requests)").unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        {
            let conn = Connection::open(&path).unwrap();
            let version: i64 = conn.query_row("SELECT version FROM schema_version", [], |r| r.get(0)).unwrap();
            assert_eq!(version, 1);
            assert!(!columns(&conn).iter().any(|c| c == "response_ms"), "columns added outside the transaction");
            conn.execute_batch("DROP TRIGGER stop_version;").unwrap();
        }
        RequestLog::open(&path, &cfg).unwrap();
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn.query_row("SELECT version FROM schema_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, REQUEST_LOG_SCHEMA_VERSION);
        assert!(columns(&conn).iter().any(|c| c == "response_ms"));
    }

    // A full agent cache is cleared before new agents are added; an agent the
    // cache knew, in the same batch, must still be stored with its id.
    #[test]
    fn known_agent_keeps_its_id_when_the_cache_is_cleared() {
        let dir = std::env::temp_dir().join(format!("guardd-reqlog-ua-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = GuardConfig::default();
        let log = RequestLog::open(dir.join("requests.db"), &cfg).unwrap();
        let mut conn = log.conn();
        let mut agents: HashMap<String, i64> = HashMap::new();
        write_batch(&mut conn, &[pending(10, "known/1.0")], &mut agents).unwrap();
        let known = agents["known/1.0"];
        for i in 0..20001 {
            agents.insert(format!("filler-{i}"), 1_000_000 + i);
        }
        write_batch(&mut conn, &[pending(20, "new/2.0"), pending(21, "known/1.0"), pending(22, "new/2.0")], &mut agents)
            .unwrap();
        let ids: Vec<i64> = {
            let mut stmt = conn.prepare("SELECT agent_id FROM requests WHERE ts >= 20 ORDER BY ts").unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0)).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        assert_eq!(ids[1], known, "the known agent lost its id");
        assert!(ids[0] > 0 && ids[0] == ids[2] && ids[0] != known);
        assert!(agents.len() < 100, "the cache was not cleared");
    }
}
