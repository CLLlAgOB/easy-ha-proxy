//! The live activity buffer and its aggregation (Python `guardd.live`, the
//! parts beyond the minute digests and the refusal rule in `live`).

use crate::constants::clamp_str;
use crate::live::live_refusal;
use crate::parser::ParsedRequest;
use crate::reqlog::{
    summary_layout, RequestQuery, RequestSummary, REQUEST_COUNT_CAP, REQUEST_SUMMARY_SECONDS,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::Instant;

pub const LIVE_MAX_ADDRESSES: usize = 300;
pub const LIVE_MAX_BLOCKED_ADDRESSES: usize = 500;
pub const LIVE_MAX_EVENTS: usize = 300;
pub const LIVE_MAX_PATHS: usize = 50;
pub const LIVE_MAX_NOT_FOUND: usize = 30;
pub const LIVE_MAX_AGENTS: usize = 30;
pub const LIVE_MAX_SLOW: usize = 50;
pub const LIVE_CACHE_SECONDS: f64 = 2.0;
pub const LIVE_WANTED_SECONDS: f64 = 120.0;
pub const LIVE_FAST_TICK_SECONDS: f64 = 2.0;
pub const FAST_REACTION_TICK_SECONDS: f64 = 1.0;
pub const LIVE_REFILL_BYTES: u64 = 16 * 1024 * 1024;
pub const LIVE_REFILL_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
pub const LIVE_REFILL_FULL: f64 = 0.98;
pub const LIVE_HOURLY_MAX_ADDRESSES: usize = 10_000;
pub const LIVE_RECORD_BASE_BYTES: usize = 230;
pub const LIVE_STRING_BYTES: usize = 49;
pub const LIVE_BUDGET_MIN_MIB: i64 = 16;
pub const LIVE_BUDGET_MAX_MIB: i64 = 128;
pub const LIVE_BUDGET_STEP_MIB: i64 = 8;
pub const LIVE_BUDGET_MAX_SECONDS: i64 = 24 * 3600;
pub const LIVE_BUDGET_MAX_RECORDS: usize = 1_000_000;
pub const LIVE_BUDGET_STATE_KEY: &str = "live_memory_budget";
pub const LIVE_BUDGET_SLACK: f64 = 1.15;
pub const LIVE_BUDGET_SERVICE_RESERVE: f64 = 96.0 * 1024.0 * 1024.0;
pub const LIVE_BUDGET_HOST_SHARE: f64 = 0.25;
pub const LIVE_RATE_SECONDS: i64 = 3600;
pub const LIVE_WINDOW_MAX_SECONDS: i64 = 3600;
pub const MIB: i64 = 1024 * 1024;

pub const LIVE_ADMIN_BACKENDS: [&str; 2] = ["be_admin", "be_stats"];

pub const ENFORCEMENT_BATCH: usize = 200;
pub const ENFORCEMENT_SWEEP_RESERVE: usize = 50;
pub const ENFORCEMENT_QUEUE_LIMIT: usize = 4096;
pub const ENFORCEMENT_RECOVERY_EVENTS: i64 = 1000;
pub const ENFORCEMENT_CURSOR_KEY: &str = "enforcement_scan_after";

/// A user agent as the log template writes it: every character outside
/// `[a-z0-9./;:_-]` made "_" (the input is already lower case).
pub fn logged_agent(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || "./;:_-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The syslog timestamp at the start of a line, which carries its zone.
pub fn line_epoch(line: &str) -> Option<f64> {
    let head: String = line.chars().take(40).collect();
    let stamp = head.split(' ').next().unwrap_or("");
    static R: OnceLock<Regex> = OnceLock::new();
    let rx = R.get_or_init(|| {
        Regex::new(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
            .expect("regex")
    });
    let c = rx.captures(stamp)?;
    let whole = crate::context::parse_iso_time(&format!(
        "{}{}",
        &c[1],
        c.get(3).map(|m| m.as_str()).unwrap_or("")
    ))?;
    let frac: f64 = c
        .get(2)
        .and_then(|m| format!("0{}", m.as_str()).parse().ok())
        .unwrap_or(0.0);
    Some(whole as f64 + frac)
}

/// One request held in the live buffer (the Python 17-field tuple).
#[derive(Debug, Clone)]
pub struct LiveRecord {
    pub ts: f64,
    pub ip: String,
    pub status: u16,
    pub host: String,
    pub path: String,
    pub method: String,
    pub backend: String,
    pub bytes_out: u64,
    pub duration_ms: i64,
    pub term: String,
    pub ban_reason: String,
    pub refusal: &'static str,
    pub response_ms: i64,
    pub times: String,
    pub request_id: String,
    pub user_agent: String,
    pub authenticated_user: String,
}

impl LiveRecord {
    pub fn from_parsed(req: &ParsedRequest, ts: f64) -> Self {
        Self {
            ts,
            ip: req.client_ip.clone(),
            status: req.status,
            host: req.host.clone(),
            path: if req.bad_request {
                "<BADREQ>".to_string()
            } else {
                req.path.chars().take(200).collect()
            },
            method: req.method.clone(),
            backend: req.backend.clone(),
            bytes_out: req.bytes_out,
            duration_ms: req.duration_ms,
            term: req.term.clone(),
            ban_reason: req.ban_reason.clone(),
            refusal: live_refusal(req.status, &req.backend, &req.term, &req.ban_reason),
            response_ms: req.response_ms,
            times: req.times.clone(),
            request_id: req.request_id.clone(),
            user_agent: req.user_agent.chars().take(200).collect(),
            authenticated_user: req.authenticated_user.clone(),
        }
    }

    /// The size estimate the memory budget counts (Python `live_record_bytes`).
    pub fn estimated_bytes(&self) -> usize {
        let mut size = LIVE_RECORD_BASE_BYTES;
        for v in [
            &self.ip,
            &self.path,
            &self.ban_reason,
            &self.times,
            &self.request_id,
            &self.authenticated_user,
        ] {
            if !v.is_empty() {
                size += LIVE_STRING_BYTES + v.chars().count();
            }
        }
        size
    }

    pub fn backend_name(&self) -> &str {
        self.backend.split('/').next().unwrap_or("")
    }

    pub fn event_json(&self) -> Value {
        json!({
            "ts": self.ts, "ip": self.ip, "host": self.host, "method": self.method, "path": self.path,
            "status": self.status, "duration_ms": self.duration_ms, "bytes": self.bytes_out,
            "backend": self.backend, "term": self.term, "refusal": self.refusal, "ban_reason": self.ban_reason,
            "response_ms": if self.response_ms >= 0 { json!(self.response_ms) } else { Value::Null },
            "times": self.times, "request_id": self.request_id, "user_agent": self.user_agent,
            "authenticated_user": self.authenticated_user,
        })
    }

    /// A live record as the request log shows a stored row.
    pub fn memory_row(&self, row_id: i64) -> Value {
        let (backend, server) = match self.backend.split_once('/') {
            Some((b, s)) => (b, s),
            None => (self.backend.as_str(), ""),
        };
        let bad = self.path == "<BADREQ>";
        json!({
            "id": row_id, "ts": self.ts as i64, "request_id": self.request_id,
            "client": self.ip, "status": self.status, "frontend": "", "backend": backend,
            "server": if server.is_empty() || server == "<NOSRV>" { "" } else { server },
            "method": self.method, "host": self.host, "path": if bad { "" } else { self.path.as_str() },
            "bytes_out": self.bytes_out, "duration_ms": self.duration_ms, "bad_request": i64::from(bad),
            "response_ms": if self.response_ms >= 0 { self.response_ms } else { -1 },
            "times": self.times, "term": self.term, "ban_reason": self.ban_reason,
            "user_agent": self.user_agent, "refusal": self.refusal,
            "authenticated_user": self.authenticated_user,
        })
    }
}

// -- memory budget ----------------------------------------------------------

fn read_first_line(path: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.lines().next().map(|l| l.trim().to_string()))
        .unwrap_or_default()
}

fn proc_kib(path: &str, key: &str) -> i64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| {
            t.lines().find(|l| l.starts_with(key)).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<i64>().ok())
            })
        })
        .map(|k| k * 1024)
        .unwrap_or(0)
}

pub fn process_rss_bytes() -> i64 {
    proc_kib("/proc/self/status", "VmRSS:")
}

pub fn host_memory_available() -> i64 {
    proc_kib("/proc/meminfo", "MemAvailable:")
}

/// systemd's MemoryMax / the cgroup's memory.max for this process, or 0.
pub fn service_memory_limit() -> i64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return 0;
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let value = if parts[0] == "0" && parts[1].is_empty() {
            read_first_line(&format!(
                "/sys/fs/cgroup{}/memory.max",
                parts[2].trim_end_matches('/')
            ))
        } else if parts[1].split(',').any(|c| c == "memory") {
            read_first_line(&format!(
                "/sys/fs/cgroup/memory{}/memory.limit_in_bytes",
                parts[2].trim_end_matches('/')
            ))
        } else {
            continue;
        };
        if let Ok(n) = value.parse::<i64>() {
            if n > 0 && n < (1i64 << 50) {
                return n;
            }
        }
    }
    0
}

/// The largest budget in MiB the buffer may be given now, and what set it.
pub fn live_budget_ceiling(held_bytes: i64, host: bool) -> (i64, &'static str) {
    let mut ceiling = LIVE_BUDGET_MAX_MIB as f64;
    let mut reason = "cap";
    let limit = service_memory_limit();
    let rss = process_rss_bytes();
    if limit != 0 && rss != 0 {
        let baseline = (rss as f64 - held_bytes as f64 * LIVE_BUDGET_SLACK).max(0.0);
        let room = (limit as f64 - baseline - LIVE_BUDGET_SERVICE_RESERVE)
            / LIVE_BUDGET_SLACK
            / MIB as f64;
        if room < ceiling {
            ceiling = room;
            reason = "service";
        }
    }
    if host {
        let available = host_memory_available();
        if available != 0 {
            let room = (held_bytes as f64
                + available as f64 * LIVE_BUDGET_HOST_SHARE / LIVE_BUDGET_SLACK)
                / MIB as f64;
            if room < ceiling {
                ceiling = room;
                reason = "host";
            }
        }
    }
    let stepped = (ceiling.max(0.0) as i64) / LIVE_BUDGET_STEP_MIB * LIVE_BUDGET_STEP_MIB;
    (stepped, reason)
}

// -- filters ------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LiveFilters {
    pub ip: String,
    pub host: String,
    pub q: String,
    pub status: String,
    pub blocked: bool,
    pub banned: bool,
    pub hide_admin: bool,
    pub agent: String,
    pub ips: Option<HashSet<String>>,
}

impl LiveFilters {
    pub fn is_empty(&self) -> bool {
        *self == LiveFilters::default()
    }

    /// The cache key, as Python's `json.dumps([window, filters], sort_keys=True)`.
    pub fn key_json(&self) -> Value {
        let mut m = Map::new();
        if !self.agent.is_empty() {
            m.insert("agent".into(), json!(self.agent));
        }
        if self.banned {
            m.insert("banned".into(), json!(true));
        }
        if self.blocked {
            m.insert("blocked".into(), json!(true));
        }
        if self.hide_admin {
            m.insert("hide_admin".into(), json!(true));
        }
        if !self.host.is_empty() {
            m.insert("host".into(), json!(self.host));
        }
        if !self.ip.is_empty() {
            m.insert("ip".into(), json!(self.ip));
        }
        if !self.q.is_empty() {
            m.insert("q".into(), json!(self.q));
        }
        if !self.status.is_empty() {
            m.insert("status".into(), json!(self.status));
        }
        Value::Object(m)
    }

    pub fn matches(&self, r: &LiveRecord) -> bool {
        if !self.ip.is_empty() && !r.ip.starts_with(&self.ip) {
            return false;
        }
        if !self.host.is_empty() && r.host != self.host {
            return false;
        }
        if !self.q.is_empty()
            && !r.path.to_lowercase().contains(&self.q)
            && !r.host.contains(&self.q)
        {
            return false;
        }
        if !self.status.is_empty()
            && r.status.to_string().chars().next() != self.status.chars().next()
        {
            return false;
        }
        if self.blocked && r.refusal.is_empty() {
            return false;
        }
        if let Some(ips) = &self.ips {
            if !ips.contains(&r.ip) {
                return false;
            }
        }
        if self.hide_admin && LIVE_ADMIN_BACKENDS.contains(&r.backend_name()) {
            return false;
        }
        if !self.agent.is_empty() && !r.user_agent.to_lowercase().contains(&self.agent) {
            return false;
        }
        true
    }
}

pub fn truthy(v: Option<&String>) -> bool {
    matches!(
        v.map(|s| s.to_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

pub fn live_filters(raw: &HashMap<String, String>) -> Result<LiveFilters, String> {
    static IP: OnceLock<Regex> = OnceLock::new();
    static HOST: OnceLock<Regex> = OnceLock::new();
    let mut f = LiveFilters::default();
    let ip = raw
        .get("ip")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !ip.is_empty() {
        if !IP
            .get_or_init(|| Regex::new(r"^[0-9A-Fa-f:.]{1,45}$").expect("regex"))
            .is_match(&ip)
        {
            return Err("invalid ip filter".into());
        }
        f.ip = ip;
    }
    let host = raw
        .get("host")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if !host.is_empty() {
        if !HOST
            .get_or_init(|| Regex::new(r"^[a-z0-9.-]{1,253}$").expect("regex"))
            .is_match(&host)
        {
            return Err("invalid host filter".into());
        }
        f.host = host;
    }
    let q = raw
        .get("q")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if !q.is_empty() {
        f.q = q.chars().take(120).collect();
    }
    let status = raw
        .get("status")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !status.is_empty() {
        if !["1xx", "2xx", "3xx", "4xx", "5xx"].contains(&status.as_str()) {
            return Err("invalid status filter".into());
        }
        f.status = status;
    }
    f.blocked = truthy(raw.get("blocked"));
    f.banned = truthy(raw.get("banned"));
    f.hide_admin = truthy(raw.get("hide_admin"));
    let agent = raw
        .get("agent")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if !agent.is_empty() {
        f.agent = logged_agent(&agent.chars().take(120).collect::<String>());
    }
    Ok(f)
}

/// Python's round(): halves to even.
pub fn py_round(x: f64) -> f64 {
    let r = x.round();
    if (x - x.trunc()).abs() == 0.5 && r % 2.0 != 0.0 {
        r - x.signum()
    } else {
        r
    }
}

fn round2(x: f64) -> f64 {
    py_round(x * 100.0) / 100.0
}

fn server_times(values: &mut [i64]) -> Map<String, Value> {
    let mut m = Map::new();
    if values.is_empty() {
        for k in ["p50_ms", "p95_ms", "avg_ms"] {
            m.insert(k.into(), Value::Null);
        }
        return m;
    }
    values.sort_unstable();
    let last = values.len() - 1;
    let pick = |q: f64| values[py_round(q * last as f64) as usize];
    m.insert("p50_ms".into(), json!(pick(0.50)));
    m.insert("p95_ms".into(), json!(pick(0.95)));
    m.insert(
        "avg_ms".into(),
        json!(values.iter().sum::<i64>() / values.len() as i64),
    );
    m
}

/// Either one value or several with counts (the Python `str | dict` trick).
#[derive(Debug, Clone)]
enum Tally {
    One(String),
    Many(Vec<(String, i64)>),
}

impl Tally {
    fn most(&self) -> (String, usize) {
        match self {
            Tally::One(v) => (v.clone(), usize::from(!v.is_empty())),
            Tally::Many(items) => {
                let mut best: Option<&(String, i64)> = None;
                for it in items {
                    if best.is_none_or(|b| it.1 > b.1) {
                        best = Some(it);
                    }
                }
                (best.map(|b| b.0.clone()).unwrap_or_default(), items.len())
            }
        }
    }

    fn bump(&mut self, value: &str, previous_total: i64) {
        match self {
            Tally::Many(items) => match items.iter_mut().find(|(h, _)| h == value) {
                Some(it) => it.1 += 1,
                None => items.push((value.to_string(), 1)),
            },
            Tally::One(known) => {
                if known.is_empty() {
                    *self = Tally::One(value.to_string());
                } else if known != value {
                    *self = Tally::Many(vec![
                        (known.clone(), previous_total),
                        (value.to_string(), 1),
                    ]);
                }
            }
        }
    }
}

struct AddressEntry<'a> {
    requests: i64,
    errors: i64,
    server_errors: i64,
    refused: i64,
    bytes: u64,
    first_ts: f64,
    last: &'a LiveRecord,
    hosts: Tally,
    reasons: Tally,
    server_ms: i64,
    answered: i64,
}

struct SiteEntry {
    first: usize,
    requests: i64,
    errors: i64,
    server_errors: i64,
    refused: i64,
    addresses: HashSet<String>,
    backend: String,
    server_ms: Vec<i64>,
    spark: Vec<i64>,
}

/// Totals, addresses, sites, a timeline and the latest requests.
pub fn live_aggregate(
    records: &[&LiveRecord],
    now: f64,
    window: i64,
    filters: &LiveFilters,
    covered: Option<i64>,
) -> Value {
    let since = now - window as f64;
    let bucket = (window / 60).max(1);
    let buckets = ((window + bucket - 1) / bucket).max(1) as usize;
    let mut ok_counts = vec![0i64; buckets];
    let mut error_counts = vec![0i64; buckets];
    let mut blocked_counts = vec![0i64; buckets];
    let mut addresses: HashMap<&str, AddressEntry> = HashMap::new();
    let mut address_order: Vec<&str> = Vec::new();
    let mut sites: HashMap<&str, SiteEntry> = HashMap::new();
    let mut statuses: Vec<(u16, i64)> = Vec::new();
    let mut refusals: Vec<(&str, i64)> = Vec::new();
    let mut events: VecDeque<&LiveRecord> = VecDeque::with_capacity(LIVE_MAX_EVENTS);
    let mut paths: HashMap<(&str, &str), [i64; 5]> = HashMap::new();
    let mut path_order: Vec<(&str, &str)> = Vec::new();
    let mut agents: HashMap<&str, (i64, i64, HashSet<&str>)> = HashMap::new();
    let mut agent_order: Vec<&str> = Vec::new();
    let mut slow: BinaryHeap<Reverse<(i64, usize)>> = BinaryHeap::new();
    let mut slow_records: HashMap<usize, &LiveRecord> = HashMap::new();
    let (mut total, mut errors_total, mut server_total, mut blocked_total) =
        (0i64, 0i64, 0i64, 0i64);
    let mut bytes_total: u64 = 0;
    let filtering = !filters.is_empty();

    for &r in records {
        if r.ts < since || (filtering && !filters.matches(r)) {
            continue;
        }
        let status = r.status;
        let refusal = r.refusal;
        let refused = !refusal.is_empty();
        let error = status >= 400;
        let server_error = status >= 500;
        total += 1;
        bytes_total += r.bytes_out;
        match statuses.iter_mut().find(|(c, _)| *c == status) {
            Some(e) => e.1 += 1,
            None => statuses.push((status, 1)),
        }
        let slot = (((r.ts - since) / bucket as f64).floor().max(0.0) as usize).min(buckets - 1);
        if refused {
            blocked_total += 1;
            match refusals.iter_mut().find(|(k, _)| *k == refusal) {
                Some(e) => e.1 += 1,
                None => refusals.push((refusal, 1)),
            }
            blocked_counts[slot] += 1;
        } else if error {
            error_counts[slot] += 1;
        } else {
            ok_counts[slot] += 1;
        }
        if error {
            errors_total += 1;
            if server_error {
                server_total += 1;
            }
        }
        let answered_ms = if r.response_ms >= 0 {
            r.response_ms
        } else {
            -1
        };
        let reason_of = || {
            if r.ban_reason.is_empty() {
                refusal.to_string()
            } else {
                r.ban_reason.clone()
            }
        };
        match addresses.get_mut(r.ip.as_str()) {
            None => {
                address_order.push(r.ip.as_str());
                addresses.insert(
                    r.ip.as_str(),
                    AddressEntry {
                        requests: 1,
                        errors: i64::from(error),
                        server_errors: i64::from(server_error),
                        refused: i64::from(refused),
                        bytes: r.bytes_out,
                        first_ts: r.ts,
                        last: r,
                        hosts: Tally::One(r.host.clone()),
                        reasons: Tally::One(if refused { reason_of() } else { String::new() }),
                        server_ms: answered_ms.max(0),
                        answered: i64::from(answered_ms >= 0),
                    },
                );
            }
            Some(entry) => {
                if answered_ms >= 0 {
                    entry.server_ms += answered_ms;
                    entry.answered += 1;
                }
                entry.requests += 1;
                entry.errors += i64::from(error);
                entry.server_errors += i64::from(server_error);
                entry.bytes += r.bytes_out;
                entry.last = r;
                let before = entry.requests - 1;
                if let Tally::One(known) = &entry.hosts {
                    if known.is_empty() && !r.host.is_empty() {
                        // Python keeps "" and a later host apart like any two values.
                        entry.hosts =
                            Tally::Many(vec![(String::new(), before), (r.host.clone(), 1)]);
                    } else {
                        entry.hosts.bump(&r.host, before);
                    }
                } else {
                    entry.hosts.bump(&r.host, before);
                }
                if refused {
                    entry.refused += 1;
                    let held_before = entry.refused - 1;
                    entry.reasons.bump(&reason_of(), held_before);
                }
            }
        }
        let order = sites.len();
        let site = sites.entry(r.host.as_str()).or_insert_with(|| SiteEntry {
            first: order,
            requests: 0,
            errors: 0,
            server_errors: 0,
            refused: 0,
            addresses: HashSet::new(),
            backend: String::new(),
            server_ms: Vec::new(),
            spark: vec![0; buckets],
        });
        if answered_ms >= 0 {
            site.server_ms.push(answered_ms);
            let seq = total as usize;
            if slow.len() < LIVE_MAX_SLOW {
                slow.push(Reverse((answered_ms, seq)));
                slow_records.insert(seq, r);
            } else if slow
                .peek()
                .is_some_and(|Reverse((smallest, _))| answered_ms > *smallest)
            {
                if let Some(Reverse((_, gone))) = slow.pop() {
                    slow_records.remove(&gone);
                }
                slow.push(Reverse((answered_ms, seq)));
                slow_records.insert(seq, r);
            }
        }
        site.spark[slot] += 1;
        let key = (r.host.as_str(), r.path.as_str());
        let counted = paths.entry(key).or_insert_with(|| {
            path_order.push(key);
            [0; 5]
        });
        counted[0] += 1;
        if refused {
            counted[4] += 1;
        } else if status == 404 {
            counted[2] += 1;
            counted[1] += 1;
        } else if server_error {
            counted[3] += 1;
        } else if error {
            counted[1] += 1;
        }
        if !r.user_agent.is_empty() {
            let client = agents.entry(r.user_agent.as_str()).or_insert_with(|| {
                agent_order.push(r.user_agent.as_str());
                (0, 0, HashSet::new())
            });
            client.0 += 1;
            client.1 += i64::from(refused);
            if client.2.len() < 1000 {
                client.2.insert(r.ip.as_str());
            }
        }
        site.requests += 1;
        site.errors += i64::from(error);
        site.server_errors += i64::from(server_error);
        site.refused += i64::from(refused);
        site.addresses.insert(r.ip.clone());
        if site.backend.is_empty() && !r.backend.ends_with("/<NOSRV>") {
            site.backend = r.backend_name().to_string();
        }
        if events.len() == LIVE_MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(r);
    }

    let covered = match covered {
        None => window,
        Some(c) => c.min(window).max(1),
    };
    let address_row = |ip: &str, e: &AddressEntry| -> Value {
        let (top_host, host_count) = e.hosts.most();
        let (reason, _) = e.reasons.most();
        let span = (now - e.first_ts + 1.0).min(covered as f64).max(1.0);
        json!({
            "ip": ip, "requests": e.requests, "rate": round2(e.requests as f64 / span),
            "errors": e.errors, "server_errors": e.server_errors, "blocked": e.refused,
            "bytes": e.bytes, "avg_ms": if e.answered > 0 { json!(e.server_ms / e.answered) } else { Value::Null },
            "top_host": top_host, "hosts": if !top_host.is_empty() || host_count > 1 { host_count } else { 0 },
            "last": e.last.ts, "last_status": e.last.status, "last_method": e.last.method,
            "last_path": e.last.path.chars().take(160).collect::<String>(), "last_host": e.last.host, "reason": reason,
        })
    };
    let mut ranked: Vec<&str> = address_order.clone();
    ranked.sort_by_key(|ip| Reverse(addresses[ip].requests));
    ranked.truncate(LIVE_MAX_ADDRESSES);
    let chosen: HashSet<&str> = ranked.iter().copied().collect();
    let mut blocked: Vec<&str> = address_order
        .iter()
        .copied()
        .filter(|ip| addresses[ip].refused > 0 && !chosen.contains(ip))
        .collect();
    blocked.sort_by_key(|ip| Reverse(addresses[ip].refused));
    blocked.truncate(LIVE_MAX_BLOCKED_ADDRESSES);
    let rows: Vec<Value> = ranked
        .iter()
        .chain(blocked.iter())
        .map(|ip| address_row(ip, &addresses[ip]))
        .collect();
    let mut site_list: Vec<(&str, SiteEntry)> = sites.into_iter().collect();
    site_list.sort_by_key(|(_, v)| v.first);
    site_list.sort_by_key(|(_, v)| Reverse(v.requests));
    let site_rows: Vec<Value> = site_list
        .into_iter()
        .take(200)
        .map(|(host, mut v)| {
            let mut m = Map::new();
            m.insert("host".into(), json!(host));
            m.insert("requests".into(), json!(v.requests));
            m.insert("errors".into(), json!(v.errors));
            m.insert("server_errors".into(), json!(v.server_errors));
            m.insert("blocked".into(), json!(v.refused));
            m.insert("addresses".into(), json!(v.addresses.len()));
            m.insert("backend".into(), json!(v.backend));
            for (k, val) in server_times(&mut v.server_ms) {
                m.insert(k, val);
            }
            m.insert("spark".into(), json!(v.spark));
            Value::Object(m)
        })
        .collect();
    let mut top_paths: Vec<(&str, &str)> = path_order.clone();
    top_paths.sort_by_key(|k| Reverse(paths[k][0]));
    let mut not_found: Vec<(&str, &str)> = path_order
        .iter()
        .copied()
        .filter(|k| paths[k][2] > 0)
        .collect();
    not_found.sort_by_key(|k| Reverse(paths[k][2]));
    let mut top_agents: Vec<&str> = agent_order.clone();
    top_agents.sort_by_key(|a| Reverse(agents[a].0));
    let mut slow_sorted: Vec<(i64, usize)> = slow.into_iter().map(|Reverse(x)| x).collect();
    slow_sorted.sort_by_key(|x| Reverse(x.0));
    let mut status_map = Map::new();
    for (code, count) in &statuses {
        status_map.insert(code.to_string(), json!(count));
    }
    let mut refusal_map = Map::new();
    for (k, v) in &refusals {
        refusal_map.insert((*k).to_string(), json!(v));
    }
    json!({
        "ok": true,
        "now": now,
        "window": window,
        "covered_seconds": covered,
        "truncated": covered < window,
        "bucket_seconds": bucket,
        "totals": {
            "requests": total, "errors": errors_total, "server_errors": server_total,
            "blocked": blocked_total, "bytes": bytes_total, "addresses": addresses.len(),
            "rate": round2(total as f64 / covered.max(1) as f64),
        },
        "timeline": (0..buckets).map(|i| json!({"ok": ok_counts[i], "errors": error_counts[i], "blocked": blocked_counts[i]})).collect::<Vec<_>>(),
        "statuses": status_map,
        "refusals": refusal_map,
        "addresses": rows,
        "addresses_total": addresses.len(),
        "sites": site_rows,
        "paths": top_paths.iter().take(LIVE_MAX_PATHS).map(|k| {
            let v = paths[k];
            json!({"host": k.0, "path": k.1, "requests": v[0], "client_errors": v[1],
                   "not_found": v[2], "server_errors": v[3], "blocked": v[4]})
        }).collect::<Vec<_>>(),
        "not_found": not_found.iter().take(LIVE_MAX_NOT_FOUND).map(|k| {
            let v = paths[k];
            json!({"host": k.0, "path": k.1, "not_found": v[2], "requests": v[0]})
        }).collect::<Vec<_>>(),
        "agents": top_agents.iter().take(LIVE_MAX_AGENTS).map(|a| {
            let v = &agents[a];
            json!({"agent": a, "requests": v.0, "blocked": v.1, "addresses": v.2.len()})
        }).collect::<Vec<_>>(),
        "slow": slow_sorted.iter().filter_map(|(_, o)| slow_records.get(o).map(|r| r.event_json())).collect::<Vec<_>>(),
        "events": events.iter().rev().map(|r| r.event_json()).collect::<Vec<_>>(),
    })
}

// -- the buffer ---------------------------------------------------------------

type Identities = Vec<(String, Vec<(String, f64)>)>;

#[derive(Debug)]
pub struct LiveBuffer {
    pub default_records: usize,
    pub default_seconds: i64,
    pub max_records: usize,
    pub max_seconds: i64,
    pub max_bytes: i64,
    bytes: i64,
    arrivals: BTreeMap<i64, (i64, i64)>,
    records: VecDeque<LiveRecord>,
    base: i64,
    cache: HashMap<String, (Instant, Value)>,
    wanted_at: Option<Instant>,
    pub started: f64,
    pub evicted_for_size: u64,
    hourly: HashMap<(i64, u16), HashMap<String, i64>>,
    identities: Identities,
}

impl LiveBuffer {
    pub fn new(max_records: usize, max_seconds: i64) -> Self {
        let default_records = max_records.max(1);
        let default_seconds = max_seconds.max(60);
        Self {
            default_records,
            default_seconds,
            max_records: default_records,
            max_seconds: default_seconds,
            max_bytes: 0,
            bytes: 0,
            arrivals: BTreeMap::new(),
            records: VecDeque::new(),
            base: 1_000_000_000_000,
            cache: HashMap::new(),
            wanted_at: None,
            started: crate::constants::utc_now_f(),
            evicted_for_size: 0,
            hourly: HashMap::new(),
            identities: Vec::new(),
        }
    }

    pub fn identities(&self, now: f64) -> Value {
        let mut out = Map::new();
        for (ip, users) in &self.identities {
            let recent: Vec<Value> = users
                .iter()
                .filter(|(_, ts)| now - 86400.0 <= *ts && *ts <= now)
                .map(|(u, ts)| json!({"username": u, "last_seen": ts}))
                .collect();
            if !recent.is_empty() {
                out.insert(ip.clone(), Value::from(recent));
            }
        }
        Value::Object(out)
    }

    pub fn wanted(&self) -> bool {
        self.wanted_at
            .is_some_and(|t| t.elapsed().as_secs_f64() < LIVE_WANTED_SECONDS)
    }

    fn count(&mut self, records: &[LiveRecord]) {
        for r in records {
            if !r.authenticated_user.is_empty() {
                let pos = self.identities.iter().position(|(ip, _)| *ip == r.ip);
                let mut users = match pos {
                    Some(p) => self.identities.remove(p).1,
                    None => Vec::new(),
                };
                match users.iter_mut().find(|(u, _)| *u == r.authenticated_user) {
                    Some(e) => e.1 = e.1.max(r.ts),
                    None => users.push((r.authenticated_user.clone(), r.ts)),
                }
                if users.len() > 8 {
                    let oldest = users
                        .iter()
                        .enumerate()
                        .min_by(|a, b| a.1 .1.total_cmp(&b.1 .1))
                        .map(|(i, _)| i);
                    if let Some(i) = oldest {
                        users.remove(i);
                    }
                }
                self.identities.push((r.ip.clone(), users));
                if self.identities.len() > 1024 {
                    self.identities.remove(0);
                }
            }
            let size = r.estimated_bytes() as i64;
            self.bytes += size;
            let minute = (r.ts as i64).div_euclid(60);
            let slot = self.arrivals.entry(minute).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += size;
            if r.status == 400 || r.status == 451 {
                let hour = (r.ts as i64).div_euclid(3600) * 3600;
                let counter = self.hourly.entry((hour, r.status)).or_default();
                *counter.entry(r.ip.clone()).or_insert(0) += 1;
                if counter.len() > LIVE_HOURLY_MAX_ADDRESSES {
                    let mut kept: Vec<(String, i64)> = counter.drain().collect();
                    kept.sort_by_key(|x| Reverse(x.1));
                    kept.truncate(LIVE_HOURLY_MAX_ADDRESSES / 2);
                    counter.extend(kept);
                }
            }
        }
        if self.arrivals.len() as i64 > LIVE_RATE_SECONDS / 60 + 10 {
            if let Some(&newest) = self.arrivals.keys().next_back() {
                let first = newest - LIVE_RATE_SECONDS / 60;
                self.arrivals.retain(|&m, _| m >= first);
            }
        }
    }

    fn trim(&mut self, newest: Option<f64>) -> usize {
        let mut dropped = 0usize;
        while !self.records.is_empty()
            && (self.records.len() > self.max_records
                || (self.max_bytes != 0 && self.bytes > self.max_bytes))
        {
            if let Some(r) = self.records.pop_front() {
                self.bytes -= r.estimated_bytes() as i64;
            }
            dropped += 1;
        }
        self.base += dropped as i64;
        self.evicted_for_size += dropped as u64;
        if let Some(newest) = newest {
            let horizon = newest - self.max_seconds as f64;
            while self.records.front().is_some_and(|r| r.ts < horizon) {
                if let Some(r) = self.records.pop_front() {
                    self.bytes -= r.estimated_bytes() as i64;
                }
                self.base += 1;
            }
        }
        if self.records.is_empty() {
            self.bytes = 0;
        }
        dropped
    }

    pub fn extend(&mut self, records: Vec<LiveRecord>) {
        let Some(last_ts) = records.last().map(|r| r.ts) else {
            return;
        };
        self.count(&records);
        self.records.extend(records);
        self.trim(Some(last_ts));
        if self.hourly.len() > 60 {
            let oldest = (last_ts as i64).div_euclid(3600) * 3600 - 25 * 3600;
            self.hourly.retain(|k, _| k.0 >= oldest);
        }
    }

    pub fn refill(&mut self, records: Vec<LiveRecord>, complete_since: f64) {
        if records.is_empty() {
            return;
        }
        self.count(&records);
        self.base -= records.len() as i64;
        for r in records.into_iter().rev() {
            self.records.push_front(r);
        }
        self.trim(None);
        self.started = self.started.min(complete_since);
        self.cache.clear();
    }

    pub fn set_budget(&mut self, max_bytes: i64) -> usize {
        let before = self.records.len();
        if max_bytes > 0 {
            self.max_bytes = max_bytes;
            self.max_records = LIVE_BUDGET_MAX_RECORDS;
            self.max_seconds = LIVE_BUDGET_MAX_SECONDS;
        } else {
            self.max_bytes = 0;
            self.max_records = self.default_records;
            self.max_seconds = self.default_seconds;
        }
        let newest = self.records.back().map(|r| r.ts);
        self.trim(newest);
        self.cache.clear();
        before - self.records.len()
    }

    fn rate(&self) -> Value {
        let (Some(first_rec), Some(last_rec)) = (self.records.front(), self.records.back()) else {
            return json!({"records_per_hour": 0, "bytes_per_hour": 0, "measured_seconds": 0});
        };
        let newest = last_rec.ts;
        let first = (newest as i64).div_euclid(60) - (LIVE_RATE_SECONDS / 60 - 1);
        let (mut count, mut size) = (0i64, 0i64);
        for (&minute, &(requests, nbytes)) in &self.arrivals {
            if minute >= first {
                count += requests;
                size += nbytes;
            }
        }
        let since = (first as f64 * 60.0).max(self.started.min(first_rec.ts));
        let measured = (newest - since).max(60.0);
        json!({
            "records_per_hour": (count as f64 * 3600.0 / measured) as i64,
            "bytes_per_hour": (size as f64 * 3600.0 / measured) as i64,
            "measured_seconds": measured as i64,
        })
    }

    pub fn search_requests(
        &self,
        query: &RequestQuery,
        before: i64,
        limit: i64,
        count: bool,
    ) -> Value {
        let limit = limit.clamp(1, 500) as usize;
        let base = self.base;
        let mut top = self.records.len() as i64;
        if before != 0 {
            top = (before - base).min(top).max(0);
        }
        let mut rows: Vec<(i64, &LiveRecord)> = Vec::new();
        let mut counted = 0i64;
        for index in (0..top).rev() {
            let r = &self.records[index as usize];
            if !query.matches(r) {
                continue;
            }
            if rows.len() <= limit {
                rows.push((base + index, r));
            }
            counted += 1;
            if counted > REQUEST_COUNT_CAP || (!count && rows.len() > limit) {
                break;
            }
        }
        let more = rows.len() > limit;
        rows.truncate(limit);
        let mut result = json!({
            "requests": rows.iter().map(|(id, r)| r.memory_row(*id)).collect::<Vec<_>>(),
            "next": if more { rows.last().map(|r| r.0).unwrap_or(0) } else { 0 },
            "complete": true,
            "timed_out": false,
            "searched_to": 0,
            "source": "memory",
            "reaches_back_to": self.records.front().map(|r| json!(r.ts)).unwrap_or(json!(0)),
        });
        if count {
            result["total"] = json!(counted.min(REQUEST_COUNT_CAP));
            result["total_exact"] = json!(counted <= REQUEST_COUNT_CAP);
        }
        result
    }

    pub fn summarize_requests(&self, query: &RequestQuery) -> Value {
        let now = crate::constants::utc_now_f();
        let oldest = self.records.front().map(|r| r.ts).unwrap_or(now);
        let start = if query.since != 0.0 {
            query.since.max(oldest)
        } else {
            oldest
        };
        let end = if query.until != 0.0 { query.until } else { now };
        let (first, step, bars) = summary_layout(start, end);
        let mut summary = RequestSummary::new(first, step, bars);
        let started = Instant::now();
        let mut reached_to = 0i64;
        for index in (0..self.records.len()).rev() {
            let r = &self.records[index];
            if query.matches(r) {
                summary.add(
                    (r.ts as i64 - first).div_euclid(step),
                    r.status,
                    !r.refusal.is_empty(),
                    1,
                );
                summary.add_client(&r.ip, 1);
                summary.add_path(&r.host, &r.path, 1);
            }
            if index % 4096 == 0
                && index != 0
                && started.elapsed().as_secs_f64() > REQUEST_SUMMARY_SECONDS
            {
                reached_to = r.ts as i64;
                break;
            }
        }
        let mut result = summary.read();
        result["complete"] = json!(reached_to == 0);
        result["reached_to"] = json!(reached_to);
        result["source"] = json!("memory");
        result
    }

    pub fn status(&self) -> Value {
        json!({
            "records": self.records.len(),
            "max_records": self.max_records,
            "max_seconds": self.max_seconds,
            "max_bytes": self.max_bytes,
            "bytes": self.bytes,
            "oldest": self.records.front().map(|r| json!(r.ts)).unwrap_or(Value::Null),
            "newest": self.records.back().map(|r| json!(r.ts)).unwrap_or(Value::Null),
            "started": self.started,
            "rate": self.rate(),
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn bytes(&self) -> i64 {
        self.bytes
    }

    pub fn snapshot(
        &mut self,
        raw: &HashMap<String, String>,
        now: Option<f64>,
        banned: Option<&HashSet<String>>,
    ) -> Result<Value, String> {
        self.wanted_at = Some(Instant::now());
        let window = match raw
            .get("window")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            None => 60,
            Some(s) => s
                .parse::<i64>()
                .map_err(|_| "window must be a number of seconds".to_string())?,
        };
        let window = window
            .min(self.max_seconds)
            .clamp(5, LIVE_WINDOW_MAX_SECONDS);
        let mut filters = live_filters(raw)?;
        let key = crate::secdb::sorted_json(&json!([window, filters.key_json()]));
        if filters.banned {
            filters.ips = Some(banned.cloned().unwrap_or_default());
        }
        if let Some((at, cached)) = self.cache.get(&key) {
            if at.elapsed().as_secs_f64() < LIVE_CACHE_SECONDS {
                return Ok(cached.clone());
            }
        }
        let now = now.unwrap_or_else(crate::constants::utc_now_f);
        let since = now - window as f64;
        let mut selected: Vec<&LiveRecord> = self
            .records
            .iter()
            .rev()
            .take_while(|r| r.ts >= since)
            .collect();
        selected.reverse();
        let oldest = self.records.front().map(|r| r.ts).unwrap_or(now);
        let covered = if oldest <= since {
            window
        } else if self.evicted_for_size > 0 {
            ((now - oldest) as i64).max(1)
        } else if self.started > since {
            ((now - self.started) as i64).max(1)
        } else {
            window
        };
        let result = live_aggregate(&selected, now, window, &filters, Some(covered));
        if self.cache.len() > 32 {
            self.cache.clear();
        }
        self.cache.insert(key, (Instant::now(), result.clone()));
        Ok(result)
    }

    pub fn attackers(&self, now: f64, limit: usize) -> Value {
        let since = (now as i64).div_euclid(3600) * 3600 - 23 * 3600;
        let mut totals: HashMap<u16, HashMap<&str, i64>> = HashMap::new();
        for ((hour, status), counter) in &self.hourly {
            if *hour >= since {
                let t = totals.entry(*status).or_default();
                for (ip, n) in counter {
                    *t.entry(ip.as_str()).or_insert(0) += n;
                }
            }
        }
        let top = |code: u16| -> Vec<Value> {
            let mut items: Vec<(&str, i64)> = totals
                .get(&code)
                .map(|m| m.iter().map(|(k, v)| (*k, *v)).collect())
                .unwrap_or_default();
            items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            items
                .into_iter()
                .take(limit)
                .map(|(ip, n)| json!({"ip": ip, "count": n}))
                .collect()
        };
        json!({
            "code_400": top(400),
            "code_451": top(451),
            "since": self.started.max(since as f64),
            "diagnostic": {"source": "guardd"},
        })
    }
}

/// An integer query parameter, clamped, with a default.
pub fn int_param(
    raw: &HashMap<String, String>,
    name: &str,
    default: i64,
    min_v: i64,
    max_v: i64,
) -> i64 {
    clamp_str(raw.get(name).map(String::as_str), default, min_v, max_v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ts: f64, ip: &str, status: u16, host: &str, path: &str) -> LiveRecord {
        LiveRecord {
            ts,
            ip: ip.into(),
            status,
            host: host.into(),
            path: path.into(),
            method: "GET".into(),
            backend: "be_site/srv1".into(),
            bytes_out: 10,
            duration_ms: 5,
            term: "----".into(),
            ban_reason: String::new(),
            refusal: "",
            response_ms: 3,
            times: String::new(),
            request_id: String::new(),
            user_agent: "curl".into(),
            authenticated_user: String::new(),
        }
    }

    #[test]
    fn aggregates_and_filters() {
        let rows = [
            rec(100.0, "1.1.1.1", 200, "a.example", "/"),
            rec(101.0, "1.1.1.1", 404, "b.example", "/x"),
            rec(102.0, "2.2.2.2", 200, "a.example", "/"),
        ];
        let refs: Vec<&LiveRecord> = rows.iter().collect();
        let out = live_aggregate(&refs, 110.0, 60, &LiveFilters::default(), None);
        assert_eq!(out["totals"]["requests"], 3);
        assert_eq!(out["addresses"][0]["ip"], "1.1.1.1");
        assert_eq!(out["addresses"][0]["hosts"], 2);
        assert_eq!(out["not_found"][0]["path"], "/x");
        let f = LiveFilters {
            status: "4xx".into(),
            ..Default::default()
        };
        let out = live_aggregate(&refs, 110.0, 60, &f, None);
        assert_eq!(out["totals"]["requests"], 1);
    }

    #[test]
    fn buffer_bounds_and_ids() {
        let mut b = LiveBuffer::new(2, 3600);
        b.extend(vec![
            rec(1.0, "a", 200, "h", "/"),
            rec(2.0, "b", 200, "h", "/"),
            rec(3.0, "c", 200, "h", "/"),
        ]);
        assert_eq!(b.len(), 2);
        let q = RequestQuery::default();
        let page = b.search_requests(&q, 0, 1, true);
        assert_eq!(page["requests"][0]["client"], "c");
        let next = page["next"].as_i64().unwrap();
        let page2 = b.search_requests(&q, next, 1, true);
        assert_eq!(page2["requests"][0]["client"], "b");
    }

    #[test]
    fn syslog_epoch() {
        assert_eq!(
            line_epoch("2026-11-22T10:00:00.500000+00:00 host haproxy[1]: x"),
            Some(1_795_341_600.5)
        );
        assert_eq!(line_epoch("Nov 22 10:00:00 host"), None);
    }
}
