//! The adaptive protection engine: a port of Python `guardd.engine.GuardEngine`.
//!
//! Reads the HAProxy access log and stick tables, scores addresses from the
//! stored findings, and applies the ban policy -- the same decisions, the same
//! records and the same state keys as the Python daemon, so either can run on
//! the same `security.db`.

use crate::alerts::AlertClient;
use crate::constants::*;
use crate::context::{
    cursor_from_state, cursor_state, CatchAllPages, DetectionContext, LoginCorrelations,
    PathCandidates, UnknownHosts,
};
use crate::enforcer::{EnforcementQueue, Enforcer};
use crate::haconfig::{
    decision_summary, first_counter, legacy_ban_readings, normalize_host, read_site_names,
    read_thresholds, validate_trap_hosts, Tables, BAN_POLICY_LEGACY, BAN_POLICY_U02,
};
use crate::live::MinuteDigests;
use crate::livebuf::{
    host_memory_available, line_epoch, live_budget_ceiling, process_rss_bytes,
    service_memory_limit, LiveBuffer, LiveRecord, ENFORCEMENT_BATCH, ENFORCEMENT_CURSOR_KEY,
    ENFORCEMENT_QUEUE_LIMIT, ENFORCEMENT_RECOVERY_EVENTS, ENFORCEMENT_SWEEP_RESERVE,
    FAST_REACTION_TICK_SECONDS, LIVE_BUDGET_MAX_MIB, LIVE_BUDGET_MAX_SECONDS, LIVE_BUDGET_MIN_MIB,
    LIVE_BUDGET_STATE_KEY, LIVE_BUDGET_STEP_MIB, LIVE_FAST_TICK_SECONDS, LIVE_REFILL_BYTES,
    LIVE_REFILL_CHUNK_BYTES, LIVE_REFILL_FULL, MIB,
};
use crate::parser::{parse_access_line, ParsedRequest};
use crate::reqlog::RequestLog;
use crate::runtime::{
    list_tables, parse_table, read_table, runtime_command, GuardConfig, RuntimeError,
};
use crate::scoring::{enforceable, score_events, ExclusionModel, ScoreContribution, ScoringPolicy};
use crate::secdb::{Decision, NewEvent, SecurityDatabase};
use crate::shield::{shield_entries, PathShield, SHIELD_ENABLED_KEY};
use crate::signatures::{is_asset, SignatureEngine};
use crate::tracking::{IpActivity, IpMemory, LogCursor, SubnetCorrelator};
use crate::watchers::{
    BanPolicyWatch, HardFloorWatch, TrustedRates, BAN_POLICY_STATE_KEY, BAN_SNAPSHOTS_KEPT,
    LEGACY_LIFTS_PER_CYCLE, RATE_WARNINGS_KEEP_DAYS, RATE_WARNINGS_KEEP_ROWS,
    TRUST_AFTER_SIGN_IN_SECONDS,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// Errors the API maps to status codes, as the Python exceptions are.
#[derive(Debug)]
pub enum EngineError {
    /// ValueError: 400.
    Value(String),
    /// LookupError: 404.
    Lookup(String),
    /// LiveBudgetConflict: 409.
    Conflict(String),
    /// ManualBanRefused / OSError: 502.
    Refused(String),
    /// Anything else: 500.
    Other(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(m)
            | Self::Lookup(m)
            | Self::Conflict(m)
            | Self::Refused(m)
            | Self::Other(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl From<String> for EngineError {
    fn from(m: String) -> Self {
        Self::Other(m)
    }
}

impl From<RuntimeError> for EngineError {
    fn from(e: RuntimeError) -> Self {
        Self::Refused(e.to_string())
    }
}

pub type EResult<T> = Result<T, EngineError>;

fn log_warn(msg: &str) {
    eprintln!("[WARNING] easy-ha-proxy-guardd: {msg}");
}

fn log_info(msg: &str) {
    eprintln!("[INFO] easy-ha-proxy-guardd: {msg}");
}

fn json_list_strings(raw: &str) -> Vec<String> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string())
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Everything `_emit` touches, kept apart so a finding can be written while
/// the address's activity is borrowed from the memory.
pub struct Sink {
    pub db: Arc<SecurityDatabase>,
    pub exclusions: ExclusionModel,
    pub queue: EnforcementQueue,
    pub subnets: SubnetCorrelator,
    pub promotions: Vec<String>,
    pub events_recorded: u64,
    pub policy: ScoringPolicy,
    pub ban_policy: &'static str,
}

impl Sink {
    pub fn scoring_policy(&self) -> ScoringPolicy {
        if self.ban_policy == BAN_POLICY_U02 {
            self.policy.u02()
        } else {
            self.policy.clone()
        }
    }

    fn queue_check(&mut self, ip: &str, event_type: &str, handled: bool) {
        if !is_weighted_event(event_type) {
            return;
        }
        if handled && !refusal_does_not_excuse(event_type) {
            return;
        }
        let urgent = self.scoring_policy().weight(event_type) >= WOULD_BAN_SCORE
            || event_type == EVENT_SUBNET_CAMPAIGN;
        self.queue.mark(ip, urgent);
    }

    /// Write one finding unless its cooldown holds; true when written.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &mut self,
        ip: &str,
        event_type: &str,
        now: i64,
        source: &str,
        category: &str,
        site: &str,
        detail: &str,
        handled: bool,
        fingerprint: Option<String>,
    ) -> Result<bool, String> {
        let window = cooldown_seconds(event_type);
        let key = fingerprint.unwrap_or_else(|| format!("{ip}|{event_type}"));
        if !self.db.cooldown_passed(&key, now, window)? {
            return Ok(false);
        }
        let verdict = self.exclusions.verdict(ip);
        self.db.observe_ip(ip, now, &verdict)?;
        self.db.record_events(&[NewEvent {
            ts: now,
            ip: ip.into(),
            event_type: event_type.into(),
            source: source.into(),
            category: category.into(),
            site: site.into(),
            detail: detail.into(),
            handled,
        }])?;
        self.queue_check(ip, event_type, handled);
        self.events_recorded += 1;
        if is_weighted_event(event_type) {
            self.promotions.push(ip.to_string());
        }
        if !handled && is_subnet_campaign_trigger(event_type) {
            let (subnet, peers) = self.subnets.observe(ip, now);
            if peers >= self.subnets.min_ips {
                self.emit(
                    ip,
                    EVENT_SUBNET_CAMPAIGN,
                    now,
                    "guardd",
                    "subnet",
                    site,
                    &format!("subnet={subnet} peers={peers}"),
                    false,
                    Some(format!("{ip}|{EVENT_SUBNET_CAMPAIGN}|{subnet}")),
                )?;
            }
        }
        Ok(true)
    }
}

/// The reputation of one address, as `GuardEngine.reputation` returns it.
#[derive(Debug, Clone)]
pub struct Reputation {
    pub ip: String,
    pub score: i64,
    pub state: &'static str,
    pub recommended_action: &'static str,
    pub events_counted: usize,
    pub categories: HashMap<String, f64>,
    pub contributions: Vec<ScoreContribution>,
    pub enforceable: bool,
    pub excluded: bool,
    pub exclusion_reason: String,
    pub authenticated_at: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: usize,
    pub blockers: Vec<String>,
    pub would_ban: bool,
    pub banned_until: i64,
    pub likely_false_positive: bool,
}

fn round2(x: f64) -> f64 {
    crate::livebuf::py_round(x * 100.0) / 100.0
}

impl Reputation {
    pub fn to_json(&self, with_contributions: bool) -> Value {
        let cats: Map<String, Value> = self
            .categories
            .iter()
            .map(|(k, v)| (k.clone(), json!(round2(*v))))
            .collect();
        let mut v = json!({
            "ip": self.ip,
            "score": self.score,
            "state": self.state,
            "recommended_action": self.recommended_action,
            "events_counted": self.events_counted,
            "categories": cats,
            "enforceable": self.enforceable,
            "excluded": self.excluded,
            "exclusion_reason": self.exclusion_reason,
            "authenticated_at": self.authenticated_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "blockers": self.blockers,
            "would_ban": self.would_ban,
            "banned_until": self.banned_until,
            "likely_false_positive": self.likely_false_positive,
        });
        if with_contributions {
            v["contributions"] = json!(self
                .contributions
                .iter()
                .map(|c| json!({
                    "ts": c.ts, "event_type": c.event_type, "category": c.category,
                    "points": round2(c.points), "reason": c.reason, "site": c.site, "detail": c.detail,
                }))
                .collect::<Vec<_>>());
        }
        v
    }
}

struct SiteNames {
    names: HashSet<String>,
    checked: Option<Instant>,
}

impl SiteNames {
    fn get(&mut self) -> &HashSet<String> {
        let due = match self.checked {
            None => true,
            Some(t) => t.elapsed().as_secs_f64() >= SITE_NAMES_RECHECK,
        };
        if due {
            self.checked = Some(Instant::now());
            self.names = read_site_names("");
        }
        &self.names
    }
}

#[derive(Debug, Clone)]
pub struct PendingAlert {
    pub rule: String,
    pub subject: String,
    pub active: Option<bool>,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
struct PreparedBan {
    ip: String,
    now: i64,
    duration: i64,
    code: i64,
    score: i64,
    after_page: bool,
    categories: String,
    decision: i64,
}

pub struct Engine {
    pub config: GuardConfig,
    pub db: Arc<SecurityDatabase>,
    pub sigs: Arc<RwLock<Arc<SignatureEngine>>>,
    pub requests: Arc<RwLock<Option<Arc<RequestLog>>>>,
    pub alerts: Option<Arc<AlertClient>>,
    pending_alerts: Vec<PendingAlert>,
    pub sink: Sink,
    pub enforcer: Enforcer,
    failing_reported: bool,
    burst_bans: VecDeque<i64>,
    burst_reported: Option<i64>,
    pub ban_durations: Vec<i64>,
    pub ban_durations_changed_at: i64,
    pub shield: PathShield,
    pub first_step_page: bool,
    quality_cache: HashMap<i64, (i64, Value)>,
    pub shield_enabled: bool,
    pub detection: DetectionContext,
    pub login_correlations: LoginCorrelations,
    pub digests: MinuteDigests,
    pub trusted_rates: TrustedRates,
    pub hard_floor: HardFloorWatch,
    ban_policy_watch: BanPolicyWatch,
    pub legacy_bans: BTreeMap<String, i64>,
    pub legacy_lifted: u64,
    pub manual_restored: u64,
    pub memory: IpMemory,
    pub catch_all: CatchAllPages,
    pub candidates: PathCandidates,
    pub unknown_hosts: UnknownHosts,
    pub trap_hosts: BTreeSet<String>,
    site_names: SiteNames,
    pub cursor: LogCursor,
    pub live: Option<Arc<Mutex<LiveBuffer>>>,
    pub live_budget: Value,
    refill_resume: Option<(u64, u64, f64)>,
    pub unreadable_tables: BTreeSet<String>,
    cycle_bytes: usize,
    known_bans: BTreeSet<String>,
    legacy_observed: Vec<(String, i64)>,
    pub last_poll_ts: Option<i64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u64,
    pub polls_total: u64,
    pub lines_read: u64,
    pub lines_parsed: u64,
    pub excluded_observations: u64,
    enforcement_scan_after: (i64, String),
    enforcement_scan_before: i64,
    enforcement_checked: usize,
    pub fast_enforcements: u64,
    pub running: Arc<AtomicBool>,
    pub lag_bytes: Arc<AtomicU64>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Engine {
    pub fn new(
        config: GuardConfig,
        db: Arc<SecurityDatabase>,
        sigs: Arc<RwLock<Arc<SignatureEngine>>>,
        alerts: Option<Arc<AlertClient>>,
        requests: Arc<RwLock<Option<Arc<RequestLog>>>>,
    ) -> Self {
        let now = utc_now();
        let override_mode = db.get_state("mode_override", "");
        let mode = if SUPPORTED_MODES.contains(&override_mode.as_str()) {
            override_mode
        } else {
            config.mode.clone()
        };
        let mut enforcer = Enforcer::new(&config, None);
        enforcer.mode = mode;
        let ban_durations = load_ban_durations(&db);
        let ban_durations_changed_at = safe_int_str(&db.get_state(BAN_DURATIONS_CHANGED_KEY, "0"));
        let sig_snapshot = sigs.read().unwrap_or_else(|p| p.into_inner()).clone();
        let detection = DetectionContext::new(&db, &sig_snapshot, now);
        let login_correlations = LoginCorrelations::new(&config.authelia_log_file, &db, now);
        let mut unknown_hosts = UnknownHosts::default();
        if let Ok(v) = serde_json::from_str::<Value>(&db.get_state(UNKNOWN_HOSTS_KEY, "[]")) {
            unknown_hosts.restore(&v);
        }
        let trap_hosts: BTreeSet<String> = json_list_strings(&db.get_state(TRAP_HOSTS_KEY, "[]"))
            .into_iter()
            .collect();
        let mut candidates = PathCandidates::default();
        if let Ok(v) = serde_json::from_str::<Value>(&db.get_state(CANDIDATES_KEY, "[]")) {
            candidates.restore(&v);
        }
        let cursor_state: Value =
            serde_json::from_str(&db.get_state("log_cursor", "{}")).unwrap_or(json!({}));
        let cursor = cursor_from_state(&config.log_file, Some(&cursor_state));
        let live = if config.live_buffer_records > 0 {
            Some(Arc::new(Mutex::new(LiveBuffer::new(
                config.live_buffer_records,
                config.live_buffer_seconds,
            ))))
        } else {
            None
        };
        let known_bans: BTreeSet<String> =
            json_list_strings(&db.get_state(KNOWN_BANS_STATE_KEY, "[]"))
                .into_iter()
                .collect();
        let legacy_observed = load_legacy_observed(&db);
        let (scan_after, scan_before) = {
            let scan: Value = serde_json::from_str(&db.get_state(ENFORCEMENT_CURSOR_KEY, "{}"))
                .unwrap_or(json!({}));
            let after = scan.get("after").and_then(Value::as_array);
            let a0 = after
                .and_then(|a| a.first())
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let a1 = after
                .and_then(|a| a.get(1))
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            let before = scan.get("before").and_then(Value::as_i64).unwrap_or(0);
            ((a0, a1), before)
        };
        let sink = Sink {
            db: db.clone(),
            exclusions: ExclusionModel::from_config(&config),
            queue: EnforcementQueue::new(config.max_tracked_ips.min(ENFORCEMENT_QUEUE_LIMIT)),
            subnets: SubnetCorrelator::default_config(),
            promotions: Vec::new(),
            events_recorded: 0,
            policy: ScoringPolicy::default(),
            ban_policy: BAN_POLICY_LEGACY,
        };
        let mut engine = Self {
            shield: PathShield::new(&config.haproxy_socket),
            first_step_page: db.get_state(FIRST_STEP_PAGE_KEY, "1") != "0",
            shield_enabled: db.get_state(SHIELD_ENABLED_KEY, "1") != "0",
            memory: IpMemory::new(config.max_tracked_ips, config.max_paths_per_ip),
            config,
            db,
            sigs,
            requests,
            alerts,
            pending_alerts: Vec::new(),
            sink,
            enforcer,
            failing_reported: false,
            burst_bans: VecDeque::new(),
            burst_reported: None,
            ban_durations,
            ban_durations_changed_at,
            quality_cache: HashMap::new(),
            detection,
            login_correlations,
            digests: MinuteDigests::new(),
            trusted_rates: TrustedRates::default(),
            hard_floor: HardFloorWatch::default(),
            ban_policy_watch: BanPolicyWatch::default(),
            legacy_bans: BTreeMap::new(),
            legacy_lifted: 0,
            manual_restored: 0,
            catch_all: CatchAllPages::default(),
            candidates,
            unknown_hosts,
            trap_hosts,
            site_names: SiteNames {
                names: HashSet::new(),
                checked: None,
            },
            cursor,
            live,
            live_budget: json!({"budget_mib": 0, "revision": 0, "changed_at": 0}),
            refill_resume: None,
            unreadable_tables: BTreeSet::new(),
            cycle_bytes: 0,
            known_bans,
            legacy_observed,
            last_poll_ts: None,
            last_error: None,
            consecutive_failures: 0,
            polls_total: 0,
            lines_read: 0,
            lines_parsed: 0,
            excluded_observations: 0,
            enforcement_scan_after: scan_after,
            enforcement_scan_before: scan_before,
            enforcement_checked: 0,
            fast_enforcements: 0,
            running: Arc::new(AtomicBool::new(false)),
            lag_bytes: Arc::new(AtomicU64::new(0)),
        };
        engine.live_budget = engine.load_live_budget();
        engine.apply_live_budget_at_start();
        engine.recover_enforcement_checks();
        engine
    }

    fn sig(&self) -> Arc<SignatureEngine> {
        self.sigs.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn ban_policy(&self) -> &'static str {
        self.sink.ban_policy
    }

    pub fn scoring_policy(&self) -> ScoringPolicy {
        self.sink.scoring_policy()
    }

    // -- the live buffer after a restart ---------------------------------------

    pub fn refill_live(&mut self, now: f64) -> usize {
        let Some(live) = self.live.clone() else {
            return 0;
        };
        let Some((inode, size)) = stat_inode_size(&self.config.log_file) else {
            return 0;
        };
        let end = if self.cursor.inode == 0 {
            size
        } else if self.cursor.inode == inode {
            self.cursor.offset.min(size)
        } else {
            return 0;
        };
        let start = end.saturating_sub(LIVE_REFILL_BYTES);
        if end <= start {
            return 0;
        }
        let horizon = now - lock(&live).max_seconds as f64;
        let Ok((records, reached_back, boundary)) = self.read_back(start, end, horizon) else {
            return 0;
        };
        let n = records.len();
        if let Some(first) = records.first().map(|r| r.ts) {
            lock(&live).refill(records, if reached_back { horizon } else { first });
        }
        if !reached_back && boundary > 0 {
            self.refill_resume = Some((inode, boundary, horizon));
        }
        n
    }

    fn queue_alert(
        &mut self,
        rule: &str,
        subject: &str,
        active: Option<bool>,
        summary: String,
        detail: String,
    ) {
        if self.alerts.is_none() {
            return;
        }
        self.pending_alerts.push(PendingAlert {
            rule: rule.to_string(),
            subject: subject.to_string(),
            active,
            summary,
            detail,
        });
    }

    pub fn take_pending_alerts(&mut self) -> Vec<PendingAlert> {
        std::mem::take(&mut self.pending_alerts)
    }

    fn read_back_file(
        log_file: &str,
        sigs: &SignatureEngine,
        start: u64,
        end: u64,
        horizon: f64,
    ) -> std::io::Result<(Vec<LiveRecord>, bool, u64)> {
        let mut f = File::open(log_file)?;
        f.seek(SeekFrom::Start(start))?;
        let mut data = vec![0u8; (end - start) as usize];
        let n = f.read(&mut data)?;
        data.truncate(n);
        let mut boundary = start;
        let mut slice: &[u8] = &data;
        if start > 0 {
            let cut = memchr::memchr(b'\n', slice)
                .map(|p| p + 1)
                .unwrap_or(slice.len());
            slice = &slice[cut..];
            boundary = start + cut as u64;
        }
        let mut records = Vec::new();
        let mut reached_back = start == 0;
        for raw in slice.split(|&b| b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            let bounded = &raw[..raw.len().min(crate::signatures::MAX_LOG_LINE_BYTES)];
            let line = String::from_utf8_lossy(bounded);
            let Some(ts) = line_epoch(&line) else {
                continue;
            };
            if ts < horizon {
                reached_back = true;
                continue;
            }
            if let Some(req) = parse_access_line(&line, sigs) {
                records.push(LiveRecord::from_parsed(&req, ts));
            }
        }
        Ok((records, reached_back, boundary))
    }

    fn read_back(
        &self,
        start: u64,
        end: u64,
        horizon: f64,
    ) -> std::io::Result<(Vec<LiveRecord>, bool, u64)> {
        let sigs = self.sig();
        Self::read_back_file(&self.config.log_file, &sigs, start, end, horizon)
    }

    fn live_full(&self) -> bool {
        let Some(live) = &self.live else { return true };
        let b = lock(live);
        if b.max_bytes != 0 {
            b.bytes() as f64 >= b.max_bytes as f64 * LIVE_REFILL_FULL
        } else {
            b.len() as f64 >= b.max_records as f64 * LIVE_REFILL_FULL
        }
    }

    /// One piece of the background read-back; Some(wait) while more remains.
    pub fn continue_refill_step(&mut self) -> Option<Duration> {
        let (inode, boundary, horizon) = self.refill_resume.take()?;
        let live = self.live.clone()?;
        if boundary == 0 || self.live_full() {
            return None;
        }
        if stat_inode_size(&self.config.log_file).map(|(i, _)| i) != Some(inode) {
            return None;
        }
        let started = Instant::now();
        let start = boundary.saturating_sub(LIVE_REFILL_CHUNK_BYTES);
        let Ok((records, reached_back, first)) = self.read_back(start, boundary, horizon) else {
            return None;
        };
        if let Some(first_ts) = records.first().map(|r| r.ts) {
            lock(&live).refill(records, if reached_back { horizon } else { first_ts });
        }
        if reached_back {
            return None;
        }
        let next = if first < boundary { first } else { start };
        self.refill_resume = Some((inode, next, horizon));
        Some(started.elapsed().max(Duration::from_millis(50)))
    }

    // -- the live buffer's memory -------------------------------------------------

    fn load_live_budget(&self) -> Value {
        let stored: Value = serde_json::from_str(&self.db.get_state(LIVE_BUDGET_STATE_KEY, ""))
            .unwrap_or(json!({}));
        let mut budget = clamp_int(stored.get("budget_mib"), 0, 0, LIVE_BUDGET_MAX_MIB);
        let revision = clamp_int(stored.get("revision"), 0, 0, 1 << 31);
        let changed_at = clamp_int(stored.get("changed_at"), 0, 0, 1 << 33);
        if 0 < budget && budget < LIVE_BUDGET_MIN_MIB {
            budget = LIVE_BUDGET_MIN_MIB;
        }
        json!({"budget_mib": budget, "revision": revision, "changed_at": changed_at})
    }

    fn apply_live_budget_at_start(&mut self) {
        let wanted = self.live_budget["budget_mib"].as_i64().unwrap_or(0);
        let Some(live) = &self.live else { return };
        if wanted == 0 {
            return;
        }
        let (ceiling, _) = live_budget_ceiling(0, false);
        let applied = LIVE_BUDGET_MIN_MIB.max(wanted.min(ceiling));
        if applied < wanted {
            log_warn(&format!(
                "Live buffer: {wanted} MiB chosen, {applied} MiB fit the service's memory limit"
            ));
        }
        lock(live).set_budget(applied * MIB);
    }

    pub fn live_memory(&self) -> EResult<Value> {
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| EngineError::Lookup("the live buffer is off".into()))?;
        let b = lock(live);
        let status = b.status();
        let (ceiling, reason) = live_budget_ceiling(b.bytes(), true);
        Ok(json!({
            "budget_mib": self.live_budget["budget_mib"],
            "applied_mib": b.max_bytes / MIB,
            "revision": self.live_budget["revision"],
            "changed_at": self.live_budget["changed_at"],
            "default": {"records": b.default_records, "seconds": b.default_seconds},
            "limits": {
                "min_mib": LIVE_BUDGET_MIN_MIB,
                "max_mib": ceiling,
                "cap_mib": LIVE_BUDGET_MAX_MIB,
                "step_mib": LIVE_BUDGET_STEP_MIB,
                "limited_by": reason,
                "max_seconds": LIVE_BUDGET_MAX_SECONDS,
                "refill_bytes": LIVE_REFILL_BYTES,
            },
            "buffer": status,
            "process": {
                "rss_bytes": process_rss_bytes(),
                "service_limit_bytes": service_memory_limit(),
                "host_available_bytes": host_memory_available(),
            },
        }))
    }

    pub fn set_live_memory(
        &mut self,
        budget_mib: Option<&Value>,
        revision: Option<&Value>,
    ) -> EResult<Value> {
        let live = self
            .live
            .clone()
            .ok_or_else(|| EngineError::Lookup("the live buffer is off".into()))?;
        let wanted = match budget_mib {
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(-1),
            Some(Value::String(s)) => s.trim().parse::<i64>().map_err(|_| {
                EngineError::Value("budget_mib and revision must be whole numbers".into())
            })?,
            _ => {
                return Err(EngineError::Value(
                    "budget_mib must be a whole number of MiB".into(),
                ))
            }
        };
        let seen = match revision {
            Some(Value::Number(n)) => n.as_i64().ok_or_else(|| {
                EngineError::Value("budget_mib and revision must be whole numbers".into())
            })?,
            Some(Value::String(s)) => s.trim().parse::<i64>().map_err(|_| {
                EngineError::Value("budget_mib and revision must be whole numbers".into())
            })?,
            _ => {
                return Err(EngineError::Value(
                    "budget_mib and revision must be whole numbers".into(),
                ))
            }
        };
        if wanted != 0 && !(LIVE_BUDGET_MIN_MIB..=LIVE_BUDGET_MAX_MIB).contains(&wanted) {
            return Err(EngineError::Value(format!(
                "budget_mib must be 0 or from {LIVE_BUDGET_MIN_MIB} to {LIVE_BUDGET_MAX_MIB}"
            )));
        }
        if seen != self.live_budget["revision"].as_i64().unwrap_or(0) {
            return Err(EngineError::Conflict(
                "changed by someone else in the meantime".into(),
            ));
        }
        let dropped = {
            let mut b = lock(&live);
            if wanted != 0 {
                let (ceiling, reason) = live_budget_ceiling(b.bytes(), true);
                if wanted > ceiling && wanted > b.max_bytes / MIB {
                    return Err(EngineError::Value(format!(
                        "at most {ceiling} MiB can be given now ({reason})"
                    )));
                }
            }
            let state =
                json!({"budget_mib": wanted, "revision": seen + 1, "changed_at": utc_now()});
            self.db
                .set_state(LIVE_BUDGET_STATE_KEY, &crate::secdb::python_json(&state))?;
            self.live_budget = state;
            b.set_budget(wanted * MIB)
        };
        log_warn(&format!(
            "Live buffer: {} from the web interface; {dropped} older requests dropped",
            if wanted != 0 {
                format!("{wanted} MiB")
            } else {
                "back to its configured profile".into()
            }
        ));
        let mut out = self.live_memory()?;
        out["dropped"] = json!(dropped);
        Ok(out)
    }

    // -- collection -----------------------------------------------------------------

    fn read_tables(socket: &str, stop: &AtomicBool) -> Result<(Tables, BTreeSet<String>), String> {
        let available = list_tables(socket).map_err(|e| e.to_string())?;
        let wanted: Vec<String> = available
            .into_iter()
            .filter(|n| {
                ["tbl_ban", "tbl_ip_auth", "tbl_err_other", "tbl_nosni_tcp"].contains(&n.as_str())
                    || n.starts_with("tbl_err_")
                    || n.starts_with("tbl_rate_")
            })
            .collect();
        let mut result: Tables = HashMap::new();
        let mut unreadable = BTreeSet::new();
        for name in wanted {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match read_table(socket, &name, "") {
                Ok(rows) => {
                    result.insert(name, rows);
                }
                Err(e @ (RuntimeError::TableUnreadable(_) | RuntimeError::AnswerTooLarge(_))) => {
                    log_warn(&format!("{e}; left out of this cycle"));
                    unreadable.insert(name);
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok((result, unreadable))
    }

    fn save_legacy_observed(&mut self) -> Result<(), String> {
        while self.legacy_observed.len() > KNOWN_BANS_MAX {
            self.legacy_observed.remove(0);
        }
        let mut m = Map::new();
        for (ip, code) in &self.legacy_observed {
            m.insert(ip.clone(), json!(code));
        }
        self.db.set_state(
            LEGACY_OBSERVED_STATE_KEY,
            &crate::secdb::python_json(&Value::Object(m)),
        )
    }

    fn observe_legacy_bans(
        &mut self,
        bans: &HashMap<String, HashMap<String, String>>,
        newly: &BTreeSet<String>,
        tables: &Tables,
        now: i64,
    ) -> Result<usize, String> {
        let mut written = 0;
        let mut changed = false;
        let mut thresholds: Option<HashMap<String, i64>> = None;
        for ip in newly {
            let empty = HashMap::new();
            let fields = bans.get(ip).unwrap_or(&empty);
            let code = field_int(fields, "gpt0");
            if !crate::watchers::is_legacy_code(code) {
                continue;
            }
            let th = thresholds.get_or_insert_with(|| read_thresholds(""));
            let remaining = (field_int(fields, "exp") / 1000).max(0);
            self.db.record_decision(
                ip,
                now,
                "observed",
                "haproxy",
                "observed",
                Decision {
                    code,
                    until: now + remaining,
                    policy: self.sink.ban_policy,
                    reason: Some(json!({
                        "first_seen": now,
                        "decided_at": null,
                        "readings": legacy_ban_readings(ip, tables, th),
                    })),
                    ..Default::default()
                },
            )?;
            match self.legacy_observed.iter_mut().find(|(i, _)| i == ip) {
                Some(e) => e.1 = code,
                None => self.legacy_observed.push((ip.clone(), code)),
            }
            written += 1;
            changed = true;
        }
        let observed = self.legacy_observed.clone();
        for (ip, code) in observed {
            let empty = HashMap::new();
            let fields = bans.get(&ip).unwrap_or(&empty);
            if field_int(fields, "gpc0") > 0 && field_int(fields, "gpt0") == code {
                continue;
            }
            self.legacy_observed.retain(|(i, _)| *i != ip);
            self.db.record_decision(
                &ip,
                now,
                "ended",
                "haproxy",
                "observed",
                Decision {
                    code,
                    policy: self.sink.ban_policy,
                    ..Default::default()
                },
            )?;
            written += 1;
            changed = true;
        }
        if changed {
            self.save_legacy_observed()?;
        }
        Ok(written)
    }

    fn settle_legacy_observed(&mut self, ip: &str) -> i64 {
        let code = self
            .legacy_observed
            .iter()
            .find(|(i, _)| i == ip)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        if code != 0 {
            self.legacy_observed.retain(|(i, _)| i != ip);
            let _ = self.save_legacy_observed();
        }
        code
    }

    pub fn ingest_tables(&mut self, tables: &Tables, now: i64) -> Result<usize, String> {
        if !self.unreadable_tables.contains("tbl_ip_auth") {
            let empty = HashMap::new();
            let auth_rows = tables.get("tbl_ip_auth").unwrap_or(&empty);
            self.sink.exclusions.refresh_authenticated(auth_rows);
            let mut authenticated: Vec<String> = auth_rows
                .iter()
                .filter(|(_, f)| field_int(f, "gpc0") > 0)
                .map(|(ip, _)| ip.clone())
                .collect();
            authenticated.sort();
            if !authenticated.is_empty() {
                self.db.record_authenticated(&authenticated, now)?;
            }
        }
        if self.unreadable_tables.contains("tbl_ban") {
            return self.ingest_rate_tables(tables, now);
        }
        let empty = HashMap::new();
        let bans = tables.get("tbl_ban").unwrap_or(&empty);
        let active: BTreeSet<String> = bans
            .iter()
            .filter(|(_, f)| field_int(f, "gpc0") > 0)
            .map(|(ip, _)| ip.clone())
            .collect();
        let newly: BTreeSet<String> = active.difference(&self.known_bans).cloned().collect();
        if let Err(e) = self.observe_legacy_bans(bans, &newly, tables, now) {
            log_warn(&format!(
                "Could not write HAProxy's own bans into the decision history: {e}"
            ));
        }
        let mut events = Vec::new();
        for ip in &newly {
            let code = field_int(&bans[ip], "gpt0");
            if code == ADAPTIVE_BAN_CODE || code == ADAPTIVE_PAGE_CODE || code == MANUAL_BAN_CODE {
                continue;
            }
            events.push(NewEvent {
                ts: now,
                ip: ip.clone(),
                event_type: EVENT_LEGACY_BAN.into(),
                source: "stick-table".into(),
                category: "ban".into(),
                site: String::new(),
                detail: format!("code={code}"),
                handled: false,
            });
            let verdict = self.sink.exclusions.verdict(ip);
            self.db.observe_ip(ip, now, &verdict)?;
        }
        if active != self.known_bans {
            let list: Vec<&String> = active.iter().take(KNOWN_BANS_MAX).collect();
            self.db.set_state(
                KNOWN_BANS_STATE_KEY,
                &crate::secdb::python_json(&json!(list)),
            )?;
        }
        self.known_bans = active.clone();
        let written = self.db.record_events(&events)?;
        self.sink.events_recorded += written as u64;
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for ip in &active {
            let code = field_int(&bans[ip], "gpt0");
            if crate::watchers::is_legacy_code(code) {
                *counts.entry(code.to_string()).or_insert(0) += 1;
            }
        }
        self.legacy_bans = counts.clone();
        if !counts.is_empty() && self.sink.ban_policy == BAN_POLICY_U02 && self.switch_recorded() {
            self.reconcile_legacy_bans(bans, now)?;
        }
        if let Err(e) = self.keep_manual_bans(bans, now) {
            log_warn(&format!(
                "Could not check the manual bans against HAProxy: {e}"
            ));
        }
        Ok(written + self.ingest_rate_tables(tables, now)?)
    }

    pub fn keep_manual_bans(
        &mut self,
        bans: &HashMap<String, HashMap<String, String>>,
        now: i64,
    ) -> Result<u64, String> {
        let known = self.db.manual_bans()?;
        let mut ips: Vec<&String> = bans.keys().collect();
        ips.sort();
        for ip in ips {
            let fields = &bans[ip];
            if field_int(fields, "gpc0") > 0 && field_int(fields, "gpt0") == MANUAL_BAN_CODE {
                let remaining = (field_int(fields, "exp") / 1000).max(0);
                self.db.note_manual_ban(ip, now, now + remaining)?;
                if !known.contains_key(ip) {
                    self.db.record_decision(
                        ip,
                        now,
                        "applied",
                        "operator",
                        "applied",
                        Decision {
                            code: MANUAL_BAN_CODE,
                            until: now + remaining,
                            policy: self.sink.ban_policy,
                            ..Default::default()
                        },
                    )?;
                }
            }
        }
        let records = self.db.manual_bans()?;
        let mut started: Option<i64> = None;
        let mut restored = 0;
        for (ip, record) in records {
            let empty = HashMap::new();
            let entry = bans.get(&ip).unwrap_or(&empty);
            let held = field_int(entry, "gpc0") > 0;
            let code = field_int(entry, "gpt0");
            if record.expires_at <= now {
                if record.reasserted != 0 && held && code == MANUAL_BAN_CODE {
                    self.enforcer
                        .lift_code(&ip, MANUAL_BAN_CODE)
                        .map_err(|e| e.to_string())?;
                }
                self.db.forget_manual_ban(&ip)?;
                continue;
            }
            if held || record.seen_at >= now {
                continue;
            }
            let s = *started.get_or_insert_with(|| self.enforcer.started_at());
            if s == 0 {
                continue;
            }
            if s > record.seen_at {
                if self
                    .enforcer
                    .restore(&ip, MANUAL_BAN_CODE)
                    .map_err(|e| e.to_string())?
                {
                    self.db.mark_manual_reasserted(&ip)?;
                    restored += 1;
                    log_warn(&format!(
                        "Restored the manual ban on {ip}, lost when HAProxy restarted"
                    ));
                    self.db.record_decision(
                        &ip,
                        now,
                        "restored",
                        "restart",
                        "applied",
                        Decision {
                            code: MANUAL_BAN_CODE,
                            until: record.expires_at,
                            policy: self.sink.ban_policy,
                            ..Default::default()
                        },
                    )?;
                }
            } else {
                self.db.forget_manual_ban(&ip)?;
            }
        }
        self.manual_restored += restored;
        Ok(restored)
    }

    // -- the ban policy (U02) --------------------------------------------------------

    pub fn detection_state(&self) -> Value {
        let policy = self.scoring_policy();
        let mut v = self.detection.summary(&self.sig());
        v["login_source"] = self.login_correlations.health();
        v["active_mode"] = json!(self.enforcer.mode);
        v["scoring"] = json!({
            "window_hours": policy.window_seconds as f64 / 3600.0,
            "decay_hours": policy.decay_seconds as f64 / 3600.0,
            "ban_score": WOULD_BAN_SCORE,
        });
        v
    }

    pub fn ban_policy_state(&self) -> Value {
        match serde_json::from_str::<Value>(&self.db.get_state(BAN_POLICY_STATE_KEY, "")) {
            Ok(v @ Value::Object(_)) => v,
            _ => json!({}),
        }
    }

    pub fn refresh_ban_policy(&mut self, now: i64) -> Result<&'static str, String> {
        let policy = self.ban_policy_watch.current();
        self.sink.ban_policy = policy;
        self.sink.exclusions.geo_trusted = policy != BAN_POLICY_U02;
        let state = self.ban_policy_state();
        let previous = state
            .get("policy")
            .and_then(Value::as_str)
            .unwrap_or(BAN_POLICY_LEGACY)
            .to_string();
        if previous == policy {
            return Ok(policy);
        }
        let mut record = json!({"policy": policy, "since": now, "previous": previous});
        if policy == BAN_POLICY_U02 {
            match self.snapshot_bans(now) {
                Ok(path) => record["snapshot"] = json!(path),
                Err(e) => {
                    log_warn(&format!(
                        "Ban policy {policy} seen, but the ban table snapshot failed: {e}"
                    ));
                    return Ok(policy);
                }
            }
        }
        self.db
            .set_state(BAN_POLICY_STATE_KEY, &crate::secdb::python_json(&record))?;
        log_warn(&format!("Ban policy is now {policy} (was {previous})"));
        Ok(policy)
    }

    pub fn switch_recorded(&self) -> bool {
        self.ban_policy_state()
            .get("policy")
            .and_then(Value::as_str)
            == Some(BAN_POLICY_U02)
    }

    fn snapshot_bans(&self, now: i64) -> Result<String, String> {
        let rows =
            read_table(&self.config.haproxy_socket, "tbl_ban", "").map_err(|e| e.to_string())?;
        let dir = self
            .db
            .path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        let target = dir.join(format!("ban-policy-u02-{now}.json"));
        let temporary = target.with_extension("tmp");
        let mut entries = Map::new();
        let mut keys: Vec<&String> = rows.keys().collect();
        keys.sort();
        for k in keys {
            let mut f = Map::new();
            let mut names: Vec<&String> = rows[k].keys().collect();
            names.sort();
            for n in names {
                f.insert(n.clone(), json!(rows[k][n]));
            }
            entries.insert(k.clone(), Value::Object(f));
        }
        let payload = json!({"entries": entries, "ts": now});
        std::fs::write(&temporary, crate::secdb::python_json(&payload))
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
        if let Ok(read) = std::fs::read_dir(&dir) {
            let mut old: Vec<std::path::PathBuf> = read
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("ban-policy-u02-") && n.ends_with(".json"))
                })
                .collect();
            old.sort();
            if old.len() > BAN_SNAPSHOTS_KEPT {
                for p in &old[..old.len() - BAN_SNAPSHOTS_KEPT] {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        Ok(target.display().to_string())
    }

    fn reconcile_legacy_bans(
        &mut self,
        bans: &HashMap<String, HashMap<String, String>>,
        now: i64,
    ) -> Result<usize, String> {
        let mut legacy: Vec<&String> = bans
            .iter()
            .filter(|(_, f)| {
                field_int(f, "gpc0") > 0 && crate::watchers::is_legacy_code(field_int(f, "gpt0"))
            })
            .map(|(ip, _)| ip)
            .collect();
        legacy.sort();
        let mut lifted = 0;
        for ip in legacy.into_iter().take(LEGACY_LIFTS_PER_CYCLE) {
            let code = match self.enforcer.lift_legacy(ip) {
                Ok(c) => c,
                Err(e) => {
                    log_warn(&format!("Could not lift the legacy ban on {ip}: {e}"));
                    break;
                }
            };
            if code == 0 {
                continue;
            }
            lifted += 1;
            let key = code.to_string();
            let left = self.legacy_bans.get(&key).copied().unwrap_or(0) - 1;
            if left > 0 {
                self.legacy_bans.insert(key, left);
            } else {
                self.legacy_bans.remove(&key);
            }
            self.sink.emit(
                ip,
                EVENT_LEGACY_BAN_LIFTED,
                now,
                "guardd",
                "",
                "",
                &format!("code={code} policy={BAN_POLICY_U02}"),
                false,
                Some(format!("{ip}|{EVENT_LEGACY_BAN_LIFTED}|{now}")),
            )?;
            self.db.record_decision(
                ip,
                now,
                "lifted",
                "policy",
                "applied",
                Decision {
                    code,
                    policy: BAN_POLICY_U02,
                    ..Default::default()
                },
            )?;
            self.settle_legacy_observed(ip);
        }
        if lifted > 0 {
            self.legacy_lifted += lifted as u64;
            log_warn(&format!(
                "Lifted {lifted} bans HAProxy wrote under the old rules"
            ));
        }
        self.apply_promotions();
        Ok(lifted)
    }

    pub fn ingest_hard_floor(&mut self, now: i64) -> Result<usize, String> {
        let queries = self.hard_floor.queries();
        if queries.is_empty() {
            return Ok(0);
        }
        let mut over: BTreeMap<(String, String, String), (i64, i64)> = BTreeMap::new();
        for (table, counter, limit) in queries {
            let payload = match runtime_command(
                &self.config.haproxy_socket,
                &format!("show table {table} data.{counter} gt {limit}"),
            ) {
                Ok(p) => p,
                Err(_) => continue,
            };
            for (ip, fields) in parse_table(&payload) {
                let value = first_counter(&fields, &counter);
                if value > limit {
                    over.insert((ip, table.clone(), counter.clone()), (value, limit));
                }
            }
        }
        let mut written = 0;
        for ((ip, table, counter), (value, limit)) in self.hard_floor.update(&over) {
            let verdict = self.sink.exclusions.verdict(&ip);
            let event_type = if verdict.excluded {
                EVENT_HARD_FLOOR_TRUSTED
            } else {
                EVENT_HARD_FLOOR
            };
            let mut detail = format!("{counter}={value} limit={limit} table={table}");
            if verdict.excluded {
                let src = if verdict.source.is_empty() {
                    verdict.reason.clone()
                } else {
                    verdict.source.clone()
                };
                detail.push_str(&format!(" trusted={src}"));
            }
            if self.sink.emit(
                &ip,
                event_type,
                now,
                "stick-table",
                "flood",
                "",
                &detail,
                false,
                None,
            )? {
                written += 1;
            }
        }
        self.apply_promotions();
        Ok(written)
    }

    pub fn ingest_rate_tables(&mut self, tables: &Tables, now: i64) -> Result<usize, String> {
        let mut written = 0;
        let thresholds = read_thresholds("");
        let mut names: Vec<&String> = tables.keys().collect();
        names.sort();
        for name in names {
            let (event_type, prefix) = if name.starts_with("tbl_rate_") {
                (EVENT_RATE_EXCEEDED, "http_req_rate")
            } else if name.starts_with("tbl_err_") {
                (EVENT_ERROR_RATE_EXCEEDED, "http_err_rate")
            } else if name == "tbl_nosni_tcp" {
                (EVENT_NOSNI_PROBING, "conn_rate")
            } else {
                continue;
            };
            let site = if name.matches('_').count() >= 2 {
                name.splitn(3, '_').last().unwrap_or("").to_string()
            } else {
                String::new()
            };
            let Some(&limit) = thresholds.get(name) else {
                continue;
            };
            let mut ips: Vec<&String> = tables[name].keys().collect();
            ips.sort();
            for ip in ips {
                let value = first_counter(&tables[name][ip], prefix);
                if value <= limit || self.sink.exclusions.verdict(ip).excluded {
                    continue;
                }
                if self.sink.emit(
                    ip,
                    event_type,
                    now,
                    "stick-table",
                    "",
                    &site,
                    &format!("{prefix}={value} limit={limit}"),
                    false,
                    Some(format!("{ip}|{event_type}|{name}")),
                )? {
                    written += 1;
                }
            }
        }
        self.apply_promotions();
        Ok(written)
    }

    fn flush_rate_warnings(&mut self, now: i64, idle: bool) -> usize {
        self.trusted_rates.tick(now, idle);
        let finished = self.trusted_rates.take_finished();
        match self.db.record_rate_warnings(&finished) {
            Ok(n) => n,
            Err(e) => {
                self.trusted_rates.dropped += finished.len() as u64;
                log_warn(&format!(
                    "Could not record {} rate warnings: {e}",
                    finished.len()
                ));
                0
            }
        }
    }

    pub fn ingest_log(&mut self, now: i64, max_bytes: Option<usize>) -> Result<usize, String> {
        let before = self.cursor.offset;
        let lines = self
            .cursor
            .read(max_bytes.unwrap_or(self.config.log_read_bytes_per_cycle));
        self.lag_bytes
            .store(self.cursor.lag_bytes, Ordering::Relaxed);
        self.cycle_bytes += self.cursor.offset.saturating_sub(before) as usize;
        self.ingest_log_lines(&lines, now)
    }

    fn ingest_log_lines(&mut self, lines: &[String], now: i64) -> Result<usize, String> {
        if lines.is_empty() {
            return Ok(0);
        }
        self.lines_read += lines.len() as u64;
        let sigs = self.sig();
        let requests = self
            .requests
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut parsed = 0u64;
        let mut live_batch = Vec::new();
        for line in lines {
            let Some(request) = parse_access_line(line, &sigs) else {
                continue;
            };
            parsed += 1;
            let ts = line_epoch(line);
            let ended = ts.unwrap_or(now as f64);
            self.digests.add(&request, ended, now);
            if self.live.is_some() {
                live_batch.push(LiveRecord::from_parsed(&request, ended));
            }
            if let Some(store) = &requests {
                store.add(&request, ts);
            }
            self.observe_request(&request, now, ts, &sigs)?;
        }
        self.lines_parsed += parsed;
        if let Some(live) = &self.live {
            lock(live).extend(live_batch);
        }
        if let Some(store) = &requests {
            store.flush(now);
        }
        Ok(lines.len())
    }

    fn apply_promotions(&mut self) {
        for ip in std::mem::take(&mut self.sink.promotions) {
            self.memory.promote(&ip);
        }
    }

    /// Fold one request into the address's memory and emit any findings.
    pub fn observe_request(
        &mut self,
        request: &ParsedRequest,
        now: i64,
        stamp: Option<f64>,
        sigs: &SignatureEngine,
    ) -> Result<(), String> {
        let ip = request.client_ip.clone();
        let verdict = self.sink.exclusions.verdict(&ip);
        let trust = if verdict.reason == "authenticated" {
            "signed-in".to_string()
        } else if verdict.reason == "whitelisted" {
            if verdict.source.is_empty() {
                "whitelist".to_string()
            } else {
                verdict.source.clone()
            }
        } else {
            String::new()
        };
        self.trusted_rates.observe(request, &trust, now, stamp);
        let catch_known = self.catch_all.known(&request.host, request.bytes_out);
        let matches =
            self.detection
                .inspect(request, now, verdict.excluded, true, catch_known, sigs);
        let actions: HashMap<String, String> = matches
            .iter()
            .map(|m| (m.id.clone(), m.action.clone()))
            .collect();
        if verdict.excluded {
            self.excluded_observations += 1;
            return Ok(());
        }
        let result = self.observe_unexcluded(request, now, stamp, sigs, &matches, &actions);
        self.apply_promotions();
        result
    }

    fn permitted(
        &self,
        actions: &HashMap<String, String>,
        rule: &str,
        request: &ParsedRequest,
        now: i64,
    ) -> bool {
        match actions.get(rule) {
            Some(a) => a == "enforce",
            None => self.detection.action(rule, request, now, "enforce").0 == "enforce",
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_unexcluded(
        &mut self,
        request: &ParsedRequest,
        now: i64,
        stamp: Option<f64>,
        sigs: &SignatureEngine,
        matches: &[crate::context::DetectionMatch],
        actions: &HashMap<String, String>,
    ) -> Result<(), String> {
        let ip = request.client_ip.as_str();
        let permit_query = !request.query_flag.is_empty()
            && self.permitted(
                actions,
                &format!("query:{}", request.query_flag),
                request,
                now,
            );
        let permit_path_flag = !request.path_flag.is_empty()
            && self.permitted(actions, "raw:path-traversal", request, now);
        let (agent, agent_category) = sigs.classify_user_agent(&request.user_agent);
        let permit_agent =
            !agent.is_empty() && self.permitted(actions, &format!("ua:{agent}"), request, now);
        let max_paths = self.config.max_paths_per_ip;
        let Self {
            memory,
            sink,
            detection,
            catch_all,
            candidates,
            unknown_hosts,
            site_names,
            trap_hosts,
            db,
            ..
        } = self;
        let activity = memory.touch(ip, now);
        activity.requests += 1;
        check_unknown_host(
            sink,
            unknown_hosts,
            trap_hosts,
            site_names.get(),
            ip,
            activity,
            now,
            request,
        )?;
        if request.bad_request {
            activity.bad_requests += 1;
            note_invalid_host(sink, ip, activity, now, request, max_paths)?;
            return Ok(());
        }
        if !request.backend.ends_with("/<NOSRV>") {
            activity.reached_backend = true;
        }
        let handled = request.denied_by_gateway() && !activity.reached_backend;
        let observed_at = match stamp {
            Some(s) => (now as f64).min(s) as i64,
            None => now,
        };
        let slow_action = if observed_at >= now - 6 * 3600 {
            detection.observe_slow(request, observed_at, handled)
        } else {
            String::new()
        };
        if slow_action == "enforce" {
            sink.emit(
                ip,
                EVENT_SCANNER_PATH,
                now,
                "haproxy-log",
                "slow-enumeration",
                &request.host,
                &request.path,
                false,
                Some(format!("{ip}|behavior:slow-enumeration|{}", request.host)),
            )?;
        }
        let mut emitted_context: HashSet<(String, String)> = HashSet::new();
        for m in matches {
            if (m.id.starts_with("custom:") || m.id.starts_with("observe:"))
                && m.action == "enforce"
            {
                let finding = (m.event_type.clone(), m.category.clone());
                if emitted_context.contains(&finding) {
                    continue;
                }
                emitted_context.insert(finding);
                activity.scanner_hits += 1;
                activity.scanner_hits_denied += u64::from(handled);
                let detail: String = format!("{} {}", m.id, request.path)
                    .chars()
                    .take(300)
                    .collect();
                sink.emit(
                    ip,
                    &m.event_type,
                    now,
                    "haproxy-log",
                    &m.category,
                    &request.host,
                    &detail,
                    handled,
                    Some(format!(
                        "{ip}|{}|{}|{}",
                        m.event_type,
                        m.category,
                        i64::from(handled)
                    )),
                )?;
                activity.note_category(&m.category, now, 16);
                check_multi_category(sink, ip, activity, now)?;
                if m.id.starts_with("custom:") {
                    check_low_and_slow(sink, ip, activity, now)?;
                    check_recurring(sink, db, ip, activity, now)?;
                }
            }
        }
        if request.status == 404 {
            activity.not_found += 1;
        } else if request.denied_by_gateway() {
            activity.gateway_denied += 1;
        } else if request.status >= 400 {
            activity.errors += 1;
        }
        if !request.path.is_empty() {
            activity.note_path(&request.path, now, max_paths);
        }
        if !request.host.is_empty() && activity.hosts.len() < 16 {
            activity.hosts.insert(request.host.clone());
        }
        if permit_query {
            activity.scanner_hits += 1;
            if handled {
                activity.scanner_hits_denied += 1;
            }
            activity.note_category(&request.query_flag, now, 16);
            sink.emit(
                ip,
                EVENT_QUERY_INJECTION,
                now,
                "haproxy-log",
                &request.query_flag,
                &request.host,
                &request.path,
                handled,
                Some(format!(
                    "{ip}|{EVENT_QUERY_INJECTION}|{}",
                    request.query_flag
                )),
            )?;
            check_multi_category(sink, ip, activity, now)?;
        }
        if permit_path_flag {
            activity.scanner_hits += 1;
            activity.scanner_hits_denied += u64::from(handled);
            activity.note_category(&request.path_flag, now, 16);
            sink.emit(
                ip,
                EVENT_SCANNER_DECISIVE,
                now,
                "haproxy-log",
                &request.path_flag,
                &request.host,
                &request.path,
                handled,
                Some(format!(
                    "{ip}|path|{}|{}",
                    request.path_flag,
                    i64::from(handled)
                )),
            )?;
        }
        if permit_agent {
            activity.scanner_hits += 1;
            if handled {
                activity.scanner_hits_denied += 1;
            }
            activity.note_category(agent_category, now, 16);
            let event = if sigs.category_is_decisive(agent_category) {
                EVENT_SCANNER_DECISIVE
            } else {
                EVENT_SCANNER_PATH
            };
            sink.emit(
                ip,
                event,
                now,
                "haproxy-log",
                agent_category,
                &request.host,
                &format!("user agent {agent}"),
                handled,
                Some(format!("{ip}|ua|{agent}|{}", i64::from(handled))),
            )?;
            check_multi_category(sink, ip, activity, now)?;
        }
        let mut category = sigs.classify_path(&request.path).to_string();
        if category.is_empty()
            && !request.path.is_empty()
            && request.path != "/"
            && !is_asset(&request.path)
        {
            let served =
                is_served(request.status) && !catch_all.known(&request.host, request.bytes_out);
            let good = activity.requests as i64
                - activity.errors as i64
                - activity.not_found as i64
                - activity.gateway_denied as i64
                - activity.bad_requests as i64;
            let looks_like_client = activity.requests >= 20 && good * 2 >= activity.requests as i64;
            candidates.note(
                &request.path,
                ip,
                &request.host,
                request.status,
                served,
                looks_like_client,
                now,
            );
        }
        if !category.is_empty()
            && is_served(request.status)
            && !sigs.category_is_decisive(&category)
            && !catch_all.is_catch_all(&request.host, request.bytes_out, &request.path)
        {
            category.clear();
        }
        let permit_path = !category.is_empty() && {
            let rule = format!("path:{category}");
            match actions.get(&rule) {
                Some(a) => a == "enforce",
                None => detection.action(&rule, request, now, "enforce").0 == "enforce",
            }
        };
        if permit_path {
            activity.scanner_hits += 1;
            if handled {
                activity.scanner_hits_denied += 1;
            }
            activity.note_category(&category, now, 16);
            let event = if sigs.category_is_decisive(&category) {
                EVENT_SCANNER_DECISIVE
            } else {
                EVENT_SCANNER_PATH
            };
            sink.emit(
                ip,
                event,
                now,
                "haproxy-log",
                &category,
                &request.host,
                &request.path,
                handled,
                Some(format!("{ip}|{event}|{category}|{}", i64::from(handled))),
            )?;
            check_multi_category(sink, ip, activity, now)?;
            check_low_and_slow(sink, ip, activity, now)?;
            check_recurring(sink, db, ip, activity, now)?;
        } else if category.is_empty()
            && ENUMERATION_STATUSES.contains(&request.status)
            && !is_asset(&request.path)
        {
            if request.status == 404 && activity.note_missing(&request.path, now, max_paths) {
                let distinct = activity.distinct_missing(now - NOT_FOUND_WINDOW);
                if distinct >= NOT_FOUND_MIN_DISTINCT {
                    sink.emit(
                        ip,
                        EVENT_NOT_FOUND_ENUM,
                        now,
                        "haproxy-log",
                        "",
                        "",
                        &format!("distinct={distinct}"),
                        false,
                        None,
                    )?;
                }
            }
            if activity.note_refused(
                &request.path,
                now,
                max_paths.max(2 * WIDE_ENUM_MIN as usize),
                WIDE_ENUM_WINDOW,
            ) {
                let count = activity.burst_misses;
                if count >= WIDE_ENUM_MIN {
                    let handled = request.denied_by_gateway() && !activity.reached_backend;
                    let detail = format!("distinct={count} within {WIDE_ENUM_WINDOW}s");
                    sink.emit(
                        ip,
                        EVENT_WIDE_ENUM,
                        now,
                        "haproxy-log",
                        "",
                        "",
                        &detail,
                        handled,
                        None,
                    )?;
                    if count >= MASS_ENUM_MIN {
                        sink.emit(
                            ip,
                            EVENT_MASS_ENUM,
                            now,
                            "haproxy-log",
                            "",
                            "",
                            &detail,
                            handled,
                            None,
                        )?;
                    }
                }
            }
        }
        if request.status == 400 || request.backend.ends_with("/<NOSRV>") {
            note_invalid_host(sink, ip, activity, now, request, max_paths)?;
        }
        Ok(())
    }

    pub fn site_names(&mut self) -> HashSet<String> {
        self.site_names.get().clone()
    }

    pub fn set_trap_hosts(&mut self, hosts: &Value) -> EResult<Vec<String>> {
        let sites = self.site_names();
        let checked = validate_trap_hosts(hosts, &sites).map_err(EngineError::Value)?;
        self.db
            .set_state(TRAP_HOSTS_KEY, &crate::secdb::python_json(&json!(checked)))?;
        self.trap_hosts = checked.iter().cloned().collect();
        log_info(&format!(
            "trap names set: {}",
            if checked.is_empty() {
                "none".into()
            } else {
                checked.join(", ")
            }
        ));
        Ok(checked)
    }

    // -- reputation -----------------------------------------------------------------

    pub fn reputation(
        &self,
        ip: &str,
        now: i64,
        policy: Option<&ScoringPolicy>,
        scheduled: Option<&BTreeMap<String, i64>>,
    ) -> Result<Reputation, String> {
        let owned_policy;
        let policy = match policy {
            Some(p) => p,
            None => {
                owned_policy = self.scoring_policy();
                &owned_policy
            }
        };
        let owned_sched;
        let scheduled = match scheduled {
            Some(s) => s,
            None => {
                owned_sched = self.db.scheduled_bans()?;
                &owned_sched
            }
        };
        let events = self.db.events_for(ip, now - policy.window_seconds, 500)?;
        let result = score_events(&events, now, policy);
        let verdict = self.sink.exclusions.verdict(ip);
        let facts = self.db.ip_facts(ip);
        let authenticated_at = facts
            .get("authenticated_at")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let mut rep = Reputation {
            ip: ip.to_string(),
            score: result.score,
            state: result.state,
            recommended_action: result.recommended_action,
            events_counted: result.events_counted,
            categories: result.categories,
            contributions: result.contributions,
            enforceable: enforceable(ip),
            excluded: verdict.excluded,
            exclusion_reason: verdict.reason.clone(),
            authenticated_at,
            first_seen: facts.get("first_seen").and_then(Value::as_i64).unwrap_or(0),
            last_seen: facts.get("last_seen").and_then(Value::as_i64).unwrap_or(0),
            event_count: events.len(),
            blockers: Vec::new(),
            would_ban: false,
            banned_until: scheduled.get(ip).copied().unwrap_or(0),
            likely_false_positive: false,
        };
        if verdict.excluded {
            rep.score = 0;
            rep.state = "NORMAL";
            rep.recommended_action = "none";
        }
        rep.blockers = self.ban_blockers(&rep, now, None);
        rep.would_ban = rep.score >= WOULD_BAN_SCORE && rep.blockers.is_empty();
        rep.likely_false_positive = authenticated_at != 0 && rep.score >= WATCH_SCORE;
        Ok(rep)
    }

    pub fn reputation_table(
        &self,
        now: i64,
        limit: i64,
        policy: Option<&ScoringPolicy>,
    ) -> Result<Vec<Reputation>, String> {
        let owned;
        let policy = match policy {
            Some(p) => p,
            None => {
                owned = self.scoring_policy();
                &owned
            }
        };
        let scheduled = self.db.scheduled_bans()?;
        let mut rows = Vec::new();
        for ip in self
            .db
            .active_addresses(now - policy.window_seconds, limit)?
        {
            rows.push(self.reputation(&ip, now, Some(policy), Some(&scheduled))?);
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.score));
        Ok(rows)
    }

    // -- enforcement ------------------------------------------------------------------

    fn recover_enforcement_checks(&mut self) {
        let since = utc_now() - self.sink.policy.window_seconds;
        if let Ok(rows) = self.db.recent_findings(ENFORCEMENT_RECOVERY_EVENTS) {
            for (ip, ts, event_type, handled) in rows.into_iter().rev() {
                if ts >= since {
                    self.sink.queue_check(&ip, &event_type, handled);
                }
            }
        }
    }

    fn visit_enforcement_checks(
        &mut self,
        now: i64,
        mut check: impl FnMut(&mut Self, &str) -> EResult<()>,
    ) -> EResult<()> {
        self.enforcement_checked = 0;
        let pending = self
            .sink
            .queue
            .batch(ENFORCEMENT_BATCH - ENFORCEMENT_SWEEP_RESERVE);
        let mut seen = HashSet::new();
        for (ip, generation) in &pending {
            seen.insert(ip.clone());
            self.enforcement_checked += 1;
            check(self, ip)?;
            self.sink.queue.acknowledge(ip, *generation);
        }
        let allowance = (ENFORCEMENT_BATCH - pending.len()) as i64;
        if self.enforcement_scan_before == 0 {
            self.enforcement_scan_before = now;
        }
        let after = self.enforcement_scan_after.clone();
        let mut addresses = self.db.enforcement_addresses(
            (after.0, &after.1),
            self.enforcement_scan_before,
            allowance,
        )?;
        if addresses.is_empty() && self.enforcement_scan_after != (0, String::new()) {
            self.enforcement_scan_after = (0, String::new());
            self.enforcement_scan_before = now;
            addresses = self.db.enforcement_addresses((0, ""), now, allowance)?;
        }
        for (first_seen, ip) in &addresses {
            if !seen.contains(ip) {
                self.enforcement_checked += 1;
                check(self, ip)?;
            }
            self.enforcement_scan_after = (*first_seen, ip.clone());
        }
        if (addresses.len() as i64) < allowance {
            self.enforcement_scan_after = (0, String::new());
            self.enforcement_scan_before = 0;
        }
        self.db.set_state(
            ENFORCEMENT_CURSOR_KEY,
            &crate::secdb::python_json(&json!({
                "after": [self.enforcement_scan_after.0, self.enforcement_scan_after.1],
                "before": self.enforcement_scan_before,
            })),
        )?;
        Ok(())
    }

    pub fn ban_blockers(&self, rep: &Reputation, now: i64, policy: Option<&str>) -> Vec<String> {
        let policy = policy.unwrap_or(self.sink.ban_policy);
        let mut blockers = Vec::new();
        if rep.excluded {
            blockers.push(format!("exempt ({})", rep.exclusion_reason));
        }
        if rep.authenticated_at != 0 {
            if policy != BAN_POLICY_U02 {
                blockers.push("has authenticated before".into());
            } else if rep.authenticated_at >= now - TRUST_AFTER_SIGN_IN_SECONDS {
                blockers.push("signed in within the last 7 days".into());
            }
        }
        if !rep.enforceable {
            blockers.push("IPv4-only ban path".into());
        }
        blockers
    }

    pub fn strike_retention(&self, level: i64) -> i64 {
        let ladder = &self.ban_durations;
        let index = (level - 1).max(0).min(ladder.len() as i64 - 1) as usize;
        ladder[index] * (level + STRIKE_RETENTION_BASE_MULTIPLIER)
    }

    pub fn longest_strike_retention(&self) -> i64 {
        (1..=self.ban_durations.len() as i64)
            .map(|l| self.strike_retention(l))
            .max()
            .unwrap_or(0)
    }

    pub fn strike_level(&self, ip: &str, now: i64) -> Result<i64, String> {
        let stamps: Vec<i64> = self
            .db
            .ban_timestamps(ip, 100)?
            .into_iter()
            .filter(|ts| *ts >= self.ban_durations_changed_at)
            .collect();
        if stamps.is_empty() {
            return Ok(0);
        }
        let mut level = 0i64;
        let mut previous = 0i64;
        for ts in stamps {
            if level != 0 && ts - previous > self.strike_retention(level) {
                level = 0;
            }
            level += 1;
            previous = ts;
        }
        let alive_from = previous.max(self.db.newest_finding_ts(ip));
        if now - alive_from > self.strike_retention(level) {
            return Ok(0);
        }
        Ok(level)
    }

    pub fn decision_reason(&self, rep: &Reputation) -> Value {
        let mut counted: Vec<&ScoreContribution> = rep
            .contributions
            .iter()
            .filter(|c| c.points > 0.0)
            .collect();
        counted.sort_by(|a, b| {
            b.points
                .partial_cmp(&a.points)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.ts.cmp(&a.ts))
        });
        let cats: Map<String, Value> = rep
            .categories
            .iter()
            .map(|(k, v)| (k.clone(), json!(round2(*v))))
            .collect();
        json!({
            "score": rep.score,
            "state": rep.state,
            "categories": cats,
            "evidence": counted.iter().take(DECISION_EVIDENCE_LISTED).map(|c| json!({
                "ts": c.ts,
                "event_type": c.event_type,
                "category": c.category,
                "points": round2(c.points),
                "site": c.site,
                "detail": c.detail.chars().take(DECISION_DETAIL_LENGTH).collect::<String>(),
            })).collect::<Vec<_>>(),
            "evidence_total": counted.len(),
        })
    }

    fn settle_pending_decisions(&mut self, now: i64) -> Result<(), String> {
        let pending = self.db.pending_decisions(now - DECISION_PENDING_GRACE)?;
        if pending.is_empty() {
            return Ok(());
        }
        let standing = match self.enforcer.active_bans() {
            Ok(s) => s,
            Err(e) => {
                log_warn(&format!(
                    "Could not read the ban table to settle decisions: {e}"
                ));
                return Ok(());
            }
        };
        let scheduled = self.db.scheduled_bans()?;
        for d in pending {
            let ip = d["ip"].as_str().unwrap_or("").to_string();
            let id = d["id"].as_i64().unwrap_or(0);
            let until = d["until"].as_i64().unwrap_or(0);
            let ts = d["ts"].as_i64().unwrap_or(0);
            let code = standing.get(&ip).copied();
            let adaptive = code.is_some_and(|c| c == ADAPTIVE_BAN_CODE || c == ADAPTIVE_PAGE_CODE);
            if adaptive && !scheduled.contains_key(&ip) && until > now {
                self.db.commit_ban(
                    id,
                    &ip,
                    until,
                    code.unwrap_or(ADAPTIVE_BAN_CODE),
                    ts,
                    &format!("score={} seconds={} [settled]", d["score"], until - ts),
                )?;
                log_warn(&format!("Recorded the ban on {ip} applied before a crash"));
                continue;
            }
            if adaptive && !scheduled.contains_key(&ip) {
                if let Err(e) = self.enforcer.lift(&ip) {
                    if e.ban_table_unsure() {
                        log_warn(&e.to_string());
                        continue;
                    }
                    return Err(e.to_string());
                }
            }
            self.db.settle_decision(id, "abandoned")?;
        }
        Ok(())
    }

    pub fn ban_duration(&self, ip: &str, now: i64) -> Result<i64, String> {
        let ladder = &self.ban_durations;
        let index = self.strike_level(ip, now)?.min(ladder.len() as i64 - 1) as usize;
        Ok(ladder[index])
    }

    pub fn set_ban_durations(&mut self, data: &Value) -> EResult<Vec<i64>> {
        let checked = validate_ban_durations(data).map_err(EngineError::Value)?;
        let now = utc_now();
        self.db.set_state(
            BAN_DURATIONS_KEY,
            &crate::secdb::python_json(&json!(checked)),
        )?;
        self.db
            .set_state(BAN_DURATIONS_CHANGED_KEY, &now.to_string())?;
        self.ban_durations = checked.clone();
        self.ban_durations_changed_at = now;
        log_warn(&format!(
            "Adaptive ban durations changed to {}",
            checked
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        Ok(checked)
    }

    pub fn apply_enforcement(&mut self, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        self.enforcement_checked = 0;
        let mut applied: Vec<String> = Vec::new();
        let mut lifted: Vec<String> = Vec::new();
        self.settle_pending_decisions(now)?;
        let mut scheduled = self.db.scheduled_bans()?;
        let mut codes = self.db.scheduled_ban_codes()?;
        let enforcing = self.enforcer.allowed();
        for (ip, until) in scheduled.clone() {
            let served = until <= now;
            if enforcing && !served {
                continue;
            }
            let taken_off = match self.enforcer.lift(&ip) {
                Ok(t) => t,
                Err(e) if e.ban_table_unsure() => {
                    log_warn(&format!("{e}; trying again next cycle"));
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if taken_off {
                lifted.push(ip.clone());
                self.sink.emit(
                    &ip,
                    EVENT_BAN_LIFTED,
                    now,
                    "guardd",
                    "",
                    "",
                    if enforcing {
                        "expired"
                    } else {
                        "enforcement disabled"
                    },
                    false,
                    Some(format!("{ip}|{EVENT_BAN_LIFTED}|{until}")),
                )?;
                let code = codes
                    .get(&ip)
                    .copied()
                    .filter(|c| *c == ADAPTIVE_BAN_CODE || *c == ADAPTIVE_PAGE_CODE)
                    .unwrap_or(ADAPTIVE_BAN_CODE);
                self.db.record_decision(
                    &ip,
                    now,
                    "lifted",
                    if served { "expiry" } else { "mode" },
                    "applied",
                    Decision {
                        code,
                        until,
                        policy: self.sink.ban_policy,
                        ..Default::default()
                    },
                )?;
            }
            if served {
                self.db.clear_ban(&ip)?;
            }
        }
        if !enforcing {
            let mut extra: Vec<String> = self.enforcer.adaptive_bans()?.into_keys().collect();
            extra.sort();
            for ip in extra {
                if scheduled.contains_key(&ip) {
                    continue;
                }
                match self.enforcer.lift(&ip) {
                    Ok(true) => lifted.push(ip),
                    Ok(false) => {}
                    Err(e) if e.ban_table_unsure() => {
                        log_warn(&format!("{e}; trying again next cycle"))
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            self.apply_promotions();
            return Ok(json!({"applied": applied, "lifted": lifted, "enforcing": false}));
        }
        let mut standing = self.enforcer.active_bans()?;
        for (ip, until) in &scheduled {
            if *until <= now || standing.contains_key(ip) {
                continue;
            }
            let code = codes
                .get(ip)
                .copied()
                .filter(|c| *c == ADAPTIVE_BAN_CODE || *c == ADAPTIVE_PAGE_CODE)
                .unwrap_or(ADAPTIVE_BAN_CODE);
            if self.enforcer.ban(ip, code)? {
                log_info(&format!("Re-asserted the ban on {ip}, gone from the table"));
            }
        }
        let policy = self.scoring_policy();
        self.visit_enforcement_checks(now, |engine, ip| {
            let row = engine.reputation(ip, now, Some(&policy), Some(&scheduled))?;
            engine.apply_row_decision(
                &row,
                now,
                &mut scheduled,
                &mut codes,
                &mut standing,
                &mut applied,
            )?;
            Ok(())
        })?;
        if !applied.is_empty() {
            self.check_burst(applied.len(), now);
        }
        self.apply_promotions();
        Ok(json!({"applied": applied, "lifted": lifted, "enforcing": true}))
    }

    pub fn apply_urgent_enforcement(&mut self, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        if !self.enforcer.allowed() || !self.sink.queue.has_urgent() {
            return Ok(json!({"applied": [], "enforcing": self.enforcer.allowed()}));
        }
        let mut scheduled = self.db.scheduled_bans()?;
        let mut codes = self.db.scheduled_ban_codes()?;
        let mut standing = self.enforcer.active_bans()?;
        let policy = self.scoring_policy();
        let mut applied = Vec::new();
        for (ip, generation) in self.sink.queue.urgent_batch(ENFORCEMENT_BATCH) {
            let row = self.reputation(&ip, now, Some(&policy), Some(&scheduled))?;
            self.apply_row_decision(
                &row,
                now,
                &mut scheduled,
                &mut codes,
                &mut standing,
                &mut applied,
            )?;
            self.sink.queue.acknowledge(&ip, generation);
        }
        if !applied.is_empty() {
            self.fast_enforcements += applied.len() as u64;
            self.check_burst(applied.len(), now);
        }
        Ok(json!({"applied": applied, "enforcing": true}))
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_row_decision(
        &self,
        row: &Reputation,
        now: i64,
        scheduled: &BTreeMap<String, i64>,
        codes: &BTreeMap<String, i64>,
        standing: &HashMap<String, i64>,
    ) -> EResult<Option<PreparedBan>> {
        let ip = row.ip.as_str();
        if row.score < WOULD_BAN_SCORE {
            return Ok(None);
        }
        let mut after_page = false;
        if scheduled.get(ip).copied().unwrap_or(0) > now {
            let escalate = codes.get(ip) == Some(&ADAPTIVE_PAGE_CODE)
                && standing.get(ip) == Some(&ADAPTIVE_PAGE_CODE)
                && self.db.signature_paths_since(ip, self.db.last_ban_ts(ip))
                    >= PAGE_ESCALATION_PATHS;
            if !escalate {
                return Ok(None);
            }
            after_page = true;
        }
        let standing_code = standing.get(ip).copied().unwrap_or(ADAPTIVE_BAN_CODE);
        if standing_code != ADAPTIVE_BAN_CODE && standing_code != ADAPTIVE_PAGE_CODE {
            return Ok(None);
        }
        if !self.ban_blockers(row, now, None).is_empty() {
            return Ok(None);
        }
        let last_ban = self.db.last_ban_ts(ip);
        let mut floor = last_ban;
        if !after_page {
            if let Some((code, until)) = self.db.last_applied_ban(ip) {
                if code == ADAPTIVE_PAGE_CODE {
                    floor = floor.max(until.min(now));
                }
            }
        }
        if last_ban != 0 && self.db.newest_finding_ts(ip) <= floor {
            return Ok(None);
        }
        let duration = self.ban_duration(ip, now)?;
        let level = self.strike_level(ip, now)?;
        let code = if self.first_step_page && level == 0 && !after_page {
            ADAPTIVE_PAGE_CODE
        } else {
            ADAPTIVE_BAN_CODE
        };
        let mut reason = self.decision_reason(row);
        if after_page {
            reason["after_page"] = json!(true);
        }
        let decision = self.db.record_decision(
            ip,
            now,
            "applied",
            "adaptive",
            "pending",
            Decision {
                code,
                until: now + duration,
                strike: level + 1,
                score: row.score,
                policy: self.sink.ban_policy,
                reason: Some(reason),
            },
        )?;
        let mut cats: Vec<&String> = row.categories.keys().collect();
        cats.sort();
        let categories = cats
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Some(PreparedBan {
            ip: ip.to_string(),
            now,
            duration,
            code,
            score: row.score,
            after_page,
            categories,
            decision,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_row_decision(
        &mut self,
        prep: PreparedBan,
        banned: bool,
        scheduled: &mut BTreeMap<String, i64>,
        codes: &mut BTreeMap<String, i64>,
        standing: &mut HashMap<String, i64>,
        applied: &mut Vec<String>,
    ) -> EResult<bool> {
        let ip = prep.ip.as_str();
        if !banned {
            self.db.settle_decision(prep.decision, "failed")?;
            self.sink.queue.mark(ip, true);
            return Ok(false);
        }
        self.db.commit_ban(
            prep.decision,
            ip,
            prep.now + prep.duration,
            prep.code,
            prep.now,
            &format!(
                "score={} seconds={} [{}]{}",
                prep.score,
                prep.duration,
                prep.categories,
                if prep.after_page {
                    " after the page"
                } else {
                    ""
                }
            ),
        )?;
        scheduled.insert(prep.ip.clone(), prep.now + prep.duration);
        codes.insert(prep.ip.clone(), prep.code);
        standing.insert(prep.ip.clone(), prep.code);
        self.sink.events_recorded += 1;
        applied.push(prep.ip.clone());
        log_warn(&format!(
            "Adaptive ban applied to {ip} for {}s (score {}){}",
            prep.duration,
            prep.score,
            if prep.code == ADAPTIVE_PAGE_CODE {
                " -- a page first"
            } else if prep.after_page {
                " -- went on after the page"
            } else {
                ""
            }
        ));
        self.queue_alert(
            "security.hostile_ip",
            ip,
            None,
            format!("Adaptive protection banned {ip} for {}s", prep.duration),
            format!(
                "score {} over {}; the ban lifts automatically when it expires",
                prep.score,
                if prep.categories.is_empty() {
                    "no category".to_string()
                } else {
                    prep.categories
                }
            ),
        );
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_row_decision(
        &mut self,
        row: &Reputation,
        now: i64,
        scheduled: &mut BTreeMap<String, i64>,
        codes: &mut BTreeMap<String, i64>,
        standing: &mut HashMap<String, i64>,
        applied: &mut Vec<String>,
    ) -> EResult<bool> {
        let Some(prep) = self.prepare_row_decision(row, now, scheduled, codes, standing)? else {
            return Ok(false);
        };
        let banned = self.enforcer.ban(&prep.ip, prep.code)?;
        self.finish_row_decision(prep, banned, scheduled, codes, standing, applied)
    }

    fn check_burst(&mut self, banned: usize, now: i64) {
        for _ in 0..banned {
            self.burst_bans.push_back(now);
        }
        while self
            .burst_bans
            .front()
            .is_some_and(|t| *t <= now - BURST_WINDOW_SECONDS)
        {
            self.burst_bans.pop_front();
        }
        let count = self.burst_bans.len();
        if count < BURST_MIN_BANS {
            return;
        }
        if self
            .burst_reported
            .is_some_and(|r| now - r < BURST_REPORT_GAP_SECONDS)
        {
            return;
        }
        self.burst_reported = Some(now);
        self.queue_alert(
            "security.burst",
            "gateway",
            None,
            format!(
                "{count} addresses banned in the last {} minutes",
                BURST_WINDOW_SECONDS / 60
            ),
            "Either a campaign is under way or a rule has started to match ordinary clients; the adaptive protection page shows who and why.".into(),
        );
    }

    pub fn report_failing(&mut self) {
        let failing = self.consecutive_failures >= ENGINE_FAILING_AFTER;
        if !failing && !self.failing_reported {
            return;
        }
        self.failing_reported = failing;
        if self.alerts.is_none() {
            return;
        }
        if failing {
            let err: String = self
                .last_error
                .clone()
                .unwrap_or_else(|| "unknown error".into())
                .chars()
                .take(200)
                .collect();
            self.queue_alert(
                ENGINE_FAILING_RULE,
                "guardd",
                Some(true),
                format!("Adaptive protection keeps failing: {err}"),
                "Until it works again nothing is scored or banned and no ban decision is recorded; bans already in HAProxy stay. The service journal of easy-ha-proxy-guardd has the details; a full disk is the usual cause.".into(),
            );
        } else {
            self.queue_alert(
                ENGINE_FAILING_RULE,
                "guardd",
                Some(false),
                "Adaptive protection works again".into(),
                String::new(),
            );
        }
    }

    pub fn place_manual_ban(&mut self, ip: &str, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        let checked = ip.trim().to_string();
        if !enforceable(&checked) {
            return Err(EngineError::Value(
                "only an IPv4 address can be banned".into(),
            ));
        }
        let mut remembered = true;
        let previous = self
            .db
            .manual_bans()
            .ok()
            .and_then(|m| m.get(&checked).copied());
        if let Err(e) =
            self.db
                .write_manual_ban(&checked, now, now + MANUAL_BAN_DEFAULT_SECONDS, now, 0)
        {
            remembered = false;
            log_warn(&format!(
                "Could not remember the manual ban on {checked}: {e}"
            ));
        }
        let put_back = |db: &SecurityDatabase| {
            if !remembered {
                return;
            }
            match previous {
                Some(p) => {
                    let _ = db.write_manual_ban(
                        &checked,
                        p.placed_at,
                        p.expires_at,
                        p.seen_at,
                        p.reasserted,
                    );
                }
                None => {
                    let _ = db.forget_manual_ban(&checked);
                }
            }
        };
        let placed = match self.enforcer.restore(&checked, MANUAL_BAN_CODE) {
            Ok(p) => p,
            Err(e) => {
                put_back(&self.db);
                return Err(EngineError::Refused(e.to_string()));
            }
        };
        if !placed {
            put_back(&self.db);
            return Err(EngineError::Refused(format!(
                "HAProxy refused the ban on {checked}"
            )));
        }
        let mut until = now + MANUAL_BAN_DEFAULT_SECONDS;
        if let Ok(rows) = read_table(
            &self.config.haproxy_socket,
            "tbl_ban",
            &format!("key {checked}"),
        ) {
            if let Some(fields) = rows.get(&checked) {
                let exp = field_int(fields, "exp");
                if exp > 0 {
                    until = now + exp / 1000;
                }
            }
        }
        let outcome = self
            .db
            .write_manual_ban(&checked, now, until, now, 0)
            .and_then(|_| {
                self.db.record_decision(
                    &checked,
                    now,
                    "applied",
                    "operator",
                    "applied",
                    Decision {
                        code: MANUAL_BAN_CODE,
                        until,
                        policy: self.sink.ban_policy,
                        ..Default::default()
                    },
                )
            });
        if let Err(e) = outcome {
            remembered = false;
            log_warn(&format!(
                "Banned {checked} by hand, but could not remember it: {e}"
            ));
        }
        log_warn(&format!("Ban placed by hand on {checked} until {until}"));
        Ok(
            json!({"ok": true, "ip": checked, "code": MANUAL_BAN_CODE, "until": until, "remembered": remembered}),
        )
    }

    pub fn forget_ban(&mut self, ip: &str, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        let checked = ip.trim().to_string();
        if checked.is_empty() {
            return Err(EngineError::Value("an address is required".into()));
        }
        if checked.parse::<std::net::IpAddr>().is_err() {
            return Err(EngineError::Value("invalid IP address".into()));
        }
        let held = self
            .db
            .scheduled_bans()?
            .get(&checked)
            .copied()
            .unwrap_or(0);
        self.db.clear_ban(&checked)?;
        let manual = self.db.forget_manual_ban(&checked)?;
        let mut refused = String::new();
        let mut lifted = false;
        let mut released = false;
        match self.enforcer.lift(&checked) {
            Ok(l) => {
                lifted = l;
                match self.enforcer.release(&checked) {
                    Ok(r) => released = r,
                    Err(e) if e.ban_table_unsure() => {
                        refused = e.to_string();
                        log_warn(&refused);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if e.ban_table_unsure() => {
                refused = e.to_string();
                log_warn(&refused);
            }
            Err(e) => return Err(e.into()),
        }
        if held != 0 || lifted {
            self.sink.emit(
                &checked,
                EVENT_BAN_LIFTED,
                now,
                "operator",
                "",
                "",
                "cleared by hand",
                false,
                Some(format!("{checked}|{EVENT_BAN_LIFTED}|{now}")),
            )?;
            log_warn(&format!(
                "Ban on {checked} cleared by hand; the schedule is dropped"
            ));
        }
        let legacy = self.settle_legacy_observed(&checked);
        if held != 0 || lifted || manual || legacy != 0 {
            let code = if held != 0 || lifted {
                ADAPTIVE_BAN_CODE
            } else if manual {
                MANUAL_BAN_CODE
            } else {
                legacy
            };
            self.db.record_decision(
                &checked,
                now,
                "lifted",
                "operator",
                if refused.is_empty() {
                    "applied"
                } else {
                    "failed"
                },
                Decision {
                    code,
                    until: held,
                    policy: self.sink.ban_policy,
                    ..Default::default()
                },
            )?;
        }
        self.apply_promotions();
        Ok(json!({
            "ok": true,
            "refused": refused,
            "ip": checked,
            "was_scheduled": held != 0,
            "lifted": lifted || released,
            "cleared": refused.is_empty(),
        }))
    }

    pub fn quality(&mut self, days: i64, now: Option<i64>) -> Result<Value, String> {
        let days = days.clamp(1, QUALITY_MAX_DAYS);
        let now = now.unwrap_or_else(utc_now);
        if let Some((at, report)) = self.quality_cache.get(&days) {
            if now - at < QUALITY_CACHE_SECONDS {
                return Ok(report.clone());
            }
        }
        let mut report = self.db.quality(now - days * 86400, now)?;
        report["days"] = json!(days);
        report["mode"] = json!(self.enforcer.mode);
        let dismissed: HashSet<String> = dismissed_candidates(&self.db).into_iter().collect();
        let sigs = self.sig();
        report["signature_candidates"] =
            json!(self.candidates.suggestions(&dismissed, 100, &sigs).len());
        let names = self
            .unknown_hosts
            .listing(50)
            .into_iter()
            .filter(|row| {
                row["clients"].as_i64().unwrap_or(0) == 0
                    && row["addresses"].as_i64().unwrap_or(0) >= QUALITY_NETWORK_MIN
                    && !self.trap_hosts.contains(row["host"].as_str().unwrap_or(""))
            })
            .count();
        report["trap_candidates"] = json!(names);
        report["trap_names"] = json!(self.trap_hosts.len());
        let shield = self.shield_state();
        report["path_shield"] = json!({
            "enabled": shield.get("enabled").cloned().unwrap_or(Value::Null),
            "active": shield.get("active").cloned().unwrap_or(Value::Null),
            "segments": shield.get("segments").cloned().unwrap_or(Value::Null),
            "paths": shield.get("paths").cloned().unwrap_or(Value::Null),
        });
        self.quality_cache.insert(days, (now, report.clone()));
        Ok(report)
    }

    pub fn weekly_summary_text(&self, report: &Value) -> (String, String) {
        let bans = report["bans"].as_i64().unwrap_or(0);
        let days = report["days"].as_i64().unwrap_or(7);
        let summary = if bans != 0 {
            format!(
                "Adaptive protection banned {} addresses in {days} days",
                report["banned_addresses"]
            )
        } else {
            format!("Adaptive protection banned nobody in {days} days")
        };
        let per_day = &report["bans_per_day"];
        let mut lines = vec![
            format!("Mode: {}.", report["mode"].as_str().unwrap_or("")),
            if per_day.is_null() {
                format!("Bans: {bans}.")
            } else {
                format!("Bans: {bans} ({per_day} a day).")
            },
            format!(
                "Decided within {QUALITY_AT_ONCE_SECONDS} s of the first finding: {} of {bans}.",
                report["decided_at_once"]
            ),
            format!(
                "Came back after a ban ended: {} of {}.",
                report["came_back_after_a_ban"], report["first_bans_ended"]
            ),
            format!(
                "Bans lifted by an operator: {}.",
                report["lifted_by_operator"]
            ),
            format!(
                "Probers that were never banned: {}.",
                report["probers_never_banned"]
            ),
        ];
        if let Some(nets) = report["networks"].as_array().filter(|n| !n.is_empty()) {
            lines.push(format!(
                "Networks with several banned addresses: {}.",
                nets.iter()
                    .map(|r| format!(
                        "{} ({})",
                        r["network"].as_str().unwrap_or(""),
                        r["addresses"]
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let mut waiting = Vec::new();
        let sc = report["signature_candidates"].as_i64().unwrap_or(0);
        if sc != 0 {
            waiting.push(format!("{sc} signature candidates"));
        }
        let tc = report["trap_candidates"].as_i64().unwrap_or(0);
        if tc != 0 {
            waiting.push(format!("{tc} host names that look like traps"));
        }
        if !waiting.is_empty() {
            lines.push(format!(
                "Waiting for your decision on the Detection rules page: {}.",
                waiting.join(" and ")
            ));
        }
        (summary, lines.join("\n"))
    }

    pub fn weekly_summary_tick(&mut self, now: Option<i64>) -> bool {
        if self.alerts.is_none() {
            return false;
        }
        let now = now.unwrap_or_else(utc_now);
        let local = crate::localtime::local(now);
        if local.weekday != WEEKLY_SUMMARY_WEEKDAY || local.hour < WEEKLY_SUMMARY_HOUR {
            return false;
        }
        let week = crate::localtime::iso_week(&local);
        if self.db.get_state(WEEKLY_SUMMARY_KEY, "") == week || self.enforcer.mode == MODE_OFF {
            return false;
        }
        let Ok(report) = self.quality(7, Some(now)) else {
            return false;
        };
        let (summary, detail) = self.weekly_summary_text(&report);
        self.queue_alert(WEEKLY_SUMMARY_RULE, &week, None, summary, detail);
        self.db.set_state(WEEKLY_SUMMARY_KEY, &week).is_ok()
    }

    pub fn first_step_state(&self) -> Value {
        let codes = self.db.scheduled_ban_codes().unwrap_or_default();
        json!({
            "enabled": self.first_step_page,
            "showing_page": codes.values().filter(|c| **c == ADAPTIVE_PAGE_CODE).count(),
        })
    }

    pub fn set_first_step_page(&mut self, enabled: &Value) -> EResult<Value> {
        let Some(enabled) = enabled.as_bool() else {
            return Err(EngineError::Value("enabled must be true or false".into()));
        };
        let mut changed = 0;
        self.db
            .set_state(FIRST_STEP_PAGE_KEY, if enabled { "1" } else { "0" })?;
        self.first_step_page = enabled;
        if !enabled {
            let standing = self.enforcer.active_bans()?;
            for (ip, code) in self.db.scheduled_ban_codes()? {
                if code != ADAPTIVE_PAGE_CODE {
                    continue;
                }
                if standing.get(&ip) == Some(&ADAPTIVE_PAGE_CODE)
                    && !self.enforcer.ban(&ip, ADAPTIVE_BAN_CODE)?
                {
                    continue;
                }
                self.db.set_ban_code(&ip, ADAPTIVE_BAN_CODE)?;
                changed += 1;
            }
        }
        log_warn(&format!(
            "First-step page switched {}{}",
            if enabled { "on" } else { "off" },
            if changed > 0 {
                format!("; {changed} first steps now cut off")
            } else {
                String::new()
            }
        ));
        let mut state = self.first_step_state();
        state["changed"] = json!(changed);
        Ok(state)
    }

    pub fn sync_shield(&mut self, now: i64) -> Value {
        let sigs = self.sig();
        match shield_entries(
            &self.enforcer.mode,
            self.shield_enabled,
            &self.detection.config.modes,
            &self.detection.config.exceptions,
            now,
            &sigs,
        ) {
            Ok(wanted) => self.shield.sync(&wanted, now),
            Err(e) => {
                self.shield.status["active"] = json!(false);
                self.shield.status["error"] = json!(e.chars().take(300).collect::<String>());
                self.shield.status.clone()
            }
        }
    }

    pub fn shield_state(&self) -> Value {
        let mut v = self.shield.status.clone();
        v["enabled"] = json!(self.shield_enabled);
        v["mode"] = json!(self.enforcer.mode);
        v
    }

    pub fn set_shield(&mut self, enabled: &Value, now: Option<i64>) -> EResult<Value> {
        let Some(enabled) = enabled.as_bool() else {
            return Err(EngineError::Value("enabled must be true or false".into()));
        };
        self.db
            .set_state(SHIELD_ENABLED_KEY, if enabled { "1" } else { "0" })?;
        self.shield_enabled = enabled;
        log_warn(&format!(
            "Path shield switched {}",
            if enabled { "on" } else { "off" }
        ));
        self.sync_shield(now.unwrap_or_else(utc_now));
        Ok(self.shield_state())
    }

    pub fn set_mode(&mut self, mode: &str, now: Option<i64>) -> EResult<Value> {
        let mode = mode.trim().to_lowercase();
        if !SUPPORTED_MODES.contains(&mode.as_str()) {
            return Err(EngineError::Value(format!(
                "mode must be one of {}",
                SUPPORTED_MODES.join(", ")
            )));
        }
        let now = now.unwrap_or_else(utc_now);
        let previous = self.enforcer.mode.clone();
        self.db.set_state("mode_override", &mode)?;
        self.enforcer.mode = mode.clone();
        log_warn(&format!(
            "Adaptive protection mode changed: {previous} -> {mode}"
        ));
        let mut result = self.apply_enforcement(Some(now))?;
        self.sync_shield(now);
        result["mode"] = json!(mode);
        result["previous"] = json!(previous);
        Ok(result)
    }

    pub fn parse_ban_detail(detail: &str) -> (Option<i64>, Vec<String>) {
        static SCORE: OnceLock<Regex> = OnceLock::new();
        static CATS: OnceLock<Regex> = OnceLock::new();
        if detail.is_empty() {
            return (None, Vec::new());
        }
        let score = SCORE
            .get_or_init(|| Regex::new(r"score=(\d+)").expect("regex"))
            .captures(detail)
            .and_then(|c| c[1].parse().ok());
        let cats = CATS
            .get_or_init(|| Regex::new(r"\[([^\]]*)\]").expect("regex"))
            .captures(detail)
            .map(|c| {
                c[1].split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        (score, cats)
    }

    pub fn current_bans(&self, now: Option<i64>) -> Result<Vec<Value>, String> {
        let now = now.unwrap_or_else(utc_now);
        let scheduled = self.db.scheduled_bans()?;
        let mut rows: Vec<(i64, Value)> = Vec::new();
        for (ip, until) in &scheduled {
            let remaining = until - now;
            if remaining <= 0 {
                continue;
            }
            let decision = self.db.adaptive_ban_detail(0, ip, 0, *until)?;
            let last_ban = decision
                .as_ref()
                .and_then(|d| d["ts"].as_i64())
                .unwrap_or_else(|| self.db.last_ban_ts(ip));
            let (rec_score, rec_cats) = Self::parse_ban_detail(&self.db.last_ban_detail(ip));
            let reason = decision
                .as_ref()
                .map(|d| d["reason"].clone())
                .unwrap_or_else(|| json!({}));
            let standing = self.reputation(ip, now, None, Some(&scheduled))?;
            let score = match &decision {
                Some(d) => d["score"].clone(),
                None => json!(rec_score.unwrap_or(standing.score)),
            };
            let summary_cats = decision_summary(&reason)
                .get("categories")
                .cloned()
                .filter(|c| c.as_array().is_some_and(|a| !a.is_empty()));
            let categories = summary_cats.unwrap_or_else(|| {
                if !rec_cats.is_empty() {
                    json!(rec_cats)
                } else {
                    let mut c: Vec<&String> = standing.categories.keys().collect();
                    c.sort();
                    json!(c)
                }
            });
            rows.push((
                remaining,
                json!({
                    "ip": ip,
                    "id": decision.as_ref().map(|d| d["id"].clone()).unwrap_or(Value::Null),
                    "until": until,
                    "seconds_left": remaining,
                    "banned_at": last_ban,
                    "strikes": decision.as_ref().map(|d| d["strike"].clone()).unwrap_or(Value::Null),
                    "score": score,
                    "state": standing.state,
                    "categories": categories,
                    "likely_false_positive": standing.likely_false_positive,
                }),
            ));
        }
        rows.sort_by_key(|r| r.0);
        Ok(rows.into_iter().map(|r| r.1).collect())
    }

    pub fn shadow_review(
        &self,
        now: Option<i64>,
        limit: i64,
        policy: Option<&ScoringPolicy>,
        signatures: Value,
    ) -> Result<Value, String> {
        let now = now.unwrap_or_else(utc_now);
        let owned;
        let policy = match policy {
            Some(p) => p,
            None => {
                owned = self.scoring_policy();
                &owned
            }
        };
        let rows = self.reputation_table(now, limit, Some(policy))?;
        let mut by_state: BTreeMap<&str, i64> = BTreeMap::new();
        for r in &rows {
            *by_state.entry(r.state).or_insert(0) += 1;
        }
        let weights: Map<String, Value> = policy
            .weights
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        Ok(json!({
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "supported_modes": SUPPORTED_MODES,
            "enforcement_possible": self.enforcer.allowed(),
            "ban_durations_seconds": self.ban_durations,
            "policy": {
                "weights": weights,
                "category_cap": policy.category_cap,
                "window_seconds": policy.window_seconds,
                "decay_seconds": policy.decay_seconds,
                "bands": DEFAULT_THRESHOLDS.iter().map(|(t, n)| json!({"from": t, "state": n, "bans": *t >= WOULD_BAN_SCORE})).collect::<Vec<_>>(),
                "would_ban_score": WOULD_BAN_SCORE,
            },
            "signatures": signatures,
            "bans": self.current_bans(Some(now))?,
            "summary": {
                "scored": rows.len(),
                "would_ban": rows.iter().filter(|r| r.would_ban).count(),
                "likely_false_positive": rows.iter().filter(|r| r.likely_false_positive).count(),
                "unenforceable": rows.iter().filter(|r| !r.enforceable && r.score > 0).count(),
                "excluded": rows.iter().filter(|r| r.excluded).count(),
                "banned_now": rows.iter().filter(|r| r.banned_until != 0).count(),
                "blocked_from_ban": rows.iter().filter(|r| r.score >= WOULD_BAN_SCORE && !r.blockers.is_empty()).count(),
                "by_state": by_state,
            },
            "addresses": rows.iter().map(|r| r.to_json(false)).collect::<Vec<_>>(),
        }))
    }

    pub fn run_maintenance(&mut self) -> Result<Value, String> {
        let now = utc_now();
        let cutoff = now - self.config.event_retention_days * 86400;
        let ban_cutoff = cutoff.min(now - self.longest_strike_retention());
        let mut deleted = self.db.apply_retention(cutoff, ban_cutoff)?;
        deleted.insert(
            "rate_warnings".into(),
            self.db.prune_rate_warnings(
                now - RATE_WARNINGS_KEEP_DAYS * 86400,
                RATE_WARNINGS_KEEP_ROWS,
            )?,
        );
        deleted.insert(
            "ban_decisions".into(),
            self.db
                .prune_decisions(ban_cutoff, DECISIONS_KEEP_ROWS, now)?,
        );
        if deleted.values().any(|v| *v != 0) {
            self.db.incremental_vacuum(256);
        }
        let pruned = self.memory.prune(now - 6 * 3600);
        self.sink.subnets.prune(now);
        self.candidates.prune(now - CANDIDATE_TTL);
        self.unknown_hosts.prune(now - UNKNOWN_HOSTS_TTL);
        self.detection.persist(now, true, &self.db)?;
        let _ = self
            .db
            .set_state(CANDIDATES_KEY, &self.candidates.snapshot(2000).to_string());
        let _ = self.db.set_state(
            UNKNOWN_HOSTS_KEY,
            &self.unknown_hosts.snapshot().to_string(),
        );
        let ordered = [
            "events",
            "cooldowns",
            "addresses",
            "rate_warnings",
            "ban_decisions",
        ];
        let text = format!(
            "{{{}}}",
            ordered
                .iter()
                .map(|k| format!("\"{k}\": {}", deleted.get(*k).copied().unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        log_info(&format!(
            "Maintenance: deleted={text} pruned_ips={pruned} tracked={}",
            self.memory.len()
        ));
        Ok(json!({"deleted": deleted, "pruned_ips": pruned}))
    }

    pub fn health(&self) -> Result<Value, String> {
        let now = utc_now();
        let stale_after = 60i64.max(self.config.poll_interval_seconds * 6);
        let (protected, probation) = self.memory.segment_counts();
        let q = self.sink.queue.status();
        let live_health = self.live.as_ref().map(|l| {
            let s = lock(l).status();
            json!({
                "records": s["records"], "bytes": s["bytes"], "budget_mib": self.live_budget["budget_mib"],
                "max_bytes": s["max_bytes"], "max_records": s["max_records"], "max_seconds": s["max_seconds"],
            })
        });
        let manual = self.db.manual_bans().map(|m| m.len()).unwrap_or(0);
        Ok(json!({
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "enforcement_possible": self.enforcer.allowed(),
            "enforcement_refusals": self.enforcer.refused,
            "bans_applied": self.enforcer.applied,
            "bans_lifted": self.enforcer.lifted,
            "bans_active": self.db.scheduled_bans()?.len(),
            "running": self.running.load(Ordering::SeqCst),
            "degraded": self.last_poll_ts.is_none_or(|t| now - t > stale_after),
            "last_poll_ts": self.last_poll_ts,
            "polls_total": self.polls_total,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "log": {
                "path": self.config.log_file,
                "lines_read": self.lines_read,
                "lines_parsed": self.lines_parsed,
                "lag_bytes": self.cursor.lag_bytes,
                "rotations": self.cursor.rotations,
                "last_error": self.cursor.last_error,
            },
            "memory": {
                "tracked_ips": protected + probation,
                "protected_ips": protected,
                "probation_ips": probation,
                "max_tracked_ips": self.memory.max_ips,
                "max_paths_per_ip": self.memory.max_paths,
                "evictions": self.memory.evictions,
            },
            "subnet_correlation": serde_json::to_value(self.sink.subnets.summary(now)).unwrap_or(Value::Null),
            "exclusions": {
                "networks": self.sink.exclusions.network_count(),
                "authenticated": self.sink.exclusions.authenticated_count(),
                "observations_skipped": self.excluded_observations,
            },
            "events_recorded": self.sink.events_recorded,
            "enforcement_checks": {
                "urgent": q.urgent,
                "ordinary": q.ordinary,
                "limit": q.limit,
                "overflows": q.overflows,
                "checked_last_cycle": self.enforcement_checked,
                "fast_enforcements": self.fast_enforcements,
                "batch_limit": ENFORCEMENT_BATCH,
                "sweep_after": [self.enforcement_scan_after.0, self.enforcement_scan_after.1],
                "sweep_before": self.enforcement_scan_before,
            },
            "rate_warnings": self.trusted_rates.summary(),
            "hard_floor": self.hard_floor.summary(),
            "path_shield": self.shield_state(),
            "first_step_page": self.first_step_state(),
            "ban_policy": {
                "current": self.sink.ban_policy,
                "switch": self.ban_policy_state(),
                "legacy_bans": self.legacy_bans,
                "legacy_lifted": self.legacy_lifted,
            },
            "manual_bans": {"remembered": manual, "restored": self.manual_restored},
            "live_buffer": live_health,
            "unreadable_tables": self.unreadable_tables,
        }))
    }

    /// Persist what a stop must not lose.
    pub fn stop(&mut self) {
        self.trusted_rates.finish_all();
        let finished = self.trusted_rates.take_finished();
        let _ = self.db.record_rate_warnings(&finished);
        let now = utc_now();
        if let Err(e) = self.detection.persist(now, true, &self.db) {
            log_warn(&format!("Could not save detection context: {e}"));
        }
        if let Err(e) = self.login_correlations.persist(now, &self.db) {
            log_warn(&format!("Could not save login correlations: {e}"));
        }
        let _ = self.db.set_state(
            "log_cursor",
            &crate::secdb::python_json(&cursor_state(&self.cursor)),
        );
    }
}

// -- derived detections (free functions over the split borrows) ----------------

fn check_multi_category(sink: &mut Sink, ip: &str, a: &IpActivity, now: i64) -> Result<(), String> {
    let n = a.recent_categories(now - MULTI_CATEGORY_WINDOW).len();
    if n < MULTI_CATEGORY_MIN {
        return Ok(());
    }
    sink.emit(
        ip,
        EVENT_SCANNER_MULTI,
        now,
        "haproxy-log",
        "",
        "",
        &format!("categories={n}"),
        a.scanning_was_all_refused(),
        None,
    )?;
    Ok(())
}

fn check_low_and_slow(sink: &mut Sink, ip: &str, a: &IpActivity, now: i64) -> Result<(), String> {
    let n = a.recent_categories(now - LOW_AND_SLOW_WINDOW).len();
    if a.scanner_hits < LOW_AND_SLOW_MIN_HITS || n < LOW_AND_SLOW_MIN_CATEGORIES {
        return Ok(());
    }
    sink.emit(
        ip,
        EVENT_LOW_AND_SLOW,
        now,
        "haproxy-log",
        "",
        "",
        &format!("hits={} categories={n}", a.scanner_hits),
        a.scanning_was_all_refused(),
        None,
    )?;
    Ok(())
}

fn check_recurring(
    sink: &mut Sink,
    db: &SecurityDatabase,
    ip: &str,
    a: &mut IpActivity,
    now: i64,
) -> Result<(), String> {
    if now - a.recurring_checked < RECURRING_RECHECK {
        return Ok(());
    }
    a.recurring_checked = now;
    let earlier = db.last_signature(ip, now - RECURRING_WINDOW, now - RECURRING_GAP);
    if earlier == 0 {
        return Ok(());
    }
    let hours = (now - earlier) / 3600;
    sink.emit(
        ip,
        EVENT_RECURRING,
        now,
        "haproxy-log",
        "",
        "",
        &format!("back after {hours}h"),
        a.scanning_was_all_refused(),
        None,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_unknown_host(
    sink: &mut Sink,
    unknown_hosts: &mut UnknownHosts,
    trap_hosts: &BTreeSet<String>,
    sites: &HashSet<String>,
    ip: &str,
    a: &IpActivity,
    now: i64,
    request: &ParsedRequest,
) -> Result<(), String> {
    let host = normalize_host(&request.host);
    if host.is_empty() || sites.is_empty() || sites.contains(&host) {
        return Ok(());
    }
    let good = a.requests as i64
        - a.errors as i64
        - a.not_found as i64
        - a.gateway_denied as i64
        - a.bad_requests as i64;
    let client = a.requests >= 20 && good * 2 >= a.requests as i64;
    unknown_hosts.note(&host, ip, client, now);
    if trap_hosts.contains(&host) && !client {
        sink.emit(
            ip,
            EVENT_SCANNER_DECISIVE,
            now,
            "haproxy-log",
            "trap",
            "",
            &format!("trap name {host}"),
            false,
            Some(format!("{ip}|trap|{host}")),
        )?;
    }
    Ok(())
}

fn note_invalid_host(
    sink: &mut Sink,
    ip: &str,
    a: &mut IpActivity,
    now: i64,
    request: &ParsedRequest,
    max_paths: usize,
) -> Result<(), String> {
    let distinct = a.note_invalid_host(
        &format!("{}|{}", request.host, request.path),
        now,
        max_paths,
        INVALID_HOST_WINDOW,
    );
    let Some(d) = distinct.filter(|d| *d >= INVALID_HOST_MIN) else {
        return Ok(());
    };
    let handled = request.denied_by_gateway() && !a.reached_backend;
    sink.emit(
        ip,
        EVENT_INVALID_HOST,
        now,
        "haproxy-log",
        "",
        "",
        &format!("distinct={d}"),
        handled,
        None,
    )?;
    Ok(())
}

// -- state helpers ----------------------------------------------------------------

pub fn load_ban_durations(db: &SecurityDatabase) -> Vec<i64> {
    let raw = db.get_state(BAN_DURATIONS_KEY, "");
    if raw.is_empty() {
        return BAN_DURATIONS.to_vec();
    }
    match serde_json::from_str::<Value>(&raw)
        .map_err(|e| e.to_string())
        .and_then(|v| validate_ban_durations(&v))
    {
        Ok(steps) => steps,
        Err(e) => {
            log_warn(&format!(
                "stored ban durations are unusable ({e}); using defaults"
            ));
            BAN_DURATIONS.to_vec()
        }
    }
}

fn load_legacy_observed(db: &SecurityDatabase) -> Vec<(String, i64)> {
    match serde_json::from_str::<Value>(&db.get_state(LEGACY_OBSERVED_STATE_KEY, "{}")) {
        Ok(Value::Object(m)) => m
            .iter()
            .map(|(ip, code)| (ip.clone(), safe_int_value(Some(code))))
            .filter(|(_, c)| crate::watchers::is_legacy_code(*c))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn dismissed_candidates(db: &SecurityDatabase) -> Vec<String> {
    json_list_strings(&db.get_state(CANDIDATES_DISMISSED_KEY, "[]"))
}

/// Hide a suggestion for good, or bring a hidden one back.
pub fn dismiss_candidate(
    db: &SecurityDatabase,
    path: &str,
    restore: bool,
    host: &str,
) -> EResult<Value> {
    let text = path.trim();
    if !text.starts_with('/') || text.chars().count() > CANDIDATE_MAX_PATH_LENGTH {
        return Err(EngineError::Value("expected a path".into()));
    }
    let key = if host.is_empty() {
        text.to_string()
    } else {
        let h = detection_host(host).map_err(EngineError::Value)?;
        serde_json::to_string(&json!([h, text])).unwrap_or_default()
    };
    let mut dismissed: Vec<String> = dismissed_candidates(db)
        .into_iter()
        .filter(|i| *i != key)
        .collect();
    if !restore {
        dismissed.push(key);
    }
    if dismissed.len() > CANDIDATES_MAX_DISMISSED {
        dismissed = dismissed[dismissed.len() - CANDIDATES_MAX_DISMISSED..].to_vec();
    }
    db.set_state(
        CANDIDATES_DISMISSED_KEY,
        &crate::secdb::python_json(&json!(dismissed)),
    )?;
    Ok(json!({"dismissed": dismissed}))
}

#[cfg(unix)]
fn stat_inode_size(path: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.ino(), m.size()))
}

#[cfg(not(unix))]
fn stat_inode_size(path: &str) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (1, m.len()))
}

// -- the collector thread -----------------------------------------------------------

/// What the collector and the API share. The live buffer, the request log
/// and the database are reachable without the engine's lock, so a search or
/// the live page never waits for a poll.
pub struct Shared {
    pub engine: Mutex<Engine>,
    pub decisions: Mutex<()>,
    pub alerts: Option<Arc<AlertClient>>,
    pub stop: Arc<AtomicBool>,
    pub lag_bytes: Arc<AtomicU64>,
    pub db: Arc<SecurityDatabase>,
    pub live: Option<Arc<Mutex<LiveBuffer>>>,
    pub requests: Arc<RwLock<Option<Arc<RequestLog>>>>,
    pub sigs: Arc<RwLock<Arc<SignatureEngine>>>,
    pub shipped: Mutex<Arc<SignatureEngine>>,
    pub overrides: Mutex<Value>,
    pub config: GuardConfig,
    pub token: String,
    pub request_log_path: String,
}

impl Shared {
    pub fn engine(&self) -> MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    pub fn flush_alerts(&self) {
        let batch = self.engine().take_pending_alerts();
        if batch.is_empty() {
            return;
        }
        let Some(alerts) = &self.alerts else { return };
        for a in batch {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            alerts.observe(&a.rule, &a.subject, a.active, &a.summary, &a.detail);
        }
    }

    fn merge_enforcer_deltas(&self, before: &Enforcer, after: &Enforcer) {
        let mut e = self.engine();
        e.enforcer.refused += after.refused.saturating_sub(before.refused);
        e.enforcer.applied += after.applied.saturating_sub(before.applied);
        e.enforcer.failed += after.failed.saturating_sub(before.failed);
        e.enforcer.lifted += after.lifted.saturating_sub(before.lifted);
    }

    pub fn continue_refill_step(&self) -> Option<Duration> {
        let (inode, boundary, horizon, log_file, live, sigs) = {
            let mut e = self.engine();
            let (inode, boundary, horizon) = e.refill_resume.take()?;
            let live = e.live.clone()?;
            if boundary == 0 || e.live_full() {
                return None;
            }
            (
                inode,
                boundary,
                horizon,
                e.config.log_file.clone(),
                live,
                e.sig(),
            )
        };
        if stat_inode_size(&log_file).map(|(i, _)| i) != Some(inode) {
            return None;
        }
        let started = Instant::now();
        let start = boundary.saturating_sub(LIVE_REFILL_CHUNK_BYTES);
        let Ok((records, reached_back, first)) =
            Engine::read_back_file(&log_file, &sigs, start, boundary, horizon)
        else {
            return None;
        };
        if let Some(first_ts) = records.first().map(|r| r.ts) {
            lock(&live).refill(records, if reached_back { horizon } else { first_ts });
        }
        if reached_back {
            return None;
        }
        let next = if first < boundary { first } else { start };
        self.engine().refill_resume = Some((inode, next, horizon));
        Some(started.elapsed().max(Duration::from_millis(50)))
    }

    fn ingest_log_detached(&self, now: i64, max_bytes: Option<usize>) -> Result<usize, String> {
        let (mut cursor, budget) = {
            let e = self.engine();
            let limit = max_bytes.unwrap_or(e.config.log_read_bytes_per_cycle);
            (e.cursor.clone(), limit)
        };
        let before = cursor.offset;
        let lines = cursor.read(budget);
        let delta = cursor.offset.saturating_sub(before) as usize;
        self.lag_bytes.store(cursor.lag_bytes, Ordering::Relaxed);
        let mut e = self.engine();
        e.cursor = cursor;
        e.cycle_bytes += delta;
        e.ingest_log_lines(&lines, now)
    }

    fn sync_shield_locked(&self, _decisions: &MutexGuard<'_, ()>, now: i64) -> Value {
        let (haproxy_socket, config_path, prev_status, wanted) = {
            let e = self.engine();
            let sigs = e.sig();
            let wanted = shield_entries(
                &e.enforcer.mode,
                e.shield_enabled,
                &e.detection.config.modes,
                &e.detection.config.exceptions,
                now,
                &sigs,
            );
            (
                e.shield.haproxy_socket.clone(),
                e.shield.config_path.clone(),
                e.shield.status.clone(),
                wanted,
            )
        };
        let status = match wanted {
            Ok(w) => {
                let mut detached = PathShield {
                    haproxy_socket,
                    config_path,
                    status: prev_status,
                };
                detached.sync(&w, now)
            }
            Err(err) => {
                let mut s = prev_status;
                s["active"] = json!(false);
                s["error"] = json!(err.chars().take(300).collect::<String>());
                s
            }
        };
        self.engine().shield.status = status.clone();
        status
    }

    pub fn set_shield(&self, enabled: &Value, now: Option<i64>) -> EResult<Value> {
        let Some(enabled) = enabled.as_bool() else {
            return Err(EngineError::Value("enabled must be true or false".into()));
        };
        let decisions = lock(&self.decisions);
        {
            let mut e = self.engine();
            e.db.set_state(SHIELD_ENABLED_KEY, if enabled { "1" } else { "0" })?;
            e.shield_enabled = enabled;
        }
        log_warn(&format!(
            "Path shield switched {}",
            if enabled { "on" } else { "off" }
        ));
        self.sync_shield_locked(&decisions, now.unwrap_or_else(utc_now));
        Ok(self.engine().shield_state())
    }

    fn settle_pending_decisions_locked(
        &self,
        _decisions: &MutexGuard<'_, ()>,
        now: i64,
    ) -> Result<(), String> {
        let pending = self.db.pending_decisions(now - DECISION_PENDING_GRACE)?;
        if pending.is_empty() {
            return Ok(());
        }
        let mut enforcer = self.engine().enforcer.clone();
        let before = enforcer.clone();
        let standing = match enforcer.active_bans() {
            Ok(s) => s,
            Err(e) => {
                log_warn(&format!(
                    "Could not read the ban table to settle decisions: {e}"
                ));
                return Ok(());
            }
        };
        let scheduled = self.db.scheduled_bans()?;
        let outcome = (|| -> Result<(), String> {
            for d in pending {
                let ip = d["ip"].as_str().unwrap_or("").to_string();
                let id = d["id"].as_i64().unwrap_or(0);
                let until = d["until"].as_i64().unwrap_or(0);
                let ts = d["ts"].as_i64().unwrap_or(0);
                let code = standing.get(&ip).copied();
                let adaptive =
                    code.is_some_and(|c| c == ADAPTIVE_BAN_CODE || c == ADAPTIVE_PAGE_CODE);
                if adaptive && !scheduled.contains_key(&ip) && until > now {
                    self.db.commit_ban(
                        id,
                        &ip,
                        until,
                        code.unwrap_or(ADAPTIVE_BAN_CODE),
                        ts,
                        &format!("score={} seconds={} [settled]", d["score"], until - ts),
                    )?;
                    log_warn(&format!("Recorded the ban on {ip} applied before a crash"));
                    continue;
                }
                if adaptive && !scheduled.contains_key(&ip) {
                    if let Err(e) = enforcer.lift(&ip) {
                        if e.ban_table_unsure() {
                            log_warn(&e.to_string());
                            continue;
                        }
                        return Err(e.to_string());
                    }
                }
                self.db.settle_decision(id, "abandoned")?;
            }
            Ok(())
        })();
        self.merge_enforcer_deltas(&before, &enforcer);
        outcome
    }

    fn apply_enforcement_locked(&self, decisions: &MutexGuard<'_, ()>, now: i64) -> EResult<Value> {
        let mut applied: Vec<String> = Vec::new();
        let mut lifted: Vec<String> = Vec::new();
        self.settle_pending_decisions_locked(decisions, now)?;
        let mut scheduled = self.db.scheduled_bans()?;
        let mut codes = self.db.scheduled_ban_codes()?;
        let (mut enforcer, ban_policy) = {
            let mut e = self.engine();
            e.enforcement_checked = 0;
            (e.enforcer.clone(), e.sink.ban_policy)
        };
        let before = enforcer.clone();
        let enforcing = enforcer.allowed();

        let result: EResult<Value> = (|| {
            for (ip, until) in scheduled.clone() {
                let served = until <= now;
                if enforcing && !served {
                    continue;
                }
                let taken_off = match enforcer.lift(&ip) {
                    Ok(t) => t,
                    Err(e) if e.ban_table_unsure() => {
                        log_warn(&format!("{e}; trying again next cycle"));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if taken_off {
                    lifted.push(ip.clone());
                    let code = codes
                        .get(&ip)
                        .copied()
                        .filter(|c| *c == ADAPTIVE_BAN_CODE || *c == ADAPTIVE_PAGE_CODE)
                        .unwrap_or(ADAPTIVE_BAN_CODE);
                    let mut e = self.engine();
                    e.sink.emit(
                        &ip,
                        EVENT_BAN_LIFTED,
                        now,
                        "guardd",
                        "",
                        "",
                        if enforcing {
                            "expired"
                        } else {
                            "enforcement disabled"
                        },
                        false,
                        Some(format!("{ip}|{EVENT_BAN_LIFTED}|{until}")),
                    )?;
                    e.db.record_decision(
                        &ip,
                        now,
                        "lifted",
                        if served { "expiry" } else { "mode" },
                        "applied",
                        Decision {
                            code,
                            until,
                            policy: ban_policy,
                            ..Default::default()
                        },
                    )?;
                }
                if served {
                    self.db.clear_ban(&ip)?;
                }
            }
            if !enforcing {
                let mut extra: Vec<String> = enforcer.adaptive_bans()?.into_keys().collect();
                extra.sort();
                for ip in extra {
                    if scheduled.contains_key(&ip) {
                        continue;
                    }
                    match enforcer.lift(&ip) {
                        Ok(true) => lifted.push(ip),
                        Ok(false) => {}
                        Err(e) if e.ban_table_unsure() => {
                            log_warn(&format!("{e}; trying again next cycle"))
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                self.engine().apply_promotions();
                return Ok(json!({"applied": applied, "lifted": lifted, "enforcing": false}));
            }
            let mut standing = enforcer.active_bans()?;
            for (ip, until) in &scheduled {
                if *until <= now || standing.contains_key(ip) {
                    continue;
                }
                let code = codes
                    .get(ip)
                    .copied()
                    .filter(|c| *c == ADAPTIVE_BAN_CODE || *c == ADAPTIVE_PAGE_CODE)
                    .unwrap_or(ADAPTIVE_BAN_CODE);
                if enforcer.ban(ip, code)? {
                    log_info(&format!("Re-asserted the ban on {ip}, gone from the table"));
                }
            }
            let (policy, pending, scan_after, mut scan_before) = {
                let mut e = self.engine();
                e.enforcement_checked = 0;
                let policy = e.scoring_policy();
                let pending = e
                    .sink
                    .queue
                    .batch(ENFORCEMENT_BATCH - ENFORCEMENT_SWEEP_RESERVE);
                if e.enforcement_scan_before == 0 {
                    e.enforcement_scan_before = now;
                }
                (
                    policy,
                    pending,
                    e.enforcement_scan_after.clone(),
                    e.enforcement_scan_before,
                )
            };

            let mut check_ip = |ip: &str,
                                scheduled: &mut BTreeMap<String, i64>,
                                codes: &mut BTreeMap<String, i64>,
                                standing: &mut HashMap<String, i64>,
                                applied: &mut Vec<String>|
             -> EResult<()> {
                let prep = {
                    let e = self.engine();
                    let row = e.reputation(ip, now, Some(&policy), Some(scheduled))?;
                    e.prepare_row_decision(&row, now, scheduled, codes, standing)?
                };
                if let Some(prep) = prep {
                    let banned = enforcer.ban(&prep.ip, prep.code)?;
                    let mut e = self.engine();
                    e.finish_row_decision(prep, banned, scheduled, codes, standing, applied)?;
                }
                Ok(())
            };

            let mut seen = HashSet::new();
            for (ip, generation) in &pending {
                seen.insert(ip.clone());
                self.engine().enforcement_checked += 1;
                check_ip(ip, &mut scheduled, &mut codes, &mut standing, &mut applied)?;
                self.engine().sink.queue.acknowledge(ip, *generation);
            }
            let allowance = (ENFORCEMENT_BATCH - pending.len()) as i64;
            let mut after = scan_after;
            let mut addresses =
                self.db
                    .enforcement_addresses((after.0, &after.1), scan_before, allowance)?;
            if addresses.is_empty() && after != (0, String::new()) {
                after = (0, String::new());
                scan_before = now;
                {
                    let mut e = self.engine();
                    e.enforcement_scan_after = after.clone();
                    e.enforcement_scan_before = scan_before;
                }
                addresses = self.db.enforcement_addresses((0, ""), now, allowance)?;
            }
            for (first_seen, ip) in &addresses {
                if !seen.contains(ip) {
                    self.engine().enforcement_checked += 1;
                    check_ip(ip, &mut scheduled, &mut codes, &mut standing, &mut applied)?;
                }
                after = (*first_seen, ip.clone());
                self.engine().enforcement_scan_after = after.clone();
            }
            if (addresses.len() as i64) < allowance {
                after = (0, String::new());
                scan_before = 0;
                let mut e = self.engine();
                e.enforcement_scan_after = after.clone();
                e.enforcement_scan_before = 0;
            }
            self.db.set_state(
                ENFORCEMENT_CURSOR_KEY,
                &crate::secdb::python_json(&json!({
                    "after": [after.0, after.1],
                    "before": scan_before,
                })),
            )?;
            {
                let mut e = self.engine();
                if !applied.is_empty() {
                    e.check_burst(applied.len(), now);
                }
                e.apply_promotions();
            }
            Ok(json!({"applied": applied, "lifted": lifted, "enforcing": true}))
        })();
        self.merge_enforcer_deltas(&before, &enforcer);
        result
    }

    pub fn apply_urgent_enforcement(&self, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        let _decisions = lock(&self.decisions);
        let (mut enforcer, policy, urgent_batch) = {
            let e = self.engine();
            if !e.enforcer.allowed() || !e.sink.queue.has_urgent() {
                return Ok(json!({"applied": [], "enforcing": e.enforcer.allowed()}));
            }
            (
                e.enforcer.clone(),
                e.scoring_policy(),
                e.sink.queue.urgent_batch(ENFORCEMENT_BATCH),
            )
        };
        let before = enforcer.clone();
        let result: EResult<Value> = (|| {
            let mut scheduled = self.db.scheduled_bans()?;
            let mut codes = self.db.scheduled_ban_codes()?;
            let mut standing = enforcer.active_bans()?;
            let mut applied = Vec::new();
            for (ip, generation) in urgent_batch {
                let prep = {
                    let e = self.engine();
                    let row = e.reputation(&ip, now, Some(&policy), Some(&scheduled))?;
                    e.prepare_row_decision(&row, now, &scheduled, &codes, &standing)?
                };
                if let Some(prep) = prep {
                    let banned = enforcer.ban(&prep.ip, prep.code)?;
                    let mut e = self.engine();
                    e.finish_row_decision(
                        prep,
                        banned,
                        &mut scheduled,
                        &mut codes,
                        &mut standing,
                        &mut applied,
                    )?;
                }
                self.engine().sink.queue.acknowledge(&ip, generation);
            }
            if !applied.is_empty() {
                let mut e = self.engine();
                e.fast_enforcements += applied.len() as u64;
                e.check_burst(applied.len(), now);
            }
            Ok(json!({"applied": applied, "enforcing": true}))
        })();
        self.merge_enforcer_deltas(&before, &enforcer);
        self.flush_alerts();
        result
    }

    pub fn place_manual_ban(&self, ip: &str, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        let checked = ip.trim().to_string();
        if !enforceable(&checked) {
            return Err(EngineError::Value(
                "only an IPv4 address can be banned".into(),
            ));
        }
        let _decisions = lock(&self.decisions);
        let (enforcer, haproxy_socket, ban_policy) = {
            let e = self.engine();
            (
                e.enforcer.clone(),
                e.config.haproxy_socket.clone(),
                e.sink.ban_policy,
            )
        };
        let mut remembered = true;
        let previous = self
            .db
            .manual_bans()
            .ok()
            .and_then(|m| m.get(&checked).copied());
        if let Err(e) =
            self.db
                .write_manual_ban(&checked, now, now + MANUAL_BAN_DEFAULT_SECONDS, now, 0)
        {
            remembered = false;
            log_warn(&format!(
                "Could not remember the manual ban on {checked}: {e}"
            ));
        }
        let put_back = |db: &SecurityDatabase| {
            if !remembered {
                return;
            }
            match previous {
                Some(p) => {
                    let _ = db.write_manual_ban(
                        &checked,
                        p.placed_at,
                        p.expires_at,
                        p.seen_at,
                        p.reasserted,
                    );
                }
                None => {
                    let _ = db.forget_manual_ban(&checked);
                }
            }
        };
        let placed = match enforcer.restore(&checked, MANUAL_BAN_CODE) {
            Ok(p) => p,
            Err(e) => {
                put_back(&self.db);
                return Err(EngineError::Refused(e.to_string()));
            }
        };
        if !placed {
            put_back(&self.db);
            return Err(EngineError::Refused(format!(
                "HAProxy refused the ban on {checked}"
            )));
        }
        let mut until = now + MANUAL_BAN_DEFAULT_SECONDS;
        if let Ok(rows) = read_table(&haproxy_socket, "tbl_ban", &format!("key {checked}")) {
            if let Some(fields) = rows.get(&checked) {
                let exp = field_int(fields, "exp");
                if exp > 0 {
                    until = now + exp / 1000;
                }
            }
        }
        let outcome = self
            .db
            .write_manual_ban(&checked, now, until, now, 0)
            .and_then(|_| {
                self.db.record_decision(
                    &checked,
                    now,
                    "applied",
                    "operator",
                    "applied",
                    Decision {
                        code: MANUAL_BAN_CODE,
                        until,
                        policy: ban_policy,
                        ..Default::default()
                    },
                )
            });
        if let Err(e) = outcome {
            remembered = false;
            log_warn(&format!(
                "Banned {checked} by hand, but could not remember it: {e}"
            ));
        }
        log_warn(&format!("Ban placed by hand on {checked} until {until}"));
        Ok(
            json!({"ok": true, "ip": checked, "code": MANUAL_BAN_CODE, "until": until, "remembered": remembered}),
        )
    }

    pub fn forget_ban(&self, ip: &str, now: Option<i64>) -> EResult<Value> {
        let now = now.unwrap_or_else(utc_now);
        let checked = ip.trim().to_string();
        if checked.is_empty() {
            return Err(EngineError::Value("an address is required".into()));
        }
        if checked.parse::<std::net::IpAddr>().is_err() {
            return Err(EngineError::Value("invalid IP address".into()));
        }
        let _decisions = lock(&self.decisions);
        let mut enforcer = self.engine().enforcer.clone();
        let before = enforcer.clone();
        let held = self
            .db
            .scheduled_bans()?
            .get(&checked)
            .copied()
            .unwrap_or(0);
        self.db.clear_ban(&checked)?;
        let manual = self.db.forget_manual_ban(&checked)?;
        let mut refused = String::new();
        let mut lifted = false;
        let mut released = false;
        let io_res: EResult<()> = (|| {
            match enforcer.lift(&checked) {
                Ok(l) => {
                    lifted = l;
                    match enforcer.release(&checked) {
                        Ok(r) => released = r,
                        Err(e) if e.ban_table_unsure() => {
                            refused = e.to_string();
                            log_warn(&refused);
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if e.ban_table_unsure() => {
                    refused = e.to_string();
                    log_warn(&refused);
                }
                Err(e) => return Err(e.into()),
            }
            Ok(())
        })();
        self.merge_enforcer_deltas(&before, &enforcer);
        io_res?;
        let mut e = self.engine();
        if held != 0 || lifted {
            e.sink.emit(
                &checked,
                EVENT_BAN_LIFTED,
                now,
                "operator",
                "",
                "",
                "cleared by hand",
                false,
                Some(format!("{checked}|{EVENT_BAN_LIFTED}|{now}")),
            )?;
            log_warn(&format!(
                "Ban on {checked} cleared by hand; the schedule is dropped"
            ));
        }
        let legacy = e.settle_legacy_observed(&checked);
        if held != 0 || lifted || manual || legacy != 0 {
            let code = if held != 0 || lifted {
                ADAPTIVE_BAN_CODE
            } else if manual {
                MANUAL_BAN_CODE
            } else {
                legacy
            };
            e.db.record_decision(
                &checked,
                now,
                "lifted",
                "operator",
                if refused.is_empty() {
                    "applied"
                } else {
                    "failed"
                },
                Decision {
                    code,
                    until: held,
                    policy: e.sink.ban_policy,
                    ..Default::default()
                },
            )?;
        }
        e.apply_promotions();
        Ok(json!({
            "ok": true,
            "refused": refused,
            "ip": checked,
            "was_scheduled": held != 0,
            "lifted": lifted || released,
            "cleared": refused.is_empty(),
        }))
    }

    pub fn set_mode(&self, mode: &str, now: Option<i64>) -> EResult<Value> {
        let mode = mode.trim().to_lowercase();
        if !SUPPORTED_MODES.contains(&mode.as_str()) {
            return Err(EngineError::Value(format!(
                "mode must be one of {}",
                SUPPORTED_MODES.join(", ")
            )));
        }
        let now = now.unwrap_or_else(utc_now);
        let decisions = lock(&self.decisions);
        let previous = {
            let mut e = self.engine();
            let prev = e.enforcer.mode.clone();
            e.db.set_state("mode_override", &mode)?;
            e.enforcer.mode = mode.clone();
            prev
        };
        log_warn(&format!(
            "Adaptive protection mode changed: {previous} -> {mode}"
        ));
        let mut result = self.apply_enforcement_locked(&decisions, now)?;
        self.sync_shield_locked(&decisions, now);
        self.flush_alerts();
        result["mode"] = json!(mode);
        result["previous"] = json!(previous);
        Ok(result)
    }

    pub fn run_maintenance(&self) -> Result<Value, String> {
        let now = utc_now();
        let (retention_days, longest_strike) = {
            let e = self.engine();
            (e.config.event_retention_days, e.longest_strike_retention())
        };
        let cutoff = now - retention_days * 86400;
        let ban_cutoff = cutoff.min(now - longest_strike);
        let mut deleted = self.db.apply_retention(cutoff, ban_cutoff)?;
        deleted.insert(
            "rate_warnings".into(),
            self.db.prune_rate_warnings(
                now - RATE_WARNINGS_KEEP_DAYS * 86400,
                RATE_WARNINGS_KEEP_ROWS,
            )?,
        );
        deleted.insert(
            "ban_decisions".into(),
            self.db
                .prune_decisions(ban_cutoff, DECISIONS_KEEP_ROWS, now)?,
        );
        if deleted.values().any(|v| *v != 0) {
            self.db.incremental_vacuum(256);
        }
        let (pruned, tracked) = {
            let mut e = self.engine();
            let pruned = e.memory.prune(now - 6 * 3600);
            e.sink.subnets.prune(now);
            e.candidates.prune(now - CANDIDATE_TTL);
            e.unknown_hosts.prune(now - UNKNOWN_HOSTS_TTL);
            e.detection.persist(now, true, &self.db)?;
            let _ =
                e.db.set_state(CANDIDATES_KEY, &e.candidates.snapshot(2000).to_string());
            let _ =
                e.db.set_state(UNKNOWN_HOSTS_KEY, &e.unknown_hosts.snapshot().to_string());
            (pruned, e.memory.len())
        };
        let ordered = [
            "events",
            "cooldowns",
            "addresses",
            "rate_warnings",
            "ban_decisions",
        ];
        let text = format!(
            "{{{}}}",
            ordered
                .iter()
                .map(|k| format!("\"{k}\": {}", deleted.get(*k).copied().unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        log_info(&format!(
            "Maintenance: deleted={text} pruned_ips={pruned} tracked={tracked}"
        ));
        Ok(json!({"deleted": deleted, "pruned_ips": pruned}))
    }

    fn poll_cycle(
        &self,
        tables: Result<(Tables, BTreeSet<String>), String>,
    ) -> Result<Value, String> {
        let now = utc_now();
        let (from_tables, budget) = {
            let mut e = self.engine();
            e.sink.exclusions.reload_files(false);
            e.refresh_ban_policy(now)?;
            let (tables, unreadable) = tables?;
            e.unreadable_tables = unreadable;
            let mut from_tables = e.ingest_tables(&tables, now)?;
            from_tables += e.ingest_hard_floor(now)?;
            let budget = (64 * 1024).max(
                e.config
                    .log_read_bytes_per_cycle
                    .saturating_sub(e.cycle_bytes),
            );
            (from_tables, budget)
        };
        let from_log = self.ingest_log_detached(now, Some(budget))?;
        self.engine().flush_rate_warnings(now, from_log == 0);
        let decisions = lock(&self.decisions);
        let enforcement = self
            .apply_enforcement_locked(&decisions, now)
            .map_err(|e| e.to_string())?;
        {
            let e = self.engine();
            e.db.set_state(
                "log_cursor",
                &crate::secdb::python_json(&cursor_state(&e.cursor)),
            )?;
        }
        self.sync_shield_locked(&decisions, now);
        drop(decisions);
        {
            let mut e = self.engine();
            e.weekly_summary_tick(Some(now));
            let Engine {
                login_correlations,
                sink,
                detection,
                db,
                ..
            } = &mut *e;
            login_correlations.poll(now, &sink.exclusions, detection, db)?;
            detection.persist(now, false, db)?;
            e.polls_total += 1;
            e.last_poll_ts = Some(now);
            e.consecutive_failures = 0;
            e.last_error = None;
        }
        Ok(json!({
            "table_events": from_tables,
            "log_lines": from_log,
            "banned": enforcement["applied"].as_array().map(Vec::len).unwrap_or(0),
            "lifted": enforcement["lifted"].as_array().map(Vec::len).unwrap_or(0),
        }))
    }
}

fn sleep_unless_stopped(stop: &AtomicBool, d: Duration) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if stop.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep((end - Instant::now()).min(Duration::from_millis(200)));
    }
    stop.load(Ordering::SeqCst)
}

/// The collector loop (Python `GuardEngine._run`).
pub fn run(shared: Arc<Shared>) {
    let (interval, maintenance_every, read_budget, running) = {
        let mut e = shared.engine();
        let refilled = e.refill_live(utc_now_f());
        if refilled > 0 {
            log_info(&format!(
                "Live activity: {refilled} requests from before the start read back"
            ));
        }
        (
            e.config.poll_interval_seconds.max(1) as f64,
            e.config.maintenance_interval_seconds as f64,
            e.config.log_read_bytes_per_cycle,
            e.running.clone(),
        )
    };
    running.store(true, Ordering::SeqCst);
    // The rest of the read-back, a piece at a time, with the engine free in between.
    let refill = {
        let bg = shared.clone();
        std::thread::spawn(move || {
            let mut added = 0usize;
            loop {
                if bg.stop.load(Ordering::SeqCst) {
                    break;
                }
                let wait = bg.continue_refill_step();
                match wait {
                    Some(d) => {
                        added += 1;
                        if sleep_unless_stopped(&bg.stop, d) {
                            break;
                        }
                    }
                    None => break,
                }
            }
            if added > 0 {
                log_info("Live activity: older requests read back from the log");
            }
        })
    };
    let mut next_maintenance = Instant::now() + Duration::from_secs_f64(maintenance_every);
    while !shared.stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let tables = Engine::read_tables(&shared.config.haproxy_socket, &shared.stop);
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        match shared.poll_cycle(tables) {
            Ok(_) => {}
            Err(err) => {
                let n = {
                    let mut e = shared.engine();
                    e.consecutive_failures += 1;
                    e.last_error = Some(err.clone());
                    e.consecutive_failures
                };
                if n == 1 || n == 10 || n.is_multiple_of(60) {
                    log_warn(&format!("Poll failed ({n} in a row): {err}"));
                }
            }
        }
        shared.engine().report_failing();
        shared.flush_alerts();
        if Instant::now() >= next_maintenance {
            if let Err(err) = shared.run_maintenance() {
                log_warn(&format!("Maintenance pass failed: {err}"));
            }
            next_maintenance = Instant::now() + Duration::from_secs_f64(maintenance_every);
        }
        let deadline = started + Duration::from_secs_f64(interval);
        let tick = FAST_REACTION_TICK_SECONDS.min(LIVE_FAST_TICK_SECONDS);
        loop {
            if shared.stop.load(Ordering::SeqCst) {
                break;
            }
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64();
            if remaining <= 0.25 {
                break;
            }
            if sleep_unless_stopped(&shared.stop, Duration::from_secs_f64(tick.min(remaining))) {
                break;
            }
            let allowance = {
                let e = shared.engine();
                let live_watching = e.live.as_ref().is_some_and(|l| lock(l).wanted());
                if !live_watching && !e.cursor.has_pending() {
                    continue;
                }
                let share =
                    (64 * 1024).max((read_budget as f64 * tick / interval.max(1.0)) as usize);
                share.min(read_budget.saturating_sub(e.cycle_bytes))
            };
            if allowance > 0 {
                let now_tick = utc_now();
                let _ = shared.ingest_log_detached(now_tick, Some(allowance));
                let urgent = {
                    let e = shared.engine();
                    e.enforcer.allowed() && e.sink.queue.has_urgent()
                };
                if urgent {
                    let _ = shared.apply_urgent_enforcement(Some(now_tick));
                }
            }
        }
        shared.engine().cycle_bytes = 0;
    }
    let _ = refill.join();
    running.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_check_stays_queued_and_invalid_unban_is_rejected() {
        let db = Arc::new(SecurityDatabase::open(":memory:").unwrap());
        let mut engine = Engine::new(
            GuardConfig::default(),
            db,
            Arc::new(RwLock::new(Arc::new(SignatureEngine::builtin()))),
            None,
            Arc::new(RwLock::new(None)),
        );
        assert!(matches!(
            engine.forget_ban("not an address", Some(1)),
            Err(EngineError::Value(_))
        ));
        engine.sink.queue.mark("192.0.2.1", false);
        engine.sink.queue.mark("192.0.2.2", false);
        let result = engine.visit_enforcement_checks(1, |_, ip| {
            if ip == "192.0.2.2" {
                Err(EngineError::Other("decision unavailable".into()))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        let retry = engine.sink.queue.batch(10);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].0, "192.0.2.2");
    }
}
