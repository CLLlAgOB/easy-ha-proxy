//! Contextual detection, login correlations, catch-all pages, signature
//! candidates and unknown host names (Python `guardd.tracking`, the parts
//! beyond the per-IP memory and the log cursor).

use crate::constants::{
    address_key, default_weight, detection_host, is_served, CANDIDATE_MAX_ADDRESSES,
    CANDIDATE_MAX_PATHS, CANDIDATE_MAX_PATH_LENGTH, CANDIDATE_MAX_SERVED, CANDIDATE_MIN_ADDRESSES,
    CATCH_ALL_MAX_HOSTS, CATCH_ALL_MAX_SIZES, CATCH_ALL_MIN_PATHS, ENUMERATION_STATUSES,
    EVENT_LOW_AND_SLOW, EVENT_MASS_ENUM, EVENT_NOT_FOUND_ENUM, EVENT_QUERY_INJECTION,
    EVENT_RECURRING, EVENT_SCANNER_DECISIVE, EVENT_SCANNER_MULTI, EVENT_SCANNER_PATH,
    EVENT_SUBNET_CAMPAIGN, EVENT_WIDE_ENUM, LOW_AND_SLOW_MIN_CATEGORIES, LOW_AND_SLOW_MIN_HITS,
    LOW_AND_SLOW_WINDOW, MASS_ENUM_MIN, MULTI_CATEGORY_MIN, MULTI_CATEGORY_WINDOW,
    NOT_FOUND_MIN_DISTINCT, NOT_FOUND_WINDOW, RECURRING_GAP, RECURRING_WINDOW,
    SUBNET_CAMPAIGN_MIN_IPS, SUBNET_CAMPAIGN_WINDOW, UNKNOWN_HOSTS_MAX, WIDE_ENUM_MIN,
    WIDE_ENUM_WINDOW,
};
use crate::parser::ParsedRequest;
use crate::scoring::{ExclusionModel, ScoringPolicy};
use crate::secdb::SecurityDatabase;
use crate::signatures::{
    classify_raw_path, is_asset, is_proto_ua_mismatch, is_unusual_method_probe, normalize_path,
    SignatureEngine,
};
use crate::tracking::{hash32, LogCursor};
use hashlink::LinkedHashMap;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

pub const DETECTION_CONFIG_KEY: &str = "detection_context_v1";
pub const DETECTION_STATS_KEY: &str = "detection_observations_v1";
pub const DETECTION_SLOW_KEY: &str = "detection_slow_v1";
pub const DETECTION_MAX_RULES: usize = 128;
pub const DETECTION_MAX_EXCEPTIONS: usize = 128;
pub const DETECTION_MAX_TRACKED: usize = 256;
pub const DETECTION_MAX_STATS: usize = 128;
pub const DETECTION_TTL: i64 = 24 * 3600;
pub const LOGIN_CORRELATIONS_KEY: &str = "detection_login_correlations_v1";

pub const DETECTION_NEW_RULES: [(&str, &str); 7] = [
    (
        "observe:sql-injection",
        "SQL query structure in a parameter; observation by default",
    ),
    (
        "observe:script-injection",
        "Script or event-handler markup in a parameter; observation by default",
    ),
    (
        "observe:encoded-sensitive-path",
        "A sensitive path appears after a second decode; observation by default",
    ),
    (
        "observe:service-api-probe",
        "Container, cloud metadata or diagnostic API route; observation by default",
    ),
    (
        "observe:proto-ua-mismatch",
        "Modern browser User-Agent over HTTP/1.0; observation by default",
    ),
    (
        "observe:unusual-method-probe",
        "Unusual or WebDAV HTTP method outside the host profile; observation by default",
    ),
    (
        "behavior:slow-enumeration",
        "24 distinct missing paths, 90% failures, three half-hour windows within six hours",
    ),
];
pub const DETECTION_WARNING_RULES: [(&str, &str); 3] = [
    (
        "auth:credential-spray",
        "Ten different usernames from one IP within fifteen minutes; warning only",
    ),
    (
        "auth:distributed-login",
        "Ten different IPs target one username within fifteen minutes; warning only",
    ),
    (
        "auth:failed-login-burst",
        "Twenty failed first-factor logins from one IP within fifteen minutes; warning only",
    ),
];

pub fn detection_profiles() -> Value {
    json!({
        "web": {"methods": ["GET", "HEAD", "POST"], "routes": []},
        "api": {"methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], "routes": ["/api"]},
        "webdav": {"methods": ["PROPFIND", "PROPPATCH", "REPORT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"],
                   "routes": ["/remote.php/dav", "/ocs/v2.php", "/.well-known"]},
        "1c": {"methods": ["GET", "POST", "OPTIONS"], "routes": []},
        "docker": {"methods": ["GET", "POST", "DELETE"], "routes": ["/v1.47", "/containers", "/images", "/info", "/version", "/v2"]},
    })
}

fn is_new_rule(name: &str) -> bool {
    DETECTION_NEW_RULES.iter().any(|(n, _)| *n == name)
}

fn is_warning_rule(name: &str) -> bool {
    DETECTION_WARNING_RULES.iter().any(|(n, _)| *n == name)
}

fn rx(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

// ---------------------------------------------------------------------------
// Catch-all pages
// ---------------------------------------------------------------------------

/// Per host: response sizes that several scanner paths all received.
type SizesSeen = Vec<(u64, BTreeSet<u32>)>;

#[derive(Debug, Default)]
pub struct CatchAllPages {
    hosts: Vec<(String, SizesSeen)>,
}

impl CatchAllPages {
    pub fn known(&self, host: &str, size: u64) -> bool {
        self.hosts
            .iter()
            .find(|(h, _)| h == host)
            .and_then(|(_, sizes)| sizes.iter().find(|(s, _)| *s == size))
            .is_some_and(|(_, seen)| seen.len() >= CATCH_ALL_MIN_PATHS)
    }

    pub fn is_catch_all(&mut self, host: &str, size: u64, path: &str) -> bool {
        let pos = match self.hosts.iter().position(|(h, _)| h == host) {
            Some(p) => p,
            None => {
                self.hosts.push((host.to_string(), Vec::new()));
                while self.hosts.len() > CATCH_ALL_MAX_HOSTS {
                    self.hosts.remove(0);
                }
                self.hosts.len() - 1
            }
        };
        let entry = self.hosts.remove(pos);
        self.hosts.push(entry);
        let sizes = &mut self.hosts.last_mut().expect("just pushed").1;
        let spos = match sizes.iter().position(|(s, _)| *s == size) {
            Some(p) => p,
            None => {
                sizes.push((size, BTreeSet::new()));
                while sizes.len() > CATCH_ALL_MAX_SIZES {
                    sizes.remove(0);
                }
                sizes.len() - 1
            }
        };
        let item = sizes.remove(spos);
        sizes.push(item);
        let seen = &mut sizes.last_mut().expect("just pushed").1;
        if seen.len() < CATCH_ALL_MIN_PATHS {
            seen.insert(hash32(path));
        }
        seen.len() >= CATCH_ALL_MIN_PATHS
    }
}

// ---------------------------------------------------------------------------
// Contextual detection settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Scope {
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub matcher: String,
    pub value: String,
    pub statuses: Vec<u16>,
}

impl Scope {
    fn matches(&self, request: &ParsedRequest) -> bool {
        let host = request.host.to_lowercase();
        let host = host.trim_end_matches('.');
        if !self.hosts.iter().any(|h| h == host) {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.contains(&request.method) {
            return false;
        }
        if !self.statuses.is_empty() && !self.statuses.contains(&request.status) {
            return false;
        }
        let path = request.path.as_str();
        match self.matcher.as_str() {
            "exact" => path == self.value,
            "segment" => path.split('/').any(|s| s == self.value),
            _ => path == self.value || path.starts_with(&format!("{}/", self.value)),
        }
    }

    fn to_json(&self, into: &mut Map<String, Value>) {
        into.insert("hosts".into(), json!(self.hosts));
        into.insert("methods".into(), json!(self.methods));
        into.insert("match".into(), json!(self.matcher));
        into.insert("value".into(), json!(self.value));
        into.insert("statuses".into(), json!(self.statuses));
    }
}

fn detection_scope(row: &Map<String, Value>) -> Result<Scope, String> {
    let hosts = row.get("hosts").and_then(Value::as_array);
    let Some(hosts) = hosts.filter(|h| (1..=8).contains(&h.len())) else {
        return Err("choose one to eight exact host names".into());
    };
    let methods = match row.get("methods") {
        None => Vec::new(),
        Some(Value::Array(m)) if m.len() <= 16 => m.clone(),
        _ => return Err("expected at most sixteen methods".into()),
    };
    static METHOD: OnceLock<Regex> = OnceLock::new();
    let mut method_list = Vec::new();
    for m in &methods {
        match m.as_str() {
            Some(s) if rx(&METHOD, r"^[A-Z]{3,16}$").is_match(s) => method_list.push(s.to_string()),
            _ => return Err("expected uppercase HTTP methods".into()),
        }
    }
    let statuses = match row.get("statuses") {
        None => Vec::new(),
        Some(Value::Array(s)) if s.len() <= 16 => s.clone(),
        _ => return Err("expected at most sixteen HTTP status codes".into()),
    };
    let mut status_list = Vec::new();
    for s in &statuses {
        match s.as_i64() {
            Some(n) if s.is_i64() || s.is_u64() => {
                if !(100..=599).contains(&n) {
                    return Err("expected at most sixteen HTTP status codes".into());
                }
                status_list.push(n as u16);
            }
            _ => return Err("expected at most sixteen HTTP status codes".into()),
        }
    }
    let matcher = match row.get("match") {
        None => "exact".to_string(),
        Some(Value::String(s)) if ["exact", "prefix", "segment"].contains(&s.as_str()) => s.clone(),
        _ => return Err("match must be exact, prefix or segment".into()),
    };
    let value = match row.get("value").and_then(Value::as_str) {
        Some(v)
            if (1..=200).contains(&v.chars().count())
                && !v
                    .chars()
                    .any(|c| "?#%\\ ".contains(c) || (c as u32) < 32 || c as u32 == 127) =>
        {
            v.to_string()
        }
        _ => return Err("expected a plain path without parameters or escapes".into()),
    };
    if matcher == "segment" {
        if value.contains('/') || value == "." || value == ".." {
            return Err("expected one path segment".into());
        }
    } else if !value.starts_with('/') || normalize_path(&value) != value {
        return Err("expected a canonical path starting with a slash".into());
    }
    if matcher == "prefix" && value == "/" {
        return Err("a prefix must name a route".into());
    }
    let mut host_set = BTreeSet::new();
    for h in hosts {
        let Some(s) = h.as_str() else {
            return Err("expected a host name without a port".into());
        };
        host_set.insert(detection_host(s)?);
    }
    let method_set: BTreeSet<String> = method_list.into_iter().collect();
    let status_set: BTreeSet<u16> = status_list.into_iter().collect();
    let trimmed = value.trim_end_matches('/');
    Ok(Scope {
        hosts: host_set.into_iter().collect(),
        methods: method_set.into_iter().collect(),
        matcher,
        value: if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        },
        statuses: status_set.into_iter().collect(),
    })
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub scope: Scope,
    pub category: String,
    pub mode: String,
}

#[derive(Debug, Clone)]
pub struct RuleException {
    pub id: String,
    pub rule: String,
    pub scope: Scope,
    pub reason: String,
    pub expires: i64,
}

/// The validated settings document plus its lookup indexes.
#[derive(Debug, Clone, Default)]
pub struct DetectionSettings {
    pub revision: i64,
    pub rules: Vec<CustomRule>,
    pub exceptions: Vec<RuleException>,
    pub modes: BTreeMap<String, String>,
    pub profiles: BTreeMap<String, String>,
    rules_by_host: HashMap<String, Vec<usize>>,
    exceptions_by_scope: HashMap<(String, String), Vec<usize>>,
}

impl DetectionSettings {
    fn index(mut self) -> Self {
        self.rules_by_host.clear();
        self.exceptions_by_scope.clear();
        for (i, row) in self.rules.iter().enumerate() {
            for host in &row.scope.hosts {
                self.rules_by_host.entry(host.clone()).or_default().push(i);
            }
        }
        for (i, row) in self.exceptions.iter().enumerate() {
            for host in &row.scope.hosts {
                self.exceptions_by_scope
                    .entry((row.rule.clone(), host.clone()))
                    .or_default()
                    .push(i);
            }
        }
        self
    }

    pub fn to_json(&self) -> Value {
        let rules: Vec<Value> = self
            .rules
            .iter()
            .map(|r| {
                let mut m = Map::new();
                m.insert("id".into(), json!(r.id));
                r.scope.to_json(&mut m);
                m.insert("category".into(), json!(r.category));
                m.insert("mode".into(), json!(r.mode));
                Value::Object(m)
            })
            .collect();
        let exceptions: Vec<Value> = self
            .exceptions
            .iter()
            .map(|r| {
                let mut m = Map::new();
                m.insert("id".into(), json!(r.id));
                m.insert("rule".into(), json!(r.rule));
                r.scope.to_json(&mut m);
                m.insert("reason".into(), json!(r.reason));
                m.insert("expires".into(), json!(r.expires));
                Value::Object(m)
            })
            .collect();
        json!({
            "version": 1,
            "revision": self.revision,
            "rules": rules,
            "exceptions": exceptions,
            "modes": self.modes,
            "profiles": self.profiles,
        })
    }

    pub fn mode(&self, rule: &str) -> Option<&str> {
        self.modes.get(rule).map(String::as_str)
    }
}

pub fn builtin_detection_ids(sigs: &SignatureEngine) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for c in sigs.path_categories() {
        ids.insert(format!("path:{c}"));
    }
    for q in sigs.query_rule_names() {
        ids.insert(format!("query:{q}"));
    }
    for (token, _) in sigs.user_agents() {
        ids.insert(format!("ua:{token}"));
    }
    ids.insert("raw:path-traversal".into());
    for (n, _) in DETECTION_NEW_RULES {
        ids.insert(n.to_string());
    }
    for (n, _) in DETECTION_WARNING_RULES {
        ids.insert(n.to_string());
    }
    ids
}

pub fn validate_detection_config(
    data: &Value,
    sigs: &SignatureEngine,
) -> Result<DetectionSettings, String> {
    let Some(obj) = data.as_object() else {
        return Err("expected detection configuration version 1".into());
    };
    let version_ok = obj
        .get("version")
        .is_some_and(|v| (v.is_i64() || v.is_u64()) && v.as_i64() == Some(1));
    if !version_ok {
        return Err("expected detection configuration version 1".into());
    }
    let empty_list = Value::Array(Vec::new());
    let empty_obj = Value::Object(Map::new());
    let rules = obj.get("rules").unwrap_or(&empty_list);
    let exceptions = obj.get("exceptions").unwrap_or(&empty_list);
    let modes = obj.get("modes").unwrap_or(&empty_obj);
    let profiles = obj.get("profiles").unwrap_or(&empty_obj);
    let Some(rules) = rules.as_array().filter(|r| r.len() <= DETECTION_MAX_RULES) else {
        return Err("too many contextual rules".into());
    };
    let Some(exceptions) = exceptions
        .as_array()
        .filter(|r| r.len() <= DETECTION_MAX_EXCEPTIONS)
    else {
        return Err("too many exceptions".into());
    };
    let Some(modes) = modes.as_object().filter(|m| m.len() <= DETECTION_MAX_RULES) else {
        return Err("too many rule modes".into());
    };
    static RULE_ID: OnceLock<Regex> = OnceLock::new();
    static EXC_ID: OnceLock<Regex> = OnceLock::new();
    static SUPPORTED: OnceLock<Regex> = OnceLock::new();
    let categories: HashSet<String> = sigs.path_categories();
    let mut checked = Vec::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for row in rules {
        let Some(row) = row.as_object() else {
            return Err("expected a stable custom rule identifier".into());
        };
        let id = row.get("id").map(value_text).unwrap_or_default();
        if !rx(&RULE_ID, r"^custom:[a-z0-9-]{1,48}$").is_match(&id) {
            return Err("expected a stable custom rule identifier".into());
        }
        if !ids.insert(id.clone()) {
            return Err("duplicate rule identifier".into());
        }
        let category = match row.get("category") {
            None => "custom".to_string(),
            Some(Value::String(c)) if c == "custom" || categories.contains(c) => c.clone(),
            _ => return Err("unknown category".into()),
        };
        let mode = match row.get("mode") {
            None => "observe".to_string(),
            Some(Value::String(m)) if m == "observe" || m == "enforce" => m.clone(),
            _ => return Err("mode must be observe or enforce".into()),
        };
        checked.push(CustomRule {
            id,
            scope: detection_scope(row)?,
            category,
            mode,
        });
    }
    let mut known = builtin_detection_ids(sigs);
    known.extend(ids.iter().cloned());
    let supported_id =
        |value: &Value| -> bool {
            match value.as_str() {
                Some(s) => known.contains(s)
                    || rx(
                        &SUPPORTED,
                        r"^(?:path|query|ua|raw|observe|behavior|auth):[A-Za-z0-9_. /+:-]{1,100}$",
                    )
                    .is_match(s),
                None => false,
            }
        };
    let mut mode_map = BTreeMap::new();
    for (k, v) in modes {
        let ok_mode = matches!(v.as_str(), Some("observe") | Some("enforce"));
        if !supported_id(&Value::String(k.clone())) || !ok_mode {
            return Err("unknown rule or mode".into());
        }
        mode_map.insert(k.clone(), v.as_str().unwrap_or("observe").to_string());
    }
    if mode_map
        .iter()
        .any(|(k, v)| v == "enforce" && (is_warning_rule(k) || k.starts_with("auth:")))
    {
        return Err("login correlations are warning-only".into());
    }
    let mut exclusions = Vec::new();
    let mut exclusion_ids = BTreeSet::new();
    for row in exceptions {
        let Some(row) = row.as_object() else {
            return Err("expected an exception identifier".into());
        };
        let id = row.get("id").map(value_text).unwrap_or_default();
        if !rx(&EXC_ID, r"^exception:[a-z0-9-]{1,48}$").is_match(&id) {
            return Err("expected an exception identifier".into());
        }
        let rule_val = row.get("rule").cloned().unwrap_or(Value::Null);
        if exclusion_ids.contains(&id) || !supported_id(&rule_val) {
            return Err("duplicate exception or unknown rule".into());
        }
        let reason = match row.get("reason").and_then(Value::as_str) {
            Some(r) if (3..=200).contains(&r.trim().chars().count()) => r.trim().to_string(),
            _ => return Err("an exception needs a reason of 3 to 200 characters".into()),
        };
        let expires = match row.get("expires") {
            None => 0,
            Some(v) if v.is_i64() || v.is_u64() => {
                let n = v.as_i64().unwrap_or(-1);
                if !(0..=4_102_444_800).contains(&n) {
                    return Err("expected an expiry timestamp or zero".into());
                }
                n
            }
            _ => return Err("expected an expiry timestamp or zero".into()),
        };
        exclusion_ids.insert(id.clone());
        exclusions.push(RuleException {
            id,
            rule: rule_val.as_str().unwrap_or("").to_string(),
            scope: detection_scope(row)?,
            reason,
            expires,
        });
    }
    let profile_names = ["web", "api", "webdav", "1c", "docker"];
    let Some(profiles) = profiles.as_object() else {
        return Err("unknown site profile or too many sites".into());
    };
    if profiles.len() > 64
        || profiles
            .values()
            .any(|v| !v.as_str().is_some_and(|s| profile_names.contains(&s)))
    {
        return Err("unknown site profile or too many sites".into());
    }
    let revision = match obj.get("revision") {
        None => 0,
        Some(v) if v.is_i64() || v.is_u64() => {
            let n = v.as_i64().unwrap_or(-1);
            if !(0..(1i64 << 53)).contains(&n) {
                return Err("invalid settings revision".into());
            }
            n
        }
        _ => return Err("invalid settings revision".into()),
    };
    let mut profile_map = BTreeMap::new();
    for (k, v) in profiles {
        profile_map.insert(detection_host(k)?, v.as_str().unwrap_or("web").to_string());
    }
    Ok(DetectionSettings {
        revision,
        rules: checked,
        exceptions: exclusions,
        modes: mode_map,
        profiles: profile_map,
        ..Default::default()
    }
    .index())
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Detection context
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StatRow {
    first: i64,
    last: i64,
    hits: i64,
    trusted: i64,
    excepted: i64,
    observe: i64,
    enforce: i64,
    ips: BTreeSet<u32>,
    hosts: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Default)]
struct SlowBucket {
    missing: i64,
    total: i64,
    good: i64,
    paths: Vec<u32>,
}

#[derive(Debug, Clone)]
struct SlowEntry {
    last: i64,
    buckets: BTreeMap<i64, SlowBucket>,
}

/// One match of a request against the detection rules.
#[derive(Debug, Clone)]
pub struct DetectionMatch {
    pub id: String,
    pub category: String,
    pub action: String,
    pub exception: String,
    pub event_type: String,
    pub points: i64,
}

impl DetectionMatch {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "category": self.category,
            "action": self.action,
            "exception": self.exception,
            "event_type": self.event_type,
            "points": self.points,
        })
    }
}

/// One bounded, non-scoring observation store; settings swap atomically.
#[derive(Debug)]
pub struct DetectionContext {
    pub config: DetectionSettings,
    stats: Vec<(String, StatRow)>,
    slow: Vec<((String, String), SlowEntry)>,
    pub evictions: u64,
    pub state_errors: u64,
    pub last_saved: i64,
}

impl DetectionContext {
    pub fn new(database: &SecurityDatabase, sigs: &SignatureEngine, now: i64) -> Self {
        let mut ctx = Self {
            config: DetectionSettings::default(),
            stats: Vec::new(),
            slow: Vec::new(),
            evictions: 0,
            state_errors: 0,
            last_saved: 0,
        };
        let raw = database.get_state(DETECTION_CONFIG_KEY, "");
        if !raw.is_empty() {
            match serde_json::from_str::<Value>(&raw)
                .map_err(|e| e.to_string())
                .and_then(|v| validate_detection_config(&v, sigs))
            {
                Ok(cfg) => ctx.config = cfg,
                Err(_) => ctx.state_errors += 1,
            }
        }
        let mut known = builtin_detection_ids(sigs);
        known.extend(ctx.config.rules.iter().map(|r| r.id.clone()));
        for row in ctx.saved_rows(database, DETECTION_STATS_KEY, DETECTION_MAX_STATS) {
            match restore_stat(&row, &known, now) {
                Ok(Some((name, stat))) => ctx.stats.push((name, stat)),
                Ok(None) => {}
                Err(()) => ctx.state_errors += 1,
            }
        }
        for row in ctx.saved_rows(database, DETECTION_SLOW_KEY, DETECTION_MAX_TRACKED) {
            match restore_slow(&row, now) {
                Ok(Some((key, entry))) => ctx.slow.push((key, entry)),
                Ok(None) => {}
                Err(()) => ctx.state_errors += 1,
            }
        }
        ctx
    }

    fn saved_rows(&mut self, database: &SecurityDatabase, key: &str, limit: usize) -> Vec<Value> {
        match serde_json::from_str::<Value>(&database.get_state(key, "[]")) {
            Ok(Value::Array(rows)) => rows.into_iter().take(limit).collect(),
            _ => {
                self.state_errors += 1;
                Vec::new()
            }
        }
    }

    pub fn replace(
        &mut self,
        data: &Value,
        database: &SecurityDatabase,
        sigs: &SignatureEngine,
    ) -> Result<(), String> {
        let mut checked = validate_detection_config(data, sigs)?;
        if checked.revision != self.config.revision {
            return Err("settings changed; reload before saving".into());
        }
        checked.revision += 1;
        let reset_slow = checked
            .mode("behavior:slow-enumeration")
            .unwrap_or("observe")
            == "enforce"
            && self
                .config
                .mode("behavior:slow-enumeration")
                .unwrap_or("observe")
                != "enforce";
        let mut states: Vec<(String, String)> =
            vec![(DETECTION_CONFIG_KEY.into(), checked.to_json().to_string())];
        if reset_slow {
            states.push((DETECTION_SLOW_KEY.into(), "[]".into()));
        }
        database.set_states(&states)?;
        if reset_slow {
            self.slow.clear();
        }
        self.config = checked;
        Ok(())
    }

    /// The configured action for a rule on this request: an exception first,
    /// then the mode, then `default`.
    pub fn action(
        &self,
        rule: &str,
        request: &ParsedRequest,
        now: i64,
        default: &str,
    ) -> (String, String) {
        let host = request.host.to_lowercase();
        let host = host.trim_end_matches('.').to_string();
        if let Some(list) = self
            .config
            .exceptions_by_scope
            .get(&(rule.to_string(), host))
        {
            for &i in list {
                let exc = &self.config.exceptions[i];
                if exc.rule == rule
                    && (exc.expires == 0 || exc.expires > now)
                    && exc.scope.matches(request)
                {
                    return ("excepted".into(), exc.id.clone());
                }
            }
        }
        (
            self.config.mode(rule).unwrap_or(default).to_string(),
            String::new(),
        )
    }

    pub fn inspect(
        &mut self,
        request: &ParsedRequest,
        now: i64,
        trusted: bool,
        record: bool,
        catch_all: bool,
        sigs: &SignatureEngine,
    ) -> Vec<DetectionMatch> {
        let mut found: Vec<(String, String, &'static str, &'static str)> = Vec::new();
        let decisive_event = |c: &str| {
            if sigs.category_is_decisive(c) {
                EVENT_SCANNER_DECISIVE
            } else {
                EVENT_SCANNER_PATH
            }
        };
        let category = sigs.classify_path(&request.path).to_string();
        if !category.is_empty()
            && (sigs.category_is_decisive(&category) || !is_served(request.status) || catch_all)
        {
            found.push((
                format!("path:{category}"),
                category.clone(),
                "enforce",
                decisive_event(&category),
            ));
        }
        if !request.query_flag.is_empty() {
            found.push((
                format!("query:{}", request.query_flag),
                request.query_flag.clone(),
                "enforce",
                EVENT_QUERY_INJECTION,
            ));
        }
        if !request.path_flag.is_empty() {
            found.push((
                "raw:path-traversal".into(),
                request.path_flag.clone(),
                "enforce",
                EVENT_SCANNER_DECISIVE,
            ));
        }
        let (agent, agent_category) = sigs.classify_user_agent(&request.user_agent);
        if !agent.is_empty() {
            found.push((
                format!("ua:{agent}"),
                agent_category.to_string(),
                "enforce",
                decisive_event(agent_category),
            ));
        }
        for name in &request.observation_flags {
            if is_new_rule(name) {
                let event = match name.as_str() {
                    "observe:service-api-probe" => EVENT_SCANNER_PATH,
                    "observe:encoded-sensitive-path" => EVENT_SCANNER_DECISIVE,
                    _ => EVENT_QUERY_INJECTION,
                };
                let short = name
                    .split_once(':')
                    .map(|(_, b)| b)
                    .unwrap_or("")
                    .to_string();
                found.push((name.clone(), short, "observe", event));
            }
        }
        if is_proto_ua_mismatch(&request.protocol, &request.user_agent) {
            found.push((
                "observe:proto-ua-mismatch".into(),
                "proto-ua-mismatch".into(),
                "observe",
                EVENT_SCANNER_PATH,
            ));
        }
        let host_key = request
            .host
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        let profile = self
            .config
            .profiles
            .get(&host_key)
            .map(String::as_str)
            .unwrap_or("web");
        if is_unusual_method_probe(&request.method, profile) {
            found.push((
                "observe:unusual-method-probe".into(),
                "unusual-method-probe".into(),
                "observe",
                EVENT_SCANNER_PATH,
            ));
        }
        if let Some(indexes) = self.config.rules_by_host.get(&host_key) {
            for &i in indexes {
                let rule = &self.config.rules[i];
                if rule.scope.matches(request) {
                    let mode: &'static str = if rule.mode == "enforce" {
                        "enforce"
                    } else {
                        "observe"
                    };
                    found.push((
                        rule.id.clone(),
                        rule.category.clone(),
                        mode,
                        decisive_event(&rule.category),
                    ));
                }
            }
        }
        let mut results = Vec::with_capacity(found.len());
        for (rule, category, default, event) in found {
            let (mode, exception) = self.action(&rule, request, now, default);
            let action = if mode == "excepted" {
                mode
            } else if trusted {
                "trusted".to_string()
            } else {
                mode
            };
            let points = if action == "enforce" {
                default_weight(event)
            } else {
                0
            };
            if record {
                self.note(&rule, request, now, &action);
            }
            results.push(DetectionMatch {
                id: rule,
                category,
                action,
                exception,
                event_type: event.to_string(),
                points,
            });
        }
        results
    }

    pub fn note(&mut self, rule: &str, request: &ParsedRequest, now: i64, action: &str) {
        let pos = self.stats.iter().position(|(n, _)| n == rule);
        let fresh = || StatRow {
            first: now,
            last: now,
            hits: 0,
            trusted: 0,
            excepted: 0,
            observe: 0,
            enforce: 0,
            ips: BTreeSet::new(),
            hosts: Vec::new(),
        };
        let mut row = match pos {
            Some(p) => {
                let (_, r) = self.stats.remove(p);
                if now - r.first >= DETECTION_TTL {
                    fresh()
                } else {
                    r
                }
            }
            None => fresh(),
        };
        row.last = now;
        row.hits += 1;
        match action {
            "trusted" => row.trusted += 1,
            "excepted" => row.excepted += 1,
            "observe" => row.observe += 1,
            "enforce" => row.enforce += 1,
            _ => {}
        }
        if row.ips.len() < 64 {
            row.ips.insert(address_key(&request.client_ip));
        }
        let host: String = request.host.chars().take(253).collect();
        let known = row.hosts.iter().any(|(h, _)| *h == request.host);
        if known || row.hosts.len() < 8 {
            match row.hosts.iter_mut().find(|(h, _)| *h == host) {
                Some(entry) => entry.1 += 1,
                None => row.hosts.push((host, 1)),
            }
        }
        self.stats.push((rule.to_string(), row));
        while self.stats.len() > DETECTION_MAX_STATS {
            self.stats.remove(0);
            self.evictions += 1;
        }
    }

    pub fn observe_slow(&mut self, request: &ParsedRequest, now: i64, handled: bool) -> String {
        if handled
            || request.host.is_empty()
            || is_asset(&request.path)
            || request.path.is_empty()
            || request.path == "/"
        {
            return String::new();
        }
        let host: String = request.host.chars().take(253).collect();
        let key = (request.client_ip.clone(), host);
        let slot = now.div_euclid(1800);
        let pos = self.slow.iter().position(|(k, _)| *k == key);
        let mut entry = match pos {
            Some(p) => self.slow.remove(p).1,
            None => SlowEntry {
                last: now,
                buckets: BTreeMap::new(),
            },
        };
        entry.last = entry.last.max(now);
        let newest = entry.last.div_euclid(1800);
        if slot < newest - 11 {
            // Put it back where it was: Python returns before move_to_end.
            let at = pos.unwrap_or(self.slow.len()).min(self.slow.len());
            self.slow.insert(at, (key, entry));
            return String::new();
        }
        entry.buckets.retain(|&b, _| b >= newest - 11);
        let bucket = entry.buckets.entry(slot).or_default();
        bucket.total += 1;
        if request.status == 404 || request.status == 410 {
            bucket.missing += 1;
            let digest = address_key(&request.path);
            if bucket.paths.len() < 32 && !bucket.paths.contains(&digest) {
                bucket.paths.push(digest);
            }
        } else if is_served(request.status) {
            bucket.good += 1;
        }
        let missing: i64 = entry.buckets.values().map(|b| b.missing).sum();
        let total: i64 = entry.buckets.values().map(|b| b.total).sum();
        let distinct: HashSet<u32> = entry
            .buckets
            .values()
            .flat_map(|b| b.paths.iter().copied())
            .collect();
        let windows = entry
            .buckets
            .values()
            .filter(|b| !b.paths.is_empty())
            .count();
        self.slow.push((key, entry));
        while self.slow.len() > DETECTION_MAX_TRACKED {
            self.slow.remove(0);
            self.evictions += 1;
        }
        if missing < 24 || missing * 10 < total * 9 {
            return String::new();
        }
        if distinct.len() < 24 || windows < 3 {
            return String::new();
        }
        let rule = "behavior:slow-enumeration";
        let (action, _) = self.action(rule, request, now, "observe");
        self.note(rule, request, now, &action);
        action
    }

    pub fn persist(
        &mut self,
        now: i64,
        force: bool,
        database: &SecurityDatabase,
    ) -> Result<(), String> {
        if !force && now - self.last_saved < 60 {
            return Ok(());
        }
        self.stats.retain(|(_, v)| v.last >= now - DETECTION_TTL);
        self.slow.retain(|(_, v)| v.last >= now - 6 * 3600);
        let stats: Vec<Value> = self
            .stats
            .iter()
            .map(|(name, v)| stat_json(name, v, true))
            .collect();
        let slow: Vec<Value> = self
            .slow
            .iter()
            .map(|((ip, host), v)| {
                let buckets: Vec<Value> = v
                    .buckets
                    .iter()
                    .map(|(s, b)| {
                        let mut paths = b.paths.clone();
                        paths.sort_unstable();
                        json!([s, b.missing, b.total, b.good, paths])
                    })
                    .collect();
                json!([[ip, host], v.last, buckets])
            })
            .collect();
        database.set_states(&[
            (
                DETECTION_STATS_KEY.to_string(),
                Value::from(stats).to_string(),
            ),
            (
                DETECTION_SLOW_KEY.to_string(),
                Value::from(slow).to_string(),
            ),
        ])?;
        self.last_saved = now;
        Ok(())
    }

    pub fn summary(&self, sigs: &SignatureEngine) -> Value {
        let mut new_rules = Map::new();
        for (k, v) in DETECTION_NEW_RULES
            .iter()
            .chain(DETECTION_WARNING_RULES.iter())
        {
            new_rules.insert((*k).into(), json!(v));
        }
        let mut warning: Vec<&str> = DETECTION_WARNING_RULES.iter().map(|(k, _)| *k).collect();
        warning.sort_unstable();
        let stats: Vec<Value> = self
            .stats
            .iter()
            .map(|(name, v)| {
                let mut row = stat_json(name, v, false);
                row["unique_ips"] = json!(v.ips.len());
                row["unique_ips_capped"] = json!(v.ips.len() >= 64);
                row
            })
            .collect();
        json!({
            "ok": true,
            "config": self.config.to_json(),
            "profiles": detection_profiles(),
            "builtin_ids": builtin_detection_ids(sigs).into_iter().collect::<Vec<_>>(),
            "new_rules": new_rules,
            "existing_behavior": [
                {"id": EVENT_SCANNER_MULTI, "categories": MULTI_CATEGORY_MIN, "hours": MULTI_CATEGORY_WINDOW / 3600},
                {"id": EVENT_LOW_AND_SLOW, "hits": LOW_AND_SLOW_MIN_HITS, "categories": LOW_AND_SLOW_MIN_CATEGORIES,
                 "hours": LOW_AND_SLOW_WINDOW / 3600},
                {"id": EVENT_NOT_FOUND_ENUM, "paths": NOT_FOUND_MIN_DISTINCT, "minutes": NOT_FOUND_WINDOW / 60},
                {"id": EVENT_WIDE_ENUM, "paths": WIDE_ENUM_MIN, "minutes": WIDE_ENUM_WINDOW / 60},
                {"id": EVENT_MASS_ENUM, "paths": MASS_ENUM_MIN, "minutes": WIDE_ENUM_WINDOW / 60},
                {"id": EVENT_RECURRING, "gap_hours": RECURRING_GAP / 3600, "days": RECURRING_WINDOW / 86400},
                {"id": EVENT_SUBNET_CAMPAIGN, "addresses": SUBNET_CAMPAIGN_MIN_IPS, "minutes": SUBNET_CAMPAIGN_WINDOW / 60},
            ],
            "warning_only": warning,
            "stats": stats,
            "limits": {
                "tracked": DETECTION_MAX_TRACKED,
                "tracked_now": self.slow.len(),
                "evictions": self.evictions,
                "window_hours": 24,
                "stats_capacity": DETECTION_MAX_STATS,
                "state_errors": self.state_errors,
            },
        })
    }

    /// What one hand-made request would match, without recording anything.
    pub fn preview(
        &mut self,
        data: &Value,
        exclusions: &ExclusionModel,
        now: i64,
        policy: Option<&ScoringPolicy>,
        sigs: &SignatureEngine,
    ) -> Result<Value, String> {
        let Some(obj) = data.as_object() else {
            return Err("expected an object".into());
        };
        let uri = obj.get("url").cloned().unwrap_or_else(|| json!("/"));
        let method = obj.get("method").cloned().unwrap_or_else(|| json!("GET"));
        let status = obj.get("status").cloned().unwrap_or_else(|| json!(404));
        let agent = obj.get("user_agent").cloned().unwrap_or_else(|| json!(""));
        let protocol = obj
            .get("protocol")
            .cloned()
            .unwrap_or_else(|| json!("HTTP/1.1"));
        let host = detection_host(obj.get("host").and_then(Value::as_str).unwrap_or(""))?;
        let uri = match uri.as_str() {
            Some(u) if u.chars().count() <= 4096 && u.starts_with('/') && !u.starts_with("//") => {
                u.to_string()
            }
            _ => return Err("expected a request path of at most 4096 characters".into()),
        };
        static METHOD: OnceLock<Regex> = OnceLock::new();
        let status = match status.as_i64() {
            Some(n) if (status.is_i64() || status.is_u64()) && (100..=599).contains(&n) => n as u16,
            _ => return Err("invalid HTTP method or status".into()),
        };
        let method = match method.as_str() {
            Some(m) if rx(&METHOD, r"^[A-Z]{3,16}$").is_match(m) => m.to_string(),
            _ => return Err("invalid HTTP method or status".into()),
        };
        let protocol = match protocol.as_str() {
            Some(p) if ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"].contains(&p) => p.to_string(),
            _ => return Err("invalid HTTP protocol".into()),
        };
        let agent = match agent.as_str() {
            Some(a) if a.chars().count() <= 512 => a.to_string(),
            _ => return Err("User-Agent must be at most 512 characters".into()),
        };
        let raw_ip = obj
            .get("ip")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("203.0.113.254");
        let ip: std::net::IpAddr = raw_ip
            .parse()
            .map_err(|_| "invalid client IP".to_string())?;
        let ip = ip.to_string();
        let verdict = exclusions.verdict(&ip);
        let request = ParsedRequest {
            client_ip: ip,
            status,
            frontend: "preview".into(),
            backend: "preview/srv1".into(),
            method,
            path: normalize_path(&uri),
            host: host.clone(),
            bad_request: false,
            query_flag: sigs.classify_query(&uri).to_string(),
            path_flag: classify_raw_path(&uri).to_string(),
            observation_flags: sigs
                .observation_flags(&uri)
                .into_iter()
                .map(String::from)
                .collect(),
            ts: 0,
            request_id: String::new(),
            bytes_out: 0,
            duration_ms: -1,
            response_ms: -1,
            times: String::new(),
            term: String::new(),
            ban_reason: String::new(),
            user_agent: agent,
            authenticated_user: String::new(),
            protocol,
        };
        let mut matches = self.inspect(&request, now, verdict.excluded, false, false, sigs);
        let mut categories: BTreeMap<String, i64> = BTreeMap::new();
        for row in matches.iter_mut() {
            if let Some(p) = policy {
                if row.action == "enforce" {
                    row.points = p.weight(&row.event_type);
                }
            }
            let e = categories.entry(row.category.clone()).or_insert(0);
            *e = (*e).max(row.points);
        }
        Ok(json!({
            "ok": true,
            "matches": matches.iter().map(DetectionMatch::to_json).collect::<Vec<_>>(),
            "path": request.path,
            "trusted": verdict.excluded,
            "trust_reason": verdict.reason,
            "profile": self.config.profiles.get(&host).cloned().unwrap_or_else(|| "web".into()),
            "nominal_points": categories.values().sum::<i64>(),
            "engine_mode": "preview",
            "note": "Single request only; live score also depends on policy, cooldowns, history and gateway refusals. Nothing was saved.",
        }))
    }
}

fn stat_json(name: &str, v: &StatRow, with_ips: bool) -> Value {
    let mut hosts = Map::new();
    for (h, n) in &v.hosts {
        hosts.insert(h.clone(), json!(n));
    }
    let mut row = json!({
        "id": name,
        "first": v.first,
        "last": v.last,
        "hits": v.hits,
        "trusted": v.trusted,
        "excepted": v.excepted,
        "observe": v.observe,
        "enforce": v.enforce,
        "hosts": hosts,
    });
    if with_ips {
        row["ips"] = json!(v.ips.iter().collect::<Vec<_>>());
    }
    row
}

fn restore_stat(
    row: &Value,
    known: &BTreeSet<String>,
    now: i64,
) -> Result<Option<(String, StatRow)>, ()> {
    let obj = row.as_object().ok_or(())?;
    let name = obj.get("id").and_then(Value::as_str).ok_or(())?.to_string();
    let first = obj.get("first").and_then(Value::as_i64).ok_or(())?;
    let last = obj.get("last").and_then(Value::as_i64).ok_or(())?;
    if !known.contains(&name) || !(now - DETECTION_TTL..=now + 60).contains(&last) || first > last {
        return Ok(None);
    }
    let mut counts = [0i64; 5];
    for (i, k) in ["hits", "trusted", "excepted", "observe", "enforce"]
        .iter()
        .enumerate()
    {
        let n = obj.get(*k).and_then(Value::as_i64).ok_or(())?;
        if !(0..=1_000_000_000_000).contains(&n) {
            return Err(());
        }
        counts[i] = n;
    }
    let mut ips = BTreeSet::new();
    for v in obj
        .get("ips")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .take(64)
    {
        let n = v.as_i64().ok_or(())?;
        if !(0..(1i64 << 32)).contains(&n) {
            return Err(());
        }
        ips.insert(n as u32);
    }
    let mut hosts = Vec::new();
    for (k, v) in obj
        .get("hosts")
        .and_then(Value::as_object)
        .ok_or(())?
        .iter()
        .take(8)
    {
        let n = v.as_i64().ok_or(())?;
        if n < 0 {
            return Err(());
        }
        hosts.push((detection_host(k).map_err(|_| ())?, n));
    }
    Ok(Some((
        name,
        StatRow {
            first,
            last,
            hits: counts[0],
            trusted: counts[1],
            excepted: counts[2],
            observe: counts[3],
            enforce: counts[4],
            ips,
            hosts,
        },
    )))
}

type SlowKey = (String, String);

fn restore_slow(row: &Value, now: i64) -> Result<Option<(SlowKey, SlowEntry)>, ()> {
    let parts = row.as_array().filter(|a| a.len() == 3).ok_or(())?;
    let key = parts[0].as_array().filter(|a| a.len() == 2).ok_or(())?;
    let ip = key[0].as_str().ok_or(())?;
    ip.parse::<std::net::IpAddr>().map_err(|_| ())?;
    let host = detection_host(key[1].as_str().ok_or(())?).map_err(|_| ())?;
    let last = parts[1].as_i64().ok_or(())?;
    let mut restored = BTreeMap::new();
    for b in parts[2].as_array().ok_or(())?.iter().take(12) {
        let b = b.as_array().filter(|a| a.len() == 5).ok_or(())?;
        let slot = b[0].as_i64().ok_or(())?;
        if !(now.div_euclid(1800) - 11..=now.div_euclid(1800)).contains(&slot) {
            continue;
        }
        let missing = b[1].as_i64().ok_or(())?;
        let total = b[2].as_i64().ok_or(())?;
        let good = b[3].as_i64().ok_or(())?;
        if [missing, total, good]
            .iter()
            .any(|n| !(0..=1_000_000_000_000).contains(n))
            || missing + good > total
        {
            return Err(());
        }
        let paths: Vec<u32> = b[4]
            .as_array()
            .ok_or(())?
            .iter()
            .take(32)
            .map(|v| v.as_u64().map(|n| n as u32).ok_or(()))
            .collect::<Result<_, _>>()?;
        restored.insert(
            slot,
            SlowBucket {
                missing,
                total,
                good,
                paths,
            },
        );
    }
    if !restored.is_empty() && (now - 6 * 3600..=now + 60).contains(&last) {
        Ok(Some((
            (ip.to_string(), host),
            SlowEntry {
                last,
                buckets: restored,
            },
        )))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Login correlations
// ---------------------------------------------------------------------------

type LoginBuckets = BTreeMap<i64, (i64, Vec<u32>)>;

/// Failed first-factor logins from Authelia's JSON log, correlated by address
/// and by user (hashed). Warning only: never bans, never locks an account.
#[derive(Debug)]
pub struct LoginCorrelations {
    entries: Vec<(String, LoginBuckets)>,
    pub cursor: LogCursor,
    pub enabled: bool,
    pub dropped: u64,
    pub last_saved: i64,
}

impl LoginCorrelations {
    pub fn new(path: &str, database: &SecurityDatabase, now: i64) -> Self {
        let saved: Value = serde_json::from_str(&database.get_state(LOGIN_CORRELATIONS_KEY, "{}"))
            .unwrap_or(Value::Null);
        let saved = if saved.is_object() { saved } else { json!({}) };
        let cursor = cursor_from_state(path, saved.get("cursor"));
        let mut lc = Self {
            entries: Vec::new(),
            cursor,
            enabled: !path.is_empty(),
            dropped: 0,
            last_saved: 0,
        };
        if let Some(rows) = saved.get("entries").and_then(Value::as_array) {
            for row in rows.iter().take(256) {
                let Some(pair) = row.as_array().filter(|a| a.len() == 2) else {
                    break;
                };
                let Some(key) = pair[0].as_str() else { break };
                let Some(buckets) = pair[1].as_array() else {
                    break;
                };
                let mut clean = BTreeMap::new();
                let mut bad = false;
                for b in buckets.iter().take(3) {
                    let Some(b) = b.as_array().filter(|a| a.len() == 3) else {
                        bad = true;
                        break;
                    };
                    let (Some(slot), Some(count), Some(peers)) =
                        (b[0].as_i64(), b[1].as_i64(), b[2].as_array())
                    else {
                        bad = true;
                        break;
                    };
                    if now / 300 - 2 <= slot && slot <= now / 300 {
                        let peers: Vec<u32> = peers
                            .iter()
                            .take(32)
                            .filter_map(|v| v.as_u64().map(|n| n as u32))
                            .collect();
                        clean.insert(slot, (count, peers));
                    }
                }
                if bad {
                    break;
                }
                if !clean.is_empty()
                    && key.chars().count() <= 80
                    && (key.starts_with("ip:") || key.starts_with("user:"))
                {
                    lc.entries.push((key.to_string(), clean));
                }
            }
        }
        lc
    }

    pub fn observe(
        &mut self,
        line: &str,
        now: i64,
        exclusions: &ExclusionModel,
        context: &mut DetectionContext,
    ) {
        if line.len() > 16384 {
            self.dropped += 1;
            return;
        }
        let Ok(data) = serde_json::from_str::<Value>(line) else {
            self.dropped += 1;
            return;
        };
        let Some(obj) = data.as_object() else { return };
        if obj.get("path").and_then(Value::as_str) != Some("/api/firstfactor")
            || obj.get("method").and_then(Value::as_str) != Some("POST")
        {
            return;
        }
        static MSG: OnceLock<Regex> = OnceLock::new();
        let msg = obj.get("msg").map(value_text).unwrap_or_default();
        let Some(m) = rx(
            &MSG,
            r"^Unsuccessful 1FA authentication attempt by user '([^']{0,256})'",
        )
        .captures(&msg) else {
            return;
        };
        let parsed = (|| -> Option<(String, i64, String)> {
            let ip: std::net::IpAddr =
                obj.get("remote_ip").and_then(Value::as_str)?.parse().ok()?;
            let stamp = parse_iso_time(obj.get("time").map(value_text)?.as_str())?;
            let username: String = obj
                .get("username")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(&m[1])
                .chars()
                .take(256)
                .collect();
            Some((ip.to_string(), stamp, username))
        })();
        let Some((ip, stamp, username)) = parsed else {
            self.dropped += 1;
            return;
        };
        if !(now - 900 <= stamp && stamp <= now + 30) {
            return;
        }
        let stamp = stamp.min(now);
        let mut keys: Vec<(String, Option<u32>)> = vec![(
            format!("ip:{ip}"),
            if username.is_empty() {
                None
            } else {
                Some(address_key(&username))
            },
        )];
        if !username.is_empty() {
            keys.push((
                format!("user:{}", sha256_hex(username.as_bytes())),
                Some(address_key(&ip)),
            ));
        }
        let slot = stamp / 300;
        for (key, peer) in keys {
            let pos = self.entries.iter().position(|(k, _)| *k == key);
            let mut buckets = match pos {
                Some(p) => self.entries.remove(p).1,
                None => BTreeMap::new(),
            };
            buckets.retain(|&s, _| !(s < now / 300 - 2 || s > now / 300));
            let bucket = buckets.entry(slot).or_insert((0, Vec::new()));
            bucket.0 += 1;
            if let Some(p) = peer {
                if !bucket.1.contains(&p) && bucket.1.len() < 32 {
                    bucket.1.push(p);
                }
            }
            let distinct: HashSet<u32> =
                buckets.values().flat_map(|b| b.1.iter().copied()).collect();
            let count: i64 = buckets.values().map(|b| b.0).sum();
            self.entries.push((key.clone(), buckets));
            while self.entries.len() > 256 {
                self.entries.remove(0);
                self.dropped += 1;
            }
            let mut rules = Vec::new();
            if key.starts_with("ip:") {
                if distinct.len() >= 10 {
                    rules.push("auth:credential-spray");
                }
                if count >= 20 {
                    rules.push("auth:failed-login-burst");
                }
            } else if distinct.len() >= 10 {
                rules.push("auth:distributed-login");
            }
            if !rules.is_empty() {
                let request = auth_request(&ip);
                for rule in rules {
                    let (mut action, _) = context.action(rule, &request, now, "observe");
                    if action != "excepted" && exclusions.verdict(&ip).excluded {
                        action = "trusted".into();
                    }
                    context.note(rule, &request, now, &action);
                }
            }
        }
    }

    pub fn poll(
        &mut self,
        now: i64,
        exclusions: &ExclusionModel,
        context: &mut DetectionContext,
        database: &SecurityDatabase,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        for line in self.cursor.read(256 * 1024) {
            self.observe(&line, now, exclusions, context);
        }
        if now - self.last_saved >= 60 {
            self.persist(now, database)?;
        }
        Ok(())
    }

    pub fn persist(&mut self, now: i64, database: &SecurityDatabase) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        self.entries.retain(|(_, b)| {
            !b.is_empty() && b.keys().max().copied().unwrap_or(i64::MIN) >= now / 300 - 2
        });
        let rows: Vec<Value> = self
            .entries
            .iter()
            .map(|(k, b)| {
                let buckets: Vec<Value> = b.iter().map(|(s, (c, p))| json!([s, c, p])).collect();
                json!([k, buckets])
            })
            .collect();
        database.set_state(
            LOGIN_CORRELATIONS_KEY,
            &json!({"cursor": cursor_state(&self.cursor), "entries": rows}).to_string(),
        )?;
        self.last_saved = now;
        Ok(())
    }

    pub fn health(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "error": if self.cursor.last_error.is_some() { "log unavailable" } else { "" },
            "lag_bytes": self.cursor.lag_bytes,
            "tracked": self.entries.len(),
            "dropped": self.dropped,
        })
    }
}

fn auth_request(ip: &str) -> ParsedRequest {
    ParsedRequest {
        client_ip: ip.to_string(),
        status: 401,
        frontend: "authelia".into(),
        backend: "authelia/srv1".into(),
        method: "POST".into(),
        path: "/api/firstfactor".into(),
        host: "authelia".into(),
        bad_request: false,
        query_flag: String::new(),
        path_flag: String::new(),
        observation_flags: Vec::new(),
        ts: 0,
        request_id: String::new(),
        bytes_out: 0,
        duration_ms: -1,
        response_ms: -1,
        times: String::new(),
        term: String::new(),
        ban_reason: String::new(),
        user_agent: String::new(),
        authenticated_user: String::new(),
        protocol: String::new(),
    }
}

pub fn cursor_from_state(path: &str, state: Option<&Value>) -> LogCursor {
    let get =
        |k: &str| crate::constants::safe_int_value(state.and_then(|s| s.get(k))).max(0) as u64;
    LogCursor::new(path, get("inode"), get("offset"), get("rotations"))
}

pub fn cursor_state(cursor: &LogCursor) -> Value {
    json!({"inode": cursor.inode, "offset": cursor.offset, "rotations": cursor.rotations})
}

/// `datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()` for the
/// shapes Authelia writes: `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
pub fn parse_iso_time(text: &str) -> Option<i64> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = rx(
        &R,
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$",
    );
    let c = r.captures(text.trim())?;
    let n = |i: usize| c[i].parse::<i64>().ok();
    let (y, mo, d, h, mi, s) = (n(1)?, n(2)?, n(3)?, n(4)?, n(5)?, n(6)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    let mut epoch = days * 86400 + h * 3600 + mi * 60 + s;
    match c.get(7).map(|m| m.as_str()) {
        None | Some("Z") => {
            if c.get(7).is_none() {
                // Naive time: Python treats it as local time.
                epoch -= local_offset_seconds(epoch);
            }
        }
        Some(z) => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z[1..].chars().filter(char::is_ascii_digit).collect();
            let oh: i64 = digits.get(0..2)?.parse().ok()?;
            let om: i64 = digits.get(2..4)?.parse().ok()?;
            epoch -= sign * (oh * 3600 + om * 60);
        }
    }
    Some(epoch)
}

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The host's UTC offset at `epoch`, in seconds east of UTC.
pub fn local_offset_seconds(epoch: i64) -> i64 {
    crate::localtime::offset_at(epoch)
}

pub fn sha256_hex(data: &[u8]) -> String {
    crate::sha256::hex(data)
}

// ---------------------------------------------------------------------------
// Signature candidates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Candidate {
    first: i64,
    last: i64,
    ips: BTreeSet<u32>,
    clients: BTreeSet<u32>,
    status: Vec<(String, i64)>,
    hosts: Vec<(String, i64)>,
}

/// Paths refused to many addresses that no signature matches.
#[derive(Debug, Default)]
pub struct PathCandidates {
    paths: LinkedHashMap<(String, String), Candidate>,
    served: LinkedHashMap<u64, i64>,
}

fn key_digest(host: &str, path: &str) -> u64 {
    (u64::from(crate::constants::crc32(host.as_bytes())) << 32)
        | u64::from(crate::constants::crc32(path.as_bytes()))
}

impl PathCandidates {
    #[allow(clippy::too_many_arguments)]
    pub fn note(
        &mut self,
        path: &str,
        ip: &str,
        host: &str,
        status: u16,
        served: bool,
        client: bool,
        ts: i64,
    ) {
        if path.chars().count() > CANDIDATE_MAX_PATH_LENGTH {
            return;
        }
        let host = host.to_lowercase().trim_end_matches('.').to_string();
        let key = (host.clone(), path.to_string());
        let digest = key_digest(&host, path);
        if served {
            self.served.insert(digest, ts);
            if self.served.len() > CANDIDATE_MAX_SERVED {
                self.served.pop_front();
            }
            self.paths.remove(&key);
            return;
        }
        if !ENUMERATION_STATUSES.contains(&status) || self.served.contains_key(&digest) {
            return;
        }
        let mut entry = match self.paths.remove(&key) {
            Some(entry) => entry,
            None => Candidate {
                first: ts,
                last: ts,
                ips: BTreeSet::new(),
                clients: BTreeSet::new(),
                status: Vec::new(),
                hosts: Vec::new(),
            },
        };
        entry.last = ts;
        let akey = address_key(ip);
        if entry.ips.len() < CANDIDATE_MAX_ADDRESSES {
            entry.ips.insert(akey);
        }
        if client && entry.clients.len() < CANDIDATE_MAX_ADDRESSES {
            entry.clients.insert(akey);
        }
        let code = status.to_string();
        match entry.status.iter_mut().find(|(c, _)| *c == code) {
            Some(e) => e.1 += 1,
            None => entry.status.push((code, 1)),
        }
        if !host.is_empty() {
            let known = entry.hosts.iter().any(|(h, _)| *h == host);
            if known || entry.hosts.len() < 5 {
                match entry.hosts.iter_mut().find(|(h, _)| *h == host) {
                    Some(e) => e.1 += 1,
                    None => entry.hosts.push((host, 1)),
                }
            }
        }
        self.paths.insert(key, entry);
        while self.paths.len() > CANDIDATE_MAX_PATHS {
            self.paths.pop_front();
        }
    }

    pub fn prune(&mut self, before: i64) -> usize {
        let n = self.paths.len();
        self.paths.retain(|_, e| e.last >= before);
        self.served.retain(|_, s| *s >= before);
        n - self.paths.len()
    }

    pub fn suggestions(
        &self,
        dismissed: &HashSet<String>,
        limit: usize,
        sigs: &SignatureEngine,
    ) -> Vec<Value> {
        let mut rows: Vec<(bool, i64, i64, Value)> = Vec::new();
        for ((host, path), e) in &self.paths {
            if e.ips.len() < CANDIDATE_MIN_ADDRESSES || dismissed.contains(path) {
                continue;
            }
            let compact = serde_json::to_string(&json!([host, path])).unwrap_or_default();
            if dismissed.contains(&compact) {
                continue;
            }
            if !sigs.classify_path(path).is_empty() {
                continue;
            }
            let mut hosts = e.hosts.clone();
            hosts.sort_by_key(|h| std::cmp::Reverse(h.1));
            let mut status = Map::new();
            for (c, n) in &e.status {
                status.insert(c.clone(), json!(n));
            }
            rows.push((
                !e.clients.is_empty(),
                -(e.ips.len() as i64),
                -e.last,
                json!({
                    "path": path,
                    "host": host,
                    "addresses": e.ips.len(),
                    "clients": e.clients.len(),
                    "first": e.first,
                    "last": e.last,
                    "status": status,
                    "hosts": hosts.into_iter().map(|(h, _)| h).collect::<Vec<_>>(),
                }),
            ));
        }
        rows.sort_by_key(|r| (r.0, r.1, r.2));
        rows.into_iter().take(limit).map(|r| r.3).collect()
    }

    pub fn snapshot(&self, limit: usize) -> Value {
        let mut ranked: Vec<_> = self.paths.iter().collect();
        ranked.sort_by_key(|x| std::cmp::Reverse(x.1.ips.len()));
        let rows: Vec<Value> = ranked
            .into_iter()
            .take(limit)
            .filter(|(_, e)| e.ips.len() >= 2)
            .map(|((_, path), e)| {
                let mut status = Map::new();
                for (c, n) in &e.status {
                    status.insert(c.clone(), json!(n));
                }
                let mut hosts = Map::new();
                for (h, n) in &e.hosts {
                    hosts.insert(h.clone(), json!(n));
                }
                json!([path, e.first, e.last, e.ips, e.clients, status, hosts])
            })
            .collect();
        Value::from(rows)
    }

    pub fn restore(&mut self, rows: &Value) {
        let Some(rows) = rows.as_array() else { return };
        for row in rows.iter().take(CANDIDATE_MAX_PATHS) {
            let Some(r) = row.as_array().filter(|a| a.len() == 7) else {
                continue;
            };
            let Some(hosts) = r[6].as_object().filter(|h| h.len() == 1) else {
                continue;
            };
            let host = hosts.keys().next().cloned().unwrap_or_default();
            let path = value_text(&r[0]);
            if path.chars().count() > CANDIDATE_MAX_PATH_LENGTH {
                continue;
            }
            let (Some(first), Some(last)) = (r[1].as_i64(), r[2].as_i64()) else {
                continue;
            };
            let ips: Option<BTreeSet<u32>> = r[3].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect()
            });
            let clients: Option<BTreeSet<u32>> = r[4].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect()
            });
            let (Some(ips), Some(clients)) = (ips, clients) else {
                continue;
            };
            let status: Vec<(String, i64)> = r[5]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(0)))
                        .collect()
                })
                .unwrap_or_default();
            let hosts_v: Vec<(String, i64)> = hosts
                .iter()
                .map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(0)))
                .collect();
            self.paths.insert(
                (host, path),
                Candidate {
                    first,
                    last,
                    ips,
                    clients,
                    status,
                    hosts: hosts_v,
                },
            );
        }
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Unknown host names
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct UnknownHost {
    first: i64,
    last: i64,
    requests: i64,
    ips: BTreeSet<u32>,
    clients: BTreeSet<u32>,
}

/// Names asked for that serve no site, and who asked.
#[derive(Debug, Default)]
pub struct UnknownHosts {
    hosts: LinkedHashMap<String, UnknownHost>,
}

impl UnknownHosts {
    pub fn note(&mut self, host: &str, ip: &str, client: bool, ts: i64) {
        let mut entry = match self.hosts.remove(host) {
            Some(entry) => entry,
            None => UnknownHost {
                first: ts,
                last: ts,
                requests: 0,
                ips: BTreeSet::new(),
                clients: BTreeSet::new(),
            },
        };
        entry.last = ts;
        entry.requests += 1;
        let key = address_key(ip);
        if entry.ips.len() < CANDIDATE_MAX_ADDRESSES {
            entry.ips.insert(key);
        }
        if client && entry.clients.len() < CANDIDATE_MAX_ADDRESSES {
            entry.clients.insert(key);
        }
        self.hosts.insert(host.to_string(), entry);
        while self.hosts.len() > UNKNOWN_HOSTS_MAX {
            self.hosts.pop_front();
        }
    }

    pub fn prune(&mut self, before: i64) {
        self.hosts.retain(|_, e| e.last >= before);
    }

    pub fn listing(&self, limit: usize) -> Vec<Value> {
        let mut rows: Vec<(i64, i64, Value)> = self
            .hosts
            .iter()
            .map(|(h, e)| {
                (
                    -(e.ips.len() as i64),
                    -e.last,
                    json!({
                        "host": h,
                        "requests": e.requests,
                        "addresses": e.ips.len(),
                        "clients": e.clients.len(),
                        "first": e.first,
                        "last": e.last,
                    }),
                )
            })
            .collect();
        rows.sort_by_key(|r| (r.0, r.1));
        rows.into_iter().take(limit).map(|r| r.2).collect()
    }

    pub fn snapshot(&self) -> Value {
        Value::from(
            self.hosts
                .iter()
                .map(|(h, e)| json!([h, e.first, e.last, e.requests, e.ips, e.clients]))
                .collect::<Vec<_>>(),
        )
    }

    pub fn restore(&mut self, rows: &Value) {
        let Some(rows) = rows.as_array() else { return };
        for row in rows.iter().take(UNKNOWN_HOSTS_MAX) {
            let Some(r) = row.as_array().filter(|a| a.len() == 6) else {
                continue;
            };
            let (Some(first), Some(last), Some(requests)) =
                (r[1].as_i64(), r[2].as_i64(), r[3].as_i64())
            else {
                continue;
            };
            let ips: Option<BTreeSet<u32>> = r[4].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect()
            });
            let clients: Option<BTreeSet<u32>> = r[5].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect()
            });
            let (Some(ips), Some(clients)) = (ips, clients) else {
                continue;
            };
            let host = value_text(&r[0]);
            self.hosts.insert(
                host,
                UnknownHost {
                    first,
                    last,
                    requests,
                    ips,
                    clients,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_refresh_order_and_drop_previously_served_paths() {
        let mut names = UnknownHosts::default();
        names.note("one.test", "192.0.2.1", false, 1);
        names.note("two.test", "192.0.2.2", false, 2);
        names.note("one.test", "192.0.2.3", true, 3);
        let saved = names.snapshot();
        assert_eq!(saved[0][0], "two.test");
        assert_eq!(saved[1][3], 2);
        let mut restored = UnknownHosts::default();
        restored.restore(&saved);
        assert_eq!(restored.snapshot(), saved);

        let mut paths = PathCandidates::default();
        paths.note("/sample", "192.0.2.1", "one.test", 404, false, false, 1);
        assert_eq!(paths.len(), 1);
        paths.note("/sample", "192.0.2.1", "one.test", 200, true, false, 2);
        paths.note("/sample", "192.0.2.2", "one.test", 404, false, false, 3);
        assert!(paths.is_empty());
        paths.prune(3);
        paths.note("/sample", "192.0.2.2", "one.test", 404, false, false, 4);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn iso_time_parses_authelia_stamps() {
        assert_eq!(parse_iso_time("2026-11-22T10:00:00Z"), Some(1_795_341_600));
        assert_eq!(
            parse_iso_time("2026-11-22T11:00:00+01:00"),
            Some(1_795_341_600)
        );
        assert_eq!(
            parse_iso_time("2026-11-22T10:00:00.123456Z"),
            Some(1_795_341_600)
        );
        assert_eq!(parse_iso_time("nonsense"), None);
    }

    #[test]
    fn catch_all_needs_three_paths() {
        let mut c = CatchAllPages::default();
        assert!(!c.is_catch_all("h", 1477, "/.env"));
        assert!(!c.is_catch_all("h", 1477, "/backup.sql"));
        assert!(!c.known("h", 1477));
        assert!(c.is_catch_all("h", 1477, "/phpinfo.php"));
        assert!(c.known("h", 1477));
        assert!(!c.known("other", 1477));
    }
}
