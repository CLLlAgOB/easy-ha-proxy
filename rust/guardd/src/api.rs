//! The guardd HTTP API over its Unix socket: every route of Python
//! `guardd.api.GuardHandler`, with the same payloads, status codes and token.

use crate::constants::{
    clamp_str, detection_host, safe_int_str, utc_now, utc_now_f, CUSTOM_CATEGORY, DECISION_FEED_SOURCES,
    MAX_CUSTOM_RULES, MAX_TOKEN_LENGTH, QUALITY_MAX_DAYS, SIGNATURE_OVERRIDES_KEY, UNKNOWN_HOSTS_TTL,
    WOULD_BAN_SCORE, ADAPTIVE_BAN_CODE, CANDIDATE_MIN_ADDRESSES, CANDIDATE_TTL, decision_feed_kinds,
};
use crate::engine::{dismiss_candidate, dismissed_candidates, EngineError, Shared};
use crate::live::DIGEST_BOUNDS_MS;
use crate::livebuf::{live_filters, truthy};
use crate::reqlog::{RequestLog, RequestQuery};
use crate::runtime::banned_now;
use crate::scoring::ScoringPolicy;
use crate::signatures::SignatureEngine;
use crate::watchers::RATE_WARNINGS_KEEP_DAYS;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

pub const REQUEST_TIMEOUT_SECS: u64 = 30;
const MAX_HTTP_HEADER_BYTES: u64 = 32 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 131_072;
const MAX_HTTP_CONNECTIONS: usize = 16;
pub const REQUEST_LOG_OVERRIDE_KEY: &str = "request_log_override";

/// Constant-time comparison of the control token.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: String,
    pub query: HashMap<String, String>,
    pub query_multi: HashMap<String, Vec<String>>,
    pub token: String,
    pub content_length: Option<i64>,
    pub body: &'a [u8],
}

fn ok(mut v: Value) -> Value {
    v["ok"] = json!(true);
    v
}

fn err(code: u16, msg: impl Into<String>) -> (u16, Value) {
    (code, json!({"ok": false, "error": msg.into()}))
}

fn merge(base: Value, extra: Value) -> Value {
    let mut b = match base {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    if let Value::Object(e) = extra {
        for (k, v) in e {
            b.insert(k, v);
        }
    }
    Value::Object(b)
}

fn percent_decode(s: &str) -> String {
    crate::signatures::unquote_plus(s)
}

fn parse_query(q: &str) -> (HashMap<String, String>, HashMap<String, Vec<String>>) {
    let mut first = HashMap::new();
    let mut multi: HashMap<String, Vec<String>> = HashMap::new();
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let (k, v) = (percent_decode(k), percent_decode(v));
        // parse_qs drops blank values.
        if v.is_empty() {
            continue;
        }
        first.entry(k.clone()).or_insert_with(|| v.clone());
        multi.entry(k).or_default().push(v);
    }
    (first, multi)
}

fn q<'a>(r: &'a Request<'_>, name: &str) -> &'a str {
    r.query.get(name).map(String::as_str).unwrap_or("")
}

/// Python `policy_from_query`: a what-if policy, every value clamped.
pub fn policy_from_query(multi: &HashMap<String, Vec<String>>, base: &ScoringPolicy) -> ScoringPolicy {
    let mut weights = base.weights.clone();
    for (name, values) in multi {
        let Some(event_type) = name.strip_prefix("w.") else { continue };
        if !crate::constants::is_weighted_event(event_type) {
            continue;
        }
        let v = clamp_str(values.first().map(String::as_str), base.weight(event_type), 0, 100);
        weights.insert(event_type.to_string(), v);
    }
    let one = |k: &str| multi.get(k).and_then(|v| v.first()).map(String::as_str);
    ScoringPolicy {
        weights,
        category_cap: clamp_str(one("cap"), base.category_cap, 1, 100),
        window_seconds: clamp_str(one("window"), base.window_seconds, 3600, 30 * 86400),
        decay_seconds: clamp_str(one("decay"), base.decay_seconds, 0, 30 * 86400),
    }
}

// -- signatures and the operator's overrides ------------------------------------

pub fn validate_token(token: &str) -> Result<String, String> {
    static OK: OnceLock<Regex> = OnceLock::new();
    let text = token.trim();
    if text.is_empty() {
        return Err("empty signature".into());
    }
    if text.chars().count() > MAX_TOKEN_LENGTH {
        return Err(format!("longer than {MAX_TOKEN_LENGTH} characters"));
    }
    let base = text.strip_suffix('*').unwrap_or(text);
    if text.ends_with('*') {
        if text.starts_with('/') {
            return Err("a prefix (*) works on a path segment, not on a whole path".into());
        }
        if base.chars().count() < 3 {
            return Err("a prefix needs at least three characters before *".into());
        }
    }
    let re = OK.get_or_init(|| Regex::new(&format!(r"^[A-Za-z0-9._~/@:+-]{{1,{MAX_TOKEN_LENGTH}}}$")).expect("regex"));
    if !re.is_match(base) {
        return Err("a signature may hold letters, digits and . _ ~ / @ : + - only, with an optional * at the end of a segment".into());
    }
    if text.starts_with('/') && text.trim_matches('/').is_empty() {
        return Err("a signature of / would match everything".into());
    }
    Ok(text.to_string())
}

pub fn validate_overrides(data: &Value) -> Result<Value, String> {
    static CAT: OnceLock<Regex> = OnceLock::new();
    let Some(obj) = data.as_object() else {
        return Err("expected an object".into());
    };
    let empty_o = Value::Object(Map::new());
    let empty_a = Value::Array(Vec::new());
    let added_raw = obj.get("added").filter(|v| !v.is_null() && *v != &json!({}) && *v != &json!(false)).unwrap_or(&empty_o);
    let disabled_raw = obj.get("disabled").filter(|v| !v.is_null() && *v != &json!([]) && *v != &json!(false)).unwrap_or(&empty_a);
    let (Some(added_raw), Some(disabled_raw)) = (added_raw.as_object(), disabled_raw.as_array()) else {
        return Err("expected added to be an object and disabled a list".into());
    };
    if added_raw.len() > MAX_CUSTOM_RULES || disabled_raw.len() > MAX_CUSTOM_RULES {
        return Err(format!("at most {MAX_CUSTOM_RULES} rules"));
    }
    let cat_re = CAT.get_or_init(|| Regex::new(r"^[a-z0-9-]{1,32}$").expect("regex"));
    let mut added = Map::new();
    for (token, category) in added_raw {
        let name = match category {
            Value::String(s) if !s.trim().is_empty() => s.trim().to_string(),
            Value::Null => CUSTOM_CATEGORY.to_string(),
            Value::String(_) => CUSTOM_CATEGORY.to_string(),
            other => other.to_string(),
        };
        if !cat_re.is_match(&name) {
            return Err(format!("{name} is not a usable category name"));
        }
        added.insert(validate_token(token)?, json!(name));
    }
    let mut disabled = BTreeSet::new();
    for t in disabled_raw {
        let text = t.as_str().map(String::from).unwrap_or_else(|| t.to_string());
        disabled.insert(validate_token(&text)?);
    }
    Ok(json!({"added": added, "disabled": disabled.into_iter().collect::<Vec<_>>()}))
}

pub fn load_overrides(db: &crate::secdb::SecurityDatabase) -> Value {
    let raw = db.get_state(SIGNATURE_OVERRIDES_KEY, "");
    if raw.is_empty() {
        return json!({"added": {}, "disabled": []});
    }
    match serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()).and_then(|v| validate_overrides(&v)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[WARNING] easy-ha-proxy-guardd: stored signature overrides are unusable ({e}); ignoring");
            json!({"added": {}, "disabled": []})
        }
    }
}

pub fn apply_overrides(shipped: &SignatureEngine, overrides: &Value) -> SignatureEngine {
    let added: Vec<(String, String)> = overrides
        .get("added")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or(CUSTOM_CATEGORY).to_string())).collect())
        .unwrap_or_default();
    let disabled: Vec<String> = overrides
        .get("disabled")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    shipped.with_overrides(&added, &disabled)
}

pub fn signature_summary(sigs: &SignatureEngine, overrides: &Value) -> Value {
    let mut grouped: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for (seg, cat) in sigs.segment_map() {
        grouped.entry(cat.clone()).or_default().0.push(seg.clone());
    }
    for (path, cat) in sigs.path_map() {
        grouped.entry(cat.clone()).or_default().1.push(path.clone());
    }
    let categories: Vec<Value> = grouped
        .into_iter()
        .map(|(name, (mut segs, mut paths))| {
            segs.sort();
            paths.sort();
            json!({"name": name, "decisive": sigs.category_is_decisive(&name), "segments": segs, "paths": paths})
        })
        .collect();
    let mut rules = sigs.query_rule_names();
    rules.sort();
    let mut agents = sigs.user_agents();
    agents.sort();
    let source = if sigs.source.is_empty() { signature_path() } else { sigs.source.clone() };
    json!({
        "version": sigs.version,
        "source": source,
        "would_ban_score": WOULD_BAN_SCORE,
        "decisive_weight": crate::constants::default_weight(crate::constants::EVENT_SCANNER_DECISIVE),
        "probable_weight": crate::constants::default_weight(crate::constants::EVENT_SCANNER_PATH),
        "query_weight": crate::constants::default_weight(crate::constants::EVENT_QUERY_INJECTION),
        "categories": categories,
        "query_rules": rules,
        "user_agents": agents.iter().map(|(t, c)| json!({"token": t, "category": c, "decisive": sigs.category_is_decisive(c)})).collect::<Vec<_>>(),
        "added": overrides.get("added").cloned().unwrap_or_else(|| json!({})),
        "disabled": overrides.get("disabled").cloned().unwrap_or_else(|| json!([])),
        "custom_category": CUSTOM_CATEGORY,
        "max_rules": MAX_CUSTOM_RULES,
    })
}

pub fn signature_path() -> String {
    std::env::var("GUARDD_SIGNATURES").unwrap_or_else(|_| "/usr/local/sbin/scanner-signatures.json".into())
}

/// Read the shipped list, falling back to the built-ins when it is unusable.
pub fn load_shipped_signatures(path: &str) -> SignatureEngine {
    match SignatureEngine::from_file(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[WARNING] easy-ha-proxy-guardd: cannot read {path} ({e}); using the built-in signatures");
            SignatureEngine::builtin()
        }
    }
}

fn current_sigs(s: &Shared) -> Arc<SignatureEngine> {
    s.sigs.read().unwrap_or_else(|p| p.into_inner()).clone()
}

fn overrides_now(s: &Shared) -> Value {
    s.overrides.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

fn rate_warnings_payload(s: &Shared, limit: i64, now: i64) -> Result<Value, String> {
    let e = s.engine();
    Ok(json!({
        "ok": true,
        "ts": now,
        "observed_only": true,
        "open": e.trusted_rates.open_episodes(),
        "recent": s.db.rate_warnings(limit)?,
        "last_24h": s.db.rate_warning_count(now - 86400),
        "keep_days": RATE_WARNINGS_KEEP_DAYS,
        "observer": e.trusted_rates.summary(),
    }))
}

fn engine_error(e: EngineError) -> (u16, Value) {
    match e {
        EngineError::Value(m) => err(400, m),
        EngineError::Lookup(m) => err(404, m),
        EngineError::Conflict(m) => err(409, m),
        EngineError::Refused(m) => err(502, m),
        EngineError::Other(m) => err(500, m),
    }
}

fn valid_ip(text: &str) -> Option<String> {
    text.trim().parse::<std::net::IpAddr>().ok().map(|a| a.to_string())
}

fn get(s: &Shared, r: &Request<'_>) -> (u16, Value) {
    let path = r.path.as_str();
    let now = utc_now();
    match path {
        "/api/v1/guard/health" => {
            let e = s.engine();
            match (e.health(), s.db.stats()) {
                (Ok(h), Ok(st)) => (200, json!({"ok": true, "ts": now, "engine": h, "database": st, "storage": s.db.storage()})),
                (Err(x), _) | (_, Err(x)) => err(500, x),
            }
        }
        "/api/v1/guard/digest" => {
            let since = q(r, "since").trim().parse::<i64>().unwrap_or(0);
            let mut e = s.engine();
            let minutes = e.digests.complete(since, now);
            (200, json!({
                "ok": true, "now": now, "bounds_ms": DIGEST_BOUNDS_MS,
                "minutes": serde_json::to_value(minutes).unwrap_or(Value::Null),
                "late": e.digests.late,
            }))
        }
        "/api/v1/guard/bans/schedule" => {
            let e = s.engine();
            match s.db.scheduled_bans() {
                Ok(b) => (200, json!({"ok": true, "now": now, "mode": e.enforcer.mode, "enforcing": e.enforcer.allowed(), "code": ADAPTIVE_BAN_CODE, "bans": b})),
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/reputation" => {
            let e = s.engine();
            match e.reputation_table(now, 200, None) {
                Ok(rows) => (200, json!({"ok": true, "ts": now, "mode": e.config.mode,
                    "addresses": rows.iter().map(|r| r.to_json(false)).collect::<Vec<_>>()})),
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/identities" => {
            let users = s.live.as_ref().map(|l| l.lock().unwrap_or_else(|p| p.into_inner()).identities(utc_now_f())).unwrap_or_else(|| json!({}));
            (200, json!({"ok": true, "users_by_ip": users}))
        }
        "/api/v1/guard/live/memory" => match s.engine().live_memory() {
            Ok(v) => (200, merge(json!({"ok": true, "ts": now}), v)),
            Err(e) => engine_error(e),
        },
        "/api/v1/guard/live" | "/api/v1/guard/attackers" => {
            let Some(live) = s.live.clone() else {
                return err(404, "the live buffer is off");
            };
            if path.ends_with("/attackers") {
                let a = live.lock().unwrap_or_else(|p| p.into_inner()).attackers(utc_now_f(), 10);
                return (200, merge(json!({"ok": true}), a));
            }
            let filters = match live_filters(&r.query) {
                Ok(f) => f,
                Err(m) => return err(400, m),
            };
            let banned = if filters.banned {
                match banned_now(&s.config.haproxy_socket) {
                    Ok(b) => Some(b),
                    Err(x) => return err(500, format!("cannot read the ban table: {x}")),
                }
            } else {
                None
            };
            let lag_bytes = s.engine().cursor.lag_bytes;
            let mut b = live.lock().unwrap_or_else(|p| p.into_inner());
            match b.snapshot(&r.query, None, banned.as_ref()) {
                Ok(result) => {
                    let status = b.status();
                    let lag_seconds = match status["newest"].as_f64() {
                        Some(n) if n != 0.0 => json!((result["now"].as_f64().unwrap_or(0.0) - n).max(0.0) as i64),
                        _ => Value::Null,
                    };
                    let mut out = result;
                    out["buffer"] = status;
                    out["lag_bytes"] = json!(lag_bytes);
                    out["lag_seconds"] = lag_seconds;
                    (200, out)
                }
                Err(m) => err(400, m),
            }
        }
        "/api/v1/guard/requests" | "/api/v1/guard/requests/status" | "/api/v1/guard/requests/summary" => {
            let store = s.requests.read().unwrap_or_else(|p| p.into_inner()).clone();
            let memory = if store.is_none() && !path.ends_with("/status") { s.live.clone() } else { None };
            if store.is_none() && memory.is_none() {
                return (404, json!({"ok": false, "enabled": false, "error": "the request log is off"}));
            }
            if path.ends_with("/status") {
                let st = store.as_ref().map(|x| x.status()).unwrap_or_else(|| json!({}));
                return (200, merge(json!({"ok": true, "ts": now}), st));
            }
            let mut params = r.query.clone();
            for (k, v) in params.iter_mut() {
                *v = v.trim().to_string();
                if k == "method" {
                    *v = v.to_uppercase();
                }
            }
            let since = clamp_str(params.get("since").map(String::as_str), 0, 0, 2_000_000_000);
            let until = clamp_str(params.get("until").map(String::as_str), 0, 0, 2_000_000_000);
            params.insert("since".into(), since.to_string());
            params.insert("until".into(), until.to_string());
            let slower = clamp_str(params.get("slower").map(String::as_str), 0, 0, 86_400_000);
            params.insert("slower".into(), slower.to_string());
            let query = RequestQuery::from_params(&params);
            if path.ends_with("/summary") {
                let payload = match &store {
                    Some(st) => st.summary(&query, crate::reqlog::REQUEST_SUMMARY_SECONDS),
                    None => Ok(memory.as_ref().map(|m| m.lock().unwrap_or_else(|p| p.into_inner()).summarize_requests(&query)).unwrap_or(Value::Null)),
                };
                return match payload {
                    Ok(p) => (200, merge(json!({"ok": true, "enabled": store.is_some(), "ts": now}), p)),
                    Err(x) => err(500, x),
                };
            }
            let count = !matches!(q(r, "count").trim().to_lowercase().as_str(), "0" | "false" | "no" | "off");
            let limit = clamp_str(Some(q(r, "limit")), 100, 1, 500);
            let before = clamp_str(Some(q(r, "before")), 0, -(1i64 << 62), 1i64 << 62);
            match &store {
                None => {
                    let p = memory
                        .as_ref()
                        .map(|m| m.lock().unwrap_or_else(|p| p.into_inner()).search_requests(&query, before, limit, count))
                        .unwrap_or(Value::Null);
                    (200, merge(json!({"ok": true, "enabled": false, "ts": now}), p))
                }
                Some(st) => match st.search(&query, before.max(0), count, limit, crate::reqlog::REQUEST_SEARCH_SECONDS) {
                    Ok(p) => (200, merge(json!({"ok": true, "ts": now}), p)),
                    Err(x) => err(500, x),
                },
            }
        }
        "/api/v1/guard/adaptive/bans" | "/api/v1/guard/adaptive/ban" => {
            let bad = || err(400, "Invalid ban history filters");
            let num = |k: &str, d: &str| -> Option<i64> {
                let v = r.query.get(k).map(String::as_str).unwrap_or(d);
                v.trim().parse::<i64>().ok()
            };
            if path.ends_with("/bans") {
                let (Some(since), Some(offset), Some(snapshot)) = (num("since", "0"), num("offset", "0"), num("snapshot", "0")) else {
                    return bad();
                };
                let query: String = q(r, "q").chars().take(100).collect();
                let terms: Vec<String> = q(r, "terms").chars().take(2048).collect::<String>().split(',').map(String::from).collect();
                let sort = r.query.get("sort").map(String::as_str).unwrap_or("ts");
                let direction = r.query.get("direction").map(String::as_str).unwrap_or("desc");
                match s.db.adaptive_ban_history(&query, since.max(0), sort, direction, offset.clamp(0, 1_000_000), snapshot.clamp(0, 1 << 62), 25, &terms) {
                    Ok(p) => (200, merge(json!({"ok": true}), p)),
                    Err(_) => bad(),
                }
            } else {
                let Some(id) = num("id", "0") else { return bad() };
                let id = id.clamp(0, 1 << 62);
                let ip = if id == 0 {
                    match valid_ip(q(r, "ip")) {
                        Some(ip) => ip,
                        None => return bad(),
                    }
                } else {
                    String::new()
                };
                let Some(at) = num("at", "0") else { return bad() };
                match s.db.adaptive_ban_detail(id, &ip, at.max(0), 0) {
                    Ok(Some(d)) => (200, json!({"ok": true, "ban": d})),
                    Ok(None) => err(404, "This ban record is no longer available"),
                    Err(_) => bad(),
                }
            }
        }
        "/api/v1/guard/decisions/feed" => {
            let kind = r.query.get("kind").map(|k| k.trim()).filter(|k| !k.is_empty()).unwrap_or("all");
            let Some(actions) = decision_feed_kinds(kind) else {
                return err(400, "kind must be all, bans or lifts");
            };
            let limit = clamp_str(Some(q(r, "limit")), 50, 1, 200);
            let before = clamp_str(Some(q(r, "before")), 0, 0, 1 << 62);
            match s.db.decision_feed(before, limit, actions) {
                Ok(mut rows) => {
                    let more = rows.len() as i64 > limit;
                    rows.truncate(limit as usize);
                    let next = if more { rows.last().and_then(|r| r["id"].as_i64()).unwrap_or(0) } else { 0 };
                    let keep = s.engine().longest_strike_retention();
                    (200, json!({"ok": true, "decisions": rows, "next": next, "sources": DECISION_FEED_SOURCES, "keep_seconds": keep}))
                }
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/decisions" => {
            let Some(address) = valid_ip(q(r, "ip")) else {
                return err(400, "invalid ip");
            };
            let address_raw = q(r, "ip").trim().to_string();
            let limit = clamp_str(Some(q(r, "limit")), 20, 1, 100);
            match s.db.ban_decisions(&address_raw, limit) {
                Ok(rows) => {
                    let keep = s.engine().longest_strike_retention();
                    let _ = address;
                    (200, json!({"ok": true, "ip": address_raw, "decisions": rows, "keep_seconds": keep}))
                }
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/quality" => {
            let days = clamp_str(Some(q(r, "days")), 7, 1, QUALITY_MAX_DAYS);
            match s.engine().quality(days, None) {
                Ok(v) => (200, json!({"ok": true, "quality": v})),
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/rate-warnings" => {
            let limit = clamp_str(Some(q(r, "limit")), 100, 1, 500);
            match rate_warnings_payload(s, limit, now) {
                Ok(v) => (200, v),
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/signatures" => (200, merge(json!({"ok": true}), signature_summary(&current_sigs(s), &overrides_now(s)))),
        "/api/v1/guard/detection-context" => (200, s.engine().detection_state()),
        "/api/v1/guard/traps" => {
            let mut e = s.engine();
            let known = !e.site_names().is_empty();
            (200, json!({
                "ok": true,
                "trap_hosts": e.trap_hosts.iter().collect::<Vec<_>>(),
                "unknown_hosts": e.unknown_hosts.listing(50),
                "site_names_known": known,
                "window_days": UNKNOWN_HOSTS_TTL / 86400,
            }))
        }
        "/api/v1/guard/signatures/candidates" => {
            let dismissed: BTreeSet<String> = dismissed_candidates(&s.db).into_iter().collect();
            let set = dismissed.iter().cloned().collect();
            let sigs = current_sigs(s);
            let list = s.engine().candidates.suggestions(&set, 100, &sigs);
            (200, json!({
                "ok": true,
                "candidates": list,
                "dismissed": dismissed.into_iter().collect::<Vec<_>>(),
                "min_addresses": CANDIDATE_MIN_ADDRESSES,
                "window_days": CANDIDATE_TTL / 86400,
            }))
        }
        "/api/v1/guard/shadow" => {
            let e = s.engine();
            let policy = policy_from_query(&r.query_multi, &e.scoring_policy());
            let limit = clamp_str(Some(q(r, "limit")), 200, 1, 500);
            let sigs = signature_summary(&current_sigs(s), &overrides_now(s));
            match e.shadow_review(None, limit, Some(&policy), sigs) {
                Ok(mut p) => {
                    p["ok"] = json!(true);
                    p["ts"] = json!(now);
                    (200, p)
                }
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/ip" => {
            let raw = q(r, "ip").trim().to_string();
            if valid_ip(&raw).is_none() {
                return err(400, "invalid ip");
            }
            let e = s.engine();
            let policy = policy_from_query(&r.query_multi, &e.scoring_policy());
            match e.reputation(&raw, now, Some(&policy), None) {
                Ok(rep) => {
                    let mut p = rep.to_json(true);
                    p["events"] = json!(s.db.events_for_json(&raw, now - policy.window_seconds, 200).unwrap_or_default());
                    p["ok"] = json!(true);
                    (200, p)
                }
                Err(x) => err(500, x),
            }
        }
        _ => err(404, "not found"),
    }
}

fn read_payload(r: &Request<'_>, max: i64) -> Result<Value, (u16, Value)> {
    let length = r.content_length.unwrap_or(0);
    if length <= 0 || length > max {
        return Err(err(400, "invalid Content-Length"));
    }
    let text = String::from_utf8_lossy(r.body);
    serde_json::from_str::<Value>(&text).map_err(|e| err(400, e.to_string()))
}

fn set_request_log(s: &Shared, enabled: bool) -> Result<Value, String> {
    s.db.set_state(REQUEST_LOG_OVERRIDE_KEY, if enabled { "on" } else { "off" })?;
    let mut slot = s.requests.write().unwrap_or_else(|p| p.into_inner());
    if enabled && slot.is_none() {
        *slot = Some(Arc::new(RequestLog::open(&s.request_log_path, &s.config)?));
        eprintln!("[WARNING] easy-ha-proxy-guardd: Request log enabled from the web interface");
    } else if !enabled {
        if let Some(store) = slot.take() {
            store.flush(utc_now());
            eprintln!("[WARNING] easy-ha-proxy-guardd: Request log disabled from the web interface");
        }
    }
    Ok(json!({"enabled": slot.is_some(), "configured": s.config.request_log_enabled}))
}

fn exactly_enabled(payload: &Value) -> Result<Value, (u16, Value)> {
    match payload.as_object() {
        Some(m) if m.len() == 1 && m.contains_key("enabled") => Ok(m["enabled"].clone()),
        _ => Err(err(400, "expected exactly one field: enabled")),
    }
}

fn post(s: &Shared, r: &Request<'_>) -> (u16, Value) {
    let path = r.path.as_str();
    let routes = [
        "/api/v1/guard/requests/enabled", "/api/v1/guard/live/memory", "/api/v1/guard/first-step-page",
        "/api/v1/guard/shield", "/api/v1/guard/traps", "/api/v1/guard/detection-context",
        "/api/v1/guard/detection-preview", "/api/v1/guard/signatures/candidates/dismiss",
        "/api/v1/guard/signatures", "/api/v1/guard/ban-durations", "/api/v1/guard/ban/manual",
        "/api/v1/guard/ban/forget", "/api/v1/guard/mode",
    ];
    if !routes.contains(&path) {
        return err(404, "not found");
    }
    if s.token.is_empty() || !constant_time_eq(r.token.trim(), &s.token) {
        return err(403, "forbidden");
    }
    let body = |max: i64| read_payload(r, max);
    match path {
        "/api/v1/guard/requests/enabled" => {
            let p = match body(4096) {
                Ok(p) if p.is_object() => p,
                Ok(_) => return err(400, "expected an object"),
                Err(e) => return e,
            };
            let enabled = match &p["enabled"] {
                Value::Bool(b) => *b,
                Value::Null => false,
                Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
            };
            match set_request_log(s, enabled) {
                Ok(v) => (200, merge(json!({"ok": true}), v)),
                Err(x) => err(500, x),
            }
        }
        "/api/v1/guard/live/memory" => {
            let p = match body(1024) {
                Ok(p) if p.is_object() => p,
                Ok(_) => return err(400, "expected an object"),
                Err(e) => return e,
            };
            let mut e = s.engine();
            match e.set_live_memory(p.get("budget_mib"), p.get("revision")) {
                Ok(v) => (200, merge(json!({"ok": true}), v)),
                Err(EngineError::Conflict(m)) => {
                    let current = e.live_memory().unwrap_or_else(|_| json!({}));
                    (409, merge(json!({"ok": false, "error": m, "conflict": true}), current))
                }
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/first-step-page" => {
            let enabled = match body(1024).and_then(|p| exactly_enabled(&p)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            match s.engine().set_first_step_page(&enabled) {
                Ok(state) => (200, json!({"ok": true, "first_step_page": state})),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/shield" => {
            let enabled = match body(1024).and_then(|p| exactly_enabled(&p)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            match s.engine().set_shield(&enabled, None) {
                Ok(state) => (200, json!({"ok": true, "path_shield": state})),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/traps" => {
            let p = match body(16384) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match s.engine().set_trap_hosts(p.get("hosts").unwrap_or(&Value::Null)) {
                Ok(h) => (200, json!({"ok": true, "trap_hosts": h})),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/detection-context" | "/api/v1/guard/detection-preview" => {
            let preview = path.ends_with("preview");
            let max = if preview { 8192 } else { 131_072 };
            let p = match body(max) {
                Ok(p) => p,
                Err(_) if preview => return err(400, "invalid request fields"),
                Err(e) => return e,
            };
            let sigs = current_sigs(s);
            let mut e = s.engine();
            if preview {
                let policy = e.scoring_policy();
                let mode = e.enforcer.mode.clone();
                let engine = &mut *e;
                let result = engine.detection.preview(&p, &engine.sink.exclusions, utc_now(), Some(&policy), &sigs);
                match result {
                    Ok(mut v) => {
                        v["active_mode"] = json!(mode);
                        (200, v)
                    }
                    Err(_) => err(400, "invalid request fields"),
                }
            } else {
                let db = s.db.clone();
                match e.detection.replace(&p, &db, &sigs) {
                    Ok(()) => (200, e.detection_state()),
                    Err(m) if m.contains("database") || m.contains("disk") => err(503, "detection storage unavailable"),
                    Err(m) => err(400, m),
                }
            }
        }
        "/api/v1/guard/signatures/candidates/dismiss" => {
            let p = match body(4096) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let text = |k: &str| p.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
            let restore = p.get("restore").is_some_and(|v| match v {
                Value::Bool(b) => *b,
                Value::Null => false,
                Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
                Value::String(s) => !s.is_empty(),
                _ => true,
            });
            match dismiss_candidate(&s.db, &text("path"), restore, &text("host")) {
                Ok(v) => (200, merge(json!({"ok": true}), v)),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/signatures" => {
            let p = match body(65536) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let checked = match validate_overrides(&p) {
                Ok(c) => c,
                Err(m) => return err(400, m),
            };
            if let Err(x) = s.db.set_state(SIGNATURE_OVERRIDES_KEY, &crate::secdb::python_json(&checked)) {
                return err(500, x);
            }
            let path = signature_path();
            let shipped = load_shipped_signatures(&path);
            let merged = Arc::new(apply_overrides(&shipped, &checked));
            *s.shipped.lock().unwrap_or_else(|p| p.into_inner()) = Arc::new(shipped);
            *s.sigs.write().unwrap_or_else(|p| p.into_inner()) = merged.clone();
            *s.overrides.lock().unwrap_or_else(|p| p.into_inner()) = checked.clone();
            (200, merge(json!({"ok": true}), signature_summary(&merged, &checked)))
        }
        "/api/v1/guard/ban-durations" => {
            let p = match body(4096) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match s.engine().set_ban_durations(p.get("durations").unwrap_or(&Value::Null)) {
                Ok(steps) => (200, json!({"ok": true, "ban_durations_seconds": steps})),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/ban/manual" => {
            let p = match body(1024) {
                Ok(p) if p.is_object() => p,
                Ok(_) => return err(400, "expected an object"),
                Err(e) => return e,
            };
            let ip = p.get("ip").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
            match s.engine().place_manual_ban(&ip, None) {
                Ok(v) => (200, v),
                Err(x) => engine_error(x),
            }
        }
        "/api/v1/guard/ban/forget" => {
            let p = match body(1024) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let ip = p.get("ip").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
            match s.engine().forget_ban(&ip, None) {
                Ok(v) => (200, v),
                Err(x) => engine_error(x),
            }
        }
        _ => {
            let length = r.content_length.unwrap_or(0);
            if length <= 0 || length > 4096 {
                return err(400, "invalid Content-Length");
            }
            let p: Value = match serde_json::from_slice(r.body) {
                Ok(p) => p,
                Err(e) => return err(400, format!("bad json: {e}")),
            };
            let mode = p.get("mode").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
            match s.engine().set_mode(&mode, None) {
                Ok(v) => (200, ok(v)),
                Err(x) => engine_error(x),
            }
        }
    }
}

pub fn dispatch(s: &Shared, r: &Request<'_>) -> (u16, Value) {
    match r.method {
        "GET" => get(s, r),
        "POST" => post(s, r),
        _ => err(404, "not found"),
    }
}

#[cfg(unix)]
struct DeadlineReader {
    stream: UnixStream,
    deadline: Instant,
}

#[cfg(unix)]
impl Read for DeadlineReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

fn read_header_line(
    reader: &mut impl BufRead,
    remaining: &mut u64,
    line: &mut String,
) -> io::Result<()> {
    line.clear();
    let bytes = reader.take(*remaining).read_line(line)? as u64;
    *remaining -= bytes;
    if !line.ends_with('\n') {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

#[cfg(unix)]
struct ConnectionSlot(Arc<AtomicUsize>);

#[cfg(unix)]
impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_HTTP_CONNECTIONS).then_some(count + 1)
            })
            .ok()?;
        Some(Self(active.clone()))
    }
}

#[cfg(unix)]
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn handle_client(stream: UnixStream, shared: Arc<Shared>) {
    let timeout = Duration::from_secs(REQUEST_TIMEOUT_SECS);
    if stream.set_write_timeout(Some(timeout)).is_err() {
        return;
    }
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(DeadlineReader {
        stream,
        deadline: Instant::now() + timeout,
    });
    let mut remaining = MAX_HTTP_HEADER_BYTES;
    let mut line = String::new();
    if read_header_line(&mut reader, &mut remaining, &mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return };
    let method = method.to_string();
    let target = target.to_string();
    let mut content_length: Option<i64> = None;
    let mut token = String::new();
    loop {
        if read_header_line(&mut reader, &mut remaining, &mut line).is_err() {
            return;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = Some(safe_int_str(v));
            } else if k.eq_ignore_ascii_case("x-guardd-token") {
                token = v.trim().to_string();
            }
        }
    }
    let wanted = content_length.unwrap_or(0).clamp(0, MAX_HTTP_BODY_BYTES as i64) as usize;
    let mut body = vec![0u8; wanted];
    if wanted > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let (first, multi) = parse_query(&query);
    let request = Request { method: &method, path, query: first, query_multi: multi, token, content_length, body: &body };
    let (code, payload) = dispatch(&shared, &request);
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.0 {code} {reason}\r\nServer: easy-ha-proxy-guardd/1.0\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    );
    let _ = writer.write_all(header.as_bytes());
    let _ = writer.write_all(&bytes);
    let _ = writer.flush();
}

/// Serve the API until `shared.stop` is set.
#[cfg(unix)]
pub fn serve(socket_path: &str, shared: Arc<Shared>) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(socket_path).map_err(|e| format!("bind {socket_path}: {e}"))?;
    set_socket_perms(socket_path);
    listener.set_nonblocking(true).map_err(|e| format!("set_nonblocking: {e}"))?;
    let active = Arc::new(AtomicUsize::new(0));
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let Some(slot) = ConnectionSlot::acquire(&active) else {
                    continue;
                };
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let st = shared.clone();
                if let Err(err) = std::thread::Builder::new().spawn(move || {
                    let _slot = slot;
                    handle_client(stream, st);
                }) {
                    eprintln!("[WARNING] easy-ha-proxy-guardd: cannot start API worker: {err}");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// root:hadmin 0660, like the Python daemon.
#[cfg(unix)]
fn set_socket_perms(socket_path: &str) {
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;
    let group = std::env::var("GUARDD_SOCKET_GROUP").unwrap_or_else(|_| "hadmin".into());
    if let (Ok(cpath), Ok(cgroup)) = (CString::new(socket_path), CString::new(group.clone())) {
        // SAFETY: getgrnam returns a pointer into static storage or null.
        let gr = unsafe { libc::getgrnam(cgroup.as_ptr()) };
        if gr.is_null() {
            eprintln!("[WARNING] easy-ha-proxy-guardd: Failed to set socket permissions: no group {group}");
        } else {
            let gid = unsafe { (*gr).gr_gid };
            if unsafe { libc::chown(cpath.as_ptr(), 0, gid) } != 0 {
                eprintln!("[WARNING] easy-ha-proxy-guardd: Failed to set socket permissions: chown failed");
            }
        }
    }
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660));
}

pub fn request_log_wanted(db: &crate::secdb::SecurityDatabase, config: &crate::runtime::GuardConfig) -> bool {
    match db.get_state(REQUEST_LOG_OVERRIDE_KEY, "").as_str() {
        "on" => true,
        "off" => false,
        _ => config.request_log_enabled,
    }
}

pub fn detection_host_ok(h: &str) -> bool {
    detection_host(h).is_ok()
}

pub fn truthy_param(v: Option<&String>) -> bool {
    truthy(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_budget_preserves_the_body() {
        let mut input = &b"Host: local\r\n\r\nbody"[..];
        let mut remaining = 15;
        let mut line = String::new();
        read_header_line(&mut input, &mut remaining, &mut line).unwrap();
        assert_eq!(line, "Host: local\r\n");
        read_header_line(&mut input, &mut remaining, &mut line).unwrap();
        assert_eq!(line, "\r\n");
        assert_eq!(remaining, 0);
        assert_eq!(input, b"body");
    }

    #[cfg(unix)]
    #[test]
    fn request_slots_are_reusable() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut slots: Vec<_> = (0..MAX_HTTP_CONNECTIONS)
            .map(|_| ConnectionSlot::acquire(&active).unwrap())
            .collect();
        assert!(ConnectionSlot::acquire(&active).is_none());
        drop(slots.pop());
        assert!(ConnectionSlot::acquire(&active).is_some());
    }

    #[test]
    fn tokens_and_overrides() {
        assert!(validate_token("/").is_err());
        assert!(validate_token("ab*").is_err());
        assert_eq!(validate_token(" .env* ").unwrap(), ".env*");
        let v = validate_overrides(&json!({"added": {"/secret": "custom", "wp-x": ""}, "disabled": ["b", "a"]})).unwrap();
        assert_eq!(v["added"]["wp-x"], "custom");
        assert_eq!(v["disabled"], json!(["a", "b"]));
        assert!(validate_overrides(&json!({"added": {"x": "Bad Cat"}})).is_err());
    }

    #[test]
    fn query_parsing_and_policy() {
        let (first, multi) = parse_query("w.SCANNER_PATH=50&cap=500&ip=1.2.3.4&blank=");
        assert_eq!(first.get("ip").unwrap(), "1.2.3.4");
        assert!(!first.contains_key("blank"));
        let p = policy_from_query(&multi, &ScoringPolicy::default());
        assert_eq!(p.weight("SCANNER_PATH"), 50);
        assert_eq!(p.category_cap, 100);
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }
}
