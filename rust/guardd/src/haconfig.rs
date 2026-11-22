//! What guardd reads out of the generated HAProxy configuration, and the small
//! host/decision helpers from Python `guardd.scoring` that go with it.
//!
//! The generated `haproxy.cfg` is the authority on limits, site names, hard
//! ceilings and the ban policy: guardd follows what HAProxy was reloaded with
//! rather than a setting of its own.

use crate::constants::{safe_int_str, LEGACY_READINGS_LISTED, MAX_TRAP_HOSTS};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::sync::OnceLock;

pub type Tables = HashMap<String, HashMap<String, HashMap<String, String>>>;

pub fn haproxy_config_path() -> String {
    std::env::var("HAPROXY_CFG").unwrap_or_else(|_| "/etc/haproxy/haproxy.cfg".to_string())
}

fn read_cfg(path: &str) -> Option<String> {
    let p = if path.is_empty() { haproxy_config_path() } else { path.to_string() };
    fs::read(&p).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn threshold_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(
        &R,
        r"(?m)^\s*acl\s+\S+\s+(?:src_http_req_rate|src_http_err_rate|sc0_conn_rate)\((?P<table>[A-Za-z0-9_.-]+)\)\s+gt\s+(?P<limit>\d+)\s*$",
    )
}

/// Map each counter table to the value HAProxy treats as too much.
pub fn read_thresholds(path: &str) -> HashMap<String, i64> {
    let Some(text) = read_cfg(path) else {
        return HashMap::new();
    };
    threshold_thresholds_from(&text)
}

fn threshold_thresholds_from(text: &str) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    for c in threshold_re().captures_iter(text) {
        out.insert(c["table"].to_string(), safe_int_str(&c["limit"]));
    }
    out
}

/// Every name the gateway serves, from its own valid_host ACL.
pub fn read_site_names(path: &str) -> HashSet<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let rx = re(&R, r"(?m)^\s*acl\s+valid_host\s+hdr\(host\)\s+-i\s+(?P<names>.+?)\s*$");
    let Some(text) = read_cfg(path) else {
        return HashSet::new();
    };
    let mut names = HashSet::new();
    for c in rx.captures_iter(&text) {
        for n in c["names"].split_whitespace() {
            names.insert(n.to_lowercase());
        }
    }
    names
}

fn hostname_ok(text: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let rx = re(
        &R,
        r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    );
    let n = text.chars().count();
    (1..=253).contains(&n) && rx.is_match(text)
}

/// Lower case, without a port; "" for an address or anything odd.
pub fn normalize_host(host: &str) -> String {
    let text = host.trim().to_lowercase();
    if text.starts_with('[') {
        return String::new();
    }
    static PORT: OnceLock<Regex> = OnceLock::new();
    static V4: OnceLock<Regex> = OnceLock::new();
    let text = re(&PORT, r":\d+$").replace(&text, "").into_owned();
    if text.is_empty() || re(&V4, r"^\d+(\.\d+){3}$").is_match(&text) {
        return String::new();
    }
    if hostname_ok(&text) {
        text
    } else {
        String::new()
    }
}

pub fn validate_trap_hosts(hosts: &Value, site_names: &HashSet<String>) -> Result<Vec<String>, String> {
    let list = hosts.as_array().ok_or_else(|| "expected a list of names".to_string())?;
    if list.len() > MAX_TRAP_HOSTS {
        return Err(format!("at most {MAX_TRAP_HOSTS} trap names"));
    }
    let mut checked: Vec<String> = Vec::new();
    for raw in list {
        let text = match raw {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let name = normalize_host(&text);
        if name.is_empty() {
            let shown: String = text.chars().take(80).collect();
            return Err(format!("{shown} is not a host name"));
        }
        if site_names.contains(&name) {
            return Err(format!("{name} serves a site and cannot be a trap"));
        }
        if !checked.contains(&name) {
            checked.push(name);
        }
    }
    checked.sort();
    Ok(checked)
}

/// A decision's reason in one line's worth, for the feed (06.6).
pub fn decision_summary(reason: &Value) -> Value {
    let mut summary = Map::new();
    let categories = reason.get("categories").and_then(Value::as_object);
    if let Some(cats) = categories.filter(|c| !c.is_empty()) {
        let mut ranked: Vec<(&String, f64)> = cats
            .iter()
            .map(|(k, v)| (k, v.as_f64().unwrap_or(0.0)))
            .collect();
        ranked.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(b.0))
        });
        summary.insert(
            "categories".into(),
            Value::from(ranked.iter().take(4).map(|(k, _)| (*k).clone()).collect::<Vec<_>>()),
        );
    } else if let Some(evidence) = reason.get("evidence").and_then(Value::as_array) {
        let mut seen: Vec<String> = Vec::new();
        for entry in evidence {
            let name = entry
                .get("category")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| entry.get("event_type").and_then(Value::as_str))
                .unwrap_or("");
            if !name.is_empty() && !seen.iter().any(|s| s == name) {
                seen.push(name.to_string());
            }
        }
        if !seen.is_empty() {
            seen.truncate(4);
            summary.insert("categories".into(), Value::from(seen));
        }
    }
    if let Some(total) = reason.get("evidence_total") {
        let n = total.as_i64().unwrap_or(0);
        if n != 0 {
            summary.insert("evidence_total".into(), Value::from(n));
        }
    }
    if let Some(readings) = reason.get("readings").and_then(Value::as_array) {
        let over: Vec<Value> = readings
            .iter()
            .filter(|e| e.is_object() && e.get("over").and_then(Value::as_bool).unwrap_or(false))
            .take(2)
            .map(|e| {
                json!({
                    "site": e.get("site").cloned().unwrap_or(Value::Null),
                    "counter": e.get("counter").cloned().unwrap_or(Value::Null),
                    "value": e.get("value").cloned().unwrap_or(Value::Null),
                    "limit": e.get("limit").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        summary.insert("over".into(), Value::from(over));
    }
    Value::Object(summary)
}

/// The per-site counters holding an address when HAProxy's own ban was first seen.
pub fn legacy_ban_readings(ip: &str, tables: &Tables, thresholds: &HashMap<String, i64>) -> Vec<Value> {
    let mut names: Vec<&String> = tables.keys().collect();
    names.sort();
    let mut readings: Vec<(bool, i64, String, Value)> = Vec::new();
    for name in names {
        let counter = if name.starts_with("tbl_rate_") {
            "http_req_rate"
        } else if name.starts_with("tbl_err_") {
            "http_err_rate"
        } else {
            continue;
        };
        let Some(fields) = tables[name].get(ip) else {
            continue;
        };
        if fields.is_empty() {
            continue;
        }
        let value = first_counter(fields, counter);
        if value <= 0 {
            continue;
        }
        let limit = thresholds.get(name).copied();
        let over = limit.is_some_and(|l| value > l);
        let site = name.splitn(3, '_').last().unwrap_or("").to_string();
        readings.push((
            over,
            value,
            name.clone(),
            json!({
                "table": name,
                "site": site,
                "counter": counter,
                "value": value,
                "limit": limit,
                "over": over,
            }),
        ));
    }
    readings.sort_by(|a, b| (!a.0, -a.1, &a.2).cmp(&(!b.0, -b.1, &b.2)));
    readings
        .into_iter()
        .take(LEGACY_READINGS_LISTED)
        .map(|r| r.3)
        .collect()
}

/// The first field whose name starts with `counter` (Python dict order is the
/// table's own column order; HAProxy prints one such column per counter).
pub fn first_counter(fields: &HashMap<String, String>, counter: &str) -> i64 {
    let mut keys: Vec<&String> = fields.keys().filter(|k| k.starts_with(counter)).collect();
    keys.sort();
    keys.first().map(|k| safe_int_str(&fields[*k])).unwrap_or(0)
}

/// A HAProxy time such as 20s or 1m in whole seconds; a bare number is ms.
pub fn haproxy_seconds(text: &str) -> i64 {
    static R: OnceLock<Regex> = OnceLock::new();
    let rx = re(&R, r"^\s*(?P<value>\d+)\s*(?P<unit>ms|s|m|h|d)?\s*$");
    let Some(c) = rx.captures(text) else {
        return 0;
    };
    let value: f64 = c["value"].parse().unwrap_or(0.0);
    if value <= 0.0 {
        return 0;
    }
    let unit = match c.name("unit").map(|m| m.as_str()).unwrap_or("ms") {
        "ms" => 0.001,
        "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        _ => 86400.0,
    };
    ((value * unit) as i64).max(1)
}

#[derive(Debug, Clone, PartialEq)]
pub struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub fn parse(token: &str) -> Option<Self> {
        let (a, p) = match token.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (token, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok().filter(|&n| n <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(n) & mask) == (u32::from(*a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from(n) & mask) == (u128::from(*a) & mask)
            }
            _ => false,
        }
    }
}

/// One site's request limit, as the generated configuration states it.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteCeiling {
    pub id: String,
    pub names: Vec<String>,
    pub limit: i64,
    pub window: i64,
    pub allow: Option<Vec<IpNetwork>>,
    pub enforced: bool,
}

pub fn read_site_ceilings(path: &str) -> HashMap<String, SiteCeiling> {
    let Some(text) = read_cfg(path) else {
        return HashMap::new();
    };
    site_ceilings_from(&text)
}

pub fn site_ceilings_from(text: &str) -> HashMap<String, SiteCeiling> {
    static HOST: OnceLock<Regex> = OnceLock::new();
    static RATE: OnceLock<Regex> = OnceLock::new();
    static IPS: OnceLock<Regex> = OnceLock::new();
    static WARN: OnceLock<Regex> = OnceLock::new();
    let host_re = re(&HOST, r"(?m)^\s*acl\s+host_(?P<id>[A-Za-z0-9_]+)\s+hdr\(host\)\s+-i\s+(?P<names>.+?)\s*$");
    let rate_re = re(
        &RATE,
        r"(?m)^backend\s+tbl_rate_(?P<id>[A-Za-z0-9_]+)\s*\n\s*stick-table\b[^\n]*?\bhttp_req_rate\((?P<window>[^)]+)\)",
    );
    let ips_re = re(&IPS, r"(?m)^\s*acl\s+site_ips_(?P<id>[A-Za-z0-9_]+)\s+src\s+(?P<addresses>.+?)\s*$");
    let warn_re = re(
        &WARN,
        r"(?m)^\s*#\s*guardd-rate-warning\s+site=(?P<id>[A-Za-z0-9_]+)\s+gt\s+(?P<limit>\d+)\s+per\s+(?P<window>\S+)\s*$",
    );
    let limits = threshold_thresholds_from(text);
    let mut windows: HashMap<String, i64> = HashMap::new();
    for c in rate_re.captures_iter(text) {
        windows.insert(c["id"].to_string(), haproxy_seconds(&c["window"]));
    }
    let mut warning_only: HashMap<String, (i64, i64)> = HashMap::new();
    for c in warn_re.captures_iter(text) {
        warning_only.insert(c["id"].to_string(), (safe_int_str(&c["limit"]), haproxy_seconds(&c["window"])));
    }
    let mut allowed: HashMap<String, Vec<IpNetwork>> = HashMap::new();
    for c in ips_re.captures_iter(text) {
        let nets: Vec<IpNetwork> = c["addresses"].split_whitespace().filter_map(IpNetwork::parse).collect();
        allowed.entry(c["id"].to_string()).or_insert(nets);
    }
    let mut names: Vec<(String, Vec<String>)> = Vec::new();
    for c in host_re.captures_iter(text) {
        let id = c["id"].to_string();
        if names.iter().any(|(n, _)| n == &id) {
            continue;
        }
        names.push((id, c["names"].split_whitespace().map(|s| s.to_lowercase()).collect()));
    }
    let mut sites = HashMap::new();
    for (site_id, hostnames) in names {
        let mut limit = limits.get(&format!("tbl_rate_{site_id}")).copied();
        let mut window = windows.get(&site_id).copied().unwrap_or(0);
        let mut enforced = true;
        if limit.is_none() || window <= 0 {
            let Some(&(l, w)) = warning_only.get(&site_id) else {
                continue;
            };
            limit = Some(l);
            window = w;
            enforced = false;
        }
        let limit = limit.unwrap_or(0);
        if limit <= 0 || window <= 0 {
            continue;
        }
        sites.insert(
            site_id.clone(),
            SiteCeiling {
                allow: allowed.get(&site_id).cloned(),
                id: site_id,
                names: hostnames,
                limit,
                window,
                enforced,
            },
        );
    }
    sites
}

/// {table: {counter: ceiling}} from the `# guardd-hard-floor` comments.
pub fn read_hard_floor(path: &str) -> BTreeMap<String, BTreeMap<String, i64>> {
    static R: OnceLock<Regex> = OnceLock::new();
    static L: OnceLock<Regex> = OnceLock::new();
    let rx = re(
        &R,
        r"(?m)^\s*#\s*guardd-hard-floor\s+table=(?P<table>[A-Za-z0-9_.-]+)(?P<limits>(?:\s+(?:http_req_rate|conn_rate|conn_cur)=\d+)+)\s*$",
    );
    let lx = re(&L, r"(?P<counter>http_req_rate|conn_rate|conn_cur)=(?P<limit>\d+)");
    let Some(text) = read_cfg(path) else {
        return BTreeMap::new();
    };
    let mut floors: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    for c in rx.captures_iter(&text) {
        let limits = floors.entry(c["table"].to_string()).or_default();
        for item in lx.captures_iter(&c["limits"]) {
            let limit = safe_int_str(&item["limit"]);
            if limit > 0 {
                limits.insert(item["counter"].to_string(), limit);
            }
        }
    }
    floors.retain(|_, l| !l.is_empty());
    floors
}

pub const BAN_POLICY_LEGACY: &str = "legacy";
pub const BAN_POLICY_U02: &str = "u02";

/// The policy the generated configuration says HAProxy runs.
pub fn read_ban_policy(path: &str) -> &'static str {
    static R: OnceLock<Regex> = OnceLock::new();
    let rx = re(&R, r"(?m)^\s*#\s*guardd-ban-policy\s+(?P<policy>legacy|u02)\s*$");
    let Some(text) = read_cfg(path) else {
        return BAN_POLICY_LEGACY;
    };
    match rx.captures(&text).map(|c| c["policy"].to_string()) {
        Some(p) if p == BAN_POLICY_U02 => BAN_POLICY_U02,
        _ => BAN_POLICY_LEGACY,
    }
}

/// (mtime_ns, size) of a file, the way the Python watchers notice changes.
pub fn file_signature(path: &str) -> Option<(i128, u64)> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    Some((mtime, meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "\
frontend fe
    acl valid_host hdr(host) -i a.example.com B.example.com
    acl host_site1 hdr(host) -i a.example.com
    acl host_site2 hdr(host) -i b.example.com
    acl site_ips_site2 src 10.0.0.0/8 192.0.2.7
    acl rate_site1 src_http_req_rate(tbl_rate_site1) gt 200
    acl err_site1 src_http_err_rate(tbl_err_site1) gt 50
    # guardd-rate-warning site=site2 gt 100 per 10s
    # guardd-hard-floor table=tbl_floor http_req_rate=1000 conn_cur=500
    # guardd-ban-policy u02
backend tbl_rate_site1
    stick-table type ip size 100k expire 1m store http_req_rate(10s)
";

    #[test]
    fn reads_ceilings_and_thresholds() {
        let t = threshold_thresholds_from(CFG);
        assert_eq!(t.get("tbl_rate_site1"), Some(&200));
        assert_eq!(t.get("tbl_err_site1"), Some(&50));
        let sites = site_ceilings_from(CFG);
        let s1 = &sites["site1"];
        assert_eq!((s1.limit, s1.window, s1.enforced), (200, 10, true));
        let s2 = &sites["site2"];
        assert_eq!((s2.limit, s2.window, s2.enforced), (100, 10, false));
        assert!(s2.allow.as_ref().unwrap()[0].contains(&"10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(normalize_host("A.Example.com:443"), "a.example.com");
        assert_eq!(normalize_host("1.2.3.4"), "");
        assert_eq!(normalize_host("[::1]:80"), "");
        assert_eq!(normalize_host("localhost"), "");
        assert_eq!(haproxy_seconds("10s"), 10);
        assert_eq!(haproxy_seconds("1500"), 1);
        assert_eq!(haproxy_seconds("1m"), 60);
    }
}
