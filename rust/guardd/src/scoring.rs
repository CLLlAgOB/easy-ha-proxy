//! Scoring policy, linear age decay, U02 weights, and IP/CIDR exclusion model.

use crate::runtime::GuardConfig;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub const EVENT_SCANNER_PATH: &str = "SCANNER_PATH";
pub const EVENT_SCANNER_DECISIVE: &str = "SCANNER_PATH_DECISIVE";
pub const EVENT_QUERY_INJECTION: &str = "QUERY_INJECTION";
pub const EVENT_SCANNER_MULTI: &str = "SCANNER_MULTI_CATEGORY";
pub const EVENT_LOW_AND_SLOW: &str = "LOW_AND_SLOW_SCANNER";
pub const EVENT_NOT_FOUND_ENUM: &str = "NOT_FOUND_ENUMERATION";
pub const EVENT_WIDE_ENUM: &str = "WIDE_ENUMERATION";
pub const EVENT_MASS_ENUM: &str = "MASS_ENUMERATION";
pub const EVENT_INVALID_HOST: &str = "INVALID_HOST_ACTIVITY";
pub const EVENT_RECURRING: &str = "RECURRING_SCANNER";
pub const EVENT_NOSNI_PROBING: &str = "NOSNI_PROBING";
pub const EVENT_RATE_EXCEEDED: &str = "RATE_EXCEEDED";
pub const EVENT_ERROR_RATE_EXCEEDED: &str = "ERROR_RATE_EXCEEDED";
pub const EVENT_LEGACY_BAN: &str = "LEGACY_HAPROXY_BAN";
pub const EVENT_HARD_FLOOR: &str = "HARD_FLOOR_EPISODE";
pub const EVENT_HARD_FLOOR_TRUSTED: &str = "HARD_FLOOR_TRUSTED";
pub const EVENT_SUBNET_CAMPAIGN: &str = "SUBNET_CAMPAIGN";

pub const DEFAULT_CATEGORY_CAP: i64 = 25;
pub const DEFAULT_SCORE_WINDOW_SECONDS: i64 = 24 * 3600;
pub const DEFAULT_DECAY_SECONDS: i64 = 6 * 3600;
pub const WOULD_BAN_SCORE: i64 = 60;

#[derive(Debug, Clone)]
pub struct ScoringPolicy {
    pub weights: HashMap<String, i64>,
    pub category_cap: i64,
    pub window_seconds: i64,
    pub decay_seconds: i64,
}

impl Default for ScoringPolicy {
    fn default() -> Self {
        let pairs: &[(&str, i64)] = &[
            (EVENT_SCANNER_PATH, 35),
            (EVENT_SCANNER_DECISIVE, 60),
            (EVENT_QUERY_INJECTION, 60),
            (EVENT_SCANNER_MULTI, 20),
            (EVENT_LOW_AND_SLOW, 30),
            (EVENT_NOT_FOUND_ENUM, 15),
            (EVENT_WIDE_ENUM, 30),
            (EVENT_MASS_ENUM, 60),
            (EVENT_RECURRING, 30),
            (EVENT_INVALID_HOST, 10),
            (EVENT_NOSNI_PROBING, 10),
            (EVENT_RATE_EXCEEDED, 15),
            (EVENT_ERROR_RATE_EXCEEDED, 15),
            (EVENT_LEGACY_BAN, 30),
            (EVENT_HARD_FLOOR, 0),
            (EVENT_SUBNET_CAMPAIGN, 25),
        ];
        Self {
            weights: pairs.iter().map(|&(k, v)| (k.to_string(), v)).collect(),
            category_cap: DEFAULT_CATEGORY_CAP,
            window_seconds: DEFAULT_SCORE_WINDOW_SECONDS,
            decay_seconds: DEFAULT_DECAY_SECONDS,
        }
    }
}

impl ScoringPolicy {
    pub fn weight(&self, event_type: &str) -> i64 {
        self.weights.get(event_type).copied().unwrap_or(0)
    }

    /// Return the U02 variant where telemetry events weigh 0 and `HARD_FLOOR_EPISODE` weighs 60.
    pub fn u02(&self) -> Self {
        let mut weights = self.weights.clone();
        for ev in [
            EVENT_RATE_EXCEEDED,
            EVENT_ERROR_RATE_EXCEEDED,
            EVENT_LEGACY_BAN,
        ] {
            weights.insert(ev.to_string(), 0);
        }
        let hf = weights.entry(EVENT_HARD_FLOOR.to_string()).or_insert(0);
        if *hf == 0 {
            *hf = 60;
        }
        Self {
            weights,
            category_cap: self.category_cap,
            window_seconds: self.window_seconds,
            decay_seconds: self.decay_seconds,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub ts: i64,
    pub event_type: String,
    pub category: String,
    pub site: String,
    pub detail: String,
    pub handled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreContribution {
    pub ts: i64,
    pub event_type: String,
    pub category: String,
    pub points: f64,
    pub reason: String,
    pub site: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreResult {
    pub score: i64,
    pub state: &'static str,
    pub recommended_action: &'static str,
    pub events_counted: usize,
    pub categories: HashMap<String, f64>,
    pub contributions: Vec<ScoreContribution>,
}

pub fn state_for(score: i64) -> &'static str {
    if score >= 80 {
        "HOSTILE"
    } else if score >= 60 {
        "HIGH_RISK"
    } else if score >= 40 {
        "SUSPICIOUS"
    } else if score >= 20 {
        "WATCH"
    } else {
        "NORMAL"
    }
}

pub fn recommended_action(state: &str) -> &'static str {
    match state {
        "HOSTILE" => "long_ban",
        "HIGH_RISK" => "temporary_ban",
        "SUSPICIOUS" => "throttle",
        "WATCH" => "observe",
        _ => "none",
    }
}

fn own_ban_observation(detail: &str) -> bool {
    matches!(detail, "code=40" | "code=41" | "code=50")
}

/// Derive a 0..100 score and explanation matching Python `guardd.scoring.score_events`.
pub fn score_events(events: &[StoredEvent], now: i64, policy: &ScoringPolicy) -> ScoreResult {
    let mut total = 0.0_f64;
    let mut per_category: HashMap<String, f64> = HashMap::new();
    let mut contributions: Vec<ScoreContribution> = Vec::new();
    let mut counted = 0usize;

    for ev in events {
        let age = (now - ev.ts).max(0);
        if age > policy.window_seconds {
            continue;
        }
        let base = policy.weight(&ev.event_type);
        if base <= 0 {
            continue;
        }
        if ev.event_type == EVENT_LEGACY_BAN && own_ban_observation(&ev.detail) {
            continue;
        }
        if ev.handled && ev.event_type != EVENT_SCANNER_DECISIVE {
            contributions.push(ScoreContribution {
                ts: ev.ts,
                event_type: ev.event_type.clone(),
                category: ev.category.clone(),
                points: 0.0,
                reason: "already refused by the gateway".to_string(),
                site: ev.site.clone(),
                detail: ev.detail.clone(),
            });
            continue;
        }
        let decay = if policy.decay_seconds > 0 {
            (1.0 - (age as f64) / (policy.decay_seconds as f64)).max(0.0)
        } else {
            1.0
        };
        let points = (base as f64) * decay;
        if points <= 0.0 {
            continue;
        }

        let cat_key = if ev.category.is_empty() {
            ev.event_type.clone()
        } else {
            ev.category.clone()
        };
        let used = per_category.get(&cat_key).copied().unwrap_or(0.0);
        let ceiling = (policy.category_cap.max(base)) as f64;
        let allowed = (ceiling - used).max(0.0);
        let granted = points.min(allowed);
        per_category.insert(cat_key, used + granted);
        total += granted;
        counted += 1;
        contributions.push(ScoreContribution {
            ts: ev.ts,
            event_type: ev.event_type.clone(),
            category: ev.category.clone(),
            points: round2(granted),
            reason: if granted < points {
                "category cap reached".to_string()
            } else {
                "counted".to_string()
            },
            site: ev.site.clone(),
            detail: ev.detail.clone(),
        });
    }

    let score = (total.round() as i64).clamp(0, 100);
    let state = state_for(score);
    let categories = per_category
        .into_iter()
        .map(|(k, v)| (k, round2(v)))
        .collect();
    ScoreResult {
        score,
        state,
        recommended_action: recommended_action(state),
        events_counted: counted,
        categories,
        contributions,
    }
}

#[inline]
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Copy)]
enum IpNet {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl IpNet {
    fn parse(entry: &str) -> Option<Self> {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (addr_str, prefix_opt) = match trimmed.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u32>().ok()?)),
            None => (trimmed, None),
        };
        let addr: IpAddr = addr_str.parse().ok()?;
        match addr {
            IpAddr::V4(v4) => {
                let p = prefix_opt.unwrap_or(32);
                if p > 32 {
                    return None;
                }
                let mask = if p == 0 { 0 } else { !0u32 << (32 - p) };
                let net = u32::from(v4) & mask;
                Some(Self::V4 { net, mask })
            }
            IpAddr::V6(v6) => {
                let p = prefix_opt.unwrap_or(128);
                if p > 128 {
                    return None;
                }
                let mask = if p == 0 { 0 } else { !0u128 << (128 - p) };
                let net = u128::from(v6) & mask;
                Some(Self::V6 { net, mask })
            }
        }
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match (*self, addr) {
            (Self::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == net,
            (Self::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == net,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub excluded: bool,
    pub reason: String,
    pub source: String,
}

#[derive(Debug)]
pub struct ExclusionModel {
    whitelist_files: Vec<String>,
    trusted_networks: Vec<String>,
    networks: Vec<(IpNet, String)>,
    signatures: HashMap<String, (i64, u64)>,
    authenticated: HashSet<String>,
    pub geo_trusted: bool,
}

impl ExclusionModel {
    pub fn from_config(config: &GuardConfig) -> Self {
        let mut model = Self {
            whitelist_files: config.whitelist_files.clone(),
            trusted_networks: config.trusted_networks.clone(),
            networks: Vec::new(),
            signatures: HashMap::new(),
            authenticated: HashSet::new(),
            geo_trusted: true,
        };
        model.reload_files(true);
        model
    }

    pub fn reload_files(&mut self, force: bool) -> bool {
        let mut sigs = HashMap::new();
        for path in &self.whitelist_files {
            let meta = fs::metadata(path).ok();
            let sig = match meta {
                Some(m) => {
                    let mtime = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    (mtime, m.len())
                }
                None => (0, 0),
            };
            sigs.insert(path.clone(), sig);
        }
        if !force && sigs == self.signatures {
            return false;
        }
        let mut nets = Vec::new();
        for path in &self.whitelist_files {
            let source = source_of(path);
            if let Ok(content) = fs::read(path) {
                for raw in String::from_utf8_lossy(&content).lines() {
                    let line = raw.split('#').next().unwrap_or("").trim();
                    if let Some(tok) = line.split_whitespace().next() {
                        if let Some(net) = IpNet::parse(tok) {
                            nets.push((net, source.to_string()));
                        }
                    }
                }
            }
        }
        for entry in &self.trusted_networks {
            if let Some(net) = IpNet::parse(entry) {
                nets.push((net, "trusted-network".to_string()));
            }
        }
        self.networks = nets;
        self.signatures = sigs;
        true
    }

    pub fn refresh_authenticated(&mut self, rows: &HashMap<String, HashMap<String, String>>) {
        self.authenticated.clear();
        for (ip, fields) in rows {
            let gpc0 = fields
                .get("gpc0")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if gpc0 > 0 {
                self.authenticated.insert(ip.clone());
            }
        }
    }

    pub fn network_count(&self) -> usize {
        self.networks.len()
    }

    pub fn authenticated_count(&self) -> usize {
        self.authenticated.len()
    }

    pub fn verdict(&self, ip: &str) -> Verdict {
        if self.authenticated.contains(ip) {
            return Verdict {
                excluded: true,
                reason: "authenticated".to_string(),
                source: String::new(),
            };
        }
        let Ok(addr) = ip.parse::<IpAddr>() else {
            return Verdict {
                excluded: true,
                reason: "unparsable".to_string(),
                source: String::new(),
            };
        };
        if is_local_addr(addr) {
            return Verdict {
                excluded: true,
                reason: "local".to_string(),
                source: String::new(),
            };
        }
        for (net, source) in &self.networks {
            if source == "geo-whitelist" && !self.geo_trusted {
                continue;
            }
            if net.contains(addr) {
                return Verdict {
                    excluded: true,
                    reason: "whitelisted".to_string(),
                    source: source.clone(),
                };
            }
        }
        Verdict {
            excluded: false,
            reason: String::new(),
            source: String::new(),
        }
    }
}

fn source_of(path: &str) -> &'static str {
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("admin") {
        "admin"
    } else if name.contains("geo") {
        "geo-whitelist"
    } else {
        "whitelist"
    }
}

fn is_local_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || ((v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// True for routable/enforceable IPv4 addresses (mirrors Python `guardd.constants.enforceable`).
pub fn enforceable(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok()
}

pub fn ip_family(ip: &str) -> i64 {
    if ip.parse::<Ipv4Addr>().is_ok() {
        4
    } else if ip.parse::<Ipv6Addr>().is_ok() {
        6
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_with_decay_caps_and_u02() {
        let policy = ScoringPolicy::default();
        let events = vec![
            StoredEvent {
                ts: 1000,
                event_type: EVENT_SCANNER_PATH.to_string(),
                category: "wordpress".to_string(),
                site: "app.example.com".to_string(),
                detail: "/wp-login.php".to_string(),
                handled: false,
            },
            StoredEvent {
                ts: 1000,
                event_type: EVENT_SCANNER_PATH.to_string(),
                category: "wordpress".to_string(),
                site: "app.example.com".to_string(),
                detail: "/wp-admin".to_string(),
                handled: false,
            },
            StoredEvent {
                ts: 1000,
                event_type: EVENT_SUBNET_CAMPAIGN.to_string(),
                category: EVENT_SUBNET_CAMPAIGN.to_string(),
                site: "".to_string(),
                detail: "198.51.100.0/24".to_string(),
                handled: false,
            },
        ];
        // Second wordpress event hits category cap (max(25, 35) = 35), plus 25 for subnet = 60.
        let res = score_events(&events, 1000, &policy);
        assert_eq!(res.score, 60);
        assert_eq!(res.state, "HIGH_RISK");

        // Under U02, HARD_FLOOR_EPISODE weighs 60 while LEGACY_HAPROXY_BAN weighs 0.
        let u02 = policy.u02();
        assert_eq!(u02.weight(EVENT_HARD_FLOOR), 60);
        assert_eq!(u02.weight(EVENT_LEGACY_BAN), 0);
    }

    #[test]
    fn exclusion_model_checks_cidrs_and_geo_trust() {
        let mut cfg = GuardConfig::default();
        cfg.whitelist_files.clear();
        cfg.trusted_networks = vec!["10.20.0.0/16".to_string(), "2001:db8:1::/48".to_string()];
        let model = ExclusionModel::from_config(&cfg);

        assert_eq!(model.verdict("127.0.0.1").reason, "local");
        assert_eq!(model.verdict("10.20.30.40").source, "trusted-network");
        assert_eq!(model.verdict("2001:db8:1::42").source, "trusted-network");
        assert!(!model.verdict("198.51.100.1").excluded);
    }
}
