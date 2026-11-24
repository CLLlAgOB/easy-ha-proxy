//! Observed rate warnings for trusted addresses, hard-floor episodes and the
//! ban policy watcher (Python `guardd.watchers`).

use crate::haconfig::{
    file_signature, haproxy_config_path, normalize_host, read_ban_policy, read_hard_floor,
    read_site_ceilings, IpNetwork, SiteCeiling, BAN_POLICY_LEGACY,
};
use crate::live::live_refusal;
use crate::parser::ParsedRequest;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

pub const RATE_WARNING: &str = "RATE_WARNING";
pub const TRUSTED_RATE_MAX_KEYS: usize = 4096;
pub const TRUSTED_RATE_MAX_PENDING: usize = 500;
pub const RATE_WARNINGS_KEEP_ROWS: i64 = 2000;
pub const RATE_WARNINGS_KEEP_DAYS: i64 = 30;
pub const RATE_CEILINGS_RECHECK: f64 = 60.0;

pub const HARD_FLOOR_SUSTAIN_READS: u32 = 2;
pub const HARD_FLOOR_MAX_TRACKED: usize = 4096;

pub const BAN_POLICY_STATE_KEY: &str = "ban_policy";
pub const LEGACY_BAN_CODES: [i64; 3] = [10, 20, 30];
pub const LEGACY_LIFTS_PER_CYCLE: usize = 200;
pub const BAN_SNAPSHOTS_KEPT: usize = 5;
pub const TRUST_AFTER_SIGN_IN_SECONDS: i64 = 7 * 86400;

pub fn is_legacy_code(code: i64) -> bool {
    LEGACY_BAN_CODES.contains(&code)
}

fn in_networks(ip: &str, networks: &[IpNetwork]) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(addr) => networks.iter().any(|n| n.contains(&addr)),
        Err(_) => false,
    }
}

/// One rate-warning episode, in the shape the database and API use.
#[derive(Debug, Clone)]
pub struct Episode {
    pub ip: String,
    pub site: String,
    pub trust: String,
    pub limit: i64,
    pub window: i64,
    pub enforced: bool,
    pub started: i64,
    pub ended: i64,
    pub last_over: i64,
    pub peak: i64,
    pub over_limit: i64,
    pub requests: i64,
    pub rate_limited: i64,
    pub banned: i64,
    pub rate_ban: bool,
}

impl Episode {
    pub fn to_json(&self, open: Option<bool>) -> Value {
        let mut v = json!({
            "kind": RATE_WARNING,
            "ip": self.ip,
            "site": self.site,
            "trust": self.trust,
            "limit": self.limit,
            "window": self.window,
            "enforced": self.enforced,
            "started": self.started,
            "ended": self.ended,
            "last_over": self.last_over,
            "peak": self.peak,
            "over_limit": self.over_limit,
            "requests": self.requests,
            "rate_limited": self.rate_limited,
            "banned": self.banned,
            "rate_ban": self.rate_ban,
        });
        if let Some(o) = open {
            v["open"] = Value::Bool(o);
        }
        v
    }
}

/// HAProxy's http_req_rate for one address on one site.
#[derive(Debug, Clone)]
struct TrustedCounter {
    start: i64,
    curr: i64,
    prev: i64,
    episode: Option<Episode>,
    order: u64,
}

impl TrustedCounter {
    fn add(&mut self, ts: i64, period: i64) -> i64 {
        let period = period.max(1);
        let ts = ts.max(self.start);
        let passed = (ts - self.start) / period;
        if passed >= 2 {
            self.prev = 0;
            self.curr = 0;
            self.start += passed * period;
        } else if passed == 1 {
            self.prev = self.curr;
            self.curr = 0;
            self.start += period;
        }
        self.curr += 1;
        let elapsed = ts - self.start;
        self.curr + (self.prev * (period - elapsed)).div_euclid(period)
    }
}

/// Episodes of trusted addresses going over a site's request limit.
#[derive(Debug)]
pub struct TrustedRates {
    path: String,
    sites: HashMap<String, SiteCeiling>,
    hosts: HashMap<String, String>,
    any_allow_list: bool,
    signature: Option<Option<(i128, u64)>>,
    checked: Option<Instant>,
    counters: HashMap<(String, String), TrustedCounter>,
    order: u64,
    finished: Vec<Episode>,
    pub max_keys: usize,
    pub clock: i64,
    pub opened: u64,
    pub evicted: u64,
    pub dropped: u64,
}

impl Default for TrustedRates {
    fn default() -> Self {
        Self::new("", TRUSTED_RATE_MAX_KEYS)
    }
}

impl TrustedRates {
    pub fn new(config_path: &str, max_keys: usize) -> Self {
        Self {
            path: config_path.to_string(),
            sites: HashMap::new(),
            hosts: HashMap::new(),
            any_allow_list: false,
            signature: None,
            checked: None,
            counters: HashMap::new(),
            order: 0,
            finished: Vec::new(),
            max_keys: max_keys.max(1),
            clock: 0,
            opened: 0,
            evicted: 0,
            dropped: 0,
        }
    }

    fn cfg_path(&self) -> String {
        if self.path.is_empty() {
            haproxy_config_path()
        } else {
            self.path.clone()
        }
    }

    pub fn reload(&mut self, force: bool) -> bool {
        let path = self.cfg_path();
        let signature = file_signature(&path);
        if !force && self.signature == Some(signature) {
            return false;
        }
        let sites = if signature.is_some() {
            read_site_ceilings(&path)
        } else {
            HashMap::new()
        };
        let mut hosts = HashMap::new();
        let mut ids: Vec<&String> = sites.keys().collect();
        ids.sort();
        for id in ids {
            for name in &sites[id].names {
                hosts.entry(name.clone()).or_insert_with(|| id.clone());
            }
        }
        let stale: Vec<(String, String)> = self
            .counters
            .keys()
            .filter(|k| self.sites.get(&k.1) != sites.get(&k.1))
            .cloned()
            .collect();
        for key in stale {
            if let Some(counter) = self.counters.remove(&key) {
                if let Some(ep) = counter.episode {
                    self.finish(ep);
                }
            }
        }
        self.any_allow_list = sites.values().any(|s| s.allow.is_some());
        self.sites = sites;
        self.hosts = hosts;
        self.signature = Some(signature);
        true
    }

    fn maybe_reload(&mut self) {
        let due = match self.checked {
            None => true,
            Some(t) => t.elapsed().as_secs_f64() >= RATE_CEILINGS_RECHECK,
        };
        if due {
            self.checked = Some(Instant::now());
            self.reload(false);
        }
    }

    pub fn observe(&mut self, request: &ParsedRequest, trust: &str, now: i64, stamp: Option<f64>) {
        if self.checked.is_none() {
            self.maybe_reload();
        }
        if trust.is_empty() && !self.any_allow_list {
            return;
        }
        let host = normalize_host(&request.host);
        if host.is_empty() {
            return;
        }
        let Some(site_id) = self.hosts.get(&host).cloned() else {
            return;
        };
        let Some(site) = self.sites.get(&site_id).cloned() else {
            return;
        };
        let mut trust = trust.to_string();
        if trust.is_empty() {
            match &site.allow {
                Some(nets) if in_networks(&request.client_ip, nets) => {
                    trust = "site-allow-list".into()
                }
                _ => return,
            }
        }
        let ts = stamp
            .map(|s| s as i64)
            .filter(|&s| s != 0)
            .or(Some(request.ts).filter(|&t| t != 0))
            .or(Some(now).filter(|&n| n != 0))
            .unwrap_or(self.clock);
        self.clock = self.clock.max(ts);
        let key = (request.client_ip.clone(), site.id.clone());
        self.order += 1;
        let order = self.order;
        if !self.counters.contains_key(&key) {
            self.counters.insert(
                key.clone(),
                TrustedCounter {
                    start: ts,
                    curr: 0,
                    prev: 0,
                    episode: None,
                    order,
                },
            );
            if self.counters.len() > self.max_keys {
                if let Some(oldest) = self
                    .counters
                    .iter()
                    .min_by_key(|(_, c)| c.order)
                    .map(|(k, _)| k.clone())
                {
                    if let Some(c) = self.counters.remove(&oldest) {
                        self.evicted += 1;
                        if let Some(ep) = c.episode {
                            self.finish(ep);
                        }
                    }
                }
            }
        }
        let Some(counter) = self.counters.get_mut(&key) else {
            return;
        };
        counter.order = order;
        let rate = counter.add(ts, site.window);
        let mut opened = false;
        if rate > site.limit {
            if counter.episode.is_none() {
                counter.episode = Some(Episode {
                    ip: request.client_ip.clone(),
                    site: site.id.clone(),
                    trust: trust.clone(),
                    limit: site.limit,
                    window: site.window,
                    enforced: site.enforced,
                    started: ts,
                    ended: ts,
                    last_over: ts,
                    peak: rate,
                    over_limit: 0,
                    requests: 0,
                    rate_limited: 0,
                    banned: 0,
                    rate_ban: false,
                });
                opened = true;
            }
            if let Some(ep) = counter.episode.as_mut() {
                ep.last_over = ts;
                ep.over_limit += 1;
                ep.peak = ep.peak.max(rate);
            }
        }
        if opened {
            self.opened += 1;
        }
        let Some(ep) = self.counters.get_mut(&key).and_then(|c| c.episode.as_mut()) else {
            return;
        };
        ep.requests += 1;
        ep.ended = ep.ended.max(ts);
        match live_refusal(
            request.status,
            &request.backend,
            &request.term,
            &request.ban_reason,
        ) {
            "rate-limited" => ep.rate_limited += 1,
            "banned" => ep.banned += 1,
            _ => {}
        }
        if request.ban_reason.starts_with("RATE_LIMIT_SITE") {
            ep.rate_ban = true;
        }
    }

    pub fn tick(&mut self, now: i64, idle: bool) {
        self.maybe_reload();
        let reference = if idle {
            self.clock.max(now)
        } else {
            self.clock
        };
        let mut finished = Vec::new();
        let mut remove = Vec::new();
        for (key, counter) in self.counters.iter_mut() {
            let window = self.sites.get(&key.1).map(|s| s.window).unwrap_or(0);
            if let Some(ep) = counter.episode.as_ref() {
                if reference - ep.last_over > window {
                    finished.push(counter.episode.take().unwrap_or_else(unreachable_episode));
                }
            }
            if counter.episode.is_none() && reference - counter.start > 2 * window {
                remove.push(key.clone());
            }
        }
        for key in remove {
            self.counters.remove(&key);
        }
        for ep in finished {
            self.finish(ep);
        }
    }

    pub fn finish_all(&mut self) {
        let mut eps = Vec::new();
        for counter in self.counters.values_mut() {
            if let Some(ep) = counter.episode.take() {
                eps.push(ep);
            }
        }
        for ep in eps {
            self.finish(ep);
        }
    }

    fn finish(&mut self, episode: Episode) {
        if self.finished.len() >= TRUSTED_RATE_MAX_PENDING {
            self.dropped += 1;
            return;
        }
        self.finished.push(episode);
    }

    pub fn take_finished(&mut self) -> Vec<Episode> {
        std::mem::take(&mut self.finished)
    }

    pub fn open_episodes(&self) -> Vec<Value> {
        let mut rows: Vec<&Episode> = self
            .counters
            .values()
            .filter_map(|c| c.episode.as_ref())
            .collect();
        rows.sort_by_key(|e| std::cmp::Reverse(e.started));
        rows.into_iter().map(|e| e.to_json(Some(true))).collect()
    }

    pub fn summary(&self) -> Value {
        json!({
            "sites": self.sites.len(),
            "tracked": self.counters.len(),
            "max_tracked": self.max_keys,
            "open": self.counters.values().filter(|c| c.episode.is_some()).count(),
            "opened": self.opened,
            "evicted": self.evicted,
            "dropped": self.dropped,
        })
    }
}

fn unreachable_episode() -> Episode {
    Episode {
        ip: String::new(),
        site: String::new(),
        trust: String::new(),
        limit: 0,
        window: 0,
        enforced: false,
        started: 0,
        ended: 0,
        last_over: 0,
        peak: 0,
        over_limit: 0,
        requests: 0,
        rate_limited: 0,
        banned: 0,
        rate_ban: false,
    }
}

/// (address, table, counter).
pub type FloorKey = (String, String, String);

/// Which addresses have stayed over a hard ceiling, read after read.
#[derive(Debug, Default)]
pub struct HardFloorWatch {
    pub config_path: String,
    key: Option<Option<(i128, u64)>>,
    checked: Option<Instant>,
    ceilings: BTreeMap<String, BTreeMap<String, i64>>,
    streak: BTreeMap<FloorKey, u32>,
    pub episodes: u64,
}

impl HardFloorWatch {
    pub fn ceilings(&mut self) -> &BTreeMap<String, BTreeMap<String, i64>> {
        let fresh =
            matches!(self.checked, Some(t) if t.elapsed().as_secs_f64() < RATE_CEILINGS_RECHECK);
        if !fresh {
            self.checked = Some(Instant::now());
            let path = if self.config_path.is_empty() {
                haproxy_config_path()
            } else {
                self.config_path.clone()
            };
            let key = file_signature(&path);
            if self.key != Some(key) {
                self.key = Some(key);
                self.ceilings = if key.is_some() {
                    read_hard_floor(&path)
                } else {
                    BTreeMap::new()
                };
            }
        }
        &self.ceilings
    }

    pub fn queries(&mut self) -> Vec<(String, String, i64)> {
        let mut out = Vec::new();
        for (table, limits) in self.ceilings() {
            for (counter, limit) in limits {
                out.push((table.clone(), counter.clone(), *limit));
            }
        }
        out
    }

    /// Take one read's offenders; return those now over for long enough.
    pub fn update(&mut self, over: &BTreeMap<FloorKey, (i64, i64)>) -> Vec<(FloorKey, (i64, i64))> {
        let mut streak = BTreeMap::new();
        let mut sustained = Vec::new();
        for (key, val) in over {
            let count = self.streak.get(key).copied().unwrap_or(0) + 1;
            if streak.len() < HARD_FLOOR_MAX_TRACKED {
                streak.insert(key.clone(), count);
            }
            if count >= HARD_FLOOR_SUSTAIN_READS {
                sustained.push((key.clone(), *val));
            }
        }
        self.streak = streak;
        self.episodes += sustained.len() as u64;
        sustained
    }

    pub fn summary(&self) -> Value {
        json!({
            "tables": self.ceilings.len(),
            "over_now": self.streak.len(),
            "sustained_reads": self.episodes,
        })
    }
}

/// The ban policy, re-read whenever the configuration file changes.
#[derive(Debug)]
pub struct BanPolicyWatch {
    pub config_path: String,
    key: Option<Option<(i128, u64)>>,
    policy: &'static str,
}

impl Default for BanPolicyWatch {
    fn default() -> Self {
        Self {
            config_path: String::new(),
            key: None,
            policy: BAN_POLICY_LEGACY,
        }
    }
}

impl BanPolicyWatch {
    pub fn current(&mut self) -> &'static str {
        let path = if self.config_path.is_empty() {
            haproxy_config_path()
        } else {
            self.config_path.clone()
        };
        let key = file_signature(&path);
        if self.key != Some(key) {
            self.key = Some(key);
            self.policy = if key.is_some() {
                read_ban_policy(&path)
            } else {
                BAN_POLICY_LEGACY
            };
        }
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_matches_haproxy_period_arithmetic() {
        let mut c = TrustedCounter {
            start: 100,
            curr: 0,
            prev: 0,
            episode: None,
            order: 0,
        };
        assert_eq!(c.add(100, 10), 1);
        assert_eq!(c.add(105, 10), 2);
        // Next period: prev=2 weighted by (10-elapsed)/10.
        assert_eq!(c.add(112, 10), 1 + (2 * 8) / 10);
        // Two periods later everything resets.
        assert_eq!(c.add(140, 10), 1);
    }

    #[test]
    fn hard_floor_needs_two_reads() {
        let mut w = HardFloorWatch::default();
        let mut over = BTreeMap::new();
        over.insert(
            (
                "1.2.3.4".to_string(),
                "t".to_string(),
                "conn_cur".to_string(),
            ),
            (900, 500),
        );
        assert!(w.update(&over).is_empty());
        assert_eq!(w.update(&over).len(), 1);
        assert!(w.update(&BTreeMap::new()).is_empty());
        assert!(w.update(&over).is_empty());
    }
}
