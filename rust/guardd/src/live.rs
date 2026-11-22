//! Compact in-memory `LiveBuffer` and per-minute `MinuteDigests` histograms.

use crate::parser::ParsedRequest;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};

pub const DIGEST_BOUNDS_MS: [i64; 18] = [
    5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000, 30000,
];
pub const DIGEST_BUCKETS: usize = DIGEST_BOUNDS_MS.len() + 1;
pub const DIGEST_CLOSE_SECONDS: i64 = 30;
pub const DIGEST_KEEP_SECONDS: i64 = 3 * 3600;
pub const DIGEST_MAX_BACKENDS: usize = 200;

/// Classify why HAProxy refused a request (matches Python `guardd.parser.live_refusal`).
pub fn live_refusal(status: u16, backend: &str, term: &str, ban_reason: &str) -> &'static str {
    if status == 423 || !ban_reason.is_empty() {
        return "banned";
    }
    if status == 429 {
        return "rate-limited";
    }
    if !backend.ends_with("/<NOSRV>") {
        return "";
    }
    match status {
        451 => "geo",
        401 => "zero-trust",
        403 => "denied",
        400 => "invalid-request",
        _ if term.starts_with("PR") => "refused",
        _ => "",
    }
}

#[inline]
fn digest_bucket(duration_ms: i64) -> usize {
    for (idx, &bound) in DIGEST_BOUNDS_MS.iter().enumerate() {
        if duration_ms <= bound {
            return idx;
        }
    }
    DIGEST_BOUNDS_MS.len()
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct RefusedCounts {
    pub geo: u64,
    pub banned: u64,
    pub rate: u64,
    pub other: u64,
}

#[derive(Debug, Default)]
struct MinuteEntry {
    backends: HashMap<String, [u64; DIGEST_BUCKETS]>,
    refused: RefusedCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompletedMinute {
    pub ts: i64,
    pub backends: HashMap<String, Vec<u64>>,
    pub refused: RefusedCounts,
}

/// Per-minute response-time histograms and refusal counts matching `/api/v1/guard/digest`.
#[derive(Debug, Default)]
pub struct MinuteDigests {
    minutes: BTreeMap<i64, MinuteEntry>,
    trim_minute: Option<i64>,
    pub late: u64,
}

impl MinuteDigests {
    pub fn new() -> Self {
        Self::default()
    }

    fn trim(&mut self, now: i64, force: bool) {
        let minute = now / 60;
        if !force && self.trim_minute == Some(minute) {
            return;
        }
        self.trim_minute = Some(minute);
        let cutoff = now - DIGEST_KEEP_SECONDS;
        self.minutes.retain(|&stamp, _| stamp >= cutoff);
    }

    pub fn add(&mut self, request: &ParsedRequest, ended: f64, now: i64) {
        let minute = ((ended as i64) / 60) * 60;
        let refusal = live_refusal(
            request.status,
            &request.backend,
            &request.term,
            &request.ban_reason,
        );
        let backend = request.backend.split('/').next().unwrap_or("");
        let answered = refusal.is_empty()
            && !request.bad_request
            && request.status > 0
            && request.response_ms >= 0
            && !backend.is_empty()
            && !request.backend.ends_with("/<NOSRV>");

        self.trim(now, false);
        if minute + 60 + DIGEST_CLOSE_SECONDS <= now {
            self.late += 1;
            return;
        }
        if refusal.is_empty() && !answered {
            return;
        }
        let entry = self.minutes.entry(minute).or_default();
        if !refusal.is_empty() {
            match refusal {
                "geo" => entry.refused.geo += 1,
                "banned" => entry.refused.banned += 1,
                "rate-limited" => entry.refused.rate += 1,
                _ => entry.refused.other += 1,
            }
            return;
        }
        if let Some(hist) = entry.backends.get_mut(backend) {
            hist[digest_bucket(request.response_ms)] += 1;
        } else if entry.backends.len() < DIGEST_MAX_BACKENDS {
            let mut hist = [0u64; DIGEST_BUCKETS];
            hist[digest_bucket(request.response_ms)] += 1;
            entry.backends.insert(backend.to_string(), hist);
        }
    }

    pub fn complete(&mut self, since: i64, now: i64) -> Vec<CompletedMinute> {
        self.trim(now, true);
        let mut out = Vec::new();
        for (&minute, entry) in &self.minutes {
            if minute > since && minute + 60 + DIGEST_CLOSE_SECONDS <= now {
                let backends = entry
                    .backends
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_vec()))
                    .collect();
                out.push(CompletedMinute {
                    ts: minute,
                    backends,
                    refused: entry.refused.clone(),
                });
            }
        }
        out
    }
}

/// Compact in-memory live request record (roughly 5x smaller than Python's 17-tuple of PyObjects).
#[derive(Debug, Clone, Serialize)]
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
    pub response_ms: i64,
    pub term: String,
    pub ban_reason: String,
    pub refusal: &'static str,
    pub request_id: String,
    pub user_agent: String,
    pub authenticated_user: String,
}

impl LiveRecord {
    pub fn from_parsed(req: &ParsedRequest, ts: f64) -> Self {
        let refusal = live_refusal(req.status, &req.backend, &req.term, &req.ban_reason);
        Self {
            ts,
            ip: req.client_ip.clone(),
            status: req.status,
            host: req.host.clone(),
            path: req.path.clone(),
            method: req.method.clone(),
            backend: req.backend.clone(),
            bytes_out: req.bytes_out,
            duration_ms: req.duration_ms,
            response_ms: req.response_ms,
            term: req.term.clone(),
            ban_reason: req.ban_reason.clone(),
            refusal,
            request_id: req.request_id.clone(),
            user_agent: req.user_agent.clone(),
            authenticated_user: req.authenticated_user.clone(),
        }
    }

    pub fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.ip.capacity()
            + self.host.capacity()
            + self.path.capacity()
            + self.method.capacity()
            + self.backend.capacity()
            + self.term.capacity()
            + self.ban_reason.capacity()
            + self.request_id.capacity()
            + self.user_agent.capacity()
            + self.authenticated_user.capacity()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveMemoryStatus {
    pub records: usize,
    pub max_records: usize,
    pub max_seconds: i64,
    pub held_bytes: usize,
    pub budget_bytes: usize,
    pub oldest_ts: f64,
    pub newest_ts: f64,
}

/// Fixed-budget ring buffer of recent requests for `/api/v1/guard/live/*`.
#[derive(Debug)]
pub struct LiveBuffer {
    pub max_records: usize,
    pub max_seconds: i64,
    pub budget_bytes: usize,
    records: VecDeque<LiveRecord>,
    held_bytes: usize,
}

impl LiveBuffer {
    pub fn new(max_records: usize, max_seconds: i64, budget_bytes: usize) -> Self {
        Self {
            max_records,
            max_seconds: max_seconds.max(60),
            budget_bytes,
            records: VecDeque::new(),
            held_bytes: 0,
        }
    }

    pub fn push(&mut self, record: LiveRecord) {
        if self.max_records == 0 {
            return;
        }
        let newest = record.ts;
        self.held_bytes += record.estimated_bytes();
        self.records.push_back(record);
        self.trim(newest);
    }

    pub fn trim(&mut self, newest: f64) -> usize {
        let cutoff = newest - (self.max_seconds as f64);
        let mut evicted = 0usize;
        while let Some(front) = self.records.front() {
            let over_count = self.records.len() > self.max_records;
            let over_age = front.ts < cutoff;
            let over_budget = self.budget_bytes > 0 && self.held_bytes > self.budget_bytes;
            if over_count || over_age || over_budget {
                if let Some(popped) = self.records.pop_front() {
                    self.held_bytes = self.held_bytes.saturating_sub(popped.estimated_bytes());
                    evicted += 1;
                }
            } else {
                break;
            }
        }
        evicted
    }

    /// Map of client IP -> latest verified username seen in the live buffer.
    pub fn identities(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for rec in &self.records {
            if !rec.authenticated_user.is_empty() {
                map.insert(rec.ip.clone(), rec.authenticated_user.clone());
            }
        }
        map
    }

    pub fn status(&self) -> LiveMemoryStatus {
        LiveMemoryStatus {
            records: self.records.len(),
            max_records: self.max_records,
            max_seconds: self.max_seconds,
            held_bytes: self.held_bytes,
            budget_bytes: self.budget_bytes,
            oldest_ts: self.records.front().map(|r| r.ts).unwrap_or(0.0),
            newest_ts: self.records.back().map(|r| r.ts).unwrap_or(0.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_access_line;
    use crate::signatures::SignatureEngine;

    #[test]
    fn minute_digests_buckets_and_refusals() {
        let sigs = SignatureEngine::builtin();
        let ok_line = "2026-08-11T06:18:05.912571+00:00 gw haproxy[1]: \
            203.0.113.1:1000 [11/Aug/2026:06:18:05.863] fe_https~ be_app/s1 \
            0/0/1/42/45 200 500 ----- 1/1/0/0/0 0/0 GET /ok HTTP/2.0";
        let geo_line = "2026-08-11T06:18:06.912571+00:00 gw haproxy[1]: \
            203.0.113.2:1001 [11/Aug/2026:06:18:06.863] fe_https~ fe_https/<NOSRV> \
            0/-1/-1/-1/2 451 80 PR--- 1/1/0/0/0 0/0 GET /.env HTTP/1.1";

        let mut digests = MinuteDigests::new();
        let req_ok = parse_access_line(ok_line, &sigs).unwrap();
        let req_geo = parse_access_line(geo_line, &sigs).unwrap();
        digests.add(&req_ok, 120.0, 125);
        digests.add(&req_geo, 121.0, 125);

        // Not complete yet at now=125 (needs >= 120 + 60 + 30 = 210)
        assert!(digests.complete(0, 180).is_empty());
        let done = digests.complete(0, 220);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].ts, 120);
        assert_eq!(done[0].refused.geo, 1);
        // 42ms lands in bucket index 3 (<= 50ms)
        assert_eq!(done[0].backends["be_app"][3], 1);
    }

    #[test]
    fn live_buffer_enforces_record_cap_and_tracks_identities() {
        let sigs = SignatureEngine::builtin();
        let line = "2026-08-11T06:18:05.912571+00:00 gw haproxy[1]: \
            203.0.113.1:1000 [11/Aug/2026:06:18:05.863] fe_https~ be_app/s1 \
            0/0/1/5/6 200 500 ----- 1/1/0/0/0 0/0 auth_user=alice GET /ok HTTP/2.0";
        let req = parse_access_line(line, &sigs).unwrap();
        let mut buf = LiveBuffer::new(2, 3600, 0);
        buf.push(LiveRecord::from_parsed(&req, 100.0));
        buf.push(LiveRecord::from_parsed(&req, 101.0));
        buf.push(LiveRecord::from_parsed(&req, 102.0));
        assert_eq!(buf.status().records, 2);
        assert_eq!(buf.identities().get("203.0.113.1").map(String::as_str), Some("alice"));
    }
}
