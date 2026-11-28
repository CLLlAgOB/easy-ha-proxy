//! Compact in-memory `LiveBuffer` and per-minute `MinuteDigests` histograms.

use crate::parser::ParsedRequest;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

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
