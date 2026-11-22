//! Engine-level constants and small helpers mirroring Python `guardd.constants`.
//!
//! Event names, weights and score bands live in `scoring`; signature limits in
//! `signatures`. Everything else the engine orchestration needs is here, with
//! the same names and values as the Python daemon so the two stay comparable.

use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::enforcer::{ADAPTIVE_BAN_CODE, ADAPTIVE_PAGE_CODE, MANUAL_BAN_CODE};
pub use crate::scoring::{
    EVENT_ERROR_RATE_EXCEEDED, EVENT_HARD_FLOOR, EVENT_HARD_FLOOR_TRUSTED, EVENT_INVALID_HOST,
    EVENT_LEGACY_BAN, EVENT_LOW_AND_SLOW, EVENT_MASS_ENUM, EVENT_NOSNI_PROBING,
    EVENT_NOT_FOUND_ENUM, EVENT_QUERY_INJECTION, EVENT_RATE_EXCEEDED, EVENT_RECURRING,
    EVENT_SCANNER_DECISIVE, EVENT_SCANNER_MULTI, EVENT_SCANNER_PATH, EVENT_SUBNET_CAMPAIGN,
    EVENT_WIDE_ENUM, WOULD_BAN_SCORE,
};

pub const MODE_OFF: &str = "off";
pub const MODE_MONITOR: &str = "monitor";
pub const MODE_ENFORCE: &str = "enforce";
pub const SUPPORTED_MODES: [&str; 3] = [MODE_OFF, MODE_MONITOR, MODE_ENFORCE];

pub const BAN_DURATIONS: [i64; 4] = [3600, 7 * 86400, 30 * 86400, 90 * 86400];
pub const BAN_DURATIONS_KEY: &str = "ban_durations";
pub const BAN_DURATIONS_CHANGED_KEY: &str = "ban_durations_changed_at";
pub const MIN_BAN_SECONDS: i64 = 60;
pub const MAX_BAN_SECONDS: i64 = 365 * 86400;
pub const MAX_BAN_STEPS: usize = 6;
pub const STRIKE_RETENTION_BASE_MULTIPLIER: i64 = 1;

pub const MANUAL_BAN_DEFAULT_SECONDS: i64 = 7 * 86400;

pub const DECISION_EVIDENCE_LISTED: usize = 12;
pub const DECISION_DETAIL_LENGTH: usize = 240;
pub const DECISION_REASON_MAX_BYTES: usize = 8192;
pub const DECISIONS_KEEP_ROWS: i64 = 20000;
pub const DECISION_PENDING_GRACE: i64 = 60;
pub const DECISION_FEED_SOURCES: [&str; 7] =
    ["adaptive", "operator", "restart", "haproxy", "policy", "expiry", "mode"];

pub fn decision_feed_kinds(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "all" => Some(&[]),
        "bans" => Some(&["applied", "restored", "observed"]),
        "lifts" => Some(&["lifted", "ended"]),
        _ => None,
    }
}

pub const PAGE_ESCALATION_PATHS: i64 = 2;
pub const FIRST_STEP_PAGE_KEY: &str = "first_step_page";
pub const KNOWN_BANS_STATE_KEY: &str = "known_bans";
pub const KNOWN_BANS_MAX: usize = 5000;
pub const LEGACY_OBSERVED_STATE_KEY: &str = "legacy_observed";
pub const LEGACY_READINGS_LISTED: usize = 6;

pub const BURST_WINDOW_SECONDS: i64 = 300;
pub const BURST_MIN_BANS: usize = 15;
pub const BURST_REPORT_GAP_SECONDS: i64 = 3600;
pub const ENGINE_FAILING_AFTER: u64 = 3;
pub const ENGINE_FAILING_RULE: &str = "security.engine_failing";

pub const EVENT_BAN_APPLIED: &str = "BAN_APPLIED";
pub const EVENT_BAN_LIFTED: &str = "BAN_LIFTED";
pub const EVENT_LEGACY_BAN_LIFTED: &str = "LEGACY_BAN_LIFTED";

pub const WATCH_SCORE: i64 = 20;

pub const DEFAULT_THRESHOLDS: [(i64, &str); 5] = [
    (80, "HOSTILE"),
    (60, "HIGH_RISK"),
    (40, "SUSPICIOUS"),
    (20, "WATCH"),
    (0, "NORMAL"),
];

/// Event types that carry a weight under the default policy (the keys of
/// Python `DEFAULT_WEIGHTS`, including the zero-weight hard floor).
pub const WEIGHTED_EVENTS: [&str; 16] = [
    EVENT_SCANNER_PATH,
    EVENT_SCANNER_DECISIVE,
    EVENT_QUERY_INJECTION,
    EVENT_SCANNER_MULTI,
    EVENT_LOW_AND_SLOW,
    EVENT_NOT_FOUND_ENUM,
    EVENT_WIDE_ENUM,
    EVENT_MASS_ENUM,
    EVENT_RECURRING,
    EVENT_INVALID_HOST,
    EVENT_NOSNI_PROBING,
    EVENT_RATE_EXCEEDED,
    EVENT_ERROR_RATE_EXCEEDED,
    EVENT_LEGACY_BAN,
    EVENT_HARD_FLOOR,
    EVENT_SUBNET_CAMPAIGN,
];

pub fn is_weighted_event(event_type: &str) -> bool {
    WEIGHTED_EVENTS.contains(&event_type)
}

pub fn default_weight(event_type: &str) -> i64 {
    match event_type {
        EVENT_SCANNER_PATH => 35,
        EVENT_SCANNER_DECISIVE | EVENT_QUERY_INJECTION | EVENT_MASS_ENUM => 60,
        EVENT_SCANNER_MULTI => 20,
        EVENT_LOW_AND_SLOW | EVENT_WIDE_ENUM | EVENT_RECURRING | EVENT_LEGACY_BAN => 30,
        EVENT_NOT_FOUND_ENUM | EVENT_RATE_EXCEEDED | EVENT_ERROR_RATE_EXCEEDED => 15,
        EVENT_INVALID_HOST | EVENT_NOSNI_PROBING => 10,
        EVENT_SUBNET_CAMPAIGN => 25,
        _ => 0,
    }
}

/// Cooldown per event type; 60 s for anything not listed.
pub fn cooldown_seconds(event_type: &str) -> i64 {
    match event_type {
        EVENT_SCANNER_PATH => 300,
        EVENT_SCANNER_MULTI | EVENT_NOT_FOUND_ENUM | EVENT_WIDE_ENUM => 900,
        EVENT_LOW_AND_SLOW | EVENT_MASS_ENUM => 3600,
        EVENT_RECURRING => 6 * 3600,
        EVENT_INVALID_HOST | EVENT_NOSNI_PROBING | EVENT_HARD_FLOOR | EVENT_HARD_FLOOR_TRUSTED => {
            600
        }
        EVENT_RATE_EXCEEDED | EVENT_ERROR_RATE_EXCEEDED => 60,
        EVENT_SUBNET_CAMPAIGN => 1800,
        _ => 60,
    }
}

pub fn is_subnet_campaign_trigger(event_type: &str) -> bool {
    matches!(
        event_type,
        EVENT_SCANNER_PATH
            | EVENT_SCANNER_DECISIVE
            | EVENT_QUERY_INJECTION
            | EVENT_WIDE_ENUM
            | EVENT_MASS_ENUM
            | EVENT_LOW_AND_SLOW
            | EVENT_HARD_FLOOR
    )
}

pub const SUBNET_CAMPAIGN_WINDOW: i64 = 1800;
pub const SUBNET_CAMPAIGN_MIN_IPS: usize = 3;

pub const MULTI_CATEGORY_MIN: usize = 3;
pub const MULTI_CATEGORY_WINDOW: i64 = 2 * 3600;
pub const LOW_AND_SLOW_MIN_HITS: u64 = 5;
pub const LOW_AND_SLOW_MIN_CATEGORIES: usize = 3;
pub const LOW_AND_SLOW_WINDOW: i64 = 6 * 3600;
pub const NOT_FOUND_MIN_DISTINCT: usize = 6;
pub const NOT_FOUND_WINDOW: i64 = 3600;
pub const ENUMERATION_STATUSES: [u16; 4] = [401, 403, 404, 410];
pub const WIDE_ENUM_MIN: u64 = 30;
pub const MASS_ENUM_MIN: u64 = 100;
pub const WIDE_ENUM_WINDOW: i64 = 600;
pub const INVALID_HOST_MIN: usize = 5;
pub const INVALID_HOST_WINDOW: i64 = 6 * 3600;

pub const QUALITY_AT_ONCE_SECONDS: i64 = 15;
pub const QUALITY_NETWORK_MIN: i64 = 3;
pub const QUALITY_NETWORKS_SHOWN: usize = 5;
pub const QUALITY_CACHE_SECONDS: i64 = 300;
pub const QUALITY_MAX_DAYS: i64 = 30;
pub const WEEKLY_SUMMARY_RULE: &str = "security.weekly_summary";
pub const WEEKLY_SUMMARY_KEY: &str = "weekly_summary_sent";
pub const WEEKLY_SUMMARY_WEEKDAY: u32 = 0; // Monday
pub const WEEKLY_SUMMARY_HOUR: u32 = 8;

pub const RECURRING_WINDOW: i64 = 30 * 86400;
pub const RECURRING_GAP: i64 = 2 * 3600;
pub const RECURRING_RECHECK: i64 = 600;

pub const CATCH_ALL_MIN_PATHS: usize = 3;
pub const CATCH_ALL_MAX_HOSTS: usize = 256;
pub const CATCH_ALL_MAX_SIZES: usize = 16;

pub const CANDIDATE_MIN_ADDRESSES: usize = 3;
pub const CANDIDATE_MAX_PATHS: usize = 20000;
pub const CANDIDATE_MAX_ADDRESSES: usize = 64;
pub const CANDIDATE_MAX_SERVED: usize = 50000;
pub const CANDIDATE_TTL: i64 = 7 * 86400;
pub const CANDIDATE_MAX_PATH_LENGTH: usize = 200;
pub const CANDIDATES_KEY: &str = "signature_candidates";
pub const CANDIDATES_DISMISSED_KEY: &str = "signature_candidates_dismissed";
pub const CANDIDATES_MAX_DISMISSED: usize = 500;

pub const TRAP_HOSTS_KEY: &str = "trap_hosts";
pub const UNKNOWN_HOSTS_KEY: &str = "unknown_hosts";
pub const MAX_TRAP_HOSTS: usize = 100;
pub const UNKNOWN_HOSTS_MAX: usize = 2000;
pub const UNKNOWN_HOSTS_TTL: i64 = 7 * 86400;
pub const SITE_NAMES_RECHECK: f64 = 60.0;

pub const SIGNATURE_OVERRIDES_KEY: &str = "signature_overrides";
pub const CUSTOM_CATEGORY: &str = "custom";
pub const MAX_CUSTOM_RULES: usize = 200;
pub const MAX_TOKEN_LENGTH: usize = 120;

pub fn is_signature_event(event_type: &str) -> bool {
    matches!(
        event_type,
        EVENT_SCANNER_PATH | EVENT_SCANNER_DECISIVE | EVENT_QUERY_INJECTION
    )
}

/// Findings that score even when HAProxy had already refused the request.
pub fn refusal_does_not_excuse(event_type: &str) -> bool {
    event_type == EVENT_SCANNER_DECISIVE
}

pub fn is_served(status: u16) -> bool {
    (200..300).contains(&status)
}

pub fn utc_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn utc_now_f() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Python `_safe_int`: `int(str(value).strip())`, 0 when unreadable.
pub fn safe_int_str(value: &str) -> i64 {
    value.trim().parse::<i64>().unwrap_or(0)
}

pub fn safe_int_value(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f.trunc() as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => safe_int_str(s),
        Some(Value::Bool(b)) => i64::from(*b),
        _ => 0,
    }
}

pub fn field_int(fields: &HashMap<String, String>, name: &str) -> i64 {
    fields.get(name).map(|v| safe_int_str(v)).unwrap_or(0)
}

/// Python `_clamp_int`.
pub fn clamp_int(value: Option<&Value>, default: i64, min_v: i64, max_v: i64) -> i64 {
    let parsed = match value {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        _ => None,
    };
    match parsed {
        Some(v) => v.clamp(min_v, max_v),
        None => default,
    }
}

pub fn clamp_str(value: Option<&str>, default: i64, min_v: i64, max_v: i64) -> i64 {
    match value.and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(v) => v.clamp(min_v, max_v),
        None => default,
    }
}

/// Check an operator-supplied ladder before it can ban anyone.
pub fn validate_ban_durations(data: &Value) -> Result<Vec<i64>, String> {
    let list = data
        .as_array()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| "ban durations must be a non-empty list".to_string())?;
    if list.len() > MAX_BAN_STEPS {
        return Err(format!("at most {MAX_BAN_STEPS} steps"));
    }
    let mut steps = Vec::with_capacity(list.len());
    for entry in list {
        let Some(n) = entry.as_i64() else {
            return Err("each step must be a whole number of seconds".to_string());
        };
        if !(MIN_BAN_SECONDS..=MAX_BAN_SECONDS).contains(&n) {
            return Err(format!(
                "each step must be between {MIN_BAN_SECONDS} seconds and {} days",
                MAX_BAN_SECONDS / 86400
            ));
        }
        steps.push(n);
    }
    if steps.windows(2).any(|w| w[1] < w[0]) {
        return Err("each step must be at least as long as the one before".to_string());
    }
    Ok(steps)
}

/// `detection_host`: a lower-case host name without a port, or an error.
pub fn detection_host(value: &str) -> Result<String, String> {
    const MSG: &str = "expected a host name without a port";
    if value.chars().count() > 253 {
        return Err(MSG.to_string());
    }
    let host = value.to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    let bytes = host.as_bytes();
    if bytes.is_empty() || host.contains("..") {
        return Err(MSG.to_string());
    }
    let ok_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok_mid = |b: u8| ok_char(b) || b == b'.' || b == b'-';
    if !ok_char(bytes[0]) || !ok_char(bytes[bytes.len() - 1]) {
        return Err(MSG.to_string());
    }
    if bytes.len() > 253 || !bytes.iter().all(|&b| ok_mid(b)) {
        return Err(MSG.to_string());
    }
    Ok(host)
}

/// zlib.crc32, used where Python keeps address keys stable across restarts.
pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

pub fn address_key(ip: &str) -> u32 {
    crc32(ip.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crc32_matches_zlib() {
        assert_eq!(crc32(b"hello"), 0x3610_a686);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn ban_durations_validated_like_python() {
        assert_eq!(validate_ban_durations(&json!([60, 3600])).unwrap(), vec![60, 3600]);
        assert!(validate_ban_durations(&json!([])).is_err());
        assert!(validate_ban_durations(&json!([3600, 60])).is_err());
        assert!(validate_ban_durations(&json!([true])).is_err());
        assert!(validate_ban_durations(&json!([1.5])).is_err());
        assert!(validate_ban_durations(&json!([59])).is_err());
    }

    #[test]
    fn detection_host_rules() {
        assert_eq!(detection_host("Example.COM.").unwrap(), "example.com");
        assert!(detection_host("a..b").is_err());
        assert!(detection_host("host:443").is_err());
        assert!(detection_host("").is_err());
    }
}
