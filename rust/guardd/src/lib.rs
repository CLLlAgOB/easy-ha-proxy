//! High-throughput Rust hot-path core for `easy-ha-proxy-guardd`.
//!
//! Provides zero-regex HAProxy access-log parsing, Aho-Corasick User-Agent
//! matching, bounded path/query/protocol classification, elastic two-segment
//! SLRU per-IP memory (`IpMemory`), IPv4 `/24` campaign correlation
//! (`SubnetCorrelator`), and rotation-safe incremental log reading (`LogCursor`).

pub mod parser;
pub mod signatures;
pub mod tracking;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub use parser::{extract_host, parse_access_line, parse_stamp, ParsedRequest};
pub use signatures::{
    classify_raw_path, is_asset, is_authentication_endpoint, is_proto_ua_mismatch,
    is_unusual_method_probe, normalize_path, user_agent_token, SignatureEngine,
};
pub use tracking::{
    format_subnet24, ipv4_subnet24_key, IpActivity, IpMemory, LogCursor, SubnetCorrelator,
    SubnetSummary,
};

/// Opaque handle for C-ABI callers (e.g., optional Python `ctypes` bridge).
pub struct GuarddHandle {
    pub engine: SignatureEngine,
}

/// Create a `GuarddHandle` from an optional `scanner-signatures.json` path.
/// Pass NULL or an invalid path to fall back to built-in signatures.
///
/// # Safety
/// `sig_path` must be either null or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn guardd_engine_new(sig_path: *const c_char) -> *mut GuarddHandle {
    let engine = if sig_path.is_null() {
        SignatureEngine::builtin()
    } else {
        match CStr::from_ptr(sig_path).to_str() {
            Ok(p) if !p.is_empty() => {
                SignatureEngine::from_file(p).unwrap_or_else(|_| SignatureEngine::builtin())
            }
            _ => SignatureEngine::builtin(),
        }
    };
    Box::into_raw(Box::new(GuarddHandle { engine }))
}

/// Destroy a handle returned by `guardd_engine_new`.
///
/// # Safety
/// `handle` must be a valid pointer obtained from `guardd_engine_new` (or null).
#[no_mangle]
pub unsafe extern "C" fn guardd_engine_free(handle: *mut GuarddHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Parse a newline-separated batch of HAProxy access-log lines and return a
/// JSON array of `Option<ParsedRequest>` entries (caller must free with `guardd_string_free`).
///
/// # Safety
/// `handle` must be a valid handle; `lines_utf8` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn guardd_parse_batch_json(
    handle: *const GuarddHandle,
    lines_utf8: *const c_char,
) -> *mut c_char {
    if handle.is_null() || lines_utf8.is_null() {
        return std::ptr::null_mut();
    }
    let engine = &(*handle).engine;
    let Ok(input) = CStr::from_ptr(lines_utf8).to_str() else {
        return std::ptr::null_mut();
    };
    let parsed: Vec<Option<ParsedRequest>> = input
        .lines()
        .map(|line| parse_access_line(line, engine))
        .collect();
    let Ok(json) = serde_json::to_string(&parsed) else {
        return std::ptr::null_mut();
    };
    CString::new(json)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Free a string returned by `guardd_parse_batch_json`.
///
/// # Safety
/// `ptr` must be a pointer returned by `guardd_parse_batch_json` (or null).
#[no_mangle]
pub unsafe extern "C" fn guardd_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_h2_and_h1_lines() {
        let sigs = SignatureEngine::builtin();
        let h2 = "2026-08-11T06:18:05.912571+00:00 haproxy-easy haproxy[976]: \
            192.168.50.186:2160 [11/Aug/2026:06:18:05.863] fe_https~ be_admin/ui \
            11/0/0/30/47 200 786 ----- 1/1/0/0/0 0/0 \
            GET https://ha.easy-ha-proxy.test/haproxy/config/state HTTP/2.0";
        let req = parse_access_line(h2, &sigs).expect("h2 line should parse");
        assert_eq!(req.client_ip, "192.168.50.186");
        assert_eq!(req.status, 200);
        assert_eq!(req.frontend, "fe_https~");
        assert_eq!(req.backend, "be_admin/ui");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/haproxy/config/state");
        assert_eq!(req.host, "ha.easy-ha-proxy.test");
        assert_eq!(req.protocol, "HTTP/2.0");
        assert_eq!(req.response_ms, 30);
        assert_eq!(req.duration_ms, 47);
        assert_eq!(req.bytes_out, 786);
        assert_eq!(req.ts, 1_786_429_085);
        assert!(!req.bad_request);

        let non_access = "2026-08-11T06:03:01.160002+00:00 haproxy-easy haproxy[976]: \
            [WARNING]  (976) : Server be_site2/srv1 is UP";
        assert!(parse_access_line(non_access, &sigs).is_none());
    }

    #[test]
    fn parses_badreq_and_ban_reason_and_auth_user() {
        let sigs = SignatureEngine::builtin();
        let bad = "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: \
            203.0.113.5:5000 [11/Aug/2026:07:26:51.096] fe_https~ fe_https/<NOSRV> \
            0/-1/-1/-1/6 400 58 PR--- 1/1/0/0/0 0/0 id=req-1 ban_reason=\"adaptive ban\" <BADREQ>";
        let req = parse_access_line(bad, &sigs).expect("badreq should parse");
        assert!(req.bad_request);
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.ban_reason, "adaptive ban");
        assert_eq!(req.term, "PR---");

        let authed = "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: \
            203.0.113.5:5000 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 \
            0/0/1/5/6 200 123 ----- 1/1/0/0/0 0/0 host=app.example.com ua=Mozilla/5.0 auth_user=alice%40example.com GET /ok HTTP/2.0";
        let req2 = parse_access_line(authed, &sigs).expect("authed should parse");
        assert_eq!(req2.authenticated_user, "alice@example.com");
        assert_eq!(req2.host, "app.example.com");
        assert_eq!(req2.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn classifies_paths_queries_agents_and_protocol_anomalies() {
        let sigs = SignatureEngine::builtin();
        assert_eq!(sigs.classify_path("/.env"), "secrets");
        assert_eq!(sigs.classify_path("/api/.env.production"), "secrets");
        assert!(sigs.category_is_decisive("secrets"));
        assert_eq!(sigs.classify_path("/api/secondfactor/webauthn/credentials"), "");
        assert_eq!(sigs.classify_path("/static/wp-admin/logo.png"), "");
        assert_eq!(sigs.classify_path("/wp-admin/install.php"), "wordpress");

        assert_eq!(sigs.classify_query("/x?a=wget+http://1.2.3.4/a.sh"), "fetch-and-run");
        assert_eq!(sigs.classify_query("/x?cmd=hello"), "");
        assert_eq!(sigs.classify_query("/x?f=%252e%252e%252f%252e%252e%252fetc"), "traversal");
        assert_eq!(sigs.classify_query("/x?a=;id"), "shell-chaining");

        assert_eq!(classify_raw_path("/../../etc/passwd"), "path-traversal");
        assert_eq!(classify_raw_path("/a/../b"), "");

        let flags = sigs.observation_flags("/v1.41/containers/json?id=1%27+UNION+SELECT+1--");
        assert!(flags.contains(&"observe:sql-injection"));
        assert!(flags.contains(&"observe:service-api-probe"));

        let enc = sigs.observation_flags("/%252eenv");
        assert!(enc.contains(&"observe:encoded-sensitive-path"));

        assert_eq!(sigs.classify_user_agent("sqlmap/1.7"), ("sqlmap", "scanner-tool"));
        assert_eq!(sigs.classify_user_agent("Mozilla/5.0"), ("", ""));

        assert!(is_proto_ua_mismatch("HTTP/1.0", "Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36"));
        assert!(!is_proto_ua_mismatch("HTTP/2.0", "Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36"));
        assert!(is_unusual_method_probe("TRACE", "web"));
        assert!(is_unusual_method_probe("PROPFIND", "web"));
        assert!(!is_unusual_method_probe("PROPFIND", "webdav"));
    }

    #[test]
    fn slru_protects_repeat_and_promoted_ips_from_botnet_flood() {
        let mut mem = IpMemory::new(20, 32);
        mem.touch("198.51.100.1", 100);
        mem.touch("198.51.100.1", 101); // promoted on repeat
        mem.touch("198.51.100.2", 102);
        mem.promote("198.51.100.2"); // explicitly promoted
        assert_eq!(mem.segment_counts(), (2, 0));

        // Flood with 200 unique one-hit botnet IPs
        for i in 0..200 {
            let ip = format!("203.0.113.{}", i % 250);
            if ip != "198.51.100.1" && ip != "198.51.100.2" {
                mem.touch(&ip, 200 + i as i64);
            }
        }
        assert_eq!(mem.len(), 20);
        assert!(mem.get("198.51.100.1").is_some(), "repeat IP must survive flood");
        assert!(mem.get("198.51.100.2").is_some(), "promoted IP must survive flood");
    }

    #[test]
    fn subnet_correlator_tracks_routable_slash24_and_skips_cgnat() {
        assert!(ipv4_subnet24_key("127.0.0.1").is_none());
        assert!(ipv4_subnet24_key("100.64.1.2").is_none());
        assert!(ipv4_subnet24_key("100.127.255.1").is_none());
        assert!(ipv4_subnet24_key("2001:db8::1").is_none());
        assert!(ipv4_subnet24_key("198.51.100.10").is_some());

        let mut corr = SubnetCorrelator::default_config();
        assert_eq!(corr.observe("198.51.100.1", 1000), ("198.51.100.0/24".to_string(), 1));
        assert_eq!(corr.observe("198.51.100.2", 1010), ("198.51.100.0/24".to_string(), 2));
        assert_eq!(corr.observe("198.51.100.3", 1020), ("198.51.100.0/24".to_string(), 3));
        assert_eq!(corr.triggers, 1);
        assert_eq!(corr.summary(1020).hot_subnets, 1);
    }
}
