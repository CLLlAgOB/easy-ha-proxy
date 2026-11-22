//! Minimal zero-dependency AF_UNIX HTTP/1.1 API server for `easy-ha-proxy-guardd`.

use crate::enforcer::{Enforcer, EnforcementQueue};
use crate::live::{LiveBuffer, MinuteDigests, DIGEST_BOUNDS_MS};
use crate::runtime::GuardConfig;
use crate::scoring::{score_events, ScoringPolicy};
use crate::signatures::SignatureEngine;
use crate::storage::SecurityDatabase;
use crate::tracking::{IpMemory, SubnetCorrelator};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

const MAX_HTTP_BODY_BYTES: usize = 65_536;
const REQUEST_TIMEOUT_SECS: u64 = 10;

pub struct DaemonState {
    pub config: GuardConfig,
    pub signatures: SignatureEngine,
    pub database: SecurityDatabase,
    pub enforcer: Enforcer,
    pub queue: EnforcementQueue,
    pub memory: IpMemory,
    pub subnets: SubnetCorrelator,
    pub live: LiveBuffer,
    pub digests: MinuteDigests,
    pub policy: ScoringPolicy,
    pub control_token: String,
    pub lines_read: u64,
    pub lines_parsed: u64,
}

impl DaemonState {
    pub fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub fn health_payload(&self, now: i64) -> Value {
        let (protected, probation) = self.memory.segment_counts();
        json!({
            "ok": true,
            "ts": now,
            "backend": "rust",
            "engine": {
                "mode": self.enforcer.mode,
                "enforcing": self.enforcer.allowed(),
                "lines_read": self.lines_read,
                "lines_parsed": self.lines_parsed,
                "tracked_ips": self.memory.len(),
                "memory_protected": protected,
                "memory_probation": probation,
                "memory_evictions": self.memory.evictions,
                "subnet_correlation": self.subnets.summary(now),
                "enforcement_queue": self.queue.status(),
                "signatures_version": self.signatures.version,
            },
            "live": self.live.status(),
        })
    }
}

/// Constant-time byte comparison to prevent timing leaks on `X-Guard-Token`.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() || ab.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// Dispatch one HTTP request against `DaemonState` and return `(status_code, json_value)`.
pub fn dispatch_http(
    state: &Arc<Mutex<DaemonState>>,
    method: &str,
    target: &str,
    token_header: &str,
    body: &[u8],
) -> (u16, Value) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let now = DaemonState::now_unix();

    match (method, path) {
        ("GET", "/api/v1/guard/health") => {
            let guard = state.lock().expect("state lock");
            (200, guard.health_payload(now))
        }
        ("GET", "/api/v1/guard/digest") => {
            let since = parse_query_param(query, "since")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            let mut guard = state.lock().expect("state lock");
            let minutes = guard.digests.complete(since, now);
            (
                200,
                json!({
                    "ok": true,
                    "now": now,
                    "bounds_ms": DIGEST_BOUNDS_MS,
                    "minutes": minutes,
                    "late": guard.digests.late,
                }),
            )
        }
        ("GET", "/api/v1/guard/live/memory") => {
            let guard = state.lock().expect("state lock");
            (200, json!({"ok": true, "memory": guard.live.status()}))
        }
        ("GET", "/api/v1/guard/identities") => {
            let guard = state.lock().expect("state lock");
            (200, json!({"ok": true, "users_by_ip": guard.live.identities()}))
        }
        ("GET", "/api/v1/guard/ip") => {
            let Some(ip) = parse_query_param(query, "ip").filter(|s| !s.is_empty()) else {
                return (400, json!({"ok": false, "error": "missing ip parameter"}));
            };
            let guard = state.lock().expect("state lock");
            let since = now - guard.policy.window_seconds;
            let events = guard
                .database
                .events_for_ip(ip, since)
                .unwrap_or_default();
            let score = score_events(&events, now, &guard.policy);
            (
                200,
                json!({
                    "ok": true,
                    "ip": ip,
                    "ts": now,
                    "score": score,
                }),
            )
        }
        ("POST", "/api/v1/guard/mode") => {
            let mut guard = state.lock().expect("state lock");
            if guard.control_token.is_empty() {
                return (403, json!({"ok": false, "error": "control token not configured"}));
            }
            if !constant_time_eq(token_header, &guard.control_token) {
                return (401, json!({"ok": false, "error": "unauthorized"}));
            }
            let Ok(payload) = serde_json::from_slice::<Value>(body) else {
                return (400, json!({"ok": false, "error": "invalid JSON body"}));
            };
            let Some(mode) = payload.get("mode").and_then(Value::as_str) else {
                return (400, json!({"ok": false, "error": "missing mode"}));
            };
            if let Err(err) = guard.enforcer.set_mode(mode) {
                return (400, json!({"ok": false, "error": err}));
            }
            if let Err(err) = guard.database.set_state("mode_override", mode) {
                return (500, json!({"ok": false, "error": err}));
            }
            (
                200,
                json!({
                    "ok": true,
                    "mode": guard.enforcer.mode,
                    "enforcing": guard.enforcer.allowed(),
                }),
            )
        }
        _ => (404, json!({"ok": false, "error": "not found"})),
    }
}

#[cfg(unix)]
fn handle_client(stream: UnixStream, state: Arc<Mutex<DaemonState>>) {
    let timeout = Some(Duration::from_secs(REQUEST_TIMEOUT_SECS));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else { return };
    let Some(target) = parts.next() else { return };

    let mut content_length: usize = 0;
    let mut token = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse::<usize>().unwrap_or(0);
                    } else if k.eq_ignore_ascii_case("x-guard-token") {
                        token = v.trim().to_string();
                    }
                }
            }
        }
    }

    let (code, payload) = if content_length > MAX_HTTP_BODY_BYTES {
        (413, json!({"ok": false, "error": "request body too large"}))
    } else {
        let mut body = vec![0u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            return;
        }
        dispatch_http(&state, method, target, &token, &body)
    };

    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let json_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        json_bytes.len()
    );
    let _ = writer.write_all(header.as_bytes());
    let _ = writer.write_all(&json_bytes);
    let _ = writer.flush();
}

/// Bind and serve the AF_UNIX HTTP API until `stop` becomes true.
#[cfg(unix)]
pub fn serve_unix_socket(
    socket_path: &str,
    state: Arc<Mutex<DaemonState>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(socket_path).map_err(|e| format!("bind {socket_path}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {e}"))?;

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let st = Arc::clone(&state);
                std::thread::spawn(move || handle_client(stream, st));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn http_over_unix(sock: &str, raw_req: &str) -> (u16, Value) {
        let mut stream = UnixStream::connect(sock).expect("connect");
        stream.write_all(raw_req.as_bytes()).expect("write");
        let mut resp = String::new();
        stream.read_to_string(&mut resp).expect("read");
        let (head, body) = resp.split_once("\r\n\r\n").expect("http split");
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .expect("status")
            .parse()
            .expect("u16");
        let json: Value = serde_json::from_str(body).expect("json");
        (status, json)
    }

    #[test]
    fn serves_health_and_authenticated_mode_switch_over_unix_socket() {
        let dir = std::env::temp_dir().join(format!("guardd_api_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock_path = dir.join("guardd.sock");
        let db_path = dir.join("security.db");
        let _ = std::fs::remove_file(&db_path);

        let cfg = GuardConfig::default();
        let db = SecurityDatabase::open(&db_path).expect("db");
        let enf = Enforcer::new(&cfg, None);
        let state = Arc::new(Mutex::new(DaemonState {
            config: cfg.clone(),
            signatures: SignatureEngine::builtin(),
            database: db,
            enforcer: enf,
            queue: EnforcementQueue::new(1000),
            memory: IpMemory::new(1000, 32),
            subnets: SubnetCorrelator::default_config(),
            live: LiveBuffer::new(1000, 3600, 0),
            digests: MinuteDigests::new(),
            policy: ScoringPolicy::default(),
            control_token: "test-secret-token".to_string(),
            lines_read: 42,
            lines_parsed: 40,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let st_bg = Arc::clone(&state);
        let sock_str = sock_path.to_str().unwrap().to_string();
        let sock_srv = sock_str.clone();
        let handle = std::thread::spawn(move || {
            let _ = serve_unix_socket(&sock_srv, st_bg, stop_bg);
        });

        for _ in 0..40 {
            if sock_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let (code, body) = http_over_unix(
            &sock_str,
            "GET /api/v1/guard/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(code, 200);
        assert_eq!(body["ok"], true);
        assert_eq!(body["backend"], "rust");
        assert_eq!(body["engine"]["lines_parsed"], 40);

        // Unauthorized POST must fail with 401.
        let payload = r#"{"mode":"enforce"}"#;
        let bad_req = format!(
            "POST /api/v1/guard/mode HTTP/1.1\r\nHost: localhost\r\nX-Guard-Token: wrong\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        );
        let (code_bad, _) = http_over_unix(&sock_str, &bad_req);
        assert_eq!(code_bad, 401);

        // Authorized POST switches mode and persists to security.db.
        let ok_req = format!(
            "POST /api/v1/guard/mode HTTP/1.1\r\nHost: localhost\r\nX-Guard-Token: test-secret-token\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        );
        let (code_ok, body_ok) = http_over_unix(&sock_str, &ok_req);
        assert_eq!(code_ok, 200);
        assert_eq!(body_ok["mode"], "enforce");
        assert_eq!(body_ok["enforcing"], true);

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
