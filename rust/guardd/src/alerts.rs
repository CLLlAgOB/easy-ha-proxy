//! Best-effort client for the alert engine (Python `easy_ha_proxy_alert_client`).
//!
//! Enforcement never depends on it: every failure is swallowed, and an
//! unchanged observation is re-sent at most every two minutes.

use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const RESEND_UNCHANGED_SECONDS: f64 = 120.0;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 65536;

pub struct AlertClient {
    pub socket_path: String,
    token: String,
    last: Mutex<HashMap<String, (String, Instant)>>,
    warned: Mutex<bool>,
}

impl std::fmt::Debug for AlertClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertClient")
            .field("socket_path", &self.socket_path)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AlertClient {
    /// A client from the environment, or None when it is not configured.
    pub fn from_env() -> Option<Self> {
        let socket_path = std::env::var("ALERTD_SOCKET_PATH")
            .unwrap_or_else(|_| "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock".into());
        let token = std::env::var("ALERTD_TOKEN")
            .unwrap_or_default()
            .trim()
            .to_string();
        if token.is_empty() || socket_path.is_empty() {
            return None;
        }
        Some(Self {
            socket_path,
            token,
            last: Mutex::new(HashMap::new()),
            warned: Mutex::new(false),
        })
    }

    pub fn observe(
        &self,
        rule: &str,
        subject: &str,
        active: Option<bool>,
        summary: &str,
        detail: &str,
    ) -> bool {
        let key = format!("{rule}\u{0}{subject}");
        let signature = format!("{active:?}\u{0}{summary}\u{0}{detail}");
        {
            let last = self.last.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((sig, at)) = last.get(&key) {
                if *sig == signature && at.elapsed().as_secs_f64() < RESEND_UNCHANGED_SECONDS {
                    return true;
                }
            }
        }
        let mut payload = Map::new();
        payload.insert("rule".into(), json!(rule));
        payload.insert("subject".into(), json!(subject));
        if let Some(a) = active {
            payload.insert("active".into(), json!(a));
        }
        if !summary.is_empty() {
            payload.insert("summary".into(), json!(summary));
        }
        if !detail.is_empty() {
            payload.insert("detail".into(), json!(detail));
        }
        let delivered = self.post("/api/v1/alerts/notify", &Value::Object(payload));
        if delivered {
            let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
            if last.len() >= 2000 {
                last.clear();
            }
            last.insert(key, (signature, Instant::now()));
        }
        delivered
    }

    pub fn clear(&self, rule: &str, subject: &str, summary: &str) -> bool {
        self.observe(rule, subject, Some(false), summary, "")
    }

    #[cfg(unix)]
    fn post(&self, path: &str, payload: &Value) -> bool {
        use std::os::unix::net::UnixStream;
        let body = payload.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Alertd-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.token,
            body.len()
        );
        let outcome = (|| -> std::io::Result<Vec<u8>> {
            let mut stream = UnixStream::connect(&self.socket_path)?;
            stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
            stream.set_read_timeout(Some(READ_TIMEOUT))?;
            stream.write_all(request.as_bytes())?;
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];
            while out.len() < MAX_RESPONSE_BYTES {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Ok(out)
        })();
        match outcome {
            Ok(bytes) => {
                *self.warned.lock().unwrap_or_else(|p| p.into_inner()) = false;
                let head = String::from_utf8_lossy(&bytes);
                head.split("\r\n").next().unwrap_or("").contains(" 200 ")
            }
            Err(err) => {
                let mut warned = self.warned.lock().unwrap_or_else(|p| p.into_inner());
                if !*warned {
                    *warned = true;
                    eprintln!(
                        "alertd unreachable at {} ({err}); notifications are paused",
                        self.socket_path
                    );
                }
                false
            }
        }
    }

    #[cfg(not(unix))]
    fn post(&self, _path: &str, _payload: &Value) -> bool {
        false
    }
}
