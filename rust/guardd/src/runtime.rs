//! Configuration loading (`guardd.json`) and native Unix-socket HAProxy runtime client.

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

pub const MODE_MONITOR: &str = "monitor";
pub const MODE_ENFORCE: &str = "enforce";
pub const DEFAULT_MAX_TRACKED_IPS: usize = 5000;
pub const DEFAULT_MAX_PATHS_PER_IP: usize = 32;
pub const RUNTIME_TIMEOUT_SECONDS: u64 = 5;
pub const RUNTIME_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardConfig {
    pub mode: String,
    pub poll_interval_seconds: i64,
    pub haproxy_socket: String,
    pub log_file: String,
    pub authelia_log_file: String,
    pub log_read_bytes_per_cycle: usize,
    pub live_buffer_records: usize,
    pub live_buffer_seconds: i64,
    pub whitelist_files: Vec<String>,
    pub trusted_networks: Vec<String>,
    pub max_tracked_ips: usize,
    pub max_paths_per_ip: usize,
    pub event_retention_days: i64,
    pub maintenance_interval_seconds: i64,
    pub request_log_enabled: bool,
    pub request_log_retention_days: i64,
    pub request_log_max_bytes: u64,
    pub request_log_reserved_free_bytes: u64,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            mode: MODE_MONITOR.to_string(),
            poll_interval_seconds: 10,
            haproxy_socket: "/run/haproxy/admin.sock".to_string(),
            log_file: "/var/log/haproxy.log".to_string(),
            authelia_log_file: String::new(),
            log_read_bytes_per_cycle: 4 * 1024 * 1024,
            live_buffer_records: 100_000,
            live_buffer_seconds: 3600,
            whitelist_files: vec![
                "/etc/haproxy/whitelist.ip".to_string(),
                "/etc/haproxy/admin.allow".to_string(),
                "/etc/haproxy/geoip/whitelist.geo".to_string(),
            ],
            trusted_networks: Vec::new(),
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            max_paths_per_ip: DEFAULT_MAX_PATHS_PER_IP,
            event_retention_days: 30,
            maintenance_interval_seconds: 300,
            request_log_enabled: false,
            request_log_retention_days: 3,
            request_log_max_bytes: 256 * 1024 * 1024,
            request_log_reserved_free_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Load `guardd.json`, falling back cleanly to defaults on missing or invalid file.
pub fn load_config(path: impl AsRef<Path>) -> GuardConfig {
    let raw: Value = match fs::read_to_string(path.as_ref()) {
        Ok(text) => serde_json::from_str(&text).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let Some(obj) = raw.as_object() else {
        return GuardConfig::default();
    };

    let def = GuardConfig::default();
    let mode = obj
        .get("mode")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|m| m == MODE_MONITOR || m == MODE_ENFORCE || m == "off")
        .unwrap_or_else(|| def.mode.clone());

    let limits = obj.get("limits").and_then(Value::as_object);
    let sources = obj.get("sources").and_then(Value::as_object);
    let exclusions = obj.get("exclusions").and_then(Value::as_object);
    let request_log = obj.get("request_log").and_then(Value::as_object);

    let str_or = |map: Option<&serde_json::Map<String, Value>>, key: &str, fallback: &str| {
        map.and_then(|m| m.get(key))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback)
            .to_string()
    };

    let str_list = |map: Option<&serde_json::Map<String, Value>>, key: &str, fallback: Vec<String>| {
        let Some(arr) = map.and_then(|m| m.get(key)).and_then(Value::as_array) else {
            return fallback;
        };
        let items: Vec<String> = arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if items.is_empty() {
            fallback
        } else {
            items
        }
    };

    GuardConfig {
        mode,
        poll_interval_seconds: clamp_i64(obj.get("poll_interval_seconds"), 10, 5, 60),
        haproxy_socket: str_or(sources, "haproxy_socket", &def.haproxy_socket),
        log_file: str_or(sources, "log_file", &def.log_file),
        authelia_log_file: str_or(sources, "authelia_log_file", ""),
        log_read_bytes_per_cycle: clamp_i64(
            limits.and_then(|m| m.get("log_read_bytes_per_cycle")),
            4 * 1024 * 1024,
            64 * 1024,
            64 * 1024 * 1024,
        ) as usize,
        live_buffer_records: clamp_i64(
            limits.and_then(|m| m.get("live_buffer_records")),
            100_000,
            0,
            1_000_000,
        ) as usize,
        live_buffer_seconds: clamp_i64(
            limits.and_then(|m| m.get("live_buffer_seconds")),
            3600,
            60,
            6 * 3600,
        ),
        whitelist_files: str_list(exclusions, "whitelist_files", def.whitelist_files),
        trusted_networks: str_list(exclusions, "trusted_networks", Vec::new()),
        max_tracked_ips: clamp_i64(
            limits.and_then(|m| m.get("max_tracked_ips")),
            DEFAULT_MAX_TRACKED_IPS as i64,
            1000,
            500_000,
        ) as usize,
        max_paths_per_ip: clamp_i64(
            limits.and_then(|m| m.get("max_paths_per_ip")),
            DEFAULT_MAX_PATHS_PER_IP as i64,
            8,
            256,
        ) as usize,
        event_retention_days: clamp_i64(
            limits.and_then(|m| m.get("event_retention_days")),
            30,
            1,
            365,
        ),
        maintenance_interval_seconds: clamp_i64(
            obj.get("maintenance_interval_seconds"),
            300,
            60,
            3600,
        ),
        request_log_enabled: request_log
            .and_then(|m| m.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        request_log_retention_days: clamp_i64(
            request_log.and_then(|m| m.get("retention_days")),
            3,
            1,
            30,
        ),
        request_log_max_bytes: clamp_i64(
            request_log.and_then(|m| m.get("max_bytes")),
            256 * 1024 * 1024,
            16 * 1024 * 1024,
            16 * 1024 * 1024 * 1024,
        ) as u64,
        request_log_reserved_free_bytes: clamp_i64(
            request_log.and_then(|m| m.get("reserved_free_bytes")),
            512 * 1024 * 1024,
            64 * 1024 * 1024,
            64 * 1024 * 1024 * 1024,
        ) as u64,
    }
}

fn clamp_i64(val: Option<&Value>, default: i64, min_v: i64, max_v: i64) -> i64 {
    let parsed = match val {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    };
    parsed.unwrap_or(default).clamp(min_v, max_v)
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(io::Error),
    AnswerTooLarge(String),
    TableUnreadable(String),
    /// HAProxy refused to remove a ban table entry: the ban still stands.
    LiftRefused(String),
}

impl RuntimeError {
    /// A lift refused, a table read that was not the table, an answer too
    /// large to have been read whole: the ban's state is unknown (R01/R10).
    pub fn ban_table_unsure(&self) -> bool {
        matches!(self, Self::AnswerTooLarge(_) | Self::TableUnreadable(_) | Self::LiftRefused(_))
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::AnswerTooLarge(m) | Self::TableUnreadable(m) | Self::LiftRefused(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<io::Error> for RuntimeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Send one command to HAProxy's AF_UNIX admin socket and read the full response
/// bounded by `RUNTIME_MAX_BYTES`.
#[cfg(unix)]
pub fn runtime_command(socket_path: &str, command: &str) -> Result<String, RuntimeError> {
    let mut stream = UnixStream::connect(socket_path)?;
    let timeout = Duration::from_secs(RUNTIME_TIMEOUT_SECONDS);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut payload = Vec::with_capacity(command.len() + 1);
    payload.extend_from_slice(command.as_bytes());
    payload.push(b'\n');
    stream.write_all(&payload)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 65_536];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > RUNTIME_MAX_BYTES {
            let cmd_head = command.split(" key ").next().unwrap_or(command);
            return Err(RuntimeError::AnswerTooLarge(format!(
                "HAProxy's answer to {cmd_head:?} is larger than {} MiB",
                RUNTIME_MAX_BYTES / (1024 * 1024)
            )));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(not(unix))]
pub fn runtime_command(_socket_path: &str, _command: &str) -> Result<String, RuntimeError> {
    Err(RuntimeError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "AF_UNIX sockets require Unix",
    )))
}

/// Read and parse a HAProxy stick-table (`show table <table> [selector]`).
pub fn read_table(
    socket_path: &str,
    table: &str,
    selector: &str,
) -> Result<HashMap<String, HashMap<String, String>>, RuntimeError> {
    let cmd = if selector.is_empty() {
        format!("show table {table}")
    } else {
        format!("show table {table} {selector}")
    };
    let payload = runtime_command(socket_path, &cmd)?;
    if selector.starts_with("key ") && payload.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let first = payload.split('\n').next().unwrap_or("").trim();
    let expected = format!("# table: {table},");
    if !first.starts_with(&expected) {
        let snippet: String = first.chars().take(120).collect();
        return Err(RuntimeError::TableUnreadable(format!(
            "HAProxy did not return table {table}: {snippet:?}"
        )));
    }
    Ok(parse_table(&payload))
}

/// Parse `show table <name>` text into `{key: {field: value}}` without regexes.
pub fn parse_table(payload: &str) -> HashMap<String, HashMap<String, String>> {
    let mut rows = HashMap::new();
    for raw in payload.lines() {
        let line = raw.trim();
        let Some(after_hex) = line.strip_prefix("0x") else {
            continue;
        };
        let Some(colon) = after_hex.find(':') else {
            continue;
        };
        if colon == 0 || !after_hex[..colon].bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let rest = after_hex[colon + 1..].trim_start();
        let Some(after_key) = rest.strip_prefix("key=") else {
            continue;
        };
        let mut tokens = after_key.split_whitespace();
        let Some(key) = tokens.next() else {
            continue;
        };
        let mut fields = HashMap::new();
        for tok in tokens {
            if let Some((name, val)) = tok.split_once('=') {
                if !name.is_empty() && !val.is_empty() {
                    fields.insert(name.to_string(), val.to_string());
                }
            }
        }
        rows.insert(key.to_string(), fields);
    }
    rows
}

/// List stick-table names via `show table`.
pub fn list_tables(socket_path: &str) -> Result<Vec<String>, RuntimeError> {
    let payload = runtime_command(socket_path, "show table")?;
    let mut names = Vec::new();
    for line in payload.lines() {
        if let Some(rest) = line.trim().strip_prefix("# table: ") {
            if let Some(name) = rest.split(',').next() {
                let n = name.trim();
                if !n.is_empty() {
                    names.push(n.to_string());
                }
            }
        }
    }
    Ok(names)
}

/// Every address currently banned (`gpt0 > 0`) in `tbl_ban`.
pub fn banned_now(socket_path: &str) -> Result<HashSet<String>, RuntimeError> {
    let rows = read_table(socket_path, "tbl_ban", "")?;
    let mut active = HashSet::new();
    for (ip, fields) in rows {
        let gpc0 = fields
            .get("gpc0")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(0);
        if gpc0 > 0 {
            active.insert(ip);
        }
    }
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stick_table_rows() {
        let sample = "# table: tbl_ban, type: ip, size:1048576, used:2\n\
            0x7f001: key=198.51.100.10 use=0 exp=86395000 gpt0=40 gpc0=1\n\
            0x7f002: key=203.0.113.5 use=0 exp=12000 gpt0=0 http_req_rate(10s)=42\n";
        let rows = parse_table(sample);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows["198.51.100.10"]["gpt0"], "40");
        assert_eq!(rows["203.0.113.5"]["http_req_rate(10s)"], "42");
    }

    #[cfg(unix)]
    #[test]
    fn reads_table_over_real_unix_socket() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let dir = std::env::temp_dir().join(format!("guardd_rt_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let sock_path = dir.join("admin.sock");
        let _ = fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = [0u8; 256];
                let _ = stream.read(&mut req);
                let resp = "# table: tbl_ban, type: ip, size:1024, used:1\n\
                    0x1: key=198.51.100.9 use=0 exp=300000 gpc0=1 gpt0=40\n";
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let banned = banned_now(sock_path.to_str().unwrap()).expect("banned_now");
        assert!(banned.contains("198.51.100.9"));
        let _ = server.join();
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir(&dir);
    }
}
