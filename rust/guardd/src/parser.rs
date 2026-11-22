//! Zero-regex byte-level HAProxy access-log parser.

use crate::signatures::{
    classify_raw_path, normalize_path, truncate_chars, unquote_strict, SignatureEngine,
    MAX_HOST_LENGTH, MAX_USER_AGENT_LENGTH,
};
use serde::Serialize;

/// One parsed HAProxy access-log line, matching Python `guardd.parser.ParsedRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedRequest {
    pub client_ip: String,
    pub status: u16,
    pub frontend: String,
    pub backend: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub bad_request: bool,
    pub query_flag: String,
    pub path_flag: String,
    pub observation_flags: Vec<String>,
    pub ts: i64,
    pub request_id: String,
    pub bytes_out: u64,
    pub duration_ms: i64,
    pub response_ms: i64,
    pub times: String,
    pub term: String,
    pub ban_reason: String,
    pub user_agent: String,
    pub authenticated_user: String,
    pub protocol: String,
}

impl ParsedRequest {
    /// True when HAProxy itself refused the client for identity (401 on `<NOSRV>`, 403, 451).
    pub fn denied_by_gateway(&self) -> bool {
        match self.status {
            403 | 451 => true,
            401 => self.backend.ends_with("/<NOSRV>"),
            _ => false,
        }
    }
}

/// Parse one HAProxy access-log line without regular expressions.
pub fn parse_access_line(line: &str, sigs: &SignatureEngine) -> Option<ParsedRequest> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let text = strip_syslog_prefix(trimmed);

    // 1. Client IP + ":<port>"
    let (client_ip, rest) = parse_client_and_port(text)?;
    let rest = skip_ws_required(rest)?;

    // 2. "[<stamp>]"
    let rest = rest.strip_prefix('[')?;
    let close_bracket = memchr::memchr(b']', rest.as_bytes())?;
    let stamp_str = &rest[..close_bracket];
    let rest = skip_ws_required(&rest[close_bracket + 1..])?;

    // 3. frontend, backend, times, status, bytes
    let (frontend, rest) = next_token(rest)?;
    let rest = skip_ws_required(rest)?;
    let (backend, rest) = next_token(rest)?;
    let rest = skip_ws_required(rest)?;
    let (times, rest) = next_token(rest)?;
    let rest = skip_ws_required(rest)?;
    let (status_tok, rest) = next_token(rest)?;
    let status = parse_status(status_tok)?;
    let rest = skip_ws_required(rest)?;
    let (bytes_tok, rest) = next_token(rest)?;
    let bytes_out = parse_bytes(bytes_tok)?;
    let remainder = skip_ws_required(rest)?;

    let ts = parse_stamp(stamp_str);
    let request_id = find_labelled_field(remainder, "id=").unwrap_or("");
    let term = next_token(remainder).map(|(t, _)| t).unwrap_or("");
    let ban_reason = find_ban_reason(remainder);

    // 4. Tail: "<METHOD> <URI> HTTP/<ver>" or "<BADREQ>"
    let Some((tail_start, method, uri, protocol)) = parse_access_tail(remainder) else {
        if remainder.trim_end().ends_with("<BADREQ>") {
            return Some(ParsedRequest {
                client_ip: client_ip.to_string(),
                status,
                frontend: frontend.to_string(),
                backend: backend.to_string(),
                method: String::new(),
                path: String::new(),
                host: String::new(),
                bad_request: true,
                query_flag: String::new(),
                path_flag: String::new(),
                observation_flags: Vec::new(),
                ts,
                request_id: request_id.to_string(),
                bytes_out,
                duration_ms: 0,
                response_ms: -1,
                times: String::new(),
                term: term.to_string(),
                ban_reason: ban_reason.to_string(),
                user_agent: String::new(),
                authenticated_user: String::new(),
                protocol: String::new(),
            });
        }
        return None;
    };

    let prefix = &remainder[..tail_start];
    let raw_ua = find_labelled_field_allow_empty(prefix, "ua=").unwrap_or("");
    let user_agent = if raw_ua == "-" {
        String::new()
    } else {
        truncate_chars(raw_ua, MAX_USER_AGENT_LENGTH).to_string()
    };

    let host_raw = find_labelled_field(remainder, "host=");
    let host = match host_raw {
        Some(h) if h != "-" && h != "{}" => truncate_chars(h, MAX_HOST_LENGTH).to_string(),
        _ => extract_host(uri),
    };

    let path = normalize_path(uri);
    let query_flag = sigs.classify_query(uri).to_string();
    let path_flag = classify_raw_path(uri).to_string();
    let observation_flags = sigs
        .observation_flags(uri)
        .into_iter()
        .map(String::from)
        .collect();
    let authenticated_user = authenticated_username(prefix);

    Some(ParsedRequest {
        client_ip: client_ip.to_string(),
        status,
        frontend: frontend.to_string(),
        backend: backend.to_string(),
        method: method.to_string(),
        path,
        host,
        bad_request: false,
        query_flag,
        path_flag,
        observation_flags,
        ts,
        request_id: request_id.to_string(),
        bytes_out,
        duration_ms: total_time(times),
        response_ms: response_time(times),
        times: truncate_chars(times, 40).to_string(),
        term: term.to_string(),
        ban_reason: ban_reason.to_string(),
        user_agent,
        authenticated_user,
        protocol: protocol.to_string(),
    })
}

/// Extract host from an absolute-form HTTP/2 target (`http://` or `https://`).
pub fn extract_host(value: &str) -> String {
    let rest = if let Some(r) = value.strip_prefix("https://") {
        r
    } else if let Some(r) = value.strip_prefix("http://") {
        r
    } else {
        return String::new();
    };
    let authority_end = rest
        .bytes()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let mut authority = &rest[..authority_end];
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }
    let host_slice = if let Some(after_open) = authority.strip_prefix('[') {
        match after_open.find(']') {
            Some(close) => &after_open[..close],
            None => return String::new(),
        }
    } else {
        match authority.find(':') {
            Some(colon) => &authority[..colon],
            None => authority,
        }
    };
    let trimmed = host_slice.trim();
    let mut cleaned = String::with_capacity(trimmed.len().min(MAX_HOST_LENGTH));
    for c in trimmed.chars() {
        let code = c as u32;
        if code <= 0x1F || code == 0x7F {
            continue;
        }
        cleaned.push(c.to_ascii_lowercase());
        if cleaned.len() >= MAX_HOST_LENGTH {
            break;
        }
    }
    cleaned
}

/// Pure arithmetic HAProxy `%t` (`DD/Mon/YYYY:HH:MM:SS`) -> UTC Unix epoch seconds.
pub fn parse_stamp(value: &str) -> i64 {
    let b = value.as_bytes();
    if b.len() < 20
        || b[2] != b'/'
        || b[6] != b'/'
        || b[11] != b':'
        || b[14] != b':'
        || b[17] != b':'
    {
        return 0;
    }
    let Some(day) = parse_2digits(b[0], b[1]) else {
        return 0;
    };
    let Some(month) = parse_month(&b[3..6]) else {
        return 0;
    };
    let Some(year) = parse_4digits(&b[7..11]) else {
        return 0;
    };
    let Some(hour) = parse_2digits(b[12], b[13]) else {
        return 0;
    };
    let Some(minute) = parse_2digits(b[15], b[16]) else {
        return 0;
    };
    let Some(second) = parse_2digits(b[18], b[19]) else {
        return 0;
    };
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return 0;
    }
    let days = days_from_civil(year as i64, month as u32, day);
    days * 86_400 + (hour as i64) * 3_600 + (minute as i64) * 60 + (second as i64)
}

/// Howard Hinnant's civil-to-days algorithm (UTC days since 1970-01-01).
#[inline]
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m = month;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

#[inline]
fn parse_2digits(a: u8, b: u8) -> Option<u32> {
    if a.is_ascii_digit() && b.is_ascii_digit() {
        Some(((a - b'0') as u32) * 10 + ((b - b'0') as u32))
    } else {
        None
    }
}

#[inline]
fn parse_4digits(s: &[u8]) -> Option<u32> {
    if s.iter().all(u8::is_ascii_digit) {
        Some(
            ((s[0] - b'0') as u32) * 1000
                + ((s[1] - b'0') as u32) * 100
                + ((s[2] - b'0') as u32) * 10
                + ((s[3] - b'0') as u32),
        )
    } else {
        None
    }
}

#[inline]
fn parse_month(m: &[u8]) -> Option<u8> {
    match m {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}

/// Strip rsyslog prefix: `^\S+\s+\S+\s+haproxy\[\d+\]:\s*`
fn strip_syslog_prefix(s: &str) -> &str {
    let Some((_, r1)) = next_token(s) else {
        return s;
    };
    let Some(r1) = skip_ws_required(r1) else {
        return s;
    };
    let Some((_, r2)) = next_token(r1) else {
        return s;
    };
    let Some(r2) = skip_ws_required(r2) else {
        return s;
    };
    let Some(after_hap) = r2.strip_prefix("haproxy[") else {
        return s;
    };
    let Some(close) = memchr::memchr(b']', after_hap.as_bytes()) else {
        return s;
    };
    if close == 0 || !after_hap[..close].bytes().all(|b| b.is_ascii_digit()) {
        return s;
    }
    let Some(after_colon) = after_hap[close + 1..].strip_prefix(':') else {
        return s;
    };
    after_colon.trim_start()
}

/// Parse `(\[[0-9A-Fa-f:]+\]|[0-9.]+):(\d+)` at the beginning of `s`.
fn parse_client_and_port(s: &str) -> Option<(&str, &str)> {
    let (tok, rest) = next_token(s)?;
    if let Some(after_open) = tok.strip_prefix('[') {
        let close = memchr::memchr(b']', after_open.as_bytes())?;
        let ip = &after_open[..close];
        if ip.is_empty() || !ip.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return None;
        }
        let port = after_open[close + 1..].strip_prefix(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((ip, rest))
    } else {
        let colon = memchr::memchr(b':', tok.as_bytes())?;
        let ip = &tok[..colon];
        let port = &tok[colon + 1..];
        if ip.is_empty()
            || !ip.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        Some((ip, rest))
    }
}

#[inline]
fn next_token(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && !b[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == 0 {
        None
    } else {
        Some((&s[..i], &s[i..]))
    }
}

#[inline]
fn skip_ws_required(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == 0 {
        None
    } else {
        Some(&s[i..])
    }
}

#[inline]
fn parse_status(tok: &str) -> Option<u16> {
    if tok == "-" {
        return Some(0);
    }
    if tok.len() == 3 && tok.bytes().all(|b| b.is_ascii_digit()) {
        tok.parse::<u16>().ok()
    } else {
        None
    }
}

#[inline]
fn parse_bytes(tok: &str) -> Option<u64> {
    if tok == "-" {
        return Some(0);
    }
    if !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit()) {
        tok.parse::<u64>().ok()
    } else {
        None
    }
}

/// Find `(?:^|\s)<key>(\S+)` in `s`.
fn find_labelled_field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let mut start = 0;
    while let Some(rel) = s[start..].find(key) {
        let pos = start + rel;
        if pos == 0 || s.as_bytes()[pos - 1].is_ascii_whitespace() {
            let val_start = pos + key.len();
            let rest = &s[val_start..];
            if let Some((tok, _)) = next_token(rest) {
                return Some(tok);
            }
        }
        start = pos + 1;
    }
    None
}

/// Find `(?:^|\s)<key>(\S*)` in `s` (allows empty value, matching `_UA_FIELD`).
fn find_labelled_field_allow_empty<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let mut start = 0;
    while let Some(rel) = s[start..].find(key) {
        let pos = start + rel;
        if pos == 0 || s.as_bytes()[pos - 1].is_ascii_whitespace() {
            let val_start = pos + key.len();
            let rest = &s[val_start..];
            let end = rest
                .bytes()
                .position(|b| b.is_ascii_whitespace())
                .unwrap_or(rest.len());
            return Some(&rest[..end]);
        }
        start = pos + 1;
    }
    None
}

fn find_ban_reason(remainder: &str) -> &str {
    const MARKER: &str = "ban_reason=\"";
    let Some(pos) = remainder.find(MARKER) else {
        return "";
    };
    let rest = &remainder[pos + MARKER.len()..];
    let Some(end) = memchr::memchr(b'"', rest.as_bytes()) else {
        return "";
    };
    truncate_chars(&rest[..end], 160)
}

/// Match `(?P<method>[A-Z]{3,10})\s+(?P<uri>\S+)\s+(?P<proto>HTTP/[0-9.]+)\s*$` from the right.
fn parse_access_tail(remainder: &str) -> Option<(usize, &str, &str, &str)> {
    let trimmed = remainder.trim_end();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();

    // 1. proto token at end
    let proto_start = rfind_ws(bytes).map(|i| i + 1).unwrap_or(0);
    let proto = &trimmed[proto_start..];
    let ver = proto.strip_prefix("HTTP/")?;
    if ver.is_empty() || !ver.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }

    // 2. uri token before proto
    let before_proto = trimmed[..proto_start].trim_end();
    if before_proto.is_empty() {
        return None;
    }
    let uri_start = rfind_ws(before_proto.as_bytes()).map(|i| i + 1).unwrap_or(0);
    let uri = &before_proto[uri_start..];
    if uri.is_empty() {
        return None;
    }

    // 3. method token before uri: 3..=10 uppercase ASCII letters
    let before_uri = before_proto[..uri_start].trim_end();
    if before_uri.is_empty() {
        return None;
    }
    let method_start = rfind_ws(before_uri.as_bytes())
        .map(|i| i + 1)
        .unwrap_or(0);
    let method = &before_uri[method_start..];
    if !(3..=10).contains(&method.len()) || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    Some((method_start, method, uri, proto))
}

#[inline]
fn rfind_ws(b: &[u8]) -> Option<usize> {
    let mut i = b.len();
    while i > 0 {
        i -= 1;
        if b[i].is_ascii_whitespace() {
            return Some(i);
        }
    }
    None
}

/// Match `(?:^|\s)auth_user=([A-Za-z0-9_.~%+-]*)\s*$` at the end of `prefix`.
fn authenticated_username(prefix: &str) -> String {
    let trimmed = prefix.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }
    let tok_start = rfind_ws(trimmed.as_bytes()).map(|i| i + 1).unwrap_or(0);
    let last_tok = &trimmed[tok_start..];
    let Some(raw) = last_tok.strip_prefix("auth_user=") else {
        return String::new();
    };
    if raw.is_empty() || raw == "-" {
        return String::new();
    }
    if !raw.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'~' | b'%' | b'+' | b'-')
    }) {
        return String::new();
    }
    let Some(decoded) = unquote_strict(raw) else {
        return String::new();
    };
    if decoded.chars().count() <= 128 && decoded.chars().all(|c| !c.is_control()) {
        decoded
    } else {
        String::new()
    }
}

/// Fourth field of `%TR/%Tw/%Tc/%Tr/%Ta`, or -1 when absent.
fn response_time(times: &str) -> i64 {
    let mut it = times.split('/');
    let Some(_) = it.next() else { return -1 };
    let Some(_) = it.next() else { return -1 };
    let Some(_) = it.next() else { return -1 };
    let Some(tr) = it.next() else { return -1 };
    let Some(_) = it.next() else { return -1 };
    if it.next().is_some() {
        return -1;
    }
    tr.parse::<i64>().unwrap_or(-1)
}

/// Last field of `%TR/%Tw/%Tc/%Tr/%Ta`, clamped at >= 0.
fn total_time(times: &str) -> i64 {
    let tail = times.rsplit('/').next().unwrap_or("");
    tail.parse::<i64>().unwrap_or(0).max(0)
}
