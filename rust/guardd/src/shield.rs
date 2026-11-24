//! The path shield (Python `guardd.enforcer.PathShield`): HAProxy refuses the
//! decisive signatures itself, from three runtime lists this keeps equal to
//! what the engine would ban for -- and empty unless the mode is enforce.

use crate::constants::MODE_ENFORCE;
use crate::context::RuleException;
use crate::haconfig::haproxy_config_path;
use crate::runtime::{runtime_command, RuntimeError};
use crate::signatures::SignatureEngine;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::OnceLock;

pub const SHIELD_ENABLED_KEY: &str = "path_shield_enabled";
pub const SHIELD_MAX_ENTRIES: usize = 2000;

fn rx(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn segment_ok(v: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"^[A-Za-z0-9._~+@%=,:!$()\[\]-]{1,128}$").is_match(v)
}

fn path_ok(v: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"^/[A-Za-z0-9._~+@%=,:!$()\[\]/-]{1,199}$").is_match(v)
}

fn host_ok(v: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    rx(&R, r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$").is_match(v)
}

/// The three list names the running configuration declares, if any.
pub fn read_shield_files(path: &str) -> Option<BTreeMap<String, String>> {
    static R: OnceLock<Regex> = OnceLock::new();
    let marker = rx(
        &R,
        r"(?m)^\s*# guardd-shield segments=(?P<segments>\S+) paths=(?P<paths>\S+) exempt=(?P<exempt>\S+)\s*$",
    );
    let p = if path.is_empty() {
        haproxy_config_path()
    } else {
        path.to_string()
    };
    let text = fs::read(&p)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())?;
    let c = marker.captures(&text)?;
    let mut out = BTreeMap::new();
    for k in ["segments", "paths", "exempt"] {
        out.insert(k.to_string(), c[k].to_string());
    }
    Some(out)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ShieldWanted {
    pub segments: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub exempt: BTreeSet<String>,
    pub skipped: Vec<String>,
}

/// What HAProxy should refuse by itself right now.
pub fn shield_entries(
    mode: &str,
    enabled: bool,
    modes: &BTreeMap<String, String>,
    exceptions: &[RuleException],
    now: i64,
    sigs: &SignatureEngine,
) -> Result<ShieldWanted, String> {
    let mut result = ShieldWanted::default();
    if mode != MODE_ENFORCE || !enabled {
        return Ok(result);
    }
    let enforcing = |category: &str| {
        sigs.category_is_decisive(category)
            && modes
                .get(&format!("path:{category}"))
                .map(String::as_str)
                .unwrap_or("enforce")
                == "enforce"
    };
    let mut skipped = BTreeSet::new();
    for (token, category) in sigs.segment_map() {
        if !enforcing(category) || token.ends_with('*') {
            continue;
        }
        let value = token.to_lowercase();
        if segment_ok(&value) {
            result.segments.insert(value);
        } else {
            skipped.insert(token.clone());
        }
    }
    for (token, category) in sigs.path_map() {
        if !enforcing(category) {
            continue;
        }
        if path_ok(token) {
            result.paths.insert(token.clone());
        } else {
            skipped.insert(token.clone());
        }
    }
    for row in exceptions {
        let Some(cat) = row.rule.strip_prefix("path:") else {
            continue;
        };
        if !sigs.category_is_decisive(cat) {
            continue;
        }
        if row.expires != 0 && row.expires <= now {
            continue;
        }
        for h in &row.scope.hosts {
            if host_ok(h) {
                result.exempt.insert(h.clone());
            }
        }
    }
    for (key, len) in [
        ("segments", result.segments.len()),
        ("paths", result.paths.len()),
        ("exempt", result.exempt.len()),
    ] {
        if len > SHIELD_MAX_ENTRIES {
            return Err(format!(
                "the path shield would hold {len} {key}; refusing a list that large"
            ));
        }
    }
    result.skipped = skipped.into_iter().take(20).collect();
    Ok(result)
}

/// Keeps HAProxy's three shield lists equal to the engine's decisive rules.
#[derive(Debug)]
pub struct PathShield {
    pub haproxy_socket: String,
    pub config_path: String,
    pub status: Value,
}

impl PathShield {
    pub fn new(haproxy_socket: &str) -> Self {
        Self {
            haproxy_socket: haproxy_socket.to_string(),
            config_path: String::new(),
            status: json!({"configured": false, "active": false, "segments": 0, "paths": 0,
                           "exempt_hosts": 0, "synced_at": 0, "replaced": 0, "error": null,
                           "skipped": []}),
        }
    }

    fn command(&self, command: &str) -> Result<String, RuntimeError> {
        runtime_command(&self.haproxy_socket, command)
    }

    /// The patterns HAProxy holds for one list.
    pub fn current(&self, name: &str) -> Result<BTreeSet<String>, String> {
        let answer = self
            .command(&format!("show acl {name}"))
            .map_err(|e| e.to_string())?;
        let mut values = BTreeSet::new();
        for line in answer.lines() {
            let mut parts = line.split_whitespace();
            let first = parts.next();
            let rest: Vec<&str> = parts.collect();
            if let (Some(f), false) = (first, rest.is_empty()) {
                if f.starts_with("0x") {
                    let value = line.trim_start()[f.len()..].trim().to_string();
                    values.insert(value);
                    continue;
                }
            }
            if !line.trim().is_empty() && !line.starts_with('#') {
                let snippet: String = line.trim().chars().take(120).collect();
                return Err(format!(
                    "HAProxy did not return the list {name}: {snippet:?}"
                ));
            }
        }
        Ok(values)
    }

    pub fn replace(&self, name: &str, values: &BTreeSet<String>) -> Result<(), String> {
        static R: OnceLock<Regex> = OnceLock::new();
        let answer = self
            .command(&format!("prepare acl {name}"))
            .map_err(|e| e.to_string())?;
        let Some(c) = rx(&R, r"New version created:\s*(\d+)").captures(&answer) else {
            let snippet: String = answer.trim().chars().take(120).collect();
            return Err(format!(
                "HAProxy did not prepare the list {name}: {snippet:?}"
            ));
        };
        let version = c[1].to_string();
        for value in values {
            let refused = self
                .command(&format!("add acl @{version} {name} {value}"))
                .map_err(|e| e.to_string())?;
            let refused = refused.trim();
            if !refused.is_empty() {
                let snippet: String = refused.chars().take(120).collect();
                return Err(format!("HAProxy refused {value:?} for {name}: {snippet}"));
            }
        }
        let refused = self
            .command(&format!("commit acl @{version} {name}"))
            .map_err(|e| e.to_string())?;
        if !refused.trim().is_empty() {
            let snippet: String = refused.trim().chars().take(120).collect();
            return Err(format!("HAProxy did not commit the list {name}: {snippet}"));
        }
        Ok(())
    }

    pub fn sync(&mut self, wanted: &ShieldWanted, now: i64) -> Value {
        let files = read_shield_files(&self.config_path);
        let mut status = json!({
            "configured": files.is_some(),
            "active": false,
            "segments": 0,
            "paths": 0,
            "exempt_hosts": 0,
            "synced_at": self.status.get("synced_at").cloned().unwrap_or(json!(0)),
            "replaced": self.status.get("replaced").cloned().unwrap_or(json!(0)),
            "error": null,
            "skipped": wanted.skipped,
        });
        let Some(files) = files else {
            self.status = status.clone();
            return status;
        };
        let outcome = (|| -> Result<(), String> {
            for (key, set) in [
                ("exempt", &wanted.exempt),
                ("segments", &wanted.segments),
                ("paths", &wanted.paths),
            ] {
                let name = &files[key];
                if &self.current(name)? != set {
                    self.replace(name, set)?;
                    let n = status["replaced"].as_i64().unwrap_or(0) + 1;
                    status["replaced"] = json!(n);
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                status["active"] = json!(!wanted.segments.is_empty() || !wanted.paths.is_empty());
                status["segments"] = json!(wanted.segments.len());
                status["paths"] = json!(wanted.paths.len());
                status["exempt_hosts"] = json!(wanted.exempt.len());
                status["synced_at"] = json!(now);
            }
            Err(err) => {
                status["error"] = json!(err.chars().take(300).collect::<String>());
            }
        }
        self.status = status.clone();
        status
    }
}
