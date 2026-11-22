//! HAProxy stick-table ban enforcer and bounded two-tier enforcement queue.

use crate::runtime::{read_table, runtime_command, GuardConfig, RuntimeError, MODE_ENFORCE};
use crate::scoring::enforceable;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

pub const ADAPTIVE_BAN_CODE: i64 = 40;
pub const ADAPTIVE_PAGE_CODE: i64 = 41;
pub const MANUAL_BAN_CODE: i64 = 50;

#[inline]
pub fn is_adaptive_code(code: i64) -> bool {
    code == ADAPTIVE_BAN_CODE || code == ADAPTIVE_PAGE_CODE
}

/// Isolated ban path preserving the monitor-mode guarantee: applying a ban is
/// refused unless `mode == "enforce"`, whereas lifting is always permitted.
#[derive(Debug, Clone)]
pub struct Enforcer {
    pub haproxy_socket: String,
    pub mode: String,
    pub refused: u64,
    pub applied: u64,
    pub failed: u64,
    pub lifted: u64,
}

impl Enforcer {
    pub fn new(config: &GuardConfig, mode_override: Option<&str>) -> Self {
        let mode = mode_override
            .filter(|m| !m.is_empty())
            .unwrap_or(&config.mode)
            .to_string();
        Self {
            haproxy_socket: config.haproxy_socket.clone(),
            mode,
            refused: 0,
            applied: 0,
            failed: 0,
            lifted: 0,
        }
    }

    #[inline]
    pub fn allowed(&self) -> bool {
        self.mode == MODE_ENFORCE
    }

    pub fn set_mode(&mut self, mode: &str) -> Result<(), String> {
        if mode != "monitor" && mode != MODE_ENFORCE {
            return Err(format!("unsupported mode: {mode}"));
        }
        self.mode = mode.to_string();
        Ok(())
    }

    /// Place an adaptive ban (`gpc0=1`, `gpt0=<code>`) into HAProxy `tbl_ban`.
    pub fn ban(&mut self, ip: &str, code: i64) -> Result<bool, RuntimeError> {
        if !self.allowed() {
            self.refused += 1;
            return Ok(false);
        }
        if !enforceable(ip) {
            return Ok(false);
        }
        let cmd = format!("set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {code}");
        let answer = runtime_command(&self.haproxy_socket, &cmd)?;
        if !answer.trim().is_empty() {
            self.failed += 1;
            return Ok(false);
        }
        self.applied += 1;
        Ok(true)
    }

    /// Put a ban entry back into `tbl_ban` regardless of active mode.
    pub fn restore(&self, ip: &str, code: i64) -> Result<bool, RuntimeError> {
        if !enforceable(ip) {
            return Ok(false);
        }
        let cmd = format!("set table tbl_ban key {ip} data.gpc0 1 data.gpt0 {code}");
        let answer = runtime_command(&self.haproxy_socket, &cmd)?;
        Ok(answer.trim().is_empty())
    }

    /// Read all active bans (`gpc0 > 0`) in `tbl_ban` mapped to their `gpt0` reason code.
    pub fn active_bans(&self) -> Result<HashMap<String, i64>, RuntimeError> {
        let rows = read_table(&self.haproxy_socket, "tbl_ban", "")?;
        let mut out = HashMap::new();
        for (ip, fields) in rows {
            let gpc0 = fields
                .get("gpc0")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if gpc0 > 0 {
                let gpt0 = fields
                    .get("gpt0")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                out.insert(ip, gpt0);
            }
        }
        Ok(out)
    }

    /// Read only entries owned by guardd (`gpt0 in {40, 41}` and `gpc0 > 0`).
    pub fn adaptive_bans(&self) -> Result<HashMap<String, HashMap<String, String>>, RuntimeError> {
        let rows = read_table(&self.haproxy_socket, "tbl_ban", "")?;
        let mut out = HashMap::new();
        for (ip, fields) in rows {
            let gpc0 = fields
                .get("gpc0")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            let gpt0 = fields
                .get("gpt0")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if gpc0 > 0 && is_adaptive_code(gpt0) {
                out.insert(ip, fields);
            }
        }
        Ok(out)
    }

    /// Lift an adaptive ban after re-reading `tbl_ban` to ensure we never clear
    /// a manual or legacy HAProxy ban.
    pub fn lift(&mut self, ip: &str) -> Result<bool, RuntimeError> {
        let rows = read_table(&self.haproxy_socket, "tbl_ban", &format!("key {ip}"))?;
        let Some(fields) = rows.get(ip) else {
            return Ok(false);
        };
        let gpt0 = fields
            .get("gpt0")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if !is_adaptive_code(gpt0) {
            return Ok(false);
        }
        self.clear_entry(ip)?;
        self.lifted += 1;
        Ok(true)
    }

    /// Clear an entry only while it still carries `code`.
    pub fn lift_code(&mut self, ip: &str, code: i64) -> Result<bool, RuntimeError> {
        let rows = read_table(&self.haproxy_socket, "tbl_ban", &format!("key {ip}"))?;
        let Some(fields) = rows.get(ip) else {
            return Ok(false);
        };
        let gpt0 = fields
            .get("gpt0")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if gpt0 != code {
            return Ok(false);
        }
        self.clear_entry(ip)?;
        self.lifted += 1;
        Ok(true)
    }

    fn clear_entry(&mut self, ip: &str) -> Result<(), RuntimeError> {
        let answer = runtime_command(&self.haproxy_socket, &format!("clear table tbl_ban key {ip}"))?;
        if !answer.trim().is_empty() {
            self.failed += 1;
            let snippet: String = answer.trim().chars().take(200).collect();
            return Err(RuntimeError::TableUnreadable(format!(
                "HAProxy refused to lift the ban on {ip}: {snippet}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueStatus {
    pub queued: usize,
    pub urgent: usize,
    pub limit: usize,
    pub overflowed: u64,
}

/// Bounded two-tier enforcement queue (`urgent` vs normal) matching Python `guardd.live.EnforcementQueue`.
#[derive(Debug)]
pub struct EnforcementQueue {
    limit: usize,
    urgent: VecDeque<String>,
    normal: VecDeque<String>,
    /// ip -> (is_urgent, generation)
    entries: HashMap<String, (bool, u64)>,
    generation: u64,
    pub overflowed: u64,
}

impl EnforcementQueue {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            urgent: VecDeque::new(),
            normal: VecDeque::new(),
            entries: HashMap::new(),
            generation: 0,
            overflowed: 0,
        }
    }

    pub fn mark(&mut self, ip: &str, is_urgent: bool) {
        self.generation += 1;
        let gen = self.generation;
        if let Some((was_urgent, g)) = self.entries.get_mut(ip) {
            *g = gen;
            if is_urgent && !*was_urgent {
                *was_urgent = true;
                self.normal.retain(|x| x != ip);
                self.urgent.push_back(ip.to_string());
            }
            return;
        }
        if self.entries.len() >= self.limit {
            if is_urgent {
                if let Some(evicted) = self.normal.pop_front() {
                    self.entries.remove(&evicted);
                    self.overflowed += 1;
                } else {
                    self.overflowed += 1;
                    return;
                }
            } else {
                self.overflowed += 1;
                return;
            }
        }
        self.entries.insert(ip.to_string(), (is_urgent, gen));
        if is_urgent {
            self.urgent.push_back(ip.to_string());
        } else {
            self.normal.push_back(ip.to_string());
        }
    }

    pub fn has_urgent(&self) -> bool {
        !self.urgent.is_empty()
    }

    pub fn urgent_batch(&self, max_items: usize) -> Vec<(String, u64)> {
        self.urgent
            .iter()
            .take(max_items)
            .filter_map(|ip| self.entries.get(ip).map(|&(_, g)| (ip.clone(), g)))
            .collect()
    }

    pub fn batch(&self, max_items: usize) -> Vec<(String, u64)> {
        let mut out = Vec::with_capacity(max_items.min(self.entries.len()));
        for ip in self.urgent.iter().chain(self.normal.iter()) {
            if out.len() >= max_items {
                break;
            }
            if let Some(&(_, g)) = self.entries.get(ip) {
                out.push((ip.clone(), g));
            }
        }
        out
    }

    pub fn acknowledge(&mut self, ip: &str, generation: u64) {
        let Some(&(was_urgent, cur_gen)) = self.entries.get(ip) else {
            return;
        };
        if cur_gen != generation {
            return;
        }
        self.entries.remove(ip);
        if was_urgent {
            self.urgent.retain(|x| x != ip);
        } else {
            self.normal.retain(|x| x != ip);
        }
    }

    pub fn status(&self) -> QueueStatus {
        QueueStatus {
            queued: self.entries.len(),
            urgent: self.urgent.len(),
            limit: self.limit,
            overflowed: self.overflowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcer_blocks_bans_in_monitor_mode() {
        let cfg = GuardConfig::default();
        let mut enf = Enforcer::new(&cfg, Some("monitor"));
        assert!(!enf.allowed());
        assert!(!enf.ban("198.51.100.1", ADAPTIVE_BAN_CODE).unwrap());
        assert_eq!(enf.refused, 1);
    }

    #[test]
    fn queue_prioritizes_urgent_and_respects_generations() {
        let mut q = EnforcementQueue::new(3);
        q.mark("198.51.100.1", false);
        q.mark("198.51.100.2", false);
        q.mark("198.51.100.3", true);
        assert!(q.has_urgent());

        // Urgent entry displaces oldest normal entry when full.
        q.mark("198.51.100.4", true);
        assert_eq!(q.overflowed, 1);
        let urgent = q.urgent_batch(10);
        assert_eq!(urgent.len(), 2);
        assert_eq!(urgent[0].0, "198.51.100.3");
        assert_eq!(urgent[1].0, "198.51.100.4");

        // Stale generation acknowledgement must not remove a re-marked IP.
        let (ip, old_gen) = urgent[0].clone();
        q.mark(&ip, true);
        q.acknowledge(&ip, old_gen);
        assert_eq!(q.status().urgent, 2);
    }
}
