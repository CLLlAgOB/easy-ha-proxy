//! Bounded per-IP SLRU memory, IPv4 /24 subnet correlator, and rotation-safe log cursor.

use crate::signatures::MAX_LOG_LINE_BYTES;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Stable 32-bit FNV-1a hash for compact path/key tracking inside `IpActivity`.
#[inline]
pub fn hash32(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Compact bounded LRU backed by a flat `Vec` (cache-friendly for <= 64 items).
#[derive(Debug, Clone, Default)]
struct SmallLru<K: PartialEq, V> {
    items: Vec<(K, V)>,
}

impl<K: PartialEq, V> SmallLru<K, V> {
    fn touch(&mut self, key: K, val: V, limit: usize) -> bool {
        if let Some(pos) = self.items.iter().position(|(k, _)| *k == key) {
            self.items.remove(pos);
            self.items.push((key, val));
            false
        } else {
            if limit > 0 && self.items.len() >= limit {
                self.items.remove(0);
            }
            if limit > 0 {
                self.items.push((key, val));
            }
            true
        }
    }

    fn clear(&mut self) {
        self.items.clear();
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn iter(&self) -> std::slice::Iter<'_, (K, V)> {
        self.items.iter()
    }
}

/// Fixed-memory per-IP activity record matching Python `guardd.tracking.IpActivity`.
#[derive(Debug, Clone, Default)]
pub struct IpActivity {
    pub first_seen: i64,
    pub last_seen: i64,
    pub requests: u64,
    pub errors: u64,
    pub not_found: u64,
    pub gateway_denied: u64,
    pub bad_requests: u64,
    pub reached_backend: bool,
    paths: SmallLru<u32, i64>,
    categories: SmallLru<String, i64>,
    pub scanner_hits: u64,
    pub scanner_hits_denied: u64,
    missing_paths: SmallLru<u32, i64>,
    refused_paths: SmallLru<u32, i64>,
    pub burst_start: i64,
    pub burst_misses: u64,
    invalid_host_keys: SmallLru<u32, i64>,
    pub invalid_host_since: i64,
    pub recurring_checked: i64,
}

impl IpActivity {
    pub fn new(ts: i64) -> Self {
        Self {
            first_seen: ts,
            last_seen: ts,
            ..Self::default()
        }
    }

    pub fn scanning_was_all_refused(&self) -> bool {
        self.scanner_hits > 0 && self.scanner_hits_denied >= self.scanner_hits
    }

    pub fn note_path(&mut self, path: &str, ts: i64, limit: usize) -> bool {
        self.paths.touch(hash32(path), ts, limit)
    }

    pub fn note_category(&mut self, category: &str, ts: i64, limit: usize) {
        self.categories.touch(category.to_string(), ts, limit);
    }

    pub fn note_missing(&mut self, path: &str, ts: i64, limit: usize) -> bool {
        self.missing_paths.touch(hash32(path), ts, limit)
    }

    pub fn note_refused(&mut self, path: &str, ts: i64, limit: usize, window: i64) -> bool {
        let fresh = self.refused_paths.touch(hash32(path), ts, limit);
        if !fresh {
            return false;
        }
        if ts - self.burst_start > window {
            self.burst_start = ts;
            self.burst_misses = 0;
        }
        self.burst_misses += 1;
        true
    }

    pub fn note_invalid_host(
        &mut self,
        key: &str,
        ts: i64,
        limit: usize,
        window: i64,
    ) -> Option<usize> {
        if self.invalid_host_since < ts - window {
            self.invalid_host_since = ts;
            self.invalid_host_keys.clear();
        }
        let fresh = self.invalid_host_keys.touch(hash32(key), ts, limit);
        if fresh {
            Some(self.invalid_host_keys.len())
        } else {
            None
        }
    }

    pub fn recent_categories(&self, since: i64) -> Vec<&str> {
        self.categories
            .iter()
            .filter_map(|(name, ts)| if *ts >= since { Some(name.as_str()) } else { None })
            .collect()
    }

    pub fn distinct_missing(&self, since: i64) -> usize {
        self.missing_paths
            .iter()
            .filter(|(_, ts)| *ts >= since)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Probation,
    Protected,
}

#[derive(Debug)]
struct Slot {
    ip: String,
    activity: IpActivity,
    segment: Segment,
    prev: Option<usize>,
    next: Option<usize>,
    alive: bool,
}

#[derive(Debug, Default)]
struct SegmentList {
    head: Option<usize>,
    tail: Option<usize>,
    len: usize,
}

/// O(1) elastic two-segment LRU (SLRU) matching Python `guardd.tracking.IpMemory`.
///
/// One-hit addresses enter `probation`; repeat or promoted addresses live in
/// `protected` (capped at 75% of `max_ips`, leaving >= 25% for probation churn).
#[derive(Debug)]
pub struct IpMemory {
    pub max_ips: usize,
    pub max_paths: usize,
    protected_limit: usize,
    index: HashMap<String, usize>,
    slots: Vec<Slot>,
    free: Vec<usize>,
    probation: SegmentList,
    protected: SegmentList,
    pub evictions: u64,
}

impl IpMemory {
    pub fn new(max_ips: usize, max_paths: usize) -> Self {
        let cap = max_ips.max(1);
        let protected_limit = if cap > 1 {
            cap.saturating_sub((cap / 4).max(1))
        } else {
            0
        };
        Self {
            max_ips: cap,
            max_paths,
            protected_limit,
            index: HashMap::with_capacity(cap.min(4096)),
            slots: Vec::with_capacity(cap.min(4096)),
            free: Vec::new(),
            probation: SegmentList::default(),
            protected: SegmentList::default(),
            evictions: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.probation.len + self.protected.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn segment_counts(&self) -> (usize, usize) {
        (self.protected.len, self.probation.len)
    }

    pub fn get(&self, ip: &str) -> Option<&IpActivity> {
        let &id = self.index.get(ip)?;
        Some(&self.slots[id].activity)
    }

    pub fn get_mut(&mut self, ip: &str) -> Option<&mut IpActivity> {
        let &id = self.index.get(ip)?;
        Some(&mut self.slots[id].activity)
    }

    /// Touch an IP at timestamp `ts`, promoting from probation to protected on second hit.
    pub fn touch(&mut self, ip: &str, ts: i64) -> &mut IpActivity {
        if let Some(&id) = self.index.get(ip) {
            self.slots[id].activity.last_seen = ts;
            let seg = self.slots[id].segment;
            match seg {
                Segment::Protected => {
                    self.detach(id, Segment::Protected);
                    self.push_back(id, Segment::Protected);
                }
                Segment::Probation => {
                    self.detach(id, Segment::Probation);
                    self.promote_slot(id);
                    self.enforce_cap();
                }
            }
            return &mut self.slots[id].activity;
        }

        let id = self.alloc_slot(ip.to_string(), IpActivity::new(ts), Segment::Probation);
        self.index.insert(self.slots[id].ip.clone(), id);
        self.push_back(id, Segment::Probation);
        self.enforce_cap();
        &mut self.slots[id].activity
    }

    /// Explicitly promote a flagged one-hit address into the protected segment.
    pub fn promote(&mut self, ip: &str) {
        let Some(&id) = self.index.get(ip) else {
            return;
        };
        if self.slots[id].segment == Segment::Probation {
            self.detach(id, Segment::Probation);
            self.promote_slot(id);
            self.enforce_cap();
        }
    }

    /// Remove entries with `last_seen < older_than`.
    pub fn prune(&mut self, older_than: i64) -> usize {
        let mut stale = Vec::new();
        for (id, slot) in self.slots.iter().enumerate() {
            if slot.alive && slot.activity.last_seen < older_than {
                stale.push(id);
            }
        }
        let count = stale.len();
        for id in stale {
            let seg = self.slots[id].segment;
            self.detach(id, seg);
            self.remove_slot(id);
        }
        count
    }

    fn alloc_slot(&mut self, ip: String, activity: IpActivity, segment: Segment) -> usize {
        if let Some(id) = self.free.pop() {
            self.slots[id] = Slot {
                ip,
                activity,
                segment,
                prev: None,
                next: None,
                alive: true,
            };
            id
        } else {
            let id = self.slots.len();
            self.slots.push(Slot {
                ip,
                activity,
                segment,
                prev: None,
                next: None,
                alive: true,
            });
            id
        }
    }

    fn remove_slot(&mut self, id: usize) {
        let ip = std::mem::take(&mut self.slots[id].ip);
        self.index.remove(&ip);
        self.slots[id].alive = false;
        self.slots[id].prev = None;
        self.slots[id].next = None;
        self.free.push(id);
    }

    fn promote_slot(&mut self, id: usize) {
        if self.protected_limit == 0 {
            self.slots[id].segment = Segment::Probation;
            self.push_back(id, Segment::Probation);
            return;
        }
        self.slots[id].segment = Segment::Protected;
        self.push_back(id, Segment::Protected);
        while self.protected.len > self.protected_limit {
            if let Some(demoted) = self.pop_front(Segment::Protected) {
                self.slots[demoted].segment = Segment::Probation;
                self.push_back(demoted, Segment::Probation);
            }
        }
    }

    fn enforce_cap(&mut self) {
        while self.len() > self.max_ips {
            let victim = if self.probation.len > 0 {
                self.pop_front(Segment::Probation)
            } else {
                self.pop_front(Segment::Protected)
            };
            if let Some(id) = victim {
                self.remove_slot(id);
                self.evictions += 1;
            } else {
                break;
            }
        }
    }

    fn list_mut(&mut self, seg: Segment) -> &mut SegmentList {
        match seg {
            Segment::Probation => &mut self.probation,
            Segment::Protected => &mut self.protected,
        }
    }

    fn push_back(&mut self, id: usize, seg: Segment) {
        let old_tail = self.list_mut(seg).tail;
        self.slots[id].prev = old_tail;
        self.slots[id].next = None;
        if let Some(t) = old_tail {
            self.slots[t].next = Some(id);
        } else {
            self.list_mut(seg).head = Some(id);
        }
        let list = self.list_mut(seg);
        list.tail = Some(id);
        list.len += 1;
    }

    fn pop_front(&mut self, seg: Segment) -> Option<usize> {
        let head = self.list_mut(seg).head?;
        self.detach(head, seg);
        Some(head)
    }

    fn detach(&mut self, id: usize, seg: Segment) {
        let prev = self.slots[id].prev;
        let next = self.slots[id].next;
        if let Some(p) = prev {
            self.slots[p].next = next;
        } else {
            self.list_mut(seg).head = next;
        }
        if let Some(n) = next {
            self.slots[n].prev = prev;
        } else {
            self.list_mut(seg).tail = prev;
        }
        self.slots[id].prev = None;
        self.slots[id].next = None;
        self.list_mut(seg).len -= 1;
    }
}

/// Return the IPv4 `/24` prefix as `(u32_key, formatted_cidr)` for routable IPv4,
/// skipping IPv6, loopback, link-local, multicast, unspecified, and RFC 6598 CGNAT (`100.64.0.0/10`).
pub fn ipv4_subnet24_key(ip: &str) -> Option<u32> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    if addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_unspecified()
    {
        return None;
    }
    let o = addr.octets();
    // RFC 6598 Carrier-Grade NAT: 100.64.0.0/10 -> first octet 100, second octet 64..=127
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return None;
    }
    Some(((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8))
}

pub fn format_subnet24(key: u32) -> String {
    format!(
        "{}.{}.{}.0/24",
        (key >> 24) & 0xFF,
        (key >> 16) & 0xFF,
        (key >> 8) & 0xFF
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct SubnetSummary {
    pub tracked_subnets: usize,
    pub hot_subnets: usize,
    pub triggers: u64,
    pub min_ips: usize,
    pub window_seconds: i64,
}

/// Bounded IPv4 `/24` campaign correlator matching Python `guardd.tracking.SubnetCorrelator`.
#[derive(Debug)]
pub struct SubnetCorrelator {
    pub window_seconds: i64,
    pub min_ips: usize,
    pub max_subnets: usize,
    pub max_ips_per_subnet: usize,
    order: Vec<u32>,
    subnets: HashMap<u32, Vec<(u32, i64)>>,
    pub triggers: u64,
}

impl SubnetCorrelator {
    pub fn new(
        window_seconds: i64,
        min_ips: usize,
        max_subnets: usize,
        max_ips_per_subnet: usize,
    ) -> Self {
        let min_ips = min_ips.max(2);
        Self {
            window_seconds: window_seconds.max(60),
            min_ips,
            max_subnets: max_subnets.max(16),
            max_ips_per_subnet: max_ips_per_subnet.max(min_ips),
            order: Vec::with_capacity(max_subnets.min(1024)),
            subnets: HashMap::with_capacity(max_subnets.min(1024)),
            triggers: 0,
        }
    }

    pub fn default_config() -> Self {
        Self::new(1800, 3, 1024, 32)
    }

    /// Observe an offending IPv4 address. Returns `(subnet_cidr, active_peer_count)`.
    pub fn observe(&mut self, ip: &str, now: i64) -> (String, usize) {
        let Some(subnet_key) = ipv4_subnet24_key(ip) else {
            return (String::new(), 0);
        };
        let ip_u32 = u32::from(ip.parse::<Ipv4Addr>().expect("validated IPv4"));
        let cutoff = now - self.window_seconds;

        if !self.subnets.contains_key(&subnet_key) {
            while self.subnets.len() >= self.max_subnets {
                if !self.order.is_empty() {
                    let oldest = self.order.remove(0);
                    self.subnets.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push(subnet_key);
            self.subnets.insert(subnet_key, Vec::with_capacity(8));
        } else if let Some(pos) = self.order.iter().position(|&k| k == subnet_key) {
            self.order.remove(pos);
            self.order.push(subnet_key);
        }

        let peers = self.subnets.get_mut(&subnet_key).expect("inserted");
        peers.retain(|&(_, seen)| seen >= cutoff);
        if let Some(pos) = peers.iter().position(|&(p, _)| p == ip_u32) {
            peers.remove(pos);
        }
        peers.push((ip_u32, now));
        while peers.len() > self.max_ips_per_subnet {
            peers.remove(0);
        }
        let count = peers.len();
        if count >= self.min_ips {
            self.triggers += 1;
        }
        (format_subnet24(subnet_key), count)
    }

    pub fn prune(&mut self, now: i64) -> usize {
        let cutoff = now - self.window_seconds;
        let mut empty = Vec::new();
        for (&subnet_key, peers) in self.subnets.iter_mut() {
            peers.retain(|&(_, seen)| seen >= cutoff);
            if peers.is_empty() {
                empty.push(subnet_key);
            }
        }
        let removed = empty.len();
        for key in empty {
            self.subnets.remove(&key);
            if let Some(pos) = self.order.iter().position(|&k| k == key) {
                self.order.remove(pos);
            }
        }
        removed
    }

    pub fn summary(&self, now: i64) -> SubnetSummary {
        let cutoff = now - self.window_seconds;
        let hot = self
            .subnets
            .values()
            .filter(|peers| peers.iter().filter(|&&(_, seen)| seen >= cutoff).count() >= self.min_ips)
            .count();
        SubnetSummary {
            tracked_subnets: self.subnets.len(),
            hot_subnets: hot,
            triggers: self.triggers,
            min_ips: self.min_ips,
            window_seconds: self.window_seconds,
        }
    }
}

/// Incremental log-file reader tracking `(inode, offset)` across rotations and truncations.
#[derive(Debug)]
pub struct LogCursor {
    pub path: PathBuf,
    pub inode: u64,
    pub offset: u64,
    pub rotations: u64,
    pub lag_bytes: u64,
    pub last_error: Option<String>,
}

impl LogCursor {
    pub fn new(path: impl Into<PathBuf>, inode: u64, offset: u64, rotations: u64) -> Self {
        Self {
            path: path.into(),
            inode,
            offset,
            rotations,
            lag_bytes: 0,
            last_error: None,
        }
    }

    #[cfg(unix)]
    fn stat_inode_size(&self) -> Result<(u64, u64), String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&self.path).map_err(|e| e.to_string())?;
        Ok((meta.ino(), meta.size()))
    }

    #[cfg(not(unix))]
    fn stat_inode_size(&self) -> Result<(u64, u64), String> {
        let meta = std::fs::metadata(&self.path).map_err(|e| e.to_string())?;
        Ok((1, meta.len()))
    }

    pub fn has_pending(&self) -> bool {
        let Ok((inode, size)) = self.stat_inode_size() else {
            return false;
        };
        if self.inode == 0 {
            return true;
        }
        inode != self.inode || size != self.offset
    }

    /// Read up to `max_bytes`, returning only complete newline-terminated lines.
    pub fn read(&mut self, max_bytes: usize) -> Vec<String> {
        let (inode, size) = match self.stat_inode_size() {
            Ok(v) => {
                self.last_error = None;
                v
            }
            Err(e) => {
                self.last_error = Some(e);
                return Vec::new();
            }
        };

        if self.inode == 0 {
            self.inode = inode;
            self.offset = size;
            return Vec::new();
        }
        if inode != self.inode {
            self.inode = inode;
            self.offset = 0;
            self.rotations += 1;
        } else if size < self.offset {
            self.offset = 0;
            self.rotations += 1;
        }

        if size <= self.offset {
            self.lag_bytes = 0;
            return Vec::new();
        }

        let remaining = size - self.offset;
        self.lag_bytes = remaining.saturating_sub(max_bytes as u64);

        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                self.last_error = Some(e.to_string());
                return Vec::new();
            }
        };
        if let Err(e) = file.seek(SeekFrom::Start(self.offset)) {
            self.last_error = Some(e.to_string());
            return Vec::new();
        }
        let mut buf = vec![0u8; max_bytes.min(remaining as usize)];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                self.last_error = Some(e.to_string());
                return Vec::new();
            }
        };
        buf.truncate(n);

        let Some(last_nl) = memchr::memrchr(b'\n', &buf) else {
            return Vec::new();
        };
        let consumed = last_nl + 1;
        self.offset += consumed as u64;

        let mut lines = Vec::new();
        for raw in buf[..consumed].split(|&b| b == b'\n') {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            if raw.is_empty() {
                continue;
            }
            let bounded = if raw.len() > MAX_LOG_LINE_BYTES {
                &raw[..MAX_LOG_LINE_BYTES]
            } else {
                raw
            };
            lines.push(String::from_utf8_lossy(bounded).into_owned());
        }
        lines
    }
}
