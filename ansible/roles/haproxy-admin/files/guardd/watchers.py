"""Observed rate warnings, hard-floor episode tracking, and ban policy watcher."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import pathlib
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .constants import LOG
from .parser import live_refusal
from .scoring import HAPROXY_CONFIG_PATH, _THRESHOLD_RE, normalize_host

# ---------------------------------------------------------------------------
# Rate warnings for trusted addresses (observed only)
# ---------------------------------------------------------------------------
#
# A trusted address -- signed in, whitelisted, on the admin list, or allowed
# on a site that only lets named addresses in -- is not a stranger to slow
# down. Today HAProxy still applies a site's request limit to a signed-in
# user (429, and with rate_ban a week-long ban), and does not count the
# whitelist at all. Before that changes, this records how often trusted
# addresses actually go over a site's limit, and what the gateway did to
# them when they did.
#
# It changes nothing: no finding, no score, no strike, no ban. It is counted
# from the log the engine reads anyway, per address and site, the way HAProxy
# counts http_req_rate, and kept as one record per episode -- from the first
# request over the limit until the rate has stayed under it for a window --
# never one row per request.

RATE_WARNING = "RATE_WARNING"
# Address-and-site counters held at once; the least recently used goes first.
TRUSTED_RATE_MAX_KEYS = 4096
# Finished episodes waiting to be written; beyond that they are counted only.
TRUSTED_RATE_MAX_PENDING = 500
RATE_WARNINGS_KEEP_ROWS = 2000
RATE_WARNINGS_KEEP_DAYS = 30
# How often the ceilings are looked for again in the generated configuration.
RATE_CEILINGS_RECHECK = 60

_HOST_ACL_RE = re.compile(
    r"^\s*acl\s+host_(?P<id>[A-Za-z0-9_]+)\s+hdr\(host\)\s+-i\s+(?P<names>.+?)\s*$",
    re.MULTILINE,
)
_RATE_TABLE_RE = re.compile(
    r"^backend\s+tbl_rate_(?P<id>[A-Za-z0-9_]+)\s*\n\s*stick-table\b[^\n]*?"
    r"\bhttp_req_rate\((?P<window>[^)]+)\)",
    re.MULTILINE,
)
_SITE_IPS_RE = re.compile(
    r"^\s*acl\s+site_ips_(?P<id>[A-Za-z0-9_]+)\s+src\s+(?P<addresses>.+?)\s*$",
    re.MULTILINE,
)
# A site open only to named addresses has no rate table at all: a ceiling
# there could only ever throttle the operator. The template states the
# site's limit in a comment instead, for these warnings and nothing else.
_WARNING_ONLY_RE = re.compile(
    r"^\s*#\s*guardd-rate-warning\s+site=(?P<id>[A-Za-z0-9_]+)\s+gt\s+"
    r"(?P<limit>\d+)\s+per\s+(?P<window>\S+)\s*$",
    re.MULTILINE,
)
_HAPROXY_TIME_RE = re.compile(r"^\s*(?P<value>\d+)\s*(?P<unit>ms|s|m|h|d)?\s*$")
_TIME_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}


def haproxy_seconds(text: Any) -> int:
    """A HAProxy time such as 20s or 1m in whole seconds; 0 if unreadable.

    A bare number is milliseconds, as HAProxy reads it.
    """
    match = _HAPROXY_TIME_RE.match(str(text or ""))
    if not match:
        return 0
    value = int(match.group("value"))
    if value <= 0:
        return 0
    return max(1, int(value * _TIME_UNITS[match.group("unit") or "ms"]))


@dataclass(frozen=True)
class SiteCeiling:
    """One site's request limit, as the generated configuration states it."""

    id: str
    names: Tuple[str, ...]
    limit: int
    window: int
    # The networks a site open only to named addresses lets in; None for an
    # ordinary site.
    allow: Optional[Tuple[Any, ...]] = None
    # False where nothing applies the limit and only these warnings read it.
    enforced: bool = True


def read_site_ceilings(path: str = "") -> Dict[str, SiteCeiling]:
    """Every site with a request limit: its names, limit and window."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        LOG.warning("cannot read %s for site limits: %s", path or HAPROXY_CONFIG_PATH, exc)
        return {}
    limits = {
        match.group("table"): int(match.group("limit"))
        for match in _THRESHOLD_RE.finditer(text)
    }
    windows = {
        match.group("id"): haproxy_seconds(match.group("window"))
        for match in _RATE_TABLE_RE.finditer(text)
    }
    warning_only = {
        match.group("id"): (int(match.group("limit")), haproxy_seconds(match.group("window")))
        for match in _WARNING_ONLY_RE.finditer(text)
    }
    allowed: Dict[str, Tuple[Any, ...]] = {}
    for match in _SITE_IPS_RE.finditer(text):
        networks = []
        for token in match.group("addresses").split():
            with contextlib.suppress(ValueError):
                networks.append(ipaddress.ip_network(token, strict=False))
        allowed.setdefault(match.group("id"), tuple(networks))
    names: Dict[str, Tuple[str, ...]] = {}
    for match in _HOST_ACL_RE.finditer(text):
        # The same ACL is written once per frontend; the first one counts.
        names.setdefault(
            match.group("id"),
            tuple(name.lower() for name in match.group("names").split()),
        )
    sites: Dict[str, SiteCeiling] = {}
    for site_id, hostnames in names.items():
        limit = limits.get(f"tbl_rate_{site_id}")
        window = windows.get(site_id, 0)
        enforced = True
        if limit is None or window <= 0:
            if site_id not in warning_only:
                continue
            limit, window = warning_only[site_id]
            enforced = False
        if limit <= 0 or window <= 0:
            continue
        sites[site_id] = SiteCeiling(
            id=site_id,
            names=hostnames,
            limit=limit,
            window=window,
            allow=allowed.get(site_id),
            enforced=enforced,
        )
    return sites


def _in_networks(ip: str, networks: Iterable[Any]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(
        address.version == network.version and address in network
        for network in networks
    )


class _TrustedCounter:
    """HAProxy's http_req_rate for one address on one site.

    The same arithmetic as HAProxy's period counter: this period's count
    plus the previous period's, weighted by how much of the window it still
    covers. Agreeing with HAProxy matters more here than being exact.
    """

    __slots__ = ("start", "curr", "prev", "episode")

    def __init__(self, ts: int) -> None:
        self.start = ts
        self.curr = 0
        self.prev = 0
        self.episode: Optional[Dict[str, Any]] = None

    def add(self, ts: int, period: int) -> int:
        # A line logged late counts in the current period, not in the past.
        ts = max(ts, self.start)
        passed = (ts - self.start) // period
        if passed >= 2:
            self.prev = 0
            self.curr = 0
            self.start += passed * period
        elif passed == 1:
            self.prev = self.curr
            self.curr = 0
            self.start += period
        self.curr += 1
        elapsed = ts - self.start
        return self.curr + (self.prev * (period - elapsed)) // period


class TrustedRates:
    """Episodes of trusted addresses going over a site's request limit."""

    def __init__(self, config_path: str = "", max_keys: int = TRUSTED_RATE_MAX_KEYS) -> None:
        self._path = config_path
        self._lock = threading.Lock()
        self._sites: Dict[str, SiteCeiling] = {}
        self._hosts: Dict[str, str] = {}
        self._any_allow_list = False
        self._signature: Optional[Tuple[int, int]] = None
        self._checked = 0.0
        self._counters: "OrderedDict[Tuple[str, str], _TrustedCounter]" = OrderedDict()
        self._finished: List[Dict[str, Any]] = []
        self.max_keys = max(1, int(max_keys))
        # The newest request time seen: the clock episodes are closed by while
        # the log is being read, so a backlog does not close them too early.
        self.clock = 0
        self.opened = 0
        self.evicted = 0
        self.dropped = 0

    # -- the ceilings -----------------------------------------------------

    def reload(self, *, force: bool = False) -> bool:
        path = self._path or HAPROXY_CONFIG_PATH
        try:
            stat = os.stat(path)
            signature: Optional[Tuple[int, int]] = (int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            signature = None
        if not force and signature == self._signature:
            return False
        sites = read_site_ceilings(path) if signature is not None else {}
        hosts: Dict[str, str] = {}
        for site in sites.values():
            for name in site.names:
                hosts.setdefault(name, site.id)
        with self._lock:
            # An episode is measured against one limit. When the limit
            # changes or the site goes, it ends.
            for key in [k for k in self._counters if self._sites.get(k[1]) != sites.get(k[1])]:
                counter = self._counters.pop(key)
                if counter.episode is not None:
                    self._finish(counter.episode)
            self._sites = sites
            self._hosts = hosts
            self._any_allow_list = any(site.allow is not None for site in sites.values())
            self._signature = signature
        return True

    def _maybe_reload(self) -> None:
        moment = time.monotonic()
        if not self._checked or moment - self._checked >= RATE_CEILINGS_RECHECK:
            self._checked = moment
            self.reload()

    # -- observing --------------------------------------------------------

    def observe(self, request: "ParsedRequest", trust: str, now: int = 0,
                stamp: Optional[float] = None) -> None:
        """Count one request, if a trusted address made it to a limited site.

        ``stamp`` is the syslog time, which carries its zone. HAProxy's %t
        is local time without one, so on a gateway east of UTC it read an
        hour or more in the future; it is used only when a line has no
        syslog stamp.
        """
        if not self._checked:
            self._maybe_reload()
        if not trust and not self._any_allow_list:
            # Nearly every request: a stranger, and no site that trusts by
            # address. Costs nothing more than this test.
            return
        host = normalize_host(request.host)
        if not host:
            return
        with self._lock:
            site_id = self._hosts.get(host)
            site = self._sites.get(site_id or "")
            if site is None:
                return
            if not trust:
                # A stranger on an ordinary site: HAProxy's own limit applies
                # and the anonymous findings already cover it.
                if site.allow is None or not _in_networks(request.client_ip, site.allow):
                    return
                trust = "site-allow-list"
            ts = int(stamp or request.ts or now or self.clock)
            self.clock = max(self.clock, ts)
            key = (request.client_ip, site.id)
            counter = self._counters.get(key)
            if counter is None:
                counter = self._counters[key] = _TrustedCounter(ts)
                if len(self._counters) > self.max_keys:
                    _, oldest = self._counters.popitem(last=False)
                    self.evicted += 1
                    if oldest.episode is not None:
                        self._finish(oldest.episode)
            else:
                self._counters.move_to_end(key)
            rate = counter.add(ts, site.window)
            episode = counter.episode
            if rate > site.limit:
                if episode is None:
                    episode = counter.episode = {
                        "kind": RATE_WARNING,
                        "ip": request.client_ip,
                        "site": site.id,
                        "trust": trust,
                        "limit": site.limit,
                        "window": site.window,
                        "enforced": site.enforced,
                        "started": ts,
                        "ended": ts,
                        "last_over": ts,
                        "peak": rate,
                        "over_limit": 0,
                        "requests": 0,
                        "rate_limited": 0,
                        "banned": 0,
                        "rate_ban": False,
                    }
                    self.opened += 1
                episode["last_over"] = ts
                episode["over_limit"] += 1
                episode["peak"] = max(episode["peak"], rate)
            if episode is None:
                return
            # What the gateway did with it under the rules in force today.
            episode["requests"] += 1
            episode["ended"] = max(episode["ended"], ts)
            refusal = live_refusal(request.status, request.backend, request.term, request.ban_reason)
            if refusal == "rate-limited":
                episode["rate_limited"] += 1
            elif refusal == "banned":
                episode["banned"] += 1
            if request.ban_reason.startswith("RATE_LIMIT_SITE"):
                episode["rate_ban"] = True

    def tick(self, now: int, *, idle: bool) -> None:
        """End the episodes whose rate has stayed under the limit for a window.

        While lines are coming in, the clock is the newest request; with the
        log caught up, it is the wall clock.
        """
        self._maybe_reload()
        with self._lock:
            reference = max(self.clock, int(now)) if idle else self.clock
            for key, counter in list(self._counters.items()):
                site = self._sites.get(key[1])
                window = site.window if site else 0
                episode = counter.episode
                if episode is not None and reference - episode["last_over"] > window:
                    self._finish(episode)
                    counter.episode = None
                if counter.episode is None and reference - counter.start > 2 * window:
                    del self._counters[key]

    def finish_all(self) -> None:
        with self._lock:
            for counter in self._counters.values():
                if counter.episode is not None:
                    self._finish(counter.episode)
                    counter.episode = None

    def _finish(self, episode: Dict[str, Any]) -> None:
        if len(self._finished) >= TRUSTED_RATE_MAX_PENDING:
            self.dropped += 1
            return
        self._finished.append(dict(episode))

    def take_finished(self) -> List[Dict[str, Any]]:
        with self._lock:
            finished, self._finished = self._finished, []
        return finished

    # -- reporting --------------------------------------------------------

    def open_episodes(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [
                {**counter.episode, "open": True}
                for counter in self._counters.values()
                if counter.episode is not None
            ]
        rows.sort(key=lambda row: row["started"], reverse=True)
        return rows

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "sites": len(self._sites),
                "tracked": len(self._counters),
                "max_tracked": self.max_keys,
                "open": sum(1 for c in self._counters.values() if c.episode is not None),
                "opened": self.opened,
                "evicted": self.evicted,
                "dropped": self.dropped,
            }


# ---------------------------------------------------------------------------
# Hard-floor episodes (U02, 04.7b)
# ---------------------------------------------------------------------------
#
# The hard floor refuses the excess and bans nobody (04.6b). What it cannot
# do is tell a flood that keeps going from a burst that stopped, and the log
# cannot either: a refused connection is never logged, and a refused request
# reads 429 like a site's soft limit. The stick tables can. Each table that
# holds a ceiling names it in a comment the template writes beside it, and
# guardd asks HAProxy only for the addresses above it -- "show table T
# data.C gt N" returns the offenders and nothing else, so the cost does not
# grow with the gateway's traffic. An address above a ceiling on two reads in
# a row (ten seconds apart) is an episode.

HARD_FLOOR_COUNTERS: Tuple[str, ...] = ("http_req_rate", "conn_rate", "conn_cur")
HARD_FLOOR_SUSTAIN_READS = 2
HARD_FLOOR_MAX_TRACKED = 4096
_HARD_FLOOR_RE = re.compile(
    r"^\s*#\s*guardd-hard-floor\s+table=(?P<table>[A-Za-z0-9_.-]+)"
    r"(?P<limits>(?:\s+(?:http_req_rate|conn_rate|conn_cur)=\d+)+)\s*$",
    re.MULTILINE,
)
_HARD_FLOOR_LIMIT_RE = re.compile(r"(?P<counter>http_req_rate|conn_rate|conn_cur)=(?P<limit>\d+)")


def read_hard_floor(path: str = "") -> Dict[str, Dict[str, int]]:
    """{table: {counter: ceiling}} from the generated configuration."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    floors: Dict[str, Dict[str, int]] = {}
    for match in _HARD_FLOOR_RE.finditer(text):
        limits = floors.setdefault(match.group("table"), {})
        for item in _HARD_FLOOR_LIMIT_RE.finditer(match.group("limits")):
            limit = int(item.group("limit"))
            if limit > 0:
                limits[item.group("counter")] = limit
    return {table: limits for table, limits in floors.items() if limits}


class HardFloorWatch:
    """Which addresses have stayed over a hard ceiling, read after read."""

    def __init__(self, config_path: str = "") -> None:
        self.config_path = config_path
        self._key: Optional[Tuple[int, int]] = None
        self._checked = 0.0
        self._ceilings: Dict[str, Dict[str, int]] = {}
        self._streak: Dict[Tuple[str, str, str], int] = {}
        self.episodes = 0

    def ceilings(self) -> Dict[str, Dict[str, int]]:
        moment = time.monotonic()
        if self._checked and moment - self._checked < RATE_CEILINGS_RECHECK:
            return self._ceilings
        self._checked = moment
        path = self.config_path or HAPROXY_CONFIG_PATH
        try:
            info = os.stat(path)
            key: Optional[Tuple[int, int]] = (info.st_mtime_ns, info.st_size)
        except OSError:
            key = None
        if key != self._key:
            self._key = key
            self._ceilings = read_hard_floor(path) if key else {}
        return self._ceilings

    def queries(self) -> List[Tuple[str, str, int]]:
        return [
            (table, counter, limit)
            for table, limits in sorted(self.ceilings().items())
            for counter, limit in sorted(limits.items())
        ]

    def update(
        self, over: Dict[Tuple[str, str, str], Tuple[int, int]]
    ) -> List[Tuple[Tuple[str, str, str], Tuple[int, int]]]:
        """Take one read's offenders; return those now over for long enough.

        ``over`` maps (address, table, counter) to (value, ceiling). An
        address missing from a read starts again from nothing, so a burst
        that one read caught and the next did not is never an episode.
        """
        streak: Dict[Tuple[str, str, str], int] = {}
        sustained = []
        for key in sorted(over):
            count = self._streak.get(key, 0) + 1
            if len(streak) < HARD_FLOOR_MAX_TRACKED:
                streak[key] = count
            if count >= HARD_FLOOR_SUSTAIN_READS:
                sustained.append((key, over[key]))
        self._streak = streak
        self.episodes += len(sustained)
        return sustained

    def summary(self) -> Dict[str, Any]:
        return {
            "tables": len(self._ceilings),
            "over_now": len(self._streak),
            "sustained_reads": self.episodes,
        }


# ---------------------------------------------------------------------------
# The ban policy HAProxy runs (U02, 04.3c and 04.9)
# ---------------------------------------------------------------------------
#
# One switch, site_defaults.ban_policy, decides it, and the generated
# configuration states the result in a comment. guardd follows that comment
# rather than a setting of its own, so it can never run one policy while
# HAProxy runs the other: whatever HAProxy was reloaded with is what guardd
# scores by.
#
# Under "u02" HAProxy writes no ban codes 10, 20 or 30. Those still in the
# table were written under the old rules, by this gateway before the switch,
# an old process, or a peer that has not switched -- and are lifted, one
# address at a time, re-read before each removal. The operator's (50) and
# this daemon's (40) are never touched. Before the first lift the whole
# table is written to a snapshot file, for the record; switching back does
# not restore it, because a ban lifted on purpose must not come back.

BAN_POLICY_LEGACY = "legacy"
BAN_POLICY_U02 = "u02"
BAN_POLICY_STATE_KEY = "ban_policy"
LEGACY_BAN_CODES = frozenset({10, 20, 30})
LEGACY_LIFTS_PER_CYCLE = 200
BAN_SNAPSHOTS_KEPT = 5
# How long a sign-in keeps an address from an adaptive ban under U02 (the
# operator's choice, 4 November): long enough for a weekend or a short trip,
# not forever. The old rule was "ever signed in".
TRUST_AFTER_SIGN_IN_SECONDS = 7 * 86400
_BAN_POLICY_RE = re.compile(
    r"^\s*#\s*guardd-ban-policy\s+(?P<policy>legacy|u02)\s*$", re.MULTILINE
)


def read_ban_policy(path: str = "") -> str:
    """The policy the generated configuration says HAProxy runs."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return BAN_POLICY_LEGACY
    found = _BAN_POLICY_RE.search(text)
    return found.group("policy") if found else BAN_POLICY_LEGACY


class BanPolicyWatch:
    """The ban policy, re-read whenever the configuration file changes.

    Checked on every poll rather than every minute: a switch should change
    what guardd scores by within one cycle of HAProxy changing.
    """

    def __init__(self, config_path: str = "") -> None:
        self.config_path = config_path
        self._key: Optional[Tuple[int, int]] = None
        self._policy = BAN_POLICY_LEGACY

    def current(self) -> str:
        path = self.config_path or HAPROXY_CONFIG_PATH
        try:
            info = os.stat(path)
            key: Optional[Tuple[int, int]] = (info.st_mtime_ns, info.st_size)
        except OSError:
            key = None
        if key != self._key:
            self._key = key
            self._policy = read_ban_policy(path) if key else BAN_POLICY_LEGACY
        return self._policy
