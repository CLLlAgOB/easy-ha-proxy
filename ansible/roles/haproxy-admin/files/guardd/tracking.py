"""Bounded per-IP SLRU memory, subnet correlation, detection context, and log cursor."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import re
import threading
import zlib
from array import array
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from . import constants as _constants

if TYPE_CHECKING:
    from .scoring import ExclusionModel
    from .storage import SecurityDatabase
from .constants import (
    CANDIDATE_MAX_ADDRESSES,
    CANDIDATE_MAX_PATHS,
    CANDIDATE_MAX_PATH_LENGTH,
    CANDIDATE_MAX_SERVED,
    CANDIDATE_MIN_ADDRESSES,
    CATCH_ALL_MAX_HOSTS,
    CATCH_ALL_MAX_SIZES,
    CATCH_ALL_MIN_PATHS,
    DEFAULT_WEIGHTS,
    ENUMERATION_STATUSES,
    EVENT_LOW_AND_SLOW,
    EVENT_MASS_ENUM,
    EVENT_NOT_FOUND_ENUM,
    EVENT_QUERY_INJECTION,
    EVENT_RECURRING,
    EVENT_SCANNER_DECISIVE,
    EVENT_SCANNER_MULTI,
    EVENT_SCANNER_PATH,
    EVENT_WIDE_ENUM,
    LOG,
    LOW_AND_SLOW_MIN_CATEGORIES,
    LOW_AND_SLOW_MIN_HITS,
    LOW_AND_SLOW_WINDOW,
    MASS_ENUM_MIN,
    MAX_LOG_LINE_BYTES,
    MULTI_CATEGORY_MIN,
    MULTI_CATEGORY_WINDOW,
    NOT_FOUND_MIN_DISTINCT,
    NOT_FOUND_WINDOW,
    QUERY_RULES,
    RECURRING_GAP,
    RECURRING_WINDOW,
    SUBNET_CAMPAIGN_MAX_IPS_PER_SUBNET,
    SUBNET_CAMPAIGN_MAX_SUBNETS,
    SUBNET_CAMPAIGN_MIN_IPS,
    SUBNET_CAMPAIGN_WINDOW,
    UNKNOWN_HOSTS_MAX,
    USER_AGENTS,
    WIDE_ENUM_MIN,
    WIDE_ENUM_WINDOW,
    _safe_int,
    _utc_now,
    category_is_decisive,
    classify_query,
    classify_user_agent,
    detection_host,
    is_served,
)
from .parser import (
    DETECTION_PROFILES,
    ParsedRequest,
    classify_path,
    classify_raw_path,
    is_asset,
    is_proto_ua_mismatch,
    is_unusual_method_probe,
    normalize_path,
    observation_flags,
)
from .scoring import ScoringPolicy

# ---------------------------------------------------------------------------
# Bounded per-IP memory
# ---------------------------------------------------------------------------


@dataclass
class IpActivity:
    """What one address has been doing, in a fixed amount of space."""

    first_seen: int = 0
    last_seen: int = 0
    requests: int = 0
    errors: int = 0
    not_found: int = 0
    gateway_denied: int = 0
    bad_requests: int = 0
    # Whether any request from this address ever reached a real server. A
    # refusal is only a shield while the answer is no: see reached_a_backend.
    reached_backend: bool = False
    paths: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    hosts: Set[str] = field(default_factory=set)
    # Detection state, all bounded: category -> last seen, and the distinct
    # 404 paths that were not assets.
    categories: "OrderedDict[str, int]" = field(default_factory=OrderedDict)
    scanner_hits: int = 0
    # How many of those the gateway had already refused. A finding derived
    # from nothing but refused requests must not score when every request it
    # was derived from scored nothing.
    scanner_hits_denied: int = 0
    missing_paths: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    # Paths refused with any enumeration status, and how many fresh ones the
    # current burst has produced: two integers per address, however wide.
    refused_paths: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    burst_start: int = 0
    burst_misses: int = 0
    invalid_host_keys: "OrderedDict[int, int]" = field(default_factory=OrderedDict)
    invalid_host_since: int = 0
    # When the stored history was last asked about a return visit, so a
    # burst of signatures costs one query, not one per request.
    recurring_checked: int = 0

    @property
    def scanning_was_all_refused(self) -> bool:
        """Every scanner hit from this address was refused on identity.

        The address reaches nothing, so a ban changes nothing -- the same
        reason a single finding scores zero. Mixed traffic does not count:
        one request that got through is enough for the derived findings to
        be worth their points.
        """

        return (
            self.scanner_hits > 0
            and self.scanner_hits_denied >= self.scanner_hits
        )

    def note_path(self, path: str, ts: int, limit: int) -> bool:
        """Remember a path by hash. True when it had not been seen before."""

        digest = hash(path) & 0xFFFFFFFF
        fresh = digest not in self.paths
        self.paths[digest] = ts
        self.paths.move_to_end(digest)
        while len(self.paths) > limit:
            self.paths.popitem(last=False)
        return fresh

    def note_category(self, category: str, ts: int, limit: int = 16) -> None:
        self.categories[category] = ts
        self.categories.move_to_end(category)
        while len(self.categories) > limit:
            self.categories.popitem(last=False)

    def note_missing(self, path: str, ts: int, limit: int) -> bool:
        digest = hash(path) & 0xFFFFFFFF
        fresh = digest not in self.missing_paths
        self.missing_paths[digest] = ts
        self.missing_paths.move_to_end(digest)
        while len(self.missing_paths) > limit:
            self.missing_paths.popitem(last=False)
        return fresh

    def note_refused(self, path: str, ts: int, limit: int, window: int) -> bool:
        """Count a refused path toward the current burst if it is new.

        The set is a bounded LRU, so a path the address keeps repeating stays
        in it and never counts twice; a sweep's paths are all new.
        """

        digest = hash(path) & 0xFFFFFFFF
        fresh = digest not in self.refused_paths
        self.refused_paths[digest] = ts
        self.refused_paths.move_to_end(digest)
        while len(self.refused_paths) > limit:
            self.refused_paths.popitem(last=False)
        if not fresh:
            return False
        if ts - self.burst_start > window:
            self.burst_start = ts
            self.burst_misses = 0
        self.burst_misses += 1
        return True

    def note_invalid_host(
        self, key: str, ts: int, limit: int, window: int
    ) -> Optional[int]:
        """Distinct host-and-path pairs in the window, or None for a repeat."""

        if self.invalid_host_since < ts - window:
            self.invalid_host_since = ts
            self.invalid_host_keys.clear()
        digest = hash(key) & 0xFFFFFFFF
        if digest in self.invalid_host_keys:
            self.invalid_host_keys.move_to_end(digest)
            return None
        self.invalid_host_keys[digest] = ts
        while len(self.invalid_host_keys) > limit:
            self.invalid_host_keys.popitem(last=False)
        return len(self.invalid_host_keys)

    def recent_categories(self, since: int) -> List[str]:
        return [
            name for name, ts in self.categories.items() if ts >= since
        ]

    def distinct_missing(self, since: int) -> int:
        return sum(1 for ts in self.missing_paths.values() if ts >= since)


class CatchAllPages:
    """Per host: response sizes that several scanner paths all received."""

    def __init__(self) -> None:
        self._hosts: "OrderedDict[str, OrderedDict[int, Set[int]]]" = OrderedDict()

    def known(self, host: str, size: int) -> bool:
        """Is this size already this host's catch-all page? Records nothing."""

        sizes = self._hosts.get(host)
        return bool(sizes) and len(sizes.get(size, ())) >= CATCH_ALL_MIN_PATHS

    def is_catch_all(self, host: str, size: int, path: str) -> bool:
        sizes = self._hosts.get(host)
        if sizes is None:
            sizes = self._hosts[host] = OrderedDict()
            while len(self._hosts) > CATCH_ALL_MAX_HOSTS:
                self._hosts.popitem(last=False)
        self._hosts.move_to_end(host)
        seen = sizes.get(size)
        if seen is None:
            seen = sizes[size] = set()
            while len(sizes) > CATCH_ALL_MAX_SIZES:
                sizes.popitem(last=False)
        sizes.move_to_end(size)
        if len(seen) < CATCH_ALL_MIN_PATHS:
            seen.add(hash(path) & 0xFFFFFFFF)
        return len(seen) >= CATCH_ALL_MIN_PATHS


def _address_key(ip: str) -> int:
    # Stable across restarts, unlike hash(), so persisted counts stay right.
    return zlib.crc32(ip.encode("utf-8", "replace"))


DETECTION_CONFIG_KEY = "detection_context_v1"
DETECTION_STATS_KEY = "detection_observations_v1"
DETECTION_SLOW_KEY = "detection_slow_v1"
DETECTION_MAX_RULES = 128
DETECTION_MAX_EXCEPTIONS = 128
DETECTION_MAX_TRACKED = 256
DETECTION_MAX_STATS = 128
DETECTION_TTL = 24 * 3600
DETECTION_NEW_RULES = {
    "observe:sql-injection": "SQL query structure in a parameter; observation by default",
    "observe:script-injection": "Script or event-handler markup in a parameter; observation by default",
    "observe:encoded-sensitive-path": "A sensitive path appears after a second decode; observation by default",
    "observe:service-api-probe": "Container, cloud metadata or diagnostic API route; observation by default",
    "observe:proto-ua-mismatch": "Modern browser User-Agent over HTTP/1.0; observation by default",
    "observe:unusual-method-probe": "Unusual or WebDAV HTTP method outside the host profile; observation by default",
    "behavior:slow-enumeration": "24 distinct missing paths, 90% failures, three half-hour windows within six hours",
}
DETECTION_WARNING_RULES = {
    "auth:credential-spray": "Ten different usernames from one IP within fifteen minutes; warning only",
    "auth:distributed-login": "Ten different IPs target one username within fifteen minutes; warning only",
    "auth:failed-login-burst": "Twenty failed first-factor logins from one IP within fifteen minutes; warning only",
}




def detection_scope(row: Dict[str, Any]) -> Dict[str, Any]:
    hosts = row.get("hosts")
    methods = row.get("methods", [])
    statuses = row.get("statuses", [])
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 8:
        raise ValueError("choose one to eight exact host names")
    if not isinstance(methods, list) or len(methods) > 16:
        raise ValueError("expected at most sixteen methods")
    if any(not isinstance(m, str) or not re.fullmatch(r"[A-Z]{3,16}", m) for m in methods):
        raise ValueError("expected uppercase HTTP methods")
    if not isinstance(statuses, list) or len(statuses) > 16 or any(type(s) is not int or not 100 <= s <= 599 for s in statuses):
        raise ValueError("expected at most sixteen HTTP status codes")
    match = row.get("match", "exact")
    value = row.get("value")
    if match not in ("exact", "prefix", "segment"):
        raise ValueError("match must be exact, prefix or segment")
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or any(c in value for c in "?#%\\ ") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("expected a plain path without parameters or escapes")
    if match == "segment":
        if "/" in value or value in (".", ".."):
            raise ValueError("expected one path segment")
    elif not value.startswith("/") or normalize_path(value) != value:
        raise ValueError("expected a canonical path starting with a slash")
    if match == "prefix" and value == "/":
        raise ValueError("a prefix must name a route")
    return {"hosts": sorted(set(detection_host(h) for h in hosts)), "methods": sorted(set(methods)),
            "match": match, "value": value.rstrip("/") or "/", "statuses": sorted(set(statuses))}


def scope_matches(row: Dict[str, Any], request: ParsedRequest) -> bool:
    if request.host.lower().rstrip(".") not in row["hosts"]:
        return False
    if row["methods"] and request.method not in row["methods"]:
        return False
    if row["statuses"] and request.status not in row["statuses"]:
        return False
    path, value = request.path, row["value"]
    if row["match"] == "exact":
        return path == value
    if row["match"] == "segment":
        return value in path.split("/")
    return path == value or path.startswith(value + "/")


def builtin_detection_ids() -> Set[str]:
    return ({"path:" + c for c in set(_constants.SCANNER_SEGMENTS.values()) | set(_constants.SCANNER_PATHS.values())}
            | {"query:" + c for c in QUERY_RULES}
            | {"ua:" + token for token, _ in USER_AGENTS.values()}
            | {"raw:path-traversal"} | set(DETECTION_NEW_RULES) | set(DETECTION_WARNING_RULES))


class DetectionSettings(dict):
    """JSON document plus private indexes; not another persisted format."""

    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data)
        self.rules_by_host: Dict[str, List[Dict[str, Any]]] = {}
        self.exceptions_by_scope: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for row in self.get("rules", []):
            for host in row["hosts"]:
                self.rules_by_host.setdefault(host, []).append(row)
        for row in self.get("exceptions", []):
            for host in row["hosts"]:
                self.exceptions_by_scope.setdefault((row["rule"], host), []).append(row)


def validate_detection_config(data: Any) -> DetectionSettings:
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("expected detection configuration version 1")
    rules, exceptions, modes, profiles = (data.get(k, default) for k, default in
                                          (("rules", []), ("exceptions", []), ("modes", {}), ("profiles", {})))
    if not isinstance(rules, list) or len(rules) > DETECTION_MAX_RULES:
        raise ValueError("too many contextual rules")
    if not isinstance(exceptions, list) or len(exceptions) > DETECTION_MAX_EXCEPTIONS:
        raise ValueError("too many exceptions")
    if not isinstance(modes, dict) or len(modes) > DETECTION_MAX_RULES:
        raise ValueError("too many rule modes")
    checked, ids = [], set()
    for row in rules:
        if not isinstance(row, dict) or not re.fullmatch(r"custom:[a-z0-9-]{1,48}", str(row.get("id", ""))):
            raise ValueError("expected a stable custom rule identifier")
        name = row["id"]
        if name in ids:
            raise ValueError("duplicate rule identifier")
        ids.add(name)
        category = row.get("category", "custom")
        if not isinstance(category, str) or category not in set(_constants.SCANNER_SEGMENTS.values()) | set(_constants.SCANNER_PATHS.values()) | {"custom"}:
            raise ValueError("unknown category")
        mode = row.get("mode", "observe")
        if mode not in ("observe", "enforce"):
            raise ValueError("mode must be observe or enforce")
        checked.append({"id": name, **detection_scope(row), "category": category, "mode": mode})
    known = builtin_detection_ids() | ids

    def supported_id(value: Any) -> bool:
        # A shipped rule can disappear in an update. Keep its scoped settings
        # dormant so an update cannot resurrect an old false positive.
        return isinstance(value, str) and (value in known or bool(re.fullmatch(
            r"(?:path|query|ua|raw|observe|behavior|auth):[A-Za-z0-9_. /+:-]{1,100}", value)))

    if any(not supported_id(k) or v not in ("observe", "enforce") for k, v in modes.items()):
        raise ValueError("unknown rule or mode")
    if any(v == "enforce" and (k in DETECTION_WARNING_RULES or k.startswith("auth:")) for k, v in modes.items()):
        raise ValueError("login correlations are warning-only")
    exclusions, exclusion_ids = [], set()
    for row in exceptions:
        if not isinstance(row, dict) or not re.fullmatch(r"exception:[a-z0-9-]{1,48}", str(row.get("id", ""))):
            raise ValueError("expected an exception identifier")
        if row["id"] in exclusion_ids or not supported_id(row.get("rule")):
            raise ValueError("duplicate exception or unknown rule")
        reason, expires = row.get("reason"), row.get("expires", 0)
        if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 200:
            raise ValueError("an exception needs a reason of 3 to 200 characters")
        if type(expires) is not int or not 0 <= expires <= 4102444800:
            raise ValueError("expected an expiry timestamp or zero")
        exclusion_ids.add(row["id"])
        exclusions.append({"id": row["id"], "rule": row["rule"], **detection_scope(row),
                           "reason": reason.strip(), "expires": expires})
    if not isinstance(profiles, dict) or len(profiles) > 64 or any(not isinstance(v, str) or v not in DETECTION_PROFILES for v in profiles.values()):
        raise ValueError("unknown site profile or too many sites")
    revision = data.get("revision", 0)
    if type(revision) is not int or not 0 <= revision < 2**53:
        raise ValueError("invalid settings revision")
    return DetectionSettings({"version": 1, "revision": revision, "rules": checked, "exceptions": exclusions, "modes": dict(modes),
                              "profiles": {detection_host(k): v for k, v in profiles.items()}})


class DetectionContext:
    """One bounded, non-scoring observation store; settings swap atomically.

    Trusted observations never enter security_events. Changing a mode affects
    future requests only: there is no replay from these aggregates into bans.
    """

    def __init__(self, database: "SecurityDatabase") -> None:
        self.database = database
        self._lock = threading.RLock()
        self.config = DetectionSettings({"version": 1, "revision": 0, "rules": [], "exceptions": [], "modes": {}, "profiles": {}})
        self.stats: OrderedDict = OrderedDict()
        self.slow: OrderedDict = OrderedDict()
        self.evictions = 0
        self.state_errors = 0
        self.last_saved = 0
        raw_config = database.get_state(DETECTION_CONFIG_KEY, "")
        if raw_config:
            try:
                self.config = validate_detection_config(json.loads(raw_config))
            except (ValueError, TypeError, RecursionError):
                self.state_errors += 1
                LOG.warning("ignoring invalid saved contextual detection settings")
        now = _utc_now()
        known = builtin_detection_ids() | {r["id"] for r in self.config["rules"]}
        for row in self._saved_rows(DETECTION_STATS_KEY, DETECTION_MAX_STATS):
            try:
                name, first, last = row["id"], int(row["first"]), int(row["last"])
                if not isinstance(name, str) or name not in known or not now - DETECTION_TTL <= last <= now + 60 or first > last:
                    continue
                counts = {k: int(row[k]) for k in ("hits", "trusted", "excepted", "observe", "enforce")}
                if any(not 0 <= n <= 10**12 for n in counts.values()):
                    raise ValueError("invalid counter")
                ips = {int(v) for v in row["ips"][:64]}
                hosts = {detection_host(k): int(v) for k, v in list(row["hosts"].items())[:8]}
                if any(not 0 <= v < 2**32 for v in ips) or any(v < 0 for v in hosts.values()):
                    raise ValueError("invalid aggregate")
                self.stats[name] = {"id": name, "first": first, "last": last, **counts, "ips": ips, "hosts": hosts}
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                self.state_errors += 1
        for row in self._saved_rows(DETECTION_SLOW_KEY, DETECTION_MAX_TRACKED):
            try:
                key, last, buckets = row
                ip, host = key
                ipaddress.ip_address(ip)
                host = detection_host(host)
                restored = {}
                for slot, missing, total, good, paths in buckets[:12]:
                    if now // 1800 - 11 <= int(slot) <= now // 1800:
                        counts = [int(missing), int(total), int(good)]
                        if any(not 0 <= n <= 10**12 for n in counts) or counts[0] + counts[2] > counts[1]:
                            raise ValueError("invalid bucket")
                        restored[int(slot)] = [*counts, array("I", (int(v) for v in paths[:32]))]
                if restored and now - 6 * 3600 <= int(last) <= now + 60:
                    self.slow[(ip, host)] = {"last": int(last), "buckets": restored}
            except (ValueError, TypeError, KeyError, OverflowError):
                self.state_errors += 1

    def _saved_rows(self, key: str, limit: int) -> List[Any]:
        try:
            rows = json.loads(self.database.get_state(key, "[]"))
            if isinstance(rows, list):
                return rows[:limit]
        except (ValueError, TypeError, RecursionError):
            pass
        self.state_errors += 1
        return []

    def replace(self, data: Any) -> Dict[str, Any]:
        checked = validate_detection_config(data)
        with self._lock:
            if checked["revision"] != self.config["revision"]:
                raise ValueError("settings changed; reload before saving")
            checked["revision"] += 1
            reset_slow = (checked["modes"].get("behavior:slow-enumeration", "observe") == "enforce"
                          and self.config["modes"].get("behavior:slow-enumeration", "observe") != "enforce")
            states = {DETECTION_CONFIG_KEY: json.dumps(checked)}
            if reset_slow:
                states[DETECTION_SLOW_KEY] = "[]"
            self.database.set_states(states)
            if reset_slow:
                self.slow.clear()
            self.config = checked
        return self.summary()

    def _action(self, rule: str, request: ParsedRequest, now: int, config: DetectionSettings, default: str) -> Tuple[str, str]:
        for exception in config.exceptions_by_scope.get((rule, request.host.lower().rstrip(".")), ()):
            if exception["rule"] == rule and (not exception["expires"] or exception["expires"] > now) and scope_matches(exception, request):
                return "excepted", exception["id"]
        return config["modes"].get(rule, default), ""

    def inspect(self, request: ParsedRequest, now: int, trusted: bool = False, record: bool = True,
                catch_all: bool = False) -> List[Dict[str, Any]]:
        config = self.config
        found = []
        category = classify_path(request.path)
        if category and (category_is_decisive(category) or not is_served(request.status) or catch_all):
            found.append(("path:" + category, category, "enforce", EVENT_SCANNER_DECISIVE if category_is_decisive(category) else EVENT_SCANNER_PATH))
        if request.query_flag:
            found.append(("query:" + request.query_flag, request.query_flag, "enforce", EVENT_QUERY_INJECTION))
        if request.path_flag:
            found.append(("raw:path-traversal", request.path_flag, "enforce", EVENT_SCANNER_DECISIVE))
        agent, category = classify_user_agent(request.user_agent)
        if agent:
            found.append(("ua:" + agent, category, "enforce", EVENT_SCANNER_DECISIVE if category_is_decisive(category) else EVENT_SCANNER_PATH))
        for name in request.observation_flags:
            if name in DETECTION_NEW_RULES:
                event = (EVENT_SCANNER_PATH if name == "observe:service-api-probe" else
                         EVENT_SCANNER_DECISIVE if name == "observe:encoded-sensitive-path" else EVENT_QUERY_INJECTION)
                found.append((name, name.split(":", 1)[1], "observe", event))
        if is_proto_ua_mismatch(request.protocol, request.user_agent):
            found.append(("observe:proto-ua-mismatch", "proto-ua-mismatch", "observe", EVENT_SCANNER_PATH))
        host_key = request.host.lower().rstrip(".")
        host_profile = config["profiles"].get(host_key, "web")
        if is_unusual_method_probe(request.method, host_profile):
            found.append(("observe:unusual-method-probe", "unusual-method-probe", "observe", EVENT_SCANNER_PATH))
        for rule in config.rules_by_host.get(host_key, ()):
            if scope_matches(rule, request):
                found.append((rule["id"], rule["category"], rule["mode"], EVENT_SCANNER_DECISIVE if category_is_decisive(rule["category"]) else EVENT_SCANNER_PATH))
        results = []
        for rule, category, default, event in found:
            mode, exception = self._action(rule, request, now, config, default)
            action = mode if mode == "excepted" else "trusted" if trusted else mode
            row = {"id": rule, "category": category, "action": action, "exception": exception,
                   "event_type": event, "points": DEFAULT_WEIGHTS.get(event, 0) if action == "enforce" else 0}
            results.append(row)
            if record:
                self.note(rule, request, now, action)
        return results

    def note(self, rule: str, request: ParsedRequest, now: int, action: str) -> None:
        with self._lock:
            row = self.stats.get(rule)
            if row is None or now - row["first"] >= DETECTION_TTL:
                row = {"id": rule, "first": now, "last": now, "hits": 0, "trusted": 0, "excepted": 0,
                       "observe": 0, "enforce": 0, "ips": set(), "hosts": {}}
                self.stats[rule] = row
            row["last"] = now
            row["hits"] += 1
            row[action] += 1
            if len(row["ips"]) < 64:
                row["ips"].add(_address_key(request.client_ip))
            if request.host in row["hosts"] or len(row["hosts"]) < 8:
                row["hosts"][request.host[:253]] = row["hosts"].get(request.host[:253], 0) + 1
            self.stats.move_to_end(rule)
            while len(self.stats) > DETECTION_MAX_STATS:
                self.stats.popitem(last=False)
                self.evictions += 1

    def observe_slow(self, request: ParsedRequest, now: int, handled: bool) -> str:
        # No 401 authentication failures, gateway denials, assets or same-size
        # guesses. A NAT full of useful traffic also fails the ratio test.
        if handled or not request.host or is_asset(request.path) or request.path in ("", "/"):
            return ""
        key, slot = (request.client_ip, request.host[:253]), now // 1800
        with self._lock:
            config = self.config
            entry = self.slow.setdefault(key, {"last": now, "buckets": {}})
            entry["last"] = max(entry["last"], now)
            newest_slot = entry["last"] // 1800
            if slot < newest_slot - 11:
                return ""
            self.slow.move_to_end(key)
            while len(self.slow) > DETECTION_MAX_TRACKED:
                self.slow.popitem(last=False)
                self.evictions += 1
            buckets = entry["buckets"]
            for old in [b for b in buckets if b < newest_slot - 11]:
                del buckets[old]
            bucket = buckets.setdefault(slot, [0, 0, 0, array("I")])
            bucket[1] += 1
            if request.status in (404, 410):
                bucket[0] += 1
                digest = _address_key(request.path)
                if len(bucket[3]) < 32 and digest not in bucket[3]:
                    bucket[3].append(digest)
            elif is_served(request.status):
                bucket[2] += 1
            missing = sum(b[0] for b in buckets.values())
            total = sum(b[1] for b in buckets.values())
            if missing < 24 or missing * 10 < total * 9:
                return ""
            distinct = set().union(*(b[3] for b in buckets.values()))
            windows = sum(bool(b[3]) for b in buckets.values())
            if len(distinct) < 24 or windows < 3:
                return ""
        rule = "behavior:slow-enumeration"
        action, _ = self._action(rule, request, now, config, "observe")
        self.note(rule, request, now, action)
        return action

    def persist(self, now: int, force: bool = False) -> None:
        if not force and now - self.last_saved < 60:
            return
        with self._lock:
            self.stats = OrderedDict((k, v) for k, v in self.stats.items() if v["last"] >= now - DETECTION_TTL)
            self.slow = OrderedDict((k, v) for k, v in self.slow.items() if v["last"] >= now - 6 * 3600)
            stats = [{**v, "ips": sorted(v["ips"])} for v in self.stats.values()]
            slow = [[list(k), v["last"], [[s, *b[:3], sorted(b[3])] for s, b in v["buckets"].items()]] for k, v in self.slow.items()]
            self.database.set_states({DETECTION_STATS_KEY: json.dumps(stats), DETECTION_SLOW_KEY: json.dumps(slow)})
            self.last_saved = now

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {"ok": True, "config": json.loads(json.dumps(self.config)),
                    "profiles": DETECTION_PROFILES, "builtin_ids": sorted(builtin_detection_ids()),
                    "new_rules": {**DETECTION_NEW_RULES, **DETECTION_WARNING_RULES},
                    "existing_behavior": [
                        {"id": EVENT_SCANNER_MULTI, "categories": MULTI_CATEGORY_MIN, "hours": MULTI_CATEGORY_WINDOW // 3600},
                        {"id": EVENT_LOW_AND_SLOW, "hits": LOW_AND_SLOW_MIN_HITS, "categories": LOW_AND_SLOW_MIN_CATEGORIES,
                         "hours": LOW_AND_SLOW_WINDOW // 3600},
                        {"id": EVENT_NOT_FOUND_ENUM, "paths": NOT_FOUND_MIN_DISTINCT, "minutes": NOT_FOUND_WINDOW // 60},
                        {"id": EVENT_WIDE_ENUM, "paths": WIDE_ENUM_MIN, "minutes": WIDE_ENUM_WINDOW // 60},
                        {"id": EVENT_MASS_ENUM, "paths": MASS_ENUM_MIN, "minutes": WIDE_ENUM_WINDOW // 60},
                        {"id": EVENT_RECURRING, "gap_hours": RECURRING_GAP // 3600, "days": RECURRING_WINDOW // 86400},
                    ],
                    "warning_only": sorted(DETECTION_WARNING_RULES),
                    "stats": [{**{k: v for k, v in row.items() if k != "ips"}, "unique_ips": len(row["ips"]),
                               "unique_ips_capped": len(row["ips"]) >= 64} for row in self.stats.values()],
                    "limits": {"tracked": DETECTION_MAX_TRACKED, "tracked_now": len(self.slow),
                               "evictions": self.evictions, "window_hours": 24,
                               "stats_capacity": DETECTION_MAX_STATS, "state_errors": self.state_errors}}

    def preview(self, data: Any, exclusions: "ExclusionModel", now: int,
                policy: Optional[ScoringPolicy] = None) -> Dict[str, Any]:
        if not isinstance(data, dict):
            raise ValueError("expected an object")
        uri, method, status = data.get("url", "/"), data.get("method", "GET"), data.get("status", 404)
        agent = data.get("user_agent", "")
        host = detection_host(data.get("host", ""))
        if not isinstance(uri, str) or len(uri) > 4096 or not uri.startswith("/") or uri.startswith("//"):
            raise ValueError("expected a request path of at most 4096 characters")
        if type(status) is not int or not 100 <= status <= 599 or not isinstance(method, str) or not re.fullmatch(r"[A-Z]{3,16}", method):
            raise ValueError("invalid HTTP method or status")
        if not isinstance(agent, str) or len(agent) > 512:
            raise ValueError("User-Agent must be at most 512 characters")
        try:
            ip = str(ipaddress.ip_address(data.get("ip") or "203.0.113.254"))
        except ValueError:
            raise ValueError("invalid client IP") from None
        verdict = exclusions.verdict(ip)
        request = ParsedRequest(client_ip=ip, status=status, frontend="preview", backend="preview/srv1", method=method,
                                path=normalize_path(uri), host=host, query_flag=classify_query(uri),
                                path_flag=classify_raw_path(uri), observation_flags=observation_flags(uri), user_agent=agent)
        matches = self.inspect(request, now, trusted=verdict.excluded, record=False)
        categories: Dict[str, int] = {}
        for row in matches:
            if policy is not None and row["action"] == "enforce":
                row["points"] = policy.weight(row["event_type"])
            categories[row["category"]] = max(categories.get(row["category"], 0), row["points"])
        return {"ok": True, "matches": matches, "path": request.path, "trusted": verdict.excluded,
                "trust_reason": verdict.reason, "profile": self.config["profiles"].get(host, "web"),
                "nominal_points": sum(categories.values()), "engine_mode": "preview",
                "note": "Single request only; live score also depends on policy, cooldowns, history and gateway refusals. Nothing was saved."}


class LoginCorrelations:
    """Read existing JSON failure logs once; never duplicate Authelia bans.

    Only a final failed 1FA line counts, not MFA, detail/error lines or login
    successes. Unknown usernames stay unknown. No account can be locked by a
    forged attempt here. Raw messages and usernames are not retained.
    """

    KEY = "detection_login_correlations_v1"

    def __init__(self, path: str, context: DetectionContext, database: "SecurityDatabase") -> None:
        self.context, self.database = context, database
        self._lock = threading.RLock()
        self.entries: OrderedDict = OrderedDict()
        saved: Dict[str, Any] = {}
        with contextlib.suppress(ValueError, TypeError):
            saved = json.loads(database.get_state(self.KEY, "{}"))
        if not isinstance(saved, dict):
            saved = {}
        cursor = saved.get("cursor", {})
        self.cursor = LogCursor(path, cursor if isinstance(cursor, dict) else {})
        self.enabled = bool(path)
        self.dropped = 0
        self.last_saved = 0
        now = _utc_now()
        with contextlib.suppress(ValueError, TypeError, KeyError, OverflowError):
            for key, buckets in saved.get("entries", [])[:256]:
                clean = {int(slot): [int(count), array("I", (int(v) for v in peers[:32]))]
                         for slot, count, peers in buckets[:3] if now // 300 - 2 <= int(slot) <= now // 300}
                if clean and isinstance(key, str) and len(key) <= 80 and key.startswith(("ip:", "user:")):
                    self.entries[key] = clean

    def observe(self, line: str, now: int, exclusions: "ExclusionModel") -> None:
        with self._lock:
            self._observe(line, now, exclusions)

    def _observe(self, line: str, now: int, exclusions: "ExclusionModel") -> None:
        if len(line) > 16384:
            self.dropped += 1
            return
        try:
            data = json.loads(line)
            if not isinstance(data, dict) or data.get("path") != "/api/firstfactor" or data.get("method") != "POST":
                return
            msg = str(data.get("msg", ""))
            match = re.match(r"Unsuccessful 1FA authentication attempt by user '([^']{0,256})'", msg)
            if not match:
                return
            ip = str(ipaddress.ip_address(data.get("remote_ip", "")))
            stamp = int(datetime.fromisoformat(str(data["time"]).replace("Z", "+00:00")).timestamp())
            if not now - 900 <= stamp <= now + 30:
                return
            username = str(data.get("username") or match.group(1))[:256]
            stamp = min(now, stamp)
        except (ValueError, TypeError, KeyError):
            self.dropped += 1
            return
        keys = [("ip:" + ip, _address_key(username) if username else None)]
        if username:
            keys.append(("user:" + hashlib.sha256(username.encode("utf-8")).hexdigest(), _address_key(ip)))
        slot = stamp // 300
        for key, peer in keys:
            buckets = self.entries.setdefault(key, {})
            self.entries.move_to_end(key)
            while len(self.entries) > 256:
                self.entries.popitem(last=False)
                self.dropped += 1
            for old in [s for s in buckets if s < now // 300 - 2 or s > now // 300]:
                del buckets[old]
            count, peers = buckets.setdefault(slot, [0, array("I")])
            buckets[slot][0] = count + 1
            if peer is not None and peer not in peers and len(peers) < 32:
                peers.append(peer)
            distinct = len(set().union(*(b[1] for b in buckets.values())))
            count = sum(b[0] for b in buckets.values())
            rules = []
            if key.startswith("ip:"):
                if distinct >= 10:
                    rules.append("auth:credential-spray")
                if count >= 20:
                    rules.append("auth:failed-login-burst")
            elif distinct >= 10:
                rules.append("auth:distributed-login")
            if rules:
                request = ParsedRequest(ip, 401, "authelia", "authelia/srv1", "POST", "/api/firstfactor", "authelia")
                for rule in rules:
                    action, _ = self.context._action(rule, request, now, self.context.config, "observe")
                    if action != "excepted" and exclusions.verdict(ip).excluded:
                        action = "trusted"
                    self.context.note(rule, request, now, action)

    def poll(self, now: int, exclusions: "ExclusionModel") -> None:
        if not self.enabled:
            return
        for line in self.cursor.read(256 * 1024):
            self.observe(line, now, exclusions)
        if now - self.last_saved >= 60:
            self.persist(now)

    def persist(self, now: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.entries = OrderedDict((k, b) for k, b in self.entries.items() if b and max(b) >= now // 300 - 2)
            rows = [[k, [[slot, b[0], list(b[1])] for slot, b in buckets.items()]] for k, buckets in self.entries.items()]
            self.database.set_state(self.KEY, json.dumps({"cursor": self.cursor.state(), "entries": rows}))
            self.last_saved = now

    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {"enabled": self.enabled, "error": "log unavailable" if self.cursor.last_error else "",
                    "lag_bytes": self.cursor.lag_bytes, "tracked": len(self.entries), "dropped": self.dropped}


class PathCandidates:
    """Paths refused to many addresses that no signature matches."""

    def __init__(self) -> None:
        # (host, path) -> {"first", "last", "ips": set, "clients": set,
        #          "status": {code: n}, "hosts": {host: n}}
        self._paths: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
        self._served: "OrderedDict[int, int]" = OrderedDict()
        self._lock = threading.Lock()

    def note(self, path: str, ip: str, host: str, status: int, served: bool,
             client: bool, ts: int) -> None:
        if len(path) > CANDIDATE_MAX_PATH_LENGTH:
            return
        host = host.lower().rstrip(".")
        key = (host, path)
        digest = hash(key)
        with self._lock:
            if served:
                self._served[digest] = ts
                self._served.move_to_end(digest)
                while len(self._served) > CANDIDATE_MAX_SERVED:
                    self._served.popitem(last=False)
                self._paths.pop(key, None)
                return
            if status not in ENUMERATION_STATUSES or digest in self._served:
                return
            entry = self._paths.get(key)
            if entry is None:
                entry = self._paths[key] = {
                    "first": ts, "last": ts, "ips": set(), "clients": set(),
                    "status": {}, "hosts": {},
                }
                while len(self._paths) > CANDIDATE_MAX_PATHS:
                    self._paths.popitem(last=False)
            self._paths.move_to_end(key)
            entry["last"] = ts
            key = _address_key(ip)
            if len(entry["ips"]) < CANDIDATE_MAX_ADDRESSES:
                entry["ips"].add(key)
            if client and len(entry["clients"]) < CANDIDATE_MAX_ADDRESSES:
                entry["clients"].add(key)
            code = str(status)
            entry["status"][code] = entry["status"].get(code, 0) + 1
            if host and (host in entry["hosts"] or len(entry["hosts"]) < 5):
                entry["hosts"][host] = entry["hosts"].get(host, 0) + 1

    def prune(self, before: int) -> int:
        with self._lock:
            stale = [path for path, entry in self._paths.items() if entry["last"] < before]
            for path in stale:
                del self._paths[path]
            for digest in [k for k, stamp in self._served.items() if stamp < before]:
                del self._served[digest]
        return len(stale)

    def suggestions(self, dismissed: Set[str], limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [
                {
                    "path": key[1],
                    "host": key[0],
                    "addresses": len(entry["ips"]),
                    "clients": len(entry["clients"]),
                    "first": entry["first"],
                    "last": entry["last"],
                    "status": dict(entry["status"]),
                    "hosts": sorted(entry["hosts"], key=lambda h: -entry["hosts"][h]),
                }
                for key, entry in self._paths.items()
                if len(entry["ips"]) >= CANDIDATE_MIN_ADDRESSES
                and key[1] not in dismissed
                and json.dumps(list(key), separators=(",", ":")) not in dismissed
            ]
        # A rule added since is already doing the job.
        rows = [row for row in rows if not classify_path(row["path"])]
        # Paths that clients asked for too sink to the bottom: likely a real link.
        rows.sort(key=lambda row: (row["clients"] > 0, -row["addresses"], -row["last"]))
        return rows[:limit]

    def snapshot(self, limit: int = 2000) -> List[List[Any]]:
        with self._lock:
            ranked = sorted(self._paths.items(), key=lambda kv: -len(kv[1]["ips"]))[:limit]
            return [
                [key[1], e["first"], e["last"], sorted(e["ips"]), sorted(e["clients"]),
                 e["status"], e["hosts"]]
                for key, e in ranked if len(e["ips"]) >= 2
            ]

    def restore(self, rows: Any) -> None:
        if not isinstance(rows, list):
            return
        with self._lock:
            for row in rows[:CANDIDATE_MAX_PATHS]:
                try:
                    path, first, last, ips, clients, status, hosts = row
                    # Old multi-host aggregates cannot prove which addresses
                    # visited which site. Relearn these instead of inventing
                    # host-specific evidence during migration.
                    if not isinstance(hosts, dict) or len(hosts) != 1:
                        continue
                    host = next(iter(hosts))
                    if len(str(path)) > CANDIDATE_MAX_PATH_LENGTH:
                        continue
                    self._paths[(host, str(path))] = {
                        "first": int(first), "last": int(last),
                        "ips": {int(x) for x in ips}, "clients": {int(x) for x in clients},
                        "status": {str(k): int(v) for k, v in dict(status).items()},
                        "hosts": {str(k): int(v) for k, v in dict(hosts).items()},
                    }
                except (TypeError, ValueError):
                    continue


class UnknownHosts:
    """Names asked for that serve no site, and who asked."""

    def __init__(self) -> None:
        self._hosts: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def note(self, host: str, ip: str, client: bool, ts: int) -> None:
        with self._lock:
            entry = self._hosts.get(host)
            if entry is None:
                entry = self._hosts[host] = {
                    "first": ts, "last": ts, "requests": 0, "ips": set(), "clients": set(),
                }
                while len(self._hosts) > UNKNOWN_HOSTS_MAX:
                    self._hosts.popitem(last=False)
            self._hosts.move_to_end(host)
            entry["last"] = ts
            entry["requests"] += 1
            key = _address_key(ip)
            if len(entry["ips"]) < CANDIDATE_MAX_ADDRESSES:
                entry["ips"].add(key)
            if client and len(entry["clients"]) < CANDIDATE_MAX_ADDRESSES:
                entry["clients"].add(key)

    def prune(self, before: int) -> None:
        with self._lock:
            for host in [h for h, e in self._hosts.items() if e["last"] < before]:
                del self._hosts[host]

    def listing(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [
                {"host": host, "requests": e["requests"], "addresses": len(e["ips"]),
                 "clients": len(e["clients"]), "first": e["first"], "last": e["last"]}
                for host, e in self._hosts.items()
            ]
        rows.sort(key=lambda row: (-row["addresses"], -row["last"]))
        return rows[:limit]

    def snapshot(self) -> List[List[Any]]:
        with self._lock:
            return [[h, e["first"], e["last"], e["requests"], sorted(e["ips"]), sorted(e["clients"])]
                    for h, e in self._hosts.items()]

    def restore(self, rows: Any) -> None:
        if not isinstance(rows, list):
            return
        with self._lock:
            for row in rows[:UNKNOWN_HOSTS_MAX]:
                try:
                    host, first, last, requests, ips, clients = row
                    self._hosts[str(host)] = {
                        "first": int(first), "last": int(last), "requests": int(requests),
                        "ips": {int(x) for x in ips}, "clients": {int(x) for x in clients},
                    }
                except (TypeError, ValueError):
                    continue


class IpMemory:
    """Elastic two-segment LRU (SLRU) over addresses with a hard ceiling.

    One-hit addresses from a botnet or spoofed-source flood enter the
    probation segment and only evict other probation entries; repeat or
    flagged addresses live in the protected segment (capped at 75% of
    max_ips) so slow scanners cannot be flushed out of working memory.
    When the protected segment is not full, probation uses the remaining
    capacity up to max_ips.
    """

    def __init__(self, max_ips: int, max_paths: int) -> None:
        self.max_ips = max(1, int(max_ips))
        self.max_paths = max_paths
        # Keep at least 25% (minimum 1 slot) available for probation churn so
        # new clients can always enter and earn promotion.
        self._protected_limit = (
            max(0, self.max_ips - max(1, self.max_ips // 4))
            if self.max_ips > 1 else 0
        )
        self._probation: "OrderedDict[str, IpActivity]" = OrderedDict()
        self._protected: "OrderedDict[str, IpActivity]" = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def _promote_locked(self, ip: str, activity: IpActivity) -> None:
        if self._protected_limit <= 0:
            self._probation[ip] = activity
            self._probation.move_to_end(ip)
            return
        self._protected[ip] = activity
        self._protected.move_to_end(ip)
        while len(self._protected) > self._protected_limit:
            demoted_ip, demoted_act = self._protected.popitem(last=False)
            self._probation[demoted_ip] = demoted_act
            self._probation.move_to_end(demoted_ip)

    def _enforce_cap_locked(self) -> None:
        while len(self._probation) + len(self._protected) > self.max_ips:
            if self._probation:
                self._probation.popitem(last=False)
            else:
                self._protected.popitem(last=False)
            self.evictions += 1

    def touch(self, ip: str, ts: int) -> IpActivity:
        with self._lock:
            activity = self._protected.get(ip)
            if activity is not None:
                activity.last_seen = ts
                self._protected.move_to_end(ip)
                return activity
            activity = self._probation.pop(ip, None)
            if activity is not None:
                activity.last_seen = ts
                self._promote_locked(ip, activity)
                self._enforce_cap_locked()
                return activity
            activity = IpActivity(first_seen=ts, last_seen=ts)
            self._probation[ip] = activity
            self._enforce_cap_locked()
            return activity

    def promote(self, ip: str) -> None:
        """Move a flagged one-hit address into the protected segment."""
        with self._lock:
            activity = self._probation.pop(ip, None)
            if activity is None:
                return
            self._promote_locked(ip, activity)
            self._enforce_cap_locked()

    def get(self, ip: str) -> Optional[IpActivity]:
        with self._lock:
            activity = self._protected.get(ip)
            if activity is not None:
                return activity
            return self._probation.get(ip)

    def prune(self, older_than: int) -> int:
        with self._lock:
            removed = 0
            for segment in (self._probation, self._protected):
                stale = [
                    ip
                    for ip, activity in segment.items()
                    if activity.last_seen < older_than
                ]
                for ip in stale:
                    segment.pop(ip, None)
                removed += len(stale)
        return removed

    def segment_counts(self) -> Tuple[int, int]:
        with self._lock:
            return len(self._protected), len(self._probation)

    def __len__(self) -> int:
        with self._lock:
            return len(self._probation) + len(self._protected)


_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")


def ipv4_subnet24(ip: str) -> str:
    """Return the /24 prefix for a routable IPv4 address, or '' otherwise.

    Skips IPv6, loopback, link-local, multicast, unspecified, and RFC 6598
    carrier-grade NAT (100.64.0.0/10) where unrelated customers share blocks.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.version != 4:
        return ""
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr in _CGNAT_NET
    ):
        return ""
    octets = addr.packed
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


class SubnetCorrelator:
    """Bounded IPv4 /24 campaign tracker.

    Tracks distinct offending IPv4 addresses per /24 over a rolling window.
    Does not ban whole subnets; only reports when an already-offending address
    belongs to a /24 with multiple concurrent offenders.
    """

    def __init__(
        self,
        *,
        window_seconds: int = SUBNET_CAMPAIGN_WINDOW,
        min_ips: int = SUBNET_CAMPAIGN_MIN_IPS,
        max_subnets: int = SUBNET_CAMPAIGN_MAX_SUBNETS,
        max_ips_per_subnet: int = SUBNET_CAMPAIGN_MAX_IPS_PER_SUBNET,
    ) -> None:
        self.window_seconds = max(60, int(window_seconds))
        self.min_ips = max(2, int(min_ips))
        self.max_subnets = max(16, int(max_subnets))
        self.max_ips_per_subnet = max(self.min_ips, int(max_ips_per_subnet))
        self._subnets: "OrderedDict[str, OrderedDict[str, int]]" = OrderedDict()
        self._lock = threading.Lock()
        self.triggers = 0

    def observe(self, ip: str, now: int) -> Tuple[str, int]:
        subnet = ipv4_subnet24(ip)
        if not subnet:
            return "", 0
        cutoff = now - self.window_seconds
        with self._lock:
            peers = self._subnets.get(subnet)
            if peers is None:
                peers = self._subnets[subnet] = OrderedDict()
                while len(self._subnets) > self.max_subnets:
                    self._subnets.popitem(last=False)
            self._subnets.move_to_end(subnet)
            stale = [peer for peer, seen in peers.items() if seen < cutoff]
            for peer in stale:
                del peers[peer]
            peers[ip] = now
            peers.move_to_end(ip)
            while len(peers) > self.max_ips_per_subnet:
                peers.popitem(last=False)
            count = len(peers)
            if count >= self.min_ips:
                self.triggers += 1
            return subnet, count

    def prune(self, now: int) -> int:
        cutoff = now - self.window_seconds
        removed = 0
        with self._lock:
            empty: List[str] = []
            for subnet, peers in self._subnets.items():
                stale = [peer for peer, seen in peers.items() if seen < cutoff]
                for peer in stale:
                    del peers[peer]
                if not peers:
                    empty.append(subnet)
            for subnet in empty:
                del self._subnets[subnet]
                removed += 1
        return removed

    def summary(self, now: int) -> Dict[str, Any]:
        cutoff = now - self.window_seconds
        with self._lock:
            hot = 0
            for peers in self._subnets.values():
                active = sum(1 for seen in peers.values() if seen >= cutoff)
                if active >= self.min_ips:
                    hot += 1
            return {
                "tracked_subnets": len(self._subnets),
                "hot_subnets": hot,
                "triggers": self.triggers,
                "min_ips": self.min_ips,
                "window_seconds": self.window_seconds,
            }


# ---------------------------------------------------------------------------
# Log cursor
# ---------------------------------------------------------------------------


class LogCursor:
    """Incremental reader for a file that rsyslog rotates underneath us.

    Position is (inode, offset): when the inode changes the file was rotated
    and reading restarts at the beginning of the new one; when the file shrinks
    it was truncated in place. Neither case may replay old history, because
    re-importing yesterday's scan would invent events that already happened.
    """

    def __init__(self, path: str, state: Dict[str, Any]) -> None:
        self.path = path
        self.inode = _safe_int(state.get("inode"))
        self.offset = _safe_int(state.get("offset"))
        self.rotations = _safe_int(state.get("rotations"))
        self.lag_bytes = 0
        self.last_error: Optional[str] = None

    def state(self) -> Dict[str, Any]:
        return {
            "inode": self.inode,
            "offset": self.offset,
            "rotations": self.rotations,
        }

    def has_pending(self) -> bool:
        """Cheap stat-only check for log growth, rotation, or truncation."""
        try:
            stat = os.stat(self.path)
        except OSError:
            return False
        if self.inode == 0:
            return True
        return int(stat.st_ino) != self.inode or int(stat.st_size) != self.offset

    def read(self, max_bytes: int) -> List[str]:
        """Return complete lines, leaving a partial trailing line for later."""

        try:
            stat = os.stat(self.path)
        except OSError as exc:
            self.last_error = str(exc)
            return []
        self.last_error = None

        inode = int(stat.st_ino)
        size = int(stat.st_size)

        if self.inode == 0:
            # First ever start: begin at the end. Importing the existing file
            # would score traffic from before the daemon existed.
            self.inode, self.offset = inode, size
            return []
        if inode != self.inode:
            self.inode, self.offset = inode, 0
            self.rotations += 1
            LOG.info("Log rotated; following the new file from the start")
        elif size < self.offset:
            self.offset = 0
            self.rotations += 1
            LOG.info("Log truncated in place; restarting from the beginning")

        if size <= self.offset:
            self.lag_bytes = 0
            return []

        self.lag_bytes = max(0, size - self.offset - max_bytes)
        lines: List[str] = []
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(max_bytes)
        except OSError as exc:
            self.last_error = str(exc)
            return []

        consumed = data.rfind(b"\n") + 1
        if consumed <= 0:
            # No complete line yet; wait rather than splitting a record.
            return []
        self.offset += consumed
        for raw in data[:consumed].splitlines():
            if len(raw) > MAX_LOG_LINE_BYTES:
                raw = raw[:MAX_LOG_LINE_BYTES]
            lines.append(raw.decode("utf-8", "replace"))
        return lines
