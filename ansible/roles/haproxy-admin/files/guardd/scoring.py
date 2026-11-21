"""Event scoring policy, decay calculation, and exclusion rules."""

from __future__ import annotations

import ipaddress
import os
import pathlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .constants import (
    DEFAULT_CATEGORY_CAP,
    DEFAULT_DECAY_SECONDS,
    DEFAULT_SCORE_WINDOW_SECONDS,
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    EVENT_ERROR_RATE_EXCEEDED,
    EVENT_HARD_FLOOR,
    EVENT_LEGACY_BAN,
    EVENT_RATE_EXCEEDED,
    EVENT_SCANNER_DECISIVE,
    LEGACY_READINGS_LISTED,
    LOG,
    MAX_TRAP_HOSTS,
    OWN_BAN_CODES,
    RECOMMENDED_ACTIONS,
    _HOSTNAME_RE,
    _clamp_int,
    _safe_int,
)
from .runtime import GuardConfig

# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoringPolicy:
    """Everything that turns stored events into a number.

    Kept separate from the events on purpose: retuning any of this re-scores
    the entire history instead of requiring another week of observation.
    """

    weights: Dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    category_cap: int = DEFAULT_CATEGORY_CAP
    window_seconds: int = DEFAULT_SCORE_WINDOW_SECONDS
    decay_seconds: int = DEFAULT_DECAY_SECONDS

    def weight(self, event_type: str) -> int:
        return int(self.weights.get(event_type, 0))


def policy_from_query(
    query: Dict[str, List[str]], base: ScoringPolicy
) -> ScoringPolicy:
    """Build a what-if policy from request parameters.

    Every key is an allow-listed event type and every value is clamped, so the
    simulator can only ask "what if this weight were different" -- it cannot
    describe anything the engine would not otherwise compute.
    """

    weights = dict(base.weights)
    for name, values in query.items():
        if not name.startswith("w."):
            continue
        event_type = name[2:]
        if event_type not in DEFAULT_WEIGHTS:
            continue
        weights[event_type] = _clamp_int(
            values[0], default=base.weight(event_type), min_v=0, max_v=100
        )
    return ScoringPolicy(
        weights=weights,
        category_cap=_clamp_int(
            query.get("cap", [None])[0],
            default=base.category_cap,
            min_v=1,
            max_v=100,
        ),
        window_seconds=_clamp_int(
            query.get("window", [None])[0],
            default=base.window_seconds,
            min_v=3600,
            max_v=30 * 86400,
        ),
        decay_seconds=_clamp_int(
            query.get("decay", [None])[0],
            default=base.decay_seconds,
            min_v=0,
            max_v=30 * 86400,
        ),
    )


# Attack evidence and telemetry (U02, 04.7b).
#
# The policy the operator set on 31 October: an ordinary excess is answered
# with a refusal of the excess (429 for a stranger, a warning for a trusted
# address), never a ban; bans are for evidence of an attack. Three findings
# are the ordinary excess and what HAProxy did about it, and each repeats its
# cause: a rate or error counter over a site's soft limit, and the legacy ban
# HAProxy wrote for exactly that reading. Real enumeration is caught from the
# log by distinct paths (NOT_FOUND/WIDE/MASS_ENUMERATION), which a monitor
# repeating one 403 never trips -- on one gateway 72 legacy bans in eight
# days were cloud monitors with sixteen answers of each code.
#
# They stay recorded, and shown with every address; under U02 they weigh
# nothing. A sustained hard-floor episode is the evidence that takes their
# place. Which weights apply follows the ban policy HAProxy runs (see
# BanPolicyWatch): DEFAULT_WEIGHTS under legacy, u02_policy under u02.
TELEMETRY_EVENTS: frozenset = frozenset(
    {EVENT_RATE_EXCEEDED, EVENT_ERROR_RATE_EXCEEDED, EVENT_LEGACY_BAN}
)
# One sustained episode reaches the ban line (the operator's choice, 4
# November): the ceilings are about five times what the busiest legitimate
# address was measured doing (216 requests in 10 s, 98 in flight), held for
# two reads in a row; in 7.6 days of two production gateways' logs no address
# came near them (the highest was 708, once, a scanner).
U02_EVIDENCE_WEIGHTS: Dict[str, int] = {EVENT_HARD_FLOOR: 60}


def u02_policy(base: ScoringPolicy) -> ScoringPolicy:
    """The same policy with telemetry weighing nothing and the floor weighed."""

    weights = dict(base.weights)
    for event_type in TELEMETRY_EVENTS:
        weights[event_type] = 0
    for event_type, weight in U02_EVIDENCE_WEIGHTS.items():
        if not weights.get(event_type):
            weights[event_type] = weight
    return ScoringPolicy(
        weights=weights,
        category_cap=base.category_cap,
        window_seconds=base.window_seconds,
        decay_seconds=base.decay_seconds,
    )


# Findings that score even when HAProxy had already refused the request.
#
# A refusal used to excuse everything: an address whose every request was
# answered 451 scored nothing, whatever it asked for. One spent a morning
# working through /.git-credentials under every common web root, was
# recognised for secrets, vcs and backup on each request, and stayed at score
# zero -- free to try the next site, one without a country filter, or the
# login page, which cannot have one.
#
# A decisive category is the content of the request, not the identity of the
# client, and no browser, framework or crawler ever asks for one. The 451
# only kept that one request out; a ban keeps the address out of every host
# and port before the TLS handshake. A plain 451 still scores nothing, so a
# person whose authorisation lapsed is never banned for being turned away.
# `handled` stays a true record of what HAProxy did, which is why the rule
# lives here: changing it re-scores the history that is already stored.
REFUSAL_DOES_NOT_EXCUSE: frozenset = frozenset({EVENT_SCANNER_DECISIVE})


def state_for(score: int) -> str:
    for threshold, name in DEFAULT_THRESHOLDS:
        if score >= threshold:
            return name
    return "NORMAL"


def _own_ban_observation(event: Dict[str, Any]) -> bool:
    detail = str(event.get("detail", ""))
    return any(detail == f"code={code}" for code in OWN_BAN_CODES)


def score_events(
    events: Iterable[Dict[str, Any]], now: int, policy: ScoringPolicy
) -> Dict[str, Any]:
    """Derive a 0..100 score and its explanation from stored events.

    Contributions fade with age rather than being decremented on a timer, and
    each scanner category is capped, so a bot grinding through fifty WordPress
    URLs counts as one finding rather than fifty.
    """

    total = 0.0
    per_category: Dict[str, float] = {}
    contributions: List[Dict[str, Any]] = []
    counted = 0

    for event in events:
        ts = int(event.get("ts", 0))
        age = max(0, now - ts)
        if age > policy.window_seconds:
            continue
        event_type = str(event.get("event_type", ""))
        base = policy.weight(event_type)
        if base <= 0:
            continue
        if event_type == EVENT_LEGACY_BAN and _own_ban_observation(event):
            # Recorded before the gateway's own bans stopped being written as
            # findings; they keep no weight.
            continue
        if int(event.get("handled", 0)) and event_type not in REFUSAL_DOES_NOT_EXCUSE:
            # HAProxy already refused this request; banning on top of a GeoIP
            # denial adds nothing.
            contributions.append(
                {
                    "ts": ts,
                    "event_type": event_type,
                    "category": str(event.get("category", "")),
                    "points": 0,
                    "reason": "already refused by the gateway",
                    "site": str(event.get("site", "")),
                    "detail": str(event.get("detail", "")),
                }
            )
            continue
        decay = 1.0
        if policy.decay_seconds > 0:
            decay = max(0.0, 1.0 - age / policy.decay_seconds)
        points = base * decay
        if points <= 0:
            continue

        category = str(event.get("category", "")) or event_type
        used = per_category.get(category, 0.0)
        # The cap stops repetition from inflating a finding, but it must never
        # clip a single event below its own weight -- otherwise raising a
        # weight above the cap would have no effect at all.
        ceiling = max(policy.category_cap, base)
        allowed = max(0.0, ceiling - used)
        granted = min(points, allowed)
        per_category[category] = used + granted
        total += granted
        counted += 1
        contributions.append(
            {
                "ts": ts,
                "event_type": event_type,
                "category": str(event.get("category", "")),
                "points": round(granted, 2),
                "reason": (
                    "category cap reached"
                    if granted < points
                    else "counted"
                ),
                # What the finding was about, not just that there was one:
                # which site, and the counter reading that triggered it.
                "site": str(event.get("site", "")),
                "detail": str(event.get("detail", "")),
            }
        )

    score = int(min(100.0, round(total)))
    state = state_for(score)
    return {
        "score": score,
        "state": state,
        "recommended_action": RECOMMENDED_ACTIONS.get(state, "none"),
        "events_counted": counted,
        "categories": {
            name: round(value, 2) for name, value in per_category.items()
        },
        "contributions": contributions,
    }


@dataclass
class Verdict:
    excluded: bool
    reason: str
    # Which list made a whitelisted address trusted: "whitelist", "admin",
    # "geo-whitelist" or "trusted-network". The rate warnings say it, because
    # the gateway treats them differently (see TrustedRates).
    source: str = ""


class ExclusionModel:
    """Who guardd must never act on.

    Mirrors the ACLs in the HAProxy configuration: the global whitelist, the
    admin allow-list, the GeoIP whitelist, and -- read live from the runtime --
    the addresses that completed Authelia authentication. HAProxy exempts all
    of these from its own bans, so scoring them would only produce noise.
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._networks: List[Any] = []
        self._signatures: Dict[str, Tuple[int, int]] = {}
        self._authenticated: Set[str] = set()
        # False under U02, set by the engine from the policy HAProxy runs.
        self.geo_trusted = True
        self.reload_files(force=True)

    # -- static files -----------------------------------------------------

    def reload_files(self, *, force: bool = False) -> bool:
        signatures: Dict[str, Tuple[int, int]] = {}
        for path in self.config.whitelist_files:
            try:
                stat = os.stat(path)
                signatures[path] = (int(stat.st_mtime), int(stat.st_size))
            except OSError:
                signatures[path] = (0, 0)
        if not force and signatures == self._signatures:
            return False

        # Each network with the list it came from.
        networks: List[Tuple[Any, str]] = []
        for path in self.config.whitelist_files:
            source = self._source_of(path)
            networks.extend((network, source) for network in self._read_acl_file(path))
        for entry in self.config.trusted_networks:
            network = self._parse_network(entry)
            if network is not None:
                networks.append((network, "trusted-network"))

        with self._lock:
            self._networks = networks
            self._signatures = signatures
        LOG.info(
            "Exclusion list reloaded: %d networks from %d files",
            len(networks),
            len(self.config.whitelist_files),
        )
        return True

    @staticmethod
    def _source_of(path: str) -> str:
        """Which of the three lists a file is, by its name.

        The admin allow-list and the GeoIP whitelist are not the same kind of
        trust as the global whitelist: HAProxy exempts a GeoIP-whitelisted
        address from the country filter only, and still rate-limits it.
        """
        name = os.path.basename(path).lower()
        if "admin" in name:
            return "admin"
        if "geo" in name:
            return "geo-whitelist"
        return "whitelist"

    @staticmethod
    def _parse_network(entry: str) -> Optional[Any]:
        try:
            return ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return None

    def _read_acl_file(self, path: str) -> List[Any]:
        networks: List[Any] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for raw in handle:
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    # HAProxy pattern files allow a trailing label after the
                    # pattern; only the first token is the address.
                    network = self._parse_network(line.split()[0])
                    if network is not None:
                        networks.append(network)
        except OSError:
            return []
        return networks

    # -- runtime ----------------------------------------------------------

    def refresh_authenticated(self, rows: Dict[str, Dict[str, str]]) -> None:
        """Addresses currently holding an Authelia authorization."""

        authenticated = {
            key
            for key, fields in rows.items()
            if _safe_int(fields.get("gpc0")) > 0
        }
        with self._lock:
            self._authenticated = authenticated

    # -- queries ----------------------------------------------------------

    def verdict(self, ip: str) -> Verdict:
        with self._lock:
            if ip in self._authenticated:
                return Verdict(True, "authenticated")
            networks = list(self._networks)
            geo_trusted = self.geo_trusted
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return Verdict(True, "unparsable")
        if address.is_loopback or address.is_link_local:
            return Verdict(True, "local")
        for network, source in networks:
            if source == "geo-whitelist" and not geo_trusted:
                # Under U02 the GeoIP whitelist means what it means to HAProxy:
                # past the country filter, not trusted (the operator's choice,
                # 4 November).
                continue
            if address.version == network.version and address in network:
                return Verdict(True, "whitelisted", source)
        return Verdict(False, "")

    @property
    def authenticated_count(self) -> int:
        with self._lock:
            return len(self._authenticated)

    @property
    def network_count(self) -> int:
        with self._lock:
            return len(self._networks)


HAPROXY_CONFIG_PATH = os.environ.get("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg")

# The thresholds are written into the generated configuration as ACLs, which
# makes that file the authority on what "exceeded" means. Reading them from
# there keeps one number in one place: change max_req_rate in the interface,
# apply, and the engine agrees without being told separately.
_THRESHOLD_RE = re.compile(
    r"^\s*acl\s+\S+\s+(?:src_http_req_rate|src_http_err_rate|sc0_conn_rate)"
    r"\((?P<table>[A-Za-z0-9_.-]+)\)\s+gt\s+(?P<limit>\d+)\s*$",
    re.MULTILINE,
)


_VALID_HOST_RE = re.compile(r"^\s*acl\s+valid_host\s+hdr\(host\)\s+-i\s+(?P<names>.+?)\s*$", re.MULTILINE)


def read_site_names(path: str = "") -> Set[str]:
    """Every name the gateway serves, from its own valid_host ACL."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return set()
    names: Set[str] = set()
    for match in _VALID_HOST_RE.finditer(text):
        names.update(name.lower() for name in match.group("names").split())
    return names


def normalize_host(host: str) -> str:
    """Lower case, without a port; "" for an address or anything odd."""
    text = (host or "").strip().lower()
    if text.startswith("["):
        return ""
    text = re.sub(r":\d+$", "", text)
    if not text or re.match(r"^\d+(\.\d+){3}$", text):
        return ""
    return text if _HOSTNAME_RE.match(text) else ""


def validate_trap_hosts(hosts: Any, site_names: Set[str]) -> List[str]:
    if not isinstance(hosts, list):
        raise ValueError("expected a list of names")
    if len(hosts) > MAX_TRAP_HOSTS:
        raise ValueError(f"at most {MAX_TRAP_HOSTS} trap names")
    checked: List[str] = []
    for raw in hosts:
        name = normalize_host(str(raw))
        if not name:
            raise ValueError(f"{str(raw)[:80]} is not a host name")
        # A trap on a name that serves a site would ban its visitors.
        if name in site_names:
            raise ValueError(f"{name} serves a site and cannot be a trap")
        if name not in checked:
            checked.append(name)
    return sorted(checked)


def read_thresholds(path: str = "") -> Dict[str, int]:
    """Map each counter table to the value HAProxy treats as too much."""
    try:
        text = pathlib.Path(path or HAPROXY_CONFIG_PATH).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        LOG.warning("cannot read %s for thresholds: %s", path or HAPROXY_CONFIG_PATH, exc)
        return {}
    return {
        match.group("table"): int(match.group("limit"))
        for match in _THRESHOLD_RE.finditer(text)
    }


def decision_summary(reason: Dict[str, Any]) -> Dict[str, Any]:
    """A decision's reason in one line's worth, for the feed (06.6): the
    categories an adaptive ban counted, heaviest first, or the site counters
    over their limit when HAProxy's own ban was first seen."""
    summary: Dict[str, Any] = {}
    categories = reason.get("categories")
    if isinstance(categories, dict) and categories:
        ranked = sorted(categories.items(), key=lambda item: (-float(item[1] or 0), str(item[0])))
        summary["categories"] = [str(name) for name, _ in ranked[:4]]
    elif isinstance(reason.get("evidence"), list):
        seen: List[str] = []
        for entry in reason["evidence"]:
            name = str((entry or {}).get("category") or (entry or {}).get("event_type") or "")
            if name and name not in seen:
                seen.append(name)
        if seen:
            summary["categories"] = seen[:4]
    if reason.get("evidence_total"):
        summary["evidence_total"] = int(reason["evidence_total"])
    readings = reason.get("readings")
    if isinstance(readings, list):
        over = [entry for entry in readings if isinstance(entry, dict) and entry.get("over")]
        summary["over"] = [
            {key: entry.get(key) for key in ("site", "counter", "value", "limit")}
            for entry in over[:2]
        ]
    return summary


def legacy_ban_readings(
    ip: str, tables: Dict[str, Dict[str, Dict[str, str]]], thresholds: Dict[str, int],
) -> List[Dict[str, Any]]:
    """The per-site request and error counters holding an address, with the
    limit each is held to: what can be said about a ban HAProxy placed on
    its own rules, which it does not explain. Over the limit first."""
    readings: List[Dict[str, Any]] = []
    for name in sorted(tables):
        if name.startswith("tbl_rate_"):
            counter = "http_req_rate"
        elif name.startswith("tbl_err_"):
            counter = "http_err_rate"
        else:
            continue
        fields = tables[name].get(ip)
        if not fields:
            continue
        value = next((_safe_int(raw) for key, raw in fields.items() if key.startswith(counter)), 0)
        if value <= 0:
            continue
        limit = thresholds.get(name)
        readings.append({
            "table": name,
            "site": name.split("_", 2)[-1],
            "counter": counter,
            "value": value,
            "limit": limit,
            "over": limit is not None and value > limit,
        })
    readings.sort(key=lambda item: (not item["over"], -item["value"], item["table"]))
    return readings[:LEGACY_READINGS_LISTED]
