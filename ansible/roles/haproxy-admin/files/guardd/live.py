"""In-memory live activity buffer, minute digests, and enforcement queue."""

from __future__ import annotations

import heapq
import itertools
import json
import re
import threading
import time
from collections import Counter, OrderedDict, deque
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

from .constants import _clamp_int

if TYPE_CHECKING:
    from .parser import ParsedRequest
    from .request_log import RequestQuery
from .parser import (
    LIVE_ADMIN_BACKENDS,
    LOGGED_AGENT_OTHER,
    L_AGENT,
    L_AUTH_USER,
    L_BACKEND,
    L_BYTES,
    L_DURATION,
    L_HOST,
    L_IP,
    L_METHOD,
    L_PATH,
    L_REASON,
    L_REFUSAL,
    L_REQUEST_ID,
    L_RESPONSE,
    L_STATUS,
    L_TERM,
    L_TIMES,
    L_TS,
    live_refusal,
)
from .request_log import REQUEST_COUNT_CAP, REQUEST_SUMMARY_SECONDS, RequestSummary, summary_layout

# ---------------------------------------------------------------------------
# Live activity
# ---------------------------------------------------------------------------
#
# The live activity page asks "who is hitting the gateway right now". It used
# to be answered by reading the access log again on every refresh of every
# open page: harmless at three requests a second, several seconds of CPU per
# refresh under a flood -- exactly when HAProxy needs the CPU. This daemon
# already reads every line once, within a byte budget, for scoring. So the
# latest requests are kept here in memory, compactly, and the page is
# answered from memory: no extra read, no second parse, and a flood larger
# than the budget makes the page fall behind instead of the gateway.

LIVE_MAX_ADDRESSES = 300
LIVE_MAX_BLOCKED_ADDRESSES = 500
LIVE_MAX_EVENTS = 300
# The top lists of the window: what was asked for most, what was not found
# most (scanners walk paths that do not exist), which clients, and the
# slowest answers.
LIVE_MAX_PATHS = 50
LIVE_MAX_NOT_FOUND = 30
LIVE_MAX_AGENTS = 30
LIVE_MAX_SLOW = 50
LIVE_CACHE_SECONDS = 2.0
LIVE_WANTED_SECONDS = 120
LIVE_FAST_TICK_SECONDS = 2.0
# Sub-poll wake interval when checking for new access-log bytes so decisive
# findings can be enforced within ~1s instead of waiting out the full poll
# interval; costs a single stat() syscall when idle.
FAST_REACTION_TICK_SECONDS = 1.0
# After a restart the buffer is filled again from the tail of the log, at
# most this much of it: an hour of a busy gateway, a few seconds to parse.
LIVE_REFILL_BYTES = 16 * 1024 * 1024
# What is older than that is read in the background, this much at a time
# (08), until the buffer is this full, the horizon is reached or the file
# begins.
LIVE_REFILL_CHUNK_BYTES = 4 * 1024 * 1024
LIVE_REFILL_FULL = 0.98
# The dashboard's top 400/451 addresses are counted per hour beside the
# buffer, not in it. At most this many addresses an hour each; past it the
# less busy half goes (the 4 November review measured 40 000 addresses in
# about 5 MB outside the budget).
LIVE_HOURLY_MAX_ADDRESSES = 10_000

_INTERN: Dict[str, str] = {}


def _interned(value: str) -> str:
    """Hosts, backends and states repeat endlessly; keep one copy of each."""
    if len(_INTERN) > 50_000:
        _INTERN.clear()
    return _INTERN.setdefault(value, value)


def line_epoch(line: str) -> Optional[float]:
    """The syslog timestamp at the start of a line, which carries its zone."""
    stamp = line[:40].split(" ", 1)[0]
    try:
        return datetime.fromisoformat(stamp).timestamp()
    except ValueError:
        return None




# ---------------------------------------------------------------------------
# Minute digests for the monitoring page
# ---------------------------------------------------------------------------
#
# The log is the only place that says how long each request took and why
# the gateway turned one away. HAProxy's counters give an average response
# time and no percentile, and count refusals by status rather than by
# reason. This daemon reads every line anyway, so it folds each into a
# digest of its minute -- a histogram of response times per backend, and
# refusals by reason -- and keeps no line. The collector of the monitoring
# page asks for the minutes that are complete and stores them like the rest
# of what it charts.

# Upper edges of the histogram, in milliseconds; one more bucket above.
DIGEST_BOUNDS_MS = (
    5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750,
    1000, 1500, 2000, 3000, 5000, 10000, 30000,
)
# A minute is complete this long after it ended: a line is written when its
# request ends and read within one poll.
DIGEST_CLOSE_SECONDS = 30
# How long complete minutes wait to be asked for.
DIGEST_KEEP_SECONDS = 3 * 3600
DIGEST_MAX_BACKENDS = 200
DIGEST_REFUSALS = ("geo", "banned", "rate", "other")


def _digest_bucket(duration_ms: int) -> int:
    for index, bound in enumerate(DIGEST_BOUNDS_MS):
        if duration_ms <= bound:
            return index
    return len(DIGEST_BOUNDS_MS)


class MinuteDigests:
    """Per-minute histograms and refusal counts, minutes keyed by when the
    request ended (the syslog stamp, which carries its zone)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._minutes: Dict[int, Dict[str, Any]] = {}
        self._trim_minute: Optional[int] = None
        self.late = 0

    def _trim_locked(self, now: int, *, force: bool = False) -> None:
        minute = now // 60
        if not force and minute == self._trim_minute:
            return
        # The producer owns retention even when no monitoring client asks
        # for digests. Scan at most once per wall-clock minute on its hot path.
        self._trim_minute = minute
        for stamp in [m for m in self._minutes if m < now - DIGEST_KEEP_SECONDS]:
            del self._minutes[stamp]

    def add(self, request: "ParsedRequest", ended: float, now: int) -> None:
        minute = int(ended) // 60 * 60
        refusal = live_refusal(request.status, request.backend, request.term, request.ban_reason)
        backend = request.backend.split("/", 1)[0] if request.backend else ""
        answered = (
            not refusal
            and not request.bad_request
            and request.status > 0
            and request.response_ms >= 0
            and backend
            and not request.backend.endswith("/<NOSRV>")
        )
        with self._lock:
            self._trim_locked(now)
            if minute + 60 + DIGEST_CLOSE_SECONDS <= now:
                # Its minute was already handed out as complete.
                self.late += 1
                return
            if not refusal and not answered:
                return
            digest = self._minutes.get(minute)
            if digest is None:
                digest = {"backends": {}, "refused": dict.fromkeys(DIGEST_REFUSALS, 0)}
                self._minutes[minute] = digest
            if refusal:
                kind = refusal if refusal in ("geo", "banned") else (
                    "rate" if refusal == "rate-limited" else "other"
                )
                digest["refused"][kind] += 1
                return
            histogram = digest["backends"].get(backend)
            if histogram is None:
                if len(digest["backends"]) >= DIGEST_MAX_BACKENDS:
                    return
                histogram = [0] * (len(DIGEST_BOUNDS_MS) + 1)
                digest["backends"][backend] = histogram
            histogram[_digest_bucket(int(request.response_ms))] += 1

    def complete(self, since: int, now: int) -> List[Dict[str, Any]]:
        """The complete minutes after since, oldest first; forgets old ones."""

        with self._lock:
            self._trim_locked(now, force=True)
            ready = sorted(
                minute for minute in self._minutes
                if minute > since and minute + 60 + DIGEST_CLOSE_SECONDS <= now
            )
            return [
                {
                    "ts": minute,
                    "backends": {name: list(hist) for name, hist in self._minutes[minute]["backends"].items()},
                    "refused": dict(self._minutes[minute]["refused"]),
                }
                for minute in ready
            ]


def live_record(request: "ParsedRequest", ts: float) -> tuple:
    return (
        ts,
        request.client_ip,
        request.status,
        _interned(request.host),
        request.path[:200] if not request.bad_request else "<BADREQ>",
        _interned(request.method),
        _interned(request.backend),
        request.bytes_out,
        request.duration_ms,
        _interned(request.term),
        request.ban_reason,
        live_refusal(request.status, request.backend, request.term, request.ban_reason),
        # %Tr: how soon the server answered; -1 when it did not. The total
        # (L_DURATION) also holds downloads and long polls.
        request.response_ms,
        # For the details of one request: where its time went, the id that
        # finds it in the request log, and the client's own name for itself.
        request.times,
        request.request_id,
        _interned(request.user_agent[:200]),
        request.authenticated_user,
    )


# The size of a live record, estimated as it is added (07.2), so the buffer
# can be bounded by memory without ever walking it. The tuple, its numbers and
# the shared strings (hosts, methods, backends, states, agents -- kept once
# in _INTERN) come to about LIVE_RECORD_BASE_BYTES; each string of the
# request's own costs its object and its characters. Calibrated with
# tracemalloc on two production gateways' logs: 532 estimated against 514
# traced and about 574 held by the process (allocator slack) on the busier.
LIVE_RECORD_BASE_BYTES = 230
LIVE_STRING_BYTES = 49
_LIVE_OWN_FIELDS = (L_IP, L_PATH, L_REASON, L_TIMES, L_REQUEST_ID, L_AUTH_USER)


def live_record_bytes(record: tuple) -> int:
    size = LIVE_RECORD_BASE_BYTES
    for index in _LIVE_OWN_FIELDS:
        if index < len(record):
            value = record[index]
            if value:
                size += LIVE_STRING_BYTES + len(value)
    return size


# The memory an operator may give the live buffer (07.4-07.5). Until one is
# chosen the buffer keeps the profile it always had -- 100000 requests or an
# hour -- so nothing changes on an installation nobody touched. A chosen
# budget bounds it by memory instead, up to a day of requests, with a count
# far above anything the budget allows as a last guard.
LIVE_BUDGET_MIN_MIB = 16
LIVE_BUDGET_MAX_MIB = 128
LIVE_BUDGET_STEP_MIB = 8
LIVE_BUDGET_MAX_SECONDS = 24 * 3600
LIVE_BUDGET_MAX_RECORDS = 1_000_000
LIVE_BUDGET_STATE_KEY = "live_memory_budget"
# What a budget may take, besides the cap above. The process holds more than
# the estimate (allocator slack, and Python keeps a peak it reached), and a
# search or a snapshot briefly needs room of its own; so inside the service's
# memory limit a reserve stays free, and growing the buffer may take at most
# a quarter of what the whole machine still has available.
LIVE_BUDGET_SLACK = 1.15
LIVE_BUDGET_SERVICE_RESERVE = 96 * 1024 * 1024
LIVE_BUDGET_HOST_SHARE = 0.25
# The traffic a budget is measured against: the last hour of arrivals.
LIVE_RATE_SECONDS = 3600
# The live page's longest window, however far the buffer reaches: a snapshot
# walks the whole window, and on a small ARM board an hour already takes a
# good part of a second.
LIVE_WINDOW_MAX_SECONDS = 3600
MIB = 1024 * 1024


class LiveBudgetConflict(Exception):
    """The budget was changed since the page asking was read."""


def _read_first_line(path: str) -> str:
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            return handle.readline().strip()
    except OSError:
        return ""


def process_rss_bytes() -> int:
    """This process's resident memory, or 0 when it cannot be read."""
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def service_memory_limit() -> int:
    """The memory limit of the service this process runs in (systemd's
    MemoryMax, a cgroup's memory.max), or 0 when there is none."""
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return 0
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        if parts[0] == "0" and parts[1] == "":
            text = _read_first_line(f"/sys/fs/cgroup{parts[2].rstrip('/')}/memory.max")
        elif "memory" in parts[1].split(","):
            text = _read_first_line(f"/sys/fs/cgroup/memory{parts[2].rstrip('/')}/memory.limit_in_bytes")
        else:
            continue
        if text.isdigit() and 0 < int(text) < 2 ** 50:
            return int(text)
    return 0


def host_memory_available() -> int:
    """MemAvailable of the whole machine, or 0 when it cannot be read."""
    try:
        with open("/proc/meminfo", encoding="ascii", errors="replace") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def live_budget_ceiling(held_bytes: int, host: bool = True) -> Tuple[int, str]:
    """The largest budget, in MiB, the buffer may be given now, and what set
    it: "cap" (this daemon's own limit), "service" (the unit's MemoryMax) or
    "host" (the memory the machine has available). Rounded down to a step of
    the panel's slider."""
    ceiling, reason = float(LIVE_BUDGET_MAX_MIB), "cap"
    limit = service_memory_limit()
    rss = process_rss_bytes()
    if limit and rss:
        # The rest of the daemon, without what the buffer holds now.
        baseline = max(0, rss - held_bytes * LIVE_BUDGET_SLACK)
        room = (limit - baseline - LIVE_BUDGET_SERVICE_RESERVE) / LIVE_BUDGET_SLACK / MIB
        if room < ceiling:
            ceiling, reason = room, "service"
    if host:
        available = host_memory_available()
        if available:
            room = (held_bytes + available * LIVE_BUDGET_HOST_SHARE / LIVE_BUDGET_SLACK) / MIB
            if room < ceiling:
                ceiling, reason = room, "host"
    stepped = int(max(0.0, ceiling)) // LIVE_BUDGET_STEP_MIB * LIVE_BUDGET_STEP_MIB
    return stepped, reason


def _live_matches(record: tuple, filters: Dict[str, Any]) -> bool:
    ip = filters.get("ip")
    if ip and not record[L_IP].startswith(ip):
        return False
    host = filters.get("host")
    if host and record[L_HOST] != host:
        return False
    query = filters.get("q")
    if query and query not in record[L_PATH].lower() and query not in record[L_HOST]:
        return False
    status = filters.get("status")
    if status and str(record[L_STATUS])[:1] != status[:1]:
        return False
    if filters.get("blocked") and not record[L_REFUSAL]:
        return False
    ips = filters.get("ips")
    if ips is not None and record[L_IP] not in ips:
        return False
    if filters.get("hide_admin") and record[L_BACKEND].partition("/")[0] in LIVE_ADMIN_BACKENDS:
        return False
    agent = filters.get("agent")
    if agent and (len(record) <= L_AGENT or agent not in record[L_AGENT].lower()):
        return False
    return True


def live_filters(raw: Dict[str, Any]) -> Dict[str, Any]:
    filters: Dict[str, Any] = {}
    ip = str(raw.get("ip") or "").strip()
    if ip:
        if not re.fullmatch(r"[0-9A-Fa-f:.]{1,45}", ip):
            raise ValueError("invalid ip filter")
        filters["ip"] = ip
    host = str(raw.get("host") or "").strip().lower()
    if host:
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            raise ValueError("invalid host filter")
        filters["host"] = host
    query = str(raw.get("q") or "").strip().lower()
    if query:
        filters["q"] = query[:120]
    status = str(raw.get("status") or "").strip()
    if status:
        if status not in ("1xx", "2xx", "3xx", "4xx", "5xx"):
            raise ValueError("invalid status filter")
        filters["status"] = status
    if str(raw.get("blocked") or "").lower() in ("1", "true", "yes", "on"):
        filters["blocked"] = True
    # Addresses in the ban table now, with everything they sent in the
    # window -- including the requests from before the ban, which the
    # gateway let through and "blocked" therefore does not show.
    if str(raw.get("banned") or "").lower() in ("1", "true", "yes", "on"):
        filters["banned"] = True
    if str(raw.get("hide_admin") or "").lower() in ("1", "true", "yes", "on"):
        filters["hide_admin"] = True
    agent = str(raw.get("agent") or "").strip().lower()
    if agent:
        # The log keeps a user agent with every other character made "_"
        # (the template's regsub), so "Windows NT" is looked for as written there.
        filters["agent"] = LOGGED_AGENT_OTHER.sub("_", agent[:120])
    return filters


def _live_event(r: tuple) -> Dict[str, Any]:
    """One request as the page shows it."""
    return {
        "ts": r[0], "ip": r[1], "host": r[3], "method": r[5], "path": r[4],
        "status": r[2], "duration_ms": r[8], "bytes": r[7], "backend": r[6],
        "term": r[9], "refusal": r[11], "ban_reason": r[10],
        "response_ms": r[12] if len(r) > 12 and r[12] >= 0 else None,
        "times": r[13] if len(r) > 13 else "",
        "request_id": r[14] if len(r) > 14 else "",
        "user_agent": r[15] if len(r) > 15 else "",
        "authenticated_user": r[L_AUTH_USER] if len(r) > L_AUTH_USER else "",
    }


def _server_times(values: List[int]) -> Dict[str, Optional[int]]:
    """Median and 95th percentile of how soon the server answered.

    An average lets one slow request in twenty hide, and a mean of totals
    put a quiet Nextcloud at twelve seconds: its long polls wait for news.
    None without an answered request, never 0 ms.
    """
    if not values:
        return {"p50_ms": None, "p95_ms": None, "avg_ms": None}
    ordered = sorted(values)
    last = len(ordered) - 1
    return {
        "p50_ms": ordered[round(0.50 * last)],
        "p95_ms": ordered[round(0.95 * last)],
        "avg_ms": sum(ordered) // len(ordered),
    }


def live_aggregate(
    records: Iterable[tuple], *, now: float, window: int, filters: Dict[str, Any],
    covered: Optional[int] = None,
) -> Dict[str, Any]:
    """Totals, addresses, sites, a timeline and the latest requests.

    Written for the worst case it has to survive: a flood from tens of
    thousands of distinct addresses. Each address is a short list, and its
    sites and refusal reasons are counted only once it has more than one.
    """
    since = now - window
    bucket = max(1, window // 60)
    buckets = (window + bucket - 1) // bucket
    ok_counts = [0] * buckets
    error_counts = [0] * buckets
    blocked_counts = [0] * buckets
    # address -> [requests, errors, 5xx, refused, bytes, ms, first ts,
    #             last record, {host: n} or host, {reason: n} or reason,
    #             server ms, answered]
    addresses: Dict[str, list] = {}
    # site -> [requests, errors, 5xx, refused, ms, set of addresses, backend,
    #          server ms of each answered request]
    sites: Dict[str, list] = {}
    statuses: Counter = Counter()
    refusals: Counter = Counter()
    events: deque = deque(maxlen=LIVE_MAX_EVENTS)
    # (host, path) -> [requests, 4xx, 404, 5xx, refused]
    paths: Dict[Tuple[str, str], list] = {}
    # user agent -> [requests, refused, set of addresses]
    agents: Dict[str, list] = {}
    # The slowest answers: a heap of (server ms, order, record), smallest on top.
    slow: List[Tuple[int, int, tuple]] = []
    total = errors_total = server_total = blocked_total = bytes_total = 0
    filtering = bool(filters)

    for record in records:
        ts = record[0]
        if ts < since or (filtering and not _live_matches(record, filters)):
            continue
        status = record[2]
        refusal = record[11]
        error = status >= 400
        server_error = status >= 500
        size = record[7]
        host = record[3]
        total += 1
        bytes_total += size
        statuses[status] += 1
        slot = int((ts - since) // bucket)
        if slot >= buckets:
            slot = buckets - 1
        if refusal:
            blocked_total += 1
            refusals[refusal] += 1
            blocked_counts[slot] += 1
        elif error:
            error_counts[slot] += 1
        else:
            ok_counts[slot] += 1
        if error:
            errors_total += 1
            if server_error:
                server_total += 1

        ip = record[1]
        answered_ms = record[12] if len(record) > 12 and record[12] >= 0 else -1
        entry = addresses.get(ip)
        if entry is None:
            addresses[ip] = [1, int(error), int(server_error), int(bool(refusal)), size,
                             record[8], ts, record, host, (record[10] or refusal) if refusal else "",
                             max(0, answered_ms), int(answered_ms >= 0)]
        else:
            if answered_ms >= 0:
                entry[10] += answered_ms
                entry[11] += 1
            entry[0] += 1
            entry[1] += error
            entry[2] += server_error
            entry[4] += size
            entry[5] += record[8]
            entry[7] = record
            known = entry[8]
            if known.__class__ is dict:
                known[host] = known.get(host, 0) + 1
            elif known != host:
                entry[8] = {known: entry[0] - 1, host: 1}
            if refusal:
                entry[3] += 1
                reason = record[10] or refusal
                held = entry[9]
                if held.__class__ is dict:
                    held[reason] = held.get(reason, 0) + 1
                elif not held:
                    entry[9] = reason
                elif held != reason:
                    entry[9] = {held: entry[3] - 1, reason: 1}

        site = sites.get(host)
        if site is None:
            site = sites[host] = [0, 0, 0, 0, 0, set(), "", [], [0] * buckets]
        if answered_ms >= 0:
            site[7].append(answered_ms)
            if len(slow) < LIVE_MAX_SLOW:
                heapq.heappush(slow, (answered_ms, total, record))
            elif answered_ms > slow[0][0]:
                heapq.heapreplace(slow, (answered_ms, total, record))
        site[8][slot] += 1
        path_key = (host, record[4])
        counted = paths.get(path_key)
        if counted is None:
            counted = paths[path_key] = [0, 0, 0, 0, 0]
        counted[0] += 1
        if refusal:
            counted[4] += 1
        elif status == 404:
            counted[2] += 1
            counted[1] += 1
        elif server_error:
            counted[3] += 1
        elif error:
            counted[1] += 1
        agent = record[15] if len(record) > 15 else ""
        if agent:
            client = agents.get(agent)
            if client is None:
                client = agents[agent] = [0, 0, set()]
            client[0] += 1
            client[1] += bool(refusal)
            if len(client[2]) < 1000:
                client[2].add(ip)
        site[0] += 1
        site[1] += error
        site[2] += server_error
        site[3] += bool(refusal)
        site[4] += record[8]
        site[5].add(ip)
        if not site[6] and not record[6].endswith("/<NOSRV>"):
            site[6] = record[6].split("/", 1)[0]
        events.append(record)

    covered = window if covered is None else max(1, min(window, covered))

    def most(value: Any) -> Tuple[str, int]:
        if value.__class__ is dict:
            return max(value.items(), key=lambda item: item[1])[0], len(value)
        return value, 1 if value else 0

    def address_row(ip: str, entry: list) -> Dict[str, Any]:
        last = entry[7]
        top_host, host_count = most(entry[8])
        reason, _ = most(entry[9])
        span = max(1.0, min(covered, now - entry[6] + 1))
        return {
            "ip": ip, "requests": entry[0], "rate": round(entry[0] / span, 2),
            "errors": entry[1], "server_errors": entry[2], "blocked": entry[3],
            "bytes": entry[4], "avg_ms": entry[10] // entry[11] if entry[11] else None,
            "top_host": top_host, "hosts": host_count if top_host or host_count > 1 else 0,
            "last": last[0], "last_status": last[2], "last_method": last[5],
            "last_path": last[4][:160], "last_host": last[3], "reason": reason,
        }

    ranked = sorted(addresses.items(), key=lambda item: -item[1][0])[:LIVE_MAX_ADDRESSES]
    chosen = {ip for ip, _ in ranked}
    blocked = sorted(
        ((ip, e) for ip, e in addresses.items() if e[3] and ip not in chosen),
        key=lambda item: -item[1][3],
    )[:LIVE_MAX_BLOCKED_ADDRESSES]
    rows = [address_row(ip, e) for ip, e in ranked] + [address_row(ip, e) for ip, e in blocked]
    site_rows = sorted(
        (
            {
                "host": host, "requests": v[0], "errors": v[1], "server_errors": v[2],
                "blocked": v[3], "addresses": len(v[5]), "backend": v[6],
                **_server_times(v[7]),
                # Requests per bar of the timeline, for the row's own line.
                "spark": v[8],
            }
            for host, v in sites.items()
        ),
        key=lambda row: -row["requests"],
    )[:200]
    return {
        "ok": True,
        "now": now,
        "window": window,
        "covered_seconds": covered,
        "truncated": covered < window,
        "bucket_seconds": bucket,
        "totals": {
            "requests": total, "errors": errors_total, "server_errors": server_total,
            "blocked": blocked_total, "bytes": bytes_total, "addresses": len(addresses),
            "rate": round(total / max(1, covered), 2),
        },
        "timeline": [
            {"ok": ok_counts[i], "errors": error_counts[i], "blocked": blocked_counts[i]}
            for i in range(buckets)
        ],
        "statuses": {str(code): count for code, count in statuses.items()},
        "refusals": dict(refusals),
        "addresses": rows,
        "addresses_total": len(addresses),
        "sites": site_rows,
        "paths": [
            {"host": key[0], "path": key[1], "requests": v[0], "client_errors": v[1],
             "not_found": v[2], "server_errors": v[3], "blocked": v[4]}
            for key, v in heapq.nlargest(LIVE_MAX_PATHS, paths.items(), key=lambda item: item[1][0])
        ],
        "not_found": [
            {"host": key[0], "path": key[1], "not_found": v[2], "requests": v[0]}
            for key, v in heapq.nlargest(
                LIVE_MAX_NOT_FOUND,
                ((key, v) for key, v in paths.items() if v[2]),
                key=lambda item: item[1][2],
            )
        ],
        "agents": [
            {"agent": name, "requests": v[0], "blocked": v[1], "addresses": len(v[2])}
            for name, v in heapq.nlargest(LIVE_MAX_AGENTS, agents.items(), key=lambda item: item[1][0])
        ],
        "slow": [_live_event(r) for _ms, _order, r in sorted(slow, key=lambda item: -item[0])],
        "events": [
            {
                "ts": r[0], "ip": r[1], "host": r[3], "method": r[5], "path": r[4],
                "status": r[2], "duration_ms": r[8], "bytes": r[7], "backend": r[6],
                "term": r[9], "refusal": r[11], "ban_reason": r[10],
                "response_ms": r[12] if len(r) > 12 and r[12] >= 0 else None,
                "times": r[13] if len(r) > 13 else "",
                "request_id": r[14] if len(r) > 14 else "",
                "user_agent": r[15] if len(r) > 15 else "",
                "authenticated_user": r[L_AUTH_USER] if len(r) > L_AUTH_USER else "",
            }
            for r in reversed(events)
        ],
    }


def _memory_row(row_id: int, r: tuple) -> Dict[str, Any]:
    """A live record as the request log shows a stored row."""
    backend, _, server = r[L_BACKEND].partition("/")
    bad = r[L_PATH] == "<BADREQ>"
    return {
        "id": row_id, "ts": int(r[L_TS]), "request_id": r[L_REQUEST_ID] if len(r) > L_REQUEST_ID else "",
        "client": r[L_IP], "status": r[L_STATUS], "frontend": "", "backend": backend,
        "server": "" if server in ("", "<NOSRV>") else server, "method": r[L_METHOD],
        "host": r[L_HOST], "path": "" if bad else r[L_PATH], "bytes_out": r[L_BYTES],
        "duration_ms": r[L_DURATION], "bad_request": 1 if bad else 0,
        "response_ms": r[L_RESPONSE] if len(r) > L_RESPONSE and r[L_RESPONSE] >= 0 else -1,
        "times": r[L_TIMES] if len(r) > L_TIMES else "",
        "term": r[L_TERM], "ban_reason": r[L_REASON],
        "user_agent": r[L_AGENT] if len(r) > L_AGENT else "", "refusal": r[L_REFUSAL],
        "authenticated_user": r[L_AUTH_USER] if len(r) > L_AUTH_USER else "",
    }


class LiveBuffer:
    """The latest requests, in memory, bounded by count and by age -- or, once
    an operator gives it a budget, by memory (07.4)."""

    def __init__(self, max_records: int, max_seconds: int) -> None:
        # The profile from guardd.json, kept for when a budget is taken away.
        self.default_records = max(1, int(max_records))
        self.default_seconds = max(60, int(max_seconds))
        self.max_records = self.default_records
        self.max_seconds = self.default_seconds
        # 0: no budget, the count and the age above decide.
        self.max_bytes = 0
        # The estimated size of everything held, kept as records come and go.
        self._bytes = 0
        # Minute -> [requests, bytes] that arrived in it: the traffic a budget
        # is measured against. Arrivals, not what is held: a buffer cut down
        # by its budget still knows how fast requests come.
        self._arrivals: Dict[int, List[int]] = {}
        self._records: deque = deque()
        # The id of the first record held. Every record keeps its id however
        # many are added after it or dropped before it, which is what lets
        # the request log page through memory without repeating a row. Far
        # from zero, so what is read back after a restart (added before the
        # first) never reaches 0, which means "nothing further" to the page.
        self._base = 10 ** 12
        self._lock = threading.Lock()
        self._compute_lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        # Never, rather than zero: the monotonic clock counts from boot, and
        # on a machine up for less than two minutes zero is "just now".
        self._wanted_at = float("-inf")
        self.started = time.time()
        self.evicted_for_size = 0
        # (hour start, status) -> Counter of addresses, for the dashboard's
        # top 400/451 -- which used to read the whole day's log on every visit.
        self._hourly: Dict[Tuple[int, int], Counter] = {}
        # Observations, NOT browser sessions: a shared IP can have several users.
        # Bounded independently of the traffic buffer, never used for access control.
        self._identities: OrderedDict = OrderedDict()

    def identities(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = time.time() if now is None else now
        with self._lock:
            return {ip: [{"username": user, "last_seen": ts} for user, ts in users.items()
                         if now - 86400 <= ts <= now]
                    for ip, users in self._identities.items()
                    if any(now - 86400 <= ts <= now for ts in users.values())}

    def wanted(self) -> bool:
        """Someone has the live page open, so the log is followed closely."""
        return time.monotonic() - self._wanted_at < LIVE_WANTED_SECONDS

    def _count(self, records: List[tuple]) -> None:
        """Size, arrivals and the dashboard's hourly tops of new records."""
        arrivals = self._arrivals
        for record in records:
            user = record[L_AUTH_USER] if len(record) > L_AUTH_USER else ""
            if user:
                ip = record[L_IP]
                users = self._identities.setdefault(ip, {})
                users[user] = max(users.get(user, 0), record[L_TS])
                if len(users) > 8:
                    del users[min(users, key=users.get)]
                self._identities.move_to_end(ip)
                if len(self._identities) > 1024:
                    self._identities.popitem(last=False)
            size = live_record_bytes(record)
            self._bytes += size
            minute = int(record[L_TS]) // 60
            slot = arrivals.get(minute)
            if slot is None:
                arrivals[minute] = [1, size]
            else:
                slot[0] += 1
                slot[1] += size
            if record[L_STATUS] in (400, 451):
                hour = int(record[L_TS]) // 3600 * 3600
                counter = self._hourly.setdefault((hour, record[L_STATUS]), Counter())
                counter[record[L_IP]] += 1
                if len(counter) > LIVE_HOURLY_MAX_ADDRESSES:
                    # Outside the memory budget, so bounded on its own: a
                    # flood of different addresses keeps the busiest ones.
                    kept = counter.most_common(LIVE_HOURLY_MAX_ADDRESSES // 2)
                    counter.clear()
                    counter.update(dict(kept))
        if len(arrivals) > LIVE_RATE_SECONDS // 60 + 10:
            first = max(arrivals) - LIVE_RATE_SECONDS // 60
            for minute in [minute for minute in arrivals if minute < first]:
                del arrivals[minute]

    def _trim(self, newest: Optional[float]) -> int:
        """Drop the oldest until the count, the budget and the age allow;
        returns how many went for size. Under the lock."""
        records = self._records
        dropped = 0
        while records and (len(records) > self.max_records
                           or (self.max_bytes and self._bytes > self.max_bytes)):
            self._bytes -= live_record_bytes(records.popleft())
            dropped += 1
        self._base += dropped
        self.evicted_for_size += dropped
        if newest is not None:
            horizon = newest - self.max_seconds
            while records and records[0][L_TS] < horizon:
                self._bytes -= live_record_bytes(records.popleft())
                self._base += 1
        if not records:
            self._bytes = 0
        return dropped

    def extend(self, records: List[tuple]) -> None:
        if not records:
            return
        with self._lock:
            self._records.extend(records)
            self._count(records)
            self._trim(records[-1][L_TS])
            if len(self._hourly) > 60:
                oldest = int(records[-1][L_TS]) // 3600 * 3600 - 25 * 3600
                for key in [key for key in self._hourly if key[0] < oldest]:
                    del self._hourly[key]

    def refill(self, records: List[tuple], complete_since: float) -> None:
        """Put back what the log says happened before the daemon started.

        Older than anything already held, so added on the left; the bounds on
        size drop the oldest first, as always. From complete_since on, the
        buffer has every request again.
        """
        if not records:
            return
        with self._lock:
            self._records.extendleft(reversed(records))
            self._base -= len(records)
            self._count(records)
            self._trim(None)
            self.started = min(self.started, float(complete_since))
            self._cache.clear()

    def set_budget(self, max_bytes: int) -> int:
        """Bound the buffer by memory (max_bytes > 0), or give it back its
        profile from guardd.json (0). What no longer fits goes at once,
        oldest first; returns how many requests that was."""
        with self._lock:
            before = len(self._records)
            if max_bytes > 0:
                self.max_bytes = int(max_bytes)
                self.max_records = LIVE_BUDGET_MAX_RECORDS
                self.max_seconds = LIVE_BUDGET_MAX_SECONDS
            else:
                self.max_bytes = 0
                self.max_records = self.default_records
                self.max_seconds = self.default_seconds
            newest = self._records[-1][L_TS] if self._records else None
            self._trim(newest)
            self._cache.clear()
            return before - len(self._records)

    def _rate(self) -> Dict[str, int]:
        """Requests and bytes an hour, over the last hour of arrivals. Under
        the lock."""
        if not self._records:
            return {"records_per_hour": 0, "bytes_per_hour": 0, "measured_seconds": 0}
        newest = self._records[-1][L_TS]
        first = int(newest) // 60 - (LIVE_RATE_SECONDS // 60 - 1)
        count = size = 0
        for minute, (requests, nbytes) in self._arrivals.items():
            if minute >= first:
                count += requests
                size += nbytes
        # Only as far back as the buffer has every request: right after a
        # start without a refill, a few minutes are not an hour.
        since = max(first * 60.0, min(self.started, self._records[0][L_TS]))
        measured = max(60.0, newest - since)
        return {
            "records_per_hour": int(count * 3600 / measured),
            "bytes_per_hour": int(size * 3600 / measured),
            "measured_seconds": int(measured),
        }

    def search_requests(self, query: "RequestQuery", *, before: Any = 0, limit: int = 100,
                        count: bool = True) -> Dict[str, Any]:
        """The request log's search, answered from memory: the last hour or
        so, with the record switched off. Shaped like the store's answer."""
        limit = _clamp_int(limit, default=100, min_v=1, max_v=500)
        with self._lock:
            records = list(self._records)
            base = self._base
        top = len(records)
        before = _clamp_int(before, default=0, min_v=-(2 ** 62), max_v=2 ** 62)
        if before:
            top = max(0, min(top, before - base))
        rows: List[Tuple[int, tuple]] = []
        counted = 0
        for index in range(top - 1, -1, -1):
            record = records[index]
            if not query.matches(record):
                continue
            if len(rows) <= limit:
                rows.append((base + index, record))
            counted += 1
            if counted > REQUEST_COUNT_CAP or (not count and len(rows) > limit):
                break
        more = len(rows) > limit
        rows = rows[:limit]
        result: Dict[str, Any] = {
            "requests": [_memory_row(row_id, record) for row_id, record in rows],
            "next": rows[-1][0] if more else 0,
            "complete": True,
            "timed_out": False,
            "searched_to": 0,
            "source": "memory",
            "reaches_back_to": records[0][L_TS] if records else 0,
        }
        if count:
            result["total"] = min(counted, REQUEST_COUNT_CAP)
            result["total_exact"] = counted <= REQUEST_COUNT_CAP
        return result

    def summarize_requests(self, query: "RequestQuery") -> Dict[str, Any]:
        """The request log's summary, answered from memory."""
        with self._lock:
            records = list(self._records)
        # Memory holds the last hour or so: a day's bars would be a day of
        # nothing and an hour squeezed against the right edge.
        oldest = records[0][L_TS] if records else time.time()
        start = max(query.since, oldest) if query.since else oldest
        end = query.until or time.time()
        summary = RequestSummary(*summary_layout(start, end))
        # Newest first and within the store's time, as the store reads: with
        # a memory budget a day of requests can be held, and on a small ARM
        # board counting 200 000 of them one by one took nearly 4 seconds.
        # One that runs out of time says how far back it got.
        deadline = time.monotonic() + REQUEST_SUMMARY_SECONDS
        matches = query.matches
        matched: List[tuple] = []
        reached_to = 0
        for index in range(len(records) - 1, -1, -1):
            record = records[index]
            if matches(record):
                matched.append(record)
            if not index % 4096 and index and time.monotonic() > deadline:
                reached_to = int(record[L_TS])
                break
        # Counted in bulk: Counter.update over a generator is counted in C.
        first, step, last_bar = summary.first, summary.step, summary.bars - 1
        bars = Counter(
            (int(r[L_TS]) - first) // step * 4
            + (3 if r[L_REFUSAL] else 2 if r[L_STATUS] >= 500 else 1 if r[L_STATUS] >= 400 else 0)
            for r in matched
        )
        for key, count in bars.items():
            bar, kind = divmod(key, 4)
            summary.histogram[min(max(bar, 0), last_bar)][kind] += count
        summary.counted += len(matched)
        summary.statuses.update(r[L_STATUS] for r in matched)
        summary.clients.update(r[L_IP] for r in matched)
        summary.paths.update((r[L_HOST], r[L_PATH]) for r in matched)
        result = summary.read()
        result.update({"complete": not reached_to, "reached_to": reached_to, "source": "memory"})
        return result

    def status(self) -> Dict[str, Any]:
        with self._lock:
            oldest = self._records[0][L_TS] if self._records else None
            newest = self._records[-1][L_TS] if self._records else None
            return {"records": len(self._records), "max_records": self.max_records,
                    "max_seconds": self.max_seconds, "max_bytes": self.max_bytes,
                    "bytes": self._bytes, "oldest": oldest, "newest": newest,
                    "started": self.started, "rate": self._rate()}

    def snapshot(self, raw: Dict[str, Any], now: Optional[float] = None,
                 banned: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        self._wanted_at = time.monotonic()
        try:
            window = int(raw.get("window") or 60)
        except (TypeError, ValueError):
            raise ValueError("window must be a number of seconds") from None
        window = max(5, min(self.max_seconds, LIVE_WINDOW_MAX_SECONDS, window))
        filters = live_filters(raw)
        key = json.dumps([window, filters], sort_keys=True)
        if filters.get("banned"):
            filters["ips"] = frozenset(banned or ())
        # One computation at a time, however many pages are open; the same
        # question asked twice inside two seconds gets the same answer.
        with self._compute_lock:
            cached = self._cache.get(key)
            if cached and time.monotonic() - cached[0] < LIVE_CACHE_SECONDS:
                return cached[1]
            now = time.time() if now is None else now
            since = now - window
            with self._lock:
                selected = []
                for record in reversed(self._records):
                    if record[L_TS] < since:
                        break
                    selected.append(record)
                oldest = self._records[0][L_TS] if self._records else now
            selected.reverse()
            # Fewer seconds than asked for when the buffer does not reach back
            # that far: the daemon just started, or a flood filled it.
            if oldest <= since:
                covered = window
            elif self.evicted_for_size:
                covered = max(1, int(now - oldest))
            elif self.started > since:
                covered = max(1, int(now - self.started))
            else:
                covered = window  # simply no traffic before the oldest request
            result = live_aggregate(selected, now=now, window=window, filters=filters, covered=covered)
            if len(self._cache) > 32:
                self._cache.clear()
            self._cache[key] = (time.monotonic(), result)
            return result

    def attackers(self, now: Optional[float] = None, limit: int = 10) -> Dict[str, Any]:
        now = time.time() if now is None else now
        since = int(now) // 3600 * 3600 - 23 * 3600
        totals = {400: Counter(), 451: Counter()}
        with self._lock:
            for (hour, status), counter in self._hourly.items():
                if hour >= since:
                    totals[status].update(counter)
        return {
            "code_400": [{"ip": ip, "count": n} for ip, n in totals[400].most_common(limit)],
            "code_451": [{"ip": ip, "count": n} for ip, n in totals[451].most_common(limit)],
            "since": max(self.started, since),
            "diagnostic": {"source": "guardd"},
        }

ENFORCEMENT_BATCH = 200
ENFORCEMENT_SWEEP_RESERVE = 50
ENFORCEMENT_QUEUE_LIMIT = 4096
ENFORCEMENT_RECOVERY_EVENTS = 1000
ENFORCEMENT_CURSOR_KEY = "enforcement_scan_after"


class EnforcementQueue:
    """Bounded, coalesced findings; FIFO within each urgency class.

    A generation prevents an acknowledgement from losing a finding emitted
    while the previous one was being checked. Overflow is recoverable: the
    findings remain in SQLite and the separate sweep always gets a share.
    """

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self._urgent: OrderedDict = OrderedDict()
        self._ordinary: OrderedDict = OrderedDict()
        self._generation = 0
        self._lock = threading.Lock()
        self.overflows = 0

    def mark(self, ip: str, urgent: bool) -> None:
        with self._lock:
            self._generation += 1
            if ip in self._urgent:
                self._urgent[ip] = self._generation
                return
            if ip in self._ordinary:
                if urgent:
                    del self._ordinary[ip]
                else:
                    self._ordinary[ip] = self._generation
                    return
            elif len(self._urgent) + len(self._ordinary) >= self.limit:
                self.overflows += 1
                if not urgent or not self._ordinary:
                    return
                # Make room for a decisive finding; the sweep recovers the
                # displaced ordinary address, whose events are still stored.
                self._ordinary.popitem(last=False)
            target = self._urgent if urgent else self._ordinary
            target[ip] = self._generation

    def batch(self, limit: int) -> List[Tuple[str, int]]:
        with self._lock:
            # Ordinary findings keep a share even during a decisive flood.
            urgent = list(itertools.islice(self._urgent.items(), limit - limit // 4))
            ordinary = list(itertools.islice(self._ordinary.items(), limit - len(urgent)))
            if len(urgent) + len(ordinary) < limit:
                urgent = list(itertools.islice(self._urgent.items(), limit - len(ordinary)))
            return urgent + ordinary

    def acknowledge(self, ip: str, generation: int) -> None:
        with self._lock:
            for queue in (self._urgent, self._ordinary):
                if queue.get(ip) == generation:
                    del queue[ip]

    def has_urgent(self) -> bool:
        with self._lock:
            return bool(self._urgent)

    def urgent_batch(self, limit: int) -> List[Tuple[str, int]]:
        with self._lock:
            return list(itertools.islice(self._urgent.items(), max(1, int(limit))))

    def status(self) -> Dict[str, int]:
        with self._lock:
            return {"urgent": len(self._urgent), "ordinary": len(self._ordinary),
                    "limit": self.limit, "overflows": self.overflows}
