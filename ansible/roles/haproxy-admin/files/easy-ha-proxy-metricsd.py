#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""easy-ha-proxy-metricsd — historical HAProxy metrics collector.

The daemon polls the HAProxy Runtime API, keeps one in-memory accumulator per
proxy object and persists one row per object per minute. It never sits between
a client and a backend, and every failure mode is confined to this process:
HAProxy keeps serving traffic whether or not the collector is running.

Read access is exposed over a root-owned Unix socket shared with the `hadmin`
group, using the same HTTP-over-unix-socket protocol as haproxy-healthd.
"""

from __future__ import annotations

import contextlib
import grp
import json
import logging
import os
import pwd
import re
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

LOG = logging.getLogger("easy-ha-proxy-metricsd")


# The alert client lives beside this script in /usr/local/sbin, which is
# sys.path[0] for a daemon started by absolute path. It is optional on purpose:
# a gateway without the alert daemon still collects metrics.
try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - the daemon runs without it
    AlertClient = None  # type: ignore[assignment]


def _alert_client():
    """An alert client if one can be built, otherwise nothing."""
    if AlertClient is None:
        return None
    client = AlertClient(source="metricsd")
    return client if client.configured else None

SOCKET_PATH = os.environ.get(
    "METRICSD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-metricsd.sock"
)
SOCKET_GROUP = os.environ.get("METRICSD_SOCKET_GROUP", "hadmin")
CONFIG_PATH = os.environ.get(
    "METRICSD_CONFIG", "/opt/haproxy-admin/metricsd.json"
)
DATABASE_PATH = os.environ.get(
    "METRICSD_DATABASE", "/var/lib/easy-ha-proxy/metrics/metrics.db"
)

SCHEMA_VERSION = 2

# Runtime API replies are bounded so a wedged or hostile socket cannot make the
# collector allocate without limit.
RUNTIME_MAX_BYTES = 8 * 1024 * 1024
RUNTIME_TIMEOUT_SECONDS = 5

BUCKET_SECONDS = 60
HOUR_SECONDS = 3600

# How stale a persisted counter baseline may be and still be credited as a
# delta. It has to cover a systemd restart (RestartSec plus startup) or every
# restart would silently drop an interval of traffic; it has to stay small
# enough that the catch-up cannot inflate a single bucket beyond recognition.
BASELINE_MAX_GAP_SECONDS = 2 * BUCKET_SECONDS

# --- Storage safety -------------------------------------------------------
#
# Monitoring history is worth less than a working gateway. Every limit below
# exists so that a database growing faster than expected runs out of its own
# budget long before the filesystem runs out of space.

GIB = 1024 ** 3
MIB = 1024 ** 2

# `auto` database cap: a tenth of the filesystem, never more than this.
AUTO_MAX_DATABASE_BYTES = 5 * GIB
AUTO_MAX_DATABASE_FRACTION = 0.10
# `auto` free-space reserve: never promise less than the floor, never demand
# more than the ceiling, and otherwise scale with the filesystem.
AUTO_RESERVE_FLOOR_BYTES = 2 * GIB
AUTO_RESERVE_CEILING_BYTES = 10 * GIB
AUTO_RESERVE_FRACTION = 0.10

WARNING_DATABASE_FRACTION = 0.80
PRESSURE_DATABASE_FRACTION = 0.90
# Resuming exactly at the threshold would flap; require real headroom back.
# The absolute floor is itself capped by a slice of the filesystem, because on
# a small volume -- an SD card or a dedicated 64 MiB mount -- a fixed 512 MiB
# of extra headroom is more space than exists, and the collector could never
# resume at all.
RESUME_DATABASE_FRACTION = 0.95
RESUME_RESERVE_MARGIN_FLOOR = 512 * MIB
RESUME_RESERVE_MARGIN_FILESYSTEM_FRACTION = 0.05
RESUME_RESERVE_MARGIN_FRACTION = 0.10

DEFAULT_WAL_SOFT_LIMIT_BYTES = 64 * MIB

STATE_NORMAL = "NORMAL"
STATE_WARNING = "WARNING"
STATE_PRESSURE = "PRESSURE"
STATE_CRITICAL = "CRITICAL"

# Retention floors applied as disk pressure escalates. Level 0 is whatever the
# operator configured; each further level trims harder. Losing resolution is
# always preferable to losing all long-term visibility, so the minute tiers
# collapse before the hourly one does.
RETENTION_LADDER: Tuple[Dict[str, int], ...] = (
    {},
    {"minute_days": 3, "minute_server_hours": 6, "hour_days": 180},
    {"minute_days": 1, "minute_server_hours": 2, "hour_days": 90},
    {"minute_days": 1, "minute_server_hours": 1, "hour_days": 30},
)

# How long the storage trend samples are kept, and how flat 7 days of growth
# has to be before the database counts as steady rather than still growing.
STORAGE_SAMPLE_INTERVAL_SECONDS = 3600
STORAGE_SAMPLE_RETENTION_SECONDS = 30 * 86400
STABLE_GROWTH_FLOOR_BYTES = 8 * MIB
STABLE_GROWTH_FRACTION = 0.02

_SIZE_UNITS: Dict[str, int] = {
    "": 1,
    "b": 1,
    "k": 1000,
    "kb": 1000,
    "kib": 1024,
    "m": 1000 ** 2,
    "mb": 1000 ** 2,
    "mib": MIB,
    "g": 1000 ** 3,
    "gb": 1000 ** 3,
    "gib": GIB,
    "t": 1000 ** 4,
    "tb": 1000 ** 4,
    "tib": 1024 ** 4,
}
_SIZE_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-z]*)$")

# --- Read API -------------------------------------------------------------
#
# Everything a caller can select is an allow-list key, never a fragment of SQL.
# Table names come from the resolution chooser, column names from CHART_SERIES,
# and object selection is parameterised -- no request text reaches a query.

MAX_CHART_POINTS = 1500
MAX_RANGE_SECONDS = 365 * 86400
# A flapping server could otherwise return a transition per poll for the whole
# window; the timeline says it was truncated rather than shipping all of them.
MAX_TIMELINE_SPANS = 200

RANGES: Dict[str, int] = {
    "1h": 3600,
    "6h": 6 * 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "1y": 365 * 86400,
}
DEFAULT_RANGE = "24h"

# metric column -> how it aggregates across buckets and across objects.
_AGGREGATIONS: Dict[str, str] = {
    "requests": "sum",
    "sessions": "sum",
    "bytes_in": "sum",
    "bytes_out": "sum",
    "resp_2xx": "sum",
    "resp_3xx": "sum",
    "resp_4xx": "sum",
    "resp_5xx": "sum",
    "resp_other": "sum",
    "check_failures": "sum",
    "conn_cur_avg": "wavg",
    "conn_cur_max": "max",
    "queue_avg": "wavg",
    "queue_max": "max",
    "response_ms_avg": "wavg",
    "response_ms_max": "max",
    "total_ms_avg": "wavg",
    "connect_ms_avg": "wavg",
    "queue_ms_avg": "wavg",
}

CHART_SERIES: Dict[str, Tuple[str, ...]] = {
    "requests": ("requests",),
    "traffic": ("bytes_in", "bytes_out"),
    "responses": ("resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx"),
    "latency": ("response_ms_avg", "response_ms_max"),
    "connections": ("conn_cur_avg", "conn_cur_max"),
}

SUMMARY_COLUMNS: Tuple[str, ...] = (
    "requests",
    "sessions",
    "bytes_in",
    "bytes_out",
    "resp_2xx",
    "resp_3xx",
    "resp_4xx",
    "resp_5xx",
    "resp_other",
)


def _aggregate_sql(column: str) -> str:
    """SQL for one metric column. The column name is never caller-supplied."""

    how = _AGGREGATIONS[column]
    if how == "sum":
        return f"COALESCE(SUM({column}), 0)"
    if how == "max":
        return f"COALESCE(MAX({column}), 0)"
    # Sample-weighted, so a minute built from two polls does not count as much
    # as a complete one.
    return (
        f"CAST(COALESCE(SUM({column} * samples) / NULLIF(SUM(samples), 0), 0) "
        "AS INTEGER)"
    )


def resolve_range(value: Any) -> Tuple[str, int]:
    key = str(value or "").strip().lower()
    if key not in RANGES:
        key = DEFAULT_RANGE
    return key, min(RANGES[key], MAX_RANGE_SECONDS)


def resolve_window(query: Dict[str, List[str]]) -> Tuple[str, int, int]:
    """The period to report on: an explicit one if given, else a preset.

    The presets answer "how are things", which is most of the time. They
    cannot answer "what happened during the incident on Tuesday morning",
    and until now nothing could -- every window ended at this instant. An
    explicit since/until pair does, and is bounded the same way a preset is,
    so a mistyped year cannot ask for a scan of the whole table.
    """

    def number(name: str) -> Optional[int]:
        raw = (query.get(name) or [""])[0]
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    since = number("since")
    until = number("until")
    if since is not None and until is not None and until > since:
        span = min(until - since, MAX_RANGE_SECONDS)
        return "custom", until - span, until

    key, seconds = resolve_range((query.get("range") or [""])[0])
    now = _utc_now()
    return key, now - seconds, now


def choose_resolution(range_seconds: int) -> Tuple[str, int]:
    """Pick the stored table and the step to group by.

    Minute rows are only worth reading when the whole window fits inside the
    point budget; past that the hourly table answers the same question with a
    fraction of the work.
    """

    if range_seconds <= 86400:
        return "metric_1m", BUCKET_SECONDS
    hours = -(-range_seconds // HOUR_SECONDS)
    step_hours = max(1, -(-hours // MAX_CHART_POINTS))
    return "metric_1h", HOUR_SECONDS * step_hours

# `show stat` columns consumed by the collector. Everything is resolved by
# header name: HAProxy appends columns between releases and the CSV order is
# not a stable interface.
COUNTER_COLUMNS: Dict[str, str] = {
    "requests": "req_tot",
    "sessions": "stot",
    "bytes_in": "bin",
    "bytes_out": "bout",
    "resp_2xx": "hrsp_2xx",
    "resp_3xx": "hrsp_3xx",
    "resp_4xx": "hrsp_4xx",
    "resp_5xx": "hrsp_5xx",
    "check_failures": "chkfail",
}
# hrsp_1xx and hrsp_other are folded together: neither is interesting on its
# own and one column is cheaper than two in every stored row.
OTHER_RESPONSE_COLUMNS = ("hrsp_1xx", "hrsp_other")

GAUGE_COLUMNS: Dict[str, str] = {
    "conn_cur": "scur",
    "queue": "qcur",
    "queue_ms": "qtime",
    "connect_ms": "ctime",
    "response_ms": "rtime",
    "total_ms": "ttime",
}

# Persisted per-bucket columns, in table order.
METRIC_COLUMNS: Tuple[str, ...] = (
    "samples",
    "requests",
    "sessions",
    "bytes_in",
    "bytes_out",
    "resp_2xx",
    "resp_3xx",
    "resp_4xx",
    "resp_5xx",
    "resp_other",
    "check_failures",
    "conn_cur_avg",
    "conn_cur_max",
    "queue_avg",
    "queue_max",
    "queue_ms_avg",
    "connect_ms_avg",
    "response_ms_avg",
    "response_ms_max",
    "total_ms_avg",
)
# Columns summed when rolling minutes up into hours; the rest are averaged
# (weighted by sample count) or maxed, see _ROLLUP_MAX.
_ROLLUP_SUM = (
    "requests",
    "sessions",
    "bytes_in",
    "bytes_out",
    "resp_2xx",
    "resp_3xx",
    "resp_4xx",
    "resp_5xx",
    "resp_other",
    "check_failures",
)
_ROLLUP_MAX = ("conn_cur_max", "queue_max", "response_ms_max")

DEFAULT_EXCLUDE_EXACT = (
    "be_admin",
    "be_http_challenge",
    "be_tls_terminator",
    "be_maintenance",
)
DEFAULT_EXCLUDE_PREFIX = ("tbl_",)


def _utc_now() -> int:
    return int(time.time())


def _clamp_int(value: Any, *, default: int, min_v: int, max_v: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, parsed))


def parse_size(value: Any, *, default: Optional[int] = None) -> Optional[int]:
    """Parse a byte size. Returns None for `auto` / `unlimited` / nonsense.

    Accepts a plain number of bytes or a suffixed string ("5GiB", "512 MB").
    None is a meaningful answer, not a failure: it means "decide at runtime
    from the actual filesystem".
    """

    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value) if value > 0 else default
    text = str(value).strip().lower()
    if not text or text in ("auto", "unlimited", "none"):
        return default
    match = _SIZE_RE.match(text)
    if not match:
        return default
    amount, unit = match.groups()
    multiplier = _SIZE_UNITS.get(unit)
    if multiplier is None:
        return default
    parsed = int(float(amount) * multiplier)
    return parsed if parsed > 0 else default


def _to_int(value: Any) -> int:
    """Parse a Runtime API cell, treating blanks and junk as zero.

    HAProxy leaves a column empty when it does not apply to the row (a
    frontend has no queue, a backend has no check counter), so a missing value
    is normal input rather than an error.
    """

    if value is None:
        return 0
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return 0


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsConfig:
    enabled: bool = True
    poll_interval_seconds: int = 10
    haproxy_socket: str = "/run/haproxy/admin.sock"
    maintenance_interval_seconds: int = 300
    retention_one_minute_days: int = 7
    retention_one_minute_server_hours: int = 24
    retention_one_hour_days: int = 365
    exclude_exact: Tuple[str, ...] = DEFAULT_EXCLUDE_EXACT
    exclude_prefix: Tuple[str, ...] = DEFAULT_EXCLUDE_PREFIX
    # None means "derive from the filesystem the database actually sits on".
    max_database_bytes: Optional[int] = None
    reserved_free_bytes: Optional[int] = None
    auto_reduce_retention: bool = True
    wal_soft_limit_bytes: int = DEFAULT_WAL_SOFT_LIMIT_BYTES

    def excluded(self, proxy: str) -> bool:
        if not proxy:
            return True
        if proxy in self.exclude_exact:
            return True
        return any(proxy.startswith(prefix) for prefix in self.exclude_prefix)


def load_config(path: str) -> MetricsConfig:
    """Read metricsd.json, falling back to defaults for anything missing.

    An install that predates a new key, or a hand-edited file with a broken
    value, must still produce a running collector -- monitoring is never
    allowed to be the reason a host fails to come up.
    """

    raw: Dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            raw = loaded
        else:
            LOG.warning("Config %s is not an object; using defaults", path)
    except FileNotFoundError:
        LOG.info("Config %s not found; using defaults", path)
    except (OSError, ValueError) as exc:
        LOG.warning("Cannot read config %s (%s); using defaults", path, exc)

    retention = raw.get("retention")
    retention = retention if isinstance(retention, dict) else {}
    exclude = raw.get("exclude")
    exclude = exclude if isinstance(exclude, dict) else {}
    storage = raw.get("storage")
    storage = storage if isinstance(storage, dict) else {}

    def _string_tuple(value: Any, fallback: Tuple[str, ...]) -> Tuple[str, ...]:
        if not isinstance(value, list):
            return fallback
        items = tuple(str(item).strip() for item in value if str(item).strip())
        return items or fallback

    return MetricsConfig(
        enabled=bool(raw.get("enabled", True)),
        poll_interval_seconds=_clamp_int(
            raw.get("poll_interval_seconds"), default=10, min_v=5, max_v=60
        ),
        haproxy_socket=str(
            raw.get("haproxy_socket") or "/run/haproxy/admin.sock"
        ).strip(),
        maintenance_interval_seconds=_clamp_int(
            raw.get("maintenance_interval_seconds"),
            default=300,
            min_v=60,
            max_v=3600,
        ),
        retention_one_minute_days=_clamp_int(
            retention.get("one_minute_days"), default=7, min_v=1, max_v=90
        ),
        retention_one_minute_server_hours=_clamp_int(
            retention.get("one_minute_server_hours"),
            default=24,
            min_v=1,
            max_v=2160,
        ),
        retention_one_hour_days=_clamp_int(
            retention.get("one_hour_days"), default=365, min_v=1, max_v=3650
        ),
        exclude_exact=_string_tuple(
            exclude.get("exact"), DEFAULT_EXCLUDE_EXACT
        ),
        exclude_prefix=_string_tuple(
            exclude.get("prefix"), DEFAULT_EXCLUDE_PREFIX
        ),
        max_database_bytes=parse_size(storage.get("max_database_size")),
        reserved_free_bytes=parse_size(storage.get("reserved_free_space")),
        auto_reduce_retention=bool(storage.get("auto_reduce_retention", True)),
        wal_soft_limit_bytes=parse_size(
            storage.get("wal_soft_limit"), default=DEFAULT_WAL_SOFT_LIMIT_BYTES
        )
        or DEFAULT_WAL_SOFT_LIMIT_BYTES,
    )


# ---------------------------------------------------------------------------
# Runtime API
# ---------------------------------------------------------------------------


def runtime_command(socket_path: str, command: str) -> str:
    """Send one Runtime API command and return the raw reply."""

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(RUNTIME_TIMEOUT_SECONDS)
        sock.connect(socket_path)
        sock.sendall(f"{command}\n".encode("utf-8"))
        chunks: List[bytes] = []
        total = 0
        while total < RUNTIME_MAX_BYTES:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def parse_show_stat(payload: str) -> List[Dict[str, str]]:
    """Parse `show stat` CSV into dicts keyed by header name.

    Rows with fewer cells than the header are accepted -- HAProxy truncates
    trailing empties -- and any extra cells are ignored so a newer build that
    appends columns does not break the collector.
    """

    lines = [line for line in payload.splitlines() if line.strip()]
    if not lines:
        return []
    header_line = lines[0]
    if not header_line.startswith("#"):
        return []
    header = [cell.strip() for cell in header_line.lstrip("# ").split(",")]
    if "pxname" not in header or "svname" not in header:
        return []

    rows: List[Dict[str, str]] = []
    for line in lines[1:]:
        if line.startswith("#"):
            continue
        cells = line.split(",")
        row = {
            header[index]: cells[index]
            for index in range(min(len(header), len(cells)))
        }
        if row.get("pxname") and row.get("svname"):
            rows.append(row)
    return rows


def classify(row: Dict[str, str]) -> Optional[Tuple[str, str, str]]:
    """Return (kind, proxy, server) for a stat row, or None to skip it."""

    proxy = (row.get("pxname") or "").strip()
    svname = (row.get("svname") or "").strip()
    if not proxy or not svname:
        return None
    if svname == "FRONTEND":
        return ("frontend", proxy, "")
    if svname == "BACKEND":
        return ("backend", proxy, "")
    return ("server", proxy, svname)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS objects (
        id         INTEGER PRIMARY KEY,
        kind       TEXT    NOT NULL,
        proxy      TEXT    NOT NULL,
        server     TEXT    NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        UNIQUE (kind, proxy, server)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS counter_baseline (
        object_id  INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        metric     TEXT    NOT NULL,
        value      INTEGER NOT NULL,
        updated_ts INTEGER NOT NULL,
        PRIMARY KEY (object_id, metric)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS server_state_events (
        id             INTEGER PRIMARY KEY,
        ts             INTEGER NOT NULL,
        object_id      INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        previous_state TEXT    NOT NULL,
        state          TEXT    NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_state_events_ts ON server_state_events (ts)",
    """
    CREATE INDEX IF NOT EXISTS idx_state_events_object
        ON server_state_events (object_id, ts)
    """,
    """
    CREATE TABLE IF NOT EXISTS collector_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS storage_samples (
        ts          INTEGER PRIMARY KEY,
        total_bytes INTEGER NOT NULL
    ) WITHOUT ROWID
    """,
)

# Non-additive steps only. Tables and indexes above are created with IF NOT
# EXISTS on every start, so a purely additive release needs no entry here --
# it just advances the recorded version.
_MIGRATIONS: Dict[int, Tuple[str, ...]] = {}


# Where the operator's names for the uplinks are kept. HAProxy knows a
# server as srv1; which cable that is, only a person knows.
CHANNEL_LABELS_KEY = "channel_labels"
# Addresses the operator has put away. Not every backend host is an
# uplink -- a single application server is just a server -- and a list
# that cannot be tidied is one nobody reads.
CHANNEL_HIDDEN_KEY = "channel_hidden"


def _metric_table_sql(name: str) -> str:
    columns = ",\n        ".join(
        f"{column} INTEGER NOT NULL DEFAULT 0" for column in METRIC_COLUMNS
    )
    return f"""
    CREATE TABLE IF NOT EXISTS {name} (
        bucket_ts INTEGER NOT NULL,
        object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
        {columns},
        PRIMARY KEY (bucket_ts, object_id)
    ) WITHOUT ROWID
    """


@dataclass
class Bucket:
    """One object's accumulated samples for the minute being collected."""

    counters: Dict[str, int] = field(default_factory=dict)
    gauge_sums: Dict[str, int] = field(default_factory=dict)
    gauge_maxima: Dict[str, int] = field(default_factory=dict)
    samples: int = 0

    def add_counter(self, name: str, delta: int) -> None:
        if delta:
            self.counters[name] = self.counters.get(name, 0) + delta

    def add_gauge(self, name: str, value: int) -> None:
        self.gauge_sums[name] = self.gauge_sums.get(name, 0) + value
        current = self.gauge_maxima.get(name)
        if current is None or value > current:
            self.gauge_maxima[name] = value

    def row(self) -> Dict[str, int]:
        samples = max(1, self.samples)

        def average(name: str) -> int:
            return self.gauge_sums.get(name, 0) // samples

        return {
            "samples": self.samples,
            "requests": self.counters.get("requests", 0),
            "sessions": self.counters.get("sessions", 0),
            "bytes_in": self.counters.get("bytes_in", 0),
            "bytes_out": self.counters.get("bytes_out", 0),
            "resp_2xx": self.counters.get("resp_2xx", 0),
            "resp_3xx": self.counters.get("resp_3xx", 0),
            "resp_4xx": self.counters.get("resp_4xx", 0),
            "resp_5xx": self.counters.get("resp_5xx", 0),
            "resp_other": self.counters.get("resp_other", 0),
            "check_failures": self.counters.get("check_failures", 0),
            "conn_cur_avg": average("conn_cur"),
            "conn_cur_max": self.gauge_maxima.get("conn_cur", 0),
            "queue_avg": average("queue"),
            "queue_max": self.gauge_maxima.get("queue", 0),
            "queue_ms_avg": average("queue_ms"),
            "connect_ms_avg": average("connect_ms"),
            "response_ms_avg": average("response_ms"),
            "response_ms_max": self.gauge_maxima.get("response_ms", 0),
            "total_ms_avg": average("total_ms"),
        }


class MetricsDatabase:
    """SQLite storage. Every public method is safe to call from any thread."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self._conn = sqlite3.connect(
            str(self.path), timeout=10, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._configure(fresh)
        self._migrate()

    def _configure(self, fresh: bool) -> None:
        cursor = self._conn.cursor()
        # auto_vacuum only takes effect when set before the first table is
        # created; changing it later would need a full VACUUM, which is exactly
        # what a disk-pressure situation cannot afford.
        if fresh:
            cursor.execute("PRAGMA auto_vacuum=INCREMENTAL")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    def _migrate(self) -> None:
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            for statement in _SCHEMA_STATEMENTS:
                cursor.execute(statement)
            cursor.execute(_metric_table_sql("metric_1m"))
            cursor.execute(_metric_table_sql("metric_1h"))
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_metric_1m_object "
                "ON metric_1m (object_id, bucket_ts)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_metric_1h_object "
                "ON metric_1h (object_id, bucket_ts)"
            )
            row = cursor.execute(
                "SELECT version FROM schema_version"
            ).fetchone()
            if row is None:
                cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,),
                )
                cursor.close()
                return

            current = int(row["version"])
            if current > SCHEMA_VERSION:
                # A newer daemon has already migrated this file. Refusing here
                # is safer than silently writing rows an unknown schema does
                # not expect.
                raise RuntimeError(
                    f"metrics database schema v{current} is newer than "
                    f"the supported v{SCHEMA_VERSION}"
                )
            # Step forward one version at a time inside the open transaction,
            # so a failure leaves the recorded version where it was rather than
            # half-applied. Deleting the user's history is never a migration.
            while current < SCHEMA_VERSION:
                for statement in _MIGRATIONS.get(current + 1, ()):
                    cursor.execute(statement)
                current += 1
                LOG.info("Migrated metrics database to schema v%d", current)
            cursor.execute("UPDATE schema_version SET version = ?", (current,))
            cursor.close()

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()

    # -- objects ----------------------------------------------------------

    def object_id(self, kind: str, proxy: str, server: str, now: int) -> int:
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "INSERT INTO objects (kind, proxy, server, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (kind, proxy, server) DO UPDATE SET last_seen = ?",
                (kind, proxy, server, now, now, now),
            )
            row = cursor.execute(
                "SELECT id FROM objects WHERE kind = ? AND proxy = ? AND server = ?",
                (kind, proxy, server),
            ).fetchone()
            cursor.close()
        return int(row["id"])

    # -- baselines --------------------------------------------------------

    def load_baselines(self) -> Dict[Tuple[int, str], Tuple[int, int]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT object_id, metric, value, updated_ts FROM counter_baseline"
            ).fetchall()
        return {
            (int(row["object_id"]), str(row["metric"])): (
                int(row["value"]),
                int(row["updated_ts"]),
            )
            for row in rows
        }

    def store_baselines(
        self, baselines: Dict[Tuple[int, str], Tuple[int, int]]
    ) -> None:
        if not baselines:
            return
        payload = [
            (object_id, metric, value, updated_ts)
            for (object_id, metric), (value, updated_ts) in baselines.items()
        ]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO counter_baseline (object_id, metric, value, updated_ts) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT (object_id, metric) DO UPDATE SET "
                "value = excluded.value, updated_ts = excluded.updated_ts",
                payload,
            )

    # -- metrics ----------------------------------------------------------

    def write_buckets(
        self, bucket_ts: int, rows: Dict[int, Dict[str, int]]
    ) -> None:
        if not rows:
            return
        columns = ", ".join(("bucket_ts", "object_id") + METRIC_COLUMNS)
        placeholders = ", ".join("?" for _ in range(len(METRIC_COLUMNS) + 2))
        payload = [
            (bucket_ts, object_id)
            + tuple(row.get(column, 0) for column in METRIC_COLUMNS)
            for object_id, row in rows.items()
        ]
        with self._lock, self._conn:
            self._conn.executemany(
                f"INSERT OR REPLACE INTO metric_1m ({columns}) "
                f"VALUES ({placeholders})",
                payload,
            )

    def record_state_change(
        self, object_id: int, previous: str, state: str, now: int
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO server_state_events (ts, object_id, previous_state, state) "
                "VALUES (?, ?, ?, ?)",
                (now, object_id, previous, state),
            )

    def load_last_states(self) -> Dict[int, str]:
        """Return the most recent recorded state for every object.

        Without this a daemon restart would re-emit a transition for every
        server that is merely still up.
        """

        with self._lock:
            rows = self._conn.execute(
                "SELECT object_id, state FROM server_state_events "
                "WHERE id IN (SELECT MAX(id) FROM server_state_events GROUP BY object_id)"
            ).fetchall()
        return {int(row["object_id"]): str(row["state"]) for row in rows}

    # -- maintenance ------------------------------------------------------

    def get_state(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_state(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO collector_state (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def rollup_hours(self, before_ts: int) -> int:
        """Aggregate complete minutes into hourly rows.

        Only whole hours in the past are summarised, so an hour is never rolled
        up while minutes are still being added to it. A watermark keeps each
        pass proportional to the minutes that arrived since the last one rather
        than to the size of the whole table.
        """

        watermark = _to_int(self.get_state("rollup_watermark", "0"))
        if before_ts <= watermark:
            return 0

        # Counters add up; sample-weighted averages keep a partial minute from
        # counting as much as a complete one; peaks stay peaks.
        sums = ", ".join(f"SUM({column})" for column in _ROLLUP_SUM)
        averaged = (
            "conn_cur_avg",
            "queue_avg",
            "queue_ms_avg",
            "connect_ms_avg",
            "response_ms_avg",
            "total_ms_avg",
        )
        projection = [
            f"bucket_ts - (bucket_ts % {HOUR_SECONDS}) AS hour_ts",
            "object_id",
            "SUM(samples)",
            sums,
        ]
        target = ["bucket_ts", "object_id", "samples", *_ROLLUP_SUM]
        for column in averaged:
            projection.append(
                f"CAST(COALESCE(SUM({column} * samples) / NULLIF(SUM(samples), 0), 0) "
                "AS INTEGER)"
            )
            target.append(column)
        for column in _ROLLUP_MAX:
            projection.append(f"MAX({column})")
            target.append(column)

        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO metric_1h ({", ".join(target)})
                SELECT {", ".join(projection)}
                FROM metric_1m
                WHERE bucket_ts >= ? AND bucket_ts < ?
                GROUP BY hour_ts, object_id
                """,
                (watermark, before_ts),
            )
            written = max(0, cursor.rowcount or 0)
            cursor.execute(
                "INSERT INTO collector_state (key, value) VALUES ('rollup_watermark', ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (str(before_ts),),
            )
            cursor.close()
        return written

    def apply_retention(
        self,
        *,
        minute_cutoff: int,
        minute_server_cutoff: int,
        hour_cutoff: int,
    ) -> Dict[str, int]:
        """Delete rows past retention. Rollups must have run first."""

        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM metric_1m WHERE bucket_ts < ?", (minute_cutoff,)
            )
            deleted_minutes = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM metric_1m WHERE bucket_ts < ? AND object_id IN "
                "(SELECT id FROM objects WHERE kind = 'server')",
                (minute_server_cutoff,),
            )
            deleted_server_minutes = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM metric_1h WHERE bucket_ts < ?", (hour_cutoff,)
            )
            deleted_hours = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM server_state_events WHERE ts < ?", (hour_cutoff,)
            )
            deleted_events = cursor.rowcount or 0
            cursor.close()
        return {
            "minutes": deleted_minutes,
            "server_minutes": deleted_server_minutes,
            "hours": deleted_hours,
            "events": deleted_events,
        }

    def incremental_vacuum(self, pages: int = 256) -> None:
        """Reclaim freelist pages in small batches.

        Never a full VACUUM: that needs room for a second copy of the database,
        which is precisely what is missing when the disk is under pressure.
        """

        with self._lock, self._conn:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute(f"PRAGMA incremental_vacuum({int(pages)})")

    def checkpoint(self, *, truncate: bool = False) -> bool:
        """Fold the WAL back into the database file.

        TRUNCATE additionally returns the WAL's disk space, but it has to wait
        for readers; a busy socket request is a reason to try again later, not
        an error worth propagating.
        """

        mode = "TRUNCATE" if truncate else "PASSIVE"
        with self._lock:
            try:
                self._conn.execute(f"PRAGMA wal_checkpoint({mode})")
                return True
            except sqlite3.Error as exc:
                LOG.debug("wal_checkpoint(%s) failed: %s", mode, exc)
                return False

    # -- read API ---------------------------------------------------------

    @staticmethod
    def _scope(site: str, alias: str = "o") -> Tuple[str, List[Any]]:
        """Which objects a request covers, as a parameterised predicate.

        Without a site the answer is the frontends -- the edge totals. With
        one it is that single backend. Mixing the two would double-count every
        request, once on the way in and once on the way out.
        """

        if not site:
            return f"{alias}.kind = 'frontend'", []
        return f"{alias}.kind = 'backend' AND {alias}.proxy = ?", [site]

    def sites(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT proxy, first_seen, last_seen FROM objects "
                "WHERE kind = 'backend' ORDER BY proxy"
            ).fetchall()
        return [
            {
                "proxy": str(row["proxy"]),
                "first_seen": int(row["first_seen"]),
                "last_seen": int(row["last_seen"]),
            }
            for row in rows
        ]

    def series(
        self, *, chart: str, site: str, since: int, until: int
    ) -> Dict[str, Any]:
        columns = CHART_SERIES[chart]
        table, step = choose_resolution(max(1, until - since))
        predicate, parameters = self._scope(site)
        projection = ", ".join(_aggregate_sql(column) for column in columns)
        query = (
            f"SELECT (m.bucket_ts / {step}) * {step} AS slot, {projection} "
            f"FROM {table} m JOIN objects o ON o.id = m.object_id "
            f"WHERE {predicate} AND m.bucket_ts >= ? AND m.bucket_ts < ? "
            "GROUP BY slot ORDER BY slot"
        )
        with self._lock:
            rows = self._conn.execute(
                query, [*parameters, since, until]
            ).fetchall()

        points = [int(row["slot"]) for row in rows]
        values = {
            column: [int(row[index + 1]) for row in rows]
            for index, column in enumerate(columns)
        }
        return {
            "chart": chart,
            "resolution_seconds": step,
            "source": table,
            "points": points[:MAX_CHART_POINTS],
            "series": {
                name: value[:MAX_CHART_POINTS] for name, value in values.items()
            },
        }

    def totals(self, *, site: str, since: int, until: int) -> Dict[str, int]:
        table, _ = choose_resolution(max(1, until - since))
        predicate, parameters = self._scope(site)
        projection = ", ".join(_aggregate_sql(column) for column in SUMMARY_COLUMNS)
        with self._lock:
            row = self._conn.execute(
                f"SELECT {projection} FROM {table} m "
                f"JOIN objects o ON o.id = m.object_id "
                f"WHERE {predicate} AND m.bucket_ts >= ? AND m.bucket_ts < ?",
                [*parameters, since, until],
            ).fetchone()
        if row is None:
            return {column: 0 for column in SUMMARY_COLUMNS}
        return {
            column: int(row[index] or 0)
            for index, column in enumerate(SUMMARY_COLUMNS)
        }

    def server_totals(self, *, since: int, until: int) -> Dict[str, Any]:
        """Traffic per backend server over a range.

        Deliberately not scoped to one site: an uplink carries every site
        that points at it, and the whole question is how much went through
        each one.
        """

        table, _ = choose_resolution(max(1, until - since))
        columns = ("bytes_in", "bytes_out", "sessions")
        projection = ", ".join(_aggregate_sql(column) for column in columns)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT o.proxy, o.server, {projection} "
                f"FROM {table} m JOIN objects o ON o.id = m.object_id "
                "WHERE o.kind = 'server' "
                "AND m.bucket_ts >= ? AND m.bucket_ts < ? "
                "GROUP BY o.proxy, o.server ORDER BY o.proxy, o.server",
                [since, until],
            ).fetchall()
        return {
            "servers": [
                {
                    "proxy": str(row["proxy"]),
                    "server": str(row["server"]),
                    **{
                        column: int(row[index + 2] or 0)
                        for index, column in enumerate(columns)
                    },
                }
                for row in rows
            ]
        }

    def latest_gauges(self, *, site: str, until: int) -> Dict[str, int]:
        """Connection gauges from the newest bucket that actually has data."""

        predicate, parameters = self._scope(site)
        inner_predicate, inner_parameters = self._scope(site, alias="o2")
        projection = ", ".join(
            _aggregate_sql(column) for column in ("conn_cur_avg", "conn_cur_max")
        )
        with self._lock:
            row = self._conn.execute(
                f"SELECT {projection} FROM metric_1m m "
                "JOIN objects o ON o.id = m.object_id "
                f"WHERE {predicate} AND m.bucket_ts = ("
                "  SELECT MAX(m2.bucket_ts) FROM metric_1m m2 "
                "  JOIN objects o2 ON o2.id = m2.object_id "
                f"  WHERE {inner_predicate} AND m2.bucket_ts <= ?)",
                [*parameters, *inner_parameters, until],
            ).fetchone()
        if row is None:
            return {"conn_cur_avg": 0, "conn_cur_max": 0}
        return {"conn_cur_avg": int(row[0] or 0), "conn_cur_max": int(row[1] or 0)}

    def backend_health(self) -> Dict[str, Any]:
        """Latest recorded state per backend and per server."""

        with self._lock:
            rows = self._conn.execute(
                "SELECT o.kind, o.proxy, o.server, e.state, e.ts "
                "FROM server_state_events e JOIN objects o ON o.id = e.object_id "
                "WHERE e.id IN (SELECT MAX(id) FROM server_state_events "
                "GROUP BY object_id) ORDER BY o.proxy, o.server"
            ).fetchall()
        backends: List[Dict[str, Any]] = []
        servers: List[Dict[str, Any]] = []
        for row in rows:
            entry = {
                "proxy": str(row["proxy"]),
                "server": str(row["server"]),
                "state": str(row["state"]),
                "since": int(row["ts"]),
            }
            (backends if row["kind"] == "backend" else servers).append(entry)
        return {
            "backends": backends,
            "servers": servers,
            "backends_up": sum(1 for item in backends if item["state"] == "UP"),
            "backends_total": len(backends),
            "servers_up": sum(1 for item in servers if item["state"] == "UP"),
            "servers_total": len(servers),
        }

    @staticmethod
    def _state_scope(site: str, alias: str = "o") -> Tuple[str, List[Any]]:
        """State history exists for backends and servers, never for frontends."""

        if not site:
            return f"{alias}.kind IN ('backend', 'server')", []
        return (
            f"{alias}.kind IN ('backend', 'server') AND {alias}.proxy = ?",
            [site],
        )

    def state_timeline(
        self, *, site: str, since: int, until: int
    ) -> Dict[str, Any]:
        """Availability spans per backend and server over a window.

        Transitions are stored as events, so the state at the start of the
        window comes from the last event before it -- a server that has been
        up for a month still has to render as up for the whole period.
        """

        predicate, parameters = self._state_scope(site)
        with self._lock:
            objects = self._conn.execute(
                "SELECT o.id, o.kind, o.proxy, o.server FROM objects o "
                f"WHERE {predicate} ORDER BY o.proxy, o.kind DESC, o.server",
                parameters,
            ).fetchall()
            if not objects:
                return {"objects": [], "truncated": False}

            identifiers = [int(row["id"]) for row in objects]
            placeholders = ", ".join("?" for _ in identifiers)
            initial = {
                int(row["object_id"]): str(row["state"])
                for row in self._conn.execute(
                    "SELECT object_id, state FROM server_state_events WHERE id IN ("
                    "  SELECT MAX(id) FROM server_state_events "
                    f"  WHERE ts <= ? AND object_id IN ({placeholders}) "
                    "  GROUP BY object_id)",
                    [since, *identifiers],
                ).fetchall()
            }
            events = self._conn.execute(
                "SELECT object_id, ts, state FROM server_state_events "
                f"WHERE object_id IN ({placeholders}) AND ts > ? AND ts <= ? "
                "ORDER BY object_id, id",
                [*identifiers, since, until],
            ).fetchall()

        by_object: Dict[int, List[Tuple[int, str]]] = {}
        for row in events:
            by_object.setdefault(int(row["object_id"]), []).append(
                (int(row["ts"]), str(row["state"]))
            )

        window = max(1, until - since)
        truncated = False
        result: List[Dict[str, Any]] = []
        for row in objects:
            object_id = int(row["id"])
            changes = by_object.get(object_id, [])
            state = initial.get(object_id)
            if state is None and not changes:
                # Never observed in or before the window: nothing to draw.
                continue

            spans: List[Dict[str, Any]] = []
            cursor = since
            current = state or changes[0][1]

            def close(end: int, state_name: str) -> None:
                if end <= cursor:
                    return
                # A restart re-observes the state it left behind, which would
                # otherwise draw as two touching bars of the same colour.
                if spans and spans[-1]["state"] == state_name:
                    spans[-1]["end"] = end
                else:
                    spans.append(
                        {"state": state_name, "start": cursor, "end": end}
                    )

            for ts, next_state in changes[:MAX_TIMELINE_SPANS]:
                close(ts, current)
                cursor = max(cursor, ts)
                current = next_state
            if len(changes) > MAX_TIMELINE_SPANS:
                truncated = True
            close(until, current)

            downtime = sum(
                span["end"] - span["start"]
                for span in spans
                if span["state"] != "UP"
            )
            result.append(
                {
                    "kind": str(row["kind"]),
                    "proxy": str(row["proxy"]),
                    "server": str(row["server"]),
                    "current_state": current,
                    "transitions": len(changes),
                    "downtime_seconds": downtime,
                    "availability": round(
                        max(0.0, (window - downtime) / window), 5
                    ),
                    "spans": spans,
                }
            )
        return {"objects": result, "truncated": truncated}

    def record_storage_sample(self, ts: int, total_bytes: int) -> None:
        """Keep one coarse size sample per hour for trend reporting."""

        slot = ts - (ts % STORAGE_SAMPLE_INTERVAL_SECONDS)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO storage_samples (ts, total_bytes) VALUES (?, ?) "
                "ON CONFLICT (ts) DO UPDATE SET total_bytes = excluded.total_bytes",
                (slot, total_bytes),
            )
            self._conn.execute(
                "DELETE FROM storage_samples WHERE ts < ?",
                (ts - STORAGE_SAMPLE_RETENTION_SECONDS,),
            )

    def storage_growth(self, now: int, current_bytes: int) -> Dict[str, Any]:
        """Growth over the last day and week, plus a coarse trend label."""

        def since(seconds: int) -> Optional[int]:
            with self._lock:
                row = self._conn.execute(
                    "SELECT total_bytes FROM storage_samples WHERE ts <= ? "
                    "ORDER BY ts DESC LIMIT 1",
                    (now - seconds,),
                ).fetchone()
            return None if row is None else current_bytes - int(row["total_bytes"])

        day = since(86400)
        week = since(7 * 86400)
        # "Stable" is a claim about the past week only. Anything narrower is
        # noise, and a forecast dressed up as a guarantee helps nobody.
        if week is None:
            trend = "unknown"
        elif abs(week) <= max(
            STABLE_GROWTH_FLOOR_BYTES, int(current_bytes * STABLE_GROWTH_FRACTION)
        ):
            trend = "stable"
        elif week > 0:
            trend = "growing"
        else:
            trend = "shrinking"
        return {
            "last_24h_bytes": day,
            "last_7d_bytes": week,
            "trend": trend,
        }

    # -- introspection ----------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            cursor = self._conn.cursor()
            version_row = cursor.execute(
                "SELECT version FROM schema_version"
            ).fetchone()
            objects = cursor.execute(
                "SELECT COUNT(*) AS value FROM objects"
            ).fetchone()
            minutes = cursor.execute(
                "SELECT COUNT(*) AS value, MIN(bucket_ts) AS oldest, "
                "MAX(bucket_ts) AS newest FROM metric_1m"
            ).fetchone()
            hours = cursor.execute(
                "SELECT COUNT(*) AS value, MIN(bucket_ts) AS oldest, "
                "MAX(bucket_ts) AS newest FROM metric_1h"
            ).fetchone()
            events = cursor.execute(
                "SELECT COUNT(*) AS value FROM server_state_events"
            ).fetchone()
            freelist = cursor.execute("PRAGMA freelist_count").fetchone()
            cursor.close()
        return {
            "schema_version": int(version_row["version"]) if version_row else 0,
            "objects": int(objects["value"]),
            "metric_1m": {
                "rows": int(minutes["value"]),
                "oldest_bucket_ts": minutes["oldest"],
                "newest_bucket_ts": minutes["newest"],
            },
            "metric_1h": {
                "rows": int(hours["value"]),
                "oldest_bucket_ts": hours["oldest"],
                "newest_bucket_ts": hours["newest"],
            },
            "state_events": int(events["value"]),
            "freelist_pages": int(freelist[0]) if freelist else 0,
        }

    def storage(self) -> Dict[str, Any]:
        def size(path: Path) -> int:
            try:
                return path.stat().st_size
            except OSError:
                return 0

        database = size(self.path)
        wal = size(self.path.with_name(self.path.name + "-wal"))
        shm = size(self.path.with_name(self.path.name + "-shm"))
        try:
            usage = os.statvfs(self.path.parent)
            filesystem = {
                "total_bytes": usage.f_blocks * usage.f_frsize,
                "free_bytes": usage.f_bavail * usage.f_frsize,
            }
        except OSError:
            filesystem = {"total_bytes": 0, "free_bytes": 0}
        return {
            "database_bytes": database,
            "wal_bytes": wal,
            "shm_bytes": shm,
            "total_bytes": database + wal + shm,
            "filesystem": filesystem,
        }


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StorageStatus:
    """One measurement of where monitoring storage stands."""

    state: str
    reason: str
    total_bytes: int
    database_bytes: int
    wal_bytes: int
    shm_bytes: int
    filesystem_total_bytes: int
    filesystem_free_bytes: int
    max_database_bytes: int
    reserved_free_bytes: int

    @property
    def database_fraction(self) -> float:
        if self.max_database_bytes <= 0:
            return 0.0
        return self.total_bytes / self.max_database_bytes

    def as_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "database_bytes": self.database_bytes,
            "wal_bytes": self.wal_bytes,
            "shm_bytes": self.shm_bytes,
            "total_bytes": self.total_bytes,
            "max_database_bytes": self.max_database_bytes,
            "database_used_fraction": round(self.database_fraction, 4),
            "reserved_free_bytes": self.reserved_free_bytes,
            "filesystem": {
                "total_bytes": self.filesystem_total_bytes,
                "free_bytes": self.filesystem_free_bytes,
            },
        }


class StorageGuard:
    """Keeps monitoring inside its own budget.

    The invariant this class exists to hold: however wrong the retention
    estimates turn out to be, historical monitoring must never be the reason
    the filesystem fills up. Losing history is acceptable; losing the gateway
    is not. Every decision therefore resolves in favour of the disk.
    """

    def __init__(
        self,
        config: MetricsConfig,
        database: MetricsDatabase,
        alerts: Optional["AlertClient"] = None,
    ) -> None:
        self.config = config
        self.database = database
        # Storage pressure used to be a journal line only, which meant nobody
        # learned that history had stopped being recorded until they opened
        # the page and found a gap.
        self.alerts = alerts
        self.state = STATE_NORMAL
        self.writes_paused = False
        self.pressure_level = 0
        self.last_cleanup_ts: Optional[int] = None
        self.last_checkpoint_ts: Optional[int] = None
        self.last_pause_ts: Optional[int] = None
        self.last_resume_ts: Optional[int] = None
        self._last_logged_state: Optional[str] = None

    # -- limits -----------------------------------------------------------

    def resolve_limits(self, filesystem_total: int) -> Tuple[int, int]:
        """Turn the configured caps into concrete byte counts.

        `auto` scales with the filesystem the database actually lives on, which
        is not necessarily the root filesystem: operators do mount a dedicated
        volume for history.
        """

        maximum = self.config.max_database_bytes
        if maximum is None:
            maximum = min(
                AUTO_MAX_DATABASE_BYTES,
                int(filesystem_total * AUTO_MAX_DATABASE_FRACTION),
            )
        reserve = self.config.reserved_free_bytes
        if reserve is None:
            reserve = max(
                AUTO_RESERVE_FLOOR_BYTES,
                min(
                    int(filesystem_total * AUTO_RESERVE_FRACTION),
                    AUTO_RESERVE_CEILING_BYTES,
                ),
            )
        return max(0, int(maximum)), max(0, int(reserve))

    def measure(self) -> StorageStatus:
        """Size everything monitoring owns and classify the result."""

        storage = self.database.storage()
        filesystem = storage["filesystem"]
        total_fs = int(filesystem["total_bytes"])
        free_fs = int(filesystem["free_bytes"])
        maximum, reserve = self.resolve_limits(total_fs)
        # WAL and SHM sit next to the database and consume the same filesystem,
        # so a limit that ignored them would not be a limit at all.
        total = int(storage["total_bytes"])

        state = STATE_NORMAL
        reason = "within limits"
        if maximum > 0 and total >= maximum:
            state, reason = STATE_CRITICAL, "database reached its size limit"
        elif reserve > 0 and free_fs <= reserve:
            state, reason = STATE_CRITICAL, "filesystem hit the free-space reserve"
        elif maximum > 0 and total >= maximum * PRESSURE_DATABASE_FRACTION:
            state, reason = STATE_PRESSURE, "database near its size limit"
        elif reserve > 0 and free_fs < reserve * 1.25:
            state, reason = STATE_PRESSURE, "filesystem near the free-space reserve"
        elif maximum > 0 and total >= maximum * WARNING_DATABASE_FRACTION:
            state, reason = STATE_WARNING, "database above 80% of its size limit"
        elif reserve > 0 and free_fs < reserve * 2:
            state, reason = STATE_WARNING, "filesystem free space below twice the reserve"

        return StorageStatus(
            state=state,
            reason=reason,
            total_bytes=total,
            database_bytes=int(storage["database_bytes"]),
            wal_bytes=int(storage["wal_bytes"]),
            shm_bytes=int(storage["shm_bytes"]),
            filesystem_total_bytes=total_fs,
            filesystem_free_bytes=free_fs,
            max_database_bytes=maximum,
            reserved_free_bytes=reserve,
        )

    # -- retention --------------------------------------------------------

    def retention_for_level(self, level: int) -> Dict[str, int]:
        """Configured retention, trimmed by the ladder at higher levels."""

        level = max(0, min(level, len(RETENTION_LADDER) - 1))
        floors = RETENTION_LADDER[level]
        return {
            "minute_days": min(
                self.config.retention_one_minute_days,
                floors.get("minute_days", self.config.retention_one_minute_days),
            ),
            "minute_server_hours": min(
                self.config.retention_one_minute_server_hours,
                floors.get(
                    "minute_server_hours",
                    self.config.retention_one_minute_server_hours,
                ),
            ),
            "hour_days": min(
                self.config.retention_one_hour_days,
                floors.get("hour_days", self.config.retention_one_hour_days),
            ),
        }

    def _trim(self, now: int, level: int) -> Dict[str, int]:
        retention = self.retention_for_level(level)
        deleted = self.database.apply_retention(
            minute_cutoff=now - retention["minute_days"] * 86400,
            minute_server_cutoff=now - retention["minute_server_hours"] * 3600,
            hour_cutoff=now - retention["hour_days"] * 86400,
        )
        if any(deleted.values()):
            self.last_cleanup_ts = now
            # Deleted pages only return to the filesystem after an incremental
            # pass; a full VACUUM would need room for a second copy of the
            # database, which is exactly what is missing here.
            self.database.incremental_vacuum(pages=4096)
        return deleted

    # -- WAL --------------------------------------------------------------

    def manage_wal(self, status: StorageStatus, now: int) -> bool:
        """Keep the write-ahead log from becoming the thing that fills the disk."""

        if status.wal_bytes < self.config.wal_soft_limit_bytes:
            return False
        truncated = self.database.checkpoint(truncate=True)
        if not truncated:
            self.database.checkpoint()
        self.last_checkpoint_ts = now
        LOG.info(
            "WAL reached %d bytes (soft limit %d); checkpointed",
            status.wal_bytes,
            self.config.wal_soft_limit_bytes,
        )
        return True

    # -- decisions --------------------------------------------------------

    def resume_margin(self, status: StorageStatus) -> int:
        """Extra free space required on top of the reserve before resuming."""

        floor = RESUME_RESERVE_MARGIN_FLOOR
        if status.filesystem_total_bytes > 0:
            floor = min(
                floor,
                int(
                    status.filesystem_total_bytes
                    * RESUME_RESERVE_MARGIN_FILESYSTEM_FRACTION
                ),
            )
        return max(
            floor, int(status.reserved_free_bytes * RESUME_RESERVE_MARGIN_FRACTION)
        )

    def _may_resume(self, status: StorageStatus) -> bool:
        margin = self.resume_margin(status)
        space_recovered = (
            status.reserved_free_bytes <= 0
            or status.filesystem_free_bytes > status.reserved_free_bytes + margin
        )
        budget_recovered = (
            status.max_database_bytes <= 0
            or status.total_bytes < status.max_database_bytes * RESUME_DATABASE_FRACTION
        )
        return space_recovered and budget_recovered

    def enforce(self, now: int) -> Dict[str, Any]:
        """Measure, clean up as far as needed, and decide whether to keep writing."""

        status = self.measure()
        actions: List[str] = []

        if self.manage_wal(status, now):
            actions.append("wal_checkpoint")
            status = self.measure()

        if status.state in (STATE_PRESSURE, STATE_CRITICAL) and (
            self.config.auto_reduce_retention
        ):
            # Escalate one rung at a time and re-measure, so a host only loses
            # the resolution it actually has to.
            for level in range(1, len(RETENTION_LADDER)):
                self.database.rollup_hours(now - (now % HOUR_SECONDS))
                deleted = self._trim(now, level)
                actions.append(f"trim_level_{level}")
                status = self.measure()
                LOG.info(
                    "Storage pressure: trimmed at level %d (%s), now %s",
                    level,
                    json.dumps(deleted),
                    status.state,
                )
                if status.state in (STATE_NORMAL, STATE_WARNING):
                    break
            self.pressure_level = min(
                len(RETENTION_LADDER) - 1, max(self.pressure_level, 1)
            )
        elif status.state == STATE_NORMAL:
            self.pressure_level = 0

        if status.state == STATE_CRITICAL:
            if not self.writes_paused:
                self.writes_paused = True
                self.last_pause_ts = now
                LOG.warning(
                    "Historical monitoring paused: %s. HAProxy traffic is not "
                    "affected.",
                    status.reason,
                )
                actions.append("paused")
        elif self.writes_paused and self._may_resume(status):
            self.writes_paused = False
            self.last_resume_ts = now
            LOG.info("Historical monitoring resumed: %s", status.reason)
            actions.append("resumed")

        if status.state != self._last_logged_state:
            LOG.info("Storage state %s -> %s (%s)",
                     self._last_logged_state or "unknown", status.state, status.reason)
            self._last_logged_state = status.state
        self.state = status.state

        self._report_to_alerts(status)

        with contextlib.suppress(sqlite3.Error):
            self.database.record_storage_sample(now, status.total_bytes)

        return {"status": status, "actions": actions}

    def _report_to_alerts(self, status: "StorageStatus") -> None:
        """Tell the alert engine what the disk looks like right now.

        Both conditions are levels: they stay true until the disk recovers, so
        the engine can hold the notification, repeat it, and announce recovery
        on its own terms. Reporting is best effort by contract — a stopped
        alert daemon must not cost a metrics sample.
        """
        if self.alerts is None:
            return
        with contextlib.suppress(Exception):
            self.alerts.observe(
                "monitoring.storage",
                "metrics",
                active=status.state in (STATE_PRESSURE, STATE_CRITICAL),
                severity=(
                    "critical" if status.state == STATE_CRITICAL else "warning"
                ),
                summary=f"Monitoring storage is {status.state}",
                detail=status.reason,
            )
            self.alerts.observe(
                "monitoring.paused",
                "metrics",
                active=self.writes_paused,
                summary=(
                    "Historical monitoring is paused; HAProxy traffic is not "
                    "affected"
                ),
                detail=status.reason,
            )

    def report(self, now: int) -> Dict[str, Any]:
        status = self.measure()
        payload = status.as_dict()
        payload["writes_paused"] = self.writes_paused
        payload["pressure_level"] = self.pressure_level
        payload["effective_retention"] = self.retention_for_level(self.pressure_level)
        payload["configured_retention"] = self.retention_for_level(0)
        payload["wal_soft_limit_bytes"] = self.config.wal_soft_limit_bytes
        payload["auto_reduce_retention"] = self.config.auto_reduce_retention
        payload["last_cleanup_ts"] = self.last_cleanup_ts
        payload["last_checkpoint_ts"] = self.last_checkpoint_ts
        payload["last_pause_ts"] = self.last_pause_ts
        payload["last_resume_ts"] = self.last_resume_ts
        with contextlib.suppress(sqlite3.Error):
            payload["growth"] = self.database.storage_growth(
                now, status.total_bytes
            )
        return payload


class Collector:
    """Polls HAProxy, accumulates a minute, then writes it out."""

    def __init__(
        self,
        config: MetricsConfig,
        database: MetricsDatabase,
        storage: Optional[StorageGuard] = None,
    ) -> None:
        self.config = config
        self.database = database
        self.storage = storage or StorageGuard(config, database)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()

        self._object_ids: Dict[Tuple[str, str, str], int] = {}
        self._baselines: Dict[Tuple[int, str], Tuple[int, int]] = {}
        self._buckets: Dict[int, Bucket] = {}
        self._bucket_ts: Optional[int] = None
        self._last_states: Dict[int, str] = {}

        self.last_poll_ts: Optional[int] = None
        self.last_flush_ts: Optional[int] = None
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0
        self.polls_total = 0
        self.buckets_written = 0
        self.buckets_dropped = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._baselines = self.database.load_baselines()
        self._last_states = self.database.load_last_states()
        self._thread = threading.Thread(
            target=self._run, name="metricsd-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=10)

    def _run(self) -> None:
        interval = self.config.poll_interval_seconds
        next_maintenance = time.monotonic() + self.config.maintenance_interval_seconds
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.poll()
            except Exception as exc:  # pylint: disable=broad-except
                # A failing collector must never take the process down: the
                # next tick simply tries again.
                self.consecutive_failures += 1
                self.last_error = str(exc)
                if self.consecutive_failures in (1, 10) or (
                    self.consecutive_failures % 60 == 0
                ):
                    LOG.warning(
                        "Poll failed (%d in a row): %s",
                        self.consecutive_failures,
                        exc,
                    )

            if time.monotonic() >= next_maintenance:
                try:
                    self.run_maintenance()
                except Exception:  # pylint: disable=broad-except
                    LOG.exception("Maintenance pass failed")
                next_maintenance = (
                    time.monotonic() + self.config.maintenance_interval_seconds
                )

            # A slow poll shortens the wait rather than shifting the schedule,
            # so buckets stay aligned to wall-clock minutes.
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.5, interval - elapsed))

        with contextlib.suppress(Exception):
            self.flush(force=True)

    # -- collection -------------------------------------------------------

    def poll(self) -> int:
        payload = runtime_command(self.config.haproxy_socket, "show stat")
        rows = parse_show_stat(payload)
        now = _utc_now()
        if not rows:
            raise RuntimeError("show stat returned no usable rows")

        bucket_ts = now - (now % BUCKET_SECONDS)
        with self._state_lock:
            if self._bucket_ts is None:
                self._bucket_ts = bucket_ts
            elif bucket_ts != self._bucket_ts:
                self._flush_locked(self._bucket_ts)
                self._bucket_ts = bucket_ts

            observed = 0
            for row in rows:
                identity = classify(row)
                if identity is None:
                    continue
                kind, proxy, server = identity
                if self.config.excluded(proxy):
                    continue
                self._observe(kind, proxy, server, row, now)
                observed += 1

        self.polls_total += 1
        self.last_poll_ts = now
        self.consecutive_failures = 0
        self.last_error = None
        return observed

    def _observe(
        self,
        kind: str,
        proxy: str,
        server: str,
        row: Dict[str, str],
        now: int,
    ) -> None:
        key = (kind, proxy, server)
        object_id = self._object_ids.get(key)
        if object_id is None:
            # Registering an object stays allowed while writes are paused. The
            # table is bounded by the number of configured proxies, not by
            # time, so it cannot be what fills a disk -- and skipping it would
            # make a site added during the pause invisible until a restart.
            object_id = self.database.object_id(kind, proxy, server, now)
            self._object_ids[key] = object_id

        bucket = self._buckets.get(object_id)
        if bucket is None:
            bucket = Bucket()
            self._buckets[object_id] = bucket
        bucket.samples += 1

        for name, column in COUNTER_COLUMNS.items():
            bucket.add_counter(
                name, self._delta(object_id, name, _to_int(row.get(column)), now)
            )
        other = sum(_to_int(row.get(column)) for column in OTHER_RESPONSE_COLUMNS)
        bucket.add_counter(
            "resp_other", self._delta(object_id, "resp_other", other, now)
        )

        for name, column in GAUGE_COLUMNS.items():
            bucket.add_gauge(name, _to_int(row.get(column)))

        if kind in ("server", "backend"):
            self._track_state(object_id, (row.get("status") or "").strip(), now)

    def _delta(self, object_id: int, metric: str, current: int, now: int) -> int:
        """Turn an absolute counter into a per-interval delta.

        Three cases produce no delta rather than a bogus one: the first sample
        of a fresh object, a counter that went backwards (HAProxy restarted),
        and a stale baseline (this daemon was down long enough that the gap
        cannot be attributed to the current minute).
        """

        key = (object_id, metric)
        previous = self._baselines.get(key)
        self._baselines[key] = (current, now)
        if previous is None:
            return 0
        last_value, last_ts = previous
        if current < last_value:
            return 0
        max_gap = max(
            BASELINE_MAX_GAP_SECONDS, 3 * self.config.poll_interval_seconds
        )
        if now - last_ts > max_gap:
            return 0
        return current - last_value

    def _track_state(self, object_id: int, status: str, now: int) -> None:
        if not status:
            return
        # HAProxy decorates transitional states ("UP 1/3", "DOWN 2/3"); the
        # base word is what a timeline should show.
        state = status.split(" ", 1)[0].strip().upper()
        if not state:
            return
        previous = self._last_states.get(object_id)
        if previous == state:
            return
        if self.storage.writes_paused:
            # Leave the remembered state alone: once writing resumes, the
            # transition still gets recorded instead of being lost silently.
            return
        self._last_states[object_id] = state
        self.database.record_state_change(object_id, previous or "", state, now)

    # -- persistence ------------------------------------------------------

    def flush(self, *, force: bool = False) -> int:
        with self._state_lock:
            if self._bucket_ts is None:
                return 0
            now = _utc_now()
            current_bucket = now - (now % BUCKET_SECONDS)
            if not force and current_bucket == self._bucket_ts:
                return 0
            written = self._flush_locked(self._bucket_ts)
            self._bucket_ts = current_bucket
            return written

    def _flush_locked(self, bucket_ts: int) -> int:
        if not self._buckets:
            return 0
        rows = {
            object_id: bucket.row()
            for object_id, bucket in self._buckets.items()
            if bucket.samples
        }
        self._buckets = {}
        if not rows:
            return 0
        if self.storage.writes_paused:
            # Counting continues in memory -- the baselines are still correct,
            # so nothing is double-counted once writing resumes -- but this
            # minute is dropped rather than grown onto a filesystem that has no
            # room for it.
            self.buckets_dropped += len(rows)
            return 0
        self.database.write_buckets(bucket_ts, rows)
        self.database.store_baselines(self._baselines)
        self.last_flush_ts = bucket_ts
        self.buckets_written += len(rows)
        return len(rows)

    def run_maintenance(self) -> Dict[str, Any]:
        now = _utc_now()
        rolled = self.database.rollup_hours(now - (now % HOUR_SECONDS))
        retention = self.storage.retention_for_level(self.storage.pressure_level)
        deleted = self.database.apply_retention(
            minute_cutoff=now - retention["minute_days"] * 86400,
            minute_server_cutoff=now - retention["minute_server_hours"] * 3600,
            hour_cutoff=now - retention["hour_days"] * 86400,
        )
        if any(deleted.values()):
            self.database.incremental_vacuum()
        # Rollups and retention run first so the guard measures the size that
        # normal housekeeping actually leaves behind, not the peak before it.
        enforcement = self.storage.enforce(now)
        status: StorageStatus = enforcement["status"]
        LOG.info(
            "Maintenance: rolled=%s deleted=%s storage=%s actions=%s",
            rolled,
            json.dumps(deleted),
            status.state,
            ",".join(enforcement["actions"]) or "none",
        )
        return {
            "rolled_up": rolled,
            "deleted": deleted,
            "storage_state": status.state,
            "actions": enforcement["actions"],
        }

    # -- reporting --------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        now = _utc_now()
        last_poll = self.last_poll_ts
        stale_after = max(60, self.config.poll_interval_seconds * 6)
        degraded = last_poll is None or (now - last_poll) > stale_after
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "degraded": degraded,
            "poll_interval_seconds": self.config.poll_interval_seconds,
            "last_poll_ts": last_poll,
            "last_poll_age_seconds": None if last_poll is None else now - last_poll,
            "last_flush_ts": self.last_flush_ts,
            "polls_total": self.polls_total,
            "buckets_written": self.buckets_written,
            "buckets_dropped": self.buckets_dropped,
            "writes_paused": self.storage.writes_paused,
            "storage_state": self.storage.state,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Unix socket API
# ---------------------------------------------------------------------------


class MetricsHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-metricsd/1.0"

    def _peer(self) -> str:
        address = getattr(self, "client_address", None)
        if isinstance(address, str) and address:
            return address
        return "unix"

    def address_string(self) -> str:  # noqa: N802
        return self._peer()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        try:
            message = fmt % args
        except Exception:  # pylint: disable=broad-except
            message = fmt
        LOG.debug("%s - %s", self._peer(), message)

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _query(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.path).query or "", keep_blank_values=True)

    def _site(self, query: Dict[str, List[str]]) -> str:
        """Resolve the site filter to a known backend, or to the edge totals."""

        requested = (query.get("site", [""])[0] or "").strip()
        if not requested or requested.lower() == "all":
            return ""
        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        known = {entry["proxy"] for entry in database.sites()}
        # An unknown name falls back to the edge totals rather than reaching a
        # query: the parameter selects from what exists, it does not describe it.
        return requested if requested in known else ""

    def do_POST(self) -> None:  # noqa: N802
        """The one thing this daemon is told rather than asked.

        An uplink's name is the operator's, not something that can be
        derived: HAProxy knows a server as srv1, and which cable that is
        only a person knows. Kept in the collector's own state table, beside
        the rollup watermark, because it belongs to the same database as the
        numbers it labels.
        """

        database: Database = self.server.database  # type: ignore[attr-defined]
        if urlparse(self.path).path != "/api/v1/metrics/channel-labels":
            self._send_json(404, {"ok": False, "error": "unknown path"})
            return
        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
            if length <= 0 or length > 65536:
                raise ValueError("invalid Content-Length")
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            labels = payload.get("labels")
            if not isinstance(labels, dict):
                raise ValueError("labels must be an object")
            if len(labels) > 64:
                raise ValueError("at most 64 labels")
            cleaned = {}
            for host, label in labels.items():
                key = str(host).strip()
                text = str(label or "").strip()[:60]
                if not key or len(key) > 255:
                    raise ValueError("a host name is missing or too long")
                if text:
                    cleaned[key] = text

            # Absent means "leave it as it is": the page sends both together,
            # but an older one sending only labels must not empty the list.
            hidden_raw = payload.get("hidden")
            if hidden_raw is None:
                hidden = json.loads(
                    database.get_state(CHANNEL_HIDDEN_KEY, "[]") or "[]"
                )
            elif isinstance(hidden_raw, list):
                if len(hidden_raw) > 64:
                    raise ValueError("at most 64 hidden channels")
                hidden = sorted({
                    str(host).strip() for host in hidden_raw
                    if str(host).strip() and len(str(host).strip()) <= 255
                })
            else:
                raise ValueError("hidden must be a list")
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        try:
            database.set_state(CHANNEL_LABELS_KEY, json.dumps(cleaned))
            database.set_state(CHANNEL_HIDDEN_KEY, json.dumps(hidden))
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        self._send_json(200, {"ok": True, "labels": cleaned, "hidden": hidden})

    def do_GET(self) -> None:  # noqa: N802
        collector: Collector = self.server.collector  # type: ignore[attr-defined]
        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/metrics/sites":
            try:
                self._send_json(200, {"ok": True, "sites": database.sites()})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/metrics/series":
            query = self._query()
            chart = (query.get("chart", [""])[0] or "").strip().lower()
            if chart not in CHART_SERIES:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "unknown chart",
                        "available": sorted(CHART_SERIES),
                    },
                )
                return
            range_key, since, until = resolve_window(query)
            try:
                payload = database.series(
                    chart=chart,
                    site=self._site(query),
                    since=since,
                    until=until,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update({"ok": True, "range": range_key, "until": until})
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/servers":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.server_totals(
                    since=since, until=until
                )
                payload["labels"] = json.loads(
                    database.get_state(CHANNEL_LABELS_KEY, "{}") or "{}"
                )
                payload["hidden"] = json.loads(
                    database.get_state(CHANNEL_HIDDEN_KEY, "[]") or "[]"
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update({"ok": True, "range": range_key,
                            "since": since, "until": until})
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/states":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.state_timeline(
                    site=self._site(query),
                    since=since,
                    until=until,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update(
                {
                    "ok": True,
                    "range": range_key,
                    "since": since,
                    "until": until,
                }
            )
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/summary":
            query = self._query()
            range_key, since, until = resolve_window(query)
            site = self._site(query)
            # The window decides the end, not the clock: an explicit period
            # that silently snapped back to "now" would report the wrong
            # thing while looking right.
            range_seconds = max(1, until - since)
            try:
                totals = database.totals(
                    site=site, since=since, until=until
                )
                payload = {
                    "ok": True,
                    "ts": until,
                    "range": range_key,
                    "range_seconds": range_seconds,
                    "since": since,
                    "until": until,
                    "site": site,
                    "totals": totals,
                    "requests_per_second": round(
                        totals["requests"] / range_seconds, 3
                    ),
                    "connections": database.latest_gauges(site=site, until=until),
                    "health": database.backend_health(),
                    "collector": collector.health(),
                    "storage": collector.storage.report(until),
                }
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/health":
            try:
                payload = {
                    "ok": True,
                    "ts": _utc_now(),
                    "collector": collector.health(),
                    "database": database.stats(),
                }
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/storage":
            try:
                now = _utc_now()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": now,
                        "path": str(database.path),
                        "storage": collector.storage.report(now),
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"ok": False, "error": "not found"})


class MetricsServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: str,
        handler_cls: type[BaseHTTPRequestHandler],
        collector: Collector,
        database: MetricsDatabase,
    ) -> None:
        super().__init__(socket_path, handler_cls)
        self.collector = collector
        self.database = database


def _set_socket_perms(socket_path: str, group_name: str) -> None:
    gid = grp.getgrnam(group_name).gr_gid
    uid = pwd.getpwnam("root").pw_uid
    os.chown(socket_path, uid, gid)
    os.chmod(socket_path, 0o660)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = load_config(CONFIG_PATH)
    if not config.enabled:
        # Staying alive as an idle process keeps the unit's health reporting
        # honest: "enabled: false" is a configuration state, not a crash.
        LOG.info("Monitoring is disabled in %s; idling", CONFIG_PATH)
        stop = threading.Event()
        with contextlib.suppress(KeyboardInterrupt):
            stop.wait()
        return

    database = MetricsDatabase(DATABASE_PATH)
    guard = StorageGuard(config, database, alerts=_alert_client())
    collector = Collector(config, database, guard)

    # Decide before the first sample is taken: a host that is already out of
    # disk must not gain a new writer just because the daemon restarted.
    initial = guard.enforce(_utc_now())
    status: StorageStatus = initial["status"]

    LOG.info(
        "Starting easy-ha-proxy-metricsd: socket=%s db=%s interval=%ss "
        "limit=%dMiB reserve=%dMiB storage=%s",
        SOCKET_PATH,
        DATABASE_PATH,
        config.poll_interval_seconds,
        status.max_database_bytes // MIB,
        status.reserved_free_bytes // MIB,
        status.state,
    )

    collector.start()

    with contextlib.suppress(OSError):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

    server = MetricsServer(SOCKET_PATH, MetricsHandler, collector, database)
    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Failed to set socket permissions: %s", exc)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        collector.stop()
        with contextlib.suppress(Exception):
            server.server_close()
        database.close()
        with contextlib.suppress(OSError):
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
