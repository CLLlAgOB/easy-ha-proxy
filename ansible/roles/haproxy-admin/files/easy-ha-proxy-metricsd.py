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
    "cpu_avg": "wavg",
    "cpu_max": "max",
    "haproxy_busy_avg": "wavg",
    "haproxy_busy_max": "max",
    "disk_used_avg": "wavg",
    "disk_total": "max",
    "disk_read": "sum",
    "disk_write": "sum",
    "net_rx": "sum",
    "net_tx": "sum",
    "temp_avg": "wavg",
    "temp_max": "max",
    "refused_geo": "sum",
    "refused_banned": "sum",
    "refused_rate": "sum",
    "refused_other": "sum",
    "memory_avg": "wavg",
    "memory_max": "max",
    "memory_total": "max",
}

CHART_SERIES: Dict[str, Tuple[str, ...]] = {
    "requests": ("requests",),
    "traffic": ("bytes_in", "bytes_out"),
    "responses": ("resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx"),
    "latency": ("response_ms_avg", "response_ms_max"),
    "connections": ("conn_cur_avg", "conn_cur_max"),
    # The machine, not the traffic. Two different questions live here: the
    # host can sit at 12% while HAProxy's own event loop is saturated and
    # every request is queueing behind it, and on a two-core gateway that
    # difference is the whole diagnosis.
    "cpu": ("cpu_avg", "cpu_max", "haproxy_busy_avg"),
    "memory": ("memory_avg", "memory_max", "memory_total"),
    # The rest of the machine: how full its disk is and how busy, what goes
    # over its network cards, and how warm it runs -- on a fanless board in
    # a cupboard, the reason it slows down.
    "disk": ("disk_used_avg", "disk_total"),
    "diskio": ("disk_read", "disk_write"),
    "network": ("net_rx", "net_tx"),
    "temperature": ("temp_avg", "temp_max"),
    # From the access log, through the adaptive protection daemon that reads
    # it: response time percentiles per backend -- HAProxy's own counters
    # only average -- and what the gateway turned away, by reason.
    "percentiles": ("p50", "p95", "p99"),
    "refusals": ("refused_geo", "refused_banned", "refused_rate", "refused_other"),
}

# Charts about the machine rather than about a proxy object. They select the
# synthetic 'host' row and ignore any site: one machine's CPU is not
# divisible among the sites it serves.
HOST_CHARTS = frozenset({"cpu", "memory", "disk", "diskio", "network", "temperature"})
# The gateway's refusals: one synthetic object, like the machine's row.
EDGE_KIND = "edge"
# The minute digests guardd keeps of the access log (see MinuteDigests there).
GUARDD_SOCKET_PATH = os.environ.get(
    "GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock"
)
DIGEST_PULL_SECONDS = 60
DIGEST_CURSOR_KEY = "digest_cursor"
# Kept in step with DIGEST_BOUNDS_MS in easy-ha-proxy-guardd.py: upper edges
# in milliseconds, with one more bucket above the last.
DIGEST_BOUNDS_MS: Tuple[int, ...] = (
    5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750,
    1000, 1500, 2000, 3000, 5000, 10000, 30000,
)
HISTOGRAM_COLUMNS: Tuple[str, ...] = tuple(f"h{index}" for index in range(len(DIGEST_BOUNDS_MS) + 1))
# The latency rollup waits this long past an hour: a minute's digest arrives
# a minute and a half after the minute, later than its traffic.
LATENCY_ROLLUP_LAG_SECONDS = 600
PERCENTILES = (("p50", 0.50), ("p95", 0.95), ("p99", 0.99))
# Charts computed from something other than the metric rows' own columns.
DERIVED_CHARTS = frozenset({"percentiles"})
# Where the machine is read from; attributes of the collector so a test can
# point them at a directory of its own.
DISK_PATH = "/"
DISKSTATS_PATH = "/proc/diskstats"
SYS_BLOCK_ROOT = "/sys/block"
SYS_NET_ROOT = "/sys/class/net"
THERMAL_ROOT = "/sys/class/thermal"
# /proc/diskstats counts sectors of 512 bytes whatever the device's own size.
DISKSTATS_SECTOR = 512
# A thermal zone reading outside this is a broken sensor, not a temperature.
TEMPERATURE_RANGE_MILLI = (-40_000, 150_000)
HOST_KIND = "host"

# What each part of the gateway uses: HAProxy, every helper service, the
# containers and the Docker engine under them. One object per part, kind
# 'component', with the name in `proxy` and the group in `server`. They
# share the host's bucketing, rollup and retention, and nothing selects
# them except the two machine charts, so they cannot leak into traffic.
COMPONENT_KIND = "component"
COMPONENT_SERVICE = "service"
COMPONENT_CONTAINER = "container"
COMPONENT_ENGINE = "engine"
# Each chart's (average, peak) column for one component.
COMPONENT_COLUMNS: Dict[str, Tuple[str, str]] = {
    "cpu": ("cpu_avg", "cpu_max"),
    "memory": ("memory_avg", "memory_max"),
}
CGROUP_ROOT = "/sys/fs/cgroup"
DOCKER_CONTAINERS_DIR = "/var/lib/docker/containers"
# Our units, by name. Anything else on the machine is "other processes".
COMPONENT_UNIT_PREFIXES = ("haproxy", "easy-ha-proxy-", "authelia-")
ENGINE_UNITS = {"docker.service": "dockerd", "containerd.service": "containerd"}
# A bound on objects, not a limit anyone should meet: a machine where
# containers come and go under random names would otherwise add a row per
# name for ever.
MAX_COMPONENTS = 48
# Units started for one job and gone after it: an update check or apply, a
# backup or a restore, a scheduled reboot. Their work belongs to the service
# that started them. Counted under their own names, every update check left
# a component behind: a day of them put 98 lines on the processor chart,
# 780 KB in its answer and nearly three seconds into opening the page.
_TRANSIENT_UNITS = (
    re.compile(r"^(?P<service>.+)-job-[0-9a-f]{6,32}$"),
    re.compile(r"^(?P<service>easy-ha-proxy-web-reboot)-[0-9a-f]{12}$"),
    re.compile(r"^(?P<service>easy-ha-proxy-reboot)-[0-9]{14}-[0-9]+-[0-9a-f]{8}$"),
)


def component_name(name: str) -> str:
    """The service a unit's work is counted under: its own, or its parent's."""

    for pattern in _TRANSIENT_UNITS:
        match = pattern.match(name)
        if match:
            return match.group("service")
    return name
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")

# Memory is stored in KiB: bytes would need wider integers in every row for
# a precision nobody reads. The read API multiplies it back out.
MEMORY_UNIT = 1024

# CPU is stored as tenths of a percent. Whole percent would round a gateway
# that idles at 0.4% down to a flat zero line, which reads as "broken"
# rather than "quiet"; the read API divides it back out, so what leaves the
# daemon is an ordinary percentage.
CPU_SCALE = 10

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


def _from_storage(chart: str, value: Any) -> Any:
    """A stored machine value as the read API returns it.

    CPU leaves as a percentage with one decimal, memory as bytes.
    """

    if chart == "memory":
        return int(value or 0) * MEMORY_UNIT
    if chart == "disk":
        # A disk is never empty: 0 is a minute it was not read.
        return int(value) * MEMORY_UNIT if value else None
    if chart in ("diskio", "network", "refusals"):
        return int(value or 0)
    if chart == "temperature":
        # Nothing was read: a gap, never a machine at 0 degrees.
        return round(int(value) / CPU_SCALE, 1) if value else None
    return round(int(value or 0) / CPU_SCALE, 1)


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
    "cpu_avg",
    "cpu_max",
    "haproxy_busy_avg",
    "haproxy_busy_max",
    "memory_avg",
    "memory_max",
    "memory_total",
    # The host row only. Disk space in KiB like memory, I/O and network in
    # bytes per bucket, temperature in tenths of a degree.
    "disk_used_avg",
    "disk_total",
    "disk_read",
    "disk_write",
    "net_rx",
    "net_tx",
    "temp_avg",
    "temp_max",
    # The edge row only: requests the gateway turned away, by reason.
    "refused_geo",
    "refused_banned",
    "refused_rate",
    "refused_other",
)
# Columns summed when rolling minutes up into hours; the rest are averaged
# (weighted by sample count) or maxed, see _ROLLUP_MAX.
# Derived from _AGGREGATIONS rather than written out again. Kept as three
# separate lists, a column added to the schema but forgotten here would still
# be collected and still be charted -- and then quietly vanish the moment the
# minute rows aged out and only the hourly rollup was left. Deriving them
# makes that impossible to get wrong; a test asserts every stored column is
# accounted for.
_ROLLUP_SUM = tuple(
    column for column in METRIC_COLUMNS if _AGGREGATIONS.get(column) == "sum"
)
_ROLLUP_MAX = tuple(
    column for column in METRIC_COLUMNS if _AGGREGATIONS.get(column) == "max"
)
_ROLLUP_WAVG = tuple(
    column for column in METRIC_COLUMNS if _AGGREGATIONS.get(column) == "wavg"
)

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
    # Traffic alerts, judged per backend on each minute's totals; 0 turns a
    # check off. A minute with fewer requests than the floor says nothing
    # either way: one failure out of three requests is not a 5xx problem.
    alert_error_ratio_percent: int = 10
    alert_slow_response_ms: int = 3000
    alert_min_requests: int = 20

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
    alerts = raw.get("alerts")
    alerts = alerts if isinstance(alerts, dict) else {}

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
        alert_error_ratio_percent=_clamp_int(
            alerts.get("error_ratio_percent"), default=10, min_v=0, max_v=100
        ),
        alert_slow_response_ms=_clamp_int(
            alerts.get("slow_response_ms"), default=3000, min_v=0, max_v=600000
        ),
        alert_min_requests=_clamp_int(
            alerts.get("min_requests"), default=20, min_v=1, max_v=1000000
        ),
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

# Which monitors run, as the operator left them on the monitoring page. Two
# are gathered by this daemon beside HAProxy's counters and stop being
# gathered when switched off: the machine's load, and its split per
# component -- the walk of the cgroup tree and the containers, the costliest
# part of a poll. The rest are drawn from the one `show stat` every poll
# reads anyway, so for them off means not shown.
MONITORS_KEY = "monitors"
GATHERED_MONITORS = (
    "machine", "components", "disk", "network", "temperature", "percentiles", "refusals",
)
# Both come from the same digest of the access log.
DIGEST_MONITORS = ("percentiles", "refusals")
# Read with the machine's row; any of them on means the row is written.
HOST_MONITORS = ("machine", "disk", "network", "temperature")
SHOWN_MONITORS = (
    "requests", "traffic", "responses", "latency", "connections",
    "uplinks", "availability",
)
MONITOR_DEFAULTS: Dict[str, bool] = {
    name: True for name in GATHERED_MONITORS + SHOWN_MONITORS
}


def monitors_from(raw: Any) -> Dict[str, bool]:
    """The stored choices over the defaults; anything unknown is dropped."""

    monitors = dict(MONITOR_DEFAULTS)
    if isinstance(raw, dict):
        for name, value in raw.items():
            if name in monitors and isinstance(value, bool):
                monitors[name] = value
    return monitors


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
            "cpu_avg": average("cpu"),
            "cpu_max": self.gauge_maxima.get("cpu", 0),
            "haproxy_busy_avg": average("haproxy_busy"),
            "haproxy_busy_max": self.gauge_maxima.get("haproxy_busy", 0),
            "memory_avg": average("memory"),
            "memory_max": self.gauge_maxima.get("memory", 0),
            "memory_total": self.gauge_maxima.get("memory_total", 0),
            "disk_used_avg": average("disk_used"),
            "disk_total": self.gauge_maxima.get("disk_total", 0),
            "disk_read": self.counters.get("disk_read", 0),
            "disk_write": self.counters.get("disk_write", 0),
            "net_rx": self.counters.get("net_rx", 0),
            "net_tx": self.counters.get("net_tx", 0),
            "temp_avg": average("temp"),
            "temp_max": self.gauge_maxima.get("temp", 0),
            "refused_geo": self.counters.get("refused_geo", 0),
            "refused_banned": self.counters.get("refused_banned", 0),
            "refused_rate": self.counters.get("refused_rate", 0),
            "refused_other": self.counters.get("refused_other", 0),
        }


def histogram_percentile(counts: List[int], share: float) -> Optional[int]:
    """The value below which share of the requests fell, in milliseconds.

    Read off the histogram: the bucket the rank falls in, and a straight line
    between its edges. The top bucket has no upper edge, so a rank there
    reads as its lower one -- "at least". None when nothing was counted.
    """

    total = sum(counts)
    if total <= 0:
        return None
    rank = share * total
    seen = 0
    for index, count in enumerate(counts):
        if count <= 0:
            continue
        if seen + count >= rank:
            lower = DIGEST_BOUNDS_MS[index - 1] if index > 0 else 0
            if index >= len(DIGEST_BOUNDS_MS):
                return lower
            upper = DIGEST_BOUNDS_MS[index]
            return int(round(lower + (upper - lower) * (rank - seen) / count))
        seen += count
    return DIGEST_BOUNDS_MS[-1]


def unix_get_json(socket_path: str, path: str, timeout: float = 10.0) -> Dict[str, Any]:
    """GET a JSON document from a local daemon over its Unix socket."""

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(socket_path)
        sock.sendall(
            f"GET {path} HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\n\r\n".encode("ascii")
        )
        chunks: List[bytes] = []
        total = 0
        while total < 16 * 1024 * 1024:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.split(b" ", 2)[1:2]
    if not status or status[0] != b"200":
        raise RuntimeError(f"{path}: {head[:80]!r}")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path}: not an object")
    return payload


def read_disk_space(path: str) -> Optional[Tuple[int, int]]:
    """(used, total) KiB of the filesystem holding path, counted as df does."""

    try:
        stat = os.statvfs(path)
    except OSError:
        return None
    total = stat.f_blocks * stat.f_frsize
    if total <= 0:
        return None
    used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
    return used // MEMORY_UNIT, total // MEMORY_UNIT


def read_disk_counters(diskstats_path: str, sys_block_root: str) -> Optional[Dict[str, Tuple[int, int]]]:
    """Bytes read and written so far, per disk.

    The disks are the entries of /sys/block backed by a device: partitions
    would count their disk twice, and loop, ram, zram and device-mapper
    entries are views of something already counted or of nothing at all.
    """

    try:
        disks = {
            name for name in os.listdir(sys_block_root)
            if os.path.exists(os.path.join(sys_block_root, name, "device"))
        }
        with open(diskstats_path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    counters: Dict[str, Tuple[int, int]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[2] not in disks:
            continue
        try:
            counters[fields[2]] = (
                int(fields[5]) * DISKSTATS_SECTOR,
                int(fields[9]) * DISKSTATS_SECTOR,
            )
        except ValueError:
            continue
    return counters or None


def read_network_counters(sys_net_root: str) -> Optional[Dict[str, Tuple[int, int]]]:
    """Bytes received and sent so far, per network card.

    Only interfaces backed by a device: loopback, Docker's bridges and veth
    pairs, and tunnels carry traffic the card already counted once.
    """

    try:
        names = sorted(os.listdir(sys_net_root))
    except OSError:
        return None
    counters: Dict[str, Tuple[int, int]] = {}
    for name in names:
        base = os.path.join(sys_net_root, name)
        if not os.path.exists(os.path.join(base, "device")):
            continue
        try:
            with open(os.path.join(base, "statistics", "rx_bytes"), "r", encoding="utf-8") as handle:
                received = int(handle.read().strip())
            with open(os.path.join(base, "statistics", "tx_bytes"), "r", encoding="utf-8") as handle:
                sent = int(handle.read().strip())
        except (OSError, ValueError):
            continue
        counters[name] = (received, sent)
    return counters or None


def read_temperature(thermal_root: str) -> Optional[int]:
    """The warmest thermal zone, in tenths of a degree; None without one."""

    warmest: Optional[int] = None
    try:
        zones = [name for name in os.listdir(thermal_root) if name.startswith("thermal_zone")]
    except OSError:
        return None
    low, high = TEMPERATURE_RANGE_MILLI
    for zone in zones:
        try:
            with open(os.path.join(thermal_root, zone, "temp"), "r", encoding="utf-8") as handle:
                milli = int(handle.read().strip())
        except (OSError, ValueError):
            continue
        if not low < milli < high:
            continue
        value = milli // 100
        if warmest is None or value > warmest:
            warmest = value
    return warmest


def _close_span(spans: List[Dict[str, Any]], start: int, end: int, state_name: str) -> None:
    """End the bar that began at start, in state_name, at end."""
    if end <= start:
        return
    # A restart re-observes the state it left behind, which would otherwise
    # draw as two touching bars of the same colour.
    if spans and spans[-1]["state"] == state_name:
        spans[-1]["end"] = end
    else:
        spans.append({"state": state_name, "start": start, "end": end})


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
            # A histogram of response times per backend and slot; a row only
            # where something was answered, so idle backends cost nothing.
            for table in ("latency_1m", "latency_1h"):
                columns = ",\n".join(
                    f"{column} INTEGER NOT NULL DEFAULT 0" for column in HISTOGRAM_COLUMNS
                )
                cursor.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} ("
                    "bucket_ts INTEGER NOT NULL, "
                    "object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, "
                    f"{columns}, PRIMARY KEY (bucket_ts, object_id)) WITHOUT ROWID"
                )
            self._add_missing_metric_columns(cursor)
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

    @staticmethod
    def _add_missing_metric_columns(cursor: sqlite3.Cursor) -> None:
        """Bring both metric tables up to the current column list.

        Deliberately not a numbered migration. A new metric column is purely
        additive -- every stored row keeps its values and the new one defaults
        to zero -- so bumping the schema version would buy nothing and cost
        the ability to roll the daemon back: the version guard makes an older
        build refuse the file outright, and refusing to start is a far worse
        failure than ignoring a column it does not know about.

        Run on every open rather than once, so it is self-healing: a database
        that somehow missed a column gets it on the next start, and adding a
        column in future needs no migration entry at all.
        """

        for table in ("metric_1m", "metric_1h"):
            existing = {
                str(row["name"])
                for row in cursor.execute(f"PRAGMA table_info({table})")
            }
            for column in METRIC_COLUMNS:
                if column in existing:
                    continue
                cursor.execute(
                    f"ALTER TABLE {table} "
                    f"ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"
                )
                LOG.info("Added metrics column %s.%s", table, column)

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
        averaged = _ROLLUP_WAVG
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

    def write_latency(self, bucket_ts: int, rows: Dict[int, List[int]]) -> None:
        """One minute's histograms, per backend. Written whole: asking for the
        same minute twice replaces it rather than counting it twice."""

        if not rows:
            return
        columns = ", ".join(HISTOGRAM_COLUMNS)
        marks = ", ".join("?" for _ in HISTOGRAM_COLUMNS)
        with self._lock, self._conn:
            self._conn.executemany(
                f"INSERT OR REPLACE INTO latency_1m (bucket_ts, object_id, {columns}) "
                f"VALUES (?, ?, {marks})",
                [(bucket_ts, object_id, *counts) for object_id, counts in rows.items()],
            )

    def rollup_latency_hours(self, before_ts: int) -> int:
        """Histograms add up, so an hour is the sum of its minutes."""

        watermark = _to_int(self.get_state("latency_rollup_watermark", "0"))
        if before_ts <= watermark:
            return 0
        sums = ", ".join(f"SUM({column})" for column in HISTOGRAM_COLUMNS)
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                f"INSERT OR REPLACE INTO latency_1h (bucket_ts, object_id, {', '.join(HISTOGRAM_COLUMNS)}) "
                f"SELECT bucket_ts - (bucket_ts % {HOUR_SECONDS}) AS hour_ts, object_id, {sums} "
                "FROM latency_1m WHERE bucket_ts >= ? AND bucket_ts < ? "
                "GROUP BY hour_ts, object_id",
                (watermark, before_ts),
            )
            written = max(0, cursor.rowcount or 0)
            cursor.execute(
                "INSERT INTO collector_state (key, value) VALUES ('latency_rollup_watermark', ?) "
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
            # The histograms age with the rows they sit beside.
            cursor.execute("DELETE FROM latency_1m WHERE bucket_ts < ?", (minute_cutoff,))
            deleted_minutes += cursor.rowcount or 0
            cursor.execute("DELETE FROM latency_1h WHERE bucket_ts < ?", (hour_cutoff,))
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
        self, *, chart: str, site: str, since: int, until: int,
        components: bool = True,
    ) -> Dict[str, Any]:
        """One chart's lines over the window.

        On the processor and memory charts, components=False leaves out the
        line per component -- a day of them was most of the page's wait --
        and keeps the group totals the chart draws by default.
        """

        columns = CHART_SERIES[chart]
        table, step = choose_resolution(max(1, until - since))
        if chart == "latency":
            return self._latency_series(
                site=site, table=table, step=step, since=since, until=until
            )
        if chart == "percentiles":
            return self._percentile_series(
                site=site, table=table, step=step, since=since, until=until
            )
        if chart == "refusals":
            # The gateway's, never a site's: a refused request reached none.
            predicate, parameters = f"o.kind = '{EDGE_KIND}'", []
        elif chart in HOST_CHARTS:
            # The machine's own row, and never scoped by site: picking a site
            # must not appear to filter a number that has nothing to do with
            # it. The kind is a module constant, not anything a caller sent.
            predicate, parameters = "o.kind = 'host'", []
        else:
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
        if chart in HOST_CHARTS or chart == "refusals":
            # Back to plain percentages and bytes at the edge -- tenths and
            # KiB are storage details nothing outside this file should have
            # to know about.
            values = {
                column: [_from_storage(chart, row[index + 1]) for row in rows]
                for index, column in enumerate(columns)
            }
        else:
            values = {
                column: [int(row[index + 1]) for row in rows]
                for index, column in enumerate(columns)
            }
        payload: Dict[str, Any] = {
            "chart": chart,
            "resolution_seconds": step,
            "source": table,
            "points": points[:MAX_CHART_POINTS],
            "series": {
                name: value[:MAX_CHART_POINTS] for name, value in values.items()
            },
        }
        if chart in COMPONENT_COLUMNS:
            add = self._add_components if components else self._add_component_groups
            add(
                payload, chart=chart, table=table, step=step,
                since=since, until=until, host=[row[1] for row in rows],
            )
        return payload

    def _add_component_groups(
        self,
        payload: Dict[str, Any],
        *,
        chart: str,
        table: str,
        step: int,
        since: int,
        until: int,
        host: List[int],
    ) -> None:
        """The group totals _add_components adds, without a line per component.

        When a slot is one stored row, SQLite sums the groups itself: one row
        per slot comes back instead of one per component and slot, and no
        component's line is built only to be thrown away. Otherwise -- a slot
        of several hourly rows, each weighed by its own samples -- the full
        path computes them, which on the hourly table is cheap anyway.
        """

        stored_step = BUCKET_SECONDS if table == "metric_1m" else HOUR_SECONDS
        if step != stored_step:
            self._add_components(
                payload, chart=chart, table=table, step=step,
                since=since, until=until, host=host,
            )
            payload.pop("components", None)
            return
        average, _peak = COMPONENT_COLUMNS[chart]
        value = f"CASE WHEN m.samples > 0 THEN COALESCE(m.{average}, 0) ELSE 0 END"
        with self._lock:
            # HAProxy's own work is not a helper's; its rows are found the way
            # _add_components names them, so both paths agree on what it is.
            haproxy = [
                int(row[0])
                for row in self._conn.execute(
                    "SELECT id, proxy FROM objects WHERE kind = 'component'"
                ).fetchall()
                if component_name(str(row[1])) == "haproxy"
            ] or [-1]
            marks = ", ".join("?" * len(haproxy))
            cursor = self._conn.execute(
                f"SELECT m.bucket_ts, "
                f"SUM(CASE WHEN o.server = ? THEN {value} ELSE 0 END), "
                f"SUM(CASE WHEN o.server = ? AND o.id NOT IN ({marks}) THEN {value} ELSE 0 END), "
                f"SUM({value}) "
                f"FROM {table} m JOIN objects o ON o.id = m.object_id "
                "WHERE o.kind = 'component' AND m.bucket_ts >= ? AND m.bucket_ts < ? "
                "GROUP BY m.bucket_ts",
                [COMPONENT_CONTAINER, COMPONENT_SERVICE, *haproxy, since, until],
            )
            cursor.row_factory = None
            rows = cursor.fetchall()

        points = payload["points"]
        size = len(points)
        position = {slot: index for index, slot in enumerate(points)}
        containers = [0] * size
        helpers = [0] * size
        claimed = [0] * size
        for slot, in_containers, in_helpers, in_all in rows:
            index = position.get(slot)
            if index is None:
                continue
            containers[index] = int(in_containers)
            helpers[index] = int(in_helpers)
            claimed[index] = int(in_all)

        if chart == "memory":
            def convert(stored: int) -> Any:
                return stored * MEMORY_UNIT
        else:
            def convert(stored: int) -> Any:
                return round(stored / CPU_SCALE, 1)

        series = payload["series"]
        series["helpers"] = [convert(item) for item in helpers]
        series["containers"] = [convert(item) for item in containers]
        series["other"] = [
            _from_storage(chart, max(0, int(host[index]) - claimed[index]))
            for index in range(min(size, len(host)))
        ]

    def _latency_series(
        self, *, site: str, table: str, step: int, since: int, until: int
    ) -> Dict[str, Any]:
        """Response time over the backends that answered in each slot.

        HAProxy measures response time on backends only; a frontend's is
        empty, so "all sites" read from the frontends drew a flat zero. Each
        backend's average counts as often as it answered requests, the peak
        is the highest of those that answered, and a slot in which nothing
        answered has no response time at all: it comes back as null, a gap,
        rather than as an instant 0 ms.
        """

        predicate, parameters = "o.kind = 'backend'", []
        if site:
            predicate, parameters = "o.kind = 'backend' AND o.proxy = ?", [site]
        query = (
            f"SELECT (m.bucket_ts / {step}) * {step} AS slot, "
            "CAST(ROUND(SUM(m.response_ms_avg * m.requests) * 1.0 "
            "/ NULLIF(SUM(m.requests), 0)) AS INTEGER), "
            "MAX(CASE WHEN m.requests > 0 THEN m.response_ms_max END) "
            f"FROM {table} m JOIN objects o ON o.id = m.object_id "
            f"WHERE {predicate} AND m.bucket_ts >= ? AND m.bucket_ts < ? "
            "GROUP BY slot ORDER BY slot"
        )
        with self._lock:
            rows = self._conn.execute(query, [*parameters, since, until]).fetchall()
        rows = rows[:MAX_CHART_POINTS]
        return {
            "chart": "latency",
            "resolution_seconds": step,
            "source": table,
            "points": [int(row[0]) for row in rows],
            "series": {
                "response_ms_avg": [row[1] for row in rows],
                "response_ms_max": [row[2] for row in rows],
            },
        }

    def _percentile_series(
        self, *, site: str, table: str, step: int, since: int, until: int
    ) -> Dict[str, Any]:
        """p50, p95 and p99 per slot, from the summed histograms of the
        backends that answered in it -- or of one backend. A slot in which
        nothing answered has none: null, a gap."""

        source = "latency_1m" if table == "metric_1m" else "latency_1h"
        predicate, parameters = "o.kind = 'backend'", []
        if site:
            predicate, parameters = "o.kind = 'backend' AND o.proxy = ?", [site]
        sums = ", ".join(f"SUM(m.{column})" for column in HISTOGRAM_COLUMNS)
        query = (
            f"SELECT (m.bucket_ts / {step}) * {step} AS slot, {sums} "
            f"FROM {source} m JOIN objects o ON o.id = m.object_id "
            f"WHERE {predicate} AND m.bucket_ts >= ? AND m.bucket_ts < ? "
            "GROUP BY slot ORDER BY slot"
        )
        with self._lock:
            rows = self._conn.execute(query, [*parameters, since, until]).fetchall()
        rows = rows[:MAX_CHART_POINTS]
        series: Dict[str, List[Any]] = {name: [] for name, _ in PERCENTILES}
        for row in rows:
            counts = [int(value or 0) for value in row[1:]]
            for name, share in PERCENTILES:
                series[name].append(histogram_percentile(counts, share))
        return {
            "chart": "percentiles",
            "resolution_seconds": step,
            "source": source,
            "points": [int(row[0]) for row in rows],
            "series": series,
        }

    def _add_components(
        self,
        payload: Dict[str, Any],
        *,
        chart: str,
        table: str,
        step: int,
        since: int,
        until: int,
        host: List[int],
    ) -> None:
        """Who uses the machine: one line per component, plus group totals.

        Aligned to the host's own slots, so every line has a value wherever
        the machine line has one; a component that was not running has zero
        there, which is the truth. The totals are added here rather than in
        the browser so that "helpers" means the same thing everywhere.
        """

        average, peak = COMPONENT_COLUMNS[chart]
        points = payload["points"]
        position = {slot: index for index, slot in enumerate(points)}
        # One pass for the line and its peak: the peak over the window is the
        # highest of the per-slot peaks. Plain tuples, read by position -- on
        # a small gateway this answer is the slowest thing the page waits for.
        stored_step = BUCKET_SECONDS if table == "metric_1m" else HOUR_SECONDS
        if step == stored_step:
            # A slot is one stored row (a day of minutes, two months of
            # hours): nothing to group, and grouping cost a sort of every row.
            selected = (
                "m.bucket_ts, o.proxy, o.server, "
                f"CASE WHEN m.samples > 0 THEN COALESCE(m.{average}, 0) ELSE 0 END, "
                f"COALESCE(m.{peak}, 0)"
            )
            grouping = ""
        else:
            selected = (
                f"(m.bucket_ts / {step}) * {step} AS slot, o.proxy, o.server, "
                f"{_aggregate_sql(average)}, {_aggregate_sql(peak)}"
            )
            grouping = " GROUP BY slot, o.id"
        with self._lock:
            cursor = self._conn.execute(
                f"SELECT {selected} FROM {table} m JOIN objects o ON o.id = m.object_id "
                "WHERE o.kind = 'component' AND m.bucket_ts >= ? AND m.bucket_ts < ?"
                + grouping,
                [since, until],
            )
            cursor.row_factory = None
            rows = cursor.fetchall()

        size = len(points)
        # One line per service: rows a job unit left under its own name --
        # every one recorded before the collector folded them -- are added
        # to the service that started it.
        found: Dict[Tuple[str, str], Dict[str, Any]] = {}
        names: Dict[str, str] = {}
        for slot, proxy, group, value, highest in rows:
            index = position.get(slot)
            if index is None:
                continue
            name = names.get(proxy)
            if name is None:
                name = names[proxy] = component_name(str(proxy))
            key = (str(group), name)
            entry = found.get(key)
            if entry is None:
                entry = found[key] = {
                    "name": name,
                    "group": key[0],
                    "raw": [0] * size,
                    "highest": 0,
                }
            entry["raw"][index] += int(value)
            if highest > entry["highest"]:
                entry["highest"] = int(highest)

        # _from_storage, without a call and a branch per value.
        if chart == "memory":
            def convert(value: int) -> Any:
                return value * MEMORY_UNIT
        else:
            def convert(value: int) -> Any:
                return round(value / CPU_SCALE, 1)

        helpers = [0] * size
        containers = [0] * size
        claimed = [0] * size
        components = []
        for entry in found.values():
            raw = entry.pop("raw")
            highest = entry.pop("highest")
            for index, value in enumerate(raw):
                claimed[index] += value
                if entry["group"] == COMPONENT_CONTAINER:
                    containers[index] += value
                elif entry["group"] == COMPONENT_SERVICE and entry["name"] != "haproxy":
                    helpers[index] += value
            entry["values"] = [convert(value) for value in raw]
            entry["mean"] = _from_storage(chart, sum(raw) // max(1, size))
            # A folded line is never lower than its own busiest slot.
            entry["peak"] = _from_storage(chart, max(highest, max(raw, default=0)))
            components.append(entry)
        components.sort(key=lambda item: (-item["mean"], item["name"]))

        series = payload["series"]
        series["helpers"] = [convert(value) for value in helpers]
        series["containers"] = [convert(value) for value in containers]
        # The rest of the machine: the kernel, sshd, whatever else runs here.
        # Never negative: the host and its parts are sampled a moment apart.
        series["other"] = [
            _from_storage(chart, max(0, int(host[index]) - claimed[index]))
            for index in range(min(size, len(host)))
        ]
        payload["components"] = components

    def host_load(self, *, since: int, until: int) -> Dict[str, float]:
        """Average and peak load over the window, as percentages.

        Zero rows is not zero load -- it means this gateway has not collected
        any yet, which is the normal state for the first minute after an
        upgrade and for every database written before v3. The caller is told
        which of the two it is rather than being handed a confident 0%.
        """

        table, _ = choose_resolution(max(1, until - since))
        columns = (
            "cpu_avg", "cpu_max", "haproxy_busy_avg", "haproxy_busy_max",
            "memory_avg", "memory_max", "memory_total",
        )
        projection = ", ".join(_aggregate_sql(column) for column in columns)
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS observed, {projection} FROM {table} m "
                "JOIN objects o ON o.id = m.object_id "
                "WHERE o.kind = 'host' AND m.bucket_ts >= ? AND m.bucket_ts < ?",
                [since, until],
            ).fetchone()
        if row is None or not int(row["observed"]):
            return {"observed": False}
        return {
            "observed": True,
            **{
                column: _from_storage(
                    "memory" if column.startswith("memory") else "cpu",
                    row[index + 1],
                )
                for index, column in enumerate(columns)
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

    BACKEND_TOTAL_COLUMNS = (
        "requests", "resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx",
        "resp_other", "bytes_in", "bytes_out", "sessions", "check_failures",
    )

    def backend_totals(self, *, since: int, until: int) -> Dict[str, Any]:
        """What each backend answered over a range, and how fast.

        Read from the backend rows HAProxy keeps, not summed from servers:
        the response classes are counted where the request is answered. The
        response time weighs each slot by the requests it answered, like the
        chart, and a backend that answered nothing has none -- null rather
        than a confident 0 ms.
        """

        table, _ = choose_resolution(max(1, until - since))
        columns = self.BACKEND_TOTAL_COLUMNS
        projection = ", ".join(_aggregate_sql(column) for column in columns)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT o.proxy, {projection}, "
                "CAST(ROUND(SUM(m.response_ms_avg * m.requests) * 1.0 "
                "/ NULLIF(SUM(m.requests), 0)) AS INTEGER), "
                "MAX(CASE WHEN m.requests > 0 THEN m.response_ms_max END) "
                f"FROM {table} m JOIN objects o ON o.id = m.object_id "
                "WHERE o.kind = 'backend' "
                "AND m.bucket_ts >= ? AND m.bucket_ts < ? "
                "GROUP BY o.proxy ORDER BY o.proxy",
                [since, until],
            ).fetchall()
        backends = []
        for row in rows:
            entry: Dict[str, Any] = {"proxy": str(row[0])}
            for index, column in enumerate(columns):
                entry[column] = int(row[index + 1] or 0)
            average = row[len(columns) + 1]
            peak = row[len(columns) + 2]
            entry["response_ms_avg"] = None if average is None else int(average)
            entry["response_ms_max"] = None if peak is None else int(peak)
            backends.append(entry)
        return {"backends": backends, "source": table}

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

            for ts, next_state in changes[:MAX_TIMELINE_SPANS]:
                _close_span(spans, cursor, ts, current)
                cursor = max(cursor, ts)
                current = next_state
            if len(changes) > MAX_TIMELINE_SPANS:
                truncated = True
            _close_span(spans, cursor, until, current)

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


# Authelia's backend: the one row whose state is its own alert. Its HTTP
# numbers are the portal's, not a site's, so the traffic alerts skip it.
AUTHELIA_BACKEND = "authelia_backend"
TRAFFIC_ALERT_SKIP = frozenset({AUTHELIA_BACKEND, "be_access_granted"})

# A site's own settings are in websites.yml, edited in the panel. Its own
# slow-response threshold (alert_slow_ms, 0 for off) is read from there: an
# application that holds requests open on purpose -- the 1C web client -- is
# "slow" by design, and one threshold for every site either misses real
# slowness or never stops alerting about that one.
WEBSITES_FILE = os.environ.get("METRICSD_WEBSITES", "/opt/haproxy-admin/config/websites.yml")
_SITE_ID_OTHER = re.compile(r"[^A-Za-z0-9_]")


def site_slow_thresholds(path: str) -> Dict[str, int]:
    """backend -> the site's own slow-response threshold in ms (0: off).

    The backend is named as the HAProxy template names it: be_ and the
    site's name with every other character made "_".
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Cannot read %s for the sites' alert thresholds: %s", path, exc)
        return {}
    sites = data.get("sites") if isinstance(data, dict) else None
    thresholds: Dict[str, int] = {}
    for site in sites if isinstance(sites, list) else []:
        if not isinstance(site, dict) or not site.get("name"):
            continue
        value = site.get("alert_slow_ms")
        if value is None or isinstance(value, bool):
            continue
        try:
            milliseconds = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= milliseconds <= 600000:
            thresholds["be_" + _SITE_ID_OTHER.sub("_", str(site["name"]))] = milliseconds
    return thresholds


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
        # Previous (total, idle) jiffies. CPU is a rate, so the first poll
        # after a start has nothing to compare against and reports nothing.
        self._cpu_previous: Optional[Tuple[int, int]] = None
        # Per component: (cpu usage in microseconds, monotonic time) at the
        # previous poll, and the names of containers already looked up.
        self.cgroup_root = CGROUP_ROOT
        self.containers_dir = DOCKER_CONTAINERS_DIR
        # Keyed by cgroup directory: a service and its jobs share a name.
        self._component_previous: Dict[str, Tuple[int, float]] = {}
        self._container_names: Dict[str, str] = {}
        self.monitors: Dict[str, bool] = dict(MONITOR_DEFAULTS)
        # The machine beyond processor and memory.
        self.disk_path = DISK_PATH
        self.diskstats_path = DISKSTATS_PATH
        self.sys_block_root = SYS_BLOCK_ROOT
        self.sys_net_root = SYS_NET_ROOT
        self.thermal_root = THERMAL_ROOT
        # Per counter set, per device: the reading at the previous poll.
        self._counter_previous: Dict[str, Dict[str, Tuple[int, int]]] = {}
        # The sites' own slow-response thresholds, read again when the file
        # changes: (modification time, thresholds).
        self.websites_path = WEBSITES_FILE
        self._site_thresholds: Tuple[Optional[float], Dict[str, int]] = (None, {})
        # The access log's minute digests, from the adaptive protection
        # daemon; whether it answered the last time it was asked.
        self.guardd_socket = GUARDD_SOCKET_PATH
        self.digests_available: Optional[bool] = None
        self._last_digest_pull = 0.0

        self.last_poll_ts: Optional[int] = None
        self.last_flush_ts: Optional[int] = None
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0
        self.polls_total = 0
        self.buckets_written = 0
        self.buckets_dropped = 0

    # -- lifecycle --------------------------------------------------------

    def load_monitors(self) -> None:
        try:
            raw = json.loads(self.database.get_state(MONITORS_KEY, "{}") or "{}")
        except ValueError:
            raw = {}
        self.monitors = monitors_from(raw)

    def set_monitors(self, changes: Dict[str, bool]) -> Dict[str, bool]:
        """Apply the operator's choices, keep them, and start obeying them."""

        monitors = monitors_from({**self.monitors, **changes})
        self.database.set_state(MONITORS_KEY, json.dumps(monitors, sort_keys=True))
        with self._state_lock:
            self.monitors = monitors
            if not monitors["components"] or not monitors["machine"]:
                # Started again later, a component's first reading must not
                # be measured against one from before the pause.
                self._component_previous.clear()
            if not monitors["machine"]:
                self._cpu_previous = None
            # A counter read again after a pause must not be measured
            # against one from before it: the pause would land in one bucket.
            for name in ("disk", "network"):
                if not monitors[name]:
                    self._counter_previous.pop(name, None)
        return monitors

    def start(self) -> None:
        self.load_monitors()
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

            if time.monotonic() - self._last_digest_pull >= DIGEST_PULL_SECONDS:
                self._last_digest_pull = time.monotonic()
                try:
                    self.pull_digests(_utc_now())
                except Exception as exc:  # pylint: disable=broad-except
                    LOG.debug("log digests unavailable: %s", exc)

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

            if any(self.monitors[name] for name in HOST_MONITORS):
                self._observe_host(now)

        self._report_authelia(rows)

        self.polls_total += 1
        self.last_poll_ts = now
        self.consecutive_failures = 0
        self.last_error = None
        return observed

    def _report_authelia(self, rows: List[Dict[str, str]]) -> None:
        """authelia.unavailable, from HAProxy's own view of the portal.

        A level: reported on every poll, so it holds while it is true and
        recovers by itself; the rule's delay keeps a restart from paging
        anyone. A gateway without Authelia has no such row and says nothing.
        """
        alerts = getattr(self.storage, "alerts", None)
        if alerts is None:
            return
        for row in rows:
            if (row.get("pxname") or "").strip() != AUTHELIA_BACKEND:
                continue
            if (row.get("svname") or "").strip() != "BACKEND":
                continue
            status = (row.get("status") or "").strip().upper()
            down = not status.startswith("UP")
            with contextlib.suppress(Exception):
                alerts.observe(
                    "authelia.unavailable",
                    "authelia",
                    active=down,
                    summary=(
                        "Authelia is not answering: sites behind it cannot sign anyone in"
                        if down
                        else "Authelia is answering"
                    ),
                    detail=f"HAProxy reports {AUTHELIA_BACKEND} as {status or 'unknown'}",
                )
            return

    def _slow_thresholds(self) -> Dict[str, int]:
        try:
            changed = os.stat(self.websites_path).st_mtime
        except OSError:
            changed = None
        if changed != self._site_thresholds[0]:
            self._site_thresholds = (
                changed, site_slow_thresholds(self.websites_path) if changed is not None else {}
            )
        return self._site_thresholds[1]

    def _report_traffic(self, rows: Dict[int, Dict[str, int]]) -> None:
        """http.error_ratio and response.slow, per backend, per minute.

        Levels judged on the minute just closed; the rules' delay turns "this
        minute" into "for five minutes". A quiet minute (below the request
        floor) clears rather than raises, so a site nobody is using cannot
        hold an alert open.
        """
        alerts = getattr(self.storage, "alerts", None)
        if alerts is None:
            return
        config = self.config
        names = {object_id: key for key, object_id in self._object_ids.items()}
        own_thresholds = self._slow_thresholds()
        for object_id, row in rows.items():
            key = names.get(object_id)
            if not key or key[0] != "backend" or key[1] in TRAFFIC_ALERT_SKIP:
                continue
            proxy = key[1]
            requests = int(row.get("requests") or 0)
            enough = requests >= config.alert_min_requests
            with contextlib.suppress(Exception):
                if config.alert_error_ratio_percent > 0:
                    errors = int(row.get("resp_5xx") or 0)
                    percent = errors * 100 // requests if requests else 0
                    failing = enough and percent >= config.alert_error_ratio_percent
                    alerts.observe(
                        "http.error_ratio",
                        proxy,
                        active=failing,
                        summary=(
                            f"{proxy}: {percent}% of responses were server errors"
                            if failing
                            else f"{proxy}: server errors back below the threshold"
                        ),
                        detail=(
                            f"{errors} of {requests} responses in the last minute were 5xx "
                            f"(threshold {config.alert_error_ratio_percent}%)"
                            if failing
                            else ""
                        ),
                    )
                own = own_thresholds.get(proxy)
                threshold = config.alert_slow_response_ms if own is None else own
                if threshold > 0:
                    average = int(row.get("response_ms_avg") or 0)
                    slow = enough and average >= threshold
                    alerts.observe(
                        "response.slow",
                        proxy,
                        active=slow,
                        summary=(
                            f"{proxy}: responses take {average} ms on average"
                            if slow
                            else f"{proxy}: response time back below the threshold"
                        ),
                        detail=(
                            f"average over the last minute, {requests} requests "
                            f"(threshold {threshold} ms"
                            f"{' for this site' if own is not None else ''})"
                            if slow
                            else ""
                        ),
                    )
                elif own == 0:
                    # Off for this site: what it held clears now rather than
                    # waiting to go stale.
                    alerts.observe(
                        "response.slow",
                        proxy,
                        active=False,
                        summary=f"{proxy}: slow-response alerts are off for this site",
                    )

    def _observe_host(self, now: int) -> None:
        """The machine's own load, which no `show stat` row reports.

        Stored as an object like every other one, so it inherits the same
        bucketing, rollup and retention for free. Nothing in the read API
        selects kind 'host' except the chart that wants it, so it cannot leak
        into a traffic total.
        """

        machine = self.monitors["machine"]
        cpu = self._read_host_cpu() if machine else None
        busy = self._read_haproxy_busy() if machine else None
        memory = self._read_host_memory() if machine else None
        disk = read_disk_space(self.disk_path) if self.monitors["disk"] else None
        disk_io = (
            self._counter_delta("disk", read_disk_counters(self.diskstats_path, self.sys_block_root))
            if self.monitors["disk"] else None
        )
        network = (
            self._counter_delta("network", read_network_counters(self.sys_net_root))
            if self.monitors["network"] else None
        )
        temperature = read_temperature(self.thermal_root) if self.monitors["temperature"] else None
        readings = (cpu, busy, memory, disk, disk_io, network, temperature)
        if all(reading is None for reading in readings):
            return

        bucket = self._machine_bucket(HOST_KIND, "", "", now)
        bucket.samples += 1
        if cpu is not None:
            bucket.add_gauge("cpu", cpu)
        if busy is not None:
            bucket.add_gauge("haproxy_busy", busy)
        if memory is not None:
            bucket.add_gauge("memory", memory[0])
            bucket.add_gauge("memory_total", memory[1])
        if disk is not None:
            bucket.add_gauge("disk_used", disk[0])
            bucket.add_gauge("disk_total", disk[1])
        if disk_io is not None:
            bucket.add_counter("disk_read", disk_io[0])
            bucket.add_counter("disk_write", disk_io[1])
        if network is not None:
            bucket.add_counter("net_rx", network[0])
            bucket.add_counter("net_tx", network[1])
        if temperature is not None:
            bucket.add_gauge("temp", temperature)

        if not machine or not self.monitors["components"]:
            return
        try:
            self._observe_components(now)
        except Exception as exc:  # pylint: disable=broad-except
            # Supplementary, like the host load: never worth a poll.
            LOG.debug("component usage unavailable: %s", exc)

    def _counter_delta(
        self, name: str, current: Optional[Dict[str, Tuple[int, int]]]
    ) -> Optional[Tuple[int, int]]:
        """What a set of per-device counters grew by since the previous poll.

        Device by device, so a disk or card that appears adds nothing until
        its second reading and one whose counter went back (a driver reload)
        is left out of that one sum, instead of turning a whole reading into
        a spike or a guess. None on the first reading.
        """

        previous = self._counter_previous.get(name)
        if current is None:
            self._counter_previous.pop(name, None)
            return None
        self._counter_previous[name] = current
        if previous is None:
            return None
        first = second = 0
        for device, (now_a, now_b) in current.items():
            before = previous.get(device)
            if before is None or now_a < before[0] or now_b < before[1]:
                continue
            first += now_a - before[0]
            second += now_b - before[1]
        return first, second

    def sensors(self) -> Dict[str, bool]:
        """What this machine can be asked about at all: a virtual machine
        has no temperature, and the page should say so rather than draw 0."""

        return {"temperature": read_temperature(self.thermal_root) is not None}

    def _machine_bucket(self, kind: str, proxy: str, server: str, now: int) -> Bucket:
        key = (kind, proxy, server)
        object_id = self._object_ids.get(key)
        if object_id is None:
            object_id = self.database.object_id(kind, proxy, server, now)
            self._object_ids[key] = object_id
        bucket = self._buckets.get(object_id)
        if bucket is None:
            bucket = Bucket()
            self._buckets[object_id] = bucket
        return bucket

    @staticmethod
    def _read_host_memory() -> Optional[Tuple[int, int]]:
        """(used, total) KiB: what `free` calls used, everything not available.

        MemAvailable rather than MemFree, so page cache the kernel would hand
        back on demand does not read as a machine running out of memory.
        """

        values: Dict[str, int] = {}
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as handle:
                for line in handle:
                    name, _, rest = line.partition(":")
                    if name in ("MemTotal", "MemAvailable"):
                        values[name] = int(rest.split()[0])
                        if len(values) == 2:
                            break
        except (OSError, ValueError, IndexError) as exc:
            LOG.debug("cannot read /proc/meminfo: %s", exc)
            return None
        total = values.get("MemTotal", 0)
        if total <= 0 or "MemAvailable" not in values:
            return None
        return max(0, total - values["MemAvailable"]), total

    # -- components ---------------------------------------------------------

    def _component_cgroups(self) -> List[Tuple[str, str, str]]:
        """(name, group, cgroup directory) for every part of the gateway.

        Units come from system.slice by name; containers are found under
        either cgroup driver -- system.slice/docker-<id>.scope with systemd,
        docker/<id> with cgroupfs -- and named from Docker's own record,
        read once per container rather than on every poll.
        """

        found: List[Tuple[str, str, str]] = []
        containers: List[Tuple[str, str]] = []
        system = os.path.join(self.cgroup_root, "system.slice")
        try:
            entries = sorted(os.listdir(system))
        except OSError:
            entries = []
        for entry in entries:
            path = os.path.join(system, entry)
            if entry in ENGINE_UNITS:
                found.append((ENGINE_UNITS[entry], COMPONENT_ENGINE, path))
            elif entry.endswith(".service") and entry.startswith(COMPONENT_UNIT_PREFIXES):
                found.append(
                    (component_name(entry[: -len(".service")]), COMPONENT_SERVICE, path)
                )
            elif entry.startswith("docker-") and entry.endswith(".scope"):
                identifier = entry[len("docker-"): -len(".scope")]
                if _CONTAINER_ID.match(identifier):
                    containers.append((identifier, path))
        docker = os.path.join(self.cgroup_root, "docker")
        try:
            for entry in sorted(os.listdir(docker)):
                if _CONTAINER_ID.match(entry):
                    containers.append((entry, os.path.join(docker, entry)))
        except OSError:
            pass

        live = set()
        for identifier, path in containers:
            live.add(identifier)
            found.append((self._container_name(identifier), COMPONENT_CONTAINER, path))
        # Forget containers that are gone, so the cache cannot grow without end.
        for identifier in list(self._container_names):
            if identifier not in live:
                del self._container_names[identifier]
        return found[:MAX_COMPONENTS]

    def _container_name(self, identifier: str) -> str:
        name = self._container_names.get(identifier)
        if name is None:
            name = identifier[:12]
            try:
                with open(
                    os.path.join(self.containers_dir, identifier, "config.v2.json"),
                    "r", encoding="utf-8",
                ) as handle:
                    recorded = str(json.load(handle).get("Name") or "").lstrip("/")
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", recorded):
                    name = recorded
            except (OSError, ValueError, AttributeError) as exc:
                LOG.debug("cannot name container %s: %s", identifier[:12], exc)
            self._container_names[identifier] = name
        return name

    @staticmethod
    def _read_cgroup(path: str) -> Tuple[Optional[int], Optional[int]]:
        """(cpu usage in microseconds, memory in KiB) of one cgroup.

        Memory as `docker stats` counts it: the cgroup's charge minus the
        file cache it could drop at once. Without that, the helper that reads
        the access log would be charged for every page of it the kernel
        happens to keep cached.
        """

        usage: Optional[int] = None
        memory: Optional[int] = None
        try:
            with open(os.path.join(path, "cpu.stat"), "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("usage_usec "):
                        usage = int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            pass
        try:
            with open(os.path.join(path, "memory.current"), "r", encoding="utf-8") as handle:
                current = int(handle.read().strip())
            inactive = 0
            with open(os.path.join(path, "memory.stat"), "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("inactive_file "):
                        inactive = int(line.split()[1])
                        break
            memory = max(0, current - inactive) // MEMORY_UNIT
        except (OSError, ValueError, IndexError):
            pass
        return usage, memory

    def _observe_components(self, now: int) -> None:
        moment = time.monotonic()
        processors = os.cpu_count() or 1
        # Each cgroup is measured on its own -- a job's counter starts at zero
        # and is gone a minute later -- and the readings of one service and
        # its jobs are added up.
        readings: Dict[Tuple[str, str], List[Optional[int]]] = {}
        seen = set()
        for name, group, path in self._component_cgroups():
            if path in seen:
                continue
            seen.add(path)
            usage, memory = self._read_cgroup(path)
            if usage is None and memory is None:
                continue
            cpu: Optional[int] = None
            if usage is not None:
                previous = self._component_previous.get(path)
                self._component_previous[path] = (usage, moment)
                if previous is not None:
                    used = usage - previous[0]
                    elapsed = moment - previous[1]
                    # A restarted unit starts its counter again: no reading
                    # rather than a negative one.
                    if used >= 0 and elapsed > 0:
                        cpu = round(100 * CPU_SCALE * used / (elapsed * 1e6 * processors))
            total = readings.setdefault((name, group), [None, None])
            if cpu is not None:
                total[0] = (total[0] or 0) + cpu
            if memory is not None:
                total[1] = (total[1] or 0) + memory
        for (name, group), (cpu, memory) in readings.items():
            bucket = self._machine_bucket(COMPONENT_KIND, name, group, now)
            bucket.samples += 1
            if cpu is not None:
                bucket.add_gauge("cpu", min(100 * CPU_SCALE, cpu))
            if memory is not None:
                bucket.add_gauge("memory", memory)
        for path in list(self._component_previous):
            if path not in seen:
                del self._component_previous[path]

    def _read_host_cpu(self) -> Optional[int]:
        """Host CPU since the previous poll, in tenths of a percent.

        None rather than zero whenever the answer would be a guess: the first
        poll after a start, a counter that went backwards, an unreadable
        /proc. Load is supplementary here, and failing to read it must never
        cost the traffic sample that shares this poll.
        """

        try:
            with open("/proc/stat", "r", encoding="utf-8") as handle:
                fields = handle.readline().split()
        except OSError as exc:
            LOG.debug("cannot read /proc/stat: %s", exc)
            return None
        if len(fields) < 9 or fields[0] != "cpu":
            return None
        try:
            values = [int(value) for value in fields[1:9]]
        except ValueError:
            return None

        # iowait counts as idle: the processor was available, the disk was
        # not, and calling that "busy" would blame the wrong component.
        idle = values[3] + values[4]
        total = sum(values)
        previous = self._cpu_previous
        self._cpu_previous = (total, idle)
        if previous is None:
            return None
        total_delta = total - previous[0]
        idle_delta = idle - previous[1]
        if total_delta <= 0:
            return None
        busy = max(0, total_delta - idle_delta)
        return min(100 * CPU_SCALE, round(100 * CPU_SCALE * busy / total_delta))

    def _read_haproxy_busy(self) -> Optional[int]:
        """How much of its own time HAProxy spent working, in tenths.

        The host figure cannot answer this. A gateway can idle at 10% while
        HAProxy's event loop is saturated and every request waits behind it,
        because the other cores have nothing to do with proxying.
        """

        try:
            payload = runtime_command(self.config.haproxy_socket, "show info")
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("show info failed: %s", exc)
            return None
        for line in payload.splitlines():
            name, separator, value = line.partition(":")
            if separator and name.strip() == "Idle_pct":
                idle = max(0, min(100, _to_int(value)))
                return (100 - idle) * CPU_SCALE
        return None

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
        # Judged on the minute even when it cannot be written: a full disk
        # must not silence the alerts about the sites.
        self._report_traffic(rows)
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

    def pull_digests(self, now: int) -> int:
        """Store the minutes of the access log's digest completed since the
        last ask: histograms per backend, refusals on the edge row.

        Nothing is asked while both monitors are off or writing is paused. A
        daemon that does not answer -- adaptive protection switched off, so
        nothing reads the log -- is remembered, for the page to say so.
        """

        if not any(self.monitors[name] for name in DIGEST_MONITORS):
            return 0
        if self.storage.writes_paused:
            return 0
        since = _to_int(self.database.get_state(DIGEST_CURSOR_KEY, "0"))
        try:
            payload = unix_get_json(self.guardd_socket, f"/api/v1/guard/digest?since={since}")
        except (OSError, ValueError, RuntimeError):
            self.digests_available = False
            raise
        self.digests_available = True
        if list(payload.get("bounds_ms") or []) != list(DIGEST_BOUNDS_MS):
            # A daemon from another release cuts the histogram elsewhere;
            # adding its buckets to ours would be a wrong answer, not a rough one.
            LOG.warning("guardd's histogram differs from ours; digests skipped")
            return 0
        written = 0
        newest = since
        for minute in payload.get("minutes") or []:
            try:
                bucket_ts = int(minute.get("ts"))
            except (TypeError, ValueError):
                continue
            if bucket_ts <= since:
                continue
            newest = max(newest, bucket_ts)
            if self.monitors["percentiles"]:
                rows: Dict[int, List[int]] = {}
                for proxy, counts in (minute.get("backends") or {}).items():
                    if (not isinstance(counts, list) or len(counts) != len(HISTOGRAM_COLUMNS)
                            or self.config.excluded(str(proxy))):
                        continue
                    object_id = self._object_for("backend", str(proxy)[:200], now)
                    rows[object_id] = [max(0, int(value)) for value in counts]
                self.database.write_latency(bucket_ts, rows)
                written += len(rows)
            if self.monitors["refusals"]:
                refused = minute.get("refused") or {}
                row = {column: 0 for column in METRIC_COLUMNS}
                row["samples"] = 1
                for key in ("geo", "banned", "rate", "other"):
                    row[f"refused_{key}"] = max(0, _to_int(refused.get(key, 0)))
                self.database.write_buckets(bucket_ts, {self._object_for(EDGE_KIND, "", now): row})
                written += 1
        if newest > since:
            self.database.set_state(DIGEST_CURSOR_KEY, str(newest))
        return written

    def _object_for(self, kind: str, proxy: str, now: int) -> int:
        key = (kind, proxy, "")
        object_id = self._object_ids.get(key)
        if object_id is None:
            object_id = self.database.object_id(kind, proxy, "", now)
            self._object_ids[key] = object_id
        return object_id

    def run_maintenance(self) -> Dict[str, Any]:
        now = _utc_now()
        rolled = self.database.rollup_hours(now - (now % HOUR_SECONDS))
        lagged = now - LATENCY_ROLLUP_LAG_SECONDS
        rolled += self.database.rollup_latency_hours(lagged - (lagged % HOUR_SECONDS))
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


# How long one connection may keep a handler thread waiting on it: for the
# request, or for the caller to take the answer. Callers are local and send a
# whole request at once; one that connected and went quiet used to hold its
# thread for good. Processing time is not limited by this.
REQUEST_TIMEOUT_SECONDS = 30


class MetricsHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-metricsd/1.0"
    timeout = REQUEST_TIMEOUT_SECONDS

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

        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        if urlparse(self.path).path == "/api/v1/metrics/monitors":
            self._set_monitors()
            return
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

    def _set_monitors(self) -> None:
        """Which monitors run: {"monitors": {"machine": false, ...}}.

        Only the names given change; an unknown name or a value that is not
        true or false is refused, so a typo cannot quietly switch nothing.
        """

        collector: Collector = self.server.collector  # type: ignore[attr-defined]
        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
            if length <= 0 or length > 4096:
                raise ValueError("invalid Content-Length")
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            changes = payload.get("monitors") if isinstance(payload, dict) else None
            if not isinstance(changes, dict) or not changes:
                raise ValueError("monitors must be a non-empty object")
            for name, value in changes.items():
                if name not in MONITOR_DEFAULTS:
                    raise ValueError(f"unknown monitor: {str(name)[:40]}")
                if not isinstance(value, bool):
                    raise ValueError(f"{name} must be true or false")
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        try:
            monitors = collector.set_monitors(changes)
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        self._send_json(200, {"ok": True, "monitors": monitors})

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
            wanted = (query.get("components", ["1"])[0] or "1").strip().lower()
            try:
                payload = database.series(
                    chart=chart,
                    site=self._site(query),
                    since=since,
                    until=until,
                    components=wanted not in ("0", "false", "no"),
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

        if path == "/api/v1/metrics/backends":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.backend_totals(since=since, until=until)
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
                    # Deliberately not scoped by site: one machine's load is
                    # not divisible among the sites it serves.
                    "load": database.host_load(since=since, until=until),
                    "health": database.backend_health(),
                    "collector": collector.health(),
                    "storage": collector.storage.report(until),
                    "monitors": dict(collector.monitors),
                    "sensors": collector.sensors(),
                    # None until asked: the page then shows the charts.
                    "log_digests": {"available": collector.digests_available},
                }
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/monitors":
            self._send_json(200, {"ok": True, "monitors": dict(collector.monitors)})
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
