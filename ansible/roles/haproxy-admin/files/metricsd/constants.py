"""Constants, storage safety, and read-API window helpers for metricsd."""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

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
# window. Past this many bars the timeline is redrawn in this many slices of
# the window, each keeping its exact up and down seconds (_compress_spans).
MAX_TIMELINE_SPANS = 200
# A backend or server HAProxy stopped reporting -- a renamed server, a deleted
# site -- is recorded once in this state, after this many polls in a row
# without it, so its last state is not carried forward for ever.
REMOVED_STATE = "REMOVED"
RETIRE_AFTER_POLLS = 3
# A bar for the time an object did not exist: before it was first reported
# and after it was removed. It is neither up nor down.
ABSENT_SPAN = "ABSENT"

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
    "be_stats",
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
