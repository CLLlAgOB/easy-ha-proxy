"""Configuration loading and HAProxy runtime socket client for metricsd."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    DEFAULT_EXCLUDE_EXACT,
    DEFAULT_EXCLUDE_PREFIX,
    DEFAULT_WAL_SOFT_LIMIT_BYTES,
    LOG,
    RUNTIME_MAX_BYTES,
    RUNTIME_TIMEOUT_SECONDS,
    _clamp_int,
    parse_size,
)

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
