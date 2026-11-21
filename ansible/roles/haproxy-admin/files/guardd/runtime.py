"""Configuration loading and HAProxy runtime admin-socket client."""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from .constants import (
    DEFAULT_MAX_PATHS_PER_IP,
    DEFAULT_MAX_TRACKED_IPS,
    LOG,
    MODE_MONITOR,
    RUNTIME_MAX_BYTES,
    RUNTIME_TIMEOUT_SECONDS,
    SUPPORTED_MODES,
    _clamp_int,
    _safe_int,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardConfig:
    mode: str = MODE_MONITOR
    poll_interval_seconds: int = 10
    haproxy_socket: str = "/run/haproxy/admin.sock"
    log_file: str = "/var/log/haproxy.log"
    authelia_log_file: str = ""
    log_read_bytes_per_cycle: int = 4 * 1024 * 1024
    # The live activity page keeps the latest requests in memory. Bounded by
    # count and by age, whichever bites first; 0 records turns it off.
    live_buffer_records: int = 100_000
    live_buffer_seconds: int = 3600
    whitelist_files: Tuple[str, ...] = (
        "/etc/haproxy/whitelist.ip",
        "/etc/haproxy/admin.allow",
        "/etc/haproxy/geoip/whitelist.geo",
    )
    trusted_networks: Tuple[str, ...] = ()
    max_tracked_ips: int = DEFAULT_MAX_TRACKED_IPS
    max_paths_per_ip: int = DEFAULT_MAX_PATHS_PER_IP
    event_retention_days: int = 30
    maintenance_interval_seconds: int = 300
    # The request log is a separate concern that happens to need the same read
    # of the same file. It has its own switch, its own database and its own
    # budget, so turning it on cannot change how the engine scores anything.
    request_log_enabled: bool = False
    request_log_retention_days: int = 3
    request_log_max_bytes: int = 256 * 1024 * 1024
    request_log_reserved_free_bytes: int = 512 * 1024 * 1024


class ConfigError(ValueError):
    """A configuration that must not be silently repaired."""


def load_config(path: str) -> GuardConfig:
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

    mode = str(raw.get("mode") or MODE_MONITOR).strip().lower()
    if mode not in SUPPORTED_MODES:
        LOG.warning("Unknown mode %r; falling back to %s", mode, MODE_MONITOR)
        mode = MODE_MONITOR

    limits = raw.get("limits")
    limits = limits if isinstance(limits, dict) else {}
    sources = raw.get("sources")
    sources = sources if isinstance(sources, dict) else {}
    exclusions = raw.get("exclusions")
    exclusions = exclusions if isinstance(exclusions, dict) else {}
    request_log = raw.get("request_log")
    request_log = request_log if isinstance(request_log, dict) else {}

    def _string_tuple(value: Any, fallback: Tuple[str, ...]) -> Tuple[str, ...]:
        if not isinstance(value, list):
            return fallback
        items = tuple(str(item).strip() for item in value if str(item).strip())
        return items if items else fallback

    return GuardConfig(
        mode=mode,
        poll_interval_seconds=_clamp_int(
            raw.get("poll_interval_seconds"), default=10, min_v=5, max_v=60
        ),
        haproxy_socket=str(
            sources.get("haproxy_socket") or "/run/haproxy/admin.sock"
        ).strip(),
        log_file=str(
            sources.get("log_file") or "/var/log/haproxy.log"
        ).strip(),
        authelia_log_file=str(sources.get("authelia_log_file") or "").strip(),
        log_read_bytes_per_cycle=_clamp_int(
            limits.get("log_read_bytes_per_cycle"),
            default=4 * 1024 * 1024,
            min_v=64 * 1024,
            max_v=64 * 1024 * 1024,
        ),
        live_buffer_records=_clamp_int(
            limits.get("live_buffer_records"), default=100_000, min_v=0, max_v=1_000_000
        ),
        live_buffer_seconds=_clamp_int(
            limits.get("live_buffer_seconds"), default=3600, min_v=60, max_v=6 * 3600
        ),
        whitelist_files=_string_tuple(
            exclusions.get("whitelist_files"),
            GuardConfig.whitelist_files,
        ),
        trusted_networks=_string_tuple(exclusions.get("trusted_networks"), ()),
        max_tracked_ips=_clamp_int(
            limits.get("max_tracked_ips"),
            default=DEFAULT_MAX_TRACKED_IPS,
            min_v=1000,
            max_v=500000,
        ),
        request_log_enabled=bool(request_log.get("enabled")),
        request_log_retention_days=_clamp_int(
            request_log.get("retention_days"), default=3, min_v=1, max_v=30
        ),
        request_log_max_bytes=_clamp_int(
            request_log.get("max_bytes"),
            default=256 * 1024 * 1024,
            min_v=16 * 1024 * 1024,
            max_v=16 * 1024 * 1024 * 1024,
        ),
        request_log_reserved_free_bytes=_clamp_int(
            request_log.get("reserved_free_bytes"),
            default=512 * 1024 * 1024,
            min_v=64 * 1024 * 1024,
            max_v=64 * 1024 * 1024 * 1024,
        ),
        max_paths_per_ip=_clamp_int(
            limits.get("max_paths_per_ip"),
            default=DEFAULT_MAX_PATHS_PER_IP,
            min_v=8,
            max_v=256,
        ),
        event_retention_days=_clamp_int(
            limits.get("event_retention_days"), default=30, min_v=1, max_v=365
        ),
        maintenance_interval_seconds=_clamp_int(
            raw.get("maintenance_interval_seconds"),
            default=300,
            min_v=60,
            max_v=3600,
        ),
    )


# ---------------------------------------------------------------------------
# HAProxy runtime access
# ---------------------------------------------------------------------------


class RuntimeAnswerTooLarge(OSError):
    """HAProxy's answer did not fit RUNTIME_MAX_BYTES: what was read is not all."""


class TableUnreadable(OSError):
    """A `show table` answer that is not the table: an error, or nothing."""


def runtime_command(socket_path: str, command: str) -> str:
    """Send one command to the runtime socket and return the whole answer.

    An answer larger than RUNTIME_MAX_BYTES raises RuntimeAnswerTooLarge
    instead of coming back cut short: a table read in part used to be taken
    for the whole table, and a row past the cut for a row that was not there
    (R10).
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(RUNTIME_TIMEOUT_SECONDS)
        sock.connect(socket_path)
        sock.sendall(f"{command}\n".encode("utf-8"))
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > RUNTIME_MAX_BYTES:
                raise RuntimeAnswerTooLarge(
                    f"HAProxy's answer to {command.split(' key ')[0]!r} is larger than "
                    f"{RUNTIME_MAX_BYTES // (1024 * 1024)} MiB"
                )
    return b"".join(chunks).decode("utf-8", "replace")


def read_table(socket_path: str, table: str, selector: str = "") -> Dict[str, Dict[str, str]]:
    """A stick table's rows, or TableUnreadable when the answer is not it.

    HAProxy opens every table answer with "# table: <name>,"; anything else
    -- "No such table", a refusal, nothing -- used to parse as an empty
    table, so a ban that could not be read was taken for one that was not
    there, and its expiry dropped from the schedule (R10).
    """
    command = f"show table {table}{(' ' + selector) if selector else ''}"
    payload = runtime_command(socket_path, command)
    if selector.startswith("key ") and not payload.strip():
        # One key asked for and not there: HAProxy 2.8, 3.2 and 3.4 all
        # answer that with an empty line and no header. Taken for an
        # unreadable table, it turned an operator's unban of an address no
        # longer in the table into "HAProxy refused". A missing table still
        # answers "No such table", and a whole table always has its header.
        return {}
    first = payload.split("\n", 1)[0].strip()
    if not first.startswith(f"# table: {table},"):
        raise TableUnreadable(f"HAProxy did not return table {table}: {first[:120]!r}")
    return parse_table(payload)


_TABLE_ROW = re.compile(r"^0x[0-9a-f]+:\s+key=(?P<key>\S+)\s+(?P<rest>.*)$")
_TABLE_FIELD = re.compile(r"(?P<name>[a-z_0-9()]+)=(?P<value>\S+)")


def parse_table(payload: str) -> Dict[str, Dict[str, str]]:
    """Parse `show table <name>` into {key: {field: value}}."""

    rows: Dict[str, Dict[str, str]] = {}
    for line in payload.splitlines():
        match = _TABLE_ROW.match(line.strip())
        if match is None:
            continue
        fields = {
            item.group("name"): item.group("value")
            for item in _TABLE_FIELD.finditer(match.group("rest"))
        }
        rows[match.group("key")] = fields
    return rows


def banned_now(socket_path: str) -> Set[str]:
    """Every address tbl_ban refuses right now, whoever put it there.

    Not only this daemon's bans: a ban made by hand on the panel or by
    HAProxy's own rules refuses the address just the same, and that is what
    an operator filtering for "banned" means.
    """
    try:
        rows = read_table(socket_path, "tbl_ban")
    except OSError as exc:
        raise RuntimeError(f"cannot read the ban table: {exc}") from exc
    return {
        ip for ip, fields in rows.items()
        if _safe_int(fields.get("gpc0")) > 0
    }


def list_tables(payload: str) -> List[str]:
    names: List[str] = []
    for line in payload.splitlines():
        match = re.search(r"\btable:\s*([^\s,]+)", line)
        if match:
            names.append(match.group(1))
    return names
