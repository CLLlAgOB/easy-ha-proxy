"""SQLite historical metrics database, migrations, and query engine."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    ABSENT_SPAN,
    BUCKET_SECONDS,
    CHART_SERIES,
    COMPONENT_COLUMNS,
    COMPONENT_CONTAINER,
    COMPONENT_SERVICE,
    CPU_SCALE,
    DIGEST_BOUNDS_MS,
    DISKSTATS_SECTOR,
    EDGE_KIND,
    HISTOGRAM_COLUMNS,
    HOST_CHARTS,
    HOUR_SECONDS,
    LOG,
    MAX_CHART_POINTS,
    MAX_TIMELINE_SPANS,
    MEMORY_UNIT,
    METRIC_COLUMNS,
    PERCENTILES,
    REMOVED_STATE,
    SCHEMA_VERSION,
    STABLE_GROWTH_FLOOR_BYTES,
    STABLE_GROWTH_FRACTION,
    STORAGE_SAMPLE_INTERVAL_SECONDS,
    STORAGE_SAMPLE_RETENTION_SECONDS,
    SUMMARY_COLUMNS,
    TEMPERATURE_RANGE_MILLI,
    _ROLLUP_MAX,
    _ROLLUP_SUM,
    _ROLLUP_WAVG,
    _aggregate_sql,
    _from_storage,
    _to_int,
    choose_resolution,
    component_name,
)

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


def _compress_spans(
    spans: List[Dict[str, Any]], since: int, until: int, slices: int
) -> List[Dict[str, Any]]:
    """The same history in at most a few bars per slice of the window.

    Cutting the list after the first MAX_TIMELINE_SPANS transitions painted
    the state of the last one kept to the end of the window: a backup server
    flapping a few hundred times a day read as down since the evening before,
    31% available, while HAProxy said it was up. Here every slice keeps how
    long it was up, down and absent, in the order those first occurred in
    it, so the totals stay exact and a run of short outages still reads as
    one (the page stripes it, monitoring_core.timelinePieces).
    """

    length = max(1, until - since)
    result: List[Dict[str, Any]] = []
    index = 0
    for number in range(slices):
        start = since + length * number // slices
        end = since + length * (number + 1) // slices
        if end <= start:
            continue
        while index < len(spans) and spans[index]["end"] <= start:
            index += 1
        seconds: Dict[str, int] = {}
        order: List[str] = []
        worst: Dict[str, int] = {}
        probe = index
        while probe < len(spans) and spans[probe]["start"] < end:
            span = spans[probe]
            overlap = min(end, span["end"]) - max(start, span["start"])
            probe += 1
            if overlap <= 0:
                continue
            state_name = span["state"]
            group = state_name if state_name in ("UP", ABSENT_SPAN) else "OTHER"
            if group not in seconds:
                seconds[group] = 0
                order.append(group)
            seconds[group] += overlap
            if group == "OTHER":
                worst[state_name] = worst.get(state_name, 0) + overlap
        cursor = start
        for group in order:
            name = max(worst, key=worst.__getitem__) if group == "OTHER" else group
            _close_span(result, cursor, cursor + seconds[group], name)
            cursor += seconds[group]
    return result


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
            self._add_object_address(cursor)
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
    def _add_object_address(cursor: sqlite3.Cursor) -> None:
        """The address a server was last reported at (HAProxy's addr).

        Additive like the metric columns and for the same reason: an older
        build ignores it. It lets a renamed server keep its history
        (Collector._continue_renamed).
        """

        existing = {str(row["name"]) for row in cursor.execute("PRAGMA table_info(objects)")}
        if "address" not in existing:
            cursor.execute("ALTER TABLE objects ADD COLUMN address TEXT NOT NULL DEFAULT ''")
            LOG.info("Added objects.address")

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

    def object_exists(self, kind: str, proxy: str, server: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM objects WHERE kind = ? AND proxy = ? AND server = ?",
                (kind, proxy, server),
            ).fetchone()
        return row is not None

    def load_server_addresses(self) -> Dict[int, str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, address FROM objects WHERE kind = 'server' AND address != ''"
            ).fetchall()
        return {int(row["id"]): str(row["address"]) for row in rows}

    def set_object_address(self, object_id: int, address: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE objects SET address = ? WHERE id = ?", (address, object_id)
            )

    def rename_candidate(
        self, proxy: str, address: str, present: set
    ) -> Optional[Tuple[int, str]]:
        """The one server of this backend last seen at this address and no
        longer reported under its own name, or None when it is not one."""

        with self._lock:
            rows = self._conn.execute(
                "SELECT id, server FROM objects "
                "WHERE kind = 'server' AND proxy = ? AND address = ?",
                (proxy, address),
            ).fetchall()
        candidates = [
            (int(row["id"]), str(row["server"]))
            for row in rows
            if str(row["server"]) not in present
        ]
        return candidates[0] if len(candidates) == 1 else None

    def rename_server(self, object_id: int, server: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE objects SET server = ? WHERE id = ?", (server, object_id)
            )

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
        with self._lock, self._conn:
            self._store_baselines_locked(baselines)

    def _store_baselines_locked(
        self, baselines: Dict[Tuple[int, str], Tuple[int, int]]
    ) -> None:
        if not baselines:
            return
        payload = [
            (object_id, metric, value, updated_ts)
            for (object_id, metric), (value, updated_ts) in baselines.items()
        ]
        self._conn.executemany(
            "INSERT INTO counter_baseline (object_id, metric, value, updated_ts) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT (object_id, metric) DO UPDATE SET "
            "value = excluded.value, updated_ts = excluded.updated_ts",
            payload,
        )

    # -- metrics ----------------------------------------------------------

    def write_buckets(
        self, bucket_ts: int, rows: Dict[int, Dict[str, int]], *, merge: bool = False,
        baselines: Optional[Dict[Tuple[int, str], Tuple[int, int]]] = None,
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
            if merge:
                # Poll flushes contain only the samples since the last flush.
                # A stop/start (or another forced flush) can split one minute
                # into several fragments. Merge those with the same rules as
                # the hourly rollup. Complete edge digests still replace their
                # row, so fetching the same digest again stays idempotent.
                updates = ["samples = metric_1m.samples + excluded.samples"]
                updates.extend(
                    f"{column} = metric_1m.{column} + excluded.{column}"
                    for column in _ROLLUP_SUM
                )
                updates.extend(
                    f"{column} = MAX(metric_1m.{column}, excluded.{column})"
                    for column in _ROLLUP_MAX
                )
                updates.extend(
                    f"{column} = CAST(COALESCE((metric_1m.{column} * metric_1m.samples "
                    f"+ excluded.{column} * excluded.samples) "
                    "/ NULLIF(metric_1m.samples + excluded.samples, 0), 0) AS INTEGER)"
                    for column in _ROLLUP_WAVG
                )
                self._conn.executemany(
                    f"INSERT INTO metric_1m ({columns}) VALUES ({placeholders}) "
                    "ON CONFLICT (bucket_ts, object_id) DO UPDATE SET "
                    + ", ".join(updates),
                    payload,
                )
            else:
                self._conn.executemany(
                    f"INSERT OR REPLACE INTO metric_1m ({columns}) "
                    f"VALUES ({placeholders})",
                    payload,
                )
            if baselines is not None:
                # The saved counter and the delta credited to this minute
                # must advance together, including on a failed write/restart.
                self._store_baselines_locked(baselines)

    def record_state_change(
        self, object_id: int, previous: str, state: str, now: int
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO server_state_events (ts, object_id, previous_state, state) "
                "VALUES (?, ?, ?, ?)",
                (now, object_id, previous, state),
            )

    def last_observed(self, object_id: int) -> Optional[int]:
        """When an object was last reported, judged by its stored history.

        Used to date the removal of an object that was already gone when this
        daemon started, rather than dating it by the restart.
        """

        with self._lock:
            minute = self._conn.execute(
                "SELECT MAX(bucket_ts) FROM metric_1m WHERE object_id = ?", (object_id,)
            ).fetchone()[0]
            hour = None
            if minute is None:
                hour = self._conn.execute(
                    "SELECT MAX(bucket_ts) FROM metric_1h WHERE object_id = ?", (object_id,)
                ).fetchone()[0]
            event = self._conn.execute(
                "SELECT MAX(ts) FROM server_state_events WHERE object_id = ?", (object_id,)
            ).fetchone()[0]
        candidates = [int(event)] if event is not None else []
        if minute is not None:
            candidates.append(int(minute) + BUCKET_SECONDS)
        elif hour is not None:
            candidates.append(int(hour))
        return max(candidates) if candidates else None

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
                "GROUP BY object_id) AND e.state != ? ORDER BY o.proxy, o.server",
                (REMOVED_STATE,),
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
        compressed = False
        result: List[Dict[str, Any]] = []

        def drawn(state_name: str) -> str:
            return ABSENT_SPAN if state_name == REMOVED_STATE else state_name

        for row in objects:
            object_id = int(row["id"])
            changes = by_object.get(object_id, [])
            state = initial.get(object_id)
            if state is None and not changes:
                # Never observed in or before the window: nothing to draw.
                continue
            if state in (None, REMOVED_STATE) and all(
                next_state == REMOVED_STATE for _, next_state in changes
            ):
                # Removed before the window opened and never back.
                continue

            spans: List[Dict[str, Any]] = []
            if state is None:
                # First reported inside the window; before that it did not
                # exist, which is not the same as having been up.
                cursor = max(since, changes[0][0])
                _close_span(spans, since, cursor, ABSENT_SPAN)
                current = changes[0][1]
            else:
                cursor = since
                current = state
            removed_at: Optional[int] = None
            for ts, next_state in changes:
                _close_span(spans, cursor, ts, drawn(current))
                cursor = max(cursor, ts)
                current = next_state
                removed_at = ts if next_state == REMOVED_STATE else None
            _close_span(spans, cursor, until, drawn(current))

            absent = sum(
                span["end"] - span["start"] for span in spans if span["state"] == ABSENT_SPAN
            )
            downtime = sum(
                span["end"] - span["start"]
                for span in spans
                if span["state"] not in ("UP", ABSENT_SPAN)
            )
            present = max(1, window - absent)
            if len(spans) > MAX_TIMELINE_SPANS:
                spans = _compress_spans(spans, since, until, MAX_TIMELINE_SPANS)
                compressed = True
            entry = {
                "kind": str(row["kind"]),
                "proxy": str(row["proxy"]),
                "server": str(row["server"]),
                "current_state": current,
                "transitions": sum(
                    1 for _, next_state in changes if next_state != REMOVED_STATE
                ),
                "downtime_seconds": downtime,
                "availability": round(max(0.0, (present - downtime) / present), 5),
                "spans": spans,
            }
            if current == REMOVED_STATE and removed_at is not None:
                entry["removed_at"] = removed_at
            result.append(entry)
        # Nothing is left out any more; "truncated" stays for older pages.
        return {"objects": result, "truncated": False, "compressed": compressed}

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
