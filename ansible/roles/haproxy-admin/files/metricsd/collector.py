"""Periodic HAProxy and host metrics collector, alerts, and monitors."""

from __future__ import annotations

import contextlib
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    AUTO_MAX_DATABASE_BYTES,
    AUTO_MAX_DATABASE_FRACTION,
    AUTO_RESERVE_CEILING_BYTES,
    AUTO_RESERVE_FLOOR_BYTES,
    AUTO_RESERVE_FRACTION,
    AlertClient,
    BASELINE_MAX_GAP_SECONDS,
    BUCKET_SECONDS,
    CGROUP_ROOT,
    COMPONENT_CONTAINER,
    COMPONENT_ENGINE,
    COMPONENT_KIND,
    COMPONENT_SERVICE,
    COMPONENT_UNIT_PREFIXES,
    COUNTER_COLUMNS,
    CPU_SCALE,
    DIGEST_BOUNDS_MS,
    DIGEST_CURSOR_KEY,
    DIGEST_PULL_SECONDS,
    DISKSTATS_PATH,
    DISK_PATH,
    DOCKER_CONTAINERS_DIR,
    EDGE_KIND,
    ENGINE_UNITS,
    GAUGE_COLUMNS,
    GUARDD_SOCKET_PATH,
    HISTOGRAM_COLUMNS,
    HOST_KIND,
    HOUR_SECONDS,
    LATENCY_ROLLUP_LAG_SECONDS,
    LOG,
    MAX_COMPONENTS,
    MEMORY_UNIT,
    METRIC_COLUMNS,
    OTHER_RESPONSE_COLUMNS,
    PRESSURE_DATABASE_FRACTION,
    REMOVED_STATE,
    RESUME_DATABASE_FRACTION,
    RESUME_RESERVE_MARGIN_FILESYSTEM_FRACTION,
    RESUME_RESERVE_MARGIN_FLOOR,
    RESUME_RESERVE_MARGIN_FRACTION,
    RETENTION_LADDER,
    RETIRE_AFTER_POLLS,
    STATE_CRITICAL,
    STATE_NORMAL,
    STATE_PRESSURE,
    STATE_WARNING,
    SYS_BLOCK_ROOT,
    SYS_NET_ROOT,
    THERMAL_ROOT,
    WARNING_DATABASE_FRACTION,
    _CONTAINER_ID,
    _to_int,
    _utc_now,
    component_name,
)
from .runtime import MetricsConfig, classify, parse_show_stat, runtime_command
from .storage import (
    Bucket,
    DIGEST_MONITORS,
    HOST_MONITORS,
    MONITORS_KEY,
    MONITOR_DEFAULTS,
    MetricsDatabase,
    monitors_from,
    read_disk_counters,
    read_disk_space,
    read_network_counters,
    read_temperature,
    unix_get_json,
)

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
        self._bucket_reported = False
        self._last_states: Dict[int, str] = {}
        # Objects HAProxy has stopped reporting: when they were first missed
        # and in how many polls in a row (see _retire_missing).
        self._missing: Dict[int, Tuple[int, int]] = {}
        self._seen_since_start: set = set()
        # The address each server was last reported at, to tell a renamed
        # server from a new one.
        self._addresses: Dict[int, str] = {}
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
        self._addresses = self.database.load_server_addresses()
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

            self._bucket_reported = False
            observed = 0
            present: set = set()
            self._continue_renamed(rows)
            for row in rows:
                identity = classify(row)
                if identity is None:
                    continue
                kind, proxy, server = identity
                if self.config.excluded(proxy):
                    continue
                self._observe(kind, proxy, server, row, now)
                observed += 1
                if kind in ("server", "backend"):
                    present.add(self._object_ids[identity])
            self._retire_missing(present, now)

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
        if kind == "server":
            address = (row.get("addr") or "").strip()
            if address and self._addresses.get(object_id) != address:
                self._addresses[object_id] = address
                self.database.set_object_address(object_id, address)

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

    def _continue_renamed(self, rows: List[Dict[str, str]]) -> None:
        """A server reported under a new name at the address of one that is
        gone from the same backend is that server, renamed.

        Moving a site to a backend set renamed its servers (main to srv1, bkp
        to backup1) while they stayed the same machines. The history now
        carries on under the new name instead of starting over beside a
        removed copy. Only an unambiguous match: one server of the backend at
        that address, absent under its old name, and the new name unknown.
        """

        names: Dict[str, set] = {}
        for row in rows:
            identity = classify(row)
            if identity and identity[0] == "server":
                names.setdefault(identity[1], set()).add(identity[2])
        for row in rows:
            identity = classify(row)
            if identity is None or identity[0] != "server" or identity in self._object_ids:
                continue
            _, proxy, server = identity
            address = (row.get("addr") or "").strip()
            if not address or self.config.excluded(proxy):
                continue
            if self.database.object_exists("server", proxy, server):
                continue
            candidate = self.database.rename_candidate(proxy, address, names[proxy])
            if candidate is None:
                continue
            object_id, old = candidate
            self.database.rename_server(object_id, server)
            self._object_ids.pop(("server", proxy, old), None)
            self._object_ids[identity] = object_id
            LOG.info("Server %s/%s continues as %s (same address %s)", proxy, old, server, address)

    def _retire_missing(self, present: set, now: int) -> None:
        """End the timeline of a backend or server HAProxy no longer reports.

        Its last state used to be carried forward for ever: after a site
        moved to a backend set its servers were renamed, and the old names
        stayed "UP" on the availability card next to the new ones, as did
        sites deleted weeks before. A few polls in a row without it, so a
        partial reply cannot retire anything.
        """

        self._seen_since_start.update(present)
        for object_id, state in list(self._last_states.items()):
            if object_id in present or state == REMOVED_STATE:
                self._missing.pop(object_id, None)
                continue
            first, count = self._missing.get(object_id, (now, 0))
            count += 1
            if count < RETIRE_AFTER_POLLS or self.storage.writes_paused:
                self._missing[object_id] = (first, count)
                continue
            self._missing.pop(object_id, None)
            if object_id not in self._seen_since_start:
                # Already gone when this daemon started: date it by the
                # history it left, not by the restart.
                first = min(now, self.database.last_observed(object_id) or first)
            self._last_states[object_id] = REMOVED_STATE
            self.database.record_state_change(object_id, state, REMOVED_STATE, first)

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
        if not rows:
            self._buckets = {}
            self._bucket_reported = False
            return 0
        # Judged on the minute even when it cannot be written: a full disk
        # must not silence the alerts about the sites.
        if not self._bucket_reported:
            self._report_traffic(rows)
            self._bucket_reported = True
        if self.storage.writes_paused:
            # Counting continues in memory -- the baselines are still correct,
            # so nothing is double-counted once writing resumes -- but this
            # minute is dropped rather than grown onto a filesystem that has no
            # room for it.
            self.buckets_dropped += len(rows)
            self._buckets = {}
            self._bucket_reported = False
            return 0
        # Keep the fragment in memory until both it and its baselines commit.
        # A database rollback can then be retried without losing or doubling it.
        self.database.write_buckets(bucket_ts, rows, merge=True, baselines=self._baselines)
        self._buckets = {}
        self._bucket_reported = False
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
