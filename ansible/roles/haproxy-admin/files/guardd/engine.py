"""Core adaptive protection orchestration engine (GuardEngine)."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .request_log import RequestLog

from .constants import (
    ADAPTIVE_BAN_CODE,
    ADAPTIVE_CODES,
    ADAPTIVE_PAGE_CODE,
    BAN_DURATIONS_CHANGED_KEY,
    BAN_DURATIONS_KEY,
    BURST_MIN_BANS,
    BURST_REPORT_GAP_SECONDS,
    BURST_WINDOW_SECONDS,
    CANDIDATES_KEY,
    CANDIDATE_TTL,
    COOLDOWN_SECONDS,
    DECISIONS_KEEP_ROWS,
    DECISION_DETAIL_LENGTH,
    DECISION_EVIDENCE_LISTED,
    DECISION_PENDING_GRACE,
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    ENGINE_FAILING_AFTER,
    ENGINE_FAILING_RULE,
    ENUMERATION_STATUSES,
    EVENT_BAN_LIFTED,
    EVENT_ERROR_RATE_EXCEEDED,
    EVENT_HARD_FLOOR,
    EVENT_HARD_FLOOR_TRUSTED,
    EVENT_INVALID_HOST,
    EVENT_LEGACY_BAN_LIFTED,
    EVENT_LOW_AND_SLOW,
    EVENT_MASS_ENUM,
    EVENT_NOSNI_PROBING,
    EVENT_NOT_FOUND_ENUM,
    EVENT_QUERY_INJECTION,
    EVENT_RATE_EXCEEDED,
    EVENT_RECURRING,
    EVENT_SCANNER_DECISIVE,
    EVENT_SCANNER_MULTI,
    EVENT_SCANNER_PATH,
    EVENT_SUBNET_CAMPAIGN,
    EVENT_WIDE_ENUM,
    FIRST_STEP_PAGE_KEY,
    INVALID_HOST_MIN,
    INVALID_HOST_WINDOW,
    KNOWN_BANS_MAX,
    KNOWN_BANS_STATE_KEY,
    LEGACY_OBSERVED_STATE_KEY,
    LOG,
    LOW_AND_SLOW_MIN_CATEGORIES,
    LOW_AND_SLOW_MIN_HITS,
    LOW_AND_SLOW_WINDOW,
    MANUAL_BAN_CODE,
    MANUAL_BAN_DEFAULT_SECONDS,
    MASS_ENUM_MIN,
    MAX_LOG_LINE_BYTES,
    MODE_OFF,
    MULTI_CATEGORY_MIN,
    MULTI_CATEGORY_WINDOW,
    ManualBanRefused,
    NOT_FOUND_MIN_DISTINCT,
    NOT_FOUND_WINDOW,
    OWN_BAN_CODES,
    PAGE_ESCALATION_PATHS,
    QUALITY_AT_ONCE_SECONDS,
    QUALITY_CACHE_SECONDS,
    QUALITY_MAX_DAYS,
    QUALITY_NETWORK_MIN,
    RECURRING_GAP,
    RECURRING_RECHECK,
    RECURRING_WINDOW,
    SITE_NAMES_RECHECK,
    STRIKE_RETENTION_BASE_MULTIPLIER,
    SUBNET_CAMPAIGN_TRIGGERS,
    SUPPORTED_MODES,
    TRAP_HOSTS_KEY,
    UNKNOWN_HOSTS_KEY,
    UNKNOWN_HOSTS_TTL,
    WATCH_SCORE,
    WEEKLY_SUMMARY_HOUR,
    WEEKLY_SUMMARY_KEY,
    WEEKLY_SUMMARY_RULE,
    WEEKLY_SUMMARY_WEEKDAY,
    WIDE_ENUM_MIN,
    WIDE_ENUM_WINDOW,
    WOULD_BAN_SCORE,
    _REQUESTS_LOCK,
    _clamp_int,
    _dismissed_candidates,
    _safe_int,
    _utc_now,
    category_is_decisive,
    classify_user_agent,
    enforceable,
    is_served,
    load_ban_durations,
    signature_summary,
    validate_ban_durations,
)
from .native import NATIVE_BATCH_MIN_LINES, parse_access_lines_native
from .parser import (
    L_TS,
    ParsedRequest,
    classify_path,
    is_asset,
    parse_access_line,
    refusal_is_a_shield,
)
_DEFAULT_PARSE_ACCESS_LINE = parse_access_line
from .runtime import (
    GuardConfig,
    RuntimeAnswerTooLarge,
    TableUnreadable,
    list_tables,
    parse_table,
    read_table,
    runtime_command,
)
from .scoring import (
    ExclusionModel,
    REFUSAL_DOES_NOT_EXCUSE,
    ScoringPolicy,
    decision_summary,
    legacy_ban_readings,
    normalize_host,
    read_site_names,
    read_thresholds,
    score_events,
    u02_policy,
    validate_trap_hosts,
)
from .watchers import (
    BAN_POLICY_LEGACY,
    BAN_POLICY_STATE_KEY,
    BAN_POLICY_U02,
    BAN_SNAPSHOTS_KEPT,
    BanPolicyWatch,
    HardFloorWatch,
    LEGACY_BAN_CODES,
    LEGACY_LIFTS_PER_CYCLE,
    RATE_WARNINGS_KEEP_DAYS,
    RATE_WARNINGS_KEEP_ROWS,
    TRUST_AFTER_SIGN_IN_SECONDS,
    TrustedRates,
)
from .tracking import (
    CatchAllPages,
    DetectionContext,
    IpActivity,
    IpMemory,
    LogCursor,
    LoginCorrelations,
    PathCandidates,
    SubnetCorrelator,
    UnknownHosts,
)
from .storage import SecurityDatabase
from .enforcer import (
    BAN_TABLE_UNSURE,
    Enforcer,
    PathShield,
    SHIELD_ENABLED_KEY,
    shield_entries,
)
from .live import (
    ENFORCEMENT_BATCH,
    ENFORCEMENT_CURSOR_KEY,
    ENFORCEMENT_QUEUE_LIMIT,
    ENFORCEMENT_RECOVERY_EVENTS,
    ENFORCEMENT_SWEEP_RESERVE,
    EnforcementQueue,
    FAST_REACTION_TICK_SECONDS,
    LIVE_BUDGET_MAX_MIB,
    LIVE_BUDGET_MAX_SECONDS,
    LIVE_BUDGET_MIN_MIB,
    LIVE_BUDGET_STATE_KEY,
    LIVE_BUDGET_STEP_MIB,
    LIVE_FAST_TICK_SECONDS,
    LIVE_REFILL_BYTES,
    LIVE_REFILL_CHUNK_BYTES,
    LIVE_REFILL_FULL,
    LiveBudgetConflict,
    LiveBuffer,
    MIB,
    MinuteDigests,
    host_memory_available,
    line_epoch,
    live_budget_ceiling,
    live_record,
    process_rss_bytes,
    service_memory_limit,
)

class GuardEngine:
    """Collect observations and apply the selected adaptive policy."""

    def __init__(
        self,
        config: GuardConfig,
        database: SecurityDatabase,
        exclusions: Optional[ExclusionModel] = None,
        alerts: Optional[Any] = None,
        requests: Optional["RequestLog"] = None,
    ) -> None:
        self.config = config
        self.database = database
        self.exclusions = exclusions or ExclusionModel(config)
        self.requests = requests
        # A ban used to be a journal line only. Whether it is worth an email is
        # the alert engine's decision, not this daemon's; here it is only
        # reported.
        self.alerts = alerts
        self._failing_reported = False
        self._burst_bans: deque = deque()
        self._burst_reported: Optional[int] = None
        # The rendered config supplies the default; an operator's choice in the
        # interface overrides it and survives a restart.
        override = database.get_state("mode_override", "")
        self.enforcer = Enforcer(
            config, override if override in SUPPORTED_MODES else config.mode
        )
        # Every decision about bans -- the cycle, an operator's unban, a mode
        # change -- under one lock. An unban that ran between the cycle's read
        # of the schedule and its re-assert used to be undone by that
        # re-assert, which still had the old schedule (F05).
        self._decisions = threading.RLock()
        self.ban_durations = load_ban_durations(database)
        self.ban_durations_changed_at = _safe_int(
            database.get_state(BAN_DURATIONS_CHANGED_KEY, "0")
        )
        self.policy = ScoringPolicy()
        self.shield = PathShield(config)
        self.first_step_page = database.get_state(FIRST_STEP_PAGE_KEY, "1") != "0"
        self._quality_cache: Dict[int, Tuple[int, Dict[str, Any]]] = {}
        self.shield_enabled = database.get_state(SHIELD_ENABLED_KEY, "1") != "0"
        self.detection = DetectionContext(database)
        self.login_correlations = LoginCorrelations(config.authelia_log_file, self.detection, database)
        self.digests = MinuteDigests()
        self.trusted_rates = TrustedRates()
        self.hard_floor = HardFloorWatch()
        self.ban_policy_watch = BanPolicyWatch()
        self.ban_policy = BAN_POLICY_LEGACY
        self.legacy_bans: Dict[str, int] = {}
        self.legacy_lifted = 0
        self.manual_restored = 0
        self.memory = IpMemory(config.max_tracked_ips, config.max_paths_per_ip)
        self.subnet_correlator = SubnetCorrelator()
        self.catch_all = CatchAllPages()
        self.candidates = PathCandidates()
        self.unknown_hosts = UnknownHosts()
        with contextlib.suppress(ValueError, TypeError):
            self.unknown_hosts.restore(
                json.loads(database.get_state(UNKNOWN_HOSTS_KEY, "[]") or "[]")
            )
        self.trap_hosts: Set[str] = set()
        with contextlib.suppress(ValueError, TypeError):
            self.trap_hosts = {str(h) for h in json.loads(database.get_state(TRAP_HOSTS_KEY, "[]") or "[]")}
        self._site_names: Set[str] = set()
        self._site_names_checked = 0.0
        with contextlib.suppress(ValueError, TypeError):
            self.candidates.restore(
                json.loads(database.get_state(CANDIDATES_KEY, "[]") or "[]")
            )
        cursor_state: Dict[str, Any] = {}
        with contextlib.suppress(ValueError):
            cursor_state = json.loads(
                self.database.get_state("log_cursor", "{}")
            )
        self.cursor = LogCursor(config.log_file, cursor_state)
        self.live: Optional[LiveBuffer] = (
            LiveBuffer(config.live_buffer_records, config.live_buffer_seconds)
            if config.live_buffer_records > 0 else None
        )
        # The operator's memory budget for it, from the panel; kept in
        # guardd's own state, which Ansible and an update leave alone.
        self._live_budget_lock = threading.Lock()
        self.live_budget = self._load_live_budget()
        self._apply_live_budget_at_start()
        # Where reading the log back stopped at the start, for the rest to be
        # read in the background: (inode, offset, horizon), or None.
        self._refill_resume: Optional[Tuple[int, int, float]] = None
        # Tables the last cycle could not read whole (R10): left out, not
        # taken for empty.
        self.unreadable_tables: Set[str] = set()
        # Bytes the fast ticks between polls already took from this cycle's
        # read budget, so following the log closely never reads more per
        # cycle than the configured limit.
        self._cycle_bytes = 0

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # The bans already seen, as they stood before a restart.
        self._known_bans: Set[str] = self._load_known_bans()
        self.legacy_observed: Dict[str, int] = self._load_legacy_observed()

        self.last_poll_ts: Optional[int] = None
        self.last_error: Optional[str] = None
        self.consecutive_failures = 0
        self.polls_total = 0
        self.lines_read = 0
        self.lines_parsed = 0
        self.events_recorded = 0
        self.excluded_observations = 0
        self.enforcement_queue = EnforcementQueue(min(config.max_tracked_ips, ENFORCEMENT_QUEUE_LIMIT))
        self._enforcement_scan_after: Tuple[int, str] = (0, "")
        self._enforcement_scan_before = 0
        with contextlib.suppress(ValueError, TypeError, AttributeError, IndexError, KeyError):
            scan = json.loads(database.get_state(ENFORCEMENT_CURSOR_KEY, "{}") or "{}")
            after = scan.get("after", [0, ""])
            self._enforcement_scan_after = (int(after[0]), str(after[1]))
            self._enforcement_scan_before = int(scan.get("before", 0))
        self._enforcement_checked = 0
        self.fast_enforcements = 0
        self._recover_enforcement_checks()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="guardd-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=10)
        # An episode still going on is kept as far as it got rather than lost.
        self.trusted_rates.finish_all()
        with contextlib.suppress(sqlite3.Error):
            self.database.record_rate_warnings(self.trusted_rates.take_finished())
            self.detection.persist(_utc_now(), force=True)
            self.login_correlations.persist(_utc_now())

    def refill_live(self, now: float) -> int:
        """After a restart, the live page's last hour from the log's tail.

        Only up to where the cursor resumes: what comes after it is read the
        usual way. Only into the live buffer: those lines were scored, stored
        and counted before the restart. A rotated log is not followed back
        into the old file. Returns the requests put back.
        """
        if self.live is None:
            return 0
        try:
            stat = os.stat(self.config.log_file)
        except OSError:
            return 0
        if self.cursor.inode == 0:
            end = int(stat.st_size)
        elif self.cursor.inode == int(stat.st_ino):
            end = min(self.cursor.offset, int(stat.st_size))
        else:
            return 0
        start = max(0, end - LIVE_REFILL_BYTES)
        if end <= start:
            return 0
        horizon = now - self.live.max_seconds
        try:
            records, reached_back, boundary = self._read_back(start, end, horizon)
        except OSError:
            return 0
        if records:
            self.live.refill(records, horizon if reached_back else records[0][L_TS])
        # The rest -- up to the budget or a day, never past the start of
        # this file -- is read in the background (08): a budget of many hours
        # used to come back as only the last 16 MiB after every update.
        if not reached_back and boundary > 0:
            self._refill_resume = (int(stat.st_ino), boundary, horizon)
        return len(records)

    def _read_back(self, start: int, end: int, horizon: float) -> Tuple[List[tuple], bool, int]:
        """The requests logged between two offsets, oldest first: whether
        they reach back past `horizon`, and where the first whole line
        begins -- where the next, older read has to end."""
        with open(self.config.log_file, "rb") as handle:
            handle.seek(start)
            data = handle.read(end - start)
        boundary = start
        if start > 0:
            # The first line is cut: it begins before what was read.
            cut = data.find(b"\n") + 1
            data = data[cut:]
            boundary = start + cut
        records: List[tuple] = []
        reached_back = start == 0
        for raw in data.splitlines():
            line = raw[:MAX_LOG_LINE_BYTES].decode("utf-8", "replace")
            ts = line_epoch(line)
            if ts is None:
                continue
            if ts < horizon:
                reached_back = True
                continue
            request = parse_access_line(line)
            if request is not None:
                records.append(live_record(request, ts))
        return records, reached_back, boundary

    def _background_refill(self) -> None:
        try:
            self.continue_refill()
        except Exception:  # pylint: disable=broad-except
            LOG.exception("Could not read older live activity back from the log")

    def _live_full(self) -> bool:
        status = self.live.status() if self.live is not None else {}
        if not status:
            return True
        if status["max_bytes"]:
            return status["bytes"] >= status["max_bytes"] * LIVE_REFILL_FULL
        return status["records"] >= status["max_records"] * LIVE_REFILL_FULL

    def continue_refill(self) -> int:
        """Read the log back further, a piece at a time, after the start (08).

        Older pieces go in on the left of the buffer, as the first one did;
        it stops at the horizon (the budget's day, or the profile's hour), at
        the start of the file, when the buffer is full, or when the log is
        rotated underneath it. Between pieces it waits as long as the last
        one took: the collector and HAProxy come first. Returns the requests
        put back.
        """
        resume, self._refill_resume = self._refill_resume, None
        if not resume or self.live is None:
            return 0
        inode, boundary, horizon = resume
        added = 0
        while boundary > 0 and not self._stop.is_set() and not self._live_full():
            try:
                if int(os.stat(self.config.log_file).st_ino) != inode:
                    break
                started = time.monotonic()
                start = max(0, boundary - LIVE_REFILL_CHUNK_BYTES)
                records, reached_back, first = self._read_back(start, boundary, horizon)
            except OSError:
                break
            if records:
                self.live.refill(records, horizon if reached_back else records[0][L_TS])
                added += len(records)
            if reached_back:
                break
            # A line longer than a piece: carry on before it.
            boundary = first if first < boundary else start
            self._stop.wait(max(0.05, time.monotonic() - started))
        if added:
            LOG.info("Live activity: %d older requests read back from the log", added)
        return added

    # -- the live buffer's memory (07.4-07.5) ------------------------------

    def _load_live_budget(self) -> Dict[str, int]:
        state = {"budget_mib": 0, "revision": 0, "changed_at": 0}
        with contextlib.suppress(ValueError, TypeError, AttributeError):
            stored = json.loads(self.database.get_state(LIVE_BUDGET_STATE_KEY, "") or "{}")
            state["budget_mib"] = _clamp_int(stored.get("budget_mib"), default=0,
                                             min_v=0, max_v=LIVE_BUDGET_MAX_MIB)
            state["revision"] = _clamp_int(stored.get("revision"), default=0, min_v=0, max_v=2 ** 31)
            state["changed_at"] = _clamp_int(stored.get("changed_at"), default=0, min_v=0, max_v=2 ** 33)
        if 0 < state["budget_mib"] < LIVE_BUDGET_MIN_MIB:
            state["budget_mib"] = LIVE_BUDGET_MIN_MIB
        return state

    def _apply_live_budget_at_start(self) -> None:
        wanted = self.live_budget["budget_mib"]
        if self.live is None or not wanted:
            return
        # The unit's memory limit may have been lowered since the choice was
        # made. What the machine has free is not asked here: early in a boot
        # it says little about later.
        ceiling, _ = live_budget_ceiling(0, host=False)
        applied = max(LIVE_BUDGET_MIN_MIB, min(wanted, ceiling))
        if applied < wanted:
            LOG.warning("Live buffer: %d MiB chosen, %d MiB fit the service's memory limit",
                        wanted, applied)
        self.live.set_budget(applied * MIB)

    def live_memory(self) -> Dict[str, Any]:
        """The live buffer's memory: the choice, what it holds, what it may
        be given and the traffic it is measured against."""
        live = self.live
        if live is None:
            raise LookupError("the live buffer is off")
        status = live.status()
        ceiling, reason = live_budget_ceiling(status["bytes"])
        return {
            "budget_mib": self.live_budget["budget_mib"],
            "applied_mib": live.max_bytes // MIB,
            "revision": self.live_budget["revision"],
            "changed_at": self.live_budget["changed_at"],
            "default": {"records": live.default_records, "seconds": live.default_seconds},
            "limits": {
                "min_mib": LIVE_BUDGET_MIN_MIB,
                "max_mib": ceiling,
                "cap_mib": LIVE_BUDGET_MAX_MIB,
                "step_mib": LIVE_BUDGET_STEP_MIB,
                "limited_by": reason,
                "max_seconds": LIVE_BUDGET_MAX_SECONDS,
                "refill_bytes": LIVE_REFILL_BYTES,
            },
            "buffer": status,
            "process": {
                "rss_bytes": process_rss_bytes(),
                "service_limit_bytes": service_memory_limit(),
                "host_available_bytes": host_memory_available(),
            },
        }

    def set_live_memory(self, budget_mib: Any, revision: Any) -> Dict[str, Any]:
        """An operator's budget in MiB, or 0 for the profile in guardd.json.

        Refused with LiveBudgetConflict when the revision is not the one in
        force -- another admin changed it since the page was read -- and with
        ValueError when it is out of range or more than the gateway can give
        now. Lowering is always allowed.
        """
        if self.live is None:
            raise LookupError("the live buffer is off")
        if isinstance(budget_mib, bool) or not isinstance(budget_mib, (int, str)):
            raise ValueError("budget_mib must be a whole number of MiB")
        try:
            wanted = int(budget_mib)
            seen = int(revision)
        except (TypeError, ValueError):
            raise ValueError("budget_mib and revision must be whole numbers") from None
        if wanted and not LIVE_BUDGET_MIN_MIB <= wanted <= LIVE_BUDGET_MAX_MIB:
            raise ValueError(
                f"budget_mib must be 0 or from {LIVE_BUDGET_MIN_MIB} to {LIVE_BUDGET_MAX_MIB}"
            )
        with self._live_budget_lock:
            if seen != self.live_budget["revision"]:
                raise LiveBudgetConflict("changed by someone else in the meantime")
            if wanted:
                ceiling, reason = live_budget_ceiling(self.live.status()["bytes"])
                if wanted > ceiling and wanted > self.live.max_bytes // MIB:
                    raise ValueError(f"at most {ceiling} MiB can be given now ({reason})")
            state = {"budget_mib": wanted, "revision": seen + 1, "changed_at": _utc_now()}
            self.database.set_state(LIVE_BUDGET_STATE_KEY, json.dumps(state))
            self.live_budget = state
            dropped = self.live.set_budget(wanted * MIB)
        LOG.warning("Live buffer: %s from the web interface; %d older requests dropped",
                    f"{wanted} MiB" if wanted else "back to its configured profile", dropped)
        return {**self.live_memory(), "dropped": dropped}

    def _run(self) -> None:
        interval = self.config.poll_interval_seconds
        next_maintenance = (
            time.monotonic() + self.config.maintenance_interval_seconds
        )
        try:
            refilled = self.refill_live(time.time())
            if refilled:
                LOG.info("Live activity: %d requests from before the start read back", refilled)
        except Exception:  # pylint: disable=broad-except
            LOG.exception("Could not read the live activity back from the log")
        if self._refill_resume is not None:
            threading.Thread(
                target=self._background_refill, name="guardd-refill", daemon=True
            ).start()
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.poll()
            except Exception as exc:  # pylint: disable=broad-except
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
            self.report_failing()
            if time.monotonic() >= next_maintenance:
                try:
                    self.run_maintenance()
                except Exception:  # pylint: disable=broad-except
                    LOG.exception("Maintenance pass failed")
                next_maintenance = (
                    time.monotonic() + self.config.maintenance_interval_seconds
                )
            deadline = started + interval
            tick = min(FAST_REACTION_TICK_SECONDS, LIVE_FAST_TICK_SECONDS)
            while not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0.25:
                    break
                if self._stop.wait(min(tick, remaining)):
                    break
                live_watching = self.live is not None and self.live.wanted()
                if not live_watching and not self.cursor.has_pending():
                    continue
                share = max(
                    64 * 1024,
                    int(self.config.log_read_bytes_per_cycle * tick / max(1, interval)),
                )
                allowance = min(share, self.config.log_read_bytes_per_cycle - self._cycle_bytes)
                if allowance > 0:
                    now_tick = _utc_now()
                    try:
                        self.ingest_log(now_tick, max_bytes=allowance)
                    except Exception:  # pylint: disable=broad-except
                        LOG.debug("fast log read failed", exc_info=True)
                    if self.enforcer.allowed and self.enforcement_queue.has_urgent():
                        try:
                            self.apply_urgent_enforcement(now_tick)
                        except Exception:  # pylint: disable=broad-except
                            LOG.debug("fast enforcement tick failed", exc_info=True)
            self._cycle_bytes = 0

    # -- collection -------------------------------------------------------

    def poll(self) -> Dict[str, int]:
        now = _utc_now()
        self.exclusions.reload_files()
        self.refresh_ban_policy(now)
        tables = self.read_tables()
        from_tables = self.ingest_tables(tables, now)
        from_tables += self.ingest_hard_floor(now)
        from_log = self.ingest_log(
            now,
            max_bytes=max(64 * 1024, self.config.log_read_bytes_per_cycle - self._cycle_bytes),
        )
        self.flush_rate_warnings(now, idle=from_log == 0)

        # Runs in every mode: expiry and the kill switch have to keep working
        # after enforcement is turned off.
        enforcement = self.apply_enforcement(now)

        self.polls_total += 1
        self.last_poll_ts = now
        self.consecutive_failures = 0
        self.last_error = None
        self.database.set_state("log_cursor", json.dumps(self.cursor.state()))
        self.sync_shield(now)
        self.weekly_summary_tick(now)
        self.login_correlations.poll(now, self.exclusions)
        self.detection.persist(now)
        return {
            "table_events": from_tables,
            "log_lines": from_log,
            "banned": len(enforcement["applied"]),
            "lifted": len(enforcement["lifted"]),
        }

    def read_tables(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        socket_path = self.config.haproxy_socket
        available = list_tables(runtime_command(socket_path, "show table"))
        # The per-site rate and error tables are generated, so they are matched
        # by prefix rather than listed; tbl_nosni_tcp carries the direct-IP
        # probing signal that never reaches the HTTP log at all.
        wanted = [
            name
            for name in available
            if name in ("tbl_ban", "tbl_ip_auth", "tbl_err_other", "tbl_nosni_tcp")
            or name.startswith(("tbl_err_", "tbl_rate_"))
        ]
        result: Dict[str, Dict[str, Dict[str, str]]] = {}
        unreadable: Set[str] = set()
        for name in wanted:
            try:
                result[name] = read_table(socket_path, name)
            except (TableUnreadable, RuntimeAnswerTooLarge) as exc:
                # Left out of this cycle, not read as empty (R10): an empty
                # ban table would end every ban seen, an empty sign-in table
                # would take everyone's trust away. Said in health.
                unreadable.add(name)
                LOG.warning("%s; left out of this cycle", exc)
        self.unreadable_tables = unreadable
        return result

    def _load_known_bans(self) -> Set[str]:
        try:
            stored = json.loads(self.database.get_state(KNOWN_BANS_STATE_KEY, "[]") or "[]")
        except (ValueError, TypeError):
            return set()
        return {str(ip) for ip in stored} if isinstance(stored, list) else set()

    def _load_legacy_observed(self) -> Dict[str, int]:
        try:
            stored = json.loads(self.database.get_state(LEGACY_OBSERVED_STATE_KEY, "{}") or "{}")
        except (ValueError, TypeError):
            return {}
        if not isinstance(stored, dict):
            return {}
        return {
            str(ip): _safe_int(code) for ip, code in stored.items()
            if _safe_int(code) in LEGACY_BAN_CODES
        }

    def _save_legacy_observed(self) -> None:
        while len(self.legacy_observed) > KNOWN_BANS_MAX:
            self.legacy_observed.pop(next(iter(self.legacy_observed)))
        self.database.set_state(LEGACY_OBSERVED_STATE_KEY, json.dumps(self.legacy_observed))

    def observe_legacy_bans(
        self,
        bans: Dict[str, Dict[str, str]],
        newly: Set[str],
        tables: Dict[str, Dict[str, Dict[str, str]]],
        now: int,
    ) -> int:
        """Write HAProxy's own bans into the decision history, as seen (06.5b).

        HAProxy does not record when it decided a ban or what tipped it over,
        and this does not make either up: what is written is when this daemon
        first saw the ban, its code and expiry, and the site counters that
        held the address at that moment. A ban already standing before this
        record existed is left alone rather than given a first sighting that
        is not one. When one leaves the table -- it ran out, HAProxy
        restarted, another ban replaced it -- that is written once.
        """
        written = 0
        changed = False
        thresholds: Optional[Dict[str, int]] = None
        for ip in sorted(newly):
            fields = bans.get(ip) or {}
            code = _safe_int(fields.get("gpt0"))
            if code not in LEGACY_BAN_CODES:
                continue
            if thresholds is None:
                thresholds = read_thresholds()
            remaining = max(0, _safe_int(fields.get("exp")) // 1000)
            self.database.record_decision(
                ip, now, "observed", "haproxy", "observed",
                code=code, until=now + remaining, policy=self.ban_policy,
                reason={
                    "first_seen": now,
                    # Not known: HAProxy keeps no record of it.
                    "decided_at": None,
                    "readings": legacy_ban_readings(ip, tables, thresholds),
                },
            )
            self.legacy_observed[ip] = code
            written += 1
            changed = True
        for ip, code in list(self.legacy_observed.items()):
            fields = bans.get(ip) or {}
            if _safe_int(fields.get("gpc0")) > 0 and _safe_int(fields.get("gpt0")) == code:
                continue
            del self.legacy_observed[ip]
            self.database.record_decision(
                ip, now, "ended", "haproxy", "observed", code=code, policy=self.ban_policy,
            )
            written += 1
            changed = True
        if changed:
            self._save_legacy_observed()
        return written

    def _settle_legacy_observed(self, ip: str) -> int:
        """Stop following an observed ban whose end was written another way;
        returns its code, 0 when it was not followed."""
        code = self.legacy_observed.pop(ip, 0)
        if code:
            self._save_legacy_observed()
        return code

    def ingest_tables(
        self, tables: Dict[str, Dict[str, Dict[str, str]]], now: int
    ) -> int:
        if "tbl_ip_auth" not in self.unreadable_tables:
            auth_rows = tables.get("tbl_ip_auth", {})
            self.exclusions.refresh_authenticated(auth_rows)
            authenticated = [
                ip
                for ip, fields in auth_rows.items()
                if _safe_int(fields.get("gpc0")) > 0
            ]
            if authenticated:
                self.database.record_authenticated(authenticated, now)

        if "tbl_ban" in self.unreadable_tables:
            # Unknown is not empty: nothing about bans is decided this cycle.
            return self.ingest_rate_tables(tables, now)
        bans = tables.get("tbl_ban", {})
        active = {
            ip for ip, fields in bans.items() if _safe_int(fields.get("gpc0")) > 0
        }
        events: List[Dict[str, Any]] = []
        newly = active - self._known_bans
        try:
            self.observe_legacy_bans(bans, newly, tables, now)
        except sqlite3.Error as exc:
            LOG.warning("Could not write HAProxy's own bans into the decision history: %s", exc)
        for ip in sorted(newly):
            if _safe_int(bans[ip].get("gpt0")) in OWN_BAN_CODES:
                # This daemon's or an operator's own ban: not something the
                # client did.
                continue
            # An observation, not a decision: HAProxy banned this address on
            # its own rules and guardd is recording that it happened.
            events.append(
                {
                    "ts": now,
                    "ip": ip,
                    "event_type": "LEGACY_HAPROXY_BAN",
                    "source": "stick-table",
                    "category": "ban",
                    "detail": f"code={_safe_int(bans[ip].get('gpt0'))}",
                }
            )
            self.database.observe_ip(ip, now, self.exclusions.verdict(ip))
        if active != self._known_bans:
            self.database.set_state(
                KNOWN_BANS_STATE_KEY, json.dumps(sorted(active)[:KNOWN_BANS_MAX])
            )
        self._known_bans = active
        written = self.database.record_events(events)
        self.events_recorded += written
        # What the preview says a switch would lift, and -- once switched --
        # what is left to lift.
        counts: Dict[str, int] = {}
        for ip in active:
            code = _safe_int(bans[ip].get("gpt0"))
            if code in LEGACY_BAN_CODES:
                counts[str(code)] = counts.get(str(code), 0) + 1
        self.legacy_bans = counts
        # Changes to the ban table, under the lock every other one takes --
        # expiry, an operator's ban or unban, a mode switch (R03).
        with self._decisions:
            if counts and self.ban_policy == BAN_POLICY_U02 and self.switch_recorded():
                self.reconcile_legacy_bans(bans, now)
            try:
                self.keep_manual_bans(bans, now)
            except OSError as exc:
                LOG.warning("Could not check the manual bans against HAProxy: %s", exc)
        return written + self.ingest_rate_tables(tables, now)

    def keep_manual_bans(self, bans: Dict[str, Dict[str, str]], now: int) -> int:
        """Remember the operator's bans, and put back what a restart lost.

        A manual ban that vanished is put back only if HAProxy started after
        it was last seen: its table was emptied. One that vanished while the
        same HAProxy kept running was lifted -- from the panel, or by hand on
        the socket -- and is forgotten, so an unban never undoes itself. Each
        ends when its table expiry, as first seen, says so.
        """
        known = self.database.manual_bans()
        for ip, fields in bans.items():
            if _safe_int(fields.get("gpc0")) > 0 and _safe_int(fields.get("gpt0")) == MANUAL_BAN_CODE:
                remaining = max(0, _safe_int(fields.get("exp")) // 1000)
                self.database.note_manual_ban(ip, now, now + remaining)
                if ip not in known:
                    # Who placed it is in the panel's change log; here, that
                    # an operator did and until when the table holds it.
                    self.database.record_decision(
                        ip, now, "applied", "operator", "applied",
                        code=MANUAL_BAN_CODE, until=now + remaining, policy=self.ban_policy,
                    )
        records = self.database.manual_bans()
        started: Optional[int] = None
        restored = 0
        for ip, record in sorted(records.items()):
            entry = bans.get(ip) or {}
            held = _safe_int(entry.get("gpc0")) > 0
            code = _safe_int(entry.get("gpt0"))
            if record["expires_at"] <= now:
                # Over. A copy put back after a restart carries a fresh table
                # expiry, past the operator's own: that one is lifted here.
                if record["reasserted"] and held and code == MANUAL_BAN_CODE:
                    self.enforcer.lift_code(ip, MANUAL_BAN_CODE)
                self.database.forget_manual_ban(ip)
                continue
            if held:
                continue
            if record["seen_at"] >= now:
                # Remembered after this cycle read the table (a ban placed by
                # hand just now): the table read says nothing about it yet.
                continue
            if started is None:
                started = self.enforcer.started_at()
            if not started:
                continue  # cannot tell a restart from an unban: wait
            if started > record["seen_at"]:
                if self.enforcer.restore(ip, MANUAL_BAN_CODE):
                    self.database.mark_manual_reasserted(ip)
                    restored += 1
                    LOG.warning("Restored the manual ban on %s, lost when HAProxy restarted", ip)
                    self.database.record_decision(
                        ip, now, "restored", "restart", "applied",
                        code=MANUAL_BAN_CODE, until=record["expires_at"], policy=self.ban_policy,
                    )
            else:
                self.database.forget_manual_ban(ip)
        self.manual_restored += restored
        return restored

    # -- the ban policy (U02) ---------------------------------------------

    def scoring_policy(self) -> ScoringPolicy:
        """The weights the policy HAProxy runs calls for."""
        return u02_policy(self.policy) if self.ban_policy == BAN_POLICY_U02 else self.policy

    def detection_state(self) -> Dict[str, Any]:
        policy = self.scoring_policy()
        return {**self.detection.summary(), "login_source": self.login_correlations.health(),
                "active_mode": self.enforcer.mode,
                "scoring": {"window_hours": policy.window_seconds / 3600,
                            "decay_hours": policy.decay_seconds / 3600, "ban_score": WOULD_BAN_SCORE}}

    def ban_policy_state(self) -> Dict[str, Any]:
        try:
            state = json.loads(self.database.get_state(BAN_POLICY_STATE_KEY, "") or "{}")
        except (TypeError, ValueError):
            state = {}
        return state if isinstance(state, dict) else {}

    def refresh_ban_policy(self, now: int) -> str:
        """Follow the policy in the configuration; mark a switch when it happens."""
        policy = self.ban_policy_watch.current()
        self.ban_policy = policy
        self.exclusions.geo_trusted = policy != BAN_POLICY_U02
        state = self.ban_policy_state()
        if state.get("policy", BAN_POLICY_LEGACY) == policy:
            return policy
        record: Dict[str, Any] = {"policy": policy, "since": now, "previous": state.get("policy", BAN_POLICY_LEGACY)}
        if policy == BAN_POLICY_U02:
            # Written before anything is lifted. If it cannot be written the
            # switch is not marked -- nothing is lifted, scoring already
            # follows the new policy -- and the next cycle tries again.
            try:
                record["snapshot"] = self.snapshot_bans(now)
            except OSError as exc:
                LOG.warning("Ban policy %s seen, but the ban table snapshot failed: %s", policy, exc)
                return policy
        self.database.set_state(BAN_POLICY_STATE_KEY, json.dumps(record))
        LOG.warning("Ban policy is now %s (was %s)", policy, record["previous"])
        return policy

    def switch_recorded(self) -> bool:
        """True once the switch to U02 is marked, and its snapshot written."""
        return self.ban_policy_state().get("policy") == BAN_POLICY_U02

    def snapshot_bans(self, now: int) -> str:
        """Write every entry of tbl_ban to a file next to the database."""
        rows = read_table(self.config.haproxy_socket, "tbl_ban")
        directory = pathlib.Path(self.database.path).parent
        target = directory / f"ban-policy-u02-{now}.json"
        temporary = target.with_suffix(".tmp")
        payload = {"ts": now, "entries": rows}
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        for old in sorted(directory.glob("ban-policy-u02-*.json"))[:-BAN_SNAPSHOTS_KEPT]:
            with contextlib.suppress(OSError):
                old.unlink()
        return str(target)

    def reconcile_legacy_bans(self, bans: Dict[str, Dict[str, str]], now: int) -> int:
        """Lift the bans HAProxy wrote under the old rules, address by address."""
        legacy = sorted(
            ip for ip, fields in bans.items()
            if _safe_int(fields.get("gpc0")) > 0 and _safe_int(fields.get("gpt0")) in LEGACY_BAN_CODES
        )
        lifted = 0
        for ip in legacy[:LEGACY_LIFTS_PER_CYCLE]:
            try:
                code = self.enforcer.lift_legacy(ip)
            except OSError as exc:
                LOG.warning("Could not lift the legacy ban on %s: %s", ip, exc)
                break
            if not code:
                continue
            lifted += 1
            # What is left to lift, as of now rather than of the last read.
            left = self.legacy_bans.get(str(code), 0) - 1
            if left > 0:
                self.legacy_bans[str(code)] = left
            else:
                self.legacy_bans.pop(str(code), None)
            self._emit(
                ip,
                EVENT_LEGACY_BAN_LIFTED,
                now,
                source="guardd",
                detail=f"code={code} policy={BAN_POLICY_U02}",
                fingerprint=f"{ip}|{EVENT_LEGACY_BAN_LIFTED}|{now}",
            )
            self.database.record_decision(
                ip, now, "lifted", "policy", "applied", code=code, policy=BAN_POLICY_U02,
            )
            # Its end is this decision; not "no longer in force" next cycle too.
            self._settle_legacy_observed(ip)
        if lifted:
            self.legacy_lifted += lifted
            LOG.warning("Lifted %d bans HAProxy wrote under the old rules", lifted)
        return lifted

    def ingest_hard_floor(self, now: int) -> int:
        """Record the addresses that have stayed over a hard ceiling.

        A trusted address over it is recorded under a type that weighs
        nothing in any policy: the floor already refuses its excess, and
        whether load alone may ever punish a trusted address is D09b's
        question, not this one's.
        """
        queries = self.hard_floor.queries()
        if not queries:
            return 0
        over: Dict[Tuple[str, str, str], Tuple[int, int]] = {}
        for table, counter, limit in queries:
            try:
                payload = runtime_command(
                    self.config.haproxy_socket, f"show table {table} data.{counter} gt {limit}"
                )
            except OSError as exc:
                LOG.debug("cannot read %s for the hard floor: %s", table, exc)
                continue
            for ip, fields in parse_table(payload).items():
                value = next(
                    (_safe_int(raw) for name, raw in fields.items() if name.startswith(counter)), 0
                )
                if value > limit:
                    over[(ip, table, counter)] = (value, limit)
        written = 0
        for (ip, table, counter), (value, limit) in self.hard_floor.update(over):
            verdict = self.exclusions.verdict(ip)
            event_type = EVENT_HARD_FLOOR_TRUSTED if verdict.excluded else EVENT_HARD_FLOOR
            detail = f"{counter}={value} limit={limit} table={table}"
            if verdict.excluded:
                detail += f" trusted={verdict.source or verdict.reason}"
            if self._emit(
                ip, event_type, now, source="stick-table", category="flood", detail=detail
            ):
                written += 1
        return written

    def ingest_rate_tables(
        self, tables: Dict[str, Dict[str, Dict[str, str]]], now: int
    ) -> int:
        """Turn the short-window counters into events, with their site.

        These say how hard an address is pushing right now. On their own they
        duplicate what HAProxy already enforces; their value is combining with
        the slow behavioural signals the log provides.

        A reading only counts when it is over the ceiling the configuration
        sets for that table. It used to count whenever it was non-zero, which
        made "RATE_EXCEEDED" the name for having made one request: on a live
        gateway that was 534 findings across 40 addresses in a day, 497 of
        them at a rate of exactly 1 against limits of 200 and above.
        """

        written = 0
        thresholds = read_thresholds()
        for name, rows in tables.items():
            if name.startswith("tbl_rate_"):
                event_type, field_prefix = EVENT_RATE_EXCEEDED, "http_req_rate"
            elif name.startswith("tbl_err_"):
                event_type, field_prefix = (
                    EVENT_ERROR_RATE_EXCEEDED,
                    "http_err_rate",
                )
            elif name == "tbl_nosni_tcp":
                event_type, field_prefix = EVENT_NOSNI_PROBING, "conn_rate"
            else:
                continue
            site = name.split("_", 2)[-1] if name.count("_") >= 2 else ""
            limit = thresholds.get(name)
            if limit is None:
                # Without the configured ceiling there is no way to tell a
                # busy client from an ordinary one, and guessing produced a
                # finding for every visitor who made a single request.
                LOG.debug("no configured threshold for %s; not scoring it", name)
                continue
            for ip, fields in rows.items():
                value = 0
                for key, raw in fields.items():
                    if key.startswith(field_prefix):
                        value = _safe_int(raw)
                        break
                if value <= limit:
                    continue
                if self.exclusions.verdict(ip).excluded:
                    continue
                if self._emit(
                    ip,
                    event_type,
                    now,
                    source="stick-table",
                    site=site,
                    detail=f"{field_prefix}={value} limit={limit}",
                    fingerprint=f"{ip}|{event_type}|{name}",
                ):
                    written += 1
        return written

    def flush_rate_warnings(self, now: int, *, idle: bool) -> int:
        """Close the episodes that are over and write them, in one go.

        A warning that cannot be written is lost, not retried: it must never
        cost the cycle its enforcement step.
        """
        self.trusted_rates.tick(now, idle=idle)
        finished = self.trusted_rates.take_finished()
        try:
            return self.database.record_rate_warnings(finished)
        except sqlite3.Error as exc:
            self.trusted_rates.dropped += len(finished)
            LOG.warning("Could not record %d rate warnings: %s", len(finished), exc)
            return 0

    def ingest_log(self, now: int, max_bytes: Optional[int] = None) -> int:
        before = self.cursor.offset
        lines = self.cursor.read(max_bytes or self.config.log_read_bytes_per_cycle)
        self._cycle_bytes += max(0, self.cursor.offset - before)
        if not lines:
            return 0
        self.lines_read += len(lines)
        parsed = 0
        live: List[tuple] = []
        native_parsed = (
            parse_access_lines_native(lines)
            if (
                len(lines) >= NATIVE_BATCH_MIN_LINES
                and parse_access_line is _DEFAULT_PARSE_ACCESS_LINE
            )
            else None
        )
        for idx, line in enumerate(lines):
            request = (
                native_parsed[idx]
                if native_parsed is not None
                else parse_access_line(line)
            )
            if request is None:
                continue
            parsed += 1
            ts = line_epoch(line)
            ended = ts if ts is not None else float(now)
            # Everything, excluded addresses too: the page charts the
            # gateway's traffic, not the engine's suspects.
            self.digests.add(request, ended, now)
            if self.live is not None:
                live.append(live_record(request, ended))
            with _REQUESTS_LOCK:
                if self.requests is not None:
                    # Diagnostics and scoring are separate concerns that happen to
                    # need the same read of the same file. The request log keeps
                    # everything, including what the engine excludes: an operator
                    # looking for their own failed request must be able to find it.
                    # Its time is the syslog stamp, as on the live page and the
                    # charts, so a link between them means the same minutes.
                    self.requests.add(request, ts)
            self.observe_request(request, now, ts)
        self.lines_parsed += parsed
        if self.live is not None:
            self.live.extend(live)
        with _REQUESTS_LOCK:
            if self.requests is not None:
                self.requests.flush(now)
        return len(lines)

    def observe_request(self, request: ParsedRequest, now: int,
                        stamp: Optional[float] = None) -> None:
        """Fold one request into the address's memory and emit any findings."""

        ip = request.client_ip
        verdict = self.exclusions.verdict(ip)
        # Before the exclusion returns: the trusted are exactly who these
        # warnings are about. Observed only (see TrustedRates).
        trust = ""
        if verdict.reason == "authenticated":
            trust = "signed-in"
        elif verdict.reason == "whitelisted":
            trust = verdict.source or "whitelist"
        self.trusted_rates.observe(request, trust, now, stamp)
        matches = self.detection.inspect(request, now, trusted=verdict.excluded,
                                         catch_all=self.catch_all.known(request.host, request.bytes_out))
        actions = {row["id"]: row["action"] for row in matches}

        def permitted(rule: str) -> bool:
            action = actions.get(rule)
            if action is None:
                action, _ = self.detection._action(rule, request, now, self.detection.config, "enforce")
            return action == "enforce"

        if verdict.excluded:
            self.excluded_observations += 1
            return

        activity = self.memory.touch(ip, now)
        activity.requests += 1
        self._check_unknown_host(ip, activity, now, request)
        if request.bad_request:
            activity.bad_requests += 1
            self._note_invalid_host(ip, activity, now, request)
            return

        if not request.backend.endswith("/<NOSRV>"):
            # A real server answered, so this address is not walled off.
            activity.reached_backend = True

        handled = refusal_is_a_shield(request, activity)
        observed_at = int(min(now, stamp)) if stamp is not None else now
        slow_action = self.detection.observe_slow(request, observed_at, handled) if observed_at >= now - 6 * 3600 else ""
        if slow_action == "enforce":
            self._emit(ip, EVENT_SCANNER_PATH, now, source="haproxy-log",
                       category="slow-enumeration", site=request.host, detail=request.path, handled=False,
                       fingerprint=f"{ip}|behavior:slow-enumeration|{request.host}")
        emitted_context = set()
        for match in matches:
            if match["id"].startswith(("custom:", "observe:")) and match["action"] == "enforce":
                finding = (match["event_type"], match["category"])
                if finding in emitted_context:
                    continue
                emitted_context.add(finding)
                activity.scanner_hits += 1
                activity.scanner_hits_denied += int(handled)
                self._emit(ip, match["event_type"], now, source="haproxy-log", category=match["category"], site=request.host,
                           detail=f"{match['id']} {request.path}"[:300], handled=handled,
                           fingerprint=f"{ip}|{match['event_type']}|{match['category']}|{int(handled)}")
                activity.note_category(match["category"], now)
                self._check_multi_category(ip, activity, now)
                if match["id"].startswith("custom:"):
                    self._check_low_and_slow(ip, activity, now)
                    self._check_recurring(ip, activity, now)
        if request.status == 404:
            activity.not_found += 1
        elif request.denied_by_gateway:
            # The counter records what the gateway did, not what the engine
            # decided to do about it.
            activity.gateway_denied += 1
        elif request.status >= 400:
            activity.errors += 1

        if request.path:
            activity.note_path(request.path, now, self.config.max_paths_per_ip)
        if request.host and len(activity.hosts) < 16:
            activity.hosts.add(request.host)

        if request.query_flag and permitted("query:" + request.query_flag):
            # Deliberately not gated on is_served. A path the site answers
            # is evidence the path is real; an injection the site answered
            # 200 is evidence it may have worked, which is the opposite of
            # a reason to let the client alone.
            activity.scanner_hits += 1
            if handled:
                activity.scanner_hits_denied += 1
            activity.note_category(request.query_flag, now)
            self._emit(
                ip,
                EVENT_QUERY_INJECTION,
                now,
                source="haproxy-log",
                category=request.query_flag,
                site=request.host,
                # The path, never the query. The rule name above already
                # says what was in it.
                detail=request.path,
                handled=handled,
                fingerprint=f"{ip}|{EVENT_QUERY_INJECTION}|{request.query_flag}",
            )
            self._check_multi_category(ip, activity, now)

        if request.path_flag and permitted("raw:path-traversal"):
            activity.scanner_hits += 1
            activity.scanner_hits_denied += int(handled)
            activity.note_category(request.path_flag, now)
            self._emit(ip, EVENT_SCANNER_DECISIVE, now, source="haproxy-log",
                       category=request.path_flag, site=request.host, detail=request.path, handled=handled,
                       fingerprint=f"{ip}|path|{request.path_flag}|{int(handled)}")

        agent, agent_category = classify_user_agent(request.user_agent)
        if agent and permitted("ua:" + agent):
            # The client said what it is. Not gated on is_served either: a
            # sqlmap run the site answers 200 is the worse case, not a
            # better one.
            activity.scanner_hits += 1
            if handled:
                activity.scanner_hits_denied += 1
            activity.note_category(agent_category, now)
            agent_event = (
                EVENT_SCANNER_DECISIVE
                if category_is_decisive(agent_category)
                else EVENT_SCANNER_PATH
            )
            self._emit(
                ip,
                agent_event,
                now,
                source="haproxy-log",
                category=agent_category,
                site=request.host,
                detail=f"user agent {agent}",
                handled=handled,
                fingerprint=f"{ip}|ua|{agent}|{int(bool(handled))}",
            )
            self._check_multi_category(ip, activity, now)

        category = classify_path(request.path)
        if not category and request.path not in ("", "/") and not is_asset(request.path):
            served = is_served(request.status) and not self.catch_all.known(
                request.host, request.bytes_out
            )
            looks_like_client = activity.requests >= 20 and (
                activity.requests - activity.errors - activity.not_found
                - activity.gateway_denied - activity.bad_requests
            ) * 2 >= activity.requests
            self.candidates.note(
                request.path, ip, request.host, request.status, served,
                looks_like_client, now,
            )
        if (
            category
            and is_served(request.status)
            and not category_is_decisive(category)
            and not self.catch_all.is_catch_all(
                request.host, request.bytes_out, request.path
            )
        ):
            # The application answered with content, so this is a path the
            # site actually has. A real WordPress installation would
            # otherwise file every one of its own users as scanning for
            # WordPress.
            #
            # A decisive category is never excused this way. No site serves
            # its own .env, git store or database dump on purpose, so a 200
            # there means one of two things: a catch-all page that answers
            # everything alike -- one gateway returned the same 1477 bytes
            # for /.env, /backup.sql and /phpinfo.php -- or a real leak.
            # Neither is a reason to trust the client asking.
            category = ""
        if category and permitted("path:" + category):
            activity.scanner_hits += 1
            if handled:
                activity.scanner_hits_denied += 1
            activity.note_category(category, now)
            event = (
                EVENT_SCANNER_DECISIVE
                if category_is_decisive(category)
                else EVENT_SCANNER_PATH
            )
            self._emit(
                ip,
                event,
                now,
                source="haproxy-log",
                category=category,
                site=request.host,
                detail=request.path,
                handled=handled,
                # Refused and answered findings cool down apart: a refused
                # probe scores nothing, and sharing its cooldown silenced an
                # answered probe of the same kind a minute later.
                fingerprint=f"{ip}|{event}|{category}|{int(bool(handled))}",
            )
            self._check_multi_category(ip, activity, now)
            self._check_low_and_slow(ip, activity, now)
            self._check_recurring(ip, activity, now)
        elif not category and request.status in ENUMERATION_STATUSES and not is_asset(request.path):
            # Enumeration without a known signature: only distinct, non-asset
            # paths count, which is what separates a scanner from a stale link
            # or a monitor that keeps asking for the same one.
            if request.status == 404 and activity.note_missing(
                request.path, now, self.config.max_paths_per_ip
            ):
                self._check_not_found_enumeration(ip, activity, now)
            # Room for twice the first threshold: an application cycling
            # through more endpoints than the set holds would otherwise look
            # like an endless supply of new paths.
            if activity.note_refused(
                request.path,
                now,
                max(self.config.max_paths_per_ip, 2 * WIDE_ENUM_MIN),
                WIDE_ENUM_WINDOW,
            ):
                self._check_enumeration_breadth(ip, activity, now, request)

        if request.status == 400 or request.backend.endswith("/<NOSRV>"):
            self._note_invalid_host(ip, activity, now, request)

    # -- derived detections ----------------------------------------------

    def _emit(
        self,
        ip: str,
        event_type: str,
        now: int,
        *,
        source: str,
        category: str = "",
        site: str = "",
        detail: str = "",
        handled: bool = False,
        fingerprint: Optional[str] = None,
    ) -> bool:
        window = COOLDOWN_SECONDS.get(event_type, 60)
        key = fingerprint or f"{ip}|{event_type}"
        if not self.database.cooldown_passed(key, now, window):
            return False
        self.database.observe_ip(ip, now, self.exclusions.verdict(ip))
        self.database.record_events(
            [
                {
                    "ts": now,
                    "ip": ip,
                    "event_type": event_type,
                    "source": source,
                    "category": category,
                    "site": site,
                    "detail": detail,
                    "handled": handled,
                }
            ]
        )
        self._queue_enforcement_check(ip, event_type, handled)
        self.events_recorded += 1
        if event_type in DEFAULT_WEIGHTS:
            self.memory.promote(ip)
        if not handled and event_type in SUBNET_CAMPAIGN_TRIGGERS:
            subnet, peers = self.subnet_correlator.observe(ip, now)
            if peers >= self.subnet_correlator.min_ips:
                self._emit(
                    ip,
                    EVENT_SUBNET_CAMPAIGN,
                    now,
                    source="guardd",
                    category="subnet",
                    site=site,
                    detail=f"subnet={subnet} peers={peers}",
                    handled=False,
                    fingerprint=f"{ip}|{EVENT_SUBNET_CAMPAIGN}|{subnet}",
                )
        return True

    def _check_multi_category(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        categories = activity.recent_categories(now - MULTI_CATEGORY_WINDOW)
        if len(categories) < MULTI_CATEGORY_MIN:
            return
        # One host is almost never WordPress and phpMyAdmin and Git at once;
        # several different technologies is a much stronger signal than the
        # same number of hits on one of them.
        self._emit(
            ip,
            EVENT_SCANNER_MULTI,
            now,
            source="haproxy-log",
            detail=f"categories={len(categories)}",
            handled=activity.scanning_was_all_refused,
        )

    def _check_low_and_slow(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        since = now - LOW_AND_SLOW_WINDOW
        categories = activity.recent_categories(since)
        if (
            activity.scanner_hits < LOW_AND_SLOW_MIN_HITS
            or len(categories) < LOW_AND_SLOW_MIN_CATEGORIES
        ):
            return
        # Deliberately rate-blind: the slower the scan, the less the existing
        # stick-table limits can see it, and the more this detection matters.
        self._emit(
            ip,
            EVENT_LOW_AND_SLOW,
            now,
            source="haproxy-log",
            detail=f"hits={activity.scanner_hits} categories={len(categories)}",
            handled=activity.scanning_was_all_refused,
        )

    def _check_not_found_enumeration(
        self, ip: str, activity: IpActivity, now: int
    ) -> None:
        distinct = activity.distinct_missing(now - NOT_FOUND_WINDOW)
        if distinct < NOT_FOUND_MIN_DISTINCT:
            return
        self._emit(
            ip,
            EVENT_NOT_FOUND_ENUM,
            now,
            source="haproxy-log",
            detail=f"distinct={distinct}",
        )

    def site_names(self) -> Set[str]:
        moment = time.monotonic()
        if moment - self._site_names_checked >= SITE_NAMES_RECHECK:
            self._site_names_checked = moment
            self._site_names = read_site_names()
        return self._site_names

    def set_trap_hosts(self, hosts: Any) -> List[str]:
        checked = validate_trap_hosts(hosts, self.site_names())
        self.database.set_state(TRAP_HOSTS_KEY, json.dumps(checked))
        self.trap_hosts = set(checked)
        LOG.info("trap names set: %s", ", ".join(checked) or "none")
        return checked

    def _check_unknown_host(self, ip: str, activity: IpActivity, now: int,
                            request: ParsedRequest) -> None:
        host = normalize_host(request.host)
        if not host:
            return
        sites = self.site_names()
        # Without the site list every name would look unknown; better to say
        # nothing than to call the gateway's own sites strangers.
        if not sites or host in sites:
            return
        client = activity.requests >= 20 and (
            activity.requests - activity.errors - activity.not_found
            - activity.gateway_denied - activity.bad_requests
        ) * 2 >= activity.requests
        self.unknown_hosts.note(host, ip, client, now)
        if host in self.trap_hosts and not client:
            # An address that otherwise uses the gateway like a client is
            # more likely holding an old bookmark than scanning; it is
            # counted above and spared here.
            self._emit(
                ip,
                EVENT_SCANNER_DECISIVE,
                now,
                source="haproxy-log",
                category="trap",
                detail=f"trap name {host}",
                fingerprint=f"{ip}|trap|{host}",
            )

    def _check_recurring(self, ip: str, activity: IpActivity, now: int) -> None:
        """A scanner signature again, hours or weeks after an earlier one.

        Read from the stored findings rather than memory, so a return after a
        restart or after the address fell out of the bounded memory still
        counts. Refused the same way as the other derived findings: an
        address the gateway has walled off entirely scores nothing.
        """

        if now - activity.recurring_checked < RECURRING_RECHECK:
            return
        activity.recurring_checked = now
        # Asked of the index directly, not read out of the latest events: a
        # busy visit fills any "last N findings" with itself and hides the
        # earlier one this rule is about.
        earlier = self.database.last_signature(ip, now - RECURRING_WINDOW, now - RECURRING_GAP)
        if not earlier:
            return
        hours = (now - earlier) // 3600
        self._emit(
            ip,
            EVENT_RECURRING,
            now,
            source="haproxy-log",
            detail=f"back after {hours}h",
            handled=activity.scanning_was_all_refused,
        )

    def _check_enumeration_breadth(
        self, ip: str, activity: IpActivity, now: int, request: ParsedRequest
    ) -> None:
        """Escalate a wide sweep of made-up paths into its own findings."""

        count = activity.burst_misses
        if count < WIDE_ENUM_MIN:
            return
        handled = refusal_is_a_shield(request, activity)
        detail = f"distinct={count} within {WIDE_ENUM_WINDOW}s"
        self._emit(
            ip, EVENT_WIDE_ENUM, now,
            source="haproxy-log", detail=detail, handled=handled,
        )
        if count >= MASS_ENUM_MIN:
            self._emit(
                ip, EVENT_MASS_ENUM, now,
                source="haproxy-log", detail=detail, handled=handled,
            )

    def _note_invalid_host(
        self, ip: str, activity: IpActivity, now: int, request: ParsedRequest
    ) -> None:
        distinct = activity.note_invalid_host(
            f"{request.host}|{request.path}",
            now,
            self.config.max_paths_per_ip,
            INVALID_HOST_WINDOW,
        )
        if distinct is None or distinct < INVALID_HOST_MIN:
            return
        self._emit(
            ip,
            EVENT_INVALID_HOST,
            now,
            source="haproxy-log",
            detail=f"distinct={distinct}",
            handled=refusal_is_a_shield(request, activity),
        )

    # -- reputation -------------------------------------------------------

    def reputation(
        self,
        ip: str,
        now: Optional[int] = None,
        policy: Optional[ScoringPolicy] = None,
        scheduled: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        now = now or _utc_now()
        policy = policy or self.scoring_policy()
        # Passed in when scoring a whole table, so one query answers for every
        # address instead of one per row.
        if scheduled is None:
            scheduled = self.database.scheduled_bans()
        events = self.database.events_for(ip, now - policy.window_seconds)
        result = score_events(events, now, policy)
        result["ip"] = ip
        result["enforceable"] = enforceable(ip)
        verdict = self.exclusions.verdict(ip)
        result["excluded"] = verdict.excluded
        result["exclusion_reason"] = verdict.reason

        facts = self.database.ip_facts(ip)
        authenticated_at = int(facts.get("authenticated_at") or 0)
        result["authenticated_at"] = authenticated_at
        result["first_seen"] = int(facts.get("first_seen") or 0)
        result["last_seen"] = int(facts.get("last_seen") or 0)
        result["event_count"] = len(events)

        if verdict.excluded:
            # An exempt address is reported with its evidence intact but no
            # standing: HAProxy would not act on it either.
            result["score"] = 0
            result["state"] = "NORMAL"
            result["recommended_action"] = "none"

        result["blockers"] = self.ban_blockers(result, now)
        result["would_ban"] = (
            result["score"] >= WOULD_BAN_SCORE and not result["blockers"]
        )
        result["banned_until"] = int(scheduled.get(ip, 0))
        # The review question that matters: did an address the engine wanted to
        # act on turn out to belong to somebody who then logged in?
        result["likely_false_positive"] = bool(
            authenticated_at and result["score"] >= WATCH_SCORE
        )
        return result

    def reputation_table(
        self,
        now: Optional[int] = None,
        limit: int = 200,
        policy: Optional[ScoringPolicy] = None,
    ) -> List[Dict[str, Any]]:
        now = now or _utc_now()
        policy = policy or self.scoring_policy()
        scheduled = self.database.scheduled_bans()
        rows = [
            self.reputation(ip, now, policy, scheduled)
            for ip in self.database.active_addresses(
                now - policy.window_seconds, limit=limit
            )
        ]
        rows.sort(key=lambda item: item["score"], reverse=True)
        return rows

    # -- enforcement ------------------------------------------------------

    def _queue_enforcement_check(self, ip: str, event_type: str, handled: bool) -> None:
        if event_type not in DEFAULT_WEIGHTS:
            return
        if handled and event_type not in REFUSAL_DOES_NOT_EXCUSE:
            return
        self.enforcement_queue.mark(
            ip,
            urgent=(
                self.scoring_policy().weight(event_type) >= WOULD_BAN_SCORE
                or event_type == EVENT_SUBNET_CAMPAIGN
            ),
        )

    def _recover_enforcement_checks(self) -> None:
        since = _utc_now() - self.policy.window_seconds
        for event in reversed(self.database.recent_findings(ENFORCEMENT_RECOVERY_EVENTS)):
            if event["ts"] >= since:
                self._queue_enforcement_check(event["ip"], event["event_type"], bool(event["handled"]))

    def _enforcement_rows(self, now: int, scheduled: Dict[str, int]) -> Iterable[Dict[str, Any]]:
        """Fresh findings first; every other address gets a bounded fair turn.

        The page's most-talkative 200 addresses must never decide who can
        be banned. No full history scan, unbounded queue or all-IP rescore
        belongs in a poll. A failed check stays pending for the next poll.
        """
        self._enforcement_checked = 0
        policy = self.scoring_policy()
        pending = self.enforcement_queue.batch(ENFORCEMENT_BATCH - ENFORCEMENT_SWEEP_RESERVE)
        seen = set()
        for ip, generation in pending:
            seen.add(ip)
            self._enforcement_checked += 1
            yield self.reputation(ip, now, policy, scheduled)
            self.enforcement_queue.acknowledge(ip, generation)

        allowance = ENFORCEMENT_BATCH - len(pending)
        if not self._enforcement_scan_before:
            self._enforcement_scan_before = now
        addresses = self.database.enforcement_addresses(
            self._enforcement_scan_after, self._enforcement_scan_before, allowance,
        )
        if not addresses and self._enforcement_scan_after != (0, ""):
            self._enforcement_scan_after = (0, "")
            self._enforcement_scan_before = now
            addresses = self.database.enforcement_addresses((0, ""), now, allowance)
        for first_seen, ip in addresses:
            if ip not in seen:
                self._enforcement_checked += 1
                yield self.reputation(ip, now, policy, scheduled)
            self._enforcement_scan_after = (first_seen, ip)
        if len(addresses) < allowance:
            self._enforcement_scan_after = (0, "")
            self._enforcement_scan_before = 0
        self.database.set_state(ENFORCEMENT_CURSOR_KEY, json.dumps({
            "after": self._enforcement_scan_after, "before": self._enforcement_scan_before,
        }))

    def ban_blockers(
        self,
        reputation: Dict[str, Any],
        now: Optional[int] = None,
        policy: Optional[str] = None,
    ) -> List[str]:
        """Why this address must not be banned, whatever its score.

        These are not tunable. The first two exist because banning the person
        administering the gateway is the failure this whole phase has to avoid,
        and the third because a ban simply would not work.
        """

        policy = policy or self.ban_policy
        blockers: List[str] = []
        if reputation.get("excluded"):
            blockers.append(f"exempt ({reputation.get('exclusion_reason')})")
        authenticated_at = int(reputation.get("authenticated_at") or 0)
        if authenticated_at:
            # Not merely authenticated right now: the runtime authorization
            # expires, and a lapsed session must not turn a real user into a
            # ban candidate. The old rule held for ever; U02 holds for seven
            # days after the address last held a sign-in, so an address that
            # was once a user's and later starts scanning can be banned again.
            if policy != BAN_POLICY_U02:
                blockers.append("has authenticated before")
            elif authenticated_at >= (now or _utc_now()) - TRUST_AFTER_SIGN_IN_SECONDS:
                blockers.append("signed in within the last 7 days")
        if not reputation.get("enforceable"):
            blockers.append("IPv4-only ban path")
        return blockers

    def strike_retention(self, level: int) -> int:
        """How long a strike earned at this level stays on the record."""

        ladder = self.ban_durations
        index = min(max(level - 1, 0), len(ladder) - 1)
        return ladder[index] * (level + STRIKE_RETENTION_BASE_MULTIPLIER)

    def longest_strike_retention(self) -> int:
        """The most any strike could be worth keeping, for the sweeper."""

        return max(
            self.strike_retention(level)
            for level in range(1, len(self.ban_durations) + 1)
        )

    def strike_level(self, ip: str, now: int) -> int:
        """How many bans this address has earned that still count.

        Derived from the ban record rather than stored alongside it, so the
        two cannot drift apart. Each link carries its own window, measured
        from the ban that created it, so a long ban keeps its own evidence
        alive instead of outliving it.

        Any fresh activity restarts the countdown from the beginning: an
        address that is still probing has served nothing out, whatever the
        clock says about its last ban.
        """

        stamps = [
            ts for ts in self.database.ban_timestamps(ip)
            # Earned under a different scale of punishment, so worth nothing
            # against this one.
            if ts >= self.ban_durations_changed_at
        ]
        if not stamps:
            return 0

        level = 0
        previous = 0
        for ts in stamps:
            if level and ts - previous > self.strike_retention(level):
                # Long enough went by with nothing: the chain lapsed and this
                # ban starts a new one.
                level = 0
            level += 1
            previous = ts

        alive_from = max(previous, self.database.newest_finding_ts(ip))
        if now - alive_from > self.strike_retention(level):
            return 0
        return level

    # -- ban decisions (06.1-06.3) ----------------------------------------

    def decision_reason(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """The reason for a ban as it stands now, to be kept as it was.

        The findings that counted, heaviest first, each with what it was
        about. The details are this daemon's own -- a normalised path, a rule
        name, a counter reading -- never a query string or a header.
        """
        counted = [
            item for item in row.get("contributions") or []
            if float(item.get("points") or 0) > 0
        ]
        counted.sort(key=lambda item: (-float(item.get("points") or 0), -int(item.get("ts") or 0)))
        return {
            "score": int(row.get("score") or 0),
            "state": str(row.get("state") or ""),
            "categories": dict(row.get("categories") or {}),
            "evidence": [
                {
                    "ts": int(item.get("ts") or 0),
                    "event_type": str(item.get("event_type") or ""),
                    "category": str(item.get("category") or ""),
                    "points": round(float(item.get("points") or 0), 2),
                    "site": str(item.get("site") or ""),
                    "detail": str(item.get("detail") or "")[:DECISION_DETAIL_LENGTH],
                }
                for item in counted[:DECISION_EVIDENCE_LISTED]
            ],
            "evidence_total": len(counted),
        }

    def settle_pending_decisions(self, now: int) -> None:
        """Settle a decision a crash left between applying and recording.

        Applied in HAProxy but not recorded: recorded now, with the time and
        term it was given, so the strike counts once. Not applied: abandoned.
        """
        pending = self.database.pending_decisions(before=now - DECISION_PENDING_GRACE)
        if not pending:
            return
        try:
            standing = self.enforcer.active_bans()
        except OSError as exc:
            LOG.warning("Could not read the ban table to settle decisions: %s", exc)
            return
        scheduled = self.database.scheduled_bans()
        for decision in pending:
            ip = decision["ip"]
            if (
                standing.get(ip) in ADAPTIVE_CODES
                and ip not in scheduled
                and int(decision["until"]) > now
            ):
                self.database.commit_ban(
                    int(decision["id"]), ip, int(decision["until"]), standing[ip],
                    int(decision["ts"]),
                    f"score={decision['score']} seconds={int(decision['until']) - int(decision['ts'])} [settled]",
                )
                LOG.warning("Recorded the ban on %s applied before a crash", ip)
                continue
            if standing.get(ip) in ADAPTIVE_CODES and ip not in scheduled:
                try:
                    self.enforcer.lift(ip)  # its term is over, or it was never ours to keep
                except BAN_TABLE_UNSURE as exc:
                    # Left pending: the next cycle tries again.
                    LOG.warning("%s", exc)
                    continue
            self.database.settle_decision(int(decision["id"]), "abandoned")

    def ban_duration(self, ip: str, now: int) -> int:
        ladder = self.ban_durations
        index = min(self.strike_level(ip, now), len(ladder) - 1)
        return ladder[index]

    def set_ban_durations(self, data: Any) -> Tuple[int, ...]:
        """Replace the ladder. Bans already placed keep the term they were
        given -- their expiry was written as an absolute time when the ban was
        applied, so changing the rule does not re-sentence anybody.
        """

        checked = validate_ban_durations(data)
        now = _utc_now()
        self.database.set_state(BAN_DURATIONS_KEY, json.dumps(list(checked)))
        self.database.set_state(BAN_DURATIONS_CHANGED_KEY, str(now))
        self.ban_durations = checked
        self.ban_durations_changed_at = now
        LOG.warning(
            "Adaptive ban durations changed to %s",
            ", ".join(str(step) for step in checked),
        )
        return checked

    def apply_enforcement(self, now: Optional[int] = None) -> Dict[str, Any]:
        """Ban what qualifies, lift what has served its time.

        Runs on every cycle regardless of mode, because expiry and the kill
        switch have to work even after enforcement has been turned back off.
        """

        with self._decisions:
            return self._apply_enforcement(now)

    def _apply_enforcement(self, now: Optional[int] = None) -> Dict[str, Any]:
        now = now or _utc_now()
        self._enforcement_checked = 0
        applied: List[str] = []
        lifted: List[str] = []

        self.settle_pending_decisions(now)
        scheduled = self.database.scheduled_bans()
        codes = self.database.scheduled_ban_codes()
        enforcing = self.enforcer.allowed
        for ip, until in scheduled.items():
            served = int(until) <= now
            # Turning enforcement off stops blocking immediately: leaving
            # addresses rejected by a feature that is no longer on would be a
            # trap.
            if enforcing and not served:
                continue
            try:
                taken_off = self.enforcer.lift(ip)
            except BAN_TABLE_UNSURE as exc:
                # The ban still stands: kept on the schedule, so the next
                # cycle lifts it -- no "lifted" written, no strike (R01).
                LOG.warning("%s; trying again next cycle", exc)
                continue
            if taken_off:
                lifted.append(ip)
                self._emit(
                    ip,
                    EVENT_BAN_LIFTED,
                    now,
                    source="guardd",
                    detail="expired" if enforcing else "enforcement disabled",
                    fingerprint=f"{ip}|{EVENT_BAN_LIFTED}|{until}",
                )
                self.database.record_decision(
                    ip, now, "lifted", "expiry" if served else "mode", "applied",
                    code=codes.get(ip) if codes.get(ip) in ADAPTIVE_CODES else ADAPTIVE_BAN_CODE,
                    until=int(until), policy=self.ban_policy,
                )
            # Forgotten only once the time was actually served. Switching the
            # mode off used to clear the schedule as well, so a pause was an
            # amnesty: on one gateway a thirty-seven minute visit to monitor
            # released ten addresses for good, and one of them came back the
            # next day and was escalated a rung for an offence it could only
            # commit because it had been let out. Enforcing again resumes
            # what was left; an operator who means to forgive can unban.
            if served:
                self.database.clear_ban(ip)

        if not enforcing:
            # A ban this daemon placed can outlive it: the stick table keeps the
            # entry for the table's expiry, so anything left over is swept here.
            for ip in self.enforcer.adaptive_bans():
                if ip in scheduled:
                    continue
                try:
                    if self.enforcer.lift(ip):
                        lifted.append(ip)
                except BAN_TABLE_UNSURE as exc:
                    LOG.warning("%s; trying again next cycle", exc)
            return {"applied": applied, "lifted": lifted, "enforcing": False}

        # A ban longer than the stick table's own expiry would lapse inside
        # HAProxy while the schedule here still called it banned, and the
        # address would be quietly let back in. The same gap opens whenever
        # HAProxy is restarted or the table is cleared by hand. Re-asserting
        # the entries the schedule still wants closes all three: `set table`
        # rewrites the entry and restarts its expiry, so the schedule is the
        # only thing that decides when a ban ends.
        # Any ban standing in the table, whoever placed it: an operator's (50)
        # or HAProxy's own is left as it is. Re-asserting over it wrote 40 in
        # place of 50, and the operator's ban then ended with the adaptive
        # one (F06). When that other ban ends, the next cycle re-asserts.
        standing = self.enforcer.active_bans()
        for ip, until in scheduled.items():
            if until <= now or ip in standing:
                continue
            # Put back as it was placed: a first step as a page, the rest as a cut-off.
            code = codes.get(ip) if codes.get(ip) in ADAPTIVE_CODES else ADAPTIVE_BAN_CODE
            if self.enforcer.ban(ip, code=code):
                LOG.info("Re-asserted the ban on %s, gone from the table", ip)

        for row in self._enforcement_rows(now, scheduled):
            self._apply_row_decision(row, now, scheduled, codes, standing, applied)
        if applied:
            self._check_burst(len(applied), now)
        return {"applied": applied, "lifted": lifted, "enforcing": True}

    def apply_urgent_enforcement(self, now: Optional[int] = None) -> Dict[str, Any]:
        """Fast-path enforcement for urgent findings between full poll cycles.

        Only runs when enforcement is active and at least one urgent IP is
        queued. Reuses the exact same per-row decision logic and lock as the
        full cycle, without running table expiry sweeps or background scans.
        """
        with self._decisions:
            now = now or _utc_now()
            if not self.enforcer.allowed or not self.enforcement_queue.has_urgent():
                return {"applied": [], "enforcing": self.enforcer.allowed}
            scheduled = self.database.scheduled_bans()
            codes = self.database.scheduled_ban_codes()
            standing = self.enforcer.active_bans()
            policy = self.scoring_policy()
            applied: List[str] = []
            pending = self.enforcement_queue.urgent_batch(ENFORCEMENT_BATCH)
            for ip, generation in pending:
                row = self.reputation(ip, now, policy, scheduled)
                self._apply_row_decision(row, now, scheduled, codes, standing, applied)
                self.enforcement_queue.acknowledge(ip, generation)
            if applied:
                self.fast_enforcements += len(applied)
                self._check_burst(len(applied), now)
            return {"applied": applied, "enforcing": True}

    def _apply_row_decision(
        self,
        row: Dict[str, Any],
        now: int,
        scheduled: Dict[str, int],
        codes: Dict[str, int],
        standing: Dict[str, int],
        applied: List[str],
    ) -> bool:
        ip = row["ip"]
        if row["score"] < WOULD_BAN_SCORE:
            return False
        after_page = False
        if scheduled.get(ip, 0) > now:
            # Serving its ban. Only a first step shown as a page is
            # looked at again: signatures on different paths after the
            # page are a scanner going on, not a person.
            if not (
                codes.get(ip) == ADAPTIVE_PAGE_CODE
                and standing.get(ip) == ADAPTIVE_PAGE_CODE
                and self.database.signature_paths_since(ip, self.database.last_ban_ts(ip))
                >= PAGE_ESCALATION_PATHS
            ):
                return False
            after_page = True
        if standing.get(ip, ADAPTIVE_BAN_CODE) not in ADAPTIVE_CODES:
            # Already banned by an operator or by HAProxy's own rules:
            # not overwritten; decided again once that ban is over.
            return False
        blockers = self.ban_blockers(row, now)
        if blockers:
            return False
        # Findings decay over hours, so a score that justified one ban is
        # still there when it expires. Requiring fresh evidence keeps the
        # progressive ladder counting repeat incidents rather than simply
        # measuring how long a single scan stays in the window.
        last_ban = self.database.last_ban_ts(ip)
        floor = last_ban
        if not after_page:
            # A first step shown as a page lets the address through to
            # HAProxy, so a person can try the same thing again while
            # it lasts. That is not a new incident: after such a ban has
            # run its course, only findings from after its end count.
            last = self.database.last_applied_ban(ip)
            if last and last["code"] == ADAPTIVE_PAGE_CODE:
                floor = max(floor, min(int(last["until"]), now))
        if last_ban and self.database.newest_finding_ts(ip) <= floor:
            return False
        duration = self.ban_duration(ip, now)
        level = self.strike_level(ip, now)
        code = ADAPTIVE_PAGE_CODE if (self.first_step_page and level == 0 and not after_page) else ADAPTIVE_BAN_CODE
        reason = self.decision_reason(row)
        if after_page:
            reason["after_page"] = True
        # The reason is written down before anything is applied, and
        # what happened after: a crash between the two leaves a pending
        # decision the next cycle settles (settle_pending_decisions).
        decision = self.database.record_decision(
            ip, now, "applied", "adaptive", "pending",
            code=code, until=now + duration,
            strike=level + 1, score=int(row["score"]),
            policy=self.ban_policy, reason=reason,
        )
        if not self.enforcer.ban(ip, code=code):
            self.database.settle_decision(decision, "failed")
            self.enforcement_queue.mark(ip, urgent=True)
            return False
        categories = ", ".join(sorted(row.get("categories") or {}))
        self.database.commit_ban(
            decision, ip, now + duration, code, now,
            f"score={row['score']} seconds={duration} [{categories}]"
            + (" after the page" if after_page else ""),
        )
        scheduled[ip] = now + duration
        codes[ip] = code
        standing[ip] = code
        self.events_recorded += 1
        applied.append(ip)
        LOG.warning(
            "Adaptive ban applied to %s for %ds (score %d)%s",
            ip,
            duration,
            row["score"],
            " -- a page first" if code == ADAPTIVE_PAGE_CODE
            else " -- went on after the page" if after_page else "",
        )
        self._report_ban(ip, duration, row, categories)
        return True

    def _check_burst(self, banned: int, now: int) -> None:
        """security.burst: many addresses banned in a few minutes.

        One ban is routine -- a scanner a day is the background. A wave is
        news: a campaign, or a rule suddenly matching ordinary clients. Once
        per window at most, and best effort like every report.
        """
        self._burst_bans.extend([now] * banned)
        while self._burst_bans and self._burst_bans[0] <= now - BURST_WINDOW_SECONDS:
            self._burst_bans.popleft()
        count = len(self._burst_bans)
        if count < BURST_MIN_BANS:
            return
        if self._burst_reported is not None and now - self._burst_reported < BURST_REPORT_GAP_SECONDS:
            return
        self._burst_reported = now
        if self.alerts is None:
            return
        with contextlib.suppress(Exception):
            self.alerts.observe(
                "security.burst",
                "gateway",
                summary=(
                    f"{count} addresses banned in the last "
                    f"{BURST_WINDOW_SECONDS // 60} minutes"
                ),
                detail=(
                    "Either a campaign is under way or a rule has started to match "
                    "ordinary clients; the adaptive protection page shows who and why."
                ),
            )

    def report_failing(self) -> None:
        """Tell the alert engine while the cycle keeps failing, and once when
        it works again (06.7).

        A level, reported every cycle it holds (the client sends an unchanged
        one again only every two minutes), so an engine that dies with it
        raised lets it go stale rather than pinning it on. Best effort, like
        every report: the cycle does not depend on the alert daemon.
        """
        failing = self.consecutive_failures >= ENGINE_FAILING_AFTER
        if not failing and not self._failing_reported:
            return
        self._failing_reported = failing
        if self.alerts is None:
            return
        with contextlib.suppress(Exception):
            if failing:
                self.alerts.observe(
                    ENGINE_FAILING_RULE,
                    "guardd",
                    active=True,
                    # No running count in it: an unchanged report is sent
                    # again only every two minutes, a changed one at once.
                    summary=(
                        "Adaptive protection keeps failing: "
                        f"{str(self.last_error or 'unknown error')[:200]}"
                    ),
                    detail=(
                        "Until it works again nothing is scored or banned and no ban decision "
                        "is recorded; bans already in HAProxy stay. The service journal of "
                        "easy-ha-proxy-guardd has the details; a full disk is the usual cause."
                    ),
                )
            else:
                self.alerts.clear(
                    ENGINE_FAILING_RULE, "guardd", summary="Adaptive protection works again",
                )

    def _report_ban(
        self, ip: str, duration: int, row: Dict[str, Any], categories: str
    ) -> None:
        """Tell the alert engine an address was acted upon.

        Best effort by contract: enforcement must not depend on the alert
        daemon being up, so anything that goes wrong here is swallowed.
        """
        if self.alerts is None:
            return
        with contextlib.suppress(Exception):
            self.alerts.observe(
                "security.hostile_ip",
                ip,
                summary=f"Adaptive protection banned {ip} for {duration}s",
                detail=(
                    f"score {row.get('score')} over {categories or 'no category'}; "
                    f"the ban lifts automatically when it expires"
                ),
            )

    def place_manual_ban(self, ip: str, now: Optional[int] = None) -> Dict[str, Any]:
        """An operator's ban, placed here rather than by the panel (R02/R03).

        Under the same lock as every other decision about the ban table, so
        an expiring adaptive ban read as code 40 can no longer clear a manual
        ban written in between. Remembered before HAProxy is asked, and with
        the term the table gives it once it is there: a restart of HAProxy
        right after the panel says "banned" puts it back. Raises ValueError
        for an address that cannot be banned and ManualBanRefused when
        HAProxy refuses.

        A new ban is a new decision (R07): its end is exactly the one the
        table gives it -- shorter than the default when the table keeps bans
        for less -- and a copy restored after a restart becomes this ban.
        A refused one, or one whose answer was lost, puts back whatever was
        remembered before it: an earlier ban by hand still standing in the
        table is still remembered (R08).
        """
        now = now or _utc_now()
        checked = str(ip or "").strip()
        if not enforceable(checked):
            raise ValueError("only an IPv4 address can be banned")
        with self._decisions:
            remembered = True
            previous: Optional[Dict[str, int]] = None
            try:
                previous = self.database.manual_bans().get(checked)
                self.database.write_manual_ban(checked, now, now + MANUAL_BAN_DEFAULT_SECONDS, now)
            except sqlite3.Error as exc:
                remembered = False
                LOG.warning("Could not remember the manual ban on %s: %s", checked, exc)

            def put_back() -> None:
                if not remembered:
                    return
                with contextlib.suppress(sqlite3.Error):
                    if previous:
                        self.database.write_manual_ban(
                            checked, previous["placed_at"], previous["expires_at"],
                            previous["seen_at"], previous["reasserted"],
                        )
                    else:
                        self.database.forget_manual_ban(checked)

            try:
                placed = self.enforcer.restore(checked, MANUAL_BAN_CODE)
            except OSError:
                put_back()  # the answer is lost: the next poll sees what HAProxy holds
                raise
            if not placed:
                put_back()
                raise ManualBanRefused(f"HAProxy refused the ban on {checked}")
            until = now + MANUAL_BAN_DEFAULT_SECONDS
            with contextlib.suppress(OSError):
                fields = read_table(self.config.haproxy_socket, "tbl_ban", f"key {checked}").get(checked) or {}
                if _safe_int(fields.get("exp")) > 0:
                    until = now + _safe_int(fields.get("exp")) // 1000
            try:
                self.database.write_manual_ban(checked, now, until, now)
                self.database.record_decision(
                    checked, now, "applied", "operator", "applied",
                    code=MANUAL_BAN_CODE, until=until, policy=self.ban_policy,
                )
            except sqlite3.Error as exc:
                # Banned all the same; the answer says it may not survive a
                # restart of HAProxy rather than promising that it will.
                remembered = False
                LOG.warning("Banned %s by hand, but could not remember it: %s", checked, exc)
        LOG.warning("Ban placed by hand on %s until %s", checked, until)
        return {"ok": True, "ip": checked, "code": MANUAL_BAN_CODE, "until": until,
                "remembered": remembered}

    def forget_ban(self, ip: str, now: Optional[int] = None) -> Dict[str, Any]:
        """Drop this daemon's hold on an address, because a person said so.

        Clearing the stick table alone is not enough, and used to look like a
        bug in the unban button: the schedule here still wanted the address
        banned, so the next cycle noticed the entry was missing and put it
        straight back. Ten seconds after the operator unbanned somebody they
        were banned again, with a re-assert line in the journal as the only
        clue that anything had happened.

        The schedule is the authority on when a ban ends, so an unban has to
        reach it. Lifting the table entry here as well makes the call
        complete on its own rather than depending on what the caller does
        next.
        """

        now = now or _utc_now()
        checked = str(ip or "").strip()
        if not checked:
            raise ValueError("an address is required")
        if "%" in checked:
            raise ValueError("invalid IP address")
        ipaddress.ip_address(checked)

        with self._decisions:
            return self._forget_ban(checked, now)

    def _forget_ban(self, checked: str, now: int) -> Dict[str, Any]:
        held = int(self.database.scheduled_bans().get(checked, 0))
        self.database.clear_ban(checked)
        # The operator's own ban is lifted by the caller; remembering it would
        # put it back after the next restart of HAProxy.
        manual = self.database.forget_manual_ban(checked)
        # The schedule goes whatever HAProxy says: the operator means the
        # address to be let go. The table entry is taken off here too --
        # whoever placed it -- under the same lock as every other change to
        # the ban table, so a ban placed meanwhile by another request is not
        # undone by a write that comes after (R09). A refusal is said, and
        # written as one -- not as a lift.
        refused = ""
        lifted = released = False
        try:
            lifted = self.enforcer.lift(checked)
            released = self.enforcer.release(checked)
        except BAN_TABLE_UNSURE as exc:
            refused = str(exc)
            LOG.warning("%s", exc)
        if held or lifted:
            self._emit(
                checked,
                EVENT_BAN_LIFTED,
                now,
                source="operator",
                detail="cleared by hand",
                fingerprint=f"{checked}|{EVENT_BAN_LIFTED}|{now}",
            )
            LOG.warning(
                "Ban on %s cleared by hand; the schedule is dropped", checked
            )
        # HAProxy's own ban is lifted here too: written as the operator's,
        # not as "no longer in force" on the next cycle.
        legacy = self._settle_legacy_observed(checked)
        if held or lifted or manual or legacy:
            self.database.record_decision(
                checked, now, "lifted", "operator", "failed" if refused else "applied",
                code=(ADAPTIVE_BAN_CODE if (held or lifted)
                      else MANUAL_BAN_CODE if manual else legacy),
                until=held, policy=self.ban_policy,
            )
        return {
            "ok": True,
            "refused": refused,
            "ip": checked,
            "was_scheduled": bool(held),
            "lifted": lifted or released,
            # HAProxy holds no ban on the address now, by this daemon's own
            # read and write: the panel has nothing left to write (R09).
            "cleared": not refused,
        }

    def quality(self, days: int = 7, now: Optional[int] = None) -> Dict[str, Any]:
        """The protection's own record of the last days, with what waits for the operator."""
        days = max(1, min(int(days), QUALITY_MAX_DAYS))
        now = now or _utc_now()
        kept = self._quality_cache.get(days)
        if kept and now - kept[0] < QUALITY_CACHE_SECONDS:
            return kept[1]
        report = self.database.quality(now - days * 86400, now)
        report["days"] = days
        report["mode"] = self.enforcer.mode
        dismissed = set(_dismissed_candidates(self.database))
        report["signature_candidates"] = len(self.candidates.suggestions(dismissed))
        names = [row for row in self.unknown_hosts.listing()
                 if not row.get("clients") and int(row.get("addresses") or 0) >= QUALITY_NETWORK_MIN
                 and row.get("host") not in self.trap_hosts]
        report["trap_candidates"] = len(names)
        report["trap_names"] = len(self.trap_hosts)
        report["path_shield"] = {key: self.shield_state().get(key) for key in ("enabled", "active", "segments", "paths")}
        self._quality_cache[days] = (now, report)
        return report

    def weekly_summary_text(self, report: Dict[str, Any]) -> Tuple[str, str]:
        """The week in two sentences and a few lines, for the alert channel."""
        bans = report["bans"]
        summary = (f"Adaptive protection banned {report['banned_addresses']} addresses in {report['days']} days"
                   if bans else f"Adaptive protection banned nobody in {report['days']} days")
        lines = [
            f"Mode: {report['mode']}.",
            f"Bans: {bans} ({report['bans_per_day']} a day)." if report.get("bans_per_day") is not None else f"Bans: {bans}.",
            f"Decided within {QUALITY_AT_ONCE_SECONDS} s of the first finding: {report['decided_at_once']} of {bans}.",
            f"Came back after a ban ended: {report['came_back_after_a_ban']} of {report['first_bans_ended']}.",
            f"Bans lifted by an operator: {report['lifted_by_operator']}.",
            f"Probers that were never banned: {report['probers_never_banned']}.",
        ]
        if report["networks"]:
            lines.append("Networks with several banned addresses: " + ", ".join(
                f"{row['network']} ({row['addresses']})" for row in report["networks"]) + ".")
        waiting = []
        if report["signature_candidates"]:
            waiting.append(f"{report['signature_candidates']} signature candidates")
        if report["trap_candidates"]:
            waiting.append(f"{report['trap_candidates']} host names that look like traps")
        if waiting:
            lines.append("Waiting for your decision on the Detection rules page: " + " and ".join(waiting) + ".")
        return summary, "\n".join(lines)

    def weekly_summary_tick(self, now: Optional[int] = None) -> bool:
        """Report the week once, on Monday morning; never a reason to fail a cycle."""
        if self.alerts is None:
            return False
        now = now or _utc_now()
        local = time.localtime(now)
        if local.tm_wday != WEEKLY_SUMMARY_WEEKDAY or local.tm_hour < WEEKLY_SUMMARY_HOUR:
            return False
        week = time.strftime("%G-W%V", local)
        if self.database.get_state(WEEKLY_SUMMARY_KEY, "") == week:
            return False
        if self.enforcer.mode == MODE_OFF:
            return False
        try:
            summary, detail = self.weekly_summary_text(self.quality(7, now))
            self.alerts.observe(WEEKLY_SUMMARY_RULE, week, summary=summary, detail=detail)
            self.database.set_state(WEEKLY_SUMMARY_KEY, week)
            return True
        except Exception:  # pylint: disable=broad-except
            LOG.debug("the weekly summary could not be reported", exc_info=True)
            return False

    def first_step_state(self) -> Dict[str, Any]:
        codes = self.database.scheduled_ban_codes()
        return {"enabled": self.first_step_page,
                "showing_page": sum(1 for code in codes.values() if code == ADAPTIVE_PAGE_CODE)}

    def set_first_step_page(self, enabled: Any) -> Dict[str, Any]:
        """Show the first step as a page, or cut it off like the rest.

        Switching it off turns the first steps standing now into cut-offs at
        once, so an operator who switches it off because of the page is not
        left waiting for them to run out. Switching it on changes only the
        bans placed from then on.
        """
        if type(enabled) is not bool:
            raise ValueError("enabled must be true or false")
        changed = 0
        with self._decisions:
            self.database.set_state(FIRST_STEP_PAGE_KEY, "1" if enabled else "0")
            self.first_step_page = enabled
            if not enabled:
                standing = self.enforcer.active_bans()
                for ip, code in self.database.scheduled_ban_codes().items():
                    if code != ADAPTIVE_PAGE_CODE:
                        continue
                    if standing.get(ip) == ADAPTIVE_PAGE_CODE and not self.enforcer.ban(ip, code=ADAPTIVE_BAN_CODE):
                        continue  # refused: still a page; the next switch or cycle tries again
                    self.database.set_ban_code(ip, ADAPTIVE_BAN_CODE)
                    changed += 1
        LOG.warning("First-step page switched %s%s", "on" if enabled else "off",
                    f"; {changed} first steps now cut off" if changed else "")
        return {**self.first_step_state(), "changed": changed}

    def sync_shield(self, now: int) -> Dict[str, Any]:
        """Bring HAProxy's shield lists in step; never a reason to fail a cycle."""
        try:
            settings = self.detection.config
            wanted = shield_entries(self.enforcer.mode, self.shield_enabled, dict(settings.get("modes") or {}),
                                    list(settings.get("exceptions") or []), now)
            return self.shield.sync(wanted, now)
        except Exception as exc:  # pylint: disable=broad-except
            self.shield.status = {**self.shield.status, "active": False, "error": str(exc)[:300]}
            return self.shield.status

    def shield_state(self) -> Dict[str, Any]:
        return {"enabled": self.shield_enabled, "mode": self.enforcer.mode, **self.shield.status}

    def set_shield(self, enabled: Any, now: Optional[int] = None) -> Dict[str, Any]:
        """Switch the shield on or off; HAProxy follows before this answers."""
        if type(enabled) is not bool:
            raise ValueError("enabled must be true or false")
        self.database.set_state(SHIELD_ENABLED_KEY, "1" if enabled else "0")
        self.shield_enabled = enabled
        LOG.warning("Path shield switched %s", "on" if enabled else "off")
        self.sync_shield(now or _utc_now())
        return self.shield_state()

    def set_mode(self, mode: str, now: Optional[int] = None) -> Dict[str, Any]:
        """Switch between observing and enforcing, and reconcile immediately."""

        mode = str(mode or "").strip().lower()
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"mode must be one of {', '.join(SUPPORTED_MODES)}")
        now = now or _utc_now()
        with self._decisions:
            previous = self.enforcer.mode
            self.database.set_state("mode_override", mode)
            self.enforcer.mode = mode
            LOG.warning("Adaptive protection mode changed: %s -> %s", previous, mode)
            result = self._apply_enforcement(now)
        # Leaving enforce empties the shield at once, not a cycle later.
        self.sync_shield(now)
        return {"mode": mode, "previous": previous, **result}

    @staticmethod
    def _parse_ban_detail(detail: str) -> Dict[str, Any]:
        """Read back the reason recorded when the ban was applied.

        The format is this daemon's own -- "score=90 seconds=86400 [vcs,
        secrets]" -- so parsing it is reading our own handwriting rather than
        guessing at someone else's. Anything unrecognised yields nothing
        rather than a wrong number.
        """

        parsed: Dict[str, Any] = {"score": None, "categories": []}
        if not detail:
            return parsed
        match = re.search(r"score=(\d+)", detail)
        if match:
            parsed["score"] = int(match.group(1))
        match = re.search(r"\[([^\]]*)\]", detail)
        if match:
            parsed["categories"] = [
                part.strip() for part in match.group(1).split(",") if part.strip()
            ]
        return parsed

    def current_bans(self, now: Optional[int] = None) -> List[Dict[str, Any]]:
        """The addresses being held right now, and until when.

        Built from the schedule rather than from the reputation table,
        because the reputation table only covers addresses seen inside the
        scoring window. An address that was banned and then went quiet --
        which is the whole point of banning it -- drops out of that window
        and would silently vanish from a list of who is banned.

        The stick table cannot answer this either. Its entries carry the
        table's own expiry, not this daemon's schedule, so it will say six
        days about a ban that lifts in an hour.
        """

        now = now or _utc_now()
        scheduled = self.database.scheduled_bans()
        rows: List[Dict[str, Any]] = []
        for ip, until in scheduled.items():
            remaining = int(until) - now
            if remaining <= 0:
                # Served, and due to be lifted on the next cycle.
                continue
            decision = self.database.adaptive_ban_detail(ip=ip, until=int(until))
            last_ban = decision['ts'] if decision else self.database.last_ban_ts(ip)
            # Why it was banned, taken from what was written down at the
            # time. Recomputing it here reports what the address is doing
            # *now*, and a banned address is doing nothing: its findings
            # decay and fall out of the scoring window while it is locked
            # out, so within hours every ban read "score 0, no categories".
            # True, useless, and the opposite of the question being asked.
            recorded = self._parse_ban_detail(self.database.last_ban_detail(ip))
            reason = (decision or {}).get('reason') or {}
            standing = self.reputation(ip, now, scheduled=scheduled)
            rows.append({
                "ip": ip,
                "id": (decision or {}).get('id'),
                "until": int(until),
                "seconds_left": remaining,
                "banned_at": last_ban,
                "strikes": (decision or {}).get('strike'),
                "score": (
                    decision['score'] if decision else
                    recorded["score"] if recorded["score"] is not None
                    else standing.get("score", 0)
                ),
                "state": standing.get("state", ""),
                "categories": (
                    decision_summary(reason).get('categories') or recorded["categories"]
                    or sorted(standing.get("categories") or {})
                ),
                "likely_false_positive": bool(
                    standing.get("likely_false_positive")
                ),
            })
        rows.sort(key=lambda row: row["seconds_left"])
        return rows

    def shadow_review(
        self,
        now: Optional[int] = None,
        limit: int = 200,
        policy: Optional[ScoringPolicy] = None,
    ) -> Dict[str, Any]:
        """What enforcement would have done, and where it would have been wrong."""

        now = now or _utc_now()
        policy = policy or self.scoring_policy()
        rows = self.reputation_table(now, limit=limit, policy=policy)
        by_state: Dict[str, int] = {}
        for row in rows:
            by_state[row["state"]] = by_state.get(row["state"], 0) + 1
        return {
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "supported_modes": list(SUPPORTED_MODES),
            "enforcement_possible": self.enforcer.allowed,
            "ban_durations_seconds": list(self.ban_durations),
            "policy": {
                "weights": dict(policy.weights),
                "category_cap": policy.category_cap,
                "window_seconds": policy.window_seconds,
                "decay_seconds": policy.decay_seconds,
                # The page said "ban what crosses the threshold" without ever
                # saying what the threshold was, so a score of 43 meant
                # nothing to the person reading it. The bands live here, not
                # in the page, because the daemon is what applies them.
                "bands": [
                    {"from": threshold, "state": name,
                     "bans": threshold >= WOULD_BAN_SCORE}
                    for threshold, name in DEFAULT_THRESHOLDS
                ],
                "would_ban_score": WOULD_BAN_SCORE,
            },
            # The page could show a score of 60 and the word "banned" and
            # never say what the address had actually done to earn it. The
            # rules live in a replaceable file now, so the version matters
            # too: without it nobody can tell which list a gateway is
            # running.
            "signatures": signature_summary(),
            # Who is actually being held, which the page could not say: the
            # ban list elsewhere shows the stick table's expiry, which is the
            # table's own and not the schedule's.
            "bans": self.current_bans(now),
            "summary": {
                "scored": len(rows),
                "would_ban": sum(1 for row in rows if row["would_ban"]),
                "likely_false_positive": sum(
                    1 for row in rows if row["likely_false_positive"]
                ),
                "unenforceable": sum(
                    1 for row in rows if not row["enforceable"] and row["score"] > 0
                ),
                "excluded": sum(1 for row in rows if row["excluded"]),
                "banned_now": sum(1 for row in rows if row["banned_until"]),
                "blocked_from_ban": sum(
                    1
                    for row in rows
                    if row["score"] >= WOULD_BAN_SCORE and row["blockers"]
                ),
                "by_state": by_state,
            },
            "addresses": [
                {key: value for key, value in row.items() if key != "contributions"}
                for row in rows
            ],
        }

    # -- maintenance ------------------------------------------------------

    def run_maintenance(self) -> Dict[str, Any]:
        now = _utc_now()
        cutoff = now - self.config.event_retention_days * 86400
        # Ban records outlive ordinary findings by as long as the ladder can
        # still be counting them.
        ban_cutoff = min(cutoff, now - self.longest_strike_retention())
        deleted = self.database.apply_retention(
            events_before=cutoff, bans_before=ban_cutoff
        )
        deleted["rate_warnings"] = self.database.prune_rate_warnings(
            before=now - RATE_WARNINGS_KEEP_DAYS * 86400, keep=RATE_WARNINGS_KEEP_ROWS
        )
        # As long as the ban records themselves: the reason must not go
        # before the strike it explains.
        deleted["ban_decisions"] = self.database.prune_decisions(
            before=ban_cutoff, keep=DECISIONS_KEEP_ROWS, now=now
        )
        if any(deleted.values()):
            self.database.incremental_vacuum()
        pruned = self.memory.prune(now - 6 * 3600)
        self.subnet_correlator.prune(now)
        self.candidates.prune(now - CANDIDATE_TTL)
        self.unknown_hosts.prune(now - UNKNOWN_HOSTS_TTL)
        self.detection.persist(now, force=True)
        with contextlib.suppress(sqlite3.Error):
            self.database.set_state(
                CANDIDATES_KEY, json.dumps(self.candidates.snapshot())
            )
            self.database.set_state(
                UNKNOWN_HOSTS_KEY, json.dumps(self.unknown_hosts.snapshot())
            )
        LOG.info(
            "Maintenance: deleted=%s pruned_ips=%d tracked=%d",
            json.dumps(deleted),
            pruned,
            len(self.memory),
        )
        return {"deleted": deleted, "pruned_ips": pruned}

    # -- reporting --------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        now = _utc_now()
        last_poll = self.last_poll_ts
        stale_after = max(60, self.config.poll_interval_seconds * 6)
        protected_ips, probation_ips = self.memory.segment_counts()
        return {
            "mode": self.enforcer.mode,
            "configured_mode": self.config.mode,
            "mode_overridden": self.enforcer.mode != self.config.mode,
            "enforcement_possible": self.enforcer.allowed,
            "enforcement_refusals": self.enforcer.refused,
            "bans_applied": self.enforcer.applied,
            "bans_lifted": self.enforcer.lifted,
            "bans_active": len(self.database.scheduled_bans()),
            "running": bool(self._thread and self._thread.is_alive()),
            "degraded": last_poll is None or (now - last_poll) > stale_after,
            "last_poll_ts": last_poll,
            "polls_total": self.polls_total,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "log": {
                "path": self.config.log_file,
                "lines_read": self.lines_read,
                "lines_parsed": self.lines_parsed,
                "lag_bytes": self.cursor.lag_bytes,
                "rotations": self.cursor.rotations,
                "last_error": self.cursor.last_error,
            },
            "memory": {
                "tracked_ips": protected_ips + probation_ips,
                "protected_ips": protected_ips,
                "probation_ips": probation_ips,
                "max_tracked_ips": self.memory.max_ips,
                "max_paths_per_ip": self.memory.max_paths,
                "evictions": self.memory.evictions,
            },
            "subnet_correlation": self.subnet_correlator.summary(now),
            "exclusions": {
                "networks": self.exclusions.network_count,
                "authenticated": self.exclusions.authenticated_count,
                "observations_skipped": self.excluded_observations,
            },
            "events_recorded": self.events_recorded,
            "enforcement_checks": {
                **self.enforcement_queue.status(),
                "checked_last_cycle": self._enforcement_checked,
                "fast_enforcements": self.fast_enforcements,
                "batch_limit": ENFORCEMENT_BATCH,
                "sweep_after": self._enforcement_scan_after,
                "sweep_before": self._enforcement_scan_before,
            },
            "rate_warnings": self.trusted_rates.summary(),
            "hard_floor": self.hard_floor.summary(),
            "path_shield": self.shield_state(),
            "first_step_page": self.first_step_state(),
            "ban_policy": {
                "current": self.ban_policy,
                "switch": self.ban_policy_state(),
                "legacy_bans": dict(self.legacy_bans),
                "legacy_lifted": self.legacy_lifted,
            },
            "manual_bans": {
                "remembered": len(self.database.manual_bans()),
                "restored": self.manual_restored,
            },
            "live_buffer": self._live_health(),
            "unreadable_tables": sorted(self.unreadable_tables),
        }

    def _live_health(self) -> Optional[Dict[str, Any]]:
        if self.live is None:
            return None
        status = self.live.status()
        return {
            "records": status["records"],
            "bytes": status["bytes"],
            "budget_mib": self.live_budget["budget_mib"],
            "max_bytes": status["max_bytes"],
            "max_records": status["max_records"],
            "max_seconds": status["max_seconds"],
        }
