"""Optional SQLite access-request log for live search and diagnostics."""

from __future__ import annotations

import contextlib
import heapq
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    LOG,
    MAX_HOST_LENGTH,
    MAX_PATH_LENGTH,
    MAX_USER_AGENT_LENGTH,
    _clamp_int,
    _utc_now,
)
from .parser import (
    LIVE_ADMIN_BACKENDS,
    LOGGED_AGENT_OTHER,
    L_AGENT,
    L_BACKEND,
    L_HOST,
    L_IP,
    L_METHOD,
    L_PATH,
    L_REFUSAL,
    L_REQUEST_ID,
    L_RESPONSE,
    L_STATUS,
    L_TS,
    ParsedRequest,
    live_refusal,
)
from .runtime import GuardConfig

# ---------------------------------------------------------------------------
# Request log
# ---------------------------------------------------------------------------

REQUEST_LOG_PATH = os.environ.get(
    "GUARDD_REQUEST_LOG", "/var/lib/easy-ha-proxy/requests/requests.db"
)

_REQUEST_SCHEMA: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS requests (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        request_id  TEXT    NOT NULL DEFAULT '',
        client      TEXT    NOT NULL DEFAULT '',
        status      INTEGER NOT NULL DEFAULT 0,
        frontend    TEXT    NOT NULL DEFAULT '',
        backend     TEXT    NOT NULL DEFAULT '',
        server      TEXT    NOT NULL DEFAULT '',
        method      TEXT    NOT NULL DEFAULT '',
        host        TEXT    NOT NULL DEFAULT '',
        path        TEXT    NOT NULL DEFAULT '',
        bytes_out   INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        bad_request INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_requests_ts ON requests(ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_rid ON requests(request_id)",
    "CREATE INDEX IF NOT EXISTS ix_requests_client ON requests(client, ts)",
    "CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status, ts)",
    # A user agent is long and repeats on almost every row, so each is kept
    # once. last_ts is when a stored request last used it: one older than
    # the oldest request left is referenced by nothing and goes.
    """
    CREATE TABLE IF NOT EXISTS agents (
        id      INTEGER PRIMARY KEY,
        agent   TEXT    NOT NULL UNIQUE,
        last_ts INTEGER NOT NULL DEFAULT 0
    )
    """,
)

REQUEST_LOG_SCHEMA_VERSION = 3
# Added in version 2, with what an older row reads as: how soon the server
# answered (%Tr; -1 when it did not), the five timers, how the request
# ended, the ban rule, and the client's user agent. Version 3 adds the
# verified username; historical rows remain unknown.
_REQUEST_ADDED_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("response_ms", "INTEGER NOT NULL DEFAULT -1"),
    ("times", "TEXT NOT NULL DEFAULT ''"),
    ("term", "TEXT NOT NULL DEFAULT ''"),
    ("ban_reason", "TEXT NOT NULL DEFAULT ''"),
    ("agent_id", "INTEGER NOT NULL DEFAULT 0"),
    ("authenticated_user", "TEXT NOT NULL DEFAULT ''"),
)

# LIKE needs an escape character so a path containing % or _ is matched
# literally rather than as a wildcard.
_LIKE_ESCAPE = "\\"

# A search answers within this, with what it found so far and where it
# stopped, rather than holding the page -- and, before, the engine -- for as
# long as a filter that matches nothing takes to scan the whole store
# (about nine seconds for three days of traffic on the gateway's ARM CPU).
REQUEST_SEARCH_SECONDS = 4.0
# Counting stops here: "more than 10 000" says as much as the exact number.
REQUEST_COUNT_CAP = 10000
# Rows are scanned newest first in steps of this many ids, so a search that
# runs out of time knows exactly how far back it looked.
REQUEST_SCAN_STEP = 20000
# Searches at once; more wait their turn instead of sharing two cores.
REQUEST_SEARCHES_AT_ONCE = 2
# An address with up to this many requests in the period is read through
# its index; one that is most of the traffic (an office behind one address,
# the operator's own) is cheaper to scan for than to sort.
REQUEST_INDEXED_ROWS = 5000


# What a search of the request log asks for, read once and answered the same
# way by the store (as SQL) and by the live buffer in memory (as a test of
# each record), so the page means the same thing whichever answers it.
_STATUS_TOKEN = re.compile(r"^([1-5])(\d\d|xx)$")
# The status codes the gateway answers itself (a server never chose them):
# the same rule as live_refusal, in SQL. The store keeps "" as the server of
# a request no server answered.
_REFUSED_SQL = (
    "(status IN (423, 429) OR ban_reason != '' OR (server = '' AND"
    " (status IN (451, 401, 403, 400) OR term LIKE 'PR%')))"
)


def parse_statuses(text: str) -> Tuple[Tuple[int, int], ...]:
    """ "404", "5xx", or several: "4xx, 500". Ranges as [low, high)."""
    ranges: List[Tuple[int, int]] = []
    for token in re.split(r"[\s,;]+", str(text or "").strip().lower())[:8]:
        found = _STATUS_TOKEN.match(token)
        if found is None:
            continue
        if found.group(2) == "xx":
            low = int(found.group(1)) * 100
            ranges.append((low, low + 100))
        else:
            code = int(token)
            ranges.append((code, code + 1))
    return tuple(dict.fromkeys(ranges))


@dataclass(frozen=True)
class RequestQuery:
    since: float = 0
    until: float = 0
    client: str = ""
    statuses: Tuple[Tuple[int, int], ...] = ()
    host: str = ""
    backend: str = ""
    request_id: str = ""
    method: str = ""
    path: str = ""
    hide_admin: bool = False
    refused: bool = False
    slower_ms: int = 0
    # As the log writes a user agent: lower case, every other character "_".
    agent: str = ""

    @classmethod
    def build(cls, *, since: Any = 0, until: Any = 0, client: str = "", status: str = "",
              host: str = "", backend: str = "", request_id: str = "", method: str = "",
              path: str = "", hide_admin: bool = False, refused: bool = False,
              slower: Any = 0, agent: str = "") -> "RequestQuery":
        agent = str(agent or "").strip().lower()[:120]
        backend = str(backend or "")[:200]
        request_id = str(request_id or "")[:200]
        return cls(
            since=float(since or 0),
            until=float(until or 0),
            client=str(client or "")[:200],
            statuses=parse_statuses(status),
            host=str(host or "")[:200],
            backend=backend,
            request_id=request_id,
            method=str(method or "").upper()[:10],
            path=str(path or "")[:MAX_PATH_LENGTH],
            # The panel's own polling is most of a quiet gateway's traffic.
            # Asked for by id, or by the panel's own backend, it is shown all
            # the same.
            hide_admin=bool(hide_admin) and not request_id and backend not in LIVE_ADMIN_BACKENDS,
            refused=bool(refused),
            slower_ms=_clamp_int(slower, default=0, min_v=0, max_v=86_400_000),
            agent=LOGGED_AGENT_OTHER.sub("_", agent) if agent else "",
        )

    def clauses(self) -> Tuple[List[str], List[Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if self.since:
            clauses.append("ts >= ?")
            parameters.append(int(self.since))
        if self.until:
            clauses.append("ts <= ?")
            parameters.append(int(self.until))
        for column, value in (
            ("client", self.client),
            ("host", self.host),
            ("backend", self.backend),
            ("request_id", self.request_id),
            ("method", self.method),
        ):
            if value:
                clauses.append(column + " = ?")
                parameters.append(value)
        if self.hide_admin:
            clauses.append("backend NOT IN (" + ",".join("?" * len(LIVE_ADMIN_BACKENDS)) + ")")
            parameters.extend(LIVE_ADMIN_BACKENDS)
        if self.path:
            # A prefix match, so /api finds everything under it. Anchored on
            # purpose: a leading wildcard would scan the whole table.
            clauses.append("path LIKE ? ESCAPE ?")
            parameters.extend([_like_literal(self.path) + "%", _LIKE_ESCAPE])
        if self.statuses:
            clauses.append(
                "(" + " OR ".join("(status >= ? AND status < ?)" for _ in self.statuses) + ")"
            )
            for low, high in self.statuses:
                parameters.extend([low, high])
        if self.refused:
            clauses.append(_REFUSED_SQL)
        if self.slower_ms:
            clauses.append("response_ms >= ?")
            parameters.append(self.slower_ms)
        if self.agent:
            clauses.append(
                "agent_id IN (SELECT id FROM agents WHERE agent LIKE ? ESCAPE ?)"
            )
            parameters.extend(["%" + _like_literal(self.agent) + "%", _LIKE_ESCAPE])
        return clauses, parameters

    def matches(self, record: tuple) -> bool:
        """The same question asked of one record of the live buffer."""
        if self.since and record[L_TS] < self.since:
            return False
        if self.until and record[L_TS] > self.until:
            return False
        if self.client and record[L_IP] != self.client:
            return False
        if self.host and record[L_HOST] != self.host:
            return False
        backend = record[L_BACKEND].partition("/")[0]
        if self.backend and backend != self.backend:
            return False
        if self.request_id and (len(record) <= L_REQUEST_ID or record[L_REQUEST_ID] != self.request_id):
            return False
        if self.method and record[L_METHOD] != self.method:
            return False
        if self.hide_admin and backend in LIVE_ADMIN_BACKENDS:
            return False
        if self.path and not record[L_PATH].startswith(self.path):
            return False
        if self.statuses and not any(low <= record[L_STATUS] < high for low, high in self.statuses):
            return False
        if self.refused and not record[L_REFUSAL]:
            return False
        if self.slower_ms and (len(record) <= L_RESPONSE or record[L_RESPONSE] < self.slower_ms):
            return False
        if self.agent and (len(record) <= L_AGENT or self.agent not in record[L_AGENT].lower()):
            return False
        return True


# The summary of a search: its requests over the period and what is most
# common among them. Within this time, as the search; a summary that runs
# out of it says how far back it got.
REQUEST_SUMMARY_SECONDS = 3.0
REQUEST_SUMMARY_TOP = 10
# Bars of the histogram: the period cut into at most this many, each a
# length a person reads at a glance.
_SUMMARY_BARS = 72
_SUMMARY_STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)


def summary_layout(start: float, end: float) -> Tuple[int, int, int]:
    """(first bar's start, seconds per bar, bars) for a period."""
    start, end = int(start), int(max(end, start + 60))
    step = next((s for s in _SUMMARY_STEPS if (end - start) / s <= _SUMMARY_BARS), _SUMMARY_STEPS[-1])
    first = start - start % step
    return first, step, max(1, -(-(end - first) // step))


class RequestSummary:
    """Counts folded in a part at a time, then read out."""

    def __init__(self, first: int, step: int, bars: int) -> None:
        self.first, self.step, self.bars = first, step, bars
        # Per bar: answered, 4xx, 5xx, refused by the gateway.
        self.histogram = [[0, 0, 0, 0] for _ in range(bars)]
        self.statuses: Counter = Counter()
        self.clients: Counter = Counter()
        self.paths: Counter = Counter()
        self.counted = 0

    def add(self, bar: int, status: int, refused: bool, count: int = 1) -> None:
        bar = min(max(int(bar), 0), self.bars - 1)
        kind = 3 if refused else 2 if status >= 500 else 1 if status >= 400 else 0
        self.histogram[bar][kind] += count
        self.statuses[status] += count
        self.counted += count

    @staticmethod
    def _most(counter: Counter, top: int) -> List[Tuple[Any, int]]:
        # Ties in a fixed order, so the store and memory read out alike.
        return heapq.nsmallest(top, counter.items(), key=lambda item: (-item[1], str(item[0])))

    def read(self) -> Dict[str, Any]:
        return {
            "start": self.first,
            "bucket_seconds": self.step,
            "buckets": self.histogram,
            "counted": self.counted,
            "statuses": [{"status": status, "count": count}
                         for status, count in self._most(self.statuses, 12)],
            "clients": [{"client": client, "count": count}
                        for client, count in self._most(self.clients, REQUEST_SUMMARY_TOP)],
            "paths": [{"host": key[0], "path": key[1], "count": count}
                      for key, count in self._most(self.paths, REQUEST_SUMMARY_TOP)],
        }


def _like_literal(value: str) -> str:
    """A value for LIKE in which % and _ mean themselves."""
    for character in (_LIKE_ESCAPE, "%", "_"):
        value = value.replace(character, _LIKE_ESCAPE + character)
    return value


def _local_offset(wall: int) -> int:
    """Seconds this host's zone was ahead of UTC at a wall-clock time
    written as if it were UTC (HAProxy's %t, read by parse_stamp)."""
    parts = time.gmtime(wall)
    try:
        return wall - int(time.mktime(tuple(parts[:8]) + (-1,)))
    except (OverflowError, ValueError):
        return 0


class RequestLog:
    """A bounded, searchable window over recent requests.

    Deliberately not a log pipeline. A day of traffic on a small production
    gateway is ~310k records, so the size cap -- not the retention window --
    is what actually holds, and it is enforced by dropping the oldest rows.

    What is stored is what the access log already contains after the engine's
    own normalization: no query string, no cookie, no body. The query is
    dropped by normalize_path before it ever reaches here, which is why there
    is no list of sensitive parameters to keep up to date. Of the headers,
    only the user agent, as the log template writes it.

    Searches read through a connection of their own: SQLite in WAL mode lets
    them run while the engine writes, so a slow search never holds up the
    reading of the log.
    """

    def __init__(self, path: str, config: GuardConfig) -> None:
        self.path = Path(path)
        self.config = config
        self._lock = threading.Lock()
        self._searching = threading.BoundedSemaphore(REQUEST_SEARCHES_AT_ONCE)
        self._pending: List[Tuple[Any, ...]] = []
        # agent text -> id, so a cycle resolves only the agents it has not
        # met before.
        self._agents: Dict[str, int] = {}
        self._paused = False
        self._pause_reason = ""
        self._last_maintenance = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        self._conn = sqlite3.connect(
            str(self.path), timeout=10, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        cursor = self._conn.cursor()
        if fresh:
            cursor.execute("PRAGMA auto_vacuum=INCREMENTAL")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        for statement in _REQUEST_SCHEMA:
            cursor.execute(statement)
        found = cursor.execute("SELECT version FROM schema_version").fetchone()
        if found is None:
            cursor.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (REQUEST_LOG_SCHEMA_VERSION,),
            )
        self._upgrade(cursor, int(found[0]) if found is not None else REQUEST_LOG_SCHEMA_VERSION)
        self._conn.commit()
        cursor.close()

    def _upgrade(self, cursor: sqlite3.Cursor, version: int) -> None:
        present = {row[1] for row in cursor.execute("PRAGMA table_info(requests)")}
        for name, kind in _REQUEST_ADDED_COLUMNS:
            if name not in present:
                cursor.execute(f"ALTER TABLE requests ADD COLUMN {name} {kind}")
        if version < 2:
            moved = self._local_stamps_to_utc(cursor)
            if moved:
                LOG.info("Request log: %d stored times moved from local time to UTC", moved)
        if version < REQUEST_LOG_SCHEMA_VERSION:
            cursor.execute(
                "UPDATE schema_version SET version = ?", (REQUEST_LOG_SCHEMA_VERSION,)
            )

    @staticmethod
    def _local_stamps_to_utc(cursor: sqlite3.Cursor) -> int:
        """Version 1 stored HAProxy's %t: the host's wall clock, read as if
        it were UTC. On a gateway three hours east of UTC every request was
        three hours in the future, and a link for "these minutes" from the
        live page or the charts opened other minutes.

        Each hour gets the offset its zone had then, summer time included,
        and every row moves once, by the offset of the hour it was in.
        """
        low, high = cursor.execute("SELECT MIN(ts), MAX(ts) FROM requests").fetchone()
        if low is None:
            return 0
        shifts = []
        hour = int(low) - int(low) % 3600
        while hour <= int(high):
            offset = _local_offset(hour)
            if offset:
                shifts.append((hour, offset))
            hour += 3600
        if not shifts:
            return 0
        LOG.info("Request log: moving stored times to UTC; a full store takes about a minute")
        cursor.execute("CREATE TEMP TABLE request_shift (hour INTEGER PRIMARY KEY, offset INTEGER)")
        cursor.executemany("INSERT INTO request_shift VALUES (?, ?)", shifts)
        # Three indexes hold ts: building them again afterwards is quicker
        # than changing every one of them for every row.
        for name in ("ix_requests_ts", "ix_requests_client", "ix_requests_status"):
            cursor.execute(f"DROP INDEX IF EXISTS {name}")
        cursor.execute(
            "UPDATE requests SET ts = ts - (SELECT offset FROM request_shift"
            " WHERE hour = requests.ts - requests.ts % 3600)"
            " WHERE ts - ts % 3600 IN (SELECT hour FROM request_shift)"
        )
        moved = cursor.rowcount
        cursor.execute("DROP TABLE request_shift")
        for statement in _REQUEST_SCHEMA:
            if statement.startswith("CREATE INDEX"):
                cursor.execute(statement)
        return moved

    def close(self) -> None:
        with self._lock, contextlib.suppress(Exception):
            self._conn.close()

    # -- ingest ---------------------------------------------------------
    def add(self, record: ParsedRequest, ts: Optional[float] = None) -> None:
        """Queue one record. Writing happens once per cycle, not per line.

        ts is the syslog stamp of the line, which carries its zone; HAProxy's
        own %t is the host's wall clock and is only the fallback.
        """
        backend, _, server = (record.backend or "").partition("/")
        self._pending.append(
            (
                int(ts) if ts else (record.ts or _utc_now()),
                record.request_id[:64],
                record.client_ip[:45],
                record.status,
                record.frontend[:64],
                backend[:64],
                "" if server in ("", "<NOSRV>") else server[:64],
                record.method[:10],
                record.host[:MAX_HOST_LENGTH],
                record.path[:MAX_PATH_LENGTH],
                record.bytes_out,
                record.duration_ms,
                1 if record.bad_request else 0,
                record.response_ms if record.response_ms >= 0 else -1,
                (record.times or "")[:40],
                (record.term or "")[:8],
                (record.ban_reason or "")[:160],
                record.authenticated_user,
                (record.user_agent or "")[:MAX_USER_AGENT_LENGTH],
            )
        )

    def _with_agent_ids(self, rows: List[Tuple[Any, ...]]) -> List[Tuple[Any, ...]]:
        """The batch with each user agent replaced by its id, the new ones
        added and every one's newest time kept."""
        newest: Dict[str, int] = {}
        for row in rows:
            agent = row[-1]
            if agent and newest.get(agent, 0) < row[0]:
                newest[agent] = row[0]
        unknown = [agent for agent in newest if agent not in self._agents]
        if unknown:
            if len(self._agents) > 20000:
                self._agents.clear()
                # The known agents of this batch were just forgotten too:
                # resolve them again, or their lines would get agent id 0.
                unknown = list(newest)
            self._conn.executemany(
                "INSERT OR IGNORE INTO agents (agent, last_ts) VALUES (?, ?)",
                [(agent, newest[agent]) for agent in unknown],
            )
            for start in range(0, len(unknown), 500):
                part = unknown[start:start + 500]
                marks = ",".join("?" * len(part))
                for agent_id, agent in self._conn.execute(
                    f"SELECT id, agent FROM agents WHERE agent IN ({marks})", part
                ):
                    self._agents[agent] = int(agent_id)
        self._conn.executemany(
            "UPDATE agents SET last_ts = ? WHERE id = ? AND last_ts < ?",
            [(stamp, self._agents[agent], stamp) for agent, stamp in newest.items()
             if agent in self._agents],
        )
        return [row[:-1] + (self._agents.get(row[-1], 0) if row[-1] else 0,) for row in rows]

    def flush(self, now: Optional[int] = None) -> int:
        """Write the queued records, then keep the store inside its budget."""
        now = now if now is not None else _utc_now()
        with self._lock:
            pending, self._pending = self._pending, []
            written = 0
            if pending and not self._paused:
                try:
                    with self._conn:
                        self._conn.executemany(
                            "INSERT INTO requests (ts, request_id, client, status,"
                            " frontend, backend, server, method, host, path,"
                            " bytes_out, duration_ms, bad_request, response_ms,"
                            " times, term, ban_reason, authenticated_user, agent_id) VALUES"
                            " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            self._with_agent_ids(pending),
                        )
                    written = len(pending)
                except sqlite3.Error as exc:
                    LOG.warning("request log write failed: %s", exc)
                    self._agents.clear()
            if now - self._last_maintenance >= 60:
                self._last_maintenance = now
                self._maintain(now)
            return written

    # -- budget ---------------------------------------------------------
    def _size(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                total += (self.path.parent / (self.path.name + suffix)).stat().st_size
        return total

    def _free_bytes(self) -> int:
        with contextlib.suppress(OSError, AttributeError):
            usage = os.statvfs(self.path.parent)
            return usage.f_bavail * usage.f_frsize
        return 0

    def _maintain(self, now: int) -> None:
        """Retention first, then the cap, then the filesystem reserve.

        The order matters. Dropping expired rows is free storage, so it runs
        before anything more aggressive. The reserve has the last word:
        diagnostics must never be the reason the gateway runs out of disk,
        which is the same rule the metrics collector follows.
        """
        cutoff = now - self.config.request_log_retention_days * 86400
        with contextlib.suppress(sqlite3.Error):
            with self._conn:
                self._conn.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))

        for _ in range(8):
            if self._size() <= self.config.request_log_max_bytes:
                break
            with contextlib.suppress(sqlite3.Error):
                with self._conn:
                    # A tenth at a time: enough to converge quickly, small
                    # enough that one pass cannot stall the poll cycle.
                    self._conn.execute(
                        "DELETE FROM requests WHERE id IN ("
                        "SELECT id FROM requests ORDER BY id LIMIT"
                        " (SELECT MAX(1, COUNT(*) / 10) FROM requests))"
                    )
                    self._conn.execute("PRAGMA incremental_vacuum")

        # A user agent no request left refers to.
        with contextlib.suppress(sqlite3.Error):
            with self._conn:
                gone = self._conn.execute(
                    "DELETE FROM agents WHERE last_ts <"
                    " (SELECT ts FROM requests ORDER BY id LIMIT 1)"
                ).rowcount
            if gone:
                self._agents.clear()

        free = self._free_bytes()
        reserve = self.config.request_log_reserved_free_bytes
        if free and free < reserve:
            if not self._paused:
                self._paused = True
                self._pause_reason = "the filesystem is below its free-space reserve"
                LOG.warning(
                    "Request log paused: %s. HAProxy traffic is not affected.",
                    self._pause_reason,
                )
        elif self._paused and free > reserve * 1.2:
            self._paused = False
            self._pause_reason = ""
            LOG.info("Request log resumed: free space recovered")

    # -- read -----------------------------------------------------------
    def _reader(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=1")
        return connection

    def search(
        self,
        *,
        since: int = 0,
        until: int = 0,
        client: str = "",
        status: str = "",
        host: str = "",
        backend: str = "",
        request_id: str = "",
        method: str = "",
        path: str = "",
        hide_admin: bool = False,
        refused: bool = False,
        slower: int = 0,
        agent: str = "",
        before: int = 0,
        count: bool = True,
        limit: int = 100,
        seconds: float = REQUEST_SEARCH_SECONDS,
    ) -> Dict[str, Any]:
        """The newest matching requests, a page at a time.

        `before` continues below the last row shown (or below where a search
        that ran out of time stopped), so new requests arriving between two
        pages neither repeat a row nor hide one. The answer says whether the
        whole period was searched; when it was not, `searched_to` is how far
        back it got and `next` continues from there.
        """
        query = RequestQuery.build(
            since=since, until=until, client=client, status=status, host=host,
            backend=backend, request_id=request_id, method=method, path=path,
            hide_admin=hide_admin, refused=refused, slower=slower, agent=agent,
        )
        clauses, parameters = query.clauses()
        since, until = int(query.since), int(query.until)
        limit = _clamp_int(limit, default=100, min_v=1, max_v=500)
        before = _clamp_int(before, default=0, min_v=0, max_v=2 ** 62)
        deadline = time.monotonic() + max(0.0, float(seconds))
        if not self._searching.acquire(timeout=10):
            raise RuntimeError("other searches of the request log are still running")
        try:
            connection = self._reader()
            try:
                index = ""
                if query.request_id:
                    index = "ix_requests_rid"
                elif query.client and self._few(connection, clauses, parameters):
                    index = "ix_requests_client"
                if index:
                    found = self._search_indexed(
                        connection, index, clauses, parameters, before, limit, count,
                    )
                else:
                    found = self._search_scan(
                        connection, clauses, parameters, since, until, before, limit,
                        count, deadline,
                    )
                # The deadline stops the searching, not what follows it.
                connection.set_progress_handler(None, 0)
                stopped_at = found.pop("stopped_at", 0)
                found["searched_to"] = self._ts_at(connection, stopped_at) if stopped_at else 0
                found["requests"] = self._present(connection, found["requests"])
                return found
            finally:
                connection.close()
        finally:
            self._searching.release()

    @staticmethod
    def _where(clauses: List[str]) -> str:
        return "".join(" AND " + clause for clause in clauses)

    def _few(self, connection: sqlite3.Connection, clauses: List[str],
             parameters: List[Any]) -> bool:
        """Whether the address's own index is the quick way to its rows."""
        found = connection.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM requests INDEXED BY ix_requests_client"
            " WHERE 1" + self._where(clauses) + " LIMIT ?)",
            parameters + [REQUEST_INDEXED_ROWS + 1],
        ).fetchone()[0]
        return found <= REQUEST_INDEXED_ROWS

    def _search_indexed(
        self, connection: sqlite3.Connection, index: str, clauses: List[str],
        parameters: List[Any], before: int, limit: int, count: bool,
    ) -> Dict[str, Any]:
        """A request id, or an address with few requests: its index finds
        every row at once, few enough to sort."""
        where = " WHERE 1" + self._where(clauses)
        if before:
            where += " AND id < ?"
            parameters = parameters + [before]
        rows = connection.execute(
            f"SELECT * FROM requests INDEXED BY {index}{where}"
            " ORDER BY id DESC LIMIT ?",
            parameters + [limit + 1],
        ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        result: Dict[str, Any] = {
            "requests": rows, "next": rows[-1]["id"] if more else 0,
            "complete": True, "timed_out": False,
        }
        if count:
            counted = connection.execute(
                f"SELECT COUNT(*) FROM (SELECT 1 FROM requests INDEXED BY {index}{where}"
                " LIMIT ?)",
                parameters + [REQUEST_COUNT_CAP + 1],
            ).fetchone()[0]
            result["total"] = min(counted, REQUEST_COUNT_CAP)
            result["total_exact"] = counted <= REQUEST_COUNT_CAP
        return result

    def _search_scan(
        self, connection: sqlite3.Connection, clauses: List[str], parameters: List[Any],
        since: int, until: int, before: int, limit: int, count: bool, deadline: float,
    ) -> Dict[str, Any]:
        """Newest first, a step of ids at a time, until the page is full, the
        period is searched, or the time is up.

        The first step always completes, so every "show more" gets further
        back than the last; after it, a step that would overrun the time is
        interrupted and searched again by the next page.
        """
        low, high = self._id_bounds(connection, since, until)
        if before:
            high = min(high, before - 1)
        where = self._where(clauses)
        rows: List[sqlite3.Row] = []
        counted = 0
        position = high      # the next id to look at, going down
        counting_from = 0    # where counting carries on once the page is full
        timed_out = False
        try:
            while position >= low and len(rows) <= limit:
                floor = max(low, position - REQUEST_SCAN_STEP + 1)
                need = limit + 1 - len(rows)
                step = connection.execute(
                    "SELECT * FROM requests NOT INDEXED WHERE id BETWEEN ? AND ?"
                    + where + " ORDER BY id DESC LIMIT ?",
                    [floor, position] + parameters + [need],
                ).fetchall()
                rows.extend(step)
                connection.set_progress_handler(lambda: time.monotonic() > deadline, 2000)
                if len(step) < need:
                    counted += len(step)
                    position = floor - 1
                else:
                    counting_from = position
                    position = floor - 1
                    break
                if time.monotonic() > deadline:
                    timed_out = position >= low
                    break
        except sqlite3.OperationalError as exc:
            if "interrupt" not in str(exc):
                raise
            timed_out = True
        more = len(rows) > limit
        rows = rows[:limit]
        if more:
            following = rows[-1]["id"]
        elif timed_out:
            following = position + 1
        else:
            following = 0
        result: Dict[str, Any] = {
            "requests": rows,
            "next": following,
            "complete": not timed_out,
            "timed_out": timed_out,
            # The oldest row searched through; the caller turns it into a time.
            "stopped_at": position + 1 if timed_out else 0,
        }
        if not count:
            return result
        # Counting goes on below where the rows stopped, within what is left
        # of the time, and stops at the cap.
        exact = not timed_out
        if counting_from:
            position = counting_from
            try:
                while position >= low and counted <= REQUEST_COUNT_CAP:
                    if time.monotonic() > deadline:
                        exact = False
                        break
                    floor = max(low, position - REQUEST_SCAN_STEP + 1)
                    counted += connection.execute(
                        "SELECT COUNT(*) FROM (SELECT 1 FROM requests NOT INDEXED"
                        " WHERE id BETWEEN ? AND ?" + where + " LIMIT ?)",
                        [floor, position] + parameters + [REQUEST_COUNT_CAP + 1 - counted],
                    ).fetchone()[0]
                    position = floor - 1
            except sqlite3.OperationalError as exc:
                if "interrupt" not in str(exc):
                    raise
                exact = False
        if counted > REQUEST_COUNT_CAP:
            counted, exact = REQUEST_COUNT_CAP, False
        result["total"] = max(counted, len(rows))
        result["total_exact"] = exact
        return result

    @staticmethod
    def _id_bounds(connection: sqlite3.Connection, since: int, until: int) -> Tuple[int, int]:
        """The first and last id of a period, found through the time index."""
        top = connection.execute(
            "SELECT id FROM requests INDEXED BY ix_requests_ts WHERE ts <= ?"
            " ORDER BY ts DESC LIMIT 1", (int(until),)
        ).fetchone() if until else connection.execute("SELECT MAX(id) FROM requests").fetchone()
        bottom = connection.execute(
            "SELECT id FROM requests INDEXED BY ix_requests_ts WHERE ts >= ?"
            " ORDER BY ts LIMIT 1", (int(since),)
        ).fetchone() if since else connection.execute("SELECT MIN(id) FROM requests").fetchone()
        high = int(top[0]) if top and top[0] is not None else 0
        low = int(bottom[0]) if bottom and bottom[0] is not None else 1
        return low, high

    def summary(self, *, seconds: float = REQUEST_SUMMARY_SECONDS, **filters: Any) -> Dict[str, Any]:
        """The requests a search finds, over its period and by what is most
        common: newest first, a step of ids at a time, as the search reads
        them, each step counted by SQLite rather than row by row here."""
        query = RequestQuery.build(**filters)
        clauses, parameters = query.clauses()
        where = self._where(clauses)
        deadline = time.monotonic() + max(0.0, float(seconds))
        if not self._searching.acquire(timeout=10):
            raise RuntimeError("other searches of the request log are still running")
        try:
            connection = self._reader()
            try:
                low, high = self._id_bounds(connection, int(query.since), int(query.until))
                oldest = self._ts_at(connection, low) if high >= low else 0
                start = query.since or oldest or time.time()
                end = query.until or time.time()
                summary = RequestSummary(*summary_layout(start, end))
                refused = f"CASE WHEN {_REFUSED_SQL} THEN 1 ELSE 0 END"
                position = high
                while position >= low:
                    floor = max(low, position - REQUEST_SCAN_STEP + 1)
                    part = "FROM requests NOT INDEXED WHERE id BETWEEN ? AND ?" + where
                    values = [floor, position] + parameters
                    for bar, status, gateway, count in connection.execute(
                        f"SELECT (ts - ?) / ?, status, {refused}, COUNT(*) {part} GROUP BY 1, 2, 3",
                        [summary.first, summary.step] + values,
                    ):
                        summary.add(bar, status, bool(gateway), count)
                    for client, count in connection.execute(
                        f"SELECT client, COUNT(*) {part} GROUP BY client", values
                    ):
                        summary.clients[client] += count
                    for host, path, count in connection.execute(
                        f"SELECT host, path, COUNT(*) {part} GROUP BY host, path", values
                    ):
                        summary.paths[(host, path)] += count
                    position = floor - 1
                    if time.monotonic() > deadline:
                        break
                result = summary.read()
                result["complete"] = position < low
                result["reached_to"] = 0 if result["complete"] else self._ts_at(connection, position + 1)
                return result
            finally:
                connection.close()
        finally:
            self._searching.release()

    @staticmethod
    def _ts_at(connection: sqlite3.Connection, row_id: int) -> int:
        found = connection.execute(
            "SELECT ts FROM requests WHERE id >= ? ORDER BY id LIMIT 1", (row_id,)
        ).fetchone()
        return int(found[0]) if found else 0

    @staticmethod
    def _present(connection: sqlite3.Connection, rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        """Rows as the page reads them: the user agent by name, and why the
        gateway itself turned a request away, worked out as the live page
        does."""
        wanted = sorted({row["agent_id"] for row in rows if row["agent_id"]})
        names: Dict[int, str] = {}
        if wanted:
            marks = ",".join("?" * len(wanted))
            names = {
                int(agent_id): agent for agent_id, agent in connection.execute(
                    f"SELECT id, agent FROM agents WHERE id IN ({marks})", wanted
                )
            }
        presented = []
        for row in rows:
            item = dict(row)
            agent_id = item.pop("agent_id", 0)
            item["user_agent"] = names.get(agent_id, "")
            item["refusal"] = live_refusal(
                item["status"],
                item["backend"] + "/" + (item["server"] or "<NOSRV>"),
                item["term"],
                item["ban_reason"],
            )
            presented.append(item)
        return presented

    def status(self) -> Dict[str, Any]:
        # Ids only ever grow and only the oldest are deleted, so the count is
        # the span of ids: no scan of the table for a status line.
        connection = self._reader()
        try:
            newest = connection.execute(
                "SELECT id, ts FROM requests ORDER BY id DESC LIMIT 1"
            ).fetchone()
            oldest = connection.execute(
                "SELECT id, ts FROM requests ORDER BY id LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        rows = int(newest["id"]) - int(oldest["id"]) + 1 if newest and oldest else 0
        return {
            "enabled": True,
            "configured": self.config.request_log_enabled,
            "rows": rows,
            "oldest_ts": int(oldest["ts"]) if oldest else 0,
            "newest_ts": int(newest["ts"]) if newest else 0,
            "database_bytes": self._size(),
            "max_bytes": self.config.request_log_max_bytes,
            "retention_days": self.config.request_log_retention_days,
            "free_bytes": self._free_bytes(),
            "paused": self._paused,
            "pause_reason": self._pause_reason,
        }
