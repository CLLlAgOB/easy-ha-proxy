"""Persistent SQLite security database, migrations, and quality metrics."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .constants import (
    DECISION_REASON_MAX_BYTES,
    EVENT_BAN_APPLIED,
    EVENT_BAN_LIFTED,
    EVENT_LEGACY_BAN,
    EVENT_LEGACY_BAN_LIFTED,
    LOG,
    MANUAL_BAN_REPLACED_MARGIN,
    MAX_PATH_LENGTH,
    OWN_BAN_CODES,
    QUALITY_AT_ONCE_SECONDS,
    QUALITY_NETWORKS_SHOWN,
    QUALITY_NETWORK_MIN,
    SCHEMA_VERSION,
    SIGNATURE_EVENTS,
    _utc_now,
    enforceable,
)
from .scoring import Verdict, decision_summary
from .watchers import RATE_WARNING

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS ip_state (
        ip               TEXT PRIMARY KEY,
        family           INTEGER NOT NULL,
        enforceable      INTEGER NOT NULL,
        first_seen       INTEGER NOT NULL,
        last_seen        INTEGER NOT NULL,
        excluded         INTEGER NOT NULL DEFAULT 0,
        exclusion_reason TEXT    NOT NULL DEFAULT '',
        banned_until     INTEGER NOT NULL DEFAULT 0,
        ban_code         INTEGER NOT NULL DEFAULT 0,
        authenticated_at INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID
    """,
    # Keep schedule reads proportional to bans, not to every address ever seen.
    "CREATE INDEX IF NOT EXISTS idx_ip_state_banned ON ip_state (banned_until) WHERE banned_until > 0",
    "CREATE INDEX IF NOT EXISTS idx_ip_state_first_seen ON ip_state (first_seen, ip)",
    # Deliberately weight-free: the score is derived when it is requested, so
    # retuning weights re-scores the whole history instead of starting over.
    # `handled` records that HAProxy already refused the request this event
    # describes -- a GeoIP 451, for instance. It is a fact about what happened,
    # not a weight, so it belongs beside the event rather than in the scoring
    # configuration; the score simply declines to count it.
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id         INTEGER PRIMARY KEY,
        ts         INTEGER NOT NULL,
        ip         TEXT    NOT NULL,
        event_type TEXT    NOT NULL,
        source     TEXT    NOT NULL,
        site       TEXT    NOT NULL DEFAULT '',
        category   TEXT    NOT NULL DEFAULT '',
        detail     TEXT    NOT NULL DEFAULT '',
        handled    INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON security_events (ip, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events (ts)",
    """
    CREATE TABLE IF NOT EXISTS event_cooldowns (
        fingerprint TEXT PRIMARY KEY,
        last_ts     INTEGER NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS guard_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    # Trusted addresses over a site's limit, one row per episode. Kept apart
    # from security_events on purpose: nothing that scores reads this table.
    # Created where it is missing rather than by a schema step, so a daemon
    # rolled back to before it still opens the database.
    """
    CREATE TABLE IF NOT EXISTS rate_warnings (
        id           INTEGER PRIMARY KEY,
        ip           TEXT    NOT NULL,
        site         TEXT    NOT NULL,
        trust        TEXT    NOT NULL,
        rate_limit   INTEGER NOT NULL,
        window_s     INTEGER NOT NULL,
        enforced     INTEGER NOT NULL DEFAULT 1,
        started      INTEGER NOT NULL,
        ended        INTEGER NOT NULL,
        peak         INTEGER NOT NULL,
        over_limit   INTEGER NOT NULL,
        requests     INTEGER NOT NULL,
        rate_limited INTEGER NOT NULL DEFAULT 0,
        banned       INTEGER NOT NULL DEFAULT 0,
        rate_ban     INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_rate_warnings_ended ON rate_warnings (ended)",
    # The operator's bans (code 50), as seen in the ban table (04.6g). The
    # table lives in HAProxy's memory, so a restart or a reboot emptied it and
    # the operator's decisions went with it, while this daemon put its own
    # back from its schedule. Created where missing, like rate_warnings.
    """
    CREATE TABLE IF NOT EXISTS manual_bans (
        ip          TEXT    PRIMARY KEY,
        placed_at   INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        seen_at     INTEGER NOT NULL,
        reasserted  INTEGER NOT NULL DEFAULT 0
    )
    """,
    # Every ban decision and every lift, with the reason as it stood when
    # the decision was made (06.1-06.3). The findings behind a ban decay out
    # of the score in hours and are swept with ordinary events; what was
    # written down at the time was only "score=90 [vcs,secrets]". The reason
    # is never rewritten; only a pending decision's outcome is settled.
    """
    CREATE TABLE IF NOT EXISTS ban_decisions (
        id       INTEGER PRIMARY KEY,
        ts       INTEGER NOT NULL,
        ip       TEXT    NOT NULL,
        action   TEXT    NOT NULL,
        source   TEXT    NOT NULL,
        code     INTEGER NOT NULL DEFAULT 0,
        until    INTEGER NOT NULL DEFAULT 0,
        strike   INTEGER NOT NULL DEFAULT 0,
        score    INTEGER NOT NULL DEFAULT 0,
        policy   TEXT    NOT NULL DEFAULT '',
        outcome  TEXT    NOT NULL,
        reason   TEXT    NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ban_decisions_ip ON ban_decisions (ip, ts)",
)

def _add_column_if_missing(
    cursor: sqlite3.Cursor, table: str, column: str, definition: str
) -> None:
    """Add a column unless it is already there.

    The schema statements above create tables in their newest shape, so a
    database can legitimately already have a column that a migration step also
    wants to add. Checking first keeps the ladder safe to re-run instead of
    failing the daemon at startup.
    """

    existing = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column in existing:
        return
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


_MIGRATIONS: Dict[int, Callable[[sqlite3.Cursor], None]] = {
    # v1 stored events without knowing whether HAProxy had already refused the
    # request. Existing rows default to "not handled", which is the safe
    # reading: they keep counting exactly as they did before.
    2: lambda cursor: _add_column_if_missing(
        cursor, "security_events", "handled", "INTEGER NOT NULL DEFAULT 0"
    ),
    # The strongest false-positive signal there is: an address the engine
    # scored that later completed Authelia authentication.
    3: lambda cursor: _add_column_if_missing(
        cursor, "ip_state", "authenticated_at", "INTEGER NOT NULL DEFAULT 0"
    ),
}


class SecurityDatabase:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
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
        cursor.close()
        self._migrate()

    def _migrate(self) -> None:
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            for statement in _SCHEMA_STATEMENTS:
                cursor.execute(statement)
            row = cursor.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (SCHEMA_VERSION,),
                )
                cursor.close()
                return
            current = int(row["version"])
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"security database schema v{current} is newer than the "
                    f"supported v{SCHEMA_VERSION}"
                )
            while current < SCHEMA_VERSION:
                step = _MIGRATIONS.get(current + 1)
                if step is not None:
                    step(cursor)
                current += 1
                LOG.info("Migrated security database to schema v%d", current)
            cursor.execute("UPDATE schema_version SET version = ?", (current,))
            cursor.close()

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()

    def get_state(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM guard_state WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row else default

    def set_state(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO guard_state (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def set_states(self, values: Dict[str, str]) -> None:
        """Persist related observations and settings in one transaction."""
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO guard_state (key, value) VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                list(values.items()),
            )

    def observe_ip(
        self, ip: str, ts: int, verdict: Verdict
    ) -> None:
        try:
            family = ipaddress.ip_address(ip).version
        except ValueError:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO ip_state "
                "(ip, family, enforceable, first_seen, last_seen, excluded, "
                " exclusion_reason) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (ip) DO UPDATE SET last_seen = excluded.last_seen, "
                "excluded = excluded.excluded, "
                "exclusion_reason = excluded.exclusion_reason",
                (
                    ip,
                    family,
                    1 if enforceable(ip) else 0,
                    ts,
                    ts,
                    1 if verdict.excluded else 0,
                    verdict.reason,
                ),
            )

    def record_events(self, events: Iterable[Dict[str, Any]]) -> int:
        payload = [
            (
                int(event["ts"]),
                str(event["ip"]),
                str(event["event_type"]),
                str(event["source"]),
                str(event.get("site", "")),
                str(event.get("category", "")),
                str(event.get("detail", ""))[:MAX_PATH_LENGTH],
                1 if event.get("handled") else 0,
            )
            for event in events
        ]
        if not payload:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO security_events "
                "(ts, ip, event_type, source, site, category, detail, handled) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                payload,
            )
        return len(payload)

    def record_authenticated(self, ips: Iterable[str], ts: int) -> int:
        """Remember that these addresses hold an Authelia authorization.

        Only addresses the engine has already scored are updated: the point is
        to mark findings that turned out to belong to a real user, not to build
        a second directory of everyone who logged in.
        """

        payload = [(ts, ip) for ip in ips]
        if not payload:
            return 0
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.executemany(
                "UPDATE ip_state SET authenticated_at = ? WHERE ip = ?", payload
            )
            updated = cursor.rowcount or 0
            cursor.close()
        return updated

    def set_ban(self, ip: str, until: int, code: int, now: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ip_state SET banned_until = ?, ban_code = ?, last_seen = ? "
                "WHERE ip = ?",
                (until, code, now, ip),
            )

    def clear_ban(self, ip: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ip_state SET banned_until = 0, ban_code = 0 WHERE ip = ?",
                (ip,),
            )

    # -- ban decisions (06.2-06.3) ----------------------------------------

    def record_decision(
        self,
        ip: str,
        ts: int,
        action: str,
        source: str,
        outcome: str,
        *,
        code: int = 0,
        until: int = 0,
        strike: int = 0,
        score: int = 0,
        policy: str = "",
        reason: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Write one decision; its reason is never changed afterwards."""
        text = json.dumps(reason or {}, sort_keys=True, ensure_ascii=False)
        if len(text) > DECISION_REASON_MAX_BYTES:
            text = json.dumps({"truncated": True}, sort_keys=True)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO ban_decisions "
                "(ts, ip, action, source, code, until, strike, score, policy, outcome, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, ip, action, source, int(code), int(until), int(strike), int(score),
                 policy, outcome, text),
            )
            return int(cursor.lastrowid)

    def settle_decision(self, decision_id: int, outcome: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ban_decisions SET outcome = ? WHERE id = ? AND outcome = 'pending'",
                (outcome, decision_id),
            )

    def commit_ban(self, decision_id: int, ip: str, until: int, code: int, now: int, detail: str) -> None:
        """Make an applied ban count, all at once: the schedule, the strike
        (a BAN_APPLIED event) and the decision's outcome, in one transaction.
        A crash leaves all three or none."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ip_state SET banned_until = ?, ban_code = ?, last_seen = ? WHERE ip = ?",
                (until, code, now, ip),
            )
            self._conn.execute(
                "INSERT INTO security_events (ts, ip, event_type, source, site, category, detail, handled) "
                "VALUES (?, ?, ?, 'guardd', '', '', ?, 0)",
                (now, ip, EVENT_BAN_APPLIED, detail[:MAX_PATH_LENGTH]),
            )
            self._conn.execute(
                "UPDATE ban_decisions SET outcome = 'applied' WHERE id = ? AND outcome = 'pending'",
                (decision_id,),
            )

    def pending_decisions(self, before: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, ip, code, until, strike, score FROM ban_decisions "
                "WHERE outcome = 'pending' AND ts < ? ORDER BY ts",
                (before,),
            ).fetchall()
        return [dict(row) for row in rows]

    def ban_decisions(self, ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, ip, action, source, code, until, strike, score, policy, outcome, reason "
                "FROM ban_decisions WHERE ip = ? ORDER BY ts DESC, id DESC LIMIT ?",
                (ip, int(limit)),
            ).fetchall()
        decisions = []
        for row in rows:
            item = dict(row)
            try:
                item["reason"] = json.loads(item["reason"] or "{}")
            except (TypeError, ValueError):
                item["reason"] = {}
            decisions.append(item)
        return decisions

    def decision_feed(
        self, before: int = 0, limit: int = 50, actions: Tuple[str, ...] = (),
    ) -> List[Dict[str, Any]]:
        """Decisions about every address, newest first, `limit` + 1 of them
        so the caller can tell whether there are more (06.6).

        Paged by id, below `before`: a decision written while someone reads
        never shifts or repeats a row, as an offset would. The reason comes
        back summarised (decision_summary), not whole.
        """
        clauses, values = [], []
        if before > 0:
            clauses.append("id < ?")
            values.append(int(before))
        if actions:
            clauses.append(f"action IN ({', '.join('?' for _ in actions)})")
            values.extend(actions)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, ip, action, source, code, until, strike, score, policy, outcome, reason "
                f"FROM ban_decisions {where}ORDER BY id DESC LIMIT ?",
                (*values, int(limit) + 1),
            ).fetchall()
        feed = []
        for row in rows:
            item = dict(row)
            try:
                reason = json.loads(item.pop("reason") or "{}")
            except (TypeError, ValueError):
                reason = {}
            item["summary"] = decision_summary(reason if isinstance(reason, dict) else {})
            feed.append(item)
        return feed

    def adaptive_ban_history(self, *, query="", since=0, sort="ts", direction="desc",
                             offset=0, snapshot=0, limit=25, terms=()):
        """Applied adaptive bans, sorted and filtered before pagination.

        Pin pages to a decision id so new bans do not shift an open history.
        Query values are bound; SQL identifiers come only from this allowlist.
        """
        columns = {"ts": "ts", "ip": "ip", "score": "score", "strike": "strike", "until": "until"}
        if sort not in columns or direction not in {"asc", "desc"}:
            raise ValueError("Invalid ban history sort")
        with self._lock:
            snapshot = snapshot or self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM ban_decisions").fetchone()[0]
            where = "source = 'adaptive' AND action = 'applied' AND outcome = 'applied' AND id <= ? AND ts >= ?"
            values = [snapshot, since]
            if query:
                terms = tuple(term for term in terms[:32] if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', term))
                where += " AND (instr(ip, ?) > 0 OR instr(lower(reason), lower(?)) > 0"
                values.extend([query, query])
                for term in terms:
                    where += ' OR instr(lower(reason), lower(?)) > 0'
                    values.append(term)
                where += ')'
            total = self._conn.execute(f"SELECT COUNT(*) FROM ban_decisions WHERE {where}", values).fetchone()[0]
            rows = self._conn.execute(
                "SELECT id, ts, ip, until, strike, score, reason FROM ban_decisions "
                f"WHERE {where} ORDER BY {columns[sort]} {direction}, id {direction} LIMIT ? OFFSET ?",
                (*values, limit, offset),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            try:
                reason = json.loads(item.pop("reason") or "{}")
            except (TypeError, ValueError):
                reason = {}
            item["categories"] = decision_summary(reason if isinstance(reason, dict) else {}).get("categories", [])
            items.append(item)
        return {"bans": items, "total": total, "snapshot": snapshot, "offset": offset, "limit": limit}

    def adaptive_ban_detail(self, *, decision_id=0, ip="", at=0, until=0):
        # Never substitute a different strike for the one the operator opened.
        if decision_id:
            where, values = "id = ?", (decision_id,)
        elif until:
            where, values = "ip = ? AND until = ?", (ip, until)
        else:
            where, values = "ip = ? AND ts = ?", (ip, at)
        with self._lock:
            row = self._conn.execute(
                "SELECT id, ts, ip, until, strike, score, reason FROM ban_decisions "
                f"WHERE {where} AND source = 'adaptive' AND action = 'applied' AND outcome = 'applied' "
                "ORDER BY id DESC LIMIT 1", values,
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            reason = json.loads(item["reason"] or "{}")
        except (TypeError, ValueError):
            reason = {}
        item["reason"] = reason if isinstance(reason, dict) else {}
        return item

    def prune_decisions(self, before: int, keep: int, now: int = 0) -> int:
        """Drop decisions older than `before`, then the oldest beyond `keep`
        rows -- but never one whose ban is still in force (until > now): a
        wave of bans must not cost a standing ban its reason (06.7)."""
        now = int(now or _utc_now())
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM ban_decisions WHERE ts < ? AND until <= ?", (before, now)
            )
            deleted = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM ban_decisions WHERE until <= ? AND id NOT IN "
                "(SELECT id FROM ban_decisions ORDER BY ts DESC, id DESC LIMIT ?)",
                (now, int(keep)),
            )
            deleted += cursor.rowcount or 0
            cursor.close()
        return deleted

    # -- the operator's bans (04.6g) --------------------------------------

    def manual_bans(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, placed_at, expires_at, seen_at, reasserted FROM manual_bans"
            ).fetchall()
        return {
            str(row["ip"]): {
                "placed_at": int(row["placed_at"]),
                "expires_at": int(row["expires_at"]),
                "seen_at": int(row["seen_at"]),
                "reasserted": int(row["reasserted"]),
            }
            for row in rows
        }

    def note_manual_ban(self, ip: str, now: int, expires_at: int) -> None:
        """Remember a manual ban seen in the table now.

        Its end is the table's expiry as first seen. A ban placed again by
        hand restarts that expiry, and is taken as the new end; a copy this
        daemon put back after a restart restarts it too, and is not.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO manual_bans (ip, placed_at, expires_at, seen_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (ip) DO UPDATE SET seen_at = excluded.seen_at, "
                "expires_at = CASE WHEN manual_bans.reasserted = 0 "
                "AND excluded.expires_at > manual_bans.expires_at + ? "
                "THEN excluded.expires_at ELSE manual_bans.expires_at END",
                (ip, now, expires_at, now, MANUAL_BAN_REPLACED_MARGIN),
            )

    def write_manual_ban(
        self, ip: str, placed_at: int, expires_at: int, seen_at: int, reasserted: int = 0,
    ) -> None:
        """Set an operator's ban exactly as given (R07/R08).

        note_manual_ban is for what is seen in the table: it only ever moves
        an end later, and leaves one restored after a restart as it was. A ban
        an operator places anew is a new decision: its end is the one the
        table gave it, longer or shorter, and it is no longer a restored copy.
        Also used to put back the previous record when a new ban is refused.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO manual_bans (ip, placed_at, expires_at, seen_at, reasserted) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (ip) DO UPDATE SET "
                "placed_at = excluded.placed_at, expires_at = excluded.expires_at, "
                "seen_at = excluded.seen_at, reasserted = excluded.reasserted",
                (ip, int(placed_at), int(expires_at), int(seen_at), int(reasserted)),
            )

    def mark_manual_reasserted(self, ip: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE manual_bans SET reasserted = 1 WHERE ip = ?", (ip,))

    def forget_manual_ban(self, ip: str) -> bool:
        with self._lock, self._conn:
            return bool(self._conn.execute("DELETE FROM manual_bans WHERE ip = ?", (ip,)).rowcount)

    def scheduled_bans(self) -> Dict[str, int]:
        """Addresses this daemon believes it has banned, and until when."""

        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, banned_until FROM ip_state WHERE banned_until > 0"
            ).fetchall()
        return {str(row["ip"]): int(row["banned_until"]) for row in rows}

    def last_ban_ts(self, ip: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS value FROM security_events "
                "WHERE ip = ? AND event_type = ?",
                (ip, EVENT_BAN_APPLIED),
            ).fetchone()
        return int(row["value"] or 0) if row else 0

    def last_ban_detail(self, ip: str) -> str:
        """What was written down when this address was last banned."""

        with self._lock:
            row = self._conn.execute(
                "SELECT detail FROM security_events "
                "WHERE ip = ? AND event_type = ? ORDER BY ts DESC LIMIT 1",
                (ip, EVENT_BAN_APPLIED),
            ).fetchone()
        return str(row["detail"] or "") if row else ""

    def newest_finding_ts(self, ip: str) -> int:
        """Timestamp of the most recent event that carries weight.

        The gateway's own bans seen in the table are not findings, including
        those recorded before they stopped being written.
        """

        own = [f"code={code}" for code in sorted(OWN_BAN_CODES)]
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS value FROM security_events "
                "WHERE ip = ? AND event_type NOT IN (?, ?) "
                f"AND NOT (event_type = ? AND detail IN ({','.join('?' * len(own))}))",
                (ip, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED, EVENT_LEGACY_BAN, *own),
            ).fetchone()
        return int(row["value"] or 0) if row else 0

    def ban_timestamps(self, ip: str, limit: int = 100) -> List[int]:
        """When this address was banned, oldest first.

        Capped: an address with more links than the ladder has rungs is
        already at the top of it, so older ones cannot change the answer.
        """

        with self._lock:
            rows = self._conn.execute(
                "SELECT ts FROM security_events "
                "WHERE ip = ? AND event_type = ? ORDER BY ts DESC LIMIT ?",
                (ip, EVENT_BAN_APPLIED, int(limit)),
            ).fetchall()
        return sorted(int(row["ts"]) for row in rows)

    def strike_count(self, ip: str, since: int) -> int:
        """How many times this address has been banned recently."""

        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS value FROM security_events "
                "WHERE ip = ? AND event_type = ? AND ts >= ?",
                (ip, EVENT_BAN_APPLIED, since),
            ).fetchone()
        return int(row["value"]) if row else 0

    def ip_facts(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT first_seen, last_seen, excluded, exclusion_reason, "
                "authenticated_at FROM ip_state WHERE ip = ?",
                (ip,),
            ).fetchone()
        return dict(row) if row else {}

    def quality(self, since: int, now: int) -> Dict[str, Any]:
        """How the protection did between two moments, from its own records.

        Counts only, and the networks the bans cluster in -- never the
        addresses. Every query is by the indexes the tables already have.
        """
        with self._lock:
            bans = self._conn.execute(
                "SELECT ip, ts, until, strike, score, reason FROM ban_decisions "
                "WHERE action = 'applied' AND source = 'adaptive' AND ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
            first = self._conn.execute("SELECT MIN(ts) AS value FROM ban_decisions").fetchone()["value"]
            operator_lifts = self._conn.execute(
                "SELECT ip, ts FROM ban_decisions "
                "WHERE action = 'lifted' AND source = 'operator' AND ts >= ?", (since,),
            ).fetchall()
            lifted_by_operator = len(operator_lifts)
            lifted_ts_by_ip: Dict[str, List[int]] = {}
            for row in operator_lifts:
                lifted_ts_by_ip.setdefault(row["ip"], []).append(int(row["ts"]))
            auth_rows = self._conn.execute(
                "SELECT ip, authenticated_at FROM ip_state WHERE authenticated_at > 0"
            ).fetchall()
            auth_at_by_ip = {row["ip"]: int(row["authenticated_at"]) for row in auth_rows}
            marks = ",".join("?" * len(SIGNATURE_EVENTS))
            quiet = (EVENT_BAN_APPLIED, EVENT_BAN_LIFTED, EVENT_LEGACY_BAN, EVENT_LEGACY_BAN_LIFTED)
            not_quiet = ",".join("?" * len(quiet))
            at_once = single = 0
            for ban in bans:
                row = self._conn.execute(
                    f"SELECT MIN(ts) AS first, COUNT(*) AS findings FROM security_events "
                    f"WHERE ip = ? AND ts BETWEEN ? AND ? AND event_type NOT IN ({not_quiet})",
                    (ban["ip"], ban["ts"] - 86400, ban["ts"] + 5, *quiet),
                ).fetchone()
                if row["first"] is not None:
                    at_once += ban["ts"] - row["first"] <= QUALITY_AT_ONCE_SECONDS
                    single += row["findings"] == 1
            ended = came_back = 0
            seen: Set[str] = set()
            for ban in bans:
                if ban["ip"] in seen or not 0 < ban["until"] < now:
                    continue
                seen.add(ban["ip"])
                ended += 1
                again = self._conn.execute(
                    f"SELECT 1 FROM security_events WHERE ip = ? AND ts > ? "
                    f"AND event_type NOT IN ({not_quiet}) LIMIT 1",
                    (ban["ip"], ban["until"], *quiet),
                ).fetchone()
                came_back += again is not None
            unbanned = self._conn.execute(
                f"SELECT COUNT(DISTINCT e.ip) AS value FROM security_events e "
                f"WHERE e.ts >= ? AND e.handled = 0 AND e.event_type IN ({marks}) "
                f"AND NOT EXISTS (SELECT 1 FROM ban_decisions d WHERE d.ip = e.ip AND d.action = 'applied')",
                (since, *sorted(SIGNATURE_EVENTS)),
            ).fetchone()["value"]
        addresses = {ban["ip"] for ban in bans}
        networks: Dict[str, int] = {}
        for ip in addresses:
            if "." in ip:
                key = ip.rsplit(".", 1)[0] + ".0/24"
                networks[key] = networks.get(key, 0) + 1
        crowded = sorted(((count, name) for name, count in networks.items() if count >= QUALITY_NETWORK_MIN),
                         reverse=True)
        steps: Dict[str, int] = {}
        signal_stats: Dict[str, Dict[str, int]] = {}
        for ban in bans:
            steps[str(ban["strike"])] = steps.get(str(ban["strike"]), 0) + 1
            ban_ip = ban["ip"]
            ban_ts = int(ban["ts"])
            ban_until = max(int(ban["until"]), ban_ts + 86400)
            was_lifted = any(ban_ts <= t <= ban_until for t in lifted_ts_by_ip.get(ban_ip, ()))
            auth_after = auth_at_by_ip.get(ban_ip, 0) > ban_ts
            disputed = was_lifted or auth_after
            reason_raw = ban["reason"] or "{}"
            evidence = []
            with contextlib.suppress(ValueError, TypeError):
                parsed_reason = json.loads(reason_raw)
                if isinstance(parsed_reason, dict) and isinstance(parsed_reason.get("evidence"), list):
                    evidence = parsed_reason["evidence"]
            seen_signals: Set[str] = set()
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                ev_type = str(item.get("event_type") or "")
                if not ev_type:
                    continue
                cat = str(item.get("category") or "")
                sig = f"{ev_type}:{cat}" if cat else ev_type
                seen_signals.add(sig)
            for sig in seen_signals:
                entry = signal_stats.setdefault(
                    sig, {"bans": 0, "lifted_by_operator": 0, "authenticated_after": 0, "disputed": 0}
                )
                entry["bans"] += 1
                if was_lifted:
                    entry["lifted_by_operator"] += 1
                if auth_after:
                    entry["authenticated_after"] += 1
                if disputed:
                    entry["disputed"] += 1
        by_signal = [
            {
                "signal": sig,
                "bans": st["bans"],
                "lifted_by_operator": st["lifted_by_operator"],
                "authenticated_after": st["authenticated_after"],
                "disputed": st["disputed"],
                "fp_rate": round(st["disputed"] / st["bans"], 3) if st["bans"] else 0.0,
            }
            for sig, st in signal_stats.items()
        ]
        by_signal.sort(key=lambda row: (-row["disputed"], -row["bans"], row["signal"]))
        covered = max(0, now - max(since, int(first or now)))
        return {
            "since": since,
            "until": now,
            "covered_seconds": covered,
            "bans": len(bans),
            "banned_addresses": len(addresses),
            "bans_per_day": round(len(bans) * 86400 / covered, 1) if covered >= 3600 else None,
            "decided_at_once": int(at_once),
            "on_a_single_finding": int(single),
            "steps": steps,
            "first_bans_ended": ended,
            "came_back_after_a_ban": int(came_back),
            "lifted_by_operator": int(lifted_by_operator),
            "probers_never_banned": int(unbanned),
            "networks": [{"network": name, "addresses": count} for count, name in crowded[:QUALITY_NETWORKS_SHOWN]],
            "addresses_in_networks": sum(count for count, _ in crowded),
            "by_signal": by_signal[:25],
        }

    def last_applied_ban(self, ip: str) -> Optional[Dict[str, int]]:
        """The code and end of the last ban that was applied to this address."""
        with self._lock:
            row = self._conn.execute(
                "SELECT code, until FROM ban_decisions WHERE ip = ? AND action = 'applied' "
                "AND outcome = 'applied' ORDER BY ts DESC, id DESC LIMIT 1",
                (ip,),
            ).fetchone()
        return {"code": int(row["code"]), "until": int(row["until"])} if row else None

    def scheduled_ban_codes(self) -> Dict[str, int]:
        """The reason code each scheduled ban was placed with."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, ban_code FROM ip_state WHERE banned_until > 0"
            ).fetchall()
        return {str(row["ip"]): int(row["ban_code"] or 0) for row in rows}

    def set_ban_code(self, ip: str, code: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE ip_state SET ban_code = ? WHERE ip = ?", (int(code), ip))

    def signature_paths_since(self, ip: str, since: int) -> int:
        """Different paths with a scanner signature this address asked for after a moment."""
        marks = ",".join("?" * len(SIGNATURE_EVENTS))
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT detail) AS value FROM security_events "
                f"WHERE ip = ? AND ts > ? AND event_type IN ({marks})",
                (ip, int(since), *sorted(SIGNATURE_EVENTS)),
            ).fetchone()
        return int(row["value"] or 0)

    def last_signature(self, ip: str, since: int, until: int) -> int:
        """When this address last matched a scanner signature in the span, or 0."""
        marks = ",".join("?" * len(SIGNATURE_EVENTS))
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS value FROM security_events "
                f"WHERE ip = ? AND ts BETWEEN ? AND ? AND event_type IN ({marks})",
                (ip, int(since), int(until), *sorted(SIGNATURE_EVENTS)),
            ).fetchone()
        return int(row["value"] or 0)

    def events_for(
        self, ip: str, since: int, limit: int = 500
    ) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, event_type, source, site, category, detail, handled "
                "FROM security_events WHERE ip = ? AND ts >= ? "
                "ORDER BY ts DESC, id DESC LIMIT ?",
                (ip, since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_addresses(self, since: int, limit: int = 500) -> List[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, COUNT(*) AS hits FROM security_events "
                "WHERE ts >= ? GROUP BY ip ORDER BY hits DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [str(row["ip"]) for row in rows]

    def enforcement_addresses(self, after: Tuple[int, str], before: int,
                              limit: int) -> List[Tuple[int, str]]:
        """One bounded index page, including quiet addresses.

        No COUNT/GROUP BY over the event history, and no OFFSET that grows
        with the database. Filtering and scoring happen for this page only.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT first_seen, ip FROM ip_state "
                "WHERE (first_seen, ip) > (?, ?) AND first_seen <= ? "
                "ORDER BY first_seen, ip LIMIT ?",
                (*after, before, int(limit)),
            ).fetchall()
        return [(int(row["first_seen"]), str(row["ip"])) for row in rows]

    def recent_findings(self, limit: int) -> List[Dict[str, Any]]:
        """A bounded tail for recovery; never sort the whole scoring window."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, ts, event_type, handled FROM security_events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def cooldown_passed(self, fingerprint: str, ts: int, window: int) -> bool:
        """True when this fingerprint may produce an event again."""

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT last_ts FROM event_cooldowns WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is not None and ts - int(row["last_ts"]) < window:
                return False
            self._conn.execute(
                "INSERT INTO event_cooldowns (fingerprint, last_ts) VALUES (?, ?) "
                "ON CONFLICT (fingerprint) DO UPDATE SET last_ts = excluded.last_ts",
                (fingerprint, ts),
            )
        return True

    def apply_retention(
        self, *, events_before: int, bans_before: Optional[int] = None
    ) -> Dict[str, int]:
        """Sweep old rows.

        Ban records are kept longer than everything else, and deliberately:
        they are what the escalating ladder is counted from. Sweeping them on
        the ordinary schedule would have quietly capped the ladder at
        whatever fits inside the retention period -- the top rungs would have
        existed in the settings and been unreachable in practice.
        """

        if bans_before is None:
            bans_before = events_before
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM security_events WHERE ts < ? "
                "AND event_type NOT IN (?, ?)",
                (events_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED),
            )
            events = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM security_events WHERE ts < ? AND event_type IN (?, ?)",
                (bans_before, EVENT_BAN_APPLIED, EVENT_BAN_LIFTED),
            )
            events += cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM event_cooldowns WHERE last_ts < ?", (events_before,)
            )
            cooldowns = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM ip_state WHERE last_seen < ? AND banned_until = 0",
                (events_before,),
            )
            addresses = cursor.rowcount or 0
            cursor.close()
        return {
            "events": events,
            "cooldowns": cooldowns,
            "addresses": addresses,
        }

    # -- rate warnings ----------------------------------------------------

    _RATE_WARNING_COLUMNS = (
        "ip", "site", "trust", "rate_limit", "window_s", "enforced", "started",
        "ended", "peak", "over_limit", "requests", "rate_limited", "banned",
        "rate_ban",
    )

    def record_rate_warnings(self, episodes: Iterable[Dict[str, Any]]) -> int:
        rows = [
            (
                str(e["ip"]), str(e["site"]), str(e["trust"]), int(e["limit"]),
                int(e["window"]), 1 if e.get("enforced", True) else 0,
                int(e["started"]), int(e["ended"]), int(e["peak"]),
                int(e["over_limit"]), int(e["requests"]),
                int(e.get("rate_limited") or 0), int(e.get("banned") or 0),
                1 if e.get("rate_ban") else 0,
            )
            for e in episodes
        ]
        if not rows:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(
                f"INSERT INTO rate_warnings ({', '.join(self._RATE_WARNING_COLUMNS)}) "
                f"VALUES ({', '.join('?' * len(self._RATE_WARNING_COLUMNS))})",
                rows,
            )
        return len(rows)

    def rate_warnings(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {', '.join(self._RATE_WARNING_COLUMNS)} FROM rate_warnings "
                "ORDER BY ended DESC, id DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["kind"] = RATE_WARNING
            item["limit"] = item.pop("rate_limit")
            item["window"] = item.pop("window_s")
            item["enforced"] = bool(item["enforced"])
            item["rate_ban"] = bool(item["rate_ban"])
            item["open"] = False
            result.append(item)
        return result

    def rate_warning_count(self, *, since: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM rate_warnings WHERE ended >= ?", (int(since),)
            ).fetchone()
        return int(row["n"] or 0)

    def prune_rate_warnings(self, *, before: int, keep: int) -> int:
        with self._lock, self._conn:
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM rate_warnings WHERE ended < ?", (int(before),))
            deleted = cursor.rowcount or 0
            cursor.execute(
                "DELETE FROM rate_warnings WHERE id NOT IN "
                "(SELECT id FROM rate_warnings ORDER BY id DESC LIMIT ?)",
                (max(0, int(keep)),),
            )
            deleted += cursor.rowcount or 0
            cursor.close()
        return deleted

    def incremental_vacuum(self, pages: int = 256) -> None:
        with self._lock, self._conn:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute(f"PRAGMA incremental_vacuum({int(pages)})")

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            cursor = self._conn.cursor()
            version = cursor.execute(
                "SELECT version FROM schema_version"
            ).fetchone()
            events = cursor.execute(
                "SELECT COUNT(*) AS value, MIN(ts) AS oldest, MAX(ts) AS newest "
                "FROM security_events"
            ).fetchone()
            addresses = cursor.execute(
                "SELECT COUNT(*) AS value, "
                "SUM(CASE WHEN excluded = 1 THEN 1 ELSE 0 END) AS excluded, "
                "SUM(CASE WHEN enforceable = 0 THEN 1 ELSE 0 END) AS unenforceable "
                "FROM ip_state"
            ).fetchone()
            by_type = cursor.execute(
                "SELECT event_type, COUNT(*) AS value FROM security_events "
                "GROUP BY event_type ORDER BY value DESC LIMIT 20"
            ).fetchall()
            cursor.close()
        return {
            "schema_version": int(version["version"]) if version else 0,
            "events": {
                "rows": int(events["value"]),
                "oldest_ts": events["oldest"],
                "newest_ts": events["newest"],
                "by_type": {
                    str(row["event_type"]): int(row["value"]) for row in by_type
                },
            },
            "addresses": {
                "rows": int(addresses["value"] or 0),
                "excluded": int(addresses["excluded"] or 0),
                "unenforceable": int(addresses["unenforceable"] or 0),
            },
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
        return {
            "database_bytes": database,
            "wal_bytes": wal,
            "shm_bytes": shm,
            "total_bytes": database + wal + shm,
        }
