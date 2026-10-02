# -*- coding: utf-8 -*-
"""Журнал административных изменений.

Отвечает на пять вопросов: кто, что, когда, из чего во что и получилось ли.

Две вещи здесь важнее удобства. Первая: секреты не попадают в журнал никогда —
значения по «чувствительным» ключам заменяются до записи, и рекурсивно, потому
что пароль обычно лежит во вложенной структуре. Вторая: сбой записи в журнал
не отменяет саму операцию. Аудит — не путь трафика, и падение SQLite не должно
мешать продлить сертификат; вместо этого счётчик ошибок виден в состоянии.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

LOG = logging.getLogger("haproxy-admin")

AUDIT_DATABASE = os.environ.get(
    "AUDIT_DATABASE", "/var/lib/easy-ha-proxy/audit/audit.db"
).strip()

SCHEMA_VERSION = 1

RESULT_SUCCESS = "success"
RESULT_FAILURE = "failure"
RESULT_DENIED = "denied"
RESULTS = (RESULT_SUCCESS, RESULT_FAILURE, RESULT_DENIED)

ACTOR_USER = "user"
ACTOR_SYSTEM = "system"

# Audit records are small and precious, so they are kept far longer than
# metrics; the cap is on count as well as age because a loop somewhere must not
# be able to grow the file without limit.
DEFAULT_RETENTION_DAYS = 365
MAX_ROWS = 200_000
MAX_JSON_BYTES = 8192
MAX_SUMMARY_CHARS = 500

# Matched against key names, case-insensitively, anywhere in the name. Erring
# towards redacting too much is the right kind of wrong here.
_SENSITIVE_KEY = re.compile(
    r"pass|secret|token|credential|private|passphrase|cookie|authorization|"
    r"session|salt|hash|_key$|^key$|apikey|api_key",
    re.IGNORECASE,
)
_REDACTED = "***"


def redact(value: Any, _depth: int = 0) -> Any:
    """Заменить значения по чувствительным ключам, сохранив структуру."""

    if _depth > 6:
        return "..."
    if isinstance(value, dict):
        clean: Dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if _SENSITIVE_KEY.search(name):
                # The fact that it was supplied is worth keeping; the value is
                # not.
                clean[name] = _REDACTED if item not in (None, "") else None
            else:
                clean[name] = redact(item, _depth + 1)
        return clean
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value[:100]]
    if isinstance(value, str) and len(value) > 1000:
        return value[:1000] + "…"
    return value


def _dump(value: Any) -> str:
    if value is None:
        return ""
    try:
        text = json.dumps(redact(value), ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = json.dumps({"unserializable": str(type(value))})
    return text[:MAX_JSON_BYTES]


def summarize(before: Any, after: Any) -> str:
    """Короткое человекочитаемое описание того, что поменялось."""

    if not isinstance(before, dict) or not isinstance(after, dict):
        return ""
    before_clean = redact(before)
    after_clean = redact(after)
    parts: List[str] = []
    for key in sorted(set(before) | set(after)):
        # Compare the originals to decide whether anything moved: comparing the
        # redacted copies would report a changed password as unchanged, because
        # both sides read "***".
        old_raw = before.get(key)
        new_raw = after.get(key)
        if old_raw == new_raw:
            continue
        old = before_clean.get(key)
        new = after_clean.get(key)
        if key not in before:
            parts.append(f"+{key}")
        elif key not in after:
            parts.append(f"-{key}")
        elif _SENSITIVE_KEY.search(str(key)) or old == new:
            # Either the key is a secret, or the only difference is inside
            # something that was redacted. Say it changed, never what to.
            parts.append(f"{key}: changed")
        else:
            parts.append(f"{key}: {old!r} → {new!r}")
    return ", ".join(parts)[:MAX_SUMMARY_CHARS]


_SCHEMA: tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id          INTEGER PRIMARY KEY,
        ts          INTEGER NOT NULL,
        actor_type  TEXT    NOT NULL,
        actor       TEXT    NOT NULL DEFAULT '',
        source_ip   TEXT    NOT NULL DEFAULT '',
        action      TEXT    NOT NULL,
        object_type TEXT    NOT NULL DEFAULT '',
        object_id   TEXT    NOT NULL DEFAULT '',
        result      TEXT    NOT NULL,
        summary     TEXT    NOT NULL DEFAULT '',
        before_json TEXT    NOT NULL DEFAULT '',
        after_json  TEXT    NOT NULL DEFAULT '',
        detail      TEXT    NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events (ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events (actor, ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, ts DESC)",
    """
    CREATE INDEX IF NOT EXISTS idx_audit_object
        ON audit_events (object_type, object_id, ts DESC)
    """,
)


class AuditLog:
    """Хранилище журнала. Потокобезопасно, ошибки не пробрасываются наружу."""

    def __init__(self, path: str = "") -> None:
        self.path = Path(path or AUDIT_DATABASE)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self.write_failures = 0
        self.last_error: Optional[str] = None

    # -- storage ----------------------------------------------------------

    def _connect(self) -> Optional[sqlite3.Connection]:
        if self._conn is not None:
            return self._conn
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.path), timeout=5, check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            with conn:
                for statement in _SCHEMA:
                    conn.execute(statement)
                row = conn.execute("SELECT version FROM schema_version").fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO schema_version (version) VALUES (?)",
                        (SCHEMA_VERSION,),
                    )
            self._conn = conn
            return conn
        except Exception as exc:  # pylint: disable=broad-except
            self._note_failure(exc)
            return None

    def _note_failure(self, exc: Exception) -> None:
        self.write_failures += 1
        self.last_error = str(exc)
        if self.write_failures in (1, 10) or self.write_failures % 100 == 0:
            LOG.warning("Audit write failed (%d so far): %s", self.write_failures, exc)

    # -- writing ----------------------------------------------------------

    def record(
        self,
        action: str,
        *,
        actor: str = "",
        actor_type: str = ACTOR_USER,
        source_ip: str = "",
        object_type: str = "",
        object_id: str = "",
        result: str = RESULT_SUCCESS,
        before: Any = None,
        after: Any = None,
        summary: str = "",
        detail: str = "",
        ts: Optional[int] = None,
    ) -> bool:
        """Записать событие. Никогда не бросает исключений."""

        import time

        if result not in RESULTS:
            result = RESULT_SUCCESS
        payload = (
            int(ts if ts is not None else time.time()),
            actor_type if actor_type in (ACTOR_USER, ACTOR_SYSTEM) else ACTOR_SYSTEM,
            str(actor or "")[:120],
            str(source_ip or "")[:64],
            str(action or "")[:120],
            str(object_type or "")[:60],
            str(object_id or "")[:200],
            result,
            (summary or summarize(before, after))[:MAX_SUMMARY_CHARS],
            _dump(before),
            _dump(after),
            str(detail or "")[:MAX_SUMMARY_CHARS],
        )
        with self._lock:
            conn = self._connect()
            if conn is None:
                return False
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO audit_events (ts, actor_type, actor, source_ip, "
                        "action, object_type, object_id, result, summary, "
                        "before_json, after_json, detail) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        payload,
                    )
                return True
            except Exception as exc:  # pylint: disable=broad-except
                self._note_failure(exc)
                return False

    # -- reading ----------------------------------------------------------

    def query(
        self,
        *,
        actor: str = "",
        action: str = "",
        object_type: str = "",
        result: str = "",
        since: int = 0,
        until: int = 0,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        parameters: List[Any] = []
        # Every filter is a parameter; none of them reaches the SQL text.
        if actor:
            clauses.append("actor = ?")
            parameters.append(actor)
        if action:
            clauses.append("action = ?")
            parameters.append(action)
        if object_type:
            clauses.append("object_type = ?")
            parameters.append(object_type)
        if result in RESULTS:
            clauses.append("result = ?")
            parameters.append(result)
        if since:
            clauses.append("ts >= ?")
            parameters.append(int(since))
        if until:
            clauses.append("ts <= ?")
            parameters.append(int(until))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))

        with self._lock:
            conn = self._connect()
            if conn is None:
                return {"total": 0, "events": []}
            try:
                total = conn.execute(
                    f"SELECT COUNT(*) AS value FROM audit_events{where}", parameters
                ).fetchone()["value"]
                rows = conn.execute(
                    f"SELECT * FROM audit_events{where} "
                    "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                    [*parameters, limit, offset],
                ).fetchall()
            except Exception as exc:  # pylint: disable=broad-except
                self._note_failure(exc)
                return {"total": 0, "events": []}
        return {"total": int(total), "events": [dict(row) for row in rows]}

    def distinct(self, column: str, limit: int = 100) -> List[str]:
        """Значения для выпадающих фильтров. Колонка — из фиксированного набора."""

        if column not in ("actor", "action", "object_type"):
            return []
        with self._lock:
            conn = self._connect()
            if conn is None:
                return []
            try:
                rows = conn.execute(
                    f"SELECT DISTINCT {column} AS value FROM audit_events "
                    f"WHERE {column} != '' ORDER BY value LIMIT ?",
                    (max(1, min(int(limit), 500)),),
                ).fetchall()
            except Exception as exc:  # pylint: disable=broad-except
                self._note_failure(exc)
                return []
        return [str(row["value"]) for row in rows]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            if conn is None:
                return {
                    "available": False,
                    "write_failures": self.write_failures,
                    "last_error": self.last_error,
                }
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS rows, MIN(ts) AS oldest, MAX(ts) AS newest "
                    "FROM audit_events"
                ).fetchone()
            except Exception as exc:  # pylint: disable=broad-except
                self._note_failure(exc)
                return {"available": False, "write_failures": self.write_failures}
        size = 0
        with_suffix = (self.path, self.path.with_name(self.path.name + "-wal"))
        for candidate in with_suffix:
            try:
                size += candidate.stat().st_size
            except OSError:
                pass
        return {
            "available": True,
            "rows": int(row["rows"]),
            "oldest_ts": row["oldest"],
            "newest_ts": row["newest"],
            "bytes": size,
            "write_failures": self.write_failures,
            "last_error": self.last_error,
        }

    def apply_retention(
        self, now: int, days: int = DEFAULT_RETENTION_DAYS, max_rows: int = MAX_ROWS
    ) -> int:
        """Удалить записи старше срока и, отдельно, сверх жёсткого лимита."""

        with self._lock:
            conn = self._connect()
            if conn is None:
                return 0
            try:
                with conn:
                    cursor = conn.execute(
                        "DELETE FROM audit_events WHERE ts < ?",
                        (now - max(1, days) * 86400,),
                    )
                    removed = cursor.rowcount or 0
                    cursor = conn.execute(
                        "DELETE FROM audit_events WHERE id NOT IN "
                        "(SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)",
                        (max(1000, int(max_rows)),),
                    )
                    removed += cursor.rowcount or 0
                return removed
            except Exception as exc:  # pylint: disable=broad-except
                self._note_failure(exc)
                return 0


_LOG_INSTANCE: Optional[AuditLog] = None
_INSTANCE_LOCK = threading.Lock()


def audit_log() -> AuditLog:
    global _LOG_INSTANCE  # pylint: disable=global-statement
    with _INSTANCE_LOCK:
        if _LOG_INSTANCE is None:
            _LOG_INSTANCE = AuditLog()
        return _LOG_INSTANCE


def record_request(action: str, **kwargs: Any) -> bool:
    """Записать событие, взяв актора и адрес из текущего запроса.

    Вызывается из маршрутов; вне запроса просто пишет системного актора.
    """

    try:
        from flask import g, has_request_context, request

        if has_request_context():
            kwargs.setdefault("actor", getattr(g, "remote_user", "") or "")
            kwargs.setdefault("actor_type", ACTOR_USER)
            # The client address as HAProxy forwarded it; the application only
            # ever sees the proxy otherwise.
            forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")
            kwargs.setdefault(
                "source_ip", (forwarded[0] if forwarded else "").strip()
                or (request.remote_addr or "")
            )
    except Exception:  # pylint: disable=broad-except
        pass
    return audit_log().record(action, **kwargs)
