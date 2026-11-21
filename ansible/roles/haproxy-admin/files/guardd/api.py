"""Unix-socket HTTP API handler, server, and CLI entrypoint."""

from __future__ import annotations

import contextlib
import grp
import hmac
import ipaddress
import json
import logging
import os
import pwd
import signal
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .constants import (
    ADAPTIVE_BAN_CODE,
    CANDIDATE_MIN_ADDRESSES,
    CANDIDATE_TTL,
    CONFIG_PATH,
    CONTROL_TOKEN,
    DATABASE_PATH,
    DECISION_FEED_KINDS,
    DECISION_FEED_SOURCES,
    LOG,
    MODE_OFF,
    ManualBanRefused,
    QUALITY_MAX_DAYS,
    SOCKET_GROUP,
    SOCKET_PATH,
    UNKNOWN_HOSTS_TTL,
    _REQUESTS_LOCK,
    _alert_client,
    _clamp_int,
    _dismissed_candidates,
    _utc_now,
    apply_overrides,
    dismiss_candidate,
    load_overrides,
    load_signatures,
    signature_summary,
    store_overrides,
)
from .runtime import ConfigError, GuardConfig, banned_now, load_config
from .scoring import policy_from_query
from .watchers import RATE_WARNINGS_KEEP_DAYS
from .storage import SecurityDatabase
from .request_log import REQUEST_LOG_PATH, RequestLog, RequestQuery
from .live import DIGEST_BOUNDS_MS, LiveBudgetConflict, live_filters
from .engine import GuardEngine

# ---------------------------------------------------------------------------
# Unix socket API
# ---------------------------------------------------------------------------


# How long one connection may keep a handler thread waiting on it: for the
# request, or for the caller to take the answer. Callers are local and send a
# whole request at once; one that connected and went quiet used to hold its
# thread for good. Processing time is not limited by this.
REQUEST_TIMEOUT_SECONDS = 30


def rate_warnings_payload(engine: "GuardEngine", database: "SecurityDatabase",
                          limit: int, now: int) -> Dict[str, Any]:
    return {
        "ok": True,
        "ts": now,
        # Nothing on this list was refused, scored or banned because of it.
        "observed_only": True,
        "open": engine.trusted_rates.open_episodes(),
        "recent": database.rate_warnings(limit=limit),
        "last_24h": database.rate_warning_count(since=now - 86400),
        "keep_days": RATE_WARNINGS_KEEP_DAYS,
        # Nested: the observer's own "open" is a count and must not
        # replace the list above.
        "observer": engine.trusted_rates.summary(),
    }


class GuardHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-guardd/1.0"
    timeout = REQUEST_TIMEOUT_SECONDS

    def address_string(self) -> str:  # noqa: N802
        return "unix"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        LOG.debug(fmt, *args)

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        engine: GuardEngine = self.server.engine  # type: ignore[attr-defined]
        database: SecurityDatabase = self.server.database  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/guard/health":
            try:
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": _utc_now(),
                        "engine": engine.health(),
                        "database": database.stats(),
                        "storage": database.storage(),
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/digest":
            # The minutes complete since the collector last asked.
            query = parse_qs(urlparse(self.path).query or "")
            try:
                since = int((query.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            now = _utc_now()
            try:
                self._send_json(200, {
                    "ok": True,
                    "now": now,
                    "bounds_ms": list(DIGEST_BOUNDS_MS),
                    "minutes": engine.digests.complete(since, now),
                    "late": engine.digests.late,
                })
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/bans/schedule":
            # When each held address is let go, and nothing else. The ban
            # list on the dashboard polls every few seconds, so this is one
            # indexed query rather than the shadow review, which scores up to
            # two hundred addresses to answer a different question.
            try:
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "now": _utc_now(),
                        "mode": engine.enforcer.mode,
                        "enforcing": engine.enforcer.allowed,
                        "code": ADAPTIVE_BAN_CODE,
                        "bans": database.scheduled_bans(),
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/reputation":
            try:
                rows = engine.reputation_table()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": _utc_now(),
                        "mode": engine.config.mode,
                        "addresses": [
                            {
                                key: value
                                for key, value in row.items()
                                if key != "contributions"
                            }
                            for row in rows
                        ],
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/identities":
            live = engine.live
            self._send_json(200, {"ok": True, "users_by_ip": live.identities() if live else {}})
            return

        if path == "/api/v1/guard/live/memory":
            try:
                self._send_json(200, {"ok": True, "ts": _utc_now(), **engine.live_memory()})
            except LookupError as exc:
                self._send_json(404, {"ok": False, "error": str(exc)})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path in ("/api/v1/guard/live", "/api/v1/guard/attackers"):
            live = engine.live
            if live is None:
                self._send_json(404, {"ok": False, "error": "the live buffer is off"})
                return
            try:
                if path.endswith("/attackers"):
                    self._send_json(200, {"ok": True, **live.attackers()})
                    return
                query = parse_qs(urlparse(self.path).query or "")
                raw = {name: (values[0] if values else "") for name, values in query.items()}
                banned = None
                if live_filters(raw).get("banned"):
                    banned = banned_now(engine.config.haproxy_socket)
                result = live.snapshot(raw, banned=banned)
                # How far behind the log the buffer is: the newest line it
                # holds, and how many bytes are still unread.
                status = live.status()
                result = {
                    **result,
                    "buffer": status,
                    "lag_bytes": engine.cursor.lag_bytes,
                    "lag_seconds": (
                        max(0, int(result["now"] - status["newest"]))
                        if status.get("newest") else None
                    ),
                }
                self._send_json(200, result)
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path in ("/api/v1/guard/requests", "/api/v1/guard/requests/status",
                    "/api/v1/guard/requests/summary"):
            with _REQUESTS_LOCK:
                requests = getattr(self.server, "requests", None)
                # With the record off, a search is answered from the live buffer:
                # the last hour or so, so a link from the live page or the charts
                # still finds its requests.
                memory = engine.live if requests is None and not path.endswith("/status") else None
                if requests is None and memory is None:
                    self._send_json(
                        404,
                        {"ok": False, "enabled": False, "error": "the request log is off"},
                    )
                    return
                try:
                    if path.endswith("/status"):
                        self._send_json(
                            200, {"ok": True, "ts": _utc_now(), **requests.status()}
                        )
                        return
                    query = parse_qs(urlparse(self.path).query or "")

                    def one(name: str) -> str:
                        return (query.get(name, [""])[0] or "").strip()

                    def yes(name: str) -> bool:
                        return one(name).lower() in ("1", "true", "yes", "on")

                    filters = dict(
                        since=_clamp_int(one("since"), default=0, min_v=0, max_v=2_000_000_000),
                        until=_clamp_int(one("until"), default=0, min_v=0, max_v=2_000_000_000),
                        client=one("client"),
                        status=one("status"),
                        host=one("host"),
                        backend=one("backend"),
                        request_id=one("request_id"),
                        method=one("method").upper(),
                        path=one("path"),
                        hide_admin=yes("hide_admin"),
                        refused=yes("refused"),
                        slower=_clamp_int(one("slower"), default=0, min_v=0, max_v=86_400_000),
                        agent=one("agent"),
                    )
                    if path.endswith("/summary"):
                        if requests is None:
                            payload = memory.summarize_requests(RequestQuery.build(**filters))
                        else:
                            payload = requests.summary(**filters)
                        self._send_json(200, {"ok": True, "enabled": requests is not None,
                                              "ts": _utc_now(), **payload})
                        return
                    count = one("count").lower() not in ("0", "false", "no", "off")
                    limit = _clamp_int(one("limit"), default=100, min_v=1, max_v=500)
                    before = _clamp_int(one("before"), default=0, min_v=-(2 ** 62), max_v=2 ** 62)
                    if requests is None:
                        payload = memory.search_requests(
                            RequestQuery.build(**filters), before=before, limit=limit, count=count,
                        )
                        self._send_json(200, {"ok": True, "enabled": False, "ts": _utc_now(), **payload})
                        return
                    payload = requests.search(
                        **filters, before=max(0, before), count=count, limit=limit,
                    )
                    self._send_json(200, {"ok": True, "ts": _utc_now(), **payload})
                except Exception as exc:  # pylint: disable=broad-except
                    self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path in {"/api/v1/guard/adaptive/bans", "/api/v1/guard/adaptive/ban"}:
            query = parse_qs(urlparse(self.path).query or "")
            def value(name, default=""):
                return query.get(name, [default])[0]
            try:
                if path.endswith("/bans"):
                    payload = database.adaptive_ban_history(
                        query=value("q")[:100], since=max(0, int(value("since", "0"))),
                        terms=tuple(value('terms')[:2048].split(',')),
                        sort=value("sort", "ts"), direction=value("direction", "desc"),
                        offset=min(1000000, max(0, int(value("offset", "0")))),
                        snapshot=min(2**62, max(0, int(value("snapshot", "0")))),
                    )
                else:
                    decision_id = min(2**62, max(0, int(value("id", "0"))))
                    ip = str(ipaddress.ip_address(value("ip"))) if not decision_id else ""
                    decision = database.adaptive_ban_detail(decision_id=decision_id, ip=ip,
                                                           at=max(0, int(value("at", "0"))))
                    if decision is None:
                        self._send_json(404, {"ok": False, "error": "This ban record is no longer available"})
                        return
                    payload = {"ban": decision}
                self._send_json(200, {"ok": True, **payload})
            except (ValueError, OverflowError):
                self._send_json(400, {"ok": False, "error": "Invalid ban history filters"})
            return

        if path == "/api/v1/guard/decisions/feed":
            # Every address's decisions, newest first (06.6). Read from the
            # database, so the stream of requests never pushes one out.
            query = parse_qs(urlparse(self.path).query or "")
            kind = (query.get("kind", ["all"])[0] or "all").strip()
            if kind not in DECISION_FEED_KINDS:
                self._send_json(400, {"ok": False, "error": "kind must be all, bans or lifts"})
                return
            try:
                limit = _clamp_int(query.get("limit", [None])[0], default=50, min_v=1, max_v=200)
                before = _clamp_int(query.get("before", [None])[0], default=0, min_v=0, max_v=2 ** 62)
                rows = database.decision_feed(before, limit, DECISION_FEED_KINDS[kind])
                more = len(rows) > limit
                rows = rows[:limit]
                self._send_json(200, {
                    "ok": True,
                    "decisions": rows,
                    "next": rows[-1]["id"] if more and rows else 0,
                    "sources": list(DECISION_FEED_SOURCES),
                    "keep_seconds": engine.longest_strike_retention(),
                })
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/decisions":
            query = parse_qs(urlparse(self.path).query or "")
            address = (query.get("ip", [""])[0] or "").strip()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "invalid ip"})
                return
            try:
                limit = _clamp_int(query.get("limit", [None])[0], default=20, min_v=1, max_v=100)
                self._send_json(200, {
                    "ok": True,
                    "ip": address,
                    "decisions": database.ban_decisions(address, limit=limit),
                    "keep_seconds": engine.longest_strike_retention(),
                })
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/quality":
            query = parse_qs(urlparse(self.path).query or "")
            try:
                days = _clamp_int(query.get("days", [None])[0], default=7, min_v=1, max_v=QUALITY_MAX_DAYS)
                self._send_json(200, {"ok": True, "quality": engine.quality(days)})
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot work out the quality report")
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/rate-warnings":
            query = parse_qs(urlparse(self.path).query or "")
            try:
                limit = _clamp_int(query.get("limit", [None])[0], default=100, min_v=1, max_v=500)
                self._send_json(200, rate_warnings_payload(engine, database, limit, _utc_now()))
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/signatures":
            self._send_json(200, {"ok": True, **signature_summary()})
            return

        if path == "/api/v1/guard/detection-context":
            self._send_json(200, engine.detection_state())
            return

        if path == "/api/v1/guard/traps":
            self._send_json(200, {
                "ok": True,
                "trap_hosts": sorted(engine.trap_hosts),
                "unknown_hosts": engine.unknown_hosts.listing(),
                "site_names_known": bool(engine.site_names()),
                "window_days": UNKNOWN_HOSTS_TTL // 86400,
            })
            return

        if path == "/api/v1/guard/signatures/candidates":
            dismissed = set(_dismissed_candidates(engine.database))
            self._send_json(200, {
                "ok": True,
                "candidates": engine.candidates.suggestions(dismissed),
                "dismissed": sorted(dismissed),
                "min_addresses": CANDIDATE_MIN_ADDRESSES,
                "window_days": CANDIDATE_TTL // 86400,
            })
            return

        if path == "/api/v1/guard/shadow":
            query = parse_qs(urlparse(self.path).query or "")
            try:
                policy = policy_from_query(query, engine.scoring_policy())
                limit = _clamp_int(
                    query.get("limit", [None])[0], default=200, min_v=1, max_v=500
                )
                payload = engine.shadow_review(limit=limit, policy=policy)
                payload["ok"] = True
                payload["ts"] = _utc_now()
                self._send_json(200, payload)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/guard/ip":
            query = parse_qs(urlparse(self.path).query or "")
            address = (query.get("ip", [""])[0] or "").strip()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "invalid ip"})
                return
            try:
                now = _utc_now()
                policy = policy_from_query(query, engine.scoring_policy())
                payload = engine.reputation(address, now, policy)
                payload["events"] = database.events_for(
                    address, now - policy.window_seconds, limit=200
                )
                payload["ok"] = True
                self._send_json(200, payload)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def _control_auth_ok(self) -> bool:
        if not CONTROL_TOKEN:
            return False
        supplied = (self.headers.get("X-Guardd-Token", "") or "").strip()
        return hmac.compare_digest(supplied, CONTROL_TOKEN)

    def do_POST(self) -> None:  # noqa: N802
        engine: GuardEngine = self.server.engine  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/guard/requests/enabled":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 4096:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise ValueError("expected an object")
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                result = _set_request_log(
                    self.server, engine, bool(payload.get("enabled"))
                )
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot change the request log")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **result})
            return

        if path == "/api/v1/guard/live/memory":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 1024:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise ValueError("expected an object")
                result = engine.set_live_memory(payload.get("budget_mib"), payload.get("revision"))
            except LiveBudgetConflict as exc:
                # The page shows what is in force now and asks again.
                current: Dict[str, Any] = {}
                with contextlib.suppress(Exception):
                    current = engine.live_memory()
                self._send_json(409, {"ok": False, "error": str(exc), "conflict": True, **current})
                return
            except LookupError as exc:
                self._send_json(404, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot change the live buffer's memory")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **result})
            return

        if path == "/api/v1/guard/first-step-page":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 1024:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                if not isinstance(payload, dict) or set(payload) != {"enabled"}:
                    raise ValueError("expected exactly one field: enabled")
                state = engine.set_first_step_page(payload["enabled"])
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, "first_step_page": state})
            return

        if path == "/api/v1/guard/shield":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 1024:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                if not isinstance(payload, dict) or set(payload) != {"enabled"}:
                    raise ValueError("expected exactly one field: enabled")
                state = engine.set_shield(payload["enabled"])
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, "path_shield": state})
            return

        if path == "/api/v1/guard/traps":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 16384:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                hosts = engine.set_trap_hosts(payload.get("hosts"))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, "trap_hosts": hosts})
            return

        if path in ("/api/v1/guard/detection-context", "/api/v1/guard/detection-preview"):
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
                if not 0 < length <= (8192 if path.endswith("preview") else 131072):
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if path.endswith("preview"):
                    result = engine.detection.preview(payload, engine.exclusions, _utc_now(), engine.scoring_policy())
                    result["active_mode"] = engine.enforcer.mode
                else:
                    engine.detection.replace(payload)
                    result = engine.detection_state()
            except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
                # A preview can contain a reset token. Never echo its payload
                # or parser exception into diagnostics or the audit trail.
                detail = "invalid request fields" if path.endswith("preview") else str(exc)
                self._send_json(400, {"ok": False, "error": detail})
                return
            except sqlite3.Error:
                self._send_json(503, {"ok": False, "error": "detection storage unavailable"})
                return
            self._send_json(200, result)
            return

        if path == "/api/v1/guard/signatures/candidates/dismiss":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 4096:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                result = dismiss_candidate(
                    engine.database, str(payload.get("path", "")),
                    restore=bool(payload.get("restore")),
                    host=str(payload.get("host", "")),
                )
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **result})
            return

        if path == "/api/v1/guard/signatures":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                # Larger than the mode payload: this one carries a rule list.
                if length <= 0 or length > 65536:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                store_overrides(engine.database, payload)
            except ValueError as exc:
                # A rejected rule is the operator's typo, not a fault.
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot store the signature overrides")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, {"ok": True, **signature_summary()})
            return

        if path == "/api/v1/guard/ban-durations":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int(
                    (self.headers.get("Content-Length") or "0").strip() or "0"
                )
                if length <= 0 or length > 4096:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace")
                )
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            try:
                steps = engine.set_ban_durations(payload.get("durations"))
            except ValueError as exc:
                # A rejected ladder is the operator's typo, not a fault.
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot store the ban durations")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(
                200, {"ok": True, "ban_durations_seconds": list(steps)}
            )
            return

        if path == "/api/v1/guard/ban/manual":
            # An operator's ban from the panel: placed and remembered here,
            # serialized with every other change to the ban table (R02/R03).
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int((self.headers.get("Content-Length") or "0").strip() or "0")
                if length <= 0 or length > 1024:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise ValueError("expected an object")
                result = engine.place_manual_ban(str(payload.get("ip", "")))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except (ManualBanRefused, OSError) as exc:
                self._send_json(502, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot place the manual ban")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, result)
            return

        if path == "/api/v1/guard/ban/forget":
            if not self._control_auth_ok():
                self._send_json(403, {"ok": False, "error": "forbidden"})
                return
            try:
                length = int(
                    (self.headers.get("Content-Length") or "0").strip() or "0"
                )
                if length <= 0 or length > 1024:
                    raise ValueError("invalid Content-Length")
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace")
                )
                result = engine.forget_ban(str(payload.get("ip", "")))
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("cannot clear the ban")
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, result)
            return

        if path != "/api/v1/guard/mode":
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        if not self._control_auth_ok():
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return

        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": f"bad json: {exc}"})
            return

        try:
            result = engine.set_mode(str(payload.get("mode", "")))
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        result["ok"] = True
        self._send_json(200, result)


REQUEST_LOG_OVERRIDE_KEY = "request_log_override"


def _request_log_wanted(database: "SecurityDatabase", config: GuardConfig) -> bool:
    """Whether to keep the request store, config plus any operator switch.

    Kept in guardd's own state rather than in guardd.json, exactly like the
    enforcement mode: the file is a template Ansible owns and rewrites, so a
    choice made in the web interface has to live somewhere Ansible does not
    reach.
    """
    override = database.get_state(REQUEST_LOG_OVERRIDE_KEY, "")
    if override in ("on", "off"):
        return override == "on"
    return bool(config.request_log_enabled)


def _set_request_log(server: "GuardServer", engine: "GuardEngine", enabled: bool):
    """Turn the store on or off now, and remember the choice."""
    with _REQUESTS_LOCK:
        engine.database.set_state(REQUEST_LOG_OVERRIDE_KEY, "on" if enabled else "off")
        if enabled and server.requests is None:
            store = RequestLog(REQUEST_LOG_PATH, engine.config)
            server.requests = store
            engine.requests = store
            LOG.warning("Request log enabled from the web interface")
        elif not enabled and server.requests is not None:
            store = server.requests
            server.requests = None
            engine.requests = None
            # Anything already queued is written before the handle goes away;
            # dropping it would lose requests the operator can see in the page
            # right now.
            with contextlib.suppress(Exception):
                store.flush()
            with contextlib.suppress(Exception):
                store.close()
            LOG.warning("Request log disabled from the web interface")
        return {
            "enabled": server.requests is not None,
            "configured": bool(engine.config.request_log_enabled),
        }


class GuardServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: str,
        handler_cls: type[BaseHTTPRequestHandler],
        engine: GuardEngine,
        database: SecurityDatabase,
    ) -> None:
        super().__init__(socket_path, handler_cls)
        self.engine = engine
        self.database = database
        # Set after construction: the request log is optional and the server
        # answers a "not enabled" 404 for its routes when it is absent.
        self.requests: Optional[RequestLog] = None


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

    # Before anything reads a log line: a signature file that turns out to be
    # unreadable leaves the built-in tables in place and says so.
    load_signatures()

    try:
        config = load_config(CONFIG_PATH)
    except ConfigError as exc:
        LOG.error("%s", exc)
        raise SystemExit(2) from exc

    # The request log rides on the same tail of the same file, so it keeps
    # working with the security engine switched off -- diagnostics should not
    # depend on whether the operator wants scoring.
    # The database first: it holds the operator's switch, and that switch
    # decides whether there is anything to do at all.
    database = SecurityDatabase(DATABASE_PATH)
    # The operator's own rules go on top of the shipped list, which was read
    # above. Order matters: the file first, then what was changed about it.
    apply_overrides(load_overrides(database))
    want_requests = _request_log_wanted(database, config)
    if config.mode == MODE_OFF and not want_requests:
        LOG.info("Adaptive protection is off in %s; idling", CONFIG_PATH)
        stop = threading.Event()

        def _idle_stop(_signum: int, _frame: Any) -> None:
            stop.set()

        for signal_number in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signal_number, _idle_stop)
        with contextlib.suppress(KeyboardInterrupt):
            stop.wait()
        database.close()
        return

    requests = RequestLog(REQUEST_LOG_PATH, config) if want_requests else None
    engine = GuardEngine(
        config, database, alerts=_alert_client(), requests=requests
    )

    # The mode in force: the panel's choice when one was made, which the
    # configuration file does not show. This line used to print the file's
    # mode, "monitor", on a gateway the panel had set to enforce.
    LOG.info(
        "Starting easy-ha-proxy-guardd: mode=%s (configured %s) socket=%s db=%s log=%s "
        "interval=%ss exclusions=%d networks",
        engine.enforcer.mode,
        config.mode,
        SOCKET_PATH,
        DATABASE_PATH,
        config.log_file,
        config.poll_interval_seconds,
        engine.exclusions.network_count,
    )

    engine.start()

    with contextlib.suppress(OSError):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

    server = GuardServer(SOCKET_PATH, GuardHandler, engine, database)
    server.requests = requests
    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Failed to set socket permissions: %s", exc)

    # systemd stops a unit with SIGTERM, which by default ends the process
    # where it stands: databases not closed, the request log's last cycle
    # not written. A backup stops this daemon to archive its databases
    # whole, so it now shuts down as the alert engine does.
    shutdown_event = threading.Event()
    received_signal: List[int] = []

    def _shutdown_watcher() -> None:
        shutdown_event.wait()
        if received_signal:
            LOG.info("Received signal %s; shutting down", received_signal[0])
        threading.Thread(target=server.shutdown, daemon=True).start()

    threading.Thread(target=_shutdown_watcher, daemon=True).start()

    def _shutdown(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)
        shutdown_event.set()

    for signal_number in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(signal_number, _shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        engine.stop()
        with contextlib.suppress(Exception):
            server.server_close()
        # The store in use now: recording may have been switched since start.
        store = getattr(server, "requests", None)
        if store is not None:
            with contextlib.suppress(Exception):
                store.flush()
            store.close()
        database.close()
        with contextlib.suppress(OSError):
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
