"""Unix-socket HTTP API handler, server, and CLI entrypoint for metricsd."""

from __future__ import annotations

import contextlib
import grp
import json
import logging
import os
import pwd
import signal
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from .constants import (
    CHART_SERIES,
    CONFIG_PATH,
    DATABASE_PATH,
    LOG,
    MIB,
    SOCKET_GROUP,
    SOCKET_PATH,
    _alert_client,
    _utc_now,
    resolve_window,
)
from .runtime import load_config
from .storage import CHANNEL_HIDDEN_KEY, CHANNEL_LABELS_KEY, MONITOR_DEFAULTS, MetricsDatabase
from .collector import Collector, StorageGuard, StorageStatus

# ---------------------------------------------------------------------------
# Unix socket API
# ---------------------------------------------------------------------------


# How long one connection may keep a handler thread waiting on it: for the
# request, or for the caller to take the answer. Callers are local and send a
# whole request at once; one that connected and went quiet used to hold its
# thread for good. Processing time is not limited by this.
REQUEST_TIMEOUT_SECONDS = 30


class MetricsHandler(BaseHTTPRequestHandler):
    server_version = "easy-ha-proxy-metricsd/1.0"
    timeout = REQUEST_TIMEOUT_SECONDS

    def _peer(self) -> str:
        address = getattr(self, "client_address", None)
        if isinstance(address, str) and address:
            return address
        return "unix"

    def address_string(self) -> str:  # noqa: N802
        return self._peer()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        try:
            message = fmt % args
        except Exception:  # pylint: disable=broad-except
            message = fmt
        LOG.debug("%s - %s", self._peer(), message)

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _query(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.path).query or "", keep_blank_values=True)

    def _site(self, query: Dict[str, List[str]]) -> str:
        """Resolve the site filter to a known backend, or to the edge totals."""

        requested = (query.get("site", [""])[0] or "").strip()
        if not requested or requested.lower() == "all":
            return ""
        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        known = {entry["proxy"] for entry in database.sites()}
        # An unknown name falls back to the edge totals rather than reaching a
        # query: the parameter selects from what exists, it does not describe it.
        return requested if requested in known else ""

    def do_POST(self) -> None:  # noqa: N802
        """The one thing this daemon is told rather than asked.

        An uplink's name is the operator's, not something that can be
        derived: HAProxy knows a server as srv1, and which cable that is
        only a person knows. Kept in the collector's own state table, beside
        the rollup watermark, because it belongs to the same database as the
        numbers it labels.
        """

        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        if urlparse(self.path).path == "/api/v1/metrics/monitors":
            self._set_monitors()
            return
        if urlparse(self.path).path != "/api/v1/metrics/channel-labels":
            self._send_json(404, {"ok": False, "error": "unknown path"})
            return
        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
            if length <= 0 or length > 65536:
                raise ValueError("invalid Content-Length")
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            labels = payload.get("labels")
            if not isinstance(labels, dict):
                raise ValueError("labels must be an object")
            if len(labels) > 64:
                raise ValueError("at most 64 labels")
            cleaned = {}
            for host, label in labels.items():
                key = str(host).strip()
                text = str(label or "").strip()[:60]
                if not key or len(key) > 255:
                    raise ValueError("a host name is missing or too long")
                if text:
                    cleaned[key] = text

            # Absent means "leave it as it is": the page sends both together,
            # but an older one sending only labels must not empty the list.
            hidden_raw = payload.get("hidden")
            if hidden_raw is None:
                hidden = json.loads(
                    database.get_state(CHANNEL_HIDDEN_KEY, "[]") or "[]"
                )
            elif isinstance(hidden_raw, list):
                if len(hidden_raw) > 64:
                    raise ValueError("at most 64 hidden channels")
                hidden = sorted({
                    str(host).strip() for host in hidden_raw
                    if str(host).strip() and len(str(host).strip()) <= 255
                })
            else:
                raise ValueError("hidden must be a list")
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        try:
            database.set_state(CHANNEL_LABELS_KEY, json.dumps(cleaned))
            database.set_state(CHANNEL_HIDDEN_KEY, json.dumps(hidden))
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        self._send_json(200, {"ok": True, "labels": cleaned, "hidden": hidden})

    def _set_monitors(self) -> None:
        """Which monitors run: {"monitors": {"machine": false, ...}}.

        Only the names given change; an unknown name or a value that is not
        true or false is refused, so a typo cannot quietly switch nothing.
        """

        collector: Collector = self.server.collector  # type: ignore[attr-defined]
        try:
            length = int((self.headers.get("Content-Length") or "0").strip() or "0")
            if length <= 0 or length > 4096:
                raise ValueError("invalid Content-Length")
            payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            changes = payload.get("monitors") if isinstance(payload, dict) else None
            if not isinstance(changes, dict) or not changes:
                raise ValueError("monitors must be a non-empty object")
            for name, value in changes.items():
                if name not in MONITOR_DEFAULTS:
                    raise ValueError(f"unknown monitor: {str(name)[:40]}")
                if not isinstance(value, bool):
                    raise ValueError(f"{name} must be true or false")
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        try:
            monitors = collector.set_monitors(changes)
        except Exception as exc:  # pylint: disable=broad-except
            self._send_json(500, {"ok": False, "error": str(exc)})
            return
        self._send_json(200, {"ok": True, "monitors": monitors})

    def do_GET(self) -> None:  # noqa: N802
        collector: Collector = self.server.collector  # type: ignore[attr-defined]
        database: MetricsDatabase = self.server.database  # type: ignore[attr-defined]
        path = urlparse(self.path).path

        if path == "/api/v1/metrics/sites":
            try:
                self._send_json(200, {"ok": True, "sites": database.sites()})
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/metrics/series":
            query = self._query()
            chart = (query.get("chart", [""])[0] or "").strip().lower()
            if chart not in CHART_SERIES:
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "error": "unknown chart",
                        "available": sorted(CHART_SERIES),
                    },
                )
                return
            range_key, since, until = resolve_window(query)
            wanted = (query.get("components", ["1"])[0] or "1").strip().lower()
            try:
                payload = database.series(
                    chart=chart,
                    site=self._site(query),
                    since=since,
                    until=until,
                    components=wanted not in ("0", "false", "no"),
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update({"ok": True, "range": range_key, "until": until})
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/servers":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.server_totals(
                    since=since, until=until
                )
                payload["labels"] = json.loads(
                    database.get_state(CHANNEL_LABELS_KEY, "{}") or "{}"
                )
                payload["hidden"] = json.loads(
                    database.get_state(CHANNEL_HIDDEN_KEY, "[]") or "[]"
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update({"ok": True, "range": range_key,
                            "since": since, "until": until})
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/backends":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.backend_totals(since=since, until=until)
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update({"ok": True, "range": range_key,
                            "since": since, "until": until})
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/states":
            query = self._query()
            range_key, since, until = resolve_window(query)
            try:
                payload = database.state_timeline(
                    site=self._site(query),
                    since=since,
                    until=until,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            payload.update(
                {
                    "ok": True,
                    "range": range_key,
                    "since": since,
                    "until": until,
                }
            )
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/summary":
            query = self._query()
            range_key, since, until = resolve_window(query)
            site = self._site(query)
            # The window decides the end, not the clock: an explicit period
            # that silently snapped back to "now" would report the wrong
            # thing while looking right.
            range_seconds = max(1, until - since)
            try:
                totals = database.totals(
                    site=site, since=since, until=until
                )
                payload = {
                    "ok": True,
                    "ts": until,
                    "range": range_key,
                    "range_seconds": range_seconds,
                    "since": since,
                    "until": until,
                    "site": site,
                    "totals": totals,
                    "requests_per_second": round(
                        totals["requests"] / range_seconds, 3
                    ),
                    "connections": database.latest_gauges(site=site, until=until),
                    # Deliberately not scoped by site: one machine's load is
                    # not divisible among the sites it serves.
                    "load": database.host_load(since=since, until=until),
                    "health": database.backend_health(),
                    "collector": collector.health(),
                    "storage": collector.storage.report(until),
                    "monitors": dict(collector.monitors),
                    "sensors": collector.sensors(),
                    # None until asked: the page then shows the charts.
                    "log_digests": {"available": collector.digests_available},
                }
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/monitors":
            self._send_json(200, {"ok": True, "monitors": dict(collector.monitors)})
            return

        if path == "/api/v1/metrics/health":
            try:
                payload = {
                    "ok": True,
                    "ts": _utc_now(),
                    "collector": collector.health(),
                    "database": database.stats(),
                }
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send_json(200, payload)
            return

        if path == "/api/v1/metrics/storage":
            try:
                now = _utc_now()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "ts": now,
                        "path": str(database.path),
                        "storage": collector.storage.report(now),
                    },
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(exc)})
            return

        self._send_json(404, {"ok": False, "error": "not found"})


class MetricsServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: str,
        handler_cls: type[BaseHTTPRequestHandler],
        collector: Collector,
        database: MetricsDatabase,
    ) -> None:
        super().__init__(socket_path, handler_cls)
        self.collector = collector
        self.database = database


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

    config = load_config(CONFIG_PATH)
    if not config.enabled:
        # Staying alive as an idle process keeps the unit's health reporting
        # honest: "enabled: false" is a configuration state, not a crash.
        LOG.info("Monitoring is disabled in %s; idling", CONFIG_PATH)
        stop = threading.Event()

        def _idle_stop(_signum: int, _frame: Any) -> None:
            stop.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, _idle_stop)
        with contextlib.suppress(KeyboardInterrupt):
            stop.wait()
        return

    database = MetricsDatabase(DATABASE_PATH)
    guard = StorageGuard(config, database, alerts=_alert_client())
    collector = Collector(config, database, guard)

    # Decide before the first sample is taken: a host that is already out of
    # disk must not gain a new writer just because the daemon restarted.
    initial = guard.enforce(_utc_now())
    status: StorageStatus = initial["status"]

    LOG.info(
        "Starting easy-ha-proxy-metricsd: socket=%s db=%s interval=%ss "
        "limit=%dMiB reserve=%dMiB storage=%s",
        SOCKET_PATH,
        DATABASE_PATH,
        config.poll_interval_seconds,
        status.max_database_bytes // MIB,
        status.reserved_free_bytes // MIB,
        status.state,
    )

    collector.start()

    with contextlib.suppress(OSError):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

    server = MetricsServer(SOCKET_PATH, MetricsHandler, collector, database)
    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("Failed to set socket permissions: %s", exc)

    shutdown_event = threading.Event()
    received_signal: List[int] = []

    def _shutdown_watcher() -> None:
        shutdown_event.wait()
        if received_signal:
            LOG.info("Received signal %s; shutting down", received_signal[0])
        server.shutdown()

    threading.Thread(target=_shutdown_watcher, daemon=True).start()

    def _handle_signal(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _handle_signal)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        collector.stop()
        with contextlib.suppress(Exception):
            server.server_close()
        database.close()
        with contextlib.suppress(OSError):
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
