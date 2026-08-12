# -*- coding: utf-8 -*-
"""Reporting side of the alert engine, shared by the helper daemons.

A producer says what it currently sees and nothing more: whether to notify,
how long to wait first, and how often to repeat are decisions that belong to
easy-ha-proxy-alertd, where they apply to every condition consistently.

Reporting must never be able to disturb the thing being reported on. Every
call here is bounded, swallows its own errors, and answers False rather than
raising, so a stopped alert daemon costs a notification and never a metrics
sample, a ban, or a reload.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from typing import Any, Dict, Optional

LOG = logging.getLogger("easy-ha-proxy-alert-client")

DEFAULT_SOCKET_PATH = "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 64 * 1024

# A level condition is reported on every cycle of its producer, which for
# metricsd is every ten seconds. Re-sending an unchanged observation that
# often is pointless work on both sides, so an unchanged one is resent only
# this often — comfortably inside the engine's stale_after window.
RESEND_UNCHANGED_SECONDS = 120


class AlertClient:
    """Submits observations to alertd over its unix socket."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        token: Optional[str] = None,
        *,
        source: str = "",
    ) -> None:
        self.socket_path = socket_path or os.environ.get(
            "ALERTD_SOCKET_PATH", DEFAULT_SOCKET_PATH
        )
        self.token = (
            token if token is not None else os.environ.get("ALERTD_TOKEN", "")
        ).strip()
        self.source = source
        self._lock = threading.Lock()
        self._last: Dict[str, tuple] = {}
        self._warned = False

    @property
    def configured(self) -> bool:
        return bool(self.token and self.socket_path)

    def observe(
        self,
        rule: str,
        subject: str,
        *,
        active: Optional[bool] = None,
        severity: str = "",
        summary: str = "",
        detail: str = "",
        trigger_delay: Optional[int] = None,
        recipient: str = "",
    ) -> bool:
        """Report one observation. Returns whether the engine accepted it.

        ``trigger_delay`` and ``recipient`` carry policy that belongs to the
        object rather than to the rule — a site's own alert_after and
        alert_email — and are passed straight through to the engine.
        """
        if not self.configured:
            return False

        key = f"{rule}\x00{subject}"
        signature = (active, severity, summary, detail, trigger_delay, recipient)
        now = time.monotonic()
        with self._lock:
            previous = self._last.get(key)
            if (
                previous is not None
                and previous[0] == signature
                and now - previous[1] < RESEND_UNCHANGED_SECONDS
            ):
                return True
            self._last[key] = (signature, now)
            # The map is keyed by rule and subject, both of which are bounded
            # by the producer, but a runaway subject must not grow it forever.
            if len(self._last) > 2000:
                self._last.clear()

        payload: Dict[str, Any] = {"rule": rule, "subject": subject}
        if active is not None:
            payload["active"] = bool(active)
        if severity:
            payload["severity"] = severity
        if summary:
            payload["summary"] = summary
        if detail:
            payload["detail"] = detail
        if trigger_delay is not None:
            payload["trigger_delay"] = int(trigger_delay)
        if recipient:
            payload["recipient"] = recipient
        return self._post("/api/v1/alerts/notify", payload)

    def clear(
        self, rule: str, subject: str, *, summary: str = "", recipient: str = ""
    ) -> bool:
        """Report that a level condition is no longer true."""
        return self.observe(
            rule, subject, active=False, summary=summary, recipient=recipient
        )

    def _post(self, path: str, payload: Dict[str, Any]) -> bool:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = (
            f"POST {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            f"X-Alertd-Token: {self.token}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8") + body

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(CONNECT_TIMEOUT_SECONDS)
                client.connect(self.socket_path)
                client.sendall(request)
                client.settimeout(READ_TIMEOUT_SECONDS)
                chunks = []
                received = 0
                while received < MAX_RESPONSE_BYTES:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    received += len(chunk)
        except OSError as exc:
            # One warning per outage rather than one per cycle: the alert
            # daemon being down must not itself flood the journal.
            if not self._warned:
                self._warned = True
                LOG.warning(
                    "alertd unreachable at %s (%s); notifications are paused",
                    self.socket_path,
                    exc,
                )
            return False
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("alert submission failed: %s", exc)
            return False

        self._warned = False
        head = b"".join(chunks).split(b"\r\n", 1)[0]
        return b" 200 " in head
