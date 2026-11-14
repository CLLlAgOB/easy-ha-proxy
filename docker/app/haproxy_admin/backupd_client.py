"""Least-privilege client for the host full-backup daemon."""

from __future__ import annotations

import os
from typing import Any

from .daemon_transport import json_line_request


BACKUPD_SOCKET_PATH = os.environ.get(
    "EASY_HA_PROXY_BACKUPD_SOCKET",
    "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock",
).strip()
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class BackupdError(RuntimeError):
    """The local backup daemon could not process a request."""


def backupd_request(payload: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
    """Send one bounded JSON request without ever logging its secret fields."""

    return json_line_request(
        BACKUPD_SOCKET_PATH,
        payload,
        service="full-backup",
        error=BackupdError,
        timeout=timeout,
        max_request=MAX_REQUEST_BYTES,
        max_response=MAX_RESPONSE_BYTES,
    )
