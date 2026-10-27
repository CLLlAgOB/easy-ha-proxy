"""Least-privilege client for the host software-update broker."""

from __future__ import annotations

import os
from typing import Any

from .daemon_transport import json_line_request


UPDATED_SOCKET_PATH = os.environ.get(
    "EASY_HA_PROXY_UPDATED_SOCKET",
    "/run/easy-ha-proxy/easy-ha-proxy-updated.sock",
).strip()
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class UpdatedError(RuntimeError):
    """The local software-update broker could not process a request."""


def updated_request(payload: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
    """Send one bounded JSON request to the fixed Unix socket."""

    return json_line_request(
        UPDATED_SOCKET_PATH,
        payload,
        service="software-update",
        error=UpdatedError,
        timeout=timeout,
        max_request=MAX_REQUEST_BYTES,
        max_response=MAX_RESPONSE_BYTES,
    )
