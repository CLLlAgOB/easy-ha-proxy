"""Least-privilege client for the host full-backup daemon."""

from __future__ import annotations

import json
import os
import socket
from typing import Any


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

    if not BACKUPD_SOCKET_PATH:
        raise BackupdError("the full-backup service socket is not configured")
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REQUEST_BYTES:
        raise BackupdError("the full-backup request is too large")

    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(BACKUPD_SOCKET_PATH)
            connection.sendall(encoded)
            while b"\n" not in response:
                chunk = connection.recv(64 * 1024)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_RESPONSE_BYTES:
                    raise BackupdError("the full-backup service response is too large")
    except BackupdError:
        raise
    except (OSError, socket.timeout) as exc:
        raise BackupdError(f"the full-backup service is unavailable: {exc}") from exc

    raw = bytes(response).split(b"\n", 1)[0]
    if not raw:
        raise BackupdError("the full-backup service returned an empty response")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupdError("the full-backup service returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise BackupdError("the full-backup service returned an invalid response")
    return result
