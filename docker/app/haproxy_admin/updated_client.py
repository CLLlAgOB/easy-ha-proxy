"""Least-privilege client for the host software-update broker."""

from __future__ import annotations

import json
import os
import socket
from typing import Any


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

    if not UPDATED_SOCKET_PATH:
        raise UpdatedError("the software-update service socket is not configured")
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_REQUEST_BYTES:
        raise UpdatedError("the software-update request is too large")

    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(UPDATED_SOCKET_PATH)
            connection.sendall(encoded)
            while b"\n" not in response:
                chunk = connection.recv(64 * 1024)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_RESPONSE_BYTES:
                    raise UpdatedError(
                        "the software-update service response is too large"
                    )
    except UpdatedError:
        raise
    except (OSError, socket.timeout) as exc:
        raise UpdatedError(
            f"the software-update service is unavailable: {exc}"
        ) from exc

    raw = bytes(response).split(b"\n", 1)[0]
    if not raw:
        raise UpdatedError("the software-update service returned an empty response")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdatedError("the software-update service returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise UpdatedError("the software-update service returned an invalid response")
    return result
