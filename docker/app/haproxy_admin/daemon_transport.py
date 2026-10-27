# -*- coding: utf-8 -*-
"""How the web application reaches the host daemons over their sockets.

Two transports, each written once:

* a JSON line over a Unix stream socket -- one request line, one answer
  line, both bounded (the backup daemon and the update broker);
* JSON over HTTP on a Unix socket, through requests-unixsocket (the alert,
  metrics and adaptive protection daemons).

The clients keep their own error classes on top, and the wording here names
each service the way its client always has, so the catalogue keeps
translating the messages. Nothing here logs: a request may carry a
passphrase, and an error never repeats the request.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict, Optional, Type
from urllib.parse import quote

try:
    import requests_unixsocket  # type: ignore
except Exception:  # pylint: disable=broad-except
    requests_unixsocket = None  # type: ignore

READ_CHUNK_BYTES = 64 * 1024


def json_line_request(
    socket_path: str,
    payload: Dict[str, Any],
    *,
    service: str,
    error: Type[Exception],
    timeout: float,
    max_request: int,
    max_response: int,
) -> Dict[str, Any]:
    """Send one compact JSON line and read one JSON object back.

    Every failure is raised as `error`, worded with `service` ("the
    full-backup service is unavailable: ..."), never with the request.
    """

    if not socket_path:
        raise error(f"the {service} service socket is not configured")
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > max_request:
        raise error(f"the {service} request is too large")

    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(socket_path)
            connection.sendall(encoded)
            while b"\n" not in response:
                chunk = connection.recv(READ_CHUNK_BYTES)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > max_response:
                    raise error(f"the {service} service response is too large")
    except error:
        raise
    except (OSError, socket.timeout) as exc:
        raise error(f"the {service} service is unavailable: {exc}") from exc

    raw = bytes(response).split(b"\n", 1)[0]
    if not raw:
        raise error(f"the {service} service returned an empty response")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error(f"the {service} service returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise error(f"the {service} service returned an invalid response")
    return result


class UnixHttp:
    """JSON over HTTP on one daemon's Unix socket.

    `unavailable` is raised whenever the daemon cannot give a usable answer; the
    page treats it as "the daemon is unavailable" and degrades. A setting the
    daemon refuses is a different thing -- the operator's typo, with the
    daemon's reason -- and comes back as ValueError when the caller names the
    status that carries it.
    """

    def __init__(
        self,
        service: str,
        socket_path: str,
        unavailable: Type[Exception],
        *,
        token_header: str = "",
        token: str = "",
    ) -> None:
        self.service = service
        self.socket_path = socket_path
        self.unavailable = unavailable
        self.token_header = token_header
        self.token = token

    def url(self, path: str) -> str:
        return "http+unix://" + quote(self.socket_path, safe="") + path

    def get(self, path: str, *, params: Optional[Dict[str, Any]] = None, timeout: float,
            check_status: bool = True, require_object: bool = False) -> Any:
        return self._request("GET", path, params=params, timeout=timeout,
                             check_status=check_status, require_object=require_object)

    def post(self, path: str, body: Any, *, timeout: float, with_token: bool = False,
             check_status: bool = True, rejected_status: Optional[int] = None,
             require_object: bool = False) -> Any:
        return self._request("POST", path, body=body, timeout=timeout, with_token=with_token,
                             check_status=check_status, rejected_status=rejected_status,
                             require_object=require_object)

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                 body: Any = None, timeout: float, with_token: bool = False,
                 check_status: bool = True, rejected_status: Optional[int] = None,
                 require_object: bool = False) -> Any:
        if requests_unixsocket is None:
            raise self.unavailable("requests-unixsocket is not installed")
        headers = {}
        if with_token and self.token_header and self.token:
            headers[self.token_header] = self.token
        try:
            session = requests_unixsocket.Session()
            if method == "GET":
                response = session.get(self.url(path), params=params or {}, timeout=timeout,
                                       headers=headers)
            else:
                response = session.post(self.url(path), json=body, timeout=timeout,
                                        headers=headers)
        except Exception as exc:  # pylint: disable=broad-except
            raise self.unavailable(str(exc)) from exc

        if rejected_status is not None and response.status_code == rejected_status:
            try:
                answer = response.json()
            except ValueError:
                answer = None
            reason = answer.get("error") if isinstance(answer, dict) else None
            raise ValueError(reason or "rejected")
        if check_status:
            try:
                response.raise_for_status()
            except Exception as exc:  # pylint: disable=broad-except
                raise self.unavailable(str(exc)) from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise self.unavailable(f"{self.service} returned a non-JSON response") from exc
        if require_object and not isinstance(data, dict):
            raise self.unavailable(f"{self.service} returned an unexpected payload")
        return data
