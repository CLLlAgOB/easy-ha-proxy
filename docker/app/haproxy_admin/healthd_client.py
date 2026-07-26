# -*- coding: utf-8 -*-
"""
Клиент для общения с root-сервисом haproxy-healthd через Unix-socket.

Использует requests-unixsocket и схему http+unix://.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

try:
    import requests_unixsocket  # type: ignore
except Exception:  # pylint: disable=broad-except
    requests_unixsocket = None  # type: ignore


LOG = logging.getLogger("haproxy-admin")

HEALTHD_SOCKET_PATH = os.environ.get(
    "HEALTHD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-healthd.sock"
).strip()
HEALTHD_TOKEN = os.environ.get("HEALTHD_TOKEN", "").strip()


def _headers() -> Dict[str, str]:
    """Заголовки для запросов к healthd.

    Токен используется только для управляющих действий, но передача его
    на безопасные GET-запросы не вредит и упрощает логику.
    """
    h: Dict[str, str] = {}
    if HEALTHD_TOKEN:
        h["X-Healthd-Token"] = HEALTHD_TOKEN
    return h


def _session() -> requests.Session:
    if requests_unixsocket is None:
        raise RuntimeError("requests-unixsocket is not installed")
    return requests_unixsocket.Session()  # type: ignore[return-value]


def _base_url() -> str:
    return "http+unix://" + quote(HEALTHD_SOCKET_PATH, safe="")


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
    accepted_error_statuses: tuple[int, ...] = (),
) -> Dict[str, Any]:
    url = _base_url() + path
    s = _session()
    resp = s.get(url, params=params or {}, timeout=timeout, headers=_headers())
    if resp.status_code not in accepted_error_statuses:
        resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        return {"ok": False, "error": "non-json response", "text": resp.text[:2000]}


def healthd_status(refresh: bool = False) -> Dict[str, Any]:
    params = {"refresh": "1"} if refresh else {}
    return _get_json("/api/v1/health/status", params=params, timeout=12)


def healthd_events(limit: int = 50) -> Dict[str, Any]:
    return _get_json("/api/v1/health/events", params={"limit": str(limit)}, timeout=10)


def healthd_logs_systemd(unit: str, tail: int = 200, since: int = 3600) -> Dict[str, Any]:
    return _get_json(
        "/api/v1/health/logs/systemd",
        params={"unit": unit, "tail": str(tail), "since": str(since)},
        timeout=20,
    )


def healthd_recent_systemd(
    limit: int = 50,
    units: Optional[List[str]] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": str(limit)}
    if units is not None:
        clean_units = [str(unit).strip() for unit in units if str(unit).strip()]
        if clean_units:
            # requests serializes list values as repeated query parameters.
            params["unit"] = clean_units
        else:
            # Preserve the distinction between omitted and explicitly empty.
            params["units"] = ""
    return _get_json(
        "/api/v1/health/recent-systemd",
        params=params,
        timeout=20,
        accepted_error_statuses=(400,),
    )


def healthd_logs_docker(container: str, tail: int = 200, since: int = 3600) -> Dict[str, Any]:
    return _get_json(
        "/api/v1/health/logs/docker",
        params={"container": container, "tail": str(tail), "since": str(since)},
        timeout=20,
    )


def _post_json(path: str, json_payload: Dict[str, Any], timeout: int = 20) -> Dict[str, Any]:
    url = _base_url() + path
    s = _session()
    resp = s.post(url, json=json_payload, timeout=timeout, headers=_headers())
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        return {"ok": False, "error": "non-json response", "text": resp.text[:2000]}


def healthd_capabilities() -> Dict[str, Any]:
    return _get_json("/api/v1/control/capabilities", timeout=10)


def healthd_control(kind: str, name: str, action: str) -> Dict[str, Any]:
    return _post_json(
        "/api/v1/control",
        json_payload={"kind": kind, "name": name, "action": action},
        timeout=30,
    )
