# -*- coding: utf-8 -*-
"""Клиент к root-сервису easy-ha-proxy-guardd через Unix-socket.

Демон отдаёт только чтение: он ничего не банит в этом релизе, поэтому и
изменяющих вызовов здесь нет.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

try:
    import requests_unixsocket  # type: ignore
except Exception:  # pylint: disable=broad-except
    requests_unixsocket = None  # type: ignore


LOG = logging.getLogger("haproxy-admin")

GUARDD_SOCKET_PATH = os.environ.get(
    "GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock"
).strip()
# Only the mode switch is mutating, and the daemon requires this token for it.
GUARDD_TOKEN = os.environ.get("GUARDD_TOKEN", "").strip()

DEFAULT_TIMEOUT = 15


class GuarddUnavailable(RuntimeError):
    """Движок не отвечает: страница деградирует, а не падает."""


def _session() -> requests.Session:
    if requests_unixsocket is None:
        raise GuarddUnavailable("requests-unixsocket is not installed")
    return requests_unixsocket.Session()  # type: ignore[return-value]


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    url = "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="") + path
    try:
        response = _session().get(url, params=params or {}, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except GuarddUnavailable:
        raise
    except ValueError as exc:
        raise GuarddUnavailable("guardd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc


def guardd_health() -> Dict[str, Any]:
    return _get_json("/api/v1/guard/health")


def guardd_shadow(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _get_json("/api/v1/guard/shadow", params=params)


def guardd_ip(address: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {"ip": address}
    query.update(params or {})
    return _get_json("/api/v1/guard/ip", params=query)


def guardd_set_mode(mode: str) -> Dict[str, Any]:
    """Switch between observing and enforcing.

    Changing this changes what happens to traffic, so it is the one call that
    carries the shared token.
    """

    url = "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="") + "/api/v1/guard/mode"
    try:
        response = _session().post(
            url,
            json={"mode": mode},
            timeout=30,
            headers={"X-Guardd-Token": GUARDD_TOKEN} if GUARDD_TOKEN else {},
        )
        response.raise_for_status()
        return response.json()
    except GuarddUnavailable:
        raise
    except ValueError as exc:
        raise GuarddUnavailable("guardd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc
