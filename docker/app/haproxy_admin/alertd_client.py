# -*- coding: utf-8 -*-
"""Клиент к root-сервису easy-ha-proxy-alertd через Unix-socket.

Демон никогда не возвращает ни URL webhook целиком, ни значение секретного
заголовка: он отдаёт их уже сокращёнными. Здесь ничего не расшифровывается и
не восстанавливается — страница видит ровно то, что отдал демон.
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

ALERTD_SOCKET_PATH = os.environ.get(
    "ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
).strip()
# Changing the rules silences alerts, so the daemon requires this token.
ALERTD_TOKEN = os.environ.get("ALERTD_TOKEN", "").strip()

DEFAULT_TIMEOUT = 15
TEST_TIMEOUT = 60


class AlertdUnavailable(RuntimeError):
    """Движок не отвечает: страница деградирует, а не падает."""


def _session() -> requests.Session:
    if requests_unixsocket is None:
        raise AlertdUnavailable("requests-unixsocket is not installed")
    return requests_unixsocket.Session()  # type: ignore[return-value]


def _url(path: str) -> str:
    return "http+unix://" + quote(ALERTD_SOCKET_PATH, safe="") + path


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    try:
        response = _session().get(_url(path), params=params or {}, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except AlertdUnavailable:
        raise
    except ValueError as exc:
        raise AlertdUnavailable("alertd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise AlertdUnavailable(str(exc)) from exc


def _post_json(
    path: str,
    payload: Dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    try:
        response = _session().post(
            _url(path),
            json=payload,
            timeout=timeout,
            headers={"X-Alertd-Token": ALERTD_TOKEN} if ALERTD_TOKEN else {},
        )
        # A rejected setting comes back as 400 with a message worth showing,
        # so the status is not raised on before the body is read.
        data = response.json()
        if not isinstance(data, dict):
            raise AlertdUnavailable("alertd returned an unexpected payload")
        return data
    except AlertdUnavailable:
        raise
    except ValueError as exc:
        raise AlertdUnavailable("alertd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise AlertdUnavailable(str(exc)) from exc


def alertd_health() -> Dict[str, Any]:
    return _get_json("/api/v1/alerts/health")


def alertd_state(limit: int = 100) -> Dict[str, Any]:
    return _get_json("/api/v1/alerts/state", params={"limit": limit})


def alertd_history(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _get_json("/api/v1/alerts/history", params=params)


def alertd_save_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    return _post_json("/api/v1/alerts/config", payload)


def alertd_send_test() -> Dict[str, Any]:
    """Deliver a test message through every configured channel.

    The webhook can take as long as its own timeout, so this call is given a
    longer budget than a settings write.
    """
    return _post_json("/api/v1/alerts/test", {}, timeout=TEST_TIMEOUT)
