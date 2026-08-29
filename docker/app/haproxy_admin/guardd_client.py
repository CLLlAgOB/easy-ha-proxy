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


def guardd_signatures() -> Dict[str, Any]:
    """The detection rules as the running daemon has them loaded."""

    return _get_json("/api/v1/guard/signatures")


def guardd_set_signatures(overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Store the operator's own rules and apply them without a restart.

    Mutating, so it carries the shared token like the mode switch does.
    """

    url = (
        "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="")
        + "/api/v1/guard/signatures"
    )
    try:
        response = _session().post(
            url,
            json=overrides,
            timeout=30,
            headers={"X-Guardd-Token": GUARDD_TOKEN} if GUARDD_TOKEN else {},
        )
        if response.status_code == 400:
            # The operator mistyped a rule. That is an answer, not an outage.
            raise ValueError(
                (response.json() or {}).get("error") or "rejected"
            )
        response.raise_for_status()
        return response.json()
    except (GuarddUnavailable, ValueError):
        raise
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc


def guardd_set_ban_durations(durations: Any) -> Dict[str, Any]:
    """Replace the escalating ban ladder.

    Mutating, so it carries the shared token like the mode switch does.
    """

    url = (
        "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="")
        + "/api/v1/guard/ban-durations"
    )
    try:
        response = _session().post(
            url,
            json={"durations": durations},
            timeout=15,
            headers={"X-Guardd-Token": GUARDD_TOKEN} if GUARDD_TOKEN else {},
        )
        if response.status_code == 400:
            # A rejected ladder is the operator's typo, not an outage.
            raise ValueError((response.json() or {}).get("error") or "rejected")
        response.raise_for_status()
        return response.json()
    except (GuarddUnavailable, ValueError):
        raise
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc


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


def _request_log_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read a request-log endpoint.

    The daemon answers 404 with a body when the log is switched off, which is
    a different thing from the daemon being unreachable. Raising on status
    here would turn "the feature is off" into "guardd is down" on the page.
    """
    url = "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="") + path
    try:
        response = _session().get(url, params=params or {}, timeout=DEFAULT_TIMEOUT)
        data = response.json()
    except GuarddUnavailable:
        raise
    except ValueError as exc:
        raise GuarddUnavailable("guardd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc
    if not isinstance(data, dict):
        raise GuarddUnavailable("guardd returned an unexpected payload")
    return data


def guardd_requests(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Search the bounded request log."""
    return _request_log_get("/api/v1/guard/requests", params=params)


def guardd_set_request_log(enabled: bool) -> Dict[str, Any]:
    """Start or stop recording requests.

    Carries the shared token like the mode switch does: this one decides
    whether the gateway keeps a record of what every visitor asked for.
    """
    url = (
        "http+unix://" + quote(GUARDD_SOCKET_PATH, safe="")
        + "/api/v1/guard/requests/enabled"
    )
    try:
        response = _session().post(
            url,
            json={"enabled": bool(enabled)},
            timeout=30,
            headers={"X-Guardd-Token": GUARDD_TOKEN} if GUARDD_TOKEN else {},
        )
        data = response.json()
    except ValueError as exc:
        raise GuarddUnavailable("guardd returned a non-JSON response") from exc
    except Exception as exc:  # pylint: disable=broad-except
        raise GuarddUnavailable(str(exc)) from exc
    if not isinstance(data, dict):
        raise GuarddUnavailable("guardd returned an unexpected payload")
    return data


def guardd_requests_status() -> Dict[str, Any]:
    return _request_log_get("/api/v1/guard/requests/status")
