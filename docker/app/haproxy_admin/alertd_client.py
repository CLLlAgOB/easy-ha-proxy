# -*- coding: utf-8 -*-
"""Client of the root service easy-ha-proxy-alertd over a Unix socket.

The daemon never returns a whole webhook URL or the value of the secret
header: it hands them out already shortened. Nothing is decoded or restored
here -- the page sees exactly what the daemon gave.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .daemon_transport import UnixHttp


ALERTD_SOCKET_PATH = os.environ.get(
    "ALERTD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-alertd.sock"
).strip()
# Changing the rules silences alerts, so the daemon requires this token.
ALERTD_TOKEN = os.environ.get("ALERTD_TOKEN", "").strip()

DEFAULT_TIMEOUT = 15
TEST_TIMEOUT = 60


class AlertdUnavailable(RuntimeError):
    """The engine does not answer: the page degrades rather than fails."""


def _alertd() -> UnixHttp:
    return UnixHttp("alertd", ALERTD_SOCKET_PATH, AlertdUnavailable,
                    token_header="X-Alertd-Token", token=ALERTD_TOKEN)


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    return _alertd().get(path, params=params, timeout=timeout)


def _post_json(
    path: str,
    payload: Dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    # A rejected setting comes back as 400 with a message worth showing, so
    # the status is not raised on before the body is read.
    return _alertd().post(path, payload, timeout=timeout, with_token=True,
                          check_status=False, require_object=True)


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
