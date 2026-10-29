# -*- coding: utf-8 -*-
"""Client of the root service easy-ha-proxy-guardd over a Unix socket.

Reads the engine's state and changes its settings (the mode, ban durations,
signatures, traps, the request log). The daemon validates every change again.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .daemon_transport import UnixHttp


GUARDD_SOCKET_PATH = os.environ.get(
    "GUARDD_SOCKET_PATH", "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock"
).strip()
# The daemon requires this token for every call that changes something.
GUARDD_TOKEN = os.environ.get("GUARDD_TOKEN", "").strip()

DEFAULT_TIMEOUT = 15


class GuarddUnavailable(RuntimeError):
    """The engine does not answer: the page degrades rather than fails."""


def _guardd() -> UnixHttp:
    return UnixHttp("guardd", GUARDD_SOCKET_PATH, GuarddUnavailable,
                    token_header="X-Guardd-Token", token=GUARDD_TOKEN)


def _get_json(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    return _guardd().get(path, params=params, timeout=timeout)


def _change(path: str, body: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
    """A setting the operator typed: the daemon may refuse it with a reason.

    A 400 is the operator's mistake, not an outage, and comes back as
    ValueError carrying the daemon's words.
    """

    return _guardd().post(path, body, timeout=timeout, with_token=True, rejected_status=400)


def guardd_ban_schedule() -> Dict[str, Any]:
    """When the engine intends each adaptive ban to end.

    Short timeout on purpose: the dashboard's ban list asks on every refresh,
    and an engine that is down must cost that list nothing more than falling
    back to the stick table's own expiry.
    """

    return _get_json("/api/v1/guard/bans/schedule", timeout=2)


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
    """Store the operator's own rules and apply them without a restart."""

    return _change("/api/v1/guard/signatures", overrides, timeout=30)


def guardd_signature_candidates() -> Dict[str, Any]:
    """Paths refused to many addresses that no rule matches yet."""

    return _get_json("/api/v1/guard/signatures/candidates")


def guardd_dismiss_candidate(path: str, restore: bool = False) -> Dict[str, Any]:
    """Hide a suggested signature for good, or bring a hidden one back."""

    return _change("/api/v1/guard/signatures/candidates/dismiss",
                   {"path": path, "restore": bool(restore)})


def guardd_traps() -> Dict[str, Any]:
    """Trap names, and the names that get traffic without serving a site."""

    return _get_json("/api/v1/guard/traps")


def guardd_set_traps(hosts: Any) -> Dict[str, Any]:
    """Replace the trap names."""

    return _change("/api/v1/guard/traps", {"hosts": hosts})


def guardd_set_ban_durations(durations: Any) -> Dict[str, Any]:
    """Replace the escalating ban ladder."""

    return _change("/api/v1/guard/ban-durations", {"durations": durations})


def guardd_forget_ban(ip: str) -> Dict[str, Any]:
    """Tell the engine to drop its hold on an address the operator unbanned."""

    return _guardd().post("/api/v1/guard/ban/forget", {"ip": (ip or "").strip()},
                          timeout=15, with_token=True)


def guardd_set_mode(mode: str) -> Dict[str, Any]:
    """Switch between observing and enforcing.

    Changing this changes what happens to traffic.
    """

    return _guardd().post("/api/v1/guard/mode", {"mode": mode}, timeout=30, with_token=True)


def _request_log_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read a request-log endpoint.

    The daemon answers 404 with a body when the log is switched off, which is
    a different thing from the daemon being unreachable. Raising on status
    here would turn "the feature is off" into "guardd is down" on the page.
    """
    return _guardd().get(path, params=params, timeout=DEFAULT_TIMEOUT,
                         check_status=False, require_object=True)


def guardd_live(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The live activity snapshot, answered from guardd's memory."""
    return _request_log_get("/api/v1/guard/live", params=params)


def guardd_attackers() -> Dict[str, Any]:
    """Top addresses answered 400 and 451 over the last day, from memory."""
    return _request_log_get("/api/v1/guard/attackers")


def guardd_requests(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Search the bounded request log."""
    return _request_log_get("/api/v1/guard/requests", params=params)


def guardd_requests_summary(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What a search of the request log finds, over time and most common."""
    return _request_log_get("/api/v1/guard/requests/summary", params=params)


def guardd_set_request_log(enabled: bool) -> Dict[str, Any]:
    """Start or stop recording requests.

    This one decides whether the gateway keeps a record of what every visitor
    asked for, so it carries the token like every other change.
    """
    return _guardd().post("/api/v1/guard/requests/enabled", {"enabled": bool(enabled)},
                          timeout=30, with_token=True, check_status=False,
                          require_object=True)


def guardd_requests_status() -> Dict[str, Any]:
    return _request_log_get("/api/v1/guard/requests/status")
