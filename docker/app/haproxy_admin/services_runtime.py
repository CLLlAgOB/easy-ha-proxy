# -*- coding: utf-8 -*-
"""Runtime-операции над серверами HAProxy.

Временные операции: Ready / Drain / Maintenance и вес. Ничего не пишется в
конфигурацию, поэтому любой reload или перезапуск HAProxy возвращает серверы
к тому, что записано в haproxy.cfg — в конфиге нет `server-state-file`.

Имя backend и сервера никогда не приходит из формы как текст: оно сверяется со
списком того, что HAProxy сейчас действительно отдаёт в `show stat`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .services import (
    EXCLUDE_EXACT,
    EXCLUDE_PREFIX,
    HAPROXY_CFG,
    SOCKET,
    _load_display_map_from_cfg,
    _parse_show_stat,
    _show_stat,
)
from .utils import haproxy_runtime_command

LOG = logging.getLogger("haproxy-admin")

STATES: Tuple[str, ...] = ("ready", "drain", "maint")
MIN_WEIGHT = 0
MAX_WEIGHT = 256

# Backends that keep the gateway reachable and authenticated. Draining the one
# serving this very page, or the one Authelia answers on, would lock the
# operator out of the interface they are clicking in.
PROTECTED_BACKENDS: frozenset[str] = frozenset(
    set(EXCLUDE_EXACT)
    | {"authelia_backend", "be_access_granted", "be_maintenance"}
)


class RuntimeError_(RuntimeError):
    """Ожидаемая ошибка, безопасная для показа в интерфейсе."""


def _is_operable(pxname: str) -> bool:
    if not pxname or pxname in PROTECTED_BACKENDS:
        return False
    return not any(pxname.startswith(prefix) for prefix in EXCLUDE_PREFIX)


def _admin_state(status: str) -> str:
    """Свести status из show stat к состоянию, которым мы управляем."""

    value = (status or "").strip().upper()
    if value.startswith("MAINT"):
        return "maint"
    if value.startswith("DRAIN"):
        return "drain"
    return "ready"


def list_backends() -> List[Dict[str, Any]]:
    """Backends и их серверы в том виде, в каком их сейчас видит HAProxy."""

    rows = _parse_show_stat(_show_stat(SOCKET))
    names = _load_display_map_from_cfg(HAPROXY_CFG)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        pxname = (row.get("pxname") or "").strip()
        svname = (row.get("svname") or "").strip()
        if svname in ("FRONTEND", "BACKEND") or not _is_operable(pxname):
            continue
        status = (row.get("status") or "").strip()
        grouped.setdefault(pxname, []).append(
            {
                "server": svname,
                "address": (row.get("addr") or "").strip(),
                "status": status,
                "admin_state": _admin_state(status),
                "weight": _to_int(row.get("weight")),
                "sessions": _to_int(row.get("scur")),
                "check_status": (row.get("check_status") or "").strip(),
            }
        )

    backends: List[Dict[str, Any]] = []
    for pxname, servers in sorted(grouped.items()):
        display = names.get(pxname) or (
            pxname[3:] if pxname.startswith("be_") else pxname
        ).replace("_", ".")
        backends.append(
            {
                "backend": pxname,
                "label": display,
                "servers": sorted(servers, key=lambda item: item["server"]),
            }
        )
    return backends


def _to_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _resolve(backend: Any, server: Any) -> Tuple[str, str]:
    """Сверить пару backend/server с тем, что реально существует."""

    wanted_backend = str(backend or "").strip()
    wanted_server = str(server or "").strip()
    for entry in list_backends():
        if entry["backend"] != wanted_backend:
            continue
        for item in entry["servers"]:
            if item["server"] == wanted_server:
                return entry["backend"], item["server"]
    raise RuntimeError_("unknown backend or server")


def _run(command: str) -> str:
    reply = (haproxy_runtime_command(command, SOCKET, timeout=5) or "").strip()
    # HAProxy answers with an empty line on success and a sentence otherwise.
    if reply:
        raise RuntimeError_(reply.splitlines()[0][:200])
    return reply


def set_state(backend: Any, server: Any, state: Any) -> Dict[str, Any]:
    wanted = str(state or "").strip().lower()
    if wanted not in STATES:
        raise RuntimeError_("state must be one of " + ", ".join(STATES))
    name, srv = _resolve(backend, server)
    _run(f"set server {name}/{srv} state {wanted}")
    LOG.warning("Runtime state of %s/%s set to %s", name, srv, wanted)
    return {"ok": True, "backend": name, "server": srv, "state": wanted}


def set_weight(backend: Any, server: Any, weight: Any) -> Dict[str, Any]:
    try:
        value = int(str(weight).strip())
    except (TypeError, ValueError) as exc:
        raise RuntimeError_("weight must be a whole number") from exc
    if not MIN_WEIGHT <= value <= MAX_WEIGHT:
        raise RuntimeError_(
            f"weight must be between {MIN_WEIGHT} and {MAX_WEIGHT}"
        )
    name, srv = _resolve(backend, server)
    _run(f"set server {name}/{srv} weight {value}")
    LOG.warning("Runtime weight of %s/%s set to %d", name, srv, value)
    return {"ok": True, "backend": name, "server": srv, "weight": value}
