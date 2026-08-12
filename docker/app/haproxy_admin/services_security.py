# -*- coding: utf-8 -*-
"""Сервисный слой раздела Adaptive protection.

Валидирует параметры симулятора весов и обогащает адреса страной из локальной
базы GeoIP. Демон валидирует те же значения повторно.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

from .cache import get_country_code
from .guardd_client import (
    GuarddUnavailable,
    guardd_health,
    guardd_ip,
    guardd_set_mode,
    guardd_shadow,
)

MODES: tuple[str, ...] = ("off", "monitor", "enforce")

LOG = logging.getLogger("haproxy-admin")

# Держим синхронно с DEFAULT_WEIGHTS в easy-ha-proxy-guardd.py.
EVENT_TYPES: tuple[str, ...] = (
    "SCANNER_PATH",
    "SCANNER_MULTI_CATEGORY",
    "LOW_AND_SLOW_SCANNER",
    "NOT_FOUND_ENUMERATION",
    "INVALID_HOST_ACTIVITY",
    "NOSNI_PROBING",
    "RATE_EXCEEDED",
    "ERROR_RATE_EXCEEDED",
    "LEGACY_HAPROXY_BAN",
)


def simulator_params(args: Dict[str, str]) -> Dict[str, Any]:
    """Собрать параметры what-if из запроса, отбросив всё лишнее."""

    params: Dict[str, Any] = {}
    for event_type in EVENT_TYPES:
        raw = args.get(f"w.{event_type}")
        if raw is None or str(raw).strip() == "":
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        params[f"w.{event_type}"] = max(0, min(100, value))
    for name, low, high in (
        ("cap", 1, 100),
        ("window", 3600, 30 * 86400),
        ("decay", 0, 30 * 86400),
    ):
        raw = args.get(name)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        params[name] = max(low, min(high, value))
    return params


def valid_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""


def _annotate(entry: Dict[str, Any]) -> Dict[str, Any]:
    address = str(entry.get("ip") or "")
    if address:
        # Local MMDB lookup only: a visitor address is never sent to a third
        # party to find out where it is from.
        entry["country"] = get_country_code(address) or ""
    return entry


def shadow(args: Dict[str, str]) -> Dict[str, Any]:
    payload = guardd_shadow(simulator_params(args))
    for entry in payload.get("addresses") or []:
        _annotate(entry)
    return payload


def address(value: str, args: Dict[str, str]) -> Dict[str, Any]:
    payload = guardd_ip(value, simulator_params(args))
    _annotate(payload)
    return payload


def health() -> Dict[str, Any]:
    return guardd_health()


def set_mode(value: Any) -> Dict[str, Any]:
    mode = str(value or "").strip().lower()
    if mode not in MODES:
        raise ValueError("mode must be one of " + ", ".join(MODES))
    return guardd_set_mode(mode)


def unavailable_payload(exc: GuarddUnavailable) -> Dict[str, Any]:
    LOG.warning("guardd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
