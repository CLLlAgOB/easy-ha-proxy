# -*- coding: utf-8 -*-
"""Сервисный слой страницы мониторинга.

Разбирает и валидирует параметры запроса, ходит в metricsd и приводит ответ к
виду, удобному для UI. Демон валидирует те же значения повторно — здесь это
защита от опечаток в UI, а не единственная граница доверия.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from .metricsd_client import (
    MetricsdUnavailable,
    metricsd_series,
    metricsd_sites,
    metricsd_states,
    metricsd_storage,
    metricsd_summary,
)
from .services import _load_display_map_from_cfg, HAPROXY_CFG

LOG = logging.getLogger("haproxy-admin")

# Держим синхронно с RANGES/CHART_SERIES в easy-ha-proxy-metricsd.py.
RANGES: Tuple[str, ...] = ("1h", "6h", "24h", "7d", "30d", "90d", "1y")
DEFAULT_RANGE = "24h"
CHARTS: Tuple[str, ...] = (
    "requests",
    "traffic",
    "responses",
    "latency",
    "connections",
)


def normalize_range(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in RANGES else DEFAULT_RANGE


def normalize_chart(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in CHARTS else ""


def display_name(proxy: str) -> str:
    """Человекочитаемое имя backend, как на остальных страницах."""

    mapping = _load_display_map_from_cfg(HAPROXY_CFG)
    tagged = mapping.get(proxy)
    if tagged:
        return tagged
    name = proxy[3:] if proxy.startswith("be_") else proxy
    return name.replace("_", ".")


def list_sites() -> List[Dict[str, str]]:
    payload = metricsd_sites()
    sites: List[Dict[str, str]] = []
    for entry in payload.get("sites") or []:
        proxy = str(entry.get("proxy") or "").strip()
        if not proxy:
            continue
        sites.append({"proxy": proxy, "label": display_name(proxy)})
    sites.sort(key=lambda item: item["label"].lower())
    return sites


def normalize_site(value: Any, sites: List[Dict[str, str]]) -> str:
    """Пустая строка означает суммарный трафик по всем frontend."""

    candidate = str(value or "").strip()
    if not candidate or candidate.lower() == "all":
        return ""
    known = {site["proxy"] for site in sites}
    return candidate if candidate in known else ""


def summary(range_key: str, site: str) -> Dict[str, Any]:
    payload = metricsd_summary(range_key, site)
    health = payload.get("health") or {}
    for group in ("backends", "servers"):
        for entry in health.get(group) or []:
            entry["label"] = display_name(str(entry.get("proxy") or ""))
    payload["site_label"] = display_name(site) if site else ""
    return payload


def series(chart: str, range_key: str, site: str) -> Dict[str, Any]:
    return metricsd_series(chart, range_key, site)


def states(range_key: str, site: str) -> Dict[str, Any]:
    payload = metricsd_states(range_key, site)
    for entry in payload.get("objects") or []:
        entry["label"] = display_name(str(entry.get("proxy") or ""))
    return payload


def storage() -> Dict[str, Any]:
    return metricsd_storage()


def unavailable_payload(exc: MetricsdUnavailable) -> Dict[str, Any]:
    """Единый ответ, когда сборщик недоступен.

    Мониторинг — не критичный путь: страница должна сказать, что данных нет,
    и не притворяться, что нулевые значения — это измерение.
    """

    LOG.warning("metricsd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
