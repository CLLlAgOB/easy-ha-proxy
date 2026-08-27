# -*- coding: utf-8 -*-
"""Сервисный слой страницы мониторинга.

Разбирает и валидирует параметры запроса, ходит в metricsd и приводит ответ к
виду, удобному для UI. Демон валидирует те же значения повторно — здесь это
защита от опечаток в UI, а не единственная граница доверия.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any, Dict, List, Tuple

from .metricsd_client import (
    MetricsdUnavailable,
    metricsd_channel_labels_save,
    metricsd_series,
    metricsd_servers,
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


# ---------------------------------------------------------------------------
# Uplinks
# ---------------------------------------------------------------------------
#
# A gateway usually reaches everything it proxies through one or two links --
# a main one and a reserve. HAProxy knows those only as a host on the far end
# of each `server` line, repeated across every backend that uses it, so the
# link itself is never named anywhere and its traffic is never separated from
# the total.
#
# Grouping the servers by that host is the whole trick. On a real gateway it
# comes out as eight backends on one address and two on another marked backup:
# the main channel and the reserve, without anything having to be configured.
#
# Read from the generated haproxy.cfg rather than from the site model on
# purpose. The names the collector stores are the ones HAProxy is running --
# `backend be_x` / `server srv1` -- and re-deriving them from the model would
# be a second implementation of the name sanitiser to drift out of step.

_SERVER_LINE = re.compile(
    r"^\s+server\s+(?P<name>\S+)\s+(?P<host>[^\s:]+|\[[^\]]+\]):(?P<port>\d+)"
    r"(?P<rest>.*)$"
)
_BACKEND_LINE = re.compile(r"^\s*backend\s+(\S+)")


def _is_local(host: str) -> bool:
    """A backend on this machine is a service, not a link to anywhere."""

    text = host.strip("[]")
    if text in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def backend_servers(path: str | None = None) -> List[Dict[str, Any]]:
    """Every `server` line, with the backend it belongs to."""

    found: List[Dict[str, Any]] = []
    current = ""
    try:
        with open(path or HAPROXY_CFG, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                header = _BACKEND_LINE.match(line)
                if header:
                    current = header.group(1)
                    continue
                if not current:
                    continue
                match = _SERVER_LINE.match(line)
                if not match:
                    continue
                found.append({
                    "proxy": current,
                    "server": match.group("name"),
                    "host": match.group("host").strip("[]"),
                    "port": int(match.group("port")),
                    "backup": " backup" in match.group("rest"),
                })
    except OSError as exc:
        LOG.warning("cannot read %s for uplinks: %s", path or HAPROXY_CFG, exc)
    return found


def channels(range_key: str) -> Dict[str, Any]:
    """The links this gateway reaches its backends through, with their traffic.

    Loopback is left out: those backends are this machine's own services --
    the interface, Authelia, certbot -- and counting them as a link would put
    the gateway's own traffic beside the uplinks it is being compared with.
    """

    servers = backend_servers()
    payload = metricsd_servers(range_key)
    labels = payload.get("labels") or {}

    # (proxy, server) is what the collector keys on, so that is the join.
    measured = {
        (str(row.get("proxy")), str(row.get("server"))): row
        for row in payload.get("servers") or []
    }

    grouped: Dict[str, Dict[str, Any]] = {}
    for entry in servers:
        host = entry["host"]
        if _is_local(host):
            continue
        channel = grouped.setdefault(host, {
            "host": host,
            "label": labels.get(host, ""),
            "names": [],
            "backends": [],
            "backup": True,
            "bytes_in": 0,
            "bytes_out": 0,
            "sessions": 0,
        })
        channel["names"].append(entry["server"])
        channel["backends"].append(entry["proxy"])
        # A link is only a reserve if every server on it is one. One backend
        # using it in anger makes it a live link.
        if not entry["backup"]:
            channel["backup"] = False
        row = measured.get((entry["proxy"], entry["server"]))
        if row:
            for column in ("bytes_in", "bytes_out", "sessions"):
                channel[column] += int(row.get(column) or 0)

    items = []
    for channel in grouped.values():
        names = channel.pop("names")
        # The name HAProxy was given is the best default label there is: an
        # operator who called it "main" and "bkp" has already named the links.
        common = max(set(names), key=names.count) if names else ""
        channel["default_label"] = common
        channel["backend_count"] = len(set(channel["backends"]))
        channel["backends"] = sorted(set(channel["backends"]))
        channel["bytes_total"] = channel["bytes_in"] + channel["bytes_out"]
        items.append(channel)

    # Live links first, then by how much went through them.
    items.sort(key=lambda c: (c["backup"], -c["bytes_total"], c["host"]))
    total = sum(c["bytes_total"] for c in items)
    for channel in items:
        channel["share"] = round(
            100.0 * channel["bytes_total"] / total, 1
        ) if total else 0.0

    return {
        "ok": True,
        "range": payload.get("range", range_key),
        "since": payload.get("since", 0),
        "until": payload.get("until", 0),
        "channels": items,
        "bytes_total": total,
    }


def save_channel_labels(labels: Any) -> Dict[str, Any]:
    if not isinstance(labels, dict):
        raise ValueError("labels must be an object")
    return metricsd_channel_labels_save(labels)


def unavailable_payload(exc: MetricsdUnavailable) -> Dict[str, Any]:
    """Единый ответ, когда сборщик недоступен.

    Мониторинг — не критичный путь: страница должна сказать, что данных нет,
    и не притворяться, что нулевые значения — это измерение.
    """

    LOG.warning("metricsd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
