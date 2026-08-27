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


# An explicit period, when the presets cannot say what happened on Tuesday
# morning. Bounded here as well as in the daemon so a mistyped year is
# refused before it becomes a query.
MAX_WINDOW_SECONDS = 366 * 86400
MIN_WINDOW_SECONDS = 60


def normalize_window(since: Any, until: Any) -> Dict[str, int]:
    """A since/until pair, or {} to fall back to the preset."""

    try:
        start = int(str(since).strip())
        end = int(str(until).strip())
    except (TypeError, ValueError):
        return {}
    if start <= 0 or end <= 0 or end - start < MIN_WINDOW_SECONDS:
        return {}
    if end - start > MAX_WINDOW_SECONDS:
        start = end - MAX_WINDOW_SECONDS
    return {"since": start, "until": end}


def summary(range_key: str, site: str,
            window: Dict[str, int] | None = None) -> Dict[str, Any]:
    payload = metricsd_summary(range_key, site, window)
    health = payload.get("health") or {}
    for group in ("backends", "servers"):
        for entry in health.get(group) or []:
            entry["label"] = display_name(str(entry.get("proxy") or ""))
    payload["site_label"] = display_name(site) if site else ""
    return payload


def series(chart: str, range_key: str, site: str,
           window: Dict[str, int] | None = None) -> Dict[str, Any]:
    return metricsd_series(chart, range_key, site, window)


def states(range_key: str, site: str,
           window: Dict[str, int] | None = None) -> Dict[str, Any]:
    payload = metricsd_states(range_key, site, window)
    objects = payload.get("objects") or []

    # A backend with one server produced two rows saying the same thing --
    # "authelia.backend / Backend" directly above "authelia /
    # authelia.backend". The backend row is the one that means anything, and
    # the server row only earns its place when there is more than one to
    # tell apart.
    servers_per_proxy: Dict[str, int] = {}
    has_backend_row: set = set()
    for entry in objects:
        proxy = str(entry.get("proxy") or "")
        if entry.get("server"):
            servers_per_proxy[proxy] = servers_per_proxy.get(proxy, 0) + 1
        else:
            has_backend_row.add(proxy)

    def keep(entry: Dict[str, Any]) -> bool:
        if not entry.get("server"):
            return True
        proxy = str(entry.get("proxy") or "")
        # Only ever collapse into a row that exists. Without this the sole
        # row of a backend that has no backend row of its own disappears
        # and the object stops being visible at all.
        if proxy not in has_backend_row:
            return True
        return servers_per_proxy.get(proxy, 0) > 1

    kept = [entry for entry in objects if keep(entry)]
    for entry in kept:
        entry["label"] = display_name(str(entry.get("proxy") or ""))
    payload["objects"] = kept
    payload["collapsed"] = len(objects) - len(kept)
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


def channels(range_key: str,
             window: Dict[str, int] | None = None) -> Dict[str, Any]:
    """The links this gateway reaches its backends through, with their traffic.

    Loopback is left out: those backends are this machine's own services --
    the interface, Authelia, certbot -- and counting them as a link would put
    the gateway's own traffic beside the uplinks it is being compared with.
    """

    servers = backend_servers()
    payload = metricsd_servers(range_key, window)
    labels = payload.get("labels") or {}
    hidden = set(payload.get("hidden") or [])

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
        channel["hidden"] = channel["host"] in hidden
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
    items.sort(key=lambda c: (c["hidden"], c["backup"], -c["bytes_total"],
                              c["host"]))
    # Shares are of what is shown. A hidden host is one the operator has said
    # is not an uplink, and counting it would make the percentages answer a
    # question nobody asked.
    total = sum(c["bytes_total"] for c in items if not c["hidden"])
    for channel in items:
        channel["share"] = round(
            100.0 * channel["bytes_total"] / total, 1
        ) if total and not channel["hidden"] else 0.0

    return {
        "ok": True,
        "range": payload.get("range", range_key),
        "since": payload.get("since", 0),
        "until": payload.get("until", 0),
        "channels": [c for c in items if not c["hidden"]],
        "hidden": [c for c in items if c["hidden"]],
        "bytes_total": total,
    }


def save_channel_labels(labels: Any, hidden: Any = None) -> Dict[str, Any]:
    if not isinstance(labels, dict):
        raise ValueError("labels must be an object")
    if hidden is not None and not isinstance(hidden, list):
        raise ValueError("hidden must be a list")
    return metricsd_channel_labels_save(labels, hidden)


def unavailable_payload(exc: MetricsdUnavailable) -> Dict[str, Any]:
    """Единый ответ, когда сборщик недоступен.

    Мониторинг — не критичный путь: страница должна сказать, что данных нет,
    и не притворяться, что нулевые значения — это измерение.
    """

    LOG.warning("metricsd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
