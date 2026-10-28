# -*- coding: utf-8 -*-
"""The service layer of the monitoring page.

Parses and validates the request's parameters, asks metricsd and shapes its
answer for the UI. The daemon validates the same values again -- here it is
a guard against typos in the UI, not the only trust boundary.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from typing import Any, Dict, List, Tuple

from .alertd_client import AlertdUnavailable, alertd_history, alertd_state
from .audit import RESULT_SUCCESS, audit_log
from .metricsd_client import (
    MetricsdUnavailable,
    metricsd_backends,
    metricsd_channel_labels_save,
    metricsd_series,
    metricsd_monitors_save,
    metricsd_servers,
    metricsd_sites,
    metricsd_states,
    metricsd_storage,
    metricsd_summary,
)
from .services import _load_display_map_from_cfg, HAPROXY_CFG

LOG = logging.getLogger("haproxy-admin")

# Kept in step with RANGES/CHART_SERIES in easy-ha-proxy-metricsd.py.
RANGES: Tuple[str, ...] = ("1h", "6h", "24h", "7d", "30d", "90d", "1y")
RANGE_SECONDS: Dict[str, int] = {
    "1h": 3600,
    "6h": 6 * 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "1y": 365 * 86400,
}
DEFAULT_RANGE = "24h"
CHARTS: Tuple[str, ...] = (
    "requests",
    "traffic",
    "responses",
    "latency",
    "connections",
    "cpu",
    "memory",
    "disk",
    "diskio",
    "network",
    "temperature",
    "percentiles",
    "refusals",
)

# Shorter names for the helper services: the prefix says only that the unit
# belongs to this gateway, which on this page goes without saying.
_COMPONENT_PREFIXES = ("easy-ha-proxy-", "haproxy-")


def component_label(name: str, group: str) -> str:
    if group == "service":
        for prefix in _COMPONENT_PREFIXES:
            if name.startswith(prefix) and len(name) > len(prefix):
                return name[len(prefix):]
    return name


def normalize_range(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in RANGES else DEFAULT_RANGE


def normalize_chart(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in CHARTS else ""


def display_name(proxy: str) -> str:
    """A backend's readable name, as on the other pages."""

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
    """An empty string means the total traffic of every frontend."""

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
           window: Dict[str, int] | None = None,
           components: bool = True) -> Dict[str, Any]:
    payload = metricsd_series(chart, range_key, site, window, components)
    for entry in payload.get("components") or []:
        entry["label"] = component_label(
            str(entry.get("name") or ""), str(entry.get("group") or "")
        )
    return payload


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


def backend_traffic(range_key: str,
                    window: Dict[str, int] | None = None) -> Dict[str, Any]:
    """How much went through each backend, busiest first.

    The availability bars say whether a backend was up; they cannot say
    which of twenty backends the traffic of a busy hour belonged to. The
    collector already keeps bytes per server, so a backend's figure is the
    sum over its servers. The machine's own services are kept: here the
    question is where the bytes went, and the interface is one of the
    answers.
    """

    payload = metricsd_servers(range_key, window)
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in payload.get("servers") or []:
        proxy = str(row.get("proxy") or "")
        if not proxy:
            continue
        entry = grouped.setdefault(proxy, {
            "proxy": proxy,
            "bytes_in": 0,
            "bytes_out": 0,
            "sessions": 0,
        })
        for column in ("bytes_in", "bytes_out", "sessions"):
            entry[column] += int(row.get(column) or 0)

    items = list(grouped.values())
    for entry in items:
        entry["label"] = display_name(entry["proxy"])
        entry["bytes_total"] = entry["bytes_in"] + entry["bytes_out"]
    items.sort(key=lambda e: (-e["bytes_total"], e["label"].lower()))
    total = sum(entry["bytes_total"] for entry in items)
    for entry in items:
        entry["share"] = round(
            100.0 * entry["bytes_total"] / total, 1
        ) if total else 0.0

    return {
        "ok": True,
        "range": payload.get("range", range_key),
        "since": payload.get("since", 0),
        "until": payload.get("until", 0),
        "backends": items,
        "bytes_total": total,
    }


# ---------------------------------------------------------------------------
# Requests per backend
# ---------------------------------------------------------------------------


def backend_requests(range_key: str,
                     window: Dict[str, int] | None = None) -> Dict[str, Any]:
    """What each backend answered over the period: how much, how badly, how fast.

    The list sorted to find the busiest backend, the failing one and the slow
    one. A backend that answered nothing is left out: thirty rows of zeros
    hide the three that matter.
    """

    payload = metricsd_backends(range_key, window)
    items: List[Dict[str, Any]] = []
    for entry in payload.get("backends") or []:
        proxy = str(entry.get("proxy") or "")
        requests = int(entry.get("requests") or 0)
        if not proxy or requests <= 0:
            continue
        classes = {
            column: int(entry.get(column) or 0)
            for column in ("resp_2xx", "resp_3xx", "resp_4xx", "resp_5xx")
        }
        answered = sum(classes.values())
        average = entry.get("response_ms_avg")
        peak = entry.get("response_ms_max")
        items.append({
            "proxy": proxy,
            "label": display_name(proxy),
            "requests": requests,
            "answered": answered,
            "resp_4xx": classes["resp_4xx"],
            "resp_5xx": classes["resp_5xx"],
            "share_4xx": round(100.0 * classes["resp_4xx"] / answered, 1) if answered else 0.0,
            "share_5xx": round(100.0 * classes["resp_5xx"] / answered, 1) if answered else 0.0,
            "response_ms_avg": None if average is None else int(average),
            "response_ms_max": None if peak is None else int(peak),
            "bytes_total": int(entry.get("bytes_in") or 0) + int(entry.get("bytes_out") or 0),
        })
    items.sort(key=lambda item: (-item["requests"], item["label"].lower()))
    return {
        "ok": True,
        "range": payload.get("range", range_key),
        "since": payload.get("since", 0),
        "until": payload.get("until", 0),
        "backends": items,
        "requests_total": sum(item["requests"] for item in items),
    }


# ---------------------------------------------------------------------------
# Events on the charts
# ---------------------------------------------------------------------------
#
# A spike reads differently beside what happened that minute: a site was
# changed, an update ran, a service was restarted, an alert fired. All of it
# is already written down -- in the change log and by the alert engine -- so
# nothing new is recorded for the charts; they only read.

# The changes that can show on a chart, with the words the page puts on them.
# Only what changes what the gateway serves: who looked at a page, or took a
# backup, is in the change log and not here.
EVENT_ACTIONS: Dict[str, str] = {
    "config.apply": "Configuration applied",
    "config.rollback": "Configuration rolled back",
    "config.revert": "Configuration reverted",
    "config.restore": "Configuration restored",
    "config.upload": "Configuration uploaded",
    "site.create": "Site added",
    "site.update": "Site changed",
    "site.delete": "Site removed",
    "tcp_proxy.create": "TCP proxy added",
    "tcp_proxy.update": "TCP proxy changed",
    "tcp_proxy.delete": "TCP proxy removed",
    "udp_forward.create": "UDP forward added",
    "udp_forward.update": "UDP forward changed",
    "udp_forward.delete": "UDP forward removed",
    "vars.update": "Variables changed",
    "backend.state": "Server state changed",
    "backend.weight": "Server weight changed",
    "service.control": "Service action",
    "update.apply": "Update started",
    "restore.start": "Restore from a backup started",
    "system.reboot": "Reboot",
    "geoip.countries": "Country rules changed",
    "adaptive.mode": "Adaptive protection mode changed",
    "certificate.issue": "Certificate issued",
    "certificate.restore": "Certificate restored",
    "certificate.standby_activate": "Standby certificate activated",
}
# An alert is marked where it began and where it ended; a reminder that it
# is still on says nothing new about that minute.
EVENT_TRANSITIONS: Dict[str, str] = {
    "fired": "alert",
    "escalated": "alert",
    "recovered": "recovered",
}
# Per source, and on the page: more than this on one chart is a smear, and
# the answer says it was cut.
MAX_EVENTS = 200


def _event_period(range_key: str, window: Dict[str, int] | None,
                  now: int) -> Tuple[int, int]:
    if window and window.get("since") and window.get("until"):
        return int(window["since"]), int(window["until"])
    return now - RANGE_SECONDS.get(range_key, RANGE_SECONDS[DEFAULT_RANGE]), now


def _rule_titles() -> Dict[str, str]:
    """The alert engine's names for its rules; {} when it cannot say."""

    try:
        catalogue = alertd_state(limit=1).get("catalogue") or []
    except AlertdUnavailable:
        return {}
    return {
        str(rule.get("name") or ""): str(rule.get("title") or "")
        for rule in catalogue
        if isinstance(rule, dict) and rule.get("name")
    }


def events(range_key: str, window: Dict[str, int] | None = None,
           now: int | None = None) -> Dict[str, Any]:
    """The changes and alerts of a period, oldest first.

    For the whole gateway even when one site is chosen: a configuration
    apply or an update touches every site, and the change log does not say
    which backend a change ended up in.
    """

    now = int(now if now is not None else time.time())
    since, until = _event_period(range_key, window, now)
    found: List[Dict[str, Any]] = []
    truncated = False

    changes = audit_log().query(
        actions=tuple(EVENT_ACTIONS), result=RESULT_SUCCESS,
        since=since, until=until, limit=MAX_EVENTS,
    )
    truncated = truncated or int(changes.get("total") or 0) > MAX_EVENTS
    for row in changes.get("events") or []:
        action = str(row.get("action") or "")
        found.append({
            "ts": int(row.get("ts") or 0),
            "kind": "change",
            "label": EVENT_ACTIONS.get(action, action),
            "object": str(row.get("object_id") or "")[:120],
            "actor": str(row.get("actor") or "")[:60],
            "summary": str(row.get("summary") or "")[:160],
        })

    alerts_available = True
    titles: Dict[str, str] = {}
    try:
        history = alertd_history({"since": since, "until": until, "limit": 500})
    except AlertdUnavailable:
        history = {}
        alerts_available = False
    if alerts_available:
        titles = _rule_titles()
    alert_rows = []
    for row in history.get("events") or []:
        kind = EVENT_TRANSITIONS.get(str(row.get("transition") or ""))
        ts = int(row.get("ts") or 0)
        # An engine older than the `until` filter answers with everything
        # after `since`; the period is kept here as well.
        if kind and since <= ts <= until:
            rule = str(row.get("rule") or "")[:80]
            alert_rows.append({
                "ts": ts,
                "kind": kind,
                "label": "Alert" if kind == "alert" else "Recovered",
                "object": str(row.get("subject") or "")[:120],
                "actor": "",
                "summary": str(row.get("summary") or "")[:160],
                "severity": str(row.get("severity") or ""),
                # What the page filters by: a flapping rule can be put away
                # without hiding the rest.
                "rule": rule,
                "title": titles.get(rule) or rule,
            })
    alert_rows.sort(key=lambda item: item["ts"])
    if len(alert_rows) > MAX_EVENTS:
        alert_rows = alert_rows[-MAX_EVENTS:]
        truncated = True
    found.extend(alert_rows)

    found.sort(key=lambda item: item["ts"])
    return {
        "ok": True,
        "since": since,
        "until": until,
        "events": found,
        "truncated": truncated,
        "alerts_available": alerts_available,
    }


# ---------------------------------------------------------------------------
# Needs attention
# ---------------------------------------------------------------------------
#
# What is wrong right now, at the top of the page. The alert engine already
# decides that -- a site down, server errors or slow answers over its
# threshold, monitoring storage under pressure -- with the operator's own
# thresholds and delays. A second set of rules here would disagree with it,
# so the strip only shows the engine's open alerts: those firing, and those
# inside their delay, which are the earliest warning there is.

ATTENTION_SEVERITIES = ("critical", "warning")
MAX_ATTENTION = 8


def attention() -> Dict[str, Any]:
    try:
        state = alertd_state(limit=1)
    except AlertdUnavailable:
        return {"ok": True, "available": False, "items": [], "more": 0}

    titles = {
        str(rule.get("name") or ""): str(rule.get("title") or "")
        for rule in state.get("catalogue") or []
        if isinstance(rule, dict)
    }
    items: List[Dict[str, Any]] = []
    for rows, pending in ((state.get("active") or [], False),
                          (state.get("pending") or [], True)):
        for row in rows:
            severity = str(row.get("severity") or "")
            if severity not in ATTENTION_SEVERITIES:
                continue
            rule = str(row.get("rule") or "")
            items.append({
                "rule": rule,
                "title": titles.get(rule) or rule,
                "subject": str(row.get("subject") or "")[:120],
                "severity": severity,
                "pending": pending,
                "since": int(row.get("since_ts") or 0),
                "summary": str(row.get("summary") or "")[:200],
            })
    # Firing before pending, critical before warning, the newest first.
    items.sort(key=lambda item: (
        item["pending"], ATTENTION_SEVERITIES.index(item["severity"]), -item["since"],
    ))
    return {
        "ok": True,
        "available": True,
        "items": items[:MAX_ATTENTION],
        "more": max(0, len(items) - MAX_ATTENTION),
    }


# The monitors the page can switch, as the daemon names them (see
# MONITOR_DEFAULTS in easy-ha-proxy-metricsd.py).
MONITORS = (
    "machine", "components", "disk", "network", "temperature", "percentiles", "refusals",
    "requests",
    "traffic", "responses", "latency", "connections", "uplinks", "availability",
)


def save_monitors(changes: Any) -> Dict[str, Any]:
    if not isinstance(changes, dict) or not changes:
        raise ValueError("monitors must be a non-empty object")
    cleaned: Dict[str, bool] = {}
    for name, value in changes.items():
        if name not in MONITORS:
            raise ValueError(f"unknown monitor: {str(name)[:40]}")
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be true or false")
        cleaned[name] = value
    return metricsd_monitors_save(cleaned)


def save_channel_labels(labels: Any, hidden: Any = None) -> Dict[str, Any]:
    if not isinstance(labels, dict):
        raise ValueError("labels must be an object")
    if hidden is not None and not isinstance(hidden, list):
        raise ValueError("hidden must be a list")
    return metricsd_channel_labels_save(labels, hidden)


def unavailable_payload(exc: MetricsdUnavailable) -> Dict[str, Any]:
    """The one answer when the collector is unavailable.

    Monitoring is not a critical path: the page must say there is no data,
    not pretend that zeros are a measurement.
    """

    LOG.warning("metricsd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}
