# -*- coding: utf-8 -*-
"""Экспорт состояния шлюза в формате Prometheus.

Собирает то, что уже знают демоны, и не опрашивает ничего сам. Каждый
источник опционален: остановленный демон стоит нескольких метрик, а не всего
ответа, и это видно по `easy_ha_proxy_source_up`.

Ярлыки намеренно ограничены по кардинальности. Здесь нет ни одного адреса
посетителя: репутация отдаётся счётчиками по состояниям, а не по адресам.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger("haproxy-admin")

# A label value goes into the scrape output verbatim, so anything that could
# end a line or a quoted value is dropped rather than escaped: these are names
# the operator chose, not free text.
_LABEL_UNSAFE = re.compile(r'[\\"\n\r]')
MAX_LABEL_CHARS = 120


def _label(value: Any) -> str:
    return _LABEL_UNSAFE.sub("", str(value or ""))[:MAX_LABEL_CHARS]


def _number(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return number


class Exposition:
    """Accumulates metric families and renders the text format once."""

    def __init__(self) -> None:
        self._families: List[str] = []
        self._seen: set[str] = set()

    def family(
        self,
        name: str,
        kind: str,
        help_text: str,
        samples: Iterable[Tuple[Dict[str, str], Any]],
    ) -> None:
        rows: List[str] = []
        for labels, value in samples:
            number = _number(value)
            if number is None:
                continue
            if labels:
                rendered = ",".join(
                    f'{key}="{_label(item)}"' for key, item in sorted(labels.items())
                )
                rows.append(f"{name}{{{rendered}}} {number:g}")
            else:
                rows.append(f"{name} {number:g}")
        if not rows:
            # A family with no samples is noise; a scraper cannot tell it from
            # a metric that is genuinely zero.
            return
        if name in self._seen:
            raise ValueError(f"duplicate metric family: {name}")
        self._seen.add(name)
        self._families.append(
            f"# HELP {name} {help_text}\n# TYPE {name} {kind}\n" + "\n".join(rows)
        )

    def render(self) -> str:
        return "\n".join(self._families) + "\n"


def _backend_samples(
    backends: Any,
) -> Dict[str, List[Tuple[Dict[str, str], Any]]]:
    """Per-backend health straight from what HAProxy reports right now.

    Labelled by backend, never by server address: an address is operational
    detail that belongs on the page, not in a time series.
    """
    servers_total: List[Tuple[Dict[str, str], Any]] = []
    servers_up: List[Tuple[Dict[str, str], Any]] = []
    sessions: List[Tuple[Dict[str, str], Any]] = []
    for entry in backends or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("backend")
        if not name:
            continue
        servers = [item for item in entry.get("servers") or [] if isinstance(item, dict)]
        labels = {"backend": _label(name)}
        healthy = sum(
            1
            for item in servers
            if str(item.get("status") or "").upper().startswith(("UP", "NO CHECK"))
        )
        servers_total.append((labels, len(servers)))
        servers_up.append((labels, healthy))
        sessions.append(
            (labels, sum(int(item.get("sessions") or 0) for item in servers))
        )
    return {"total": servers_total, "healthy": servers_up, "sessions": sessions}


def collect(sources: Optional[Dict[str, Any]] = None) -> str:
    """Build the exposition. Never raises: a scrape is not worth a 500."""
    from . import services_prometheus_sources as default_sources

    reader = sources if sources is not None else default_sources.readers()
    exposition = Exposition()
    availability: List[Tuple[Dict[str, str], Any]] = []

    def read(name: str):
        function = reader.get(name)
        if function is None:
            return None
        try:
            payload = function()
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("prometheus: %s unavailable: %s", name, exc)
            availability.append(({"source": name}, 0))
            return None
        availability.append(({"source": name}, 1))
        return payload if isinstance(payload, dict) else None

    exposition.family(
        "easy_ha_proxy_build_info",
        "gauge",
        "Always 1; present so a scrape can be distinguished from an empty target.",
        [({}, 1)],
    )

    # -- HAProxy, as it reports itself right now ------------------------
    haproxy = read("haproxy")
    if haproxy:
        samples = _backend_samples(haproxy.get("backends"))
        exposition.family(
            "easy_ha_proxy_backend_servers_total",
            "gauge",
            "Servers configured in the backend.",
            samples["total"],
        )
        exposition.family(
            "easy_ha_proxy_backend_servers_up",
            "gauge",
            "Servers currently passing their health check.",
            samples["healthy"],
        )
        exposition.family(
            "easy_ha_proxy_backend_sessions",
            "gauge",
            "Sessions currently open across the backend's servers.",
            samples["sessions"],
        )

    # -- Monitoring storage ---------------------------------------------
    storage = read("storage")
    if storage:
        states = ("NORMAL", "WARNING", "PRESSURE", "CRITICAL")
        current = str(storage.get("state") or "").upper()
        exposition.family(
            "easy_ha_proxy_monitoring_storage_state",
            "gauge",
            "1 for the storage state the collector is in.",
            [({"state": state}, 1 if state == current else 0) for state in states],
        )
        exposition.family(
            "easy_ha_proxy_monitoring_paused",
            "gauge",
            "1 while historical monitoring has stopped writing.",
            [({}, 1 if storage.get("writes_paused") else 0)],
        )
        exposition.family(
            "easy_ha_proxy_monitoring_database_bytes",
            "gauge",
            "Size of the metrics database on disk.",
            [({}, storage.get("total_bytes"))],
        )
        exposition.family(
            "easy_ha_proxy_monitoring_filesystem_free_bytes",
            "gauge",
            "Free space on the filesystem holding the metrics database.",
            [({}, storage.get("filesystem_free_bytes"))],
        )

    # -- Adaptive protection ---------------------------------------------
    guard = read("guard")
    if guard:
        database = guard.get("database") or {}
        exposition.family(
            "easy_ha_proxy_guard_addresses",
            "gauge",
            "Addresses the engine is tracking, by state. No address is exposed.",
            [
                ({"state": _label(state)}, count)
                for state, count in sorted((guard.get("states") or {}).items())
            ],
        )
        exposition.family(
            "easy_ha_proxy_guard_bans_active",
            "gauge",
            "Bans the engine currently holds.",
            [({}, guard.get("bans_active", database.get("bans_active")))],
        )
        exposition.family(
            "easy_ha_proxy_guard_events_total",
            "counter",
            "Security events recorded since the database was created.",
            [({}, database.get("events"))],
        )
        exposition.family(
            "easy_ha_proxy_guard_enforcing",
            "gauge",
            "1 when the engine is allowed to ban, 0 while it only observes.",
            [({}, 1 if str(guard.get("mode") or "") == "enforce" else 0)],
        )

    # -- Alerts ------------------------------------------------------------
    alerts = read("alerts")
    if alerts:
        exposition.family(
            "easy_ha_proxy_alerts_firing",
            "gauge",
            "Alerts currently firing.",
            [({}, alerts.get("firing"))],
        )
        exposition.family(
            "easy_ha_proxy_alerts_pending",
            "gauge",
            "Conditions observed but still inside their trigger delay.",
            [({}, alerts.get("pending"))],
        )
        channels = alerts.get("channels") or {}
        exposition.family(
            "easy_ha_proxy_alert_channel_ready",
            "gauge",
            "1 when a notification channel is configured and usable.",
            [
                ({"channel": _label(name)}, 1 if ready else 0)
                for name, ready in sorted(channels.items())
            ],
        )

    # -- Certificates ------------------------------------------------------
    certificates = read("certificates")
    if certificates:
        exposition.family(
            "easy_ha_proxy_certificate_days_remaining",
            "gauge",
            "Days until the installed certificate expires; negative once expired.",
            [
                ({"domain": _label(domain)}, days)
                for domain, days in sorted((certificates.get("days") or {}).items())
            ],
        )

    # -- Jobs ---------------------------------------------------------------
    jobs = read("jobs")
    if jobs:
        exposition.family(
            "easy_ha_proxy_job_last_success_timestamp_seconds",
            "gauge",
            "When each kind of job last completed successfully.",
            [
                ({"job": _label(kind)}, when)
                for kind, when in sorted((jobs.get("last_success") or {}).items())
            ],
        )
        exposition.family(
            "easy_ha_proxy_job_last_failed",
            "gauge",
            "1 when the most recent job of that kind failed.",
            [
                ({"job": _label(kind)}, 1 if failed else 0)
                for kind, failed in sorted((jobs.get("last_failed") or {}).items())
            ],
        )

    exposition.family(
        "easy_ha_proxy_source_up",
        "gauge",
        "1 when the daemon behind a group of metrics answered this scrape.",
        availability,
    )
    exposition.family(
        "easy_ha_proxy_scrape_timestamp_seconds",
        "gauge",
        "When this exposition was built.",
        [({}, int(time.time()))],
    )
    return exposition.render()
