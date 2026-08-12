# -*- coding: utf-8 -*-
"""Откуда экспортёр берёт цифры.

Отдельный модуль, потому что сборка экспозиции должна тестироваться без
сокетов: `services_prometheus.collect()` принимает этот словарь и не знает,
настоящие за ним демоны или подстановка.
"""

from __future__ import annotations

from typing import Any, Callable, Dict


def _haproxy() -> Dict[str, Any]:
    from . import services_runtime

    return {"backends": services_runtime.list_backends()}


def _storage() -> Dict[str, Any]:
    from .metricsd_client import metricsd_storage

    payload = metricsd_storage()
    # metricsd answers {"ok": true, ...status}; the status is what matters.
    return payload.get("storage") if isinstance(payload.get("storage"), dict) else payload


def _guard() -> Dict[str, Any]:
    from .guardd_client import guardd_health

    return guardd_health()


def _alerts() -> Dict[str, Any]:
    from .alertd_client import alertd_health

    return alertd_health()


def _certificates() -> Dict[str, Any]:
    """Days remaining per site, from the certificate daemon."""
    from .certd_client import get_certs_status_for_domains
    from .services_haproxy_sites import get_sites_and_defaults_for_ui

    _defaults, sites = get_sites_and_defaults_for_ui()
    domains = []
    for item in sites:
        effective = item.get("effective") or {}
        domain = str(effective.get("domain") or effective.get("name") or "").strip()
        if domain and not effective.get("tcp_passthrough"):
            domains.append(domain)
    days: Dict[str, Any] = {}
    for domain, status in (get_certs_status_for_domains(domains) or {}).items():
        remaining = status.get("haproxy_days_left")
        if remaining is None:
            remaining = status.get("le_days_left")
        if remaining is not None:
            days[domain] = remaining
    return {"days": days}


def _jobs() -> Dict[str, Any]:
    """Whether the last backup and the last software update succeeded."""
    from .backupd_client import backupd_request
    from .updated_client import updated_request

    last_success: Dict[str, Any] = {}
    last_failed: Dict[str, Any] = {}

    def absorb(kind: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        job = payload.get("job") or payload.get("last_job") or {}
        if not isinstance(job, dict):
            return
        status = str(job.get("status") or "").lower()
        last_failed[kind] = status == "failed"
        if status == "completed":
            completed = job.get("completed_at")
            if completed is not None:
                last_success[kind] = completed

    absorb("backup", backupd_request({"action": "status"}, timeout=5.0))
    absorb("update", updated_request({"action": "status"}))
    return {"last_success": last_success, "last_failed": last_failed}


def readers() -> Dict[str, Callable[[], Dict[str, Any]]]:
    """The live sources, one callable per group of metrics."""
    return {
        "haproxy": _haproxy,
        "storage": _storage,
        "guard": _guard,
        "alerts": _alerts,
        "certificates": _certificates,
        "jobs": _jobs,
    }
