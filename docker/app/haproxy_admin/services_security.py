# -*- coding: utf-8 -*-
"""Сервисный слой раздела Adaptive protection.

Валидирует параметры симулятора весов и обогащает адреса страной из локальной
базы GeoIP. Демон валидирует те же значения повторно.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional

from .cache import get_country_code
from .guardd_client import (
    guardd_signatures,
    guardd_set_signatures,
    guardd_requests,
    guardd_requests_status,
    guardd_set_request_log,
    GuarddUnavailable,
    guardd_health,
    guardd_ip,
    guardd_set_ban_durations,
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


# Which knob each finding is about. The page exists so an operator can decide
# whether a limit is wrong, and that decision needs three things the daemon
# does not have: the real site name behind the sanitised table name, the limit
# that was configured, and the name of the setting to change.
_LIMIT_FOR_EVENT = {
    "RATE_EXCEEDED": ("max_req_rate", "rate_window", "requests"),
    "ERROR_RATE_EXCEEDED": ("err_limit", "err_window", "errors"),
}


def _site_limits() -> Dict[str, Dict[str, Any]]:
    """Map the sanitised stick-table suffix back to a real site and its limits."""
    from .services_haproxy_config import CONFIG_YAML, _load_yaml, jinja_combine
    from .services_haproxy_sites import get_websites_list

    defaults = (_load_yaml(CONFIG_YAML) or {}).get("site_defaults") or {}
    table: Dict[str, Dict[str, Any]] = {}
    for site in get_websites_list():
        name = str(site.get("name") or "")
        if not name:
            continue
        effective = jinja_combine(defaults, site, True)
        table[re.sub(r"[^A-Za-z0-9_]", "_", name)] = {
            "site": name,
            "domain": str(effective.get("domain") or name),
            "max_req_rate": effective.get("max_req_rate"),
            "rate_window": effective.get("rate_window") or defaults.get("rate_window"),
            "err_limit": effective.get("err_limit") or defaults.get("err_limit"),
            "err_window": effective.get("err_window") or defaults.get("err_window"),
        }
    return table


def _explain(contribution: Dict[str, Any], limits: Dict[str, Dict[str, Any]]) -> None:
    """Say what was measured, against what, and which setting moves it."""
    known = limits.get(str(contribution.get("site") or ""))
    if known:
        contribution["site_name"] = known["site"]
        contribution["site_domain"] = known["domain"]

    mapping = _LIMIT_FOR_EVENT.get(str(contribution.get("event_type") or ""))
    detail = str(contribution.get("detail") or "")
    observed_match = re.search(r"(?:req|err)_rate=(\d+)", detail)
    if not (mapping and observed_match):
        return
    setting, window_key, unit = mapping
    observed = int(observed_match.group(1))
    contribution["observed"] = observed
    contribution["unit"] = unit
    contribution["setting"] = setting

    # The daemon reads the ceiling out of the generated configuration and puts
    # it in the finding, so that number is what actually applied at the time.
    # websites.yml is only the fallback, and it can disagree if the setting was
    # changed after the finding was recorded.
    limit_match = re.search(r"limit=(\d+)", detail)
    limit = int(limit_match.group(1)) if limit_match else known and known.get(setting)
    if not isinstance(limit, int) or limit <= 0:
        return
    contribution["limit"] = limit
    if known:
        contribution["window"] = known.get(window_key)
    contribution["over_by"] = max(0, observed - limit)
    # Headroom above the peak, so raising it to exactly what was seen does not
    # put the operator back here on the next slightly busier minute -- but
    # never a number below the limit already in force, which would read as
    # advice to tighten it.
    contribution["suggested"] = max(limit + 1, int(observed * 1.5))


def address(value: str, args: Dict[str, str]) -> Dict[str, Any]:
    payload = guardd_ip(value, simulator_params(args))
    _annotate(payload)
    try:
        limits = _site_limits()
    except Exception:  # pylint: disable=broad-except
        # Enrichment is a convenience; the findings themselves must still show.
        LOG.warning("cannot read site limits for the findings", exc_info=True)
        limits = {}
    contributions = payload.get("contributions") or []
    for contribution in contributions:
        _explain(contribution, limits)
    _withhold_advice_from_attackers(contributions)
    return payload


# Findings that say the address is not a misconfigured client but something
# probing the gateway.
_HOSTILE_MARKERS = ("SCANNER", "INVALID_HOST", "NOSNI", "LEGACY_HAPROXY_BAN")


def _withhold_advice_from_attackers(contributions: List[Dict[str, Any]]) -> None:
    """Do not offer to raise a limit for an address that is attacking.

    The suggestion exists for the opposite case -- a real application that
    opens twenty connections at once and trips a threshold nobody tuned. Shown
    beside a request for /vendor/phpunit/.../eval-stdin.php and
    /cgi-bin/../bin/sh it becomes advice to widen the door for a scanner,
    which is how an operator ends up making the gateway more permissive
    towards the one address that least deserves it.

    The measurement stays: what was observed, against which limit, and by how
    much. Only the recommendation goes.
    """
    hostile = any(
        marker in str(contribution.get("event_type") or "")
        for contribution in contributions
        for marker in _HOSTILE_MARKERS
    )
    if not hostile:
        return
    for contribution in contributions:
        if "suggested" in contribution:
            contribution.pop("suggested")
            contribution["advice_withheld"] = "the address is probing the gateway"


def health() -> Dict[str, Any]:
    return guardd_health()


def detection_rules() -> Dict[str, Any]:
    return guardd_signatures()


def set_detection_rules(payload: Any) -> Dict[str, Any]:
    """Pass the operator's rules to the daemon, which is what validates them.

    Deliberately not re-validated here. The daemon owns the rules and has to
    refuse a bad one anyway, whoever sends it; a second copy of the same
    checks in the web layer would be one more thing to drift.
    """

    if not isinstance(payload, dict):
        raise ValueError("expected an object")
    return guardd_set_signatures({
        "added": payload.get("added") or {},
        "disabled": payload.get("disabled") or [],
    })


def set_mode(value: Any) -> Dict[str, Any]:
    mode = str(value or "").strip().lower()
    if mode not in MODES:
        raise ValueError("mode must be one of " + ", ".join(MODES))
    return guardd_set_mode(mode)


# Bounds are checked here as well as in the daemon. The daemon's are the ones
# that hold; these exist so a typo comes back as a sentence the operator can
# read rather than as a rejected request from a socket they never see.
MAX_BAN_STEPS = 6
MIN_BAN_SECONDS = 60
MAX_BAN_SECONDS = 365 * 86400


def set_ban_durations(value: Any) -> Dict[str, Any]:
    if not isinstance(value, list) or not value:
        raise ValueError("ban durations must be a non-empty list")
    if len(value) > MAX_BAN_STEPS:
        raise ValueError(f"at most {MAX_BAN_STEPS} steps")
    steps = []
    for entry in value:
        if isinstance(entry, bool):
            raise ValueError("each step must be a whole number of seconds")
        try:
            seconds = int(entry)
        except (TypeError, ValueError):
            raise ValueError("each step must be a whole number of seconds")
        if seconds < MIN_BAN_SECONDS or seconds > MAX_BAN_SECONDS:
            raise ValueError(
                f"each step must be between {MIN_BAN_SECONDS} seconds and "
                f"{MAX_BAN_SECONDS // 86400} days"
            )
        steps.append(seconds)
    for earlier, later in zip(steps, steps[1:]):
        if later < earlier:
            raise ValueError(
                "each step must be at least as long as the one before"
            )
    return guardd_set_ban_durations(steps)


def unavailable_payload(exc: GuarddUnavailable) -> Dict[str, Any]:
    LOG.warning("guardd unavailable: %s", exc)
    return {"ok": False, "unavailable": True, "error": str(exc)}


# The Log Explorer reads the same daemon. Filters are passed through by name
# so a new one on the daemon side does not need a change here, but the set is
# closed: an unknown key is dropped rather than forwarded.
REQUEST_FILTERS = (
    "since", "until", "client", "status", "host", "backend",
    "request_id", "method", "path", "limit", "offset",
)


def requests(args) -> Dict[str, Any]:
    params = {}
    for key in REQUEST_FILTERS:
        value = str(args.get(key) or "").strip()
        if value:
            params[key] = value[:200]
    return guardd_requests(params)


def requests_status() -> Dict[str, Any]:
    return guardd_requests_status()


def set_request_log(enabled: Any) -> Dict[str, Any]:
    return guardd_set_request_log(bool(enabled))
