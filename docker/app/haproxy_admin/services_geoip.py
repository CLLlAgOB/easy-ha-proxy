"""Least-privilege client for local GeoIP database management."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import yaml

from .services_haproxy_config import (
    CONFIG_YAML,
    WEBSITES_YAML,
    _controld_json_request,
    config_transaction_is_pending,
)


GEOIP_CONTROL_TIMEOUT = 360
MAX_COUNTRIES = 249
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


def _request(command: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is not None:
        encoded = base64.b64encode(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).decode("ascii")
        command = f"{command} {encoded}"
    return _controld_json_request(command, timeout=GEOIP_CONTROL_TIMEOUT)


def _runtime_geoip_config() -> dict[str, Any]:
    try:
        raw = CONFIG_YAML.read_bytes()
        values = yaml.safe_load(raw.decode("utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return {"available": False, "error": f"Cannot read runtime vars.yml: {exc}"}
    if not isinstance(values, dict):
        return {"available": False, "error": "Runtime vars.yml root is not a mapping"}
    enabled = values.get("enable_geoip", False)
    mode = str(values.get("geoip_mode") or "allow").strip().lower()
    countries = values.get("geoip_country_codes") or []
    if not isinstance(enabled, bool):
        return {"available": False, "error": "enable_geoip must be boolean"}
    if mode not in {"allow", "deny"}:
        return {"available": False, "error": "geoip_mode must be allow or deny"}
    try:
        countries = normalize_countries(countries)
    except ValueError as exc:
        return {"available": False, "error": str(exc)}
    return {
        "available": True,
        "enable_geoip": enabled,
        "geoip_mode": mode,
        "countries": countries,
    }


def _attach_runtime_config(result: dict[str, Any]) -> dict[str, Any]:
    runtime = _runtime_geoip_config()
    result["runtime_config"] = runtime
    selection = result.get("selection")
    if isinstance(selection, dict) and runtime.get("available"):
        result["runtime_config_in_sync"] = (
            selection.get("countries") == runtime.get("countries")
            and selection.get("access_filter_enabled")
            == runtime.get("enable_geoip")
        )
    else:
        result["runtime_config_in_sync"] = False
    return result


def get_geoip_status() -> dict[str, Any]:
    return _attach_runtime_config(_request("geoip-status"))


def update_geoip_now(force: Any = False) -> dict[str, Any]:
    if not isinstance(force, bool):
        return {"ok": False, "validation_error": True, "error": "force must be boolean"}
    result = _request("geoip-update", {"force": force})
    status = result.get("status")
    if isinstance(status, dict):
        _attach_runtime_config(status)
    return result


def normalize_countries(values: Any) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("countries must be a list")
    if len(values) > MAX_COUNTRIES:
        raise ValueError("at most 249 countries can be selected")
    countries: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError("country codes must be strings")
        code = raw.strip().upper()
        if not COUNTRY_RE.fullmatch(code):
            raise ValueError(f"invalid ISO country code: {raw!r}")
        countries.add(code)
    return sorted(countries)


def _site_geoip_country_usage() -> dict[str, list[str]]:
    """Return per-country site references that must keep their ACL files."""
    try:
        websites = yaml.safe_load(WEBSITES_YAML.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read websites.yml GeoIP policies: {exc}") from exc
    if not isinstance(websites, dict):
        raise ValueError("websites.yml root must be a mapping")
    sites = websites.get("sites") or []
    if not isinstance(sites, list):
        raise ValueError("websites.yml sites value must be a list")

    usage: dict[str, list[str]] = {}
    for index, site in enumerate(sites):
        if not isinstance(site, dict):
            raise ValueError(f"sites[{index}] must be an object")
        raw_countries = site.get("geo_countries")
        if raw_countries in (None, []):
            continue
        try:
            site_countries = normalize_countries(raw_countries)
        except ValueError as exc:
            raise ValueError(f"sites[{index}].geo_countries: {exc}") from exc
        label = str(site.get("domain") or site.get("name") or f"sites[{index}]")
        for code in site_countries:
            usage.setdefault(code, []).append(label)
    return usage


def configure_geoip_countries(values: Any, revision: Any) -> dict[str, Any]:
    pending, pending_message = config_transaction_is_pending()
    if pending:
        return {"ok": False, "conflict": True, "error": pending_message}
    try:
        countries = normalize_countries(values)
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    try:
        usage = _site_geoip_country_usage()
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    required = sorted(set(usage) - set(countries))
    if required:
        details = "; ".join(
            f"{code} ({', '.join(sorted(usage[code]))})" for code in required
        )
        return {
            "ok": False,
            "validation_error": True,
            "error": (
                "Countries used by per-site GeoIP policies cannot be removed: "
                + details
            ),
        }
    revision_text = str(revision or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", revision_text):
        return {
            "ok": False,
            "validation_error": True,
            "error": "the GeoIP selection revision is missing or invalid",
        }
    result = _request(
        "geoip-configure",
        {"countries": countries, "revision": revision_text},
    )
    status = result.get("status")
    if isinstance(status, dict):
        _attach_runtime_config(status)
    return result


def reconcile_geoip_runtime() -> dict[str, Any]:
    """Apply current vars.yml GeoIP settings after a confirmed HAProxy apply.

    Country/mode validation still happens in the normal vars workflow. This
    hook only updates the root-managed selection and derived ACL when the
    confirmed ``enable_geoip`` or country list differs from runtime state.
    """
    status = get_geoip_status()
    if not status.get("ok"):
        return {
            "ok": False,
            "error": status.get("error") or "cannot read GeoIP runtime status",
            "status": status,
        }
    if status.get("runtime_config_in_sync"):
        return {
            "ok": True,
            "unchanged": True,
            "message": "GeoIP runtime selection is already in sync",
            "status": status,
        }
    runtime = status.get("runtime_config")
    selection = status.get("selection")
    if not isinstance(runtime, dict) or not runtime.get("available"):
        return {
            "ok": False,
            "error": (runtime or {}).get("error")
            if isinstance(runtime, dict)
            else "runtime GeoIP configuration is unavailable",
            "status": status,
        }
    if not isinstance(selection, dict):
        return {"ok": False, "error": "GeoIP selection is unavailable", "status": status}
    return configure_geoip_countries(
        runtime.get("countries"), selection.get("revision")
    )
