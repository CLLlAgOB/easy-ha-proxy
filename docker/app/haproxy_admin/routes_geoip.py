"""Superadmin page and JSON endpoints for local GeoIP management."""

from __future__ import annotations

from flask import jsonify, render_template, request

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request
from .routes import bp
from .services_geoip import (
    configure_geoip_countries,
    get_geoip_status,
    set_geoip_schedule,
    update_geoip_now,
)


def _audited(action, result, *, object_id="", summary=""):
    """Record the outcome and hand the daemon's answer back unchanged."""
    ok = bool(isinstance(result, dict) and result.get("ok"))
    record_request(
        action,
        object_type="geoip",
        object_id=object_id,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=summary if ok else "",
        detail="" if ok else str((result or {}).get("error") or "")[:500],
    )
    return result


def _response(result):
    if result.get("ok"):
        return jsonify(result)
    if result.get("conflict"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status


@bp.get("/haproxy/geoip")
def haproxy_geoip_page():
    return render_template("haproxy_geoip.html")


@bp.get("/haproxy/geoip/status")
def haproxy_geoip_status():
    return _response(get_geoip_status())


@bp.post("/haproxy/geoip/update")
def haproxy_geoip_update():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or not set(payload).issubset({"force"}):
        return jsonify({"ok": False, "error": "invalid request fields"}), 400
    force = bool(payload.get("force", False))
    return _response(
        _audited(
            "geoip.update",
            update_geoip_now(force),
            summary=f"force: {force}",
        )
    )


@bp.post("/haproxy/geoip/countries")
def haproxy_geoip_countries():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or set(payload) != {"countries", "revision"}:
        return jsonify({"ok": False, "error": "countries and revision are required"}), 400
    countries = payload.get("countries")
    return _response(
        _audited(
            "geoip.countries",
            configure_geoip_countries(countries, payload.get("revision")),
            summary=(
                "countries: " + ", ".join(str(c) for c in countries)
                if isinstance(countries, list)
                else ""
            ),
        )
    )


@bp.post("/haproxy/geoip/schedule")
def haproxy_geoip_schedule():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or set(payload) != {"schedule"}:
        return jsonify({"ok": False, "error": "schedule is required"}), 400
    schedule = payload.get("schedule")
    return _response(
        _audited(
            "geoip.schedule",
            set_geoip_schedule(schedule),
            summary=f"schedule: {schedule!r}",
        )
    )
