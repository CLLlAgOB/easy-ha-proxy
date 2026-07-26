"""Superadmin page and JSON endpoints for local GeoIP management."""

from __future__ import annotations

from flask import jsonify, render_template, request

from .routes import bp
from .services_geoip import (
    configure_geoip_countries,
    get_geoip_status,
    update_geoip_now,
)


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
    return _response(update_geoip_now(payload.get("force", False)))


@bp.post("/haproxy/geoip/countries")
def haproxy_geoip_countries():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or set(payload) != {"countries", "revision"}:
        return jsonify({"ok": False, "error": "countries and revision are required"}), 400
    return _response(
        configure_geoip_countries(payload.get("countries"), payload.get("revision"))
    )
