# routes_monitoring.py
#
# Страница исторического мониторинга. Читающие маршруты — все, кроме одного:
# подписи каналов задаёт оператор, и этот маршрут защищён как любая другая
# форма (superadmin + CSRF).

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .metricsd_client import MetricsdUnavailable
from .routes import bp
from . import services_monitoring as monitoring

LOG = logging.getLogger("haproxy-admin")


@bp.get("/monitoring")
def monitoring_page():
    return render_template(
        "monitoring.html",
        ranges=monitoring.RANGES,
        default_range=monitoring.DEFAULT_RANGE,
    )


@bp.get("/api/monitoring/sites")
def api_monitoring_sites():
    try:
        return jsonify({"ok": True, "sites": monitoring.list_sites()})
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/channels")
def api_monitoring_channels():
    """The links this gateway reaches its backends through.

    Not scoped by site on purpose: a link carries every site pointed at it,
    and the question the page answers is how much went through each one.
    """

    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        return jsonify(monitoring.channels(range_key))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.post("/api/monitoring/channels/labels")
def api_monitoring_channel_labels():
    payload = request.get_json(silent=True) or {}
    if not getattr(g, "is_superadmin", False):
        record_request(
            "monitoring.channel_labels",
            object_type="monitoring",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = monitoring.save_channel_labels(payload.get("labels"))
    except ValueError as exc:
        record_request(
            "monitoring.channel_labels",
            object_type="monitoring",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503
    record_request(
        "monitoring.channel_labels",
        object_type="monitoring",
        after=result.get("labels"),
        detail="uplink names changed",
    )
    return jsonify(result)


@bp.get("/api/monitoring/summary")
def api_monitoring_summary():
    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        sites = monitoring.list_sites()
        site = monitoring.normalize_site(request.args.get("site"), sites)
        return jsonify(monitoring.summary(range_key, site))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/series")
def api_monitoring_series():
    chart = monitoring.normalize_chart(request.args.get("chart"))
    if not chart:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "unknown chart",
                    "available": list(monitoring.CHARTS),
                }
            ),
            400,
        )
    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        sites = monitoring.list_sites()
        site = monitoring.normalize_site(request.args.get("site"), sites)
        return jsonify(monitoring.series(chart, range_key, site))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/states")
def api_monitoring_states():
    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        sites = monitoring.list_sites()
        site = monitoring.normalize_site(request.args.get("site"), sites)
        return jsonify(monitoring.states(range_key, site))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/storage")
def api_monitoring_storage():
    try:
        return jsonify(monitoring.storage())
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503
