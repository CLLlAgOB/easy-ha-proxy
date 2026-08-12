# routes_monitoring.py
#
# Страница исторического мониторинга. Все маршруты только читают: демон не
# принимает изменяющих команд, поэтому CSRF-токены здесь не нужны.

from __future__ import annotations

import logging

from flask import jsonify, render_template, request

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
