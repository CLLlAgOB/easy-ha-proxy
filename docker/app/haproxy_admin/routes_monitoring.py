# routes_monitoring.py
#
# Страница исторического мониторинга. Читающие маршруты — все, кроме одного:
# подписи каналов задаёт оператор, и этот маршрут защищён как любая другая
# форма (superadmin + CSRF).

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, RESULT_SUCCESS, record_request
from .metricsd_client import MetricsdUnavailable
from .routes import bp
from . import services_live as live
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


def _window():
    """The exact period asked for, or {} to use the preset."""

    return monitoring.normalize_window(
        request.args.get("since"), request.args.get("until")
    )


@bp.get("/api/monitoring/channels")
def api_monitoring_channels():
    """The links this gateway reaches its backends through.

    Not scoped by site on purpose: a link carries every site pointed at it,
    and the question the page answers is how much went through each one.
    """

    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        return jsonify(monitoring.channels(range_key, _window()))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/backends")
def api_monitoring_backends():
    """Traffic per backend over the period, busiest first."""

    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        return jsonify(monitoring.backend_traffic(range_key, _window()))
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
        result = monitoring.save_channel_labels(
            payload.get("labels"), payload.get("hidden")
        )
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
        return jsonify(monitoring.summary(range_key, site, _window()))
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
        return jsonify(monitoring.series(chart, range_key, site, _window()))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/states")
def api_monitoring_states():
    range_key = monitoring.normalize_range(request.args.get("range"))
    try:
        sites = monitoring.list_sites()
        site = monitoring.normalize_site(request.args.get("site"), sites)
        return jsonify(monitoring.states(range_key, site, _window()))
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


@bp.get("/api/monitoring/storage")
def api_monitoring_storage():
    try:
        return jsonify(monitoring.storage())
    except MetricsdUnavailable as exc:
        return jsonify(monitoring.unavailable_payload(exc)), 503


# ---------------------------------------------------------------------------
# Live activity
# ---------------------------------------------------------------------------


@bp.get("/monitoring/live")
def live_activity_page():
    return render_template("live_activity.html", windows=live.WINDOWS)


@bp.get("/api/monitoring/live")
def api_live_activity():
    try:
        return jsonify(live.live_view(request.args))
    except live.LiveUnavailable as exc:
        LOG.warning("live activity unavailable: %s", exc)
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503


@bp.post("/api/monitoring/live/ban")
def api_live_ban():
    """Ban one address by hand from the live page."""
    payload = request.get_json(silent=True) or {}
    ip = str(payload.get("ip") or "").strip()
    drop_allowlist = bool(payload.get("drop_allowlist"))
    # The operator's own address, as HAProxy saw it, so the page can refuse to
    # lock them out.
    from .routes_haproxy_config import _trusted_client_ip

    result = live.ban_address(ip, _trusted_client_ip(), drop_allowlist=drop_allowlist)
    record_request(
        "ban.place",
        object_type="ip",
        object_id=ip[:64],
        result=RESULT_SUCCESS if result.get("ok") else RESULT_FAILURE,
        summary=(
            "dropped from the allow list and banned by hand from the live activity page"
            if drop_allowlist
            else "by hand from the live activity page"
        ),
        detail="" if result.get("ok") else str(result.get("error"))[:300],
    )
    return jsonify(result), (200 if result.get("ok") else 400)
