# routes_alerts.py
#
# Раздел «Оповещения». Условия и политика уведомлений живут в
# easy-ha-proxy-alertd; здесь только чтение его состояния и запись настроек.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .alertd_client import (
    AlertdUnavailable,
    alertd_health,
    alertd_history,
    alertd_save_config,
    alertd_send_test,
    alertd_state,
)
from .audit import RESULT_DENIED, RESULT_FAILURE, RESULT_SUCCESS, record_request
from .routes import bp

LOG = logging.getLogger("haproxy-admin")

MAX_LIMIT = 500


def _superadmin() -> bool:
    return bool(getattr(g, "is_superadmin", False))


def _unavailable(exc: Exception):
    # The alert daemon being down is a degraded page, not an error page: the
    # gateway itself is unaffected and the operator needs to be told which.
    LOG.warning("alertd unavailable: %s", exc)
    return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503


def _limit(value, default: int = 100) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_LIMIT, number))


@bp.get("/system/alerts")
def alerts_page():
    return render_template("alerts.html")


@bp.get("/api/alerts/state")
def api_alerts_state():
    try:
        return jsonify(alertd_state(limit=_limit(request.args.get("limit"))))
    except AlertdUnavailable as exc:
        return _unavailable(exc)


@bp.get("/api/alerts/health")
def api_alerts_health():
    try:
        return jsonify(alertd_health())
    except AlertdUnavailable as exc:
        return _unavailable(exc)


@bp.get("/api/alerts/history")
def api_alerts_history():
    params = {
        "limit": _limit(request.args.get("limit")),
        "offset": _limit(request.args.get("offset", 0), default=0),
    }
    for key in ("rule", "severity"):
        value = str(request.args.get(key) or "").strip()
        if value:
            params[key] = value
    try:
        return jsonify(alertd_history(params))
    except AlertdUnavailable as exc:
        return _unavailable(exc)


@bp.post("/api/alerts/config")
def api_alerts_config():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "a JSON object is required"}), 400

    if not _superadmin():
        record_request(
            "alerts.config",
            object_type="alerts",
            object_id="settings",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    try:
        result = alertd_save_config(payload)
    except AlertdUnavailable as exc:
        record_request(
            "alerts.config",
            object_type="alerts",
            object_id="settings",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return _unavailable(exc)

    ok = bool(result.get("ok"))
    # The webhook URL and the header value are secrets, so the record names
    # the fields that were touched and never their values.
    record_request(
        "alerts.config",
        object_type="alerts",
        object_id="settings",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary="fields: " + ", ".join(sorted(str(key) for key in payload)),
        detail="" if ok else str(result.get("error") or "")[:500],
    )
    return jsonify(result), 200 if ok else 400


@bp.post("/api/alerts/test")
def api_alerts_test():
    if not _superadmin():
        record_request(
            "alerts.test",
            object_type="alerts",
            object_id="channels",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    try:
        result = alertd_send_test()
    except AlertdUnavailable as exc:
        record_request(
            "alerts.test",
            object_type="alerts",
            object_id="channels",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return _unavailable(exc)

    ok = bool(result.get("ok"))
    record_request(
        "alerts.test",
        object_type="alerts",
        object_id="channels",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary="delivered: " + (", ".join(result.get("delivered") or []) or "none"),
        detail="" if ok else "; ".join(result.get("errors") or [])[:500],
    )
    return jsonify(result), 200 if ok else 502
