# routes_alerts.py
#
# The "Alerts" section. The conditions and the notification policy live in
# easy-ha-proxy-alertd; here its state is only read and its settings written.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .alertd_client import (
    AlertdUnavailable,
    alertd_delete_history,
    alertd_dismiss,
    alertd_health,
    alertd_history,
    alertd_portal,
    alertd_quieten,
    alertd_retry_mail,
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


def _offset(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(1_000_000, number))


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
        # A page offset starts at 0; the limit's floor of 1 hid the newest entry.
        "offset": _offset(request.args.get("offset")),
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


@bp.get("/api/alerts/portal")
def api_alerts_portal():
    """What the header of every page shows: open alerts above its floor."""
    try:
        return jsonify(alertd_portal())
    except AlertdUnavailable as exc:
        return _unavailable(exc)


def _alert_key(payload) -> tuple:
    rule = str(payload.get("rule") or "").strip()[:80]
    subject = str(payload.get("subject") or "").strip()[:200]
    return rule, subject


@bp.post("/api/alerts/quieten")
def api_alerts_quieten():
    """Acknowledge an alert, mute it for a while, or undo either.

    Any operator may: it is how a person on duty says "I have it". It changes
    what is sent and shown, never whether the condition is watched.
    """
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "a JSON object is required"}), 400
    rule, subject = _alert_key(payload)
    mode = str(payload.get("mode") or "")
    body = {"rule": rule, "subject": subject, "mode": mode,
            "by": getattr(g, "remote_user", "") or ""}
    if "seconds" in payload:
        body["seconds"] = payload.get("seconds")
    try:
        result = alertd_quieten(body)
    except AlertdUnavailable as exc:
        return _unavailable(exc)
    ok = bool(result.get("ok"))
    record_request(
        "alerts.quieten",
        object_type="alert",
        object_id=f"{rule}:{subject}",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=f"mode: {mode}" + (f", seconds: {body['seconds']}" if "seconds" in body else ""),
        detail="" if ok else str(result.get("error") or "")[:300],
    )
    return jsonify(result), 200 if ok else 400


@bp.post("/api/alerts/dismiss")
def api_alerts_dismiss():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "a JSON object is required"}), 400
    rule, subject = _alert_key(payload)
    try:
        result = alertd_dismiss({"rule": rule, "subject": subject,
                                 "by": getattr(g, "remote_user", "") or ""})
    except AlertdUnavailable as exc:
        return _unavailable(exc)
    ok = bool(result.get("ok"))
    record_request(
        "alerts.dismiss",
        object_type="alert",
        object_id=f"{rule}:{subject}",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        detail="" if ok else str(result.get("error") or "")[:300],
    )
    return jsonify(result), 200 if ok else 400


@bp.post("/api/alerts/mail/retry")
def api_alerts_mail_retry():
    """Have the mail relay try what it holds now instead of at its next turn.

    Any operator may: it sends nothing that was not already on its way.
    """
    try:
        result = alertd_retry_mail()
    except AlertdUnavailable as exc:
        return _unavailable(exc)
    ok = bool(result.get("ok"))
    record_request(
        "alerts.mail_retry",
        object_type="alert",
        object_id="mail.delivery_failed:relay",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        detail="" if ok else str(result.get("error") or "")[:300],
    )
    return jsonify(result), 200 if ok else 400


@bp.post("/api/alerts/history/delete")
def api_alerts_history_delete():
    """Remove alert history: chosen rows, or all of it. A superadmin's call,
    like every other change that removes a record."""
    payload = request.get_json(silent=True) or {}
    if not _superadmin():
        record_request(
            "alerts.history_delete",
            object_type="alerts",
            object_id="history",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "a JSON object is required"}), 400
    body = {}
    if payload.get("all") is True:
        body["all"] = True
    elif isinstance(payload.get("ids"), list):
        body["ids"] = payload["ids"][:1000]
    try:
        result = alertd_delete_history(body)
    except AlertdUnavailable as exc:
        return _unavailable(exc)
    ok = bool(result.get("ok"))
    record_request(
        "alerts.history_delete",
        object_type="alerts",
        object_id="history",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=("all" if body.get("all") else f"rows: {len(body.get('ids') or [])}")
        + (f", deleted: {result.get('deleted')}" if ok else ""),
        detail="" if ok else str(result.get("error") or "")[:300],
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
