# routes_config_history.py
#
# Просмотр истории конфигурации. Только чтение: версии создаёт подтверждение
# транзакции, а не запрос из интерфейса.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .routes import bp
from . import services_config_history as history

LOG = logging.getLogger("haproxy-admin")


def _client_ip() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")
    return (forwarded[0] if forwarded else "").strip() or (request.remote_addr or "")


@bp.get("/haproxy/config/history")
def config_history_page():
    return render_template("config_history.html")


@bp.get("/api/haproxy/config/versions")
def api_config_versions():
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    try:
        return jsonify({"ok": True, "versions": history.list_versions(limit)})
    except history.HistoryUnavailable as exc:
        return jsonify(history.unavailable_payload(exc)), 503


@bp.get("/api/haproxy/config/versions/diff")
def api_config_version_diff():
    left = str(request.args.get("left") or "").strip()
    right = str(request.args.get("right") or history.CURRENT).strip()
    if not left:
        return jsonify({"ok": False, "error": "left version is required"}), 400
    try:
        payload = history.diff(left, right)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except history.HistoryUnavailable as exc:
        return jsonify(history.unavailable_payload(exc)), 503
    payload["ok"] = True
    return jsonify(payload)


@bp.post("/api/haproxy/config/versions/restore")
def api_config_version_restore():
    """Put a stored version back through the normal guarded apply.

    The only route in this section that changes anything, so it is
    superadmin-only, CSRF protected and audited. Everything that makes an apply
    safe -- validation, the admin-lockout guard, the confirmation window and
    automatic rollback -- comes from the existing path, not from here.
    """

    payload = request.get_json(silent=True) or {}
    version_id = str(payload.get("version") or "").strip()

    if not getattr(g, "is_superadmin", False):
        record_request(
            "config.restore",
            object_type="config_version",
            object_id=version_id,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    if not version_id:
        return jsonify({"ok": False, "error": "version is required"}), 400

    try:
        result = history.restore(version_id, client_ip=_client_ip())
    except history.RestoreError as exc:
        record_request(
            "config.restore",
            object_type="config_version",
            object_id=version_id,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(
            {"ok": False, "error": str(exc), "error_code": exc.error_code}
        ), 400
    except history.HistoryUnavailable as exc:
        record_request(
            "config.restore",
            object_type="config_version",
            object_id=version_id,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(history.unavailable_payload(exc)), 503

    # Recorded as started, not as finished: the change still has to be
    # confirmed before the deadline or it rolls itself back.
    record_request(
        "config.restore",
        object_type="config_version",
        object_id=version_id,
        summary="restore started, awaiting confirmation",
        detail=str(result.get("state") or ""),
    )
    return jsonify(result)
