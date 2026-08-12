# routes_security.py
#
# Раздел Adaptive protection. Только чтение: демон в этом релизе не принимает
# изменяющих команд и ничего не банит.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .guardd_client import GuarddUnavailable
from .routes import bp
from . import services_security as security

LOG = logging.getLogger("haproxy-admin")


@bp.get("/security/adaptive")
def adaptive_protection_page():
    return render_template(
        "adaptive_protection.html", event_types=security.EVENT_TYPES
    )


@bp.get("/api/security/adaptive/shadow")
def api_adaptive_shadow():
    try:
        return jsonify(security.shadow(request.args))
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503


@bp.get("/api/security/adaptive/ip")
def api_adaptive_ip():
    address = security.valid_ip(request.args.get("ip"))
    if not address:
        return jsonify({"ok": False, "error": "invalid ip"}), 400
    try:
        return jsonify(security.address(address, request.args))
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503


@bp.get("/api/security/adaptive/health")
def api_adaptive_health():
    try:
        return jsonify(security.health())
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503


@bp.post("/api/security/adaptive/mode")
def api_adaptive_mode():
    """Switch between observing and enforcing.

    The only mutating route in this section, so it is superadmin-only and CSRF
    protected like every other state-changing form in the application.
    """

    payload = request.get_json(silent=True) or {}
    requested = str(payload.get("mode") or "")
    if not getattr(g, "is_superadmin", False):
        record_request(
            "adaptive.mode",
            object_type="adaptive_protection",
            object_id=requested,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = security.set_mode(requested)
    except ValueError as exc:
        record_request(
            "adaptive.mode",
            object_type="adaptive_protection",
            object_id=requested,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except GuarddUnavailable as exc:
        record_request(
            "adaptive.mode",
            object_type="adaptive_protection",
            object_id=requested,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(security.unavailable_payload(exc)), 503
    # Switching to enforce starts banning, and switching away lifts every ban
    # it applied: both belong in the record with their counts.
    record_request(
        "adaptive.mode",
        object_type="adaptive_protection",
        object_id=result.get("mode", ""),
        before={"mode": result.get("previous")},
        after={"mode": result.get("mode")},
        detail=(
            f"banned {len(result.get('applied') or [])}, "
            f"lifted {len(result.get('lifted') or [])}"
        ),
    )
    LOG.warning(
        "Adaptive protection mode set to %s by %s",
        result.get("mode"),
        getattr(g, "remote_user", "unknown"),
    )
    return jsonify(result)
