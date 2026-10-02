# routes_security.py
#
# Раздел Adaptive protection и страница правил обнаружения. Меняют состояние
# только два маршрута: переключение режима и правила оператора; оба требуют
# superadmin и CSRF, как любая другая форма в приложении.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, RESULT_SUCCESS, record_request
from .guardd_client import GuarddUnavailable
from .routes import bp
from . import services_security as security

LOG = logging.getLogger("haproxy-admin")


@bp.get("/security/adaptive")
def adaptive_protection_page():
    return render_template(
        "adaptive_protection.html", event_types=security.EVENT_TYPES
    )


@bp.get("/security/detection-rules")
def detection_rules_page():
    """The rules, on their own page.

    They were a card on the shadow-review page, which put a list of eighty
    signatures between the operator and the numbers they came to read.
    """

    return render_template("detection_rules.html")


@bp.get("/api/security/detection-rules")
def api_detection_rules():
    try:
        return jsonify(security.detection_rules())
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503


@bp.post("/api/security/detection-rules")
def api_set_detection_rules():
    """Store the operator's own rules.

    Changing what the engine bans by is exactly as consequential as changing
    the mode, so it is guarded the same way.
    """

    payload = request.get_json(silent=True) or {}
    if not getattr(g, "is_superadmin", False):
        record_request(
            "adaptive.rules",
            object_type="detection_rules",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    try:
        before = security.detection_rules()
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503

    try:
        result = security.set_detection_rules(payload)
    except ValueError as exc:
        record_request(
            "adaptive.rules",
            object_type="detection_rules",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except GuarddUnavailable as exc:
        record_request(
            "adaptive.rules",
            object_type="detection_rules",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(security.unavailable_payload(exc)), 503

    # A rule added or suppressed here changes who gets banned, so the record
    # carries both sides rather than a count.
    record_request(
        "adaptive.rules",
        object_type="detection_rules",
        before={"added": before.get("added"), "disabled": before.get("disabled")},
        after={"added": result.get("added"), "disabled": result.get("disabled")},
        detail=(
            f"{len(result.get('added') or {})} added, "
            f"{len(result.get('disabled') or [])} suppressed"
        ),
    )
    LOG.warning(
        "Detection rules changed by %s", getattr(g, "remote_user", "unknown")
    )
    return jsonify(result)


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


@bp.post("/api/security/adaptive/durations")
def api_adaptive_ban_durations():
    """Set how long an adaptive ban lasts, by strike.

    Mutating and it decides how long real visitors stay locked out, so it is
    superadmin-only, CSRF protected and recorded, exactly like the mode.
    """

    payload = request.get_json(silent=True) or {}
    requested = payload.get("durations")
    if not getattr(g, "is_superadmin", False):
        record_request(
            "adaptive.ban_durations",
            object_type="adaptive_protection",
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = security.set_ban_durations(requested)
    except ValueError as exc:
        record_request(
            "adaptive.ban_durations",
            object_type="adaptive_protection",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except GuarddUnavailable as exc:
        record_request(
            "adaptive.ban_durations",
            object_type="adaptive_protection",
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(security.unavailable_payload(exc)), 503
    record_request(
        "adaptive.ban_durations",
        object_type="adaptive_protection",
        after={"durations": result.get("ban_durations_seconds")},
    )
    LOG.warning(
        "Adaptive ban durations set to %s by %s",
        result.get("ban_durations_seconds"),
        getattr(g, "remote_user", "unknown"),
    )
    return jsonify(result)


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


# ---------------------------------------------------------------------------
# Log Explorer
# ---------------------------------------------------------------------------


@bp.get("/security/requests")
def request_log_page():
    return render_template("request_log.html")


@bp.get("/api/security/requests")
def api_request_log():
    try:
        return jsonify(security.requests(request.args))
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503


@bp.post("/api/security/requests/enabled")
def api_request_log_enabled():
    """Start or stop recording requests.

    Superadmin only and audited, like the enforcement switch: this decides
    whether the gateway keeps a record of what every visitor asked for.
    """
    payload = request.get_json(silent=True) or {}
    wanted = bool(payload.get("enabled"))
    if not getattr(g, "is_superadmin", False):
        record_request(
            "request_log.enabled",
            object_type="request_log",
            object_id=str(wanted).lower(),
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = security.set_request_log(wanted)
    except GuarddUnavailable as exc:
        record_request(
            "request_log.enabled",
            object_type="request_log",
            object_id=str(wanted).lower(),
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify(security.unavailable_payload(exc)), 503
    record_request(
        "request_log.enabled",
        object_type="request_log",
        object_id=str(wanted).lower(),
        after={"enabled": result.get("enabled")},
        result=RESULT_SUCCESS,
        summary="recording requests" if result.get("enabled") else "recording stopped",
    )
    return jsonify(result)


@bp.get("/api/security/requests/status")
def api_request_log_status():
    try:
        return jsonify(security.requests_status())
    except GuarddUnavailable as exc:
        return jsonify(security.unavailable_payload(exc)), 503
