# routes_runtime.py
#
# Временные операции над серверами HAProxy. Меняющие маршруты требуют
# superadmin и защищены CSRF, как остальные формы приложения.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .routes import bp
from . import services_runtime as runtime

LOG = logging.getLogger("haproxy-admin")


def _superadmin() -> bool:
    return bool(getattr(g, "is_superadmin", False))


def _target(payload: dict) -> str:
    return f"{payload.get('backend')}/{payload.get('server')}"


@bp.get("/haproxy/backends")
def haproxy_backends_page():
    return render_template("haproxy_backends.html", is_superadmin=_superadmin())


@bp.get("/api/haproxy/backends")
def api_haproxy_backends():
    try:
        return jsonify({"ok": True, "backends": runtime.list_backends()})
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("backend listing failed")
        return jsonify({"ok": False, "error": str(exc)}), 502


@bp.post("/api/haproxy/backends/state")
def api_haproxy_backend_state():
    payload = request.get_json(silent=True) or {}
    if not _superadmin():
        record_request(
            "backend.state",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = runtime.set_state(
            payload.get("backend"), payload.get("server"), payload.get("state")
        )
    except runtime.RuntimeError_ as exc:
        record_request(
            "backend.state",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("runtime state change failed")
        record_request(
            "backend.state",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 502
    record_request(
        "backend.state",
        object_type="server",
        object_id=f"{result['backend']}/{result['server']}",
        summary=f"state: {result['state']}",
    )
    return jsonify(result)


@bp.post("/api/haproxy/backends/weight")
def api_haproxy_backend_weight():
    payload = request.get_json(silent=True) or {}
    if not _superadmin():
        record_request(
            "backend.weight",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        result = runtime.set_weight(
            payload.get("backend"), payload.get("server"), payload.get("weight")
        )
    except runtime.RuntimeError_ as exc:
        record_request(
            "backend.weight",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("runtime weight change failed")
        record_request(
            "backend.weight",
            object_type="server",
            object_id=_target(payload),
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "error": str(exc)}), 502
    record_request(
        "backend.weight",
        object_type="server",
        object_id=f"{result['backend']}/{result['server']}",
        summary=f"weight: {result['weight']}",
    )
    return jsonify(result)
