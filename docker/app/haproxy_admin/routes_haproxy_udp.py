# routes_haproxy_udp.py
# Kernel-NAT UDP forwarding (variant A): list/add/delete page + JSON endpoints.

import traceback

from flask import flash, jsonify, redirect, render_template, request, url_for

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request, summarize
from .routes import bp
from .services_haproxy_udp import (
    delete_udp_forward,
    get_udp_forwards_list,
    get_udp_status,
    save_udp_from_json,
)


def _stored_udp(name):
    """The forward as it is on disk, so a record can say what the save changed."""
    if not name:
        return {}
    for forward in get_udp_forwards_list():
        if isinstance(forward, dict) and str(forward.get("name") or "") == name:
            return forward
    return {}


def _record_udp_delete(name, ok, message):
    record_request(
        "udp_forward.delete",
        object_type="udp_forward",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        detail="" if ok else str(message)[:500],
    )


@bp.route("/haproxy/udp", methods=["GET", "POST"])
def haproxy_udp_page():
    """List, add, edit, and delete UDP forwards with synchronous apply."""
    error = None
    edit_forward = None
    original_name = None

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()

        if action == "delete":
            name = (request.form.get("name") or "").strip()
            if not name:
                error = "A UDP forward name is required for deletion"
            else:
                ok, msg = delete_udp_forward(name)
                _record_udp_delete(name, ok, msg)
                if ok:
                    flash(msg, "success")
                    return redirect(url_for("routes.haproxy_udp_page"))
                error = msg
        else:
            original_name = (
                request.form.get("original_name") or ""
            ).strip() or None
            udp_obj = {
                "name": (request.form.get("name") or "").strip(),
                "listen_port": (request.form.get("listen_port") or "").strip(),
                "backend_host": (request.form.get("backend_host") or "").strip(),
                "backend_port": (request.form.get("backend_port") or "").strip(),
                "ban_check": bool(request.form.get("ban_check")),
                "zero_trust": bool(request.form.get("zero_trust")),
                "enabled": bool(request.form.get("enabled")),
            }
            before = _stored_udp(original_name)
            try:
                ok, msg = save_udp_from_json(
                    udp_obj,
                    original_name=original_name,
                )
            except Exception:
                traceback.print_exc()
                ok, msg = False, "Internal error while saving the UDP forward"
            record_request(
                "udp_forward.update" if before else "udp_forward.create",
                object_type="udp_forward",
                object_id=udp_obj["name"],
                result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                summary=summarize(before, udp_obj) if ok else "",
                detail="" if ok else str(msg)[:500],
            )
            if ok:
                flash(msg, "success")
                return redirect(url_for("routes.haproxy_udp_page"))
            error = msg
            edit_forward = udp_obj

    if request.method == "GET":
        original_name = (request.args.get("edit") or "").strip() or None
        if original_name:
            edit_forward = next(
                (
                    item
                    for item in get_udp_forwards_list()
                    if str(item.get("name") or "") == original_name
                ),
                None,
            )
            if edit_forward is None:
                error = f"UDP forward with name={original_name!r} not found"

    return render_template(
        "haproxy_udp.html",
        udp_forwards=get_udp_forwards_list(),
        udp_status=get_udp_status(),
        error=error,
        edit_forward=edit_forward,
        original_name=original_name,
    )


@bp.post("/haproxy/udp/save")
def haproxy_udp_save():
    """Create/edit one UDP forward via JSON (edit form / API)."""
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Invalid JSON: {exc}"}), 400
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "Expected a JSON object"}), 400

    udp = payload.get("udp")
    original_name = (payload.get("original_name") or "").strip() or None
    if not isinstance(udp, dict):
        return jsonify({"ok": False, "error": "The 'udp' field must be an object"}), 400

    name = str(udp.get("name") or original_name or "").strip()
    before = _stored_udp(original_name)

    try:
        ok, msg = save_udp_from_json(udp, original_name=original_name)
    except Exception as exc:
        traceback.print_exc()
        record_request(
            "udp_forward.update" if before else "udp_forward.create",
            object_type="udp_forward",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": "Internal error while saving UDP forward"}), 500

    record_request(
        "udp_forward.update" if before else "udp_forward.create",
        object_type="udp_forward",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=summarize(before, udp) if ok else "",
        detail="" if ok else str(msg)[:500],
    )
    return jsonify({"ok": ok, ("message" if ok else "error"): msg})


@bp.post("/haproxy/udp/<name>/delete")
def haproxy_udp_delete(name):
    """Delete one UDP forward by name (JSON endpoint)."""
    try:
        ok, msg = delete_udp_forward(name)
    except Exception as exc:
        traceback.print_exc()
        _record_udp_delete(name, False, exc)
        return jsonify({"ok": False, "error": "Internal error while deleting UDP forward"}), 500

    _record_udp_delete(name, ok, msg)
    return jsonify({"ok": ok, ("message" if ok else "error"): msg})
