# routes_backend_presets.py
# Backend sets: one page to keep named address lists that sites, TCP proxies
# and UDP forwards can pick instead of typing the addresses again.

import traceback

from flask import flash, redirect, render_template, request, url_for

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request
from .backend_presets import (
    MAX_SERVERS,
    delete_preset,
    find,
    load_presets,
    preset_revision,
    save_preset,
    usage,
)
from .routes import bp


@bp.app_context_processor
def _backend_sets_for_templates():
    """Editors list the sets in their pickers; read only when a page asks."""
    return {"backend_presets_list": load_presets}


def _form_preset():
    hosts = request.form.getlist("server_host")
    roles = request.form.getlist("server_role")
    weights = request.form.getlist("server_weight")
    notes = request.form.getlist("server_note")
    servers = []
    for index, host in enumerate(hosts[:MAX_SERVERS + 4]):
        servers.append({
            "host": host.strip(),
            "role": roles[index] if index < len(roles) else "primary",
            "weight": weights[index].strip() if index < len(weights) else "",
            "note": notes[index] if index < len(notes) else "",
        })
    return {"name": (request.form.get("name") or "").strip(), "servers": servers}


@bp.route("/haproxy/backend-sets", methods=["GET", "POST"])
def backend_presets_page():
    """List, create, edit and delete backend sets."""
    error = None
    form_preset = None
    original_name = None
    revision = None

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()
        if action == "delete":
            name = (request.form.get("name") or "").strip()
            try:
                ok, msg = delete_preset(name)
            except Exception:
                traceback.print_exc()
                ok, msg = False, "Internal error while deleting the backend set"
            record_request(
                "backend_set.delete", object_type="backend_set", object_id=name,
                result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                detail="" if ok else str(msg)[:500],
            )
            if ok:
                flash(msg, "success")
                return redirect(url_for("routes.backend_presets_page"))
            error = msg
        else:
            original_name = (request.form.get("original_name") or "").strip() or None
            revision = (request.form.get("revision") or "").strip() or None
            form_preset = _form_preset()
            try:
                ok, msg = save_preset(form_preset, original_name, revision)
            except Exception:
                traceback.print_exc()
                ok, msg = False, "Internal error while saving the backend set"
            record_request(
                "backend_set.update" if original_name else "backend_set.create",
                object_type="backend_set", object_id=form_preset["name"],
                result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                summary=", ".join(
                    f"{s['host']} ({s['role']})" for s in form_preset["servers"] if s["host"]
                )[:500] if ok else "",
                detail="" if ok else str(msg)[:500],
            )
            if ok:
                flash(msg, "success")
                return redirect(url_for("routes.backend_presets_page"))
            error = msg

    presets = load_presets()
    if request.method == "GET":
        original_name = (request.args.get("edit") or "").strip() or None
        if original_name:
            form_preset = find(presets, original_name)
            if form_preset is None:
                error = f"Backend set {original_name!r} was not found"
                original_name = None
            else:
                revision = preset_revision(form_preset)

    return render_template(
        "backend_presets.html",
        presets=presets,
        used=usage(),
        error=error,
        form_preset=form_preset or {"name": "", "servers": []},
        original_name=original_name,
        revision=revision,
        max_servers=MAX_SERVERS,
    )
