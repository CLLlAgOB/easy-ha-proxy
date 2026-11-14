# routes_haproxy_tcp.py
# JSON endpoints for the TCP proxies (the edit page).

import traceback
from flask import jsonify, request

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request, summarize
from .routes import bp
from .services_haproxy_config import StaleEntry, source_lock
from .services_haproxy_tcp import (
    delete_tcp_proxy,
    get_tcp_proxies_list,
    save_tcp_from_json,
    tcp_revision,
)


def _stored_tcp(name):
    """The proxy as it is on disk, so a record can say what the save changed."""
    if not name:
        return {}
    for proxy in get_tcp_proxies_list():
        if isinstance(proxy, dict) and proxy.get("name") == name:
            return proxy
    return {}


@bp.post("/haproxy/tcp/save")
def haproxy_tcp_save():
    """
    Saves a TCP proxy (create or edit) from JSON.
    Body:
      {
        "tcp": { ... },           # the TCP proxy object
        "original_name": "old"    # optional, when editing and renaming
      }
    """
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid JSON: {e}"}), 400

    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": 'Expected a JSON object'}), 400

    tcp = payload.get("tcp")
    original_name = (payload.get("original_name") or "").strip() or None

    if not isinstance(tcp, dict):
        return jsonify({"ok": False, "error": "The 'tcp' field must be an object"}), 400

    name = str(tcp.get("name") or original_name or "").strip()
    expected_revision = payload.get("revision") or None
    before = {}
    revision = None

    try:
        with source_lock("tcp"):
            before = _stored_tcp(original_name)
            ok, msg = save_tcp_from_json(
                tcp, original_name=original_name, expected_revision=expected_revision
            )
            if ok:
                revision = tcp_revision(name)
    except StaleEntry as exc:
        record_request(
            "tcp_proxy.update",
            object_type="tcp_proxy",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "conflict": True, "error": str(exc)}), 409
    except Exception as exc:
        traceback.print_exc()
        record_request(
            "tcp_proxy.update" if before else "tcp_proxy.create",
            object_type="tcp_proxy",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": 'Internal error while saving TCP proxy'}), 500

    record_request(
        "tcp_proxy.update" if before else "tcp_proxy.create",
        object_type="tcp_proxy",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=summarize(before, tcp) if ok else "",
        detail="" if ok else str(msg)[:500],
    )
    answer = {"ok": ok, ("message" if ok else "error"): msg}
    if revision:
        answer["revision"] = revision
    return jsonify(answer)


@bp.post("/haproxy/tcp/<name>/delete")
def haproxy_tcp_delete(name):
    """
    Deletes a TCP proxy by name (a JSON endpoint).
    """
    try:
        ok, msg = delete_tcp_proxy(name)
    except Exception as exc:
        traceback.print_exc()
        record_request(
            "tcp_proxy.delete",
            object_type="tcp_proxy",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": 'Internal error while deleting TCP proxy'}), 500

    record_request(
        "tcp_proxy.delete",
        object_type="tcp_proxy",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        detail="" if ok else str(msg)[:500],
    )
    return jsonify({"ok": ok, ("message" if ok else "error"): msg})
