# routes_trash.py
#
# The trash: deleted sites, TCP proxies and UDP forwards (kept by the panel)
# and deleted certificates, authorities and their settings (kept by certd on
# the host), on one page. Everything here is superadmin-only, as the
# deletions themselves are, and every change is in the change log.

from __future__ import annotations

import logging
from typing import Any, Dict, List

from flask import g, jsonify, render_template, request

from . import trash
from .audit import RESULT_DENIED, RESULT_FAILURE, RESULT_SUCCESS, record_request
from .certd_client import CertdUnavailable, trash_list, trash_purge, trash_restore, trash_settings
from .routes import bp

LOG = logging.getLogger("haproxy-admin")
SOURCES = ("panel", "certd")


def _superadmin() -> bool:
    return bool(getattr(g, "is_superadmin", False))


def _denied(action: str, object_id: str = ""):
    record_request(
        action,
        object_type="trash",
        object_id=object_id,
        result=RESULT_DENIED,
        detail="superadmin required",
    )
    return jsonify({"ok": False, "error": "superadmin required"}), 403


@bp.before_app_request
def _start_trash_purger():
    # The term is kept on a panel nobody opens, too.
    trash.ensure_purger()


def _certd_items() -> Dict[str, Any]:
    try:
        payload = trash_list()
    except CertdUnavailable as exc:
        LOG.warning("certd unavailable: %s", exc)
        return {"items": [], "error": "The certificate service does not answer", "keep_days": None}
    if not payload.get("ok"):
        return {"items": [], "error": str(payload.get("error") or "unknown error"), "keep_days": None}
    items: List[Dict[str, Any]] = []
    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        shown = details.get("domains") or []
        detail = ", ".join(str(name) for name in shown if name) if isinstance(shown, list) else ""
        for key in ("provider", "lineage", "host"):
            if not detail and details.get(key):
                detail = str(details[key])
        items.append({
            "source": "certd",
            "id": str(item.get("id") or ""),
            "kind": str(item.get("kind") or ""),
            "name": str(item.get("name") or ""),
            "detail": detail,
            "not_after": details.get("not_after") or "",
            "deleted_at": int(item.get("deleted_at") or 0),
            "deleted_by": str(item.get("deleted_by") or ""),
            "expires_at": int(item.get("expires_at") or 0),
        })
    keep_days = payload.get("keep_days")
    return {"items": items, "error": "", "keep_days": keep_days if isinstance(keep_days, int) else None}


def _json_body() -> Dict[str, Any]:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


@bp.get("/haproxy/trash")
def trash_page():
    return render_template("trash.html", max_keep_days=trash.MAX_KEEP_DAYS)


@bp.get("/api/haproxy/trash")
def api_trash_list():
    if not _superadmin():
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    try:
        items, panel_keep_days = trash.list_with_term()
        panel_error = ""
    except (OSError, trash.TrashError) as exc:
        LOG.warning("panel trash unreadable: %s", exc)
        items, panel_keep_days, panel_error = (
            [],
            trash.keep_days(),
            "The trash of sites and forwards cannot be read",
        )
    certd = _certd_items()
    merged = items + certd["items"]
    merged.sort(key=lambda item: (item["deleted_at"], item["id"]), reverse=True)
    return jsonify({
        "ok": True,
        "items": merged,
        "keep_days": panel_keep_days,
        # Shown when certd keeps its items on another term than the panel's
        # (it was down when the term was last saved): saving again aligns them.
        "certd_keep_days": certd["keep_days"],
        "errors": [message for message in (panel_error, certd["error"]) if message],
    })


@bp.post("/api/haproxy/trash/settings")
def api_trash_settings():
    payload = _json_body()
    if not _superadmin():
        return _denied("trash.settings", "settings")
    try:
        days = trash.normalize_keep_days(payload.get("keep_days"))
    except trash.TrashError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    # Both keepers under one lock: two changes interleaved could otherwise
    # each answer "saved" and leave the panel and certd on different terms.
    try:
        with trash.settings_lock():
            days = trash.set_keep_days(days)
            error = ""
            try:
                answer = trash_settings(days)
                if not answer.get("ok"):
                    error = str(answer.get("error") or "certd refused")
            except CertdUnavailable as exc:
                LOG.warning("certd unavailable: %s", exc)
                error = "The certificate service does not answer"
    except trash.TrashError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except OSError as exc:
        LOG.warning("trash settings not saved: %s", exc)
        return jsonify({"ok": False, "error": "The trash settings could not be saved"}), 500
    record_request(
        "trash.settings",
        object_type="trash",
        object_id="settings",
        result=RESULT_FAILURE if error else RESULT_SUCCESS,
        summary="kept until emptied" if days == 0 else f"kept for {days} days",
        detail=error[:500],
    )
    if error:
        return jsonify({
            "ok": False,
            "keep_days": days,
            "error": f"Saved for sites and forwards, but not for certificates: {error}",
            "partial": True,
        }), 502
    return jsonify({"ok": True, "keep_days": days})


def _target() -> tuple[str, str]:
    payload = _json_body()
    return str(payload.get("source") or ""), str(payload.get("id") or "")


@bp.post("/api/haproxy/trash/restore")
def api_trash_restore():
    source, item_id = _target()
    if not _superadmin():
        return _denied("trash.restore", item_id)
    if source not in SOURCES or not item_id:
        return jsonify({"ok": False, "error": "source and id are required"}), 400
    try:
        if source == "panel":
            result = trash.restore(item_id)
        else:
            result = trash_restore(item_id)
    except trash.TrashError as exc:
        record_request(
            "trash.restore",
            object_type="trash",
            object_id=item_id,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": str(exc)}), 404
    except CertdUnavailable as exc:
        LOG.warning("certd unavailable: %s", exc)
        record_request(
            "trash.restore",
            object_type="trash",
            object_id=item_id,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503
    record_request(
        "trash.restore",
        object_type=str(result.get("kind") or "trash"),
        object_id=str(result.get("name") or item_id),
        result=RESULT_SUCCESS if result.get("ok") else RESULT_FAILURE,
        detail="" if result.get("ok") else str(result.get("error") or "")[:500],
    )
    if not result.get("ok"):
        return jsonify(result), 409
    if source == "panel" and result.get("kind") in ("site", "tcp"):
        result["apply_needed"] = True
    if source == "certd" and result.get("kind") == "haproxy_cert":
        result["apply_needed"] = True
    return jsonify(result)


@bp.post("/api/haproxy/trash/delete")
def api_trash_delete():
    source, item_id = _target()
    if not _superadmin():
        return _denied("trash.delete", item_id)
    if source not in SOURCES or not item_id:
        return jsonify({"ok": False, "error": "source and id are required"}), 400
    try:
        result = trash.remove(item_id) if source == "panel" else trash_purge(item_id)
    except trash.TrashError as exc:
        record_request(
            "trash.delete",
            object_type="trash",
            object_id=item_id,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": str(exc)}), 404
    except CertdUnavailable as exc:
        LOG.warning("certd unavailable: %s", exc)
        record_request(
            "trash.delete",
            object_type="trash",
            object_id=item_id,
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503
    if not result.get("ok"):
        record_request(
            "trash.delete",
            object_type=str(result.get("kind") or "trash"),
            object_id=str(result.get("name") or item_id),
            result=RESULT_FAILURE,
            detail=str(result.get("error") or "")[:500],
        )
        return jsonify(result), 400
    record_request(
        "trash.delete",
        object_type=str(result.get("kind") or "trash"),
        object_id=str(result.get("name") or item_id),
        detail="deleted for good from the trash",
    )
    return jsonify(result)


@bp.post("/api/haproxy/trash/empty")
def api_trash_empty():
    if not _superadmin():
        return _denied("trash.empty")
    errors = []
    removed = 0
    try:
        panel_removed, panel_failed = trash.empty_detailed()
        removed += panel_removed
        if panel_failed:
            errors.append(
                f"{len(panel_failed)} items could not be deleted: " + "; ".join(panel_failed)
            )
    except (OSError, trash.TrashError) as exc:
        errors.append(str(exc))
    try:
        answer = trash_purge(everything=True)
        # What certd really deleted, also when some of it could not be.
        removed += int(answer.get("removed") or 0)
        if not answer.get("ok"):
            errors.append(str(answer.get("error") or "certd refused"))
    except CertdUnavailable as exc:
        errors.append(f"certd unavailable: {exc}")
    record_request(
        "trash.empty",
        object_type="trash",
        object_id="all",
        result=RESULT_FAILURE if errors else RESULT_SUCCESS,
        detail=(f"{removed} items deleted for good" + ("; " + "; ".join(errors) if errors else ""))[:500],
    )
    return jsonify({"ok": not errors, "removed": removed, "error": "; ".join(errors)}), (502 if errors else 200)
