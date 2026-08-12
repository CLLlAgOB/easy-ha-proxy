# routes_audit.py
#
# Просмотр журнала изменений. Только чтение: запись в журнал делают сами
# операции, а править историю нельзя вообще.

from __future__ import annotations

import logging
import time

from flask import jsonify, render_template, request

from .audit import RESULTS, audit_log
from .routes import bp

LOG = logging.getLogger("haproxy-admin")

MAX_LIMIT = 500
RANGES = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "all": 0,
}
DEFAULT_RANGE = "7d"


def _clean(value, allowed=None, limit=120):
    text = str(value or "").strip()[:limit]
    if allowed is not None and text not in allowed:
        return ""
    return text


@bp.get("/system/audit")
def audit_page():
    return render_template("audit.html", ranges=list(RANGES), default_range=DEFAULT_RANGE)


@bp.get("/api/audit/events")
def api_audit_events():
    range_key = _clean(request.args.get("range"), allowed=set(RANGES)) or DEFAULT_RANGE
    window = RANGES[range_key]
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0

    payload = audit_log().query(
        actor=_clean(request.args.get("actor")),
        action=_clean(request.args.get("action")),
        object_type=_clean(request.args.get("object_type"), limit=60),
        result=_clean(request.args.get("result"), allowed=set(RESULTS)),
        since=int(time.time()) - window if window else 0,
        limit=max(1, min(limit, MAX_LIMIT)),
        offset=max(0, offset),
    )
    payload["ok"] = True
    payload["range"] = range_key
    return jsonify(payload)


@bp.get("/api/audit/filters")
def api_audit_filters():
    log = audit_log()
    return jsonify(
        {
            "ok": True,
            "actors": log.distinct("actor"),
            "actions": log.distinct("action"),
            "object_types": log.distinct("object_type"),
            "results": list(RESULTS),
        }
    )


@bp.get("/api/audit/status")
def api_audit_status():
    return jsonify({"ok": True, "audit": audit_log().stats()})
