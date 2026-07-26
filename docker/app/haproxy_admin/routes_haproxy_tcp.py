# routes_haproxy_tcp.py
# JSON-эндпоинты для TCP-прокси (страница редактирования).

import traceback
from flask import jsonify, request

from .routes import bp
from .services_haproxy_tcp import save_tcp_from_json, delete_tcp_proxy


@bp.post("/haproxy/tcp/save")
def haproxy_tcp_save():
    """
    Сохранение TCP-прокси (создание/редактирование) через JSON.
    Формат тела:
      {
        "tcp": { ... },           # объект TCP-прокси
        "original_name": "old"    # опционально, если редактируем и переименовываем
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

    try:
        ok, msg = save_tcp_from_json(tcp, original_name=original_name)
    except Exception:
        traceback.print_exc()
        return jsonify({"ok": False, "error": 'Internal error while saving TCP proxy'}), 500

    return jsonify({"ok": ok, ("message" if ok else "error"): msg})


@bp.post("/haproxy/tcp/<name>/delete")
def haproxy_tcp_delete(name):
    """
    Удаление TCP-прокси по имени (JSON-эндпоинт).
    """
    try:
        ok, msg = delete_tcp_proxy(name)
    except Exception:
        traceback.print_exc()
        return jsonify({"ok": False, "error": 'Internal error while deleting TCP proxy'}), 500

    return jsonify({"ok": ok, ("message" if ok else "error"): msg})
