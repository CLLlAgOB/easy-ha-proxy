# routes_health.py

from __future__ import annotations

import logging

from flask import g, render_template, request, jsonify

from .routes import bp
from .healthd_client import (
    healthd_status,
    healthd_events,
    healthd_logs_systemd,
    healthd_recent_systemd,
    healthd_logs_docker,
    healthd_capabilities,
    healthd_control,
)

LOG = logging.getLogger("haproxy-admin")


@bp.get("/system/health")
def system_health_page():
    return render_template("health.html", is_superadmin=_is_superadmin())


def _is_superadmin() -> bool:
    """Use the identity already authenticated by the application boundary."""
    return bool(getattr(g, "is_superadmin", False))


@bp.get("/api/control-plane-health")
def api_control_plane_health():
    """Minimal HAProxy-routed readiness endpoint used by guarded config apply."""
    return jsonify({"ok": True, "service": "haproxy-admin"})


@bp.get("/api/health/status")
def api_health_status():
    refresh = request.args.get("refresh", "0") == "1"
    try:
        data = healthd_status(refresh=refresh)
        return jsonify(data)
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd status error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.get("/api/health/events")
def api_health_events():
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    try:
        data = healthd_events(limit=limit)
        return jsonify(data)
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd events error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.get("/api/health/logs/systemd")
def api_health_logs_systemd():
    unit = (request.args.get("unit", "") or "").strip()
    if not unit:
        return jsonify({"ok": False, "error": "unit is required"}), 400

    try:
        tail = int(request.args.get("tail", "200"))
        since = int(request.args.get("since", "3600"))
    except ValueError:
        tail, since = 200, 3600

    try:
        data = healthd_logs_systemd(unit=unit, tail=tail, since=since)
        return jsonify(data)
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd logs systemd error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.get("/api/health/recent-systemd")
def api_health_recent_systemd():
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50

    limit = max(1, min(limit, 500))

    units = None
    if "unit" in request.args or "units" in request.args:
        units = []
        seen = set()
        raw_values = request.args.getlist("unit") + request.args.getlist("units")
        for raw_value in raw_values:
            for raw_unit in (raw_value or "").split(","):
                unit = raw_unit.strip()
                if not unit or unit in seen:
                    continue
                seen.add(unit)
                units.append(unit)

    try:
        data = healthd_recent_systemd(limit=limit, units=units)
        status = 400 if data.get("ok") is False and data.get("invalid_units") else 200
        return jsonify(data), status
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd recent systemd logs error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.get("/api/health/logs/docker")
def api_health_logs_docker():
    container = (request.args.get("container", "") or "").strip()
    if not container:
        return jsonify({"ok": False, "error": "container is required"}), 400

    try:
        tail = int(request.args.get("tail", "200"))
        since = int(request.args.get("since", "3600"))
    except ValueError:
        tail, since = 200, 3600

    try:
        data = healthd_logs_docker(container=container, tail=tail, since=since)
        return jsonify(data)
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd logs docker error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.get("/api/health/capabilities")
def api_health_capabilities():
    """Возвращает разрешённые управляющие действия (из healthd)."""
    try:
        data = healthd_capabilities()
        return jsonify(data)
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd capabilities error")
        return jsonify({"ok": False, "error": str(e)}), 502


@bp.post("/api/health/control")
def api_health_control():
    """Прокси к /api/v1/control в healthd.

    Дополнительно:
    - Требуем superadmin (по Remote-Groups), чтобы управление не было доступно
      обычным пользователям.
    - Валидируем action относительно capabilities, чтобы нельзя было вызвать
      произвольную команду даже если кто-то подделает запрос.
    """
    if not _is_superadmin():
        return jsonify({"ok": False, "error": "forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    kind = (payload.get("kind") or "").strip().lower()
    name = (payload.get("name") or "").strip()
    action = (payload.get("action") or "").strip().lower()

    if kind not in {"systemd", "docker"}:
        return jsonify({"ok": False, "error": "kind must be systemd|docker"}), 400
    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400
    if action not in {"start", "stop", "restart", "reload"}:
        return jsonify({"ok": False, "error": "action must be start|stop|restart|reload"}), 400

    # проверяем, что action разрешён
    try:
        caps = healthd_capabilities()
        if caps.get("ok") is not True:
            return jsonify({"ok": False, "error": "healthd capabilities not ok"}), 502

        allowed_map = (caps.get("systemd") if kind == "systemd" else caps.get("docker")) or {}

        # exact match or glob match
        allowed: set[str] = set()
        if name in allowed_map and isinstance(allowed_map.get(name), list):
            allowed.update([str(x) for x in allowed_map.get(name) or []])

        # glob patterns (haproxy-*.service etc.)
        import fnmatch

        for k, v in allowed_map.items():
            if k == name:
                continue
            if isinstance(k, str) and ("*" in k or "?" in k):
                try:
                    if fnmatch.fnmatch(name, k) and isinstance(v, list):
                        allowed.update([str(x) for x in v])
                except Exception:
                    pass

        if action not in allowed:
            return jsonify({"ok": False, "error": "action not allowed", "allowed": sorted(allowed)}), 403

    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd capabilities validate error")
        return jsonify({"ok": False, "error": str(e)}), 502

    try:
        data = healthd_control(kind=kind, name=name, action=action)
        # нормализуем поле текста для UI
        if isinstance(data, dict) and "text" not in data:
            out = data.get("stdout") or ""
            err = data.get("stderr") or ""
            data["text"] = (out + ("\n" if out and err else "") + err).strip()
        return jsonify(data), (202 if data.get("scheduled") else (200 if data.get("ok") else 500))
    except Exception as e:  # pylint: disable=broad-except
        LOG.exception("healthd control error")
        return jsonify({"ok": False, "error": str(e)}), 502
