# -*- coding: utf-8 -*-
"""
Маршруты для интерактивной страницы настроек Authelia (без access_control.rules).
"""

from flask import Blueprint, render_template, request, current_app, g, jsonify

from .services_authelia_settings import (
    load_settings_form_data,
    load_latest_local_notification,
    load_mail_settings,
    mark_local_notification,
    reveal_local_notification,
    save_mail_settings,
    test_mail_settings,
    save_settings_from_form,
)

bp_authelia_settings = Blueprint(
    "authelia_settings",
    __name__,
    url_prefix="/authelia/settings",
)


@bp_authelia_settings.get("/mail")
def get_mail_configuration():
    """Return redacted SMTP/notifier settings and an optimistic revision."""
    try:
        return jsonify(load_mail_settings())
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception("Failed to load Authelia mail settings")
        return jsonify({"ok": False, "error": str(exc)}), 502


@bp_authelia_settings.post("/mail")
def update_mail_configuration():
    """Validate, persist, and atomically apply SMTP/notifier settings."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {
        "settings", "apply", "revision"
    }:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "settings, apply, and revision are required",
            }
        ), 400
    if payload.get("apply") is not True:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "apply must be true",
            }
        ), 400

    result = save_mail_settings(
        payload.get("settings"),
        apply=payload["apply"],
        revision=payload.get("revision"),
    )
    if result.get("ok"):
        status = 200
    elif result.get("conflict") or result.get("relay_unavailable"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status


@bp_authelia_settings.post("/mail/test")
def send_mail_test_message():
    """Save no secrets here; send via the guarded privileged daemon."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"revision", "recipient"}:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "revision and recipient are required",
            }
        ), 400
    result = test_mail_settings(
        revision=payload.get("revision"),
        recipient=payload.get("recipient"),
    )
    if result.get("ok"):
        status = 200
    elif result.get("rate_limited"):
        status = 429
    elif result.get("conflict") or result.get("unsupported"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status


@bp_authelia_settings.get("/notifications/latest")
def get_latest_local_notification():
    """Return metadata only for the latest filesystem notification."""
    result = load_latest_local_notification()
    if result.get("ok"):
        status = 200
    elif result.get("conflict"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status


@bp_authelia_settings.post("/notifications/latest/reveal")
def reveal_current_local_notification():
    """Reveal the exact current plaintext and audit the trusted operator."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"id", "revision"}:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "id and revision are required",
            }
        ), 400
    result = reveal_local_notification(
        notification_id=payload.get("id"),
        revision=payload.get("revision"),
        actor=getattr(g, "remote_user", ""),
    )
    if result.get("ok"):
        status = 200
    elif result.get("rate_limited"):
        status = 429
    elif result.get("conflict"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status


@bp_authelia_settings.post("/notifications/latest/handled")
def update_current_local_notification_status():
    """Mark the exact current notification handled without deleting its file."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"id", "revision"}:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "id and revision are required",
            }
        ), 400
    result = mark_local_notification(
        notification_id=payload.get("id"),
        revision=payload.get("revision"),
        actor=getattr(g, "remote_user", ""),
    )
    if result.get("ok"):
        status = 200
    elif result.get("conflict"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 502
    return jsonify(result), status

@bp_authelia_settings.route("/", methods=["GET", "POST"])
def edit_settings():
    """Страница общих настроек Authelia (configuration.yml без access_control.rules)."""
    msg: str | None = None
    msg_category: str = "info"

    if request.method == "POST":
        # Какая кнопка нажата: сохранить или сохранить+применить
        submit_action = request.form.get("submit_action", "save")

        # Сохраняем настройки через сервисный слой (он ходит в authelia-configd)
        ok, msg = save_settings_from_form(request.form)
        msg_category = "success" if ok else "danger"

        # Если всё OK и нажали «Сохранить и применить» — просим демон перезапустить Authelia
        if ok and submit_action == "apply":
            try:
                # Локальный импорт, чтобы избежать циклических импортов модулей
                from .authelia_acl import (  # type: ignore[attr-defined]
                    _configd_request,
                    _wait_for_authelia_healthy,
                )

                resp = _configd_request({"action": "restart"})
            except Exception as exc:  # noqa: BLE001
                current_app.logger.exception(
                    "Failed to restart Authelia via configd")
                extra = str(exc)
                base = msg or 'Settings saved.'
                msg = f"{base} But Authelia did not restart: {extra}"
                msg_category = "warning"
            else:
                if not resp.get("ok"):
                    extra = resp.get("error") or 'unknown error'
                    base = msg or 'Settings saved.'
                    msg = f"{base} But Authelia did not restart: {extra}"
                    msg_category = "warning"
                else:
                    # Здесь Authelia уже перезапущена демоном, но мы дополнительно
                    # ждём health-check, чтобы при обновлении страницы не словить белый экран.
                    if not _wait_for_authelia_healthy():
                        base = msg or 'Settings saved.'
                        msg = (
                            f"{base} Authelia was restarted, but did not become ready "
                            'before the health-check timed out. If the page does not open, '
                            'refresh it in a few seconds.'
                        )
                        msg_category = "warning"
                    else:
                        base = msg or 'Settings saved.'
                        msg = f"{base} Authelia restarted successfully."
                        msg_category = "success"

    # Всегда пробуем перечитать актуальные настройки из демона
    try:
        form_data = load_settings_form_data()
    except Exception as exc:  # noqa: BLE001
        current_app.logger.exception(
            "Failed to load Authelia settings from configd: %s", exc
        )
        msg = f"Failed to read Authelia configuration: {exc}"
        msg_category = "danger"
        form_data = {
            "server": {},
            "log": {},
            "session": {},
            "identity_validation": {},
            "totp": {},
            "webauthn": {},
            "authentication_backend": {},
            "access_control": {},
            "storage": {},
            "regulation": {},
            "notifier": {},
        }

    return render_template(
        "authelia_settings.html",
        msg=msg,
        msg_category=msg_category,
        form=form_data,
        **form_data,
    )
