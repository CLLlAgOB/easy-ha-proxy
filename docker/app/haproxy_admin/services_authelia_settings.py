# -*- coding: utf-8 -*-
"""
Сервисный слой для страницы интерактивных настроек Authelia (без access_control.rules).
"""

from typing import Dict, Any, Tuple
import logging
import ipaddress
import re

from .authelia_config_client import (
    get_config_without_rules,
    get_latest_notification,
    get_mail_settings,
    reveal_latest_notification,
    send_mail_test,
    set_latest_notification_handled,
    update_mail_settings,
    update_settings,
)

LOG = logging.getLogger(__name__)

_MAIL_MODES = {"filesystem", "relay"}
_TLS_MODES = {"smtps", "starttls", "plain"}
_PASSWORD_ACTIONS = {"keep", "replace", "clear"}
_MAIL_FIELDS = {
    "mode", "host", "port", "username", "password_action", "password",
    "sender", "recipient", "subject", "timeout", "tls_mode",
    "tls_skip_verify",
}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_TIMEOUT_RE = re.compile(r"^[1-9][0-9]{0,5}(?:ms|s|m|h)$")
_NOTIFICATION_METADATA_FIELDS = {
    "id",
    "revision",
    "received_at",
    "recipient_masked",
    "size",
    "handled",
    "handled_at",
}
_NOTIFICATION_LATEST_RESPONSE_FIELDS = {
    "ok",
    "mode",
    "status",
    "latest",
    "error",
    "validation_error",
    "conflict",
}
_NOTIFICATION_HANDLE_RESPONSE_FIELDS = {
    "ok",
    "status",
    "latest",
    "error",
    "validation_error",
    "conflict",
    "forbidden",
}


def _get_nested(d: Dict[str, Any], path, default=None):
    cur = d
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or len(cur) <= p:
                return default
            cur = cur[p]
        else:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(p)
        if cur is None:
            return default
    return cur


def load_settings_form_data() -> Dict[str, Any]:
    """
    Загружает конфиг (без rules и без секретов) и преобразует его
    в плоский dict для HTML-формы.

    ВНИМАНИЕ: параметры Redis и notifier.smtp здесь не редактируются
    через веб-интерфейс.
    """
    resp = get_config_without_rules()
    if not resp.get("ok"):
        raise RuntimeError(
            resp.get("error", "authelia-configd config_view failed"))

    cfg = resp.get("config") or {}

    form: Dict[str, Any] = {}

    # --- server ---
    form["server_address"] = _get_nested(cfg, ["server", "address"], "")

    # --- log ---
    form["log_level"] = _get_nested(cfg, ["log", "level"], "warn")
    form["log_format"] = _get_nested(cfg, ["log", "format"], "json")
    form["log_file_path"] = _get_nested(cfg, ["log", "file_path"], "")
    form["log_keep_stdout"] = bool(
        _get_nested(cfg, ["log", "keep_stdout"], True))

    # --- session ---
    form["session_name"] = _get_nested(
        cfg, ["session", "name"], "authelia_session")
    form["session_same_site"] = _get_nested(
        cfg, ["session", "same_site"], "lax")
    form["session_expiration"] = _get_nested(
        cfg, ["session", "expiration"], "12h")
    form["session_inactivity"] = _get_nested(
        cfg, ["session", "inactivity"], "30m")
    form["session_remember_me"] = _get_nested(
        cfg, ["session", "remember_me"], "3M")

    # cookies[0]
    form["cookie_domain"] = _get_nested(
        cfg, ["session", "cookies", 0, "domain"], "")
    form["cookie_authelia_url"] = _get_nested(
        cfg, ["session", "cookies", 0, "authelia_url"], ""
    )
    form["cookie_default_redirection_url"] = _get_nested(
        cfg, ["session", "cookies", 0, "default_redirection_url"], ""
    )

    # --- storage.local ---
    form["storage_local_path"] = _get_nested(
        cfg, ["storage", "local", "path"], "/config/db.sqlite3"
    )

    # --- authentication_backend.file ---
    form["auth_refresh_interval"] = _get_nested(
        cfg, ["authentication_backend", "refresh_interval"], "always"
    )
    form["auth_file_path"] = _get_nested(
        cfg, ["authentication_backend", "file",
              "path"], "/config/users_database.yml"
    )
    form["auth_file_watch"] = bool(
        _get_nested(cfg, ["authentication_backend", "file", "watch"], True)
    )
    form["auth_password_algorithm"] = _get_nested(
        cfg, ["authentication_backend", "file",
              "password", "algorithm"], "argon2id"
    )

    # --- regulation ---
    modes = _get_nested(cfg, ["regulation", "modes"], ["ip"])
    if isinstance(modes, list):
        form["reg_modes"] = ", ".join(str(x) for x in modes)
    else:
        form["reg_modes"] = str(modes) if modes is not None else "ip"

    form["reg_max_retries"] = _get_nested(
        cfg, ["regulation", "max_retries"], 5)
    form["reg_find_time"] = _get_nested(cfg, ["regulation", "find_time"], "2m")
    form["reg_ban_time"] = _get_nested(cfg, ["regulation", "ban_time"], "1h")

    # --- totp ---
    form["totp_issuer"] = _get_nested(cfg, ["totp", "issuer"], "")
    form["totp_period"] = _get_nested(cfg, ["totp", "period"], 30)
    form["totp_skew"] = _get_nested(cfg, ["totp", "skew"], 1)

    return form


def load_mail_settings() -> Dict[str, Any]:
    """Load SMTP settings without ever exposing the stored password."""
    resp = get_mail_settings()
    if not resp.get("ok"):
        raise RuntimeError(resp.get("error") or "authelia-configd mail_view failed")
    settings = resp.get("settings")
    if not isinstance(settings, dict):
        raise RuntimeError("authelia-configd returned invalid mail settings")
    settings.pop("password", None)
    return {
        "ok": True,
        "settings": settings,
        "capabilities": resp.get("capabilities") or {},
        "revision": str(resp.get("revision") or ""),
    }


def _mail_text(value: Any, label: str, maximum: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if len(text) > maximum or _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains invalid characters or is too long")
    return text


def _mail_host(value: Any) -> str:
    host = _mail_text(value, "SMTP host", 253)
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if not all(_DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("SMTP host must be a valid IP address or DNS name")
    return host.rstrip(".")


def _mail_email(value: Any, label: str) -> str:
    email = _mail_text(value, label, 254)
    if not _EMAIL_RE.fullmatch(email):
        raise ValueError(f"{label} must be a valid email address")
    return email


def validate_mail_settings_payload(payload: Any) -> Dict[str, Any]:
    """Strictly normalize the browser-to-daemon mail configuration contract."""
    if not isinstance(payload, dict):
        raise ValueError("settings must be an object")
    unexpected = set(payload) - _MAIL_FIELDS
    missing = _MAIL_FIELDS - set(payload)
    if unexpected or missing:
        details = []
        if missing:
            details.append("missing: " + ", ".join(sorted(missing)))
        if unexpected:
            details.append("unsupported: " + ", ".join(sorted(unexpected)))
        raise ValueError("invalid mail settings fields (" + "; ".join(details) + ")")

    mode = str(payload.get("mode") or "").strip().lower()
    if mode not in _MAIL_MODES:
        raise ValueError("mode must be filesystem or relay")
    tls_mode = str(payload.get("tls_mode") or "").strip().lower()
    if tls_mode not in _TLS_MODES:
        raise ValueError("tls_mode must be smtps, starttls, or plain")
    password_action = str(payload.get("password_action") or "").strip().lower()
    if password_action not in _PASSWORD_ACTIONS:
        raise ValueError("password_action must be keep, replace, or clear")

    raw_host = payload.get("host")
    if mode == "filesystem" and isinstance(raw_host, str) and not raw_host.strip():
        host = ""
    else:
        host = _mail_host(raw_host)
    port_value = payload.get("port")
    if mode == "filesystem" and port_value in (None, ""):
        port_value = 25
    if isinstance(port_value, bool):
        raise ValueError("SMTP port must be an integer")
    try:
        port = int(port_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("SMTP port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SMTP port must be between 1 and 65535")

    password = payload.get("password")
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) > 1024 or _CONTROL_RE.search(password):
        raise ValueError("password contains invalid characters or is too long")
    if password_action == "replace" and not password:
        raise ValueError("a non-empty password is required when replacing it")
    if password_action != "replace" and password:
        raise ValueError("password must be empty unless password_action is replace")

    tls_skip_verify = payload.get("tls_skip_verify")
    if not isinstance(tls_skip_verify, bool):
        raise ValueError("tls_skip_verify must be true or false")

    raw_sender = payload.get("sender")
    raw_recipient = payload.get("recipient")
    raw_subject = payload.get("subject")
    if mode == "filesystem":
        sender = (
            _mail_email(raw_sender, "Sender")
            if isinstance(raw_sender, str) and raw_sender.strip()
            else ""
        )
        recipient = (
            _mail_email(raw_recipient, "Recipient")
            if isinstance(raw_recipient, str) and raw_recipient.strip()
            else ""
        )
        subject = _mail_text(raw_subject, "Subject", 255, required=False)
    else:
        sender = _mail_email(raw_sender, "Sender")
        recipient = _mail_email(raw_recipient, "Recipient")
        subject = _mail_text(raw_subject, "Subject", 255)

    return {
        "mode": mode,
        "host": host,
        "port": port,
        "username": _mail_text(
            payload.get("username"), "SMTP username", 320, required=False
        ),
        "password_action": password_action,
        "password": password,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "timeout": _mail_text(payload.get("timeout"), "Timeout", 16),
        "tls_mode": tls_mode,
        "tls_skip_verify": tls_skip_verify,
    }


def save_mail_settings(
    payload: Any,
    *,
    apply: bool = True,
    revision: Any,
) -> Dict[str, Any]:
    """Validate and persist notifier/SMTP settings via authelia-configd."""
    if apply is not True:
        return {
            "ok": False,
            "validation_error": True,
            "error": "apply must be true",
        }
    try:
        settings = validate_mail_settings_payload(payload)
        if not _TIMEOUT_RE.fullmatch(settings["timeout"]):
            raise ValueError("Timeout must look like 10s, 2m, 1h, or 500ms")
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}

    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision):
        return {
            "ok": False,
            "validation_error": True,
            "error": "revision must be the current 64-character SHA-256 value",
        }

    resp = update_mail_settings(settings, apply=apply, revision=revision)
    if not isinstance(resp, dict):
        return {"ok": False, "error": "authelia-configd returned an invalid response"}
    resp_settings = resp.get("settings")
    if isinstance(resp_settings, dict):
        resp_settings.pop("password", None)
    return resp


def test_mail_settings(*, revision: Any, recipient: Any) -> Dict[str, Any]:
    """Validate the public test request and forward only safe scalar fields."""
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision):
        return {
            "ok": False,
            "validation_error": True,
            "error": "revision must be the current 64-character SHA-256 value",
        }
    try:
        normalized_recipient = _mail_email(recipient, "Recipient")
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    response = send_mail_test(
        revision=revision,
        recipient=normalized_recipient,
    )
    if not isinstance(response, dict):
        return {"ok": False, "error": "authelia-configd returned an invalid response"}
    return response


def load_latest_local_notification() -> Dict[str, Any]:
    """Load latest-only metadata; notification plaintext is never returned here."""
    response = get_latest_notification()
    if not isinstance(response, dict):
        return {"ok": False, "error": "authelia-configd returned an invalid response"}
    return _allowlist_notification_response(
        response, _NOTIFICATION_LATEST_RESPONSE_FIELDS
    )


def _allowlist_notification_response(
    response: Dict[str, Any], allowed_fields: set[str]
) -> Dict[str, Any]:
    """Copy only the notification fields intentionally exposed to the browser."""
    filtered = {
        key: response[key]
        for key in allowed_fields
        if key in response and key != "latest"
    }
    if "latest" in response and "latest" in allowed_fields:
        latest = response.get("latest")
        filtered["latest"] = (
            {
                key: latest[key]
                for key in _NOTIFICATION_METADATA_FIELDS
                if key in latest
            }
            if isinstance(latest, dict)
            else None
        )
    return filtered


def _notification_reference(notification_id: Any, revision: Any) -> Tuple[str, str]:
    if (
        not isinstance(notification_id, str)
        or not re.fullmatch(r"[a-f0-9]{64}", notification_id)
        or not isinstance(revision, str)
        or not re.fullmatch(r"[a-f0-9]{64}", revision)
    ):
        raise ValueError("id and revision must be current 64-character values")
    return notification_id, revision


def _notification_actor(actor: Any) -> str:
    return _mail_text(actor, "Actor", 128)


def reveal_local_notification(
    *, notification_id: Any, revision: Any, actor: Any
) -> Dict[str, Any]:
    """Reveal only the exact current notification and identify the operator."""
    try:
        normalized_id, normalized_revision = _notification_reference(
            notification_id, revision
        )
        normalized_actor = _notification_actor(actor)
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    response = reveal_latest_notification(
        notification_id=normalized_id,
        revision=normalized_revision,
        actor=normalized_actor,
    )
    if not isinstance(response, dict):
        return {"ok": False, "error": "authelia-configd returned an invalid response"}
    return response


def mark_local_notification(
    *,
    notification_id: Any,
    revision: Any,
    actor: Any,
) -> Dict[str, Any]:
    """Irreversibly mark the exact current notification handled."""
    try:
        normalized_id, normalized_revision = _notification_reference(
            notification_id, revision
        )
        normalized_actor = _notification_actor(actor)
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    response = set_latest_notification_handled(
        notification_id=normalized_id,
        revision=normalized_revision,
        actor=normalized_actor,
    )
    if not isinstance(response, dict):
        return {"ok": False, "error": "authelia-configd returned an invalid response"}
    return _allowlist_notification_response(
        response, _NOTIFICATION_HANDLE_RESPONSE_FIELDS
    )


def _parse_int(form, name: str, default=None) -> int | None:
    val = (form.get(name) or "").strip()
    if val == "":
        return default
    try:
        return int(val)
    except ValueError as exc:
        raise ValueError(
            f"Field '{name}' must be an integer, not '{val}'"
        ) from exc


def save_settings_from_form(form_data) -> Tuple[bool, str]:
    """
    Принимает request.form, формирует ФРАГМЕНТ конфигурации Authelia
    и отправляет его демону settings_update.

    ВАЖНО: обновляем только "человеческие" поля:
      - log.level
      - session.* (кроме redis и secret)
      - regulation.*
      - totp.*
    Всё остальное (server, redis, storage, auth_backend.file, notifier.smtp)
    не трогаем.
    """
    try:
        cfg: Dict[str, Any] = {}

        # ---------------- LOG ----------------
        log: Dict[str, Any] = {}
        level = (form_data.get("log_level") or "").strip() or "warn"
        log["level"] = level
        # формат/файл/stdout не трогаем → не отправляем
        cfg["log"] = log

        # ---------------- SESSION ----------------
        session: Dict[str, Any] = {}
        session["name"] = (
            (form_data.get("session_name") or "").strip() or "authelia_session"
        )
        session["same_site"] = (
            (form_data.get("session_same_site") or "").strip() or "lax"
        )
        session["expiration"] = (
            (form_data.get("session_expiration") or "").strip() or "12h"
        )
        session["inactivity"] = (
            (form_data.get("session_inactivity") or "").strip() or "30m"
        )
        session["remember_me"] = (
            (form_data.get("session_remember_me") or "").strip() or "3M"
        )

        cookie = {
            "domain": (form_data.get("cookie_domain") or "").strip(),
            "authelia_url": (form_data.get("cookie_authelia_url") or "").strip(),
            "default_redirection_url": (
                form_data.get("cookie_default_redirection_url") or ""
            ).strip(),
        }
        session["cookies"] = [cookie]

        # ВАЖНО: redis сюда НЕ добавляем → не трогаем существующий блок session.redis
        cfg["session"] = session

        # ---------------- REGULATION ----------------
        reg: Dict[str, Any] = {}
        modes_str = (form_data.get("reg_modes") or "").strip() or "ip"
        modes = [m.strip() for m in modes_str.split(",") if m.strip()]
        reg["modes"] = modes
        reg["max_retries"] = _parse_int(form_data, "reg_max_retries", 5)
        reg["find_time"] = (form_data.get("reg_find_time")
                            or "").strip() or "2m"
        reg["ban_time"] = (form_data.get("reg_ban_time") or "").strip() or "1h"
        cfg["regulation"] = reg

        # ---------------- TOTP ----------------
        totp: Dict[str, Any] = {}
        totp["issuer"] = (form_data.get("totp_issuer") or "").strip()
        totp["period"] = _parse_int(form_data, "totp_period", 30)
        totp["skew"] = _parse_int(form_data, "totp_skew", 1)
        cfg["totp"] = totp

    except ValueError as exc:
        # Ошибка парсинга чисел
        return False, str(exc)

    # Отправляем во второй план (root-демон)
    resp = update_settings(cfg)
    if not resp.get("ok"):
        return (
            False,
            f"Failed to save settings via authelia-configd: {resp.get('error')}",
        )

    return True, 'Authelia settings saved successfully.'
