# -*- coding: utf-8 -*-
"""
Клиент для общения с root-сервисом authelia-configd через UNIX-сокет.
"""

import json
import logging
import os
import socket
from typing import Any, Dict, List

LOG = logging.getLogger(__name__)

SOCKET_PATH = os.environ.get(
    "AUTHELIA_CONFIG_SOCKET",
    "/run/easy-ha-proxy/authelia-configd.sock",
)


def _send_request(payload: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False) + "\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(SOCKET_PATH)
            s.sendall(data.encode("utf-8"))

            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        LOG.error("authelia-configd socket error: %s", exc, exc_info=True)
        return {"ok": False, "error": f"socket error: {exc}"}

    if not buf:
        return {"ok": False, "error": "empty response from authelia-configd"}

    line = buf.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    if not line:
        return {"ok": False, "error": "empty JSON from authelia-configd"}

    try:
        resp = json.loads(line)
    except Exception as exc:  # noqa: BLE001
        LOG.error("invalid json from authelia-configd: %s", exc, exc_info=True)
        return {
            "ok": False,
            "error": f"invalid json from authelia-configd: {exc}",
        }

    return resp


def get_rules() -> Dict[str, Any]:
    return _send_request({"action": "rules_list"})


def save_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return _send_request({"action": "rules_save", "rules": rules})


def get_config_without_rules() -> Dict[str, Any]:
    return _send_request({"action": "config_view"})


def restart_authelia() -> Dict[str, Any]:
    """Перезапустить Authelia (docker restart + ожидание порта)."""
    return _send_request({"action": "restart"}, timeout=60.0)

def update_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Передать фрагмент конфигурации (без rules и без секретов)
    демону для обновления настроек.
    """
    return _send_request({"action": "settings_update", "config": config})


def get_mail_settings() -> Dict[str, Any]:
    """Return redacted Authelia notifier and external SMTP settings."""
    return _send_request({"action": "mail_view"})


def update_mail_settings(
    settings: Dict[str, Any],
    *,
    apply: bool = True,
    revision: str,
) -> Dict[str, Any]:
    """Persist mail settings through the privileged configuration daemon."""
    return _send_request(
        {
            "action": "mail_update",
            "settings": settings,
            "apply": apply,
            "revision": revision,
        },
        # Bounded worst case is below 800 seconds: validation (60s), a stopped
        # relay inspection, candidate reconciliation, and one full rollback.
        # Keep this below Gunicorn's 870s and HAProxy's 15-minute timeout.
        timeout=840.0,
    )


def send_mail_test(*, revision: str, recipient: str) -> Dict[str, Any]:
    """Ask configd to send one rate-limited test message."""
    return _send_request(
        {
            "action": "mail_test",
            "revision": revision,
            "recipient": recipient,
        },
        timeout=180.0,
    )


def get_latest_notification() -> Dict[str, Any]:
    """Return metadata only for the latest local Authelia notification."""
    return _send_request({"action": "notification_latest"})


def reveal_latest_notification(
    *, notification_id: str, revision: str, actor: str
) -> Dict[str, Any]:
    """Reveal the current plaintext through the privileged daemon."""
    return _send_request(
        {
            "action": "notification_reveal",
            "id": notification_id,
            "revision": revision,
            "actor": actor,
        }
    )


def set_latest_notification_handled(
    *, notification_id: str, revision: str, actor: str
) -> Dict[str, Any]:
    """Irreversibly mark the current notification handled in dashboard state."""
    return _send_request(
        {
            "action": "notification_handle",
            "id": notification_id,
            "revision": revision,
            "handled": True,
            "actor": actor,
        }
    )
