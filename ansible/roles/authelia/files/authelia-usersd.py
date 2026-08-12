#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
authelia-usersd — маленький root-демон для управления users_database.yml Authelia.

Протокол (одна строка JSON на запрос, одна строка JSON на ответ):

Запрос:
  {
    "action": "update",
    "username": "example-user",
    "fields": {
      "displayname": "...",
      "email": "...",
      "groups": ["admins", "users"],
      "disabled": false
    },
    "password_plain": "<new-password>"   # опционально
  }

Ответ:
  {"ok": true, "message": "user updated"}
или
  {"ok": false, "error": "текст ошибки"}

Также поддерживает:
  action = "list"   → вернуть список всех пользователей
  action = "get"    → вернуть одного пользователя
  action = "create" → создать нового пользователя
  action = "delete" → удалить пользователя

Переменные окружения:
  AUTHELIA_USERS_FILE        — путь к users_database.yml
  AUTHELIA_DOCKER_COMPOSE_FILE (необязательно, зарезервировано)
  AUTHELIA_CONTAINER_NAME    — имя docker-контейнера Authelia
  AUTHELIA_CONFIG_PATH       — путь до configuration.yml внутри контейнера
  AUTHELIA_USERS_SOCKET      — unix-сокет демона
"""

import json
import logging
import os
import pwd
import signal
import socket
import sys
import time
import re
from datetime import datetime
from typing import Tuple, Dict, Any

import yaml
from argon2 import PasswordHasher

# --- Конфиг из окружения ---

USERS_FILE = os.environ.get("AUTHELIA_USERS_FILE",
                            "/opt/authelia/users_database.yml")
DOCKER_COMPOSE_FILE = os.environ.get(
    "AUTHELIA_DOCKER_COMPOSE_FILE", "/opt/authelia/docker-compose.yml")
AUTHELIA_CONTAINER = os.environ.get("AUTHELIA_CONTAINER_NAME", "authelia")
AUTHELIA_CONFIG_PATH = os.environ.get(
    "AUTHELIA_CONFIG_PATH", "/config/configuration.yml")
SOCKET_PATH = os.environ.get(
    "AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock")
MAX_REQUEST_BYTES = 1024 * 1024
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

LOG = logging.getLogger("authelia-usersd")


def _backup_users_file() -> None:
    """Создаёт бэкап users_database.yml с небольшой ротацией (оставляем максимум 14 файлов)."""
    if not os.path.exists(USERS_FILE):
        return

    # Создаём жёсткую ссылку текущего файла
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = f"{USERS_FILE}.bak-{ts}"
    try:
        os.link(USERS_FILE, backup_path)
        LOG.info("Backup created: %s", backup_path)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Backup failed (%s): %s", backup_path, exc)

    # Ротация: оставляем только 14 самых свежих
    dir_name = os.path.dirname(USERS_FILE) or "."
    base_name = os.path.basename(USERS_FILE)
    prefix = base_name + ".bak-"

    try:
        candidates = [
            os.path.join(dir_name, f)
            for f in os.listdir(dir_name)
            if f.startswith(prefix)
        ]
    except OSError as exc:  # noqa: BLE001
        LOG.warning("Backup rotation list failed: %s", exc)
        return

    def _mtime(path: str) -> float:
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    candidates.sort(key=_mtime, reverse=True)
    for old in candidates[14:]:
        try:
            os.remove(old)
            LOG.info("Old backup removed: %s", old)
        except OSError as exc:  # noqa: BLE001
            LOG.warning("Failed to remove old backup %s: %s", old, exc)


def _load_users_data() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Загружает YAML users_database.yml.

    Возвращает (root_data, users_node).

    root_data — весь YAML как dict.
    users_node — dict username -> attrs.

    Поддерживает:
      - корень: { users: { user1: {...}, ... } }
      - корень: { user1: {...}, user2: {...}, ... }
    """
    if not os.path.exists(USERS_FILE):
        raise FileNotFoundError(f"users file not found: {USERS_FILE}")

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("unexpected YAML structure (root is not a dict)")

    if "users" in data and isinstance(data["users"], dict):
        return data, data["users"]

    # вариант без "users:"
    return data, data


def _save_users_data(root_data: Dict[str, Any]) -> None:
    """
    Атомарно сохраняет YAML обратно в USERS_FILE с предварительным бэкапом.

    ВАЖНО: не меняем владельца и права файла — они остаются такими,
    какими были до сохранения (Ansible рулит owner/group/mode).
    """
    # Запоминаем текущие права/владельца, если файл уже есть.
    prev_stat = None
    try:
        prev_stat = os.stat(USERS_FILE)
    except FileNotFoundError:
        prev_stat = None
    except OSError as exc:  # noqa: BLE001
        LOG.warning("Failed to stat %s before save: %s", USERS_FILE, exc)
        prev_stat = None

    _backup_users_file()

    # Ownership/mode MUST be set on the temp file *before* the rename. Authelia
    # runs `watch: true` and reloads the users database the instant the file is
    # replaced; if the live path momentarily pointed at this root-owned temp
    # file, that reload would fail with "permission denied" and Authelia would
    # keep serving the stale in-memory database until the next change. The temp
    # file is created in the same directory, so it also inherits the directory's
    # default ACL (which grants the web reader its read access).
    #
    # Fall back to the "authelia" account when the previous file is missing so a
    # first-ever write is still readable by the container.
    if prev_stat is not None:
        target_uid, target_gid = prev_stat.st_uid, prev_stat.st_gid
    else:
        try:
            entry = pwd.getpwnam("authelia")
            target_uid, target_gid = entry.pw_uid, entry.pw_gid
        except KeyError:
            target_uid, target_gid = -1, -1

    tmp_path = USERS_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                root_data,
                f,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=True,  # как у тебя было
            )
            f.flush()
            os.fsync(f.fileno())

        if target_uid != -1:
            try:
                os.chown(tmp_path, target_uid, target_gid)
            except OSError as exc:  # noqa: BLE001
                LOG.warning("Failed to set owner/group on temp users file: %s", exc)
        try:
            os.chmod(tmp_path, 0o640)
        except OSError as exc:  # noqa: BLE001
            LOG.warning("Failed to set mode on temp users file: %s", exc)

        # Атомарная замена: боевой путь всегда указывает на читаемый файл.
        os.replace(tmp_path, USERS_FILE)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    LOG.info("Users file updated: %s", USERS_FILE)


def _hash_password(plain: str) -> str:
    """
    Считает совместимый с Authelia argon2id-хэш локально.
    Пароль не попадает в argv процесса и список процессов.
    """
    if not 8 <= len(plain) <= 1024:
        raise ValueError("Пароль должен содержать от 8 до 1024 символов")
    return PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    ).hash(plain)


def _safe_user_view(username: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Оставляем только безопасные поля для UI/ответов (без password)."""
    raw_groups = raw.get("groups") or []
    groups = (
        [str(group) for group in raw_groups]
        if isinstance(raw_groups, (list, tuple, set))
        else [str(raw_groups)]
    )
    return {
        "username": username,
        "displayname": raw.get("displayname", "") or "",
        "email": raw.get("email", "") or "",
        "groups": groups,
        "disabled": bool(raw.get("disabled", False)),
    }


def _validated_username(req: Dict[str, Any]) -> str:
    username = str(req.get("username") or "").strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "username must contain only letters, digits, '.', '_', '@' or '-' (max 64)"
        )
    return username


def _validated_fields(req: Dict[str, Any]) -> Dict[str, Any]:
    fields = req.get("fields") or {}
    if not isinstance(fields, dict):
        raise ValueError("fields must be an object")
    out: Dict[str, Any] = {}
    for key in ("displayname", "email"):
        if key in fields:
            raw_value = str(fields[key] or "")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_value):
                raise ValueError(f"{key} is invalid")
            value = raw_value.strip()
            max_length = 254 if key == "email" else 320
            if not value or len(value) > max_length:
                raise ValueError(f"{key} is invalid")
            if key == "email" and not EMAIL_RE.fullmatch(value):
                raise ValueError("email is invalid")
            out[key] = value
    if "groups" in fields:
        groups = fields["groups"]
        if not isinstance(groups, list) or len(groups) > 50:
            raise ValueError("groups must be a list with no more than 50 entries")
        out["groups"] = [
            str(group).strip() for group in groups
            if USERNAME_RE.fullmatch(str(group).strip())
        ]
        if len(out["groups"]) != len(groups):
            raise ValueError("group name is invalid")
    if "disabled" in fields:
        out["disabled"] = bool(fields["disabled"])
    return out


def _password_from_request(req: Dict[str, Any]) -> str:
    """Return a password unchanged; whitespace is a valid password character."""
    value = req.get("password_plain")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("password_plain must be a string")
    return value


def _is_enabled_superadmin(user: Any) -> bool:
    if not isinstance(user, dict) or bool(user.get("disabled", False)):
        return False
    groups = user.get("groups") or []
    if not isinstance(groups, (list, tuple, set)):
        groups = [groups]
    return "superadmin" in {str(group).strip() for group in groups}


def _removes_last_enabled_superadmin(
    users_node: Dict[str, Any],
    username: str,
    replacement: Dict[str, Any] | None,
) -> bool:
    current = users_node.get(username)
    if not _is_enabled_superadmin(current):
        return False
    if replacement is not None and _is_enabled_superadmin(replacement):
        return False
    return not any(
        other_name != username and _is_enabled_superadmin(other_user)
        for other_name, other_user in users_node.items()
    )


def _handle_list(req: Dict[str, Any]) -> Dict[str, Any]:
    root, users_node = _load_users_data()
    users = []
    for username in sorted(users_node.keys()):
        val = users_node.get(username) or {}
        if not isinstance(val, dict):
            continue
        users.append(_safe_user_view(username, val))
    return {"ok": True, "users": users}


def _handle_get(req: Dict[str, Any]) -> Dict[str, Any]:
    username = _validated_username(req)

    root, users_node = _load_users_data()
    user = users_node.get(username)
    if not isinstance(user, dict):
        return {"ok": False, "error": f"user '{username}' not found"}

    return {"ok": True, "user": _safe_user_view(username, user)}


def _handle_update(req: Dict[str, Any]) -> Dict[str, Any]:
    username = _validated_username(req)
    fields = _validated_fields(req)
    password_plain = _password_from_request(req)

    root, users_node = _load_users_data()
    user = users_node.get(username)
    if not isinstance(user, dict):
        # В режиме update не создаём нового, только изменяем существующего
        return {"ok": False, "error": f"user '{username}' not found"}

    prospective_user = dict(user)
    prospective_user.update(fields)
    if _removes_last_enabled_superadmin(
        users_node, username, prospective_user
    ):
        return {
            "ok": False,
            "error": "the last enabled superadmin cannot be disabled or demoted",
        }

    user.setdefault("groups", [])

    # обновляем редактируемые поля
    for key in ("displayname", "email", "disabled", "groups"):
        if key in fields:
            user[key] = fields[key]

    if password_plain:
        try:
            pwd_hash = _hash_password(password_plain)
        except Exception as exc:  # noqa: BLE001
            LOG.error("hash password failed", exc_info=exc)
            return {
                "ok": False,
                "error": f"Ошибка генерации пароля через Authelia: {exc}",
            }
        user["password"] = pwd_hash

    users_node[username] = user
    _save_users_data(root)

    return {"ok": True, "user": _safe_user_view(username, user)}


def _handle_create(req: Dict[str, Any]) -> Dict[str, Any]:
    username = _validated_username(req)
    fields = _validated_fields(req)
    password_plain = _password_from_request(req)

    if not password_plain:
        return {"ok": False, "error": "password_plain is required for create"}

    root, users_node = _load_users_data()
    if username in users_node:
        return {"ok": False, "error": f"user '{username}' already exists"}

    try:
        pwd_hash = _hash_password(password_plain)
    except Exception as exc:  # noqa: BLE001
        LOG.error("hash password failed", exc_info=exc)
        return {
            "ok": False,
            "error": f"Ошибка генерации пароля через Authelia: {exc}",
        }

    user: Dict[str, Any] = {
        "password": pwd_hash,
        "displayname": fields.get("displayname", "") or "",
        "email": fields.get("email", "") or "",
        "groups": list(fields.get("groups", []) or []),
        "disabled": bool(fields.get("disabled", False)),
    }

    users_node[username] = user
    _save_users_data(root)

    return {"ok": True, "user": _safe_user_view(username, user)}


def _handle_delete(req: Dict[str, Any]) -> Dict[str, Any]:
    username = _validated_username(req)

    root, users_node = _load_users_data()
    if username not in users_node:
        return {"ok": False, "error": f"user '{username}' not found"}

    if _removes_last_enabled_superadmin(users_node, username, None):
        return {
            "ok": False,
            "error": "the last enabled superadmin cannot be deleted",
        }

    deleted = users_node.pop(username, None)
    _save_users_data(root)
    return {
        "ok": True,
        "message": f"user '{username}' deleted",
        "user": _safe_user_view(username, deleted or {}),
    }


def _dispatch_request(req: Dict[str, Any]) -> Dict[str, Any]:
    action = (req.get("action") or "").strip()
    if action == "list":
        return _handle_list(req)
    if action == "get":
        return _handle_get(req)
    if action == "update":
        return _handle_update(req)
    if action == "create":
        return _handle_create(req)
    if action == "delete":
        return _handle_delete(req)
    return {"ok": False, "error": f"unknown action: {action}"}


def handle_request(req: Dict[str, Any]) -> Dict[str, Any]:
    """Маршрутизация по action с безопасным ответом на ошибки валидации."""
    if not isinstance(req, dict):
        return {"ok": False, "error": "request must be a JSON object"}
    try:
        return _dispatch_request(req)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}


def serve() -> None:
    """Основной цикл сервера."""
    # убираем старый сокет, если остался
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except Exception:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    # права на сокет: rw для owner+group; group задаётся в unit-файле
    os.chmod(SOCKET_PATH, 0o660)
    srv.listen(10)

    LOG.info("authelia-usersd listening on %s", SOCKET_PATH)

    def _sigterm(signum, frame):
        LOG.info("Got signal %s, shutting down", signum)
        try:
            srv.close()
        except Exception:
            pass
        try:
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break

        with conn:
            try:
                conn.settimeout(15)
                data = b""
                # читаем до \n (одна строка JSON)
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > MAX_REQUEST_BYTES:
                        raise ValueError("request is too large")

                if not data:
                    continue

                line = data.split(b"\n", 1)[0].decode(
                    "utf-8", errors="replace").strip()
                if not line:
                    continue

                try:
                    req = json.loads(line)
                except Exception as exc:  # noqa: BLE001
                    resp = {"ok": False, "error": f"invalid json: {exc}"}
                else:
                    if isinstance(req, dict):
                        LOG.debug(
                            "Request action=%r username=%r",
                            req.get("action"),
                            req.get("username"),
                        )
                    resp = handle_request(req)

            except Exception as exc:  # noqa: BLE001
                LOG.exception("request handling failed")
                resp = {"ok": False, "error": f"internal error: {exc}"}

            resp_line = json.dumps(resp, ensure_ascii=False) + "\n"
            try:
                conn.sendall(resp_line.encode("utf-8"))
            except Exception:
                pass


def main() -> None:
    # Настраиваем root-логгер только при запуске демона: делать это на импорте
    # значит менять логирование любого процесса, который просто импортирует модуль.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        serve()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("fatal error in server: %s", exc)
        time.sleep(1)
        sys.exit(1)


if __name__ == "__main__":
    main()
