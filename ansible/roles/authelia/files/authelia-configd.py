#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
authelia-configd — root-демон для управления Authelia configuration.yml.

Умеет:

  action = "rules_list"
    → вернуть список access_control.rules (list[dict]) — старый JSON-API

  action = "rules_save"
    → сохранить новый список access_control.rules (через JSON-API)
       * бэкапит configuration.yml
       * пишет configuration.yml.tmp
       * (опционально) валидирует через authelia config validate
       * os.replace(.tmp, configuration.yml)

  action = "rules_get"
    → вернуть access_control.rules как YAML-список (строка rules_yaml)

  action = "rules_set"
    → принять YAML-список правил (rules_yaml), подставить в
      access_control.rules, провалидировать и сохранить

  action = "config_view"
    → вернуть ВЕСЬ configuration.yml, но:
       - без access_control.rules
       - с замазанными:
           session.secret
           storage.encryption_key
           identity_validation.reset_password.jwt_secret

  action = "settings_update"
    → принять фрагмент конфигурации (без rules и без секретов) и смержить
      его поверх текущего configuration.yml, с валидацией и сохранением

  action = "mail_view" / "mail_update"
    → безопасно читать и транзакционно изменять notifier, SMTP relay,
      runtime .env и managed easy-ha-proxy configuration. Пароль никогда
      не возвращается клиенту

  action = "mail_test"
    → отправить одно тестовое сообщение с текущими сохранёнными параметрами;
      сообщение принимается внутренним Postfix relay через sendmail, после
      чего демон ограниченное время ждёт обезличенный результат внешней
      SMTP-доставки по уникальному Message-ID

  action = "notification_latest" / "notification_reveal" /
           "notification_handle"
    → безопасно показать метаданные, однократно раскрыть или отметить
      обработанным только текущее filesystem-уведомление. Это не история:
      Authelia сама заменяет файл при следующем уведомлении

  action = "restart"
    → перезапустить Authelia (docker restart контейнера) и дождаться,
      пока HTTP health-check и ForwardAuth backend HAProxy снова
      станут доступны

Переменные окружения:

  AUTHELIA_CONFIG_FILE       — путь к configuration.yml на хосте
                               (по умолчанию /opt/authelia/configuration.yml)
  AUTHELIA_CONFIG_SOCKET     — unix-сокет демона
                               (по умолчанию /run/easy-ha-proxy/authelia-configd.sock)
  AUTHELIA_CONTAINER_NAME    — имя docker-контейнера Authelia
                               (по умолчанию authelia)
  AUTHELIA_CONFIG_PATH       — путь до configuration.yml ВНУТРИ контейнера
                               (по умолчанию /config/configuration.yml)

  AUTHELIA_VALIDATE_CONFIG   — "true"/"1" чтобы включить authelia config validate
  AUTHELIA_RESTART_HOST      — адрес для проверки порта (по умолчанию 127.0.0.1)
  AUTHELIA_RESTART_PORT      — порт Authelia (по умолчанию 9091)
  AUTHELIA_RESTART_TIMEOUT   — таймаут ожидания, сек (по умолчанию 30)
  AUTHELIA_HAPROXY_SOCKET    — HAProxy runtime socket used to verify that
                               ForwardAuth routing has recovered
"""

import csv
import http.client
import json
import fcntl
import hashlib
import hmac
import ipaddress
import logging
import os
import pwd
import re
import secrets
import signal
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from copy import deepcopy
from email.message import EmailMessage
import subprocess
from urllib.parse import urlsplit

import yaml

LOG = logging.getLogger("authelia-configd")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

CONFIG_FILE = os.environ.get(
    "AUTHELIA_CONFIG_FILE",
    "/opt/authelia/configuration.yml",
)
SOCKET_PATH = os.environ.get(
    "AUTHELIA_CONFIG_SOCKET",
    "/run/easy-ha-proxy/authelia-configd.sock",
)

AUTHELIA_CONTAINER = os.environ.get("AUTHELIA_CONTAINER_NAME", "authelia")
AUTHELIA_CONFIG_PATH = os.environ.get(
    "AUTHELIA_CONFIG_PATH",
    "/config/configuration.yml",
)

VALIDATE_CONFIG = os.environ.get(
    "AUTHELIA_VALIDATE_CONFIG", "false"
).lower() in ("1", "true", "yes")

RESTART_HOST = os.environ.get("AUTHELIA_RESTART_HOST", "127.0.0.1")
RESTART_PORT = int(os.environ.get("AUTHELIA_RESTART_PORT", "9091"))
RESTART_TIMEOUT = int(os.environ.get("AUTHELIA_RESTART_TIMEOUT", "30"))
HAPROXY_RUNTIME_SOCKET = os.environ.get(
    "AUTHELIA_HAPROXY_SOCKET", "/run/haproxy/admin.sock"
)
AUTHELIA_HEALTH_PATH = "/api/health"
AUTHELIA_HAPROXY_BACKEND = "authelia_backend"
AUTHELIA_HAPROXY_SERVER = "authelia"
MAX_HAPROXY_STATS_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024

ENV_FILE = os.environ.get("AUTHELIA_ENV_FILE", "/opt/authelia/.env")
COMPOSE_FILE = os.environ.get(
    "AUTHELIA_COMPOSE_FILE", "/opt/authelia/docker-compose.yml"
)
MANAGED_CONFIG_DIR = os.environ.get(
    "EASY_HA_PROXY_CONFIG_DIR", "/etc/easy-ha-proxy"
)
MANAGED_VARS_FILE = os.path.join(MANAGED_CONFIG_DIR, "vars.yml")
MANAGED_AUTHELIA_FILE = os.path.join(MANAGED_CONFIG_DIR, "authelia.yml")
MANAGED_SECRETS_FILE = os.path.join(MANAGED_CONFIG_DIR, "secrets.yml")
MAIL_NOTIFY_STATE_FILE = os.path.join(MANAGED_CONFIG_DIR, "mail-notify.json")
MAIL_LOCK_FILE = os.environ.get(
    "AUTHELIA_MAIL_LOCK_FILE", "/run/easy-ha-proxy/authelia-mail.lock"
)

MAIL_MODES = {"filesystem", "relay"}
MAIL_TLS_MODES = {"smtps", "starttls", "plain"}
MAIL_PASSWORD_ACTIONS = {"keep", "replace", "clear"}
MAIL_FIELDS = {
    "mode", "host", "port", "username", "password_action", "password",
    "sender", "recipient", "subject", "timeout", "tls_mode",
    "tls_skip_verify",
}
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
DNS_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
TIMEOUT_RE = re.compile(r"^[1-9][0-9]{0,5}(?:ms|s|m|h)$")
REVISION_RE = re.compile(r"^[a-f0-9]{64}$")
MAIL_REVISION_KEY = os.urandom(32)
try:
    MAIL_TEST_COOLDOWN_SECONDS = max(
        5, min(300, int(os.environ.get("AUTHELIA_MAIL_TEST_COOLDOWN", "15")))
    )
except ValueError:
    MAIL_TEST_COOLDOWN_SECONDS = 15
try:
    MAIL_TEST_RESULT_TIMEOUT = max(
        3, min(30, int(os.environ.get("AUTHELIA_MAIL_TEST_RESULT_TIMEOUT", "12")))
    )
except ValueError:
    MAIL_TEST_RESULT_TIMEOUT = 12
MAIL_TEST_LOCK = threading.Lock()
MAIL_TEST_LAST_AT = 0.0

NOTIFICATION_STATE_FILE = os.environ.get(
    "AUTHELIA_NOTIFICATION_STATE_FILE", ""
).strip()
NOTIFICATION_ROOT_DIR = os.environ.get(
    "AUTHELIA_NOTIFICATION_ROOT", "/opt/authelia"
)
NOTIFICATION_STATE_DIR = os.environ.get(
    "AUTHELIA_NOTIFICATION_STATE_DIR", "/var/lib/easy-ha-proxy"
)
NOTIFICATION_STATE_NAME = "authelia-notification-state.json"
NOTIFICATION_MAX_BYTES = 256 * 1024
NOTIFICATION_STATE_MAX_BYTES = 8 * 1024
NOTIFICATION_ID_RE = re.compile(r"^[a-f0-9]{64}$")
NOTIFICATION_ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}$")
NOTIFICATION_REVISION_KEY = os.urandom(32)
NOTIFICATION_CLIENT_USER = os.environ.get(
    "AUTHELIA_NOTIFICATION_CLIENT_USER", "haproxyadmin"
).strip()
try:
    NOTIFICATION_EXPECTED_UID = int(
        os.environ.get("AUTHELIA_NOTIFICATION_UID", "-1")
    )
except ValueError:
    NOTIFICATION_EXPECTED_UID = -1
try:
    NOTIFICATION_REVEAL_COOLDOWN_SECONDS = max(
        1,
        min(
            60,
            int(os.environ.get("AUTHELIA_NOTIFICATION_REVEAL_COOLDOWN", "3")),
        ),
    )
except ValueError:
    NOTIFICATION_REVEAL_COOLDOWN_SECONDS = 3
NOTIFICATION_REVEAL_LOCK = threading.Lock()
NOTIFICATION_REVEALED_AT: Dict[str, float] = {}


# ---------------------------------------------------------------------------
# Работа с файлом configuration.yml
# ---------------------------------------------------------------------------

def _backup_config_file() -> None:
    """Создаёт бэкап CONFIG_FILE с небольшой ротацией (оставляем максимум 14 файлов)."""
    if not os.path.exists(CONFIG_FILE):
        return

    # Include microseconds because the UI can save twice within one second
    # (for example Save followed by Save and apply).
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = f"{CONFIG_FILE}.bak-{ts}"

    try:
        # Never follow a swapped symlink from the container-writable runtime
        # directory while this privileged daemon creates a backup.
        os.link(CONFIG_FILE, backup_path, follow_symlinks=False)
        LOG.info("Backup created: %s", backup_path)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Backup failed (%s): %s", backup_path, exc)

    dir_name = os.path.dirname(CONFIG_FILE) or "."
    base_name = os.path.basename(CONFIG_FILE)
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


def _load_config_data() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Загружает configuration.yml.

    Возвращает (root_data, rules_list).

    root_data — полный YAML как dict.
    rules_list — список правил access_control.rules (list[dict]).
    """
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            f"Authelia config file not found: {CONFIG_FILE}"
        )

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError("configuration.yml: root is not a dict")

    ac = data.get("access_control")
    if ac is None:
        ac = {}
        data["access_control"] = ac

    if not isinstance(ac, dict):
        raise ValueError("configuration.yml: 'access_control' is not a dict")

    rules = ac.get("rules")
    if rules is None:
        rules = []
        ac["rules"] = rules

    if not isinstance(rules, list):
        raise ValueError(
            "configuration.yml: 'access_control.rules' is not a list"
        )

    return data, rules


def _deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    """
    Рекурсивное обновление dst значениями из src:
      - если и dst[k], и src[k] словари → идём внутрь
      - иначе dst[k] просто перезаписывается

    Поля, которых нет в src, в dst не трогаем.
    """
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_update(dst[key], value)
        else:
            dst[key] = value


def _mask_sensitive_fields(cfg: Dict[str, Any]) -> None:
    """Recursively redact scalar credentials before returning config to the UI."""
    sensitive = {
        "secret", "password", "token", "api_key", "private_key",
        "encryption_key", "jwt_secret", "client_secret",
    }

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                # Some keys such as authentication_backend.file.password are
                # configuration mappings, not credentials.
                if str(key).lower() in sensitive and not isinstance(value, (dict, list)):
                    node[key] = "*****"
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(cfg)


def _reject_unsafe_values(
    node: Any,
    depth: int = 0,
    seen: set[int] | None = None,
) -> int:
    if seen is None:
        seen = set()
    if depth > 20:
        raise ValueError("configuration fragment is too deeply nested")
    if isinstance(node, str):
        if len(node) > 16384 or any(ord(char) < 32 for char in node):
            raise ValueError("configuration contains an unsafe string")
        return 1
    if isinstance(node, dict):
        if id(node) in seen:
            raise ValueError("YAML aliases and recursive structures are not allowed")
        seen.add(id(node))
        count = 1
        for key, value in node.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("configuration contains an invalid key")
            count += _reject_unsafe_values(value, depth + 1, seen)
        if count > 5000:
            raise ValueError("configuration fragment is too large")
        return count
    if isinstance(node, list):
        if id(node) in seen:
            raise ValueError("YAML aliases and recursive structures are not allowed")
        seen.add(id(node))
        count = 1 + sum(
            _reject_unsafe_values(value, depth + 1, seen) for value in node
        )
        if count > 5000:
            raise ValueError("configuration fragment is too large")
        return count
    if node is not None and not isinstance(node, (bool, int, float)):
        raise ValueError("configuration contains an unsupported value")
    return 1


def _validate_config_via_authelia(tmp_host_path: str) -> None:
    """
    Валидирует конфиг через `authelia config validate` внутри контейнера.

    tmp_host_path — путь к .tmp на хосте (например /opt/authelia/configuration.yml.tmp).
    В контейнере предполагаем, что каталог CONFIG_FILE смонтирован в AUTHELIA_CONFIG_PATH.
    """
    if not VALIDATE_CONFIG:
        LOG.info(
            "AUTHELIA_VALIDATE_CONFIG=false, пропускаем authelia config validate"
        )
        return

    if not AUTHELIA_CONTAINER or not AUTHELIA_CONFIG_PATH:
        LOG.warning(
            "AUTHELIA_CONTAINER_NAME or AUTHELIA_CONFIG_PATH not set; "
            "skipping Authelia config validation",
        )
        return

    cfg_dir, cfg_base = os.path.split(AUTHELIA_CONFIG_PATH)
    if not cfg_base:
        LOG.warning(
            "AUTHELIA_CONFIG_PATH has no filename, skipping validation: %s",
            AUTHELIA_CONFIG_PATH,
        )
        return

    # CONFIG_FILE's directory is mounted as cfg_dir. Use the actual staged
    # basename so validation also works with collision-resistant temp names.
    container_tmp = os.path.join(
        cfg_dir or "/", os.path.basename(tmp_host_path)
    )

    cmd = [
        "docker",
        "exec",
        "-i",
        AUTHELIA_CONTAINER,
        "authelia",
        "config",
        "validate",
        "--config",
        container_tmp,
    ]

    LOG.info("Running Authelia config validate: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Не удалось запустить docker exec для Authelia: {exc}"
        ) from exc

    if proc.returncode != 0:
        # Authelia's config contains credentials. Some validators echo the
        # offending YAML fragment, so neither journal nor API errors may
        # include stdout/stderr here.
        LOG.error("Authelia config validation failed with rc=%s", proc.returncode)
        raise RuntimeError(
            f"Authelia configuration validation failed (rc={proc.returncode})"
        )

    LOG.info("Authelia config validate OK for %s", container_tmp)


def _save_config_data(root_data: Dict[str, Any]) -> None:
    """
    Атомарно сохраняет YAML обратно в CONFIG_FILE с предварительным бэкапом
    и (опциональной) валидацией через Authelia.

    ВАЖНО: не меняем владельца и права файла — они сохраняются такими,
    какими были до вызова (чтобы Ansible управлял ими).
    """
    # Запоминаем текущие права/владельца, если файл уже есть.
    prev_stat = None
    try:
        prev_stat = os.stat(CONFIG_FILE)
    except FileNotFoundError:
        prev_stat = None
    except OSError as exc:  # noqa: BLE001
        LOG.warning("Failed to stat %s before save: %s", CONFIG_FILE, exc)
        prev_stat = None

    _backup_config_file()

    # Owner/mode MUST be set on the temp file *before* validation and the
    # rename. `authelia config validate` runs inside the Authelia container
    # (uid 19010, not root); a root-owned temp file is unreadable there, so
    # validation would fail with "permission denied" and no rule change (or any
    # config edit) could ever be saved through the web UI. The rename then also
    # exposes a readable file, matching the users-database fix.
    if prev_stat is not None:
        target_uid, target_gid = prev_stat.st_uid, prev_stat.st_gid
    else:
        try:
            entry = pwd.getpwnam("authelia")
            target_uid, target_gid = entry.pw_uid, entry.pw_gid
        except KeyError:
            target_uid, target_gid = -1, -1

    tmp_path = CONFIG_FILE + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            root_data,
            f,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
        f.flush()
        os.fsync(f.fileno())

    if target_uid != -1:
        try:
            os.chown(tmp_path, target_uid, target_gid)
        except OSError as exc:  # noqa: BLE001
            LOG.warning("Failed to set owner/group on temp config file: %s", exc)
    try:
        os.chmod(tmp_path, 0o640)
    except OSError as exc:  # noqa: BLE001
        LOG.warning("Failed to set mode on temp config file: %s", exc)

    try:
        _validate_config_via_authelia(tmp_path)
    except Exception as exc:  # noqa: BLE001
        LOG.error("Authelia config validation failed: %s", exc)
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

    # Атомарная замена: боевой путь всегда указывает на читаемый файл.
    os.replace(tmp_path, CONFIG_FILE)
    LOG.info("Config file updated: %s", CONFIG_FILE)

    # Владелец/права уже выставлены на temp до rename; этот блок оставлен как
    # подстраховка на случай нестандартных default-ACL каталога.
    if prev_stat is not None:
        try:
            # Владелец/группа
            os.chown(CONFIG_FILE, prev_stat.st_uid, prev_stat.st_gid)
        except PermissionError as exc:  # noqa: BLE001
            LOG.warning(
                "Failed to restore owner/group for %s: %s",
                CONFIG_FILE,
                exc,
            )
        except OSError as exc:  # noqa: BLE001
            LOG.warning(
                "OS error while restoring owner/group for %s: %s",
                CONFIG_FILE,
                exc,
            )

        try:
            # Права (маска с обрезкой до 0777)
            os.chmod(CONFIG_FILE, 0o640)
        except OSError as exc:  # noqa: BLE001
            LOG.warning(
                "Failed to restore mode for %s: %s",
                CONFIG_FILE,
                exc,
            )


# ---------------------------------------------------------------------------
# Transactional Authelia notifier / SMTP settings
# ---------------------------------------------------------------------------

class MailSettingsError(ValueError):
    """Invalid or unsafe mail configuration."""


class RelayUnavailableError(MailSettingsError):
    """The installed Compose stack has no mail_relay service."""


class MailSettingsConflictError(MailSettingsError):
    """A managed file changed during the guarded transaction."""


class MailRelayQueueSafetyError(RuntimeError):
    """Relay recreation was refused to preserve an existing mail queue."""

    def __init__(self, message: str, *, authelia_stopped: bool = False) -> None:
        super().__init__(message)
        self.authelia_stopped = authelia_stopped


def _safe_read_file(path: str) -> Tuple[bytes, os.stat_result]:
    """Read a bounded regular file without following symbolic links."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MailSettingsError(f"cannot safely open {path}: {exc}") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise MailSettingsError(f"managed path is not a regular file: {path}")
        if file_stat.st_size < 0 or file_stat.st_size > MAX_CONFIG_BYTES:
            raise MailSettingsError(f"managed file has an unsafe size: {path}")
        chunks = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_CONFIG_BYTES:
            raise MailSettingsError(f"managed file is too large: {path}")
        return data, file_stat
    finally:
        os.close(fd)


def _decode_text(data: bytes, path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise MailSettingsError(f"managed file is not UTF-8: {path}") from None


def _load_yaml_mapping_bytes(data: bytes, path: str) -> Dict[str, Any]:
    try:
        value = yaml.safe_load(_decode_text(data, path)) or {}
    except yaml.YAMLError:
        # Parser diagnostics may quote the offending line, including a mail
        # password from secrets.yml. Keep API and journal errors content-free.
        raise MailSettingsError(f"invalid YAML in managed file: {path}") from None
    if not isinstance(value, dict):
        raise MailSettingsError(f"YAML root must be a mapping: {path}")
    _reject_unsafe_values(value)
    return value


def _decode_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value[1:-1]
        if isinstance(decoded, str):
            return decoded.replace("$$", "$")
    if len(value) >= 2 and value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    return value


def _parse_env(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            result[key] = _decode_env_value(value)
    return result


def _encode_env_value(value: str) -> str:
    # Compose interpolates '$' in unquoted/double-quoted env_file values. '$$'
    # is its documented literal-dollar escape. JSON quoting safely handles
    # spaces, '#', quotes and backslashes without invoking a shell.
    return json.dumps(value.replace("$", "$$"), ensure_ascii=False)


def _render_env_with_updates(text: str, updates: Dict[str, str]) -> str:
    emitted: set[str] = set()
    rendered: List[str] = []
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            rendered.append(line)
            continue
        raw_key = line.split("=", 1)[0]
        key = raw_key.strip()
        if key not in updates:
            rendered.append(line)
            continue
        # Collapse duplicate credential keys. Docker env_file normally uses
        # the last occurrence, so preserving a stale duplicate would defeat
        # password replacement/clearing.
        if key not in emitted:
            rendered.append(f"{key}={_encode_env_value(updates[key])}")
            emitted.add(key)
    for key, value in updates.items():
        if key not in emitted:
            rendered.append(f"{key}={_encode_env_value(value)}")
    return "\n".join(rendered).rstrip("\n") + "\n"


def _yaml_bytes(value: Dict[str, Any]) -> bytes:
    return yaml.safe_dump(
        value,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    ).encode("utf-8")


def _stage_file(
    path: str,
    data: bytes,
    previous_stat: os.stat_result,
    *,
    force_mode: int | None = None,
) -> str:
    directory = os.path.dirname(path) or "."
    prefix = "." + os.path.basename(path) + ".mail-"
    fd, temp_path = tempfile.mkstemp(prefix=prefix, dir=directory)
    try:
        mode = force_mode if force_mode is not None else stat.S_IMODE(previous_stat.st_mode)
        os.fchmod(fd, mode)
        try:
            os.fchown(fd, previous_stat.st_uid, previous_stat.st_gid)
        except PermissionError:
            if os.geteuid() == 0:
                raise
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
    os.close(fd)
    return temp_path


def _fsync_directories(paths: List[str]) -> None:
    for directory in sorted({os.path.dirname(path) or "." for path in paths}):
        try:
            fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            continue
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)


def _restore_files(
    snapshots: Dict[str, Tuple[bytes, os.stat_result]],
    paths: List[str] | None = None,
) -> None:
    restore_paths = paths or list(snapshots)
    staged: Dict[str, str] = {}
    try:
        for path in restore_paths:
            data, old_stat = snapshots[path]
            staged[path] = _stage_file(
                path,
                data,
                old_stat,
                force_mode=(
                    0o600
                    if path in {MANAGED_SECRETS_FILE, MAIL_NOTIFY_STATE_FILE}
                    else None
                ),
            )
        for path in restore_paths:
            os.replace(staged.pop(path), path)
        _fsync_directories(restore_paths)
    finally:
        for temp_path in staged.values():
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _commit_mail_files(
    updates: Dict[str, bytes],
    snapshots: Dict[str, Tuple[bytes, os.stat_result]],
) -> None:
    staged: Dict[str, str] = {}
    replaced: List[str] = []
    try:
        for path, data in updates.items():
            _old_data, old_stat = snapshots[path]
            staged[path] = _stage_file(
                path,
                data,
                old_stat,
                force_mode=(
                    0o600
                    if path in {MANAGED_SECRETS_FILE, MAIL_NOTIFY_STATE_FILE}
                    else None
                ),
            )
        _validate_config_via_authelia(staged[CONFIG_FILE])
        # Validation can take several seconds. Refuse to overwrite Ansible or
        # another administrator if any source changed after revision check.
        for path, (expected_data, _expected_stat) in snapshots.items():
            current_data, _current_stat = _safe_read_file(path)
            if not hmac.compare_digest(current_data, expected_data):
                raise MailSettingsConflictError(
                    f"managed mail source changed during validation: {path}"
                )
        _backup_config_file()
        for path in updates:
            os.replace(staged.pop(path), path)
            replaced.append(path)
        _fsync_directories(list(updates))
    except Exception:
        if replaced:
            _restore_files(snapshots, replaced)
        raise
    finally:
        for temp_path in staged.values():
            try:
                os.unlink(temp_path)
            except OSError:
                pass


@contextmanager
def _mail_lock():
    lock_dir = os.path.dirname(MAIL_LOCK_FILE) or "."
    os.makedirs(lock_dir, mode=0o750, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(MAIL_LOCK_FILE, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise MailSettingsError("mail settings lock is not a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _mail_notify_state_path() -> str:
    # MANAGED_CONFIG_DIR is intentionally resolved at call time. Tests and
    # supported service overrides may change it after module import.
    return os.path.join(MANAGED_CONFIG_DIR, "mail-notify.json")


def _ensure_mail_notify_state_file() -> str:
    """Seed the state for upgrades which predate the certificate hook."""
    path = _mail_notify_state_path()
    if os.path.lexists(path):
        return path
    vars_data, _vars_stat = _safe_read_file(MANAGED_VARS_FILE)
    managed_vars = _load_yaml_mapping_bytes(vars_data, MANAGED_VARS_FILE)
    only_for = managed_vars.get("mail_notify_only_for", [])
    if not isinstance(only_for, list):
        only_for = []
    data = (
        json.dumps(
            {
                "enabled": bool(managed_vars.get("mail_notify_enabled", False)),
                "from": str(managed_vars.get("mail_notify_from") or ""),
                "only_for": only_for,
                "to": str(managed_vars.get("mail_notify_to") or ""),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(prefix=".mail-notify.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError:
            pass
        _fsync_directories([path])
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_path)
        except OSError:
            pass
    return path


def _load_mail_state() -> Dict[str, Any]:
    mail_notify_state_file = _ensure_mail_notify_state_file()
    paths = [
        CONFIG_FILE,
        ENV_FILE,
        COMPOSE_FILE,
        MANAGED_VARS_FILE,
        MANAGED_AUTHELIA_FILE,
        MANAGED_SECRETS_FILE,
        mail_notify_state_file,
    ]
    snapshots = {path: _safe_read_file(path) for path in paths}
    return {
        "snapshots": snapshots,
        "config": _load_yaml_mapping_bytes(snapshots[CONFIG_FILE][0], CONFIG_FILE),
        "env_text": _decode_text(snapshots[ENV_FILE][0], ENV_FILE),
        "env": _parse_env(_decode_text(snapshots[ENV_FILE][0], ENV_FILE)),
        "compose": _load_yaml_mapping_bytes(
            snapshots[COMPOSE_FILE][0], COMPOSE_FILE
        ),
        "vars": _load_yaml_mapping_bytes(
            snapshots[MANAGED_VARS_FILE][0], MANAGED_VARS_FILE
        ),
        "authelia": _load_yaml_mapping_bytes(
            snapshots[MANAGED_AUTHELIA_FILE][0], MANAGED_AUTHELIA_FILE
        ),
        "secrets": _load_yaml_mapping_bytes(
            snapshots[MANAGED_SECRETS_FILE][0], MANAGED_SECRETS_FILE
        ),
        "mail_notify_state": json.loads(
            _decode_text(
                snapshots[mail_notify_state_file][0], mail_notify_state_file
            )
        ),
    }


def _mail_revision(state: Dict[str, Any]) -> str:
    # This digest covers secret-bearing files. Keep it opaque with a
    # per-process HMAC key so the public revision cannot become an offline
    # password oracle. A daemon restart intentionally invalidates open forms.
    digest = hmac.new(MAIL_REVISION_KEY, digestmod=hashlib.sha256)
    snapshots = state["snapshots"]
    for path in sorted(snapshots):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(snapshots[path][0])
        digest.update(b"\0")
    return digest.hexdigest()


def _relay_available(state: Dict[str, Any]) -> bool:
    services = state.get("compose", {}).get("services")
    return isinstance(services, dict) and isinstance(services.get("mail_relay"), dict)


def _smtp_address_parts(address: Any) -> Tuple[str, int, str]:
    text = str(address or "").strip()
    try:
        parsed = urlsplit(text)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "", 25, "starttls"
    scheme = parsed.scheme.lower()
    tls_mode = "smtps" if scheme in {"smtps", "submissions"} else "starttls"
    return host, port or (465 if tls_mode == "smtps" else 25), tls_mode


def _mail_mode(config: Dict[str, Any]) -> str:
    notifier = config.get("notifier")
    if not isinstance(notifier, dict) or isinstance(notifier.get("filesystem"), dict):
        return "filesystem"
    smtp = notifier.get("smtp")
    if not isinstance(smtp, dict):
        return "filesystem"
    host, _port, _tls_mode = _smtp_address_parts(smtp.get("address"))
    return "relay" if host == "mail_relay" else "direct"


def _first_text(*values: Any, default: str = "") -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _current_password(state: Dict[str, Any]) -> str:
    config = state["config"]
    notifier = config.get("notifier") if isinstance(config, dict) else None
    smtp = notifier.get("smtp") if isinstance(notifier, dict) else None
    smtp_password = smtp.get("password") if isinstance(smtp, dict) else ""
    env = state["env"]
    return _first_text(
        env.get("SMTP_PASSWORD"),
        env.get("MAIL_SMTP_PASSWORD"),
        state["secrets"].get("mail_smtp_pass"),
        smtp_password,
    )


def _mail_settings_model(state: Dict[str, Any]) -> Dict[str, Any]:
    config = state["config"]
    notifier = config.get("notifier")
    notifier = notifier if isinstance(notifier, dict) else {}
    smtp = notifier.get("smtp")
    smtp = smtp if isinstance(smtp, dict) else {}
    runtime_mode = _mail_mode(config)
    mode = "filesystem" if runtime_mode == "filesystem" else "relay"
    env = state["env"]
    managed_vars = state["vars"]
    managed_authelia = state["authelia"]

    host = _first_text(
        env.get("SMTP_SERVER"),
        env.get("MAIL_SMTP_SERVER"),
        managed_vars.get("mail_smtp_host"),
    )
    raw_port = _first_text(
        env.get("SMTP_PORT"),
        env.get("MAIL_SMTP_PORT"),
        managed_vars.get("mail_smtp_port"),
        default="587",
    )
    try:
        port = int(raw_port)
    except ValueError:
        port = 587
    username = _first_text(
        env.get("SMTP_USERNAME"),
        env.get("MAIL_SMTP_USERNAME"),
        managed_vars.get("mail_smtp_user"),
    )
    tls_mode = _first_text(
        env.get("EASY_HA_PROXY_SMTP_TLS_MODE"),
        managed_vars.get("mail_smtp_ssl_mode"),
        default="smtps" if port == 465 else "starttls",
    ).lower()
    if tls_mode not in MAIL_TLS_MODES:
        tls_mode = "smtps" if port == 465 else "starttls"

    tls_cfg = smtp.get("tls")
    tls_cfg = tls_cfg if isinstance(tls_cfg, dict) else {}
    settings = {
        "mode": mode,
        "host": host,
        "port": port,
        "username": username,
        "password_configured": bool(_current_password(state)),
        "sender": _first_text(
            smtp.get("sender"),
            managed_vars.get("mail_notify_from"),
        ),
        "recipient": _first_text(
            smtp.get("startup_check_address"),
            managed_vars.get("mail_notify_to"),
        ),
        "subject": _first_text(smtp.get("subject"), managed_authelia.get("mail_subject")),
        "timeout": _first_text(
            smtp.get("timeout"), managed_authelia.get("mail_smtp_timeout"), default="10s"
        ),
        "tls_mode": tls_mode,
        "tls_skip_verify": bool(
            tls_cfg.get(
                "skip_verify",
                managed_vars.get(
                    "mail_smtp_tls_skip_verify",
                    managed_authelia.get("mail_smtp_tls_skip_verify", False),
                ),
            )
        ),
    }
    return {
        "ok": True,
        "settings": settings,
        "capabilities": {
            "relay_available": _relay_available(state),
            "legacy_direct": runtime_mode == "direct",
        },
        "revision": _mail_revision(state),
    }


def _validate_mail_text(
    value: Any,
    label: str,
    maximum: int,
    *,
    required: bool = True,
) -> str:
    if not isinstance(value, str):
        raise MailSettingsError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise MailSettingsError(f"{label} is required")
    if len(text) > maximum or CONTROL_RE.search(text):
        raise MailSettingsError(f"{label} contains invalid characters or is too long")
    return text


def _validate_mail_host(value: Any) -> str:
    host = _validate_mail_text(value, "SMTP host", 253)
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if not all(DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise MailSettingsError("SMTP host must be a valid IP address or DNS name")
    return host.rstrip(".")


def _validate_mail_email(value: Any, label: str) -> str:
    email = _validate_mail_text(value, label, 254)
    if not EMAIL_RE.fullmatch(email):
        raise MailSettingsError(f"{label} must be a valid email address")
    return email


def _validate_mail_payload(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise MailSettingsError("settings must be an object")
    missing = MAIL_FIELDS - set(value)
    unexpected = set(value) - MAIL_FIELDS
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(sorted(missing)))
        if unexpected:
            details.append("unsupported: " + ", ".join(sorted(unexpected)))
        raise MailSettingsError(
            "invalid mail settings fields (" + "; ".join(details) + ")"
        )

    mode = str(value.get("mode") or "").strip().lower()
    if mode not in MAIL_MODES:
        raise MailSettingsError("mode must be filesystem or relay")
    tls_mode = str(value.get("tls_mode") or "").strip().lower()
    if tls_mode not in MAIL_TLS_MODES:
        raise MailSettingsError("tls_mode must be smtps, starttls, or plain")
    password_action = str(value.get("password_action") or "").strip().lower()
    if password_action not in MAIL_PASSWORD_ACTIONS:
        raise MailSettingsError("password_action must be keep, replace, or clear")

    raw_host = value.get("host")
    host = (
        ""
        if mode == "filesystem" and isinstance(raw_host, str) and not raw_host.strip()
        else _validate_mail_host(raw_host)
    )
    raw_port = value.get("port")
    if mode == "filesystem" and raw_port in (None, ""):
        raw_port = 25
    if isinstance(raw_port, bool):
        raise MailSettingsError("SMTP port must be an integer")
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise MailSettingsError("SMTP port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise MailSettingsError("SMTP port must be between 1 and 65535")

    password = value.get("password")
    if not isinstance(password, str):
        raise MailSettingsError("password must be a string")
    if len(password) > 1024 or CONTROL_RE.search(password):
        raise MailSettingsError("password contains invalid characters or is too long")
    if password_action == "replace" and not password:
        raise MailSettingsError("a non-empty password is required when replacing it")
    if password_action != "replace" and password:
        raise MailSettingsError(
            "password must be empty unless password_action is replace"
        )

    tls_skip_verify = value.get("tls_skip_verify")
    if not isinstance(tls_skip_verify, bool):
        raise MailSettingsError("tls_skip_verify must be true or false")
    timeout = _validate_mail_text(value.get("timeout"), "Timeout", 16)
    if not TIMEOUT_RE.fullmatch(timeout):
        raise MailSettingsError("Timeout must look like 10s, 2m, 1h, or 500ms")

    raw_sender = value.get("sender")
    raw_recipient = value.get("recipient")
    if mode == "filesystem":
        sender = (
            _validate_mail_email(raw_sender, "Sender")
            if isinstance(raw_sender, str) and raw_sender.strip()
            else ""
        )
        recipient = (
            _validate_mail_email(raw_recipient, "Recipient")
            if isinstance(raw_recipient, str) and raw_recipient.strip()
            else ""
        )
        subject = _validate_mail_text(
            value.get("subject"), "Subject", 255, required=False
        )
    else:
        sender = _validate_mail_email(raw_sender, "Sender")
        recipient = _validate_mail_email(raw_recipient, "Recipient")
        subject = _validate_mail_text(value.get("subject"), "Subject", 255)

    return {
        "mode": mode,
        "host": host,
        "port": port,
        "username": _validate_mail_text(
            value.get("username"), "SMTP username", 320, required=False
        ),
        "password_action": password_action,
        "password": password,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "timeout": timeout,
        "tls_mode": tls_mode,
        "tls_skip_verify": tls_skip_verify,
    }


def _mail_relay_hostname(state: Dict[str, Any], settings: Dict[str, Any]) -> str:
    """Derive a stable Postfix identity, never from the upstream SMTP host."""
    managed_vars = state.get("vars")
    managed_vars = managed_vars if isinstance(managed_vars, dict) else {}
    domains: List[str] = []
    root_domain = managed_vars.get("root_domain")
    if isinstance(root_domain, str) and root_domain.strip():
        domains.append(root_domain.strip().strip("."))
    for sender in (settings.get("sender"), managed_vars.get("mail_notify_from")):
        if isinstance(sender, str) and "@" in sender:
            domains.append(sender.rsplit("@", 1)[1].strip().strip("."))
    for domain in domains:
        hostname = f"mail-relay.{domain}".lower()
        if len(hostname) <= 253 and all(
            DNS_LABEL_RE.fullmatch(label) for label in hostname.split(".")
        ):
            return hostname
    raise MailSettingsError(
        "cannot derive a valid mail relay hostname from root_domain or sender"
    )


def _prepare_mail_updates(
    state: Dict[str, Any], settings: Dict[str, Any]
) -> Dict[str, bytes]:
    mode = settings["mode"]
    password = _current_password(state)
    if mode == "relay" and settings["password_action"] == "replace":
        password = settings["password"]
    elif mode == "relay" and settings["password_action"] == "clear":
        password = ""

    config = deepcopy(state["config"])
    old_notifier = config.get("notifier")
    old_notifier = old_notifier if isinstance(old_notifier, dict) else {}
    notifier: Dict[str, Any] = {
        "disable_startup_check": bool(
            old_notifier.get("disable_startup_check", False)
        ),
        "template_path": str(
            old_notifier.get("template_path") or "/config/email_templates"
        ),
    }
    if mode == "filesystem":
        old_filesystem = old_notifier.get("filesystem")
        old_filesystem = old_filesystem if isinstance(old_filesystem, dict) else {}
        notifier["filesystem"] = {
            "filename": str(
                old_filesystem.get("filename") or "/config/notification.log"
            )
        }
    else:
        common_smtp: Dict[str, Any] = {
            "timeout": settings["timeout"],
            "sender": settings["sender"],
            "subject": settings["subject"],
            "startup_check_address": settings["recipient"],
            "address": "smtp://mail_relay:25",
            "username": "",
            "password": "",
            "disable_require_tls": True,
            "disable_starttls": True,
        }
        notifier["smtp"] = common_smtp
    config["notifier"] = notifier

    env_updates: Dict[str, str] = {}
    if mode == "relay":
        if settings["tls_mode"] == "plain":
            relay_tls_security_level = "none"
            relay_use_tls = "no"
        else:
            relay_tls_security_level = (
                "encrypt" if settings["tls_skip_verify"] else "verify"
            )
            relay_use_tls = "yes"
        relay_tls_wrappermode = (
            "yes" if settings["tls_mode"] == "smtps" else "no"
        )
        relay_hostname = _mail_relay_hostname(state, settings)
        env_updates = {
            "MAIL_SMTP_SERVER": settings["host"],
            "MAIL_SMTP_PORT": str(settings["port"]),
            "MAIL_SMTP_USERNAME": settings["username"],
            "MAIL_SMTP_PASSWORD": password,
            "SERVER_HOSTNAME": relay_hostname,
            "SMTP_SERVER": settings["host"],
            "SMTP_PORT": str(settings["port"]),
            "SMTP_USERNAME": settings["username"],
            "SMTP_PASSWORD": password,
            "EASY_HA_PROXY_SMTP_TLS_MODE": settings["tls_mode"],
            "POSTFIX_smtp_tls_security_level": relay_tls_security_level,
            "POSTFIX_smtp_tls_wrappermode": relay_tls_wrappermode,
            "POSTFIX_smtp_use_tls": relay_use_tls,
            "POSTFIX_smtp_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
            "POSTFIX_smtp_connect_timeout": settings["timeout"],
        }

    managed_vars = deepcopy(state["vars"])
    managed_vars["mail_notify_enabled"] = mode == "relay"
    if mode == "relay":
        managed_vars.update(
            {
                "mail_notify_to": settings["recipient"],
                "mail_notify_from": settings["sender"],
                "mail_smtp_host": settings["host"],
                "mail_smtp_port": settings["port"],
                "mail_smtp_user": settings["username"],
                "mail_smtp_auth": "on" if settings["username"] else "off",
                "mail_smtp_ssl_mode": settings["tls_mode"],
                "mail_smtp_tls_skip_verify": settings["tls_skip_verify"],
            }
        )
    managed_authelia = deepcopy(state["authelia"])
    managed_authelia.update(
        {
            "mail_relay_server": mode == "relay",
            "authelia_notifier_type": "filesystem" if mode == "filesystem" else "smtp",
            "mail_subject": settings["subject"],
            "mail_smtp_timeout": settings["timeout"],
        }
    )
    managed_secrets = deepcopy(state["secrets"])
    if mode == "relay":
        managed_secrets["mail_smtp_pass"] = password
    notify_state = state.get("mail_notify_state")
    notify_state = notify_state if isinstance(notify_state, dict) else {}
    only_for = notify_state.get("only_for")
    only_for = only_for if isinstance(only_for, list) else []

    return {
        CONFIG_FILE: _yaml_bytes(config),
        ENV_FILE: _render_env_with_updates(state["env_text"], env_updates).encode(
            "utf-8"
        ),
        MANAGED_VARS_FILE: _yaml_bytes(managed_vars),
        MANAGED_AUTHELIA_FILE: _yaml_bytes(managed_authelia),
        MANAGED_SECRETS_FILE: _yaml_bytes(managed_secrets),
        _mail_notify_state_path(): (
            json.dumps(
                {
                    "enabled": mode == "relay",
                    "from": (
                        settings["sender"]
                        if mode == "relay"
                        else str(notify_state.get("from") or "")
                    ),
                    "only_for": only_for,
                    "to": (
                        settings["recipient"]
                        if mode == "relay"
                        else str(notify_state.get("to") or "")
                    ),
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    }


def _container_health(container: str, timeout: int) -> bool:
    deadline = time.time() + timeout
    template = "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
    while time.time() < deadline:
        try:
            proc = subprocess.run(
                ["docker", "inspect", "--format", template, container],
                text=True,
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if proc.returncode == 0:
            status, _separator, health = proc.stdout.strip().partition("|")
            if status == "running" and health in {"healthy", "none"}:
                return True
            if status in {"dead", "exited"} or health == "unhealthy":
                return False
        time.sleep(1)
    return False


def _relay_queue_status() -> str:
    """Return absent, empty, nonempty, or unknown without logging mail."""
    try:
        inspect = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "mail_relay"],
            text=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if inspect.returncode != 0:
        return "absent"
    if inspect.stdout.strip().lower() != "true":
        # A stopped container may still hold a Postfix spool. Start the exact
        # existing container first so its queue can be inspected and drained;
        # never force-recreate it blindly.
        try:
            started = subprocess.run(
                ["docker", "start", "mail_relay"],
                text=True,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        if started.returncode != 0 or not _container_health(
            "mail_relay", RESTART_TIMEOUT
        ):
            return "unknown"

    commands = (
        ["docker", "exec", "mail_relay", "postqueue", "-j"],
        ["docker", "exec", "mail_relay", "postqueue", "-p"],
    )
    for index, command in enumerate(commands):
        try:
            proc = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        output = (proc.stdout or "").strip()
        if index == 0:
            return "empty" if not output else "nonempty"
        if not output or "Mail queue is empty" in output:
            return "empty"
        return "nonempty"
    return "unknown"


def _relay_spool_status() -> str:
    """Return absent, managed, legacy, or unknown for the Postfix spool."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", "mail_relay"],
            text=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if proc.returncode != 0:
        try:
            listed = subprocess.run(
                [
                    "docker", "ps", "-a", "--filter", "name=^/mail_relay$",
                    "--format", "{{.Names}}",
                ],
                text=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        if listed.returncode == 0 and not listed.stdout.strip():
            return "absent"
        return "unknown"
    try:
        mounts = json.loads(proc.stdout)
    except (TypeError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(mounts, list):
        return "unknown"
    for mount in mounts:
        if not isinstance(mount, dict):
            return "unknown"
        if mount.get("Destination") != "/var/spool/postfix":
            continue
        if (
            mount.get("Type") == "volume"
            and mount.get("Name") == "easy-ha-proxy-mail-relay-spool"
        ):
            return "managed"
        return "legacy"
    return "legacy"


def _mail_transport_changed(
    state: Dict[str, Any], settings: Dict[str, Any]
) -> bool:
    current = _mail_settings_model(state)["settings"]
    if any(
        settings[key] != current.get(key)
        for key in (
            "host", "port", "username", "timeout", "tls_mode",
            "tls_skip_verify",
        )
    ):
        return True
    password_action = settings["password_action"]
    current_password = _current_password(state)
    if password_action == "clear":
        return bool(current_password)
    if password_action == "replace":
        # Never expose a stored-password equality timing oracle.
        return True
    return False


def _apply_mail_stack(
    mode: str, *, recreate_relay: bool = True
) -> Dict[str, Any]:
    if mode != "relay":
        result = _handle_restart({})
        if not result.get("ok"):
            raise RuntimeError(result.get("error") or "Authelia restart failed")
        relay_status = _relay_queue_status()
        if relay_status == "empty":
            try:
                stopped = subprocess.run(
                    ["docker", "stop", "mail_relay"],
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired):
                stopped = None
            if stopped is not None and stopped.returncode == 0:
                return {"relay_state": "stopped"}
            return {
                "relay_state": "left_running",
                "warning": (
                    "Email notifications are disabled, but the empty relay "
                    "container could not be stopped."
                ),
            }
        if relay_status in {"nonempty", "unknown"}:
            return {
                "relay_state": "left_running",
                "warning": (
                    "Email notifications are disabled. The relay container was "
                    "left running because its queue is not empty or could not "
                    "be verified; let it drain before stopping it."
                ),
            }
        return {"relay_state": relay_status}

    if not recreate_relay:
        result = _handle_restart({})
        if not result.get("ok"):
            raise RuntimeError(result.get("error") or "Authelia restart failed")
        return {"relay_state": "unchanged"}

    spool_status = _relay_spool_status()
    if spool_status == "unknown":
        raise MailRelayQueueSafetyError(
            "mail_relay spool safety could not be verified; inspect the existing "
            "container before applying new transport settings"
        )
    if spool_status == "legacy":
        queue_status = _relay_queue_status()
        if queue_status == "nonempty":
            raise MailRelayQueueSafetyError(
                "the legacy mail_relay has queued messages in its container layer; "
                "wait for the queue to drain before migrating it"
            )
        if queue_status == "unknown":
            raise MailRelayQueueSafetyError(
                "the legacy mail_relay queue could not be inspected; its "
                "container-layer spool will not be replaced"
            )

    # Quiesce Authelia before the final queue check. The managed certificate
    # hook takes a shared MAIL_LOCK_FILE lock, while this transaction holds the
    # exclusive lock, so neither managed producer can enqueue during recreate.
    LOG.info("Stopping Authelia before mail relay recreation")
    try:
        stopped = subprocess.run(
            ["docker", "stop", AUTHELIA_CONTAINER],
            text=True,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("could not stop Authelia for safe relay apply") from exc
    if stopped.returncode != 0:
        raise RuntimeError(
            f"could not stop Authelia for safe relay apply (rc={stopped.returncode})"
        )

    if spool_status == "legacy":
        queue_status = _relay_queue_status()
        if queue_status == "nonempty":
            raise MailRelayQueueSafetyError(
                "the legacy mail_relay received queued messages during the "
                "migration barrier; the old container will be preserved",
                authelia_stopped=True,
            )
        if queue_status == "unknown":
            raise MailRelayQueueSafetyError(
                "the legacy mail_relay queue could not be verified after "
                "stopping Authelia; the old container will be preserved",
                authelia_stopped=True,
            )

    command = [
        "docker", "compose", "-f", COMPOSE_FILE,
        "--profile", "mail-relay", "up", "-d",
        "--force-recreate", "mail_relay",
    ]
    LOG.info("Recreating Authelia mail relay stack")
    try:
        proc = subprocess.run(
            command,
            cwd=os.path.dirname(COMPOSE_FILE) or ".",
            text=True,
            capture_output=True,
            timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"docker compose mail apply failed: {exc}") from exc
    if proc.returncode != 0:
        # Compose output can include expanded environment values. Keep the
        # password out of both the daemon journal and JSON response.
        LOG.error("docker compose mail apply failed with rc=%s", proc.returncode)
        raise RuntimeError(
            f"docker compose mail apply failed (rc={proc.returncode})"
        )
    if not _container_health("mail_relay", RESTART_TIMEOUT):
        raise RuntimeError("mail_relay did not become healthy")
    result = _handle_restart({})
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "Authelia restart failed")
    return {"relay_state": "running"}


def _mail_test_message(
    sender: str, recipient: str, *, message_id: str
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "easy-ha-proxy email test"
    message["Message-ID"] = message_id
    message.set_content(
        "This is a test message sent from the easy-ha-proxy Authelia mail "
        "settings page. The result shown by easy-ha-proxy can confirm whether "
        "the configured external SMTP relay accepted this message, but not "
        "whether it reached the final inbox."
    )
    return message


def _parse_mail_test_delivery(
    output: str, message_id: str
) -> Tuple[str, str]:
    """Return queue id and a non-sensitive delivery state from Postfix logs."""
    queue_id = ""
    escaped_id = re.escape(message_id)
    for line in output.splitlines():
        match = re.search(
            rf"(?:^|\s)([A-Za-z0-9]+):\s+.*message-id={escaped_id}(?:\s|$)",
            line,
            re.IGNORECASE,
        )
        if match:
            queue_id = match.group(1)
            break
    if not queue_id:
        return "", "queued"

    state = "queued"
    queue_pattern = re.compile(
        rf"(?:^|\s){re.escape(queue_id)}:\s+.*\bstatus="
        r"(sent|deferred|bounced|expired)\b",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = queue_pattern.search(line)
        if not match:
            continue
        postfix_state = match.group(1).lower()
        if postfix_state == "sent":
            return queue_id, "relay_accepted"
        if postfix_state in {"bounced", "expired"}:
            return queue_id, "rejected"
        if postfix_state == "deferred":
            state = "deferred"
    return queue_id, state


def _wait_for_mail_test_delivery(
    message_id: str, *, submitted_at: float, timeout: int
) -> str:
    """Best-effort bounded wait for the first external Postfix result.

    The relay image publishes Postfix logs through ``docker logs``.  A unique
    Message-ID lets us correlate only this test message without returning or
    logging SMTP responses, sender addresses, or recipient addresses.  Missing
    or unfamiliar logs safely degrade to ``queued`` instead of overstating
    delivery.
    """
    deadline = time.monotonic() + timeout
    last_state = "queued"
    since = str(max(0, int(submitted_at) - 2))
    while time.monotonic() < deadline:
        try:
            proc = subprocess.run(
                [
                    "docker", "logs", "--since", since, "--tail", "2000",
                    "mail_relay",
                ],
                text=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(0.5)
            continue
        if proc.returncode == 0:
            # Docker may return container logs on stdout, stderr, or both.
            # Keep the raw content process-local because it contains addresses.
            _queue_id, state = _parse_mail_test_delivery(
                (proc.stdout or "") + "\n" + (proc.stderr or ""),
                message_id,
            )
            if state in {"relay_accepted", "rejected"}:
                return state
            if state == "deferred":
                last_state = state
        time.sleep(0.5)
    return last_state


def _send_relay_mail_test(settings: Dict[str, Any], recipient: str) -> str:
    if not _container_health("mail_relay", 10):
        raise RuntimeError("mail_relay is not healthy")
    sender = _validate_mail_email(settings.get("sender"), "Sender")
    message_id = (
        f"<easy-ha-proxy-test-{secrets.token_hex(16)}@easy-ha-proxy.invalid>"
    )
    message = _mail_test_message(
        sender,
        recipient,
        message_id=message_id,
    )
    command = [
        "docker", "exec", "-i", "mail_relay", "/usr/sbin/sendmail",
        "-i", "-f", sender, "--", recipient,
    ]
    submitted_at = time.time()
    proc = subprocess.run(
        command,
        input=message.as_bytes(),
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError("mail_relay rejected the test message")
    return _wait_for_mail_test_delivery(
        message_id,
        submitted_at=submitted_at,
        timeout=MAIL_TEST_RESULT_TIMEOUT,
    )


def _claim_mail_test_slot() -> int:
    global MAIL_TEST_LAST_AT  # noqa: PLW0603
    now = time.monotonic()
    with MAIL_TEST_LOCK:
        elapsed = now - MAIL_TEST_LAST_AT
        if elapsed < MAIL_TEST_COOLDOWN_SECONDS:
            return max(1, int(MAIL_TEST_COOLDOWN_SECONDS - elapsed) + 1)
        MAIL_TEST_LAST_AT = now
    return 0


# ---------------------------------------------------------------------------
# Рестарт Authelia и ожидание порта
# ---------------------------------------------------------------------------

def _authelia_health_ready() -> bool:
    """Return true only after Authelia's HTTP health endpoint is ready."""
    connection = http.client.HTTPConnection(RESTART_HOST, RESTART_PORT, timeout=2.0)
    try:
        connection.request(
            "GET",
            AUTHELIA_HEALTH_PATH,
            headers={"Connection": "close", "User-Agent": "easy-ha-proxy-configd"},
        )
        response = connection.getresponse()
        response.read(4096)
        return 200 <= response.status < 300
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def _haproxy_stats_report_backend_up(stats: str) -> bool:
    """Parse `show stat` output and require the exact Authelia server to be UP."""
    rows = csv.reader(stats.splitlines())
    try:
        header = next(rows)
    except StopIteration:
        return False
    if not header:
        return False
    header[0] = header[0].lstrip("# ")
    try:
        pxname_index = header.index("pxname")
        svname_index = header.index("svname")
        status_index = header.index("status")
    except ValueError:
        return False

    required_columns = max(pxname_index, svname_index, status_index)
    for row in rows:
        if len(row) <= required_columns:
            continue
        if (
            row[pxname_index] == AUTHELIA_HAPROXY_BACKEND
            and row[svname_index] == AUTHELIA_HAPROXY_SERVER
        ):
            status = row[status_index].strip().upper()
            return status == "UP" or status.startswith("UP ")
    return False


def _haproxy_authelia_backend_up() -> bool:
    """Query HAProxy runtime state without invoking a shell command."""
    chunks: List[bytes] = []
    received = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(HAPROXY_RUNTIME_SOCKET)
            client.sendall(b"show stat\n")
            while received <= MAX_HAPROXY_STATS_BYTES:
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
    except OSError:
        return False
    if not chunks or received > MAX_HAPROXY_STATS_BYTES:
        return False
    stats = b"".join(chunks).decode("utf-8", errors="replace")
    return _haproxy_stats_report_backend_up(stats)


def _wait_for_authelia_ready(timeout: int, interval: float = 0.5) -> bool:
    """Wait for HTTP readiness and for HAProxy to route ForwardAuth again."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _authelia_health_ready() and _haproxy_authelia_backend_up():
            return True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
    return False


def _handle_restart(req: Dict[str, Any]) -> Dict[str, Any]:
    """Restart Authelia and wait until ForwardAuth routing is usable again."""
    cmd = ["docker", "restart", AUTHELIA_CONTAINER]
    LOG.info("Restarting Authelia via: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("docker restart failed")
        return {"ok": False, "error": f"docker restart failed: {exc}"}

    if proc.returncode != 0:
        LOG.error("docker restart failed with rc=%s", proc.returncode)
        return {
            "ok": False,
            "error": f"docker restart failed (rc={proc.returncode})",
        }

    if _wait_for_authelia_ready(RESTART_TIMEOUT):
        LOG.info(
            "Authelia restarted, healthy on %s:%s, and available through HAProxy",
            RESTART_HOST,
            RESTART_PORT,
        )
        return {
            "ok": True,
            "message": "Authelia restarted and ForwardAuth routing is available",
        }

    LOG.error(
        "Authelia restart timeout: health or HAProxy backend %s/%s is not "
        "ready after %s seconds",
        AUTHELIA_HAPROXY_BACKEND,
        AUTHELIA_HAPROXY_SERVER,
        RESTART_TIMEOUT,
    )
    return {
        "ok": False,
        "error": (
            "Authelia restart timed out: HTTP health or HAProxy ForwardAuth "
            "routing did not recover"
        ),
    }


# ---------------------------------------------------------------------------
# Обработчики действий (rules/config/settings)
# ---------------------------------------------------------------------------

def _handle_rules_list(req: Dict[str, Any]) -> Dict[str, Any]:
    """Старый JSON-API: вернуть rules как list[dict]."""
    _root, rules = _load_config_data()
    return {"ok": True, "rules": rules}


def _handle_rules_save(req: Dict[str, Any]) -> Dict[str, Any]:
    """Старый JSON-API: принять list[dict] и сохранить в access_control.rules."""
    new_rules = req.get("rules")

    if not isinstance(new_rules, list):
        return {"ok": False, "error": "field 'rules' must be a list"}
    if len(new_rules) > 500:
        return {"ok": False, "error": "no more than 500 rules are allowed"}

    try:
        _reject_unsafe_values(new_rules)
        for i, r in enumerate(new_rules):
            if not isinstance(r, dict):
                raise ValueError(
                    f"rules[{i}] must be a dict, got {type(r).__name__}"
                )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    root, _old_rules = _load_config_data()
    ac = root.get("access_control")
    if ac is None or not isinstance(ac, dict):
        ac = {}
        root["access_control"] = ac

    ac["rules"] = new_rules

    try:
        _save_config_data(root)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Failed to save configuration")
        return {
            "ok": False,
            "error": f"Ошибка сохранения configuration.yml: {exc}",
        }

    return {"ok": True, "rules": new_rules}


def _handle_rules_get(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Новый API для UI: вернуть rules как YAML-список.

    Ответ:
      { "ok": true, "rules_yaml": "<yaml>" }
    """
    try:
        _root, rules = _load_config_data()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("rules_get: failed to load config")
        return {"ok": False, "error": f"Не удалось прочитать configuration.yml: {exc}"}

    try:
        rules_yaml = yaml.safe_dump(
            rules,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.exception("rules_get: failed to dump rules YAML")
        return {"ok": False, "error": f"Не удалось сформировать YAML правил: {exc}"}

    return {"ok": True, "rules_yaml": rules_yaml}


def _protected_domains() -> set[str]:
    """Domains whose rules must keep requiring authentication."""
    raw = os.environ.get("EASY_HA_PROXY_PROTECTED_DOMAINS", "")
    return {
        item.strip().lower().rstrip(".")
        for item in raw.split(",")
        if item.strip()
    }


def _reject_unprotected_control_plane(rules: List[Any]) -> None:
    """Refuse rules that drop authentication for the control-plane domains.

    The administration and Authelia domains must never be reachable with a
    "bypass" policy: the UI is the tool that edits these rules, so a single
    mistake there would otherwise remove its own front door protection.
    """
    protected = _protected_domains()
    if not protected:
        return
    for index, rule in enumerate(rules):
        policy = str(rule.get("policy") or "").strip().lower()
        if policy != "bypass":
            continue
        raw_domains = rule.get("domain")
        if isinstance(raw_domains, str):
            candidates = [raw_domains]
        elif isinstance(raw_domains, list):
            candidates = [str(item) for item in raw_domains]
        else:
            continue
        for candidate in candidates:
            name = candidate.strip().lower().rstrip(".")
            if name in protected:
                raise ValueError(
                    f"rules[{index}]: policy 'bypass' is not allowed for the "
                    f"protected domain {name}"
                )


def _handle_rules_set(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Новый API для UI: принять YAML-список правил и сохранить его в access_control.rules.

    Ожидаем:
      { "action": "rules_set", "rules_yaml": "<yaml-список>" }
    """
    rules_yaml = req.get("rules_yaml")
    if not isinstance(rules_yaml, str):
        return {"ok": False, "error": "field 'rules_yaml' must be a string"}

    try:
        parsed = yaml.safe_load(rules_yaml) or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Некорректный YAML rules_yaml: {exc}"}

    if not isinstance(parsed, list):
        return {"ok": False, "error": "rules_yaml должен быть YAML-списком"}
    if len(parsed) > 500:
        return {"ok": False, "error": "Допускается не более 500 правил"}

    try:
        _reject_unsafe_values(parsed)
        for i, r in enumerate(parsed):
            if not isinstance(r, dict):
                raise ValueError(
                    f"rules[{i}] must be a dict, got {type(r).__name__}"
                )
        _reject_unprotected_control_plane(parsed)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    try:
        root, _old_rules = _load_config_data()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("rules_set: failed to load config")
        return {"ok": False, "error": f"Не удалось прочитать configuration.yml: {exc}"}

    ac = root.get("access_control")
    if ac is None or not isinstance(ac, dict):
        ac = {}
        root["access_control"] = ac

    ac["rules"] = parsed

    try:
        _save_config_data(root)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("rules_set: failed to save configuration")
        return {
            "ok": False,
            "error": f"Ошибка сохранения configuration.yml: {exc}",
        }

    return {"ok": True, "message": "Правила access_control успешно обновлены"}


def _handle_config_view(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Вернуть полный конфиг для UI-настроек, но:
      - без access_control.rules
      - с замазанными секретами.
    """
    root, _rules = _load_config_data()
    data = deepcopy(root)

    ac = data.get("access_control")
    if isinstance(ac, dict) and "rules" in ac:
        ac.pop("rules")

    _mask_sensitive_fields(data)
    return {"ok": True, "config": data}


class NotificationInboxError(RuntimeError):
    """The guarded local notification source cannot be read safely."""


class NotificationInboxConflict(NotificationInboxError):
    """The browser is referring to a notification which is no longer current."""


def _notification_source_path(config: Dict[str, Any]) -> str:
    """Map the configured container file to its direct host-side /config file.

    The web application never receives or mounts this path. The privileged
    daemon deliberately supports only a direct child of the same host
    directory selected by AUTHELIA_NOTIFICATION_ROOT; nested paths and path
    traversal would make O_NOFOLLOW insufficient for protecting every path
    component.
    """
    notifier = config.get("notifier")
    filesystem = notifier.get("filesystem") if isinstance(notifier, dict) else None
    if not isinstance(filesystem, dict):
        raise NotificationInboxError("filesystem notifications are not enabled")
    filename = filesystem.get("filename")
    if not isinstance(filename, str):
        raise NotificationInboxError("filesystem notification filename is invalid")
    parts = filename.strip().split("/")
    basename = parts[2] if len(parts) == 3 and parts[:2] == ["", "config"] else ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", basename):
        raise NotificationInboxError(
            "filesystem notification filename must be a direct /config file"
        )
    try:
        root_stat = os.lstat(NOTIFICATION_ROOT_DIR)
    except OSError as exc:
        raise NotificationInboxError(
            "the local notification root is unavailable"
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise NotificationInboxError("the local notification root is unsafe")
    if stat.S_IMODE(root_stat.st_mode) & 0o022:
        raise NotificationInboxError("the local notification root is writable by peers")
    if NOTIFICATION_EXPECTED_UID >= 0 and root_stat.st_uid != NOTIFICATION_EXPECTED_UID:
        raise NotificationInboxError("the local notification root owner is invalid")
    return os.path.join(NOTIFICATION_ROOT_DIR, basename)


@contextmanager
def _open_notification_snapshot(config: Dict[str, Any]):
    """Yield one bounded, stable snapshot without following the final symlink."""
    path = _notification_source_path(config)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise NotificationInboxError("safe local notification open is unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        yield None
        return
    except OSError as exc:
        raise NotificationInboxError(
            "the local notification cannot be opened safely"
        ) from exc

    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise NotificationInboxError("the local notification is not a regular file")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise NotificationInboxError("the local notification permissions are unsafe")
        if before.st_nlink != 1:
            raise NotificationInboxError("the local notification has an unsafe link count")
        if NOTIFICATION_EXPECTED_UID >= 0 and before.st_uid != NOTIFICATION_EXPECTED_UID:
            raise NotificationInboxError("the local notification owner is invalid")
        if before.st_size < 0 or before.st_size > NOTIFICATION_MAX_BYTES:
            raise NotificationInboxError("the local notification is too large")

        chunks: List[bytes] = []
        remaining = NOTIFICATION_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise NotificationInboxConflict(
                "the local notification changed while it was being read"
            )
        if len(data) > NOTIFICATION_MAX_BYTES:
            raise NotificationInboxError("the local notification is too large")
        if not data.strip():
            yield None
            return
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise NotificationInboxError(
                "the local notification is not valid UTF-8"
            ) from None

        source_digest = hmac.new(
            NOTIFICATION_REVISION_KEY,
            digestmod=hashlib.sha256,
        )
        source_digest.update(b"easy-ha-proxy-notification-source-v1\0")
        source_digest.update(repr(identity_after).encode("ascii"))
        source_digest.update(b"\0")
        source_digest.update(data)
        source_key = source_digest.hexdigest()

        notification_id = hmac.new(
            NOTIFICATION_REVISION_KEY,
            b"easy-ha-proxy-notification-id-v1\0" + source_key.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        revision = hmac.new(
            NOTIFICATION_REVISION_KEY,
            b"easy-ha-proxy-notification-revision-v1\0"
            + source_key.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        yield {
            "data": data,
            "id": notification_id,
            "received_at": datetime.fromtimestamp(
                after.st_mtime, tz=timezone.utc
            ).isoformat(),
            "revision": revision,
            "source_key": source_key,
            "text": text,
        }
    finally:
        os.close(fd)


def _notification_state_path() -> str:
    if NOTIFICATION_STATE_FILE:
        return NOTIFICATION_STATE_FILE
    return os.path.join(NOTIFICATION_STATE_DIR, NOTIFICATION_STATE_NAME)


def _notification_state_directory(path: str) -> str:
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        directory_stat = os.lstat(directory)
    except OSError as exc:
        raise NotificationInboxError(
            "the local notification state directory is unavailable"
        ) from exc
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise NotificationInboxError("the local notification state directory is unsafe")
    if directory_stat.st_uid != os.geteuid() or stat.S_IMODE(directory_stat.st_mode) & 0o077:
        raise NotificationInboxError(
            "the local notification state directory is not root-only"
        )
    return directory


def _load_notification_state() -> Dict[str, Any]:
    path = _notification_state_path()
    if not os.path.lexists(path):
        return {}
    try:
        raw, state_stat = _safe_read_file(path)
        if state_stat.st_uid != os.geteuid():
            raise NotificationInboxError("the local notification state owner is invalid")
        if stat.S_IMODE(state_stat.st_mode) != 0o600:
            raise NotificationInboxError(
                "the local notification state permissions are unsafe"
            )
        if state_stat.st_nlink != 1 or state_stat.st_size > NOTIFICATION_STATE_MAX_BYTES:
            raise NotificationInboxError("the local notification state is unsafe")
        state = json.loads(_decode_text(raw, path))
    except (MailSettingsError, json.JSONDecodeError) as exc:
        raise NotificationInboxError(
            "the local notification state is invalid"
        ) from exc
    if not isinstance(state, dict):
        raise NotificationInboxError("the local notification state is invalid")
    if state and (
        set(state)
        != {
            "actor",
            "handled",
            "handled_at",
            "id",
            "revision",
            "source_key",
            "version",
        }
        or state.get("version") != 1
        or state.get("handled") is not True
        or not isinstance(state.get("id"), str)
        or not NOTIFICATION_ID_RE.fullmatch(state["id"])
        or not isinstance(state.get("revision"), str)
        or not NOTIFICATION_ID_RE.fullmatch(state["revision"])
        or not isinstance(state.get("source_key"), str)
        or not NOTIFICATION_ID_RE.fullmatch(state["source_key"])
        or not isinstance(state.get("actor"), str)
        or not NOTIFICATION_ACTOR_RE.fullmatch(state["actor"])
        or not isinstance(state.get("handled_at"), str)
        or len(state["handled_at"]) > 64
        or CONTROL_RE.search(state["handled_at"])
    ):
        raise NotificationInboxError("the local notification state is invalid")
    return state


def _write_notification_state(state: Dict[str, Any]) -> None:
    path = _notification_state_path()
    directory = _notification_state_directory(path)
    if os.path.lexists(path):
        current = os.lstat(path)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
        ):
            raise NotificationInboxError(
                "the local notification state path is unsafe"
            )
    payload = (
        json.dumps(
            state,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > NOTIFICATION_STATE_MAX_BYTES:
        raise NotificationInboxError("the local notification state is too large")
    fd, temp_path = tempfile.mkstemp(
        prefix=".authelia-notification-latest.", dir=directory
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = ""
        _fsync_directories([path])
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _notification_state_for(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    tombstone = _load_notification_state()
    handled = bool(
        tombstone
        and hmac.compare_digest(tombstone["source_key"], snapshot["source_key"])
        and hmac.compare_digest(tombstone["id"], snapshot["id"])
        and hmac.compare_digest(tombstone["revision"], snapshot["revision"])
    )
    return {
        "id": snapshot["id"],
        "revision": snapshot["revision"],
        "handled": handled,
        "handled_at": tombstone.get("handled_at") if handled else None,
    }


def _notification_header(text: str, names: set[str], maximum: int) -> str:
    for line in text.splitlines()[:20]:
        if not line.strip():
            break
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in names:
            cleaned = " ".join(value.strip().split())
            return cleaned[:maximum]
    return ""


def _mask_notification_recipient(value: str) -> str:
    """Return enough routing context for metadata without exposing an address."""
    match = re.search(
        r"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@"
        r"([A-Za-z0-9.-]+)",
        value,
    )
    if not match:
        return "••••" if value else ""
    local, domain = match.groups()
    visible = local[0] if local else "•"
    return f"{visible}***@{domain.lower()}"


def _notification_metadata(
    snapshot: Dict[str, Any], state: Dict[str, Any]
) -> Dict[str, Any]:
    text = snapshot["text"]
    recipient = _notification_header(text, {"recipient", "to"}, 320)
    return {
        "id": state["id"],
        "revision": state["revision"],
        "received_at": snapshot["received_at"],
        "recipient_masked": _mask_notification_recipient(recipient),
        "size": len(snapshot["data"]),
        "handled": state["handled"],
        "handled_at": state.get("handled_at"),
    }


def _notification_latest() -> Dict[str, Any]:
    config, _rules = _load_config_data()
    if _mail_mode(config) != "filesystem":
        return {
            "ok": True,
            "mode": "relay",
            "status": "disabled",
            "latest": None,
        }
    with _open_notification_snapshot(config) as snapshot:
        if snapshot is None:
            return {
                "ok": True,
                "mode": "filesystem",
                "status": "empty",
                "latest": None,
            }
        state = _notification_state_for(snapshot)
        return {
            "ok": True,
            "mode": "filesystem",
            "status": "handled" if state["handled"] else "pending",
            "latest": _notification_metadata(snapshot, state),
        }


def _validate_notification_reference(req: Dict[str, Any]) -> Tuple[str, str]:
    notification_id = req.get("id")
    revision = req.get("revision")
    if (
        not isinstance(notification_id, str)
        or not NOTIFICATION_ID_RE.fullmatch(notification_id)
        or not isinstance(revision, str)
        or not NOTIFICATION_ID_RE.fullmatch(revision)
    ):
        raise ValueError("id and revision must be current 64-character values")
    return notification_id, revision


def _validate_notification_actor(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("actor is required")
    actor = value.strip()
    if not NOTIFICATION_ACTOR_RE.fullmatch(actor):
        raise ValueError("actor is invalid")
    return actor


def _require_current_notification(
    config: Dict[str, Any], notification_id: str, revision: str
):
    if _mail_mode(config) != "filesystem":
        raise NotificationInboxConflict("filesystem notifications are not enabled")
    snapshot_context = _open_notification_snapshot(config)
    snapshot = snapshot_context.__enter__()
    try:
        if snapshot is None:
            raise NotificationInboxConflict("there is no current local notification")
        state = _notification_state_for(snapshot)
        if not (
            hmac.compare_digest(state["id"], notification_id)
            and hmac.compare_digest(state["revision"], revision)
        ):
            raise NotificationInboxConflict(
                "the local notification changed; refresh before continuing"
            )
        return snapshot_context, snapshot, state
    except Exception:
        snapshot_context.__exit__(*sys.exc_info())
        raise


def _claim_notification_reveal(actor: str) -> int:
    now = time.monotonic()
    with NOTIFICATION_REVEAL_LOCK:
        previous = NOTIFICATION_REVEALED_AT.get(actor, 0.0)
        remaining = NOTIFICATION_REVEAL_COOLDOWN_SECONDS - (now - previous)
        if remaining > 0:
            return max(1, int(remaining + 0.999))
        NOTIFICATION_REVEALED_AT[actor] = now
        cutoff = now - max(300, NOTIFICATION_REVEAL_COOLDOWN_SECONDS * 10)
        for old_actor, revealed_at in list(NOTIFICATION_REVEALED_AT.items()):
            if revealed_at < cutoff:
                NOTIFICATION_REVEALED_AT.pop(old_actor, None)
    return 0


def _handle_notification_latest(req: Dict[str, Any]) -> Dict[str, Any]:
    if set(req) != {"action"}:
        return {
            "ok": False,
            "validation_error": True,
            "error": "notification_latest does not accept additional fields",
        }
    try:
        with _mail_lock():
            return _notification_latest()
    except NotificationInboxConflict as exc:
        return {"ok": False, "conflict": True, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        LOG.warning(
            "Failed to read local Authelia notification metadata (%s)",
            type(exc).__name__,
        )
        return {"ok": False, "error": "failed to read local notification metadata"}


def _handle_notification_reveal(req: Dict[str, Any]) -> Dict[str, Any]:
    if set(req) != {"action", "id", "revision", "actor"}:
        return {
            "ok": False,
            "validation_error": True,
            "error": "id, revision, and actor are required",
        }
    try:
        notification_id, revision = _validate_notification_reference(req)
        actor = _validate_notification_actor(req.get("actor"))
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    try:
        with _mail_lock():
            config, _rules = _load_config_data()
            context, snapshot, state = _require_current_notification(
                config, notification_id, revision
            )
            try:
                retry_after = _claim_notification_reveal(actor)
                if retry_after:
                    return {
                        "ok": False,
                        "rate_limited": True,
                        "retry_after": retry_after,
                        "error": "please wait before revealing the notification again",
                    }
                LOG.info("Local Authelia notification revealed by actor=%r", actor)
                return {
                    "ok": True,
                    "id": state["id"],
                    "revision": state["revision"],
                    "content": snapshot["text"],
                }
            finally:
                context.__exit__(None, None, None)
    except NotificationInboxConflict as exc:
        return {"ok": False, "conflict": True, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        LOG.warning(
            "Failed to reveal local Authelia notification (%s)",
            type(exc).__name__,
        )
        return {"ok": False, "error": "failed to reveal local notification"}


def _handle_notification_handle(req: Dict[str, Any]) -> Dict[str, Any]:
    if set(req) != {"action", "id", "revision", "handled", "actor"}:
        return {
            "ok": False,
            "validation_error": True,
            "error": "id, revision, handled=true, and actor are required",
        }
    if req.get("handled") is not True:
        return {
            "ok": False,
            "validation_error": True,
            "error": "handled must be true",
        }
    try:
        notification_id, revision = _validate_notification_reference(req)
        actor = _validate_notification_actor(req.get("actor"))
    except ValueError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    try:
        with _mail_lock():
            config, _rules = _load_config_data()
            context, snapshot, state = _require_current_notification(
                config, notification_id, revision
            )
            try:
                handled_at = datetime.now(tz=timezone.utc).isoformat()
                _write_notification_state(
                    {
                        "version": 1,
                        "source_key": snapshot["source_key"],
                        "id": snapshot["id"],
                        "revision": snapshot["revision"],
                        "handled": True,
                        "handled_at": handled_at,
                        "actor": actor,
                    }
                )
                state = {
                    "id": snapshot["id"],
                    "revision": snapshot["revision"],
                    "handled": True,
                    "handled_at": handled_at,
                }
                LOG.info(
                    "Local Authelia notification marked handled by actor=%r",
                    actor,
                )
                return {
                    "ok": True,
                    "status": "handled",
                    "latest": _notification_metadata(snapshot, state),
                }
            finally:
                context.__exit__(None, None, None)
    except NotificationInboxConflict as exc:
        return {"ok": False, "conflict": True, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        LOG.warning(
            "Failed to update local Authelia notification status (%s)",
            type(exc).__name__,
        )
        return {"ok": False, "error": "failed to update local notification status"}


def _handle_mail_view(req: Dict[str, Any]) -> Dict[str, Any]:
    """Return notifier/SMTP settings with credentials reduced to a boolean."""
    try:
        with _mail_lock():
            return _mail_settings_model(_load_mail_state())
    except MailSettingsError as exc:
        LOG.error("Failed to load mail settings: managed configuration is invalid")
        return {"ok": False, "error": f"failed to load mail settings: {exc}"}
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Failed to load mail settings")
        return {"ok": False, "error": "failed to load mail settings"}


def _handle_mail_test(req: Dict[str, Any]) -> Dict[str, Any]:
    """Send one bounded test message with the current persisted settings."""
    if set(req) != {"action", "revision", "recipient"}:
        return {
            "ok": False,
            "validation_error": True,
            "error": "revision and recipient are required",
        }
    revision = req.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        return {
            "ok": False,
            "validation_error": True,
            "error": "revision must be the current 64-character SHA-256 value",
        }
    try:
        recipient = _validate_mail_email(req.get("recipient"), "Recipient")
    except MailSettingsError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}

    try:
        with _mail_lock():
            state = _load_mail_state()
            current_revision = _mail_revision(state)
            if revision != current_revision:
                return {
                    "ok": False,
                    "conflict": True,
                    "error": (
                        "Mail settings changed after this page was loaded. "
                        "Reload them before sending a test message."
                    ),
                    "revision": current_revision,
                }
            mode = _mail_mode(state["config"])
            if mode != "relay":
                return {
                    "ok": False,
                    "unsupported": True,
                    "error": "Enable the internal mail relay first.",
                    "revision": current_revision,
                }
            retry_after = _claim_mail_test_slot()
            if retry_after:
                return {
                    "ok": False,
                    "rate_limited": True,
                    "retry_after": retry_after,
                    "error": "Please wait before sending another test message.",
                    "revision": current_revision,
                }

            settings = _mail_settings_model(state)["settings"]
            try:
                delivery_status = _send_relay_mail_test(settings, recipient)
            except Exception as exc:  # noqa: BLE001
                # SMTP server responses may contain attacker-controlled text;
                # report only the exception class and never credentials/output.
                LOG.warning(
                    "Mail test failed in %s mode (%s)",
                    mode,
                    type(exc).__name__,
                )
                return {
                    "ok": False,
                    "error": (
                        "The test message was not accepted. Check the SMTP "
                        "settings and the Authelia/mail_relay logs."
                    ),
                    "revision": current_revision,
                }

            if delivery_status == "rejected":
                return {
                    "ok": False,
                    "accepted": True,
                    "rejected": True,
                    "delivery_status": delivery_status,
                    "delivery_guaranteed": False,
                    "error": (
                        "The internal relay accepted the test message, but the "
                        "configured external SMTP relay rejected it. Check the "
                        "SMTP credentials, sender policy, and mail_relay logs."
                    ),
                    "revision": current_revision,
                }

            if delivery_status == "relay_accepted":
                message = (
                    "The configured external SMTP relay accepted the test "
                    "message. Final inbox delivery still cannot be guaranteed."
                )
            elif delivery_status == "deferred":
                message = (
                    "The internal relay queued the test message after a "
                    "temporary external delivery failure and will retry it."
                )
            else:
                message = (
                    "The internal relay queued the test message, but no "
                    "definitive external delivery result was available within "
                    "the bounded check window."
                )

            return {
                "ok": True,
                "message": message,
                "mode": mode,
                "recipient": recipient,
                "accepted": True,
                "upstream_accepted": delivery_status == "relay_accepted",
                "delivery_status": delivery_status,
                "delivery_guaranteed": False,
                "revision": current_revision,
            }
    except MailSettingsError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Mail test setup failed (%s)", type(exc).__name__)
        return {"ok": False, "error": "Failed to prepare the mail test."}


def _handle_mail_update(req: Dict[str, Any]) -> Dict[str, Any]:
    """Persist runtime and managed mail settings as one guarded transaction."""
    apply_changes = req.get("apply")
    if apply_changes is not True:
        return {
            "ok": False,
            "validation_error": True,
            "error": "apply must be true",
        }
    revision = req.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        return {
            "ok": False,
            "validation_error": True,
            "error": "revision must be the current 64-character SHA-256 value",
        }
    try:
        settings = _validate_mail_payload(req.get("settings"))
    except MailSettingsError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}

    try:
        with _mail_lock():
            state = _load_mail_state()
            current_revision = _mail_revision(state)
            if revision != current_revision:
                return {
                    "ok": False,
                    "conflict": True,
                    "error": (
                        "Mail settings changed after this page was loaded. "
                        "Reload them and review your changes."
                    ),
                    "revision": current_revision,
                }

            old_mode = _mail_mode(state["config"])
            recreate_relay = settings["mode"] == "relay" and (
                old_mode != "relay" or _mail_transport_changed(state, settings)
            )
            if (
                apply_changes
                and settings["mode"] == "relay"
                and not _relay_available(state)
            ):
                return {
                    "ok": False,
                    "conflict": True,
                    "relay_unavailable": True,
                    "error": (
                        "mail relay is not installed in the current Compose stack; "
                        "run a full easy-ha-proxy update, then retry"
                    ),
                    "revision": current_revision,
                }
            updates = _prepare_mail_updates(state, settings)

            snapshots = state["snapshots"]
            if all(
                hmac.compare_digest(data, snapshots[path][0])
                for path, data in updates.items()
            ):
                result = _mail_settings_model(state)
                result.update(
                    {
                        "applied": True,
                        "message": "Mail settings are already active.",
                    }
                )
                return result
            try:
                _commit_mail_files(updates, snapshots)
            except MailSettingsConflictError as exc:
                try:
                    changed_revision = _mail_revision(_load_mail_state())
                except Exception:  # noqa: BLE001
                    changed_revision = current_revision
                return {
                    "ok": False,
                    "conflict": True,
                    "error": str(exc),
                    "revision": changed_revision,
                }
            except Exception as exc:  # noqa: BLE001
                LOG.exception("Failed to commit mail settings")
                return {
                    "ok": False,
                    "error": f"failed to save mail settings: {exc}",
                    "revision": current_revision,
                }

            if apply_changes:
                apply_info: Dict[str, Any] = {}
                try:
                    apply_info = _apply_mail_stack(
                        settings["mode"], recreate_relay=recreate_relay
                    )
                except Exception as apply_exc:  # noqa: BLE001
                    LOG.exception("Mail apply failed; restoring previous settings")
                    rollback_errors: List[str] = []
                    try:
                        _restore_files(snapshots, list(updates))
                    except Exception as restore_exc:  # noqa: BLE001
                        LOG.exception("Mail file rollback failed")
                        rollback_errors.append(f"file rollback failed: {restore_exc}")
                    else:
                        if settings["mode"] != "relay":
                            # Filesystem apply only restarts Authelia; it
                            # never recreates the relay. After restoring the old
                            # files, restart Authelia without touching a queued
                            # relay from the previous mode.
                            try:
                                restart_result = _handle_restart({})
                                if not restart_result.get("ok"):
                                    raise RuntimeError(
                                        restart_result.get("error")
                                        or "Authelia restart failed"
                                    )
                            except Exception as restart_exc:  # noqa: BLE001
                                LOG.exception("Previous Authelia recovery failed")
                                rollback_errors.append(
                                    f"previous Authelia recovery failed: {restart_exc}"
                                )
                        elif isinstance(apply_exc, MailRelayQueueSafetyError):
                            if apply_exc.authelia_stopped:
                                try:
                                    restart_result = _handle_restart({})
                                    if not restart_result.get("ok"):
                                        raise RuntimeError(
                                            restart_result.get("error")
                                            or "Authelia restart failed"
                                        )
                                except Exception as restart_exc:  # noqa: BLE001
                                    LOG.exception("Previous Authelia recovery failed")
                                    rollback_errors.append(
                                        f"previous Authelia recovery failed: {restart_exc}"
                                    )
                        elif not recreate_relay:
                            try:
                                restart_result = _handle_restart({})
                                if not restart_result.get("ok"):
                                    raise RuntimeError(
                                        restart_result.get("error")
                                        or "Authelia restart failed"
                                    )
                            except Exception as restart_exc:  # noqa: BLE001
                                LOG.exception("Previous Authelia recovery failed")
                                rollback_errors.append(
                                    f"previous Authelia recovery failed: {restart_exc}"
                                )
                        else:
                            try:
                                _apply_mail_stack(old_mode)
                            except Exception as restart_exc:  # noqa: BLE001
                                LOG.exception("Previous mail stack recovery failed")
                                rollback_errors.append(
                                    f"previous stack recovery failed: {restart_exc}"
                                )
                    try:
                        restored_revision = _mail_revision(_load_mail_state())
                    except Exception:  # noqa: BLE001
                        restored_revision = current_revision
                    error = f"mail settings apply failed and changes were rolled back: {apply_exc}"
                    if rollback_errors:
                        error += "; " + "; ".join(rollback_errors)
                    return {
                        "ok": False,
                        "rolled_back": not rollback_errors,
                        "error": error,
                        "revision": restored_revision,
                    }

            result = _mail_settings_model(_load_mail_state())
            result.update(
                {
                    "applied": True,
                    "message": "Mail settings saved and applied safely.",
                }
            )
            if apply_info.get("warning"):
                result["warning"] = apply_info["warning"]
                result["relay_state"] = apply_info.get("relay_state")
            return result
    except MailSettingsError as exc:
        return {"ok": False, "validation_error": True, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Unexpected mail settings update failure")
        return {"ok": False, "error": f"mail settings update failed: {exc}"}


def _handle_settings_update(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Обновление общих настроек конфигурации (server/log/session/etc.)
    без трогания access_control.rules и секретов.

    Ожидаем:
      {
        "action": "settings_update",
        "config": { ... }   # фрагмент конфигурации
      }
    """
    cfg_in = req.get("config")
    if not isinstance(cfg_in, dict):
        return {"ok": False, "error": "field 'config' must be a dict"}

    cfg = deepcopy(cfg_in)
    allowed_sections = {"log", "session", "regulation", "totp"}
    unexpected = set(cfg) - allowed_sections
    if unexpected:
        return {
            "ok": False,
            "error": "unsupported configuration sections: " + ", ".join(sorted(unexpected)),
        }
    try:
        _reject_unsafe_values(cfg)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # На всякий случай защищаемся от попытки передать секреты:
    try:
        ses = cfg.get("session")
        if isinstance(ses, dict):
            ses.pop("secret", None)
    except Exception:
        pass

    try:
        storage = cfg.get("storage")
        if isinstance(storage, dict):
            storage.pop("encryption_key", None)
    except Exception:
        pass

    try:
        ident = cfg.get("identity_validation")
        if isinstance(ident, dict):
            reset = ident.get("reset_password")
            if isinstance(reset, dict):
                reset.pop("jwt_secret", None)
    except Exception:
        pass

    # Не даём случайно затереть rules
    ac_in = cfg.get("access_control")
    if isinstance(ac_in, dict):
        ac_in.pop("rules", None)

    # Загружаем полный конфиг с rules и секретами
    root, _rules = _load_config_data()

    # Мерджим фрагмент поверх
    _deep_update(root, cfg)

    try:
        _save_config_data(root)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("Failed to save configuration (settings_update)")
        return {
            "ok": False,
            "error": f"Ошибка сохранения configuration.yml: {exc}",
        }

    return {"ok": True}


def _notification_peer_allowed(peer_uid: int | None) -> bool:
    if peer_uid == 0:
        return True
    if peer_uid is None or not NOTIFICATION_CLIENT_USER:
        return False
    try:
        expected_uid = pwd.getpwnam(NOTIFICATION_CLIENT_USER).pw_uid
    except (KeyError, OSError):
        return False
    return hmac.compare_digest(str(peer_uid), str(expected_uid))


def _socket_peer_uid(conn: socket.socket) -> int | None:
    """Read Linux AF_UNIX peer credentials without trusting request JSON."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = conn.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
    except (OSError, struct.error):
        return None
    return uid


def handle_request(
    req: Dict[str, Any], *, peer_uid: int | None = None
) -> Dict[str, Any]:
    action = (req.get("action") or "").strip()

    if action in {"notification_reveal", "notification_handle"} and not (
        _notification_peer_allowed(peer_uid)
    ):
        LOG.warning(
            "Denied sensitive local notification action=%r for peer_uid=%r",
            action,
            peer_uid,
        )
        return {
            "ok": False,
            "forbidden": True,
            "error": "the local notification action is not available to this client",
        }

    # Новый YAML-API для ACL-UI
    if action == "rules_get":
        return _handle_rules_get(req)
    if action == "rules_set":
        return _handle_rules_set(req)

    # Старый JSON-API
    if action == "rules_list":
        return _handle_rules_list(req)
    if action == "rules_save":
        return _handle_rules_save(req)

    if action == "config_view":
        return _handle_config_view(req)
    if action == "mail_view":
        return _handle_mail_view(req)
    if action == "mail_test":
        return _handle_mail_test(req)
    if action == "mail_update":
        return _handle_mail_update(req)
    if action == "notification_latest":
        return _handle_notification_latest(req)
    if action == "notification_reveal":
        return _handle_notification_reveal(req)
    if action == "notification_handle":
        return _handle_notification_handle(req)
    if action == "restart":
        return _handle_restart(req)
    if action == "settings_update":
        return _handle_settings_update(req)

    return {"ok": False, "error": f"unknown action: {action!r}"}


# ---------------------------------------------------------------------------
# Серверный цикл
# ---------------------------------------------------------------------------

def serve() -> None:
    """Основной цикл сервера (UNIX-сокет)."""
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except Exception:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o660)
    srv.listen(10)

    LOG.info("authelia-configd listening on %s", SOCKET_PATH)

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
                peer_uid = _socket_peer_uid(conn)
                conn.settimeout(15)
                data = b""
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
                    "utf-8", errors="replace"
                ).strip()
                if not line:
                    continue

                try:
                    req = json.loads(line)
                except Exception as exc:  # noqa: BLE001
                    resp = {"ok": False, "error": f"invalid json: {exc}"}
                else:
                    # Never log request bodies: mail_update may contain a new
                    # SMTP password. The action is enough for diagnostics.
                    LOG.debug("Request action=%r", req.get("action"))
                    resp = handle_request(req, peer_uid=peer_uid)

            except Exception as exc:  # noqa: BLE001
                LOG.exception("request handling failed")
                resp = {"ok": False, "error": f"internal error: {exc}"}

            resp_line = json.dumps(resp, ensure_ascii=False) + "\n"
            try:
                conn.sendall(resp_line.encode("utf-8"))
            except Exception:
                pass


if __name__ == "__main__":
    try:
        serve()
    except Exception as exc:  # noqa: BLE001
        LOG.exception("fatal error in server: %s", exc)
        time.sleep(1)
        sys.exit(1)
