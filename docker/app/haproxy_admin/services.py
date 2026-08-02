# -*- coding: utf-8 -*-
"""
services.py — таблицы ban/err, лог-аналитика, ipset-FW, сессии, статусы бэкендов.

Все пути/настройки читаются из ENV, которые рендерятся Ansible:
  SOCKET_PATH                 (по умолчанию /run/haproxy/admin.sock)
  UI_EXCLUDE_EXACT           (comma-separated; по умолчанию: be_admin,be_http_challenge,be_tls_terminator,be_maintenance)
  UI_EXCLUDE_PREFIX          (comma-separated; по умолчанию: tbl_)
  LOG_FILE                   (по умолчанию /var/log/haproxy.log)
  WHITELIST_GEO_FILE         (по умолчанию /etc/haproxy/geoip/whitelist.geo)
  WHITELIST_GLOBAL_FILE      (по умолчанию /etc/haproxy/whitelist.ip)
  AUTHELIA_BANS_CMD          (по умолчанию /usr/local/sbin/authelia-bans.sh)
"""
from __future__ import annotations

import csv
import os
import socket
import json
import yaml
import re
import ipaddress
import logging
import subprocess
import shlex
from io import StringIO
from datetime import datetime, timedelta
from collections import defaultdict

from .utils import (
    run_cmd,
    haproxy_runtime_command,
    parse_table_output,
    logger,
    parse_sessions,
    reload_haproxy,
    # is_ip_in_whitelist,
    # is_ip_in_global_whitelist,
    ensure_whitelist_file,
    ensure_whitelist_global_file,
    controld_get_attackers,
)
from .cache import get_country_code

# ───────── Конфиг из ENV (заполняется Ansible через .env) ─────────

SOCKET: str = os.environ.get("SOCKET_PATH", "/run/haproxy/admin.sock").strip()
HAPROXY_CFG: str = os.environ.get(
    "HAPROXY_CFG", "/etc/haproxy/haproxy.cfg").strip()


# списки исключений
EXCLUDE_EXACT: set[str] = set(
    s for s in os.environ.get(
        "UI_EXCLUDE_EXACT",
        "be_admin,be_http_challenge,be_tls_terminator,be_maintenance"
    ).split(",") if s
)
EXCLUDE_PREFIX: tuple[str, ...] = tuple(
    s for s in os.environ.get("UI_EXCLUDE_PREFIX", "tbl_").split(",") if s
)

# журналы и вайтлисты
LOG_FILE: str = os.environ.get("LOG_FILE", "/var/log/haproxy.log").strip()
WHITELIST_FILE: str = os.environ.get(
    "WHITELIST_GEO_FILE", "/etc/haproxy/geoip/whitelist.geo").strip()
WHITELIST_GLOBAL_FILE: str = os.environ.get(
    "WHITELIST_GLOBAL_FILE", "/etc/haproxy/whitelist.ip").strip()

# helper для Authelia bans:
AUTHELIA_BANS_CMD: str = os.environ.get(
    "AUTHELIA_BANS_CMD", "/usr/local/sbin/authelia-bans.sh"
).strip()
AUTHELIA_BANS_SOCKET: str = os.environ.get(
    "AUTHELIA_BANS_SOCKET", ""
).strip()


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


AUTHELIA_BANS_SOCKET_TIMEOUT: int = _bounded_env_int(
    "AUTHELIA_BANS_SOCKET_TIMEOUT", 10, 2, 60
)
AUTHELIA_BANS_MAX_RESPONSE_BYTES: int = _bounded_env_int(
    "AUTHELIA_BANS_MAX_RESPONSE_BYTES", 2 * 1024 * 1024, 4096, 16 * 1024 * 1024
)

# Логи Authelia (JSON)
AUTHELIA_LOG_FILE: str = os.environ.get(
    "AUTHELIA_LOG_FILE", ""
).strip()
AUTHELIA_LOG_LIMIT: int = _bounded_env_int("AUTHELIA_LOG_LIMIT", 200, 1, 1000)
AUTHELIA_LOG_MAX_SCAN_BYTES: int = _bounded_env_int(
    "AUTHELIA_LOG_MAX_SCAN_BYTES", 16 * 1024 * 1024, 64 * 1024, 128 * 1024 * 1024
)

AUTHELIA_USERS_FILE: str = os.environ.get(
    "AUTHELIA_USERS_FILE", ""
).strip()

AUTHELIA_USERS_SOCKET: str = os.environ.get(
    "AUTHELIA_USERS_SOCKET", "/run/easy-ha-proxy/authelia-usersd.sock").strip()


# производные от SOCKET (для multi-process master-worker)
SOCKET_DIR: str = os.path.dirname(SOCKET) or "/run/haproxy"
SOCKET_BASIS: str = os.path.basename(SOCKET) or "admin.sock"
SOCKET_RE = re.compile(rf"^{re.escape(SOCKET_BASIS)}(\.\d+)?$")

# кэши
table_cache: dict = {"ban": None, "err": None}
cache_time: datetime = datetime.min

_cfg_disp_cache = {"mtime": -1.0, "map": {}}
logger = logging.getLogger("haproxy-admin")


# ───────── Helpers: динамический список stick-таблиц ─────────

def _list_all_tables() -> list[str]:
    """
    Универсальный листинг: поддерживает 'show table' и оба формата ('table:' и 'table=').
    """
    out = haproxy_runtime_command("show table", SOCKET, timeout=2)
    names: set[str] = set()
    for ln in str(out).splitlines():
        ln = ln.strip()
        if not ln or (ln.startswith('#') and 'table' not in ln):
            continue
        m = re.search(r"\btable:\s*([^\s,]+)",
                      ln) or re.search(r"\btable=([^\s,]+)", ln)
        if m:
            names.add(m.group(1))
    return sorted(names)


def _list_err_tables() -> list[str]:
    all_names = _list_all_tables()
    err = [n for n in all_names if n ==
           "tbl_err_nosni" or n.startswith("tbl_err_")]
    if not err and "tbl_err" in all_names:  # совместимость со старой схемой
        err = ["tbl_err"]
    return sorted(err)


def _aggregate_err_tables(err_tables: list[dict]) -> dict:
    acc: dict[str, dict[str, int]] = {}
    for t in err_tables:
        if not t or not t.get("rows"):
            continue
        for row in t["rows"]:
            ip = row[0]
            try:
                cnt = int(str(row[1]))
            except Exception:
                cnt = 0
            try:
                exp = int(str(row[2]))
            except Exception:
                exp = 0
            cur = acc.get(ip, {"cnt": 0, "exp": 0})
            cur["cnt"] += cnt
            cur["exp"] = max(cur["exp"], exp)
            acc[ip] = cur
    rows = sorted(([ip, v["cnt"], v["exp"]] for ip, v in acc.items()),
                  key=lambda r: r[1], reverse=True)[:50]
    return {"headers": ["IP Address", "Error Count", "Expires"],
            "rows": rows,
            "meta": {"name": "tbl_err_all", "used": len(rows), "size": len(rows)}}


def get_ip_auth_table() -> dict:
    """
    Возвращает структуру по tbl_ip_auth:
      headers: список заголовков
      rows:    [ip, gpc0, ttl_seconds]
      meta:    служебная инфа (name, used, size, error)
    """
    try:
        raw = haproxy_runtime_command("show table tbl_ip_auth", SOCKET, timeout=2)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("ip_auth table error: %s", exc)
        return {
            "headers": ["IP", "Flag (gpc0)", "TTL (sec)"],
            "rows": [],
            "meta": {
                "name": "tbl_ip_auth",
                "used": 0,
                "size": 0,
                "error": f"exception: {exc}",
            },
        }

    # Если таблица missing или HAProxy вернул ошибку — считаем, что функционал отключён
    raw_strip = raw.strip()
    if not raw_strip or "Unknown table" in raw_strip or "No such table" in raw_strip:
        return {
            "headers": ["IP", "Flag (gpc0)", "TTL (sec)"],
            "rows": [],
            "meta": {
                "name": "tbl_ip_auth",
                "used": 0,
                "size": 0,
                "error": "table_missing",
            },
        }

    rows: list[list] = []
    size = 0
    used = 0

    for line in raw_strip.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("# table:"):
            # строка вида: "# table: tbl_ip_auth, type: ip, size:204800, used:2"
            # вытащим size/used по возможности
            parts = line.split(",")
            for p in parts:
                p = p.strip()
                if p.startswith("size="):
                    try:
                        size = int(p.split("=", 1)[1])
                    except Exception:
                        pass
                elif p.startswith("used="):
                    try:
                        used = int(p.split("=", 1)[1])
                    except Exception:
                        pass
            continue

        # строки вида:
        # 0x5e30978186c8: key=198.51.100.178 use=0 exp=32301965 shard=0 gpc0=106
        ip = ""
        flag = 0
        ttl_sec = 0

        for token in line.split():
            if token.startswith("key="):
                ip = token.split("=", 1)[1]
            elif token.startswith("gpc0="):
                try:
                    flag = int(token.split("=", 1)[1])
                except Exception:
                    flag = 0
            elif token.startswith("exp="):
                try:
                    exp_ms = int(token.split("=", 1)[1])
                    ttl_sec = max(0, exp_ms // 1000)  # ms → секунды
                except Exception:
                    ttl_sec = 0

        if ip:
            rows.append([ip, flag, ttl_sec])

    return {
        "headers": ["IP", "Flag (gpc0)", "TTL (sec)"],
        "rows": rows,
        "meta": {
            "name": "tbl_ip_auth",
            "used": len(rows) if used == 0 else used,
            "size": size or len(rows),
            "error": None,
        },
    }


def get_tables():
    """
    Кэшированное чтение tbl_ban + агрегация всех tbl_err_*.
    """
    global table_cache, cache_time
    if datetime.now() - cache_time <= timedelta(seconds=5):
        return table_cache
    try:
        ban_raw = haproxy_runtime_command("show table tbl_ban", SOCKET, timeout=2)
        ban = parse_table_output(ban_raw)

        err_names = _list_err_tables()
        err_multi = []
        for name in err_names:
            raw = haproxy_runtime_command(f"show table {name}", SOCKET, timeout=2)
            parsed = parse_table_output(raw)
            err_multi.append({"name": name, "table": parsed})

        err_agg = _aggregate_err_tables([x["table"] for x in err_multi])
        table_cache = {"ban": ban, "err": err_agg, "err_multi": err_multi}
    except Exception as e:  # pylint: disable=broad-except
        logger.error("parse tables: %s", e)
        table_cache = {"ban": None, "err": None, "err_multi": []}
    cache_time = datetime.now()
    return table_cache


# ────── RAW таблицы (без обработки) ────────────────────────────
def get_tables_raw() -> dict:
    """
    Возвращает RAW:
      - ban_raw: строка
      - err_raw: dict{name -> raw_text} по всем err-таблицам (или строка для совместимости)
        + сюда же добавляем tbl_ip_auth
    """
    def _safe(command: str) -> str:
        try:
            return haproxy_runtime_command(command, SOCKET, timeout=2)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("raw table error: %s", exc)
            return f"ERROR: {exc}"

    # tbl_ban как и раньше
    ban_raw = _safe("show table tbl_ban")

    # RAW для tbl_ip_auth
    ip_auth_raw = _safe("show table tbl_ip_auth")

    # err-таблицы
    names = _list_err_tables()
    if not names:
        # Старый режим совместимости: одна строка с tbl_err.
        # Просто допишем к ней RAW от tbl_ip_auth, чтобы тип остался str.
        base_err_raw = _safe("show table tbl_err")
        # Если tbl_ip_auth есть, просто приклеим её вывод ниже.
        err_raw = base_err_raw + "\n\n" + ip_auth_raw
    else:
        # Новый режим: err_raw — dict {name: raw_text}
        err_raw: dict[str, str] = {}
        for n in names:
            err_raw[n] = _safe(f"show table {n}")

        # Добавляем tbl_ip_auth как ещё одну "таблицу"
        err_raw["tbl_ip_auth"] = ip_auth_raw

    return {"ban_raw": ban_raw, "err_raw": err_raw}

# ───── Authelia regulation bans (CLI helper) ─────


def _call_authelia_bansd(action: str, **params) -> dict:
    """
    Низкоуровневый клиент к демону authelia-bansd по unix-сокету.

    Возвращает dict вида:
      {"ok": True, ...}  или {"ok": False, "error": "..."}.
    """
    if not AUTHELIA_BANS_SOCKET:
        return {"ok": False, "error": "AUTHELIA_BANS_SOCKET not set"}

    req = {"action": action}
    req.update(params)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(AUTHELIA_BANS_SOCKET)
            s.settimeout(float(AUTHELIA_BANS_SOCKET_TIMEOUT))
            payload = json.dumps(req, ensure_ascii=False) + "\n"
            s.sendall(payload.encode("utf-8"))

            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > AUTHELIA_BANS_MAX_RESPONSE_BYTES:
                    return {
                        "ok": False,
                        "error": "reply from authelia-bansd is too large",
                    }

            if not data:
                return {"ok": False, "error": "empty reply from daemon"}

            line = data.split(b"\n", 1)[0]
            resp = json.loads(line.decode("utf-8"))
            if not isinstance(resp, dict):
                return {
                    "ok": False,
                    "error": "invalid reply from authelia-bansd",
                }
            return resp
    except Exception as exc:  # noqa: BLE001
        logger.exception("authelia-bansd socket error")
        return {"ok": False, "error": str(exc)}


USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]+$")
IP_CIDR_RE = re.compile(r"^[0-9a-fA-F:./]+$")


def _authelia_bans_error(resp: dict) -> str:
    error = str(resp.get("error") or "authelia-bansd error").strip()
    details: list[str] = []
    for key, label in (("rc_users", "users"), ("rc_ips", "ips")):
        value = resp.get(key)
        if value not in (None, 0, "0"):
            details.append(f"{label} rc={value}")
    for key, label in (
        ("stderr_users", "users"),
        ("stderr_ips", "ips"),
        ("stdout_users", "users output"),
        ("stdout_ips", "ips output"),
    ):
        value = " ".join(str(resp.get(key) or "").split())
        if value:
            details.append(f"{label}: {value[:1000]}")
    return f"{error}: {'; '.join(details)}" if details else error


def _parse_authelia_ban_list(
    output: object,
    subject_header: str,
) -> tuple[list[dict[str, str]], str]:
    """Parse the aligned table produced by ``authelia storage bans * list``.

    The CLI dynamically changes column widths and uses ``never`` instead of a
    timestamp for permanent bans. Header offsets are therefore safer than a
    whitespace split. Unknown future output is returned as raw text instead of
    being mistaken for either an empty list or valid rows.
    """
    text = str(output or "").strip()
    if not text:
        return [], ""
    if text.casefold().rstrip(".") == "no results":
        return [], ""

    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return [], text

    header = lines[0]
    matches = list(re.finditer(r"\S+", header))
    expected = ["id", subject_header.casefold(), "expires", "source", "reason"]
    if [match.group(0).casefold() for match in matches] != expected:
        return [], text

    starts = [match.start() for match in matches]
    entries: list[dict[str, str]] = []
    for line in lines[1:]:
        values = [
            line[start:(starts[index + 1] if index + 1 < len(starts) else None)].strip()
            for index, start in enumerate(starts)
        ]
        if len(values) != 5 or not values[0] or not values[1]:
            return [], text
        entries.append(
            {
                "id": values[0],
                "subject": values[1],
                "expires": values[2],
                "source": values[3],
                "reason": values[4],
            }
        )
    return entries, ""


def _authelia_bans_result(users_output: object, ips_output: object) -> dict:
    users, users_raw = _parse_authelia_ban_list(users_output, "Username")
    ips, ips_raw = _parse_authelia_ban_list(ips_output, "IP")
    return {
        "users": users,
        "ips": ips,
        "users_raw": users_raw,
        "ips_raw": ips_raw,
        "error": None,
    }


def get_authelia_bans() -> dict:
    """
    Возвращает текущие баны Authelia (regulation).

    Приоритет:
      1) authelia-bansd через unix-сокет AUTHELIA_BANS_SOCKET;
      2) fallback — прямой вызов AUTHELIA_BANS_CMD (CLI).
    """
    # 1) через демон
    if AUTHELIA_BANS_SOCKET:
        resp = _call_authelia_bansd("list")
        if not resp.get("ok"):
            return {
                "users": [],
                "ips": [],
                "users_raw": "",
                "ips_raw": "",
                "error": _authelia_bans_error(resp),
            }
        return _authelia_bans_result(
            resp.get("users", ""),
            resp.get("ips", ""),
        )

    # 2) CLI fallback (если сокет не настроен)
    if not AUTHELIA_BANS_CMD:
        return {
            "users": [],
            "ips": [],
            "users_raw": "",
            "ips_raw": "",
            "error": 'AUTHELIA_BANS_CMD is not configured',
        }

    helper = shlex.split(AUTHELIA_BANS_CMD)
    users = run_cmd([*helper, "list-users"])
    ips = run_cmd([*helper, "list-ips"])

    error_parts: list[str] = []

    if users.startswith("Command failed") or users.startswith("Command timed out"):
        error_parts.append(f"users: {users}")
        users_out = ""
    else:
        users_out = users

    if ips.startswith("Command failed") or ips.startswith("Command timed out"):
        error_parts.append(f"ips: {ips}")
        ips_out = ""
    else:
        ips_out = ips

    error = "\n".join(error_parts) if error_parts else None
    if error:
        return {
            "users": [],
            "ips": [],
            "users_raw": "",
            "ips_raw": "",
            "error": error,
        }
    return _authelia_bans_result(users_out, ips_out)


def authelia_unban_user(username: str):
    """
    Разбан пользователя в regulation Authelia.
    """
    username = (username or "").strip()
    if not username:
        return "Empty username", 400
    if not USERNAME_RE.match(username):
        return 'Invalid characters in username', 400

    # 1) через демон
    if AUTHELIA_BANS_SOCKET:
        resp = _call_authelia_bansd("revoke-user", username=username)
        if not resp.get("ok"):
            return resp.get("error", 'authelia-bansd daemon error'), 500
        msg = resp.get(
            "message") or 'User unbanned (if a ban existed)'
        return msg, 200

    # 2) CLI fallback
    if not AUTHELIA_BANS_CMD:
        return 'AUTHELIA_BANS_CMD is not configured', 500

    out = run_cmd([*shlex.split(AUTHELIA_BANS_CMD), "revoke-user", username])
    if out.startswith("Command failed") or out.startswith("Command timed out"):
        logger.error("authelia_unban_user failed: %s", out)
        return out, 500

    return 'User unbanned (if a ban existed)', 200


def authelia_unban_ip(ip: str):
    """
    Разбан IP в regulation Authelia.
    """
    ip = (ip or "").strip()
    if not ip:
        return 'IP is required', 400
    if not IP_CIDR_RE.match(ip):
        return "Invalid IP/CIDR", 400
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return "Invalid IP/CIDR", 400

    # 1) через демон
    if AUTHELIA_BANS_SOCKET:
        resp = _call_authelia_bansd("revoke-ip", ip=ip)
        if not resp.get("ok"):
            return resp.get("error", 'authelia-bansd daemon error'), 500
        msg = resp.get("message") or 'IP unbanned (if a ban existed)'
        return msg, 200

    # 2) CLI fallback
    if not AUTHELIA_BANS_CMD:
        return 'AUTHELIA_BANS_CMD is not configured', 500

    out = run_cmd([*shlex.split(AUTHELIA_BANS_CMD), "revoke-ip", ip])
    if out.startswith("Command failed") or out.startswith("Command timed out"):
        logger.error("authelia_unban_ip failed: %s", out)
        return out, 500

    return 'IP unbanned (if a ban existed)', 200


def _call_authelia_usersd(payload: dict) -> dict:
    """
    Низкоуровневый клиент к демону authelia-usersd по unix-сокету.

    payload — dict, например:
      {"action": "update", "username": "...", "fields": {...}, "password_plain": "..."}

    Возвращает dict вида:
      {"ok": True, ...} или {"ok": False, "error": "..."}.
    """
    if not AUTHELIA_USERS_SOCKET:
        return {"ok": False, "error": "AUTHELIA_USERS_SOCKET not set"}

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(AUTHELIA_USERS_SOCKET)
            line = json.dumps(payload, ensure_ascii=False) + "\n"
            s.sendall(line.encode("utf-8"))

            data = b""
            while b"\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk

            if not data:
                return {"ok": False, "error": "empty reply from authelia-usersd"}

            resp_line = data.split(b"\n", 1)[0]
            return json.loads(resp_line.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.exception("authelia-usersd socket error")
        return {"ok": False, "error": str(exc)}


# ───────── ACL dump helpers ─────────────────────────────────────


def _acl_dump_for(file_path: str) -> str:
    """
    Возвращает текстовый дамп строк runtime-ACL, связанных с указанным файлом.
    Делает `show acl`, ищет нужный ACL-id по скобкам (path), затем `show acl <id>`.
    Если ACL not foundа — возвращает пояснение.
    """
    out = haproxy_runtime_command("show acl", SOCKET, timeout=2)
    acl_id = None
    for line in str(out).splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) < 2:
            continue
        path = parts[1].strip("()")
        if path == file_path:
            acl_id = f"#{parts[0]}"
            break

    if not acl_id:
        return f"(ACL for {file_path} was not found in memory)"

    body = haproxy_runtime_command(f"show acl {acl_id}", SOCKET, timeout=2)
    return body.strip() or f"(ACL {acl_id} is empty)"


def get_whitelists() -> dict:
    """
    Возвращает содержимое файлов whitelist'ов и их runtime-ACL.
    """
    # GEO файл
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                geo_file = f.read()
        else:
            geo_file = '(file is missing)'
    except Exception as e:  # pylint: disable=broad-except
        geo_file = f"(read error: {e})"

    # GLOBAL файл
    try:
        if os.path.exists(WHITELIST_GLOBAL_FILE):
            with open(WHITELIST_GLOBAL_FILE, "r", encoding="utf-8") as f:
                global_file = f.read()
        else:
            global_file = '(file is missing)'
    except Exception as e:  # pylint: disable=broad-except
        global_file = f"(read error: {e})"

    # Runtime ACL
    try:
        geo_runtime = _acl_dump_for(WHITELIST_FILE)
    except Exception as e:  # pylint: disable=broad-except
        geo_runtime = f"(runtime ACL read error: {e})"

    try:
        global_runtime = _acl_dump_for(WHITELIST_GLOBAL_FILE)
    except Exception as e:  # pylint: disable=broad-except
        global_runtime = f"(runtime ACL read error: {e})"

    return {
        "geo_file_path": WHITELIST_FILE,
        "geo_file": geo_file,
        "geo_runtime": geo_runtime,
        "global_file_path": WHITELIST_GLOBAL_FILE,
        "global_file": global_file,
        "global_runtime": global_runtime,
    }


# ───────── Бан/разбан ───────────────────────────────────────────

def unban_ip(ip: str):
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return "Invalid IP", 400
    haproxy_runtime_command(
        f"set table tbl_ban key {ip} data.gpc0 0", SOCKET, timeout=2
    )
    global cache_time
    cache_time = datetime.min
    return "OK", 200


# ───── helpers для GEO whitelist ─────

def _get_acl_id_for_whitelist() -> str | None:
    """Ищет runtime ACL-id, связанную с WHITELIST_FILE."""
    out = haproxy_runtime_command("show acl", SOCKET, timeout=2)
    for line in out.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) < 2:
            continue
        path = parts[1].strip("()")
        if path == WHITELIST_FILE:
            return f"#{parts[0]}"
    return None


def _add_acl_runtime(cidr: str) -> str:
    """Добавляет CIDR в ACL whitelist прямо в памяти HAProxy."""
    acl_id = _get_acl_id_for_whitelist()
    if not acl_id:
        return "ACL-id not found; skipped runtime update"
    return haproxy_runtime_command(
        f"add acl {acl_id} {cidr}", SOCKET, timeout=2
    ).strip()


def _del_acl_runtime(cidr: str) -> str:
    """Удаляет CIDR из ACL whitelist в памяти HAProxy."""
    acl_id = _get_acl_id_for_whitelist()
    if not acl_id:
        return "ACL-id not found; skipped runtime update"
    return haproxy_runtime_command(
        f"del acl {acl_id} {cidr}", SOCKET, timeout=2
    ).strip()


def _safe_runtime_acl(action: str, cidr: str, callback) -> str:
    """Выполняет runtime ACL-операцию без падения пользовательского API."""
    try:
        return callback(cidr)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "whitelist runtime ACL %s failed for %s: %s",
            action,
            cidr,
            exc,
        )
        return f"runtime ACL {action} failed: {exc}"


def _safe_reload_haproxy() -> str:
    """Перезагружает HAProxy без проброса исключений в Flask route."""
    try:
        return reload_haproxy()
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("whitelist reload failed")
        return f"reload failed: {exc}"


def add_to_whitelist(ip: str):
    """
    ТЕПЕРЬ: toggle-поведение.

    • Принимает IP или сеть.
    • Если ТАКОЙ CIDR уже есть в файле whitelist.geo — удаляем из файла и runtime ACL.
    • Если нет — добавляем и подгружаем в runtime ACL.
    """
    try:
        ipaddress.ip_address(ip)
        cidr = f"{ip}/32"
    except ValueError:
        try:
            cidr = str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return "Invalid IP/network", 400

    ensure_whitelist_file()

    # читаем текущий файл
    try:
        with open(WHITELIST_FILE, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        logger.error("add_to_whitelist: read error: %s", e)
        return f"Allow-list file read error: {e}", 500

    exists_exact = any(ln.strip() == cidr for ln in lines)

    if exists_exact:
        # ─── режим УДАЛЕНИЯ ───
        new_lines = [ln for ln in lines if ln.strip() != cidr]
        try:
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except OSError as e:
            logger.error("add_to_whitelist: write error (remove): %s", e)
            return f"Allow-list file write error: {e}", 500

        rt_res = _safe_runtime_acl("remove", cidr, _del_acl_runtime)
        rl_res = _safe_reload_haproxy()

        # КОРОТКОЕ сообщение пользователю
        msg = f"Removed: {cidr}"
        # Если хочешь, можно логировать подробности:
        logger.info("whitelist remove %s (rt=%s, reload=%s)",
                    cidr, rt_res, rl_res)

        return msg, 200

    # ─── режим ДОБАВЛЕНИЯ ───
    try:
        with open(WHITELIST_FILE, "a", encoding="utf-8") as f:
            f.write(cidr + "\n")
    except OSError as e:
        logger.error("add_to_whitelist: write error (add): %s", e)
        return f"Allow-list file write error: {e}", 500

    rt_res = _safe_runtime_acl("add", cidr, _add_acl_runtime)
    rl_res = _safe_reload_haproxy()

    msg = f"Added: {cidr}"
    logger.info("whitelist add %s (rt=%s, reload=%s)", cidr, rt_res, rl_res)

    return msg, 200


# ───── helpers для ГЛОБАЛЬНОГО файла ─────

def _get_acl_id_for_global_whitelist() -> str | None:
    """Ищет runtime ACL-id, связанную с WHITELIST_GLOBAL_FILE."""
    out = haproxy_runtime_command("show acl", SOCKET, timeout=2)
    for line in out.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) < 2:
            continue
        path = parts[1].strip("()")
        if path == WHITELIST_GLOBAL_FILE:
            return f"#{parts[0]}"
    return None


def _add_acl_runtime_global(cidr: str) -> str:
    """Добавляет CIDR в глобальную ACL whitelist прямо в памяти HAProxy."""
    acl_id = _get_acl_id_for_global_whitelist()
    if not acl_id:
        return "ACL-id not found; skipped runtime update"
    return haproxy_runtime_command(
        f"add acl {acl_id} {cidr}", SOCKET, timeout=2
    ).strip()


def _del_acl_runtime_global(cidr: str) -> str:
    """Удаляет CIDR из глобальной ACL whitelist в памяти HAProxy."""
    acl_id = _get_acl_id_for_global_whitelist()
    if not acl_id:
        return "ACL-id not found; skipped runtime update"
    return haproxy_runtime_command(
        f"del acl {acl_id} {cidr}", SOCKET, timeout=2
    ).strip()


def add_to_global_whitelist(ip: str):
    """
    ТЕПЕРЬ: toggle-поведение для глобального whitelist.ip.

    • Если такой CIDR уже есть в файле — удаляем и из файла, и из runtime ACL.
    • Если нет — добавляем и подгружаем.
    """
    try:
        ipaddress.ip_address(ip)
        cidr = f"{ip}/32"
    except ValueError:
        try:
            cidr = str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return "Invalid IP/network", 400

    ensure_whitelist_global_file()

    try:
        with open(WHITELIST_GLOBAL_FILE, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        logger.error("add_to_global_whitelist: read error: %s", e)
        return f"Global allow-list file read error: {e}", 500

    exists_exact = any(ln.strip() == cidr for ln in lines)

    if exists_exact:
        # ─── УДАЛЕНИЕ ───
        new_lines = [ln for ln in lines if ln.strip() != cidr]
        try:
            with open(WHITELIST_GLOBAL_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except OSError as e:
            logger.error(
                "add_to_global_whitelist: write error (remove): %s", e)
            return f"Global allow-list file write error: {e}", 500

        rt_res = _safe_runtime_acl(
            "remove-global", cidr, _del_acl_runtime_global
        )
        rl_res = _safe_reload_haproxy()

        msg = f"Removed from global allow list: {cidr}"
        logger.info("global whitelist remove %s (rt=%s, reload=%s)",
                    cidr, rt_res, rl_res)

        return msg, 200

    # ─── ДОБАВЛЕНИЕ ───
    try:
        with open(WHITELIST_GLOBAL_FILE, "a", encoding="utf-8") as f:
            f.write(cidr + "\n")
    except OSError as e:
        logger.error("add_to_global_whitelist: write error (add): %s", e)
        return f"Global allow-list file write error: {e}", 500

    rt_res = _safe_runtime_acl("add-global", cidr, _add_acl_runtime_global)
    rl_res = _safe_reload_haproxy()

    msg = f"Added to global allow list: {cidr}"
    logger.info("global whitelist add %s (rt=%s, reload=%s)",
                cidr, rt_res, rl_res)

    return msg, 200


# ───────── активные сессии (агрегация по IP) ─────────────────────

def _all_admin_sockets() -> list[str]:
    """
    Возвращает списком все runtime-сокеты текущего и draining-поколений.
    Ищем в той же директории, что и SOCKET_PATH, по имени admin.sock(.N).
    """
    try:
        sockets = sorted(
            os.path.join(SOCKET_DIR, fn)
            for fn in os.listdir(SOCKET_DIR)
            if SOCKET_RE.match(fn)
        )
        return sockets or [SOCKET]
    except OSError:
        return [SOCKET]


def get_connections() -> dict:
    """
    Собирает все сессии со всех процессов HAProxy и возвращает агрегированный список по src_ip.
    """
    sockets = _all_admin_sockets()
    all_conn = []
    for sock in sockets:
        raw = haproxy_runtime_command("show sess", sock, timeout=2)
        if str(raw).startswith("Command"):  # нет доступа/не тот слой
            continue
        parsed = parse_sessions(str(raw))
        parsed = [c for c in parsed
                  if c.get('src_ip') and not str(c['src_ip']).startswith('unix:')
                  and str(c.get('fe', '')).upper() != 'GLOBAL']
        all_conn.extend(parsed)

    counts: dict[str, int] = defaultdict(int)
    for c in all_conn:
        ip = c.get('src_ip')
        if not ip:
            continue
        counts[ip] += 1

    items = [{
        "src_ip": ip,
        "count": cnt,
        "country": get_country_code(ip)
    } for ip, cnt in counts.items()]

    items.sort(key=lambda x: (-x["count"], x["src_ip"]))
    return {"list": items, "total": len(all_conn)}


def _load_display_map_from_cfg(path: str | None = None) -> dict[str, str]:
    """
    Парсит haproxy.cfg и вытягивает пары:
      backend <name>
        # display-name: example.com, www.example.com
    Кэшируется по mtime.
    """
    if not path:
        path = HAPROXY_CFG

    try:
        mt = os.path.getmtime(path)
    except OSError:
        mt = -1.0

    if mt == _cfg_disp_cache["mtime"]:
        return _cfg_disp_cache["map"]

    mapping: dict[str, str] = {}
    be_pat = re.compile(r'^\s*backend\s+(\S+)')
    tag_pat = re.compile(r'^\s*#\s*display-name:\s*(.+)\s*$')

    current_be: str | None = None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                m_be = be_pat.match(line)
                if m_be:
                    current_be = m_be.group(1).strip()
                    continue
                m_tag = tag_pat.match(line)
                if m_tag and current_be:
                    mapping.setdefault(current_be, m_tag.group(1).strip())
    except OSError:
        pass

    _cfg_disp_cache["mtime"] = mt
    _cfg_disp_cache["map"] = mapping
    return mapping


# ───────── show stat helpers ─────────────────────────────────────

def _admin_sockets() -> list[str]:
    """Return only HAProxy stats sockets, never the master control socket."""
    return _all_admin_sockets()


def _show_stat(sock: str) -> str:
    """CSV из 'show stat' для указанного сокета."""
    try:
        return haproxy_runtime_command("show stat", sock, timeout=2) or ""
    except Exception as exc:
        logger.warning("show stat failed on %s: %s", sock, exc)
        return ""


def _parse_show_stat(csv_text: str) -> list[dict]:
    """Парсинг 'show stat' CSV -> список dict."""
    if not csv_text.strip():
        return []
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    header_line = lines[0].lstrip("# ").strip()
    reader = csv.DictReader(
        StringIO("\n".join([header_line] + lines[1:])), delimiter=",")
    return list(reader)


def _is_service_backend(pxname: str) -> bool:
    if not pxname:
        return True
    if pxname in EXCLUDE_EXACT:
        return True
    return any(pxname.startswith(p) for p in EXCLUDE_PREFIX)


def _pretty_backend(pxname: str) -> str:
    n = pxname[3:] if pxname.startswith("be_") else pxname
    return n.replace("_", ".")


# ───────── основная: статусы бэкендов для UI ─────────────────────

def get_backends_status() -> dict:
    """
    Собирает 'show stat' со всех сокетов, исключает служебные бэкенды,
    применяет display-map и возвращает агрегат по backend.
    """
    rows: list[dict] = []
    for sock in _admin_sockets():
        txt = _show_stat(sock)
        if not txt:
            continue
        parsed = _parse_show_stat(txt)
        if parsed:
            rows.extend(parsed)

    # дедуп
    seen: set[tuple[str | None, str | None]] = set()
    dedup: list[dict] = []
    for r in rows:
        key = (r.get("pxname"), r.get("svname"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)
    rows = dedup

    # только server-строки
    servers = [r for r in rows if (
        r.get("svname") not in ("FRONTEND", "BACKEND"))]

    # исключаем служебные
    by_be: dict[str, list[dict]] = {}
    for r in servers:
        be = (r.get("pxname") or "").strip()
        if not be or _is_service_backend(be):
            continue
        by_be.setdefault(be, []).append(r)

    if not by_be:
        logger.warning("backends_status: no items; pxnames=%s",
                       sorted({(r.get('pxname') or '') for r in rows if r.get('pxname')}))

    # читаем имена прямо из haproxy.cfg по тегам
    name_map = _load_display_map_from_cfg(HAPROXY_CFG)

    def is_up(status: str | None) -> bool:
        s = (status or "").strip().lower()
        return s.startswith("up") or s == "no check" or s == "open" or s.startswith("ready")

    def _pretty_backend(pxname: str) -> str:
        n = pxname[3:] if pxname.startswith("be_") else pxname
        return n.replace("_", ".")

    items = []
    for be, lst in sorted(by_be.items()):
        total = len(lst)
        ups = sum(1 for r in lst if is_up(r.get("status")))
        downs = total - ups
        color = "red" if total == 0 or ups == 0 else (
            "yellow" if downs > 0 else "green")
        display = name_map.get(be) or _pretty_backend(be)
        items.append({"backend": be, "site": display, "up": ups,
                     "down": downs, "total": total, "status": color})

    return {"items": items}


def _iter_authelia_log_lines_reverse(max_bytes: int | None = None):
    """Yield complete log lines newest-first without reading the whole file."""
    if not AUTHELIA_LOG_FILE:
        return

    byte_limit = max_bytes or AUTHELIA_LOG_MAX_SCAN_BYTES
    chunk_size = 64 * 1024
    with open(AUTHELIA_LOG_FILE, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        remaining = min(position, byte_limit)
        pending = b""

        while position > 0 and remaining > 0:
            read_size = min(chunk_size, position, remaining)
            position -= read_size
            remaining -= read_size
            handle.seek(position)
            block = handle.read(read_size) + pending
            parts = block.split(b"\n")
            pending = parts[0]
            for raw_line in reversed(parts[1:]):
                if raw_line:
                    yield raw_line.decode("utf-8", errors="replace").rstrip("\r")

        # If the scan reached the beginning, ``pending`` is a complete first
        # line. If the byte limit stopped us mid-file, it is only a fragment
        # and must not be presented as a real log entry.
        if position == 0 and pending:
            yield pending.decode("utf-8", errors="replace").rstrip("\r")


def _tail_authelia_log_lines(limit: int) -> list[str]:
    """Return up to ``limit`` newest lines in their on-disk order."""
    if limit <= 0 or not AUTHELIA_LOG_FILE:
        return []
    newest_first: list[str] = []
    for line in _iter_authelia_log_lines_reverse():
        newest_first.append(line)
        if len(newest_first) >= limit:
            break
    newest_first.reverse()
    return newest_first


def _parse_authelia_text_log_line(line: str) -> dict:
    """Best-effort parser for Authelia's supported logfmt/text format."""
    if "=" not in line:
        return {}
    try:
        tokens = shlex.split(line)
    except ValueError:
        return {}
    result: dict[str, object] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            result[key] = value
    return result if "time" in result or "level" in result or "msg" in result else {}


def _parse_authelia_log_line(line: str) -> dict:
    try:
        parsed = json.loads(line)
    except (TypeError, ValueError):
        parsed = _parse_authelia_text_log_line(line)
    if not isinstance(parsed, dict):
        parsed = {}
    parsed["raw"] = line
    return parsed


def _authelia_log_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple, bool, int, float)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            pass
    return str(value)


_AUTHELIA_LOG_PRIMARY_FIELDS = {
    "time",
    "level",
    "remote_ip",
    "method",
    "path",
    "username",
    "msg",
    "error",
    "raw",
}


def _authelia_log_entry(data: dict, line: str) -> dict:
    details = [
        {"name": str(key), "value": _authelia_log_text(value)}
        for key, value in data.items()
        if key not in _AUTHELIA_LOG_PRIMARY_FIELDS and value not in (None, "")
    ]
    details.sort(
        key=lambda item: (
            0 if item["name"] in {"provider", "providers"} else 1,
            item["name"],
        )
    )
    return {
        "time": _authelia_log_text(data.get("time")),
        "level": _authelia_log_text(data.get("level")),
        "remote_ip": _authelia_log_text(data.get("remote_ip")),
        "method": _authelia_log_text(data.get("method")),
        "path": _authelia_log_text(data.get("path")),
        "username": _authelia_log_text(data.get("username")),
        "msg": _authelia_log_text(data.get("msg")),
        "error": _authelia_log_text(data.get("error")),
        "details": details,
        "raw": line,
    }


def _read_authelia_users_from_file() -> tuple[list[dict], str | None]:
    """
    Читает AUTHELIA_USERS_FILE (file backend) и возвращает (users, error).

    users — список словарей:
      {
        "username": ...,
        "displayname": ...,
        "email": ...,
        "groups": [...],
        "disabled": bool,
      }
    Остальные поля в YAML не трогаем и не возвращаем.
    """
    if not AUTHELIA_USERS_FILE:
        return [], 'AUTHELIA_USERS_FILE is not configured (no path to users_database.yml)'

    if not os.path.exists(AUTHELIA_USERS_FILE):
        return [], f"Authelia users file not found: {AUTHELIA_USERS_FILE}"

    try:
        with open(AUTHELIA_USERS_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:  # noqa: BLE001
        logger.error("authelia users read error: %s", exc)
        return [], f"Authelia users file read error: {exc}"

    # Вариант 1: структура с корнем "users:"
    # Вариант 2: сразу словарь username -> attrs
    if isinstance(data, dict) and isinstance(data.get("users"), dict):
        users_node = data["users"]
    elif isinstance(data, dict):
        users_node = data
    else:
        return [], "Unexpected Authelia users file structure"

    result: list[dict] = []
    for username, info in users_node.items():
        if not isinstance(info, dict):
            continue

        displayname = info.get("displayname", "")
        email = info.get("email", "")
        groups = info.get("groups") or []
        disabled = bool(info.get("disabled", False))

        if not isinstance(groups, (list, tuple)):
            groups = [str(groups)]

        result.append(
            {
                "username": str(username),
                "displayname": str(displayname),
                "email": str(email),
                "groups": [str(g) for g in groups],
                "disabled": disabled,
            }
        )

    result.sort(key=lambda u: u["username"].lower())
    return result, None


def get_authelia_logs(
    ip: str | None = None,
    username: str | None = None,
    level: str | None = None,
    limit: int | None = None,
) -> tuple[list[dict], str | None]:
    """
    Возвращает (logs, error).

    logs — список словарей:
      {
        "time": ..., "level": ..., "remote_ip": ..., "method": ...,
        "path": ..., "username": ..., "msg": ..., "error": ..., "raw": ...
      }

    Фильтры:
      ip       — точное совпадение с remote_ip или вхождение в raw-строку;
      username — совпадение с полем username или вхождение в msg;
      level    — сравнение по lower() с полем level.
    """
    if not AUTHELIA_LOG_FILE:
        return [], 'AUTHELIA_LOG_FILE is not configured (no path to Authelia logs)'

    try:
        eff_limit = int(limit) if limit is not None else AUTHELIA_LOG_LIMIT
    except (TypeError, ValueError):
        eff_limit = AUTHELIA_LOG_LIMIT
    eff_limit = max(1, min(eff_limit, 1000))

    try:
        if os.path.getsize(AUTHELIA_LOG_FILE) == 0:
            return [], None
    except OSError as exc:
        logger.error("authelia log stat error: %s", exc)
        return [], f"Cannot access Authelia log file: {exc}"

    ip = (ip or "").strip() or None
    username = (username or "").strip() or None
    level = (level or "").strip() or None
    if level:
        level = level.lower()

    entries: list[dict] = []

    username_folded = username.casefold() if username else None

    try:
        # Read backwards until enough matches are found or the bounded byte
        # budget is exhausted. This makes rare filters useful without loading
        # a potentially hundreds-of-megabytes log into a web worker.
        for line in _iter_authelia_log_lines_reverse():
            if not line.strip():
                continue
            data = _parse_authelia_log_line(line)
            entry = _authelia_log_entry(data, line)

            if level and entry["level"].casefold() != level:
                continue

            if ip:
                remote_ip = entry["remote_ip"].strip()
                if remote_ip:
                    if ip != remote_ip:
                        continue
                elif ip not in entry["raw"]:
                    continue

            if username_folded:
                searchable = "\n".join(
                    (entry["username"], entry["msg"], entry["error"])
                ).casefold()
                if username_folded not in searchable:
                    continue

            entries.append(entry)
            if len(entries) >= eff_limit:
                break
    except OSError as exc:
        logger.error("authelia log read error: %s", exc)
        return [], f"Cannot read Authelia log file: {exc}"

    return entries, None


# ───────── Аналитика логов (топ ошибочных IP) ────────────────────

def get_attackers():
    """
    Возвращает данные для «Аналитика угроз» (топ IP по 400 и 451).

    В текущей версии UI лог-файл читать не пытаемся — всё берём через root-демон
    haproxy-controld, чтобы не раздавать права на LOG_FILE процессу веб-приложения.
    """
    data = controld_get_attackers()

    # ошибки демона пробрасываем как есть, чтобы было видно причину (сокет/команда/и т.д.)
    if not isinstance(data, dict):
        return {"error": "controld returned non-dict response", "diagnostic": {"source": "controld"}}

    if data.get("error"):
        # гарантируем, что diagnostic есть
        diag = data.get("diagnostic") or {}
        if isinstance(diag, dict):
            diag.setdefault("source", "controld")
        return {"error": data.get("error"), "diagnostic": diag}

    # поддержим несколько форматов payload (на случай разных версий демона)
    raw_400 = data.get("code_400") or data.get("a400") or data.get("400") or []
    raw_451 = data.get("code_451") or data.get("a451") or data.get("451") or []
    diag = data.get("diagnostic") or {}
    if isinstance(diag, dict):
        diag.setdefault("source", "controld")

    def _normalize(src):
        # dict{ip:count} → list[dict]
        if isinstance(src, dict):
            src = [{"ip": ip, "count": cnt} for ip, cnt in src.items()]

        out = []
        if not isinstance(src, list):
            return out

        for item in src:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("ip", "")).strip()
            if not ip:
                continue
            try:
                cnt = int(item.get("count") or item.get(
                    "cnt") or item.get("hits") or 0)
            except Exception:
                cnt = 0

            country = item.get("country") or get_country_code(ip)
            out.append({"ip": ip, "count": cnt, "country": country})
        # сортировка по убыванию на всякий случай
        out.sort(key=lambda x: x.get("count", 0), reverse=True)
        return out[:10]

    return {"code_400": _normalize(raw_400), "code_451": _normalize(raw_451), "diagnostic": diag}


# ─────────────────────────────────────────────────────────────────────────────
# Authelia users (users_database.yml via authelia-usersd)
# ─────────────────────────────────────────────────────────────────────────────

def get_authelia_users() -> tuple[list[dict], list[str], str | None]:
    """
    Возвращает (users, all_groups, error).

    users — список словарей с полями:
      username, displayname, email, groups (list[str]), disabled (bool)
    all_groups — отсортированный список всех уникальных групп.
    """
    resp = _call_authelia_usersd({"action": "list"})
    if not resp.get("ok"):
        return [], [], resp.get("error") or "authelia-usersd list failed"

    users = resp.get("users") or []
    if not isinstance(users, list):
        users = []

    all_groups_set: set[str] = set()
    norm_users: list[dict] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        groups = u.get("groups") or []
        if isinstance(groups, list):
            groups_list = [str(g) for g in groups]
        else:
            groups_list = [str(groups)]
        for g in groups_list:
            all_groups_set.add(g)
        norm_users.append(
            {
                "username": str(u.get("username", "")),
                "displayname": u.get("displayname", "") or "",
                "email": u.get("email", "") or "",
                "groups": groups_list,
                "disabled": bool(u.get("disabled", False)),
            }
        )

    all_groups = sorted(all_groups_set)
    return norm_users, all_groups, None


def get_authelia_user(username: str) -> tuple[dict | None, str | None]:
    """Возвращает (user, error). user с теми же полями, что и в get_authelia_users."""
    username = (username or "").strip()
    if not username:
        return None, "username is required"

    resp = _call_authelia_usersd({"action": "get", "username": username})
    if not resp.get("ok"):
        return None, resp.get("error") or "authelia-usersd get failed"

    u = resp.get("user") or {}
    if not isinstance(u, dict):
        return None, "invalid user payload from authelia-usersd"

    groups = u.get("groups") or []
    if isinstance(groups, list):
        groups_list = [str(g) for g in groups]
    else:
        groups_list = [str(groups)]

    user = {
        "username": str(u.get("username", username)),
        "displayname": u.get("displayname", "") or "",
        "email": u.get("email", "") or "",
        "groups": groups_list,
        "disabled": bool(u.get("disabled", False)),
    }
    return user, None


def update_authelia_user(
    username: str,
    fields: dict,
    password_plain: str | None = None,
) -> tuple[dict | None, str | None]:
    """Обновляет существующего пользователя. Возвращает (user, error)."""
    username = (username or "").strip()
    if not username:
        return None, "username is required"

    payload: dict = {
        "action": "update",
        "username": username,
        "fields": fields or {},
    }
    if password_plain:
        payload["password_plain"] = password_plain

    resp = _call_authelia_usersd(payload)
    if not resp.get("ok"):
        return None, resp.get("error") or "authelia-usersd update failed"

    user = resp.get("user") or {}
    if not isinstance(user, dict):
        return None, "invalid user payload from authelia-usersd"

    return user, None


def create_authelia_user(
    username: str,
    fields: dict,
    password_plain: str,
) -> tuple[dict | None, str | None]:
    """Создаёт нового пользователя. Возвращает (user, error)."""
    username = (username or "").strip()
    if not username:
        return None, "username is required"
    if not password_plain:
        return None, "password is required"

    payload: dict = {
        "action": "create",
        "username": username,
        "fields": fields or {},
        "password_plain": password_plain,
    }

    resp = _call_authelia_usersd(payload)
    if not resp.get("ok"):
        return None, resp.get("error") or "authelia-usersd create failed"

    user = resp.get("user") or {}
    if not isinstance(user, dict):
        return None, "invalid user payload from authelia-usersd"

    return user, None


def delete_authelia_user(username: str) -> tuple[bool, str | None]:
    """Удаляет пользователя. Возвращает (ok, error)."""
    username = (username or "").strip()
    if not username:
        return False, "username is required"

    payload = {"action": "delete", "username": username}
    resp = _call_authelia_usersd(payload)
    if not resp.get("ok"):
        return False, resp.get("error") or "authelia-usersd delete failed"

    return True, None
