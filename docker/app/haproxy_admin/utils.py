#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
haproxy_admin.utils – вспомогательные функции/константы
"""

from __future__ import annotations
import subprocess
import re
import os
import ipaddress
import logging
import time
import socket
import base64
import json
import shlex
from datetime import datetime, timedelta

logger = logging.getLogger('haproxy-admin')

# ────────── общие константы (читаем из ENV, есть дефолты) ──────────
SOCKET = os.environ.get("SOCKET_PATH", "/run/haproxy/admin.sock").strip()
WHITELIST_FILE = os.environ.get(
    "WHITELIST_GEO_FILE", "/etc/haproxy/geoip/whitelist.geo").strip()
WHITELIST_GLOBAL_FILE = os.environ.get(
    "WHITELIST_GLOBAL_FILE", "/etc/haproxy/whitelist.ip").strip()
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/haproxy.log").strip()

TIME_RX = re.compile(r'(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?')

# env/настройки для журналов и бан-таблицы
JOURNAL_UNIT = os.getenv("HAPADM_JOURNAL_UNIT", "haproxy.service")
BAN_TABLE = os.getenv("HAPADM_BAN_TABLE", "tbl_ban")
# Окно вокруг точки бана: ±2 минуты по умолчанию (настраивается)
BAN_DELTA_SECONDS = int(os.getenv("HAPADM_BAN_DELTA_SECONDS", "120"))
LOG_LIMIT = int(os.getenv("HAPADM_LOG_LIMIT", "30"))
# Включить принудительный возврат отладочной информации, если ничего не нашли
DEBUG_ON_EMPTY = os.getenv("HAPADM_DEBUG_ON_EMPTY",
                           "1") not in ("0", "false", "False", "")

# список источников для journalctl (в порядке приоритета)
JOURNAL_SOURCES = [s.strip() for s in os.getenv(
    "HAPADM_JOURNAL_SOURCES",
    "-u haproxy, SYSLOG_IDENTIFIER=haproxy, -u haproxy.service, -u rsyslog.service, *"
).split(",") if s.strip()]

# сокет root-демона (haproxy-controld)
CONTROL_SOCKET = os.environ.get(
    "HAPROXY_CONTROL_SOCKET",
    "/run/easy-ha-proxy/haproxy-controld.sock",
).strip()

# экспортируем get_country_code из cache.py, чтобы импортировать всегда из utils
from .cache import get_country_code  # noqa: E402  pylint: disable=wrong-import-position

__all__ = [
    # константы
    'SOCKET', 'WHITELIST_FILE', 'WHITELIST_GLOBAL_FILE', 'LOG_FILE',
    # функции
    'run_cmd', 'haproxy_runtime_command', 'parse_table_output', 'parse_sessions',
    'reload_haproxy',
    'ensure_whitelist_file', 'ensure_whitelist_global_file',
    # 'is_ip_in_global_whitelist', #'is_ip_in_whitelist',
    'read_log_file',
    'get_country_code',
    'grep_last_logs_for_ip',
    'controld_get_attackers',
]

# ───────────────────────── Shell-команды ─────────────────────────────


def run_cmd(cmd: str | list[str]) -> str:
    """Run a command without invoking a shell."""
    args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    if not args:
        return "Command error: empty command"
    logger.debug("Executing command: %r", args)
    try:
        proc = subprocess.Popen(  # noqa: S603
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = proc.communicate(timeout=30)
        if proc.returncode != 0:
            return f"Command failed ({proc.returncode}): {err.strip()}"
        return out
    except subprocess.TimeoutExpired:
        proc.kill()
        return "Command timed out"
    except Exception as exc:  # pylint: disable=broad-except
        return f"Command error: {exc}"


def haproxy_runtime_command(
    command: str,
    socket_path: str = SOCKET,
    timeout: float = 5.0,
) -> str:
    """Send one command directly to a HAProxy Runtime API Unix socket."""
    if "\n" in command or "\r" in command or "\x00" in command:
        raise ValueError("invalid HAProxy runtime command")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        client.connect(socket_path)
        client.sendall((command + "\n").encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        while True:
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 16 * 1024 * 1024:
                raise ValueError("HAProxy runtime response is too large")
    finally:
        client.close()
    return b"".join(chunks).decode("utf-8", "replace")

# ──────────────────────── Парсинг таблиц HAProxy ─────────────────────


def parse_table_output(output: str) -> dict | None:
    """
    Разбирает вывод «show table …» и возвращает dict со структурой
    {headers, rows, meta}.

    • Для ban-таблицы (tbl_ban):
        rows = [IP, Status, ReasonCode, ExpiresSec]
        - Status: "Blocked" если int(gpc0) > 0, иначе "Not blocked"
        - ReasonCode: gpt0 (куда мы пишем var(txn.ban_code) в HAProxy)
        - ExpiresSec: exp из HAProxy, конвертированный из мс в секунды

    • Для err-таблиц (tbl_err_*):
        rows = [IP, ErrorCount, ExpiresSec]
        берётся top-10 IP с наибольшим http_err_rate.

    • exp, приходящее от HAProxy в мс, конвертируется в секунды.
    """
    import re

    lines = output.splitlines()
    if not lines:
        return None

    # ───── meta ─────
    meta = {}
    m = re.search(
        r'table:\s+(\w+).*type:\s+(\w+).*size:(\d+).*used:(\d+)', lines[0]
    )
    if m:
        meta = {
            'name':  m.group(1),
            'type':  m.group(2),
            'size':  int(m.group(3)),
            'used':  int(m.group(4)),
        }

    rows: list[list[str]] = []
    for ln in lines[1:]:
        ln = ln.strip()
        if not ln:
            continue

        parts = ln.split()
        # data = { key: value, exp: ..., gpc0: ..., gpt0: ..., http_err_rate(...): ... }
        data = {
            k: v
            for p in parts[1:]
            if '=' in p
            for k, v in [p.split('=', 1)]
        }

        ip = data.get('key', '')

        # exp в выводе HAProxy почти всегда в миллисекундах
        exp_raw = data.get('exp', '0')
        try:
            exp_sec = str(int(int(exp_raw) / 1000))  # мс → с
        except ValueError:
            exp_sec = exp_raw

        # ───── BAN (tbl_ban: есть gpc0, опционально gpt0) ─────
        if 'gpc0' in data:
            try:
                blocked = int(data['gpc0']) > 0
            except ValueError:
                blocked = False

            # gpt0 мы используем как ban_code (см. шаблон HAProxy: sc-set-gpt0(2) var(txn.ban_code))
            ban_code = data.get('gpt0', '')

            # теперь 4 колонки: IP, статус, код причины, TTL (сек)
            rows.append([
                ip,
                "Blocked" if blocked else "Not blocked",
                ban_code,
                exp_sec,
            ])

        # ───── ERR (tbl_err_*: http_err_rate) ─────
        elif any('http_err_rate' in k for k in data):
            err_key = next(k for k in data if 'http_err_rate' in k)
            rows.append([ip, data[err_key], exp_sec])

    # ───── сортировка/обрезка для ERR ─────
    if meta.get('name', '').startswith('tbl_err'):
        rows.sort(
            key=lambda r: int(r[1]) if str(r[1]).isdigit() else 0,
            reverse=True
        )
        rows = rows[:10]

    # ───── заголовки ─────
    if meta.get('name', '').startswith('tbl_ban'):
        # 4 колонки: IP, статус, причина (код), TTL
        headers = ["IP Address", "Status", "Reason", "Expires"]
    elif meta.get('name', '').startswith('tbl_err'):
        headers = ["IP Address", "Error Count", "Expires"]
    else:
        # запасной вариант для любых других таблиц
        headers = ["IP Address", "Value", "Expires"]

    return {'headers': headers, 'rows': rows, 'meta': meta}


# ───────────────────── Парсинг «show sess» ───────────────────────────


def _age_to_sec(txt: str) -> int:
    m = TIME_RX.fullmatch(txt)
    if not m:
        return 0
    h, m_, s = m.groups(default='0')
    return int(h) * 3600 + int(m_) * 60 + int(s)


def parse_sessions(output: str) -> list[dict]:
    """
    Разбирает «show sess» и возвращает список сессий.
    ВАЖНО: раньше отбрасывали строки, где в первом токене нет ':',
    из-за этого на большинстве инсталляций список выходил пустым.
    """
    conns: list[dict] = []
    now = time.time()

    for raw in output.splitlines():
        raw = raw.strip()
        if not raw:
            continue

        parts = raw.split()
        if not parts:
            continue

        # Идентификатор строки (может быть вида 0x..., иногда с ':')
        row_id = parts[0].rstrip(':')

        c = {
            'id':  row_id,
            'src_ip': None, 'src_port': None,
            'fe': None, 'be': None, 'srv': None,
            'duration': 0, 'age_raw': None,
        }

        for p in parts[1:]:
            if '=' not in p:
                continue
            k, v = p.split('=', 1)

            if k == 'src':
                ip_port = v.rsplit(':', 1)
                c['src_ip'] = ip_port[0]
                c['src_port'] = ip_port[1] if len(ip_port) == 2 else None
            elif k in ('fe', 'be', 'srv'):
                c[k] = v
            elif k == 'age_ms' and v.isdigit():
                c['duration'] = int(v) // 1000
                c['age_raw'] = v
            elif k == 'age':
                c['age_raw'] = v
                c['duration'] = int(v) if v.isdigit() else _age_to_sec(v)
            elif k == 'ctime' and v.isdigit():
                c['duration'] = int(now - int(v))

        # Достаточно наличия src_ip
        if c['src_ip']:
            conns.append(c)

    return sorted(conns, key=lambda x: x['duration'], reverse=True)

# ─────────────── HAProxy Runtime API helpers ─────────────────────────


def reload_haproxy() -> str:
    """
    Универсальный graceful-reload:
    1) если доступен haproxy-controld — просим его сделать reload от root;
    2) иначе пробуем master socket;
    3) иначе пробуем systemctl reload haproxy;
    4) в случае неудачи возвращаем текст ошибки, не бросая исключение.
    """
    MASTER_SOCK = "/run/haproxy/master.sock"
    attempts: list[str] = []

    if CONTROL_SOCKET and os.path.exists(CONTROL_SOCKET):
        resp = _controld_request("reload", timeout=15).strip()
        if resp.startswith("OK"):
            detail = resp[2:].strip() or "ok"
            return f"controld reload ok: {detail}"
        msg = resp or "empty response"
        attempts.append(f"controld reload failed: {msg}")
        logger.warning("reload_haproxy via controld failed: %s", msg)

    if os.path.exists(MASTER_SOCK):
        try:
            out = haproxy_runtime_command("reload", MASTER_SOCK, timeout=5).strip()
            if out and "Error" in out:
                return f"master reload error: {out}"
            return "master reload ok"
        except Exception as exc:  # pylint: disable=broad-except
            attempts.append(f"master reload failed: {exc}")
            logger.warning("reload_haproxy via master socket skipped: %s", exc)

    try:
        subprocess.check_output(
            ["systemctl", "reload", "haproxy"],
            stderr=subprocess.STDOUT, text=True, timeout=15
        )
        return "systemctl reload ok"
    except Exception as exc:  # pylint: disable=broad-except
        attempts.append(f"systemctl reload failed: {exc}")
        logger.warning("reload_haproxy skipped: %s", exc)
        return "; ".join(attempts) if attempts else "reload skipped"

# ─────── whitelist.geo helpers ─────────


def ensure_whitelist_file() -> None:
    """
    Гарантируем, что файл whitelist.geo существует.

    ВАЖНО:
    - Никакого chown здесь больше нет.
    - Права/владельца выставляет Ansible на хосте.
    - Если нет прав создать файл/каталог — просто пишем warning и продолжаем.
    """
    try:
        base_dir = os.path.dirname(WHITELIST_FILE) or "/"
        try:
            os.makedirs(base_dir, exist_ok=True)
        except PermissionError as e:
            logger.warning(
                "ensure_whitelist_file: cannot create dir %r: %s",
                base_dir, e
            )
            return

        if not os.path.exists(WHITELIST_FILE):
            try:
                with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                    f.write("# HAProxy whitelist\n")
                # chmod можно оставить — владелец файла тот, кто его создал
                os.chmod(WHITELIST_FILE, 0o644)
                logger.info("Created whitelist file %s", WHITELIST_FILE)
            except PermissionError as e:
                logger.warning(
                    "ensure_whitelist_file: cannot create file %r: %s",
                    WHITELIST_FILE, e
                )
                return
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("ensure_whitelist_file unexpected error: %s", exc)


def ensure_whitelist_global_file() -> None:
    """
    Гарантируем, что файл whitelist.ip существует.

    Аналогично ensure_whitelist_file:
    - Без chown.
    - Права/владельца выставляет Ansible.
    """
    try:
        base = os.path.dirname(WHITELIST_GLOBAL_FILE) or "/etc/haproxy"
        try:
            os.makedirs(base, exist_ok=True)
        except PermissionError as e:
            logger.warning(
                "ensure_whitelist_global_file: cannot create dir %r: %s",
                base, e
            )
            return

        if not os.path.exists(WHITELIST_GLOBAL_FILE):
            try:
                with open(WHITELIST_GLOBAL_FILE, "w", encoding="utf-8") as f:
                    f.write("# HAProxy global whitelist\n")
                os.chmod(WHITELIST_GLOBAL_FILE, 0o644)
                logger.info("Created whitelist file %s", WHITELIST_GLOBAL_FILE)
            except PermissionError as e:
                logger.warning(
                    "ensure_whitelist_global_file: cannot create file %r: %s",
                    WHITELIST_GLOBAL_FILE, e
                )
                return
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("ensure_whitelist_global_file unexpected error: %s", exc)


# ─────────────── чтение журнала ───────────────


def read_log_file() -> tuple[str, str, int]:
    """Возвращает (лог, метод_чтения, кол-во_строк)."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as handle:
            log = handle.read()
        return log, "file", len(log.splitlines())
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("read_log_file error: %s", exc)
        return f"Error reading logs: {exc}", "error", 0


# ────────────────────── logs helper (через root-демон) ─────────────────


def _controld_request(cmd: str, timeout: float = 10.0) -> str:
    """
    Отправляет команду в haproxy-controld по Unix-сокету и возвращает raw-ответ.
    Протокол: одна строка команды + '\n', ответ текстом, сокет закрывается сервером.
    """
    if not CONTROL_SOCKET:
        return "ERROR control socket is empty"

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(CONTROL_SOCKET)
        s.sendall((cmd.strip() + "\n").encode("utf-8", "replace"))

        chunks: list[bytes] = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)

        return b"".join(chunks).decode("utf-8", "replace").strip("\n")
    except Exception as exc:  # pylint: disable=broad-except
        return f"ERROR controld request failed: {exc}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def grep_last_logs_for_ip(ip: str, limit: int = LOG_LIMIT) -> list[str]:
    """
    Перенесено в root-демон (haproxy-controld).

    Здесь — только RPC-вызов:
      logs-ip <ip> <limit>
    Ответ:
      OK <base64(text)>
      ERROR <message>
    """
    # минимальная валидация, чтобы не слать мусор
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return [f"[ERROR] invalid ip: {ip}"]

    resp = _controld_request(f"logs-ip {ip} {int(limit)}")
    if not resp:
        return ["[ERROR] empty response from controld"]

    if resp.startswith("ERROR"):
        return [resp]

    if not resp.startswith("OK"):
        return [f"[ERROR] unexpected response: {resp[:200]}"]

    # ожидаем формат: "OK <b64>"
    parts = resp.split(" ", 1)
    if len(parts) == 1:
        # "OK" без payload
        return []
    b64 = parts[1].strip()
    if not b64:
        return []

    try:
        raw = base64.b64decode(b64.encode("ascii"), validate=False)
        text = raw.decode("utf-8", "replace")
        return [ln for ln in text.splitlines() if ln.strip()]
    except Exception as exc:  # pylint: disable=broad-except
        return [f"[ERROR] cannot decode logs payload: {exc}"]


def controld_get_attackers(timeout: float = 10.0) -> dict:
    """
    Запрашивает у root-демона haproxy-controld агрегированную статистику по логам
    (для «Аналитика угроз»: топ IP по 400 и 451).

    RPC-команда:
      logs-attackers

    Ожидаемый ответ демона:
      OK <base64(json)>
      ERROR <message>

    Возвращает dict (распарсенный JSON) либо dict с ключом 'error'.
    """
    resp = _controld_request("logs-attackers", timeout=timeout)

    if not resp:
        return {"error": "empty response from controld", "diagnostic": {"source": "controld"}}

    if resp.startswith("ERROR"):
        # оставляем сообщение как есть, чтобы видеть текст демона
        return {"error": resp, "diagnostic": {"source": "controld"}}

    if not resp.startswith("OK"):
        return {"error": f"unexpected response: {resp[:200]}", "diagnostic": {"source": "controld"}}

    payload = resp.split(" ", 1)[1].strip() if " " in resp else ""
    if not payload:
        # допустимо: OK без данных
        return {"code_400": [], "code_451": [], "diagnostic": {"source": "controld", "empty": True}}

    # 1) основной вариант: base64(json)
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=False)
        text = raw.decode("utf-8", "replace")
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"error": "controld payload is not a JSON object", "diagnostic": {"source": "controld"}}
    except Exception:
        pass

    # 2) fallback: демону проще вернуть JSON напрямую без b64
    try:
        data = json.loads(payload)
        if isinstance(data, dict):
            return data
        return {"error": "controld payload is not a JSON object", "diagnostic": {"source": "controld"}}
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": f"cannot parse controld payload as json: {exc}", "diagnostic": {"source": "controld"}}
