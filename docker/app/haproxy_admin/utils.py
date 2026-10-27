#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
haproxy_admin.utils -- helper functions and constants
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

logger = logging.getLogger('haproxy-admin')

# ────────── shared constants (read from the environment, with defaults) ──────────
SOCKET = os.environ.get("SOCKET_PATH", "/run/haproxy/admin.sock").strip()
WHITELIST_FILE = os.environ.get(
    "WHITELIST_GEO_FILE", "/etc/haproxy/geoip/whitelist.geo").strip()
WHITELIST_GLOBAL_FILE = os.environ.get(
    "WHITELIST_GLOBAL_FILE", "/etc/haproxy/whitelist.ip").strip()
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/haproxy.log").strip()

TIME_RX = re.compile(r'(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?')

# environment settings for the logs and the ban table
JOURNAL_UNIT = os.getenv("HAPADM_JOURNAL_UNIT", "haproxy.service")
BAN_TABLE = os.getenv("HAPADM_BAN_TABLE", "tbl_ban")
# The window around the moment of a ban: ±2 minutes by default (configurable)
BAN_DELTA_SECONDS = int(os.getenv("HAPADM_BAN_DELTA_SECONDS", "120"))
LOG_LIMIT = int(os.getenv("HAPADM_LOG_LIMIT", "30"))
# Always return debug information when nothing was found
DEBUG_ON_EMPTY = os.getenv("HAPADM_DEBUG_ON_EMPTY",
                           "1") not in ("0", "false", "False", "")

# journalctl sources, in order of preference
JOURNAL_SOURCES = [s.strip() for s in os.getenv(
    "HAPADM_JOURNAL_SOURCES",
    "-u haproxy, SYSLOG_IDENTIFIER=haproxy, -u haproxy.service, -u rsyslog.service, *"
).split(",") if s.strip()]

# the root daemon's socket (haproxy-controld)
CONTROL_SOCKET = os.environ.get(
    "HAPROXY_CONTROL_SOCKET",
    "/run/easy-ha-proxy/haproxy-controld.sock",
).strip()

# get_country_code from cache.py is re-exported, so it is always imported from utils
from .cache import get_country_code  # noqa: E402  pylint: disable=wrong-import-position

__all__ = [
    # constants
    'SOCKET', 'WHITELIST_FILE', 'WHITELIST_GLOBAL_FILE', 'LOG_FILE',
    # functions
    'run_cmd', 'haproxy_runtime_command', 'parse_table_output', 'parse_sessions',
    'reload_haproxy',
    'ensure_whitelist_file', 'ensure_whitelist_global_file',
    # 'is_ip_in_global_whitelist', #'is_ip_in_whitelist',
    'read_log_file',
    'get_country_code',
    'grep_last_logs_for_ip',
    'controld_get_attackers',
]

# ───────────────────────── Shell commands ─────────────────────────────


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

# ──────────────────────── Parsing HAProxy tables ─────────────────────


def parse_table_output(output: str) -> dict | None:
    """
    Parses the output of "show table ..." and returns a dict
    {headers, rows, meta}.

    • For the ban table (tbl_ban):
        rows = [IP, Status, ReasonCode, ExpiresSec]
        - Status: "Blocked" if int(gpc0) > 0, otherwise "Not blocked"
        - ReasonCode: gpt0 (where HAProxy stores var(txn.ban_code))
        - ExpiresSec: HAProxy's exp, converted from ms to seconds

    • For the err tables (tbl_err_*):
        rows = [IP, ErrorCount, ExpiresSec]
        the top 10 addresses by http_err_rate.

    • exp comes from HAProxy in ms and is converted to seconds.
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

        # exp in HAProxy's output is almost always in milliseconds
        exp_raw = data.get('exp', '0')
        try:
            exp_sec = str(int(int(exp_raw) / 1000))  # ms -> s
        except ValueError:
            exp_sec = exp_raw

        # ───── BAN (tbl_ban: has gpc0, optionally gpt0) ─────
        if 'gpc0' in data:
            try:
                blocked = int(data['gpc0']) > 0
            except ValueError:
                blocked = False

            # gpt0 holds the ban_code (see the HAProxy template: sc-set-gpt0(2) var(txn.ban_code))
            ban_code = data.get('gpt0', '')

            # four columns: IP, status, reason code, TTL (s)
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

    # ───── sorting and trimming for ERR ─────
    if meta.get('name', '').startswith('tbl_err'):
        rows.sort(
            key=lambda r: int(r[1]) if str(r[1]).isdigit() else 0,
            reverse=True
        )
        rows = rows[:10]

    # ───── headers ─────
    if meta.get('name', '').startswith('tbl_ban'):
        # four columns: IP, status, reason (code), TTL
        headers = ["IP Address", "Status", "Reason", "Expires"]
    elif meta.get('name', '').startswith('tbl_err'):
        headers = ["IP Address", "Error Count", "Expires"]
    else:
        # the fallback for any other table
        headers = ["IP Address", "Value", "Expires"]

    return {'headers': headers, 'rows': rows, 'meta': meta}


# ───────────────────── Parsing "show sess" ───────────────────────────


def _age_to_sec(txt: str) -> int:
    m = TIME_RX.fullmatch(txt)
    if not m:
        return 0
    h, m_, s = m.groups(default='0')
    return int(h) * 3600 + int(m_) * 60 + int(s)


def parse_sessions(output: str) -> list[dict]:
    """
    Parses "show sess" and returns the list of sessions.
    IMPORTANT: lines whose first token had no ':' used to be dropped, which
    left the list empty on most installations.
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

        # The line's identifier (such as 0x..., sometimes with ':')
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

        # A src_ip is enough
        if c['src_ip']:
            conns.append(c)

    return sorted(conns, key=lambda x: x['duration'], reverse=True)

# ─────────────── HAProxy Runtime API helpers ─────────────────────────


def reload_haproxy() -> str:
    """
    A graceful reload that works everywhere:
    1) if haproxy-controld is available, ask it to reload as root;
    2) otherwise try the master socket;
    3) otherwise try systemctl reload haproxy;
    4) on failure, return the error text instead of raising.
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
    Makes sure whitelist.geo exists.

    IMPORTANT:
    - There is no chown here any more.
    - Ansible sets the owner and mode on the host.
    - Without the rights to create the file or directory, a warning is logged and that is all.
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
                # chmod can stay: the file belongs to whoever created it
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
    Makes sure whitelist.ip exists.

    Like ensure_whitelist_file:
    - No chown.
    - Ansible sets the owner and mode.
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


# ─────────────── reading the log ───────────────


def read_log_file() -> tuple[str, str, int]:
    """Returns (log, how it was read, number of lines)."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as handle:
            log = handle.read()
        return log, "file", len(log.splitlines())
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("read_log_file error: %s", exc)
        return f"Error reading logs: {exc}", "error", 0


# ────────────────────── logs helper (through the root daemon) ─────────────────


def _controld_request(cmd: str, timeout: float = 10.0) -> str:
    """
    Sends a command to haproxy-controld over the Unix socket and returns the raw answer.
    Protocol: one command line + '\n', a text answer, the server closes the socket.
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
    Moved into the root daemon (haproxy-controld).

    Only the RPC call is here:
      logs-ip <ip> <limit>
    Answer:
      OK <base64(text)>
      ERROR <message>
    """
    # minimal validation, so no junk is sent
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

    # expected: "OK <b64>"
    parts = resp.split(" ", 1)
    if len(parts) == 1:
        # "OK" without a payload
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
    Asks the root daemon haproxy-controld for log statistics
    (for "Threat analytics": the top addresses by 400 and 451).

    RPC command:
      logs-attackers

    Expected answer:
      OK <base64(json)>
      ERROR <message>

    Returns the parsed JSON as a dict, or a dict with the key 'error'.
    """
    resp = _controld_request("logs-attackers", timeout=timeout)

    if not resp:
        return {"error": "empty response from controld", "diagnostic": {"source": "controld"}}

    if resp.startswith("ERROR"):
        # keep the message as it is, so the daemon's text is visible
        return {"error": resp, "diagnostic": {"source": "controld"}}

    if not resp.startswith("OK"):
        return {"error": f"unexpected response: {resp[:200]}", "diagnostic": {"source": "controld"}}

    payload = resp.split(" ", 1)[1].strip() if " " in resp else ""
    if not payload:
        # allowed: OK without data
        return {"code_400": [], "code_451": [], "diagnostic": {"source": "controld", "empty": True}}

    # 1) the usual form: base64(json)
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=False)
        text = raw.decode("utf-8", "replace")
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"error": "controld payload is not a JSON object", "diagnostic": {"source": "controld"}}
    except Exception:
        pass

    # 2) fallback: the daemon may find it easier to return JSON without b64
    try:
        data = json.loads(payload)
        if isinstance(data, dict):
            return data
        return {"error": "controld payload is not a JSON object", "diagnostic": {"source": "controld"}}
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": f"cannot parse controld payload as json: {exc}", "diagnostic": {"source": "controld"}}
