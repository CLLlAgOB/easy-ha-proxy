#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
haproxy-controld — единый root-демон управления HAProxy:

1) Фоновая синхронизация банов:
   stick-table tbl_ban (HAProxy) → ipset haproxy_ban (iptables HP_BAN).

2) Команды по Unix-сокету:
   - "reload"              → systemctl reload haproxy
   - "sync-bans"           → одноразовая синхронизация tbl_ban → ipset
   - "ping"                → проверка связи
   - "certs-backup"        → backup сертификатов
   - "certs-restore <b64>" → restore сертификатов
   - "check-config <b64>"  → haproxy -c -f (tmp)
   - "write-config <b64>"  → запись haproxy.cfg
   - "apply-config <cfg-b64> <checks-b64>" → guarded apply + HTTPS checks + rollback
   - "begin-config-transaction <cfg-b64> <checks-b64> <sources-b64> <timeout>"
                              → guarded apply awaiting browser confirmation
   - "config-transaction-status [id]" → persisted transaction status
   - "confirm-config-transaction <id> <sha256>" → commit pending config
   - "rollback-config-transaction <id>" → restore previous config and YAML
   - "geoip-status" → local DB-IP release, selection, timer, and journal state
   - "geoip-update <b64-json>" → run the fixed GeoIP updater now
   - "geoip-configure <b64-json>" → transactionally replace selected countries
   - "geoip-schedule <b64-json>" → set update cadence (daily/weekly/monthly)
   - "udp-apply-json" → synchronously install udp.yml and return runtime state
   - "udp-status" → return the last successfully installed UDP ruleset state
   - "udp-port-check <start> <end>" → inspect host UDP listener conflicts
   - "logs-ip <ip> <n>"    → поиск логов по IP (journalctl/файл) + фикc времени через epoch

Не зависит от haproxy_admin/Flask, работает только с:
- admin-сокетом HAProxy;
- ipset;
- systemctl;
- journald/journalctl.
"""
import os
import zipfile
import base64
import re
import time
import logging
import subprocess
import socket
import threading
import io
import tempfile
import ipaddress
import json
import stat
import ssl
import shutil
import hashlib
import secrets
from collections import defaultdict
from typing import Set
from pathlib import Path
from datetime import datetime, timedelta, timezone


# ───── конфигурация через ENV (с дефолтами) ─────

# admin-сокет HAProxy (для show table)
SOCKET_PATH = os.environ.get("SOCKET_PATH", "/run/haproxy/admin.sock")
BAN_TABLE = os.environ.get("HAPADM_BAN_TABLE", "tbl_ban")
IPSET_NAME = os.environ.get("HAPADM_IPSET_NAME", "haproxy_ban")
# Zero-trust: mirror the authorized-IP table into an ipset the UDP DNAT rules
# whitelist against (analogous to the ban table -> haproxy_ban mirror).
AUTH_TABLE = os.environ.get("HAPADM_AUTH_TABLE", "tbl_ip_auth")
AUTH_IPSET = os.environ.get("HAPADM_AUTH_IPSET", "haproxy_ip_auth")
CERTS_HAP_DIR = os.environ.get("HAPADM_CERTS_HAP_DIR", "/etc/haproxy/certs")
CERTS_LE_DIR = os.environ.get("HAPADM_CERTS_LE_DIR", "/etc/letsencrypt")
HAPROXY_CFG_PATH = os.environ.get(
    "HAPROXY_CFG_PATH", "/etc/haproxy/haproxy.cfg")
HAPADM_LOG_TIME_ORDER = os.environ.get(
    "HAPADM_LOG_TIME_ORDER", "asc").lower()  # asc|desc

# логи (для logs-ip)
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/haproxy.log").strip()
LOG_LIMIT = int(os.getenv("HAPADM_LOG_LIMIT", "30"))
BAN_DELTA_SECONDS = int(os.getenv("HAPADM_BAN_DELTA_SECONDS", "120"))
DEBUG_ON_EMPTY = os.getenv("HAPADM_DEBUG_ON_EMPTY",
                           "1") not in ("0", "false", "False", "")

# список источников для journalctl (в порядке приоритета)
JOURNAL_SOURCES = [s.strip() for s in os.getenv(
    "HAPADM_JOURNAL_SOURCES",
    "-u haproxy, SYSLOG_IDENTIFIER=haproxy, -u haproxy.service, -u rsyslog.service, *"
).split(",") if s.strip()]

# таймауты и ограничения для journalctl (ускоряет logs-ip при бане)
JOURNAL_PER_SOURCE_TIMEOUT = float(os.getenv("HAPADM_JOURNAL_TIMEOUT", "3"))
JOURNAL_TOTAL_TIMEOUT = float(os.getenv("HAPADM_JOURNAL_TOTAL_TIMEOUT", "8"))
JOURNAL_USE_GREP = os.getenv("HAPADM_JOURNAL_USE_GREP", "1") not in ("0", "false", "False", "no", "")
JOURNAL_LINES_MULT = int(os.getenv("HAPADM_JOURNAL_LINES_MULT", "4"))

# TTL ban-таблицы (ускорение: можно задать явно или закэшировать)
BAN_TTL_OVERRIDE_SECONDS = int(os.getenv("HAPADM_BAN_TTL_SECONDS", "0"))
BAN_TTL_CACHE_SECONDS = int(os.getenv("HAPADM_BAN_TTL_CACHE_SECONDS", "300"))

# короткий кэш ответа logs-ip (чтобы повторный запрос не делал тяжёлые вызовы)
LOGS_IP_CACHE_SECONDS = float(os.getenv("HAPADM_LOGS_IP_CACHE_SECONDS", "2"))

# чтение хвоста LOG_FILE из Python (без tac|grep); параметры чтения
LOG_FILE_TAIL_CHUNK = int(os.getenv("HAPADM_LOG_FILE_TAIL_CHUNK", "65536"))   # bytes
LOG_FILE_TAIL_MAX_BYTES = int(os.getenv("HAPADM_LOG_FILE_TAIL_MAX_BYTES", "0"))  # 0 = без лимита
MAX_COMMAND_BYTES = int(os.getenv("HAPADM_MAX_COMMAND_BYTES", str(32 * 1024 * 1024)))
MAX_CONFIG_BYTES = int(os.getenv("HAPADM_MAX_CONFIG_BYTES", str(4 * 1024 * 1024)))
CONFIG_BACKUP_DIR = Path(os.getenv(
    "HAPROXY_CONFIG_BACKUP_DIR", "/opt/haproxy-admin/backups/haproxy"
))
GUARDED_CONFIG_BACKUPS = int(os.getenv("HAPROXY_GUARDED_CONFIG_BACKUPS", "14"))
CONTROL_PLANE_CHECK_ATTEMPTS = int(os.getenv("HAPROXY_CONTROL_PLANE_CHECK_ATTEMPTS", "6"))
CONTROL_PLANE_CHECK_INTERVAL = float(os.getenv("HAPROXY_CONTROL_PLANE_CHECK_INTERVAL", "1"))
CONTROL_PLANE_CHECK_TIMEOUT = float(os.getenv("HAPROXY_CONTROL_PLANE_CHECK_TIMEOUT", "2"))
CONFIG_SOURCE_DIR = Path(os.getenv(
    "HAPROXY_CONFIG_SOURCE_DIR", "/opt/haproxy-admin/config"
))
CONFIG_TRANSACTION_DIR = Path(os.getenv(
    "HAPROXY_CONFIG_TRANSACTION_DIR",
    "/var/lib/easy-ha-proxy/haproxy-config-guard",
))
CONFIG_TRANSACTION_STATE = "transaction.json"
CONFIG_TRANSACTION_VERSION = 1
MAINTENANCE_REBOOT_MARKER = Path(os.getenv(
    "EASY_HA_PROXY_REBOOT_MARKER",
    "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json",
))
ASSISTANT_REBOOT_MARKER = Path("/run/easy-ha-proxy/reboot-scheduled")
CONFIG_TRANSACTION_ACTIVE_STATES = frozenset({
    "prepared",
    "pending_confirmation",
    "rolling_back",
    "rollback_failed",
})
CONFIG_TRANSACTION_MIN_TIMEOUT = 1
CONFIG_TRANSACTION_MAX_TIMEOUT = int(os.getenv(
    "HAPROXY_CONFIG_TRANSACTION_MAX_TIMEOUT", "900"
))
MAX_TRANSACTION_SOURCE_FILE_BYTES = int(os.getenv(
    "HAPROXY_CONFIG_SOURCE_MAX_BYTES", str(2 * 1024 * 1024)
))
MAX_TRANSACTION_SOURCES_PAYLOAD_BYTES = int(os.getenv(
    "HAPROXY_CONFIG_SOURCES_PAYLOAD_MAX_BYTES", str(18 * 1024 * 1024)
))
MAX_TRANSACTION_STATE_BYTES = int(os.getenv(
    "HAPROXY_CONFIG_TRANSACTION_STATE_MAX_BYTES", str(20 * 1024 * 1024)
))
CONFIG_SOURCE_FILENAMES = frozenset({"vars.yml", "websites.yml", "tcp.yml"})
GEOIP_DIRECTORY = Path("/etc/haproxy/geoip")
GEOIP_SELECTION_PATH = GEOIP_DIRECTORY / "selection.json"
GEOIP_RELEASES_PATH = GEOIP_DIRECTORY / "releases"
GEOIP_UPDATE_COMMAND = "/usr/local/bin/update-geoip.sh"
GEOIP_UPDATE_SERVICE = "easy-ha-proxy-geoip-update.service"
GEOIP_UPDATE_TIMER = "easy-ha-proxy-geoip-update.timer"
GEOIP_FORCE_MARKER = Path("/run/easy-ha-proxy/geoip-force-download")
GEOIP_TIMER_DROPIN = Path(
    "/etc/systemd/system/easy-ha-proxy-geoip-update.timer.d/zz-web-schedule.conf"
)
# Web-selectable update cadence. Whitelisted so the UI can never set a
# sub-daily schedule or inject an arbitrary systemd calendar expression.
GEOIP_ALLOWED_SCHEDULES = ("daily", "weekly", "monthly")
GEOIP_MAX_SELECTION_BYTES = 16 * 1024
GEOIP_MAX_STATE_BYTES = 128 * 1024
GEOIP_MAX_COUNTRIES = 249
GEOIP_UPDATE_TIMEOUT = int(os.getenv("HAPROXY_GEOIP_UPDATE_TIMEOUT", "300"))
UDP_FORWARD_STATE = Path(os.getenv(
    "HAPROXY_UDP_FORWARD_STATE",
    "/run/easy-ha-proxy/udp-forward-state.json",
))
UDP_FORWARD_STATE_MAX_BYTES = 16 * 1024
UDP_MAX_PORT_RANGE = 1024
MAX_ARCHIVE_BYTES = int(os.getenv("HAPADM_MAX_ARCHIVE_BYTES", str(64 * 1024 * 1024)))
MAX_ARCHIVE_FILES = int(os.getenv("HAPADM_MAX_ARCHIVE_FILES", "4096"))
MAX_ARCHIVE_EXPANDED_BYTES = int(
    os.getenv("HAPADM_MAX_ARCHIVE_EXPANDED_BYTES", str(256 * 1024 * 1024))
)
MAX_COMPRESSION_RATIO = int(os.getenv("HAPADM_MAX_COMPRESSION_RATIO", "100"))


# интервал фоновой синхры
try:
    INTERVAL = int(os.environ.get("HAPADM_BAN_SYNC_INTERVAL", "10"))
except ValueError:
    INTERVAL = 10

# сокет управления (для reload/sync-bans/логов/backup/restore/etc)
CONTROL_SOCKET = os.environ.get(
    "HAPROXY_CONTROL_SOCKET",
    "/run/easy-ha-proxy/haproxy-controld.sock",
)

# команда перезапуска HAProxy
SYSTEMCTL_CMD = os.environ.get(
    "HAPROXY_SYSTEMCTL_CMD",
    "systemctl reload haproxy",
)

LOG = logging.getLogger("haproxy-controld")

# ───── маленькие кэши, чтобы не дёргать тяжёлые команды слишком часто ─────
_BAN_TTL_CACHE_LOCK = threading.Lock()
_BAN_TTL_CACHE_VALUE: int | None = None
_BAN_TTL_CACHE_TS: float = 0.0

_LOGS_IP_CACHE_LOCK = threading.Lock()
# key: (ip, limit) -> (expires_epoch, lines)
_LOGS_IP_CACHE: dict[tuple[str, int], tuple[float, list[str]]] = {}
_GUARDED_APPLY_LOCK = threading.Lock()
_GEOIP_OPERATION_LOCK = threading.Lock()



# ───── вспомогательные функции ─────

def run_cmd(args, input_data: str | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
    """
    Обёртка над subprocess.run с логированием ошибок.
    """
    proc = subprocess.run(
        args,
        input=input_data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command {args!r} failed with code {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc


def _udp_ports_in_use(start: int, end: int) -> set[int]:
    """Return host UDP listener ports within the inclusive requested range.

    Reads /proc/net/udp{,6} in the host namespace (the container application
    cannot see this itself). Used to reject a UDP forward whose listen range
    would hijack a service already running on the host.
    """
    result: set[int] = set()
    for proc_path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(proc_path, "r", encoding="ascii", errors="replace") as fh:
                next(fh, None)  # skip the header row
                for line in fh:
                    fields = line.split()
                    if len(fields) < 2 or ":" not in fields[1]:
                        continue
                    try:
                        port = int(fields[1].rsplit(":", 1)[1], 16)
                    except ValueError:
                        continue
                    if start <= port <= end:
                        result.add(port)
        except OSError:
            continue
    return result


def _read_udp_forward_state() -> dict[str, object]:
    try:
        state_stat = UDP_FORWARD_STATE.lstat()
        if (
            stat.S_ISLNK(state_stat.st_mode)
            or not stat.S_ISREG(state_stat.st_mode)
            or state_stat.st_size <= 0
            or state_stat.st_size > UDP_FORWARD_STATE_MAX_BYTES
        ):
            raise RuntimeError("UDP forwarding state has an unsafe file type or size")
        state = json.loads(UDP_FORWARD_STATE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("UDP forwarding has not been applied yet") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("UDP forwarding state is unreadable") from exc
    if not isinstance(state, dict) or set(state) != {
        "version",
        "applied_at",
        "forwards",
        "ports",
        "local_backends",
    }:
        raise RuntimeError("UDP forwarding state has an invalid format")
    if state.get("version") != 1:
        raise RuntimeError("UDP forwarding state version is unsupported")
    if (
        not isinstance(state.get("applied_at"), str)
        or not 1 <= len(str(state["applied_at"])) <= 128
    ):
        raise RuntimeError("UDP forwarding state timestamp is invalid")
    for field in ("forwards", "ports", "local_backends"):
        value = state.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RuntimeError(f"UDP forwarding state field {field} is invalid")
    return state


def _send_control_json(conn: socket.socket, result: dict[str, object]) -> None:
    payload = base64.b64encode(
        json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    prefix = "OK" if result.get("ok") is True else "ERROR"
    conn.sendall(f"{prefix} {payload}\n".encode("ascii"))


# ───── сертификаты ─────

def _ensure_within(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("archive path escapes the destination directory") from exc
    return candidate_resolved


def _validate_zip(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_FILES:
        raise ValueError("archive contains too many files")

    expanded = 0
    for info in infos:
        name = info.filename
        path = Path(name)
        if name.startswith("/") or ".." in path.parts:
            raise ValueError("archive contains an unsafe path")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise ValueError("archive contains a symbolic link")
        expanded += info.file_size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ValueError("archive expands beyond the allowed size")
        if (
            info.compress_size > 0
            and info.file_size > 1024 * 1024
            and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise ValueError("archive has a suspicious compression ratio")
    return infos

def certs_backup_b64() -> str:
    """
    Собирает ZIP из каталогов CERTS_HAP_DIR и CERTS_LE_DIR
    и возвращает его в виде base64-строки.
    """
    buf = io.BytesIO()
    total_files = 0
    total_size = 0
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1) /etc/haproxy/certs
        hap_dir = Path(CERTS_HAP_DIR)
        if hap_dir.is_dir():
            for p in hap_dir.rglob("*"):
                if not p.is_file():
                    continue
                try:
                    _ensure_within(hap_dir, p)
                except ValueError:
                    continue
                total_files += 1
                total_size += p.stat().st_size
                if (
                    total_files > MAX_ARCHIVE_FILES
                    or total_size > MAX_ARCHIVE_EXPANDED_BYTES
                ):
                    raise ValueError("certificate backup exceeds the allowed size")
                rel = p.relative_to(hap_dir)
                arcname = str(Path("haproxy_certs") / rel)
                zf.write(p, arcname)

        # 2) /etc/letsencrypt (если задан)
        le_root = Path(CERTS_LE_DIR) if CERTS_LE_DIR else None
        if le_root and le_root.is_dir():
            for p in le_root.rglob("*"):
                if not p.is_file():
                    continue
                try:
                    _ensure_within(le_root, p)
                except ValueError:
                    continue
                total_files += 1
                total_size += p.stat().st_size
                if (
                    total_files > MAX_ARCHIVE_FILES
                    or total_size > MAX_ARCHIVE_EXPANDED_BYTES
                ):
                    raise ValueError("certificate backup exceeds the allowed size")
                rel = p.relative_to(le_root)
                arcname = str(Path("letsencrypt") / rel)
                zf.write(p, arcname)

    raw = buf.getvalue()
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("certificate backup exceeds the allowed size")
    b64 = base64.b64encode(raw).decode("ascii")
    LOG.info("certs-backup: size=%d bytes, b64_len=%d", len(raw), len(b64))
    return b64


def certs_restore_b64(b64: str) -> str:
    """
    Принимает base64 ZIP, раскладывает файлы в CERTS_HAP_DIR и CERTS_LE_DIR.
    Возвращает текстовое сообщение для лога/ответа.
    """
    raw = base64.b64decode(b64, validate=True)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("certificate archive exceeds the allowed size")
    buf = io.BytesIO(raw)
    hap_dir = Path(CERTS_HAP_DIR)
    le_root = Path(CERTS_LE_DIR) if CERTS_LE_DIR else None

    restored = 0

    with zipfile.ZipFile(buf, "r") as zf:
        for info in _validate_zip(zf):
            name = info.filename
            if info.is_dir():
                continue

            if name.startswith("haproxy_certs/"):
                rel = Path(name).relative_to("haproxy_certs")
                dst = _ensure_within(hap_dir, hap_dir / rel)
            elif name.startswith("letsencrypt/") and le_root:
                rel = Path(name).relative_to("letsencrypt")
                dst = _ensure_within(le_root, le_root / rel)
            else:
                # неизвестный префикс — игнорируем
                continue

            dst.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(dst, "wb") as out:
                remaining = info.file_size
                while remaining:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("truncated certificate archive")
                    out.write(chunk)
                    remaining -= len(chunk)
            os.chmod(dst, 0o600)
            restored += 1

    msg = f"restored {restored} files"
    LOG.info("certs-restore: %s", msg)
    return msg


# ───── ipset/bans ─────

def ensure_ipset() -> None:
    """
    Гарантируем, что IPSET_NAME существует.
    """
    try:
        subprocess.run(
            ["ipset", "create", IPSET_NAME, "hash:ip", "family", "inet", "-exist"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        LOG.info("Ensured ipset %s exists", IPSET_NAME)
    except Exception as e:
        LOG.error("Failed to ensure ipset %s: %s", IPSET_NAME, e)
        raise


def get_banned_ips_from_haproxy() -> Set[str]:
    """
    Читает stick-таблицу BAN_TABLE через admin-сокет HAProxy
    и возвращает множество IP, для которых gpc0 > 0.
    """
    try:
        proc = run_cmd(
            ["socat", SOCKET_PATH, "stdio"],
            input_data=f"show table {BAN_TABLE}\n",
            timeout=5,
        )
    except Exception as e:
        LOG.error("Failed to fetch table %s from HAProxy: %s", BAN_TABLE, e)
        return set()

    banned_ips: Set[str] = set()

    # Пример строк:
    # 0x7e27...: key=192.0.2.83 use=0 exp=... gpt0=20 gpc0=1
    line_re = re.compile(
        r"key=(?P<ip>\d+\.\d+\.\d+\.\d+).*?\bgpc0=(?P<gpc0>\d+)"
    )

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        m = line_re.search(line)
        if not m:
            continue

        ip = m.group("ip")
        gpc0 = int(m.group("gpc0"))
        if gpc0 > 0:
            banned_ips.add(ip)

    return banned_ips


def _parse_short_iso_ts(line: str) -> datetime | None:
    # ожидаем: "2025-12-15T01:15:56+07:00 ..."
    ts = line.split(" ", 1)[0].strip()
    if not ts:
        return None
    try:
        # journalctl может печатать Z — нормализуем
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _sort_log_lines_by_time(lines: list[str]) -> list[str]:
    if HAPADM_LOG_TIME_ORDER not in ("asc", "desc"):
        return lines

    with_ts: list[tuple[datetime, int, str]] = []
    no_ts: list[tuple[int, str]] = []

    for i, ln in enumerate(lines):
        dt = _parse_short_iso_ts(ln)
        if dt is None:
            no_ts.append((i, ln))
        else:
            with_ts.append((dt, i, ln))

    with_ts.sort(key=lambda x: x[0], reverse=(HAPADM_LOG_TIME_ORDER == "desc"))
    # сохраняем исходный порядок для строк без ts
    no_ts.sort(key=lambda x: x[0])

    return [ln for _, _, ln in with_ts] + [ln for _, ln in no_ts]


def get_ipset_members() -> Set[str]:
    """
    Возвращает множество IP, которые сейчас лежат в ipset IPSET_NAME.
    """
    try:
        proc = run_cmd(["ipset", "list", IPSET_NAME], timeout=5)
    except RuntimeError as e:
        LOG.error("Failed to list ipset %s: %s", IPSET_NAME, e)
        return set()

    members: Set[str] = set()
    capture = False

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Members:"):
            capture = True
            continue
        if not capture:
            continue

        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if ip.count(".") == 3:
            members.add(ip)

    return members


def sync_bans_once() -> None:
    """
    Одна итерация синхронизации tbl_ban → ipset.
    """
    haproxy_banned = get_banned_ips_from_haproxy()
    ipset_members = get_ipset_members()

    if not haproxy_banned and not ipset_members:
        return

    to_add = haproxy_banned - ipset_members
    to_del = ipset_members - haproxy_banned

    for ip in sorted(to_add):
        try:
            subprocess.run(
                ["ipset", "add", IPSET_NAME, ip, "-exist"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            LOG.warning("Failed to add %s to %s: %s", ip, IPSET_NAME, e)

    for ip in sorted(to_del):
        try:
            subprocess.run(
                ["ipset", "del", IPSET_NAME, ip],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            LOG.warning("Failed to del %s from %s: %s", ip, IPSET_NAME, e)

    if to_add or to_del:
        LOG.info(
            "Sync done: +%d, -%d (haproxy=%d, ipset=%d)",
            len(to_add),
            len(to_del),
            len(haproxy_banned),
            len(ipset_members),
        )


def ensure_auth_ipset() -> None:
    """Ensure the zero-trust authorized-IP ipset exists."""
    subprocess.run(
        ["ipset", "create", AUTH_IPSET, "hash:ip", "family", "inet", "-exist"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    LOG.info("Ensured ipset %s exists", AUTH_IPSET)


def get_authorized_ips_from_haproxy() -> "Set[str] | None":
    """Authorized IPs (gpc0>0) from AUTH_TABLE.

    Returns None if the fetch fails so a transient error never wipes the
    authorized set (unlike bans, an empty result must not clear it).
    """
    try:
        proc = run_cmd(
            ["socat", SOCKET_PATH, "stdio"],
            input_data=f"show table {AUTH_TABLE}\n",
            timeout=5,
        )
    except Exception as e:
        LOG.warning("Failed to fetch table %s from HAProxy: %s", AUTH_TABLE, e)
        return None

    authorized: Set[str] = set()
    line_re = re.compile(r"key=(?P<ip>\d+\.\d+\.\d+\.\d+).*?\bgpc0=(?P<gpc0>\d+)")
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.search(line)
        if m and int(m.group("gpc0")) > 0:
            authorized.add(m.group("ip"))
    return authorized


def get_auth_ipset_members() -> Set[str]:
    """IPs currently in the authorized-IP ipset."""
    try:
        proc = run_cmd(["ipset", "list", AUTH_IPSET], timeout=5)
    except RuntimeError as e:
        LOG.error("Failed to list ipset %s: %s", AUTH_IPSET, e)
        return set()
    members: Set[str] = set()
    capture = False
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Members:"):
            capture = True
            continue
        if capture:
            parts = line.split()
            if parts and parts[0].count(".") == 3:
                members.add(parts[0])
    return members


def sync_auth_once() -> None:
    """One iteration of AUTH_TABLE -> AUTH_IPSET (zero-trust whitelist)."""
    authorized = get_authorized_ips_from_haproxy()
    if authorized is None:
        return  # fetch failed; leave the authorized set untouched
    members = get_auth_ipset_members()
    if not authorized and not members:
        return
    for ip in sorted(authorized - members):
        try:
            subprocess.run(
                ["ipset", "add", AUTH_IPSET, ip, "-exist"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            LOG.warning("Failed to add %s to %s: %s", ip, AUTH_IPSET, e)
    for ip in sorted(members - authorized):
        try:
            subprocess.run(
                ["ipset", "del", AUTH_IPSET, ip],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            LOG.warning("Failed to del %s from %s: %s", ip, AUTH_IPSET, e)


def bans_loop() -> None:
    """
    Фоновый цикл синхронизации банов и авторизованных IP (zero-trust).
    """
    LOG.info("Ban-sync loop started: table=%s, ipset=%s, interval=%ss",
             BAN_TABLE, IPSET_NAME, INTERVAL)
    try:
        ensure_ipset()
    except Exception:
        LOG.error("Ban-sync loop aborted: ipset init failed")
        return
    try:
        ensure_auth_ipset()
    except Exception as e:
        LOG.error("Auth ipset init failed; zero-trust UDP will not update: %s", e)

    while True:
        try:
            sync_bans_once()
        except Exception as e:
            LOG.error("Unexpected ban-sync error: %s", e)
        try:
            sync_auth_once()
        except Exception as e:
            LOG.error("Unexpected auth-sync error: %s", e)
        time.sleep(INTERVAL)


# ───── logs-ip (перенесено из utils; фикс времени через epoch) ─────

def _is_selfcheck_line(line: str, ip: str) -> bool:
    # исключаем сам запрос к /ip/<ip> чтобы не ловить текущий вызов
    return "GET /ip/" in line or f"/ip/{ip}" in line


def _fmt_sec(v: int | None) -> str:
    if v is None:
        return "None"
    if v < 60:
        return f"{v}s"
    if v < 3600:
        return f"{v//60}m{v % 60:02d}s"
    if v < 86400:
        m = (v % 3600) // 60
        s = v % 60
        return f"{v//3600}h{m:02d}m{s:02d}s"
    d = v // 86400
    h = (v % 86400) // 3600
    m = (v % 3600) // 60
    return f"{d}d{h:02d}h{m:02d}m"


def _get_ban_table_ttl_seconds(table: str = BAN_TABLE) -> int:
    """
    TTL таблицы (expire) из «show table <table>». Возвращает секунды; fallback 7 дней.

    Оптимизация:
      1) можно задать TTL явно через HAPADM_BAN_TTL_SECONDS;
      2) иначе TTL кэшируется на BAN_TTL_CACHE_SECONDS;
      3) сначала пытаемся лёгкий запрос «show table <table> key 0.0.0.0», чтобы избежать дампа всей таблицы.
    """
    if BAN_TTL_OVERRIDE_SECONDS > 0:
        return BAN_TTL_OVERRIDE_SECONDS

    now = time.time()
    with _BAN_TTL_CACHE_LOCK:
        if (
            _BAN_TTL_CACHE_VALUE is not None
            and (now - _BAN_TTL_CACHE_TS) < max(1, BAN_TTL_CACHE_SECONDS)
        ):
            return _BAN_TTL_CACHE_VALUE

    def _parse_expire_seconds(text: str) -> int | None:
        m = re.search(r'\bexpire\b[^\d]*(\d+)\s*([a-zA-Z]+)?', text or "")
        if not m:
            return None
        val = int(m.group(1))
        unit = (m.group(2) or "").lower()
        # expire без суффикса обычно секунды
        if unit in ("ms", "msec"):
            return max(1, val // 1000)
        if unit in ("", "s", "sec"):
            return val
        if unit in ("m", "min"):
            return val * 60
        if unit == "h":
            return val * 3600
        if unit in ("d", "day", "days"):
            return val * 86400
        return None

    ttl: int | None = None
    try:
        # 1) Лёгкий запрос: header + (в идеале) ничего больше
        for cmd in (
            f"show table {table} key 0.0.0.0\n",
            f"show table {table}\n",  # fallback: может быть тяжёлым
        ):
            proc = run_cmd(
                ["socat", SOCKET_PATH, "stdio"],
                input_data=cmd,
                timeout=5,
            )
            ttl = _parse_expire_seconds(proc.stdout or "")
            if ttl is not None:
                break
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_get_ban_table_ttl_seconds: %s", exc)

    if ttl is None:
        ttl = 7 * 24 * 3600

    with _BAN_TTL_CACHE_LOCK:
        globals()["_BAN_TTL_CACHE_VALUE"] = ttl
        globals()["_BAN_TTL_CACHE_TS"] = now
    return ttl


def _get_ban_remaining_seconds(ip: str, table: str = BAN_TABLE) -> int | None:
    """Остаток TTL ключа (ip) из «show table <table> key <ip>» в секундах, либо None, если нет записи."""
    try:
        proc = run_cmd(
            ["socat", SOCKET_PATH, "stdio"],
            input_data=f"show table {table} key {ip}\n",
            timeout=5,
        )
        out = (proc.stdout or "").strip()
        if not out:
            return None

        # exp/expire: exp БЕЗ суффикса → миллисекунды (ВАЖНО)
        m = re.search(r'\bexp(?:ire)?\s*[:=]?\s*(\d+)\s*([a-zA-Z]+)?\b', out)
        if not m:
            m = re.search(r'\bexpires?\s+in\s+(\d+)\s*([a-zA-Z]+)\b', out)
        if not m:
            return None

        val = int(m.group(1))
        unit = (m.group(2) or "").lower()
        if unit in ("", "ms", "msec"):
            return max(1, val // 1000)
        if unit in ("s", "sec"):
            return val
        if unit in ("m", "min"):
            return val * 60
        if unit == "h":
            return val * 3600
        if unit in ("d", "day", "days"):
            return val * 86400
        return val
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_get_ban_remaining_seconds: %s", exc)
    return None


def _normalize_remaining_seconds(rem: int, ttl: int) -> int:
    """
    Приводим ban_remaining к секундам:
    - если rem >> ttl (в 10+ раз), считаем, что rem в миллисекундах → делим на 1000
    - если после деления всё ещё rem > ttl*2, подрезаем до ttl
    - не даём уйти в отрицательные/некорректные значения
    """
    if rem <= 0:
        return 0
    # эвристика: exp почти всегда в мс, а ttl — в секундах.
    if ttl > 0 and rem > ttl * 10:
        rem = rem // 1000
    if ttl > 0 and rem > ttl * 2:
        rem = ttl
    return max(0, rem)


def _parse_source_to_args(source_flag: str) -> tuple[list[str], list[str]]:
    """
    Возвращает (opt_args, match_args) для journalctl.
    source_flag поддерживает старые строки:
      - "-u haproxy"
      - "SYSLOG_IDENTIFIER=haproxy"
      - "-u haproxy.service"
      - "*"
    """
    opt_args: list[str] = []
    match_args: list[str] = []

    src = source_flag.strip()
    if not src or src == "*":
        return opt_args, match_args

    # если это FIELD=VALUE — это match-аргумент journalctl
    if "=" in src and not src.lstrip().startswith("-"):
        match_args.append(src)
        return opt_args, match_args

    # голое слово ("haproxy") journalctl не принимает как match; исторические
    # конфигурации с таким значением трактуем как syslog identifier
    if not src.lstrip().startswith("-") and " " not in src:
        opt_args.extend(["-t", src])
        return opt_args, match_args

    # иначе опции вида "-u haproxy"
    parts = src.split()
    if parts:
        opt_args.extend(parts)
    return opt_args, match_args


def _journal_window_for_ip(
    ip: str,
    since_epoch: int,
    until_epoch: int,
    limit: int = LOG_LIMIT,
    collect_debug: bool = False,
):
    """
    Поиск в journald в заданном окне с фильтром по IP и отсевом самозапросов.

    Оптимизации:
      • ограничиваем вывод journalctl через -n (после фильтрации);
      • (если возможно) используем --grep=<ip>, чтобы journalctl сам отфильтровал сообщения;
      • вводим общий бюджет времени на все источники (JOURNAL_TOTAL_TIMEOUT).
    """
    started = time.monotonic()
    debug = {
        "since_epoch": since_epoch,
        "until_epoch": until_epoch,
        "sources": [],
        "timeouts": {
            "per_source": JOURNAL_PER_SOURCE_TIMEOUT,
            "total": JOURNAL_TOTAL_TIMEOUT,
        },
        "used_grep": JOURNAL_USE_GREP,
    }

    nlines = max(limit * max(1, JOURNAL_LINES_MULT), limit + 5)

    def _run_one(source_flag: str, use_grep: bool) -> tuple[list[str], dict]:
        opt_args, match_args = _parse_source_to_args(source_flag)

        args = [
            "journalctl",
            "--no-pager",
            "-q",
            "-o", "short-iso",
            "--since", f"@{since_epoch}",
            "--until", f"@{until_epoch}",
            "-n", str(nlines),
        ] + opt_args + match_args

        if use_grep:
            args += ["--grep", re.escape(ip)]

        remaining_total = JOURNAL_TOTAL_TIMEOUT - (time.monotonic() - started)
        timeout = min(JOURNAL_PER_SOURCE_TIMEOUT, max(0.1, remaining_total))

        out = ""
        err = ""
        rc: int | None = None
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            rc = proc.returncode
            out = proc.stdout or ""
            err = proc.stderr or ""
        except subprocess.TimeoutExpired:
            err = "TIMEOUT"
        except Exception as exc:  # pylint: disable=broad-except
            err = f"EXC: {exc}"

        dt = time.monotonic() - t0

        # фильтрация и сортировка (тут уже мало строк)
        raw_lines = out.splitlines()
        filtered: list[str] = []
        for ln in raw_lines:
            if ip in ln and not _is_selfcheck_line(ln, ip):
                filtered.append(ln)

        ordered = _sort_log_lines_by_time(filtered)[:limit]

        info = {
            "source": source_flag,
            "args": args,
            "duration_s": round(dt, 3),
            "returncode": rc,
            "found_total": len(filtered),
            "returned": len(ordered),
            "stderr": err[:4000],
            "used_grep": use_grep,
        }
        return ordered, info

    for src in JOURNAL_SOURCES:
        if (time.monotonic() - started) >= JOURNAL_TOTAL_TIMEOUT:
            break

        # 1) пробуем с --grep (быстрее и меньше вывода), 2) если не получилось — без него
        lines1, info1 = _run_one(src, use_grep=JOURNAL_USE_GREP)
        debug["sources"].append(info1)
        if lines1:
            return (lines1, debug) if collect_debug else lines1

        if JOURNAL_USE_GREP and info1.get("returncode") not in (0, None) and info1.get("stderr"):
            lines2, info2 = _run_one(src, use_grep=False)
            debug["sources"].append(info2)
            if lines2:
                return (lines2, debug) if collect_debug else lines2

    return ([], debug) if collect_debug else []


def _file_tail_for_ip(ip: str, limit: int = LOG_LIMIT) -> list[str]:
    """
    Быстрый поиск последних совпадений по IP в LOG_FILE.

    Было: tac|grep|tac (несколько процессов + shell).
    Теперь: читаем файл с конца блоками и останавливаемся, как только нашли нужное число строк.
    """
    if not LOG_FILE:
        return []
    if not os.path.exists(LOG_FILE):
        return []

    chunk_size = max(4096, int(LOG_FILE_TAIL_CHUNK))
    max_bytes = int(LOG_FILE_TAIL_MAX_BYTES) if LOG_FILE_TAIL_MAX_BYTES else 0

    try:
        found: list[str] = []
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            buf = b""
            scanned = 0

            while pos > 0 and len(found) < limit:
                if max_bytes and scanned >= max_bytes:
                    break

                to_read = min(chunk_size, pos)
                pos -= to_read
                f.seek(pos)
                chunk = f.read(to_read)
                scanned += to_read

                buf = chunk + buf
                parts = buf.split(b"\n")
                buf = parts[0]  # неполная строка в начале буфера

                for raw in reversed(parts[1:]):
                    if len(found) >= limit:
                        break
                    ln = raw.decode("utf-8", "replace")
                    if ip in ln and not _is_selfcheck_line(ln, ip):
                        found.append(ln)

            if pos == 0 and buf and len(found) < limit:
                ln = buf.decode("utf-8", "replace")
                if ip in ln and not _is_selfcheck_line(ln, ip):
                    found.append(ln)

        found.reverse()  # вернуть в естественном порядке
        return found
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("_file_tail_for_ip: %s", exc)
        return []


def grep_last_logs_for_ip(ip: str, limit: int = LOG_LIMIT) -> list[str]:
    """
    Логика:
      • сначала быстрый кэш (LOGS_IP_CACHE_SECONDS);
      • пробуем хвост LOG_FILE (дёшево);
      • если IP в ban-таблице → считаем ban_start и берём journald в окне [ban_start ± DELTA];
      • иначе → результат хвоста LOG_FILE.

    При отсутствии совпадений (и DEBUG_ON_EMPTY=1) возвращаем диагностический блок.
    """
    # 0) короткий кэш (полезно, если UI/клиент повторяет запрос после таймаута)
    if LOGS_IP_CACHE_SECONDS > 0:
        key = (ip, int(limit))
        now = time.time()
        with _LOGS_IP_CACHE_LOCK:
            item = _LOGS_IP_CACHE.get(key)
            if item and item[0] > now:
                return item[1]

    # 1) быстрый хвост по файлу (часто это всё, что нужно, даже если IP уже в бане)
    file_lines = _file_tail_for_ip(ip, limit=limit)
    if file_lines:
        if LOGS_IP_CACHE_SECONDS > 0:
            with _LOGS_IP_CACHE_LOCK:
                _LOGS_IP_CACHE[(ip, int(limit))] = (time.time() + LOGS_IP_CACHE_SECONDS, file_lines)
        return file_lines

    # 2) проверяем бан
    ban_remaining_raw = _get_ban_remaining_seconds(ip)
    if ban_remaining_raw is not None:
        ban_ttl = _get_ban_table_ttl_seconds()
        ban_remaining = _normalize_remaining_seconds(ban_remaining_raw, ban_ttl)
        served = max(ban_ttl - ban_remaining, 0)

        ban_start = int(time.time() - served)
        since_epoch = max(0, ban_start - BAN_DELTA_SECONDS)
        until_epoch = max(0, ban_start + BAN_DELTA_SECONDS)

        # journald (может быть относительно тяжёлым)
        if DEBUG_ON_EMPTY:
            j_lines, dbg = _journal_window_for_ip(
                ip=ip,
                since_epoch=since_epoch,
                until_epoch=until_epoch,
                limit=limit,
                collect_debug=True,
            )
        else:
            j_lines = _journal_window_for_ip(
                ip=ip,
                since_epoch=since_epoch,
                until_epoch=until_epoch,
                limit=limit,
                collect_debug=False,
            )
            dbg = None

        if j_lines:
            if LOGS_IP_CACHE_SECONDS > 0:
                with _LOGS_IP_CACHE_LOCK:
                    _LOGS_IP_CACHE[(ip, int(limit))] = (time.time() + LOGS_IP_CACHE_SECONDS, j_lines)
            return j_lines

        if DEBUG_ON_EMPTY and dbg:
            def _dbg_block() -> list[str]:
                block = [
                    "[DEBUG] No journal matches for banned IP",
                    f"ip={ip}",
                    f"ban_remaining_raw={ban_remaining_raw}",
                    f"ban_ttl={ban_ttl} ({_fmt_sec(ban_ttl)})",
                    f"ban_remaining_norm={ban_remaining} ({_fmt_sec(ban_remaining)})",
                    f"served={served} ({_fmt_sec(served)})",
                    f"ban_start_epoch={ban_start}",
                    f"window_since_epoch={since_epoch}",
                    f"window_until_epoch={until_epoch}",
                    f"sources_tried={', '.join(s['source'] for s in dbg.get('sources', []))}",
                ]
                for s in dbg.get("sources", []):
                    block.append(
                        "  - {source}: found_total={found_total} returned={returned} dur={duration_s}s "
                        "rc={returncode} used_grep={used_grep} args={args} stderr={stderr}".format(
                            source=s.get("source"),
                            found_total=s.get("found_total"),
                            returned=s.get("returned"),
                            duration_s=s.get("duration_s"),
                            returncode=s.get("returncode"),
                            used_grep=s.get("used_grep"),
                            args=" ".join(s.get("args") or []),
                            stderr=(s.get("stderr") or ""),
                        )
                    )
                return block

            return _dbg_block()

        return []

    # 3) не в бане → но по файлу тоже ничего не нашли
    if DEBUG_ON_EMPTY:
        try:
            exists = os.path.exists(LOG_FILE)
            size = os.path.getsize(LOG_FILE) if exists else 0
            mtime = datetime.fromtimestamp(os.path.getmtime(LOG_FILE)).strftime(
                "%Y-%m-%d %H:%M:%S") if exists else "n/a"
        except Exception:  # pylint: disable=broad-except
            exists, size, mtime = False, 0, "n/a"

        return [
            "[DEBUG] No file matches for non-banned IP",
            f"ip={ip}",
            f"log_file={LOG_FILE}",
            f"exists={exists} size={size}B mtime_local={mtime}",
            f"limit={limit}",
        ]

    return []


_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def logs_attackers() -> dict:
    """
    Агрегация для «Аналитика угроз»:
    - топ IP по HTTP 400
    - топ IP по HTTP 451 (гео-блокировка)
    Логика поиска кодов такая же, как у вас была в приложении: ищем подстроки ' 400 ' и ' 451 '.
    """
    if not os.path.exists(LOG_FILE):
        return {
            "error": "Файл логов не найден",
            "diagnostic": {"log_path": LOG_FILE},
        }

    diag = {
        "source": "file",
        "log_path": LOG_FILE,
        "total_lines": 0,
        "lines_with_400": 0,
        "lines_with_451": 0,
        "ip_matches": 0,
    }

    a400 = defaultdict(int)
    a451 = defaultdict(int)

    # читаем потоково, чтобы не грузить память
    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            diag["total_lines"] += 1

            has400 = " 400 " in ln
            has451 = " 451 " in ln

            if has400:
                diag["lines_with_400"] += 1
            if has451:
                diag["lines_with_451"] += 1

            if not (has400 or has451):
                continue

            m = _IP_RE.search(ln)
            if not m:
                continue

            ip = m.group(1)
            diag["ip_matches"] += 1
            if has400:
                a400[ip] += 1
            if has451:
                a451[ip] += 1

    def _top(src: dict, n: int = 10):
        return sorted(src.items(), key=lambda x: x[1], reverse=True)[:n]

    return {
        "code_400": [{"ip": ip, "count": cnt} for ip, cnt in _top(a400)],
        "code_451": [{"ip": ip, "count": cnt} for ip, cnt in _top(a451)],
        "diagnostic": diag,
    }

# ───── обработка команд по сокету ─────


def cmd_reload() -> tuple[bool, str]:
    """
    Выполнить systemctl reload haproxy.
    """
    try:
        LOG.info("Executing reload command: %s", SYSTEMCTL_CMD)
        proc = subprocess.run(
            SYSTEMCTL_CMD.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode == 0:
            msg = (proc.stdout or "reloaded").strip()
            return True, msg
        err = (proc.stderr or f"systemctl exit code {proc.returncode}").strip()
        return False, err
    except Exception as e:
        return False, f"reload exception: {e!r}"


def haproxy_check_config_from_b64(b64: str) -> tuple[int, str, str]:
    """
    Принимает base64(cfg_text), пишет во временный файл
    и запускает `haproxy -c -f <tmpfile>` на хосте.

    Возвращает (rc, stdout, stderr).
    """
    raw = base64.b64decode(b64, validate=True)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("HAProxy configuration exceeds the allowed size")
    _enforce_config_policy(raw)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, prefix="hapadm-check-", suffix=".cfg"
        ) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name

        proc = subprocess.run(
            ["/usr/sbin/haproxy", "-c", "-f", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _enforce_config_policy(raw: bytes) -> None:
    """Keep the config editor from turning HAProxy into a root command runner."""
    text = raw.decode("utf-8")
    forbidden = {
        "program", "pidfile", "module-load", "setuid", "setgid",
        "external-check",
    }
    allowed_global = {
        "log", "nbthread", "maxconn", "chroot", "stats", "user", "group",
        "daemon", "ca-base", "crt-base", "ssl-default-bind-ciphersuites",
        "ssl-default-bind-ciphers", "ssl-default-bind-options", "localpeer",
        "lua-prepend-path", "lua-load",
    }
    in_global = False
    saw_global = False
    required = {"user": False, "group": False, "chroot": False}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(None, 1)[0].lower()
        if token in forbidden:
            raise ValueError(f"HAProxy directive '{token}' is not allowed")
        if token == "global":
            if saw_global:
                raise ValueError("multiple global sections are not allowed")
            in_global = True
            saw_global = True
            continue
        if in_global and not raw_line[:1].isspace():
            in_global = False
        if not in_global:
            continue

        if token.startswith("tune."):
            pass
        elif token not in allowed_global:
            raise ValueError(f"global directive '{token}' is not allowed")

        if token == "user":
            required["user"] = line == "user haproxy"
        elif token == "group":
            required["group"] = line == "group haproxy"
        elif token == "chroot":
            required["chroot"] = line == "chroot /var/lib/haproxy"
        elif token == "stats" and line.startswith("stats socket "):
            socket_path = line.split()[2]
            if not socket_path.startswith("/run/haproxy/"):
                raise ValueError("HAProxy stats socket must stay under /run/haproxy")
        elif token == "lua-load":
            lua_path = line.split(None, 1)[1].strip()
            if lua_path != "/etc/haproxy/lua/auth-request.lua":
                raise ValueError("unapproved HAProxy Lua entry point")
        elif token == "lua-prepend-path":
            lua_path = line.split(None, 1)[1].strip()
            if not lua_path.startswith("/etc/haproxy/lua/"):
                raise ValueError("HAProxy Lua search path must stay under /etc/haproxy/lua")

    if not saw_global or not all(required.values()):
        raise ValueError("required HAProxy privilege-drop directives are missing")


def haproxy_write_config_from_b64(b64: str) -> None:
    """Validate and atomically replace the live HAProxy configuration."""
    raw = base64.b64decode(b64, validate=True)
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("invalid HAProxy configuration size")
    _enforce_config_policy(raw)

    cfg_path = Path(HAPROXY_CFG_PATH)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=cfg_path.parent,
            prefix=".haproxy.cfg.",
        ) as tmp:
            tmp.write(raw)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name

        proc = subprocess.run(
            ["/usr/sbin/haproxy", "-c", "-f", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "validation failed").strip()
            raise ValueError(f"HAProxy rejected the configuration: {detail}")

        try:
            current = cfg_path.stat()
            os.chown(tmp_path, current.st_uid, current.st_gid)
            os.chmod(tmp_path, stat.S_IMODE(current.st_mode))
        except FileNotFoundError:
            os.chmod(tmp_path, 0o640)

        os.replace(tmp_path, cfg_path)
        tmp_path = None
        dir_fd = os.open(cfg_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


_CONTROL_PLANE_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_CONTROL_PLANE_ACL_RE = re.compile(
    r"^\s*acl\s+(host_admin|host_authelia)\s+"
    r"hdr\(host\)\s+-i\s+(.+?)\s*$",
    re.MULTILINE,
)
_CONTROL_PLANE_PATHS = {
    "admin": "/api/control-plane-health",
    "authelia": "/api/health",
}


def _decode_control_plane_checks(checks_b64: str) -> list[dict[str, str]]:
    """Decode and strictly validate guarded-apply HTTPS checks."""
    raw = base64.b64decode(checks_b64, validate=True)
    if not raw or len(raw) > 16 * 1024:
        raise ValueError("invalid control-plane check payload size")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, list) or not 1 <= len(payload) <= 2:
        raise ValueError("one or two control-plane checks are required")

    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("invalid control-plane check")
        service = str(item.get("service") or "").strip().lower()
        domain = str(item.get("domain") or "").strip().lower().rstrip(".")
        if service not in _CONTROL_PLANE_PATHS or service in seen:
            raise ValueError("invalid or duplicate control-plane service")
        if not _CONTROL_PLANE_DOMAIN_RE.fullmatch(domain):
            raise ValueError(f"invalid control-plane domain for {service}")
        seen.add(service)
        checks.append({
            "service": service,
            "domain": domain,
            "path": _CONTROL_PLANE_PATHS[service],
        })

    if "admin" not in seen:
        raise ValueError("the HAProxy Admin check is required")
    return checks


def _control_plane_domains_from_config(raw: bytes) -> dict[str, tuple[str, ...]]:
    """Extract protected host ACLs without importing the web application."""
    text = raw.decode("utf-8")
    domains: dict[str, tuple[str, ...]] = {}
    for match in _CONTROL_PLANE_ACL_RE.finditer(text):
        values = tuple(sorted({
            value.strip().lower().rstrip(".")
            for value in match.group(2).split()
            if value.strip()
        }))
        if values:
            domains[match.group(1)] = values
    return domains


def _validate_guarded_control_plane_transition(
    previous: bytes,
    candidate: bytes,
    checks: list[dict[str, str]],
) -> None:
    """Bind checks to unchanged protected ACLs before touching the live file."""
    active_domains = _control_plane_domains_from_config(previous)
    candidate_domains = _control_plane_domains_from_config(candidate)
    if not active_domains.get("host_admin"):
        raise ValueError("the current config has no protected HAProxy Admin domain")
    if active_domains != candidate_domains:
        raise ValueError(
            "protected HAProxy Admin/Authelia domains changed; "
            "use the domain migration workflow"
        )

    expected: dict[str, str] = {}
    mapping = {"host_admin": "admin", "host_authelia": "authelia"}
    for acl_name, service in mapping.items():
        domains = candidate_domains.get(acl_name) or ()
        if len(domains) > 1:
            raise ValueError(f"multiple protected domains found for {service}")
        if domains:
            expected[service] = domains[0]
    supplied = {check["service"]: check["domain"] for check in checks}
    if supplied != expected:
        raise ValueError("control-plane checks do not match the protected domains")


def _create_guarded_config_backup(raw: bytes, candidate_sha256: str) -> str:
    """Persist the known-good config before replacing it."""
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("the current HAProxy configuration cannot be backed up")
    CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = CONFIG_BACKUP_DIR / (
        f"haproxy.cfg.pre-apply.{timestamp}.{candidate_sha256[:12]}"
    )
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=CONFIG_BACKUP_DIR,
            prefix=".haproxy.cfg.pre-apply.",
        ) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_path = handle.name
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, backup)
        tmp_path = None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass

    backups = sorted(
        CONFIG_BACKUP_DIR.glob("haproxy.cfg.pre-apply.*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old_backup in backups[max(1, GUARDED_CONFIG_BACKUPS):]:
        try:
            old_backup.unlink()
        except OSError:
            LOG.warning("Could not remove old HAProxy config backup %s", old_backup)
    return str(backup)


def _probe_control_plane_service(check: dict[str, str]) -> dict[str, object]:
    """Reach a critical service through HAProxy on loopback with real SNI/Host."""
    service = check["service"]
    domain = check["domain"]
    path = check["path"]
    result: dict[str, object] = {
        "service": service,
        "domain": domain,
        "path": path,
        "ok": False,
        "status": None,
        "failure": "",
    }
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(
            ("127.0.0.1", 443), timeout=CONTROL_PLANE_CHECK_TIMEOUT
        ) as raw_socket:
            raw_socket.settimeout(CONTROL_PLANE_CHECK_TIMEOUT)
            with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    "User-Agent: easy-ha-proxy-config-guard/1\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                )
                tls_socket.sendall(request.encode("ascii"))
                response = bytearray()
                while b"\r\n" not in response and len(response) < 8192:
                    chunk = tls_socket.recv(2048)
                    if not chunk:
                        break
                    response.extend(chunk)

        status_line = bytes(response).split(b"\r\n", 1)[0].decode(
            "ascii", "replace"
        )
        match = re.fullmatch(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?", status_line)
        if not match:
            raise RuntimeError(f"invalid HTTP response: {status_line or 'empty'}")
        status = int(match.group(1))
        result["status"] = status
        result["ok"] = status == 200
        if status != 200:
            result["failure"] = f"expected HTTP 200, received HTTP {status}"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = str(exc)
    return result


def _run_control_plane_checks(
    checks: list[dict[str, str]],
) -> list[dict[str, object]]:
    """Retry the complete critical-service set while HAProxy settles."""
    latest: list[dict[str, object]] = []
    attempts = max(1, min(CONTROL_PLANE_CHECK_ATTEMPTS, 30))
    for attempt in range(1, attempts + 1):
        latest = [_probe_control_plane_service(check) for check in checks]
        for result in latest:
            result["attempt"] = attempt
        if all(bool(result.get("ok")) for result in latest):
            return latest
        if attempt < attempts:
            time.sleep(max(0.1, CONTROL_PLANE_CHECK_INTERVAL))
    return latest


def _restore_guarded_config(
    previous_b64: str,
    checks: list[dict[str, str]],
) -> dict[str, object]:
    """Restore, reload, and verify the last known-good HAProxy config."""
    result: dict[str, object] = {
        "ok": False,
        "reload_ok": False,
        "reload_output": "",
        "checks": [],
        "failure": "",
    }
    try:
        haproxy_write_config_from_b64(previous_b64)
        reload_ok, reload_output = cmd_reload()
        result["reload_ok"] = reload_ok
        result["reload_output"] = reload_output
        if not reload_ok:
            result["failure"] = f"rollback reload failed: {reload_output}"
            return result
        rollback_checks = _run_control_plane_checks(checks)
        result["checks"] = rollback_checks
        result["ok"] = all(bool(item.get("ok")) for item in rollback_checks)
        if not result["ok"]:
            result["failure"] = "critical services did not recover after rollback"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = f"rollback failed: {exc}"
    return result


def _haproxy_apply_config_guarded_locked(
    cfg_b64: str,
    checks_b64: str,
) -> dict[str, object]:
    """Apply a candidate config and automatically restore the previous one on failure."""
    checks = _decode_control_plane_checks(checks_b64)
    candidate = base64.b64decode(cfg_b64, validate=True)
    if not candidate or len(candidate) > MAX_CONFIG_BYTES:
        raise ValueError("invalid HAProxy configuration size")

    current_path = Path(HAPROXY_CFG_PATH)
    previous = current_path.read_bytes()
    if not previous or len(previous) > MAX_CONFIG_BYTES:
        raise ValueError("a valid current HAProxy configuration is required for rollback")
    _validate_guarded_control_plane_transition(previous, candidate, checks)

    candidate_sha256 = hashlib.sha256(candidate).hexdigest()
    previous_sha256 = hashlib.sha256(previous).hexdigest()
    backup_path = _create_guarded_config_backup(previous, candidate_sha256)
    previous_b64 = base64.b64encode(previous).decode("ascii")
    result: dict[str, object] = {
        "ok": False,
        "applied": False,
        "rolled_back": False,
        "rollback_ok": None,
        "candidate_sha256": candidate_sha256,
        "previous_sha256": previous_sha256,
        "backup_path": backup_path,
        "checks": [],
        "rollback": None,
        "reload_output": "",
        "failure": "",
    }

    try:
        haproxy_write_config_from_b64(cfg_b64)
        reload_ok, reload_output = cmd_reload()
        result["reload_output"] = reload_output
        if not reload_ok:
            result["failure"] = f"HAProxy reload failed: {reload_output}"
        else:
            check_results = _run_control_plane_checks(checks)
            result["checks"] = check_results
            if all(bool(item.get("ok")) for item in check_results):
                result["ok"] = True
                result["applied"] = True
                return result
            failed = [
                f"{item.get('service')} ({item.get('domain')}): {item.get('failure')}"
                for item in check_results
                if not item.get("ok")
            ]
            result["failure"] = "; ".join(failed) or "critical service check failed"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = f"guarded apply failed: {exc}"

    rollback = _restore_guarded_config(previous_b64, checks)
    result["rolled_back"] = True
    result["rollback"] = rollback
    result["rollback_ok"] = bool(rollback.get("ok"))
    return result


def haproxy_apply_config_guarded(cfg_b64: str, checks_b64: str) -> dict[str, object]:
    """Serialize guarded config changes so backups and rollbacks cannot race."""
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration apply is running")
    try:
        _ensure_no_active_config_transaction_locked()
        return _haproxy_apply_config_guarded_locked(cfg_b64, checks_b64)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _transaction_state_path() -> Path:
    return CONFIG_TRANSACTION_DIR / CONFIG_TRANSACTION_STATE


def _ensure_transaction_dir() -> Path:
    """Create the root-owned transaction directory without accepting symlinks."""
    CONFIG_TRANSACTION_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory_stat = CONFIG_TRANSACTION_DIR.lstat()
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RuntimeError("HAProxy config transaction path is not a safe directory")
    os.chmod(CONFIG_TRANSACTION_DIR, 0o700)
    return CONFIG_TRANSACTION_DIR


def _persist_config_transaction(state: dict[str, object]) -> None:
    """Atomically persist private transaction state for restart recovery."""
    directory = _ensure_transaction_dir()
    raw = json.dumps(
        state,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not raw or len(raw) > MAX_TRANSACTION_STATE_BYTES:
        raise RuntimeError("HAProxy config transaction state exceeds the size limit")

    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=directory,
            prefix=".transaction.",
        ) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = handle.name
        os.chmod(temporary, 0o600)
        os.replace(temporary, _transaction_state_path())
        temporary = None
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _load_config_transaction() -> dict[str, object] | None:
    path = _transaction_state_path()
    try:
        state_stat = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
        raise RuntimeError("HAProxy config transaction state is not a regular file")
    if state_stat.st_size <= 0 or state_stat.st_size > MAX_TRANSACTION_STATE_BYTES:
        raise RuntimeError("HAProxy config transaction state has an invalid size")
    raw = path.read_bytes()
    state = json.loads(raw.decode("utf-8"))
    if not isinstance(state, dict) or state.get("version") != CONFIG_TRANSACTION_VERSION:
        raise RuntimeError("HAProxy config transaction state has an invalid format")
    transaction_id = state.get("transaction_id")
    if not isinstance(transaction_id, str) or not transaction_id:
        raise RuntimeError("HAProxy config transaction state has no transaction id")
    return state


def _ensure_no_active_config_transaction_locked() -> None:
    """Keep legacy writes from bypassing a confirmable transaction."""
    state = _load_config_transaction()
    if state is None:
        return
    if state.get("state") == "pending_confirmation":
        deadline = float(state.get("deadline_epoch") or 0)
        if deadline and time.time() >= deadline:
            _rollback_config_transaction_locked(
                state, "confirmation timeout expired before another config write"
            )
            state = _load_config_transaction()
    if state is not None and state.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES:
        raise RuntimeError(
            "another HAProxy config transaction is still active"
        )


def haproxy_write_config_serialized(cfg_b64: str) -> None:
    """Preserve legacy write-config while respecting pending transactions."""
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration operation is running")
    try:
        _ensure_no_active_config_transaction_locked()
        haproxy_write_config_from_b64(cfg_b64)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _decode_config_transaction_sources(
    sources_b64: str,
) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, object] | None]:
    """Decode the fixed-name YAML mappings and optional GeoIP selection."""
    raw = base64.b64decode(sources_b64, validate=True)
    if not raw or len(raw) > MAX_TRANSACTION_SOURCES_PAYLOAD_BYTES:
        raise ValueError("invalid config source payload size")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not {"candidate", "previous"}.issubset(payload):
        raise ValueError("config sources must contain candidate and previous mappings")
    if not set(payload).issubset({"candidate", "previous", "geoip_selection"}):
        raise ValueError("config sources contain unsupported transaction fields")

    decoded: dict[str, dict[str, bytes]] = {}
    for group in ("candidate", "previous"):
        mapping = payload.get(group)
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError(f"config source {group} mapping is empty")
        if not set(mapping).issubset(CONFIG_SOURCE_FILENAMES):
            raise ValueError("config source payload contains an unsupported filename")
        group_decoded: dict[str, bytes] = {}
        for filename, encoded in mapping.items():
            if not isinstance(encoded, str):
                raise ValueError(f"invalid encoded content for {filename}")
            content = base64.b64decode(encoded, validate=True)
            if len(content) > MAX_TRANSACTION_SOURCE_FILE_BYTES:
                raise ValueError(f"config source {filename} exceeds the size limit")
            if b"\x00" in content:
                raise ValueError(f"config source {filename} contains a NUL byte")
            content.decode("utf-8")
            group_decoded[filename] = content
        decoded[group] = group_decoded

    if set(decoded["candidate"]) != set(decoded["previous"]):
        raise ValueError("candidate and previous config source filenames differ")

    geoip_selection_raw = payload.get("geoip_selection")
    geoip_selection: dict[str, object] | None = None
    if geoip_selection_raw is not None:
        if not isinstance(geoip_selection_raw, dict) or set(geoip_selection_raw) != {
            "version",
            "countries",
            "access_filter_enabled",
        }:
            raise ValueError("config GeoIP selection has an invalid format")
        countries_raw = geoip_selection_raw.get("countries")
        enabled = geoip_selection_raw.get("access_filter_enabled")
        if (
            geoip_selection_raw.get("version") != 1
            or not isinstance(countries_raw, list)
            or not isinstance(enabled, bool)
            or len(countries_raw) > GEOIP_MAX_COUNTRIES
        ):
            raise ValueError("config GeoIP selection has an invalid format")
        countries: list[str] = []
        for code in countries_raw:
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z]{2}", code):
                raise ValueError("config GeoIP selection contains an invalid country code")
            countries.append(code)
        if countries != sorted(set(countries)):
            raise ValueError("config GeoIP selection countries are not canonical")
        if enabled and not countries:
            raise ValueError(
                "GeoIP filtering cannot be enabled without selected countries"
            )
        geoip_selection = {
            "version": 1,
            "countries": countries,
            "access_filter_enabled": enabled,
        }
    return decoded["candidate"], decoded["previous"], geoip_selection


def _open_config_source_directory() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(CONFIG_SOURCE_DIR, flags)
    except OSError as exc:
        raise RuntimeError("HAProxy config source directory is unavailable or unsafe") from exc


def _read_config_source_at(directory_fd: int, filename: str) -> tuple[bytes, os.stat_result]:
    if filename not in CONFIG_SOURCE_FILENAMES:
        raise ValueError("unsupported config source filename")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RuntimeError(f"config source {filename} is unavailable or unsafe") from exc
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise RuntimeError(f"config source {filename} is not a regular file")
        if source_stat.st_size > MAX_TRANSACTION_SOURCE_FILE_BYTES:
            raise RuntimeError(f"config source {filename} exceeds the size limit")
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_TRANSACTION_SOURCE_FILE_BYTES:
                raise RuntimeError(f"config source {filename} exceeds the size limit")
            chunks.append(chunk)
        return b"".join(chunks), source_stat
    finally:
        os.close(source_fd)


def _verify_candidate_config_sources(candidate: dict[str, bytes]) -> None:
    directory_fd = _open_config_source_directory()
    try:
        for filename, expected in candidate.items():
            current, _ = _read_config_source_at(directory_fd, filename)
            if not secrets.compare_digest(current, expected):
                raise ValueError(
                    f"live config source {filename} changed before the transaction"
                )
    finally:
        os.close(directory_fd)


def _verify_live_transaction_candidate(state: dict[str, object]) -> None:
    """Verify that HAProxy and YAML still match the pending candidate."""
    expected_config_sha256 = str(state.get("candidate_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_config_sha256):
        raise RuntimeError("persisted candidate config hash is invalid")
    current_config = Path(HAPROXY_CFG_PATH).read_bytes()
    if not current_config or len(current_config) > MAX_CONFIG_BYTES:
        raise RuntimeError("live HAProxy configuration has an invalid size")
    current_config_sha256 = hashlib.sha256(current_config).hexdigest()
    if not secrets.compare_digest(current_config_sha256, expected_config_sha256):
        raise RuntimeError("live HAProxy configuration changed before confirmation")

    expected_sources = state.get("candidate_source_sha256")
    if (
        not isinstance(expected_sources, dict)
        or not expected_sources
        or not set(expected_sources).issubset(CONFIG_SOURCE_FILENAMES)
    ):
        raise RuntimeError("persisted candidate config source hashes are invalid")
    directory_fd = _open_config_source_directory()
    try:
        for filename, expected_hash_raw in expected_sources.items():
            expected_hash = str(expected_hash_raw)
            if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise RuntimeError(
                    f"persisted candidate hash for {filename} is invalid"
                )
            current_source, _ = _read_config_source_at(directory_fd, filename)
            current_hash = hashlib.sha256(current_source).hexdigest()
            if not secrets.compare_digest(current_hash, expected_hash):
                raise RuntimeError(
                    f"live config source {filename} changed before confirmation"
                )
    finally:
        os.close(directory_fd)
    _verify_transaction_geoip_candidate(state)


def _restore_config_sources(previous: dict[str, bytes]) -> list[str]:
    """Atomically restore allow-listed YAML files using directory-relative I/O."""
    directory_fd = _open_config_source_directory()
    restored: list[str] = []
    try:
        directory_stat = os.fstat(directory_fd)
        for filename, content in previous.items():
            if filename not in CONFIG_SOURCE_FILENAMES:
                raise ValueError("unsupported rollback config source filename")
            try:
                _, target_stat = _read_config_source_at(directory_fd, filename)
                owner = target_stat.st_uid
                group = target_stat.st_gid
                mode = stat.S_IMODE(target_stat.st_mode)
            except RuntimeError:
                owner = directory_stat.st_uid
                group = directory_stat.st_gid
                mode = 0o644

            temporary = f".{filename}.transaction.{secrets.token_hex(8)}"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            temporary_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
            try:
                view = memoryview(content)
                while view:
                    written = os.write(temporary_fd, view)
                    view = view[written:]
                os.fsync(temporary_fd)
                os.fchmod(temporary_fd, mode)
                try:
                    os.fchown(temporary_fd, owner, group)
                except PermissionError:
                    if os.geteuid() == 0:
                        raise
            finally:
                os.close(temporary_fd)
            try:
                os.replace(
                    temporary,
                    filename,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
            except Exception:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                raise
            os.fsync(directory_fd)
            restored.append(filename)
    finally:
        os.close(directory_fd)
    return restored


def _canonical_config_geoip_selection(selection: dict[str, object]) -> bytes:
    return (
        json.dumps(selection, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _open_geoip_directory() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(GEOIP_DIRECTORY, flags)
    except OSError as exc:
        raise RuntimeError("GeoIP runtime directory is unavailable or unsafe") from exc


def _write_geoip_selection_raw(raw: bytes) -> None:
    """Atomically replace root-managed selection.json without following links."""
    if not raw or len(raw) > GEOIP_MAX_SELECTION_BYTES or b"\x00" in raw:
        raise ValueError("invalid GeoIP selection snapshot")
    raw.decode("utf-8")
    directory_fd = _open_geoip_directory()
    temporary = f".selection.json.transaction.{secrets.token_hex(8)}"
    temporary_created = False
    try:
        directory_stat = os.fstat(directory_fd)
        try:
            target_stat = os.stat(
                GEOIP_SELECTION_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
                raise RuntimeError("GeoIP selection is not a regular file")
            owner = target_stat.st_uid
            group = target_stat.st_gid
            mode = stat.S_IMODE(target_stat.st_mode)
        except FileNotFoundError:
            owner = directory_stat.st_uid
            group = directory_stat.st_gid
            mode = 0o644

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temporary_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        temporary_created = True
        try:
            view = memoryview(raw)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
            os.fsync(temporary_fd)
            os.fchmod(temporary_fd, mode)
            try:
                os.fchown(temporary_fd, owner, group)
            except PermissionError:
                if os.geteuid() == 0:
                    raise
        finally:
            os.close(temporary_fd)
        os.replace(
            temporary,
            GEOIP_SELECTION_PATH.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_created = False
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _remove_geoip_selection() -> None:
    directory_fd = _open_geoip_directory()
    try:
        try:
            target_stat = os.stat(
                GEOIP_SELECTION_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise RuntimeError("GeoIP selection is not a regular file")
        os.unlink(GEOIP_SELECTION_PATH.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _active_geoip_release_name() -> str:
    release = _geoip_current_release()
    return release.name if release is not None else ""


def _switch_geoip_release(release_name: str) -> None:
    """Restore the exact active release captured before the transaction."""
    if release_name:
        if (
            release_name in {".", ".."}
            or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,254}", release_name)
        ):
            raise RuntimeError("persisted GeoIP release name is invalid")
        try:
            releases_stat = GEOIP_RELEASES_PATH.lstat()
        except OSError as exc:
            raise RuntimeError("GeoIP releases directory is unavailable") from exc
        if stat.S_ISLNK(releases_stat.st_mode) or not stat.S_ISDIR(
            releases_stat.st_mode
        ):
            raise RuntimeError("GeoIP releases directory is unsafe")
        release = GEOIP_RELEASES_PATH / release_name
        try:
            release_stat = release.lstat()
            resolved = release.resolve(strict=True)
            resolved.relative_to(GEOIP_RELEASES_PATH.resolve(strict=True))
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError("persisted GeoIP release is unavailable") from exc
        if stat.S_ISLNK(release_stat.st_mode) or not stat.S_ISDIR(release_stat.st_mode):
            raise RuntimeError("persisted GeoIP release is unsafe")

    directory_fd = _open_geoip_directory()
    temporary = f".current.transaction.{secrets.token_hex(8)}"
    temporary_created = False
    try:
        try:
            current_stat = os.stat("current", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current_stat = None
        if current_stat is not None and not stat.S_ISLNK(current_stat.st_mode):
            raise RuntimeError("GeoIP current release pointer is not a symlink")
        if not release_name:
            if current_stat is not None:
                os.unlink("current", dir_fd=directory_fd)
                os.fsync(directory_fd)
            return
        os.symlink(f"releases/{release_name}", temporary, dir_fd=directory_fd)
        temporary_created = True
        os.replace(
            temporary,
            "current",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_created = False
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _geoip_runtime_fingerprint(
    expected_selection: dict[str, object],
) -> dict[str, str]:
    selection, selection_raw = _geoip_selection()
    if (
        selection.get("countries") != expected_selection.get("countries")
        or selection.get("access_filter_enabled")
        is not expected_selection.get("access_filter_enabled")
    ):
        raise RuntimeError("GeoIP runtime selection does not match the candidate")
    release = _geoip_current_release()
    if release is None:
        raise RuntimeError("GeoIP runtime has no active release")
    release_state = _read_geoip_state(release)
    database_path = release / "dbip-country-lite.mmdb"
    allowed_path = release / "allowed.geo"
    if (
        release_state.get("release_format_version") != 1
        or release_state.get("countries") != expected_selection.get("countries")
        or release_state.get("access_filter_enabled")
        is not expected_selection.get("access_filter_enabled")
        or not _sha256_matches(database_path, release_state.get("database_sha256"))
        or not _sha256_matches(allowed_path, release_state.get("allowed_sha256"))
    ):
        raise RuntimeError("GeoIP active release does not match the candidate")
    if expected_selection.get("access_filter_enabled"):
        try:
            if allowed_path.stat().st_size <= 0:
                raise RuntimeError("GeoIP candidate ACL is empty")
        except OSError as exc:
            raise RuntimeError("GeoIP candidate ACL is unavailable") from exc
    return {
        "selection_sha256": hashlib.sha256(selection_raw).hexdigest(),
        "release": release.name,
        "database_sha256": str(release_state.get("database_sha256") or "").lower(),
        "allowed_sha256": str(release_state.get("allowed_sha256") or "").lower(),
    }


def _verify_transaction_geoip_candidate(state: dict[str, object]) -> None:
    geoip = state.get("geoip")
    if geoip is None:
        return
    if not isinstance(geoip, dict):
        raise RuntimeError("persisted GeoIP transaction data is invalid")
    selection = geoip.get("candidate_selection")
    expected = geoip.get("candidate_fingerprint")
    if not isinstance(selection, dict) or not isinstance(expected, dict):
        raise RuntimeError("persisted GeoIP candidate data is incomplete")
    current = _geoip_runtime_fingerprint(selection)
    for key in ("selection_sha256", "release", "database_sha256", "allowed_sha256"):
        expected_value = str(expected.get(key) or "")
        current_value = str(current.get(key) or "")
        if not expected_value or not secrets.compare_digest(expected_value, current_value):
            raise RuntimeError("GeoIP runtime changed before confirmation")


def _restore_transaction_geoip(state: dict[str, object]) -> None:
    geoip = state.get("geoip")
    if geoip is None:
        return
    if not isinstance(geoip, dict):
        raise RuntimeError("persisted GeoIP rollback data is invalid")
    previous_present = geoip.get("previous_selection_present")
    previous_encoded = geoip.get("previous_selection_b64")
    previous_release = geoip.get("previous_release")
    if (
        not isinstance(previous_present, bool)
        or not isinstance(previous_encoded, str)
        or not isinstance(previous_release, str)
    ):
        raise RuntimeError("persisted GeoIP rollback data is incomplete")
    previous_raw = base64.b64decode(previous_encoded, validate=True)
    if previous_present:
        _write_geoip_selection_raw(previous_raw)
    else:
        _remove_geoip_selection()
    _switch_geoip_release(previous_release)

    selection_now, selection_raw_now = _geoip_selection()
    del selection_now
    if previous_present:
        if not secrets.compare_digest(selection_raw_now, previous_raw):
            raise RuntimeError("GeoIP selection rollback could not be verified")
    elif selection_raw_now:
        raise RuntimeError("GeoIP selection rollback could not be verified")
    if _active_geoip_release_name() != previous_release:
        raise RuntimeError("GeoIP release rollback could not be verified")


def _safe_check_status(item: object) -> dict[str, object]:
    if not isinstance(item, dict):
        return {}
    safe: dict[str, object] = {}
    for key in ("service", "domain", "path", "ok", "status", "attempt"):
        value = item.get(key)
        if isinstance(value, (str, int, bool)) or value is None:
            safe[key] = value
    failure = item.get("failure")
    if failure:
        safe["failure"] = str(failure)[:2000]
    return safe


def _sanitized_config_transaction_status(
    state: dict[str, object] | None,
) -> dict[str, object]:
    if state is None:
        return {"ok": True, "state": "none", "pending": False}
    status_name = str(state.get("state") or "unknown")
    deadline = float(state.get("deadline_epoch") or 0)
    remaining = max(0, int(deadline - time.time() + 0.999)) if deadline else 0
    confirm_by = (
        datetime.fromtimestamp(deadline, timezone.utc).isoformat()
        if deadline
        else None
    )
    result: dict[str, object] = {
        "ok": status_name in {"pending_confirmation", "confirmed", "rolled_back"},
        "state": status_name,
        "pending": status_name == "pending_confirmation",
        "transaction_id": str(state.get("transaction_id") or ""),
        "candidate_sha256": str(state.get("candidate_sha256") or ""),
        "previous_sha256": str(state.get("previous_sha256") or ""),
        "created_at": str(state.get("created_at") or ""),
        "deadline_epoch": deadline or None,
        "deadline": confirm_by,
        "confirm_by": confirm_by,
        "remaining_seconds": remaining,
        "source_files": sorted(
            str(name) for name in (state.get("candidate_source_sha256") or {})
        ),
        "checks": [
            _safe_check_status(item) for item in (state.get("checks") or [])
        ],
        "failure": str(state.get("failure") or "")[:4000],
        "rollback_reason": str(state.get("rollback_reason") or "")[:500],
    }
    rollback = state.get("rollback")
    if isinstance(rollback, dict):
        result["rollback"] = {
            "ok": bool(rollback.get("ok")),
            "reload_ok": bool(rollback.get("reload_ok")),
            "sources_ok": bool(rollback.get("sources_ok")),
            "geoip_ok": bool(rollback.get("geoip_ok", True)),
            "restored_sources": [
                str(name) for name in (rollback.get("restored_sources") or [])
                if str(name) in CONFIG_SOURCE_FILENAMES
            ],
            "failure": str(rollback.get("failure") or "")[:4000],
            "checks": [
                _safe_check_status(item) for item in (rollback.get("checks") or [])
            ],
        }
    return result


def _transaction_matches(state: dict[str, object], transaction_id: str) -> bool:
    expected = str(state.get("transaction_id") or "")
    return bool(expected and transaction_id and secrets.compare_digest(expected, transaction_id))


def _rollback_config_transaction_locked(
    state: dict[str, object],
    reason: str,
) -> dict[str, object]:
    """Restore YAML and GeoIP state before reloading the previous HAProxy config."""
    state["state"] = "rolling_back"
    state["rollback_reason"] = reason
    state["failure"] = str(state.get("failure") or "")
    _persist_config_transaction(state)

    sources_ok = False
    restored_sources: list[str] = []
    source_failure = ""
    previous_sources_raw = state.get("previous_sources")
    try:
        if not isinstance(previous_sources_raw, dict):
            raise RuntimeError("persisted previous config sources are missing")
        previous_sources = {
            str(filename): base64.b64decode(str(encoded), validate=True)
            for filename, encoded in previous_sources_raw.items()
        }
        restored_sources = _restore_config_sources(previous_sources)
        sources_ok = True
    except Exception as exc:  # noqa: BLE001
        source_failure = f"config source rollback failed: {exc}"

    geoip_ok = False
    geoip_failure = ""
    try:
        _restore_transaction_geoip(state)
        geoip_ok = True
    except Exception as exc:  # noqa: BLE001
        geoip_failure = f"GeoIP rollback failed: {exc}"

    config_result: dict[str, object]
    previous_config = state.get("previous_config_b64")
    checks = state.get("control_plane_checks")
    if not isinstance(previous_config, str) or not isinstance(checks, list):
        config_result = {
            "ok": False,
            "reload_ok": False,
            "checks": [],
            "failure": "persisted rollback data is incomplete",
        }
    else:
        config_result = _restore_guarded_config(previous_config, checks)

    config_failure = str(config_result.get("failure") or "")
    failures = [
        value
        for value in (source_failure, geoip_failure, config_failure)
        if value
    ]
    rollback_ok = bool(config_result.get("ok")) and sources_ok and geoip_ok
    state["state"] = "rolled_back" if rollback_ok else "rollback_failed"
    state["rollback"] = {
        "ok": rollback_ok,
        "reload_ok": bool(config_result.get("reload_ok")),
        "sources_ok": sources_ok,
        "geoip_ok": geoip_ok,
        "restored_sources": restored_sources,
        "checks": config_result.get("checks") or [],
        "failure": "; ".join(failures),
    }
    if failures:
        state["failure"] = "; ".join(failures)
    if rollback_ok:
        state.pop("previous_config_b64", None)
        state.pop("previous_sources", None)
        state.pop("geoip", None)
    _persist_config_transaction(state)
    return _sanitized_config_transaction_status(state)


def _expire_config_transaction_locked() -> dict[str, object] | None:
    state = _load_config_transaction()
    if state is None:
        return None
    if state.get("state") == "pending_confirmation":
        deadline = float(state.get("deadline_epoch") or 0)
        if deadline and time.time() >= deadline:
            return _rollback_config_transaction_locked(state, "confirmation timeout expired")
    return _sanitized_config_transaction_status(state)


def _config_transaction_watchdog(transaction_id: str, deadline_epoch: float) -> None:
    while True:
        remaining = deadline_epoch - time.time()
        if remaining > 0:
            time.sleep(min(remaining, 30.0))
            continue
        with _GUARDED_APPLY_LOCK:
            try:
                state = _load_config_transaction()
                if (
                    state is not None
                    and _transaction_matches(state, transaction_id)
                    and state.get("state") == "pending_confirmation"
                    and time.time() >= float(state.get("deadline_epoch") or 0)
                ):
                    _rollback_config_transaction_locked(
                        state, "confirmation timeout expired"
                    )
            except Exception:  # noqa: BLE001
                LOG.exception("HAProxy config transaction watchdog failed")
        return


def _schedule_config_transaction_watchdog(
    transaction_id: str,
    deadline_epoch: float,
) -> None:
    threading.Thread(
        target=_config_transaction_watchdog,
        args=(transaction_id, deadline_epoch),
        daemon=True,
        name=f"config-guard-{transaction_id[:8]}",
    ).start()


def begin_config_transaction(
    cfg_b64: str,
    checks_b64: str,
    sources_b64: str,
    timeout_text: str,
) -> dict[str, object]:
    """Apply a candidate and leave it pending until a browser confirms it."""
    try:
        timeout_seconds = int(timeout_text, 10)
    except ValueError as exc:
        raise ValueError("invalid config transaction timeout") from exc
    if not CONFIG_TRANSACTION_MIN_TIMEOUT <= timeout_seconds <= CONFIG_TRANSACTION_MAX_TIMEOUT:
        raise ValueError("config transaction timeout is outside the allowed range")
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration operation is running")
    geoip_lock_acquired = False
    try:
        existing = _load_config_transaction()
        if existing is not None:
            if existing.get("state") == "pending_confirmation":
                deadline = float(existing.get("deadline_epoch") or 0)
                if deadline and time.time() >= deadline:
                    _rollback_config_transaction_locked(
                        existing, "confirmation timeout expired"
                    )
                    existing = _load_config_transaction()
            if existing and existing.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES:
                raise RuntimeError("another HAProxy config transaction is still active")

        checks = _decode_control_plane_checks(checks_b64)
        candidate = base64.b64decode(cfg_b64, validate=True)
        if not candidate or len(candidate) > MAX_CONFIG_BYTES:
            raise ValueError("invalid HAProxy configuration size")
        (
            candidate_sources,
            previous_sources,
            candidate_geoip_selection,
        ) = _decode_config_transaction_sources(sources_b64)
        _verify_candidate_config_sources(candidate_sources)

        previous_geoip_selection = b""
        previous_geoip_selection_present = False
        previous_geoip_release = ""
        if candidate_geoip_selection is not None:
            if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
                raise RuntimeError("another GeoIP operation is already running")
            geoip_lock_acquired = True
            service = _systemd_properties(
                GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
            )
            if service.get("ActiveState") in {"activating", "active", "reloading"}:
                raise RuntimeError("another GeoIP operation is already running")
            previous_selection_state, previous_geoip_selection = _geoip_selection()
            previous_geoip_selection_present = bool(
                previous_selection_state.get("available")
            )
            previous_geoip_release = _active_geoip_release_name()

        current_path = Path(HAPROXY_CFG_PATH)
        previous = current_path.read_bytes()
        if not previous or len(previous) > MAX_CONFIG_BYTES:
            raise ValueError("a valid current HAProxy configuration is required for rollback")
        _validate_guarded_control_plane_transition(previous, candidate, checks)

        candidate_sha256 = hashlib.sha256(candidate).hexdigest()
        previous_sha256 = hashlib.sha256(previous).hexdigest()
        transaction_id = secrets.token_urlsafe(24)
        backup_path = _create_guarded_config_backup(previous, candidate_sha256)
        state: dict[str, object] = {
            "version": CONFIG_TRANSACTION_VERSION,
            "transaction_id": transaction_id,
            "state": "prepared",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "candidate_sha256": candidate_sha256,
            "previous_sha256": previous_sha256,
            "candidate_source_sha256": {
                filename: hashlib.sha256(content).hexdigest()
                for filename, content in candidate_sources.items()
            },
            "previous_config_b64": base64.b64encode(previous).decode("ascii"),
            "previous_sources": {
                filename: base64.b64encode(content).decode("ascii")
                for filename, content in previous_sources.items()
            },
            "control_plane_checks": checks,
            "checks": [],
            "backup_path": backup_path,
            "deadline_epoch": 0,
            "failure": "",
            "rollback": None,
        }
        if candidate_geoip_selection is not None:
            candidate_selection_raw = _canonical_config_geoip_selection(
                candidate_geoip_selection
            )
            state["geoip"] = {
                "candidate_selection": candidate_geoip_selection,
                "candidate_selection_sha256": hashlib.sha256(
                    candidate_selection_raw
                ).hexdigest(),
                "candidate_fingerprint": None,
                "previous_selection_present": previous_geoip_selection_present,
                "previous_selection_b64": base64.b64encode(
                    previous_geoip_selection
                ).decode("ascii"),
                "previous_release": previous_geoip_release,
            }
        _persist_config_transaction(state)

        try:
            if candidate_geoip_selection is not None:
                _write_geoip_selection_raw(candidate_selection_raw)
                geoip_ok, geoip_output = _run_geoip_command(
                    [
                        GEOIP_UPDATE_COMMAND,
                        "--skip-reload",
                        "--config-transaction-id",
                        transaction_id,
                    ]
                )
                state["geoip_update_output"] = geoip_output
                if not geoip_ok:
                    raise RuntimeError(
                        "GeoIP candidate preparation failed: "
                        + (geoip_output or "updater failed")
                    )
                geoip_state = state.get("geoip")
                if not isinstance(geoip_state, dict):
                    raise RuntimeError("GeoIP transaction state is unavailable")
                geoip_state["candidate_fingerprint"] = _geoip_runtime_fingerprint(
                    candidate_geoip_selection
                )
                _persist_config_transaction(state)

            haproxy_write_config_from_b64(cfg_b64)
            reload_ok, reload_output = cmd_reload()
            state["reload_output"] = reload_output
            if not reload_ok:
                state["failure"] = f"HAProxy reload failed: {reload_output}"
                return _rollback_config_transaction_locked(
                    state, "candidate reload failed"
                )
            check_results = _run_control_plane_checks(checks)
            state["checks"] = check_results
            if not all(bool(item.get("ok")) for item in check_results):
                failed = [
                    f"{item.get('service')} ({item.get('domain')}): {item.get('failure')}"
                    for item in check_results
                    if not item.get("ok")
                ]
                state["failure"] = "; ".join(failed) or "critical service check failed"
                return _rollback_config_transaction_locked(
                    state, "candidate health check failed"
                )
        except Exception as exc:  # noqa: BLE001
            state["failure"] = f"guarded transaction apply failed: {exc}"
            return _rollback_config_transaction_locked(state, "candidate apply failed")

        deadline = time.time() + timeout_seconds
        state["state"] = "pending_confirmation"
        state["deadline_epoch"] = deadline
        _persist_config_transaction(state)
        _schedule_config_transaction_watchdog(transaction_id, deadline)
        return _sanitized_config_transaction_status(state)
    finally:
        if geoip_lock_acquired:
            _GEOIP_OPERATION_LOCK.release()
        _GUARDED_APPLY_LOCK.release()


def config_transaction_status(transaction_id: str = "") -> dict[str, object]:
    # GeoIP selection changes deliberately share the guarded-apply lock while
    # they rebuild/reload ACLs. Status is read-only and transaction.json is
    # replaced atomically, so never make UI polling wait behind that work.
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        state = _load_config_transaction()
        if transaction_id:
            if state is None or not _transaction_matches(state, transaction_id):
                raise ValueError("HAProxy config transaction id does not match")
        result = _sanitized_config_transaction_status(state)
        result["busy"] = True
        return result
    try:
        status_result = _expire_config_transaction_locked()
        state = _load_config_transaction()
        if transaction_id:
            if state is None or not _transaction_matches(state, transaction_id):
                raise ValueError("HAProxy config transaction id does not match")
        return status_result or _sanitized_config_transaction_status(state)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _config_transaction_busy_result(
    transaction_id: str,
    action: str,
    candidate_sha256: str = "",
) -> dict[str, object]:
    """Return a retryable conflict instead of completing after client timeout."""
    state = _load_config_transaction()
    if state is None or not _transaction_matches(state, transaction_id):
        raise ValueError("HAProxy config transaction id does not match")
    result = _sanitized_config_transaction_status(state)
    if action == "confirmation":
        expected_sha256 = str(state.get("candidate_sha256") or "")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256)
            or not secrets.compare_digest(expected_sha256, candidate_sha256)
        ):
            raise ValueError("HAProxy config transaction candidate hash does not match")
        if state.get("state") == "confirmed":
            return result
    elif action == "rollback" and state.get("state") == "rolled_back":
        return result
    state_name = str(state.get("state") or "")
    retryable_states = (
        {"prepared", "pending_confirmation"}
        if action == "confirmation"
        else {"prepared", "pending_confirmation", "rolling_back", "rollback_failed"}
    )
    retryable = state_name in retryable_states
    result.update({
        "ok": False,
        "busy": True,
        "conflict": True,
        "retryable": retryable,
        "error": (
            "Another HAProxy configuration operation is running; "
            f"retry {action} shortly"
            if retryable
            else f"HAProxy configuration transaction cannot perform {action} "
            f"while it is {state_name or 'unknown'}"
        ),
    })
    return result


def confirm_config_transaction(
    transaction_id: str,
    candidate_sha256: str,
) -> dict[str, object]:
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return _config_transaction_busy_result(
            transaction_id,
            "confirmation",
            candidate_sha256,
        )
    try:
        state = _load_config_transaction()
        if state is None or not _transaction_matches(state, transaction_id):
            raise ValueError("HAProxy config transaction id does not match")
        expected_sha256 = str(state.get("candidate_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) or not secrets.compare_digest(
            expected_sha256, candidate_sha256
        ):
            raise ValueError("HAProxy config transaction candidate hash does not match")
        if state.get("state") == "confirmed":
            return _sanitized_config_transaction_status(state)
        if state.get("state") != "pending_confirmation":
            raise RuntimeError("HAProxy config transaction is not awaiting confirmation")
        deadline = float(state.get("deadline_epoch") or 0)
        if not deadline or time.time() >= deadline:
            _rollback_config_transaction_locked(state, "confirmation timeout expired")
            raise RuntimeError("HAProxy config transaction confirmation arrived too late")
        try:
            _verify_live_transaction_candidate(state)
        except Exception as exc:  # noqa: BLE001
            state["failure"] = f"pending candidate verification failed: {exc}"
            rollback = _rollback_config_transaction_locked(
                state, "pending candidate changed before confirmation"
            )
            outcome = (
                "the previous configuration was restored"
                if rollback.get("state") == "rolled_back"
                else "automatic rollback failed"
            )
            raise RuntimeError(
                f"HAProxy config transaction candidate changed; {outcome}"
            ) from exc
        state["state"] = "confirmed"
        state["confirmed_at"] = datetime.now(timezone.utc).isoformat()
        state.pop("previous_config_b64", None)
        state.pop("previous_sources", None)
        state.pop("geoip", None)
        _persist_config_transaction(state)
        return _sanitized_config_transaction_status(state)
    finally:
        _GUARDED_APPLY_LOCK.release()


def rollback_config_transaction(transaction_id: str) -> dict[str, object]:
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return _config_transaction_busy_result(transaction_id, "rollback")
    try:
        state = _load_config_transaction()
        if state is None or not _transaction_matches(state, transaction_id):
            raise ValueError("HAProxy config transaction id does not match")
        if state.get("state") == "rolled_back":
            return _sanitized_config_transaction_status(state)
        if state.get("state") not in {
            "prepared", "pending_confirmation", "rolling_back", "rollback_failed"
        }:
            raise RuntimeError("HAProxy config transaction cannot be rolled back")
        return _rollback_config_transaction_locked(state, "manual rollback requested")
    finally:
        _GUARDED_APPLY_LOCK.release()


def recover_config_transaction() -> None:
    """Recover an interrupted or pending transaction before serving clients."""
    with _GUARDED_APPLY_LOCK:
        state = _load_config_transaction()
        if state is None:
            return
        state_name = state.get("state")
        if state_name in {"prepared", "rolling_back", "rollback_failed"}:
            _rollback_config_transaction_locked(state, "controld restart recovery")
        elif state_name == "pending_confirmation":
            deadline = float(state.get("deadline_epoch") or 0)
            if not deadline or time.time() >= deadline:
                _rollback_config_transaction_locked(
                    state, "confirmation timeout expired during restart"
                )
            else:
                _schedule_config_transaction_watchdog(
                    str(state["transaction_id"]), deadline
                )


def _decode_geoip_payload(encoded: str, expected_keys: set[str]) -> dict[str, object]:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid GeoIP request encoding") from exc
    if not raw or len(raw) > GEOIP_MAX_SELECTION_BYTES:
        raise ValueError("invalid GeoIP request size")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid GeoIP request JSON") from exc
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("invalid GeoIP request fields")
    return value


def _geoip_selection() -> tuple[dict[str, object], bytes]:
    try:
        selection_stat = GEOIP_SELECTION_PATH.lstat()
    except FileNotFoundError:
        return {
            "countries": [],
            "access_filter_enabled": False,
            "revision": hashlib.sha256(b"").hexdigest(),
            "available": False,
        }, b""
    if stat.S_ISLNK(selection_stat.st_mode) or not stat.S_ISREG(selection_stat.st_mode):
        raise RuntimeError("GeoIP selection is not a regular file")
    if selection_stat.st_size <= 0 or selection_stat.st_size > GEOIP_MAX_SELECTION_BYTES:
        raise RuntimeError("GeoIP selection has an invalid size")
    raw = GEOIP_SELECTION_PATH.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GeoIP selection is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "version",
        "countries",
        "access_filter_enabled",
    }:
        raise RuntimeError("GeoIP selection has an invalid format")
    countries = value.get("countries")
    enabled = value.get("access_filter_enabled")
    if value.get("version") != 1 or not isinstance(countries, list) or not isinstance(enabled, bool):
        raise RuntimeError("GeoIP selection has an invalid format")
    normalized: set[str] = set()
    for code in countries:
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z]{2}", code):
            raise RuntimeError("GeoIP selection contains an invalid country code")
        normalized.add(code)
    if len(normalized) != len(countries) or list(countries) != sorted(normalized):
        raise RuntimeError("GeoIP selection countries are not canonical")
    return {
        "available": True,
        "countries": list(countries),
        "access_filter_enabled": enabled,
        "revision": hashlib.sha256(raw).hexdigest(),
    }, raw


def _geoip_current_release() -> Path | None:
    current = GEOIP_DIRECTORY / "current"
    try:
        target = current.resolve(strict=True)
        releases = GEOIP_RELEASES_PATH.resolve(strict=True)
        target.relative_to(releases)
        target_stat = target.lstat()
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return None
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISDIR(target_stat.st_mode):
        return None
    return target


def _read_geoip_state(release: Path) -> dict[str, object]:
    path = release / "state.json"
    try:
        state_stat = path.lstat()
    except FileNotFoundError:
        return {}
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
        return {}
    if state_stat.st_size <= 0 or state_stat.st_size > GEOIP_MAX_STATE_BYTES:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _sha256_matches(path: Path, expected: object) -> bool:
    expected_text = str(expected or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_text):
        return False
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return secrets.compare_digest(digest.hexdigest(), expected_text)
    except OSError:
        return False


def _systemd_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    if unit not in {GEOIP_UPDATE_SERVICE, GEOIP_UPDATE_TIMER}:
        raise ValueError("unsupported systemd unit")
    argv = ["/usr/bin/systemctl", "show", unit]
    for name in properties:
        argv.append(f"--property={name}")
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout or "systemctl failed").strip()[:2000]}
    output: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in properties:
            output[key] = value
    return output


def _geoip_journal_tail(lines: int = 20) -> list[str]:
    safe_lines = min(max(int(lines), 1), 100)
    try:
        result = subprocess.run(
            [
                "/usr/bin/journalctl",
                "-u",
                GEOIP_UPDATE_SERVICE,
                "--no-pager",
                "-q",
                "-o",
                "short-iso",
                "--lines",
                str(safe_lines),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"journal unavailable: {exc}"]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "journalctl failed").strip()
        return [f"journal unavailable: {detail[:1000]}"]
    return [line[:4000] for line in result.stdout.splitlines()[-safe_lines:]]


def geoip_status() -> dict[str, object]:
    selection_error = None
    try:
        selection, _ = _geoip_selection()
    except Exception as exc:  # noqa: BLE001
        selection_error = str(exc)
        selection = {
            "available": False,
            "countries": [],
            "access_filter_enabled": False,
            "revision": "",
        }

    database: dict[str, object] = {"available": False, "integrity_ok": False}
    release = _geoip_current_release()
    if release is not None:
        state = _read_geoip_state(release)
        database_path = release / "dbip-country-lite.mmdb"
        allowed_path = release / "allowed.geo"
        try:
            database_size = database_path.stat().st_size
        except OSError:
            database_size = 0
        try:
            allowed_size = allowed_path.stat().st_size
        except OSError:
            allowed_size = 0
        build_epoch = int(state.get("database_build_epoch") or 0)
        build_at = (
            datetime.fromtimestamp(build_epoch, timezone.utc).isoformat()
            if build_epoch > 0
            else None
        )
        integrity_ok = (
            state.get("release_format_version") == 1
            and _sha256_matches(database_path, state.get("database_sha256"))
            and _sha256_matches(allowed_path, state.get("allowed_sha256"))
        )
        database = {
            "available": bool(database_size and state),
            "release": release.name,
            "provider": str(state.get("provider") or ""),
            "source_period": str(state.get("source_period") or ""),
            "activated_at": state.get("activated_at"),
            "build_at": build_at,
            "records": int(state.get("database_records") or 0),
            "size_bytes": database_size,
            "allowed_size_bytes": allowed_size,
            "allowed_networks": int(state.get("allowed_networks") or 0),
            "country_networks": state.get("country_networks")
            if isinstance(state.get("country_networks"), dict)
            else {},
            "countries": state.get("countries")
            if isinstance(state.get("countries"), list)
            else [],
            "access_filter_enabled": bool(state.get("access_filter_enabled")),
            "integrity_ok": integrity_ok,
        }

    service_raw = _systemd_properties(
        GEOIP_UPDATE_SERVICE,
        (
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainStatus",
            "InactiveExitTimestamp",
        ),
    )
    timer_raw = _systemd_properties(
        GEOIP_UPDATE_TIMER,
        (
            "ActiveState",
            "SubState",
            "UnitFileState",
            "LastTriggerUSec",
            "NextElapseUSecRealtime",
        ),
    )
    service = {
        "active_state": service_raw.get("ActiveState", "unknown"),
        "sub_state": service_raw.get("SubState", "unknown"),
        "result": service_raw.get("Result", "unknown"),
        "exit_status": service_raw.get("ExecMainStatus", ""),
        "last_run_at": service_raw.get("InactiveExitTimestamp") or None,
    }
    if service_raw.get("error"):
        service["error"] = service_raw["error"]
    timer = {
        "active_state": timer_raw.get("ActiveState", "unknown"),
        "sub_state": timer_raw.get("SubState", "unknown"),
        "enabled": timer_raw.get("UnitFileState") == "enabled",
        "last_trigger_at": timer_raw.get("LastTriggerUSec") or None,
        "next_run_at": timer_raw.get("NextElapseUSecRealtime") or None,
        "schedule": _geoip_schedule_current(),
    }
    if timer_raw.get("error"):
        timer["error"] = timer_raw["error"]
    result: dict[str, object] = {
        "ok": selection_error is None,
        "database": database,
        "selection": selection,
        "service": service,
        "timer": timer,
        "update_running": service["active_state"] in {"activating", "active"}
        and service["sub_state"] not in {"dead", "exited"},
        "journal_tail": _geoip_journal_tail(),
    }
    if selection_error:
        result["error"] = selection_error
    active_countries = database.get("countries")
    result["selection_applied"] = (
        database.get("available")
        and active_countries == selection.get("countries")
        and database.get("access_filter_enabled")
        == selection.get("access_filter_enabled")
    )
    return result


def _geoip_schedule_current() -> str:
    """Return the effective OnCalendar keyword for the update timer.

    Reads the merged unit (base + drop-ins) via ``systemctl cat``; the last
    non-empty OnCalendar wins, matching systemd's override semantics.
    """
    try:
        out = subprocess.run(
            ["/usr/bin/systemctl", "cat", GEOIP_UPDATE_TIMER],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    value = ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("OnCalendar="):
            value = stripped.split("=", 1)[1].strip()
    return value


def geoip_set_schedule(schedule: object) -> dict[str, object]:
    """Override the update cadence via a systemd timer drop-in.

    Only daily/weekly/monthly are accepted, so the UI can never schedule a
    sub-daily run or inject an arbitrary systemd calendar expression.
    """
    value = str(schedule or "").strip().lower()
    if value not in GEOIP_ALLOWED_SCHEDULES:
        return {
            "ok": False,
            "error": "schedule must be one of: "
            + ", ".join(GEOIP_ALLOWED_SCHEDULES),
        }
    content = (
        "# Managed by the easy-ha-proxy web UI.\n"
        "[Timer]\n"
        "OnCalendar=\n"
        f"OnCalendar={value}\n"
    )
    try:
        GEOIP_TIMER_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        tmp = GEOIP_TIMER_DROPIN.with_name(GEOIP_TIMER_DROPIN.name + ".tmp")
        tmp.write_text(content, encoding="ascii")
        os.replace(tmp, GEOIP_TIMER_DROPIN)
    except OSError as exc:
        return {"ok": False, "error": f"cannot write timer override: {exc}"}
    reload_ok, reload_detail = _run_geoip_command(
        ["/usr/bin/systemctl", "daemon-reload"]
    )
    if not reload_ok:
        return {"ok": False, "error": f"daemon-reload failed: {reload_detail}"}
    restart_ok, restart_detail = _run_geoip_command(
        ["/usr/bin/systemctl", "restart", GEOIP_UPDATE_TIMER]
    )
    if not restart_ok:
        return {"ok": False, "error": f"timer restart failed: {restart_detail}"}
    LOG.info("geoip: update schedule set to %s", value)
    result = {
        "ok": True,
        "message": f"GeoIP update schedule set to {value}",
        "schedule": value,
    }
    result["status"] = geoip_status()
    return result


def _run_geoip_command(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=GEOIP_UPDATE_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = "\n".join(
        item.strip() for item in (result.stdout, result.stderr) if item.strip()
    )[-8000:]
    return result.returncode == 0, output


def geoip_update_now(force: bool) -> dict[str, object]:
    if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "another GeoIP operation is already running", "conflict": True}
    try:
        transaction = _load_config_transaction()
        if (
            transaction is not None
            and transaction.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES
        ):
            return {
                "ok": False,
                "error": "a HAProxy configuration transaction is still active",
                "conflict": True,
            }
        service = _systemd_properties(
            GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
        )
        if service.get("ActiveState") in {"activating", "active", "reloading"}:
            return {
                "ok": False,
                "error": "another GeoIP operation is already running",
                "conflict": True,
                "status": geoip_status(),
            }
        marker_created = False
        if force:
            marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                marker_flags |= os.O_NOFOLLOW
            try:
                marker_fd = os.open(GEOIP_FORCE_MARKER, marker_flags, 0o600)
            except FileExistsError:
                return {
                    "ok": False,
                    "error": "a forced GeoIP update is already queued",
                    "conflict": True,
                    "status": geoip_status(),
                }
            try:
                os.write(marker_fd, b"force\n")
                os.fsync(marker_fd)
            finally:
                os.close(marker_fd)
            marker_created = True
        ok, detail = _run_geoip_command(
            ["/usr/bin/systemctl", "start", "--no-block", GEOIP_UPDATE_SERVICE]
        )
        if not ok and marker_created:
            GEOIP_FORCE_MARKER.unlink(missing_ok=True)
        status = geoip_status()
        return {
            "ok": ok,
            "started": ok,
            "message": "GeoIP update started" if ok else "GeoIP update failed",
            "error": None if ok else "GeoIP update failed",
            "stdout": detail,
            "active_acl_preserved": bool(status.get("selection_applied")),
            "status": status,
        }
    finally:
        _GEOIP_OPERATION_LOCK.release()


def geoip_configure(countries: object, expected_revision: object) -> dict[str, object]:
    if not isinstance(countries, list) or len(countries) > GEOIP_MAX_COUNTRIES:
        raise ValueError("countries must be a list with at most 249 entries")
    normalized: set[str] = set()
    for raw in countries:
        if not isinstance(raw, str):
            raise ValueError("country codes must be strings")
        code = raw.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            raise ValueError(f"invalid ISO country code: {raw!r}")
        normalized.add(code)
    selected = sorted(normalized)
    revision = str(expected_revision or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ValueError("the GeoIP selection revision is missing or invalid")
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return {
            "ok": False,
            "error": "another HAProxy configuration operation is already running",
            "conflict": True,
        }
    try:
        try:
            _ensure_no_active_config_transaction_locked()
        except RuntimeError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "conflict": True,
            }
        if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
            return {
                "ok": False,
                "error": "another GeoIP operation is already running",
                "conflict": True,
            }
        try:
            service = _systemd_properties(
                GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
            )
            if service.get("ActiveState") in {"activating", "active", "reloading"}:
                return {
                    "ok": False,
                    "error": "another GeoIP operation is already running",
                    "conflict": True,
                    "status": geoip_status(),
                }
            _, current_raw = _geoip_selection()
            current_revision = hashlib.sha256(current_raw).hexdigest()
            if not secrets.compare_digest(current_revision, revision):
                return {
                    "ok": False,
                    "error": "GeoIP selection changed in another session; reload it before saving",
                    "conflict": True,
                    "current_revision": current_revision,
                    "status": geoip_status(),
                }
            argv = [GEOIP_UPDATE_COMMAND, "--configure-selection"]
            for code in selected:
                argv.extend(("--country", code))
            ok, detail = _run_geoip_command(argv)
            status = geoip_status()
            return {
                "ok": ok,
                "message": "GeoIP country selection updated"
                if ok
                else "GeoIP country selection update failed",
                "error": None if ok else "GeoIP country selection update failed",
                "stdout": detail,
                "active_acl_preserved": bool(status.get("selection_applied")),
                "status": status,
            }
        finally:
            _GEOIP_OPERATION_LOCK.release()
    finally:
        _GUARDED_APPLY_LOCK.release()


def handle_client(conn: socket.socket) -> None:
    try:
        conn.settimeout(30)
        # читаем ОДНУ строку команды целиком (важно для больших base64)
        chunks: list[bytes] = []
        received = 0
        while True:
            data = conn.recv(4096)
            if not data:
                break
            received += len(data)
            if received > MAX_COMMAND_BYTES:
                conn.sendall(b"ERROR command is too large\n")
                return
            chunks.append(data)
            if b"\n" in data:
                break

        if not chunks:
            return

        raw = b"".join(chunks)
        line = raw.split(b"\n", 1)[0]
        cmd = line.decode("utf-8", "replace").strip()

        # Once the update broker has committed a reboot timer, do not admit a
        # new host mutation from another browser tab. Read-only inspection and
        # transaction confirmation/rollback stay available.
        reboot_blocked_exact = {"reload", "udp-apply", "udp-apply-json"}
        reboot_blocked_prefixes = (
            "certs-restore ",
            "write-config ",
            "apply-config ",
            "begin-config-transaction ",
            "geoip-update ",
            "geoip-configure ",
            "geoip-schedule ",
        )
        if (
            os.path.lexists(MAINTENANCE_REBOOT_MARKER)
            or os.path.lexists(ASSISTANT_REBOOT_MARKER)
        ) and (
            cmd in reboot_blocked_exact
            or cmd.startswith(reboot_blocked_prefixes)
        ):
            conn.sendall(b"ERROR a server reboot is scheduled\n")
            return

        # ---- reload ----
        if cmd == "reload":
            ok, msg = cmd_reload()
            if ok:
                conn.sendall(f"OK {msg}\n".encode("utf-8", "replace"))
            else:
                conn.sendall(f"ERROR {msg}\n".encode("utf-8", "replace"))
            return

        # ---- одноразовая sync-bans ----
        if cmd == "sync-bans":
            try:
                sync_bans_once()
                conn.sendall(b"OK sync-bans done\n")
            except Exception as e:
                conn.sendall(
                    f"ERROR sync-bans: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- reload UDP forwarding rules (iptables DNAT) ----
        # Re-runs the loader unit synchronously. The JSON command returns the
        # generator's durable /run state, so the UI reports success only after
        # the complete ruleset has been installed.
        if cmd in {"udp-apply", "udp-apply-json"}:
            try:
                run_cmd(
                    ["systemctl", "restart", "iptables-haproxy-udp.service"],
                    timeout=60,
                )
                state = _read_udp_forward_state()
                if cmd == "udp-apply-json":
                    _send_control_json(conn, {"ok": True, **state})
                else:
                    conn.sendall(b"OK udp-apply done\n")
            except Exception as e:
                LOG.error("udp-apply error: %s", e)
                if cmd == "udp-apply-json":
                    _send_control_json(
                        conn,
                        {"ok": False, "error": f"UDP forwarding apply failed: {e}"},
                    )
                else:
                    conn.sendall(
                        f"ERROR udp-apply: {e}\n".encode("utf-8", "replace")
                    )
            return

        if cmd == "udp-status":
            try:
                _send_control_json(
                    conn,
                    {"ok": True, **_read_udp_forward_state()},
                )
            except Exception as exc:
                _send_control_json(
                    conn,
                    {"ok": False, "error": str(exc)[:4000]},
                )
            return

        # ---- check whether a host UDP listen port/range is already occupied ----
        if cmd.startswith("udp-port-check"):
            parts = cmd.split()
            try:
                start = int(parts[1])
                end = int(parts[2]) if len(parts) >= 3 else start
                if (
                    not 1 <= start <= end <= 65535
                    or end - start + 1 > UDP_MAX_PORT_RANGE
                ):
                    raise ValueError
            except (IndexError, ValueError):
                conn.sendall(b"ERROR udp-port-check: invalid port range\n")
                return
            busy = _udp_ports_in_use(start, end)
            if busy:
                conn.sendall(f"OK busy {min(busy)}\n".encode("ascii"))
            else:
                conn.sendall(f"OK free {start}-{end}\n".encode("ascii"))
            return

        # ---- backup сертификатов ----
        if cmd == "certs-backup":
            try:
                b64 = certs_backup_b64()
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                LOG.error("certs-backup error: %s", e)
                conn.sendall(
                    f"ERROR certs-backup: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- restore сертификатов ----
        if cmd.startswith("certs-restore "):
            try:
                _, b64 = cmd.split(" ", 1)
                msg = certs_restore_b64(b64)
                conn.sendall(f"OK {msg}\n".encode("utf-8", "replace"))
            except Exception as e:
                LOG.error("certs-restore error: %s", e)
                conn.sendall(
                    f"ERROR certs-restore: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- проверка конфига haproxy -c ----
        if cmd.startswith("check-config "):
            try:
                _, cfg_b64 = cmd.split(" ", 1)
                rc, stdout, stderr = haproxy_check_config_from_b64(cfg_b64)

                stdout_b64 = base64.b64encode(
                    (stdout or "").encode("utf-8", "replace")
                ).decode("ascii")
                stderr_b64 = base64.b64encode(
                    (stderr or "").encode("utf-8", "replace")
                ).decode("ascii")

                resp = f"OK {rc}\n{stdout_b64}\n{stderr_b64}\n"
                conn.sendall(resp.encode("utf-8", "replace"))
            except Exception as e:
                msg = f"ERROR check-config: {e}"
                conn.sendall(msg.encode("utf-8", "replace"))
            return

        # ---- запись конфига /etc/haproxy/haproxy.cfg ----
        if cmd.startswith("write-config "):
            try:
                _, cfg_b64 = cmd.split(" ", 1)
                haproxy_write_config_serialized(cfg_b64)
                conn.sendall(b"OK wrote haproxy.cfg\n")
            except Exception as e:
                msg = f"ERROR write-config: {e}\n"
                conn.sendall(msg.encode("utf-8", "replace"))
            return

        # ---- transactional config apply with critical-service rollback ----
        if cmd.startswith("apply-config "):
            try:
                parts = cmd.split(" ", 2)
                if len(parts) != 3:
                    raise ValueError("apply-config requires config and checks payloads")
                result = haproxy_apply_config_guarded(parts[1], parts[2])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as e:
                result = {
                    "ok": False,
                    "applied": False,
                    "rolled_back": False,
                    "rollback_ok": None,
                    "failure": f"guarded apply request failed: {e}",
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- confirmable config transaction with a server-side deadline ----
        if cmd.startswith("begin-config-transaction "):
            try:
                parts = cmd.split(" ", 4)
                if len(parts) != 5:
                    raise ValueError(
                        "begin-config-transaction requires config, checks, "
                        "sources, and timeout payloads"
                    )
                result = begin_config_transaction(
                    parts[1], parts[2], parts[3], parts[4]
                )
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("pending") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd == "config-transaction-status" or cmd.startswith(
            "config-transaction-status "
        ):
            try:
                parts = cmd.split()
                if len(parts) > 2:
                    raise ValueError("config-transaction-status accepts one optional id")
                result = config_transaction_status(parts[1] if len(parts) == 2 else "")
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"OK {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("confirm-config-transaction "):
            try:
                parts = cmd.split()
                if len(parts) != 3:
                    raise ValueError(
                        "confirm-config-transaction requires id and candidate hash"
                    )
                result = confirm_config_transaction(parts[1], parts[2])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("rollback-config-transaction "):
            try:
                parts = cmd.split()
                if len(parts) != 2:
                    raise ValueError("rollback-config-transaction requires an id")
                result = rollback_config_transaction(parts[1])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("state") == "rolled_back" else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- local GeoIP database and runtime country selection ----
        if cmd == "geoip-status":
            try:
                result = geoip_status()
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-update "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(parts[1], {"force"})
                force = request_payload.get("force")
                if not isinstance(force, bool):
                    raise ValueError("force must be boolean")
                result = geoip_update_now(force)
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-configure "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(
                    parts[1], {"countries", "revision"}
                )
                result = geoip_configure(
                    request_payload.get("countries"),
                    request_payload.get("revision"),
                )
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-schedule "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(parts[1], {"schedule"})
                result = geoip_set_schedule(request_payload.get("schedule"))
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- logs-ip ----
        if cmd.startswith("logs-ip "):
            try:
                _, rest = cmd.split(" ", 1)
                parts = rest.split()
                if not parts:
                    conn.sendall(b"ERROR logs-ip: missing ip\n")
                    return

                ip = parts[0].strip()
                n = int(parts[1]) if len(parts) >= 2 else LOG_LIMIT

                # валидация IP
                ipaddress.ip_address(ip)

                lines = grep_last_logs_for_ip(ip, limit=n)
                lines = _sort_log_lines_by_time(lines)
                payload = "\n".join(lines).encode("utf-8", "replace")
                b64 = base64.b64encode(payload).decode("ascii")
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                conn.sendall(
                    f"ERROR logs-ip: {e}\n".encode("utf-8", "replace"))
            return

        # ---- logs-attackers ----
        if cmd == "logs-attackers":
            try:
                data = logs_attackers()
                payload = json.dumps(data, ensure_ascii=False).encode(
                    "utf-8", "replace")
                b64 = base64.b64encode(payload).decode("ascii")
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                conn.sendall(
                    f"ERROR logs-attackers: {e}\n".encode("utf-8", "replace"))
            return

        # ---- ping ----
        if cmd == "ping":
            conn.sendall(b"OK pong\n")
            return

        conn.sendall(b"ERROR unknown command\n")
    except Exception as e:
        LOG.error("Error while handling client: %s", e)
        try:
            conn.sendall(f"ERROR exception: {e}\n".encode("utf-8", "replace"))
        except Exception:
            pass


def control_socket_loop() -> None:
    """
    Основной цикл: слушаем Unix-сокет и принимаем команды.

    Оптимизация: каждый клиент обрабатывается в отдельном потоке, чтобы тяжёлые команды
    (например logs-ip) не блокировали принятие следующих подключений.
    """
    sock_path = CONTROL_SOCKET
    sock_dir = os.path.dirname(sock_path) or "/run"

    # удаляем старый сокет, если остался
    try:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    except OSError as e:
        LOG.error("Failed to unlink old socket %s: %s", sock_path, e)
        return

    os.makedirs(sock_dir, exist_ok=True)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(sock_path)
        os.chmod(sock_path, 0o660)
        srv.listen(5)
        LOG.info("haproxy-controld is listening on %s", sock_path)
    except Exception as e:
        LOG.error("Failed to bind/listen on %s: %s", sock_path, e)
        return

    def _client_worker(c: socket.socket) -> None:
        with c:
            handle_client(c)

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(
                target=_client_worker,
                args=(conn,),
                daemon=True,
                name="controld-client",
            ).start()
    finally:
        try:
            srv.close()
        finally:
            if os.path.exists(sock_path):
                os.unlink(sock_path)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    LOG.info(
        "Starting haproxy-controld: SOCKET_PATH=%s, BAN_TABLE=%s, "
        "IPSET_NAME=%s, INTERVAL=%ss, CONTROL_SOCKET=%s",
        SOCKET_PATH,
        BAN_TABLE,
        IPSET_NAME,
        INTERVAL,
        CONTROL_SOCKET,
    )

    try:
        recover_config_transaction()
    except Exception:  # noqa: BLE001
        # Do not silently discard an incomplete transaction. Keeping the
        # daemon available lets an authenticated administrator inspect and
        # retry a rollback through the control socket.
        LOG.exception("Could not recover the persisted HAProxy config transaction")

    # Запускаем фоновый поток бан-синхронизации
    t = threading.Thread(target=bans_loop, daemon=True, name="ban-sync-loop")
    t.start()

    # В главном потоке — loop по сокету управления
    control_socket_loop()


if __name__ == "__main__":
    main()
