#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
haproxy-healthd — root-демон мониторинга для haproxy-admin.

HTTP API поверх Unix-socket:

- статусы systemd unit'ов (allow-list + glob-паттерны);
- статусы Docker контейнеров (allow-list);
- журналы (journalctl / docker logs) для этих объектов;
- лента событий (смена состояния между снимками).

Изменение "по лучшим практикам" для снижения CPU:
- по умолчанию НЕТ фонового polling (status собирается только по запросу);
- есть TTL-кэш статуса (cache_ttl_seconds), чтобы UI мог автообновляться без частых systemctl/docker;
- раскрытие unit_globs (systemctl list-unit-files) кэшируется (units_rescan_seconds);
- systemctl show ограничен --property=... (меньше вывода/парсинга).
- docker inspect использует --format (меньше данных, без JSON парсинга).

Фоновый polling можно включить, если нужно:
  ENV HEALTHD_BACKGROUND_POLL=1
"""

from __future__ import annotations

import fnmatch
import hmac
import json
import logging
import os
import pwd
import grp
import re
import socket
import subprocess
import threading
import time
from collections import deque, OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import UnixStreamServer, ThreadingMixIn
from typing import Any, Dict, Optional, Tuple, List
from urllib.parse import parse_qs, urlparse


LOG = logging.getLogger("haproxy-healthd")

SOCKET_PATH = os.environ.get(
    "HEALTHD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-healthd.sock")
CONFIG_PATH = os.environ.get(
    "HEALTHD_CONFIG", "/opt/haproxy-admin/healthd.json")
SOCKET_GROUP = os.environ.get("HEALTHD_SOCKET_GROUP", "hadmin")

# Каталог для journalctl --cursor-file (сервер хранит курсоры сам, чтобы UI не таскал cursor).
CURSOR_DIR = os.environ.get(
    "HEALTHD_CURSOR_DIR", "/run/haproxy-healthd-cursors")

# --- Logs performance tuning ---
try:
    LOGS_CACHE_TTL = float(os.environ.get("HEALTHD_LOGS_CACHE_TTL", "1.0"))
except ValueError:
    LOGS_CACHE_TTL = 1.0

try:
    LOGS_CACHE_MAX = int(os.environ.get("HEALTHD_LOGS_CACHE_MAX", "256"))
except ValueError:
    LOGS_CACHE_MAX = 256

try:
    LOGS_CACHE_MAX_VALUE_BYTES = int(os.environ.get(
        "HEALTHD_LOGS_CACHE_MAX_VALUE_BYTES", str(256 * 1024)))
except ValueError:
    LOGS_CACHE_MAX_VALUE_BYTES = 256 * 1024

try:
    LOGS_CMD_TIMEOUT = int(os.environ.get("HEALTHD_LOGS_CMD_TIMEOUT", "12"))
except ValueError:
    LOGS_CMD_TIMEOUT = 12

# --- Control API (start/stop/restart/reload) ---
CONTROL_TOKEN = os.environ.get("HEALTHD_TOKEN", "").strip()
HEALTHD_UNIT = os.environ.get(
    "HEALTHD_UNIT", "haproxy-healthd.service").strip()

# По умолчанию: НЕТ фонового polling.
BACKGROUND_POLL = (os.environ.get(
    "HEALTHD_BACKGROUND_POLL", "0").strip() == "1")

# High-volume/self-generated traffic is intentionally excluded from the
# compact dashboard feed by default. Both services remain available through
# the per-unit log view and can be explicitly selected in the recent feed.
RECENT_SYSTEMD_EXCLUDED_UNITS = frozenset({
    "haproxy.service",
    "haproxy-healthd.service",
})

RECENT_SYSTEMD_DEFAULT_LIMIT = 50
RECENT_SYSTEMD_MAX_LIMIT = 500


def _unit_base(unit: str) -> str:
    u = (unit or "").strip()
    if u.endswith(".service"):
        u = u[:-len(".service")]
    return u


def _control_allowed_actions(kind: str, name: str) -> Tuple[str, ...]:
    """Возвращает допустимые действия для ресурса согласно политике."""
    kind = (kind or "").strip().lower()
    nm = (name or "").strip()

    if kind == "docker":
        # Критические контейнеры — только restart
        if nm in {"haproxy-admin", "authelia", "authelia-redis"}:
            return ("restart",)
        return ("start", "stop", "restart")

    if kind == "systemd":
        base = _unit_base(nm)
        # HAProxy: разрешаем reload и restart
        if base == "haproxy":
            return ("reload", "restart")
        # Authelia*: start/stop/restart
        if base.startswith("authelia"):
            return ("start", "stop", "restart")
        # Сам healthd: только restart
        if base == _unit_base(HEALTHD_UNIT):
            return ("restart",)
        # Остальные демоны: start/stop/restart
        return ("start", "stop", "restart")

    return tuple()


@dataclass(frozen=True)
class HealthdConfig:
    systemd_units: Tuple[str, ...]
    systemd_unit_globs: Tuple[str, ...]
    docker_containers: Tuple[str, ...]
    poll_interval_seconds: int
    events_max: int

    # TTL-кэш статуса (сек). 0 => всегда собирать заново по запросу.
    cache_ttl_seconds: int

    # Как часто пересканировать systemctl list-unit-files для glob'ов (сек).
    units_rescan_seconds: int

    # logs limits
    logs_default_tail: int
    logs_max_tail: int
    logs_default_since_seconds: int
    logs_max_since_seconds: int


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run_cmd(argv: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    """Выполнить команду, вернуть (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", "command not found"
    except Exception as e:  # pylint: disable=broad-except
        return 1, "", str(e)


# ───── небольшой TTL/LRU кэш для /logs ─────

class _TTLCache:
    def __init__(self, ttl_seconds: float, max_entries: int, max_value_bytes: int):
        self.ttl = max(0.0, float(ttl_seconds))
        self.max_entries = max(0, int(max_entries))
        self.max_value_bytes = max(0, int(max_value_bytes))
        self._lock = threading.RLock()
        self._data: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()

    def get(self, key: tuple) -> Optional[dict]:
        if self.ttl <= 0 or self.max_entries <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            ts, val = item
            if (now - ts) > self.ttl:
                try:
                    del self._data[key]
                except KeyError:
                    pass
                return None
            self._data.move_to_end(key)
            return dict(val)

    def put(self, key: tuple, value: dict) -> None:
        if self.ttl <= 0 or self.max_entries <= 0:
            return
        try:
            raw = json.dumps(value, ensure_ascii=False).encode(
                "utf-8", "replace")
        except Exception:
            return
        if self.max_value_bytes > 0 and len(raw) > self.max_value_bytes:
            return
        now = time.monotonic()
        with self._lock:
            self._data[key] = (now, dict(value))
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)


def _parse_kv(output: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in output.splitlines():
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def _clamp_int(value: Optional[str], default: int, min_v: int, max_v: int) -> int:
    if value is None or value == "":
        return default
    try:
        n = int(value, 10)
    except ValueError:
        return default
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def _parse_recent_systemd_units(
    query: Dict[str, List[str]],
) -> Optional[List[str]]:
    """Parse an optional recent-feed unit selection.

    ``unit`` may be repeated. ``units`` is accepted as a comma-separated
    convenience parameter. The distinction between an omitted selection and
    an explicitly empty one is intentional: omitted uses the safe defaults,
    while ``units=`` selects no services.
    """
    if "unit" not in query and "units" not in query:
        return None

    selected: List[str] = []
    seen = set()
    for key in ("unit", "units"):
        for raw_value in query.get(key, []):
            for raw_unit in (raw_value or "").split(","):
                unit = raw_unit.strip()
                if not unit or unit in seen:
                    continue
                seen.add(unit)
                selected.append(unit)
    return selected


def _load_config(path: str) -> HealthdConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {path}")

    raw = json.loads(p.read_text(encoding="utf-8"))

    systemd = raw.get("systemd") or {}
    docker = raw.get("docker") or {}
    logs = raw.get("logs") or {}

    units = tuple(str(x) for x in (systemd.get("units") or []))
    unit_globs = tuple(str(x) for x in (systemd.get("unit_globs") or []))
    containers = tuple(str(x) for x in (docker.get("containers") or []))

    poll = int(raw.get("poll_interval_seconds") or 5)
    events_max = int(raw.get("events_max") or 200)

    cache_ttl = int(raw.get("cache_ttl_seconds") or 15)
    units_rescan = int(raw.get("units_rescan_seconds") or 60)

    logs_default_tail = int(logs.get("default_tail") or 200)
    logs_max_tail = int(logs.get("max_tail") or 2000)
    logs_default_since = int(logs.get("default_since_seconds") or 3600)
    logs_max_since = int(logs.get("max_since_seconds") or 86400)

    # sanity
    poll = max(1, min(poll, 300))
    events_max = max(10, min(events_max, 2000))

    cache_ttl = max(0, min(cache_ttl, 3600))
    units_rescan = max(5, min(units_rescan, 3600))

    logs_max_tail = max(50, min(logs_max_tail, 20000))
    logs_default_tail = max(10, min(logs_default_tail, logs_max_tail))
    logs_max_since = max(300, min(logs_max_since, 7 * 24 * 3600))
    logs_default_since = max(60, min(logs_default_since, logs_max_since))

    return HealthdConfig(
        systemd_units=units,
        systemd_unit_globs=unit_globs,
        docker_containers=containers,
        poll_interval_seconds=poll,
        events_max=events_max,
        cache_ttl_seconds=cache_ttl,
        units_rescan_seconds=units_rescan,
        logs_default_tail=logs_default_tail,
        logs_max_tail=logs_max_tail,
        logs_default_since_seconds=logs_default_since,
        logs_max_since_seconds=logs_max_since,
    )


# systemd status (минимальный набор свойств)
_SYSTEMCTL_PROPS = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Type",
    "UnitFileState",
    "Description",
    "MainPID",
    "ExecMainPID",
    "Result",
    "ExecMainStatus",
    "ActiveEnterTimestamp",
    "InactiveEnterTimestamp",
    "InactiveExitTimestamp",
)


def _systemd_health(data: Dict[str, str]) -> Tuple[Optional[bool], str]:
    """Return health and a concise display state for a systemd unit.

    A timer-triggered ``Type=oneshot`` service normally returns to
    ``inactive/dead`` after a successful run. Treating every inactive unit as
    unhealthy would therefore produce a permanent false alarm for scheduled
    jobs. Their last result and exit status are the meaningful signals.
    """
    load_state = (data.get("LoadState") or "").strip()
    active_state = (data.get("ActiveState") or "").strip()
    sub_state = (data.get("SubState") or "").strip()
    unit_type = (data.get("Type") or "").strip()
    result = (data.get("Result") or "").strip()
    exec_main_status = _parse_int(data.get("ExecMainStatus", ""))

    if load_state and load_state != "loaded":
        return False, load_state
    if active_state == "failed":
        return False, "failed"
    if unit_type == "oneshot" and active_state == "activating":
        return None, "running"
    if active_state in {"activating", "deactivating"}:
        return None, active_state
    if active_state == "active":
        return True, "loaded" if sub_state == "exited" else "active"
    if unit_type == "oneshot" and active_state == "inactive":
        inactive_exit_timestamp = (
            data.get("InactiveExitTimestamp") or ""
        ).strip()
        if not inactive_exit_timestamp or inactive_exit_timestamp.lower() == "n/a":
            return None, "not-run"
        succeeded = result in {"", "success"} and exec_main_status in {None, 0}
        return (True, "completed") if succeeded else (False, "failed")
    if active_state == "inactive":
        return False, "inactive"
    return None, active_state or "?"


def _systemd_display_sub_state(
    data: Dict[str, str], healthy: Optional[bool], display_state: str
) -> str:
    """Return a human-readable sub-state without replacing raw systemd data."""
    sub_state = (data.get("SubState") or "").strip()
    if (data.get("Type") or "").strip() != "oneshot":
        return sub_state

    active_state = (data.get("ActiveState") or "").strip()
    result = (data.get("Result") or "").strip()
    if active_state == "activating" or display_state == "running":
        return "running"
    if display_state == "completed" and healthy is True:
        return "success"
    if display_state == "not-run" and healthy is None:
        return "—"
    if healthy is False:
        return result if result and result != "success" else (sub_state or "failed")
    return sub_state


def _get_systemd_status(unit: str) -> Dict[str, Any]:
    cmd = ["systemctl", "show", unit, "--no-pager"]
    # Ограничиваем вывод нужными property.
    for p in _SYSTEMCTL_PROPS:
        cmd += ["--property", p]

    rc, out, err = _run_cmd(cmd, timeout=12)
    if rc != 0:
        return {"ok": False, "unit": unit, "cmd": " ".join(cmd), "rc": rc, "error": err.strip()}

    data = _parse_kv(out)
    healthy, display_state = _systemd_health(data)
    display_sub_state = _systemd_display_sub_state(
        data, healthy, display_state
    )
    return {
        "ok": True,
        "unit": unit,
        "load_state": data.get("LoadState"),
        "active_state": data.get("ActiveState"),
        "sub_state": data.get("SubState"),
        "unit_type": data.get("Type"),
        "unit_file_state": data.get("UnitFileState"),
        "description": data.get("Description"),
        "main_pid": data.get("MainPID"),
        "exec_main_pid": data.get("ExecMainPID"),
        "result": data.get("Result"),
        "exec_main_status": _parse_int(data.get("ExecMainStatus", "")),
        "active_enter_timestamp": data.get("ActiveEnterTimestamp"),
        "inactive_enter_timestamp": data.get("InactiveEnterTimestamp"),
        "inactive_exit_timestamp": data.get("InactiveExitTimestamp"),
        "healthy": healthy,
        "display_state": display_state,
        "display_sub_state": display_sub_state,
    }


# docker status (через --format, без большого JSON)
# --format использует Go templates.
_DOCKER_INSPECT_TEMPLATE = "\n".join([
    "Status={{.State.Status}}",
    "Running={{.State.Running}}",
    "Paused={{.State.Paused}}",
    "Restarting={{.State.Restarting}}",
    "OOMKilled={{.State.OOMKilled}}",
    "Dead={{.State.Dead}}",
    "ExitCode={{.State.ExitCode}}",
    "StartedAt={{.State.StartedAt}}",
    "FinishedAt={{.State.FinishedAt}}",
    "Health={{if .State.Health}}{{.State.Health.Status}}{{end}}",
    "Image={{.Config.Image}}",
])


def _parse_bool(s: str) -> Optional[bool]:
    t = (s or "").strip().lower()
    if t in {"true", "1", "yes"}:
        return True
    if t in {"false", "0", "no"}:
        return False
    return None


def _parse_int(s: str) -> Optional[int]:
    try:
        return int((s or "").strip(), 10)
    except Exception:
        return None


def _get_docker_status(name: str) -> Dict[str, Any]:
    cmd = ["docker", "container", "inspect",
           "--format", _DOCKER_INSPECT_TEMPLATE, name]
    rc, out, err = _run_cmd(cmd, timeout=12)
    if rc != 0:
        return {"ok": False, "name": name, "cmd": " ".join(cmd), "rc": rc, "error": err.strip()}

    kv = _parse_kv(out)
    return {
        "ok": True,
        "name": name,
        "status": kv.get("Status"),
        "running": _parse_bool(kv.get("Running", "")),
        "paused": _parse_bool(kv.get("Paused", "")),
        "restarting": _parse_bool(kv.get("Restarting", "")),
        "oom_killed": _parse_bool(kv.get("OOMKilled", "")),
        "dead": _parse_bool(kv.get("Dead", "")),
        "exit_code": _parse_int(kv.get("ExitCode", "")),
        "started_at": kv.get("StartedAt"),
        "finished_at": kv.get("FinishedAt"),
        "health": kv.get("Health") or None,
        "image": kv.get("Image"),
    }


class _State:
    def __init__(self, cfg: HealthdConfig):
        self.cfg = cfg
        self.lock = threading.RLock()

        self.cache: Dict[str, Any] = {
            "ok": True,
            "ts_utc": _utc_now_iso(),
            "systemd": {"units": {}, "errors": []},
            "docker": {"containers": {}, "errors": [], "available": None},
            "meta": {"cached": False, "cache_age_seconds": None},
        }

        self.events: deque[Dict[str, Any]] = deque(maxlen=cfg.events_max)

        # внутренние метрики кэша
        self._last_collect_mono: float = 0.0
        self._prev_sig: Dict[str, str] = {}

        # кэш раскрытия glob'ов
        self._units_rescan_mono: float = 0.0
        self._units_expanded_cache: List[str] = []

        # stampede lock: чтобы параллельные запросы не запускали сбор одновременно
        self._collect_lock = threading.Lock()

        self._logs_cache = _TTLCache(
            LOGS_CACHE_TTL, LOGS_CACHE_MAX, LOGS_CACHE_MAX_VALUE_BYTES)

        # cursor-file синхронизация для follow-режима логов
        self._cursor_locks: Dict[str, threading.Lock] = {}
        self._cursor_locks_guard = threading.RLock()
        try:
            Path(CURSOR_DIR).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # optional background polling
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._poll_loop, name="healthd-poller", daemon=True)

    def start(self) -> None:
        if BACKGROUND_POLL:
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if BACKGROUND_POLL:
            self._thread.join(timeout=3)

    def _allowed_unit(self, unit: str) -> bool:
        if unit in self.cfg.systemd_units:
            return True
        for pat in self.cfg.systemd_unit_globs:
            if fnmatch.fnmatch(unit, pat):
                return True
        return False

    def _allowed_container(self, name: str) -> bool:
        return name in self.cfg.docker_containers

    def snapshot(self, refresh: bool = False) -> Dict[str, Any]:
        """
        Возвращает кэш статуса.
        Если refresh=True — принудительно собирает заново.
        Если refresh=False — собирает только если TTL истёк или кэша ещё нет.
        """
        ttl = int(self.cfg.cache_ttl_seconds or 0)

        if refresh or ttl <= 0:
            return self.force_refresh()

        now = time.monotonic()
        with self.lock:
            last = self._last_collect_mono
            have = bool(self.cache.get("systemd", {}).get("units")) or bool(
                self.cache.get("docker", {}).get("containers"))
            if have and last > 0 and (now - last) < ttl:
                out = json.loads(json.dumps(self.cache))
                out["meta"]["cached"] = True
                out["meta"]["cache_age_seconds"] = int(now - last)
                return out

        # TTL истёк — собираем
        return self.force_refresh()

    def force_refresh(self) -> Dict[str, Any]:
        with self._collect_lock:
            new_cache, sig = self._collect()

            now_iso = _utc_now_iso()
            now_mono = time.monotonic()

            with self.lock:
                # события: сравнить сигнатуры
                for key, new_val in sig.items():
                    old_val = self._prev_sig.get(key)
                    if old_val is None:
                        continue
                    if old_val != new_val:
                        kind, name = key.split(":", 1)
                        self.events.append({
                            "ts_utc": now_iso,
                            "kind": kind,
                            "name": name,
                            "from": old_val,
                            "to": new_val,
                        })

                self._prev_sig = sig
                self.cache = new_cache
                self._last_collect_mono = now_mono

        # выдаём копию
        out = json.loads(json.dumps(self.cache))
        out["meta"]["cached"] = False
        out["meta"]["cache_age_seconds"] = 0
        return out

    def events_snapshot(self, limit: int) -> List[Dict[str, Any]]:
        with self.lock:
            items = list(self.events)[-limit:]
            return json.loads(json.dumps(items))

    # ───────────── units expansion ─────────────

    def _expand_units(self) -> List[str]:
        """
        Возвращает список unit'ов для проверки:
        - явные units из config
        - glob'ы раскрываются через systemctl list-unit-files не чаще units_rescan_seconds
        """
        base: List[str] = list(self.cfg.systemd_units)
        globs = list(self.cfg.systemd_unit_globs)
        if not globs:
            return sorted(set(base))

        now = time.monotonic()
        need_rescan = False

        with self.lock:
            if not self._units_expanded_cache:
                need_rescan = True
            elif (now - self._units_rescan_mono) >= float(self.cfg.units_rescan_seconds):
                need_rescan = True

        if not need_rescan:
            with self.lock:
                expanded = list(self._units_expanded_cache)
            return sorted(set(base + expanded))

        # rescan
        expanded: List[str] = []
        rc, out, err = _run_cmd(
            ["systemctl", "list-unit-files", "--type=service",
                "--no-pager", "--no-legend"],
            timeout=15,
        )
        if rc == 0:
            for line in out.splitlines():
                if not line.strip():
                    continue
                unit_name = line.split(None, 1)[0].strip()
                for pat in globs:
                    if fnmatch.fnmatch(unit_name, pat):
                        expanded.append(unit_name)

        with self.lock:
            self._units_expanded_cache = sorted(set(expanded))
            self._units_rescan_mono = now
            # ошибки list-unit-files запишем в cache при следующем collect (ниже)

        return sorted(set(base + expanded))

    # ───────────── background polling (optional) ─────────────

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.force_refresh()
            except Exception:
                LOG.exception("poll refresh failed")
            self._stop.wait(self.cfg.poll_interval_seconds)

    # ───────────── сбор статуса ─────────────

    def _collect(self) -> Tuple[Dict[str, Any], Dict[str, str]]:
        now = _utc_now_iso()
        cache: Dict[str, Any] = {
            "ok": True,
            "ts_utc": now,
            "systemd": {"units": {}, "errors": []},
            "docker": {"containers": {}, "errors": [], "available": None},
            "meta": {"cached": False, "cache_age_seconds": None},
        }
        sig: Dict[str, str] = {}

        # systemd units (expanded)
        units_to_check = self._expand_units()

        # если есть glob'ы и rescan мог дать ошибку — повторим list-unit-files только чтобы отразить ошибку
        # (не влияет на expanded cache в этом месте)
        if self.cfg.systemd_unit_globs:
            rc, _, err = _run_cmd(
                ["systemctl", "list-unit-files", "--type=service",
                    "--no-pager", "--no-legend"],
                timeout=15,
            )
            if rc != 0:
                cache["systemd"]["errors"].append(
                    {"cmd": "systemctl list-unit-files", "rc": rc, "err": err.strip()})

        for unit in units_to_check:
            if not self._allowed_unit(unit):
                continue
            info = _get_systemd_status(unit)
            cache["systemd"]["units"][unit] = info
            sig[f"systemd:{unit}"] = f"{info.get('active_state', '?')}/{info.get('sub_state', '?')}"

        # docker availability
        rc, _, _ = _run_cmd(["docker", "version"], timeout=6)
        cache["docker"]["available"] = (rc == 0)
        if rc != 0:
            return cache, sig

        for name in self.cfg.docker_containers:
            if not self._allowed_container(name):
                continue
            info = _get_docker_status(name)
            cache["docker"]["containers"][name] = info
            sig[f"docker:{name}"] = str(info.get("status") or "?")

        return cache, sig

    # ───────────── logs ─────────────

    @staticmethod
    def _sanitize_cursor_name(s: str) -> str:
        out = []
        for ch in (s or ""):
            if ch.isalnum() or ch in ("-", "_", "."):
                out.append(ch)
            else:
                out.append("_")
        return "".join(out)[:180] or "unnamed"

    def _cursor_path(self, kind: str, name: str) -> str:
        safe = self._sanitize_cursor_name(f"{kind}_{name}")
        return str(Path(CURSOR_DIR) / f"{safe}.cursor")

    def _cursor_lock(self, key: str) -> threading.Lock:
        with self._cursor_locks_guard:
            lk = self._cursor_locks.get(key)
            if lk is None:
                lk = threading.Lock()
                self._cursor_locks[key] = lk
            return lk

    def get_logs_systemd(
        self,
        unit: str,
        tail: int,
        since_seconds: int,
        mode: str = "tail",
        reset_cursor: bool = False,
        cursor: str = "",
    ) -> Dict[str, Any]:
        """
        mode:
          - "tail": клиент хранит cursor сам (через --show-cursor / --after-cursor)
          - "follow": сервер хранит cursor-file (journalctl --cursor-file).
        """
        if not self._allowed_unit(unit):
            return {"ok": False, "error": "unit is not allowed", "unit": unit}

        tail = max(10, min(tail, self.cfg.logs_max_tail))
        since_seconds = max(
            60, min(since_seconds, self.cfg.logs_max_since_seconds))
        mode = (mode or "tail").strip().lower()
        cursor = (cursor or "").strip()

        if mode == "follow":
            cursor_file = self._cursor_path("systemd", unit)
            cache_key = ("systemd_follow", unit, tail,
                         since_seconds, reset_cursor)
            cached = self._logs_cache.get(cache_key)
            if cached is not None:
                cached["cached"] = True
                return cached

            lk = self._cursor_lock(f"systemd:{unit}")
            with lk:
                if reset_cursor:
                    try:
                        if os.path.exists(cursor_file):
                            os.unlink(cursor_file)
                    except OSError:
                        pass

                file_exists = os.path.exists(cursor_file)

                if not file_exists:
                    cmd = [
                        "journalctl", "-u", unit,
                        "--no-pager", "-q", "-o", "short-iso",
                        "--cursor-file", cursor_file,
                        "--lines", str(tail),
                        "--since", f"-{since_seconds}s",
                    ]
                else:
                    cmd = [
                        "journalctl", "-u", unit,
                        "--no-pager", "-q", "-o", "short-iso",
                        "--cursor-file", cursor_file,
                        "--lines", f"+{tail}",
                    ]

                rc, out, err = _run_cmd(cmd, timeout=LOGS_CMD_TIMEOUT)

            resp = {
                "ok": rc == 0,
                "unit": unit,
                "mode": "follow",
                "cursor_file": os.path.basename(cursor_file),
                "cmd": " ".join(cmd),
                "rc": rc,
                "text": out if out else err,
            }
            self._logs_cache.put(cache_key, resp)
            return resp

        # tail mode
        after_cursor = cursor
        cache_key = ("systemd", unit, tail, since_seconds, after_cursor)
        cached = self._logs_cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            return cached

        cmd = [
            "journalctl", "-u", unit,
            "--no-pager", "-q", "-o", "short-iso",
            "--show-cursor",
            "--lines", str(tail),
        ]
        if after_cursor:
            cmd += ["--after-cursor", after_cursor]
        else:
            cmd += ["--since", f"-{since_seconds}s"]

        rc, out, err = _run_cmd(cmd, timeout=LOGS_CMD_TIMEOUT)

        cursor_out = ""
        text_out = out
        if out:
            lines = out.splitlines()
            if lines and lines[-1].lstrip().startswith("-- cursor:"):
                cursor_out = lines[-1].split(":",
                                             1)[1].strip() if ":" in lines[-1] else ""
                text_out = "\n".join(lines[:-1])
                if text_out:
                    text_out += "\n"

        resp = {
            "ok": rc == 0,
            "unit": unit,
            "mode": "tail",
            "cmd": " ".join(cmd),
            "rc": rc,
            "cursor": cursor_out,
            "text": text_out if text_out else err,
        }

        self._logs_cache.put(cache_key, resp)
        return resp

    def get_recent_systemd_logs(
        self,
        limit: int = RECENT_SYSTEMD_DEFAULT_LIMIT,
        units: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return the newest journal entries across selected monitored units.

        ``units=None`` applies the default exclusions. An explicit list may
        include those normally excluded services, but every name must still be
        present in the expanded configured allow-list.
        """
        limit = max(1, min(limit, RECENT_SYSTEMD_MAX_LIMIT))
        available_units = sorted({
            unit for unit in self._expand_units()
            if self._allowed_unit(unit)
        })
        available_set = set(available_units)

        if units is None:
            selected_units = [
                unit for unit in available_units
                if unit not in RECENT_SYSTEMD_EXCLUDED_UNITS
            ]
            requested_units: Optional[List[str]] = None
        else:
            requested_units = []
            requested_seen = set()
            for raw_unit in units:
                unit = str(raw_unit or "").strip()
                if not unit or unit in requested_seen:
                    continue
                requested_seen.add(unit)
                requested_units.append(unit)

            invalid_units = sorted(
                unit for unit in requested_units if unit not in available_set
            )
            if invalid_units:
                return {
                    "ok": False,
                    "error": "one or more units are not monitored",
                    "invalid_units": invalid_units,
                    "available_units": available_units,
                    "default_excluded_units": sorted(
                        RECENT_SYSTEMD_EXCLUDED_UNITS
                    ),
                }
            requested_set = set(requested_units)
            selected_units = [
                unit for unit in available_units if unit in requested_set
            ]

        excluded_units = [
            unit for unit in available_units if unit not in set(selected_units)
        ]

        if not selected_units:
            return {
                "ok": True,
                "items": [],
                "units": [],
                "available_units": available_units,
                "requested_units": requested_units,
                "excluded_units": excluded_units,
                "default_excluded_units": sorted(
                    RECENT_SYSTEMD_EXCLUDED_UNITS
                ),
                "limit": limit,
            }

        cache_key = ("systemd_recent", tuple(selected_units), limit)
        cached = self._logs_cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            return cached

        cmd = ["journalctl"]
        for unit in selected_units:
            cmd.extend(["-u", unit])
        cmd.extend([
            "--no-pager",
            "-q",
            "-o", "json",
            "--lines", str(limit),
            "--reverse",
        ])

        rc, out, err = _run_cmd(cmd, timeout=LOGS_CMD_TIMEOUT)
        items: List[Dict[str, Any]] = []
        if rc == 0:
            for raw_line in out.splitlines():
                try:
                    record = json.loads(raw_line)
                except (TypeError, ValueError):
                    continue

                message = record.get("MESSAGE", "")
                if not isinstance(message, str):
                    message = json.dumps(message, ensure_ascii=False)

                timestamp = ""
                try:
                    timestamp = datetime.fromtimestamp(
                        int(record.get("__REALTIME_TIMESTAMP") or 0) / 1_000_000,
                        tz=timezone.utc,
                    ).isoformat(timespec="seconds")
                except (TypeError, ValueError, OSError, OverflowError):
                    pass

                priority: Optional[int]
                try:
                    priority = int(record.get("PRIORITY"))
                except (TypeError, ValueError):
                    priority = None

                items.append({
                    "ts_utc": timestamp,
                    "unit": (
                        record.get("_SYSTEMD_UNIT")
                        or record.get("UNIT")
                        or record.get("OBJECT_SYSTEMD_UNIT")
                        or record.get("SYSLOG_IDENTIFIER")
                        or "systemd"
                    ),
                    # Do not name this field ``message``: the web application's
                    # JSON localization hook intentionally translates UI
                    # messages under that key. Journal text must stay raw.
                    "raw_message": message[:4000],
                    "priority": priority,
                })

        resp = {
            "ok": rc == 0,
            "items": items,
            "units": selected_units,
            "available_units": available_units,
            "requested_units": requested_units,
            "excluded_units": excluded_units,
            "default_excluded_units": sorted(
                RECENT_SYSTEMD_EXCLUDED_UNITS
            ),
            "limit": limit,
            "cmd": " ".join(cmd),
            "rc": rc,
            "error": "" if rc == 0 else (err.strip() or "journalctl failed"),
        }
        self._logs_cache.put(cache_key, resp)
        return resp

    def get_logs_docker(self, container: str, tail: int, since_seconds: int) -> Dict[str, Any]:
        if not self._allowed_container(container):
            return {"ok": False, "error": "container is not allowed", "container": container}

        tail = max(10, min(tail, self.cfg.logs_max_tail))
        since_seconds = max(
            60, min(since_seconds, self.cfg.logs_max_since_seconds))

        cache_key = ("docker", container, tail, since_seconds)
        cached = self._logs_cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            return cached

        cmd = ["docker", "logs", "--since",
               f"{since_seconds}s", "--tail", str(tail), container]
        rc, out, err = _run_cmd(cmd, timeout=LOGS_CMD_TIMEOUT)

        resp = {
            "ok": rc == 0,
            "container": container,
            "cmd": " ".join(cmd),
            "rc": rc,
            "text": out if out else err,
        }

        self._logs_cache.put(cache_key, resp)
        return resp


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "haproxy-healthd/1.3"

    def _peer(self) -> str:
        ca = getattr(self, "client_address", None)
        if isinstance(ca, tuple):
            try:
                host = ca[0]
                return str(host) if host else "unix"
            except Exception:
                return "unix"
        if isinstance(ca, str):
            return ca or "unix"
        return "unix"

    def address_string(self) -> str:  # noqa: N802
        return self._peer()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        try:
            msg = fmt % args
        except Exception:
            msg = fmt
        LOG.info("%s - %s", self._peer(), msg)

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False,
                          indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        st: _State = self.server.state  # type: ignore[attr-defined]
        url = urlparse(self.path)
        path = url.path
        qs = parse_qs(url.query or "", keep_blank_values=True)

        if path == "/api/v1/health/ping":
            self._send_json(200, {"ok": True, "ts_utc": _utc_now_iso()})
            return

        if path == "/api/v1/control/capabilities":
            caps_systemd: Dict[str, Any] = {}
            for u in st.cfg.systemd_units:
                caps_systemd[u] = list(_control_allowed_actions("systemd", u))
            for g in st.cfg.systemd_unit_globs:
                caps_systemd[g] = list(_control_allowed_actions("systemd", g))
            caps_docker: Dict[str, Any] = {c: list(_control_allowed_actions(
                "docker", c)) for c in st.cfg.docker_containers}
            self._send_json(
                200, {"ok": True, "systemd": caps_systemd, "docker": caps_docker})
            return

        if path == "/api/v1/health/status":
            refresh = (qs.get("refresh", ["0"])[0] == "1")
            try:
                data = st.snapshot(refresh=refresh)
                self._send_json(200, data)
            except Exception as e:  # pylint: disable=broad-except
                self._send_json(500, {"ok": False, "error": str(e)})
            return

        if path == "/api/v1/health/events":
            limit = _clamp_int(qs.get("limit", [None])[
                               0], default=50, min_v=1, max_v=500)
            self._send_json(
                200, {"ok": True, "items": st.events_snapshot(limit)})
            return

        if path == "/api/v1/health/logs/systemd":
            unit = (qs.get("unit", [""])[0] or "").strip()
            tail = _clamp_int(qs.get("tail", [None])[
                              0], default=st.cfg.logs_default_tail, min_v=10, max_v=st.cfg.logs_max_tail)
            since = _clamp_int(qs.get("since", [None])[
                               0], default=st.cfg.logs_default_since_seconds, min_v=60, max_v=st.cfg.logs_max_since_seconds)
            if not unit:
                self._send_json(
                    400, {"ok": False, "error": "unit is required"})
                return

            mode = (qs.get("mode", ["tail"])[0] or "tail").strip().lower()
            reset_cursor = (qs.get("reset_cursor", ["0"])[0] == "1")
            cursor = (qs.get("cursor", [""])[0] or "").strip()

            self._send_json(200, st.get_logs_systemd(
                unit, tail=tail, since_seconds=since, mode=mode, reset_cursor=reset_cursor, cursor=cursor))
            return

        if path == "/api/v1/health/recent-systemd":
            limit = _clamp_int(
                qs.get("limit", [None])[0],
                default=RECENT_SYSTEMD_DEFAULT_LIMIT,
                min_v=1,
                max_v=RECENT_SYSTEMD_MAX_LIMIT,
            )
            units = _parse_recent_systemd_units(qs)
            data = st.get_recent_systemd_logs(limit=limit, units=units)
            self._send_json(200 if data.get("ok") else 400, data)
            return

        if path == "/api/v1/health/logs/docker":
            container = (qs.get("container", [""])[0] or "").strip()
            tail = _clamp_int(qs.get("tail", [None])[
                              0], default=st.cfg.logs_default_tail, min_v=10, max_v=st.cfg.logs_max_tail)
            since = _clamp_int(qs.get("since", [None])[
                               0], default=st.cfg.logs_default_since_seconds, min_v=60, max_v=st.cfg.logs_max_since_seconds)
            if not container:
                self._send_json(
                    400, {"ok": False, "error": "container is required"})
                return
            self._send_json(200, st.get_logs_docker(
                container, tail=tail, since_seconds=since))
            return

        self._send_json(404, {"ok": False, "error": "not found"})

    def _control_auth_ok(self) -> bool:
        if not CONTROL_TOKEN:
            return False
        token = (self.headers.get("X-Healthd-Token", "") or "").strip()
        return hmac.compare_digest(token, CONTROL_TOKEN)

    def do_POST(self) -> None:  # noqa: N802
        st: _State = self.server.state  # type: ignore[attr-defined]
        url = urlparse(self.path)
        path = url.path

        if path != "/api/v1/control":
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        if not self._control_auth_ok():
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return

        try:
            length = int(
                (self.headers.get("Content-Length") or "0").strip() or "0")
        except Exception:
            length = 0

        if length <= 0 or length > 16384:
            self._send_json(
                400, {"ok": False, "error": "invalid Content-Length"})
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except Exception as e:
            self._send_json(400, {"ok": False, "error": f"bad json: {e}"})
            return

        kind = (payload.get("kind") or "").strip().lower()
        name = (payload.get("name") or "").strip()
        action = (payload.get("action") or "").strip().lower()

        if kind not in {"systemd", "docker"}:
            self._send_json(
                400, {"ok": False, "error": "kind must be systemd|docker"})
            return
        if not name:
            self._send_json(400, {"ok": False, "error": "name is required"})
            return
        if action not in {"start", "stop", "restart", "reload"}:
            self._send_json(
                400, {"ok": False, "error": "action must be start|stop|restart|reload"})
            return

        if kind == "systemd" and not st._allowed_unit(name):
            self._send_json(403, {"ok": False, "error": "unit not allowed"})
            return
        if kind == "docker" and not st._allowed_container(name):
            self._send_json(
                403, {"ok": False, "error": "container not allowed"})
            return

        allowed = set(_control_allowed_actions(kind, name))
        if action not in allowed:
            self._send_json(
                403, {"ok": False, "error": "action not allowed", "allowed": sorted(allowed)})
            return

        if kind == "systemd":
            cmd = ["systemctl", action, name]

            # self-restart async
            if action == "restart" and _unit_base(name) == _unit_base(HEALTHD_UNIT):
                def _restart_self() -> None:
                    time.sleep(0.2)
                    _run_cmd(cmd, timeout=30)

                threading.Thread(target=_restart_self, daemon=True).start()
                with st.lock:
                    st.events.append({"ts_utc": _utc_now_iso(
                    ), "kind": "control", "name": f"{kind}:{name}", "from": "-", "to": f"{action} scheduled"})
                self._send_json(202, {"ok": True, "scheduled": True, "kind": kind,
                                "name": name, "action": action, "cmd": " ".join(cmd)})
                return

            rc, out, err = _run_cmd(cmd, timeout=30)
        else:
            cmd = ["docker", action, name]
            rc, out, err = _run_cmd(cmd, timeout=60)

        ok = (rc == 0)
        with st.lock:
            st.events.append({"ts_utc": _utc_now_iso(), "kind": "control",
                             "name": f"{kind}:{name}", "from": "-", "to": f"{action} rc={rc}"})

        self._send_json(200 if ok else 500, {
            "ok": ok,
            "kind": kind,
            "name": name,
            "action": action,
            "cmd": " ".join(cmd),
            "rc": rc,
            "stdout": out,
            "stderr": err,
        })


class HealthServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: str, handler_cls: type[BaseHTTPRequestHandler], state: _State):
        super().__init__(socket_path, handler_cls)
        self.state = state  # type: ignore[assignment]


def _set_socket_perms(sock_path: str, group_name: str) -> None:
    gid = grp.getgrnam(group_name).gr_gid
    uid = pwd.getpwnam("root").pw_uid
    os.chown(sock_path, uid, gid)
    os.chmod(sock_path, 0o660)


# ---------------------------------------------------------------------------
# Per-site availability email alerts.
#
# Sites opt in through websites.yml (edited in the web UI):
#   alert_enabled: true            # default false
#   alert_mode: down | degraded    # degraded also alerts on partial outages
#   alert_after: 5m                # continuous downtime before the alert
#   alert_email: ops@example.com   # optional per-site recipient override
#
# Mail is delivered exactly like certificate notifications: through the
# mail_relay container using the shared /etc/easy-ha-proxy/mail-notify.json
# state, so alerts are silently skipped while email delivery is disabled.
# ---------------------------------------------------------------------------

SITE_ALERTS_WEBSITES = os.getenv(
    "HAPADM_SITE_ALERTS_WEBSITES", "/opt/haproxy-admin/config/websites.yml"
)
SITE_ALERTS_INTERVAL = max(
    5.0, float(os.getenv("HAPADM_SITE_ALERTS_INTERVAL", "15"))
)
SITE_ALERTS_HAPROXY_SOCKET = os.getenv(
    "HAPADM_SITE_ALERTS_HAPROXY_SOCKET", "/run/haproxy/admin.sock"
)
SITE_ALERTS_MAIL_STATE = os.getenv(
    "HAPADM_SITE_ALERTS_MAIL_STATE", "/etc/easy-ha-proxy/mail-notify.json"
)
SITE_ALERTS_MAIL_LOCK = os.getenv(
    "HAPADM_SITE_ALERTS_MAIL_LOCK", "/run/easy-ha-proxy/authelia-mail.lock"
)
SITE_ALERTS_REPEAT_SECONDS = max(
    600, int(os.getenv("HAPADM_SITE_ALERTS_REPEAT_SECONDS", "21600"))
)

_INTERVAL_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}
_INTERVAL_VALUE_RE = re.compile(r"^([1-9][0-9]*)(ms|s|m|h|d)$")
_SITE_ID_RE = re.compile(r"[^A-Za-z0-9_]")
_ALERT_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$")


def _alert_after_seconds(value: object, default: float = 300.0) -> float:
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    match = _INTERVAL_VALUE_RE.fullmatch(str(value or "").strip())
    if not match:
        return default
    return int(match.group(1)) * _INTERVAL_UNIT_SECONDS[match.group(2)]


def _format_duration(seconds: float) -> str:
    """Render a downtime span as days/hours/minutes instead of raw minutes."""
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _format_servers(servers: List[Dict[str, Any]]) -> str:
    """One line per backend server: name, address:port when known, and state."""
    lines: List[str] = []
    for item in servers:
        addr = str(item.get("addr") or "").strip()
        state = "UP" if item.get("up") else "DOWN"
        if addr:
            lines.append(f"  - {item.get('name')} ({addr}): {state}")
        else:
            lines.append(f"  - {item.get('name')}: {state}")
    return "\n".join(lines)


def _haproxy_show_stat(socket_path: str) -> List[Dict[str, str]]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(socket_path)
        sock.sendall(b"show stat\n")
        chunks: List[bytes] = []
        total = 0
        while total < 8 * 1024 * 1024:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    text_out = b"".join(chunks).decode("utf-8", "replace")
    lines = [ln for ln in text_out.splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("# "):
        return []
    header = [h.strip() for h in lines[0][2:].split(",")]
    rows: List[Dict[str, str]] = []
    for line in lines[1:]:
        values = line.split(",")
        rows.append({header[i]: values[i] for i in range(min(len(header), len(values)))})
    return rows


class SiteAlertEngine(threading.Thread):
    def __init__(self) -> None:
        super().__init__(name="site-alerts", daemon=True)
        self._stop = threading.Event()
        # site name -> {"bad_since": float|None, "alerted_at": float|None,
        #               "alerted_state": str}
        self._incidents: Dict[str, Dict[str, Any]] = {}
        self._yaml = None
        try:
            import yaml as _yaml  # type: ignore

            self._yaml = _yaml
        except Exception:
            LOG.warning(
                "PyYAML is unavailable; per-site availability alerts are disabled"
            )

    def stop(self) -> None:
        self._stop.set()

    # -- configuration ------------------------------------------------------
    def _load_sites(self) -> List[Dict[str, Any]]:
        if self._yaml is None:
            return []
        try:
            with open(SITE_ALERTS_WEBSITES, "r", encoding="utf-8") as stream:
                data = self._yaml.safe_load(stream) or {}
        except FileNotFoundError:
            return []
        except Exception as exc:  # noqa: BLE001 - config must not kill healthd
            LOG.warning("site-alerts: cannot read %s: %s", SITE_ALERTS_WEBSITES, exc)
            return []
        sites = data.get("sites") if isinstance(data, dict) else None
        result: List[Dict[str, Any]] = []
        for site in sites or []:
            if isinstance(site, dict) and site.get("alert_enabled") is True:
                result.append(site)
        return result

    def _mail_state(self) -> Optional[Dict[str, str]]:
        try:
            with open(SITE_ALERTS_MAIL_STATE, "r", encoding="utf-8") as stream:
                state = json.load(stream)
        except Exception:
            return None
        if not isinstance(state, dict) or state.get("enabled") is not True:
            return None
        sender = str(state.get("from") or "")
        recipient = str(state.get("to") or "")
        if not _ALERT_EMAIL_RE.fullmatch(sender):
            return None
        return {"from": sender, "to": recipient}

    # -- evaluation ---------------------------------------------------------
    @staticmethod
    def _site_condition(
        site_id: str, rows: List[Dict[str, str]]
    ) -> Optional[Dict[str, Any]]:
        backend = f"be_{site_id}"
        servers_total = 0
        servers_up = 0
        servers: List[Dict[str, Any]] = []
        backend_up: Optional[bool] = None
        for row in rows:
            if row.get("pxname") != backend:
                continue
            svname = row.get("svname") or ""
            status = (row.get("status") or "").upper()
            if svname == "BACKEND":
                backend_up = not status.startswith("DOWN")
            elif svname != "FRONTEND":
                servers_total += 1
                is_up = status.startswith("UP") or status.startswith("NO CHECK")
                if is_up:
                    servers_up += 1
                servers.append(
                    {"name": svname, "addr": row.get("addr") or "", "up": is_up}
                )
        if backend_up is None:
            return None
        if backend_up is False or (servers_total > 0 and servers_up == 0):
            state = "down"
        elif servers_total > 0 and servers_up < servers_total:
            state = "degraded"
        else:
            state = "ok"
        return {
            "state": state,
            "up": servers_up,
            "total": servers_total,
            "servers": servers,
        }

    # -- delivery -----------------------------------------------------------
    def _send_mail(self, recipient: str, subject: str, body: str) -> bool:
        state = self._mail_state()
        if state is None:
            LOG.warning(
                "site-alerts: email delivery is disabled; alert not sent (%s)",
                subject,
            )
            return False
        sender = state["from"]
        to = recipient if _ALERT_EMAIL_RE.fullmatch(recipient) else state["to"]
        if not _ALERT_EMAIL_RE.fullmatch(to):
            LOG.warning("site-alerts: no valid recipient; alert not sent")
            return False
        message = (
            f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n"
        )
        lock_dir = os.path.dirname(SITE_ALERTS_MAIL_LOCK)
        try:
            os.makedirs(lock_dir, mode=0o750, exist_ok=True)
            with open(SITE_ALERTS_MAIL_LOCK, "a+b") as lock_file:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                proc = subprocess.run(
                    [
                        "/usr/bin/docker",
                        "exec",
                        "-i",
                        "mail_relay",
                        "/usr/sbin/sendmail",
                        "-i",
                        "-f",
                        sender,
                        "--",
                        to,
                    ],
                    input=message.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
        except Exception as exc:  # noqa: BLE001 - delivery is best effort
            LOG.warning("site-alerts: mail delivery failed: %s", exc)
            return False
        if proc.returncode != 0:
            LOG.warning(
                "site-alerts: mail_relay rejected the alert (exit %s)",
                proc.returncode,
            )
            return False
        return True

    # -- main loop ----------------------------------------------------------
    def run(self) -> None:
        if self._yaml is None:
            return
        while not self._stop.wait(SITE_ALERTS_INTERVAL):
            try:
                sites = self._load_sites()
                if not sites:
                    self._incidents.clear()
                    continue
                rows = _haproxy_show_stat(SITE_ALERTS_HAPROXY_SOCKET)
                if not rows:
                    continue
                seen: set = set()
                for site in sites:
                    name = str(site.get("name") or site.get("domain") or "")
                    if not name:
                        continue
                    seen.add(name)
                    condition = self._site_condition(
                        _SITE_ID_RE.sub("_", name), rows
                    )
                    if condition is None:
                        continue
                    self._evaluate(site, name, condition)
                for stale in set(self._incidents) - seen:
                    self._incidents.pop(stale, None)
            except Exception:  # noqa: BLE001 - the loop must survive anything
                LOG.exception("site-alerts: evaluation cycle failed")

    def _evaluate(
        self,
        site: Dict[str, Any],
        name: str,
        condition: Dict[str, Any],
    ) -> None:
        mode = str(site.get("alert_mode") or "down")
        triggers = {"down"} if mode == "down" else {"down", "degraded"}
        threshold = _alert_after_seconds(site.get("alert_after"))
        recipient = str(site.get("alert_email") or "")
        record = self._incidents.setdefault(
            name, {"bad_since": None, "alerted_at": None, "alerted_state": ""}
        )
        now = time.time()
        state = condition["state"]
        summary = f"Backend servers up: {condition['up']}/{condition['total']}\n"
        servers_block = _format_servers(condition.get("servers") or [])
        if servers_block:
            summary += servers_block + "\n"
        if state in triggers:
            if record["bad_since"] is None:
                record["bad_since"] = now
            elapsed = now - record["bad_since"]
            repeat_due = (
                record["alerted_at"] is not None
                and now - record["alerted_at"] >= SITE_ALERTS_REPEAT_SECONDS
            )
            if elapsed >= threshold and (record["alerted_at"] is None or repeat_due):
                label = "DOWN" if state == "down" else "PARTIALLY DOWN"
                sent = self._send_mail(
                    recipient,
                    f"[easy-ha-proxy] {name}: {label}",
                    (
                        f"Site: {name}\n"
                        f"State: {label.lower()} for {_format_duration(elapsed)}\n"
                        + summary
                    ),
                )
                if sent:
                    LOG.warning("site-alerts: alert sent for %s (%s)", name, state)
                    record["alerted_at"] = now
                    record["alerted_state"] = state
        else:
            if record["alerted_at"] is not None:
                self._send_mail(
                    recipient,
                    f"[easy-ha-proxy] {name}: RECOVERED",
                    (
                        f"Site: {name}\n"
                        "State: available again\n"
                        + summary
                    ),
                )
                LOG.info("site-alerts: recovery notice sent for %s", name)
            record["bad_since"] = None
            record["alerted_at"] = None
            record["alerted_state"] = ""


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    cfg = _load_config(CONFIG_PATH)
    state = _State(cfg)

    LOG.info(
        "Starting haproxy-healthd: socket=%s config=%s ttl=%ss background_poll=%s",
        SOCKET_PATH, CONFIG_PATH, cfg.cache_ttl_seconds, "1" if BACKGROUND_POLL else "0",
    )

    # Прогреваем кэш один раз при старте (по вашему запросу).
    try:
        state.force_refresh()
    except Exception:
        LOG.exception("Initial refresh failed")

    # Optional background polling
    state.start()

    site_alerts = SiteAlertEngine()
    site_alerts.start()

    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except OSError:
        pass

    server = HealthServer(SOCKET_PATH, HealthHandler, state)

    try:
        _set_socket_perms(SOCKET_PATH, SOCKET_GROUP)
    except Exception as e:
        LOG.warning("Failed to set socket permissions: %s", e)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted")
    finally:
        try:
            site_alerts.stop()
            state.stop()
        finally:
            try:
                server.server_close()
            finally:
                try:
                    if os.path.exists(SOCKET_PATH):
                        os.unlink(SOCKET_PATH)
                except OSError:
                    pass


if __name__ == "__main__":
    main()
