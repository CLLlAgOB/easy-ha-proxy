"""Constants, configuration history versioning, and cert bundle helpers."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import logging
import os
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Dict

# ───── configuration from the environment (with defaults) ─────

# HAProxy's admin socket (for show table)
SOCKET_PATH = os.environ.get("SOCKET_PATH", "/run/haproxy/admin.sock")
BAN_TABLE = os.environ.get("HAPADM_BAN_TABLE", "tbl_ban")
IPSET_NAME = os.environ.get("HAPADM_IPSET_NAME", "haproxy_ban")
# The first steps of adaptive bans (reason code 41), which HAProxy answers
# with a page. They stay in IPSET_NAME -- the UDP forwards drop every ban --
# and the TCP rule for 80/443 drops what is in IPSET_NAME and not in this
# set, so a first step reaches HAProxy and its page. A gateway whose rule
# does not know this set simply drops them as before.
PAGE_IPSET = os.environ.get("HAPADM_BAN_PAGE_IPSET", "haproxy_ban_page")
FIRST_STEP_PAGE_CODE = 41
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

# logs (for logs-ip)
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/haproxy.log").strip()
LOG_LIMIT = int(os.getenv("HAPADM_LOG_LIMIT", "30"))
BAN_DELTA_SECONDS = int(os.getenv("HAPADM_BAN_DELTA_SECONDS", "120"))
DEBUG_ON_EMPTY = os.getenv("HAPADM_DEBUG_ON_EMPTY",
                           "1") not in ("0", "false", "False", "")

# journalctl sources, in order of preference
JOURNAL_SOURCES = [s.strip() for s in os.getenv(
    "HAPADM_JOURNAL_SOURCES",
    "-u haproxy, SYSLOG_IDENTIFIER=haproxy, -u haproxy.service, -u rsyslog.service, *"
).split(",") if s.strip()]

# journalctl timeouts and limits (they keep logs-ip fast for a banned address)
JOURNAL_PER_SOURCE_TIMEOUT = float(os.getenv("HAPADM_JOURNAL_TIMEOUT", "3"))
JOURNAL_TOTAL_TIMEOUT = float(os.getenv("HAPADM_JOURNAL_TOTAL_TIMEOUT", "8"))
JOURNAL_USE_GREP = os.getenv("HAPADM_JOURNAL_USE_GREP", "1") not in ("0", "false", "False", "no", "")
JOURNAL_LINES_MULT = int(os.getenv("HAPADM_JOURNAL_LINES_MULT", "4"))

# the ban table's TTL (to save time: set it explicitly, or it is cached)
BAN_TTL_OVERRIDE_SECONDS = int(os.getenv("HAPADM_BAN_TTL_SECONDS", "0"))
BAN_TTL_CACHE_SECONDS = int(os.getenv("HAPADM_BAN_TTL_CACHE_SECONDS", "300"))

# a short cache of the logs-ip answer (so a repeated request does not run the heavy calls again)
LOGS_IP_CACHE_SECONDS = float(os.getenv("HAPADM_LOGS_IP_CACHE_SECONDS", "2"))

# reading the tail of LOG_FILE in Python (no tac|grep); how it is read
LOG_FILE_TAIL_CHUNK = int(os.getenv("HAPADM_LOG_FILE_TAIL_CHUNK", "65536"))   # bytes
# How much of the log's tail a search reads at most (0: the whole file). It
# used to be unlimited: an address that is not there read every byte, on a
# two-core gateway, for each request (F10, 30 October review).
LOG_FILE_TAIL_MAX_BYTES = int(os.getenv("HAPADM_LOG_FILE_TAIL_MAX_BYTES", str(64 * 1024 * 1024)))
# Log searches at once; more wait their turn.
_LOG_SCANS = threading.BoundedSemaphore(2)


def _line_has_ip(line: str, ip: str) -> bool:
    """The address itself, not one that starts with it: 203.0.113.1 used to
    find 203.0.113.10 and 203.0.113.100 as well."""
    return re.search(r"(?<![0-9A-Fa-f.:])" + re.escape(ip) + r"(?![0-9A-Fa-f])", line) is not None
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

# --- Configuration history -------------------------------------------------
#
# The guarded transaction already carries the managed sources so it can roll a
# failed apply back, but it discards them once the change is confirmed. Keeping
# a copy of every confirmed version is what turns "undo the last apply" into
# "see what changed last Tuesday, and put that back".
CONFIG_HISTORY_DIR = Path(os.getenv(
    "HAPROXY_CONFIG_HISTORY_DIR",
    "/var/lib/easy-ha-proxy/config-history",
))


# The alert client lives beside this script in /usr/local/sbin, which is
# sys.path[0] for a daemon started by absolute path. Optional on purpose: the
# gateway still applies configuration without the alert daemon.
try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - the daemon runs without it
    AlertClient = None  # type: ignore[assignment]

_ALERTS = None
if AlertClient is not None:
    _candidate = AlertClient(source="controld")
    _ALERTS = _candidate if _candidate.configured else None


def report_alert(rule: str, subject: str, summary: str, detail: str = "") -> None:
    """Tell the alert engine something failed. Never disturbs the operation."""
    if _ALERTS is None:
        return
    try:
        _ALERTS.observe(rule, subject, summary=summary, detail=detail)
    except Exception:  # noqa: BLE001 - reporting is best effort
        pass
CONFIG_HISTORY_KEEP = int(os.getenv("HAPROXY_CONFIG_HISTORY_KEEP", "50"))
CONFIG_HISTORY_META = "meta.json"
ADMIN_ALLOWLIST_PATH = Path(os.getenv(
    "HAPROXY_ADMIN_ALLOWLIST_PATH", "/etc/haproxy/admin.allow"
))
ADMIN_ALLOWLIST_MAX_ENTRIES = 256
ADMIN_ALLOWLIST_MAX_BYTES = 64 * 1024
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
# UDP failover: a forward with a backup backend is moved to it when its main
# backend stops answering, and back once the main one has answered for a while.
UDP_FAILOVER_STATE = Path(os.getenv("HP_UDP_FAILOVER", "/run/easy-ha-proxy/udp-failover.json"))
UDP_FAILOVER_STATE_MAX_BYTES = 64 * 1024
UDP_CONFIG = Path(os.getenv("HP_UDP_CONFIG", "/opt/haproxy-admin/config/udp.yml"))
UDP_GENERATOR = os.getenv("HP_UDP_GENERATOR", "/usr/local/sbin/haproxy-udp-forward.py")
UDP_HEALTH_INTERVAL = max(2, int(os.getenv("HP_UDP_HEALTH_INTERVAL", "5")))
# Three missed checks in a row (fifteen seconds) move a forward to its backup;
# six good ones in a row (thirty seconds) bring it back. The gap keeps a main
# backend that answers one check in two from flapping.
UDP_FAIL_AFTER = 3
UDP_RECOVER_AFTER = 6
UDP_FAILOVER_RULE = "udp.failover"
UDP_FAILOVER_REPORT_SECONDS = 300
# A switch whose rules could not be applied is tried again this often, until
# it is in effect: the state file already says "backup" by then, so without a
# retry nothing would ever apply it.
UDP_APPLY_RETRY_SECONDS = 30
MAX_ARCHIVE_BYTES = int(os.getenv("HAPADM_MAX_ARCHIVE_BYTES", str(64 * 1024 * 1024)))
MAX_ARCHIVE_FILES = int(os.getenv("HAPADM_MAX_ARCHIVE_FILES", "4096"))
MAX_ARCHIVE_EXPANDED_BYTES = int(
    os.getenv("HAPADM_MAX_ARCHIVE_EXPANDED_BYTES", str(256 * 1024 * 1024))
)
MAX_COMPRESSION_RATIO = int(os.getenv("HAPADM_MAX_COMPRESSION_RATIO", "100"))


# the background synchronisation interval
try:
    INTERVAL = int(os.environ.get("HAPADM_BAN_SYNC_INTERVAL", "10"))
except ValueError:
    INTERVAL = 10

# the control socket (for reload, sync-bans, logs, backup, restore and the rest)
CONTROL_SOCKET = os.environ.get(
    "HAPROXY_CONTROL_SOCKET",
    "/run/easy-ha-proxy/haproxy-controld.sock",
)

# the command that reloads HAProxy
SYSTEMCTL_CMD = os.environ.get(
    "HAPROXY_SYSTEMCTL_CMD",
    "systemctl reload haproxy",
)
HAPROXY_BIN = "/usr/sbin/haproxy"

# How long a command may run. Each keeps a thread of this daemon -- the ban
# sync loop or a control request -- for as long as it runs. systemd fails a
# reload job by itself after 90 seconds, so the reload limit only catches a
# systemctl that hangs past that.
IPSET_TIMEOUT_SECONDS = 15
HAPROXY_CHECK_TIMEOUT_SECONDS = 30
HAPROXY_RELOAD_TIMEOUT_SECONDS = 120

LOG = logging.getLogger("haproxy-controld")

# ───── small caches, so heavy commands are not run too often ─────
_BAN_TTL_CACHE_LOCK = threading.Lock()
_BAN_TTL_CACHE_VALUE: int | None = None
_BAN_TTL_CACHE_TS: float = 0.0

_LOGS_IP_CACHE_LOCK = threading.Lock()
# key: (ip, limit) -> (expires_epoch, lines)
_LOGS_IP_CACHE: dict[tuple[str, int], tuple[float, list[str]]] = {}
_GUARDED_APPLY_LOCK = threading.Lock()
_GEOIP_OPERATION_LOCK = threading.Lock()



# ───── helpers ─────

def run_cmd(args, input_data: str | None = None, *, timeout: float) -> subprocess.CompletedProcess:
    """
    subprocess.run with a time limit; a non-zero exit raises RuntimeError.
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


class UdpFailover:
    """Which backend each UDP forward with a backup sends to, and why.

    The forwards to check come from the generator itself (--health-targets),
    read again only when udp.yml changes, so its rules decide what a backup
    is. A switch is written to UDP_FAILOVER_STATE and the generator run again;
    the conntrack entries of flows to the backend left behind are removed so
    those clients move at once instead of after the UDP timeout.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.targets: list[dict] = []
        self.config_key: "tuple | None" = None
        self.state: Dict[str, dict] = {}
        self.error: "str | None" = None
        self.reported: Dict[str, float] = {}
        self.conntrack_missing = False
        # Switches written to the state file but not confirmed in effect:
        # name -> (side wanted, target). Once an apply has failed nobody knows
        # where the rules send -- the generator replaces them before it writes
        # its status, and a timed-out systemctl proves nothing -- so a switch
        # back does not cancel anything: only a successful apply settles it.
        self.pending: Dict[str, tuple] = {}
        self.apply_error: "str | None" = None
        self.retry_at = 0.0
        self._initialized = False
        self._reconcile_pending = False

    # -- reading ----------------------------------------------------------
    def _startup_state(self) -> tuple[dict[str, str], bool]:
        """Recover the desired sides, without treating them as applied rules.

        A controller restart leaves the firewall and this file in place. A
        previous command may have failed after changing rules, so a saved
        state (including an empty one) needs a confirmed apply on startup.
        """
        try:
            with UDP_FAILOVER_STATE.open(encoding="utf-8") as handle:
                raw = handle.read(UDP_FAILOVER_STATE_MAX_BYTES + 1)
            if len(raw) > UDP_FAILOVER_STATE_MAX_BYTES:
                raise ValueError("state exceeds the size limit")
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("active"), dict):
                raise ValueError("invalid state schema")
            active = data["active"]
            if any(not isinstance(name, str) or side not in ("primary", "backup") for name, side in active.items()):
                raise ValueError("invalid saved backend side")
            return {name: side for name, side in active.items() if side == "backup"}, True
        except FileNotFoundError:
            return {}, False
        except (OSError, ValueError) as exc:
            LOG.warning("UDP failover state could not be recovered; reconciling the current configuration: %s", exc)
            return {}, True

    def load_targets(self) -> list[dict]:
        try:
            info = UDP_CONFIG.stat()
            key = (info.st_ino, info.st_mtime_ns, info.st_size)
        except OSError:
            self.targets, self.config_key = [], None
            return self.targets
        if key == self.config_key:
            return self.targets
        try:
            proc = run_cmd(["/usr/bin/python3", UDP_GENERATOR, "--config", str(UDP_CONFIG), "--health-targets"],
                           timeout=30)
            targets = json.loads(proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "[]")
            if not isinstance(targets, list):
                raise ValueError("not a list")
        except (RuntimeError, OSError, ValueError, IndexError, subprocess.TimeoutExpired) as exc:
            # Keep checking what was read last; say why the new file was not.
            self.error = f"udp.yml could not be read for failover: {str(exc)[:300]}"
            LOG.warning("%s", self.error)
            return self.targets
        self.targets, self.config_key, self.error = targets, key, None
        return self.targets

    # -- checking ---------------------------------------------------------
    @staticmethod
    def probe(ip: "str | None", check: str, port: "int | None") -> bool:
        if not ip:
            return False
        if check == "tcp":
            try:
                with socket.create_connection((ip, int(port or 0)), timeout=2):
                    return True
            except OSError:
                return False
        try:
            run_cmd(["ping", "-n", "-q", "-c", "1", "-W", "1", ip], timeout=4)
            return True
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            return False

    def tick(self, now: "float | None" = None) -> list[tuple]:
        """Check every forward with a backup once; returns the switches made."""
        now = time.time() if now is None else now
        with self.lock:
            targets = self.load_targets()
            startup_active: dict[str, str] = {}
            startup_sync = False
            if not self._initialized:
                # Do not overwrite a saved choice while the configuration
                # needed to interpret it is temporarily unreadable.
                if self.error:
                    return []
                startup_active, startup_sync = self._startup_state()
                self._reconcile_pending = startup_sync
                self._initialized = True
            switches = []
            names = set()
            for target in targets:
                name = str(target.get("name") or "")
                if not name:
                    continue
                names.add(name)
                entry = self.state.setdefault(name, {"active": startup_active.get(name, "primary"), "since": now, "fails": 0, "oks": 0})
                if self._reconcile_pending:
                    self.pending[name] = (entry["active"], target)
                primary_ok = self.probe(target.get("primary"), target.get("check", "ping"), target.get("health_port"))
                backup_ok = self.probe(target.get("backup"), target.get("check", "ping"), target.get("health_port"))
                entry.update(primary_ok=primary_ok, backup_ok=backup_ok, checked_at=now,
                             primary=target.get("primary"), backup=target.get("backup"))
                if entry["active"] == "primary":
                    entry["fails"] = 0 if primary_ok else entry["fails"] + 1
                    if entry["fails"] >= UDP_FAIL_AFTER and backup_ok:
                        switches.append((name, "primary", "backup", target))
                else:
                    entry["oks"] = entry["oks"] + 1 if primary_ok else 0
                    # Back at once when the backup stops answering and the main one answers.
                    if entry["oks"] >= UDP_RECOVER_AFTER or (primary_ok and not backup_ok):
                        switches.append((name, "backup", "primary", target))
            for gone in set(self.state) - names:
                self.state.pop(gone)
                self.pending.pop(gone, None)
                self._report(gone, False, "", now, force=True)
            if switches or startup_sync or self._file_out_of_step():
                for name, _old, new, target in switches:
                    self.state[name].update(active=new, since=now, fails=0, oks=0)
                    self.pending[name] = (new, target)
                self._write_state()
            if (self.pending or self._reconcile_pending) and (switches or now >= self.retry_at):
                self._apply(now)
            for name, entry in self.state.items():
                self._report(name, entry["active"] == "backup", self._detail(name, entry), now,
                             force=any(item[0] == name for item in switches))
            return switches

    # -- acting -----------------------------------------------------------
    def _file_out_of_step(self) -> bool:
        wanted = {name: "backup" for name, entry in self.state.items() if entry["active"] == "backup"}
        try:
            data = json.loads(UDP_FAILOVER_STATE.read_text(encoding="utf-8"))
            current = data.get("active") if isinstance(data, dict) else None
        except (OSError, ValueError):
            current = None
        return (current or {}) != wanted

    def _write_state(self) -> None:
        payload = {"version": 1,
                   "active": {name: "backup" for name, entry in self.state.items() if entry["active"] == "backup"}}
        UDP_FAILOVER_STATE.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".udp-failover.", dir=str(UDP_FAILOVER_STATE.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, UDP_FAILOVER_STATE)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def _apply(self, now: float) -> None:
        """Apply the rules for every pending switch; kept pending on failure."""
        for name, (new, _target) in self.pending.items():
            LOG.warning("UDP forward %s: sending to its %s backend", name, new)
        try:
            run_cmd(["systemctl", "restart", "iptables-haproxy-udp.service"], timeout=60)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            LOG.error("UDP failover could not apply the rules: %s", exc)
            self.apply_error = f"the switch could not be applied: {str(exc)[:300]}"
            self.retry_at = now + UDP_APPLY_RETRY_SECONDS
            return
        done, self.pending, self.apply_error = self.pending, {}, None
        self._reconcile_pending = False
        for _name, (new, target) in done.items():
            # Flows to the side not wanted, wherever the rules sent before.
            left = target.get("backup" if new == "primary" else "primary")
            if not left:
                continue
            # Flows already set up keep their old destination until the
            # conntrack entry times out; removing them moves clients now.
            try:
                run_cmd(["conntrack", "-D", "-p", "udp", "--reply-src", str(left)], timeout=10)
            except FileNotFoundError:
                if not self.conntrack_missing:
                    LOG.warning("conntrack is not installed: existing UDP flows move after their timeout")
                self.conntrack_missing = True
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                pass  # "0 flow entries have been deleted" exits 1

    def _detail(self, name: str, entry: dict) -> str:
        if entry["active"] == "backup":
            return (f"The main backend {entry.get('primary')} of UDP forward {name} stopped answering; "
                    f"traffic goes to the backup {entry.get('backup')} until the main one answers again.")
        return ""

    def _report(self, name: str, active: bool, detail: str, now: float, *, force: bool = False) -> None:
        if _ALERTS is None:
            return
        if not force and now - self.reported.get(name, 0) < UDP_FAILOVER_REPORT_SECONDS:
            return
        self.reported[name] = now
        try:
            _ALERTS.observe(UDP_FAILOVER_RULE, name, active=active,
                            summary=f"UDP forward {name} runs on its backup backend", detail=detail)
        except Exception:  # pylint: disable=broad-except
            LOG.debug("udp failover alert failed", exc_info=True)

    def public_state(self) -> dict:
        with self.lock:
            return {
                "error": self.error or self.apply_error,
                "forwards": {
                    name: {**{key: entry.get(key) for key in
                              ("active", "since", "primary_ok", "backup_ok", "checked_at", "primary", "backup")},
                           # "active" is what is wanted; this says it is not in effect yet.
                           "apply_pending": name in self.pending}
                    for name, entry in self.state.items()
                },
            }


UDP_FAILOVER = UdpFailover()


def udp_failover_loop() -> None:
    LOG.info("UDP failover loop started: interval=%ss", UDP_HEALTH_INTERVAL)
    while True:
        try:
            UDP_FAILOVER.tick()
        except Exception:  # pylint: disable=broad-except
            LOG.exception("UDP failover check failed")
        time.sleep(UDP_HEALTH_INTERVAL)


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


# ───── certificates ─────

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
    Builds a ZIP of CERTS_HAP_DIR and CERTS_LE_DIR
    and returns it as a base64 string.
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

        # 2) /etc/letsencrypt (if set)
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


_CERTBOT_HOOK_KEY_RE = re.compile(
    r"^\s*(?:pre|post|deploy|renew|manual_auth|manual_cleanup)[_-]hook\s*=",
    re.IGNORECASE | re.MULTILINE,
)
_ALLOWED_LE_RESTORE_DIRS = frozenset({"accounts", "archive", "live", "renewal", "keys", "csr"})


def _is_allowed_le_restore_rel(rel: Path) -> bool:
    parts = rel.parts
    if len(parts) < 2:
        return False
    top = parts[0]
    if top not in _ALLOWED_LE_RESTORE_DIRS:
        return False
    if top == "renewal":
        return len(parts) == 2 and parts[1].endswith(".conf") and not parts[1].startswith(".")
    return True


def certs_restore_b64(b64: str) -> str:
    """
    Takes a base64 ZIP and unpacks its files into CERTS_HAP_DIR and CERTS_LE_DIR.
    Returns a text message for the log or the answer.
    """
    raw = base64.b64decode(b64, validate=True)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("certificate archive exceeds the allowed size")
    buf = io.BytesIO(raw)
    hap_dir = Path(CERTS_HAP_DIR)
    le_root = Path(CERTS_LE_DIR) if CERTS_LE_DIR else None

    restored = 0
    remaining_budget = MAX_ARCHIVE_EXPANDED_BYTES

    with zipfile.ZipFile(buf, "r") as zf:
        for info in _validate_zip(zf):
            name = info.filename
            if info.is_dir():
                continue

            is_le_renewal = False
            if name.startswith("haproxy_certs/"):
                rel = Path(name).relative_to("haproxy_certs")
                if len(rel.parts) != 1 or not rel.name.endswith(".pem") or rel.name.startswith("."):
                    continue
                dst = _ensure_within(hap_dir, hap_dir / rel)
            elif name.startswith("letsencrypt/") and le_root:
                rel = Path(name).relative_to("letsencrypt")
                if not _is_allowed_le_restore_rel(rel):
                    continue
                is_le_renewal = rel.parts[0] == "renewal"
                dst = _ensure_within(le_root, le_root / rel)
            else:
                # an unknown prefix is ignored
                continue

            chunks: list[bytes] = []
            read_total = 0
            with zf.open(info, "r") as src:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    read_total += len(chunk)
                    if read_total > remaining_budget:
                        raise ValueError("certificate archive expands beyond the allowed size")
                    chunks.append(chunk)
            if read_total != info.file_size:
                raise ValueError("certificate archive entry size mismatch")
            remaining_budget -= read_total
            payload = b"".join(chunks)
            if is_le_renewal and _CERTBOT_HOOK_KEY_RE.search(payload.decode("utf-8", errors="replace")):
                LOG.warning("certs-restore: refused renewal config with hook directive: %s", rel)
                continue

            dst.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb") as out:
                    fd = -1
                    out.write(payload)
                    out.flush()
                    os.fsync(out.fileno())
            finally:
                if fd != -1:
                    os.close(fd)
            restored += 1

    msg = f"restored {restored} files"
    LOG.info("certs-restore: %s", msg)
    return msg
