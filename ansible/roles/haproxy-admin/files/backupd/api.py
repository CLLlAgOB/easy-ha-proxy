"""Scheduled backup timer management, Unix-socket server, and CLI entrypoint."""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import constants as _constants
from .constants import (
    BackupdError,
    CONNECTION_SLOTS,
    LIST_LIMIT,
    LOG,
    MAX_REQUEST_BYTES,
    OPERATION_THREAD_LOCK,
    REQUEST_FIELDS,
    SHUTDOWN_REQUESTED,
    SOCKET_PATH,
    SOURCE_DIR,
    STOP_EVENT,
    TERMINAL_STATUSES,
    atomic_json,
    cleanup_stale_worker_artifacts,
    ensure_layout,
    load_job,
    recover_stale_jobs,
    report_alert,
    require_passphrase,
    safe_json_file,
    utc_now,
)
from .jobs import (
    SYSTEMCTL_PATH,
    acquire_operation,
    local_storage,
    prune_local_backups,
    release_operation,
    systemctl_properties,
)
from .operations import (
    delete_item,
    expire_orphaned_uploads,
    stage_backup,
    start_backup,
    start_inspect,
    start_restore,
    status_response,
)
from .destinations import (
    SCHEDULED_BACKUP_TIMEOUT,
    delete_destination,
    list_destinations,
    load_destination,
    retrust_destination,
    save_destination,
    test_destination,
    upload_backup,
    write_private,
)

# ---------------------------------------------------------------------------
# The scheduled copy
# ---------------------------------------------------------------------------
#
# An unattended backup has to encrypt with something, and the only place that
# something can live is this host. That is a real weakening and it is stated
# plainly rather than hidden: the stored passphrase protects the archive
# wherever it is *sent*, not against someone who already owns the gateway.
# Without a stored passphrase the schedule refuses to run rather than making a
# weaker archive on its own initiative.

SCHEDULE_PATH = Path(
    os.environ.get("BACKUPD_SCHEDULE", "/etc/easy-ha-proxy/backup-schedule.json")
)
SCHEDULE_PASSPHRASE_PATH = Path(
    os.environ.get(
        "BACKUPD_SCHEDULE_PASSPHRASE", "/etc/easy-ha-proxy/backup-schedule.key"
    )
)

# The hour is systemd's business, not this file's: the timer is what actually
# wakes the job, so changing the time means rewriting the timer and reloading
# it. A drop-in keeps the packaged unit intact -- and clears OnCalendar before
# setting it, because systemd treats the setting as a list and would otherwise
# fire at both the old time and the new one.
BACKUP_TIMER_UNIT = "easy-ha-proxy-backup.timer"
TIMER_DROPIN_DIR = Path(
    os.environ.get(
        "BACKUPD_TIMER_DROPIN",
        "/etc/systemd/system/easy-ha-proxy-backup.timer.d",
    )
)
TIMER_DROPIN_PATH = TIMER_DROPIN_DIR / "schedule.conf"
DEFAULT_SCHEDULE_TIME = "03:20"
_TIME_RE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")


def schedule_time(value: Any, *, default: str = DEFAULT_SCHEDULE_TIME) -> str:
    """A 24-hour HH:MM, or the default. Never anything systemd could choke on."""
    text = str(value or "").strip()
    if not text:
        return default
    if not _TIME_RE.fullmatch(text):
        raise BackupdError(
            "the time must be given as HH:MM on a 24-hour clock", code="invalid"
        )
    return text


def write_timer_time(value: str) -> None:
    """Point the timer at a new hour and make systemd notice."""
    TIMER_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TIMER_DROPIN_DIR, 0o755)
    body = "\n".join(
        (
            "# Written by easy-ha-proxy-backupd from the Backups page.",
            "# The empty OnCalendar clears the packaged one; without it",
            "# systemd would keep both and run the backup twice.",
            "[Timer]",
            "OnCalendar=",
            f"OnCalendar=*-*-* {value}:00",
            "",
        )
    )
    temporary = TIMER_DROPIN_PATH.with_suffix(".conf.tmp")
    temporary.write_text(body, encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, TIMER_DROPIN_PATH)
    for command in (
        [SYSTEMCTL_PATH, "daemon-reload"],
        # Restart rather than reload: a timer recomputes its next elapse only
        # when restarted, so without this the change would take effect a day
        # late.
        [SYSTEMCTL_PATH, "restart", BACKUP_TIMER_UNIT],
    ):
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise BackupdError(
                "the schedule was saved but the timer could not be updated: "
                + result.stderr.decode("utf-8", "replace").strip()[:200],
                code="invalid",
            )

    with _SCHEDULE_TIMER_LOCK:
        _SCHEDULE_TIMER_CACHE.clear()


def timer_next_run() -> str:
    """What systemd says the next firing will be, or nothing if it is inert."""
    try:
        properties = systemctl_properties(
            BACKUP_TIMER_UNIT, ["NextElapseUSecRealtime", "ActiveState"]
        )
    except Exception:  # noqa: BLE001 - reporting must not break the page
        return ""
    if properties.get("ActiveState") != "active":
        return ""
    return properties.get("NextElapseUSecRealtime", "") or ""


DEFAULT_KEEP_LOCAL = 3


def keep_local_value(value: Any, *, default: int = DEFAULT_KEEP_LOCAL) -> int:
    """How many archives to keep on this server: a whole number, 1 to 50.

    Absent means the default; anything else is checked rather than coerced,
    so a deliberate value is never quietly replaced by the default.
    """
    if value is None or value == "":
        return default
    whole = isinstance(value, int) and not isinstance(value, bool)
    if not whole and not (isinstance(value, str) and value.strip().isdigit()):
        raise BackupdError(
            "the number of backups kept on this server must be a whole number", code="invalid"
        )
    number = int(value)
    if not 1 <= number <= LIST_LIMIT:
        raise BackupdError(
            f"the number of backups kept on this server must be between 1 and {LIST_LIMIT}",
            code="invalid",
        )
    return number


def load_schedule() -> dict[str, Any]:
    try:
        record = safe_json_file(SCHEDULE_PATH)
    except Exception:  # noqa: BLE001 - a broken file must not stop the daemon
        record = {}
    return {
        "enabled": bool(record.get("enabled")),
        "destinations": [
            str(item)
            for item in (record.get("destinations") or [])
            if isinstance(item, str)
        ],
        "include_ssh": bool(record.get("include_ssh")),
        "quiesce": record.get("quiesce", True) is not False,
        "passphrase_stored": SCHEDULE_PASSPHRASE_PATH.is_file(),
        "last_run": record.get("last_run", ""),
        "last_result": record.get("last_result", ""),
        # The stored time is what the operator asked for; next_run is what
        # systemd will actually do about it, which is the honest answer when
        # the timer is stopped or the drop-in never landed.
        "time": schedule_time(record.get("time"), default=DEFAULT_SCHEDULE_TIME),
        "next_run": timer_next_run(),
        "keep_local": stored_keep_local(record.get("keep_local")),
    }


def stored_keep_local(value: Any) -> int:
    # A hand-edited file must not stop the daemon; it falls back instead.
    try:
        return keep_local_value(value)
    except BackupdError:
        return DEFAULT_KEEP_LOCAL


def schedule_status(_request: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "schedule": {**load_schedule(), **schedule_timer_metadata()}}


_SCHEDULE_TIMER_CACHE = {}
_SCHEDULE_TIMER_LOCK = threading.Lock()


def schedule_timer_metadata():
    if not _SCHEDULE_TIMER_LOCK.acquire(blocking=False):
        return dict(_SCHEDULE_TIMER_CACHE.get('value') or {})
    try:
        if time.monotonic() - _SCHEDULE_TIMER_CACHE.get('at', -60) < 30:
            return dict(_SCHEDULE_TIMER_CACHE['value'])
        value = {}
        helper = SOURCE_DIR / 'installer/timer_metadata.py'
        if helper.is_file() and not helper.is_symlink():
            try:
                reply = subprocess.run(['/usr/bin/python3', str(helper), 'backups'], stdin=subprocess.DEVNULL,
                                       capture_output=True, text=True, timeout=8)
                metadata = json.loads(reply.stdout)
                if reply.returncode == 0 and isinstance(metadata, dict) and metadata.get('protocol') == 1:
                    value = {'timer': metadata.get('timer'), 'other_timers': metadata.get('other_timers', []),
                             'timer_checked_at': metadata.get('checked_at')}
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass  # Legacy next_run is still returned; never invent a time.
        _SCHEDULE_TIMER_CACHE.update(at=time.monotonic(), value=value)
        return dict(value)
    finally:
        _SCHEDULE_TIMER_LOCK.release()


def save_schedule(request: dict[str, Any]) -> dict[str, Any]:
    current = load_schedule()
    names = request.get("destinations")
    if names is None:
        names = current["destinations"]
    if not isinstance(names, list):
        raise BackupdError("destinations must be a list", code="invalid")
    chosen = []
    for item in names:
        name = str(item or "").strip().lower()
        # Refuse a name that does not resolve, so the schedule cannot be armed
        # pointing at nothing.
        load_destination(name)
        chosen.append(name)

    passphrase = request.get("passphrase")
    if isinstance(passphrase, str) and passphrase:
        write_private(
            SCHEDULE_PASSPHRASE_PATH, require_passphrase(passphrase).encode("utf-8")
        )
    elif passphrase == "":
        with contextlib.suppress(FileNotFoundError):
            SCHEDULE_PASSPHRASE_PATH.unlink()

    enabled = request.get("enabled")
    enabled = current["enabled"] if enabled is None else bool(enabled)
    if enabled and not SCHEDULE_PASSPHRASE_PATH.is_file():
        raise BackupdError(
            "a stored passphrase is required before the schedule can run",
            code="invalid",
        )
    if enabled and not chosen:
        raise BackupdError(
            "choose at least one destination before enabling the schedule",
            code="invalid",
        )

    wanted_time = schedule_time(
        request.get("time"), default=current.get("time", DEFAULT_SCHEDULE_TIME)
    )

    record = {
        "enabled": enabled,
        "destinations": chosen,
        "include_ssh": bool(request.get("include_ssh", current["include_ssh"])),
        "quiesce": request.get("quiesce", current["quiesce"]) is not False,
        "last_run": current["last_run"],
        "last_result": current["last_result"],
        "time": wanted_time,
        "keep_local": keep_local_value(
            request.get("keep_local"), default=current["keep_local"]
        ),
    }
    atomic_json(SCHEDULE_PATH, record, mode=0o600)
    # Only when the hour actually moved. Saving a destination or a passphrase
    # is a far more common act than changing the time, and each rewrite costs
    # a daemon-reload and restarts the timer -- which also discards the
    # randomised delay it had already picked.
    if wanted_time != current.get("time", DEFAULT_SCHEDULE_TIME):
        write_timer_time(wanted_time)
    return {"ok": True, "schedule": load_schedule()}


def record_schedule_outcome(result: str) -> None:
    try:
        record = safe_json_file(SCHEDULE_PATH)
    except Exception:  # noqa: BLE001
        record = {}
    record["last_run"] = utc_now()
    record["last_result"] = result[:500]
    with contextlib.suppress(Exception):
        atomic_json(SCHEDULE_PATH, record, mode=0o600)


def run_scheduled_backup(request: dict[str, Any]) -> dict[str, Any]:
    """Make a backup and send it away. Invoked by the timer or by a person.

    Runs inline rather than as a background job: the timer wants an exit code,
    and the maintenance lock the backup takes is what keeps it from racing a
    restore or an update.
    """
    schedule = load_schedule()
    # The timer asks whether the schedule is on; a person pressing the button
    # has already answered that by pressing it. Everything else the run needs
    # -- a stored passphrase, somewhere to send it -- is still required.
    on_demand = bool(request.get("on_demand"))
    if not schedule["enabled"] and not on_demand:
        return {"ok": True, "skipped": "the schedule is off"}
    if on_demand and not schedule["destinations"]:
        raise BackupdError(
            "choose at least one destination before running it", code="invalid"
        )
    if not schedule["passphrase_stored"]:
        record_schedule_outcome("no stored passphrase")
        raise BackupdError("no stored passphrase", code="invalid")

    passphrase = SCHEDULE_PASSPHRASE_PATH.read_text(encoding="utf-8").strip()
    started = start_backup(
        {
            "action": "start_backup",
            "passphrase": passphrase,
            "include_ssh": schedule["include_ssh"],
            "quiesce": schedule["quiesce"],
        }
    )
    passphrase = ""
    job_id = started["job_id"]

    deadline = time.monotonic() + SCHEDULED_BACKUP_TIMEOUT
    state: dict[str, Any] = {}
    while time.monotonic() < deadline:
        time.sleep(5)
        with contextlib.suppress(BackupdError):
            state = load_job(job_id, include_logs=False)
        if state.get("status") in TERMINAL_STATUSES:
            break
    if state.get("status") != "completed":
        record_schedule_outcome(f"the backup did not complete: {state.get('status')}")
        report_alert(
            "backup.failed",
            job_id,
            "The scheduled backup did not complete",
            str(state.get("error") or "")[:500],
        )
        return {"ok": False, "job_id": job_id, "error": "the backup did not complete"}

    backup_id = ((state.get("output") or {}).get("backup_id")) or ""
    uploads = []
    failures = []
    for name in schedule["destinations"]:
        try:
            outcome = upload_backup(
                {"action": "upload", "backup_id": backup_id, "destination": name}
            )
        except BackupdError as exc:
            failures.append(f"{name}: {exc}")
            continue
        uploads.append(outcome)
        if not outcome.get("ok"):
            failures.append(f"{name}: {outcome.get('error')}")

    # Old local archives go only once every destination has a verified copy
    # of this one. A failed or unverified upload keeps them all: then the
    # local archives may be the only recent copies there are.
    pruned: list[str] = []
    if uploads and not failures:
        try:
            lock_fd = acquire_operation()
        except BackupdError as exc:
            LOG.warning("Local retention skipped this run: %s", exc)
        else:
            try:
                pruned = prune_local_backups(schedule["keep_local"])
            finally:
                release_operation(lock_fd)

    outcome = (
        "; ".join(failures) if failures else f"copied to {len(uploads)} destination(s)"
    )
    if pruned:
        outcome += f"; removed {len(pruned)} older local backup(s)"
    record_schedule_outcome(outcome)

    storage = local_storage()
    if storage["low"]:
        report_alert(
            "backup.space_low",
            "local",
            "Backup storage is running out of space",
            (
                f"{storage['free_bytes']} bytes free, below "
                f"{storage['low_space_bytes']}; {storage['count']} local "
                f"backup(s) use {storage['bytes']} bytes"
            ),
        )
    return {
        "ok": not failures,
        "job_id": job_id,
        "backup_id": backup_id,
        "uploads": uploads,
        "errors": failures,
        "pruned": pruned,
        "local": storage,
    }


def dispatch(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise BackupdError("request must be a JSON object")
    action = request.get("action")
    if action not in REQUEST_FIELDS:
        raise BackupdError("unknown backup daemon action")
    unexpected = set(request) - REQUEST_FIELDS[action]
    if unexpected:
        raise BackupdError("unexpected request fields: " + ", ".join(sorted(unexpected)))
    if action == "status":
        return status_response(request)
    if action == "stage_backup":
        return stage_backup(request)
    if action == "start_backup":
        return start_backup(request)
    if action == "start_inspect":
        return start_inspect(request)
    if action == "start_restore":
        return start_restore(request)
    if action == "destinations":
        return list_destinations(request)
    if action == "destination_save":
        return save_destination(request)
    if action == "destination_delete":
        return delete_destination(request)
    if action == "destination_test":
        return test_destination(request)
    if action == "destination_retrust":
        return retrust_destination(request)
    if action == "upload":
        return upload_backup(request)
    if action == "schedule":
        return schedule_status(request)
    if action == "schedule_save":
        return save_schedule(request)
    if action == "run_scheduled":
        return run_scheduled_backup(request)
    return delete_item(request)


def peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        return _constants.APP_UID
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def receive_request(connection: socket.socket) -> bytes:
    deadline = time.monotonic() + 10
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackupdError("request timed out")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
        except socket.timeout as exc:
            raise BackupdError("request timed out") from exc
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise BackupdError("request exceeds 64 KiB", code="too_large")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise BackupdError("request must contain exactly one JSON line")
    return bytes(data[:-1])


def handle_connection(connection: socket.socket) -> None:
    with connection:
        try:
            APP_UID = _constants.APP_UID
            if peer_uid(connection) not in {0, APP_UID}:
                raise BackupdError("socket peer is not authorized")
            raw = receive_request(connection)
            request = json.loads(raw.decode("utf-8"))
            response = dispatch(request)
        except BackupdError as exc:
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": exc.code,
            }
        except FileNotFoundError as exc:
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": "not_found",
            }
        except (ValueError, json.JSONDecodeError) as exc:
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": "invalid",
            }
        except OSError as exc:
            if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                code = "insufficient_space"
            elif exc.errno in {errno.EEXIST, errno.EBUSY}:
                code = "conflict"
            elif exc.errno == errno.EFBIG:
                code = "too_large"
            elif exc.errno == errno.ENOENT:
                code = "not_found"
            else:
                code = "internal"
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": code,
            }
        except Exception:  # noqa: BLE001 - never expose a traceback to the client
            LOG.exception("Unhandled backup daemon request error")
            response = {
                "ok": False,
                "error": "internal backup daemon error",
                "error_code": "internal",
            }
        encoded = (json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            connection.settimeout(5)
            connection.sendall(encoded)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass


def handle_connection_in_slot(connection: socket.socket) -> None:
    try:
        handle_connection(connection)
    finally:
        CONNECTION_SLOTS.release()


def signal_stop(_signum: int, _frame: Any) -> None:
    SHUTDOWN_REQUESTED.set()
    if not OPERATION_THREAD_LOCK.locked():
        STOP_EVENT.set()


def serve() -> None:
    ensure_layout()
    recover_stale_jobs()
    cleanup_stale_worker_artifacts()
    expire_orphaned_uploads()
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCKET_PATH))
        os.chown(SOCKET_PATH, _constants.APP_UID, _constants.APP_PRIMARY_GID)
        os.chmod(SOCKET_PATH, 0o600)
        server.listen(16)
        server.settimeout(1)
        LOG.info("Listening on %s", SOCKET_PATH)
        while not STOP_EVENT.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            if not CONNECTION_SLOTS.acquire(blocking=False):
                with connection:
                    try:
                        connection.settimeout(1)
                        connection.sendall(
                            b'{"ok":false,"error":"too many active requests",'
                            b'"error_code":"busy"}\n'
                        )
                    except (OSError, socket.timeout):
                        pass
                continue
            thread = threading.Thread(
                target=handle_connection_in_slot,
                args=(connection,),
                daemon=True,
            )
            thread.start()
    finally:
        server.close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    try:
        serve()
    except (BackupdError, OSError, KeyError) as exc:
        LOG.error("Cannot start backup daemon: %s", exc)
        return 1
    return 0
