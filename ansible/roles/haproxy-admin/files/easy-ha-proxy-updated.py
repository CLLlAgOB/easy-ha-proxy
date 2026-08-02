#!/usr/bin/env python3
"""Least-privilege broker for asynchronous easy-ha-proxy update jobs.

The web container can request only a read-only update scan or an allow-listed
component update.  It cannot provide commands, Ansible tags, repository URLs,
paths, or image references.  Job and plan state lives on the host so updating
the haproxy-admin container does not lose progress or the final result.
"""

from __future__ import annotations

import datetime as dt
import errno
import fcntl
import grp
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
from typing import Any
import uuid


LOG = logging.getLogger("easy-ha-proxy-updated")


class UpdatedError(RuntimeError):
    """Expected request or job failure safe to return to the web UI."""

    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


def env_int(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise UpdatedError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise UpdatedError(f"{name} is outside the supported range")
    return value


SOCKET_PATH = Path(
    os.environ.get(
        "UPDATED_SOCKET_PATH",
        "/run/easy-ha-proxy/easy-ha-proxy-updated.sock",
    )
)
STATE_ROOT = Path(
    os.environ.get(
        "UPDATED_STATE_ROOT",
        "/var/lib/easy-ha-proxy/update-web",
    )
)
JOBS_DIR = STATE_ROOT / "jobs"
LATEST_PLAN_PATH = STATE_ROOT / "latest-plan.json"
SOURCE_DIR = Path(
    os.environ.get("UPDATED_SOURCE_DIR", "/opt/easy-ha-proxy/source")
)
CONFIG_DIR = Path(
    os.environ.get("UPDATED_CONFIG_DIR", "/etc/easy-ha-proxy")
)
PYTHON_PATH = Path(
    os.environ.get("UPDATED_PYTHON_PATH", "/opt/easy-ha-proxy/venv/bin/python")
)
CLI_PATH = Path(
    os.environ.get("UPDATED_CLI_PATH", "/usr/local/bin/easy-ha-proxy")
)
APP_USER = os.environ.get("UPDATED_SOCKET_USER", "haproxyadmin")
APP_GROUP = os.environ.get("UPDATED_APP_GROUP", "hadmin")
SERVICE_NAME = os.environ.get(
    "UPDATED_SERVICE_NAME", "easy-ha-proxy-updated.service"
)
ACTIVE_MARKER = Path(
    os.environ.get(
        "UPDATED_ACTIVE_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-update.active",
    )
)
RESTART_REQUEST_MARKER = Path(
    os.environ.get(
        "UPDATED_RESTART_REQUEST_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-updated-restart.requested",
    )
)
# This is deliberately the same lock used by backupd.  Holding it makes an
# update conflict with backup, inspect, restore, and backup deletion.
MAINTENANCE_LOCK_PATH = Path(
    os.environ.get(
        "UPDATED_MAINTENANCE_LOCK",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock",
    )
)
HAPROXY_TRANSACTION_MARKER = Path(
    os.environ.get(
        "UPDATED_HAPROXY_TRANSACTION_MARKER",
        "/opt/haproxy-admin/backups/haproxy/pending_ui_transaction.json",
    )
)
HAPROXY_TRANSACTION_STATE = Path(
    os.environ.get(
        "UPDATED_HAPROXY_TRANSACTION_STATE",
        "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json",
    )
)

MAX_REQUEST_BYTES = env_int(
    "UPDATED_MAX_REQUEST_BYTES", 32 * 1024, maximum=64 * 1024
)
MAX_RESPONSE_BYTES = env_int(
    "UPDATED_MAX_RESPONSE_BYTES", 2 * 1024 * 1024, maximum=4 * 1024 * 1024
)
MAX_CAPTURE_BYTES = env_int(
    "UPDATED_MAX_CAPTURE_BYTES", 256 * 1024, maximum=1024 * 1024
)
MAX_STATE_BYTES = env_int(
    "UPDATED_MAX_STATE_BYTES", 1024 * 1024, maximum=2 * 1024 * 1024
)
JOB_TIMEOUT_SECONDS = env_int(
    "UPDATED_JOB_TIMEOUT_SECONDS", 2 * 60 * 60, maximum=12 * 60 * 60
)
CHECK_TIMEOUT_SECONDS = env_int(
    "UPDATED_CHECK_TIMEOUT_SECONDS", 10 * 60, maximum=30 * 60
)
PLAN_TTL_SECONDS = env_int(
    "UPDATED_PLAN_TTL_SECONDS", 15 * 60, maximum=24 * 60 * 60
)
LIST_LIMIT = env_int("UPDATED_LIST_LIMIT", 30, maximum=100)
MAX_CONNECTIONS = env_int("UPDATED_MAX_CONNECTIONS", 16, maximum=64)

PROTOCOL_VERSION = 1
IDENTIFIER_RE = re.compile(r"^[0-9a-f]{32}$")
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ALLOWED_COMPONENTS = frozenset(
    {
        "all",
        "services",
        "daemons",
        "authelia-container",
        "admin-container",
        "os",
    }
)
SOURCE_COMPONENTS = frozenset({"all", "services", "daemons"})
CONTAINER_COMPONENTS = frozenset(
    {"authelia-container", "admin-container"}
)
ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "interrupted"})
HAPROXY_TRANSACTION_ACTIVE_STATES = frozenset(
    {"prepared", "pending_confirmation", "rolling_back", "rollback_failed"}
)
HAPROXY_TRANSACTION_SETTLED_STATES = frozenset({"confirmed", "rolled_back"})
SOURCE_CHANNELS = frozenset({"github", "local"})
IMAGE_CHANNELS = frozenset({"latest", "alpha"})
RELEASE_CHANNELS = frozenset({"stable", "alpha", "local"})
# Unified channel -> (branch, image) for github-tracked channels.
RELEASE_CHANNEL_MAP = {
    "stable": {"branch": "main", "image_channel": "latest"},
    "alpha": {"branch": "alpha", "image_channel": "alpha"},
}
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")


def derive_release_channel(
    source_channel: str, branch: str, image_channel: str
) -> str:
    # Keyed off the image tag so pre-branch installs still map cleanly.
    if (source_channel or "github") == "local":
        return "local"
    if (image_channel or "latest") == "alpha":
        return "alpha"
    return "stable"
REQUEST_FIELDS = {
    "status": frozenset({"action", "job_id"}),
    "start_check": frozenset(
        {"action", "image_channel", "source_channel", "release_channel"}
    ),
    "start_apply": frozenset(
        {"action", "plan_id", "components", "confirmation"}
    ),
    "set_channels": frozenset(
        {"action", "image_channel", "source_channel", "release_channel"}
    ),
    "reboot": frozenset({"action", "confirmation"}),
    "cancel_reboot": frozenset({"action"}),
}

STATE_LOCK = threading.RLock()
OPERATION_THREAD_LOCK = threading.Lock()
CONNECTION_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)
STOP_EVENT = threading.Event()
SHUTDOWN_REQUESTED = threading.Event()
APP_UID = -1
APP_PRIMARY_GID = -1
APP_GROUP_GID = -1


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise UpdatedError(f"invalid {label}")
    return value


def ensure_absolute_path(path: Path, label: str) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise UpdatedError(f"unsafe {label}")


def ensure_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    ensure_absolute_path(path, "state path")
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UpdatedError(f"state path is not a real directory: {path}")
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def ensure_layout() -> None:
    global APP_UID, APP_PRIMARY_GID, APP_GROUP_GID
    user = pwd.getpwnam(APP_USER)
    group = grp.getgrnam(APP_GROUP)
    APP_UID = user.pw_uid
    APP_PRIMARY_GID = user.pw_gid
    APP_GROUP_GID = group.gr_gid
    for path, label in (
        (SOCKET_PATH, "socket path"),
        (STATE_ROOT, "state path"),
        (SOURCE_DIR, "source path"),
        (CONFIG_DIR, "configuration path"),
        (MAINTENANCE_LOCK_PATH, "maintenance lock"),
        (ACTIVE_MARKER, "active marker"),
        (RESTART_REQUEST_MARKER, "restart marker"),
        (HAPROXY_TRANSACTION_MARKER, "HAProxy transaction marker"),
        (HAPROXY_TRANSACTION_STATE, "HAProxy transaction state"),
    ):
        ensure_absolute_path(path, label)
    ensure_directory(STATE_ROOT, uid=0, gid=APP_GROUP_GID, mode=0o750)
    ensure_directory(JOBS_DIR, uid=0, gid=APP_GROUP_GID, mode=0o750)
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chown(SOCKET_PATH.parent, 0, APP_GROUP_GID)
    os.chmod(SOCKET_PATH.parent, 0o750)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise UpdatedError("update state is too large", code="too_large")
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fchown(descriptor, 0, APP_GROUP_GID)
            os.fchmod(descriptor, 0o640)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def safe_json_file(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or not 0 < info.st_size <= MAX_STATE_BYTES
    ):
        raise UpdatedError(f"unsafe update state file: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
            raise UpdatedError(f"state file changed while opening: {path.name}")
        raw = os.read(descriptor, MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise UpdatedError(f"invalid update state file: {path.name}")
    return payload


def state_path(job_id: str) -> Path:
    return JOBS_DIR / f"{identifier(job_id, 'job id')}.json"


def new_job(operation: str, **values: Any) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    state = {
        "id": job_id,
        "operation": operation,
        "status": "queued",
        "created_at": utc_now(),
        "started_at": None,
        "completed_at": None,
        "components": [],
        "current_component": None,
        "plan_id": None,
        "output": None,
        "result": None,
        "error": None,
    }
    state.update(values)
    with STATE_LOCK:
        atomic_json(state_path(job_id), state)
    return state


def public_job(state: dict[str, Any], *, include_log: bool = True) -> dict[str, Any]:
    output = state.get("output") if isinstance(state.get("output"), dict) else None
    if output is not None and not include_log:
        output = {key: value for key, value in output.items() if key != "log"}
    return {
        "id": str(state.get("id") or ""),
        "operation": str(state.get("operation") or ""),
        "status": str(state.get("status") or ""),
        "created_at": state.get("created_at"),
        "started_at": state.get("started_at"),
        "completed_at": state.get("completed_at"),
        "components": state.get("components")
        if isinstance(state.get("components"), list)
        else [],
        "current_component": state.get("current_component"),
        "plan_id": state.get("plan_id"),
        "output": output,
        "result": state.get("result")
        if isinstance(state.get("result"), dict)
        else None,
        "error": str(state.get("error"))[:4096] if state.get("error") else None,
    }


def load_job(job_id: str, *, include_log: bool = True) -> dict[str, Any]:
    path = state_path(job_id)
    if not path.exists():
        raise UpdatedError("update job was not found", code="not_found")
    state = safe_json_file(path)
    if state.get("id") != job_id:
        raise UpdatedError("update job identifier does not match")
    return public_job(state, include_log=include_log)


def update_job(job_id: str, **updates: Any) -> dict[str, Any]:
    with STATE_LOCK:
        path = state_path(job_id)
        state = safe_json_file(path)
        state.update(updates)
        atomic_json(path, state)
    return public_job(state)


def list_jobs() -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for path in JOBS_DIR.glob("*.json"):
        if not IDENTIFIER_RE.fullmatch(path.stem):
            continue
        try:
            jobs.append(load_job(path.stem, include_log=False))
        except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
            LOG.warning("Ignoring unsafe update job state %s", path.name)
    jobs.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return jobs[:LIST_LIMIT]


def active_job() -> dict[str, Any] | None:
    return next(
        (job for job in list_jobs() if job.get("status") in ACTIVE_STATUSES),
        None,
    )


def recover_stale_jobs() -> None:
    for job in list_jobs():
        if job.get("status") in ACTIVE_STATUSES:
            update_job(
                job["id"],
                status="interrupted",
                completed_at=utc_now(),
                error="the update broker restarted before the job completed",
            )
    for marker in (ACTIVE_MARKER, RESTART_REQUEST_MARKER):
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
    for path in JOBS_DIR.glob(".*.output"):
        if not IDENTIFIER_RE.fullmatch(path.name[1:-len(".output")]):
            continue
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0:
                path.unlink()
        except FileNotFoundError:
            pass
    stop_orphan_transient_jobs()


def stop_orphan_transient_jobs() -> None:
    """Transient job units outlive a crashed broker; reconcile them at start.

    Their jobs were just marked interrupted, so a still-running child would
    otherwise race the next operation for the same managed state.
    """

    if not transient_jobs_supported():
        return
    try:
        result = subprocess.run(
            [
                SYSTEMCTL_PATH,
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "easy-ha-proxy-updated-job-*.service",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        LOG.warning("Could not list orphan transient update jobs")
        return
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit.startswith("easy-ha-proxy-updated-job-"):
            LOG.warning("Stopping orphan transient update job %s", unit)
            stop_transient_unit(unit)


def sanitize_log(value: str) -> str:
    clean = CONTROL_RE.sub("", value).replace("\r", "")
    encoded = clean.encode("utf-8", "replace")
    if len(encoded) > MAX_CAPTURE_BYTES:
        prefix = b"[output truncated]\n"
        if MAX_CAPTURE_BYTES <= len(prefix):
            return prefix[:MAX_CAPTURE_BYTES].decode("ascii")
        encoded = prefix + encoded[-(MAX_CAPTURE_BYTES - len(prefix)):]
        # The byte slice can begin inside a UTF-8 sequence. Dropping only that
        # incomplete leading code point keeps the advertised byte cap exact.
        clean = encoded.decode("utf-8", "ignore")
    return clean


def read_tail(stream: Any) -> str:
    # os.pread keeps the file offset untouched: the running child shares the
    # same open file description and would otherwise write where a concurrent
    # live read repositioned the offset, corrupting its own log.
    stream.flush()
    descriptor = stream.fileno()
    size = os.fstat(descriptor).st_size
    if size <= 0:
        return ""
    offset = max(0, size - MAX_CAPTURE_BYTES * 2)
    return sanitize_log(
        os.pread(descriptor, size - offset, offset).decode("utf-8", "replace")
    )


def child_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PYTHONUNBUFFERED": "1",
        "EASY_HA_PROXY_LANGUAGE": "en",
        # A web update reports a required reboot; it never schedules one.
        "EASY_HA_PROXY_REBOOT_DECISION": "no",
    }


SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
SHUTDOWN_PATH = os.environ.get("UPDATED_SHUTDOWN_PATH", "/usr/sbin/shutdown")
# Delayed + cancelable reboot: the HTTP response returns before the box goes
# down, and there is a window to cancel with `shutdown -c`.
REBOOT_DELAY = os.environ.get("UPDATED_REBOOT_DELAY", "+1")
REBOOT_CONFIRMATION = "REBOOT"
# A restore in progress must never be interrupted by a reboot.
BACKUPD_RESTORE_ACTIVE_MARKER = Path(
    os.environ.get(
        "UPDATED_BACKUPD_RESTORE_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active",
    )
)
# systemd records a scheduled shutdown/reboot here.
SYSTEMD_SHUTDOWN_SCHEDULED = Path("/run/systemd/shutdown/scheduled")
TRANSIENT_STOP_TIMEOUT = 30


def transient_jobs_supported() -> bool:
    """Privileged children escape this broker's sandbox through PID 1.

    The broker unit keeps NoNewPrivileges; APT, dpkg, and snap-confined
    certbot only work when their processes are spawned by systemd itself as
    transient units. Unprivileged test runs fall back to direct execution.
    """

    return (
        os.geteuid() == 0
        and os.path.isdir("/run/systemd/system")
        and os.access(SYSTEMD_RUN_PATH, os.X_OK)
    )


def systemctl_properties(unit: str, names: list[str]) -> dict[str, str]:
    result = subprocess.run(
        [SYSTEMCTL_PATH, "show", unit, *(f"--property={name}" for name in names)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    properties: dict[str, str] = {}
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    return properties


def stop_transient_unit(unit: str) -> None:
    for command in (
        [SYSTEMCTL_PATH, "stop", unit],
        [SYSTEMCTL_PATH, "reset-failed", unit],
    ):
        try:
            subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=TRANSIENT_STOP_TIMEOUT + 15,
            )
        except (OSError, subprocess.TimeoutExpired):
            LOG.warning("Could not clean up transient unit %s", unit)


def read_file_tail(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return ""
    try:
        size = os.fstat(descriptor).st_size
        if size <= 0:
            return ""
        offset = max(0, size - MAX_CAPTURE_BYTES * 2)
        return sanitize_log(
            os.pread(descriptor, size - offset, offset).decode("utf-8", "replace")
        )
    finally:
        os.close(descriptor)


def run_transient_command(
    job_id: str,
    argv: list[str],
    *,
    timeout: int,
    log_prefix: str = "",
) -> tuple[int, str]:
    unit = f"easy-ha-proxy-updated-job-{uuid.uuid4().hex[:12]}.service"
    output_path = JOBS_DIR / f".{identifier(job_id, 'job id')}.output"
    descriptor = os.open(
        output_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if log_prefix:
            os.write(descriptor, (log_prefix + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    command = [
        SYSTEMD_RUN_PATH,
        "--quiet",
        "--no-block",
        "--unit",
        unit,
        "--service-type=oneshot",
        "-p",
        "RemainAfterExit=yes",
        "-p",
        f"StandardOutput=append:{output_path}",
        "-p",
        "StandardError=inherit",
        "-p",
        "KillMode=control-group",
        "-p",
        f"TimeoutStopSec={TRANSIENT_STOP_TIMEOUT}",
    ]
    for key, value in child_environment().items():
        command.append(f"--setenv={key}={value}")
    command.append("--")
    command.extend(argv)
    try:
        started = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        output_path.unlink(missing_ok=True)
        raise UpdatedError(f"could not start the privileged update job: {exc}") from exc
    if started.returncode != 0:
        detail = started.stderr.decode("utf-8", "replace").strip()
        output_path.unlink(missing_ok=True)
        raise UpdatedError(
            "could not start the privileged update job"
            + (f": {detail}" if detail else "")
        )
    begun = time.monotonic()
    last_publish = 0.0
    timed_out = False
    try:
        while True:
            properties = systemctl_properties(
                unit, ["LoadState", "ActiveState", "SubState", "ExecMainStatus"]
            )
            active = properties.get("ActiveState", "")
            if properties.get("LoadState") == "not-found":
                # Only successfully finished transient units are unloaded
                # automatically; failed ones stay loaded until reset.
                return 0, read_file_tail(output_path)
            if active == "failed":
                try:
                    returncode = int(properties.get("ExecMainStatus") or 1)
                except ValueError:
                    returncode = 1
                return returncode or 1, read_file_tail(output_path)
            if active == "active" and properties.get("SubState") == "exited":
                try:
                    returncode = int(properties.get("ExecMainStatus") or 0)
                except ValueError:
                    returncode = 0
                return returncode, read_file_tail(output_path)
            if time.monotonic() - begun > timeout:
                timed_out = True
                raise UpdatedError("update command exceeded its timeout")
            if time.monotonic() - last_publish >= 2:
                update_job(job_id, output={"log": read_file_tail(output_path)})
                last_publish = time.monotonic()
            time.sleep(0.5)
    finally:
        stop_transient_unit(unit)
        if timed_out:
            update_job(job_id, output={"log": read_file_tail(output_path)})
        output_path.unlink(missing_ok=True)


def run_command(
    job_id: str,
    argv: list[str],
    *,
    timeout: int,
    log_prefix: str = "",
) -> tuple[int, str]:
    if transient_jobs_supported():
        return run_transient_command(
            job_id, argv, timeout=timeout, log_prefix=log_prefix
        )
    return run_direct_command(job_id, argv, timeout=timeout, log_prefix=log_prefix)


def run_direct_command(
    job_id: str,
    argv: list[str],
    *,
    timeout: int,
    log_prefix: str = "",
) -> tuple[int, str]:
    with tempfile.TemporaryFile() as output_file:
        if log_prefix:
            output_file.write((log_prefix + "\n").encode("utf-8"))
            output_file.flush()
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=output_file,
            stderr=subprocess.STDOUT,
            env=child_environment(),
            start_new_session=True,
        )
        started = time.monotonic()
        last_publish = 0.0
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    raise UpdatedError("update command exceeded its timeout")
                if time.monotonic() - last_publish >= 2:
                    update_job(
                        job_id,
                        output={"log": read_tail(output_file)},
                    )
                    last_publish = time.monotonic()
                time.sleep(0.25)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        return process.returncode, read_tail(output_file)


def checker_command(
    *,
    image_channel: str | None = None,
    source_channel: str | None = None,
    branch: str | None = None,
) -> list[str]:
    checker = SOURCE_DIR / "installer/update_plan.py"
    if not checker.is_file() or checker.is_symlink():
        raise UpdatedError(
            "the structured update checker is unavailable; run one controller update first",
            code="not_found",
        )
    python = PYTHON_PATH if PYTHON_PATH.is_file() else Path("/usr/bin/python3")
    command = [str(python), str(checker), "--format", "json"]
    if image_channel:
        command.extend(("--image-channel", image_channel))
    if source_channel:
        command.extend(("--source-channel", source_channel))
    if branch:
        command.extend(("--branch", branch))
    return command


def parse_checker_output(raw: str) -> dict[str, Any]:
    # run_command prepends one broker-owned progress line. Decode exactly one
    # JSON value after the first object delimiter; trailing non-whitespace is
    # rejected by json.loads.
    start = raw.find("{")
    if start < 0:
        raise UpdatedError("the update checker returned an empty response")
    try:
        payload = json.loads(raw[start:])
    except json.JSONDecodeError as exc:
        raise UpdatedError("the update checker returned invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), list):
        raise UpdatedError("the update checker returned an invalid plan")
    seen: set[str] = set()
    for component in payload["components"]:
        if not isinstance(component, dict):
            raise UpdatedError("the update checker returned an invalid component")
        component_id = component.get("id")
        if component_id not in ALLOWED_COMPONENTS or component_id in seen:
            raise UpdatedError("the update checker returned an unsupported component")
        seen.add(component_id)
        if component.get("state") not in {
            "available",
            "current",
            "unknown",
            "blocked",
        }:
            raise UpdatedError("the update checker returned an invalid component state")
    source_channel = payload.get("source_channel")
    image_channel = payload.get("image_channel")
    if source_channel not in {"github", "local"}:
        raise UpdatedError("the update checker returned an invalid source channel")
    if image_channel not in {"latest", "alpha"}:
        raise UpdatedError("the update checker returned an invalid image channel")
    return payload


def execute_checker(
    job_id: str,
    *,
    image_channel: str | None = None,
    source_channel: str | None = None,
    branch: str | None = None,
) -> dict[str, Any]:
    command = checker_command(
        image_channel=image_channel,
        source_channel=source_channel,
        branch=branch,
    )
    returncode, output = run_command(
        job_id,
        command,
        timeout=CHECK_TIMEOUT_SECONDS,
        log_prefix="Checking Git, managed Docker images, host daemons, and APT cache…",
    )
    if returncode != 0:
        raise UpdatedError(
            "the update checker failed" + (f": {output.splitlines()[-1]}" if output else "")
        )
    return parse_checker_output(output)


def plan_digest(payload: dict[str, Any]) -> str:
    material = {
        "source_channel": payload.get("source_channel"),
        "image_channel": payload.get("image_channel"),
        "components": payload.get("components"),
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def store_plan(payload: dict[str, Any]) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    plan = dict(payload)
    plan["id"] = uuid.uuid4().hex
    plan["protocol_version"] = PROTOCOL_VERSION
    plan["created_at"] = now.isoformat()
    plan["expires_at"] = (
        now + dt.timedelta(seconds=PLAN_TTL_SECONDS)
    ).isoformat()
    plan["digest"] = plan_digest(plan)
    atomic_json(LATEST_PLAN_PATH, plan)
    return plan


def load_latest_plan() -> dict[str, Any] | None:
    if not LATEST_PLAN_PATH.exists():
        return None
    plan = safe_json_file(LATEST_PLAN_PATH)
    if not IDENTIFIER_RE.fullmatch(str(plan.get("id") or "")):
        raise UpdatedError("the cached update plan is invalid")
    return plan


def plan_is_expired(plan: dict[str, Any]) -> bool:
    try:
        expires = dt.datetime.fromisoformat(str(plan["expires_at"]))
    except (KeyError, TypeError, ValueError):
        return True
    if expires.tzinfo is None:
        return True
    return dt.datetime.now(dt.timezone.utc) >= expires


def component_signature(component: dict[str, Any]) -> str:
    material = {
        key: component.get(key)
        for key in (
            "id",
            "state",
            "actionable",
            "installed",
            "available",
            "candidate",
            "count",
            # update_plan keeps the exact image and daemon digests, plus the
            # selected APT package set, in details while the top-level version
            # can be only a count.  Signing details closes that stale-plan gap.
            "details",
        )
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def selected_components(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > len(ALLOWED_COMPONENTS):
        raise UpdatedError("select at least one supported update component")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in ALLOWED_COMPONENTS:
            raise UpdatedError("unsupported update component")
        if item in result:
            raise UpdatedError("duplicate update component")
        result.append(item)
    if "all" in result:
        result = [item for item in result if item not in SOURCE_COMPONENTS - {"all"}]
        result = [item for item in result if item not in CONTAINER_COMPONENTS]
    # Updating the web application last reduces avoidable reconnects.  APT is
    # always last because it can leave the host awaiting a reboot.
    order = {
        "all": 0,
        "services": 1,
        "daemons": 2,
        "authelia-container": 3,
        "admin-container": 4,
        "os": 5,
    }
    return sorted(result, key=order.__getitem__)


def plan_component_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = plan.get("components")
    if not isinstance(components, list):
        raise UpdatedError("the cached update plan is invalid")
    return {
        str(item.get("id")): item
        for item in components
        if isinstance(item, dict) and item.get("id") in ALLOWED_COMPONENTS
    }


def validate_selection(plan: dict[str, Any], components: list[str]) -> None:
    available = plan_component_map(plan)
    for component_id in components:
        component = available.get(component_id)
        if (
            component is None
            or component.get("state") != "available"
            or component.get("actionable") is not True
        ):
            raise UpdatedError(
                f"component is not an actionable update: {component_id}",
                code="stale_plan",
            )
    if SOURCE_COMPONENTS.intersection(components):
        metadata = CONFIG_DIR / "metadata.yml"
        try:
            text = metadata.read_text(encoding="utf-8")
        except OSError as exc:
            raise UpdatedError("managed metadata is unavailable", code="conflict") from exc
        if re.search(r"(?m)^configuration_pending:\s*(true|yes|1)\s*$", text, re.I):
            raise UpdatedError(
                "managed configuration is pending; apply or revert it before updating host source",
                code="config_pending",
            )
        if haproxy_transaction_active():
            raise UpdatedError(
                "an HAProxy configuration confirmation is active",
                code="config_pending",
            )


def haproxy_transaction_active() -> bool:
    """Fail closed while either UI or authoritative transaction state is active.

    The UI marker is useful during the normal browser workflow, but it can be
    absent after a web-container crash.  haproxy-controld persists the actual
    transaction separately and keeps settled records for diagnostics, so mere
    existence of that authoritative file is not enough.
    """

    if os.path.lexists(HAPROXY_TRANSACTION_MARKER):
        return True
    if not os.path.lexists(HAPROXY_TRANSACTION_STATE):
        return False
    try:
        state = safe_json_file(HAPROXY_TRANSACTION_STATE)
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
        LOG.warning("HAProxy transaction state is unreadable; blocking source update")
        return True
    state_name = state.get("state")
    if state_name in HAPROXY_TRANSACTION_ACTIVE_STATES:
        return True
    if state_name in HAPROXY_TRANSACTION_SETTLED_STATES:
        return False
    LOG.warning("HAProxy transaction state is unknown; blocking source update")
    return True


def validate_fresh_candidates(
    stored: dict[str, Any],
    fresh: dict[str, Any],
    components: list[str],
) -> None:
    old_map = plan_component_map(stored)
    new_map = plan_component_map(fresh)
    for component_id in components:
        old = old_map.get(component_id)
        new = new_map.get(component_id)
        if (
            old is None
            or new is None
            or new.get("state") != "available"
            or new.get("actionable") is not True
            or component_signature(old) != component_signature(new)
        ):
            raise UpdatedError(
                f"the update candidate changed for {component_id}; check again",
                code="stale_plan",
            )


def reviewed_source_revision(
    plan: dict[str, Any], components: list[str]
) -> str | None:
    """Return the exact remote revision approved for a GitHub source update."""

    if not SOURCE_COMPONENTS.intersection(components):
        return None
    if plan.get("source_channel") != "github":
        return None
    source = plan_component_map(plan).get("all")
    candidate = str((source or {}).get("available") or "").strip().lower()
    if not SOURCE_REVISION_RE.fullmatch(candidate):
        raise UpdatedError(
            "the checked source revision is unavailable; check again",
            code="stale_plan",
        )
    return candidate


def container_components_for_selection(components: list[str]) -> set[str]:
    if "all" in components:
        return set(CONTAINER_COMPONENTS)
    return set(components).intersection(CONTAINER_COMPONENTS)


def reviewed_container_digests(
    plan: dict[str, Any], components: list[str], *, current: bool = False
) -> dict[tuple[str, str], str]:
    """Return exact reviewed or installed image digests for selected updates."""

    result: dict[tuple[str, str], str] = {}
    component_map = plan_component_map(plan)
    digest_field = "current_digest" if current else "available_digest"
    for component_id in sorted(container_components_for_selection(components)):
        component = component_map.get(component_id)
        details = component.get("details") if isinstance(component, dict) else None
        images = details.get("images") if isinstance(details, dict) else None
        if not isinstance(images, list) or not images:
            raise UpdatedError(
                f"the checked image digests are unavailable for {component_id}",
                code="stale_plan",
            )
        for item in images:
            if not isinstance(item, dict):
                raise UpdatedError("the checked image plan is invalid", code="stale_plan")
            image = str(item.get("target_image") or item.get("image") or "")
            digest = str(item.get(digest_field) or "").lower()
            if (
                not image
                or len(image) > 512
                or CONTROL_RE.search(image)
                or not IMAGE_DIGEST_RE.fullmatch(digest)
            ):
                raise UpdatedError(
                    f"the checked image digest is unavailable for {component_id}",
                    code="stale_plan",
                )
            key = (component_id, image)
            if key in result:
                raise UpdatedError("the checked image plan contains duplicates", code="stale_plan")
            result[key] = digest
    return result


def validate_reviewed_container_candidates(
    stored: dict[str, Any], fresh: dict[str, Any], components: list[str]
) -> None:
    expected = reviewed_container_digests(stored, components)
    if not expected:
        return
    current = reviewed_container_digests(fresh, components)
    if current != expected:
        raise UpdatedError(
            "a managed image candidate changed after the update check; check again",
            code="stale_plan",
        )


def validate_applied_container_digests(
    stored: dict[str, Any], applied: dict[str, Any], components: list[str]
) -> None:
    expected = reviewed_container_digests(stored, components)
    if not expected:
        return
    actual = reviewed_container_digests(applied, components, current=True)
    if actual != expected:
        raise UpdatedError(
            "an applied image digest differs from the reviewed update plan",
            code="verification_failed",
        )


def acquire_operation() -> int:
    if SHUTDOWN_REQUESTED.is_set():
        raise UpdatedError("the update broker is shutting down", code="conflict")
    if not OPERATION_THREAD_LOCK.acquire(blocking=False):
        raise UpdatedError("another maintenance operation is active", code="busy")
    descriptor = -1
    try:
        descriptor = os.open(
            MAINTENANCE_LOCK_PATH,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except (OSError, BlockingIOError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        OPERATION_THREAD_LOCK.release()
        raise UpdatedError("another maintenance operation is active", code="busy") from exc


def release_operation(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
        OPERATION_THREAD_LOCK.release()
        if SHUTDOWN_REQUESTED.is_set():
            STOP_EVENT.set()


def finish_failed(job_id: str, exc: Exception, log: str = "") -> None:
    current_log = ""
    try:
        current = load_job(job_id)
        output = current.get("output")
        if isinstance(output, dict) and isinstance(output.get("log"), str):
            current_log = sanitize_log(output["log"])
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
        pass
    candidate_log = sanitize_log(log)
    if len(current_log.encode("utf-8")) > len(candidate_log.encode("utf-8")):
        candidate_log = current_log
    updates: dict[str, Any] = {
        "status": "failed",
        "completed_at": utc_now(),
        "error": (str(exc) or exc.__class__.__name__)[:4096],
    }
    if candidate_log:
        updates["output"] = {"log": candidate_log}
    update_job(job_id, **updates)
    LOG.warning("Update job %s failed: %s", job_id, exc)


def check_worker(
    job_id: str,
    lock_fd: int,
    image_channel: str | None,
    source_channel: str | None,
    branch: str | None = None,
) -> None:
    try:
        update_job(
            job_id,
            status="running",
            started_at=utc_now(),
            current_component="check",
        )
        payload = execute_checker(
            job_id,
            image_channel=image_channel,
            source_channel=source_channel,
            branch=branch,
        )
        plan = store_plan(payload)
        update_job(
            job_id,
            status="completed",
            completed_at=utc_now(),
            current_component=None,
            plan_id=plan["id"],
            result={"plan_id": plan["id"], "updates_available": sum(
                1 for item in plan["components"]
                if item.get("state") == "available" and item.get("actionable") is True
            )},
        )
    except Exception as exc:  # noqa: BLE001 - stored as bounded job failure
        finish_failed(job_id, exc)
    finally:
        release_operation(lock_fd)


def update_command(
    component: str,
    *,
    source_channel: str,
    image_channel: str,
    expected_source_revision: str | None = None,
) -> list[str]:
    if component not in ALLOWED_COMPONENTS:
        raise UpdatedError("unsupported update component")
    command = [
        str(CLI_PATH),
        "update",
        "--component",
        component,
        "--source-channel",
        source_channel,
    ]
    if component in {"all", "admin-container"}:
        command.extend(("--image-channel", image_channel))
    if component in SOURCE_COMPONENTS and source_channel == "github":
        revision = str(expected_source_revision or "").lower()
        if not SOURCE_REVISION_RE.fullmatch(revision):
            raise UpdatedError("the approved source revision is unavailable")
        command.extend(("--expected-source-revision", revision))
    return command


def request_self_restart_if_needed() -> None:
    if not RESTART_REQUEST_MARKER.exists():
        return
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "try-restart", "--no-block", SERVICE_NAME],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_environment(),
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        LOG.exception("Could not request deferred update-broker restart")
        return
    if result.returncode != 0:
        LOG.error(
            "Could not request deferred update-broker restart: systemctl exit %s",
            result.returncode,
        )
        return
    try:
        RESTART_REQUEST_MARKER.unlink()
    except FileNotFoundError:
        pass


def apply_worker(
    job_id: str,
    lock_fd: int,
    plan: dict[str, Any],
    components: list[str],
) -> None:
    combined_log = ""
    try:
        # Ensure the HTTP 202 response reaches the browser before a selected
        # admin-container update starts recreating this web application.
        time.sleep(1.0)
        # Configuration can change after the request-level validation but
        # before this worker starts. Recheck while holding the maintenance
        # lock before declaring the mutating update active.
        validate_selection(plan, components)
        ACTIVE_MARKER.write_text(f"job_id={job_id}\n", encoding="utf-8")
        os.chmod(ACTIVE_MARKER, 0o600)
        update_job(job_id, status="running", started_at=utc_now())
        fresh = execute_checker(
            job_id,
            image_channel=str(plan.get("image_channel") or "latest"),
            source_channel=str(plan.get("source_channel") or "github"),
        )
        validate_fresh_candidates(plan, fresh, components)
        validate_reviewed_container_candidates(plan, fresh, components)
        source_channel = str(plan.get("source_channel"))
        image_channel = str(plan.get("image_channel"))
        expected_source_revision = reviewed_source_revision(plan, components)
        for component in components:
            update_job(job_id, current_component=component)
            heading = f"\n=== Applying component: {component} ==="
            command = update_command(
                component,
                source_channel=source_channel,
                image_channel=image_channel,
                expected_source_revision=expected_source_revision,
            )
            returncode, output = run_command(
                job_id,
                command,
                timeout=JOB_TIMEOUT_SECONDS,
                log_prefix=sanitize_log(combined_log + heading),
            )
            combined_log = sanitize_log(output)
            if returncode != 0:
                raise UpdatedError(
                    f"component update failed: {component} (exit code {returncode})"
                )
        reboot_required = Path("/var/run/reboot-required").exists()
        result: dict[str, Any] = {
            "components": components,
            "reboot_required": reboot_required,
        }
        try:
            refreshed_payload = execute_checker(
                job_id,
                image_channel=image_channel,
                source_channel=source_channel,
            )
            validate_applied_container_digests(plan, refreshed_payload, components)
            refreshed = store_plan(refreshed_payload)
            result["refreshed_plan_id"] = refreshed["id"]
        except Exception as exc:  # noqa: BLE001 - update already succeeded
            if container_components_for_selection(components):
                raise
            result["recheck_error"] = str(exc)[:4096]
            try:
                LATEST_PLAN_PATH.unlink()
            except FileNotFoundError:
                pass
        update_job(
            job_id,
            status="completed",
            completed_at=utc_now(),
            current_component=None,
            output={"log": combined_log},
            result=result,
        )
    except Exception as exc:  # noqa: BLE001 - stored as bounded job failure
        finish_failed(job_id, exc, combined_log)
    finally:
        try:
            ACTIVE_MARKER.unlink()
        except FileNotFoundError:
            pass
        release_operation(lock_fd)
        request_self_restart_if_needed()


def start_thread(target: Any, *args: Any) -> None:
    threading.Thread(target=target, args=args, daemon=True).start()


def start_check(request: dict[str, Any]) -> dict[str, Any]:
    release_channel = request.get("release_channel")
    if release_channel is not None and release_channel not in RELEASE_CHANNELS:
        raise UpdatedError("release channel must be stable, alpha or local")
    image_channel = request.get("image_channel")
    source_channel = request.get("source_channel")
    branch: str | None = None
    # A unified release channel derives the source/branch/image to preview
    # without persisting anything first.
    if release_channel == "local":
        source_channel = "local"
    elif release_channel in RELEASE_CHANNEL_MAP:
        mapping = RELEASE_CHANNEL_MAP[release_channel]
        source_channel = "github"
        branch = mapping["branch"]
        image_channel = mapping["image_channel"]
    if image_channel is not None and image_channel not in IMAGE_CHANNELS:
        raise UpdatedError("image channel must be latest or alpha")
    if source_channel is not None and source_channel not in SOURCE_CHANNELS:
        raise UpdatedError("source channel must be github or local")
    if branch is not None and not BRANCH_RE.fullmatch(branch):
        raise UpdatedError("invalid git branch")
    lock_fd = acquire_operation()
    try:
        job = new_job("check")
        start_thread(
            check_worker, job["id"], lock_fd, image_channel, source_channel, branch
        )
        return {"ok": True, "job_id": job["id"], "job": public_job(job)}
    except Exception:
        release_operation(lock_fd)
        raise


def start_apply(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("confirmation") != "UPDATE":
        raise UpdatedError("type UPDATE to confirm component updates")
    plan_id = identifier(request.get("plan_id"), "plan id")
    plan = load_latest_plan()
    if plan is None or plan.get("id") != plan_id or plan_is_expired(plan):
        raise UpdatedError("the update plan is stale; check again", code="stale_plan")
    components = selected_components(request.get("components"))
    validate_selection(plan, components)
    lock_fd = acquire_operation()
    try:
        job = new_job(
            "apply",
            components=components,
            plan_id=plan_id,
        )
        start_thread(apply_worker, job["id"], lock_fd, plan, components)
        return {"ok": True, "job_id": job["id"], "job": public_job(job)}
    except Exception:
        release_operation(lock_fd)
        raise


def read_deployment() -> dict[str, str]:
    deployment: dict[str, str] = {}
    metadata_path = CONFIG_DIR / "metadata.yml"
    try:
        info = metadata_path.lstat()
        if (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_size <= MAX_STATE_BYTES
        ):
            metadata_text = metadata_path.read_text(encoding="utf-8")
            for key, allowed in (
                ("source_channel", SOURCE_CHANNELS),
                ("image_channel", IMAGE_CHANNELS),
            ):
                match = re.search(
                    rf"(?m)^{key}:\s*['\"]?([a-z]+)['\"]?\s*(?:#.*)?$",
                    metadata_text,
                )
                if match and match.group(1) in allowed:
                    deployment[key] = match.group(1)
            branch_match = re.search(
                r"(?m)^branch:\s*['\"]?([A-Za-z0-9._/-]{1,100})['\"]?\s*(?:#.*)?$",
                metadata_text,
            )
            if branch_match and BRANCH_RE.fullmatch(branch_match.group(1)):
                deployment["branch"] = branch_match.group(1)
    except (OSError, UnicodeError):
        pass
    deployment["release_channel"] = derive_release_channel(
        deployment.get("source_channel", "github"),
        deployment.get("branch", "main"),
        deployment.get("image_channel", "latest"),
    )
    return deployment


def set_channels(request: dict[str, Any]) -> dict[str, Any]:
    release_channel = request.get("release_channel")
    if release_channel is not None and release_channel not in RELEASE_CHANNELS:
        raise UpdatedError("release channel must be stable, alpha or local")
    source_channel = request.get("source_channel")
    if source_channel is not None and source_channel not in SOURCE_CHANNELS:
        raise UpdatedError("source channel must be github or local")
    image_channel = request.get("image_channel")
    if image_channel is not None and image_channel not in IMAGE_CHANNELS:
        raise UpdatedError("image channel must be latest or alpha")
    if release_channel is None and source_channel is None and image_channel is None:
        raise UpdatedError("select a channel to persist")
    command = [str(CLI_PATH), "set-channels"]
    if release_channel is not None:
        command.extend(("--release-channel", release_channel))
    if source_channel is not None:
        command.extend(("--source-channel", source_channel))
    if image_channel is not None:
        command.extend(("--image-channel", image_channel))
    lock_fd = acquire_operation()
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=child_environment(),
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            tail = sanitize_log(
                result.stdout.decode("utf-8", "replace")
            ).strip().splitlines()
            raise UpdatedError(
                "persisting the deployment channels failed"
                + (f": {tail[-1]}" if tail else "")
            )
        # A cached plan was built for the previous channels; drop it so the
        # next apply cannot silently reapply the superseded channel choice.
        try:
            LATEST_PLAN_PATH.unlink()
        except FileNotFoundError:
            pass
        return {"ok": True, "deployment": read_deployment()}
    except subprocess.TimeoutExpired as exc:
        raise UpdatedError("persisting the deployment channels timed out") from exc
    finally:
        release_operation(lock_fd)


def status_response(request: dict[str, Any]) -> dict[str, Any]:
    requested = request.get("job_id")
    jobs = (
        [load_job(identifier(requested, "job id"))]
        if requested is not None
        else list_jobs()
    )
    plan = load_latest_plan()
    if plan is not None:
        plan = dict(plan)
        plan["stale"] = plan_is_expired(plan)
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "deployment": read_deployment(),
        "plan": plan,
        "jobs": jobs,
        "active_job": active_job(),
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "reboot_scheduled": reboot_is_scheduled(),
    }


def reboot_is_scheduled() -> bool:
    return SYSTEMD_SHUTDOWN_SCHEDULED.exists()


def request_reboot(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("confirmation") != REBOOT_CONFIRMATION:
        raise UpdatedError("reboot requires an explicit confirmation")
    job = active_job()
    if job is not None:
        return {
            "ok": False,
            "error": "An update is in progress; the reboot was refused.",
            "error_code": "operation_active",
            "active_job": job,
        }
    if BACKUPD_RESTORE_ACTIVE_MARKER.exists():
        return {
            "ok": False,
            "error": "A restore is in progress; the reboot was refused.",
            "error_code": "operation_active",
        }
    try:
        result = subprocess.run(
            [
                SHUTDOWN_PATH,
                "-r",
                REBOOT_DELAY,
                "easy-ha-proxy: reboot requested from the web UI",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdatedError(f"failed to schedule the reboot: {exc}")
    if result.returncode != 0:
        raise UpdatedError(
            "failed to schedule the reboot: "
            + (result.stderr or result.stdout or "unknown error").strip()
        )
    LOG.warning("reboot scheduled from the web UI (delay %s)", REBOOT_DELAY)
    return {"ok": True, "message": "Reboot scheduled.", "reboot_scheduled": True}


def cancel_reboot(request: dict[str, Any]) -> dict[str, Any]:
    try:
        subprocess.run(
            [SHUTDOWN_PATH, "-c"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdatedError(f"failed to cancel the reboot: {exc}")
    LOG.info("reboot cancel requested from the web UI")
    return {
        "ok": True,
        "message": "Reboot canceled.",
        "reboot_scheduled": reboot_is_scheduled(),
    }


def dispatch(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise UpdatedError("request must be a JSON object")
    action = request.get("action")
    if action not in REQUEST_FIELDS:
        raise UpdatedError("unknown update broker action")
    unexpected = set(request) - REQUEST_FIELDS[action]
    if unexpected:
        raise UpdatedError("unexpected request fields: " + ", ".join(sorted(unexpected)))
    if action == "status":
        return status_response(request)
    if action == "start_check":
        return start_check(request)
    if action == "set_channels":
        return set_channels(request)
    if action == "reboot":
        return request_reboot(request)
    if action == "cancel_reboot":
        return cancel_reboot(request)
    return start_apply(request)


def peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise UpdatedError("Unix peer credentials are unavailable")
    raw = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def receive_request(connection: socket.socket) -> bytes:
    deadline = time.monotonic() + 10
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpdatedError("request timed out")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
        except socket.timeout as exc:
            raise UpdatedError("request timed out") from exc
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise UpdatedError("request is too large", code="too_large")
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise UpdatedError("request must contain exactly one JSON line")
    return bytes(data[:-1])


def handle_connection(connection: socket.socket) -> None:
    with connection:
        try:
            if peer_uid(connection) not in {0, APP_UID}:
                raise UpdatedError("socket peer is not authorized")
            request = json.loads(receive_request(connection).decode("utf-8"))
            response = dispatch(request)
        except UpdatedError as exc:
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": exc.code,
            }
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": "invalid",
            }
        except OSError as exc:
            if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                code = "insufficient_space"
            elif exc.errno in {errno.EBUSY, errno.EEXIST}:
                code = "conflict"
            elif exc.errno == errno.ENOENT:
                code = "not_found"
            else:
                code = "internal"
            response = {
                "ok": False,
                "error": str(exc)[:4096],
                "error_code": code,
            }
        except Exception:  # noqa: BLE001 - do not expose tracebacks
            LOG.exception("Unhandled update broker request error")
            response = {
                "ok": False,
                "error": "internal update broker error",
                "error_code": "internal",
            }
        encoded = (json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            encoded = (
                b'{"ok":false,"error":"response is too large",'
                b'"error_code":"too_large"}\n'
            )
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
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCKET_PATH))
        os.chown(SOCKET_PATH, APP_UID, APP_PRIMARY_GID)
        os.chmod(SOCKET_PATH, 0o600)
        server.listen(16)
        server.settimeout(1)
        LOG.info("Listening on %s", SOCKET_PATH)
        while not STOP_EVENT.is_set():
            try:
                connection, _address = server.accept()
            except socket.timeout:
                continue
            if not CONNECTION_SLOTS.acquire(blocking=False):
                with connection:
                    try:
                        connection.sendall(
                            b'{"ok":false,"error":"too many active requests",'
                            b'"error_code":"busy"}\n'
                        )
                    except OSError:
                        pass
                continue
            threading.Thread(
                target=handle_connection_in_slot,
                args=(connection,),
                daemon=True,
            ).start()
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
    except (UpdatedError, OSError, KeyError) as exc:
        LOG.error("Cannot start update broker: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
