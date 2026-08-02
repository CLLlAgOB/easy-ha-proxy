#!/usr/bin/env python3
"""Root broker for asynchronous easy-ha-proxy full backup and restore jobs.

The web application is deliberately unable to execute privileged programs or
write host configuration.  It can only place an encrypted upload in the
dedicated spool and submit one small JSON request through this Unix socket.
Passphrases are kept in the worker thread long enough to write them to the
child's stdin; they are never placed in argv, the environment, state files, or
logs.
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
import shutil
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


LOG = logging.getLogger("easy-ha-proxy-backupd")


class BackupdError(RuntimeError):
    """Expected request or job failure safe to return to the UI."""

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
        raise BackupdError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise BackupdError(f"{name} is outside the supported range")
    return value


SOCKET_PATH = Path(
    os.environ.get(
        "BACKUPD_SOCKET_PATH",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd.sock",
    )
)
SPOOL_ROOT = Path(
    os.environ.get(
        "BACKUPD_ROOT_DIR",
        "/var/lib/easy-ha-proxy/backup-web",
    )
)
JOBS_DIR = SPOOL_ROOT / "jobs"
UPLOADS_DIR = SPOOL_ROOT / "uploads"
BACKUPS_DIR = SPOOL_ROOT / "backups"
SOURCE_DIR = Path(
    os.environ.get("BACKUPD_SOURCE_DIR", "/opt/easy-ha-proxy/source")
)
APP_USER = os.environ.get("BACKUPD_SOCKET_USER", "haproxyadmin")
APP_GROUP = os.environ.get("BACKUPD_APP_GROUP", "hadmin")
RESTORE_ACTIVE_MARKER = Path(
    os.environ.get(
        "BACKUPD_RESTORE_ACTIVE_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active",
    )
)
RESTART_REQUEST_MARKER = Path(
    os.environ.get(
        "BACKUPD_RESTART_REQUEST_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd-restart.requested",
    )
)
REBOOT_MARKER = Path(
    os.environ.get(
        "BACKUPD_REBOOT_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json",
    )
)
ASSISTANT_REBOOT_MARKER = Path("/run/easy-ha-proxy/reboot-scheduled")
OPERATION_LOCK_PATH = Path(
    os.environ.get(
        "BACKUPD_OPERATION_LOCK",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock",
    )
)
SERVICE_NAME = os.environ.get(
    "BACKUPD_SERVICE_NAME", "easy-ha-proxy-backupd.service"
)

MAX_REQUEST_BYTES = env_int(
    "BACKUPD_MAX_REQUEST_BYTES", 64 * 1024, maximum=64 * 1024
)
MAX_ARCHIVE_BYTES = env_int(
    "BACKUPD_MAX_ARCHIVE_BYTES", 8 * 1024 * 1024 * 1024
)
MIN_FREE_BYTES = env_int("BACKUPD_MIN_FREE_BYTES", 512 * 1024 * 1024)
MAX_CAPTURE_BYTES = env_int(
    "BACKUPD_MAX_CAPTURE_BYTES", 64 * 1024, maximum=512 * 1024
)
MAX_STATE_BYTES = env_int(
    "BACKUPD_MAX_STATE_BYTES", 256 * 1024, maximum=1024 * 1024
)
JOB_TIMEOUT_SECONDS = env_int(
    "BACKUPD_JOB_TIMEOUT_SECONDS", 6 * 60 * 60, maximum=24 * 60 * 60
)
LIST_LIMIT = env_int("BACKUPD_LIST_LIMIT", 50, maximum=200)
UPLOAD_TTL_SECONDS = env_int(
    "BACKUPD_UPLOAD_TTL_SECONDS", 24 * 60 * 60, maximum=30 * 24 * 60 * 60
)
MAX_CONNECTIONS = env_int("BACKUPD_MAX_CONNECTIONS", 16, maximum=64)

IDENTIFIER_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARCHIVE_SUFFIX = ".tar.gz.enc"
CHECKSUM_SUFFIX = ARCHIVE_SUFFIX + ".sha256"
META_SUFFIX = ARCHIVE_SUFFIX + ".json"
STAGE_RECORD_PREFIX = "stage-"
STAGE_RECORD_SUFFIX = ".json"
ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "interrupted"})
MANIFEST_MARKER = "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
BACKUP_FILE_MARKER = "EASY_HA_PROXY_FULL_BACKUP_FILE="
MANIFEST_KEYS = (
    "format",
    "format_version",
    "created_at",
    "hostname",
    "machine",
    "ssh_included",
    "quiesced",
    "payload_sha256",
    "ssh_payload_sha256",
    "payload_expanded_bytes",
    "ssh_payload_expanded_bytes",
    "root_domain",
    "admin_domain",
    "configuration_mode",
)

REQUEST_FIELDS = {
    "status": frozenset({"action", "job_id"}),
    "stage_backup": frozenset({"action", "backup_id"}),
    "start_backup": frozenset(
        {"action", "passphrase", "include_ssh", "quiesce"}
    ),
    "start_inspect": frozenset({"action", "upload_id", "passphrase"}),
    "start_restore": frozenset(
        {
            "action",
            "upload_id",
            "passphrase",
            "inspection_job_id",
            "restore_ssh",
            "confirmation",
            "scope",
        }
    ),
    "delete": frozenset({"action", "kind", "id", "confirmation"}),
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
        raise BackupdError(f"invalid {label}")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise BackupdError(f"{label} must be true or false")
    return value


def require_passphrase(value: Any) -> str:
    if not isinstance(value, str) or len(value) < 12:
        raise BackupdError("the backup passphrase must contain at least 12 characters")
    if len(value) > 1024 or "\x00" in value or "\n" in value or "\r" in value:
        raise BackupdError("the backup passphrase is invalid")
    return value


def ensure_absolute_path(path: Path, label: str) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise BackupdError(f"unsafe {label}")


def ensure_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    ensure_absolute_path(path, "spool path")
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise BackupdError(f"spool path is not a real directory: {path}")
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
        (SPOOL_ROOT, "spool root"),
        (SOURCE_DIR, "source path"),
        (RESTORE_ACTIVE_MARKER, "restore marker"),
        (RESTART_REQUEST_MARKER, "restart marker"),
        (REBOOT_MARKER, "reboot marker"),
        (ASSISTANT_REBOOT_MARKER, "assistant reboot marker"),
        (OPERATION_LOCK_PATH, "operation lock"),
    ):
        ensure_absolute_path(path, label)

    ensure_directory(SPOOL_ROOT, uid=0, gid=APP_GROUP_GID, mode=0o750)
    ensure_directory(JOBS_DIR, uid=0, gid=APP_GROUP_GID, mode=0o750)
    ensure_directory(BACKUPS_DIR, uid=0, gid=APP_GROUP_GID, mode=0o750)
    ensure_directory(
        UPLOADS_DIR,
        uid=APP_UID,
        gid=APP_PRIMARY_GID,
        mode=0o700,
    )
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chown(SOCKET_PATH.parent, 0, APP_GROUP_GID)
    os.chmod(SOCKET_PATH.parent, 0o750)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, payload: dict[str, Any], *, mode: int = 0o640) -> None:
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_STATE_BYTES:
        raise BackupdError("job state is too large", code="too_large")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.fchown(descriptor, 0, APP_GROUP_GID)
            os.fchmod(descriptor, mode)
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


def safe_json_file(path: Path, *, expected_uid: int = 0) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != expected_uid
        or info.st_size <= 0
        or info.st_size > MAX_STATE_BYTES
    ):
        raise BackupdError(f"unsafe state file: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if current.st_dev != info.st_dev or current.st_ino != info.st_ino:
            raise BackupdError(f"state file changed while opening: {path.name}")
        raw = os.read(descriptor, MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_STATE_BYTES:
        raise BackupdError(f"state file is too large: {path.name}")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise BackupdError(f"invalid state file: {path.name}")
    return data


def state_path(job_id: str) -> Path:
    return JOBS_DIR / f"{identifier(job_id, 'job id')}.json"


def new_job(operation: str, *, upload_id: str | None = None) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    state = {
        "id": job_id,
        "operation": operation,
        "status": "queued",
        "created_at": utc_now(),
        "started_at": None,
        "completed_at": None,
        "upload_id": upload_id,
        "manifest": None,
        "output": None,
        "error": None,
    }
    with STATE_LOCK:
        atomic_json(state_path(job_id), state)
    return state


def load_job(job_id: str, *, include_logs: bool = True) -> dict[str, Any]:
    path = state_path(job_id)
    if not path.exists():
        raise BackupdError("job was not found", code="not_found")
    state = safe_json_file(path)
    if state.get("id") != job_id:
        raise BackupdError("job state identifier does not match")
    return public_job(state, include_logs=include_logs)


def update_job(job_id: str, **updates: Any) -> dict[str, Any]:
    with STATE_LOCK:
        path = state_path(job_id)
        state = safe_json_file(path)
        state.update(updates)
        atomic_json(path, state)
    return public_job(state)


def public_job(
    state: dict[str, Any],
    *,
    include_logs: bool = True,
) -> dict[str, Any]:
    output = state.get("output") if isinstance(state.get("output"), dict) else None
    if output is not None and not include_logs:
        output = {
            key: value
            for key, value in output.items()
            if key not in {"stdout", "stderr"}
        }
    return {
        "id": str(state.get("id") or ""),
        "operation": str(state.get("operation") or ""),
        "status": str(state.get("status") or ""),
        "created_at": state.get("created_at"),
        "started_at": state.get("started_at"),
        "completed_at": state.get("completed_at"),
        "upload_id": state.get("upload_id"),
        "scope": state.get("scope"),
        "manifest": state.get("manifest") if isinstance(state.get("manifest"), dict) else None,
        "output": output,
        "error": str(state.get("error"))[:4096] if state.get("error") else None,
    }


def list_jobs() -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for path in JOBS_DIR.glob("*.json"):
        job_id = path.stem
        if not IDENTIFIER_RE.fullmatch(job_id):
            continue
        try:
            jobs.append(load_job(job_id, include_logs=False))
        except (BackupdError, OSError, ValueError, json.JSONDecodeError):
            LOG.warning("Ignoring unsafe job state %s", path.name)
    jobs.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return jobs[:LIST_LIMIT]


def active_job() -> dict[str, Any] | None:
    for job in list_jobs():
        if job.get("status") in ACTIVE_STATUSES:
            return job
    return None


def recover_stale_jobs() -> None:
    for job in list_jobs():
        if job.get("status") in ACTIVE_STATUSES:
            update_job(
                job["id"],
                status="interrupted",
                completed_at=utc_now(),
                error="the backup daemon restarted before the job completed",
            )
    for marker in (RESTORE_ACTIVE_MARKER, RESTART_REQUEST_MARKER):
        try:
            marker.unlink()
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
                "easy-ha-proxy-backupd-job-*.service",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        LOG.warning("Could not list orphan transient backup jobs")
        return
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit.startswith("easy-ha-proxy-backupd-job-"):
            LOG.warning("Stopping orphan transient backup job %s", unit)
            stop_transient_unit(unit)


def cleanup_stale_worker_artifacts() -> None:
    """Remove root-owned scratch data left by an interrupted daemon process."""

    for parent in (JOBS_DIR, SOCKET_PATH.parent):
        for path in parent.glob(".job-*.*"):
            if not re.fullmatch(
                r"\.job-[0-9a-f]{12}\.(stdout|stderr|stdin)", path.name
            ):
                continue
            try:
                info = path.lstat()
                if (
                    stat.S_ISREG(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and info.st_uid == 0
                ):
                    path.unlink()
            except FileNotFoundError:
                pass

    for path in JOBS_DIR.glob(f".*.upload{ARCHIVE_SUFFIX}*"):
        name = path.name
        suffix = f".upload{ARCHIVE_SUFFIX}"
        job_id = name[1 : -len(suffix)] if name.endswith(suffix) else ""
        if name.endswith(suffix + ".sha256"):
            job_id = name[1 : -len(suffix + ".sha256")]
        if not IDENTIFIER_RE.fullmatch(job_id):
            continue
        try:
            info = path.lstat()
            if (
                stat.S_ISREG(info.st_mode)
                and not stat.S_ISLNK(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid == 0
            ):
                path.unlink()
        except FileNotFoundError:
            pass

    directory_patterns = (
        (JOBS_DIR, re.compile(r"^\.[0-9a-f]{32}\.recovery-source$")),
        (BACKUPS_DIR, re.compile(r"^\.work-[0-9a-f]{32}$")),
    )
    for parent, pattern in directory_patterns:
        for path in parent.iterdir():
            if not pattern.fullmatch(path.name):
                continue
            try:
                info = path.lstat()
                if (
                    stat.S_ISDIR(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and info.st_uid == 0
                ):
                    shutil.rmtree(path)
            except FileNotFoundError:
                pass


def upload_path(upload_id: str) -> Path:
    return UPLOADS_DIR / f"{identifier(upload_id, 'upload id')}{ARCHIVE_SUFFIX}"


def backup_archive_path(backup_id: str) -> Path:
    return BACKUPS_DIR / f"{identifier(backup_id, 'backup id')}{ARCHIVE_SUFFIX}"


def backup_checksum_path(backup_id: str) -> Path:
    return BACKUPS_DIR / f"{identifier(backup_id, 'backup id')}{CHECKSUM_SUFFIX}"


def backup_meta_path(backup_id: str) -> Path:
    return BACKUPS_DIR / f"{identifier(backup_id, 'backup id')}{META_SUFFIX}"


def stage_record_path(upload_id: str) -> Path:
    return JOBS_DIR / (
        f"{STAGE_RECORD_PREFIX}{identifier(upload_id, 'upload id')}"
        f"{STAGE_RECORD_SUFFIX}"
    )


def safe_regular_file(
    path: Path,
    *,
    expected_uid: int | None,
    maximum_size: int,
) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or (expected_uid is not None and info.st_uid != expected_uid)
        or info.st_size <= 0
    ):
        raise BackupdError(f"unsafe or unsupported file: {path.name}")
    if info.st_size > maximum_size:
        raise BackupdError(
            f"file exceeds the configured size limit: {path.name}",
            code="too_large",
        )
    return info


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def copy_upload_to_job(upload_id: str, job_id: str) -> tuple[Path, str, int]:
    source, before, expected_checksum = resolve_upload_source(upload_id)
    destination = JOBS_DIR / f".{job_id}.upload{ARCHIVE_SUFFIX}"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    source_fd = os.open(source, flags)
    destination_fd = -1
    digest = hashlib.sha256()
    copied = 0
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(source_fd)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            raise BackupdError("upload changed while it was being opened")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_ARCHIVE_BYTES:
                raise BackupdError(
                    "uploaded archive exceeds the configured limit",
                    code="too_large",
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        after = os.fstat(source_fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or copied != before.st_size
        ):
            raise BackupdError("upload changed while it was being copied")
        os.fchown(destination_fd, 0, 0)
        os.fchmod(destination_fd, 0o600)
        os.fsync(destination_fd)
        actual_checksum = digest.hexdigest()
        if expected_checksum is not None and actual_checksum != expected_checksum:
            raise BackupdError(
                "staged server backup no longer matches its checksum",
                code="conflict",
            )
    except Exception:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    return destination, actual_checksum, copied


def cleanup_job_upload(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    sidecar = Path(str(path) + ".sha256")
    try:
        sidecar.unlink()
    except FileNotFoundError:
        pass


def ensure_free_space(path: Path, required: int) -> None:
    anchor = path if path.exists() else path.parent
    free = shutil.disk_usage(anchor).free
    if free < required:
        raise BackupdError(
            f"insufficient free space: {free} bytes available, {required} required",
            code="insufficient_space",
        )


def sanitize_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BackupdError("backup manifest is not a JSON object")
    result: dict[str, Any] = {}
    for key in MANIFEST_KEYS:
        item = value.get(key)
        if item is None or isinstance(item, (str, int, float, bool)):
            if isinstance(item, str):
                item = item[:1024]
            result[key] = item
    if result.get("format") != "easy-ha-proxy-full-backup":
        raise BackupdError("unsupported full-backup manifest")
    for key in ("payload_expanded_bytes", "ssh_payload_expanded_bytes"):
        size = result.get(key)
        if size is not None and (
            not isinstance(size, int) or isinstance(size, bool) or size < 0
        ):
            raise BackupdError(f"backup manifest field is invalid: {key}")
    return result


def restore_expanded_bytes(
    manifest: dict[str, Any],
    *,
    restore_ssh: bool,
) -> int:
    core = manifest.get("payload_expanded_bytes")
    if not isinstance(core, int) or isinstance(core, bool) or core < 0:
        raise BackupdError(
            "repeat archive inspection to calculate restore disk requirements",
            code="conflict",
        )
    ssh: Any = 0
    if restore_ssh and manifest.get("ssh_included") is True:
        ssh = manifest.get("ssh_payload_expanded_bytes")
        if not isinstance(ssh, int) or isinstance(ssh, bool) or ssh < 0:
            raise BackupdError(
                "repeat archive inspection to calculate SSH restore disk requirements",
                code="conflict",
            )
    total = core + ssh
    if total > 65 * 1024 * 1024 * 1024:
        raise BackupdError(
            "expanded backup exceeds the supported restore limit",
            code="too_large",
        )
    return total


def marker_value(output: str, marker: str) -> str:
    for line in reversed(output.splitlines()):
        if line.startswith(marker):
            value = line[len(marker) :].strip()
            if not value or len(value.encode("utf-8")) > MAX_STATE_BYTES:
                raise BackupdError(f"invalid {marker.rstrip('=')} marker")
            return value
    raise BackupdError(f"backup helper did not return {marker.rstrip('=')}")


def manifest_from_output(output: str) -> dict[str, Any]:
    raw = marker_value(output, MANIFEST_MARKER)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BackupdError("backup helper returned invalid manifest JSON") from exc
    return sanitize_manifest(parsed)


def sanitize_output(value: str, passphrase: str) -> str:
    if passphrase:
        value = value.replace(passphrase, "[REDACTED]")
    clean_lines: list[str] = []
    for raw_line in value.splitlines():
        if raw_line.startswith(MANIFEST_MARKER):
            raw_line = MANIFEST_MARKER + "<omitted>"
        elif raw_line.startswith(BACKUP_FILE_MARKER):
            raw_line = BACKUP_FILE_MARKER + "<stored>"
        clean = "".join(
            character
            for character in raw_line
            if character in "\t" or ord(character) >= 32
        )
        clean_lines.append(clean)
    result = "\n".join(clean_lines)
    encoded = result.encode("utf-8", "replace")
    if len(encoded) > MAX_CAPTURE_BYTES:
        encoded = encoded[-MAX_CAPTURE_BYTES:]
        result = "[output truncated]\n" + encoded.decode("utf-8", "replace")
    return result


def read_tail(stream: Any) -> str:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    end = stream.tell()
    stream.seek(max(0, end - max(MAX_CAPTURE_BYTES * 4, MAX_STATE_BYTES)))
    return stream.read().decode("utf-8", "replace")


def live_tail(stream: Any, limit: int) -> str:
    """Read the last bytes without moving the shared child file offset."""

    descriptor = stream.fileno()
    size = os.fstat(descriptor).st_size
    if size <= 0:
        return ""
    offset = max(0, size - limit)
    return os.pread(descriptor, size - offset, offset).decode("utf-8", "replace")


def publish_live_output(
    job_id: str,
    stdout_file: Any,
    stderr_file: Any,
    passphrase: str,
) -> None:
    """Best-effort live progress: a failed publish must never fail the job."""

    limit = MAX_CAPTURE_BYTES // 2
    try:
        update_job(
            job_id,
            output={
                "stdout": sanitize_output(live_tail(stdout_file, limit), passphrase),
                "stderr": sanitize_output(live_tail(stderr_file, limit), passphrase),
                "live": True,
            },
        )
    except (BackupdError, OSError, ValueError, json.JSONDecodeError):
        LOG.debug("Skipping one live progress publish for job %s", job_id)


def child_environment(*, recovery_source: Path | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PYTHONUNBUFFERED": "1",
        # The web broker runs with a hardened service sandbox. Its overlay
        # restore must reconcile only from dependencies and images already on
        # the host; direct controller restores remain network-capable.
        "EASY_HA_PROXY_OFFLINE_RESTORE": "1",
    }
    if recovery_source is not None:
        environment["EASY_HA_PROXY_SOURCE_DIR"] = str(recovery_source)
    return environment


SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
TRANSIENT_STOP_TIMEOUT = 30


def transient_jobs_supported() -> bool:
    """Privileged children escape this broker's sandbox through PID 1.

    The broker unit keeps NoNewPrivileges; snap-confined certbot inside the
    restore reconciliation only works when its processes are spawned by
    systemd itself as transient units. Unprivileged test runs fall back to
    direct execution.
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


def read_path_tail(path: Path, limit: int) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return ""
    try:
        size = os.fstat(descriptor).st_size
        if size <= 0:
            return ""
        offset = max(0, size - limit)
        return os.pread(descriptor, size - offset, offset).decode("utf-8", "replace")
    finally:
        os.close(descriptor)


def private_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_transient_helper(
    argv: list[str],
    passphrase: str,
    *,
    job_id: str | None = None,
    recovery_source: Path | None = None,
) -> tuple[int, str, str, str, str]:
    token = uuid.uuid4().hex[:12]
    unit = f"easy-ha-proxy-backupd-job-{token}.service"
    stdout_path = JOBS_DIR / f".job-{token}.stdout"
    stderr_path = JOBS_DIR / f".job-{token}.stderr"
    # The helper only accepts its passphrase on stdin; the transient unit
    # reads it from a root-only file on the runtime tmpfs (never persisted to
    # disk) that is removed as soon as the job finishes.
    stdin_path = SOCKET_PATH.parent / f".job-{token}.stdin"
    private_file(stdout_path, b"")
    private_file(stderr_path, b"")
    private_file(stdin_path, (passphrase + "\n").encode("utf-8"))
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
        f"StandardInput=file:{stdin_path}",
        "-p",
        f"StandardOutput=append:{stdout_path}",
        "-p",
        f"StandardError=append:{stderr_path}",
        "-p",
        "KillMode=control-group",
        "-p",
        f"TimeoutStopSec={TRANSIENT_STOP_TIMEOUT}",
    ]
    for key, value in child_environment(recovery_source=recovery_source).items():
        command.append(f"--setenv={key}={value}")
    command.append("--")
    command.extend(argv)
    returncode: int | None = None
    try:
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
            raise BackupdError(f"could not start the privileged backup job: {exc}") from exc
        if started.returncode != 0:
            detail = started.stderr.decode("utf-8", "replace").strip()
            raise BackupdError(
                "could not start the privileged backup job"
                + (f": {detail}" if detail else "")
            )
        begun = time.monotonic()
        last_publish = 0.0
        while True:
            properties = systemctl_properties(
                unit,
                ["LoadState", "ActiveState", "SubState", "ExecMainStatus"],
            )
            active = properties.get("ActiveState", "")
            if properties.get("LoadState") == "not-found":
                returncode = 0
                break
            if active == "failed":
                try:
                    returncode = int(properties.get("ExecMainStatus") or 1)
                except ValueError:
                    returncode = 1
                returncode = returncode or 1
                break
            if active == "active" and properties.get("SubState") == "exited":
                try:
                    returncode = int(properties.get("ExecMainStatus") or 0)
                except ValueError:
                    returncode = 0
                break
            if time.monotonic() - begun > JOB_TIMEOUT_SECONDS:
                raise BackupdError("backup job exceeded the configured timeout")
            if job_id is not None and time.monotonic() - last_publish >= 2:
                limit = MAX_CAPTURE_BYTES // 2
                try:
                    update_job(
                        job_id,
                        output={
                            "stdout": sanitize_output(
                                read_path_tail(stdout_path, limit), passphrase
                            ),
                            "stderr": sanitize_output(
                                read_path_tail(stderr_path, limit), passphrase
                            ),
                            "live": True,
                        },
                    )
                except (BackupdError, OSError, ValueError, json.JSONDecodeError):
                    LOG.debug("Skipping one live progress publish for job %s", job_id)
                last_publish = time.monotonic()
            time.sleep(0.5)
        tail_limit = max(MAX_CAPTURE_BYTES * 4, MAX_STATE_BYTES)
        raw_stdout = read_path_tail(stdout_path, tail_limit)
        raw_stderr = read_path_tail(stderr_path, tail_limit)
        return (
            returncode,
            raw_stdout,
            raw_stderr,
            sanitize_output(raw_stdout, passphrase),
            sanitize_output(raw_stderr, passphrase),
        )
    finally:
        stop_transient_unit(unit)
        stdin_path.unlink(missing_ok=True)
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)


def run_helper(
    argv: list[str],
    passphrase: str,
    *,
    job_id: str | None = None,
    recovery_source: Path | None = None,
) -> tuple[int, str, str, str, str]:
    if transient_jobs_supported():
        return run_transient_helper(
            argv, passphrase, job_id=job_id, recovery_source=recovery_source
        )
    return run_direct_helper(
        argv, passphrase, job_id=job_id, recovery_source=recovery_source
    )


def run_direct_helper(
    argv: list[str],
    passphrase: str,
    *,
    job_id: str | None = None,
    recovery_source: Path | None = None,
) -> tuple[int, str, str, str, str]:
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
            env=child_environment(recovery_source=recovery_source),
            start_new_session=True,
        )
        try:
            assert process.stdin is not None
            try:
                process.stdin.write((passphrase + "\n").encode("utf-8"))
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()
            deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
            last_publish = 0.0
            while True:
                try:
                    returncode = process.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() >= deadline:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    raise BackupdError("backup job exceeded the configured timeout")
                if job_id is not None and time.monotonic() - last_publish >= 2:
                    publish_live_output(job_id, stdout_file, stderr_file, passphrase)
                    last_publish = time.monotonic()
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            else:
                # The helper should not leave detached tar/openssl/Ansible
                # descendants after its own exit. Kill any process still in
                # the per-job session before the operation lock is released.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        raw_stdout = read_tail(stdout_file)
        raw_stderr = read_tail(stderr_file)
    return (
        returncode,
        raw_stdout,
        raw_stderr,
        sanitize_output(raw_stdout, passphrase),
        sanitize_output(raw_stderr, passphrase),
    )


def helper_script() -> Path:
    script = SOURCE_DIR / "installer/full_backup.py"
    info = script.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise BackupdError("the managed full-backup helper is unavailable")
    return script


def acquire_operation() -> int:
    # A worker persists its terminal state immediately before its finally block
    # releases the lock. Give that very small hand-off window a chance to close
    # so a UI action submitted as soon as polling observes "completed" does not
    # receive a spurious busy response. Genuinely active jobs still fail fast.
    if SHUTDOWN_REQUESTED.is_set():
        raise BackupdError("backup daemon is shutting down", code="conflict")
    if os.path.lexists(REBOOT_MARKER) or os.path.lexists(ASSISTANT_REBOOT_MARKER):
        raise BackupdError("a server reboot is scheduled", code="conflict")
    deadline = time.monotonic() + 1.0
    while not OPERATION_THREAD_LOCK.acquire(blocking=False):
        if time.monotonic() >= deadline:
            raise BackupdError(
                "another backup operation is already active",
                code="busy",
            )
        time.sleep(0.02)
    descriptor = -1
    try:
        descriptor = os.open(OPERATION_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if SHUTDOWN_REQUESTED.is_set():
            release_operation(descriptor)
            raise BackupdError("backup daemon is shutting down", code="conflict")
        if os.path.lexists(REBOOT_MARKER) or os.path.lexists(
            ASSISTANT_REBOOT_MARKER
        ):
            release_operation(descriptor)
            raise BackupdError("a server reboot is scheduled", code="conflict")
        return descriptor
    except (OSError, BlockingIOError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        OPERATION_THREAD_LOCK.release()
        if SHUTDOWN_REQUESTED.is_set():
            STOP_EVENT.set()
        raise BackupdError(
            "another backup operation is already active",
            code="busy",
        ) from exc


def release_operation(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
        OPERATION_THREAD_LOCK.release()
        if SHUTDOWN_REQUESTED.is_set():
            STOP_EVENT.set()


def result_output(
    returncode: int,
    stdout: str,
    stderr: str,
    **values: Any,
) -> dict[str, Any]:
    result = {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }
    result.update(values)
    return result


def finish_failed(
    job_id: str,
    exc: Exception,
    *,
    returncode: int | None = None,
    stdout: str = "",
    stderr: str = "",
) -> None:
    message = str(exc) or exc.__class__.__name__
    detail = next(
        (line.strip() for line in reversed(stderr.splitlines()) if line.strip()),
        "",
    )
    if detail and detail not in message:
        message = f"{message}: {detail}"
    message = message[:4096]
    update_job(
        job_id,
        status="failed",
        completed_at=utc_now(),
        output=result_output(returncode or 1, stdout, stderr),
        error=message,
    )
    LOG.warning("Job %s failed: %s", job_id, message)


def store_backup_artifact(
    job_id: str,
    raw_stdout: str,
    manifest: dict[str, Any],
    work_dir: Path,
) -> dict[str, Any]:
    marker = marker_value(raw_stdout, BACKUP_FILE_MARKER)
    candidate = Path(marker)
    if not candidate.is_absolute():
        raise BackupdError("backup helper returned a relative archive path")
    resolved_work = work_dir.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_work)
    except ValueError as exc:
        raise BackupdError("backup helper returned an archive outside its work area") from exc
    info = safe_regular_file(
        candidate,
        expected_uid=0,
        maximum_size=MAX_ARCHIVE_BYTES,
    )
    checksum_source = Path(str(candidate) + ".sha256")
    checksum_info = safe_regular_file(
        checksum_source,
        expected_uid=0,
        maximum_size=64 * 1024,
    )
    checksum = sha256_file(candidate)
    expected = read_checksum_file(checksum_source, checksum_info)
    if expected != checksum:
        raise BackupdError("backup helper checksum does not match the encrypted archive")

    backup_id = uuid.uuid4().hex
    destination = backup_archive_path(backup_id)
    checksum_destination = backup_checksum_path(backup_id)
    metadata_path = backup_meta_path(backup_id)
    checksum_temporary = BACKUPS_DIR / f".{checksum_destination.name}.tmp"
    metadata = {
        "id": backup_id,
        "archive_name": destination.name,
        "checksum_name": checksum_destination.name,
        "size_bytes": info.st_size,
        "created_at": str(manifest.get("created_at") or utc_now()),
        "sha256": checksum,
        "manifest": manifest,
        "job_id": job_id,
    }
    try:
        os.replace(candidate, destination)
        os.replace(checksum_source, checksum_destination)
        os.chown(destination, 0, APP_GROUP_GID)
        os.chmod(destination, 0o640)
        descriptor = os.open(
            checksum_temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(
                f"{checksum}  {destination.name}\n".encode("ascii")
            )
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fchown(descriptor, 0, APP_GROUP_GID)
            os.fchmod(descriptor, 0o640)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(checksum_temporary, checksum_destination)
        atomic_json(metadata_path, metadata)
        fsync_directory(BACKUPS_DIR)
    except Exception:
        for path in (
            destination,
            checksum_destination,
            checksum_temporary,
            metadata_path,
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        fsync_directory(BACKUPS_DIR)
        raise
    return public_backup(metadata)


def public_backup(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(value.get("id") or ""),
        "archive_name": str(value.get("archive_name") or ""),
        "checksum_name": str(value.get("checksum_name") or ""),
        "size_bytes": int(value.get("size_bytes") or 0),
        "created_at": value.get("created_at"),
        "sha256": str(value.get("sha256") or ""),
        "manifest": value.get("manifest") if isinstance(value.get("manifest"), dict) else None,
    }


def list_backups() -> list[dict[str, Any]]:
    backups: list[dict[str, Any]] = []
    for path in BACKUPS_DIR.glob(f"*{META_SUFFIX}"):
        backup_id = path.name[: -len(META_SUFFIX)]
        if not IDENTIFIER_RE.fullmatch(backup_id):
            continue
        try:
            metadata = safe_json_file(path)
            if metadata.get("id") != backup_id:
                raise BackupdError("backup metadata identifier does not match")
            archive = backup_archive_path(backup_id)
            checksum = backup_checksum_path(backup_id)
            archive_info = safe_regular_file(
                archive,
                expected_uid=0,
                maximum_size=MAX_ARCHIVE_BYTES,
            )
            safe_regular_file(checksum, expected_uid=0, maximum_size=64 * 1024)
            if archive_info.st_size != int(metadata.get("size_bytes") or -1):
                raise BackupdError("backup size does not match metadata")
            if not SHA256_RE.fullmatch(str(metadata.get("sha256") or "")):
                raise BackupdError("backup metadata checksum is invalid")
            backups.append(public_backup(metadata))
        except (BackupdError, OSError, ValueError, json.JSONDecodeError):
            LOG.warning("Ignoring unsafe backup metadata %s", path.name)
    backups.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return backups[:LIST_LIMIT]


def read_checksum_file(path: Path, info: os.stat_result) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != info.st_dev or opened.st_ino != info.st_ino:
            raise BackupdError("backup checksum changed while it was being opened")
        raw = os.read(descriptor, 64 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(raw) > 64 * 1024:
        raise BackupdError("backup checksum file is too large", code="too_large")
    try:
        checksum = raw.decode("ascii", "strict").split()[0]
    except (UnicodeDecodeError, IndexError) as exc:
        raise BackupdError("backup checksum file is invalid") from exc
    if not SHA256_RE.fullmatch(checksum):
        raise BackupdError("backup checksum file is invalid")
    return checksum


def verified_backup_files(
    backup_id: str,
    *,
    verify_content: bool = False,
) -> tuple[Path, os.stat_result, str]:
    archive = backup_archive_path(backup_id)
    checksum_path = backup_checksum_path(backup_id)
    metadata_path = backup_meta_path(backup_id)
    archive_info = safe_regular_file(
        archive,
        expected_uid=0,
        maximum_size=MAX_ARCHIVE_BYTES,
    )
    checksum_info = safe_regular_file(
        checksum_path,
        expected_uid=0,
        maximum_size=64 * 1024,
    )
    metadata = safe_json_file(metadata_path)
    if (
        metadata.get("id") != backup_id
        or metadata.get("archive_name") != archive.name
        or metadata.get("checksum_name") != checksum_path.name
        or int(metadata.get("size_bytes") or -1) != archive_info.st_size
    ):
        raise BackupdError("backup metadata does not match its files")
    sanitize_manifest(metadata.get("manifest"))
    expected = str(metadata.get("sha256") or "")
    if not SHA256_RE.fullmatch(expected):
        raise BackupdError("backup metadata checksum is invalid")
    if read_checksum_file(checksum_path, checksum_info) != expected:
        raise BackupdError("backup checksum sidecar does not match metadata")
    if verify_content and sha256_file(archive) != expected:
        raise BackupdError("backup archive checksum verification failed")
    return archive, archive_info, expected


def load_stage_record(
    upload_id: str,
) -> tuple[dict[str, Any], Path, os.stat_result, str] | None:
    path = stage_record_path(upload_id)
    try:
        record = safe_json_file(path)
    except FileNotFoundError:
        return None
    backup_id = identifier(record.get("backup_id"), "staged backup id")
    if record.get("upload_id") != upload_id:
        raise BackupdError("staged backup record identifier does not match")
    archive, archive_info, expected = verified_backup_files(backup_id)
    if (
        record.get("sha256") != expected
        or int(record.get("size_bytes") or -1) != archive_info.st_size
    ):
        raise BackupdError(
            "staged backup record no longer matches the server backup",
            code="conflict",
        )
    return record, archive, archive_info, expected


def resolve_upload_source(
    upload_id: str,
) -> tuple[Path, os.stat_result, str | None]:
    staged = load_stage_record(upload_id)
    if staged is not None:
        _record, archive, archive_info, expected = staged
        return archive, archive_info, expected
    source = upload_path(upload_id)
    try:
        info = safe_regular_file(
            source,
            expected_uid=APP_UID,
            maximum_size=MAX_ARCHIVE_BYTES,
        )
    except FileNotFoundError as exc:
        raise BackupdError("uploaded archive was not found", code="not_found") from exc
    return source, info, None


def stage_backup(request: dict[str, Any]) -> dict[str, Any]:
    backup_id = identifier(request.get("backup_id"), "backup id")
    lock_fd = acquire_operation()
    try:
        _archive, archive_info, expected_checksum = verified_backup_files(backup_id)
        upload_id = uuid.uuid4().hex
        while stage_record_path(upload_id).exists():
            upload_id = uuid.uuid4().hex
        atomic_json(
            stage_record_path(upload_id),
            {
                "upload_id": upload_id,
                "backup_id": backup_id,
                "sha256": expected_checksum,
                "size_bytes": archive_info.st_size,
                "created_at": utc_now(),
            },
        )
        return {"ok": True, "upload_id": upload_id, "size": archive_info.st_size}
    finally:
        release_operation(lock_fd)


def successful_inspections() -> dict[str, dict[str, Any]]:
    inspections: dict[str, dict[str, Any]] = {}
    for job in list_jobs():
        if (
            job.get("operation") == "inspect"
            and job.get("status") == "completed"
            and isinstance(job.get("output"), dict)
            and isinstance(job.get("upload_id"), str)
        ):
            inspections.setdefault(job["upload_id"], job)
    return inspections


def expire_orphaned_uploads() -> None:
    if not OPERATION_THREAD_LOCK.acquire(blocking=False):
        return
    try:
        cutoff = time.time() - UPLOAD_TTL_SECONDS
        for path in UPLOADS_DIR.glob(".*.part"):
            upload_id = path.name[1:-len(".part")]
            if not IDENTIFIER_RE.fullmatch(upload_id):
                continue
            try:
                info = path.lstat()
                if (
                    stat.S_ISREG(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and info.st_nlink == 1
                    and info.st_uid == APP_UID
                    and info.st_mtime < cutoff
                ):
                    path.unlink()
                    LOG.info("Expired interrupted upload %s", upload_id)
            except FileNotFoundError:
                continue
            except OSError:
                LOG.warning("Could not safely expire upload part %s", path.name)
        for path in UPLOADS_DIR.glob(f"*{ARCHIVE_SUFFIX}"):
            upload_id = path.name[: -len(ARCHIVE_SUFFIX)]
            if not IDENTIFIER_RE.fullmatch(upload_id):
                continue
            try:
                info = safe_regular_file(
                    path,
                    expected_uid=APP_UID,
                    maximum_size=MAX_ARCHIVE_BYTES,
                )
                if info.st_mtime < cutoff:
                    path.unlink()
                    LOG.info("Expired orphaned upload %s", upload_id)
            except FileNotFoundError:
                continue
            except (BackupdError, OSError):
                LOG.warning("Could not safely expire upload %s", path.name)
        for path in JOBS_DIR.glob(
            f"{STAGE_RECORD_PREFIX}*{STAGE_RECORD_SUFFIX}"
        ):
            upload_id = path.name[
                len(STAGE_RECORD_PREFIX) : -len(STAGE_RECORD_SUFFIX)
            ]
            if not IDENTIFIER_RE.fullmatch(upload_id):
                continue
            try:
                info = path.lstat()
                safe_json_file(path)
                if info.st_mtime < cutoff:
                    path.unlink()
                    LOG.info("Expired staged server backup %s", upload_id)
            except FileNotFoundError:
                continue
            except (BackupdError, OSError, ValueError, json.JSONDecodeError):
                LOG.warning("Could not safely expire stage record %s", path.name)
    finally:
        OPERATION_THREAD_LOCK.release()
        if SHUTDOWN_REQUESTED.is_set():
            STOP_EVENT.set()


def list_uploads() -> list[dict[str, Any]]:
    inspections = successful_inspections()
    uploads: list[dict[str, Any]] = []
    for path in UPLOADS_DIR.glob(f"*{ARCHIVE_SUFFIX}"):
        upload_id = path.name[: -len(ARCHIVE_SUFFIX)]
        if not IDENTIFIER_RE.fullmatch(upload_id):
            continue
        try:
            info = safe_regular_file(
                path,
                expected_uid=APP_UID,
                maximum_size=MAX_ARCHIVE_BYTES,
            )
        except (BackupdError, OSError):
            continue
        inspection = inspections.get(upload_id)
        output = inspection.get("output") if inspection else None
        uploads.append(
            {
                "id": upload_id,
                "archive_name": path.name,
                "size_bytes": info.st_size,
                "created_at": dt.datetime.fromtimestamp(
                    info.st_mtime, tz=dt.timezone.utc
                ).isoformat(),
                "sha256": output.get("sha256") if isinstance(output, dict) else None,
                "manifest": inspection.get("manifest") if inspection else None,
                "inspection_job_id": inspection.get("id") if inspection else None,
            }
        )
    for path in JOBS_DIR.glob(
        f"{STAGE_RECORD_PREFIX}*{STAGE_RECORD_SUFFIX}"
    ):
        upload_id = path.name[
            len(STAGE_RECORD_PREFIX) : -len(STAGE_RECORD_SUFFIX)
        ]
        if not IDENTIFIER_RE.fullmatch(upload_id):
            continue
        try:
            record_data = load_stage_record(upload_id)
            if record_data is None:
                continue
            record, _archive, archive_info, _expected = record_data
        except (BackupdError, OSError, ValueError, json.JSONDecodeError):
            LOG.warning("Ignoring unsafe staged server backup %s", path.name)
            continue
        uploads = [item for item in uploads if item.get("id") != upload_id]
        inspection = inspections.get(upload_id)
        output = inspection.get("output") if inspection else None
        uploads.append(
            {
                "id": upload_id,
                "archive_name": f"{upload_id}{ARCHIVE_SUFFIX}",
                "size_bytes": archive_info.st_size,
                "created_at": record.get("created_at"),
                "sha256": output.get("sha256") if isinstance(output, dict) else None,
                "manifest": inspection.get("manifest") if inspection else None,
                "inspection_job_id": inspection.get("id") if inspection else None,
                "staged_backup_id": record.get("backup_id"),
            }
        )
    uploads.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return uploads[:LIST_LIMIT]


def start_worker(target: Any, *args: Any) -> None:
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()


def backup_worker(
    job_id: str,
    passphrase: str,
    include_ssh: bool,
    quiesce: bool,
    lock_fd: int,
) -> None:
    work_dir = BACKUPS_DIR / f".work-{job_id}"
    safe_stdout = ""
    safe_stderr = ""
    returncode: int | None = None
    try:
        time.sleep(2)
        update_job(job_id, status="running", started_at=utc_now())
        ensure_free_space(BACKUPS_DIR, MIN_FREE_BYTES)
        work_dir.mkdir(mode=0o700)
        command = [
            "/usr/bin/python3",
            str(helper_script()),
            "backup",
            "--output-dir",
            str(work_dir),
            "--passphrase-stdin",
        ]
        if include_ssh:
            command.append("--include-ssh")
        if not quiesce:
            command.append("--no-quiesce")
        returncode, raw_stdout, _raw_stderr, safe_stdout, safe_stderr = run_helper(
            command, passphrase, job_id=job_id
        )
        if returncode != 0:
            raise BackupdError("full backup helper failed")
        try:
            manifest = manifest_from_output(raw_stdout)
        except BackupdError:
            # Older format-v1 helpers only print the archive path during
            # creation. Inspect that just-created archive with the same
            # in-memory passphrase so the persistent artifact always has a
            # verified manifest. Newer helpers emit the marker directly and
            # skip this second decrypt/validation pass.
            marker = marker_value(raw_stdout, BACKUP_FILE_MARKER)
            candidate = Path(marker)
            resolved_work = work_dir.resolve()
            try:
                candidate.resolve().relative_to(resolved_work)
            except ValueError as exc:
                raise BackupdError(
                    "backup helper returned an archive outside its work area"
                ) from exc
            safe_regular_file(
                candidate,
                expected_uid=0,
                maximum_size=MAX_ARCHIVE_BYTES,
            )
            inspect_command = [
                "/usr/bin/python3",
                str(helper_script()),
                "inspect",
                str(candidate),
                "--passphrase-stdin",
            ]
            (
                inspect_returncode,
                inspect_raw_stdout,
                inspect_raw_stderr,
                _inspect_safe_stdout,
                _inspect_safe_stderr,
            ) = run_helper(inspect_command, passphrase, job_id=job_id)
            safe_stdout = sanitize_output(
                raw_stdout + "\n" + inspect_raw_stdout,
                passphrase,
            )
            safe_stderr = sanitize_output(
                _raw_stderr + "\n" + inspect_raw_stderr,
                passphrase,
            )
            if inspect_returncode != 0:
                returncode = inspect_returncode
                raise BackupdError("new full backup failed its manifest inspection")
            manifest = manifest_from_output(inspect_raw_stdout)
        artifact = store_backup_artifact(job_id, raw_stdout, manifest, work_dir)
        update_job(
            job_id,
            status="completed",
            completed_at=utc_now(),
            manifest=manifest,
            output=result_output(
                returncode,
                safe_stdout,
                safe_stderr,
                backup_id=artifact["id"],
                archive_name=artifact["archive_name"],
                checksum_name=artifact["checksum_name"],
                size_bytes=artifact["size_bytes"],
                sha256=artifact["sha256"],
            ),
            error=None,
        )
    except Exception as exc:  # noqa: BLE001 - job boundary
        finish_failed(
            job_id,
            exc,
            returncode=returncode,
            stdout=safe_stdout,
            stderr=safe_stderr,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        passphrase = ""
        release_operation(lock_fd)


def inspect_worker(
    job_id: str,
    upload_id: str,
    passphrase: str,
    lock_fd: int,
) -> None:
    staged: Path | None = None
    safe_stdout = ""
    safe_stderr = ""
    returncode: int | None = None
    try:
        update_job(job_id, status="running", started_at=utc_now())
        _source, upload_info, _expected = resolve_upload_source(upload_id)
        # One immutable job copy plus the decrypted outer bundle must fit.
        # The helper validates the exact outer expanded size before extraction.
        ensure_free_space(JOBS_DIR, upload_info.st_size * 2 + MIN_FREE_BYTES)
        ensure_free_space(
            Path(tempfile.gettempdir()),
            upload_info.st_size * 2 + MIN_FREE_BYTES,
        )
        staged, checksum, size = copy_upload_to_job(upload_id, job_id)
        command = [
            "/usr/bin/python3",
            str(helper_script()),
            "inspect",
            str(staged),
            "--passphrase-stdin",
        ]
        returncode, raw_stdout, _raw_stderr, safe_stdout, safe_stderr = run_helper(
            command, passphrase, job_id=job_id
        )
        if returncode != 0:
            raise BackupdError("full backup inspection failed")
        manifest = manifest_from_output(raw_stdout)
        update_job(
            job_id,
            status="completed",
            completed_at=utc_now(),
            manifest=manifest,
            output=result_output(
                returncode,
                safe_stdout,
                safe_stderr,
                sha256=checksum,
                size_bytes=size,
            ),
            error=None,
        )
    except Exception as exc:  # noqa: BLE001 - job boundary
        finish_failed(
            job_id,
            exc,
            returncode=returncode,
            stdout=safe_stdout,
            stderr=safe_stderr,
        )
    finally:
        cleanup_job_upload(staged)
        passphrase = ""
        release_operation(lock_fd)


def copy_recovery_source(job_id: str) -> Path:
    required = (
        SOURCE_DIR / "install-local.sh",
        SOURCE_DIR / "installer/full_backup.py",
        SOURCE_DIR / "installer/easy_ha_proxy.py",
        SOURCE_DIR / "ansible/easy-ha-proxy.yml",
        SOURCE_DIR / "ansible/requirements.yml",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise BackupdError("managed recovery source is incomplete")
    destination = JOBS_DIR / f".{job_id}.recovery-source"
    shutil.copytree(
        SOURCE_DIR,
        destination,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    for root, directories, files in os.walk(destination):
        os.chown(root, 0, 0)
        for name in directories:
            os.chown(os.path.join(root, name), 0, 0)
        for name in files:
            os.chown(os.path.join(root, name), 0, 0)
    return destination


def request_self_restart_if_needed() -> None:
    if not RESTART_REQUEST_MARKER.is_file():
        return
    SHUTDOWN_REQUESTED.set()
    try:
        RESTART_REQUEST_MARKER.unlink()
    except FileNotFoundError:
        return
    try:
        subprocess.Popen(
            ["/bin/systemctl", "restart", "--no-block", SERVICE_NAME],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_environment(),
            start_new_session=True,
        )
    except OSError:
        LOG.exception("Could not request a deferred backup daemon restart")


def restore_worker(
    job_id: str,
    upload_id: str,
    expected_sha256: str,
    manifest: dict[str, Any],
    passphrase: str,
    restore_ssh: bool,
    scope: str,
    lock_fd: int,
) -> None:
    staged: Path | None = None
    recovery_source: Path | None = None
    safe_stdout = ""
    safe_stderr = ""
    returncode: int | None = None
    try:
        time.sleep(2)
        update_job(job_id, status="running", started_at=utc_now())
        _source, upload_info, _expected = resolve_upload_source(upload_id)
        _expanded_bytes = restore_expanded_bytes(
            manifest,
            restore_ssh=restore_ssh,
        )
        ensure_free_space(JOBS_DIR, upload_info.st_size * 2 + MIN_FREE_BYTES)
        ensure_free_space(
            Path(tempfile.gettempdir()),
            upload_info.st_size * 2 + MIN_FREE_BYTES,
        )
        # full_backup.py performs the authoritative root-filesystem check with
        # the measured payload size, current managed-state size, and rollback
        # overhead. Avoid rejecting an exact replacement merely because both
        # old and new apparent sizes do not fit at the same time.
        ensure_free_space(Path("/"), MIN_FREE_BYTES)
        staged, checksum, size = copy_upload_to_job(upload_id, job_id)
        if checksum != expected_sha256:
            raise BackupdError(
                "uploaded archive changed after the successful inspection"
            )
        sidecar = Path(str(staged) + ".sha256")
        sidecar.write_text(f"{checksum}  {staged.name}\n", encoding="ascii")
        os.chmod(sidecar, 0o600)
        os.chown(sidecar, 0, 0)
        recovery_source = copy_recovery_source(job_id)
        command = [
            "/usr/bin/python3",
            str(recovery_source / "installer/full_backup.py"),
            "restore",
            str(staged),
            "--mode",
            "overlay",
            "--apply",
            "--yes",
            "--passphrase-stdin",
        ]
        if scope == "config":
            command.extend(("--scope", "config", "--skip-ssh"))
        else:
            command.append("--replace-managed")
            command.append("--restore-ssh" if restore_ssh else "--skip-ssh")
        returncode, _raw_stdout, _raw_stderr, safe_stdout, safe_stderr = run_helper(
            command,
            passphrase,
            job_id=job_id,
            recovery_source=recovery_source,
        )
        if returncode != 0:
            raise BackupdError("full backup restore failed")
        update_job(
            job_id,
            status="completed",
            completed_at=utc_now(),
            manifest=manifest,
            output=result_output(
                returncode,
                safe_stdout,
                safe_stderr,
                sha256=checksum,
                size_bytes=size,
            ),
            error=None,
        )
    except Exception as exc:  # noqa: BLE001 - job boundary
        finish_failed(
            job_id,
            exc,
            returncode=returncode,
            stdout=safe_stdout,
            stderr=safe_stderr,
        )
    finally:
        cleanup_job_upload(staged)
        if recovery_source is not None:
            shutil.rmtree(recovery_source, ignore_errors=True)
        try:
            RESTORE_ACTIVE_MARKER.unlink()
        except FileNotFoundError:
            pass
        passphrase = ""
        request_self_restart_if_needed()
        release_operation(lock_fd)


def start_backup(request: dict[str, Any]) -> dict[str, Any]:
    passphrase = require_passphrase(request.get("passphrase"))
    include_ssh = require_bool(request.get("include_ssh"), "include_ssh")
    quiesce = require_bool(request.get("quiesce"), "quiesce")
    lock_fd = acquire_operation()
    try:
        job = new_job("backup")
        start_worker(
            backup_worker,
            job["id"],
            passphrase,
            include_ssh,
            quiesce,
            lock_fd,
        )
    except Exception:
        release_operation(lock_fd)
        raise
    return {"ok": True, "job_id": job["id"]}


def start_inspect(request: dict[str, Any]) -> dict[str, Any]:
    upload_id = identifier(request.get("upload_id"), "upload id")
    passphrase = require_passphrase(request.get("passphrase"))
    lock_fd = acquire_operation()
    try:
        resolve_upload_source(upload_id)
        job = new_job("inspect", upload_id=upload_id)
        start_worker(inspect_worker, job["id"], upload_id, passphrase, lock_fd)
    except Exception:
        release_operation(lock_fd)
        raise
    return {"ok": True, "job_id": job["id"]}


def start_restore(request: dict[str, Any]) -> dict[str, Any]:
    upload_id = identifier(request.get("upload_id"), "upload id")
    inspection_job_id = identifier(
        request.get("inspection_job_id"), "inspection job id"
    )
    passphrase = require_passphrase(request.get("passphrase"))
    restore_ssh = require_bool(request.get("restore_ssh"), "restore_ssh")
    scope = request.get("scope", "full")
    if scope not in {"full", "config"}:
        raise BackupdError("restore scope must be full or config")
    if scope == "config" and restore_ssh:
        raise BackupdError(
            "SSH keys are not part of a configuration-scope restore"
        )
    if request.get("confirmation") != "RESTORE":
        raise BackupdError("restore confirmation must be exactly RESTORE")
    lock_fd = acquire_operation()
    marker_created = False
    try:
        resolve_upload_source(upload_id)
        inspection = load_job(inspection_job_id)
        inspection_output = inspection.get("output")
        if (
            inspection.get("operation") != "inspect"
            or inspection.get("status") != "completed"
            or inspection.get("upload_id") != upload_id
            or not isinstance(inspection_output, dict)
            or not SHA256_RE.fullmatch(str(inspection_output.get("sha256") or ""))
            or not isinstance(inspection.get("manifest"), dict)
        ):
            raise BackupdError(
                "restore requires a successful inspection of the same uploaded archive",
                code="conflict",
            )
        restore_expanded_bytes(
            inspection["manifest"],
            restore_ssh=restore_ssh,
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(RESTORE_ACTIVE_MARKER, flags, 0o600)
        try:
            os.write(descriptor, (inspection_job_id + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        marker_created = True
        job = new_job("restore", upload_id=upload_id)
        update_job(job["id"], manifest=inspection["manifest"], scope=scope)
        start_worker(
            restore_worker,
            job["id"],
            upload_id,
            str(inspection_output["sha256"]),
            inspection["manifest"],
            passphrase,
            restore_ssh,
            scope,
            lock_fd,
        )
    except Exception:
        if marker_created:
            try:
                RESTORE_ACTIVE_MARKER.unlink()
            except FileNotFoundError:
                pass
        release_operation(lock_fd)
        raise
    return {"ok": True, "job_id": job["id"]}


def delete_item(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("confirmation") != "DELETE":
        raise BackupdError("delete confirmation must be exactly DELETE")
    kind = request.get("kind")
    if kind not in {"upload", "backup", "job"}:
        raise BackupdError("delete kind must be upload, backup, or job")
    item_id = identifier(request.get("id"), f"{kind} id")
    lock_fd = acquire_operation()
    try:
        deleted: list[str] = []
        if kind == "upload":
            stage_path = stage_record_path(item_id)
            if stage_path.exists():
                safe_json_file(stage_path)
                path = stage_path
            else:
                path = upload_path(item_id)
                try:
                    safe_regular_file(
                        path,
                        expected_uid=APP_UID,
                        maximum_size=MAX_ARCHIVE_BYTES,
                    )
                except FileNotFoundError as exc:
                    raise BackupdError(
                        "uploaded archive was not found",
                        code="not_found",
                    ) from exc
            path.unlink()
            deleted.append(path.name)
        elif kind == "backup":
            for path, maximum in (
                (backup_archive_path(item_id), MAX_ARCHIVE_BYTES),
                (backup_checksum_path(item_id), 64 * 1024),
                (backup_meta_path(item_id), MAX_STATE_BYTES),
            ):
                safe_regular_file(path, expected_uid=0, maximum_size=maximum)
            for path in (
                backup_archive_path(item_id),
                backup_checksum_path(item_id),
                backup_meta_path(item_id),
            ):
                path.unlink()
                deleted.append(path.name)
        else:
            job = load_job(item_id)
            if job.get("status") in ACTIVE_STATUSES:
                raise BackupdError(
                    "an active job cannot be deleted",
                    code="conflict",
                )
            path = state_path(item_id)
            path.unlink()
            deleted.append(path.name)
        return {"ok": True, "deleted": {"kind": kind, "id": item_id, "files": deleted}}
    finally:
        release_operation(lock_fd)


def status_response(request: dict[str, Any]) -> dict[str, Any]:
    expire_orphaned_uploads()
    requested = request.get("job_id")
    jobs = (
        [load_job(identifier(requested, "job id"))]
        if "job_id" in request
        else list_jobs()
    )
    return {
        "ok": True,
        "jobs": jobs,
        "backups": list_backups(),
        "uploads": list_uploads(),
        "active_job": active_job(),
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
    return delete_item(request)


def peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        return APP_UID
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
        os.chown(SOCKET_PATH, APP_UID, APP_PRIMARY_GID)
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


if __name__ == "__main__":
    raise SystemExit(main())
