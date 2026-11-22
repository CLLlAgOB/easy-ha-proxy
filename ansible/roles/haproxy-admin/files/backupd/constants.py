"""Constants, paths, locks, and job state records for backupd."""

from __future__ import annotations

import datetime as dt
import grp
import json
import logging
import os
import pwd
import re
import shutil
import stat
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

# Bound across sibling submodules when the package finishes loading.
SYSTEMCTL_PATH: Any = None
stop_transient_unit: Any = None
transient_jobs_supported: Any = None

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
# Free space below this -- or below a tenth of the filesystem, on a small
# one -- is reported after a scheduled run, well before MIN_FREE_BYTES makes
# the next backup refuse to start at all.
LOW_SPACE_BYTES = env_int("BACKUPD_LOW_SPACE_BYTES", 2 * 1024 * 1024 * 1024)
LOW_SPACE_FRACTION = 0.10
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


# The alert client lives beside this script in /usr/local/sbin, which is
# sys.path[0] for a daemon started by absolute path. Optional on purpose: the
# job still runs on a gateway without the alert daemon.
try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - the daemon runs without it
    AlertClient = None  # type: ignore[assignment]

_ALERTS = None
if AlertClient is not None:
    _candidate = AlertClient(source="backupd")
    _ALERTS = _candidate if _candidate.configured else None


def report_alert(rule: str, subject: str, summary: str, detail: str = "") -> None:
    """Tell the alert engine a job failed. Never disturbs the job itself."""
    if _ALERTS is None:
        return
    try:
        _ALERTS.observe(rule, subject, summary=summary, detail=detail)
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)
MANIFEST_MARKER = "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
BACKUP_FILE_MARKER = "EASY_HA_PROXY_FULL_BACKUP_FILE="
MANIFEST_KEYS = (
    "format",
    "format_version",
    "created_at",
    "hostname",
    "machine",
    "ssh_included",
    "metrics_included",
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
    "destinations": frozenset({"action"}),
    "destination_save": frozenset(
        {
            "action", "name", "type", "host", "port", "user", "path",
            "private_key", "host_key", "keep_daily", "keep_weekly",
            "keep_monthly", "endpoint", "region", "bucket", "prefix",
            "access_key", "secret_key", "allow_insecure", "verify",
            "auth", "password",
        }
    ),
    "destination_delete": frozenset({"action", "name"}),
    "destination_test": frozenset({"action", "name"}),
    "destination_retrust": frozenset({"action", "name"}),
    "upload": frozenset({"action", "backup_id", "destination"}),
    "schedule": frozenset({"action"}),
    "schedule_save": frozenset(
        {
            "action", "enabled", "destinations", "include_ssh", "quiesce",
            "passphrase", "time", "keep_local",
        }
    ),
    "run_scheduled": frozenset({"action", "on_demand"}),
}

STATE_LOCK = threading.RLock()
OPERATION_THREAD_LOCK = threading.Lock()
DESTINATION_UPLOAD_LOCKS_GUARD = threading.Lock()
DESTINATION_UPLOAD_LOCKS: dict[tuple[str, ...], tuple[Any, int]] = {}
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


def _set_owner(target, uid: int, gid: int, *, fd: bool = False) -> None:
    """Give the file its intended ownership, where that is possible at all.

    The daemon runs as root, so this always applies in a deployment. It does
    not apply when the module is exercised by a test as an ordinary user, and
    there it must not be fatal -- every caller has already created the file
    with a restrictive mode, so failing to widen it to a group leaves the file
    stricter than intended, never looser.
    """
    try:
        if fd:
            os.fchown(target, uid, gid)
        else:
            os.chown(target, uid, gid)
    except PermissionError:
        if os.geteuid() == 0:
            raise
        LOG.debug("not root: leaving ownership of %s as it is", target)


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
            _set_owner(descriptor, 0, APP_GROUP_GID, fd=True)
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
    # The point of the owner check is that nobody but the daemon's own account
    # can have written this file. In a deployment that account is root, which
    # is what expected_uid means. When the module is exercised by an ordinary
    # user the same rule has to be read against that user, or the check refuses
    # files it wrote itself a moment earlier.
    if expected_uid == 0 and os.geteuid() != 0:
        expected_uid = os.geteuid()
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
