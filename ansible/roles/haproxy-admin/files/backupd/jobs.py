"""Upload staging, transient systemd job runner, and local artifact storage."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from . import constants as _constants
from .constants import (
    ARCHIVE_SUFFIX,
    ASSISTANT_REBOOT_MARKER,
    BACKUPS_DIR,
    BACKUP_FILE_MARKER,
    BackupdError,
    CHECKSUM_SUFFIX,
    IDENTIFIER_RE,
    JOBS_DIR,
    JOB_TIMEOUT_SECONDS,
    LIST_LIMIT,
    LOG,
    LOW_SPACE_BYTES,
    LOW_SPACE_FRACTION,
    MANIFEST_KEYS,
    MANIFEST_MARKER,
    MAX_ARCHIVE_BYTES,
    MAX_CAPTURE_BYTES,
    MAX_STATE_BYTES,
    META_SUFFIX,
    MIN_FREE_BYTES,
    OPERATION_LOCK_PATH,
    OPERATION_THREAD_LOCK,
    REBOOT_MARKER,
    SHA256_RE,
    SHUTDOWN_REQUESTED,
    SOCKET_PATH,
    SOURCE_DIR,
    STAGE_RECORD_PREFIX,
    STAGE_RECORD_SUFFIX,
    STOP_EVENT,
    UPLOADS_DIR,
    _set_owner,
    atomic_json,
    fsync_directory,
    identifier,
    load_job,
    report_alert,
    safe_json_file,
    update_job,
    utc_now,
)

# Bound across sibling submodules when the package finishes loading.
resolve_upload_source: Any = None

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
        _set_owner(destination_fd, 0, 0, fd=True)
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
        "EASY_HA_PROXY_MAINTENANCE_LOCK_HELD": "backupd",
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
    # A failed backup that nobody hears about is the same as no backup.
    operation = ""
    try:
        operation = str(load_job(job_id, include_logs=False).get("operation") or "")
    except Exception:  # pylint: disable=broad-except
        pass
    report_alert(
        "restore.failed" if operation == "restore" else "backup.failed",
        job_id,
        f"The {operation or 'backup'} job failed",
        message,
    )


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
        _set_owner(destination, 0, _constants.APP_GROUP_GID)
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
            _set_owner(descriptor, 0, _constants.APP_GROUP_GID, fd=True)
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
    return all_backups()[:LIST_LIMIT]


def all_backups() -> list[dict[str, Any]]:
    """Every valid archive on this server, newest first.

    The page lists at most LIST_LIMIT of them; retention and the storage
    summary have to see all of them, or an archive past the limit would sit
    on the disk where nothing could see it, count it or remove it.
    """
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
    return backups


def local_storage(backups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """How much the archives on this server take, and how much room is left."""

    if backups is None:
        backups = all_backups()
    # Before the first backup the directory may not exist yet; the space
    # that matters is that of the filesystem it will be created on.
    anchor = BACKUPS_DIR
    while not anchor.exists() and anchor != anchor.parent:
        anchor = anchor.parent
    usage = shutil.disk_usage(anchor)
    threshold = max(
        2 * MIN_FREE_BYTES,
        min(LOW_SPACE_BYTES, int(usage.total * LOW_SPACE_FRACTION)),
    )
    return {
        "count": len(backups),
        "bytes": sum(int(item.get("size_bytes") or 0) for item in backups),
        "free_bytes": usage.free,
        "filesystem_bytes": usage.total,
        "low_space_bytes": threshold,
        "low": usage.free < threshold,
    }


def staged_backup_ids() -> set[str]:
    """Archives a restore has been staged from; those are not pruned."""

    staged: set[str] = set()
    for path in JOBS_DIR.glob(f"{STAGE_RECORD_PREFIX}*{STAGE_RECORD_SUFFIX}"):
        with contextlib.suppress(Exception):
            backup_id = str(safe_json_file(path).get("backup_id") or "")
            if IDENTIFIER_RE.fullmatch(backup_id):
                staged.add(backup_id)
    return staged


def remove_backup_files(backup_id: str) -> list[str]:
    """Delete one archive with its checksum and metadata, checked first."""

    paths = (
        (backup_archive_path(backup_id), MAX_ARCHIVE_BYTES),
        (backup_checksum_path(backup_id), 64 * 1024),
        (backup_meta_path(backup_id), MAX_STATE_BYTES),
    )
    for path, maximum in paths:
        safe_regular_file(path, expected_uid=0, maximum_size=maximum)
    deleted = []
    for path, _maximum in paths:
        path.unlink()
        deleted.append(path.name)
    return deleted


def prune_local_backups(keep: int) -> list[str]:
    """Keep the newest ``keep`` archives on this server and remove the rest.

    Only ever called once every destination holds a verified copy of the
    newest archive, so nothing removed here is the last copy of anything
    recent. An archive a restore has been staged from is left alone.
    """

    staged = staged_backup_ids()
    removed: list[str] = []
    for backup in all_backups()[max(keep, 1):]:
        backup_id = backup["id"]
        if backup_id in staged:
            continue
        try:
            remove_backup_files(backup_id)
        except (BackupdError, OSError) as exc:
            LOG.warning("Could not remove old local backup %s: %s", backup_id, exc)
            continue
        removed.append(backup_id)
    return removed


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
