"""Superadmin full-backup and disaster-recovery web workflow."""

from __future__ import annotations

import errno
import os
from pathlib import Path
import re
import shutil
import stat
import uuid

from flask import Blueprint, abort, jsonify, render_template, request, send_file

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request
from .backupd_client import BackupdError, backupd_request


bp_system_backups = Blueprint(
    "system_backups",
    __name__,
    url_prefix="/system/backups",
)

BACKUP_EXCHANGE_ROOT = Path(
    os.environ.get(
        "EASY_HA_PROXY_BACKUP_EXCHANGE_ROOT",
        "/var/lib/easy-ha-proxy/backup-web",
    )
)
UPLOAD_ROOT = BACKUP_EXCHANGE_ROOT / "uploads"
DOWNLOAD_ROOT = BACKUP_EXCHANGE_ROOT / "backups"
MAX_UPLOAD_BYTES = int(
    os.environ.get("EASY_HA_PROXY_BACKUP_MAX_UPLOAD_BYTES", str(8 * 1024**3))
)
UPLOAD_DISK_RESERVE_BYTES = int(
    os.environ.get("EASY_HA_PROXY_BACKUP_DISK_RESERVE_BYTES", str(512 * 1024**2))
)
IDENTIFIER_RE = re.compile(r"^[a-f0-9]{32}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _daemon_response(result: dict, *, accepted: bool = False):
    if result.get("ok"):
        return jsonify(result), (202 if accepted else 200)
    code = str(result.get("error_code") or "")
    if code in {"busy", "conflict", "operation_active"} or result.get("conflict"):
        status_code = 409
    elif code in {"not_found", "missing"}:
        status_code = 404
    elif code == "too_large":
        status_code = 413
    elif code == "insufficient_space":
        status_code = 507
    elif code in {"invalid", "validation", "bad_request"} or result.get(
        "validation_error"
    ):
        status_code = 400
    else:
        status_code = 502
    return jsonify(result), status_code


# Every job that changes the host goes through _call_daemon, so one audit
# point covers them all. The payload also carries the archive passphrase, so
# the summary is built from an allow-list and never from the payload itself.
AUDITED_ACTIONS = {
    "start_backup": ("backup.start", ("include_ssh", "quiesce")),
    "start_restore": ("restore.start", ("upload_id", "scope", "restore_ssh")),
    "delete": ("backup.delete", ("kind", "id")),
    "destination_save": ("backup_destination.save", ("name", "type", "host", "user")),
    "destination_delete": ("backup_destination.delete", ("name",)),
    "destination_test": ("backup_destination.test", ("name",)),
    "upload": ("backup.upload", ("backup_id", "destination")),
    # The passphrase travels in this payload, which is why the summary
    # is built from named fields and never from the payload itself.
    "schedule_save": ("backup_schedule.save", ("enabled", "destinations")),
    "run_scheduled": ("backup_schedule.run", ()),
}

DESTINATION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def _destination_name(value) -> str:
    text = str(value or "").strip().lower()
    if not DESTINATION_NAME_RE.fullmatch(text):
        abort(400, description="the destination name may use a-z, 0-9 and dashes")
    return text


def _call_daemon(payload: dict, *, accepted: bool = False, timeout: float = 10.0):
    entry = AUDITED_ACTIONS.get(str(payload.get("action") or ""))
    try:
        result = backupd_request(payload, timeout=timeout)
    except BackupdError as exc:
        if entry:
            record_request(
                entry[0],
                object_type="backup",
                object_id=str(payload.get("id") or payload.get("upload_id") or ""),
                result=RESULT_FAILURE,
                detail=str(exc)[:500],
            )
        return jsonify({"ok": False, "error": str(exc)}), 503
    if entry:
        action, fields = entry
        ok = bool(result.get("ok"))
        record_request(
            action,
            object_type="backup",
            object_id=str(
                result.get("job_id")
                or payload.get("id")
                or payload.get("upload_id")
                or ""
            ),
            result=RESULT_SUCCESS if ok else RESULT_FAILURE,
            summary=", ".join(
                f"{field}: {payload[field]}" for field in fields if field in payload
            ),
            detail="" if ok else str(result.get("error") or "")[:500],
        )
    return _daemon_response(result, accepted=accepted)


def _json_payload(required: set[str], optional: set[str] | None = None):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="a JSON object is required")
    allowed = required | (optional or set())
    if set(payload) - allowed or not required.issubset(payload):
        abort(400, description="invalid request fields")
    return payload


def _passphrase(value) -> str:
    if not isinstance(value, str) or len(value) < 12 or len(value) > 1024:
        abort(400, description="the backup passphrase must contain 12 to 1024 characters")
    if "\x00" in value or "\n" in value or "\r" in value:
        abort(400, description="the backup passphrase contains unsupported characters")
    return value


def _identifier(value, label: str) -> str:
    text = str(value or "").strip().lower()
    if not IDENTIFIER_RE.fullmatch(text):
        abort(400, description=f"invalid {label}")
    return text


@bp_system_backups.get("/")
def page():
    return render_template(
        "system_backups.html",
        max_upload_gib=round(MAX_UPLOAD_BYTES / 1024**3, 1),
    )


@bp_system_backups.get("/api/status")
def status_view():
    payload = {"action": "status"}
    job_id = (request.args.get("job_id") or "").strip().lower()
    if job_id:
        payload["job_id"] = _identifier(job_id, "job id")
    return _call_daemon(payload)


@bp_system_backups.post("/api/jobs/backup")
def start_backup():
    payload = _json_payload(
        {"passphrase", "include_ssh", "quiesce"},
    )
    if not isinstance(payload["include_ssh"], bool) or not isinstance(
        payload["quiesce"], bool
    ):
        abort(400, description="include_ssh and quiesce must be boolean")
    return _call_daemon(
        {
            "action": "start_backup",
            "passphrase": _passphrase(payload["passphrase"]),
            "include_ssh": payload["include_ssh"],
            "quiesce": payload["quiesce"],
        },
        accepted=True,
    )


@bp_system_backups.post("/api/uploads")
def upload_archive():
    """Stream an encrypted archive directly to the dedicated host spool."""

    request.max_content_length = MAX_UPLOAD_BYTES
    length = request.content_length
    if length is None:
        return jsonify({"ok": False, "error": "Content-Length is required"}), 411
    if length < 1:
        return jsonify({"ok": False, "error": "the backup file is empty"}), 400
    if length > MAX_UPLOAD_BYTES:
        return jsonify({"ok": False, "error": "the backup file is too large"}), 413
    if request.mimetype != "application/octet-stream":
        return jsonify(
            {"ok": False, "error": "application/octet-stream is required"}
        ), 415
    if not UPLOAD_ROOT.is_dir():
        return jsonify({"ok": False, "error": "the restore upload spool is unavailable"}), 503
    try:
        free = shutil.disk_usage(UPLOAD_ROOT).free
    except OSError as exc:
        return jsonify({"ok": False, "error": f"cannot inspect free disk space: {exc}"}), 503
    if free - UPLOAD_DISK_RESERVE_BYTES < length:
        return jsonify({"ok": False, "error": "not enough free disk space for the upload"}), 507

    upload_id = uuid.uuid4().hex
    temporary = UPLOAD_ROOT / f".{upload_id}.part"
    destination = UPLOAD_ROOT / f"{upload_id}.tar.gz.enc"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    written = 0
    committed = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            while True:
                chunk = request.stream.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES or written > length:
                    raise OSError(errno.EFBIG, "upload exceeds the declared size")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if written != length:
            raise OSError(errno.EIO, "upload ended before the declared size")
        os.replace(temporary, destination)
        committed = True
        directory_descriptor = os.open(
            UPLOAD_ROOT,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if committed:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        status_code = 413 if exc.errno == errno.EFBIG else 400
        return jsonify({"ok": False, "error": f"upload failed: {exc}"}), status_code

    return jsonify({"ok": True, "upload_id": upload_id, "size": written}), 201


@bp_system_backups.post("/api/uploads/<upload_id>/inspect")
def inspect_archive(upload_id: str):
    payload = _json_payload({"passphrase"})
    return _call_daemon(
        {
            "action": "start_inspect",
            "upload_id": _identifier(upload_id, "upload id"),
            "passphrase": _passphrase(payload["passphrase"]),
        },
        accepted=True,
    )


@bp_system_backups.post("/api/backups/<backup_id>/stage")
def stage_backup(backup_id: str):
    """Prepare a root-owned stored backup for the normal inspect workflow."""

    return _call_daemon(
        {
            "action": "stage_backup",
            "backup_id": _identifier(backup_id, "backup id"),
        },
        timeout=10.0,
    )


@bp_system_backups.post("/api/jobs/restore")
def start_restore():
    payload = _json_payload(
        {
            "upload_id",
            "inspection_job_id",
            "passphrase",
            "restore_ssh",
            "confirmation",
        },
        {"scope"},
    )
    if payload["confirmation"] != "RESTORE":
        abort(400, description="type RESTORE to confirm full replacement")
    if not isinstance(payload["restore_ssh"], bool):
        abort(400, description="restore_ssh must be boolean")
    scope = payload.get("scope", "full")
    if scope not in {"full", "config"}:
        abort(400, description="scope must be full or config")
    if scope == "config" and payload["restore_ssh"]:
        abort(400, description="SSH keys are not part of a configuration-scope restore")
    return _call_daemon(
        {
            "action": "start_restore",
            "upload_id": _identifier(payload["upload_id"], "upload id"),
            "inspection_job_id": _identifier(
                payload["inspection_job_id"], "inspection job id"
            ),
            "passphrase": _passphrase(payload["passphrase"]),
            "restore_ssh": payload["restore_ssh"],
            "confirmation": "RESTORE",
            "scope": scope,
        },
        accepted=True,
    )


@bp_system_backups.post("/api/delete")
def delete_artifact():
    payload = _json_payload({"kind", "id", "confirmation"})
    if payload["kind"] not in {"backup", "upload"}:
        abort(400, description="kind must be backup or upload")
    if payload["confirmation"] != "DELETE":
        abort(400, description="type DELETE to remove the artifact")
    return _call_daemon(
        {
            "action": "delete",
            "kind": payload["kind"],
            "id": _identifier(payload["id"], "artifact id"),
            "confirmation": "DELETE",
        }
    )


def _backup_record(backup_id: str) -> dict:
    try:
        result = backupd_request({"action": "status"}, timeout=10.0)
    except BackupdError as exc:
        abort(503, description=str(exc))
    if not result.get("ok"):
        abort(503, description=str(result.get("error") or "backup service error"))
    for item in result.get("backups") or []:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or item.get("backup_id") or "").lower()
        if item_id == backup_id:
            return item
    abort(404, description="backup not found")


def _download_path(backup_id: str, record: dict, checksum: bool) -> tuple[Path, str]:
    key = "checksum_name" if checksum else "archive_name"
    filename = str(record.get(key) or "")
    if not SAFE_FILENAME_RE.fullmatch(filename) or Path(filename).name != filename:
        abort(502, description="the backup service returned an unsafe artifact name")
    if not filename.startswith(f"{backup_id}."):
        abort(502, description="the backup artifact does not match its identifier")
    candidate = DOWNLOAD_ROOT / filename
    try:
        file_stat = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        root = DOWNLOAD_ROOT.resolve(strict=True)
    except OSError:
        abort(404, description="backup artifact not found")
    if root not in resolved.parents or not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        abort(502, description="the backup artifact failed a safety check")
    return resolved, filename


@bp_system_backups.get("/download/<backup_id>")
def download_backup(backup_id: str):
    identifier = _identifier(backup_id, "backup id")
    checksum = request.args.get("checksum") == "1"
    path, filename = _download_path(identifier, _backup_record(identifier), checksum)
    return send_file(
        path,
        as_attachment=True,
        download_name=filename,
        conditional=True,
        max_age=0,
    )


# ---------------------------------------------------------------------------
# Off-host destinations
# ---------------------------------------------------------------------------


@bp_system_backups.get("/api/destinations")
def list_destinations_view():
    return _call_daemon({"action": "destinations"})


@bp_system_backups.post("/api/destinations")
def save_destination_view():
    payload = _json_payload(
        {"name", "type"},
        {
            "host", "user", "path", "port", "private_key", "host_key",
            "keep_daily", "keep_weekly", "keep_monthly", "endpoint", "region",
            "bucket", "prefix", "access_key", "secret_key", "allow_insecure",
        },
    )
    command = {"action": "destination_save", "name": _destination_name(payload["name"])}
    for key in (
        "type", "host", "user", "path", "port", "private_key", "host_key",
        "keep_daily", "keep_weekly", "keep_monthly", "endpoint", "region",
        "bucket", "prefix", "access_key", "secret_key", "allow_insecure",
    ):
        if key in payload:
            command[key] = payload[key]
    return _call_daemon(command)


@bp_system_backups.post("/api/destinations/delete")
def delete_destination_view():
    payload = _json_payload({"name"})
    return _call_daemon(
        {"action": "destination_delete", "name": _destination_name(payload["name"])}
    )


@bp_system_backups.post("/api/destinations/test")
def test_destination_view():
    payload = _json_payload({"name"})
    # The far end may be slow to answer; the daemon has its own timeout.
    return _call_daemon(
        {"action": "destination_test", "name": _destination_name(payload["name"])},
        timeout=90.0,
    )


@bp_system_backups.post("/api/destinations/upload")
def upload_backup_view():
    payload = _json_payload({"backup_id", "destination"})
    return _call_daemon(
        {
            "action": "upload",
            "backup_id": _identifier(payload["backup_id"], "backup id"),
            "destination": _destination_name(payload["destination"]),
        },
        accepted=False,
        timeout=1800.0,
    )


# ---------------------------------------------------------------------------
# The nightly schedule
#
# The daemon has carried this since the destinations were built, and the
# systemd timer has been firing daily all along -- but nothing here exposed
# it, so an operator could say where a copy should go and never say when.
# Every firing found the schedule off and exited without doing anything.
# ---------------------------------------------------------------------------


@bp_system_backups.get("/api/schedule")
def schedule_view():
    return _call_daemon({"action": "schedule"})


@bp_system_backups.post("/api/schedule")
def save_schedule_view():
    payload = _json_payload(
        set(),
        {"enabled", "destinations", "include_ssh", "quiesce", "passphrase"},
    )
    command = {"action": "schedule_save"}

    if "enabled" in payload:
        if not isinstance(payload["enabled"], bool):
            abort(400, description="enabled must be boolean")
        command["enabled"] = payload["enabled"]

    for key in ("include_ssh", "quiesce"):
        if key in payload:
            if not isinstance(payload[key], bool):
                abort(400, description=f"{key} must be boolean")
            command[key] = payload[key]

    if "destinations" in payload:
        names = payload["destinations"]
        if not isinstance(names, list):
            abort(400, description="destinations must be a list")
        command["destinations"] = [_destination_name(name) for name in names]

    if "passphrase" in payload:
        supplied = payload["passphrase"]
        # An empty string is how the page asks for the stored passphrase to be
        # forgotten, so it must reach the daemon rather than be validated as
        # if it were a new one.
        if supplied == "":
            command["passphrase"] = ""
        else:
            command["passphrase"] = _passphrase(supplied)

    return _call_daemon(command)


@bp_system_backups.post("/api/schedule/run")
def run_schedule_view():
    # The same job the timer runs, started by hand. It can take as long as a
    # full backup and an upload, so it gets the upload timeout rather than
    # the default.
    return _call_daemon({"action": "run_scheduled"}, timeout=1800.0)
