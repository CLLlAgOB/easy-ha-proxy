"""Constants, privilege helpers, and job state management for updated."""

from __future__ import annotations

import datetime as dt
import grp
import json
import logging
import os
import pwd
import re
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# Bound across sibling submodules when the package finishes loading.
SYSTEMCTL_PATH: Any = None
read_file_tail: Any = None
stop_transient_unit: Any = None
systemctl_properties: Any = None
transient_jobs_supported: Any = None

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
REBOOT_MARKER = Path(
    os.environ.get(
        "UPDATED_REBOOT_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json",
    )
)
ASSISTANT_REBOOT_MARKER = Path("/run/easy-ha-proxy/reboot-scheduled")
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
# A scheduled check, so "updates are available" reaches the
# operator without anyone opening the page. 0 switches it off. The first one
# waits a while after start, so a reboot does not begin with a git clone.
AUTO_CHECK_HOURS = env_int("UPDATED_AUTO_CHECK_HOURS", 24, minimum=0, maximum=24 * 30)
AUTO_CHECK_DELAY_SECONDS = env_int(
    "UPDATED_AUTO_CHECK_DELAY_SECONDS", 900, minimum=0, maximum=24 * 3600
)
AUTO_CHECK_RETRY_SECONDS = 3600
# The page can change the interval without Ansible: its choice is kept in the
# broker's own state and wins over the default above. The schedule looks at it
# once a minute, so a change takes effect without a restart.
AUTO_CHECK_CHOICES = (0, 6, 12, 24, 72, 168)
AUTO_CHECK_POLL_SECONDS = 60
SETTINGS_PATH = STATE_ROOT / "settings.json"
MAX_CONNECTIONS = env_int("UPDATED_MAX_CONNECTIONS", 16, maximum=64)

PROTOCOL_VERSION = 2
IDENTIFIER_RE = re.compile(r"^[0-9a-f]{32}$")
BOOT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ACTOR_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# "changes" never appears in a plan of its own: it is the source update with
# only the playbook steps the changed files need, and the plan describes it in
# the "all" component's details.scope.
CHANGES_COMPONENT = "changes"
ALLOWED_COMPONENTS = frozenset(
    {
        "all",
        CHANGES_COMPONENT,
        "services",
        "daemons",
        "authelia-container",
        "admin-container",
        "os",
        "haproxy",
    }
)
SOURCE_COMPONENTS = frozenset({"all", "services", "daemons", CHANGES_COMPONENT})
CONTAINER_COMPONENTS = frozenset(
    {"authelia-container", "admin-container"}
)
ACTIVE_STATUSES = frozenset({"queued", "running"})
# Progress for the page. The installer prints "EHP-PROGRESS phase=<name>" as it
# moves through its own steps, and the easy_ha_proxy_progress Ansible callback
# prints "EHP-PROGRESS <done>/<total> <task>" before each task. Only the part of
# the log after the current component's heading counts: earlier components'
# output is carried into the same log.
COMPONENT_HEADING = "=== Applying component:"
PROGRESS_RE = re.compile(
    r"^EHP-PROGRESS (?:phase=(?P<phase>[a-z-]{1,24})"
    r"|(?P<done>\d{1,6})/(?P<total>\d{1,6})(?: (?P<task>[^\n]{0,400}))?)[ \t]*$",
    re.MULTILINE,
)
PROGRESS_PHASES = frozenset(
    {
        "checking", "verifying", "starting", "source", "prepare", "syntax",
        "playbook", "rechecking",
    }
)
MAX_PROGRESS_TASK = 160
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
    _candidate = AlertClient(source="updated")
    _ALERTS = _candidate if _candidate.configured else None


AVAILABLE_RULE = "update.available"
AVAILABLE_SUBJECT = "software"
# Names for the alert text, which is read away from the page.
ALERT_COMPONENT_NAMES = {
    "all": "a new source revision",
    "services": "host services",
    "daemons": "helper daemons",
    "authelia-container": "Authelia containers",
    "admin-container": "the web application",
    "os": "operating-system packages",
    "haproxy": "HAProxy",
}
ALERT_CHANGELOG_LINES = 15


def availability_report(plan: dict[str, Any]) -> tuple[bool, str, str] | None:
    """(active, summary, detail) for the "updates available" level, or None
    when the check could not tell either way."""

    components = [item for item in plan.get("components") or [] if isinstance(item, dict)]
    actionable = [
        item for item in components
        if item.get("state") == "available" and item.get("actionable") is True
    ]
    if not actionable:
        if any(item.get("state") == "unknown" for item in components):
            return None
        return False, "Software is up to date", ""
    names = []
    for item in actionable:
        name = ALERT_COMPONENT_NAMES.get(str(item.get("id")), str(item.get("id")))
        if item.get('id') == 'haproxy':
            name += f" {item.get('installed') or '?'} → {item.get('available') or '?'}"
        count = (item.get("details") or {}).get("package_count") if item.get("id") == "os" else None
        names.append(f"{name} ({count})" if isinstance(count, int) and count > 0 else name)
    summary = f"Software updates are available: {', '.join(names)}"
    lines: list[str] = []
    source = next((item for item in actionable if item.get("id") == "all"), None)
    changelog = ((source or {}).get("details") or {}).get("changelog")
    if isinstance(changelog, dict) and isinstance(changelog.get("commits"), list):
        count = changelog.get("count")
        more = "" if changelog.get("complete") else "+"
        lines.append(f"{count}{more} new change(s):")
        for commit in changelog["commits"][:ALERT_CHANGELOG_LINES]:
            if isinstance(commit, dict):
                lines.append(f"- {commit.get('subject') or commit.get('revision')}")
        lines.append("")
    lines.append("Install them from Software updates in HAProxy Admin.")
    return True, summary, "\n".join(lines)


def report_availability(plan: dict[str, Any]) -> None:
    """Keep the "updates available" level in step with the newest check."""
    if _ALERTS is None:
        return
    try:
        report = availability_report(plan)
        if report is None:
            return
        active, summary, detail = report
        _ALERTS.observe(
            AVAILABLE_RULE, AVAILABLE_SUBJECT, active=active, summary=summary, detail=detail
        )
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)


def report_alert(rule: str, subject: str, summary: str, detail: str = "") -> None:
    """Tell the alert engine a job failed. Never disturbs the job itself."""
    if _ALERTS is None:
        return
    try:
        _ALERTS.observe(rule, subject, summary=summary, detail=detail)
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)
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
    "set_settings": frozenset({"action", "auto_check_hours"}),
    "set_auto_install": frozenset({"action", "enabled", "start", "end", "os", "unified", "runtime"}),
    "summary": frozenset({"action"}),
    "start_check": frozenset(
        {"action", "image_channel", "source_channel", "release_channel"}
    ),
    "start_apply": frozenset(
        {"action", "plan_id", "components", "confirmation"}
    ),
    "set_channels": frozenset(
        {"action", "image_channel", "source_channel", "release_channel"}
    ),
    "reboot": frozenset(
        {"action", "confirmation", "expected_boot_id", "actor"}
    ),
    "cancel_reboot": frozenset({"action", "expected_boot_id", "actor"}),
    "prepare_haproxy_migration": frozenset({"action", "target_branch"}),
    "apply_haproxy_migration": frozenset({"action", "plan_id", "confirmation"}),
    "start_haproxy_transition": frozenset({"action", "target_branch", "confirmed"}),
    "os_security_status": frozenset({"action", "job_id"}),
    "ssh_protection_status": frozenset({"action", "job_id"}),
    "ssh_protection_connection": frozenset({"action", "user", "ip", "hostname", "local_address", "port"}),
    "ssh_protection_monitor": frozenset({"action", "enabled"}),
    "ssh_protection_configure": frozenset({"action", "operation", "trusted", "policy"}),
    "ssh_protection_unban": frozenset({"action", "ip"}),
    "os_security_check": frozenset({"action"}),
    "os_security_install": frozenset({"action", "confirmation"}),
    "os_security_configure": frozenset({"action", "mode", "interval", "start", "end", "confirmation"}),
    "set_auto_reboot": frozenset({"action", "enabled", "time", "allow_service_reboot", "confirmation", "expected_boot_id", "actor"}),
    "set_service_restarts": frozenset({"action", "enabled", "time", "confirmation", "expected_boot_id", "actor"}),
    "os_security_restart_check": frozenset({"action"}),
    "os_security_restart": frozenset({"action", "confirmation"}),
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
        (REBOOT_MARKER, "reboot marker"),
        (ASSISTANT_REBOOT_MARKER, "assistant reboot marker"),
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


def parse_progress(text: str) -> dict[str, Any] | None:
    """The newest progress marker of the component that is running now."""

    section = text.rsplit(COMPONENT_HEADING, 1)[-1]
    last = None
    for match in PROGRESS_RE.finditer(section):
        last = match
    if last is None:
        return None
    if last.group("phase"):
        phase = last.group("phase")
        return {"phase": phase} if phase in PROGRESS_PHASES else None
    task = CONTROL_RE.sub("", last.group("task") or "").strip()[:MAX_PROGRESS_TASK]
    return {
        "phase": "playbook",
        "done": int(last.group("done")),
        "total": int(last.group("total")),
        "task": task,
    }


def public_progress(value: Any) -> dict[str, Any] | None:
    """Only the shape the page knows, whatever ended up in the state file."""

    if not isinstance(value, dict) or value.get("phase") not in PROGRESS_PHASES:
        return None
    result: dict[str, Any] = {"phase": value["phase"]}
    for key in ("done", "total"):
        number = value.get(key)
        if isinstance(number, int) and 0 <= number <= 999999:
            result[key] = number
    task = value.get("task")
    if isinstance(task, str) and task:
        result["task"] = CONTROL_RE.sub("", task)[:MAX_PROGRESS_TASK]
    return result


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
        "component_index": state.get("component_index")
        if isinstance(state.get("component_index"), int)
        else None,
        "component_started_at": str(state.get("component_started_at"))[:40]
        if state.get("component_started_at")
        else None,
        "scheduled": state.get("scheduled") is True,
        "progress": public_progress(state.get("progress")),
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
    # PID 1 owns these children. They may still be installing packages or
    # restoring containers after this broker crashed. Keep their markers and
    # output intact, and do not accept new work until they have finished.
    stop_orphan_transient_jobs()
    for job in list_jobs():
        if job.get("status") in ACTIVE_STATUSES:
            update_job(
                job["id"],
                status="interrupted",
                completed_at=utc_now(),
                error="the update broker restarted before the job completed",
                output={"log": read_file_tail(JOBS_DIR / f".{identifier(job['id'], 'job id')}.output")
                        or (job.get('output') or {}).get('log', '')},
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


def stop_orphan_transient_jobs() -> None:
    """Transient job units outlive a crashed broker; reconcile them at start.

    Wait for live children before cleaning up finished units. Stopping an
    installer kills its entire cgroup, including dpkg and container recovery.
    Startup stays closed to new work while the old operation has custody.
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
        raise UpdatedError("Could not inspect surviving update jobs") from None
    if result.returncode:
        raise UpdatedError("Could not inspect surviving update jobs")
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit.startswith("easy-ha-proxy-updated-job-"):
            LOG.warning("Waiting for surviving update job %s", unit)
            while True:
                if SHUTDOWN_REQUESTED.is_set():
                    raise UpdatedError("Broker stopped while waiting for surviving update jobs")
                properties = systemctl_properties(unit, ["LoadState", "ActiveState", "SubState", "Job"])
                if properties.get("LoadState") == "not-found":
                    break
                active = properties.get("ActiveState")
                if not active:
                    raise UpdatedError("Could not inspect surviving update job " + unit)
                pending = (properties.get("Job") or "0").split()[0] != "0"
                if not pending and (active in {"inactive", "failed"}
                                    or (active == "active" and properties.get("SubState") == "exited")):
                    break
                time.sleep(0.5)
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
        # Ask the installer and Ansible for the progress markers above.
        "EASY_HA_PROXY_PROGRESS": "1",
        # A web update reports a required reboot; it never schedules one.
        "EASY_HA_PROXY_REBOOT_DECISION": "no",
        # The broker holds the maintenance lock for the job it starts.
        "EASY_HA_PROXY_MAINTENANCE_LOCK_HELD": "updated",
    }
