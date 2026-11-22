"""Transient systemd command runner, update plan storage, and lock handling."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .constants import (
    ACTIVE_MARKER,
    ALLOWED_COMPONENTS,
    AUTO_CHECK_CHOICES,
    AUTO_CHECK_HOURS,
    CHANGES_COMPONENT,
    CHECK_TIMEOUT_SECONDS,
    CONFIG_DIR,
    CONTAINER_COMPONENTS,
    CONTROL_RE,
    HAPROXY_TRANSACTION_ACTIVE_STATES,
    HAPROXY_TRANSACTION_MARKER,
    HAPROXY_TRANSACTION_SETTLED_STATES,
    HAPROXY_TRANSACTION_STATE,
    IDENTIFIER_RE,
    IMAGE_DIGEST_RE,
    JOBS_DIR,
    LATEST_PLAN_PATH,
    LOG,
    MAINTENANCE_LOCK_PATH,
    MAX_CAPTURE_BYTES,
    OPERATION_THREAD_LOCK,
    PLAN_TTL_SECONDS,
    PROTOCOL_VERSION,
    PYTHON_PATH,
    SETTINGS_PATH,
    SHUTDOWN_REQUESTED,
    SOURCE_COMPONENTS,
    SOURCE_DIR,
    SOURCE_REVISION_RE,
    STOP_EVENT,
    UpdatedError,
    atomic_json,
    child_environment,
    env_int,
    identifier,
    load_job,
    new_job,
    parse_progress,
    read_tail,
    report_alert,
    report_availability,
    safe_json_file,
    sanitize_log,
    update_job,
    utc_now,
)

# Bound across sibling submodules when the package finishes loading.
auto_install_settings: Any = None
haproxy_patch_active: Any = None
last_auto_install: Any = None
read_deployment: Any = None
reboot_guard_present: Any = None
security_recovery_pending: Any = None

SYSTEMD_RUN_PATH = "/usr/bin/systemd-run"
SYSTEMCTL_PATH = "/usr/bin/systemctl"
# Delayed + cancelable reboot: PID 1 owns a uniquely named timer, so the HTTP
# response reaches the browser before the host goes down and cancellation can
# never affect a shutdown scheduled by another administrator.
REBOOT_DELAY_SECONDS = env_int(
    "UPDATED_REBOOT_DELAY_SECONDS", 60, minimum=15, maximum=15 * 60
)
REBOOT_UNIT_PREFIX = "easy-ha-proxy-web-reboot"
REBOOT_UNIT_RE = re.compile(
    rf"^{re.escape(REBOOT_UNIT_PREFIX)}-[0-9a-f]{{12}}$"
)
REBOOT_CONFIRMATION = "REBOOT"
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
REBOOT_REQUIRED_PATH = Path("/var/run/reboot-required")
# A restore in progress must never be interrupted by a reboot.
BACKUPD_RESTORE_ACTIVE_MARKER = Path(
    os.environ.get(
        "UPDATED_BACKUPD_RESTORE_MARKER",
        "/run/easy-ha-proxy/easy-ha-proxy-backupd-restore.active",
    )
)
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


def transient_job_unit_name():
    return f"easy-ha-proxy-updated-job-{uuid.uuid4().hex[:12]}.service"


def run_transient_command(
    job_id: str,
    argv: list[str],
    *,
    timeout: int,
    log_prefix: str = "",
) -> tuple[int, str]:
    unit = transient_job_unit_name()
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
    if len(argv) > 1 and Path(argv[1]) == SOURCE_DIR / 'installer/apt_metadata.py':
        command.extend(['-p', 'CPUQuota=100%', '-p', 'MemoryMax=512M'])
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
                publish_output(job_id, read_file_tail(output_path))
                last_publish = time.monotonic()
            time.sleep(0.5)
    finally:
        stop_transient_unit(unit)
        if timed_out:
            update_job(job_id, output={"log": read_file_tail(output_path)})
        output_path.unlink(missing_ok=True)


def publish_output(job_id: str, log: str) -> None:
    updates: dict[str, Any] = {"output": {"log": log}}
    progress = parse_progress(log)
    if progress is not None:
        updates["progress"] = progress
    update_job(job_id, **updates)


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
                    publish_output(job_id, read_tail(output_file))
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
    if (SOURCE_DIR / 'installer/haproxy_update_status.py').is_file():
        command.append('--haproxy-status')
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
        if (
            component_id not in ALLOWED_COMPONENTS
            or component_id == CHANGES_COMPONENT
            or component_id in seen
        ):
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


METADATA_CONTEXT = threading.local()


def trusted_source(filename):
    path = SOURCE_DIR / 'installer' / filename
    if not path.is_file() or path.is_symlink():
        raise UpdatedError('Update the host services before using controlled HAProxy updates')
    return path


def refresh_apt_metadata(job_id):
    if not (SOURCE_DIR / 'installer/apt_metadata.py').is_file():
        return  # Legacy checker protocol while installing the new broker.
    descriptor = None
    try:
        if getattr(METADATA_CONTEXT, 'unlocked', False):
            descriptor = os.open(MAINTENANCE_LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise UpdatedError('Another maintenance operation is active', code='busy') from error
        update_job(job_id, progress={'phase': 'checking'})
        python = PYTHON_PATH if PYTHON_PATH.is_file() else Path('/usr/bin/python3')
        code, _ = run_command(job_id, [str(python), str(trusted_source('apt_metadata.py')), 'refresh'],
                              timeout=130, log_prefix='Refreshing signed package metadata without installing packages…')
        # A completed failed refresh writes a durable unknown state. A failure
        # to launch the helper must not leave a previously current plan trusted.
        if code:
            raise UpdatedError('APT metadata refresh helper could not complete')
    except Exception:
        # An old green plan must disappear even when the privileged helper
        # could not start and therefore could not invalidate its own record.
        LATEST_PLAN_PATH.unlink(missing_ok=True)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def execute_checker(
    job_id: str,
    *,
    image_channel: str | None = None,
    source_channel: str | None = None,
    branch: str | None = None,
) -> dict[str, Any]:
    refresh_apt_metadata(job_id)
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
    if isinstance(material.get('details'), dict):
        details = dict(material['details'])
        if isinstance(details.get('apt'), dict):
            details['apt'] = {key: details['apt'].get(key) for key in ('fresh', 'sources')}
        details.pop('last_operation', None)
        material['details'] = details
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
    elif CHANGES_COMPONENT in result:
        # It covers what the narrower source updates would do.
        result = [item for item in result if item not in {"services", "daemons"}]
    # Updating the web application last reduces avoidable reconnects.  APT is
    # always last because it can leave the host awaiting a reboot.
    order = {
        "all": 0,
        CHANGES_COMPONENT: 1,
        "services": 1,
        "daemons": 2,
        "authelia-container": 3,
        "admin-container": 4,
        "os": 5,
        "haproxy": 6,
    }
    return sorted(result, key=order.__getitem__)


def changes_scope(component: dict[str, Any] | None) -> dict[str, Any] | None:
    """The scope a plan's source component offers for a changes-only update."""

    details = component.get("details") if isinstance(component, dict) else None
    scope = details.get("scope") if isinstance(details, dict) else None
    if not isinstance(scope, dict) or scope.get("ready") is not True:
        return None
    tags = scope.get("tags")
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        return None
    return scope


def plan_source_component(plan_map: dict[str, dict[str, Any]], component_id: str) -> dict[str, Any] | None:
    """The plan entry a selected component is checked against."""

    if component_id == CHANGES_COMPONENT:
        source = plan_map.get("all")
        return source if changes_scope(source) is not None else None
    return plan_map.get(component_id)


def component_requirements(entry: dict[str, Any] | None, component_id: str) -> list[list[str]]:
    """What has to be installed with a component, as clauses: every clause
    needs one of its components in the same selection."""

    details = (entry or {}).get("details") if isinstance(entry, dict) else None
    if not isinstance(details, dict):
        return []
    if component_id == CHANGES_COMPONENT:
        scope = details.get("scope")
        clauses = scope.get("requires") if isinstance(scope, dict) else None
    else:
        clauses = details.get("requires")
    if not isinstance(clauses, list):
        return []
    return [
        [str(item) for item in clause if item in ALLOWED_COMPONENTS]
        for clause in clauses
        if isinstance(clause, list)
    ]


def validate_requirements(plan_map: dict[str, dict[str, Any]], components: list[str]) -> None:
    """The host and the web application come from one source: a selection that
    would install one without the other is refused here, not only on the page."""

    selected = set(components)
    # The full stack pulls the web application image itself.
    satisfied = selected | ({"admin-container"} if "all" in selected else set())
    for component_id in components:
        entry = plan_source_component(plan_map, component_id)
        for clause in component_requirements(entry, component_id):
            if clause and not satisfied.intersection(clause):
                raise UpdatedError(
                    f"{component_id} has to be installed together with "
                    + " or ".join(clause),
                    code="dependency",
                )


def plan_component_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = plan.get("components")
    if not isinstance(components, list):
        raise UpdatedError("the cached update plan is invalid")
    return {
        str(item.get("id")): item
        for item in components
        if isinstance(item, dict) and item.get("id") in ALLOWED_COMPONENTS
    }


CHANNEL_MISMATCH_MESSAGE = (
    "This update was checked for a different release channel than the one "
    "this gateway is set to. Save the channel first, or run the check again."
)


def validate_plan_channel(plan: dict[str, Any]) -> None:
    """Refuse to apply a plan checked for a channel this gateway is not on.

    The check deliberately previews whichever channel is selected on the
    page, saved or not. Applying that preview was never a supported path, and
    it failed in the least helpful way available: the apply-time recheck fell
    back to the branch in the gateway's metadata, found a different
    candidate, and reported "the update candidate changed; check again" --
    which it would repeat after every check, for ever. Had the recheck
    followed the preview instead, the gateway would have been moved to
    another branch without its channel ever being saved.

    So it is refused up front, in words that say what actually happened.
    """

    deployment = read_deployment()
    planned_source = str(plan.get("source_channel") or "github")
    planned_image = str(plan.get("image_channel") or "latest")
    mismatch = (
        planned_source != deployment.get("source_channel", "github")
        or planned_image != deployment.get("image_channel", "latest")
    )
    planned_branch = plan.get("branch")
    if not mismatch and planned_source != "local" and planned_branch:
        mismatch = str(planned_branch) != deployment.get("branch", "main")
    if mismatch:
        raise UpdatedError(CHANNEL_MISMATCH_MESSAGE, code="channel_mismatch")


def validate_selection(plan: dict[str, Any], components: list[str]) -> None:
    validate_plan_channel(plan)
    available = plan_component_map(plan)
    for component_id in components:
        component = plan_source_component(available, component_id)
        if (
            component is None
            or component.get("state") != "available"
            or component.get("actionable") is not True
        ):
            raise UpdatedError(
                f"component is not an actionable update: {component_id}",
                code="stale_plan",
            )
    validate_requirements(available, components)
    if SOURCE_COMPONENTS.intersection(components) or 'haproxy' in components:
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
        old = plan_source_component(old_map, component_id)
        new = plan_source_component(new_map, component_id)
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
            # A reviewed image is named by what it will become, an installed
            # one by what runs now. The check after an update reads the
            # branch again, and a commit pushed while the update ran may
            # already re-pin the running image: named by its next target, it
            # would not be found, and a faithful update would fail.
            if current:
                image = str(item.get("current_image") or item.get("image") or "")
            else:
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
    component_map = plan_component_map(applied)
    for component_id in container_components_for_selection(components):
        images = (component_map[component_id].get("details") or {}).get("images") or []
        for image in images:
            if (
                image.get("state") == "unknown"
                or image.get("reason") in {"running-older-image", "running-unchecked", "running-image-unreadable"}
                or image.get("running") in {"different-content", "unchecked", "unreadable", "not-running"}
            ):
                LOG.warning("Installed container verification failed for %s", component_id)
                raise UpdatedError(
                    "The container update could not be verified. Check the running containers and try again.",
                    code="verification_failed",
                )


def acquire_operation(*, allow_scheduled_reboot: bool = False, allow_security_recovery: bool = False) -> int:
    if SHUTDOWN_REQUESTED.is_set():
        raise UpdatedError("the update broker is shutting down", code="conflict")
    if haproxy_patch_active():
        raise UpdatedError('An interrupted HAProxy update requires recovery before other maintenance', code='conflict')
    if not allow_security_recovery and security_recovery_pending():
        raise UpdatedError('Restore system management after the interrupted OS security policy change', code='conflict')
    if not allow_scheduled_reboot and reboot_guard_present():
        raise UpdatedError("a server reboot is scheduled", code="conflict")
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
        if not allow_scheduled_reboot and reboot_guard_present():
            release_operation(descriptor)
            raise UpdatedError("a server reboot is scheduled", code="conflict")
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


def finish_failed(job_id: str, exc: Exception, log: str = "", *, alert: bool = True) -> None:
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
    if not alert:
        return
    report_alert(
        "update.failed",
        job_id,
        "A software update job failed",
        (str(exc) or exc.__class__.__name__)[:1000],
    )


def run_check(
    job_id: str,
    image_channel: str | None,
    source_channel: str | None,
    branch: str | None = None,
    *,
    alert_on_failure: bool = True,
) -> bool:
    try:
        update_job(
            job_id,
            status="running",
            started_at=utc_now(),
            current_component="check",
            progress={"phase": "checking"},
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
        report_availability(plan)
        return True
    except Exception as exc:  # noqa: BLE001 - stored as bounded job failure
        finish_failed(job_id, exc, alert=alert_on_failure)
        return False


def check_worker(
    job_id: str,
    lock_fd: int,
    image_channel: str | None,
    source_channel: str | None,
    branch: str | None = None,
) -> None:
    try:
        run_check(job_id, image_channel, source_channel, branch)
    finally:
        release_operation(lock_fd)


def maintenance_lock_busy() -> bool:
    """Whether a backup, restore or update holds the shared lock right now."""
    try:
        descriptor = os.open(
            MAINTENANCE_LOCK_PATH,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError:
        return True
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def auto_check_once() -> str:
    """One scheduled check. Only its bounded APT refresh holds the shared lock;
    subsequent Git/registry probes release it so backups can run meanwhile.
    """
    if SHUTDOWN_REQUESTED.is_set() or reboot_guard_present() or ACTIVE_MARKER.exists() or haproxy_patch_active():
        return "busy"
    if not OPERATION_THREAD_LOCK.acquire(blocking=False):
        return "busy"
    try:
        if maintenance_lock_busy():
            return "busy"
        job = new_job("check", scheduled=True)
        METADATA_CONTEXT.unlocked = True
        try:
            done = run_check(job["id"], None, None, None, alert_on_failure=False)
        finally:
            METADATA_CONTEXT.unlocked = False
        return "done" if done else "failed"
    finally:
        OPERATION_THREAD_LOCK.release()
        if SHUTDOWN_REQUESTED.is_set():
            STOP_EVENT.set()


def read_settings() -> dict[str, Any]:
    try:
        return safe_json_file(SETTINGS_PATH) if SETTINGS_PATH.exists() else {}
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
        LOG.warning("Ignoring unreadable update settings %s", SETTINGS_PATH.name)
        return {}


def auto_check_hours() -> int:
    """The interval in force: the page's choice, else the configured default."""
    value = read_settings().get("auto_check_hours")
    if isinstance(value, int) and not isinstance(value, bool) and value in AUTO_CHECK_CHOICES:
        return value
    return AUTO_CHECK_HOURS


# What the schedule decided last; the page shows it.
AUTO_CHECK_STATE: dict[str, float | None] = {"next_at": None, "retry_after": 0.0}


def settings_payload() -> dict[str, Any]:
    next_at = AUTO_CHECK_STATE.get("next_at")
    return {
        "auto_check_hours": auto_check_hours(),
        "default_auto_check_hours": AUTO_CHECK_HOURS,
        "choices": list(AUTO_CHECK_CHOICES),
        "next_auto_check_at": (
            dt.datetime.fromtimestamp(next_at, dt.timezone.utc).isoformat()
            if isinstance(next_at, (int, float)) and next_at > 0
            else None
        ),
        "auto_install": {**auto_install_settings(), "last": last_auto_install()},
    }
