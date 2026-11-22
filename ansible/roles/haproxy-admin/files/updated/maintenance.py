"""Auto-install policy, unified maintenance window, and deployment state."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .constants import (
    ACTIVE_MARKER,
    ALLOWED_COMPONENTS,
    AUTO_CHECK_CHOICES,
    AUTO_CHECK_DELAY_SECONDS,
    AUTO_CHECK_POLL_SECONDS,
    AUTO_CHECK_RETRY_SECONDS,
    BRANCH_RE,
    CHANGES_COMPONENT,
    CLI_PATH,
    CONFIG_DIR,
    IMAGE_CHANNELS,
    JOB_TIMEOUT_SECONDS,
    LATEST_PLAN_PATH,
    LOG,
    MAX_STATE_BYTES,
    OPERATION_THREAD_LOCK,
    PYTHON_PATH,
    RELEASE_CHANNELS,
    RELEASE_CHANNEL_MAP,
    RESTART_REQUEST_MARKER,
    SERVICE_NAME,
    SETTINGS_PATH,
    SHUTDOWN_REQUESTED,
    SOURCE_CHANNELS,
    SOURCE_COMPONENTS,
    SOURCE_DIR,
    SOURCE_REVISION_RE,
    STATE_ROOT,
    STOP_EVENT,
    UpdatedError,
    atomic_json,
    child_environment,
    derive_release_channel,
    identifier,
    load_job,
    new_job,
    public_job,
    report_alert,
    report_availability,
    safe_json_file,
    sanitize_log,
    update_job,
    utc_now,
)
from .runner import (
    AUTO_CHECK_STATE,
    REBOOT_CONFIRMATION,
    REBOOT_DELAY_SECONDS,
    REBOOT_REQUIRED_PATH,
    acquire_operation,
    auto_check_hours,
    auto_check_once,
    changes_scope,
    check_worker,
    container_components_for_selection,
    execute_checker,
    finish_failed,
    load_latest_plan,
    plan_component_map,
    plan_is_expired,
    read_settings,
    release_operation,
    reviewed_source_revision,
    run_command,
    selected_components,
    settings_payload,
    store_plan,
    trusted_source,
    validate_applied_container_digests,
    validate_fresh_candidates,
    validate_reviewed_container_candidates,
    validate_selection,
)

# Bound across sibling submodules when the package finishes loading.
OS_SECURITY_ROOT: Any = None
auto_reboot_tick: Any = None
current_boot_id: Any = None
haproxy_operation: Any = None
os_security_check_tick: Any = None
os_security_local_time: Any = None
os_security_snapshot: Any = None
os_security_tick: Any = None
os_security_watch: Any = None
os_security_worker: Any = None
reboot_guard_present: Any = None
request_reboot: Any = None
service_reboot_reason: Any = None
service_restart_tick: Any = None

# Automatic installation, off until the page turns it on. easy-ha-proxy's
# own updates -- the host source, the panel image, the Authelia stack images,
# as the project tested them -- and, only with a second switch of its own, the
# operating system's packages (the os component: apt upgrade with Docker's
# live-restore and the HAProxy hold, the same as the Install button). Never
# HAProxy and never a reboot: a reboot the packages ask for is left to the
# automatic reboot policy, or to the operator. Once a night, inside a window
# of the gateway's local hours, through exactly the path the Install button
# takes: a fresh plan, the same selection rules, the same guards. A failed
# installation raises update.failed like any other; a refused one too.
AUTO_INSTALL_WINDOW = (3, 5)
AUTO_INSTALL_PATH = STATE_ROOT / "auto-install.json"
AUTO_INSTALL_STATE: dict[str, Any] = {"night": None}
AUTO_INSTALL_EXCLUDED = frozenset({"os", "haproxy"})
# Only the second switch takes the operating system's packages along.
AUTO_INSTALL_OS = "os"
MAINTENANCE_CYCLE = threading.Event()


def maintenance_module():
    path = trusted_source('maintenance_window.py')
    spec = importlib.util.spec_from_file_location('easy_ha_proxy_maintenance_window', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unified_policy():
    settings = read_settings()
    return maintenance_module().policy(settings) if settings.get('auto_install_unified') is True else None


def auto_install_settings() -> dict[str, Any]:
    settings = read_settings()
    start = settings.get("auto_install_start")
    end = settings.get("auto_install_end")
    if not (
        isinstance(start, int) and isinstance(end, int)
        and not isinstance(start, bool) and not isinstance(end, bool)
        and 0 <= start <= 23 and 0 <= end <= 23 and start != end
    ):
        start, end = AUTO_INSTALL_WINDOW
    return {
        "enabled": settings.get("auto_install") is True,
        "start": start,
        "end": end,
        "os": settings.get("auto_install_os") is True,
        "unified": settings.get('auto_install_unified') is True,
        "runtime": settings.get('auto_install_runtime') is True,
        'updated_at': settings.get('maintenance_updated_at'),
    }


def set_auto_install(request: dict[str, Any]) -> dict[str, Any]:
    enabled = request.get("enabled")
    start = request.get("start")
    end = request.get("end")
    if not isinstance(enabled, bool):
        raise UpdatedError("enabled must be true or false", code="invalid")
    # An older panel does not send the second switch; it keeps its value.
    with_os = request.get("os", auto_install_settings()["os"])
    if not isinstance(with_os, bool):
        raise UpdatedError("os must be true or false", code="invalid")
    options = {key: request.get(key, auto_install_settings()[key]) for key in ('unified', 'runtime')}
    if any(type(value) is not bool for value in options.values()):
        raise UpdatedError('maintenance options must be true or false', code='invalid')
    if options['unified'] and (enabled or not auto_install_settings()['unified']):
        security = os_security_snapshot()
        if security.get('error') or security.get('recovery_required') or security['policy']['mode'] == 'system':
            raise UpdatedError('Enable managed OS security before enabling the unified maintenance window', code='dependency')
    for value in (start, end):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 23:
            raise UpdatedError("the window is given in whole hours, 0 to 23", code="invalid")
    if start == end:
        raise UpdatedError("the window must not start and end at the same hour", code="invalid")
    settings = read_settings()
    settings.update(auto_install=enabled, auto_install_start=start, auto_install_end=end,
                    auto_install_os=with_os or options['unified'], auto_install_unified=options['unified'],
                    auto_install_runtime=options['runtime'], maintenance_revision=uuid.uuid4().hex,
                    maintenance_updated_at=time.time())
    atomic_json(SETTINGS_PATH, settings)
    LOG.info("Automatic installation %s, window %02d:00-%02d:00, operating-system packages %s",
             "on" if enabled else "off", start, end, "included" if with_os else "excluded")
    return {"ok": True, "settings": settings_payload()}


def in_install_window(local: dt.datetime, start: int, end: int) -> bool:
    """Whether a local time falls in [start, end), the window may span midnight."""

    if start < end:
        return start <= local.hour < end
    return local.hour >= start or local.hour < end


def install_night(local: dt.datetime, start: int, end: int) -> str:
    """The date the current window opened on, so a night gets one attempt."""

    opened = local.date()
    if start > end and local.hour < end:
        opened -= dt.timedelta(days=1)
    return opened.isoformat()


def auto_install_selection(plan: dict[str, Any], with_os: bool = False) -> list[str]:
    """What the Install button's "select all" would take, without HAProxy.

    The changes-only update when the plan offers it, with the container
    images beside it; else the complete stack, which brings the services,
    the daemons and the panel with it; else each actionable component. The
    operating system's packages come last, and only when asked for.
    """

    selection = project_selection(plan)
    os_entry = plan_component_map(plan).get(AUTO_INSTALL_OS) or {}
    if with_os and os_entry.get("state") == "available" and os_entry.get("actionable") is True:
        # APT runs last, as the Install button orders it: it can leave the
        # host waiting for a reboot.
        selection.append(AUTO_INSTALL_OS)
    return selection


def project_selection(plan: dict[str, Any]) -> list[str]:
    available = plan_component_map(plan)
    actionable = [
        component_id
        for component_id, item in available.items()
        if item.get("state") == "available"
        and item.get("actionable") is True
        and component_id not in AUTO_INSTALL_EXCLUDED
    ]
    if "all" in actionable and changes_scope(available.get("all")) is not None:
        return [CHANGES_COMPONENT] + [
            component_id
            for component_id in ("authelia-container", "admin-container")
            if component_id in actionable
        ]
    if "all" in actionable:
        # The complete stack pulls the Authelia and panel images itself.
        return ["all"]
    return sorted(actionable)


def last_auto_install() -> dict[str, Any] | None:
    try:
        return safe_json_file(AUTO_INSTALL_PATH) if AUTO_INSTALL_PATH.exists() else None
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
        return None


def record_auto_install(outcome: str, **values: Any) -> None:
    record = {"at": utc_now(), "outcome": outcome, **values}
    try:
        atomic_json(AUTO_INSTALL_PATH, record)
    except OSError:
        LOG.warning("Could not record the automatic installation")
    LOG.info("Automatic installation: %s %s", outcome, values or "")


def auto_install_once() -> str:
    """One night's attempt: "busy" to try again in a minute, else the outcome."""

    if SHUTDOWN_REQUESTED.is_set() or reboot_guard_present() or ACTIVE_MARKER.exists():
        return "busy"
    plan = load_latest_plan()
    if plan is None or plan_is_expired(plan):
        checked = auto_check_once()
        if checked == "busy":
            return "busy"
        plan = load_latest_plan()
        if checked != "done" or plan is None or plan_is_expired(plan):
            record_auto_install("check-failed")
            report_alert("update.failed", "auto-install",
                         "The automatic installation could not check for updates")
            return "check-failed"
    options = auto_install_settings()
    if options['unified'] and (plan_component_map(plan).get('os') or {}).get('state') not in {'current', 'available'}:
        record_auto_install('refused', error='The OS package plan is unverified')
        report_alert('update.failed', 'unified-maintenance', 'The OS package plan is unverified; installation was refused')
        return 'refused'
    components = auto_install_selection(plan, with_os=options['os'] or options['unified'])
    if not components:
        record_auto_install("nothing")
        return "nothing"
    try:
        validate_selection(plan, components)
        lock_fd = acquire_operation()
    except UpdatedError as exc:
        if exc.code == "busy":
            return "busy"
        record_auto_install("refused", components=components, error=str(exc)[:500])
        report_alert("update.failed", "auto-install",
                     "The automatic installation was refused", str(exc)[:1000])
        return "refused"
    extra = {}
    unified = unified_policy()
    if unified:
        window = maintenance_module().current(unified, os_security_local_time())
        if not window:
            release_operation(lock_fd)
            return 'deferred'
        extra['maintenance'] = {**window, 'revision': unified['id'], 'runtime': unified['runtime']}
    job = new_job("apply", components=components, plan_id=plan["id"], scheduled=True, **extra)
    record_auto_install("started", components=components, job_id=job["id"])
    # The same worker as the Install button; it reports a failure itself.
    options = {'maintenance': extra['maintenance']} if extra else {}
    apply_worker(job["id"], lock_fd, plan, components, **options)
    result = load_job(job["id"], include_log=False)
    status = str(result.get("status") or "")
    outcome = 'deferred' if (result.get('result') or {}).get('deferred_components') else "installed" if status == "completed" else "failed"
    record_auto_install(outcome, components=components, job_id=job["id"])
    return outcome


def auto_install_tick(now: dt.datetime | None = None) -> str | None:
    """Called each minute by the schedule; None when it is not the time."""

    settings = auto_install_settings()
    if settings['unified']:
        return unified_maintenance_tick(now)
    if not settings["enabled"]:
        return None
    local = (now or dt.datetime.now()).astimezone()
    if not in_install_window(local, settings["start"], settings["end"]):
        return None
    night = install_night(local, settings["start"], settings["end"])
    if AUTO_INSTALL_STATE.get("night") == night:
        return None
    outcome = auto_install_once()
    if outcome != "busy":
        AUTO_INSTALL_STATE["night"] = night
    return outcome


def unified_security_stage(action):
    descriptor = acquire_operation()
    try:
        value = unified_policy()
        if not value or not maintenance_module().current(value, os_security_local_time()):
            raise UpdatedError('The maintenance window closed before application', code='window_closed')
        job = new_job('security-' + action, components=['os'], scheduled=True)
    except Exception:
        release_operation(descriptor)
        raise
    os_security_worker(job['id'], descriptor, action, maintenance_revision=value['id'])
    result = load_job(job['id'], include_log=False)
    if result.get('status') != 'completed':
        if 'window' in str(result.get('error', '')).lower() and 'closed' in str(result.get('error', '')).lower():
            raise UpdatedError('The maintenance window closed before application', code='window_closed')
        raise UpdatedError('Unified maintenance could not finish the service or security stage')


def unified_reboot(value, window):
    if not REBOOT_REQUIRED_PATH.exists() and not service_reboot_reason():
        return 'completed'
    if time.time() + REBOOT_DELAY_SECONDS >= window['closes_at']:
        return 'deferred'
    descriptor = acquire_operation()
    try:
        current = unified_policy()
        if not current or current['id'] != value['id'] or not maintenance_module().current(current, os_security_local_time()):
            return 'deferred'
        atomic_json(OS_SECURITY_ROOT / 'maintenance-reboot.json', {
            **maintenance_module().restart_policy(value), 'allow_service_reboot': True,
            'attempt': {'window': window['key'], 'state': 'scheduled', 'at': time.time()},
        })
        request_reboot({'confirmation': REBOOT_CONFIRMATION, 'expected_boot_id': current_boot_id(), 'actor': 'unified-maintenance'},
                       automatic={'unified': True, 'policy_revision': value['id'], 'window': window['key']},
                       held_lock=descriptor)
        return 'reboot-scheduled'
    finally:
        release_operation(descriptor)


def unified_maintenance_tick(now=None):
    value = unified_policy()
    if not value or not value['enabled']:
        return None
    window = maintenance_module().current(value, now or os_security_local_time())
    if not window or SHUTDOWN_REQUESTED.is_set() or ACTIVE_MARKER.exists() or reboot_guard_present():
        return None
    path = STATE_ROOT / 'maintenance-cycle.json'
    previous = safe_json_file(path) if path.exists() else {}
    if previous.get('night') == window['key'] and previous.get('revision') == value['id'] and previous.get('outcome') != 'busy':
        if previous.get('outcome') == 'running':
            previous.update(outcome='interrupted', completed_at=utc_now())
            atomic_json(path, previous)
            report_alert('update.failed', 'unified-maintenance', 'Unified maintenance was interrupted; review recovery status')
            record_auto_install('interrupted')
        return None  # Persistent, including a failed/interrupted cycle: never repeat destructive work in a loop.
    if not OPERATION_THREAD_LOCK.acquire(blocking=False):
        return 'busy'
    OPERATION_THREAD_LOCK.release()
    record = {'night': window['key'], 'revision': value['id'], 'started_at': utc_now(), 'outcome': 'running'}
    atomic_json(path, record)
    MAINTENANCE_CYCLE.set()
    outcome = 'completed'
    try:
        runtime_state = OS_SECURITY_ROOT / 'runtime-maintenance.json'
        if runtime_state.exists() and safe_json_file(runtime_state).get('phase') not in {'completed', 'recovered'}:
            raise UpdatedError('Runtime maintenance requires operator recovery before another automatic cycle')
        for stage in ('updates', 'security', 'haproxy', 'services', 'reboot'):
            current = unified_policy()
            if (not current or current['id'] != value['id']
                    or not maintenance_module().current(current, os_security_local_time())):
                outcome = 'deferred'
                break
            record['stage'] = stage
            atomic_json(path, record)
            if stage == 'updates':
                answer = auto_install_once()
                if answer not in {'installed', 'nothing'}:
                    outcome = answer if answer in {'busy', 'deferred'} else 'failed'
                    break
            elif stage == 'security':
                unified_security_stage('install')
            elif stage == 'haproxy':
                if auto_check_once() != 'done':
                    raise UpdatedError('Could not check HAProxy after installing system packages')
                plan = load_latest_plan()
                entry = plan_component_map(plan).get('haproxy') or {}
                if entry.get('state') == 'available' and entry.get('actionable') is True:
                    descriptor = acquire_operation()
                    job = new_job('apply', components=['haproxy'], plan_id=plan['id'], scheduled=True,
                                  maintenance={**window, 'revision': value['id'], 'runtime': value['runtime']})
                    apply_worker(job['id'], descriptor, plan, ['haproxy'],
                                 maintenance={**window, 'revision': value['id'], 'runtime': value['runtime']})
                    if load_job(job['id'], include_log=False).get('status') != 'completed':
                        raise UpdatedError('Controlled HAProxy application did not complete')
                elif entry.get('state') in {'unknown', 'blocked'}:
                    details = entry.get('details') or {}
                    installed = entry.get('current_version') or entry.get('installed')
                    candidate = entry.get('available_version') or entry.get('available')
                    if (details.get('needs_reload') or (candidate and installed and candidate != installed)
                            or details.get('qualified') is True):
                        raise UpdatedError('Pending HAProxy application requires operator review')
            elif stage == 'services':
                unified_security_stage('restart')
            else:
                outcome = unified_reboot(value, window)
        record.update(outcome=outcome, completed_at=utc_now())
    except Exception as error:
        deferred = isinstance(error, UpdatedError) and error.code == 'window_closed'
        record.update(outcome='deferred' if deferred else 'failed', error=str(error)[:1000], completed_at=utc_now())
        if not deferred:
            report_alert('update.failed', 'unified-maintenance', 'Unified maintenance failed', str(error)[:1000])
    finally:
        atomic_json(path, record)
        record_auto_install(record['outcome'])
        MAINTENANCE_CYCLE.clear()
        request_self_restart_if_needed()
    return record['outcome']


def set_settings(request: dict[str, Any]) -> dict[str, Any]:
    value = request.get("auto_check_hours")
    if isinstance(value, bool) or not isinstance(value, int) or value not in AUTO_CHECK_CHOICES:
        raise UpdatedError(
            "auto_check_hours must be one of " + ", ".join(str(item) for item in AUTO_CHECK_CHOICES),
            code="invalid",
        )
    settings = read_settings()
    settings["auto_check_hours"] = value
    atomic_json(SETTINGS_PATH, settings)
    # The next pass of the schedule recomputes from the new interval.
    AUTO_CHECK_STATE["next_at"] = None
    AUTO_CHECK_STATE["retry_after"] = 0.0
    LOG.info("Automatic update checks set to every %s h (0 = off)", value)
    return {"ok": True, "settings": settings_payload()}


def last_check_time() -> float:
    try:
        plan = load_latest_plan()
        created = dt.datetime.fromisoformat(str((plan or {}).get("created_at") or ""))
        return created.timestamp()
    except (UpdatedError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0.0


def seconds_until_auto_check(now: float) -> float | None:
    """How long until the newest check is an interval old; None when off."""
    hours = auto_check_hours()
    if hours <= 0:
        return None
    return max(0.0, last_check_time() + hours * 3600 - now)


def auto_check_loop() -> None:
    started = time.time()
    while True:
        try:
            if SETTINGS_PATH.exists():
                safe_json_file(SETTINGS_PATH)  # A corrupt policy must not reactivate old independent schedules.
            unified = auto_install_settings()['unified']
        except Exception:
            LOG.exception('The maintenance policy could not be read')
            if STOP_EVENT.wait(AUTO_CHECK_POLL_SECONDS):
                return
            continue
        answer = ''
        try:
            if time.time() >= started + AUTO_CHECK_DELAY_SECONDS:
                # The unified window owns installations, not checks: the
                # check keeps running on its interval and after each boot.
                answer = os_security_check_tick() if unified else os_security_tick()
        except Exception:
            answer = 'failed'
            LOG.exception('Scheduled OS security maintenance failed')
        try:
            if time.time() >= started + AUTO_CHECK_DELAY_SECONDS:
                os_security_watch(last_answer=answer)
        except Exception:
            LOG.exception('The OS security watch failed')
        try:
            if not unified and time.time() >= started + AUTO_CHECK_DELAY_SECONDS:
                service_restart_tick()
        except Exception:
            LOG.exception('Scheduled service restarts failed')
        try:
            if not unified and time.time() >= started + AUTO_CHECK_DELAY_SECONDS:
                auto_reboot_tick()
        except Exception:
            LOG.exception('Scheduled automatic reboot failed')
        try:
            now = time.time()
            wait = seconds_until_auto_check(now)
            if wait is None:
                AUTO_CHECK_STATE["next_at"] = None
            else:
                due = max(
                    now + wait,
                    started + AUTO_CHECK_DELAY_SECONDS,
                    float(AUTO_CHECK_STATE.get("retry_after") or 0.0),
                )
                AUTO_CHECK_STATE["next_at"] = due
                if now >= due:
                    outcome = auto_check_once()
                    LOG.info("Scheduled update check: %s", outcome)
                    if outcome != "done":
                        AUTO_CHECK_STATE["retry_after"] = time.time() + AUTO_CHECK_RETRY_SECONDS
        except Exception:  # noqa: BLE001 - the schedule must outlive one bad run
            LOG.exception("Scheduled update check failed")
            AUTO_CHECK_STATE["retry_after"] = time.time() + AUTO_CHECK_RETRY_SECONDS
        try:
            if time.time() >= started + AUTO_CHECK_DELAY_SECONDS:
                # record_auto_install logs the outcome itself.
                auto_install_tick()
        except Exception:  # noqa: BLE001 - the schedule must outlive one bad run
            LOG.exception("Automatic installation failed")
        if STOP_EVENT.wait(AUTO_CHECK_POLL_SECONDS):
            return


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
    if component == CHANGES_COMPONENT:
        command.append("--no-full-fallback")
    return command


def request_self_restart_if_needed() -> None:
    if MAINTENANCE_CYCLE.is_set():
        return
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


def apply_haproxy_patch(job_id, plan, log_prefix, *, maintenance=None):
    entry = plan_component_map(plan).get('haproxy') or {}
    details = entry.get('details') or {}
    expected = entry.get('available_version') or entry.get('available')
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{1,100}', expected):
        raise UpdatedError('The reviewed HAProxy version is unavailable', code='stale_plan')
    python = PYTHON_PATH if PYTHON_PATH.is_file() else Path('/usr/bin/python3')
    command = [str(python), str(trusted_source('haproxy_package_migrate.py')), 'patch', '--expected-version', expected]
    if isinstance(maintenance, dict):
        command.extend(['--maintenance-revision', maintenance['revision'], '--maintenance-until', str(maintenance['closes_at']),
                        '--maintenance-state-root', str(OS_SECURITY_ROOT)])
    if details.get('needs_reload') is True:
        command.append('--reinstall')
    previous = haproxy_operation()
    code, output = run_command(job_id, command, timeout=JOB_TIMEOUT_SECONDS, log_prefix=log_prefix)
    result = haproxy_operation()
    if maintenance and result and result.get('phase') == 'prepared' and time.time() >= maintenance['closes_at']:
        raise UpdatedError('The maintenance window closed before HAProxy application', code='window_closed')
    if result and result.get('id') != (previous or {}).get('id'):
        update_job(job_id, result={'haproxy': result})
    if (code or not result or result.get('id') == (previous or {}).get('id')
            or result.get('phase') != 'committed' or result.get('target_verified') is not True):
        raise UpdatedError('HAProxy update failed; review its recovery status and job log', code='verification_failed')
    return result, output


def apply_worker(
    job_id: str,
    lock_fd: int,
    plan: dict[str, Any],
    components: list[str],
    *, maintenance=None,
) -> None:
    combined_log = ""
    component_seconds: dict[str, int] = {}
    haproxy_result = None
    lock_reacquired = True
    try:
        # Ensure the HTTP 202 response reaches the browser before a selected
        # admin-container update starts recreating this web application.
        time.sleep(1.0)
        # Configuration can change after the request-level validation but
        # before this worker starts. Recheck while holding the maintenance
        # lock before declaring the mutating update active.
        validate_selection(plan, components)
        if 'haproxy' in components and components[-1] != 'haproxy':
            raise UpdatedError('The controlled HAProxy update must run last')
        ACTIVE_MARKER.write_text(f"job_id={job_id}\n", encoding="utf-8")
        os.chmod(ACTIVE_MARKER, 0o600)
        update_job(
            job_id,
            status="running",
            started_at=utc_now(),
            progress={"phase": "verifying"},
        )
        fresh = execute_checker(
            job_id,
            image_channel=str(plan.get("image_channel") or "latest"),
            source_channel=str(plan.get("source_channel") or "github"),
            # The branch the plan was checked against, so the recheck
            # compares like with like instead of trusting the metadata.
            branch=(str(plan["branch"]) if plan.get("branch") else None),
        )
        validate_fresh_candidates(plan, fresh, components)
        validate_reviewed_container_candidates(plan, fresh, components)
        source_channel = str(plan.get("source_channel"))
        image_channel = str(plan.get("image_channel"))
        expected_source_revision = reviewed_source_revision(plan, components)
        deferred_components = []
        for index, component in enumerate(components):
            if isinstance(maintenance, dict):
                current = unified_policy()
                if (not current or current['id'] != maintenance.get('revision')
                        or not maintenance_module().current(current, os_security_local_time())):
                    deferred_components = components[index:]
                    break
            begun = time.monotonic()
            update_job(
                job_id,
                current_component=component,
                component_index=index,
                component_started_at=utc_now(),
                progress={"phase": "starting"},
            )
            heading = f"\n=== Applying component: {component} ==="
            if component == 'haproxy':
                # HAProxy is last. Transfer custody of the common lock to the
                # PID-1-owned child; it takes the lock itself before any work.
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_reacquired = False
                options = {'maintenance': maintenance} if isinstance(maintenance, dict) else {}
                haproxy_result, output = apply_haproxy_patch(job_id, plan, sanitize_log(combined_log + heading), **options)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    lock_reacquired = True
                except BlockingIOError:
                    pass  # Another operation may start after the verified child exits.
                returncode = 0
            else:
                command = update_command(
                    component,
                    source_channel=source_channel,
                    image_channel=image_channel,
                    expected_source_revision=expected_source_revision,
                )
                if component == 'os' and load_job(job_id, include_log=False).get('scheduled') is True:
                    command.append('--automatic-os')
                    if isinstance(maintenance, dict):
                        flag = '--runtime-maintenance' if maintenance.get('runtime') is True else '--maintenance-revision'
                        command.extend([flag, str(maintenance['revision']),
                                        '--maintenance-until', str(maintenance['closes_at'])])
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
            component_seconds[component] = int(time.monotonic() - begun)
        reboot_required = Path("/var/run/reboot-required").exists()
        applied_components = components[:len(component_seconds)]
        result: dict[str, Any] = {
            "components": applied_components,
            'deferred_components': deferred_components,
            "reboot_required": reboot_required,
            # How long each part took, for the next installation's estimate.
            "component_seconds": component_seconds,
        }
        if haproxy_result is not None:
            result['haproxy'] = haproxy_result
        update_job(job_id, progress={"phase": "rechecking"})
        try:
            if not lock_reacquired:
                raise UpdatedError('The update was verified; recheck after the other maintenance operation completes')
            refreshed_payload = execute_checker(
                job_id,
                image_channel=image_channel,
                source_channel=source_channel,
                # The branch that was reviewed and installed, like the check
                # before the update; not whatever the metadata says.
                branch=(str(plan["branch"]) if plan.get("branch") else None),
            )
            validate_applied_container_digests(plan, refreshed_payload, applied_components)
            refreshed = store_plan(refreshed_payload)
            report_availability(refreshed)
            result["refreshed_plan_id"] = refreshed["id"]
        except Exception as exc:  # noqa: BLE001 - update already succeeded
            if container_components_for_selection(applied_components):
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
        if isinstance(exc, UpdatedError) and exc.code == 'window_closed' and isinstance(maintenance, dict):
            update_job(job_id, status='completed', completed_at=utc_now(), current_component=None,
                       result={'components': components[:len(component_seconds)],
                               'deferred_components': components[len(component_seconds):]}, output={'log':combined_log})
        else:
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


# The build the host runs, for the panel's footer: which commit the managed
# source is at, when it was made, and the fingerprint of its web files -- the
# same `git ls-tree` sum CI labels the panel image with, so the panel can say
# whether it was built from what the host has. The source is a shallow clone,
# so a commit count would always be 1; the commit time orders builds instead.
BUILD_TTL_SECONDS = 60.0
WEB_TREE_INPUTS = ("Dockerfile", ".dockerignore", "docker/app")
_HOST_BUILD: dict[str, Any] = {"at": None, "value": None}
_HOST_BUILD_LOCK = threading.Lock()


def _source_git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={SOURCE_DIR}", "-C", str(SOURCE_DIR), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace")


# The release the source says it is: one line, MAJOR.MINOR.PATCH with an
# optional pre-release tag such as 1.1.0-alpha. Anything else is no version.
SOURCE_VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,24})?$")


def _read_source_version() -> str:
    try:
        text = (SOURCE_DIR / "VERSION").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return text if SOURCE_VERSION_RE.fullmatch(text) else ""


def _read_host_build() -> dict[str, str] | None:
    if not (SOURCE_DIR / ".git").exists():
        return None
    head = (_source_git("log", "-1", "--format=%H %cI") or "").split()
    if len(head) != 2 or not SOURCE_REVISION_RE.fullmatch(head[0]):
        return None
    try:
        committed = dt.datetime.fromisoformat(head[1])
    except ValueError:
        return None
    listing = _source_git("ls-tree", "-r", "--full-tree", "HEAD", "--", *WEB_TREE_INPUTS)
    return {
        "revision": head[0],
        "committed_at": committed.astimezone(dt.timezone.utc).isoformat(timespec="seconds"),
        "web_tree": hashlib.sha256(listing.encode("utf-8")).hexdigest() if listing else "",
        "version": _read_source_version(),
    }


def host_build() -> dict[str, str] | None:
    """The installed source's build, read at most once a minute."""

    with _HOST_BUILD_LOCK:
        at = _HOST_BUILD["at"]
        if at is not None and time.monotonic() - at < BUILD_TTL_SECONDS:
            return _HOST_BUILD["value"]
        value = _read_host_build()
        _HOST_BUILD.update(at=time.monotonic(), value=value)
        return value


def summary_payload(plan: dict[str, Any] | None) -> dict[str, Any]:
    """What the navigation shows: whether the newest check found anything.

    "product" when easy-ha-proxy itself has an update, "os" when only the
    operating system's packages do -- those come nearly every day and should
    not shout like the rest -- and None when there is nothing to install.
    A plan past its install deadline still counts: it is what the newest
    check found, and the page asks for a fresh check before installing.
    """

    kinds = [
        str(item.get("id"))
        for item in (plan or {}).get("components") or []
        if isinstance(item, dict)
        and item.get("state") == "available"
        and item.get("actionable") is True
    ]
    level = "product" if any(kind != "os" for kind in kinds) else ("os" if kinds else None)
    return {
        "level": level,
        "components": kinds,
        "checked_at": (plan or {}).get("created_at"),
        "build": host_build(),
    }


def summary_response() -> dict[str, Any]:
    try:
        plan = load_latest_plan()
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError):
        plan = None
    return {"ok": True, **summary_payload(plan)}


HAPROXY_UPDATE_STATE = Path('/var/lib/easy-ha-proxy/haproxy-package-migration/last-update.json')
HAPROXY_MIGRATION_STATE = HAPROXY_UPDATE_STATE.with_name('last-migration.json')
HAPROXY_MIGRATION_PLAN = STATE_ROOT / 'haproxy-migration-plan.json'
HAPROXY_MIGRATION_CONFIRMATION = 'MIGRATE 3.4'
HAPROXY_SETTLED_PHASES = frozenset({'committed', 'rolled_back', 'aborted', 'preparing', 'prepared'})


def read_haproxy_operation(path):
    try:
        if path.is_symlink() or path.stat().st_size > 64 * 1024:
            return None
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or not re.fullmatch(r'[0-9a-f]{32}', str(data.get('id', ''))):
            return None
        if not isinstance(data.get('phase'), str):
            return None
        if any(data.get(key) is not None and not isinstance(data[key], list) for key in ('target_packages', 'extra_packages')):
            return None
        return {key: data.get(key) for key in ('id', 'kind', 'phase', 'architecture', 'created_at', 'engine_digest',
                                               'old_version', 'target_runtime_version', 'target_packages', 'extra_packages', 'updated_at',
                                               'failure', 'target_verified', 'rollback_verified')}
    except (OSError, ValueError, TypeError):
        return None
