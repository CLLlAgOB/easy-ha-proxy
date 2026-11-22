"""Unix-socket request dispatcher and CLI entrypoint for updated."""

from __future__ import annotations

import datetime as dt
import errno
import fcntl
import ipaddress
import json
import logging
import os
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from . import constants as _constants
from .constants import (
    ACTIVE_MARKER,
    ACTOR_RE,
    ASSISTANT_REBOOT_MARKER,
    BOOT_ID_RE,
    CONNECTION_SLOTS,
    LATEST_PLAN_PATH,
    LOG,
    MAINTENANCE_LOCK_PATH,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    OPERATION_THREAD_LOCK,
    PROTOCOL_VERSION,
    REBOOT_MARKER,
    REQUEST_FIELDS,
    SHUTDOWN_REQUESTED,
    SOCKET_PATH,
    STATE_ROOT,
    STOP_EVENT,
    UpdatedError,
    _ALERTS,
    active_job,
    atomic_json,
    child_environment,
    ensure_layout,
    fsync_directory,
    identifier,
    list_jobs,
    load_job,
    new_job,
    public_job,
    recover_stale_jobs,
    safe_json_file,
    update_job,
    utc_now,
)
from .runner import (
    BACKUPD_RESTORE_ACTIVE_MARKER,
    BOOT_ID_PATH,
    REBOOT_CONFIRMATION,
    REBOOT_DELAY_SECONDS,
    REBOOT_REQUIRED_PATH,
    REBOOT_UNIT_PREFIX,
    REBOOT_UNIT_RE,
    SYSTEMCTL_PATH,
    SYSTEMD_RUN_PATH,
    acquire_operation,
    finish_failed,
    haproxy_transaction_active,
    load_latest_plan,
    plan_is_expired,
    release_operation,
    run_command,
    settings_payload,
    systemctl_properties,
    trusted_source,
)
from .maintenance import (
    auto_check_loop,
    read_deployment,
    set_auto_install,
    set_channels,
    set_settings,
    start_apply,
    start_check,
    start_thread,
    summary_payload,
    summary_response,
    unified_policy,
)
from .migrations import (
    OS_SECURITY_ROOT,
    auto_reboot_record,
    auto_reboot_snapshot,
    auto_reboot_tool,
    cancel_automatic_reboot_intent,
    haproxy_operation,
    migration_status,
    os_security_install_due,
    os_security_live_settings,
    os_security_local_time,
    os_security_policy,
    os_security_schedule,
    os_security_snapshot,
    os_security_tool,
    os_security_worker,
    service_reboot_reason,
    service_restart_record,
    service_restart_snapshot,
    service_restart_tool,
    set_auto_reboot,
    set_service_restarts,
    start_haproxy_migration,
    start_haproxy_transition,
)

def start_os_security(request, *, scheduled=False):
    action = {'os_security_check': 'check', 'os_security_install': 'install',
              'os_security_configure': 'configure', 'os_security_cycle': 'cycle',
              'os_security_restart_check': 'restart-check', 'os_security_restart': 'restart',
              'os_security_restart_cycle': 'restart-cycle'}[request['action']]
    policy = os_security_policy(request) if action == 'configure' else None
    if policy and policy['mode'] == 'system' and unified_policy():
        raise UpdatedError('Disable the unified maintenance window before returning updates to Linux', code='dependency')
    if action in {'install', 'configure', 'restart'} and request.get('confirmation') != 'SECURITY':
        raise UpdatedError('Type SECURITY to confirm OS security management')
    os_security_tool()
    if action in {'restart-check', 'restart', 'restart-cycle'}:
        service_restart_tool()
    lock_fd = acquire_operation(allow_security_recovery=bool(policy and policy['mode'] == 'system'))
    try:
        if haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before OS maintenance', code='config_pending')
        if policy and policy['mode'] == 'system' and auto_reboot_record()['enabled']:
            # Returning control to Linux also revokes the panel's reboot policy.
            value = auto_reboot_record()
            value.update(enabled=False, id=uuid.uuid4().hex, updated_at=time.time())
            atomic_json(OS_SECURITY_ROOT / 'reboot-policy.json', value)
        if policy and policy['mode'] == 'system' and service_restart_record()['enabled']:
            value = service_restart_record()
            value.update(enabled=False, id=uuid.uuid4().hex, updated_at=time.time())
            atomic_json(OS_SECURITY_ROOT / 'restart-policy.json', value)
        if action in {'install', 'cycle', 'restart', 'restart-cycle'} and os_security_snapshot()['policy']['mode'] == 'system':
            raise UpdatedError('Enable OS security management before installing updates', code='dependency')
        job = new_job('security-' + action, components=['os'], scheduled=scheduled)
        start_thread(os_security_worker, job['id'], lock_fd, action, policy)
        return {'ok': True, 'job_id': job['id'], 'job': public_job(job)}
    except Exception:
        release_operation(lock_fd)
        raise


def os_security_tick(now=None):
    snapshot = os_security_snapshot()
    policy, status = snapshot['policy'], snapshot.get('status') or {}
    if not snapshot['available'] or snapshot['recovery_required'] or policy['mode'] == 'system':
        return 'disabled'
    local = now or os_security_local_time()
    stamp = local.timestamp()
    last_attempt = status.get('last_attempt') or 0
    last_success = status.get('last_success') or 0
    # Persisted timestamps prevent a broker restart or a failure from making
    # a new APT job every minute. A busy operation does not consume the turn.
    due = stamp - last_success >= policy['interval'] * 3600
    install_due = os_security_install_due(policy, status, local)
    last_relevant_attempt = (status.get('last_install_attempt') or 0) if install_due else last_attempt
    if stamp - last_relevant_attempt < 1800:
        return 'waiting'
    if not due and not install_due:
        return 'waiting'
    try:
        start_os_security({'action': 'os_security_cycle'}, scheduled=True)
    except UpdatedError as error:
        return error.code
    return 'started'


def boot_started_at() -> float:
    """When this boot began (btime in /proc/stat), 0 when it cannot be read."""

    try:
        for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
            if line.startswith("btime "):
                return float(line.split()[1])
    except (OSError, ValueError, IndexError, UnicodeError):
        pass
    return 0.0


def restart_check_predates_boot(restart: Any) -> bool:
    """Whether a restart finding was made before the current boot.

    A reboot restarts every service and activates the installed kernel, so
    what such a check listed no longer holds. Shown as current, it kept "some
    services require a restart" up all day after the night's reboot.
    """

    if not isinstance(restart, dict):
        return False
    checked = restart.get("checked_at")
    boot = boot_started_at()
    return type(checked) in (int, float) and boot > 0 and checked < boot


def os_security_check_tick(now=None):
    """Checks only, for the unified window: installing waits for the window.

    Due on the policy's interval, and at once (after the startup delay) when
    the last finding predates this boot. A failed check waits 30 minutes.
    """

    snapshot = os_security_snapshot()
    policy, status = snapshot['policy'], snapshot.get('status') or {}
    if not snapshot['available'] or snapshot['recovery_required'] or policy['mode'] == 'system':
        return 'disabled'
    stamp = (now or os_security_local_time()).timestamp()
    last_attempt = float(status.get('last_attempt') or 0)
    stale = restart_check_predates_boot(status.get('restart'))
    due = stamp - float(status.get('last_success') or 0) >= policy['interval'] * 3600
    if stale and last_attempt < boot_started_at():
        due = True
    elif stamp - last_attempt < 1800:
        return 'waiting'
    if not due and not stale:
        return 'waiting'
    try:
        start_os_security({'action': 'os_security_check'}, scheduled=True)
    except UpdatedError as error:
        return error.code
    return 'started'


def os_security_response(request):
    result = {'ok': True, **os_security_snapshot()}
    result['jobs'] = [job for job in list_jobs() if job.get('operation', '').startswith('security-')][:10]
    active = active_job()
    result['active_job'] = public_job(active, include_log=False) if active else None
    result['configuring'] = bool(active and active.get('operation') == 'security-configure' and active.get('status') in {'queued', 'running'})
    if result['configuring']:
        result['recovery_required'] = False
    result['live_settings'] = os_security_live_settings() if result['available'] else None
    result['schedule'] = os_security_schedule(result)
    result['automatic_reboot'] = auto_reboot_snapshot()
    result['service_restarts'] = service_restart_snapshot()
    result['maintenance_window'] = unified_policy()
    result['boot_id'] = current_boot_id()
    status = result.get('status')
    if isinstance(status, dict) and restart_check_predates_boot(status.get('restart')):
        status['restart'] = {**status['restart'], 'before_boot': True}
    if request.get('job_id'):
        job = load_job(identifier(request['job_id'], 'job id'))
        if not job.get('operation', '').startswith('security-'):
            raise UpdatedError('OS security job was not found', code='not_found')
        result['job'] = job
    result['server_time'] = utc_now()
    result['server_timezone'] = dt.datetime.now().astimezone().strftime('%Z %z')
    return result


SSH_PROTECTION_MONITOR = STATE_ROOT / 'ssh-protection-monitor.json'
SSH_PROTECTION_JOB = 'ssh-protection'


def ssh_protection_command(operation):
    return ['/usr/bin/python3', str(trusted_source('ssh_protection.py')), operation]


def ssh_protection_query(operation, *options):
    try:
        result = subprocess.run([*ssh_protection_command(operation), *options], capture_output=True,
                                timeout=9, check=False, env=child_environment())
        payload = json.loads(result.stdout)
        if isinstance(payload, dict):
            if not result.returncode and payload.get('ok') is True:
                return payload
            if payload.get('error'):
                raise UpdatedError(str(payload['error']), code='verification_failed')
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    raise UpdatedError('Could not read Fail2ban on the server', code='verification_failed')


def ssh_protection_status(request):
    enabled = ssh_monitoring_enabled()
    requested = request.get('job_id')
    if requested is not None:
        job = load_job(identifier(requested, 'job id'))
        if job.get('operation') != SSH_PROTECTION_JOB:
            raise UpdatedError('SSH protection job was not found', code='not_found')
    else:
        job = next((value for value in list_jobs() if value.get('operation') == SSH_PROTECTION_JOB), None)
    result = {'ok': True, 'monitoring': enabled, 'job': job}
    if enabled:
        try:
            result.update(ssh_protection_query('status'))
        except UpdatedError as error:
            # The page still answers, so the operator can pause monitoring
            # or read the last job while Fail2ban cannot be read.
            result.update(state='unavailable', error=str(error))
        result['ok'] = True
    return result


def ssh_monitoring_enabled():
    return not SSH_PROTECTION_MONITOR.exists() or safe_json_file(SSH_PROTECTION_MONITOR).get('enabled') is not False


def ssh_protection_watch_loop():
    expected = False
    samples = []
    while not STOP_EVENT.wait(60):
        try:
            if ACTIVE_MARKER.exists():
                continue
            detail = ''
            burst = False
            retired = False
            if not ssh_monitoring_enabled():
                expected, samples = False, []
                retired = True
            else:
                status = ssh_protection_query('monitor')
                active = status['state'] == 'active'
                expected = bool(status.get('managed_enabled')) if status.get('managed') else expected or active
                retired = bool(status.get('managed') and not status.get('managed_enabled') and not active)
                firewall = (status.get('firewall') or {}).get('state')
                if expected and not active:
                    detail = 'The expected Fail2ban SSH rule is inactive or its service is unavailable.'
                elif expected and status.get('managed_enabled') and status.get('external_config'):
                    detail = 'External SSH settings can override the panel-managed Fail2ban rule.'
                elif expected and status.get('error'):
                    detail = 'Could not read Fail2ban on the server'
                elif expected and firewall in {'missing', 'ports_changed', 'unknown', 'order_unknown'}:
                    detail = {
                        'missing': 'The firewall is missing rules for one or more active SSH blocks.',
                        'ports_changed': 'The SSH listening ports have changed since the Fail2ban rule was configured.',
                        'unknown': 'The firewall rules for SSH could not be read.',
                        'order_unknown': 'Earlier firewall rules may take precedence over SSH blocks.',
                    }[firewall]
                total = status.get('total_banned')
                if active and type(total) is int:
                    now = time.monotonic()
                    if samples and total < samples[-1][1]:
                        samples.clear()
                    samples = [(at, count) for at, count in samples if now - at <= 300]
                    samples.append((now, total))
                    burst = total - samples[0][1] >= 10
                else:
                    samples.clear()
            _ALERTS.observe("ssh.protection_lost", 'host', active=bool(detail),
                            summary='SSH blocking could not be verified', detail=detail, retired=retired)
            _ALERTS.observe("ssh.ban_burst", 'host', active=burst, summary='Burst of SSH blocks',
                            detail='Fail2ban recorded at least ten new SSH blocks within five minutes.' if burst else '',
                            retired=retired)
        except (UpdatedError, OSError, ValueError, KeyError):
            if expected:
                _ALERTS.observe("ssh.protection_lost", 'host', active=True,
                                summary='SSH blocking could not be verified', detail='Could not read Fail2ban on the server')
            LOG.debug('Could not check SSH protection', exc_info=True)


def ssh_protection_worker(job_id, lock_fd, argv):
    log = ''
    try:
        update_job(job_id, status='running', started_at=utc_now())
        ACTIVE_MARKER.write_text(f'job_id={job_id}\n', encoding='utf-8')
        os.chmod(ACTIVE_MARKER, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        code, log = run_command(job_id, argv, timeout=900)
        payload = json.loads(log.strip().splitlines()[-1])
        if code or payload.get('ok') is not True or payload.get('request_id') != job_id:
            raise UpdatedError(payload.get('error') or 'Could not configure SSH protection; review the job log')
        update_job(job_id, status='completed', completed_at=utc_now(),
                   result={'message': payload['message']}, output={'log': log})
    except (ValueError, IndexError, AttributeError):
        finish_failed(job_id, UpdatedError('Could not configure SSH protection; review the job log'), log, alert=False)
    except Exception as error:
        finish_failed(job_id, error, log, alert=False)
    finally:
        try:
            if argv[2] == 'install':
                LATEST_PLAN_PATH.unlink(missing_ok=True)
            ACTIVE_MARKER.unlink(missing_ok=True)
        finally:
            release_operation(lock_fd)


def configure_ssh_protection(request):
    operation, trusted = request.get('operation'), request.get('trusted')
    if operation not in ('install', 'enable', 'disable') or not isinstance(trusted, list) or len(trusted) > 32:
        raise UpdatedError('Invalid SSH protection operation')
    addresses = []
    for value in trusted:
        if not isinstance(value, str) or not 1 <= len(value) <= 64 or '%' in value:
            raise UpdatedError('Enter a valid IPv4 or IPv6 address or subnet')
        try:
            addresses.append(str(ipaddress.ip_network(value, strict=False) if '/' in value else ipaddress.ip_address(value)))
        except ValueError:
            raise UpdatedError('Enter a valid IPv4 or IPv6 address or subnet') from None
    argv = ssh_protection_command(operation)
    if 'policy' in request:
        policy = request['policy']
        if (not isinstance(policy, dict) or policy.keys() != {'maxretry', 'findtime', 'bantime'}
                or any(type(value) is not int for value in policy.values())
                or not 2 <= policy['maxretry'] <= 50
                or not 60 <= policy['findtime'] <= 86400 or policy['findtime'] % 60
                or not 60 <= policy['bantime'] <= 604800 or policy['bantime'] % 60):
            raise UpdatedError('Invalid SSH blocking thresholds')
        argv.extend(['--policy', json.dumps(policy)])
    lock_fd = acquire_operation(allow_security_recovery=operation != 'install')
    try:
        job = new_job(SSH_PROTECTION_JOB)
        argv.extend(['--maintenance-lock', str(MAINTENANCE_LOCK_PATH), '--request-id', job['id'], '--trusted', *addresses])
        start_thread(ssh_protection_worker, job['id'], lock_fd, argv)
        return {'ok': True, 'job_id': job['id'], 'job': public_job(job, include_log=False)}
    except Exception:
        release_operation(lock_fd)
        raise


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
    boot_id = current_boot_id()
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "deployment": read_deployment(),
        "plan": plan,
        "jobs": jobs,
        "active_job": active_job(),
        "boot_id": boot_id,
        "reboot_required": REBOOT_REQUIRED_PATH.exists(),
        "reboot_scheduled": reboot_is_scheduled(),
        "reboot_scheduled_elsewhere": os.path.lexists(ASSISTANT_REBOOT_MARKER),
        "reboot_delay_seconds": REBOOT_DELAY_SECONDS,
        "settings": settings_payload(),
        "summary": summary_payload(plan),
        'haproxy_operation': haproxy_operation(),
        'haproxy_migration': migration_status(plan),
    }


def current_boot_id() -> str:
    try:
        value = BOOT_ID_PATH.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as exc:
        raise UpdatedError("the current boot id is unavailable", code="conflict") from exc
    if not BOOT_ID_RE.fullmatch(value):
        raise UpdatedError("the current boot id is invalid", code="conflict")
    return value


def request_identity(request: dict[str, Any]) -> tuple[str, str]:
    expected_boot_id = request.get("expected_boot_id")
    if not isinstance(expected_boot_id, str) or not BOOT_ID_RE.fullmatch(
        expected_boot_id
    ):
        raise UpdatedError("a valid expected boot id is required", code="validation")
    actor = request.get("actor")
    if not isinstance(actor, str) or not ACTOR_RE.fullmatch(actor):
        raise UpdatedError("a valid authenticated actor is required", code="validation")
    boot_id = current_boot_id()
    if expected_boot_id != boot_id:
        raise UpdatedError(
            "the server boot changed; reload the page and try again",
            code="stale_boot",
        )
    return boot_id, actor


def reboot_marker_state() -> dict[str, Any] | None:
    if not os.path.lexists(REBOOT_MARKER):
        return None
    try:
        state = safe_json_file(REBOOT_MARKER)
    except (UpdatedError, OSError, ValueError, json.JSONDecodeError) as exc:
        LOG.error("The web reboot marker is unsafe or unreadable: %s", exc)
        raise UpdatedError("the web reboot marker is unsafe", code="conflict") from exc
    unit = state.get("unit")
    marker_boot_id = state.get("boot_id")
    if (
        not isinstance(unit, str)
        or not REBOOT_UNIT_RE.fullmatch(unit)
        or not isinstance(marker_boot_id, str)
        or not BOOT_ID_RE.fullmatch(marker_boot_id)
    ):
        raise UpdatedError("the web reboot marker is invalid", code="conflict")
    if marker_boot_id != current_boot_id():
        REBOOT_MARKER.unlink(missing_ok=True)
        fsync_directory(REBOOT_MARKER.parent)
        return None
    return state


def reboot_is_scheduled() -> bool:
    return reboot_marker_state() is not None


def reboot_guard_present() -> bool:
    return os.path.lexists(REBOOT_MARKER) or os.path.lexists(
        ASSISTANT_REBOOT_MARKER
    )


def stop_reboot_unit(unit: str) -> None:
    if not REBOOT_UNIT_RE.fullmatch(unit):
        raise UpdatedError("the scheduled reboot unit is invalid", code="conflict")
    try:
        result = subprocess.run(
            [
                SYSTEMCTL_PATH,
                "stop",
                f"{unit}.timer",
                f"{unit}.service",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdatedError(f"failed to stop the reboot timer: {exc}") from exc
    remaining = []
    for suffix in ("timer", "service"):
        try:
            properties = systemctl_properties(
                f"{unit}.{suffix}", ["LoadState", "ActiveState"]
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpdatedError(
                f"failed to verify the reboot timer stopped: {exc}"
            ) from exc
        # A failed D-Bus query can otherwise look like an empty, inactive
        # result. Cancellation must be proven before its guard is removed.
        if not {"LoadState", "ActiveState"}.issubset(properties):
            raise UpdatedError("failed to verify the reboot timer stopped")
        if properties.get("ActiveState") in {
            "activating",
            "active",
            "reloading",
            "deactivating",
        }:
            remaining.append(f"{unit}.{suffix}")
    if remaining:
        raise UpdatedError(
            "failed to stop the reboot timer: "
            + (result.stderr or result.stdout or ", ".join(remaining)).strip()
        )


def request_reboot(request: dict[str, Any], *, automatic=None, held_lock=None) -> dict[str, Any]:
    if request.get("confirmation") != REBOOT_CONFIRMATION:
        raise UpdatedError("reboot requires an explicit confirmation")
    boot_id, actor = request_identity(request)
    existing = reboot_marker_state()
    if existing is not None:
        return {
            "ok": True,
            "message": "Reboot is already scheduled.",
            "reboot_scheduled": True,
            "reboot_delay_seconds": REBOOT_DELAY_SECONDS,
            "boot_id": boot_id,
        }
    lock_fd = acquire_operation() if held_lock is None else held_lock
    try:
        existing = reboot_marker_state()
        if existing is not None:
            return {
                "ok": True,
                "message": "Reboot is already scheduled.",
                "reboot_scheduled": True,
                "reboot_delay_seconds": REBOOT_DELAY_SECONDS,
                "boot_id": boot_id,
            }
        if automatic is not None and not REBOOT_REQUIRED_PATH.exists():
            unified = unified_policy() if automatic.get('unified') is True else None
            allowed = bool(unified and unified['enabled'] and unified['id'] == automatic.get('policy_revision'))
            if not (allowed or auto_reboot_record().get('allow_service_reboot')) or not service_reboot_reason():
                raise UpdatedError('the operating system does not currently require a reboot', code='not_required')
            automatic.update(reason='services', restart_policy_revision=service_restart_record()['id'])
        if BACKUPD_RESTORE_ACTIVE_MARKER.exists():
            raise UpdatedError(
                "a restore is in progress; the reboot was refused",
                code="operation_active",
            )
        if haproxy_transaction_active():
            raise UpdatedError(
                "an HAProxy configuration confirmation is active",
                code="config_pending",
            )
        unit = f"{REBOOT_UNIT_PREFIX}-{uuid.uuid4().hex[:12]}"
        # Publish the root-owned guard before asking PID 1 to create the timer.
        # The shared lock keeps update/backup workers out, while controld uses
        # this marker to reject new host configuration mutations.
        atomic_json(
            REBOOT_MARKER,
            {
                "version": 1,
                "unit": unit,
                "boot_id": boot_id,
                "actor": actor,
                "scheduled_at": utc_now(),
                "delay_seconds": REBOOT_DELAY_SECONDS,
                **({'automatic': automatic} if automatic else {}),
            },
        )
        result = subprocess.run(
            [
                SYSTEMD_RUN_PATH,
                f"--unit={unit}",
                "--description=easy-ha-proxy web controlled reboot",
                f"--on-active={REBOOT_DELAY_SECONDS}s",
                "--timer-property=AccuracySec=1s",
                *(['--timer-property=RemainAfterElapse=no', '--property=TimeoutStartSec=infinity',
                   '--', '/usr/bin/python3', str(auto_reboot_tool()), 'fire', '--state-root', str(OS_SECURITY_ROOT),
                   '--maintenance-lock', str(MAINTENANCE_LOCK_PATH), '--reboot-marker', str(REBOOT_MARKER),
                   '--required-marker', str(REBOOT_REQUIRED_PATH), '--unit', unit]
                  if automatic else [SYSTEMCTL_PATH, 'reboot']),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise UpdatedError(
                "failed to schedule the reboot: "
                + (result.stderr or result.stdout or "unknown error").strip()
            )
    except Exception as exc:
        cleanup_safe = True
        if "unit" in locals():
            try:
                stop_reboot_unit(unit)
            except UpdatedError as cleanup_exc:
                # Keep the marker (and therefore every maintenance guard) if
                # PID 1 may still own a live timer.  An administrator can then
                # retry cancellation without an untracked reboot racing work.
                cleanup_safe = False
                LOG.error(
                    "Could not prove the failed reboot timer was stopped: %s",
                    cleanup_exc,
                )
        if cleanup_safe and os.path.lexists(REBOOT_MARKER):
            REBOOT_MARKER.unlink(missing_ok=True)
            fsync_directory(REBOOT_MARKER.parent)
        if isinstance(exc, (OSError, subprocess.TimeoutExpired)):
            raise UpdatedError(f"failed to schedule the reboot: {exc}") from exc
        raise
    finally:
        # Hold the lock through timer creation and marker persistence so no
        # update or backup can enter the scheduling gap.
        if held_lock is None:
            release_operation(lock_fd)
    LOG.warning(
        "reboot scheduled from the web UI by %s (delay %ss)",
        actor,
        REBOOT_DELAY_SECONDS,
    )
    return {
        "ok": True,
        "message": "Reboot scheduled.",
        "reboot_scheduled": True,
        "reboot_delay_seconds": REBOOT_DELAY_SECONDS,
        "boot_id": boot_id,
    }


def cancel_reboot(request: dict[str, Any]) -> dict[str, Any]:
    boot_id, actor = request_identity(request)
    lock_fd = acquire_operation(allow_scheduled_reboot=True)
    try:
        state = reboot_marker_state()
        if state is None:
            raise UpdatedError("no web-scheduled reboot exists", code="not_found")
        cancel_automatic_reboot_intent(state)
        stop_reboot_unit(str(state["unit"]))
        REBOOT_MARKER.unlink()
        fsync_directory(REBOOT_MARKER.parent)
    finally:
        release_operation(lock_fd)
    LOG.info("reboot canceled from the web UI by %s", actor)
    return {
        "ok": True,
        "message": "Reboot canceled.",
        "reboot_scheduled": False,
        "boot_id": boot_id,
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
    if action == "set_settings":
        return set_settings(request)
    if action == "set_auto_install":
        return set_auto_install(request)
    if action == "summary":
        return summary_response()
    if action == "reboot":
        return request_reboot(request)
    if action == "cancel_reboot":
        return cancel_reboot(request)
    if action == 'set_auto_reboot':
        return set_auto_reboot(request)
    if action == 'set_service_restarts':
        return set_service_restarts(request)
    if action == 'prepare_haproxy_migration':
        return start_haproxy_migration(request)
    if action == 'apply_haproxy_migration':
        return start_haproxy_migration(request, apply=True)
    if action == 'start_haproxy_transition':
        return start_haproxy_transition(request)
    if action == 'os_security_status':
        return os_security_response(request)
    if action == 'ssh_protection_status':
        return ssh_protection_status(request)
    if action == 'ssh_protection_connection':
        if not ssh_monitoring_enabled():
            raise UpdatedError('Resume SSH monitoring before checking a connection')
        options = []
        for key in ('user', 'ip', 'hostname', 'local_address', 'port'):
            value = request.get(key, '')
            if not isinstance(value, str) or len(value) > 253:
                raise UpdatedError('Invalid OpenSSH connection parameters')
            if value:
                options.append('--' + key.replace('_', '-') + '=' + value)
        return ssh_protection_query('check-connection', *options)
    if action == 'ssh_protection_monitor':
        if type(request.get('enabled')) is not bool:
            raise UpdatedError('Invalid SSH monitoring setting')
        atomic_json(SSH_PROTECTION_MONITOR, {'enabled': request['enabled']})
        return {'ok': True}
    if action == 'ssh_protection_configure':
        return configure_ssh_protection(request)
    if action == 'ssh_protection_unban':
        ip = request.get('ip')
        if not isinstance(ip, str) or not 1 <= len(ip) <= 64 or '%' in ip:
            raise UpdatedError('Invalid IP address')
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise UpdatedError('Invalid IP address') from None
        lock_fd = acquire_operation(allow_security_recovery=True, allow_scheduled_reboot=True)
        try:
            return ssh_protection_query('unban', '--ip', ip)
        finally:
            release_operation(lock_fd)
    if action in {'os_security_check', 'os_security_install', 'os_security_configure', 'os_security_restart_check', 'os_security_restart'}:
        return start_os_security(request)
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
            APP_UID = _constants.APP_UID
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
    # Always running: it idles while the interval is 0, so the page can switch
    # checks on without a restart.
    threading.Thread(target=auto_check_loop, name="auto-check", daemon=True).start()
    if _ALERTS is not None:
        threading.Thread(target=ssh_protection_watch_loop, name="ssh-protection-watch", daemon=True).start()
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
                connection, _address = server.accept()
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
