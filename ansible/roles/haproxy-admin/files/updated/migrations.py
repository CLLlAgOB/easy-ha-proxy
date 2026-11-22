"""HAProxy package migration broker, OS security, and auto-reboot guards."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .constants import (
    ACTIVE_MARKER,
    IDENTIFIER_RE,
    JOB_TIMEOUT_SECONDS,
    LATEST_PLAN_PATH,
    LOG,
    MAINTENANCE_LOCK_PATH,
    PLAN_TTL_SECONDS,
    PYTHON_PATH,
    REBOOT_MARKER,
    SHUTDOWN_REQUESTED,
    STATE_ROOT,
    UpdatedError,
    _ALERTS,
    active_job,
    atomic_json,
    fsync_directory,
    identifier,
    new_job,
    public_job,
    safe_json_file,
    update_job,
    utc_now,
)
from .runner import (
    REBOOT_CONFIRMATION,
    REBOOT_REQUIRED_PATH,
    acquire_operation,
    finish_failed,
    haproxy_transaction_active,
    load_latest_plan,
    plan_component_map,
    plan_is_expired,
    release_operation,
    run_command,
    trusted_source,
)
from .maintenance import (
    HAPROXY_MIGRATION_CONFIRMATION,
    HAPROXY_MIGRATION_PLAN,
    HAPROXY_MIGRATION_STATE,
    HAPROXY_SETTLED_PHASES,
    HAPROXY_UPDATE_STATE,
    auto_install_settings,
    in_install_window,
    install_night,
    maintenance_module,
    read_haproxy_operation,
    start_thread,
    unified_policy,
)

# Bound across sibling submodules when the package finishes loading.
current_boot_id: Any = None
reboot_marker_state: Any = None
request_identity: Any = None
request_reboot: Any = None
restart_check_predates_boot: Any = None
start_os_security: Any = None
stop_reboot_unit: Any = None

def haproxy_operation():
    operations = [op for path in (HAPROXY_UPDATE_STATE, HAPROXY_MIGRATION_STATE)
                  if (op := read_haproxy_operation(path)) is not None]
    # Never hide a required recovery behind a newer completed operation.
    operations.sort(key=lambda op: (op.get('phase') not in HAPROXY_SETTLED_PHASES,
                                   op.get('updated_at') if isinstance(op.get('updated_at'), (float, int)) else 0), reverse=True)
    return operations[0] if operations else None


def haproxy_patch_active():
    for path in (HAPROXY_UPDATE_STATE, HAPROXY_MIGRATION_STATE):
        operation = read_haproxy_operation(path)
        if operation is None:
            if os.path.lexists(path):
                return True
        elif operation.get('phase') not in HAPROXY_SETTLED_PHASES:
            return True
    return False


def migration_tool_digest():
    tool = trusted_source('haproxy_package_migrate.py')
    if tool.stat().st_size > 1024 * 1024:
        raise UpdatedError('Update host services before preparing a HAProxy migration', code='dependency')
    source = tool.read_bytes()
    if b'WEB_MIGRATION_PROTOCOL = 1' not in source:
        raise UpdatedError('Update host services before preparing a HAProxy migration', code='dependency')
    return hashlib.sha256(source).hexdigest()


def migration_offer(plan):
    result = {'target_branch': '3.4', 'state': 'blocked', 'reason': ''}
    try:
        migration_tool_digest()
    except (OSError, UpdatedError):
        return {**result, 'reason': 'Update host services before preparing a HAProxy migration'}
    if not plan or plan_is_expired(plan):
        return {**result, 'state': 'check_required', 'reason': 'Check for updates before preparing a HAProxy migration'}
    entry = plan_component_map(plan).get('haproxy') or {}
    details = entry.get('details') or {}
    if details.get('branch') == '3.4' and details.get('binary_matches') is True:
        return {**result, 'state': 'current', 'reason': 'HAProxy 3.4 is already installed; use updates within its branch'}
    if details.get('qualified') is not True:
        return {**result, 'reason': 'Migration requires Ubuntu 24.04 on AMD64 or ARM64'}
    if (details.get('package') != 'haproxy' or not str(details.get('installed_version', '')).startswith('2.8.')
            or not str(details.get('running_version', '')).startswith('2.8.') or details.get('binary_matches') is not True):
        return {**result, 'reason': 'Migration requires a verified distribution HAProxy 2.8 installation'}
    return {**result, 'state': 'available', 'reason': 'Prepare and review the transition from HAProxy 2.8 to 3.4 LTS'}


def migration_fingerprint(operation):
    material = {key: operation.get(key) for key in
                ('id', 'kind', 'architecture', 'created_at', 'engine_digest', 'old_version',
                 'target_runtime_version', 'target_packages', 'extra_packages')}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def migration_review(*, require_fresh=False):
    if not os.path.lexists(HAPROXY_MIGRATION_PLAN):
        if require_fresh:
            raise UpdatedError('Prepare a new HAProxy migration plan first', code='stale_plan')
        return None
    plan = safe_json_file(HAPROXY_MIGRATION_PLAN)
    identifier(plan.get('id'), 'migration plan id')
    identifier(plan.get('transaction_id'), 'migration transaction id')
    operation = read_haproxy_operation(HAPROXY_MIGRATION_STATE)
    fresh = (not plan_is_expired(plan) and not plan.get('consumed_by') and operation
             and operation.get('kind') == 'migration' and operation.get('phase') == 'prepared'
             and operation.get('id') == plan['transaction_id']
             and migration_fingerprint(operation) == plan.get('fingerprint')
             and migration_tool_digest() == plan.get('source_digest'))
    if require_fresh and not fresh:
        raise UpdatedError('The HAProxy migration plan is stale; prepare it again', code='stale_plan')
    return {**plan, 'stale': not bool(fresh)}


def public_migration_operation(operation):
    if not operation:
        return None
    result = {key: operation.get(key) for key in ('id', 'phase', 'old_version', 'architecture', 'target_runtime_version',
                                                  'target_verified', 'rollback_verified', 'updated_at')}
    result['packages'] = [{'name': str(p.get('Package', ''))[:80], 'version': str(p.get('Version', ''))[:120]}
                          for p in (operation.get('target_packages') or [])[:8] if isinstance(p, dict)]
    result['dependencies'] = [{'name': str(p.get('Package', ''))[:80], 'version': str(p.get('Version', ''))[:120]}
                              for p in (operation.get('extra_packages') or [])[:8] if isinstance(p, dict)]
    return result


def migration_status(plan):
    offer = migration_offer(plan)
    recovery_blocked = haproxy_patch_active()
    if recovery_blocked:
        offer.update(state='blocked', reason='HAProxy update or recovery is in progress. Other maintenance is blocked.')
    operation = read_haproxy_operation(HAPROXY_MIGRATION_STATE)
    try:
        review = migration_review()
    except (UpdatedError, OSError, ValueError, TypeError):
        review = None
    public = None
    if review:
        public = {key: review.get(key) for key in ('id', 'transaction_id', 'expires_at', 'stale', 'consumed_by')}
        public['stale'] = public['stale'] or recovery_blocked
        public['operation'] = public_migration_operation(operation)
    return {**offer, 'plan': public, 'last_operation': public_migration_operation(operation),
            'automatic': automatic_migration_offer(plan, operation, recovery_blocked)}


def migration_platform_supported():
    try:
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        return (release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04'
                and os.uname().machine in {'aarch64', 'x86_64'})
    except OSError:
        return False


def automatic_migration_tool():
    migration_tool_digest()
    tool = trusted_source('haproxy_package_migrate.py')
    if b'AUTOMATIC_MIGRATION_PROTOCOL = 1' not in tool.read_bytes():
        raise UpdatedError('Update host services before using the automatic HAProxy transition', code='dependency')
    trusted_source('apt_metadata.py')
    return tool


def automatic_migration_offer(plan, operation, recovery_blocked):
    result = {'can_start': False, 'current': False, 'reason': ''}
    try:
        automatic_migration_tool()
    except (OSError, UpdatedError):
        return {**result, 'reason': 'Update host services before using the automatic HAProxy transition'}
    if recovery_blocked:
        return {**result, 'reason': 'HAProxy update or recovery is in progress. Other maintenance is blocked.'}
    if not migration_platform_supported():
        return {**result, 'reason': 'Migration requires Ubuntu 24.04 on AMD64 or ARM64'}
    # This cached display hint never authorizes execution. The native worker
    # verifies the current package, running binary and configuration itself.
    details = ((plan_component_map(plan).get('haproxy') or {}).get('details') or {}) if plan else {}
    if plan and not plan_is_expired(plan) and details.get('binary_matches') is True:
        current = details.get('branch') == '3.4'
    else:
        current = bool(operation and operation.get('phase') == 'committed' and operation.get('target_verified') is True)
    return {**result, 'can_start': not current, 'current': current,
            'reason': 'HAProxy 3.4 is already installed; use updates within its branch' if current else
            'Configuration checks, package preparation and the transition run automatically after confirmation.'}


def migration_worker(job_id, lock_fd, review=None, automatic=False):
    """A fixed root child owns maintenance custody through switch/recovery."""
    log = ''
    try:
        if haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before migration', code='config_pending')
        update_job(job_id, status='running', started_at=utc_now(), current_component='haproxy',
                   progress={'phase': 'checking' if automatic else 'prepare' if review is None else 'starting'})
        ACTIVE_MARKER.write_text(f'job_id={job_id}\n', encoding='utf-8')
        os.chmod(ACTIVE_MARKER, 0o600)
        python = PYTHON_PATH if PYTHON_PATH.is_file() else Path('/usr/bin/python3')
        command = [str(python), str(trusted_source('haproxy_package_migrate.py'))]
        previous = read_haproxy_operation(HAPROXY_MIGRATION_STATE)
        if automatic:
            automatic_migration_tool()
            HAPROXY_MIGRATION_PLAN.unlink(missing_ok=True)
            LATEST_PLAN_PATH.unlink(missing_ok=True)
            command.extend(['migrate', '--web-progress'])
        elif review is None:
            HAPROXY_MIGRATION_PLAN.unlink(missing_ok=True)
            command.extend(['prepare', '--web-progress'])
        else:
            # Revalidate after queueing, before handing control to the child.
            operation = read_haproxy_operation(HAPROXY_MIGRATION_STATE)
            if (not operation or operation.get('phase') != 'prepared'
                    or migration_fingerprint(operation) != review['fingerprint']
                    or migration_tool_digest() != review['source_digest'] or plan_is_expired(review)):
                raise UpdatedError('The HAProxy migration plan is stale; prepare it again', code='stale_plan')
            LATEST_PLAN_PATH.unlink(missing_ok=True)
            command.extend(['apply', '--id', review['transaction_id'], '--web-progress'])
        # As with patch updates, the PID-1-owned child takes the same lock.
        # A racing backup can only refuse preparation/apply before changes.
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        code, log = run_command(job_id, command, timeout=JOB_TIMEOUT_SECONDS)
        operation = read_haproxy_operation(HAPROXY_MIGRATION_STATE)
        if review is None and not automatic:
            if (code or not operation or operation.get('id') == (previous or {}).get('id')
                    or operation.get('phase') != 'prepared' or operation.get('kind') != 'migration'
                    or not str(operation.get('target_runtime_version', '')).startswith('3.4.')
                    or operation.get('engine_digest') != migration_tool_digest()):
                raise UpdatedError('HAProxy migration preparation failed; review the job log', code='verification_failed')
            review = {'id': uuid.uuid4().hex, 'transaction_id': identifier(operation['id'], 'migration transaction id'),
                      'expires_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=PLAN_TTL_SECONDS)).isoformat(),
                      'fingerprint': migration_fingerprint(operation), 'source_digest': migration_tool_digest()}
            atomic_json(HAPROXY_MIGRATION_PLAN, review)
            message = 'HAProxy migration prepared; review the target version before confirming'
        else:
            if operation:
                update_job(job_id, result={'haproxy': public_migration_operation(operation)})
            wrong_transaction = (operation and operation.get('id') == (previous or {}).get('id')) if automatic else (
                not operation or operation.get('id') != review['transaction_id'])
            if (code or not operation or wrong_transaction
                    or automatic and (operation.get('kind') != 'migration'
                                      or not str(operation.get('target_runtime_version', '')).startswith('3.4.')
                                      or operation.get('engine_digest') != migration_tool_digest())
                    or operation.get('phase') != 'committed' or operation.get('target_verified') is not True):
                raise UpdatedError('HAProxy migration failed; review its recovery status and job log', code='verification_failed')
            message = 'HAProxy migration verified'
        update_job(job_id, status='completed', completed_at=utc_now(),
                   result={'message': message, 'haproxy': public_migration_operation(operation)},
                   output={'log': log})
    except Exception as exc:
        finish_failed(job_id, exc, log)
    finally:
        ACTIVE_MARKER.unlink(missing_ok=True)
        release_operation(lock_fd)


def start_haproxy_migration(request, *, apply=False):
    if apply:
        if request.get('confirmation') != HAPROXY_MIGRATION_CONFIRMATION:
            raise UpdatedError('Type MIGRATE 3.4 to confirm the HAProxy transition')
        plan_id = identifier(request.get('plan_id'), 'migration plan id')
    elif request.get('target_branch') != '3.4':
        raise UpdatedError('Only the qualified HAProxy 3.4 LTS migration is supported')
    lock_fd = acquire_operation()
    try:
        if haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before migration', code='config_pending')
        review = None
        if apply:
            review = migration_review(require_fresh=True)
            if review['id'] != plan_id:
                raise UpdatedError('The HAProxy migration plan is stale; prepare it again', code='stale_plan')
        else:
            offer = migration_offer(load_latest_plan())
            if offer['state'] != 'available':
                raise UpdatedError(offer['reason'], code='dependency')
        job = new_job('haproxy-migrate' if apply else 'haproxy-prepare', components=['haproxy'],
                      plan_id=review['id'] if review else None)
        if review:
            atomic_json(HAPROXY_MIGRATION_PLAN, {**review, 'consumed_by': job['id']})
        start_thread(migration_worker, job['id'], lock_fd, review)
        return {'ok': True, 'job_id': job['id'], 'job': public_job(job)}
    except Exception:
        release_operation(lock_fd)
        raise


def start_haproxy_transition(request):
    if request.get('target_branch') != '3.4' or request.get('confirmed') is not True:
        raise UpdatedError('Confirm the transition to HAProxy 3.4 LTS')
    automatic_migration_tool()
    if not migration_platform_supported():
        raise UpdatedError('Migration requires Ubuntu 24.04 on AMD64 or ARM64', code='dependency')
    lock_fd = acquire_operation()
    try:
        if haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before migration', code='config_pending')
        job = new_job('haproxy-transition', components=['haproxy'])
        start_thread(migration_worker, job['id'], lock_fd, None, True)
        return {'ok': True, 'job_id': job['id'], 'job': public_job(job)}
    except Exception:
        release_operation(lock_fd)
        raise


OS_SECURITY_ROOT = STATE_ROOT / 'os-security'
OS_SECURITY_MODES = frozenset({'system', 'notify', 'auto', 'window', 'daily'})
OS_SECURITY_INTERVALS = (1, 2, 4, 6, 12, 24)
OS_SECURITY_DEFAULT = {'mode': 'system', 'interval': 4, 'start': 3, 'end': 5}
OS_SECURITY_INSPECTION_CACHE = {}
OS_SECURITY_INSPECTION_LOCK = threading.Lock()


def security_recovery_pending():
    path = OS_SECURITY_ROOT / 'policy.json'
    if not os.path.lexists(path):
        return False
    try:
        record = safe_json_file(path)
        os_security_policy(record.get('policy') or {})
        return record.get('phase') != 'ready'
    except (OSError, ValueError, UpdatedError):
        return True


def os_security_policy(request):
    value = {key: request.get(key) for key in ('mode', 'interval', 'start', 'end')}
    if (not isinstance(value['mode'], str) or value['mode'] not in OS_SECURITY_MODES or type(value['interval']) is not int or value['interval'] not in OS_SECURITY_INTERVALS
            or any(type(value[key]) is not int or not 0 <= value[key] <= 23 for key in ('start', 'end'))
            or value['start'] == value['end']):
        raise UpdatedError('Invalid OS security policy')
    return value


def os_security_tool():
    tool = trusted_source('os_security.py')
    if tool.stat().st_size > 1024 * 1024 or b'PROTOCOL = 1' not in tool.read_bytes():
        raise UpdatedError('Update host services before using OS security management', code='dependency')
    return tool


AUTO_REBOOT_TIME = re.compile(r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')


def auto_reboot_tool():
    tool = trusted_source('auto_reboot.py')
    if tool.stat().st_size > 1024 * 1024 or b'AUTO_REBOOT_PROTOCOL = 1' not in tool.read_bytes():
        raise UpdatedError('Update host services before configuring automatic reboots', code='dependency')
    return tool


def auto_reboot_record():
    path = OS_SECURITY_ROOT / 'reboot-policy.json'
    if not os.path.lexists(path):
        return {'enabled': False, 'time': '03:00', 'id': None, 'updated_at': 0}
    value = safe_json_file(path)
    if (type(value.get('enabled')) is not bool or not isinstance(value.get('time'), str)
            or not AUTO_REBOOT_TIME.fullmatch(value['time']) or not IDENTIFIER_RE.fullmatch(str(value.get('id', '')))
            or type(value.get('updated_at')) not in (int, float) or not isinstance(value.get('attempt', {}), dict)
            or type(value.get('allow_service_reboot', False)) is not bool):
        raise UpdatedError('The automatic reboot policy is invalid', code='conflict')
    return value


def auto_reboot_window(local, text):
    hour, minute = map(int, text.split(':'))
    anchor = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
    if local.timestamp() < anchor.timestamp():
        anchor -= dt.timedelta(days=1)
    anchor = dt.datetime.fromtimestamp(anchor.timestamp(), local.tzinfo)
    return anchor, anchor.strftime('%Y-%m-%d') + ' ' + text


def service_restart_tool():
    tool = trusted_source('service_restarts.py')
    if tool.stat().st_size > 1024 * 1024 or b'SERVICE_RESTART_PROTOCOL = 1' not in tool.read_bytes():
        raise UpdatedError('Update host services before managing service restarts', code='dependency')
    return tool


def service_restart_record():
    unified = unified_policy()
    if unified:
        return maintenance_module().restart_policy(unified)
    path = OS_SECURITY_ROOT / 'restart-policy.json'
    if not os.path.lexists(path):
        return {'enabled': False, 'time': '02:15', 'id': None, 'updated_at': 0}
    value = safe_json_file(path)
    if (type(value.get('enabled')) is not bool or not isinstance(value.get('time'), str)
            or not AUTO_REBOOT_TIME.fullmatch(value['time']) or not IDENTIFIER_RE.fullmatch(str(value.get('id', '')))
            or type(value.get('updated_at')) not in (int, float)):
        raise UpdatedError('The service restart policy is invalid', code='conflict')
    return value


def os_security_last_install():
    """When managed packages were last installed (or an installation began).

    Mirrors service_restarts.last_install: a restart pass that finished before
    then has not seen what the installation replaced.
    """
    path = OS_SECURITY_ROOT / 'status.json'
    try:
        status = safe_json_file(path) if os.path.lexists(path) else {}
    except (OSError, ValueError, TypeError, UpdatedError):
        status = {}
    values = [status.get(key) for key in ('last_install_at', 'last_install_attempt')]
    # The ordinary APT path is separate from unattended-upgrades, but its
    # installations invalidate the same service-restart evidence.
    package_path = OS_SECURITY_ROOT / 'package-install.json'
    if os.path.lexists(package_path):
        attempted = safe_json_file(package_path).get('last_install_attempt')
        if type(attempted) not in (int, float) or not 0 < attempted < float('inf'):
            raise UpdatedError('The OS package installation record is invalid', code='conflict')
        values.append(attempted)
    return max([value for value in values if type(value) in (int, float)] or [0])


def service_restart_due(value, status, local, installed_at=None):
    anchor, key = auto_reboot_window(local, value['time'])
    installed_at = os_security_last_install() if installed_at is None else installed_at
    same = status.get('policy_id') == value['id'] and status.get('boot_id') == current_boot_id()
    retry = 900 if status.get('state') == 'running' else 300
    # Done for tonight only once a pass has seen the latest installation: one
    # that installs inside the window gets its own pass, in the same window.
    done = (status.get('policy_id') == value['id'] and status.get('window') == key and status.get('state') == 'ready'
            and bool(status.get('applied')) and status.get('completed_at', 0) >= installed_at)
    return (value['enabled'] and 0 <= local.timestamp() - anchor.timestamp() < 3600
            and value['updated_at'] <= anchor.timestamp()
            and not done
            and (not same or local.timestamp() - status.get('last_attempt', 0) >= retry)), key


def service_restart_snapshot():
    result = {'available': False, 'enabled': False, 'time': '02:15', 'status': None}
    try:
        service_restart_tool()
        result['available'] = True
        value = service_restart_record()
        result.update({key: value.get(key) for key in ('enabled', 'time', 'updated_at')})
        path = OS_SECURITY_ROOT / 'restart-status.json'
        status = safe_json_file(path) if os.path.lexists(path) else {}
        result['status'] = status or None
        if value['enabled']:
            local = os_security_local_time()
            due, _ = service_restart_due(value, status, local)
            if due:
                upcoming = local
            else:
                retry = 900 if status.get('state') == 'running' else 300
                upcoming = dt.datetime.fromtimestamp(max(local.timestamp(), status.get('last_attempt', 0) + retry), local.tzinfo)
                if not service_restart_due(value, status, upcoming)[0]:
                    hour, minute = map(int, value['time'].split(':'))
                    upcoming = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
                    if upcoming.timestamp() <= local.timestamp():
                        upcoming += dt.timedelta(days=1)
            result['next_window'] = dt.datetime.fromtimestamp(upcoming.timestamp(), local.tzinfo).isoformat()
    except (OSError, ValueError, TypeError, KeyError, UpdatedError) as error:
        result['error'] = str(error)
    return result


def set_service_restarts(request):
    boot_id, actor = request_identity(request)
    if (type(request.get('enabled')) is not bool or not isinstance(request.get('time'), str)
            or not AUTO_REBOOT_TIME.fullmatch(request['time']) or request.get('confirmation') != 'SECURITY'):
        raise UpdatedError('Confirm a valid service restart policy')
    service_restart_tool()
    lock_fd = acquire_operation(allow_scheduled_reboot=True, allow_security_recovery=not request['enabled'])
    try:
        if request['enabled'] and os_security_snapshot()['policy']['mode'] == 'system':
            raise UpdatedError('Enable managed OS security updates before scheduling service restarts', code='dependency')
        if request['enabled'] and haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before OS maintenance', code='config_pending')
        marker = reboot_marker_state()
        if marker and (marker.get('automatic') or {}).get('reason') == 'services':
            cancel_automatic_reboot_intent(marker)
            stop_reboot_unit(marker['unit'])
            REBOOT_MARKER.unlink()
            fsync_directory(REBOOT_MARKER.parent)
        value = {'enabled': request['enabled'], 'time': request['time'], 'id': uuid.uuid4().hex,
                 'actor': actor, 'updated_at': time.time()}
        OS_SECURITY_ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
        atomic_json(OS_SECURITY_ROOT / 'restart-policy.json', value)
    finally:
        release_operation(lock_fd)
    LOG.warning('Service restart policy changed by %s: enabled=%s time=%s', actor, value['enabled'], value['time'])
    return {'ok': True, 'service_restarts': service_restart_snapshot(), 'boot_id': boot_id}


def service_restart_tick(now=None):
    if SHUTDOWN_REQUESTED.is_set():
        return 'disabled'
    snapshot = service_restart_snapshot()
    managed = os_security_snapshot()
    if (not snapshot['available'] or snapshot.get('error') or not snapshot['enabled']
            or managed.get('recovery_required') or managed['policy']['mode'] == 'system'):
        return 'disabled'
    value = service_restart_record()
    if not service_restart_due(value, snapshot.get('status') or {}, now or os_security_local_time())[0]:
        return 'waiting'
    try:
        start_os_security({'action': 'os_security_restart_cycle'}, scheduled=True)
    except UpdatedError as error:
        return error.code
    return 'started'


def service_reboot_reason():
    tool = service_restart_tool()
    try:
        child = subprocess.run(['/usr/bin/python3', str(tool), 'reboot-reason', '--state-root', str(OS_SECURITY_ROOT)],
                               capture_output=True, text=True, timeout=90)
        value = json.loads(child.stdout)
        if child.returncode or not isinstance(value, dict) or value.get('ok') is not True or not isinstance(value.get('services'), list):
            raise ValueError('unverified restart state')
        return value['services']
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise UpdatedError('The remaining service restarts could not be verified', code='verification_failed') from error


def auto_reboot_due(record, local):
    anchor, key = auto_reboot_window(local, record['time'])
    attempt = record.get('attempt') or {}
    return (record['enabled'] is True and 0 <= local.timestamp() - anchor.timestamp() < 3600
            and record['updated_at'] <= anchor.timestamp()
            and not (attempt.get('window') == key and attempt.get('state') in {'scheduled', 'triggered', 'canceled'})
            and local.timestamp() - attempt.get('at', 0) >= 300), key


def auto_reboot_snapshot():
    result = {'available': False, 'required': REBOOT_REQUIRED_PATH.exists(), 'pending': None}
    try:
        auto_reboot_tool()
        result['available'] = True
        record = auto_reboot_record()
        result.update({key: record.get(key) for key in ('enabled', 'time', 'updated_at', 'attempt')})
        result['allow_service_reboot'] = record.get('allow_service_reboot', False)
        marker = reboot_marker_state()
        if marker:
            result['pending'] = {key: marker.get(key) for key in ('scheduled_at', 'delay_seconds', 'automatic')}
            result['pending']['due_at'] = (dt.datetime.fromisoformat(marker['scheduled_at']) + dt.timedelta(seconds=marker['delay_seconds'])).isoformat()
        if record['enabled']:
            local = os_security_local_time()
            retry = dt.datetime.fromtimestamp(max(local.timestamp(), (record.get('attempt') or {}).get('at', 0) + 300), local.tzinfo)
            due, _ = auto_reboot_due(record, retry)
            if due:
                result['next_window'] = retry.isoformat()
            else:
                hour, minute = map(int, record['time'].split(':'))
                upcoming = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
                if upcoming.timestamp() <= local.timestamp():
                    upcoming += dt.timedelta(days=1)
                result['next_window'] = dt.datetime.fromtimestamp(upcoming.timestamp(), local.tzinfo).isoformat()
    except (OSError, ValueError, TypeError, KeyError, UpdatedError) as error:
        result['error'] = str(error)
    return result


def cancel_automatic_reboot_intent(marker):
    if not marker or not marker.get('automatic'):
        return
    record = auto_reboot_record()
    if record.get('id') == marker['automatic'].get('policy_revision'):
        record['attempt'] = {'window': marker['automatic'].get('window'), 'state': 'canceled', 'at': time.time()}
        atomic_json(OS_SECURITY_ROOT / 'reboot-policy.json', record)


def set_auto_reboot(request):
    boot_id, actor = request_identity(request)
    if (type(request.get('enabled')) is not bool or not isinstance(request.get('time'), str)
            or not AUTO_REBOOT_TIME.fullmatch(request['time']) or request.get('confirmation') != 'REBOOT'
            or type(request.get('allow_service_reboot', False)) is not bool):
        raise UpdatedError('Confirm a valid automatic reboot policy')
    auto_reboot_tool()
    if request.get('allow_service_reboot'):
        service_restart_tool()
        if b'SERVICE_REBOOT_PROTOCOL = 1' not in auto_reboot_tool().read_bytes():
            raise UpdatedError('Update host services before allowing service reboot fallback', code='dependency')
    lock_fd = acquire_operation(allow_scheduled_reboot=True, allow_security_recovery=not request['enabled'])
    try:
        if request['enabled'] and os_security_snapshot()['policy']['mode'] == 'system':
            raise UpdatedError('Enable managed OS security updates before enabling scheduled reboots', code='dependency')
        if request['enabled'] and haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before OS maintenance', code='config_pending')
        marker = reboot_marker_state()
        if marker and marker.get('automatic'):
            cancel_automatic_reboot_intent(marker)
            stop_reboot_unit(marker['unit'])
            REBOOT_MARKER.unlink()
            fsync_directory(REBOOT_MARKER.parent)
        value = {'enabled': request['enabled'], 'time': request['time'], 'allow_service_reboot': request.get('allow_service_reboot', False), 'id': uuid.uuid4().hex,
                 'actor': actor, 'updated_at': time.time()}
        OS_SECURITY_ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
        atomic_json(OS_SECURITY_ROOT / 'reboot-policy.json', value)
    finally:
        release_operation(lock_fd)
    LOG.warning('Automatic reboot policy changed by %s: enabled=%s time=%s', actor, value['enabled'], value['time'])
    return {'ok': True, 'automatic_reboot': auto_reboot_snapshot(), 'boot_id': boot_id}


def auto_reboot_tick(now=None):
    if SHUTDOWN_REQUESTED.is_set():
        return 'disabled'
    record = auto_reboot_record()
    if not record['enabled'] or not (REBOOT_REQUIRED_PATH.exists() or record.get('allow_service_reboot', False)):
        return 'disabled'
    local = now or os_security_local_time()
    due, key = auto_reboot_due(record, local)
    if not due:
        return 'waiting'
    try:
        auto_reboot_tool()
        lock_fd = acquire_operation()
    except UpdatedError as error:
        return error.code
    try:
        # Re-read consent under the same custody as timer creation.
        record = auto_reboot_record()
        due, key = auto_reboot_due(record, local)
        if not due or os_security_snapshot()['policy']['mode'] == 'system':
            return 'disabled'
        record['attempt'] = {'window': key, 'state': 'scheduled', 'at': local.timestamp()}
        atomic_json(OS_SECURITY_ROOT / 'reboot-policy.json', record)
        try:
            request_reboot({'confirmation': REBOOT_CONFIRMATION, 'expected_boot_id': current_boot_id(), 'actor': 'os-security-auto'},
                           automatic={'policy_revision': record['id'], 'window': key}, held_lock=lock_fd)
        except Exception as error:
            # With "also reboot for deferred services" on, the window opens
            # every night whether or not anything asks for a reboot. "Nothing
            # does" is then the usual answer of a healthy gateway: it used to
            # be recorded as a deferral with an error and logged with a
            # traceback, twelve times a night.
            not_required = isinstance(error, UpdatedError) and error.code == 'not_required'
            if not os.path.lexists(REBOOT_MARKER):
                if not_required:
                    record['attempt'] = {'window': key, 'state': 'not_required', 'at': local.timestamp()}
                else:
                    record['attempt'].update(state='deferred', error=str(error)[:500])
                atomic_json(OS_SECURITY_ROOT / 'reboot-policy.json', record)
            if not_required:
                return 'not_required'
            if isinstance(error, UpdatedError):
                # A refusal the broker gave itself (a restore in progress, an
                # unanswered HAProxy confirmation): recorded above, said once
                # per attempt in one line, tried again in five minutes.
                LOG.warning('Scheduled automatic reboot deferred: %s', error)
                return error.code
            raise
        return 'scheduled'
    finally:
        release_operation(lock_fd)


def os_security_snapshot():
    result = {'policy': dict(OS_SECURITY_DEFAULT), 'status': None, 'recovery_required': False, 'available': False}
    try:
        tool = os_security_tool()
        result['available'] = True
        result['daily_supported'] = b'SETTINGS_PROTOCOL = 1' in tool.read_bytes()
        path = OS_SECURITY_ROOT / 'policy.json'
        if os.path.lexists(path):
            record = safe_json_file(path)
            result['policy'] = os_security_policy(record.get('policy') or {})
            result['policy_phase'] = record.get('phase')
            result['policy_updated_at'] = record.get('updated_at')
            result['recovery_required'] = record.get('phase') != 'ready'
        path = OS_SECURITY_ROOT / 'status.json'
        if os.path.lexists(path):
            status = safe_json_file(path)
            result['status'] = {key: status.get(key) for key in (
                'state', 'error', 'last_attempt', 'checked_at', 'last_success', 'platform', 'packages',
                'package_count', 'eligible_count', 'restart', 'native_timer', 'native_policy', 'installed_count', 'last_install_at', 'last_install_attempt')}
            result['status']['unapplied_count'] = len(status.get('unapplied_packages') or {})
        path = OS_SECURITY_ROOT / 'restart-status.json'
        if os.path.lexists(path):
            service = safe_json_file(path)
            current = result['status'] or {'state': 'unverified'}
            same_boot = service.get('boot_id') == current_boot_id()
            candidates = [item for item in (current.get('restart'), service.get('restart') if same_boot else None,
                          service.get('check') if service.get('check_boot_id') == current_boot_id() else None) if isinstance(item, dict)]
            if same_boot and service.get('state') == 'unknown':
                current['restart'] = {'error': service.get('error') or 'Service restarts could not be verified', 'checked_at': service.get('last_attempt', 0)}
                result['status'] = current
            elif candidates:
                current['restart'] = max(candidates, key=lambda item: item.get('checked_at', 0))
                result['status'] = current
    except (UpdatedError, OSError, ValueError, TypeError) as error:
        result['error'] = str(error)
        result['recovery_required'] = security_recovery_pending()
    return result


def os_security_live_settings():
    """Short, cached read-only probe; never loads the package cache on GET."""
    if not OS_SECURITY_INSPECTION_LOCK.acquire(blocking=False):
        return dict(OS_SECURITY_INSPECTION_CACHE.get('value') or {'error': 'Reading current Linux settings…'})
    try:
        if time.monotonic() - OS_SECURITY_INSPECTION_CACHE.get('at', -60) < 30:
            return dict(OS_SECURITY_INSPECTION_CACHE['value'])
        try:
            tool = os_security_tool()
            if b'SETTINGS_PROTOCOL = 1' not in tool.read_bytes():
                raise UpdatedError('Update host services to read current Linux settings')
            probe = subprocess.run(['/usr/bin/python3', str(tool), 'inspect'], stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, timeout=8)
            value = json.loads(probe.stdout)
            if probe.returncode or not isinstance(value, dict) or value.get('ok') is not True:
                raise UpdatedError(value.get('error', 'Current Linux settings could not be read') if isinstance(value, dict) else 'Current Linux settings could not be read')
        except (OSError, ValueError, UpdatedError, subprocess.TimeoutExpired) as error:
            value = {'error': str(error)}
        OS_SECURITY_INSPECTION_CACHE.update(at=time.monotonic(), value=value)
        return dict(value)
    finally:
        OS_SECURITY_INSPECTION_LOCK.release()


def os_security_local_time():
    from zoneinfo import ZoneInfo
    try:
        with open('/etc/localtime', 'rb') as handle:
            return dt.datetime.now(ZoneInfo.from_file(handle))
    except (OSError, ValueError):
        return dt.datetime.now().astimezone()


def os_security_install_due(policy, status, local):
    last = status.get('last_install_at') or 0
    previous = dt.datetime.fromtimestamp(last, local.tzinfo) if last else None
    if policy['mode'] == 'daily':
        return local.hour == policy['start'] and (previous is None or previous.date() != local.date())
    return (policy['mode'] == 'window' and in_install_window(local, policy['start'], policy['end'])
            and (previous is None or install_night(previous, policy['start'], policy['end']) != install_night(local, policy['start'], policy['end'])))


def os_security_schedule(snapshot, now=None):
    policy, status = snapshot['policy'], snapshot.get('status') or {}
    if snapshot.get('recovery_required') or snapshot.get('configuring') or policy['mode'] == 'system':
        return {}
    local = now or os_security_local_time()
    stamp = local.timestamp()
    result = {'next_check': max(stamp, (status.get('last_success') or 0) + policy['interval'] * 3600,
                                (status.get('last_attempt') or 0) + 1800)}
    if policy['mode'] == 'auto':
        result['next_install'] = dt.datetime.fromtimestamp(result['next_check'], local.tzinfo).isoformat()
    if policy['mode'] in {'daily', 'window'}:
        if os_security_install_due(policy, status, local):
            next_time = dt.datetime.fromtimestamp(max(stamp, (status.get('last_install_attempt') or 0) + 1800), local.tzinfo)
            # A retry must still fit the allowed hour/window.
            end = (policy['start'] + 1) % 24 if policy['mode'] == 'daily' else policy['end']
            if not in_install_window(next_time, policy['start'], end):
                next_time = (local + dt.timedelta(days=1)).replace(hour=policy['start'], minute=0, second=0, microsecond=0)
        else:
            next_time = local.replace(hour=policy['start'], minute=0, second=0, microsecond=0)
            if next_time <= local:
                next_time += dt.timedelta(days=1)
        result['next_install'] = next_time.isoformat()
    return result


def os_security_notifications(snapshot):
    if _ALERTS is None:
        return
    status = snapshot.get('status') or {}
    if snapshot.get('error'):
        return
    if status.get('state') not in {'ready', 'unknown'}:
        return
    try:
        _ALERTS.observe("os.security_check_failed", 'host', active=status.get('state') == 'unknown',
                        summary='OS security updates could not be checked', detail=str(status.get('error') or ''))
        if status.get('state') != 'ready':
            return  # Unknown never resolves an existing security incident.
        count = status.get('package_count')
        if type(count) is int:
            mode = (snapshot.get('policy') or OS_SECURITY_DEFAULT)['mode']
            settings = auto_install_settings() if mode != 'system' else {}
            automatic = (settings['enabled'] if settings.get('unified')
                         else mode in {'auto', 'daily', 'window'})
            if count == 0:
                _ALERTS.observe("os.security_updates", 'host', active=False,
                                summary='No OS security updates are pending')
            elif not automatic:
                _ALERTS.observe("os.security_updates", 'host', active=True,
                                summary='OS security updates are available',
                                detail=f'{count} package(s) require a security update.')
            elif unapplied := status.get('unapplied_count'):
                _ALERTS.observe("os.security_updates", 'host', active=True,
                                summary='OS security updates remain after an installation attempt',
                                detail=f'{unapplied} package(s) still require a security update after an installation attempt.')
            else:
                # Fixes are pending but the next automatic installation owns
                # them: an incident left from the notify-only mode, or about
                # a version that has since been superseded, closes quietly.
                # "Resolved" would claim that nothing is pending.
                _ALERTS.observe("os.security_updates", 'host', active=False, retired=True,
                                summary='Security updates are left to the automatic installation')
        restart = status.get('restart') or {}
        if not restart.get('error'):
            pending = bool(restart.get('reboot_required') or restart.get('services'))
            if restart_check_predates_boot(restart):
                pending = False  # the reboot since restarted everything
            _ALERTS.observe("os.security_restart", 'host', active=pending,
                            summary=('Security updates require a server reboot' if restart.get('reboot_required')
                                     else 'Some services require a restart after security updates'),
                            detail=', '.join(restart.get('services') or []))
    except Exception:
        LOG.debug('OS security alert reporting failed', exc_info=True)


# Managed OS security switches Linux's own upgrade timer off and installs
# through this broker instead. The alerts above are sent at the end of a job,
# so whatever keeps a job from starting -- a policy change left half done, a
# state that cannot be read, a confirmation of the HAProxy configuration nobody
# answered -- used to end in silence: no fixes installed and nothing said.
# This is looked at on every pass of the schedule, job or no job.
OS_SECURITY_STALLED_RULE = "os.security_stalled"
OS_SECURITY_STALLED_FLOOR_SECONDS = 24 * 3600
OS_SECURITY_STALLED_INTERVALS = 3
OS_SECURITY_WATCH_REPEAT_SECONDS = 600
OS_SECURITY_WATCH = {'at': 0.0, 'reason': None}


def os_security_stalled(now, last_answer=''):
    """Why managed OS security is not doing its work, or '' when it is.

    Read from the policy record itself rather than from the snapshot: a
    snapshot that failed falls back to "Linux manages it", which is the one
    answer that must not be assumed here.
    """
    path = OS_SECURITY_ROOT / 'policy.json'
    if not os.path.lexists(path):
        return ''  # never taken over: Linux's own timer is in charge
    try:
        record = safe_json_file(path)
        policy = os_security_policy(record.get('policy') or {})
    except (OSError, ValueError, UpdatedError) as error:
        return ('The OS security policy cannot be read, so it is not known whether updates are installed. '
                + str(error)[:300])
    if record.get('phase') != 'ready':
        active = active_job()
        if active and active.get('operation') == 'security-configure' and active.get('status') in {'queued', 'running'}:
            return ''
        return ("An interrupted policy change left OS security needing recovery. "
                "Linux's own automatic updates may be switched off, and the panel installs nothing until it is resolved.")
    if policy['mode'] == 'system':
        return ''
    snapshot = os_security_snapshot()
    if snapshot.get('error'):
        return 'Managed OS security cannot run. ' + str(snapshot['error'])[:300]
    status = snapshot.get('status') or {}
    limit = max(OS_SECURITY_STALLED_FLOOR_SECONDS, OS_SECURITY_STALLED_INTERVALS * policy['interval'] * 3600)
    last = max(float(status.get('last_success') or 0), float(record.get('updated_at') or 0))
    if now - last <= limit:
        return ''
    detail = f'No OS security check has succeeded for {int((now - last) // 3600)} hours.'
    if status.get('state') == 'unknown' and status.get('error'):
        detail += ' Last error: ' + str(status['error'])[:300]
    elif last_answer and last_answer not in {'started', 'waiting'}:
        detail += ' The schedule could not start a check: ' + str(last_answer)[:80] + '.'
    return detail


def os_security_watch(now=None, last_answer=''):
    """Tell the alert engine whether managed OS security is stalled."""
    if _ALERTS is None:
        return ''
    now = time.time() if now is None else now
    reason = os_security_stalled(now, last_answer)
    # A level is refreshed, not repeated: again when it changes, and often
    # enough that the alert engine does not take silence for recovery.
    if reason == OS_SECURITY_WATCH['reason'] and now - OS_SECURITY_WATCH['at'] < OS_SECURITY_WATCH_REPEAT_SECONDS:
        return reason
    OS_SECURITY_WATCH.update(at=now, reason=reason)
    try:
        _ALERTS.observe(OS_SECURITY_STALLED_RULE, 'host', active=bool(reason),
                        summary='OS security updates are not running', detail=reason)
    except Exception:  # pylint: disable=broad-except
        LOG.debug('OS security alert reporting failed', exc_info=True)
    return reason


def os_security_worker(job_id, lock_fd, action, policy=None, *, maintenance_revision=None):
    log = ''
    try:
        if haproxy_transaction_active():
            raise UpdatedError('Resolve pending HAProxy configuration changes before OS maintenance', code='config_pending')
        tool = service_restart_tool() if action in {'restart-check', 'restart', 'restart-cycle'} else os_security_tool()
        update_job(job_id, status='running', started_at=utc_now(), current_component='os', progress={'phase': 'checking'})
        ACTIVE_MARKER.write_text(f'job_id={job_id}\n', encoding='utf-8')
        os.chmod(ACTIVE_MARKER, 0o600)
        command = ['/usr/bin/python3', str(tool), action, '--state-root', str(OS_SECURITY_ROOT),
                   '--maintenance-lock', str(MAINTENANCE_LOCK_PATH), '--request-id', job_id]
        if maintenance_revision is not None:
            command.extend(['--maintenance-revision', maintenance_revision])
        if policy:
            for key in ('mode', 'interval', 'start', 'end'):
                command.extend(['--' + key, str(policy[key])])
        # The PID-1-owned worker holds custody even if this broker dies.
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        code, log = run_command(job_id, command, timeout=JOB_TIMEOUT_SECONDS)
        try:
            result = json.loads(log.strip().splitlines()[-1])
        except (ValueError, IndexError):
            result = {}
        if not isinstance(result, dict):
            result = {}
        if code or result.get('ok') is not True or result.get('request_id') != job_id:
            raise UpdatedError(str(result.get('error') or 'OS security operation failed; review the job log'), code='verification_failed')
        if action == 'restart' or (action == 'restart-cycle' and result.get('applied')):
            if (result.get('applied') is not True or result.get('verified') is not True
                    or result.get('unresolved') or result.get('failed_services')):
                raise UpdatedError('Service restarts remain unverified; review remaining services in OS security',
                                   code='verification_failed')
        if action in {'install', 'cycle', 'configure'}:
            LATEST_PLAN_PATH.unlink(missing_ok=True)
        update_job(job_id, status='completed', completed_at=utc_now(), result={'message': str(result.get('message') or '')}, output={'log': log})
    except Exception as error:
        finish_failed(job_id, error, log)
    finally:
        with OS_SECURITY_INSPECTION_LOCK:
            OS_SECURITY_INSPECTION_CACHE.clear()
        os_security_notifications(os_security_snapshot())
        ACTIVE_MARKER.unlink(missing_ok=True)
        release_operation(lock_fd)
