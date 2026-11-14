"""Final root-owned check for an explicitly enabled scheduled OS reboot."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import os
from pathlib import Path
import re
import stat
import time

from os_security import SecurityError, assert_managed, atomic, command, local_time, maintenance_guard, read_json

AUTO_REBOOT_PROTOCOL = 1
SERVICE_REBOOT_PROTOCOL = 1
TIME = re.compile(r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')
UNIT = re.compile(r'^easy-ha-proxy-web-reboot-[0-9a-f]{12}$')
BOOT = Path('/proc/sys/kernel/random/boot_id')
APT_LOCKS = tuple(Path(name) for name in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock',
    '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock'))


def read_policy(path):
    value = read_json(path)
    if (type(value.get('enabled')) is not bool or not isinstance(value.get('time'), str) or not TIME.fullmatch(value['time'])
            or not re.fullmatch(r'[0-9a-f]{32}', str(value.get('id', '')))
            or type(value.get('updated_at')) not in (int, float) or not isinstance(value.get('attempt', {}), dict)
            or type(value.get('allow_service_reboot', False)) is not bool):
        raise SecurityError('The automatic reboot policy is invalid')
    return value


def window(local, text):
    if not isinstance(text, str) or not TIME.fullmatch(text):
        raise SecurityError('Invalid automatic reboot time')
    hour, minute = map(int, text.split(':'))
    anchor = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
    if local.timestamp() < anchor.timestamp():
        anchor -= dt.timedelta(days=1)
    # Epoch arithmetic handles a repeated hour exactly once and normalizes a
    # nonexistent spring time to the corresponding real local time.
    anchor = dt.datetime.fromtimestamp(anchor.timestamp(), local.tzinfo)
    return anchor, anchor.strftime('%Y-%m-%d') + ' ' + text


def due(policy, local):
    anchor, key = window(local, policy['time'])
    attempt = policy.get('attempt') or {}
    return (policy['enabled'] is True and 0 <= local.timestamp() - anchor.timestamp() < 3600
            and policy.get('updated_at', float('inf')) <= anchor.timestamp()
            and not (attempt.get('window') == key and attempt.get('state') in {'scheduled', 'triggered', 'canceled'})
            and local.timestamp() - attempt.get('at', 0) >= 300), key


@contextlib.contextmanager
def package_locks():
    with contextlib.ExitStack() as stack:
        for path in APT_LOCKS:
            if not path.exists():
                continue
            handle = stack.enter_context(os.fdopen(os.open(path, os.O_RDWR | os.O_NOFOLLOW), 'r+'))
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                raise SecurityError(f'Unsafe package-manager lock: {path} (expected a root-owned regular file)')
            try:
                fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SecurityError('APT is busy; the automatic reboot was deferred') from None
        yield


def fire(root, lock, marker, required, unit, *, now=None):
    if not UNIT.fullmatch(unit):
        raise SecurityError('Invalid automatic reboot unit')
    # The policy and marker are re-read after acquiring custody. A canceled
    # timer, old boot or replaced policy can never authorize this executor.
    with os.fdopen(os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'r+') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise SecurityError('Unsafe maintenance lock')
        fcntl.flock(handle, fcntl.LOCK_EX)
        if not marker.exists():
            return 'canceled'
        owned = read_json(marker)
        automatic = owned.get('automatic') or {}
        if owned.get('unit') != unit or not isinstance(automatic, dict) or not automatic:
            return 'obsolete'
        policy = None
        result = 'deferred'
        error_text = ''
        try:
            policy = read_policy(root / 'reboot-policy.json')
            if (owned.get('boot_id') != BOOT.read_text().strip() or policy.get('enabled') is not True
                    or policy.get('id') != automatic.get('policy_revision')
                    or (policy.get('attempt') or {}).get('window') != automatic.get('window')
                    or (policy.get('attempt') or {}).get('state') != 'scheduled'):
                result = 'canceled'
                return result
            local = now or local_time()
            anchor, key = window(local, policy['time'])
            if key != automatic.get('window') or not 0 <= local.timestamp() - anchor.timestamp() < 3600:
                result = 'missed'
                return result
            service_reason = automatic.get('reason') == 'services' and policy.get('allow_service_reboot', False)
            if not required.exists() and not service_reason:
                result = 'not_required'
                return result
            managed = read_json(root / 'policy.json')
            assert_managed(managed)
            maintenance_guard(allow_web_reboot=True)
            # Retain real POSIX APT locks through the final reboot request.
            with package_locks():
                if not required.exists():
                    from service_restarts import fallback_services, policy as restart_policy
                    if (not service_reason or restart_policy(root)['id'] != automatic.get('restart_policy_revision')
                            or not fallback_services(root, now=local)):
                        result = 'not_required'
                        return result
                policy['attempt'].update(state='triggered', at=time.time(), error=None)
                atomic(root / 'reboot-policy.json', policy)
                command(['/usr/bin/systemctl', 'reboot'], timeout=30)
            result = 'triggered'
            return result
        except (SecurityError, OSError, ValueError) as error:
            error_text = str(error)[:500]
            print(error_text, flush=True)
            return result
        finally:
            if result != 'triggered':
                if policy and policy.get('id') == automatic.get('policy_revision'):
                    policy['attempt'] = {'window': automatic.get('window'), 'state': result, 'at': time.time(), 'error': error_text}
                    atomic(root / 'reboot-policy.json', policy)
                marker.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fire',))
    parser.add_argument('--state-root', type=Path, default=Path('/var/lib/easy-ha-proxy/update-web/os-security'))
    parser.add_argument('--maintenance-lock', type=Path, default=Path('/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock'))
    parser.add_argument('--reboot-marker', type=Path, default=Path('/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json'))
    parser.add_argument('--required-marker', type=Path, default=Path('/var/run/reboot-required'))
    parser.add_argument('--unit', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Scheduled reboots require root')
    os.umask(0o077)
    print(fire(args.state_root, args.maintenance_lock, args.reboot_marker, args.required_marker, args.unit), flush=True)


if __name__ == '__main__':
    main()
