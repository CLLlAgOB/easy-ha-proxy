"""Apply pending service restarts independently of new package installations."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from os_security import ROOT, LOCK, SecurityError, assert_managed, atomic, command, local_time, maintenance_guard, platform, read_json, restart_status
from auto_reboot import package_locks

SERVICE_RESTART_PROTOCOL = 1
TIME = re.compile(r'^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')
UNIT = re.compile(r'^[A-Za-z0-9_@.:\-]+\.service$')
BOOT = Path('/proc/sys/kernel/random/boot_id')
# These services are deliberately left to controlled maintenance. Never infer
# that an arbitrary failed restart can be fixed by rebooting the host.
PROTECTED = re.compile(r'^(?:haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd)\.service$')
DEFERRED = re.compile(r'^(?:dbus(?:-broker)?|dnsmasq|systemd-networkd|systemd-resolved|systemd-logind|networking|NetworkManager|ModemManager|wpa_supplicant|libvirtd|virtlogd|virtlockd|gdm3?|kdm|sddm|lightdm|bird6?|frr|bluetooth)\.service$')
EXCLUSIONS = ("$nrconf{override_rc}{qr(^(haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd|dbus|dbus-broker|dnsmasq|systemd-networkd|systemd-resolved|systemd-logind|networking|NetworkManager|ModemManager|wpa_supplicant)\\.service$)} = 0;\n")


def policy(root):
    path = root / 'restart-policy.json'
    if not path.exists():
        return {'enabled': False, 'time': '02:15', 'id': None, 'updated_at': 0}
    value = read_json(path)
    if (type(value.get('enabled')) is not bool or not isinstance(value.get('time'), str) or not TIME.fullmatch(value['time'])
            or not re.fullmatch(r'[0-9a-f]{32}', str(value.get('id', '')))
            or type(value.get('updated_at')) not in (int, float)):
        raise SecurityError('The service restart policy is invalid')
    return value


def window(local, text):
    hour, minute = map(int, text.split(':'))
    anchor = local.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
    if local.timestamp() < anchor.timestamp():
        anchor -= dt.timedelta(days=1)
    anchor = dt.datetime.fromtimestamp(anchor.timestamp(), local.tzinfo)
    return anchor, anchor.strftime('%Y-%m-%d') + ' ' + text


def due(value, status, local, boot_id):
    anchor, key = window(local, value['time'])
    same = status.get('policy_id') == value['id'] and status.get('boot_id') == boot_id
    retry = 900 if status.get('state') == 'running' else 300
    return (value['enabled'] and 0 <= local.timestamp() - anchor.timestamp() < 3600
            and value['updated_at'] <= anchor.timestamp()
            and not (status.get('policy_id') == value['id'] and status.get('window') == key and status.get('state') == 'ready' and status.get('applied'))
            and (not same or local.timestamp() - status.get('last_attempt', 0) >= retry)), key


def classification(service):
    if PROTECTED.fullmatch(service):
        return 'protected'
    if DEFERRED.fullmatch(service):
        return 'deferred'
    return 'automatic' if UNIT.fullmatch(service) or service == 'systemd-manager' else 'unknown'


def checked_restart():
    result = restart_status()
    if result.get('error'):
        raise SecurityError(result['error'])
    if any(classification(service) == 'unknown' for service in result['services']):
        raise SecurityError('The restart checker returned an unsupported service')
    result['details'] = [{'service': service, 'kind': classification(service)} for service in result['services']]
    return result


def fallback_services(root, *, now=None, restart=None):
    """Fresh evidence for an explicitly allowed reboot, never an error fallback."""
    value = policy(root)
    path = root / 'restart-status.json'
    if not value['enabled'] or not path.exists():
        return []
    status = read_json(path)
    local = now or local_time()
    anchor, key = window(local, value['time'])
    if (status.get('state') != 'ready' or status.get('applied') is not True or status.get('verified') is not True
            or status.get('policy_id') != value['id'] or status.get('boot_id') != BOOT.read_text().strip()
            or status.get('window') != key or value['updated_at'] > anchor.timestamp()
            or not anchor.timestamp() <= status.get('completed_at', 0) <= local.timestamp()
            or local.timestamp() - status.get('completed_at', 0) > 24 * 3600
            or status.get('failed_services') or status.get('unresolved')):
        return []
    deferred = status.get('deferred') or []
    if not deferred or any(classification(service) not in {'protected', 'deferred'} for service in deferred):
        return []
    fresh = restart if restart is not None else checked_restart()
    services = fresh.get('services') or []
    if fresh.get('error') or not services or not set(services).issubset(deferred):
        return []
    return sorted(set(services))


def run(action, root, *, now=None):
    platform()
    return execute(action, root, now=now)


def execute(action, root, *, now=None):
    managed = read_json(root / 'policy.json') if (root / 'policy.json').exists() else {}
    if action != 'restart-check':
        assert_managed(managed)
    value = policy(root)
    path = root / 'restart-status.json'
    previous = read_json(path) if path.exists() else {}
    local = now or local_time()
    boot_id = BOOT.read_text().strip()
    _, key = window(local, value['time'])
    if action == 'restart-cycle' and not due(value, previous, local, boot_id)[0]:
        return {'message': 'The service restart window is not due'}
    # A read-only check must not erase a successful application or consume
    # tonight's scheduled pass. Keep its result separate from the attempt.
    if action == 'restart-check':
        try:
            maintenance_guard()
            fresh = checked_restart()
            atomic(path, {**previous, 'check': fresh, 'check_boot_id': boot_id})
            return {'message': 'Service restart check completed', 'restart': fresh}
        except Exception as error:
            atomic(path, {**previous, 'check': {'error': str(error)[:500], 'checked_at': time.time()}, 'check_boot_id': boot_id})
            raise
    state = {'state': 'running', 'last_attempt': local.timestamp(), 'policy_id': value['id'],
             'boot_id': boot_id, 'window': key, 'applied': False, 'verified': False, 'error': None}
    atomic(path, state)
    try:
        # Record preflight failures too, so a busy or unsafe package lock
        # is visible and obeys the same retry delay.
        maintenance_guard()
        with package_locks():
            before = checked_restart()
            automatic = [unit for unit in before['services'] if classification(unit) == 'automatic']
            # Preserve native and operator exclusions; add protection for the
            # network and the workers that currently own maintenance custody.
            if automatic:
                print('EHP-PROGRESS phase=playbook', flush=True)
                with tempfile.TemporaryDirectory(prefix='service-restarts-', dir=root) as temporary:
                    config = Path(temporary) / 'needrestart.conf'
                    config.write_text("my $loaded = do q(/etc/needrestart/needrestart.conf); die($@ || $!) unless defined $loaded;\n" + EXCLUSIONS)
                    _, log = command(['/usr/sbin/needrestart', '-r', 'a', '-c', str(config)], timeout=600,
                                     env={'NEEDRESTART_MODE': 'a'})
                    print(log, flush=True)
            after = checked_restart()
            failed = []
            for unit in automatic:
                if unit == 'systemd-manager':
                    continue
                code, text = command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'], check=False)
                if code or text.strip() not in {'active', 'reloading'}:
                    failed.append(unit)
            deferred = [unit for unit in after['services'] if classification(unit) in {'protected', 'deferred'}]
            unresolved = sorted(set(after['services']) - set(deferred))
            state.update(state='ready', completed_at=time.time(), applied=True, verified=not failed and not unresolved,
                         before=before['services'], restart=after, restarted=sorted(set(automatic) - set(after['services']) - set(failed)),
                         deferred=deferred, unresolved=unresolved, failed_services=failed)
            atomic(path, state)
            if failed:
                raise SecurityError('Some services did not become active after their restart')
            return {'message': 'Service restarts finished; review remaining services', **state}
    except Exception as error:
        atomic(path, {**state, 'state': 'unknown', 'verified': False, 'error': str(error)[:500]})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('restart-check', 'restart', 'restart-cycle', 'reboot-reason'))
    parser.add_argument('--state-root', type=Path, default=ROOT)
    parser.add_argument('--maintenance-lock', type=Path, default=LOCK)
    parser.add_argument('--request-id', default='')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Service restarts require root')
    os.umask(0o077)
    try:
        if args.action == 'reboot-reason':
            result = {'services': fallback_services(args.state_root)}
        else:
            args.maintenance_lock.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(os.open(args.maintenance_lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = run(args.action, args.state_root)
        print(json.dumps({'ok': True, 'request_id': args.request_id, **result}), flush=True)
        return 0
    except (SecurityError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
