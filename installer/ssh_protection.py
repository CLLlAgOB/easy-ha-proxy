"""Inspect and manage Fail2ban for the Linux host's OpenSSH service."""
from __future__ import annotations

import argparse
import configparser
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

from os_security import SecurityError, atomic, command, maintenance_guard, platform


CLIENT = '/usr/bin/fail2ban-client'
SYSTEMCTL = '/usr/bin/systemctl'
UNIT = 'fail2ban.service'
CONFIG = Path('/etc/fail2ban')
DROP_IN = CONFIG / 'jail.d/99-easy-ha-proxy-sshd.local'
HEADER = '# Managed by Easy HA Proxy for SSH protection.\n'
JOURNAL_MATCH = '_SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session + _COMM=sshd-auth'
COUNTERS = {'Currently failed': 'currently_failed', 'Total failed': 'total_failed',
            'Currently banned': 'currently_banned', 'Total banned': 'total_banned'}
MAX_BANS = 200


def quick(*argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=2, env={**os.environ, 'LC_ALL': 'C'}, check=False)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def address(value, *, network=False):
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or '%' in value:
        raise ValueError('Enter a valid IPv4 or IPv6 address or subnet' if network else 'Invalid IP address')
    try:
        return str(ipaddress.ip_network(value, strict=False) if network and '/' in value else ipaddress.ip_address(value))
    except ValueError:
        raise ValueError('Enter a valid IPv4 or IPv6 address or subnet' if network else 'Invalid IP address') from None


def trusted_addresses(values):
    if not isinstance(values, list) or len(values) > 32:
        raise ValueError('Enter up to 32 trusted addresses or subnets')
    return list(dict.fromkeys(address(value, network=True) for value in values))


def openssh_settings():
    code, output = quick('/usr/sbin/sshd', '-T')
    if code:
        return {}
    allowed = {'passwordauthentication', 'kbdinteractiveauthentication', 'permitrootlogin', 'persourcepenalties'}
    return {key: value for line in output.splitlines() if ' ' in line
            for key, value in [line.split(' ', 1)] if key in allowed}


def listening_ports():
    ss = shutil.which('ss', path='/usr/sbin:/usr/bin:/sbin:/bin')
    if not ss:
        return []
    code, output = quick(ss, '-H', '-lntp')
    if code:
        return []
    endpoints = [line.split()[3] for line in output.splitlines()
                 if len(line.split()) >= 6 and '("sshd",' in line]
    code, state = quick(SYSTEMCTL, 'is-active', 'ssh.socket')
    if not code and state.strip() == 'active':
        code, sockets = quick(SYSTEMCTL, 'show', '--property=Listen', '--value', 'ssh.socket')
        if code:
            return []
        endpoints.extend(re.findall(r'(\S+)\s+\(Stream\)', sockets))
    ports = {int(match[1]) for endpoint in endpoints if (match := re.search(r':(\d{1,5})$', endpoint))}
    return sorted(port for port in ports if 0 < port <= 65535)


def config_text(enabled, ports=(), backend=None, trusted=()):
    text = HEADER + '[sshd]\nenabled = ' + ('true' if enabled else 'false') + '\n'
    if backend:
        text += ('port = ' + ','.join(map(str, ports)) + '\n'
                 + f'backend = {backend}\n'
                 + 'action = iptables-multiport[name=sshd, port="%(port)s", protocol=tcp]\n'
                 + 'findtime = 600\nmaxretry = 5\nbantime = 3600\n'
                 + 'ignoreip = ' + ' '.join(('127.0.0.0/8', '::1', *trusted)) + '\n')
        filter_args = '_daemon="sshd(?:-session|-auth)?"'
        if backend == 'systemd':
            filter_args += f', journalmatch="{JOURNAL_MATCH}"'
        text += f'filter = sshd[{filter_args}]\n'
        if backend == 'polling':
            text += 'logpath = /var/log/auth.log\n'
    return text


def read_config(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 256 * 1024:
        raise SecurityError('An existing Fail2ban configuration requires administrator review')
    return path.read_text(encoding='utf-8')


def managed_config():
    try:
        text = read_config(DROP_IN)
    except FileNotFoundError:
        return None
    if not text.startswith(HEADER + '[sshd]\nenabled = '):
        raise SecurityError('An existing Fail2ban configuration requires administrator review')
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)
    section = parser['sshd']
    enabled = section.getboolean('enabled')
    ports = [int(port) for port in section.get('port', '').split(',') if port]
    backend = section.get('backend')
    trusted = trusted_addresses(section.get('ignoreip', '').split()[2:])
    if (backend not in {None, 'systemd', 'polling'} or any(not 0 < port <= 65535 for port in ports)
            or text != config_text(enabled, ports, backend, trusted)):
        raise SecurityError('An existing Fail2ban configuration requires administrator review')
    return {'text': text, 'enabled': enabled, 'ports': ports, 'backend': backend, 'trusted': trusted}


def external_ssh_config():
    paths = [CONFIG / 'jail.local', *DROP_IN.parent.glob('*.conf'), *DROP_IN.parent.glob('*.local')]
    for path in paths:
        if path == DROP_IN or not os.path.lexists(path):
            continue
        text = read_config(path)
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(text)
        if (path.parent == DROP_IN.parent and path.name == 'defaults-debian.conf'
                and set(parser.sections()) == {'sshd'} and not parser.defaults()
                and dict(parser['sshd']) == {'enabled': 'true'}):
            continue
        if {'ignoreip', 'ignorecommand'} & parser.defaults().keys() or parser.has_section('INCLUDES') or any(
            name.lower().startswith(('sshd', 'openssh')) or
            re.match(r'^sshd(?:\s|\[|$)', parser[name].get('filter', '').strip(), re.IGNORECASE)
            for name in parser.sections()
        ):
            return True
    return False


def jail_status():
    code, output = quick(CLIENT, 'status', 'sshd')
    if code:
        return None
    values = {label: value.strip() for label, value in re.findall(r'[\x60|]- ([^:\n]+):([^\n]*)', output)}
    if not all(values.get(key, '').isdigit() for key in COUNTERS):
        raise SecurityError('The Fail2ban SSH rule returned an unreadable status')
    bans = []
    for value in values.get('Banned IP list', '').split()[:MAX_BANS]:
        try:
            bans.append(address(value))
        except ValueError:
            continue
    return {**{name: int(values[key]) for key, name in COUNTERS.items()}, 'banned': bans}


def snapshot():
    result = {'state': 'not_installed', 'managed': False, 'trusted': [], 'openssh': openssh_settings()}
    try:
        installed = Path(CLIENT).is_file()
        if installed:
            _, unit = quick(SYSTEMCTL, 'show', '--property=ActiveState', '--value', UNIT)
            status = jail_status()
            if status is not None:
                result.update(state='active', **status)
            elif unit.strip() == 'active' and quick(CLIENT, 'ping')[0] == 0:
                result['state'] = 'jail_disabled'
            else:
                result['state'] = {'failed': 'service_failed', 'inactive': 'service_stopped'}.get(unit.strip(), 'unavailable')
        local = managed_config()
        if local:
            result.update(managed=True, managed_enabled=local['enabled'], trusted=local['trusted'],
                          ports=local['ports'], backend=local['backend'])
        result['external_config'] = external_ssh_config()
    except (OSError, ValueError, configparser.Error, SecurityError) as error:
        result['error'] = str(error)
    return result


def log_backend():
    code, output = quick('/usr/bin/journalctl', '--quiet', '-n', '1', '-o', 'json',
                         '--output-fields=_COMM', '--', *JOURNAL_MATCH.split())
    if not code and output.lstrip().startswith('{'):
        return 'systemd'
    if Path('/var/log/auth.log').is_file():
        return 'polling'
    if not code:
        # A new socket-activated host may have no SSH messages yet.
        return 'systemd'
    raise SecurityError('No readable SSH log source was found')


def reload_ssh_jail(running, enabled):
    if running:
        command([CLIENT, 'reload', '--if-exists', 'sshd'])
    elif enabled:
        command([SYSTEMCTL, 'start', UNIT])


def verify_ssh_jail(running, enabled):
    # A newly started unit can become active before it has loaded its jails.
    attempts = 20 if enabled and not running else 1
    for _ in range(attempts):
        if enabled == (jail_status() is not None):
            if running and quick(CLIENT, 'ping')[0] != 0:
                raise SecurityError('The Fail2ban service did not become ready')
            return
        if attempts > 1:
            time.sleep(0.25)
    raise SecurityError('The Fail2ban SSH rule could not be verified')


def set_protection(action, trusted):
    platform()
    local = managed_config()
    if external_ssh_config():
        raise SecurityError('SSH protection is configured outside the panel')
    installed = Path(CLIENT).is_file()
    if action == 'install' and installed:
        raise SecurityError('Fail2ban is already installed. Refresh its status before continuing.')
    if action != 'install' and not installed:
        raise SecurityError('Install Fail2ban before changing SSH protection')
    enabled = action != 'disable'
    if not enabled and not local:
        raise SecurityError('Only panel-managed SSH protection can be disabled here')
    active = jail_status() if installed else None
    if active is not None and (not local or not local['enabled']):
        raise SecurityError('SSH protection is configured outside the panel')
    if enabled:
        ports = listening_ports()
        if not ports:
            raise SecurityError('No active OpenSSH listening port was found')
        backend = log_backend()
    else:
        ports, backend, trusted = local['ports'], local['backend'], local['trusted']

    if action == 'install':
        maintenance_guard()
        # The package can start its daemon during installation. Keep its
        # distribution sshd jail disabled until the managed policy is checked.
        atomic(DROP_IN, config_text(False))
        command(['/usr/bin/apt-get', '-o', 'DPkg::Lock::Timeout=10', '--assume-yes', '--no-remove', '--no-upgrade',
                 '--no-install-recommends', 'install', 'fail2ban', 'python3-systemd', 'iptables'], timeout=600)
        local = managed_config()
        if external_ssh_config():
            raise SecurityError('SSH protection is configured outside the panel')

    previous = local['text'] if local else None
    running = quick(CLIENT, 'ping')[0] == 0
    try:
        if enabled:
            for firewall in ('iptables', 'ip6tables'):
                if quick(firewall, '-w', '2', '-S', 'INPUT')[0]:
                    raise SecurityError('The server firewall could not be checked for SSH blocking')
        atomic(DROP_IN, config_text(enabled, ports, backend, trusted))
        command([CLIENT, '-t'])
        reload_ssh_jail(running, enabled)
        verify_ssh_jail(running, enabled)
        if enabled:
            command([SYSTEMCTL, 'enable', UNIT])
    except (OSError, SecurityError):
        if previous is None:
            DROP_IN.unlink(missing_ok=True)
        else:
            atomic(DROP_IN, previous)
        if running:
            command([CLIENT, 'reload', '--if-exists', 'sshd'], check=False)
        elif enabled:
            command([SYSTEMCTL, 'stop', UNIT], check=False)
        raise
    return 'SSH protection is enabled.' if enabled else 'SSH protection is disabled.'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('status', 'install', 'enable', 'disable', 'unban'))
    parser.add_argument('--trusted', nargs='*', default=[])
    parser.add_argument('--ip')
    parser.add_argument('--maintenance-lock', type=Path)
    parser.add_argument('--request-id')
    args = parser.parse_args()
    try:
        if args.action == 'status':
            result = snapshot()
        elif args.action == 'unban':
            ip = address(args.ip)
            code, _ = quick(CLIENT, 'set', 'sshd', 'unbanip', ip)
            if code:
                raise SecurityError('The IP could not be unblocked in the Fail2ban SSH rule')
            result = {'message': 'IP removed from SSH blocks.'}
        else:
            with contextlib.ExitStack() as stack:
                lock = os.open(args.maintenance_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stack.callback(os.close, lock)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise SecurityError('Another maintenance operation is active') from None
                result = {'message': set_protection(args.action, trusted_addresses(args.trusted))}
        print(json.dumps({'ok': True, 'request_id': args.request_id, **result}))
        return 0
    except (OSError, ValueError, configparser.Error, SecurityError) as error:
        print(json.dumps({'ok': False, 'request_id': args.request_id, 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
