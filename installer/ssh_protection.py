"""Inspect and manage Fail2ban for the Linux host's OpenSSH service."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import configparser
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
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
DEFAULT_POLICY = {'maxretry': 5, 'findtime': 600, 'bantime': 3600}
OPENSSH_FIELDS = {'passwordauthentication', 'kbdinteractiveauthentication', 'permitrootlogin',
                  'persourcepenalties', 'pubkeyauthentication', 'authenticationmethods',
                  'allowusers', 'allowgroups', 'denyusers', 'denygroups'}
# The panel's own HTTP ban chain (iptables-haproxy-ban.service) is inserted
# first in INPUT and only drops ports 80 and 443, so it cannot pass an SSH
# connection that Fail2ban blocks.
HARMLESS_INPUT_RULES = frozenset({'-A INPUT -j HP_BAN'})
BAN_TIME = re.compile(r'(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)')


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


def validated_policy(policy):
    if (not isinstance(policy, dict) or policy.keys() != DEFAULT_POLICY.keys()
            or any(type(value) is not int for value in policy.values())
            or not 2 <= policy['maxretry'] <= 50
            or not 60 <= policy['findtime'] <= 86400 or policy['findtime'] % 60
            or not 60 <= policy['bantime'] <= 604800 or policy['bantime'] % 60):
        raise ValueError('Invalid SSH blocking thresholds')
    return policy


def openssh_settings(*options):
    code, output = quick('/usr/sbin/sshd', '-T', *options)
    if code:
        return {}
    settings = {}
    for line in output.splitlines():
        key, _, value = line.partition(' ')
        if key in OPENSSH_FIELDS and value:
            settings[key] = (settings.get(key, '') + ' ' + value).strip()[:2048]
    return settings


def check_connection(user, source, hostname=None, local_address=None, port=None):
    if not isinstance(user, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\$?', user):
        raise ValueError('Enter a valid SSH username')
    source = address(source)
    if hostname and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', hostname):
        raise ValueError('Enter a valid client hostname')
    fields = [f'user={user}', f'addr={source}', f'host={hostname or source}']
    if local_address:
        fields.append('laddr=' + address(local_address))
    if port:
        if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            raise ValueError('Enter a valid local SSH port')
        fields.append('lport=' + port)
    settings = openssh_settings('-C', ','.join(fields))
    if not settings:
        raise SecurityError('OpenSSH settings could not be evaluated for this connection')
    return settings


def listening_endpoints():
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
    return sorted({endpoint for endpoint in endpoints if re.fullmatch(r'[\w.:%*\[\]-]+:\d{1,5}', endpoint)})[:32]


def listening_ports(endpoints=None):
    ports = {int(endpoint.rsplit(':', 1)[1]) for endpoint in (listening_endpoints() if endpoints is None else endpoints)}
    return sorted(port for port in ports if 0 < port <= 65535)


def config_text(enabled, ports=(), backend=None, trusted=(), policy=None):
    text = HEADER + '[sshd]\nenabled = ' + ('true' if enabled else 'false') + '\n'
    if backend:
        policy = DEFAULT_POLICY if policy is None else policy
        text += ('port = ' + ','.join(map(str, ports)) + '\n'
                 + f'backend = {backend}\n'
                 + 'action = iptables-multiport[name=sshd, port="%(port)s", protocol=tcp]\n'
                 + ''.join(f'{key} = {policy[key]}\n' for key in ('findtime', 'maxretry', 'bantime'))
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
    return path.read_bytes().decode('utf-8')


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
    policy = validated_policy({key: section.getint(key, fallback=value) for key, value in DEFAULT_POLICY.items()})
    if (backend not in {None, 'systemd', 'polling'} or any(not 0 < port <= 65535 for port in ports)
            or text != config_text(enabled, ports, backend, trusted, policy)):
        raise SecurityError('An existing Fail2ban configuration requires administrator review')
    return {'text': text, 'enabled': enabled, 'ports': ports, 'backend': backend, 'trusted': trusted, 'policy': policy}


def unmodified_package_defaults(path, text):
    code, conffiles = quick('/usr/bin/dpkg-query', '--show', '--showformat=${Conffiles}', 'fail2ban')
    if code:
        return False
    # dpkg stores an MD5 for each shipped conffile to detect local edits.
    checksum = hashlib.md5(text.encode('utf-8'), usedforsecurity=False).hexdigest()
    return any(line.strip().rsplit(maxsplit=1) == [str(path), checksum] for line in conffiles.splitlines())


def external_ssh_config():
    paths = [CONFIG / 'jail.local', *DROP_IN.parent.glob('*.conf'), *DROP_IN.parent.glob('*.local')]
    for path in paths:
        if path == DROP_IN or not os.path.lexists(path):
            continue
        text = read_config(path)
        if path == DROP_IN.parent / 'defaults-debian.conf':
            if unmodified_package_defaults(path, text):
                continue
            return True
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(text)
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


def ban_times(addresses):
    if not addresses:
        return {}
    code, output = quick(CLIENT, 'get', 'sshd', 'banip', '--with-time')
    if code:
        return {}
    active = set(addresses)
    result = {}
    for line in output.splitlines():
        match = BAN_TIME.fullmatch(line.strip())
        if not match:
            continue
        ip, started, duration, expires = match.groups()
        try:
            ip = address(ip)
        except ValueError:
            continue
        if ip in active:
            result[ip] = {'started': started, 'expires': expires if duration != '-1' else None, 'permanent': duration == '-1'}
    return result


def effective_jail_policy():
    keys = ('maxretry', 'findtime', 'bantime', 'ignoreip')
    with ThreadPoolExecutor(max_workers=len(keys)) as pool:
        queries = {key: pool.submit(quick, CLIENT, 'get', 'sshd', key) for key in keys}
    result = {}
    for key, query in queries.items():
        code, output = query.result()
        value = output.strip()
        if not code and key == 'ignoreip' and value.startswith(('These IP addresses/networks are ignored:', 'No IP address/network is ignored')):
            matches = re.findall(r'^[`|]- (\S{1,253})$', value, re.M)
            result['trusted'] = matches[:50]
        elif not code and re.fullmatch(r'-?\d{1,12}', value):
            result[key] = int(value)
    return result


def firewall_family(family, ports, banned):
    tool = '/usr/sbin/iptables-save' if family == 4 else '/usr/sbin/ip6tables-save'
    code, rules = quick(tool, '-t', 'filter')
    if code:
        return 'unknown'
    hook = False
    earlier_input = False
    priority_uncertain = False
    earlier_jail_rule = False
    blocked = set()
    reached_return = False
    try:
        for line in rules.splitlines():
            if line.startswith('-A INPUT ') and line.strip() not in HARMLESS_INPUT_RULES:
                args = shlex.split(line)
                if (not hook and len(args) == 10 and args[2:7] == ['-p', 'tcp', '-m', 'multiport', '--dports']
                        and args[8:] == ['-j', 'f2b-sshd'] and set(args[7].split(',')) == {str(port) for port in ports}):
                    hook = True
                    priority_uncertain = earlier_input
                earlier_input = True
            elif not reached_return and line.startswith('-A f2b-sshd '):
                args = shlex.split(line)
                if args[2:] == ['-j', 'RETURN']:
                    reached_return = True
                if (args[2:3] == ['-s'] and
                        args[4:] in (['-j', 'DROP'], ['-j', 'REJECT'],
                                     ['-j', 'REJECT', '--reject-with', 'icmp-port-unreachable'],
                                     ['-j', 'REJECT', '--reject-with', 'icmp6-port-unreachable'])):
                    network = ipaddress.ip_network(args[3])
                    if network.prefixlen == network.max_prefixlen:
                        ip = str(network.network_address)
                        blocked.add(ip)
                        if ip in banned and earlier_jail_rule:
                            priority_uncertain = True
                elif not reached_return:
                    # An administrator rule can accept or return before the
                    # generated block, or jump to a chain we do not inspect.
                    # Its mere presence below the INPUT hook is not proof
                    # that a later block will be reached.
                    earlier_jail_rule = True
    except ValueError:
        return 'unknown'
    if banned:
        if not hook or not banned <= blocked:
            return 'missing'
        return 'order_unknown' if priority_uncertain else 'verified'
    return 'idle'


def firewall_status(configured, live, status):
    if not live:
        return {'state': 'unknown'}
    if set(live) != set(configured):
        return {'state': 'ports_changed'}
    addresses = {4: set(), 6: set()}
    for value in status['banned']:
        addresses[ipaddress.ip_address(value).version].add(value)
    families = {str(family): firewall_family(family, configured, values) if values else 'idle'
                for family, values in addresses.items()}
    observed = set(families.values())
    if 'missing' in observed:
        state = 'missing'
    elif 'unknown' in observed:
        state = 'unknown'
    elif 'order_unknown' in observed:
        state = 'order_unknown'
    elif status['currently_banned'] > len(status['banned']):
        state = 'partial'
    else:
        state = 'verified' if 'verified' in observed else 'idle'
    return {'state': state, 'families': families}


def snapshot(*, monitor=False):
    result = {'state': 'not_installed', 'managed': False, 'trusted': [], 'policy': DEFAULT_POLICY}
    if not monitor:
        result['openssh'] = openssh_settings()
    try:
        installed = Path(CLIENT).is_file()
        status = None
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
                          ports=local['ports'], backend=local['backend'], policy=local['policy'])
        result['external_config'] = external_ssh_config()
        if not monitor or (status and local and local['enabled'] and not result['external_config']):
            result['listeners'] = listening_endpoints()
        if status is not None:
            if not monitor:
                result['ban_times'] = ban_times(status['banned'])
                result['effective_policy'] = effective_jail_policy()
            result['firewall'] = (firewall_status(local['ports'], listening_ports(result['listeners']), status)
                                  if local and local['enabled'] and not result['external_config'] else {'state': 'external'})
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


def set_protection(action, trusted, policy=None):
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
        policy = validated_policy(policy) if policy is not None else (local or {}).get('policy', DEFAULT_POLICY)
        ports = listening_ports()
        if not ports:
            raise SecurityError('No active OpenSSH listening port was found')
        if len(ports) > 15:
            raise SecurityError('The firewall action supports up to 15 SSH ports')
        backend = log_backend()
    else:
        ports, backend, trusted = local['ports'], local['backend'], local['trusted']
        policy = local['policy']

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
            firewalls = [
                shutil.which('iptables', path='/usr/sbin:/sbin:/usr/bin:/bin') or '/usr/sbin/iptables',
            ]
            if os.path.exists('/proc/net/if_inet6'):
                firewalls.append(
                    shutil.which('ip6tables', path='/usr/sbin:/sbin:/usr/bin:/bin') or '/usr/sbin/ip6tables'
                )
            for firewall in firewalls:
                if quick(firewall, '-w', '2', '-S', 'INPUT')[0]:
                    raise SecurityError('The server firewall could not be checked for SSH blocking')
        atomic(DROP_IN, config_text(enabled, ports, backend, trusted, policy))
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
    parser.add_argument('action', choices=('status', 'monitor', 'check-connection', 'install', 'enable', 'disable', 'unban'))
    parser.add_argument('--trusted', nargs='*', default=[])
    parser.add_argument('--ip')
    parser.add_argument('--policy', type=json.loads)
    parser.add_argument('--user')
    parser.add_argument('--hostname')
    parser.add_argument('--local-address')
    parser.add_argument('--port')
    parser.add_argument('--maintenance-lock', type=Path)
    parser.add_argument('--request-id')
    args = parser.parse_args()
    try:
        if args.action in ('status', 'monitor'):
            result = snapshot(monitor=args.action == 'monitor')
        elif args.action == 'check-connection':
            result = {'openssh': check_connection(args.user, args.ip, args.hostname, args.local_address, args.port)}
        elif args.action == 'unban':
            ip = address(args.ip)
            code, _ = quick(CLIENT, 'set', 'sshd', 'unbanip', ip)
            if code:
                raise SecurityError('The IP could not be unblocked in the Fail2ban SSH rule')
            result = {'message': 'IP removed from SSH blocks.'}
        else:
            if args.maintenance_lock is None:
                raise SecurityError('--maintenance-lock is required')
            with contextlib.ExitStack() as stack:
                lock = os.open(args.maintenance_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stack.callback(os.close, lock)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise SecurityError('Another maintenance operation is active') from None
                result = {'message': set_protection(args.action, trusted_addresses(args.trusted), args.policy)}
        print(json.dumps({'ok': True, 'request_id': args.request_id, **result}))
        return 0
    except (OSError, ValueError, configparser.Error, SecurityError) as error:
        print(json.dumps({'ok': False, 'request_id': args.request_id, 'error': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
