"""Read installed, running and eligible HAProxy versions without changing the host."""
from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
import re
import socket

import apt_metadata

PACKAGES = frozenset({'haproxy', 'haproxy-awslc', 'libssl-awslc'})
LAST_UPDATE = Path('/var/lib/easy-ha-proxy/haproxy-package-migration/last-update.json')


def checksum(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(part)
    return result.hexdigest()


def runtime_state(binary, sock=Path('/run/haproxy/admin.sock')):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(sock))
        connection.sendall(b'show info\n')
        connection.shutdown(socket.SHUT_WR)
        reply = bytearray()
        while True:
            part = connection.recv(16384)
            if not part:
                break
            reply.extend(part)
            if len(reply) > 256 * 1024:
                raise ValueError('HAProxy runtime reply exceeds the limit')
    fields = dict(line.split(': ', 1) for line in reply.decode().splitlines() if ': ' in line)
    pid = str(int(fields['Pid']))
    process = Path('/proc') / pid
    libraries = set()
    for line in (process / 'maps').read_text().splitlines():
        columns = line.split(None, 5)
        if (len(columns) == 6 and 'x' in columns[1] and columns[5].endswith(' (deleted)')
                and columns[5].startswith(('/usr/', '/lib/', '/bin/', '/sbin/'))):
            libraries.add(Path(columns[5].removesuffix(' (deleted)')).name)
    return {'running_version': fields['Version'], 'binary_matches': checksum(process / 'exe') == checksum(binary),
            'replaced_libraries': sorted(libraries)}


def probe(runner, *, binary=Path('/usr/sbin/haproxy'), metadata=None, reader=runtime_state, last_update=LAST_UPDATE, qualified=None,
          protection=Path('/etc/needrestart/conf.d/easy-ha-proxy-haproxy.conf')):
    if qualified is None:
        try:
            release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
            qualified = (release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04'
                         and platform.machine() in ('aarch64', 'x86_64'))
        except OSError:
            qualified = False
    details = {'installed_version': None, 'running_version': None, 'candidate_version': None,
               'branch': None, 'provider': None, 'protected': False, 'needs_reload': False,
               'qualified': qualified, 'apt': metadata if metadata is not None else apt_metadata.assess()}

    def result(state, summary):
        return {'id': 'haproxy', 'state': state, 'actionable': state == 'available', 'summary': summary,
                'current_version': details['installed_version'], 'available_version': details['candidate_version'],
                'installed': details['installed_version'], 'available': details['candidate_version'], 'details': details}

    try:
        last = json.loads(last_update.read_text())
        if re.fullmatch(r'[0-9a-f]{32}', str(last.get('id', ''))):
            details['last_operation'] = {key: last.get(key) for key in
                                         ('id', 'phase', 'old_version', 'target_packages', 'updated_at', 'failure',
                                          'rollback_verified', 'target_verified')}
    except (OSError, ValueError, TypeError):
        pass
    if not binary.is_file():
        return result('blocked', 'HAProxy is not installed on this host.')
    found = {}
    for name in ('haproxy', 'haproxy-awslc'):
        response = runner.run(('dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', name), timeout=10)
        parts = response.stdout.strip().split('\t')
        if response.returncode == 0 and len(parts) == 2 and parts[0] == 'installed':
            found[name] = parts[1]
    if len(found) != 1:
        return result('unknown', 'The installed HAProxy package could not be determined.')
    name, version = next(iter(found.items()))
    branch = '3.4' if name == 'haproxy-awslc' else '2.8'
    details.update(package=name, installed_version=version, branch=branch,
                   provider='HAProxy Technologies' if name == 'haproxy-awslc' else 'Ubuntu',
                   source='ha34 / Ubuntu noble' if name == 'haproxy-awslc' else 'Ubuntu noble')
    policy = runner.run(('apt-cache', 'policy', name), timeout=15)
    match = re.search(r'^\s+Candidate:\s*(\S+)', policy.stdout, re.M)
    if policy.returncode == 0 and match and match[1] != '(none)':
        details['candidate_version'] = match[1]
    if not re.search(r'^\s+\d+\s+(?:https?://|file:)', policy.stdout, re.M):
        details['candidate_version'] = None
    selections = runner.run(('dpkg', '--get-selections'), timeout=10)
    held = {line.split()[0].split(':', 1)[0] for line in selections.stdout.splitlines()
            if len(line.split()) == 2 and line.split()[1] == 'hold'}
    required = {name} | ({'libssl-awslc'} if name == 'haproxy-awslc' else set())
    try:
        guarded_restart = '$nrconf{override_rc}{qr(^haproxy\\.service$)} = 0;' in protection.read_text()
    except OSError:
        guarded_restart = False
    details['protected'] = selections.returncode == 0 and required <= held and guarded_restart
    try:
        details.update(reader(binary))
    except (OSError, ValueError, KeyError, UnicodeError):
        return result('unknown', 'The running HAProxy version could not be verified.')
    if not details.get('binary_matches'):
        return result('blocked', 'The running HAProxy binary differs from the installed package; operator recovery is required.')
    details['needs_reload'] = bool(details.get('replaced_libraries'))
    if not qualified:
        return result('blocked', 'Controlled HAProxy updates require qualified Ubuntu 24.04 ARM64 or AMD64; use the distribution update procedure on other platforms.')
    if not details['apt'].get('fresh'):
        return result('unknown', 'APT metadata is stale or its refresh failed. Check for updates again.')
    if not details['candidate_version']:
        return result('unknown', 'No eligible HAProxy package candidate was found.')
    if not version.startswith(branch + '.') or not details['candidate_version'].startswith(branch + '.'):
        return result('blocked', 'A different HAProxy branch requires a separate migration.')
    if not details['protected']:
        return result('blocked', 'Enable controlled HAProxy package protection with a host-service update first.')
    newer = runner.run(('dpkg', '--compare-versions', details['candidate_version'], 'gt', version), timeout=5)
    if newer.returncode == 0:
        return result('available', 'A HAProxy patch update is available in the selected branch.')
    if newer.returncode != 1:
        return result('unknown', 'HAProxy package versions could not be compared.')
    if details['candidate_version'] != version:
        return result('blocked', 'The eligible HAProxy candidate is older than the installed package.')
    if details['needs_reload']:
        return result('available', 'HAProxy must reload to use updated system libraries; the package version is unchanged.')
    return result('current', 'Installed and running HAProxy are current in the selected branch.')
