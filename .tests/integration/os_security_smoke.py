"""Disposable signed APT repository: real security installation, holds, restore.

Never run on a gateway. Debian containers exercise native APT with a timer
adapter; the Ubuntu AMD64/ARM64 runners also exercise actual systemd custody.
"""
from __future__ import annotations

import argparse
import email.utils
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'installer'))
import os_security as security  # noqa: E402


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def build_package(root, name, version, architecture):
    directory = root / (name + '-' + version)
    (directory / 'DEBIAN').mkdir(parents=True)
    (directory / 'DEBIAN/control').write_text(f'Package: {name}\nVersion: {version}\nArchitecture: {architecture}\nMaintainer: Disposable fixture <fixture@example.test>\nDescription: Disposable OS security test\n')
    data = directory / 'usr/share/ehp-os-security-fixture'
    data.mkdir(parents=True)
    (data / name).write_text(version + '\n')
    archive = root / (name + '-' + version + '.deb')
    command(['dpkg-deb', '--build', str(directory), str(archive)])
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--systemd', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('EHP_SECURITY_DISPOSABLE') != '1':
        parser.error('Requires root and EHP_SECURITY_DISPOSABLE=1 on a disposable machine')
    if not args.systemd and not Path('/.dockerenv').exists():
        parser.error('The timer adapter is only for disposable containers')
    os.umask(0o022)
    base = Path(tempfile.mkdtemp(prefix='ehp-disposable-os-security-'))
    base.chmod(0o755)
    if not args.systemd:
        Path('/run/systemd/system').mkdir(parents=True, exist_ok=True)
        original_command = security.command
        timer = {'enabled': 'enabled', 'active': True}

        def adapted(argv, **kwargs):
            if argv[0] != '/usr/bin/systemctl':
                return original_command(argv, **kwargs)
            if 'stop' in argv: timer['active'] = False
            if 'disable' in argv: timer['enabled'] = 'disabled'
            if 'enable' in argv: timer['enabled'] = 'enabled'
            if 'start' in argv: timer['active'] = True
            if argv[1:3] == ['show', security.TIMER]:
                return 0, 'LoadState=loaded\nUnitFileState=' + timer['enabled'] + '\nActiveState=' + ('active' if timer['active'] else 'inactive') + '\n'
            return 0, 'inactive\n' if 'apt-daily-upgrade.service' in argv else '0\n'
        security.command = adapted
    distro, codename = security.platform()
    architecture = command(['dpkg', '--print-architecture'])
    names = ['ehp-security-fixture', 'ehp-held-fixture', 'ehp-protected-fixture', 'ehp-nonsecurity-fixture']
    security.PROTECTED = security.PROTECTED | {'ehp-protected-fixture'}
    baseline = security.native_timer()
    state = base / 'state'
    source_backup = base / 'original-sources'
    source_backup.mkdir()
    source = Path('/etc/apt/sources.list.d/ehp-disposable-security.list')
    extra = Path('/etc/apt/apt.conf.d/98-ehp-disposable-inherited')
    moved = []
    try:
        for name in names:
            command(['dpkg', '-i', str(build_package(base, name, '1.0', architecture))], env={**os.environ, 'NEEDRESTART_MODE': 'l'})
        command(['apt-mark', 'hold', 'ehp-held-fixture'])
        for existing in [Path('/etc/apt/sources.list'), *Path('/etc/apt/sources.list.d').glob('*')]:
            if existing.is_file() and (existing.name == 'sources.list' or existing.suffix in {'.sources', '.list'}):
                destination = source_backup / existing.name
                existing.rename(destination)
                moved.append((destination, existing))
        gpg_home = base / 'gnupg'; gpg_home.mkdir(mode=0o700)
        gpg = ['gpg', '--homedir', str(gpg_home), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
        command(gpg + ['--quick-generate-key', 'Disposable security fixture <fixture@example.test>', 'rsa2048', 'sign', '0'])
        key = base / 'key.asc'; key.write_text(command(gpg + ['--armor', '--export'])); key.chmod(0o644)
        repo = base / 'repo'; (repo / 'pool').mkdir(parents=True)
        for suffix, selection in (('security', names[:3]), ('updates', names[3:])):
            suite = codename + '-' + suffix
            records = []
            for name in selection:
                archive = build_package(base, name, '2.0' if suffix == 'security' else '9.0', architecture)
                output = repo / 'pool' / archive.name; shutil.copyfile(archive, output)
                records.append(command(['dpkg-deb', '-f', str(output)]) + f'\nFilename: pool/{output.name}\nSize: {output.stat().st_size}\nSHA256: {hashlib.sha256(output.read_bytes()).hexdigest()}\n\n')
            distribution = repo / 'dists' / suite
            index = distribution / ('main/binary-' + architecture); index.mkdir(parents=True)
            (index / 'Packages').write_text(''.join(records))
            (index / 'Packages.gz').write_bytes(gzip.compress((index / 'Packages').read_bytes(), mtime=0))
            origin = 'Ubuntu' if distro == 'ubuntu' else 'Debian'
            label = 'Debian-Security' if distro == 'debian' and suffix == 'security' else origin
            release = f'Origin: {origin}\nLabel: {label}\nSuite: {suite}\nCodename: {suite if distro == "debian" else codename}\nDate: {email.utils.formatdate(usegmt=True)}\nArchitectures: {architecture}\nComponents: main\nSHA256:\n'
            for item in (index / 'Packages', index / 'Packages.gz'):
                release += f' {hashlib.sha256(item.read_bytes()).hexdigest()} {item.stat().st_size} {item.relative_to(distribution)}\n'
            (distribution / 'Release').write_text(release)
            command(gpg + ['--yes', '--clearsign', '--output', str(distribution / 'InRelease'), str(distribution / 'Release')])
        source.write_text(''.join(f'deb [signed-by={key}] {repo.as_uri()} {codename}-{suffix} main\n' for suffix in ('security', 'updates')))
        extra.write_text(f'Unattended-Upgrade::Allowed-Origins {{ "{origin}:{codename}-updates"; }};\nUnattended-Upgrade::Automatic-Reboot "true";\nUnattended-Upgrade::InstallOnShutdown "true";\n')
        policy = {'mode': 'notify', 'interval': 4, 'start': 3, 'end': 5}
        security.run('configure', state, policy)
        check = security.run('check', state)
        assert check['package_count'] == 3, check
        assert check['eligible_count'] == 1, check
        assert check['native_policy']['reboot'] is False and check['native_policy']['shutdown'] is False, check
        security.run('cycle', state)
        assert command(['dpkg-query', '-W', '-f=${Version}', names[0]]) == '1.0'
        # No library changes in this fixture, and unrelated CI runner services
        # must not be restarted by needrestart while the test is reporting.
        original_environment = security.apt_environment

        def fixture_environment(*values):
            environment = original_environment(*values)
            assert environment['NEEDRESTART_MODE'] == 'a'
            return {**environment, 'NEEDRESTART_MODE': 'l'}
        security.apt_environment = fixture_environment
        security.run('configure', state, {**policy, 'mode': 'auto'})
        result = security.run('cycle', state)
        assert result['installed_count'] == 1, result
        assert result['package_count'] == 2, result
        assert command(['dpkg-query', '-W', '-f=${Version}', names[0]]) == '2.0'
        for name in names[1:]:
            assert command(['dpkg-query', '-W', '-f=${Version}', name]) == '1.0', name
        security.run('configure', state, {**policy, 'mode': 'system'})
        assert security.native_timer() == baseline
        assert not security.RESTART_DROPIN.exists() and not security.APT_GUARD.exists()
        print(json.dumps({'ok': True, 'architecture': architecture, 'distro': distro, 'systemd': args.systemd,
                          'security_installed': True, 'nonsecurity_unchanged': True, 'held_and_protected_unchanged': True, 'native_timer_restored': True}))
    finally:
        if (state / 'policy.json').exists() and security.read_json(state / 'policy.json').get('baseline'):
            security.run('configure', state, {'mode': 'system', 'interval': 4, 'start': 3, 'end': 5})
        source.unlink(missing_ok=True); extra.unlink(missing_ok=True)
        for backup, original in moved:
            backup.rename(original)
        command(['apt-mark', 'unhold', 'ehp-held-fixture'])
        command(['dpkg', '--purge', *names], env={**os.environ, 'NEEDRESTART_MODE': 'l'})


if __name__ == '__main__':
    main()
