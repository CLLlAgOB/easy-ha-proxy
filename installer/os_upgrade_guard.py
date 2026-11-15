"""Preflight ordinary APT upgrades and record them for restart scheduling.

Run by the update_packages role after refreshing APT metadata, immediately
before installation. The automatic path permits only runtime patch updates;
manual upgrades retain the operator's explicit choice. No package is changed
by this helper. An attempt is recorded before APT so partial failures and an
interrupted play still invalidate earlier service-restart evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


HAPROXY_PACKAGES = frozenset({'haproxy', 'haproxy-awslc', 'libssl-awslc'})
RUNTIME_PACKAGES = frozenset({'docker-ce', 'docker-ce-cli', 'docker.io', 'docker-ce-rootless-extras',
                              'containerd', 'containerd.io', 'runc',
                              'moby-engine', 'moby-cli', 'moby-containerd', 'moby-runc'})
INSTALL = re.compile(r'^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?)'
                     r'(?: \[([^\]]+)\])? \((\S+)(?:\s|\))')
VERSION = re.compile(r'^(?:(\d+):)?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$')
STATE_ROOT = Path('/var/lib/easy-ha-proxy/update-web/os-security')


class UpgradeRefused(RuntimeError):
    pass


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False,
                            env={**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise UpgradeRefused('The package upgrade preflight failed: ' + Path(argv[0]).name)
    return result.stdout


def patch_line(version):
    match = VERSION.fullmatch(version or '')
    if not match or re.search(r'(?:[~+-])(?:rc|alpha|beta)(?:[.\d-]|$)', version):
        return None
    # Epoch and release line must stay unchanged, including Docker's minor
    # release: live-restore supports patch updates, not a new release line.
    return (int(match[1] or 0), int(match[2]), int(match[3]))


def validate(selections, simulation, *, automatic=False):
    for line in selections.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].split(':', 1)[0] in HAPROXY_PACKAGES:
            if fields[1] not in {'hold', 'deinstall', 'purge'}:
                raise UpgradeRefused('HAProxy package protection is missing: ' + fields[0])
    runtimes = []
    for line in simulation.splitlines():
        if line.startswith('Remv '):
            raise UpgradeRefused('An OS upgrade must not remove packages')
        if not line.startswith('Inst '):
            continue
        match = INSTALL.match(line)
        if not match:
            raise UpgradeRefused('An APT package candidate could not be verified')
        package, installed, candidate = match.groups()
        name = package.split(':', 1)[0]
        if name in HAPROXY_PACKAGES:
            raise UpgradeRefused('HAProxy packages must be updated separately: ' + package)
        if automatic and name in RUNTIME_PACKAGES:
            if patch_line(installed) is None or patch_line(installed) != patch_line(candidate):
                raise UpgradeRefused('Automatic OS installation requires manual review of '
                                     f'{package}: {installed or "not installed"} -> {candidate}. '
                                     'Only patch updates within the installed runtime release line are automatic.')
            runtimes.append(package)
    return runtimes


def record_attempt(root, *, now=None):
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.package-install.', dir=root)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({'last_install_attempt': time.time() if now is None else now}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / 'package-install.json')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(*, automatic=False, root=STATE_ROOT):
    selections = run(['/usr/bin/dpkg', '--get-selections'])
    # Match Ansible's force_apt_get + upgrade=yes, including new dependencies.
    simulation = run(['/usr/bin/apt-get', '-s', '--with-new-pkgs', 'upgrade'])
    runtimes = validate(selections, simulation, automatic=automatic)
    if runtimes:
        # The operator may have disabled live-restore in their configuration.
        # Do not turn that into an unattended Docker outage.
        live = run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                    'info', '--format', '{{.LiveRestoreEnabled}}'])
        if live.strip().lower() != 'true':
            raise UpgradeRefused('Automatic runtime updates require verified Docker live-restore')
    record_attempt(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--automatic', action='store_true')
    parser.add_argument('--state-root', type=Path, default=STATE_ROOT)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('OS upgrade preflight requires root')
    try:
        prepare(automatic=args.automatic, root=args.state_root)
    except (UpgradeRefused, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
