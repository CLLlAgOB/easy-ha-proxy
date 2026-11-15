"""Guard APT upgrades and record them for restart scheduling.

Run by the update_packages role after refreshing APT metadata, immediately
before installation. The automatic path permits only runtime patch updates;
manual upgrades retain the operator's explicit choice. With a verified unified
window lease this helper also installs packages and restores containers.
An attempt is recorded before APT so partial failures and an interrupted play
still invalidate earlier service-restart evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
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
MAINTENANCE_LOCK = Path('/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock')
DPKG_FRONTEND_LOCK = Path('/var/lib/dpkg/lock-frontend')
RUNTIME_CONFIG_FILES = ('/etc/docker/daemon.json', '/opt/authelia/docker-compose.yml', '/opt/haproxy-admin/docker-compose.yml')


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


def validate(selections, simulation, *, automatic=False, allow_runtime_change=False):
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
            if (patch_line(installed) is None or patch_line(candidate) is None
                    or not allow_runtime_change and patch_line(installed) != patch_line(candidate)):
                raise UpgradeRefused('Automatic OS installation requires manual review of '
                                     f'{package}: {installed or "not installed"} -> {candidate}. '
                                     'Only patch updates within the installed runtime release line are automatic.')
            runtimes.append(package)
    return runtimes


def write_record(path, value):
    root = path.parent
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=root)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def record_attempt(root, *, now=None):
    write_record(root / 'package-install.json', {'last_install_attempt': time.time() if now is None else now})


def runtime_consent(root, revision, deadline, *, reserve=0, require_runtime=True, local=None):
    from datetime import datetime, timedelta, time as clocktime
    from zoneinfo import ZoneInfo
    path = root.parent / 'settings.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 1024 * 1024:
        raise UpgradeRefused('Unsafe runtime maintenance consent')
    settings = json.loads(path.read_text())
    if local is None:
        with open('/etc/localtime', 'rb') as stream:
            local = datetime.now(ZoneInfo.from_file(stream))
    start, end = settings.get('auto_install_start'), settings.get('auto_install_end')
    hours_valid = type(start) is int and type(end) is int and 0 <= start < 24 and 0 <= end < 24 and start != end
    if not hours_valid:
        raise UpgradeRefused('Invalid runtime maintenance window')
    day = local.date() - timedelta(days=local.hour < start)
    opened = datetime.combine(day, clocktime(start), local.tzinfo).timestamp()
    closed = datetime.combine(day + timedelta(days=end <= start), clocktime(end), local.tzinfo).timestamp()
    updated = settings.get('maintenance_updated_at')
    inside = (opened <= local.timestamp() < closed and type(updated) in (int, float)
              and 0 < updated <= opened and abs(deadline - closed) < 1)
    if (not inside or settings.get('auto_install') is not True or settings.get('auto_install_unified') is not True
            or require_runtime and settings.get('auto_install_runtime') is not True or settings.get('maintenance_revision') != revision
            or not time.time() + reserve < deadline <= time.time() + 86400):
        raise UpgradeRefused('Runtime maintenance consent was revoked or its window has closed')


def run_upgrade(argv):
    # Do not use the end of the window as a dpkg timeout. The enclosing host
    # systemd job retains its normal emergency timeout; installation finishes
    # and stopped containers are restored even if the allowed window closes.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                check=False, env={**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
        output.seek(0, os.SEEK_END)
        output.seek(max(0, output.tell() - 128 * 1024))
        print(re.sub(r'https?://\S+', '[repository]', output.read().decode('utf-8', 'replace')), flush=True)
    if result.returncode:
        raise UpgradeRefused('OS package installation failed; inspect the package-manager state')


def container_state(identity):
    template = ('{"id":{{json .Id}},"name":{{json .Name}},"status":{{json .State.Status}},'
                '"paused":{{json .State.Paused}},"health":'
                '{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}')
    value = json.loads(run(['/usr/bin/docker', 'inspect', '--format', template, identity]))
    if not re.fullmatch('[0-9a-f]{64}', str(value.get('id', ''))):
        raise UpgradeRefused('A container identity could not be verified')
    return value


def running_containers():
    identities = run(['/usr/bin/docker', 'ps', '--no-trunc', '-q']).split()
    if len(identities) > 256 or any(not re.fullmatch('[0-9a-f]{64}', value) for value in identities):
        raise UpgradeRefused('The running container set could not be verified')
    result = [container_state(identity) for identity in identities]
    if any(item['status'] != 'running' or item['paused'] or item['health'] not in (None, 'healthy') for item in result):
        raise UpgradeRefused('Resolve unhealthy, restarting or paused containers before runtime maintenance')
    return result


def restore_containers(containers):
    run(['/usr/bin/systemctl', 'start', 'docker.service'])
    for item in containers:
        current = container_state(item['id'])
        if current['status'] != 'running':
            run(['/usr/bin/docker', 'start', item['id']])
    until = time.monotonic() + 180
    while True:
        states = [container_state(item['id']) for item in containers]
        if all(item['status'] == 'running' and not item['paused'] and item['health'] in (None, 'healthy') for item in states):
            return
        if time.monotonic() >= until:
            raise UpgradeRefused('Some containers did not recover; further runtime updates require operator recovery')
        time.sleep(2)


def perform_maintenance(root, revision, deadline, *, allow_runtime_change=True):
    journal = root / 'runtime-maintenance.json'
    if journal.exists() and json.loads(journal.read_text()).get('phase') not in {'completed', 'recovered'}:
        raise UpgradeRefused('Previous runtime maintenance requires recovery before another upgrade')
    runtime_consent(root, revision, deadline, require_runtime=allow_runtime_change)
    selections = run(['/usr/bin/dpkg', '--get-selections'])
    simulation = run(['/usr/bin/apt-get', '-s', '--with-new-pkgs', 'upgrade'])
    runtimes = validate(selections, simulation, automatic=True, allow_runtime_change=allow_runtime_change)
    if runtimes and not allow_runtime_change:
        if run(['/usr/bin/docker', 'info', '--format', '{{.LiveRestoreEnabled}}']).strip().lower() != 'true':
            raise UpgradeRefused('Automatic runtime patch updates require Docker live-restore')
    changes = [match for line in simulation.splitlines() if (match := INSTALL.match(line))
               and match[1].split(':', 1)[0] in RUNTIME_PACKAGES and patch_line(match[2]) != patch_line(match[3])]
    if runtimes and run(['/usr/bin/docker', 'info', '--format', '{{.Swarm.LocalNodeState}}']).strip() == 'active':
        raise UpgradeRefused('Automatic runtime maintenance does not support Docker Swarm')
    # Fetch before causing downtime. A slow mirror may consume the window;
    # consent and the restore reserve are checked again after the download.
    run_upgrade(['/usr/bin/apt-get', '-y', '--download-only', '--with-new-pkgs', 'upgrade'])
    runtime_consent(root, revision, deadline, reserve=600 if changes else 0, require_runtime=allow_runtime_change)
    reviewed = [line for line in simulation.splitlines() if line.startswith(('Inst ', 'Remv '))]
    latest = run(['/usr/bin/apt-get', '-s', '--with-new-pkgs', 'upgrade'])
    if reviewed != [line for line in latest.splitlines() if line.startswith(('Inst ', 'Remv '))]:
        raise UpgradeRefused('APT candidates changed during download; runtime maintenance was deferred')
    containers = running_containers() if runtimes else []
    record = {'phase': 'prepared', 'revision': revision, 'containers': containers, 'started_at': time.time()}
    if runtimes:
        backup = root / ('runtime-backup-' + str(int(time.time())))
        backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        for index, source in enumerate(RUNTIME_CONFIG_FILES):
            path = Path(source)
            if path.is_file() and not path.is_symlink():
                target = backup / f'{index}-{path.name}'
                shutil.copyfile(path, target)
                target.chmod(0o600)
                with target.open('rb') as stream:
                    os.fsync(stream.fileno())
        descriptor = os.open(backup, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        record['backup'] = str(backup)
        write_record(journal, record)
    failure = None
    installation_started = False
    try:
        if changes:
            record['phase'] = 'stopping'
            write_record(journal, record)
            if containers:
                run(['/usr/bin/docker', 'stop', '--time', '60', *[item['id'] for item in containers]])
            if run(['/usr/bin/docker', 'ps', '-q']).strip():
                raise UpgradeRefused('New containers appeared during maintenance; the upgrade was refused')
        runtime_consent(root, revision, deadline, require_runtime=allow_runtime_change)
        record_attempt(root)
        record['phase'] = 'upgrading'
        if runtimes:
            write_record(journal, record)
        installation_started = True
        run_upgrade(['/usr/bin/apt-get', '-y', '--no-remove', '--with-new-pkgs',
                     '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', 'upgrade'])
    except Exception as error:
        failure = error
    finally:
        if runtimes:
            record['phase'] = 'restoring'
            try:
                write_record(journal, record)
            except OSError:
                pass  # A failed journal write must never prevent restoring containers.
            try:
                restore_containers(containers)
                # A refusal before APT started needs no package recovery once
                # the original containers are healthy again. Allow next night's
                # cycle, while retaining the refusal in the journal.
                phase = ('failed' if installation_started else 'recovered') if failure else 'completed'
                record.update(phase=phase, restored=True, installation_started=installation_started,
                              completed_at=time.time())
                if failure:
                    record['error'] = str(failure)
            except Exception as error:
                record.update(phase='recovery_required', restored=False, error=str(error), completed_at=time.time())
                failure = error
            write_record(journal, record)
    if failure:
        raise UpgradeRefused(str(failure)) from failure


def recover_runtime(root):
    import fcntl
    MAINTENANCE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(MAINTENANCE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w') as custody:
        try:
            fcntl.flock(custody, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpgradeRefused('Another maintenance operation is active; wait before runtime recovery') from None
        journal = root / 'runtime-maintenance.json'
        record = json.loads(journal.read_text())
        containers = record.get('containers')
        if (not isinstance(containers, list) or len(containers) > 256
                or any(not isinstance(item, dict) or not re.fullmatch('[0-9a-f]{64}', str(item.get('id', ''))) for item in containers)):
            raise UpgradeRefused('Unsafe runtime recovery record')
        # A previous child may still be finishing dpkg after a broker failure.
        # Recovery restores containers only; it never installs/downgrades packages.
        with open(DPKG_FRONTEND_LOCK, 'r+') as lock:
            try:
                fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UpgradeRefused('APT is still active; wait before runtime recovery') from None
            restore_containers(containers)
            record.update(phase='recovered', restored=True, recovered_at=time.time())
            write_record(journal, record)


def prepare(*, automatic=False, root=STATE_ROOT):
    journal = root / 'runtime-maintenance.json'
    if journal.exists() and json.loads(journal.read_text()).get('phase') not in {'completed', 'recovered'}:
        raise UpgradeRefused('Runtime recovery is required; run os_upgrade_guard.py --recover-runtime')
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
    parser.add_argument('--runtime-maintenance')
    parser.add_argument('--maintenance-revision')
    parser.add_argument('--maintenance-until', type=float)
    parser.add_argument('--recover-runtime', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('OS upgrade preflight requires root')
    try:
        if args.recover_runtime:
            recover_runtime(args.state_root)
        elif args.runtime_maintenance is not None or args.maintenance_revision is not None:
            revision = args.runtime_maintenance or args.maintenance_revision
            if (not args.automatic or not re.fullmatch('[0-9a-f]{32}', revision)
                    or args.maintenance_until is None):
                raise UpgradeRefused('Runtime maintenance requires a valid automatic window lease')
            perform_maintenance(args.state_root, revision, args.maintenance_until,
                                allow_runtime_change=args.runtime_maintenance is not None)
        else:
            prepare(automatic=args.automatic, root=args.state_root)
    except (UpgradeRefused, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
