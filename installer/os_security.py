"""Root-only security updates through the distribution's unattended-upgrades.

No action is taken on deployment. An explicit policy takes custody of the
native upgrade timer; returning to system management restores its prior state.
The worker, not its web broker, holds the maintenance lock through APT.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import functools
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import tempfile
import time

PROTOCOL = 1
SETTINGS_PROTOCOL = 1
ROOT = Path('/var/lib/easy-ha-proxy/update-web/os-security')
LOCK = Path('/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock')
TIMER = 'apt-daily-upgrade.timer'
MODES = frozenset({'system', 'notify', 'auto', 'window', 'daily'})
INTERVALS = (1, 2, 4, 6, 12, 24)
PROTECTED = frozenset({'haproxy', 'haproxy-awslc', 'libssl-awslc', 'docker.io', 'docker-ce',
                       'docker-ce-cli', 'containerd', 'containerd.io', 'runc', 'docker-buildx-plugin',
                       'docker-compose-plugin'})
RESTART_DROPIN = Path('/etc/needrestart/conf.d/easy-ha-proxy-os-security.conf')
APT_GUARD = Path('/etc/apt/apt.conf.d/99-easy-ha-proxy-os-security')
APT_GUARD_CONFIG = ('// Managed by easy-ha-proxy OS security.\nAPT::Periodic::Unattended-Upgrade "0";\n'
                    'Unattended-Upgrade::InstallOnShutdown "false";\nUnattended-Upgrade::Automatic-Reboot "false";\n')
RESTART_CONFIG = ("# Managed by easy-ha-proxy OS security; deferred services remain visible.\n"
                  "$nrconf{override_rc}{qr(^(haproxy|docker|containerd|easy-ha-proxy-updated|easy-ha-proxy-updated-job-[0-9a-f]{12}|easy-ha-proxy-backupd)\\.service$)} = 0;\n")
PREVIOUS_RESTART_CONFIG = RESTART_CONFIG.replace('|easy-ha-proxy-updated-job-[0-9a-f]{12}', '')
PKG = re.compile(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$')


class SecurityError(RuntimeError):
    pass


def local_time():
    from zoneinfo import ZoneInfo
    try:
        with open('/etc/localtime', 'rb') as handle:
            return dt.datetime.now(ZoneInfo.from_file(handle))
    except (OSError, ValueError):
        return dt.datetime.now().astimezone()


def read_json(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or not 0 < info.st_size <= 1024 * 1024):
        raise SecurityError('Unsafe OS security state')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW)) as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SecurityError('OS security state changed while opening')
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SecurityError('Invalid OS security state')
    return value


def atomic(path, value, *, mode=0o600):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, 'w') as handle:
            handle.write(json.dumps(value) + '\n' if isinstance(value, dict) else value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def command(argv, *, timeout=60, env=None, check=True):
    """Bounded memory, no shell, and enough grace for dpkg to stop cleanly."""
    with tempfile.TemporaryFile() as output:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                              env={**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive', **(env or {})},
                              start_new_session=True) as child:
            try:
                child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                raise SecurityError('OS security command timed out; inspect package-manager state') from None
            size = output.tell()
            output.seek(max(0, size - 128 * 1024))
            text = re.sub(r'https?://\S+', '[repository]', output.read().decode('utf-8', 'replace'))
    if check and child.returncode:
        print(text, flush=True)
        raise SecurityError('OS security command failed: ' + Path(argv[0]).name)
    return child.returncode, text


def platform():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro, codename = (release.get(key, '').strip('"') for key in ('ID', 'VERSION_CODENAME'))
    if distro not in {'ubuntu', 'debian'} or not re.fullmatch('[a-z][a-z0-9-]{1,30}', codename):
        raise SecurityError('OS security updates require Ubuntu or Debian with a supported APT setup')
    if not Path('/run/systemd/system').is_dir():
        raise SecurityError('OS security management requires systemd')
    return distro, codename


def security_origin(origin, distro, codename):
    if not origin.trusted:
        return False
    if distro == 'ubuntu':
        return (origin.origin, origin.archive) in {
            ('Ubuntu', codename + '-security'), ('UbuntuESMApps', codename + '-apps-security'),
            ('UbuntuESM', codename + '-infra-security')}
    return (origin.origin == 'Debian' and origin.label == 'Debian-Security'
            and origin.codename == codename + '-security')


def security_packages(cache, distro, codename, compare):
    rows = []
    for package in cache:
        if not package.is_installed:
            continue
        versions = [v for v in package.versions if compare(v.version, package.installed.version) > 0
                    and any(security_origin(o, distro, codename) for o in v.origins)]
        if not versions:
            continue
        target = max(versions, key=functools.cmp_to_key(lambda a, b: compare(a.version, b.version)))
        name = package.fullname
        if not PKG.fullmatch(name):
            raise SecurityError('Invalid APT package name')
        rows.append({'name': name, 'installed': package.installed.version, 'candidate': target.version,
                     'protected': package.name.split(':', 1)[0] in PROTECTED, 'held': package._pkg.selected_state == 2})
    return sorted(rows, key=lambda row: row['name'])


def validate_policy(value):
    if set(value) != {'mode', 'interval', 'start', 'end'} or not isinstance(value.get('mode'), str) or value['mode'] not in MODES:
        raise SecurityError('Invalid OS security policy')
    if type(value['interval']) is not int or value['interval'] not in INTERVALS:
        raise SecurityError('Invalid OS security check interval')
    if any(type(value[key]) is not int or not 0 <= value[key] <= 23 for key in ('start', 'end')) or value['start'] == value['end']:
        raise SecurityError('Invalid OS security installation window')
    return dict(value)


def window_open(policy, now=None):
    hour = (now or dt.datetime.now().astimezone()).hour
    start, end = policy['start'], policy['end']
    if policy['mode'] == 'daily':
        return hour == start
    return start <= hour < end if start < end else hour >= start or hour < end


def scheduled_install(policy, status, now=None):
    local = now or dt.datetime.now().astimezone()
    if policy['mode'] == 'auto':
        return True
    if policy['mode'] not in {'daily', 'window'} or not window_open(policy, local):
        return False
    last = status.get('last_install_at')
    return (policy['mode'] != 'daily' or not last
            or dt.datetime.fromtimestamp(last, local.tzinfo).date() != local.date())


def inspect_settings():
    """Read effective Linux settings without an APT cache, refresh or mutation."""
    platform()
    _, text = command(['/usr/bin/apt-config', 'shell', 'ENABLED', 'APT::Periodic::Enable',
                       'LISTS', 'APT::Periodic::Update-Package-Lists', 'UPGRADE', 'APT::Periodic::Unattended-Upgrade',
                       'REBOOT', 'Unattended-Upgrade::Automatic-Reboot', 'SHUTDOWN', 'Unattended-Upgrade::InstallOnShutdown'], timeout=3)
    values = dict(part.split('=', 1) for part in shlex.split(text) if '=' in part)
    _, text = command(['/usr/bin/systemctl', 'show', TIMER,
                       '--property=LoadState,UnitFileState,ActiveState,TimersCalendar,NextElapseUSecRealtime,RandomizedDelayUSec'], timeout=3)
    timer = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    if timer.get('LoadState') not in {'loaded', 'masked'}:
        raise SecurityError('The native APT upgrade timer is not supported')
    enabled = values.get('ENABLED', '1').lower() not in {'0', 'false', 'no', 'off'}
    from timer_metadata import timer as timer_metadata
    native_timer_info = timer_metadata(TIMER)
    return {'checked_at': time.time(), 'periodic_enabled': enabled, 'next_run_at': native_timer_info['next_run_at'],
            'upgrade_interval': values.get('UPGRADE', '0'), 'lists_interval': values.get('LISTS', '0'),
            'automatic_reboot': values.get('REBOOT', 'false').lower() in {'1', 'true', 'yes', 'on'},
            'install_on_shutdown': values.get('SHUTDOWN', 'false').lower() in {'1', 'true', 'yes', 'on'},
            'timer_enabled': timer.get('UnitFileState'), 'timer_active': timer.get('ActiveState') == 'active',
            'calendar': re.findall(r'OnCalendar=([^;}]*)', timer.get('TimersCalendar', '')),
            'random_delay': timer.get('RandomizedDelayUSec', ''),
            'next_run': timer.get('NextElapseUSecRealtime', ''),
            'automatic_install': enabled and values.get('UPGRADE', '0') != '0'
                and timer.get('ActiveState') == 'active'}


def native_timer():
    _, text = command(['/usr/bin/systemctl', 'show', TIMER, '--property=LoadState,UnitFileState,ActiveState'])
    fields = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    if fields.get('LoadState') not in {'loaded', 'masked'} or fields.get('UnitFileState') not in {'enabled', 'enabled-runtime', 'disabled', 'masked', 'masked-runtime', 'static', 'indirect'}:
        raise SecurityError('The native APT upgrade timer is not supported')
    return {'enabled': fields['UnitFileState'], 'active': fields.get('ActiveState') == 'active'}


def restore_timer(baseline):
    # Never unmask a timer: a baseline mask remains in place throughout.
    if baseline['enabled'] in {'enabled', 'enabled-runtime'}:
        command(['/usr/bin/systemctl', 'enable', *(['--runtime'] if baseline['enabled'] == 'enabled-runtime' else []), TIMER])
    if baseline['active']:
        command(['/usr/bin/systemctl', 'start', TIMER])
    actual = native_timer()
    if actual != baseline:
        raise SecurityError('The native APT timer could not be restored; manual recovery is required')


def assert_native_idle():
    _, text = command(['/usr/bin/systemctl', 'show', 'apt-daily-upgrade.service', '--property=ActiveState', '--value'])
    if text.strip() not in {'inactive', 'failed'}:
        raise SecurityError('Native automatic upgrades are active; wait before changing the policy')


def assert_managed(record, *, allow_previous_guard=False):
    if record.get('phase') != 'ready' or record.get('policy', {}).get('mode') == 'system':
        raise SecurityError('Enable OS security management before installing updates')
    timer = native_timer()
    if timer['active'] or timer['enabled'] not in {'disabled', 'masked', 'masked-runtime', 'static', 'indirect'}:
        raise SecurityError('Native APT timer settings changed; review the OS security policy')
    allowed_guards = {RESTART_CONFIG, PREVIOUS_RESTART_CONFIG} if allow_previous_guard else {RESTART_CONFIG}
    if RESTART_DROPIN.is_symlink() or not RESTART_DROPIN.is_file() or RESTART_DROPIN.read_text() not in allowed_guards:
        raise SecurityError('OS security restart protection changed; review the policy')
    if APT_GUARD.is_symlink() or not APT_GUARD.is_file() or APT_GUARD.read_text() != APT_GUARD_CONFIG:
        raise SecurityError('OS security APT protection changed; review the policy')
    _, effective = command(['/usr/bin/apt-config', 'shell', 'PERIODIC', 'APT::Periodic::Unattended-Upgrade',
                             'SHUTDOWN', 'Unattended-Upgrade::InstallOnShutdown', 'REBOOT', 'Unattended-Upgrade::Automatic-Reboot'])
    if set(effective.splitlines()) != {"PERIODIC='0'", "SHUTDOWN='false'", "REBOOT='false'"}:
        raise SecurityError('Another APT setting overrides managed OS security protection')
    assert_native_idle()


def bootstrap(cache, distro, codename):
    missing = [name for name in ('unattended-upgrades', 'needrestart') if name not in cache or not cache[name].is_installed]
    if not missing:
        return
    from apt_metadata import refresh
    metadata = refresh()
    if not metadata['fresh']:
        raise SecurityError(metadata['error'])
    cache.open(None)
    _, simulation = command(['/usr/bin/apt-get', '-s', '--no-install-recommends', 'install', *missing])
    install = []
    for line in simulation.splitlines():
        if line.startswith('Remv '):
            raise SecurityError('Installing security tools would remove packages')
        if not line.startswith('Inst '):
            continue
        match = re.fullmatch(r'Inst (\S+) \((\S+) .+', line)
        if not match or not PKG.fullmatch(match[1]):
            raise SecurityError('Installing security tools would change existing packages')
        name, version = match[1], match[2]
        versions = [v for v in cache[name].versions if v.version == version]
        official = lambda o: o.trusted and o.origin == ('Ubuntu' if distro == 'ubuntu' else 'Debian') and (
            o.codename in {codename, codename + '-security', codename + '-updates'} or o.archive in {codename, codename + '-security', codename + '-updates'})
        if not versions or not any(official(o) for o in versions[0].origins):
            raise SecurityError('Security tools require signed distribution packages')
        install.append(name + '=' + version)
    if not install or len(install) > 100:
        raise SecurityError('Security-tool installation could not be planned safely')
    _, log = command(['/usr/bin/apt-get', '-y', '--no-remove', '--no-install-recommends', '--no-upgrade', 'install', *install],
                     timeout=1800, env={'NEEDRESTART_MODE': 'l'})
    print(log, flush=True)


def configure(root, value, cache, distro, codename):
    policy = validate_policy(value)
    path = root / 'policy.json'
    old = read_json(path) if path.exists() else None
    if old and old.get('phase') != 'ready' and policy['mode'] != 'system':
        raise SecurityError('Restore system management after the interrupted policy change')
    baseline = old.get('baseline') if old else None
    if policy['mode'] == 'system':
        if baseline:
            timer = native_timer()
            if timer['active'] or timer['enabled'] not in {'disabled', 'masked', 'masked-runtime', 'static', 'indirect'}:
                raise SecurityError('Native APT timer settings changed; refusing to overwrite them')
            atomic(path, {**old, 'phase': 'configuring'})
            for guard_path, expected in ((RESTART_DROPIN, RESTART_CONFIG), (APT_GUARD, APT_GUARD_CONFIG)):
                if os.path.lexists(guard_path):
                    allowed = {expected, PREVIOUS_RESTART_CONFIG} if guard_path == RESTART_DROPIN else {expected}
                    if guard_path.is_symlink() or guard_path.read_text() not in allowed:
                        raise SecurityError('OS security protection changed; review the policy')
                    guard_path.unlink()
            try:
                restore_timer(baseline)
            except Exception:
                atomic(path, {**old, 'phase': 'recovery_required'})
                raise
        atomic(path, {'phase': 'ready', 'policy': policy, 'updated_at': time.time()})
        return
    if old and old.get('policy', {}).get('mode') != 'system' and old.get('phase') == 'ready':
        assert_managed(old, allow_previous_guard=True)
    if not baseline:
        if os.path.lexists(RESTART_DROPIN) or os.path.lexists(APT_GUARD):
            raise SecurityError('The OS security configuration already exists outside panel management')
        baseline = native_timer()
    journal = {'phase': 'configuring', 'baseline': baseline, 'policy': policy, 'updated_at': time.time()}
    atomic(path, journal)
    try:
        command(['/usr/bin/systemctl', 'stop', TIMER])
        current = native_timer()
        if current['active']:
            raise SecurityError('The native APT timer could not be stopped')
        assert_native_idle()
        if current['enabled'] in {'enabled', 'enabled-runtime'}:
            command(['/usr/bin/systemctl', 'disable', *(['--runtime'] if current['enabled'] == 'enabled-runtime' else []), TIMER])
        atomic(RESTART_DROPIN, RESTART_CONFIG, mode=0o644)
        atomic(APT_GUARD, APT_GUARD_CONFIG, mode=0o644)
        bootstrap(cache, distro, codename)
        journal['phase'] = 'ready'
        assert_managed(journal)
        atomic(path, journal)
    except Exception:
        # The durable journal survives even an interrupted rollback. The
        # operator can choose "system" again; no package downgrade is tried.
        try:
            if old and old.get('policy', {}).get('mode') != 'system':
                atomic(path, old)
            else:
                for guard_path, expected in ((RESTART_DROPIN, RESTART_CONFIG), (APT_GUARD, APT_GUARD_CONFIG)):
                    if guard_path.is_file() and not guard_path.is_symlink() and guard_path.read_text() == expected:
                        guard_path.unlink()
                restore_timer(baseline)
                atomic(path, old or {'phase': 'ready', 'policy': {'mode': 'system', 'interval': 4, 'start': 3, 'end': 5}})
        except Exception:
            atomic(path, {**journal, 'phase': 'recovery_required'})
        raise


def apt_environment(directory, distro, codename):
    """Read normal APT configuration, then clear lists before restricting it.

    APT_CONFIG alone loads *before* apt.conf.d. Redirecting its main file is
    necessary to prevent a pre-existing PPA policy or reboot option winning.
    """
    main = directory / 'main.conf'
    patterns = ([f'origin=Ubuntu,archive={codename}-security', f'origin=UbuntuESMApps,archive={codename}-apps-security',
                 f'origin=UbuntuESM,archive={codename}-infra-security'] if distro == 'ubuntu' else
                [f'origin=Debian,label=Debian-Security,codename={codename}-security'])
    base = '#include "/etc/apt/apt.conf";\n' if Path('/etc/apt/apt.conf').is_file() else ''
    base += '#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n'
    base += 'Unattended-Upgrade::Origins-Pattern { ' + ' '.join('"' + p + '";' for p in patterns) + ' };\n'
    base += 'Unattended-Upgrade::Package-Blacklist { ' + ' '.join('"^' + n.replace('.', '[.]') + '(:[a-z0-9]+)?$";' for n in sorted(PROTECTED)) + ' };\n'
    base += 'APT::Get::AllowUnauthenticated "false";\nAcquire::AllowInsecureRepositories "false";\n'
    base += 'APT::Ignore-Hold "false";\nAPT::Get::allow-change-held-packages "false";\n'
    base += '\n'.join('Unattended-Upgrade::' + name + ' "false";' for name in (
        'Automatic-Reboot', 'Automatic-Reboot-WithUsers', 'InstallOnShutdown', 'Remove-Unused-Dependencies',
        'Remove-New-Unused-Dependencies', 'Remove-Unused-Kernel-Packages', 'Allow-downgrade', 'Allow-APT-Mark-Fallback')) + '\n'
    # A root-defined binary-specific subtree is loaded after main.conf too.
    # Refuse one for this executor instead of silently weakening the policy.
    base += '#clear Binary::unattended-upgrade;\n#clear Binary::unattended-upgrades;\n'
    atomic(main, base)
    initial = directory / 'initial.conf'
    atomic(initial, 'Dir::Etc::main "' + str(main) + '";\n')
    return {'APT_CONFIG': str(initial), 'NEEDRESTART_MODE': 'a'}


def restart_status():
    reboot = Path('/run/reboot-required').exists()
    services, error = [], None
    if Path('/usr/sbin/needrestart').is_file():
        code, text = command(['/usr/sbin/needrestart', '-b', '-r', 'l'], timeout=60, check=False)
        if code:
            error = 'The restart check failed'
        else:
            services = sorted(set(re.findall(r'^NEEDRESTART-SVC:\s*(\S+)\s*$', text, re.M)))[:100]
            match = re.search(r'^NEEDRESTART-KSTA:\s*([0-9]+)', text, re.M)
            if match and int(match[1]) in {1, 2, 3}:
                reboot = reboot or int(match[1]) > 1
            else:
                error = 'The kernel restart state is unknown'
    else:
        error = 'The restart checker is not installed'
    # needrestart's override_rc can omit deliberately deferred services from
    # its batch list. Inspect their deleted executable/library mappings too.
    for service in ('haproxy', 'docker', 'containerd', 'easy-ha-proxy-updated', 'easy-ha-proxy-backupd'):
        code, text = command(['/usr/bin/systemctl', 'show', service + '.service', '--property=MainPID', '--value'], check=False)
        if not code and text.strip().isdigit() and int(text.strip()) > 0:
            try:
                process = Path('/proc') / text.strip()
                if '(deleted)' in os.readlink(process / 'exe') or ' (deleted)' in (process / 'maps').read_text():
                    services.append(service + '.service')
            except OSError:
                error = 'A running service could not be checked for replaced libraries'
    return {'reboot_required': reboot, 'services': sorted(set(services)), 'error': error, 'checked_at': time.time()}


def maintenance_guard(*, allow_web_reboot=False):
    for name in ('easy-ha-proxy-web-reboot.json', 'reboot-scheduled', 'easy-ha-proxy-backupd-restore.active'):
        if name == 'easy-ha-proxy-web-reboot.json' and allow_web_reboot:
            continue  # Only the final executor calls this after verifying its own marker.
        if os.path.lexists(Path('/run/easy-ha-proxy') / name):
            raise SecurityError('Another maintenance or reboot operation is pending')
    for name in ('last-update.json', 'last-migration.json'):
        path = Path('/var/lib/easy-ha-proxy/haproxy-package-migration') / name
        if os.path.lexists(path):
            operation = read_json(path)
            if operation.get('phase') not in {'committed', 'rolled_back', 'aborted', 'preparing', 'prepared'}:
                raise SecurityError('Recover the unfinished HAProxy operation before OS maintenance')
    marker = Path('/opt/haproxy-admin/backups/haproxy/pending_ui_transaction.json')
    if os.path.lexists(marker):
        raise SecurityError('Resolve pending HAProxy configuration changes before OS maintenance')
    transaction = Path('/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json')
    if os.path.lexists(transaction) and read_json(transaction).get('state') not in {'confirmed', 'rolled_back'}:
        raise SecurityError('Resolve pending HAProxy configuration changes before OS maintenance')
    code, text = command(['/usr/bin/dpkg', '--audit'])
    if code or text.strip():
        raise SecurityError('The package manager needs recovery before OS security updates')
    # A crashed executor may have left a package process stopping. These are
    # POSIX APT locks, not the separate application maintenance flock.
    for path in ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock'):
        if not Path(path).exists():
            continue
        with open(path, 'r+') as lock:
            try:
                fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SecurityError('APT is busy; retry OS security maintenance later') from None
            fcntl.lockf(lock, fcntl.LOCK_UN)


def reload_apt_config(apt_pkg):
    # Configuration.clear needs a key; an empty key does not clear the root.
    for key in apt_pkg.config.list():
        apt_pkg.config.clear(key)
    apt_pkg.init_config()
    apt_pkg.init_system()


def installer_available():
    return Path('/usr/bin/unattended-upgrade').is_file()


def run(action, root, requested=None):
    distro, codename = platform()
    try:
        import apt
        import apt_pkg
    except ImportError:
        raise SecurityError('Update host services to install python3-apt before using OS security management') from None
    reload_apt_config(apt_pkg)
    maintenance_guard()
    cache = apt.Cache()
    if action == 'configure':
        configure(root, requested, cache, distro, codename)
        reload_apt_config(apt_pkg)
        path = root / 'status.json'
        status = read_json(path) if path.exists() else {'state': 'unverified'}
        status.update(native_timer=native_timer(), native_policy={
            'periodic': apt_pkg.config.find('APT::Periodic::Unattended-Upgrade', '0'),
            'reboot': apt_pkg.config.find_b('Unattended-Upgrade::Automatic-Reboot', False),
            'shutdown': apt_pkg.config.find_b('Unattended-Upgrade::InstallOnShutdown', False)})
        atomic(path, status)
        return {'message': 'OS security policy saved'}
    policy = read_json(root / 'policy.json') if (root / 'policy.json').exists() else {'phase': 'ready', 'policy': {'mode': 'system', 'interval': 4, 'start': 3, 'end': 5}}
    value = validate_policy(policy['policy'])
    if action in {'install', 'cycle'}:
        assert_managed(policy)
    elif policy.get('phase') != 'ready':
        raise SecurityError('Restore system management after the interrupted policy change')
    if value['mode'] != 'system':
        assert_managed(policy)
    status_path = root / 'status.json'
    previous = read_json(status_path) if status_path.exists() else {}
    state = {**previous, 'state': 'checking', 'error': None, 'last_attempt': time.time(), 'platform': distro + ' ' + codename}
    if action == 'install' or action == 'cycle' and scheduled_install(value, previous):
        state['last_install_attempt'] = time.time()
    atomic(status_path, state)
    try:
        from apt_metadata import refresh
        print('EHP-PROGRESS phase=checking', flush=True)
        metadata = refresh()
        if not metadata['fresh']:
            raise SecurityError(metadata['error'])
        cache.open(None)
        before = security_packages(cache, distro, codename, apt_pkg.version_compare)
        install = action == 'install' or action == 'cycle' and scheduled_install(value, previous)
        if install:
            state['last_install_attempt'] = time.time()
            atomic(status_path, state)
            assert_managed(policy)
            if not installer_available():
                raise SecurityError('The security installer is not installed; save the policy again')
            if any(not row['protected'] and not row['held'] for row in before):
                print('EHP-PROGRESS phase=playbook', flush=True)
                with tempfile.TemporaryDirectory(prefix='os-security-', dir=root) as temporary:
                    _, log = command(['/usr/bin/unattended-upgrade', '--verbose', '--minimal-upgrade-steps'], timeout=5400,
                                     env=apt_environment(Path(temporary), distro, codename))
                    print(log, flush=True)
            cache.open(None)
        after = security_packages(cache, distro, codename, apt_pkg.version_compare)
        remaining = {row['name']: row for row in after}
        installed = sum(row['name'] not in remaining or apt_pkg.version_compare(remaining[row['name']]['installed'], row['installed']) > 0 for row in before) if install else 0
        state.update(state='ready', error=None, checked_at=time.time(), packages=after[:200], package_count=len(after),
                     eligible_count=sum(not row['protected'] and not row['held'] for row in after),
                     restart=restart_status(), native_timer=native_timer(), installed_count=installed,
                     native_policy={'periodic': apt_pkg.config.find('APT::Periodic::Unattended-Upgrade', '0'),
                                    'reboot': apt_pkg.config.find_b('Unattended-Upgrade::Automatic-Reboot', False),
                                    'shutdown': apt_pkg.config.find_b('Unattended-Upgrade::InstallOnShutdown', False)},
                     last_install_at=time.time() if install else previous.get('last_install_at'),
                     last_success=time.time())
        atomic(status_path, state)
        return {'message': 'OS security installation finished; review remaining updates and restarts' if install else 'OS security check completed', **state}
    except Exception as error:
        atomic(status_path, {**state, 'state': 'unknown', 'error': str(error)[:500]})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install', 'cycle', 'configure', 'inspect'))
    parser.add_argument('--state-root', type=Path, default=ROOT)
    parser.add_argument('--maintenance-lock', type=Path, default=LOCK)
    parser.add_argument('--mode', choices=sorted(MODES))
    parser.add_argument('--interval', type=int, default=4)
    parser.add_argument('--start', type=int, default=3)
    parser.add_argument('--end', type=int, default=5)
    parser.add_argument('--request-id', default='')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('OS security maintenance must run as root')
    os.umask(0o077)
    try:
        if args.action == 'inspect':
            print(json.dumps({'ok': True, **inspect_settings()}), flush=True)
            return 0
        os.nice(10)
        if Path('/usr/bin/ionice').is_file():
            command(['/usr/bin/ionice', '-c', '2', '-n', '7', '-p', str(os.getpid())], check=False)
        args.maintenance_lock.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(os.open(args.maintenance_lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = run(args.action, args.state_root, {'mode': args.mode, 'interval': args.interval, 'start': args.start, 'end': args.end})
        print(json.dumps({'ok': True, 'request_id': args.request_id, **result}), flush=True)
        return 0
    except (SecurityError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
