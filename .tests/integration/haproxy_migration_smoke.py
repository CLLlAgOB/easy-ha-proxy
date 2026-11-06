"""Real package/reload/rollback qualification on disposable Ubuntu 24.04 only.

--systemd uses the real service manager on a GitHub runner. The container mode
uses the same migration engine and real APT/HAProxy processes, with a small
service adapter because a normal Docker container has no systemd PID 1.
"""
from __future__ import annotations

import argparse
import atexit
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('package_migration', ROOT / 'installer/haproxy_package_migrate.py')
migration = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = migration
spec.loader.exec_module(migration)


class ProcessHost(migration.Host):
    def __init__(self):
        super().__init__()
        self.process = None
        self.seeds = {}
        self.services = {'haproxy-controld.service', 'easy-ha-proxy-guardd.service', 'apt-daily.timer'}
        self.output = open('/tmp/migration-fixture-process.log', 'a')

    def command(self, args, **kwargs):
        if args[0] == '/usr/bin/systemctl':
            return subprocess.CompletedProcess(args, 0, '', '')
        return super().command(args, **kwargs)

    def active(self, unit):
        if unit == 'haproxy.service':
            return self.process is not None and self.process.poll() is None
        return unit in self.services

    def main_pid(self):
        return self.process.pid if self.active('haproxy.service') else 0

    def service(self, action, unit='haproxy.service'):
        if unit in self.seeds and action == 'stop':
            process = self.seeds.pop(unit)
            process.terminate()
            process.wait(timeout=10)
            return
        if unit == 'haproxy.service':
            if action == 'reload':
                self.process.send_signal(signal.SIGUSR2)
                return
            if self.active(unit):
                self.process.terminate()
                self.process.wait(timeout=10)
            if action in ('start', 'restart'):
                self.process = subprocess.Popen(['/usr/sbin/haproxy', '-W', '-db', '-f', '/etc/haproxy/haproxy.cfg'],
                                                stdout=self.output, stderr=self.output)
            return
        if action == 'stop':
            self.services.discard(unit)
        else:
            self.services.add(unit)

    def machine(self):
        return 'disposable-container-fixture'

    def worker_digest(self, pid):
        # Docker omits CAP_SYS_PTRACE, so /proc of the unprivileged worker is
        # unreadable. Verify its parent and the actual reexecuted master here;
        # real systemd qualification uses the production worker check directly.
        status = (Path('/proc') / pid / 'status').read_text()
        if '\nPPid:\t' + str(self.process.pid) + '\n' not in status:
            raise RuntimeError('Fixture worker does not belong to this master')
        return migration.digest(Path('/proc') / str(self.process.pid) / 'exe')

    def control_journal(self, default):
        return default

    def guard_database(self):
        return Path('/var/lib/easy-ha-proxy/security/security.db')

    def start_seed(self, directory, unit):
        self.seeds[unit + '.service'] = subprocess.Popen(
            [str(directory / 'baseline-haproxy'), '-db', '-f', str(directory / 'seed.cfg')],
            stdout=self.output, stderr=self.output)

    def watchdog(self, directory, unit):
        pass

    def cancel_watchdog(self, unit):
        pass

    def close(self):
        for process in list(self.seeds.values()) + ([self.process] if self.process else []):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        self.output.close()


def run(args):
    subprocess.run(args, check=True, capture_output=True, text=True)


def fixture(systemd):
    variables = Path('/etc/easy-ha-proxy/vars.yml')
    marker = Path('/etc/easy-ha-proxy/migration-fixture/owned')
    if variables.exists() and not marker.exists():
        raise RuntimeError('Refusing to replace an existing managed installation')
    if systemd:
        for name in ('haproxy-controld', 'easy-ha-proxy-guardd', 'haproxy-certd'):
            path = Path('/etc/systemd/system') / (name + '.service')
            if path.exists() and not marker.exists():
                raise RuntimeError('Refusing to replace an existing host service')
    base = marker.parent
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    marker.write_text('disposable migration qualification\n')
    variables.write_text('admin_domain: admin.example.test\nkeep_this_setting: preserved\n')
    variables.chmod(0o600)
    database = Path('/var/lib/easy-ha-proxy/security/security.db')
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE IF NOT EXISTS ip_state (ip TEXT PRIMARY KEY, banned_until INTEGER)')
        connection.execute('CREATE TABLE IF NOT EXISTS manual_bans (ip TEXT PRIMARY KEY, expires_at INTEGER)')
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=admin.example.test', '-addext',
         'subjectAltName=DNS:admin.example.test,DNS:auth.example.test',
         '-keyout', str(base / 'key.pem'), '-out', str(base / 'cert.pem')])
    (base / 'combined.pem').write_bytes((base / 'cert.pem').read_bytes() + (base / 'key.pem').read_bytes())
    trust = Path('/usr/local/share/ca-certificates/ehp-migration-fixture.crt')
    trust.write_bytes((base / 'cert.pem').read_bytes())
    run(['update-ca-certificates'])
    Path('/var/lib/haproxy/server-state').write_text('1\n')
    Path('/var/lib/haproxy/server-state').chmod(0o600)
    Path('/run/haproxy').mkdir(exist_ok=True)
    Path('/etc/haproxy/haproxy.cfg').write_text(f'''global
    localpeer ha-local
    nbthread 1
    user haproxy
    group haproxy
    stats socket /run/haproxy/admin.sock mode 600 user root group root level admin
    server-state-file /var/lib/haproxy/server-state
    .if !feature(OPENSSL_AWSLC)
    tune.ssl.default-dh-param 2048
    .endif
    .if version_atleast(3.1)
    tune.lua.bool-sample-conversion normal
    .endif
defaults
    mode http
    timeout connect 1s
    timeout client 5s
    timeout server 5s
    load-server-state-from-file global
peers migration
    peer ha-local 127.0.0.1:19240
backend tbl_ban
    stick-table type ip size 1k expire 30m store gpc0,gpt0 peers migration
backend tbl_ip_auth
    stick-table type ip size 1k expire 30m store gpc0 peers migration
frontend fe_https
    bind 127.0.0.1:443 ssl crt {base}/combined.pem
    acl host_admin hdr(host) -i admin.example.test
    acl host_authelia hdr(host) -i auth.example.test
    http-request return status 200 if host_admin {{ path /api/control-plane-health }}
    http-request redirect location https://auth.example.test/ if host_admin
    http-request return status 200 if host_authelia {{ path /api/health }}
    default_backend be_admin
backend be_admin
    server fixture 127.0.0.1:19999
''')
    if systemd:
        for name in ('haproxy-controld', 'easy-ha-proxy-guardd', 'haproxy-certd'):
            (Path('/etc/systemd/system') / (name + '.service')).write_text(
                '[Unit]\nDescription=Disposable migration qualification fixture\n[Service]\nExecStart=/bin/sleep infinity\n')
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'start', 'haproxy-controld', 'easy-ha-proxy-guardd', 'haproxy-certd'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--systemd', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('EHP_MIGRATION_DISPOSABLE') != '1':
        parser.error('Requires root and EHP_MIGRATION_DISPOSABLE=1 on a disposable system')
    if not args.systemd and not Path('/.dockerenv').exists():
        parser.error('Container adapter can only run in a disposable container')
    fixture(args.systemd)
    host = migration.Host() if args.systemd else ProcessHost()
    if isinstance(host, ProcessHost):
        atexit.register(host.close)
    host.service('restart')
    paths = migration.Paths(source=ROOT)
    engine = migration.Engine(paths, host)
    baseline_packages = host.packages()
    old = baseline_packages['haproxy']
    engine.wait_worker(old)
    engine.health()
    migration.runtime(paths.socket, 'set table tbl_ban key 198.51.100.22 data.gpc0 1 data.gpt0 40')
    migration.runtime(paths.socket, 'set table tbl_ip_auth key 198.51.100.22 data.gpc0 7')
    migration.runtime(paths.socket, 'set server be_admin/fixture state maint')
    migration.runtime(paths.socket, 'set server be_admin/fixture weight 17')
    baseline = paths.config.read_bytes()
    original_variables = paths.variables.read_bytes()
    results = {}
    try:
        prepared = engine.prepare()
        results['exercise'] = engine.apply(prepared['id'], exercise_rollback=True)
        assert results['exercise']['target_verified'] and results['exercise']['rollback_verified']
        assert info_version(paths) == old
        assert paths.config.read_bytes() == baseline
        assert paths.variables.read_bytes() == original_variables
        assert paths.variables.stat().st_mode & 0o777 == 0o600
        assert paths.server_state.stat().st_mode & 0o777 == 0o600
        assert {name: host.packages().get(name) for name in engine.allowed_packages} == {
            name: baseline_packages.get(name) for name in engine.allowed_packages}

        class ColdFailure(migration.Engine):
            fired = False

            def health(self):
                super().health()
                if not self.fired and info_version(self.paths).startswith('3.4.'):
                    self.fired = True
                    self.host.service('stop')
                    raise migration.MigrationError('Injected failed candidate service')

        cold = ColdFailure(paths, host)
        prepared = cold.prepare()
        try:
            cold.apply(prepared['id'])
        except migration.MigrationError:
            pass
        else:
            raise AssertionError('Injected failure unexpectedly succeeded')
        assert cold.fired and cold.state['rollback_verified'] and cold.state['phase'] == 'rolled_back'
        assert info_version(paths) == old
        results['cold_rollback'] = cold.summary()

        engine = migration.Engine(paths, host)
        prepared = engine.prepare()
        results['apply'] = engine.apply(prepared['id'])
        assert results['apply']['phase'] == 'committed'
        assert info_version(paths).startswith('3.4.')
        results['manual_rollback'] = engine.rollback(prepared['id'])
        assert results['manual_rollback']['rollback_verified'] and info_version(paths) == old
        assert paths.variables.read_bytes() == original_variables
        assert paths.config.read_bytes() == baseline
        assert {name: host.packages().get(name) for name in engine.allowed_packages} == {
            name: baseline_packages.get(name) for name in engine.allowed_packages}
        for table in ('tbl_ban', 'tbl_ip_auth'):
            assert len(list(migration.table_rows(paths.socket, table))) == 1
        print(json.dumps(results, indent=2))
    finally:
        if isinstance(host, ProcessHost):
            host.close()


def info_version(paths):
    return migration.info(paths.socket)['Version']


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # These journals contain only this disposable fixture. Emit diagnostics
        # because private-host transaction logs are deliberately never exposed.
        for journal in Path('/var/lib/easy-ha-proxy/haproxy-package-migration').glob('*/transaction.json'):
            state = json.loads(journal.read_text())
            print({key: state.get(key) for key in ('id', 'phase', 'failure', 'rollback_failure')}, file=sys.stderr)
            log = journal.with_name('commands.jsonl')
            if log.exists():
                for line in log.read_text().splitlines():
                    record = json.loads(line)
                    if record['rc']:
                        print(record, file=sys.stderr)
        raise
