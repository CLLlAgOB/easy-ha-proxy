"""Real dpkg patch/reload/rollback against a disposable signed test repository.

The repacked fixture changes package revisions and the exact AWS-LC dependency,
using the installed, real native HAProxy binary. It does not claim to qualify
an unreleased future HAProxy implementation. Never run on an existing gateway.
"""
from __future__ import annotations

import argparse
import email.utils
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'installer'))
import apt_metadata  # noqa: E402

spec = importlib.util.spec_from_file_location('patch_fixture', Path(__file__).with_name('haproxy_migration_smoke.py'))
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
m = fixture.migration


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def repository(base, packages, architecture):
    repo = base / 'repo'
    pool = repo / 'pool'
    pool.mkdir(parents=True)
    records = []
    targets = {}
    for name, version in packages.items():
        run(['apt-get', '-o', 'APT::Get::AllowUnauthenticated=false', 'download', name + '=' + version], cwd=base)
        archive = next(p for p in base.glob('*.deb') if run(['dpkg-deb', '-f', str(p), 'Package']) == name)
        extracted = base / ('unpack-' + name)
        run(['dpkg-deb', '-R', str(archive), str(extracted)])
        control = extracted / 'DEBIAN/control'
        text = control.read_text()
        target = version + '+fixture1'
        text = re.sub(r'^Version: .*$', 'Version: ' + target, text, flags=re.M)
        if name == 'haproxy-awslc':
            text = text.replace('libssl-awslc (= ' + packages['libssl-awslc'] + ')',
                                'libssl-awslc (= ' + packages['libssl-awslc'] + '+fixture1)')
        control.write_text(text)
        output = pool / (name + '.deb')
        run(['dpkg-deb', '--build', str(extracted), str(output)])
        records.append(run(['dpkg-deb', '-f', str(output)]) + '\nFilename: pool/' + output.name
                       + '\nSize: ' + str(output.stat().st_size) + '\nSHA256: ' + m.digest(output) + '\n\n')
        targets[name] = target
    directory = repo / 'dists/noble'
    index = directory / ('main/binary-' + architecture)
    index.mkdir(parents=True)
    (index / 'Packages').write_text(''.join(records))
    (index / 'Packages.gz').write_bytes(gzip.compress((index / 'Packages').read_bytes(), mtime=0))
    release = ('Origin: EHP-Disposable-Fixture\nLabel: EHP-Disposable-Fixture\nSuite: noble\nCodename: noble\n'
               'Date: ' + email.utils.formatdate(usegmt=True) + '\nArchitectures: ' + architecture + '\nComponents: main\nSHA256:\n')
    for path in (index / 'Packages', index / 'Packages.gz'):
        release += ' ' + m.digest(path) + ' ' + str(path.stat().st_size) + ' ' + str(path.relative_to(directory)) + '\n'
    (directory / 'Release').write_text(release)
    keyring = base / 'gnupg'
    keyring.mkdir(mode=0o700)
    gpg = ['gpg', '--homedir', str(keyring), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
    run(gpg + ['--quick-generate-key', 'EHP disposable test <fixture@example.test>', 'rsa2048', 'sign', '0'])
    key = base / 'fixture.asc'
    key.write_text(run(gpg + ['--armor', '--export']))
    key.chmod(0o644)
    run(gpg + ['--yes', '--clearsign', '--output', str(directory / 'InRelease'), str(directory / 'Release')])
    source = Path('/etc/apt/sources.list.d/ehp-disposable-patch.list')
    source.write_text('deb [signed-by=' + str(key) + '] ' + repo.as_uri() + ' noble main\n')
    result = apt_metadata.refresh()
    assert result['fresh'], result
    return repo, key, targets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--systemd', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('EHP_MIGRATION_DISPOSABLE') != '1':
        parser.error('Requires root and EHP_MIGRATION_DISPOSABLE=1 on a disposable machine')
    if not args.systemd and not Path('/.dockerenv').exists():
        parser.error('The adapter requires a disposable container')
    fixture.fixture(args.systemd)
    host = m.Host() if args.systemd else fixture.ProcessHost()
    packages = host.packages()
    name = 'haproxy-awslc' if 'haproxy-awslc' in packages else 'haproxy'
    wanted = {name: packages[name]}
    if name == 'haproxy-awslc':
        wanted['libssl-awslc'] = packages['libssl-awslc']
        Path('/etc/easy-ha-proxy/vars.yml').write_text('haproxy_package_provider: haproxy-technologies\nhaproxy_package_branch: "3.4"\n')
        Path('/etc/easy-ha-proxy/vars.yml').chmod(0o600)
    for package in wanted:
        run(['apt-mark', 'hold', package])
    host.service('restart')
    engine = m.Engine(m.Paths(source=ROOT), host)
    runtime_version = re.search(r'HAProxy version (\S+)', run(['haproxy', '-v']))[1]
    engine.wait_worker(runtime_version)
    m.runtime(engine.paths.socket, 'set table tbl_ban key 198.51.100.22 data.gpc0 1 data.gpt0 40')
    m.runtime(engine.paths.socket, 'set table tbl_ip_auth key 198.51.100.22 data.gpc0 7')
    m.runtime(engine.paths.socket, 'set server be_admin/fixture state maint')
    m.runtime(engine.paths.socket, 'set server be_admin/fixture weight 17')
    base = Path(tempfile.mkdtemp(prefix='ehp-disposable-patch-'))
    base.chmod(0o755)
    try:
        repo, key, targets = repository(base, wanted, run(['dpkg', '--print-architecture']))
        defaults = base / 'source/ansible/roles/haproxy/defaults'
        defaults.mkdir(parents=True)
        (defaults / 'main.yml').write_text('haproxy_community_key_sha256: ' + hashlib.sha256(key.read_bytes()).hexdigest() + '\n')
        paths = m.Paths(source=base / 'source')

        class Patch(m.Engine):
            vendor = repo.as_uri() + '/'
            key_url = key.as_uri()

        baseline_config = paths.config.read_bytes()
        baseline_vars = paths.variables.read_bytes()
        # Ordinary OS updates must leave both the core and its exact TLS
        # dependency held, despite higher signed package candidates existing.
        simulated = run(['apt-get', '-s', 'upgrade'])
        assert not any(re.match(r'^Inst ' + re.escape(package) + r'(?:\s|:)', line)
                       for package in wanted for line in simulated.splitlines()), simulated
        results = {}
        patcher = Patch(paths, host)
        prepared = patcher.prepare_patch(targets[name])
        results['exercise'] = patcher.apply(prepared['id'], exercise_rollback=True)
        assert results['exercise']['rollback_verified'] and host.packages()[name] == wanted[name]

        class Cold(Patch):
            fired = False

            def health(self):
                super().health()
                if not self.fired and self.state.get('phase') == 'installing_target' and self.host.packages()[name] == targets[name]:
                    self.fired = True
                    self.host.service('stop')
                    raise m.MigrationError('Injected unavailable patched worker')

        cold = Cold(paths, host)
        prepared = cold.prepare_patch(targets[name])
        try:
            cold.apply(prepared['id'])
        except m.MigrationError:
            pass
        assert cold.fired and cold.state['rollback_verified']
        results['cold_rollback'] = cold.summary()
        patcher = Patch(paths, host)
        prepared = patcher.prepare_patch(targets[name])
        results['apply'] = patcher.apply(prepared['id'])
        assert host.packages()[name] == targets[name]
        if 'libssl-awslc' in wanted:
            assert host.packages()['libssl-awslc'] == targets['libssl-awslc']
        results['manual_rollback'] = patcher.rollback(prepared['id'])
        assert host.packages()[name] == wanted[name]
        assert paths.config.read_bytes() == baseline_config and paths.variables.read_bytes() == baseline_vars
        for package, version in wanted.items():
            assert host.packages()[package] == version and package in patcher.holds()
        for table in ('tbl_ban', 'tbl_ip_auth'):
            assert len(list(m.table_rows(paths.socket, table))) == 1
        print(json.dumps(results, indent=2))
    finally:
        Path('/etc/apt/sources.list.d/ehp-disposable-patch.list').unlink(missing_ok=True)
        if isinstance(host, fixture.ProcessHost):
            host.close()
        shutil.rmtree(base)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        fixture.diagnostics(error)
        raise
