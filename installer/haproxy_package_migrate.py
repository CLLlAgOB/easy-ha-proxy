"""Explicit, root-only HAProxy provider migration; never part of an OS update.

Prepare downloads authenticated packages without changing system APT sources.
Apply uses only those local packages and keeps a temporary HAProxy peer alive
until the new worker, critical tables and control plane have been verified.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
from dataclasses import dataclass
import email.utils
import fcntl
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

import yaml


class MigrationError(RuntimeError):
    pass


class RollbackExercise(MigrationError):
    pass


@dataclass(frozen=True)
class Paths:
    root: Path = Path('/var/lib/easy-ha-proxy/haproxy-package-migration')
    config: Path = Path('/etc/haproxy/haproxy.cfg')
    variables: Path = Path('/etc/easy-ha-proxy/vars.yml')
    server_state: Path = Path('/var/lib/haproxy/server-state')
    socket: Path = Path('/run/haproxy/admin.sock')
    lock: Path = Path('/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock')
    control_state: Path = Path('/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json')
    policy: Path = Path('/usr/sbin/policy-rc.d')
    repository: Path = Path('/etc/apt/sources.list.d/easy-ha-proxy-haproxy.list')
    priorities: Path = Path('/etc/apt/preferences.d/easy-ha-proxy-haproxy')
    signing_key: Path = Path('/usr/share/keyrings/easy-ha-proxy-haproxy-community.asc')
    binary: Path = Path('/usr/sbin/haproxy')
    source: Path = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def atomic(path: Path, data: bytes, mode=0o600, uid=0, gid=0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise MigrationError('Migration state must be a root-owned directory')
    os.chmod(path, 0o700)


def lines_from_socket(path: Path, command: str):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        connection.sendall((command + '\n').encode())
        connection.shutdown(socket.SHUT_WR)
        with connection.makefile('r', encoding='utf-8', errors='strict') as stream:
            for line in stream:
                if len(line) > 1024 * 1024:
                    raise MigrationError('Unexpectedly large Runtime API line')
                yield line.rstrip('\r\n')


def runtime(path: Path, command: str) -> str:
    return '\n'.join(lines_from_socket(path, command))


def info(path: Path) -> dict[str, str]:
    return dict(line.split(': ', 1) for line in lines_from_socket(path, 'show info') if ': ' in line)


def table_rows(path: Path, table: str):
    header = False
    for line in lines_from_socket(path, 'show table ' + table):
        if not line:
            continue
        if line.startswith('# table: ' + table + ', type: ip,'):
            header = True
            continue
        if not header:
            raise MigrationError('Unexpected critical-table response')
        fields = dict(item.split('=', 1) for item in line.split() if '=' in item)
        try:
            address = str(ipaddress.IPv4Address(fields['key']))
            expiry = int(fields['exp'])
            counters = {key: int(fields[key]) for key in ('gpc0', 'gpt0') if key in fields}
            if 'gpc0' not in counters or (table == 'tbl_ban' and 'gpt0' not in counters):
                raise ValueError('missing counter')
            if any(value < 0 or value > 0xffffffff for value in counters.values()):
                raise ValueError('invalid counter')
        except (KeyError, ValueError) as error:
            raise MigrationError('Invalid critical-table entry') from error
        yield address, expiry, counters
    if not header:
        raise MigrationError('Critical table is missing')


def snapshot_tables(path: Path, destination: Path, tables: dict) -> dict[str, int]:
    temporary = destination.with_suffix('.new.sqlite')
    if temporary.exists():
        temporary.unlink()
    counts = {}
    with sqlite3.connect(temporary) as database:
        database.execute('CREATE TABLE entries (tab TEXT, ip TEXT, expiry INTEGER, gpc0 INTEGER, gpt0 INTEGER, seen INTEGER DEFAULT 0, PRIMARY KEY(tab,ip))')
        for table in tables:
            count = 0
            for address, remaining, counters in table_rows(path, table):
                database.execute('INSERT INTO entries(tab,ip,expiry,gpc0,gpt0) VALUES(?,?,?,?,?)',
                                 (table, address, int(time.time() * 1000) + remaining,
                                  counters['gpc0'], counters.get('gpt0')))
                count += 1
            counts[table] = count
        database.commit()
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    return counts


def verify_tables(path: Path, snapshot: Path, tables: dict) -> dict[str, int]:
    """Compare without loading a large IP table into Python memory.

    An active authenticated client can legitimately increment gpc0 and renew its
    auth lifetime. With an unchanged counter the lifetime must not be reset.
    """
    changed = extended = missing = 0
    marker = time.time_ns()
    with sqlite3.connect(snapshot) as database:
        for table in tables:
            for address, remaining, counters in table_rows(path, table):
                row = database.execute('SELECT expiry,gpc0,gpt0 FROM entries WHERE tab=? AND ip=?',
                                       (table, address)).fetchone()
                if row is None or row[0] <= int(time.time() * 1000) + 1000:
                    continue
                database.execute('UPDATE entries SET seen=? WHERE tab=? AND ip=?', (marker, table, address))
                auth_renewed = table == 'tbl_ip_auth' and counters['gpc0'] > row[1]
                if counters['gpc0'] < row[1] or (table == 'tbl_ban' and counters.get('gpt0') != row[2]):
                    changed += 1
                if not auth_renewed and int(time.time() * 1000) + remaining > row[0] + 2000:
                    extended += 1
            missing += database.execute('SELECT count(*) FROM entries WHERE tab=? AND seen!=? AND expiry>?',
                                        (table, marker, int(time.time() * 1000) + 1000)).fetchone()[0]
        database.commit()
    if changed or extended or missing:
        raise MigrationError(f'Critical state mismatch: missing={missing}, changed={changed}, extended={extended}')
    return {'missing': missing, 'changed': changed, 'extended': extended}


def peer_layout(text: str) -> dict:
    """Only the project's single-node loopback peer layout is qualified here."""
    local = re.findall(r'^\s+localpeer ([A-Za-z0-9_-]+)\s*$', text, re.M)
    sections = re.findall(r'^peers ([A-Za-z0-9_-]+)\s*\n((?:[ \t].*\n|\n|#[^\n]*\n)*)', text, re.M)
    if len(local) != 1 or len(sections) != 1:
        raise MigrationError('Exactly one local peers section is required')
    name, body = sections[0]
    peers = re.findall(r'^\s+peer ([A-Za-z0-9_-]+) (127\.0\.0\.1):([0-9]+)\s*$', body, re.M)
    significant = [line.strip() for line in body.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if len(peers) != 1 or len(significant) != 1 or peers[0][0] != local[0]:
        raise MigrationError('Remote/custom peer layouts need a separate migration procedure')
    tables = {}
    for table in ('tbl_ban', 'tbl_ip_auth'):
        block = re.search(r'^backend ' + table + r'\s*\n((?:[ \t].*\n|\n|#[^\n]*\n)*)', text, re.M)
        if block is None:
            if table == 'tbl_ban':
                raise MigrationError('Ban table is missing')
            continue
        declarations = [line.strip() for line in block[1].splitlines() if line.strip().startswith('stick-table ')]
        if len(declarations) != 1 or not re.fullmatch(
            r'stick-table type ip size [0-9]+[km]? expire [0-9]+[smhd] store (?:gpc0,gpt0|gpt0,gpc0|gpc0) peers ' + re.escape(name), declarations[0]):
            raise MigrationError('Unsupported critical-table definition')
        if table == 'tbl_ban' and 'gpt0' not in declarations[0]:
            raise MigrationError('Ban reason counter is missing')
        tables[table] = declarations[0]
    return {'cluster': name, 'local': local[0], 'port': int(peers[0][2]), 'tables': tables}


def add_seed(text: str, layout: dict, name: str, port: int) -> str:
    marker = f'    peer {layout["local"]} 127.0.0.1:{layout["port"]}'
    lines = text.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == marker]
    if len(matches) != 1:
        raise MigrationError('Local peer declaration changed')
    lines.insert(matches[0] + 1, f'    peer {name} 127.0.0.1:{port}\n')
    return ''.join(lines)


def seed_config(layout: dict, name: str, port: int, socket_path: Path) -> str:
    result = f'''global
    localpeer {name}
    nbthread 1
    user haproxy
    group haproxy
    stats socket {socket_path} mode 600 user root group root level admin
defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s
peers {layout['cluster']}
    peer {name} 127.0.0.1:{port}
    peer {layout['local']} 127.0.0.1:{layout['port']}
'''
    for table, declaration in layout['tables'].items():
        result += '\nbackend ' + table + '\n    ' + declaration + '\n'
    return result


def paragraphs(data: str) -> list[dict[str, str]]:
    result = []
    for paragraph in data.split('\n\n'):
        record = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                key, value = line.split(': ', 1)
                record[key] = value
        if record:
            result.append(record)
    return result


def parse_apt_plan(text: str, allowed: set[str]) -> set[str]:
    changed = set()
    for line in text.splitlines():
        if line.startswith(('Inst ', 'Remv ', 'Conf ')):
            package = line.split()[1].split(':', 1)[0]
            if package not in allowed:
                raise MigrationError('APT would change an unrelated package: ' + package)
            changed.add(package)
    return changed


class Host:
    def __init__(self):
        self.log: Path | None = None

    def command(self, args, *, cwd=None, check=True, timeout=120, env_extra=None):
        with subprocess.Popen(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True,
                              env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C', **(env_extra or {}))) as child:
            try:
                out, err = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate()
                raise MigrationError('Command timed out: ' + str(args[0])) from None
            process = subprocess.CompletedProcess(args, child.returncode, out, err)
        if self.log:
            with self.log.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps({'args': [str(x) for x in args], 'rc': process.returncode,
                                         'out': process.stdout, 'err': process.stderr}) + '\n')
            os.chmod(self.log, 0o600)
        if check and process.returncode:
            raise MigrationError(f'{Path(args[0]).name} failed with exit {process.returncode}; see the private transaction log')
        return process

    def active(self, unit):
        return self.command(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0

    def service(self, action, unit='haproxy.service'):
        self.command(['/usr/bin/systemctl', action, unit])

    def main_pid(self):
        return int(self.command(['/usr/bin/systemctl', 'show', 'haproxy.service', '--property=MainPID', '--value']).stdout.strip())

    def packages(self):
        result = self.command(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
        return {name.split(':', 1)[0]: version for name, version, status_ in
                (line.split('\t') for line in result.stdout.splitlines()) if status_ == 'installed'}

    def machine(self):
        return hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()

    def worker_digest(self, pid):
        return digest(Path('/proc') / str(int(pid)) / 'exe')

    def start_seed(self, directory: Path, unit: str):
        libraries = directory / 'baseline-libraries'
        environment = (['--setenv=LD_LIBRARY_PATH=' + ':'.join(sorted({str(p.parent) for p in libraries.rglob('lib*.so*')}))]
                       if libraries.exists() else [])
        self.command(['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + unit,
                      '--property=CPUQuota=50%', '--property=MemoryMax=256M',
                      '--property=Restart=no', '--property=NoNewPrivileges=yes',
                      *environment, str(directory / 'baseline-haproxy'), '-db', '-f', str(directory / 'seed.cfg')])

    def watchdog(self, directory: Path, unit: str):
        self.command(['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + unit,
                      '--on-active=300s', '--timer-property=AccuracySec=1s',
                      '--property=Restart=on-failure', '--property=RestartSec=10s',
                      sys.executable, str(directory / 'recover.py'), 'recover', '--id', directory.name])

    def cancel_watchdog(self, unit: str):
        self.command(['/usr/bin/systemctl', 'stop', unit + '.timer'], check=False)

    def control_journal(self, default: Path) -> Path:
        pid = self.command(['/usr/bin/systemctl', 'show', 'haproxy-controld.service', '--property=MainPID', '--value']).stdout.strip()
        environment = dict(item.split(b'=', 1) for item in (Path('/proc') / pid / 'environ').read_bytes().split(b'\0') if b'=' in item)
        value = environment.get(b'HAPROXY_CONFIG_TRANSACTION_DIR')
        return Path(value.decode()) / 'transaction.json' if value else default

    def guard_database(self):
        pid = self.command(['/usr/bin/systemctl', 'show', 'easy-ha-proxy-guardd.service', '--property=MainPID', '--value']).stdout.strip()
        environment = dict(item.split(b'=', 1) for item in (Path('/proc') / pid / 'environ').read_bytes().split(b'\0') if b'=' in item)
        return Path(environment.get(b'GUARDD_DATABASE', b'/var/lib/easy-ha-proxy/security/security.db').decode())


class LocalTLS(http.client.HTTPSConnection):
    def connect(self):
        connection = socket.create_connection(('127.0.0.1', self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(connection, server_hostname=self.host)


def local_probe(domain: str, path: str) -> int:
    if not re.fullmatch(r'[A-Za-z0-9.-]+', domain):
        raise MigrationError('Invalid control-plane hostname')
    context = ssl.create_default_context()
    ca = Path('/etc/easy-ha-proxy/certificate-authorities/internal/ca.crt')
    if ca.is_file():
        context.load_verify_locations(cafile=str(ca))
    connection = LocalTLS(domain, 443, timeout=5, context=context)
    try:
        connection.request('GET', path, headers={'Host': domain, 'Connection': 'close'})
        response = connection.getresponse()
        response.read(65536)
        return response.status
    finally:
        connection.close()


class Engine:
    paused_units = ('easy-ha-proxy-guardd.service', 'haproxy-certd.service', 'haproxy-controld.service',
                    'haproxy-state-dump.timer', 'certbot.timer', 'snap.certbot.renew.timer',
                    'apt-daily.timer', 'apt-daily-upgrade.timer')
    optional_dependencies = {'libjemalloc2', 'libopentracing1', 'libopentracing-c-wrapper0t64'}
    allowed_packages = {'haproxy', 'haproxy-awslc', 'libssl-awslc'} | optional_dependencies
    vendor = 'https://www.haproxy.com/download/haproxy/performance/ubuntu/ha34/'
    key_url = 'https://pks.haproxy.com/linux/community/RPM-GPG-KEY-HAProxy'

    def __init__(self, paths: Paths | None = None, host: Host | None = None, *, observer=None):
        self.paths = paths or Paths()
        self.host = host or Host()
        self.state = {}
        self.directory: Path | None = None
        self.patch = False
        self.observer = observer
        self.lock_depth = 0

    @contextlib.contextmanager
    def locked(self):
        if self.lock_depth:
            yield
            return
        self.paths.lock.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            details = os.fstat(descriptor)
            if details.st_uid != 0 or not stat.S_ISREG(details.st_mode):
                raise MigrationError('Unsafe maintenance lock')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise MigrationError('Another maintenance operation is running') from error
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1
        finally:
            os.close(descriptor)

    def save(self, phase=None):
        if phase:
            self.state['phase'] = phase
        self.state['updated_at'] = time.time()
        atomic(self.directory / 'transaction.json', (json.dumps(self.state, indent=2) + '\n').encode())
        if self.state.get('kind') == 'patch':
            atomic(self.paths.root / 'last-update.json', (json.dumps(self.summary()) + '\n').encode())
        if self.observer:
            with contextlib.suppress(Exception):
                self.observer(self.summary())

    def load(self, identifier):
        if not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise MigrationError('Invalid migration id')
        private_directory(self.paths.root)
        self.directory = self.paths.root / identifier
        details = self.directory.lstat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
            raise MigrationError('Unsafe transaction directory')
        path = self.directory / 'transaction.json'
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
            raise MigrationError('Unsafe transaction journal')
        self.state = json.loads(path.read_text())
        self.patch = self.state.get('kind') == 'patch'
        if self.state.get('format') != 1 or self.state.get('id') != identifier:
            raise MigrationError('Invalid transaction journal')
        if self.state.get('machine') != self.host.machine():
            raise MigrationError('The transaction belongs to a different machine')
        self.host.log = self.directory / 'commands.jsonl'

    def backup(self, path: Path):
        key = str(path)
        if key in self.state['files']:
            return
        if not path.exists() and not path.is_symlink():
            self.state['files'][key] = {'exists': False}
            return
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_uid != 0:
            raise MigrationError('Managed migration files must be regular root-owned files: ' + key)
        name = 'saved-' + hashlib.sha256(key.encode()).hexdigest()
        atomic(self.directory / name, path.read_bytes())
        self.state['files'][key] = {'exists': True, 'file': name, 'digest': digest(path),
                                   'mode': stat.S_IMODE(details.st_mode), 'uid': details.st_uid, 'gid': details.st_gid}

    def original(self, path: Path) -> bytes:
        record = self.state['files'][str(path)]
        if not record['exists']:
            return b''
        saved = self.directory / record['file']
        if digest(saved) != record['digest']:
            raise MigrationError('Backup integrity check failed')
        return saved.read_bytes()

    def restore(self, path: Path):
        record = self.state['files'][str(path)]
        if path.is_symlink():
            raise MigrationError('Refusing to replace an unexpected symlink')
        if path.exists():
            current = digest(path)
            known = {record.get('digest'), self.state.get('written_files', {}).get(str(path))}
            if current not in known:
                raise MigrationError('A managed file changed outside this operation: ' + str(path))
        if record['exists']:
            atomic(path, self.original(path), record['mode'], record['uid'], record['gid'])
        elif path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink():
                raise MigrationError('Refusing to remove an unexpected migration file')
            path.unlink()

    def put(self, path: Path, data: bytes, mode=0o600, uid=0, gid=0):
        if path.is_symlink():
            raise MigrationError('Refusing to replace a managed symlink')
        self.state.setdefault('written_files', {})[str(path)] = hashlib.sha256(data).hexdigest()
        self.save()
        atomic(path, data, mode, uid, gid)

    def unchanged(self, path: Path):
        record = self.state['files'][str(path)]
        if (record['exists'] != path.exists() or path.is_symlink()
                or (record['exists'] and digest(path) != record['digest'])):
            raise MigrationError('Managed configuration changed after preparation: ' + str(path))

    def download(self, url, destination, expected=None, limit=64 * 1024 * 1024):
        temporary = destination.with_name(destination.name + '.part')
        total = 0
        with urllib.request.urlopen(url, timeout=30) as response, temporary.open('wb') as stream:
            for chunk in iter(lambda: response.read(65536), b''):
                total += len(chunk)
                if total > limit:
                    raise MigrationError('Repository object exceeds the size limit')
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        if expected and digest(temporary) != expected:
            raise MigrationError('Repository object checksum mismatch')
        os.replace(temporary, destination)

    def authenticated_packages(self, architecture):
        defaults = yaml.safe_load((self.paths.source / 'ansible/roles/haproxy/defaults/main.yml').read_text())
        signing_digest = defaults['haproxy_community_key_sha256']
        if not re.fullmatch(r'[0-9a-f]{64}', signing_digest):
            raise MigrationError('Invalid configured signing-key checksum')
        self.download(self.key_url, self.directory / 'repository.asc', signing_digest)
        home = self.directory / 'gnupg'
        private_directory(home)
        self.host.command(['/usr/bin/gpg', '--homedir', str(home), '--no-options', '--batch', '--dearmor',
                           '--output', str(self.directory / 'repository.gpg'), str(self.directory / 'repository.asc')])
        self.download(self.vendor + 'dists/noble/InRelease', self.directory / 'InRelease', limit=1024 * 1024)
        self.host.command(['/usr/bin/gpgv', '--homedir', str(home), '--keyring', str(self.directory / 'repository.gpg'),
                           '--output', str(self.directory / 'Release'), str(self.directory / 'InRelease')])
        release = (self.directory / 'Release').read_text()
        fields = paragraphs(release)[0]
        published = email.utils.parsedate_to_datetime(fields['Date']).timestamp()
        if published > time.time() + 3600 or published < time.time() - 60 * 86400:
            raise MigrationError('Repository metadata is too old or dated in the future')
        if fields.get('Valid-Until') and email.utils.parsedate_to_datetime(fields['Valid-Until']).timestamp() < time.time():
            raise MigrationError('Repository metadata expired')
        relative = 'main/binary-' + architecture + '/Packages.gz'
        matches = re.findall(r'^ ([0-9a-f]{64})\s+[0-9]+\s+' + re.escape(relative) + r'\s*$', release, re.M)
        if len(matches) != 1:
            raise MigrationError('Signed repository metadata has no unique architecture index')
        self.download(self.vendor + 'dists/noble/' + relative, self.directory / 'Packages.gz', matches[0])
        with gzip.open(self.directory / 'Packages.gz', 'rt') as stream:
            index = stream.read(8 * 1024 * 1024 + 1)
        if len(index) > 8 * 1024 * 1024:
            raise MigrationError('Package index is unexpectedly large')
        records = paragraphs(index)
        candidates = [record for record in records if record.get('Package') == 'haproxy-awslc'
                      and record.get('Architecture') == architecture and re.match(r'^3[.]4[.]', record.get('Version', ''))]
        if not candidates:
            raise MigrationError('No HAProxy 3.4 package for this architecture')
        target = candidates[0]
        for candidate in candidates[1:]:
            if self.host.command(['/usr/bin/dpkg', '--compare-versions', candidate['Version'], 'gt', target['Version']], check=False).returncode == 0:
                target = candidate
        dependency = re.search(r'libssl-awslc \(= ([^()]+)\)', target.get('Depends', ''))
        if dependency is None:
            raise MigrationError('Unqualified TLS dependency layout')
        libraries = [record for record in records if record.get('Package') == 'libssl-awslc'
                     and record.get('Architecture') == architecture and record.get('Version') == dependency[1]]
        if len(libraries) != 1:
            raise MigrationError('The exact TLS dependency is missing')
        result = []
        for package in (target, libraries[0]):
            filename = package['Filename']
            if not re.fullmatch(r'pool/[A-Za-z0-9_./+~-]+[.]deb', filename) or '..' in Path(filename).parts:
                raise MigrationError('Invalid signed package filename')
            destination = self.directory / (package['Package'] + '.deb')
            self.download(self.vendor + filename, destination, package['SHA256'])
            self.check_deb(destination, package['Package'], package['Version'], architecture)
            result.append({key: package[key] for key in ('Package', 'Version', 'SHA256')})
        return result

    def check_deb(self, path, package, version, architecture):
        fields = self.host.command(['/usr/bin/dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture']).stdout
        parsed = dict(line.split(': ', 1) for line in fields.splitlines() if ': ' in line)
        if parsed != {'Package': package, 'Version': version, 'Architecture': architecture}:
            raise MigrationError('Package identity does not match the authenticated index')

    def native_preflight(self):
        os_fields = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if os_fields.get('ID', '').strip('"') != 'ubuntu' or os_fields.get('VERSION_ID', '').strip('"') != '24.04':
            raise MigrationError('Only Ubuntu 24.04 is qualified for this migration')
        architecture = self.host.command(['/usr/bin/dpkg', '--print-architecture']).stdout.strip()
        if self.host.command(['/usr/bin/dpkg', '--audit']).stdout.strip():
            raise MigrationError('Resolve unfinished package operations before migration')
        if architecture not in ('arm64', 'amd64'):
            raise MigrationError('Only ARM64 and AMD64 are qualified')
        packages = self.host.packages()
        name = 'haproxy-awslc' if self.patch and 'haproxy-awslc' in packages else 'haproxy'
        branch = '3.4' if name == 'haproxy-awslc' else '2.8'
        if not re.match(r'^' + re.escape(branch) + r'[.]', packages.get(name, '')):
            raise MigrationError('Preparation requires the distribution HAProxy 2.8 package')
        if not self.patch and 'haproxy-awslc' in packages:
            raise MigrationError('A provider migration must start on distribution HAProxy 2.8')
        if not self.host.active('haproxy.service') or not self.host.active('haproxy-controld.service'):
            raise MigrationError('HAProxy and its control service must be healthy before preparation')
        active = info(self.paths.socket)
        binary_version = re.search(r'HAProxy version (\S+)', self.host.command([str(self.paths.binary), '-v']).stdout)
        if not binary_version or active.get('Version') != binary_version[1] or self.host.worker_digest(active['Pid']) != digest(self.paths.binary):
            raise MigrationError('Running and installed HAProxy versions differ')
        variables = yaml.safe_load(self.paths.variables.read_text())
        provider = 'haproxy-technologies' if name == 'haproxy-awslc' else 'distribution'
        if not isinstance(variables, dict) or variables.get('haproxy_package_provider', 'distribution') != provider:
            raise MigrationError('Installer provider and installed package differ')
        config = self.paths.config.read_text()
        if not re.search(r'^\s+server-state-file ' + re.escape(str(self.paths.server_state)) + r'\s*$', config, re.M):
            raise MigrationError('The qualified server-state file must be enabled')
        if 'load-server-state-from-file global' not in config:
            raise MigrationError('Administrative server-state loading must be enabled')
        available = re.search(r'^MemAvailable:\s+([0-9]+) kB$', Path('/proc/meminfo').read_text(), re.M)
        if available is None or int(available[1]) < 384 * 1024:
            raise MigrationError('At least 384 MiB of available RAM is required for the temporary handoff')
        return architecture, packages

    def prepare(self):
        with self.locked():
            architecture, packages = self.native_preflight()
            private_directory(self.paths.root)
            if shutil.disk_usage(self.paths.root).free < 512 * 1024 * 1024:
                raise MigrationError('At least 512 MiB of free disk space is required for rollback artifacts')
            self.directory = self.paths.root / uuid.uuid4().hex
            private_directory(self.directory)
            self.host.log = self.directory / 'commands.jsonl'
            self.state = {'format': 1, 'id': self.directory.name, 'machine': self.host.machine(),
                          'architecture': architecture, 'created_at': time.time(), 'files': {},
                          'engine_digest': digest(Path(__file__)),
                          'holds': sorted(self.holds() & {'haproxy', 'haproxy-awslc', 'libssl-awslc'}),
                          'old_version': packages['haproxy'], 'phase': 'preparing'}
            self.save()
            for path in (self.paths.config, self.paths.variables, self.paths.server_state, self.paths.policy,
                         self.paths.repository, self.paths.priorities, self.paths.signing_key):
                self.backup(path)
            self.state['layout'] = peer_layout(self.original(self.paths.config).decode())
            if self.paths.socket != Path('/run/haproxy/admin.sock'):
                raise MigrationError('Custom Runtime API socket is not qualified')
            private_directory(self.directory / 'old')
            self.host.command(['/usr/bin/apt-get', '-o', 'APT::Get::AllowUnauthenticated=false',
                               'download', 'haproxy=' + packages['haproxy']], cwd=self.directory / 'old')
            old = list((self.directory / 'old').glob('*.deb'))
            if len(old) != 1:
                raise MigrationError('The exact rollback package could not be downloaded')
            shutil.move(old[0], self.directory / 'haproxy-old.deb')
            self.check_deb(self.directory / 'haproxy-old.deb', 'haproxy', packages['haproxy'], architecture)
            self.state['old_digest'] = digest(self.directory / 'haproxy-old.deb')
            self.inspect_baseline()
            shutil.copyfile(self.paths.binary, self.directory / 'baseline-haproxy')
            os.chmod(self.directory / 'baseline-haproxy', 0o700)
            self.state['old_binary_digest'] = digest(self.paths.binary)
            self.state['target_packages'] = self.authenticated_packages(architecture)
            tls = self.state['target_packages'][1]['Version']
            if packages.get('libssl-awslc') not in (None, tls):
                raise MigrationError('Migration would upgrade an existing TLS library')
            self.state['tls_was_installed'] = 'libssl-awslc' in packages
            self.state['tls_baseline'] = packages.get('libssl-awslc')
            self.state['extra_packages'] = []
            self.state['extra_baseline'] = {name: packages.get(name) for name in self.optional_dependencies}
            plan = self.host.command(self.package_command(simulate=True)).stdout
            parse_apt_plan(plan, self.allowed_packages)
            for name in sorted(self.optional_dependencies):
                match = re.search(r'^Inst ' + re.escape(name) + r'(?::\S+)? (?:\[[^\]]+\] )?\((\S+)', plan, re.M)
                if not match:
                    continue
                if packages.get(name) is not None:
                    raise MigrationError('Migration would upgrade an existing system dependency: ' + name)
                temporary = self.directory / ('download-' + name)
                private_directory(temporary)
                self.host.command(['/usr/bin/apt-get', '-o', 'APT::Get::AllowUnauthenticated=false',
                                   'download', name + '=' + match[1]], cwd=temporary)
                archives = list(temporary.glob('*.deb'))
                if len(archives) != 1:
                    raise MigrationError('The exact system dependency could not be downloaded: ' + name)
                destination = self.directory / (name + '.deb')
                shutil.move(archives[0], destination)
                self.check_deb(destination, name, match[1], architecture)
                self.state['extra_packages'].append({'Package': name, 'Version': match[1], 'SHA256': digest(destination)})
            parse_apt_plan(self.host.command(self.package_command(simulate=True)).stdout, self.allowed_packages)
            # Extracted binaries run with their private matching library. Nothing
            # is copied into /usr or installed until apply is explicitly invoked.
            private_directory(self.directory / 'target')
            for package in self.state['target_packages'] + self.state['extra_packages']:
                self.host.command(['/usr/bin/dpkg-deb', '-x', str(self.directory / (package['Package'] + '.deb')), str(self.directory / 'target')])
            self.inspect_target()
            if digest(Path(__file__)) != self.state['engine_digest']:
                raise MigrationError('Migration implementation changed during preparation')
            atomic(self.directory / 'recover.py', Path(__file__).read_bytes(), 0o700)
            self.save('prepared')
            return self.summary()

    def inspect_baseline(self):
        target = self.directory / 'baseline'
        self.host.command(['/usr/bin/dpkg-deb', '-x', str(self.directory / 'haproxy-old.deb'), str(target)])
        installed = Path('/usr/lib/systemd/system/haproxy.service')
        packaged = target / 'usr/lib/systemd/system/haproxy.service'
        if not packaged.exists():
            packaged = target / 'lib/systemd/system/haproxy.service'
        if not installed.exists():
            installed = Path('/lib/systemd/system/haproxy.service')
        if digest(target / 'usr/sbin/haproxy') != digest(self.paths.binary):
            raise MigrationError('The installed binary differs from the exact rollback package')
        if Path('/etc/systemd/system/haproxy.service').exists() or digest(installed) != digest(packaged):
            raise MigrationError('Custom HAProxy service units require a separate qualification')
        for directory in (Path('/etc/systemd/system/haproxy.service.d'), Path('/run/systemd/system/haproxy.service.d')):
            for dropin in directory.glob('*.conf'):
                if re.search(r'^\s*(?:Exec\w*|Type|RootDirectory|User|Group)\s*=', dropin.read_text(), re.M):
                    raise MigrationError('Custom HAProxy execution overrides require a separate qualification')
        control = self.directory / 'baseline-control'
        self.host.command(['/usr/bin/dpkg-deb', '-e', str(self.directory / 'haproxy-old.deb'), str(control)])
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            path = control / name
            if path.exists() and re.search(r'\bsystemctl\s+(?:--\S+\s+)*(?:stop|restart|try-restart)\b', path.read_text()):
                raise MigrationError('Baseline package actions bypass policy-rc.d')
        shutil.rmtree(target)

    def holds(self):
        text = self.host.command(['/usr/bin/dpkg', '--get-selections']).stdout
        return {line.split()[0].split(':', 1)[0] for line in text.splitlines()
                if len(line.split()) == 2 and line.split()[1] == 'hold'}

    def restore_holds(self, *, rollback=False):
        installed = self.host.packages()
        for name in ('haproxy', 'haproxy-awslc', 'libssl-awslc'):
            if name in installed:
                held = name in self.state.get('holds', []) if rollback else True
                self.host.command(['/usr/bin/apt-mark', 'hold' if held else 'unhold', name])

    def download_exact(self, package, version, destination):
        """APT authenticates new downloads; retained verified archives cover retired versions."""
        temporary = self.directory / ('old-download-' + package)
        private_directory(temporary)
        try:
            self.host.command(['/usr/bin/apt-get', '-o', 'APT::Get::AllowUnauthenticated=false',
                               'download', package + '=' + version], cwd=temporary)
            files = list(temporary.glob('*.deb'))
            if len(files) != 1:
                raise MigrationError('Exact rollback package download is missing')
            shutil.move(files[0], destination)
        except MigrationError:
            found = False
            for folder in self.paths.root.iterdir():
                if not re.fullmatch(r'[0-9a-f]{32}', folder.name) or folder.is_symlink():
                    continue
                journal = folder / 'transaction.json'
                try:
                    details = journal.lstat()
                    if details.st_uid != 0 or not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077:
                        continue
                    previous = json.loads(journal.read_text())
                    for record in previous.get('target_packages', []):
                        archive = folder / (package + '.deb')
                        if (record.get('Package') == package and record.get('Version') == version
                                and archive.is_file() and digest(archive) == record.get('SHA256')):
                            shutil.copyfile(archive, destination)
                            found = True
                            break
                except (OSError, ValueError):
                    continue
                if found:
                    break
            if not found:
                raise MigrationError('The exact rollback archive is unavailable: ' + package) from None
        self.check_deb(destination, package, version, self.state['architecture'])
        return {'Package': package, 'Version': version, 'SHA256': digest(destination)}

    def prepare_patch(self, expected_version, *, reinstall=False):
        self.patch = True
        try:
            return self._prepare_patch(expected_version, reinstall=reinstall)
        except Exception as error:
            if self.directory and self.state.get('phase') == 'preparing':
                self.state['failure'] = str(error)
                self.save('aborted')
            raise

    def _prepare_patch(self, expected_version, *, reinstall):
        with self.locked():
            previous = self.paths.root / 'last-update.json'
            if previous.exists():
                if previous.is_symlink() or previous.stat().st_size > 64 * 1024:
                    raise MigrationError('Unsafe previous HAProxy update record')
                try:
                    operation = json.loads(previous.read_text())
                except (OSError, ValueError) as error:
                    raise MigrationError('The previous HAProxy update record is unreadable') from error
                if not isinstance(operation, dict) or operation.get('phase') not in {'committed', 'rolled_back', 'aborted', 'preparing', 'prepared'}:
                    raise MigrationError('Recover the unfinished HAProxy update before preparing another one')
            architecture, packages = self.native_preflight()
            name = 'haproxy-awslc' if 'haproxy-awslc' in packages else 'haproxy'
            branch = '3.4' if name == 'haproxy-awslc' else '2.8'
            if not re.fullmatch(re.escape(branch) + r'[.][0-9]+[A-Za-z0-9.+:~_-]*', expected_version):
                raise MigrationError('The selected version is outside the installed HAProxy branch')
            if self.host.command(['/usr/bin/dpkg', '--compare-versions', expected_version, 'lt', packages[name]], check=False).returncode == 0:
                raise MigrationError('A patch update must not downgrade HAProxy')
            if expected_version == packages[name] and not reinstall:
                raise MigrationError('The selected HAProxy version is already installed')
            held = self.holds()
            required = {name} | ({'libssl-awslc'} if name == 'haproxy-awslc' else set())
            if not required <= held:
                raise MigrationError('Enable controlled HAProxy package protection before updating')
            private_directory(self.paths.root)
            if shutil.disk_usage(self.paths.root).free < 512 * 1024 * 1024:
                raise MigrationError('At least 512 MiB of free disk space is required')
            self.directory = self.paths.root / uuid.uuid4().hex
            private_directory(self.directory)
            self.host.log = self.directory / 'commands.jsonl'
            self.state = {'format': 1, 'kind': 'patch', 'id': self.directory.name, 'machine': self.host.machine(),
                          'architecture': architecture, 'created_at': time.time(), 'files': {},
                          'engine_digest': digest(Path(__file__)), 'old_version': packages[name], 'old_package': name,
                          'old_runtime_version': info(self.paths.socket)['Version'], 'target_branch': branch,
                          'holds': sorted(held & required), 'phase': 'preparing', 'extra_packages': [],
                          'extra_baseline': {key: packages.get(key) for key in self.optional_dependencies},
                          'tls_was_installed': 'libssl-awslc' in packages, 'tls_baseline': packages.get('libssl-awslc')}
            self.save()
            for path in (self.paths.config, self.paths.variables, self.paths.server_state, self.paths.policy,
                         self.paths.repository, self.paths.priorities, self.paths.signing_key):
                self.backup(path)
            self.state['layout'] = peer_layout(self.original(self.paths.config).decode())
            record = self.download_exact(name, packages[name], self.directory / 'haproxy-old.deb')
            self.state['old_digest'] = record['SHA256']
            self.inspect_baseline()
            atomic(self.directory / 'baseline-haproxy', self.paths.binary.read_bytes(), 0o700)
            self.state['old_binary_digest'] = digest(self.paths.binary)
            if name == 'haproxy-awslc':
                self.state['old_tls'] = self.download_exact('libssl-awslc', packages['libssl-awslc'], self.directory / 'tls-old.deb')
                libraries = self.directory / 'baseline-libraries'
                self.host.command(['/usr/bin/dpkg-deb', '-x', str(self.directory / 'tls-old.deb'), str(libraries)])
                self.state['baseline_library_hashes'] = {}
                for file in libraries.rglob('*'):
                    if file.is_file():
                        if not file.resolve().is_relative_to(libraries.resolve()):
                            raise MigrationError('A baseline TLS library escapes the private directory')
                        self.state['baseline_library_hashes'][str(file.relative_to(libraries))] = digest(file)
                self.state['target_packages'] = self.authenticated_packages(architecture)
                if self.state['target_packages'][0]['Version'] != expected_version:
                    raise MigrationError('HAProxy repository changed; check for updates again')
            else:
                record = self.download_exact(name, expected_version, self.directory / (name + '.deb'))
                self.state['target_packages'] = [record]
            plan = self.host.command(self.package_command(simulate=True)).stdout
            parse_apt_plan(plan, self.allowed_packages)
            for dependency in sorted(self.optional_dependencies):
                match = re.search(r'^Inst ' + re.escape(dependency) + r'(?::\S+)? (?:\[[^\]]+\] )?\((\S+)', plan, re.M)
                if match:
                    if packages.get(dependency) is not None:
                        raise MigrationError('Update the system dependency separately first: ' + dependency)
                    self.state['extra_packages'].append(self.download_exact(dependency, match[1], self.directory / (dependency + '.deb')))
            private_directory(self.directory / 'target')
            for package in self.state['target_packages'] + self.state['extra_packages']:
                self.host.command(['/usr/bin/dpkg-deb', '-x', str(self.directory / (package['Package'] + '.deb')), str(self.directory / 'target')])
            self.inspect_target()
            if digest(Path(__file__)) != self.state['engine_digest']:
                raise MigrationError('Update implementation changed during preparation')
            atomic(self.directory / 'recover.py', Path(__file__).read_bytes(), 0o700)
            self.save('prepared')
            return self.summary()

    def package_command(self, *, simulate=False, rollback=False):
        command = ['/usr/bin/apt-get', '--no-install-recommends', '-o', 'Dpkg::Options::=--force-confold',
                   '-o', 'Dir::Cache::archives=' + str(self.directory / 'archives'),
                   '--allow-change-held-packages', '--allow-downgrades']
        if simulate:
            command.append('--simulate')
        else:
            command.extend(['--yes', '--no-download'])
        command.append('install')
        if rollback:
            command.extend(['--reinstall', str(self.directory / 'haproxy-old.deb')])
            if self.patch and self.state.get('old_tls'):
                command.append(str(self.directory / 'tls-old.deb'))
            remove = ([] if self.patch else ['haproxy-awslc']) + ([] if self.state['tls_was_installed'] else ['libssl-awslc'])
            remove += [package['Package'] for package in self.state.get('extra_packages', [])]
            for package in remove:
                known = self.host.command(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}', package], check=False)
                if known.returncode == 0 and known.stdout.strip() != 'not-installed':
                    command.append(package + '-')
        else:
            if self.patch:
                command.append('--reinstall')
            command.extend([str(self.directory / (package['Package'] + '.deb')) for package in
                            self.state['target_packages'] + self.state.get('extra_packages', [])])
        return command

    def inspect_target(self):
        target = self.directory / 'target'
        unit = target / 'usr/lib/systemd/system/haproxy.service'
        if not unit.exists():
            unit = target / 'lib/systemd/system/haproxy.service'
        text = unit.read_text()
        if 'ExecReload=/bin/kill -USR2 $MAINPID' not in text or 'ExecStart=/usr/sbin/haproxy -Ws ' not in text or 'Type=notify' not in text:
            raise MigrationError('The package changed its service contract')
        directory = Path('/etc/haproxy/conf.d')
        if directory.exists() and any(directory.iterdir()):
            raise MigrationError('The new service would load an existing conf.d directory')
        self.state['unit_digest'] = digest(unit)
        self.state['target_binary_digest'] = digest(target / 'usr/sbin/haproxy')
        control = self.directory / 'target-control'
        name = self.state['target_packages'][0]['Package']
        self.host.command(['/usr/bin/dpkg-deb', '-e', str(self.directory / (name + '.deb')), str(control)])
        for script in ('preinst', 'postinst', 'prerm', 'postrm'):
            path = control / script
            if path.exists() and re.search(r'\bsystemctl\s+(?:--\S+\s+)*(?:stop|restart|try-restart)\b', path.read_text()):
                raise MigrationError('Package service actions bypass policy-rc.d; review the package')
        library_directories = sorted({str(path.parent) for path in target.rglob('lib*.so*')})
        if not library_directories and name == 'haproxy-awslc':
            raise MigrationError('The private TLS library is missing')
        result = self.host.command([str(target / 'usr/sbin/haproxy'), '-v'],
                                   env_extra={'LD_LIBRARY_PATH': ':'.join(library_directories)})
        match = re.search(r'HAProxy version (\S+)', result.stdout)
        if not match or not match[1].startswith(self.state.get('target_branch', '3.4') + '.'):
            raise MigrationError('The private target binary has an unexpected version')
        self.state['target_runtime_version'] = match[1]
        result = self.host.command([str(target / 'usr/sbin/haproxy'), '-Ws', '-c', '-dr', '-f', str(self.paths.config)],
                                   env_extra={'LD_LIBRARY_PATH': ':'.join(library_directories)})
        if 'not supported by AWS-LC' in result.stderr or 'bool-sample-conversion' in result.stderr:
            raise MigrationError('Apply the current alpha HAProxy configuration before migration')

    def check_artifacts(self):
        if digest(Path(__file__)) != self.state.get('engine_digest'):
            raise MigrationError('Migration implementation changed; use the saved recovery command or prepare afresh')
        if digest(self.directory / 'recover.py') != self.state['engine_digest']:
            raise MigrationError('Saved recovery command integrity check failed')
        if time.time() - self.state['created_at'] > 86400 and self.state['phase'] == 'prepared':
            raise MigrationError('Preparation expired; create a fresh transaction')
        if digest(self.directory / 'haproxy-old.deb') != self.state['old_digest']:
            raise MigrationError('Rollback package integrity check failed')
        if digest(self.directory / 'baseline-haproxy') != self.state['old_binary_digest']:
            raise MigrationError('Baseline binary integrity check failed')
        for package in self.state['target_packages'] + self.state.get('extra_packages', []):
            if digest(self.directory / (package['Package'] + '.deb')) != package['SHA256']:
                raise MigrationError('Target package integrity check failed')
        if self.state.get('old_tls') and digest(self.directory / 'tls-old.deb') != self.state['old_tls']['SHA256']:
            raise MigrationError('Rollback TLS package integrity check failed')
        for name, expected in self.state.get('baseline_library_hashes', {}).items():
            if digest(self.directory / 'baseline-libraries' / name) != expected:
                raise MigrationError('Private baseline TLS library integrity check failed')

    def quiet(self):
        for unit in ('haproxy-state-dump.service', 'certbot.service', 'snap.certbot.renew.service'):
            if self.host.active(unit):
                raise MigrationError('A state dump or certificate renewal is running; retry after it completes')
        path = Path(self.state.get('control_journal', str(self.paths.control_state)))
        if path.exists():
            data = json.loads(path.read_text())
            if data.get('state') in {'prepared', 'pending_confirmation', 'rolling_back', 'rollback_failed'}:
                raise MigrationError('Resolve the active configuration transaction before migrating')

    def pause(self):
        for service in ('apt-daily.service', 'apt-daily-upgrade.service'):
            if self.host.active(service):
                raise MigrationError('A system package maintenance service is running')
        self.state['control_journal'] = str(self.host.control_journal(self.paths.control_state))
        if self.host.active('easy-ha-proxy-guardd.service'):
            self.state['guard_database'] = str(self.host.guard_database())
        self.quiet()
        self.state['resume_units'] = [unit for unit in self.paused_units if self.host.active(unit)]
        self.save('quiescing')
        for unit in self.state['resume_units']:
            self.host.service('stop', unit)
        self.quiet()

    def resume(self, *, timers=False):
        # Control comes back before guardd can submit a new enforcement action.
        ordered = sorted([unit for unit in self.state.get('resume_units', []) if unit.endswith('.timer') == timers], key=lambda unit: (
            0 if unit == 'haproxy-controld.service' else 2 if unit == 'easy-ha-proxy-guardd.service' else 1))
        for unit in ordered:
            self.host.service('start', unit)
        for unit in ordered:
            if not self.host.active(unit):
                raise MigrationError('A previously active service did not recover: ' + unit)

    def snapshot(self, source=None):
        counts = snapshot_tables(source or self.paths.socket, self.directory / 'tables.sqlite', self.state['layout']['tables'])
        self.state['table_counts'] = counts
        self.save()

    def check_guard(self):
        """Never switch an already inconsistent persisted protection schedule."""
        name = self.state.get('guard_database')
        if not name:
            return
        path = Path(name)
        if not path.is_file():
            raise MigrationError('The active guard database is missing')
        missing = 0
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as guard, \
                sqlite3.connect(self.directory / 'tables.sqlite') as snapshot:
            guard.execute('PRAGMA query_only=ON')
            for query, code in [('SELECT ip, banned_until FROM ip_state WHERE banned_until > ?', 40),
                                ('SELECT ip, expires_at FROM manual_bans WHERE expires_at > ?', 50)]:
                for address, _ in guard.execute(query, (int(time.time()) + 2,)):
                    row = snapshot.execute('SELECT gpc0,gpt0 FROM entries WHERE tab=? AND ip=?', ('tbl_ban', address)).fetchone()
                    if not row or row[0] <= 0 or row[1] != code:
                        missing += 1
        if missing:
            raise MigrationError(f'Persisted guard decisions differ from Runtime API: {missing} entries; resolve drift first')

    def check_tables(self, source=None):
        return verify_tables(source or self.paths.socket, self.directory / 'tables.sqlite', self.state['layout']['tables'])

    def await_tables(self, source=None):
        deadline = time.monotonic() + 20
        last = None
        while time.monotonic() < deadline:
            try:
                return self.check_tables(source)
            except (MigrationError, OSError) as error:
                last = error
                time.sleep(.25)
        raise MigrationError('Critical-table handoff did not finish: ' + str(last))

    def dump_servers(self):
        data = runtime(self.paths.socket, 'show servers state')
        if not data.startswith('1\n') or '# be_id' not in data:
            raise MigrationError('The administrative server state could not be saved')
        self.state['server_state'] = data + '\n'
        self.store_servers()
        self.save()

    def store_servers(self):
        record = self.state['files'][str(self.paths.server_state)]
        atomic(self.paths.server_state, self.state['server_state'].encode(),
               record.get('mode', 0o644), record.get('uid', 0), record.get('gid', 0))

    def check_servers(self):
        def parse(text):
            lines = text.splitlines()
            header = next(line[2:].split() for line in lines if line.startswith('# be_id'))
            rows = [dict(zip(header, line.split(), strict=True)) for line in lines if line and not line.startswith('#') and line != '1']
            return {(row['be_name'], row['srv_name']): (row['srv_admin_state'], row['srv_uweight']) for row in rows}
        expected = parse(self.state['server_state'])
        actual = parse(runtime(self.paths.socket, 'show servers state'))
        if expected != actual:
            raise MigrationError('Backend administrative state or runtime weights changed')

    def reload(self, expected_version):
        self.host.command([str(self.paths.binary), '-Ws', '-c', '-f', str(self.paths.config)])
        self.store_servers()
        previous_worker = info(self.paths.socket)['Pid']
        self.host.service('reload')
        self.wait_worker(expected_version, previous_worker=previous_worker)
        self.await_tables()
        self.check_servers()

    def wait_worker(self, expected_version, *, previous_worker=None):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                current = info(self.paths.socket)
                if current.get('Version') == expected_version and current.get('Pid') != previous_worker:
                    if self.host.worker_digest(current['Pid']) == digest(self.paths.binary):
                        return current
            except (OSError, KeyError):
                pass
            time.sleep(.25)
        raise MigrationError('The running worker did not switch to the expected binary')

    def health(self):
        text = self.paths.config.read_text()
        admin = re.findall(r'^\s+acl host_admin hdr\(host\) -i ([A-Za-z0-9.-]+)\s*$', text, re.M)
        authentication = re.findall(r'^\s+acl host_authelia hdr\(host\) -i ([A-Za-z0-9.-]+)\s*$', text, re.M)
        if len(admin) != 1:
            raise MigrationError('No unique administration hostname')
        if local_probe(admin[0], '/api/control-plane-health') != 200:
            raise MigrationError('The administration control-plane probe failed')
        # A loopback probe must not grant anonymous access to the ordinary UI.
        if local_probe(admin[0], '/') not in (301, 302, 303, 307, 308, 401, 403):
            raise MigrationError('Anonymous access to the administration UI changed')
        if authentication and local_probe(authentication[0], '/api/health') != 200:
            raise MigrationError('The real authentication service is not healthy')
        rows = list(csv.DictReader(runtime(self.paths.socket, 'show stat').lstrip('# ').splitlines()))
        if not any(row.get('pxname') == 'be_admin' for row in rows):
            raise MigrationError('The Runtime API statistics contract changed')

    def units(self):
        suffix = self.state['id'][:12] + '-' + str(self.state.get('generation', 0))
        return 'easy-ha-proxy-haproxy-seed-' + suffix, 'easy-ha-proxy-haproxy-watchdog-' + suffix

    def arm(self, operation):
        self.state.update(operation=operation, seed_ready=False, config_modified=False, recovery_attempts=0,
                          generation=self.state.get('generation', 0) + 1)
        self.save('arming')
        _, watchdog = self.units()
        self.host.watchdog(self.directory, watchdog)

    def abort_downgrade(self):
        if self.state.get('config_modified') and digest(self.paths.config) != self.state['files'][str(self.paths.config)]['digest']:
            self.restore(self.paths.config)
            self.reload(self.state['target_runtime_version'])
        self.finish('committed')

    def bootstrap_seed(self, expected_version):
        layout = self.state['layout']
        name = 'migration-' + self.state['id'][:12]
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        self.state['seed_port'] = port
        self.state['seed_name'] = name
        atomic(self.directory / 'seed.cfg', seed_config(layout, name, port, self.directory / 'seed.sock').encode())
        self.save('bootstrapping_peer')
        seed, _ = self.units()
        candidate = add_seed(self.original(self.paths.config).decode(), layout, name, port)
        temporary = self.directory / 'with-seed.cfg'
        atomic(temporary, candidate.encode(), 0o600)
        self.host.command([str(self.paths.binary), '-c', '-f', str(temporary)])
        original = self.state['files'][str(self.paths.config)]
        self.state['config_modified'] = True
        self.put(self.paths.config, candidate.encode(), original['mode'], original['uid'], original['gid'])
        self.reload(expected_version)
        # A new empty peer must not participate in the live worker's initial
        # reload resynchronization. Start it after the original tables arrived.
        self.host.start_seed(self.directory, seed)
        self.await_tables(self.directory / 'seed.sock')
        self.state['seed_ready'] = True
        self.save('peer_ready')

    def policy_block(self):
        self.put(self.paths.policy, b'#!/bin/sh\n# Temporary HAProxy package migration guard\nexit 101\n', 0o755)
        self.state['policy_blocked'] = True
        self.save()

    def repository_files(self):
        if self.patch:
            return
        repository = ('deb [arch=' + self.state['architecture'] + ' signed-by=' + str(self.paths.signing_key) + '] '
                      + self.vendor.rstrip('/') + ' noble main\n')
        priorities = '''Package: haproxy-awslc
Pin: version 3.4.*
Pin-Priority: 990

Package: haproxy-awslc
Pin: version *
Pin-Priority: -1

Package: haproxy
Pin: version *
Pin-Priority: -1

Package: *
Pin: origin "www.haproxy.com"
Pin-Priority: 100
'''
        self.put(self.paths.repository, repository.encode(), 0o644)
        self.put(self.paths.priorities, priorities.encode(), 0o644)
        self.put(self.paths.signing_key, (self.directory / 'repository.asc').read_bytes(), 0o644)

    def refresh_repository(self):
        if self.patch:
            return
        # The switch and rollback never depend on a network request. Populate
        # only this provider's update index after committing a healthy service.
        try:
            self.host.command(['/usr/bin/apt-get', '--error-on=any', 'update', '-o',
                               'Dir::Etc::sourcelist=' + str(self.paths.repository), '-o',
                               'Dir::Etc::sourceparts=-', '-o', 'APT::Get::List-Cleanup=0'], timeout=60)
            self.state['repository_index_refreshed'] = True
        except MigrationError as error:
            self.state['cleanup_warning'] = 'Provider update index needs a refresh: ' + str(error)
        self.save()

    def install(self, rollback=False):
        command = self.package_command(simulate=True, rollback=rollback)
        parse_apt_plan(self.host.command(command).stdout, self.allowed_packages)
        archives = self.directory / 'archives'
        private_directory(archives)
        packages = ([{'Package': self.state.get('old_package', 'haproxy'), 'Version': self.state['old_version']}]
                    + ([self.state['old_tls']] if self.state.get('old_tls') else []) if rollback
                    else self.state['target_packages'] + self.state.get('extra_packages', []))
        for package in packages:
            source = self.directory / (('tls-old.deb' if package['Package'] == 'libssl-awslc' else 'haproxy-old.deb')
                                       if rollback else package['Package'] + '.deb')
            filename = f'{package["Package"]}_{package["Version"]}_{self.state["architecture"]}.deb'
            atomic(archives / filename, source.read_bytes())
        before = self.host.packages()
        self.state['packages_touched'] = True
        self.save()
        # Noble's needrestart APT hook invokes systemctl directly, independently
        # of policy-rc.d. Suspend that hook only for this bounded transaction;
        # the qualified worker is reexecuted and checked explicitly below.
        self.host.command(self.package_command(rollback=rollback), timeout=120,
                          env_extra={'NEEDRESTART_SUSPEND': '1', 'NEEDRESTART_MODE': 'l'})
        after = self.host.packages()
        changed = {package for package in before.keys() | after.keys() if before.get(package) != after.get(package)}
        if not changed <= self.allowed_packages:
            raise MigrationError('Unexpected package mutation detected')
        if rollback:
            old_name = self.state.get('old_package', 'haproxy')
            if after.get(old_name) != self.state['old_version'] or (not self.patch and 'haproxy-awslc' in after):
                raise MigrationError('The baseline package was not restored')
            if self.state.get('old_tls') and after.get('libssl-awslc') != self.state['old_tls']['Version']:
                raise MigrationError('The baseline TLS package was not restored')
        elif after.get(self.state['target_packages'][0]['Package']) != self.state['target_packages'][0]['Version']:
            raise MigrationError('The target package was not installed')
        if not rollback and any(after.get(package['Package']) != package['Version'] for package in
                                self.state['target_packages'] + self.state.get('extra_packages', [])):
            raise MigrationError('A target dependency version differs from the authenticated preparation')

    def finish(self, phase):
        seed, watchdog = self.units()
        if self.state.get('policy_blocked'):
            self.restore(self.paths.policy)
        self.state['policy_blocked'] = False
        self.resume()
        self.health()
        self.restore_holds(rollback=phase == 'rolled_back')
        self.save(phase)
        try:
            self.resume(timers=True)
            self.host.service('stop', seed + '.service')
        except MigrationError as error:
            self.state['cleanup_warning'] = str(error)
            self.save()
        self.host.cancel_watchdog(watchdog)

    def rollback_locked(self):
        self.save('rolling_back')
        if self.state.get('seed_ready'):
            self.await_tables(self.directory / 'seed.sock')
        for path in (self.paths.repository, self.paths.priorities, self.paths.signing_key):
            self.restore(path)
        self.policy_block()
        current_packages = self.host.packages()
        baseline_intact = (current_packages.get(self.state.get('old_package', 'haproxy')) == self.state['old_version']
                           and (self.patch or 'haproxy-awslc' not in current_packages)
                           and digest(self.paths.binary) == self.state['old_binary_digest'])
        if not baseline_intact or self.state.get('packages_touched'):
            self.install(rollback=True)
        self.host.command(['/usr/bin/systemctl', 'daemon-reload'])
        # Keep the seed in the restored configuration until the restored worker
        # has recovered its tables, even when the candidate service died.
        if self.state.get('seed_ready'):
            candidate = add_seed(self.original(self.paths.config).decode(), self.state['layout'],
                                 self.state['seed_name'], self.state['seed_port'])
            record = self.state['files'][str(self.paths.config)]
            self.put(self.paths.config, candidate.encode(), record['mode'], record['uid'], record['gid'])
        else:
            self.restore(self.paths.config)
        self.store_servers()
        if not self.host.active('haproxy.service'):
            self.host.service('restart')
            self.wait_worker(self.state.get('old_runtime_version', self.state['old_version']))
        self.reload(self.state.get('old_runtime_version', self.state['old_version']))
        self.restore(self.paths.config)
        self.reload(self.state.get('old_runtime_version', self.state['old_version']))
        self.restore(self.paths.variables)
        self.state['rollback_verified'] = True
        self.finish('rolled_back')

    def apply(self, identifier, *, exercise_rollback=False):
        with self.locked():
            self.load(identifier)
            if self.state['phase'] != 'prepared':
                raise MigrationError('Apply requires a freshly prepared transaction')
            self.check_artifacts()
            for path in (self.paths.config, self.paths.variables, self.paths.policy, self.paths.repository,
                         self.paths.priorities, self.paths.signing_key):
                self.unchanged(path)
            _, packages = self.native_preflight()
            if packages[self.state.get('old_package', 'haproxy')] != self.state['old_version'] or digest(self.paths.binary) != self.state['old_binary_digest']:
                raise MigrationError('The baseline package changed after preparation')
            if any(packages.get(name) != version for name, version in self.state['extra_baseline'].items()):
                raise MigrationError('A system dependency changed after preparation')
            if packages.get('libssl-awslc') != self.state['tls_baseline']:
                raise MigrationError('The TLS dependency changed after preparation')
            self.health()
            self.arm('apply')
            _, watchdog = self.units()
            try:
                self.pause()
                # A UI transaction can finish between the first check and
                # stopping controld. Recheck under the quiesced control plane.
                for path in (self.paths.config, self.paths.variables, self.paths.policy, self.paths.repository,
                             self.paths.priorities, self.paths.signing_key):
                    self.unchanged(path)
                self.snapshot()
                self.check_guard()
                self.dump_servers()
                self.bootstrap_seed(self.state.get('old_runtime_version', self.state['old_version']))
                self.policy_block()
                self.repository_files()
                self.save('installing_target')
                previous_pid = self.host.main_pid()
                self.install()
                if self.host.main_pid() != previous_pid or info(self.paths.socket).get('Version') != self.state.get('old_runtime_version', self.state['old_version']):
                    raise MigrationError('An APT hook unexpectedly restarted the live service')
                self.host.command(['/usr/bin/systemctl', 'daemon-reload'])
                self.reload(self.state['target_runtime_version'])
                self.health()
                self.state['target_verified'] = True
                self.save('target_verified')
                if exercise_rollback:
                    raise RollbackExercise('Requested post-switch rollback exercise')
                self.snapshot()
                self.await_tables(self.directory / 'seed.sock')
                self.restore(self.paths.config)
                self.reload(self.state['target_runtime_version'])
                if not self.patch:
                    variables = yaml.safe_load(self.original(self.paths.variables).decode())
                    variables.update(haproxy_package_provider='haproxy-technologies', haproxy_package_branch='3.4')
                    record = self.state['files'][str(self.paths.variables)]
                    self.put(self.paths.variables, yaml.safe_dump(variables, sort_keys=False, allow_unicode=True).encode(),
                             record['mode'], record['uid'], record['gid'])
                self.state['committed_vars_digest'] = digest(self.paths.variables)
                self.state['committed_repository_digests'] = {str(path): digest(path) for path in
                    (self.paths.repository, self.paths.priorities, self.paths.signing_key) if path.exists()}
                self.finish('committed')
            except Exception as error:
                if self.state['phase'] == 'committed':
                    raise MigrationError('Migration committed; inspect the journal for a post-commit cleanup failure') from error
                self.state['failure'] = str(error)
                self.save()
                try:
                    # A verification failure may occur after control services
                    # were resumed. Freeze them again before any rollback write.
                    for unit in self.state.get('resume_units', []):
                        if self.host.active(unit):
                            self.host.service('stop', unit)
                    if 'server_state' in self.state:
                        self.rollback_locked()
                    else:
                        if self.state.get('policy_blocked'):
                            self.restore(self.paths.policy)
                        self.resume()
                        self.resume(timers=True)
                        self.save('aborted')
                        self.host.cancel_watchdog(watchdog)
                except Exception as rollback_error:
                    self.state['rollback_failure'] = str(rollback_error)
                    self.save('rollback_failed')
                    raise MigrationError('Automatic rollback needs operator recovery; preserve the transaction directory') from rollback_error
                if not isinstance(error, RollbackExercise):
                    if self.state['phase'] == 'aborted':
                        raise MigrationError('Migration aborted before the package switch; existing configuration preserved') from error
                    raise MigrationError('Migration failed; the baseline was restored and verified') from error
            if self.state['phase'] == 'committed':
                self.refresh_repository()
            return self.summary()

    def committed_unchanged(self):
        if digest(self.paths.config) != self.state['files'][str(self.paths.config)]['digest']:
            raise MigrationError('Configuration changed since migration; qualify a fresh downgrade')
        if digest(self.paths.variables) != self.state['committed_vars_digest']:
            raise MigrationError('Installer variables changed since migration; qualify a fresh downgrade')
        for name, expected in self.state['committed_repository_digests'].items():
            if digest(Path(name)) != expected:
                raise MigrationError('Repository configuration changed since migration')
        self.unchanged(self.paths.policy)

    def rollback(self, identifier):
        with self.locked():
            self.load(identifier)
            if self.state['phase'] in ('rolled_back', 'aborted'):
                return self.summary()
            if self.state['phase'] != 'committed':
                raise MigrationError('Rollback requires a committed migration; use recover for an interrupted operation')
            if self.state['phase'] == 'committed':
                # A later downgrade is allowed only while the managed source
                # files still match this transaction; never discard later edits.
                self.committed_unchanged()
                if info(self.paths.socket).get('Version') != self.state['target_runtime_version']:
                    raise MigrationError('The target was upgraded since this transaction; qualify a fresh downgrade')
                self.check_artifacts()
                self.health()
                self.arm('rollback')
                try:
                    self.pause()
                    self.committed_unchanged()
                    self.snapshot()
                    self.check_guard()
                    self.dump_servers()
                    self.bootstrap_seed(self.state['target_runtime_version'])
                except Exception:
                    self.abort_downgrade()
                    raise
            self.check_artifacts()
            try:
                self.rollback_locked()
            except Exception as error:
                self.state['rollback_failure'] = str(error)
                self.save('rollback_failed')
                raise
            return self.summary()

    def recover(self, identifier):
        with self.locked():
            self.load(identifier)
            seed, watchdog = self.units()
            if self.state['phase'] == 'preparing':
                self.save('aborted')
                return self.summary()
            if self.state['phase'] in ('committed', 'rolled_back', 'aborted', 'prepared'):
                self.resume()
                self.resume(timers=True)
                self.host.command(['/usr/bin/systemctl', 'stop', seed + '.service'], check=False)
                self.host.cancel_watchdog(watchdog)
                return self.summary()
            attempts = int(self.state.get('recovery_attempts', 0))
            if attempts >= 3:
                self.state['operator_recovery_required'] = True
                self.save('recovery_exhausted')
                return self.summary()
            self.state['recovery_attempts'] = attempts + 1
            self.save()
            if self.state.get('operation') == 'rollback' and not self.state.get('seed_ready'):
                self.abort_downgrade()
            elif 'server_state' not in self.state:
                if self.state.get('policy_blocked'):
                    self.restore(self.paths.policy)
                self.resume()
                self.resume(timers=True)
                self.save('aborted')
                self.host.cancel_watchdog(watchdog)
            else:
                self.check_artifacts()
                self.rollback_locked()
            return self.summary()

    def summary(self):
        return {key: self.state.get(key) for key in ('id', 'kind', 'phase', 'architecture', 'old_version', 'old_runtime_version', 'target_packages',
                                                     'extra_packages',
                                                     'failure', 'rollback_verified', 'target_verified', 'table_counts',
                                                     'cleanup_warning', 'updated_at')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'patch', 'apply', 'rollback', 'recover', 'status'))
    parser.add_argument('--id')
    parser.add_argument('--exercise-rollback', action='store_true')
    parser.add_argument('--expected-version')
    parser.add_argument('--reinstall', action='store_true')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('This operator command must run as root')
    os.umask(0o077)
    engine = Engine()
    try:
        if args.action == 'prepare':
            result = engine.prepare()
        elif args.action == 'patch':
            if not args.expected_version:
                parser.error('--expected-version is required')
            previous = []

            def progress(summary):
                phase = summary.get('phase')
                if not previous or previous[-1] != phase:
                    previous.append(phase)
                    value = 'prepare' if phase in ('preparing', 'prepared') else 'verifying' if phase == 'target_verified' else 'playbook'
                    print('EHP-PROGRESS phase=' + value, flush=True)

            engine.observer = progress
            with engine.locked():
                prepared = engine.prepare_patch(args.expected_version, reinstall=args.reinstall)
                result = engine.apply(prepared['id'], exercise_rollback=args.exercise_rollback)
        elif not args.id:
            parser.error('--id is required')
        elif args.action == 'apply':
            result = engine.apply(args.id, exercise_rollback=args.exercise_rollback)
        elif args.action == 'rollback':
            result = engine.rollback(args.id)
        elif args.action == 'recover':
            result = engine.recover(args.id)
        else:
            engine.load(args.id)
            result = engine.summary()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (MigrationError, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(json.dumps({'error': str(error), 'transaction': engine.state.get('id'),
                          'phase': engine.state.get('phase')}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
