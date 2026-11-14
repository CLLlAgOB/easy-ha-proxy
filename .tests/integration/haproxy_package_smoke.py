"""Exercise the real generated configuration, Lua, TLS and Runtime API.

Run as root on a disposable system with the selected HAProxy package installed.
All listeners use loopback and temporary ports; no service is started/reloaded.
Authentication responses come from a fixture, not from a real user account.
"""
from __future__ import annotations

import argparse
import csv
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'docker/app'))
from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine, jinja_regex_replace,
)
from haproxy_admin.utils import parse_table_output  # noqa: E402


class Backend(BaseHTTPRequestHandler):
    auth_failure = False
    auth_requests = []

    def do_HEAD(self):
        self.auth_requests.append({'path': self.path, 'cookie': self.headers.get('Cookie')})
        if self.auth_failure:
            self.send_response(503)
        elif self.headers.get('Cookie') == 'session=allowed':
            self.send_response(200)
            self.send_header('Remote-User', 'test-user')
        elif self.headers.get('Cookie') == 'session=redirect':
            self.send_response(302)
            self.send_header('Location', 'https://auth.example.test/')
        else:
            self.send_response(403)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        payload = b'fixture backend\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def runtime(path, command):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        sock.sendall((command + '\n').encode())
        sock.shutdown(socket.SHUT_WR)
        parts = []
        while True:
            part = sock.recv(65536)
            if not part:
                break
            parts.append(part)
        return b''.join(parts).decode()


class LocalTLSConnection(http.client.HTTPSConnection):
    def connect(self):
        plain = socket.create_connection(('127.0.0.1', self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(plain, server_hostname=self.host)


def qualify(expected):
    version = subprocess.check_output(['haproxy', '-v'], text=True).splitlines()[0]
    assert re.search(r'HAProxy version ' + re.escape(expected) + r'\.', version), version
    checks = []
    with tempfile.TemporaryDirectory(prefix='ehp-haproxy-smoke-', dir='/tmp') as tmp:
        base = Path(tmp)
        base.chmod(0o755)
        backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        worker = threading.Thread(target=backend.serve_forever, daemon=True)
        worker.start()
        backend_port = backend.server_port
        tls_port = unused_port()
        config_dir = base / 'etc'
        certs = config_dir / 'certs'
        certs.mkdir(parents=True)
        (base / 'state').mkdir()
        errors = config_dir / 'errors'
        shutil.copytree('/etc/haproxy/errors', errors)
        for name in ('maintenance.http', 'access_granted.http'):
            source = ROOT / 'ansible/roles/haproxy/templates' / (name + '.j2')
            (errors / name).write_text(Environment().from_string(source.read_text()).render())
        shutil.copyfile(ROOT / 'ansible/roles/haproxy/files/default-favicon.ico', errors / 'default-favicon.ico')
        page = ROOT / 'ansible/roles/haproxy/templates/ban_first_step.html.j2'
        (errors / 'ban-first-step.html').write_text(Environment().from_string(page.read_text()).render())
        lua = config_dir / 'lua'
        (lua / 'haproxy-lua-http').mkdir(parents=True)
        source_lua = ROOT / 'ansible/roles/authelia/files/lua'
        shutil.copyfile(source_lua / 'auth-request.lua', lua / 'auth-request.lua')
        shutil.copyfile(source_lua / 'http.lua', lua / 'haproxy-lua-http/http.lua')
        shutil.copyfile(source_lua / 'json.lua', lua / 'json.lua')
        for name in ('admin.allow', 'whitelist.ip', 'guardd-shield-segments.lst', 'guardd-shield-paths.lst', 'guardd-shield-exempt.lst'):
            (config_dir / name).write_text('')
        (config_dir / 'admin.allow').write_text('127.0.0.1\n')
        (config_dir / 'geoip').mkdir()
        (config_dir / 'geoip/whitelist.geo').write_text('')
        key, cert = base / 'key.pem', base / 'cert.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=shop.example.test', '-addext',
            'subjectAltName=DNS:shop.example.test,DNS:admin.example.test,IP:127.0.0.1',
            '-keyout', str(key), '-out', str(cert),
        ], check=True, capture_output=True)
        (certs / 'test.pem').write_bytes(cert.read_bytes() + key.read_bytes())
        env = Environment(loader=FileSystemLoader(str(ROOT / 'ansible/roles/haproxy/templates')),
                          trim_blocks=True, lstrip_blocks=True)
        env.filters.update(regex_replace=jinja_regex_replace, combine=jinja_combine)
        config = env.get_template('haproxy.cfg.j2').render(
            sites=[{'name': 'shop', 'domain': 'shop.example.test',
                    'backend_ip': '127.0.0.1', 'backend_port': backend_port,
                    'authelia_enabled': True}],
            site_defaults={'ban_policy': 'u02'}, tcp_proxies=[], tcp=[],
            admin_domain='admin.example.test', aut_domain='auth.example.test',
            authelia_enabled=True, admin_password=False, enable_geoip=False,
            peers_enabled=False, haproxy_server_state_enabled=False,
            haproxy_socket_group='root', haproxy_certs_dir=str(certs) + '/',
        )
        policy_spec = importlib.util.spec_from_file_location(
            'haproxy_smoke_policy', ROOT / 'ansible/roles/haproxy-admin/files/haproxy-controld.py')
        policy = importlib.util.module_from_spec(policy_spec)
        sys.modules[policy_spec.name] = policy
        policy_spec.loader.exec_module(policy)
        policy._enforce_config_policy(config.encode())
        checks.append('host control service accepts the generated configuration')
        config = config.replace('/etc/haproxy', str(config_dir)).replace('/var/lib/haproxy', str(base / 'state'))
        config = config.replace('/run/haproxy/admin.sock', str(base / 'admin.sock'))
        config = config.replace('ipv4@*:443', '127.0.0.1:' + str(tls_port))
        config = config.replace('127.0.0.1:9091', '127.0.0.1:' + str(backend_port))
        config = config.replace('127.0.0.1:5000', '127.0.0.1:' + str(backend_port))
        conf = base / 'haproxy.cfg'
        conf.write_text(config)
        process_env = dict(os.environ, HAPROXY_ADMIN_PROXY_SECRET='smoke-test-secret-' + 'a' * 40)
        parsed = subprocess.run(['haproxy', '-c', '-f', str(conf)], env=process_env,
                                capture_output=True, text=True)
        assert parsed.returncode == 0, parsed.stdout + parsed.stderr
        assert 'bool-sample-conversion' not in parsed.stderr, parsed.stderr
        assert 'not supported by AWS-LC' not in parsed.stderr, parsed.stderr
        assert 'will still be processed before' not in parsed.stderr, parsed.stderr
        checks.append('generated configuration and Lua load')
        # Every kind of backend the template writes, checked by this HAProxy
        # (not started): a passthrough site, a service site with its access
        # page, a TCP proxy and a paused site. A passthrough backend's ban
        # rule once joined the next directive -- trim_blocks ate its newline
        # -- and only a gateway with such a site found out.
        every_kind = env.get_template('haproxy.cfg.j2').render(
            sites=[{'name': 'shop', 'domain': 'shop.example.test',
                    'backend_ip': '127.0.0.1', 'backend_port': backend_port, 'authelia_enabled': True},
                   {'name': 'files', 'domain': 'files.example.test', 'tcp_passthrough': True,
                    'backend_ip': '127.0.0.1', 'backend_port': backend_port},
                   {'name': 'help', 'domain': 'help.example.test', 'access_gate': True,
                    'authelia_enabled': True, 'access_portal_enabled': True},
                   {'name': 'old', 'domain': 'old.example.test', 'paused': True,
                    'backend_ip': '127.0.0.1', 'backend_port': backend_port}],
            site_defaults={'ban_policy': 'u02'},
            tcp_proxies=[{'name': 'db', 'bind_port': 15432, 'backend_host': '127.0.0.1',
                          'backend_port': backend_port}],
            tcp=[{'name': 'db', 'bind_port': 15432, 'backend_host': '127.0.0.1', 'backend_port': backend_port}],
            admin_domain='admin.example.test', aut_domain='auth.example.test', admin_ips_enabled=True,
            authelia_enabled=True, admin_password=False, enable_geoip=False,
            peers_enabled=False, haproxy_server_state_enabled=False,
            haproxy_socket_group='root', haproxy_certs_dir=str(certs) + '/',
        )
        every_kind = every_kind.replace('/etc/haproxy', str(config_dir)).replace('/var/lib/haproxy', str(base / 'state'))
        every_kind = every_kind.replace('/run/haproxy/admin.sock', str(base / 'admin-every-kind.sock'))
        (base / 'every-kind.cfg').write_text(every_kind)
        parsed = subprocess.run(['haproxy', '-c', '-f', str(base / 'every-kind.cfg')], env=process_env,
                                capture_output=True, text=True)
        assert parsed.returncode == 0, parsed.stdout + parsed.stderr
        checks.append('a configuration with every kind of backend')
        log = base / 'process.log'
        with log.open('w') as output:
            process = subprocess.Popen(['haproxy', '-db', '-f', str(conf)], env=process_env,
                                       stdout=output, stderr=output)
        try:
            for _ in range(100):
                if (base / 'admin.sock').exists():
                    break
                assert process.poll() is None, log.read_text()
                time.sleep(0.05)
            else:
                raise AssertionError('Runtime socket did not appear: ' + log.read_text())

            def request(cookie='', host='admin.example.test', tls_version=None):
                context = ssl.create_default_context(cafile=str(cert))
                if tls_version:
                    context.minimum_version = context.maximum_version = tls_version
                connection = LocalTLSConnection(host, tls_port, context=context, timeout=5)
                try:
                    connection.request('GET', '/', headers={'Host': host, 'Cookie': cookie})
                    response = connection.getresponse()
                    body = response.read()
                    return response.status, response.getheader('Location'), body
                finally:
                    connection.close()

            for host in ('admin.example.test', 'shop.example.test'):
                assert request(host=host)[0] == 403, (host, 'anonymous must be refused')
                authorized = request('session=allowed', host)
                assert authorized[0] == 200, (host, authorized, Backend.auth_requests, log.read_text())
                redirected = request('session=redirect', host)
                assert redirected[:2] == (302, 'https://auth.example.test/'), redirected
            checks.append('Lua forward-auth: anonymous deny, authorized allow, login redirect')
            for version_name in ('TLSv1_2', 'TLSv1_3'):
                assert request('session=allowed', tls_version=getattr(ssl.TLSVersion, version_name))[0] == 200
            checks.append('TLS 1.2 and 1.3 with certificate verification')
            Backend.auth_failure = True
            assert request('session=allowed')[0] == 503, 'Auth failure must fail closed'
            Backend.auth_failure = False
            checks.append('authentication outage fails closed')
            command = 'set table tbl_ban key 198.51.100.20 data.gpc0 1 data.gpt0 900'
            reply = runtime(base / 'admin.sock', command)
            assert not reply.strip(), reply
            table = runtime(base / 'admin.sock', 'show table tbl_ban')
            parsed_table = parse_table_output(table)
            assert parsed_table and '198.51.100.20' in str(parsed_table), table
            assert 'gpc0=1' in table and 'gpt0=900' in table, table
            runtime(base / 'admin.sock', 'clear table tbl_ban key 198.51.100.20')
            assert '198.51.100.20' not in runtime(base / 'admin.sock', 'show table tbl_ban')
            checks.append('Runtime API ban table write/read/application parser/clear')
            raw = runtime(base / 'admin.sock', 'show stat')
            rows = list(csv.DictReader(io.StringIO(raw.lstrip('# '))))
            assert any(r.get('pxname') == 'be_shop' and r.get('svname') == 'BACKEND' for r in rows), raw[:500]
            checks.append('Runtime API statistics retain named CSV fields')
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            backend.shutdown()
            backend.server_close()
            worker.join(timeout=5)
        return {'version': version, 'checks': checks}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-branch', default='3.4')
    args = parser.parse_args()
    print(json.dumps(qualify(args.expected_branch), indent=2))
