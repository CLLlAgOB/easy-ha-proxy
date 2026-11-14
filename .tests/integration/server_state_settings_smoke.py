"""Audit config changes against real, isolated HAProxy workers and backends."""
import argparse
import csv
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

from server_state_tls_smoke import main as tls_cases, rpc, running, state


def transition(template, normalizer, before, after, commands=(), expected=None, probe=None, snapshot_expected=None):
    with tempfile.TemporaryDirectory(prefix="ehp-state-settings-") as directory:
        root = Path(directory)
        script = template.read_text().replace(
            "{{ haproxy_socket | default('/run/haproxy/admin.sock') }}", str(root / "admin.sock")
        ).replace("{{ haproxy_server_state_file | default('/var/lib/haproxy/server-state') }}", str(root / "state"))
        (root / "dump.sh").write_text(script)
        with running(root, load=False, **{"tls": False, **before}) as control:
            for command in commands:
                answer = rpc(control, command)
                assert not answer.strip() or "IP changed" in answer, (command, answer)
            config_path = root / "haproxy.cfg"
            desired = (f" server main {after.get('backend_host', '127.0.0.1')}:{after.get('backend_port', 9)}"
                       f" weight {after.get('weight', 100)} {after.get('server_options', '')}"
                       + (" ssl" if after.get("tls") else ""))
            config = re.sub(r"(?m)^ server main .+$", desired, config_path.read_text())
            if before.get("backend_options"):
                config = config.replace(before["backend_options"], "", 1)
            config = config.replace("backend target\n", "backend target\n" + after.get("backend_options", ""), 1)
            config_path.write_text(config)
            subprocess.run(["sh", str(root / "dump.sh"), str(config_path), str(normalizer)], check=True, timeout=5)
            assert (root / "state").is_file(), "The dumper did not create a server-state snapshot"
            if snapshot_expected:
                lines = (root / "state").read_text().splitlines()
                saved = dict(zip(lines[1][2:].split(), lines[2].split(), strict=True))
                for key, value in snapshot_expected.items():
                    assert saved[key] == value, (key, value, saved)
        with running(root, load=True, **{"tls": False, **after}) as control:
            if probe:
                probe(root, control)
            _, actual = state(control)
            rows = csv.DictReader(io.StringIO(rpc(control, "show stat")))
            stats = next(row for row in rows if row["# pxname"] == "target" and row["svname"] == "main")
            actual.update({key: stats[key] for key in ("bck", "slim")})
            actual["check_enabled"] = bool(int(actual["srv_check_state"]) & 4)
            for key, value in (expected or {}).items():
                assert actual[key] == value, (key, value, actual)


def request(root):
    text = (root / "haproxy.cfg").read_text()
    port = int(re.search(r"bind 127\.0\.0\.1:(\d+)", text)[1])
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/", headers={"Host": "client.example.test"})
        reply = connection.getresponse()
        return reply.status, reply.read().decode()
    finally:
        connection.close()


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append((self.headers.get("Host"),
                                     self.connection.selected_alpn_protocol() if isinstance(self.connection, ssl.SSLSocket) else None))
        self.send_response(404 if self.path == "/healthz" else 200)
        self.end_headers()
        self.wfile.write(self.headers.get("Host", "").encode())

    def log_message(self, *_args):
        pass


def main(template, normalizer):
    for command in ("haproxy", "socat", "openssl"):
        assert shutil.which(command), "Missing runtime audit dependency: " + command
    assert normalizer.is_file(), "Missing state normalizer: " + str(normalizer)
    tls_cases(template, normalizer)
    cases = [
        ("IPv4", {}, {"backend_host": "127.0.0.2"}, (), {"srv_addr": "127.0.0.2"}),
        ("IPv6", {}, {"backend_host": "[::1]"}, (), {"srv_addr": "::1"}),
        ("IP to DNS", {}, {"backend_host": "ip6-localhost"}, (), {"srv_addr": "::1", "srv_fqdn": "ip6-localhost"}),
        ("DNS rename", {"backend_host": "localhost"}, {"backend_host": "ip6-localhost"},
         ("set server target/main addr 127.0.0.2",), {"srv_addr": "::1"}),
        ("same DNS cache", {"backend_host": "localhost"}, {"backend_host": "localhost"},
         ("set server target/main addr 127.0.0.2",), {"srv_fqdn": "localhost"}),
        ("configured weight", {}, {"weight": 55}, ("set server target/main weight 17",), {"srv_uweight": "55"}),
        ("zero weight to enabled", {"weight": 0}, {"weight": 100}, (), {"srv_uweight": "100", "srv_admin_state": "0"}),
        ("manual drain with new weight", {}, {"weight": 55}, ("set server target/main state drain",),
         {"srv_uweight": "55", "srv_admin_state": "8"}),
        ("configured disabled to enabled", {"server_options": "disabled"}, {}, (), {"srv_admin_state": "0"}),
        ("enabled to configured disabled", {}, {"server_options": "disabled"}, (), {"srv_admin_state": "5"}),
        ("add health check", {}, {"server_options": "check inter 10s"}, (), {"check_enabled": True}),
        ("remove failed health check", {"server_options": "check inter 10s"}, {},
         ("set server target/main health down",), {"srv_op_state": "2"}),
        ("keep explicit health disable", {"server_options": "check inter 10s"}, {"server_options": "check inter 10s"},
         ("disable health target/main",), {"check_enabled": False}),
        ("backup and maxconn", {}, {"server_options": "backup maxconn 11"}, (), {"bck": "1", "slim": "11"}),
        ("backup to main", {"server_options": "backup"}, {}, (), {"bck": "0"}),
    ]
    passed = []
    for label, before, after, commands, expected in cases:
        # Preserve our cache in the snapshot. HAProxy can legitimately choose
        # a fresh DNS result if the saved IP has a different address family.
        snapshot_expected = {"srv_addr": "127.0.0.2"} if label == "same DNS cache" else None
        transition(template, normalizer, before, after, commands, expected, snapshot_expected=snapshot_expected)
        passed.append(label)
    plain = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    plain.observed = []
    thread = threading.Thread(target=plain.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = {"backend_port": plain.server_port}
        after = {**endpoint, "backend_options": " http-request set-header Host new.example.test\n"}
        def host_probe(root, _control):
            assert request(root) == (200, "new.example.test")
        transition(template, normalizer, endpoint, after, probe=host_probe)
        passed.append("backend Host header")
        after = {**endpoint, "server_options": "check inter 100ms rise 1 fall 1",
                 "backend_options": " option httpchk\n http-check send meth GET uri /healthz\n http-check expect status 404\n"}
        def health_probe(_root, control):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                stats = next(row for row in csv.DictReader(io.StringIO(rpc(control, "show stat")))
                             if row["# pxname"] == "target" and row["svname"] == "main")
                if stats["status"] == "UP" and stats["check_code"] == "404":
                    return
                time.sleep(.025)
            raise AssertionError(stats)
        before = {**endpoint, "server_options": "check inter 10s"}
        # The helper defaults check-ssl; explicitly disable it for this plain backend.
        after["server_options"] += " no-check-ssl"
        transition(template, normalizer, before, after, ("set server target/main health down",), probe=health_probe)
        passed.append("new HTTP health URI and expected status")
    finally:
        plain.shutdown()
        plain.server_close()
        thread.join(timeout=3)
    with tempfile.TemporaryDirectory(prefix="ehp-state-tls-backend-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=backend.example.test", "-addext", "subjectAltName=DNS:backend.example.test",
                        "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        secure = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        secure.observed = []
        names = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["http/1.1", "h2"])
        context.set_servername_callback(lambda _sock, name, _ctx: names.append(name))
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        thread = threading.Thread(target=secure.serve_forever, daemon=True)
        thread.start()
        try:
            before = {"tls": True, "backend_port": secure.server_port,
                      "server_options": "sni str(old.example.test) alpn h2"}
            after = {**before, "server_options": "sni str(new.example.test) alpn http/1.1"}
            def tls_probe(root, _control):
                assert request(root)[0] == 200
                assert names[-1] == "new.example.test", names
                assert secure.observed[-1][1] == "http/1.1", secure.observed
            transition(template, normalizer, before, after, probe=tls_probe)
            passed.append("backend SNI and ALPN")
            for hostname, expected_status in (("backend.example.test", 200), ("wrong.example.test", 503)):
                after = {**before, "server_options": f"verify required ca-file {cert} verifyhost {hostname} sni str({hostname}) alpn http/1.1"}
                def verify_probe(root, _control, expected_status=expected_status, hostname=hostname):
                    response = request(root)
                    assert response[0] == expected_status, (hostname, expected_status, response)
                transition(template, normalizer, before, after, probe=verify_probe)
                passed.append("certificate verification " + hostname)
        finally:
            secure.shutdown()
            secure.server_close()
            thread.join(timeout=3)
    print(json.dumps({"settings_passed": passed, "total_with_tls_port_cases": len(passed) + 4}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--normalizer", type=Path, default=Path(__file__).resolve().parents[2] / "installer/haproxy_server_state.py")
    options = parser.parse_args()
    main(options.template, options.normalizer)
