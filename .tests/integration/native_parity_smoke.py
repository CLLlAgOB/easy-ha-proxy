"""Compare public panel reads and the server-state CLI on synthetic data."""

from __future__ import annotations

from contextlib import closing
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "docker/app/haproxy_admin"
PROXY = {"X-Easy-HA-Proxy-Secret": "parity-ci-local-proxy"}
HEALTH = {**PROXY, "Remote-User": "easy-ha-proxy-healthcheck", "Remote-Groups": "healthcheck"}
ADMIN = {**PROXY, "Remote-User": "parity-admin", "Remote-Groups": "superadmin"}


def read_panel(port, path, headers):
    with closing(HTTPConnection("127.0.0.1", port, timeout=2)) as connection:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()


class NativeParitySmoke(unittest.TestCase):
    def test_panel_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            with closing(socket.socket()) as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]

            env = {
                "HAPROXY_ADMIN_LISTEN_ADDR": f"127.0.0.1:{port}",
                "HAPROXY_ADMIN_PROXY_SECRET": PROXY["X-Easy-HA-Proxy-Secret"],
                "HAPROXY_ADMIN_SECRET_KEY": "parity-ci-local-session",
                "HAPROXY_ADMIN_STATIC_DIR": str(APP / "static"),
                "HAPROXY_ADMIN_TRANSLATIONS_DIR": str(APP / "translations"),
                "HAPROXY_ADMIN_TEMPLATES_DIR": str(APP / "templates"),
                "HAPROXY_ADMIN_TRASH_DIR": str(tmp / "trash"),
                "WHITELIST_GLOBAL_FILE": str(tmp / "whitelist"),
                "WHITELIST_FILE": str(tmp / "whitelist-site"),
                "AUDIT_DATABASE": str(tmp / "audit.db"),
            }
            sys.path.insert(0, str(APP.parent))
            with patch.dict(os.environ, env):
                from haproxy_admin import create_app

                flask = create_app().test_client()
                with (tmp / "panel.log").open("w+", encoding="utf-8") as log, subprocess.Popen(
                    [os.environ["PANEL_BIN"], "serve"], stdout=log, stderr=subprocess.STDOUT,
                ) as panel:
                    try:
                        self.check_panel_reads(panel, port, flask, log)
                    finally:
                        panel.terminate()
                        try:
                            panel.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            panel.kill()
                            panel.wait()

    def check_panel_reads(self, panel, port, flask, log):
        deadline = time.monotonic() + 10
        while panel.poll() is None and time.monotonic() < deadline:
            try:
                if read_panel(port, "/api/control-plane-health", HEALTH)[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            log.seek(0)
            self.fail("Go panel did not become ready\n" + log.read())

        for path in ("/api/control-plane-health", "/api/access-portal-health"):
            with self.subTest(path=path):
                legacy = flask.get(path, headers=HEALTH)
                status, body = read_panel(port, path, HEALTH)
                self.assertEqual(status, legacy.status_code)
                self.assertEqual(json.loads(body), legacy.get_json())
                self.assertEqual(status, 200)

        for path in ("/static/js/acme_email.js", "/i18n/messages.js?lang=ru"):
            with self.subTest(path=path):
                legacy = flask.get(path, headers=ADMIN)
                status, body = read_panel(port, path, ADMIN)
                self.assertEqual(status, 200)
                self.assertEqual((status, body), (legacy.status_code, legacy.data))

    def test_server_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, state = root / "haproxy.cfg", root / "server.state"
            config.write_text("defaults\n  default-server check\nbackend app\n  server web 192.0.2.10:80\n")
            state.write_text(
                "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight "
                "srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health "
                "srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord\n"
                "3 app 1 web 192.0.2.10 2 0 1 1 100 6 3 4 6 0 0 0 - 80 -\n"
            )
            args = ["--config", str(config), "--state", str(state)]
            python = subprocess.run(
                [sys.executable, str(ROOT / "installer/haproxy_server_state.py"), *args],
                check=True, capture_output=True, timeout=10,
            )
            go = subprocess.run(
                [os.environ["AGENT_BIN"], "server-state", *args],
                check=True, capture_output=True, timeout=10,
            )
            self.assertIn(b"3 app 1 web", python.stdout)
            self.assertEqual((go.stdout, go.stderr), (python.stdout, python.stderr))


if __name__ == "__main__":
    unittest.main()
