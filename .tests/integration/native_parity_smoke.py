"""Compare public panel reads and the server-state CLI on synthetic data."""

from __future__ import annotations

from contextlib import closing
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
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
OPERATOR = {**PROXY, "Remote-User": "parity-op", "Remote-Groups": "admins"}
_META_CSRF_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"')


def request_panel(port, method, path, headers, body=None):
    with closing(HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(), response.getheaders()


def read_panel(port, path, headers):
    status, body, _ = request_panel(port, "GET", path, headers)
    return status, body


def extract_cookie_header(headers):
    parts = []
    for key, val in headers:
        if key.lower() == "set-cookie":
            cookie = SimpleCookie()
            cookie.load(val)
            for name, morsel in cookie.items():
                parts.append(f"{name}={morsel.value}")
    return "; ".join(parts)


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

        # MED-35: RBAC boundary parity (unauthenticated & non-superadmin vs superadmin).
        with self.subTest("rbac-missing-proxy-secret"):
            legacy = flask.get("/api/control-plane-health", headers={"Remote-User": "nobody", "Remote-Groups": "superadmin"})
            status, _ = read_panel(port, "/api/control-plane-health", {"Remote-User": "nobody", "Remote-Groups": "superadmin"})
            self.assertEqual(status, legacy.status_code)
            self.assertEqual(status, 403)

        with self.subTest("rbac-admins-blocked-on-superadmin-route"):
            legacy = flask.get("/haproxy", headers=OPERATOR)
            status, _ = read_panel(port, "/haproxy", OPERATOR)
            self.assertEqual(status, legacy.status_code)
            self.assertEqual(status, 403)

        # MED-35: CSRF enforcement & mutating route parity (/language + /api/whitelist-global).
        with self.subTest("csrf-missing-token-rejected"):
            form = b"language=ru&next=/"
            hdrs = {**ADMIN, "Content-Type": "application/x-www-form-urlencoded"}
            legacy = flask.post("/language", data=form, headers=hdrs)
            status, _, _ = request_panel(port, "POST", "/language", hdrs, body=form)
            self.assertEqual(status, legacy.status_code)
            self.assertEqual(status, 400)

        with self.subTest("csrf-valid-mutating-language-and-whitelist"):
            legacy_get = flask.get("/", headers=ADMIN)
            self.assertEqual(legacy_get.status_code, 200)
            legacy_csrf = _META_CSRF_RE.search(legacy_get.get_data(as_text=True))
            self.assertIsNotNone(legacy_csrf)

            go_status, go_html, go_hdrs = request_panel(port, "GET", "/", ADMIN)
            self.assertEqual(go_status, 200)
            go_csrf = _META_CSRF_RE.search(go_html.decode("utf-8", "replace"))
            self.assertIsNotNone(go_csrf)
            go_cookie = extract_cookie_header(go_hdrs)
            self.assertIn("easy_ha_proxy_session=", go_cookie)

            # Query-string CSRF must be rejected on both stacks.
            form = b"language=ru&next=/"
            legacy_qs = flask.post(
                f"/language?csrf_token={legacy_csrf.group(1)}",
                data=form,
                headers={**ADMIN, "Content-Type": "application/x-www-form-urlencoded"},
            )
            go_qs_status, _, _ = request_panel(
                port,
                "POST",
                f"/language?csrf_token={go_csrf.group(1)}",
                {**ADMIN, "Content-Type": "application/x-www-form-urlencoded", "Cookie": go_cookie},
                body=form,
            )
            self.assertEqual(go_qs_status, legacy_qs.status_code)
            self.assertEqual(go_qs_status, 400)

            # Header CSRF + matching session cookie succeeds on form POST /language (303 + cookie).
            legacy_ok = flask.post(
                "/language",
                data=form,
                headers={
                    **ADMIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRF-Token": legacy_csrf.group(1),
                },
            )
            go_ok_status, _, go_ok_hdrs = request_panel(
                port,
                "POST",
                "/language",
                {
                    **ADMIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": go_cookie,
                    "X-CSRF-Token": go_csrf.group(1),
                },
                body=form,
            )
            self.assertEqual(go_ok_status, legacy_ok.status_code)
            self.assertEqual(go_ok_status, 303)
            self.assertIn("easy_ha_proxy_language=ru", extract_cookie_header(go_ok_hdrs))

            # Form mutating route with CSRF: /api/whitelist-global (writes IP to file;
            # runtime HAProxy reload socket is absent in smoke container so both return 502).
            wl_body = b"ip=203.0.113.55"
            legacy_wl = flask.post(
                "/api/whitelist-global",
                data=wl_body,
                headers={
                    **ADMIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRF-Token": legacy_csrf.group(1),
                },
            )
            go_wl_status, go_wl_body, _ = request_panel(
                port,
                "POST",
                "/api/whitelist-global",
                {
                    **ADMIN,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": go_cookie,
                    "X-CSRF-Token": go_csrf.group(1),
                },
                body=wl_body,
            )
            self.assertEqual(go_wl_status, legacy_wl.status_code)
            self.assertEqual(go_wl_status, 502)
            self.assertTrue(len(go_wl_body) > 0)

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
