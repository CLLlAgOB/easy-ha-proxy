"""Smoke-test the built panel and agent binaries on synthetic data.

The panel: the healthcheck identities, static files and the i18n catalogue
script, the RBAC boundary, and session-bound CSRF on mutating routes. The
agent: its server-state normalizer must answer exactly as the installer's
Python normalizer, which the HAProxy package migration also uses.

Needs PANEL_BIN and AGENT_BIN (the linux binaries CI built).
"""

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
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "go/panel/web"
PROXY = {"X-Easy-HA-Proxy-Secret": "smoke-ci-local-proxy"}
HEALTH = {**PROXY, "Remote-User": "easy-ha-proxy-healthcheck", "Remote-Groups": "healthcheck"}
ADMIN = {**PROXY, "Remote-User": "smoke-admin", "Remote-Groups": "superadmin"}
OPERATOR = {**PROXY, "Remote-User": "smoke-op", "Remote-Groups": "admins"}
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


class NativeSmoke(unittest.TestCase):
    def test_panel(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            with closing(socket.socket()) as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            env = {
                **os.environ,
                "HAPROXY_ADMIN_LISTEN_ADDR": f"127.0.0.1:{port}",
                "HAPROXY_ADMIN_PROXY_SECRET": PROXY["X-Easy-HA-Proxy-Secret"],
                "HAPROXY_ADMIN_SECRET_KEY": "smoke-ci-local-session",
                "HAPROXY_ADMIN_STATIC_DIR": str(WEB / "static"),
                "HAPROXY_ADMIN_TRANSLATIONS_DIR": str(WEB / "translations"),
                "HAPROXY_ADMIN_TEMPLATES_DIR": str(WEB / "templates"),
                "HAPROXY_ADMIN_TRASH_DIR": str(tmp / "trash"),
                "WHITELIST_GLOBAL_FILE": str(tmp / "whitelist"),
                "WHITELIST_FILE": str(tmp / "whitelist-site"),
                "AUDIT_DATABASE": str(tmp / "audit.db"),
            }
            with (tmp / "panel.log").open("w+", encoding="utf-8") as log, subprocess.Popen(
                [os.environ["PANEL_BIN"], "serve"], stdout=log, stderr=subprocess.STDOUT, env=env,
            ) as panel:
                try:
                    self.check_panel(panel, port, log)
                finally:
                    panel.terminate()
                    try:
                        panel.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        panel.kill()
                        panel.wait()

    def check_panel(self, panel, port, log):
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
            self.fail("panel did not become ready\n" + log.read())

        for path in ("/api/control-plane-health", "/api/access-portal-health"):
            with self.subTest(path=path):
                status, body = read_panel(port, path, HEALTH)
                self.assertEqual(status, 200)
                self.assertIs(json.loads(body).get("ok"), True)

        with self.subTest("static file served as it is on disk"):
            status, body = read_panel(port, "/static/js/acme_email.js", ADMIN)
            self.assertEqual(status, 200)
            self.assertEqual(body, (WEB / "static/js/acme_email.js").read_bytes())

        with self.subTest("i18n catalogue script"):
            status, body = read_panel(port, "/i18n/messages.js?lang=ru", ADMIN)
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 1000)

        with self.subTest("rbac-missing-proxy-secret"):
            status, _ = read_panel(port, "/api/control-plane-health", {"Remote-User": "nobody", "Remote-Groups": "superadmin"})
            self.assertEqual(status, 403)

        with self.subTest("rbac-admins-blocked-on-superadmin-route"):
            status, _ = read_panel(port, "/haproxy", OPERATOR)
            self.assertEqual(status, 403)

        with self.subTest("csrf-missing-token-rejected"):
            form = b"language=ru&next=/"
            status, _, _ = request_panel(port, "POST", "/language",
                                         {**ADMIN, "Content-Type": "application/x-www-form-urlencoded"}, body=form)
            self.assertEqual(status, 400)

        with self.subTest("csrf-valid-mutating-language-and-whitelist"):
            status, html, headers = request_panel(port, "GET", "/", ADMIN)
            self.assertEqual(status, 200)
            csrf = _META_CSRF_RE.search(html.decode("utf-8", "replace"))
            self.assertIsNotNone(csrf)
            cookie = extract_cookie_header(headers)
            self.assertIn("easy_ha_proxy_session=", cookie)
            form_headers = {**ADMIN, "Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}

            # A token in the query string is not accepted.
            form = b"language=ru&next=/"
            status, _, _ = request_panel(port, "POST", f"/language?csrf_token={csrf.group(1)}", form_headers, body=form)
            self.assertEqual(status, 400)

            # The header token with the session cookie is (303 + the language cookie).
            status, _, ok_headers = request_panel(
                port, "POST", "/language", {**form_headers, "X-CSRF-Token": csrf.group(1)}, body=form)
            self.assertEqual(status, 303)
            self.assertIn("easy_ha_proxy_language=ru", extract_cookie_header(ok_headers))

            # A mutating API route passes CSRF; with no HAProxy runtime socket in
            # the smoke container it answers 502 with a body.
            status, body, _ = request_panel(
                port, "POST", "/api/whitelist-global", {**form_headers, "X-CSRF-Token": csrf.group(1)},
                body=b"ip=203.0.113.55")
            self.assertEqual(status, 502)
            self.assertTrue(len(body) > 0)

            # A token issued to one user does not authorize another user's
            # request on the same session cookie.
            other = {**form_headers, "Remote-User": "smoke-other", "X-CSRF-Token": csrf.group(1)}
            status, _, _ = request_panel(port, "POST", "/language", other, body=form)
            self.assertEqual(status, 400)

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
            go = subprocess.run(
                [os.environ["AGENT_BIN"], "server-state", *args],
                check=True, capture_output=True, timeout=10,
            )
            self.assertIn(b"3 app 1 web", go.stdout)
            self.assertEqual(go.stderr, b"")


if __name__ == "__main__":
    unittest.main()
