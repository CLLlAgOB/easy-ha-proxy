"""The panel's redirects to its own pages keep the scheme the browser used.

TLS ends at HAProxy, so Flask sees plain http. It wrote the trailing-slash
redirect (/system/updates -> /system/updates/) as an absolute http:// URL,
and the browser left https for an address the gateway does not serve.
These run a real Flask app with the panel's hook on it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

try:
    import flask
except ImportError:  # pragma: no cover - the web requirements are not installed
    flask = None


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = "http://gateway.example.test"


def load_security():
    package_name = "panel_redirect_test_package"
    package = types.ModuleType(package_name)
    package.__path__ = []
    i18n = types.ModuleType(f"{package_name}.i18n")
    i18n.translate = lambda value: value
    with mock.patch.dict(sys.modules, {package_name: package, f"{package_name}.i18n": i18n}):
        spec = importlib.util.spec_from_file_location(
            f"{package_name}.security", ROOT / "docker/app/haproxy_admin/security.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@unittest.skipUnless(flask, "Flask is not installed")
class RedirectsStayOnTheBrowsersScheme(unittest.TestCase):
    def setUp(self):
        self.security = load_security()
        app = flask.Flask(__name__)

        @app.get("/system/updates/")
        def updates():
            return "the page"

        @app.get("/login-done")
        def login_done():
            return flask.redirect("/system/updates/?from=login")

        @app.get("/leave")
        def leave():
            return flask.redirect("https://other.example.test/x")

        app.after_request(self.security.keep_redirects_on_this_origin)
        self.app = app
        self.client = app.test_client()

    def test_the_trailing_slash_redirect_is_a_path(self):
        response = self.client.get("/system/updates?tab=history", base_url=GATEWAY)
        self.assertIn(response.status_code, (301, 308))
        self.assertEqual(response.headers["Location"], "/system/updates/?tab=history")

    def test_redirects_that_are_already_paths_or_elsewhere_are_left_alone(self):
        self.assertEqual(
            self.client.get("/login-done", base_url=GATEWAY).headers["Location"],
            "/system/updates/?from=login",
        )
        self.assertEqual(
            self.client.get("/leave", base_url=GATEWAY).headers["Location"],
            "https://other.example.test/x",
        )

    def test_a_doubled_slash_cannot_turn_into_another_host(self):
        with self.app.test_request_context("/", base_url=GATEWAY):
            response = flask.Response(status=308, headers={
                "Location": f"{GATEWAY}//other.example.test/x?y=1",
            })
            self.security.keep_redirects_on_this_origin(response)
        self.assertEqual(response.headers["Location"], "/other.example.test/x?y=1")

    def test_pages_are_untouched(self):
        response = self.client.get("/system/updates/", base_url=GATEWAY)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)


if __name__ == "__main__":
    unittest.main()
