"""A CSRF token is good for as long as its session, not for an hour.

A page reads its token once, when it loads. Flask-WTF's default limit of one
hour made every write from a page left open longer -- "check for updates" on
the updates page, say -- fail with "CSRF validation failed" until the page
was reloaded. These run a real Flask app with Flask-WTF, set up the way the
panel's factory sets it up, and move the clock forward.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock

try:
    import flask
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    from itsdangerous.timed import TimestampSigner
except ImportError:  # pragma: no cover - the web requirements are not installed
    flask = None


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docker/app/haproxy_admin"


def load_security():
    package_name = "csrf_lifetime_test_package"
    package = types.ModuleType(package_name)
    package.__path__ = []
    i18n = types.ModuleType(f"{package_name}.i18n")
    i18n.translate = lambda value: value
    with mock.patch.dict(sys.modules, {package_name: package, f"{package_name}.i18n": i18n}):
        spec = importlib.util.spec_from_file_location(
            f"{package_name}.security", PACKAGE / "security.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@unittest.skipUnless(flask, "Flask and Flask-WTF are not installed")
class ATokenLastsAsLongAsItsSession(unittest.TestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.secret_key = "test-secret"
        load_security().init_csrf(app, CSRFProtect())

        @app.get("/page")
        def page():
            return generate_csrf()

        @app.post("/check")
        def check():
            return "checked"

        self.app = app
        self.client = app.test_client()

    def later(self, seconds):
        now = int(time.time())
        return mock.patch.object(TimestampSigner, "get_timestamp", return_value=now + seconds)

    def post(self, client, token):
        return client.post("/check", headers={"X-CSRFToken": token} if token else {})

    def test_a_page_left_open_still_writes(self):
        token = self.client.get("/page").get_data(as_text=True)
        for hours in (2, 24 * 7):
            with self.subTest(hours=hours), self.later(hours * 3600):
                response = self.post(self.client, token)
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

    def test_the_check_itself_is_still_made(self):
        token = self.client.get("/page").get_data(as_text=True)
        self.assertEqual(self.post(self.client, None).status_code, 400)
        self.assertEqual(self.post(self.client, "not-a-token").status_code, 400)
        # A token belongs to its own session: another browser cannot use it.
        stranger = self.app.test_client()
        stranger.get("/page")
        self.assertEqual(self.post(stranger, token).status_code, 400)


class ThePanelUsesIt(unittest.TestCase):
    def test_the_factory_switches_csrf_on_through_init_csrf(self):
        source = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("init_csrf(app, csrf)", source)
        self.assertNotIn("csrf.init_app(", source)


if __name__ == "__main__":
    unittest.main()
