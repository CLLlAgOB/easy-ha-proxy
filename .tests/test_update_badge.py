"""A dot in the navigation when updates are waiting.

Beside "Maintenance" and beside "Software updates", for a superadmin -- the
only one who can install anything. It glows for easy-ha-proxy's own updates;
operating-system packages, which come nearly every day, get a quiet dot that
does not compete with it. The page renders it on the server, so it never pops
in after load: the answer comes from a small broker "summary" kept for a
minute per worker, asked with a one-second timeout, and a broker that is busy
or gone costs nothing but the dot. The updates page keeps it current while
it polls, so a check or an installation shows at once.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
WINDOWS = sys.platform == "win32"
sys.path.insert(0, str(ROOT / "docker" / "app"))


def load_broker():
    name = "easy_ha_proxy_updated_badge_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def plan(*available):
    return {"created_at": "2026-10-26T20:00:00+00:00", "components": [
        {"id": component_id, "state": "available", "actionable": True} for component_id in available
    ] + [{"id": "daemons", "state": "current", "actionable": False},
         {"id": "admin-container", "state": "blocked", "actionable": False}]}


@unittest.skipIf(WINDOWS, "the broker needs fcntl")
class TheBrokerSummary(unittest.TestCase):
    def setUp(self):
        self.broker = load_broker()

    def test_easy_ha_proxy_updates_glow_and_os_packages_stay_quiet(self):
        self.assertEqual(self.broker.summary_payload(plan("all", "os"))["level"], "product")
        self.assertEqual(self.broker.summary_payload(plan("admin-container"))["level"], "product")
        self.assertEqual(self.broker.summary_payload(plan("os"))["level"], "os")
        self.assertIsNone(self.broker.summary_payload(plan())["level"])
        self.assertIsNone(self.broker.summary_payload(None)["level"])

    def test_it_is_a_request_of_its_own_and_part_of_the_status(self):
        self.assertEqual(self.broker.REQUEST_FIELDS["summary"], frozenset({"action"}))
        with mock.patch.object(self.broker, "load_latest_plan", return_value=plan("os")):
            self.assertEqual(self.broker.dispatch({"action": "summary"})["level"], "os")
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertIn('"summary": summary_payload(plan)', source)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePanelCache(unittest.TestCase):
    def setUp(self):
        import flask
        from haproxy_admin import updates_badge

        self.badge = updates_badge
        self.badge.forget()
        self.addCleanup(self.badge.forget)
        self.app = flask.Flask("badge-test")

    def level(self, superadmin=True):
        import flask
        with self.app.test_request_context():
            flask.g.is_superadmin = superadmin
            return self.badge.current_level()

    def test_only_a_superadmin_sees_it_and_nobody_else_costs_a_request(self):
        with mock.patch.object(self.badge, "updated_request") as request:
            self.assertIsNone(self.level(superadmin=False))
        request.assert_not_called()

    def test_one_request_a_minute(self):
        with mock.patch.object(self.badge, "updated_request",
                               return_value={"ok": True, "level": "product"}) as request:
            self.assertEqual(self.level(), "product")
            self.assertEqual(self.level(), "product")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["timeout"], self.badge.BADGE_TIMEOUT_SECONDS)
        self.assertLessEqual(self.badge.BADGE_TIMEOUT_SECONDS, 1.0)

    def test_a_broker_that_is_gone_or_old_costs_only_the_dot(self):
        for outcome in (OSError("no socket"), {"ok": False, "error": "unknown update broker action"},
                        {"ok": True, "level": "something-else"}):
            with self.subTest(outcome=outcome):
                self.badge.forget()
                side = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
                with mock.patch.object(self.badge, "updated_request", **side):
                    self.assertIsNone(self.level())

    def test_the_updates_page_keeps_it_current(self):
        self.badge.remember({"level": "os"})
        with mock.patch.object(self.badge, "updated_request") as request:
            self.assertEqual(self.level(), "os")
        request.assert_not_called()
        routes = (APP / "routes_updates.py").read_text(encoding="utf-8")
        status = routes.split("def status_view(")[1].split("\n\n\n")[0]
        self.assertIn('updates_badge.remember(data["summary"])', status)


def render_nav(level):
    environment = Environment(loader=FileSystemLoader(str(APP / "templates")), autoescape=True)
    return environment.get_template("_haproxy_nav.html").render(
        url_for=lambda name, **kwargs: f"/{name}",
        request=SimpleNamespace(endpoint="routes.index"),
        updates_badge=level,
        debug_routes_enabled=False,
    )


class TheNavigation(unittest.TestCase):
    def test_the_dot_sits_beside_maintenance_and_software_updates(self):
        html = render_nav("product")
        self.assertEqual(html.count('class="nav-update-dot nav-update-dot--product"'), 2)
        maintenance = html.split('data-nav-group="maintenance"')[1].split("</summary>")[0]
        self.assertIn("nav-update-dot--product", maintenance)
        item = html.split('data-nav-endpoint="system_updates.page"')[1].split("</a>")[0]
        self.assertIn("nav-update-dot--product", item)
        self.assertIn('title="Software updates are available"', html)

    def test_os_packages_get_the_quiet_dot_and_nothing_gets_none(self):
        self.assertEqual(render_nav("os").count("nav-update-dot--os"), 2)
        self.assertIn("Operating-system package updates are available", render_nav("os"))
        self.assertNotIn("nav-update-dot", render_nav(None))

    def test_every_page_is_given_the_level(self):
        init = (APP / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("def inject_updates_badge():", init)
        self.assertIn('{"updates_badge": updates_badge.current_level()}', init)

    def test_the_glow_respects_reduced_motion(self):
        css = (APP / "static/css/styles.css").read_text(encoding="utf-8")
        self.assertIn("@keyframes nav-update-glow", css)
        reduced = css.split("@media (prefers-reduced-motion: reduce)")
        self.assertTrue(any(".nav-update-dot--product" in part.split("}\n}")[0] for part in reduced[1:]))

    def test_the_updates_page_moves_the_dot_with_its_polls(self):
        script = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")
        self.assertIn("syncNavDot(payload.summary)", script)
        self.assertIn('[data-nav-group="maintenance"] > summary', script)
        self.assertIn('[data-nav-endpoint="system_updates.page"]', script)

    def test_the_titles_are_translated(self):
        catalogue = json.loads((APP / "translations/ru/updates.json").read_text(encoding="utf-8"))["messages"]
        for key in ("Software updates are available", "Operating-system package updates are available"):
            self.assertIn(key, catalogue)


if __name__ == "__main__":
    unittest.main()
