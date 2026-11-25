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

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"
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


def render_nav(level):
    environment = Environment(loader=FileSystemLoader(str(_WEB_DIR / "templates")), autoescape=True)
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


    def test_the_update_dot_is_still_and_motion_can_be_reduced(self):
        css = (_WEB_DIR / "static/css/styles.css").read_text(encoding="utf-8")
        for selector in (".nav-update-dot {", ".nav-update-dot--product {"):
            self.assertNotIn("animation", css.split(selector)[1].split("}")[0])
        reduced = css.split("@media (prefers-reduced-motion: reduce)")[1]
        self.assertIn("animation-iteration-count: 1 !important", reduced)

    def test_the_updates_page_moves_the_dot_with_its_polls(self):
        script = (_WEB_DIR / "static/js/system_updates.js").read_text(encoding="utf-8")
        self.assertIn("syncNavDot(payload.summary)", script)
        self.assertIn('[data-nav-group="maintenance"] > summary', script)
        self.assertIn('[data-nav-endpoint="system_updates.page"]', script)

    def test_the_titles_are_translated(self):
        catalogue = json.loads((_WEB_DIR / "translations/ru/updates.json").read_text(encoding="utf-8"))["messages"]
        for key in ("Software updates are available", "Operating-system package updates are available"):
            self.assertIn(key, catalogue)


if __name__ == "__main__":
    unittest.main()
