"""The panel's side of switching monitors: what it accepts, what it forwards,
and that the page offers every monitor the daemon knows, in both languages."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_monitoring as monitoring  # noqa: E402


def daemon():
    spec = importlib.util.spec_from_file_location(
        "metricsd_monitors_panel", ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SavingTheChoice(unittest.TestCase):
    def test_only_known_monitors_and_booleans_are_forwarded(self):
        for changes in (None, [], {}, {"machnie": False}, {"machine": "off"}, {"machine": 0}):
            with self.subTest(changes=changes):
                with mock.patch.object(monitoring, "metricsd_monitors_save") as saved:
                    with self.assertRaises(ValueError):
                        monitoring.save_monitors(changes)
                saved.assert_not_called()
        with mock.patch.object(monitoring, "metricsd_monitors_save", return_value={"ok": True}) as saved:
            monitoring.save_monitors({"machine": False, "latency": True})
        saved.assert_called_once_with({"machine": False, "latency": True})

    def test_the_panel_and_the_daemon_name_the_same_monitors(self):
        module = daemon()
        self.assertEqual(set(monitoring.MONITORS), set(module.MONITOR_DEFAULTS))


class ThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (APP / "templates/monitoring.html").read_text(encoding="utf-8")
        cls.routes = (APP / "routes_monitoring.py").read_text(encoding="utf-8")
        # Every Russian catalogue, wherever it lives, as the panel loads them.
        cls.catalog = {}
        for path in (APP / "translations").rglob("*.json"):
            catalogue = json.loads(path.read_text(encoding="utf-8"))
            if catalogue.get("meta", {}).get("code") == "ru":
                cls.catalog.update(catalogue["messages"])

    def test_every_monitor_has_its_switch(self):
        offered = set(re.findall(r'data-monitor="([a-z]+)"', self.template))
        self.assertEqual(offered, set(monitoring.MONITORS))

    def test_only_a_superadmin_switches_them(self):
        route = self.routes.split('@bp.post("/api/monitoring/monitors")')[1].split("@bp.")[0]
        self.assertIn('getattr(g, "is_superadmin", False)', route)
        self.assertIn("403", route)
        self.assertIn('"monitoring.monitors"', route)
        self.assertIn('data-editable="{{ \'true\' if can_switch_monitors else \'false\' }}"', self.template)

    def test_the_card_reads_in_russian(self):
        card = self.template.split('id="mon-monitors-card"')[1].split('id="mon-overlay"')[0]
        texts = [
            " ".join(text.split())
            for text in re.findall(r">([^<>{}]+)<", card)
            if text.strip() and not text.strip().startswith("{%")
        ]
        self.assertTrue(texts)
        for text in texts:
            with self.subTest(text=text):
                self.assertIn(text, self.catalog)
        for message in ("Saved", "Not saved"):
            self.assertIn(message, self.catalog)


if __name__ == "__main__":
    unittest.main()
