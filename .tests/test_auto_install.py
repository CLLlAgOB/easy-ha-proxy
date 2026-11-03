"""easy-ha-proxy's own updates can install themselves, at night, when asked.

The operator asked for automatic installation (2026-10-29), and chose its
bounds (2026-11-03): only easy-ha-proxy's own updates -- the host, the panel,
the Authelia images, as the project tested them -- never the operating
system's packages and never a reboot; in a night window of the gateway's
hours, 03:00-05:00 unless changed; off until turned on. It takes the Install
button's own path: a fresh plan, the same selection and guards, the same
worker. A failure or a refusal raises update.failed.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
APP = ROOT / "docker/app/haproxy_admin"
WINDOWS = sys.platform == "win32"


def load_broker():
    name = "easy_ha_proxy_updated_auto_install_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def component(component_id, state="available", **details):
    return {"id": component_id, "state": state, "actionable": state == "available", "details": details}


def at(hour, minute=0, day=4):
    return dt.datetime(2026, 11, day, hour, minute).astimezone()


@unittest.skipIf(WINDOWS, "the broker needs fcntl")
class TheRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = load_broker()

    def test_the_window_keeps_to_its_hours(self):
        inside = self.broker.in_install_window
        self.assertTrue(inside(at(3, 30), 3, 5))
        self.assertFalse(inside(at(5, 0), 3, 5))
        self.assertFalse(inside(at(2, 59), 3, 5))
        # across midnight
        self.assertTrue(inside(at(23, 30), 23, 2))
        self.assertTrue(inside(at(1, 0), 23, 2))
        self.assertFalse(inside(at(2, 0), 23, 2))

    def test_a_night_across_midnight_is_one_night(self):
        night = self.broker.install_night
        self.assertEqual(night(at(23, 30, day=3), 23, 2), night(at(1, 0, day=4), 23, 2))

    def test_the_changes_update_with_the_images_but_not_the_os(self):
        plan = {"components": [
            component("all", scope={"ready": True, "tags": ["ha-cfg"]}),
            component("os"), component("authelia-container"), component("admin-container"),
            component("daemons", state="current"),
        ]}
        self.assertEqual(self.broker.auto_install_selection(plan),
                         ["changes", "authelia-container", "admin-container"])

    def test_the_complete_stack_alone_when_no_changes_update_is_offered(self):
        plan = {"components": [component("all"), component("authelia-container"), component("os")]}
        self.assertEqual(self.broker.auto_install_selection(plan), ["all"])

    def test_only_the_os_is_nothing(self):
        self.assertEqual(self.broker.auto_install_selection({"components": [component("os")]}), [])


@unittest.skipIf(WINDOWS, "the broker needs fcntl")
class TheSchedule(unittest.TestCase):
    def setUp(self):
        self.broker = load_broker()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name, value in (("SETTINGS_PATH", root / "settings.json"),
                            ("AUTO_INSTALL_PATH", root / "auto-install.json"),
                            # root-owned files on a gateway; plain ones here
                            ("atomic_json", lambda path, payload: Path(path).write_text(json.dumps(payload))),
                            ("safe_json_file", lambda path: json.loads(Path(path).read_text()))):
            patcher = mock.patch.object(self.broker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.broker.AUTO_INSTALL_STATE["night"] = None

    def turn_on(self, start=3, end=5):
        return self.broker.set_auto_install({"action": "set_auto_install", "enabled": True,
                                             "start": start, "end": end})

    def test_it_is_off_until_turned_on(self):
        self.assertFalse(self.broker.auto_install_settings()["enabled"])
        with mock.patch.object(self.broker, "auto_install_once") as once:
            self.assertIsNone(self.broker.auto_install_tick(at(3, 30)))
        once.assert_not_called()

    def test_once_a_night_inside_the_window(self):
        self.turn_on()
        with mock.patch.object(self.broker, "auto_install_once", return_value="installed") as once:
            self.assertIsNone(self.broker.auto_install_tick(at(2, 30)))
            self.assertEqual(self.broker.auto_install_tick(at(3, 1)), "installed")
            self.assertIsNone(self.broker.auto_install_tick(at(3, 2)))
            self.assertEqual(self.broker.auto_install_tick(at(3, 1, day=5)), "installed")
        self.assertEqual(once.call_count, 2)

    def test_busy_tries_again_the_next_minute(self):
        self.turn_on()
        with mock.patch.object(self.broker, "auto_install_once", side_effect=["busy", "installed"]) as once:
            self.broker.auto_install_tick(at(3, 1))
            self.broker.auto_install_tick(at(3, 2))
        self.assertEqual(once.call_count, 2)

    def test_a_window_without_hours_is_refused(self):
        with self.assertRaises(self.broker.UpdatedError):
            self.turn_on(start=4, end=4)
        with self.assertRaises(self.broker.UpdatedError):
            self.broker.set_auto_install({"action": "set_auto_install", "enabled": "yes", "start": 3, "end": 5})

    def test_it_installs_through_the_install_buttons_worker(self):
        plan = {"id": "a" * 32, "components": [component("admin-container"), component("os")]}
        with mock.patch.object(self.broker, "load_latest_plan", return_value=plan), \
                mock.patch.object(self.broker, "plan_is_expired", return_value=False), \
                mock.patch.object(self.broker, "validate_selection") as validate, \
                mock.patch.object(self.broker, "acquire_operation", return_value=7), \
                mock.patch.object(self.broker, "new_job", return_value={"id": "b" * 32}), \
                mock.patch.object(self.broker, "apply_worker") as worker, \
                mock.patch.object(self.broker, "load_job", return_value={"status": "completed"}), \
                mock.patch.object(self.broker, "ACTIVE_MARKER", Path("/nonexistent/marker")), \
                mock.patch.object(self.broker, "reboot_guard_present", return_value=False):
            self.assertEqual(self.broker.auto_install_once(), "installed")
        validate.assert_called_once_with(plan, ["admin-container"])
        worker.assert_called_once_with("b" * 32, 7, plan, ["admin-container"])
        self.assertEqual(self.broker.last_auto_install()["outcome"], "installed")

    def test_a_refusal_is_said(self):
        plan = {"id": "a" * 32, "components": [component("all")]}
        refusal = self.broker.UpdatedError("managed configuration is pending", code="config_pending")
        with mock.patch.object(self.broker, "load_latest_plan", return_value=plan), \
                mock.patch.object(self.broker, "plan_is_expired", return_value=False), \
                mock.patch.object(self.broker, "validate_selection", side_effect=refusal), \
                mock.patch.object(self.broker, "report_alert") as alert, \
                mock.patch.object(self.broker, "ACTIVE_MARKER", Path("/nonexistent/marker")), \
                mock.patch.object(self.broker, "reboot_guard_present", return_value=False):
            self.assertEqual(self.broker.auto_install_once(), "refused")
        self.assertEqual(alert.call_args[0][0], "update.failed")
        self.assertEqual(self.broker.last_auto_install()["outcome"], "refused")


class ThePage(unittest.TestCase):
    def test_the_page_offers_it_and_says_its_bounds(self):
        template = (APP / "templates/system_updates.html").read_text(encoding="utf-8")
        self.assertIn('id="updates-auto-install"', template)
        self.assertIn("Operating-system packages and reboots stay with you.", template)
        routes = (APP / "routes_updates.py").read_text(encoding="utf-8")
        self.assertIn('"set_auto_install": ("update.auto_install"', routes)


if __name__ == "__main__":
    unittest.main()
