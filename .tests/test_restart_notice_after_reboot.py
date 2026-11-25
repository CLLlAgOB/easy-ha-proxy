"""The restart notice and the unified window after a night that rebooted.

Two gateways kept "some services require a restart after security updates"
up all day although the unified window was set to restart services itself:

* one rebooted at night and the finding was from before the reboot, which
  restarted every service; with the unified window no check ran by day, so
  nothing replaced it;
* on the other the night stopped at its first stage: the upgrade guard read
  the containers with a Go template that Docker 29 refuses for a container
  without a health check, so the services stage never ran.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
WINDOWS = sys.platform == "win32"
BOOT = 1_000_000.0


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {name: module}):
        spec.loader.exec_module(module)
    return module


class TheGuardReadsEveryContainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.dict(sys.modules):
            sys.path.insert(0, str(ROOT / "installer"))
            try:
                cls.guard = load("restart_notice_guard", ROOT / "installer/os_upgrade_guard.py")
            finally:
                sys.path.remove(str(ROOT / "installer"))

    def inspect(self, state):
        record = [{"Id": "a" * 64, "Name": "/nextcloud", "State": state}]
        with mock.patch.object(self.guard, "run", return_value=json.dumps(record)) as run:
            value = self.guard.container_state("a" * 64)
        # The whole record, never a template that tests a key Docker may omit.
        self.assertNotIn("--format", run.call_args.args[0])
        return value

    def test_a_container_without_a_health_check(self):
        value = self.inspect({"Status": "running", "Paused": False})
        self.assertEqual(value, {"id": "a" * 64, "name": "/nextcloud", "status": "running",
                                 "paused": False, "health": None})

    def test_a_container_with_a_health_check(self):
        value = self.inspect({"Status": "running", "Paused": False, "Health": {"Status": "starting"}})
        self.assertEqual(value["health"], "starting")

    def test_an_unverifiable_record_is_refused(self):
        with mock.patch.object(self.guard, "run", return_value="[]"):
            with self.assertRaises(self.guard.UpgradeRefused):
                self.guard.container_state("a" * 64)


class ThePage(unittest.TestCase):
    def test_the_page_says_the_finding_and_the_run_predate_the_reboot(self):
        script = (ROOT / "go/panel/web/static/js/os_security.js").read_text(encoding="utf-8")
        self.assertIn("restart.before_boot ?", script)
        self.assertIn("const earlierBoot =", script)
        catalog = json.loads((ROOT / "go/panel/web/translations/ru/maintenance_window.json")
                             .read_text(encoding="utf-8"))["messages"]
        for sentence in ("The last check was made before the server rebooted, and the reboot restarted every service. "
                         "A new check runs shortly after startup.",
                         "The last service restart run was before the server rebooted, and the reboot restarted every service."):
            self.assertIn(sentence, script)
            self.assertIn(sentence, catalog)


if __name__ == "__main__":
    unittest.main()
