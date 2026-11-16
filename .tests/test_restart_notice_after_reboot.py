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

import datetime as dt
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


@unittest.skipIf(WINDOWS, "the broker needs fcntl")
class AFindingFromBeforeTheBoot(unittest.TestCase):
    def setUp(self):
        self.b = load("restart_notice_broker", BROKER)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(self.b, "boot_started_at", return_value=BOOT).start()
        self.started = mock.patch.object(self.b, "start_os_security").start()
        self.status = {"last_attempt": BOOT - 600, "last_success": BOOT - 600,
                       "restart": {"checked_at": BOOT - 600, "services": ["containerd.service"],
                                   "reboot_required": False, "error": None}}
        mock.patch.object(self.b, "os_security_snapshot", side_effect=lambda: {
            "available": True, "recovery_required": False,
            "policy": {"mode": "daily", "interval": 4, "start": 2, "end": 3},
            "status": json.loads(json.dumps(self.status))}).start()

    def at(self, seconds):
        return dt.datetime.fromtimestamp(BOOT + seconds, dt.timezone.utc)

    def test_it_is_rechecked_soon_after_the_boot(self):
        self.assertEqual(self.b.os_security_check_tick(self.at(900)), "started")
        self.started.assert_called_once_with({"action": "os_security_check"}, scheduled=True)

    def test_the_unified_window_never_installs_from_this_tick(self):
        self.status["restart"]["checked_at"] = BOOT + 60
        self.status["last_success"] = BOOT + 60 - 5 * 3600
        self.status["last_attempt"] = BOOT + 60 - 5 * 3600
        self.assertEqual(self.b.os_security_check_tick(self.at(3600)), "started")
        self.started.assert_called_once_with({"action": "os_security_check"}, scheduled=True)

    def test_a_fresh_finding_waits_for_the_interval(self):
        self.status.update(last_attempt=BOOT + 60, last_success=BOOT + 60)
        self.status["restart"]["checked_at"] = BOOT + 60
        self.assertEqual(self.b.os_security_check_tick(self.at(3600)), "waiting")
        self.started.assert_not_called()

    def test_a_failed_check_after_the_boot_waits_half_an_hour(self):
        self.status["last_attempt"] = BOOT + 900
        self.assertEqual(self.b.os_security_check_tick(self.at(1200)), "waiting")
        self.assertEqual(self.b.os_security_check_tick(self.at(900 + 1801)), "started")

    def test_the_page_is_told_and_the_alert_resolves(self):
        self.assertTrue(self.b.restart_check_predates_boot(self.status["restart"]))
        self.assertFalse(self.b.restart_check_predates_boot({"checked_at": BOOT + 1}))
        alerts = mock.Mock()
        with mock.patch.object(self.b, "_ALERTS", alerts):
            self.b.os_security_notifications({"status": {"state": "ready", "package_count": 0, **self.status}})
        restart = [call for call in alerts.observe.call_args_list if call.args[0] == "os.security_restart"]
        self.assertFalse(restart[0].kwargs["active"])

    def test_the_unified_loop_runs_checks_instead_of_nothing(self):
        source = BROKER.read_text(encoding="utf-8")
        self.assertIn("answer = os_security_check_tick() if unified else os_security_tick()", source)


class ThePage(unittest.TestCase):
    def test_the_page_says_the_finding_and_the_run_predate_the_reboot(self):
        script = (ROOT / "docker/app/haproxy_admin/static/js/os_security.js").read_text(encoding="utf-8")
        self.assertIn("restart.before_boot ?", script)
        self.assertIn("const earlierBoot =", script)
        catalog = json.loads((ROOT / "docker/app/haproxy_admin/translations/ru/maintenance_window.json")
                             .read_text(encoding="utf-8"))["messages"]
        for sentence in ("The last check was made before the server rebooted, and the reboot restarted every service. "
                         "A new check runs shortly after startup.",
                         "The last service restart run was before the server rebooted, and the reboot restarted every service."):
            self.assertIn(sentence, script)
            self.assertIn(sentence, catalog)


if __name__ == "__main__":
    unittest.main()
