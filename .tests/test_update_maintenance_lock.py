"""An update from the command line cannot run over one started from the panel.

The update broker and the backup daemon hold one lock for every update,
backup, inspection and restore. An update typed on the command line used not
to take it: on the test gateway one ran over an update started from the
panel, and that update's final check saw the panel's container being
recreated and reported the update as failed.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import easy_ha_proxy  # noqa: E402


class TheLock(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.lock = self.directory / "run" / "operation.lock"
        environment = mock.patch.dict(os.environ, {}, clear=False)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(easy_ha_proxy.MAINTENANCE_LOCK_HELD_ENV, None)
        # Typed on a terminal, not run by the broker.
        broker = mock.patch.object(easy_ha_proxy, "started_by_update_broker", return_value=False)
        broker.start()
        self.addCleanup(broker.stop)
        self.addCleanup(self.release)

    def release(self):
        descriptor = easy_ha_proxy._maintenance_lock_descriptor
        if descriptor >= 0:
            os.close(descriptor)
            easy_ha_proxy._maintenance_lock_descriptor = -1

    def test_it_is_taken_and_said_in_the_environment(self):
        easy_ha_proxy.hold_maintenance_lock(self.lock)
        self.assertTrue(self.lock.exists())
        self.assertEqual(os.environ[easy_ha_proxy.MAINTENANCE_LOCK_HELD_ENV], "cli")
        # Held: another taker is refused.
        other = os.open(self.lock, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)

    def test_a_running_operation_refuses_the_update(self):
        self.lock.parent.mkdir(parents=True)
        holder = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        with self.assertRaises(easy_ha_proxy.InstallerError) as raised:
            easy_ha_proxy.hold_maintenance_lock(self.lock)
        self.assertIn("Another maintenance operation", str(raised.exception))
        self.assertNotIn(easy_ha_proxy.MAINTENANCE_LOCK_HELD_ENV, os.environ)

    def test_a_job_whose_lock_is_already_held_does_not_take_it_again(self):
        self.lock.parent.mkdir(parents=True)
        holder = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        for value in ("updated", "cli"):
            os.environ[easy_ha_proxy.MAINTENANCE_LOCK_HELD_ENV] = value
            easy_ha_proxy.hold_maintenance_lock(self.lock)
        self.assertEqual(easy_ha_proxy._maintenance_lock_descriptor, -1)


class RecognisingABrokerJob(unittest.TestCase):
    def cgroup(self, text):
        path = Path(tempfile.mkstemp()[1])
        self.addCleanup(path.unlink)
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_unit_of_a_job_is_recognised(self):
        job = self.cgroup("0::/system.slice/easy-ha-proxy-updated-job-e4ea21b3f3d3.service\n")
        self.assertTrue(easy_ha_proxy.started_by_update_broker(job))
        legacy = self.cgroup(
            "12:pids:/system.slice/easy-ha-proxy-updated-job-0123456789ab.service\n"
            "0::/system.slice/easy-ha-proxy-updated-job-0123456789ab.service\n"
        )
        self.assertTrue(easy_ha_proxy.started_by_update_broker(legacy))

    def test_anything_else_is_not(self):
        for text in (
            "0::/user.slice/user-0.slice/session-3.scope\n",
            "0::/system.slice/ehp-test-update.service\n",
            "0::/system.slice/easy-ha-proxy-updated.service\n",
        ):
            with self.subTest(text=text):
                self.assertFalse(easy_ha_proxy.started_by_update_broker(self.cgroup(text)))
        self.assertFalse(easy_ha_proxy.started_by_update_broker(Path("/nonexistent/cgroup")))


class TheWiring(unittest.TestCase):
    def test_the_update_takes_it_first_and_keeps_it_across_the_restart(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        update = source.split("def command_update(")[1].split("\ndef ")[0]
        self.assertLess(update.index("require_root()"), update.index("hold_maintenance_lock()"))
        self.assertLess(update.index("hold_maintenance_lock()"), update.index("update_managed_source("))
        restart = source.split("def reexec_after_source_update(")[1].split("\ndef ")[0]
        self.assertIn("os.set_inheritable(_maintenance_lock_descriptor, True)", restart)
        self.assertLess(restart.index("set_inheritable"), restart.index("os.execve("))

    def test_the_broker_and_the_cli_name_the_same_lock(self):
        broker = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py").read_text(encoding="utf-8")
        self.assertIn('"/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"', broker)
        self.assertEqual(
            str(easy_ha_proxy.MAINTENANCE_LOCK_PATH),
            os.environ.get("EASY_HA_PROXY_MAINTENANCE_LOCK",
                           "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"),
        )
        self.assertIn('"EASY_HA_PROXY_MAINTENANCE_LOCK_HELD": "updated"', broker)
        self.assertIn('f"easy-ha-proxy-updated-job-', broker)


if __name__ == "__main__":
    unittest.main()
