"""A night with nothing to reboot for is not a failed reboot (N02).

Seen on the test gateway: with "also reboot for deferred services" on, the
reboot window opened every night although nothing asked for a reboot. The
broker's own answer -- not required -- was recorded as a deferral with an
error, shown on the page as "the reboot was deferred because maintenance could
not finish safely", and logged as "Scheduled automatic reboot failed" with a
traceback, again every five minutes for the hour the window stays open.

Held here: that answer is an ordinary outcome, the window keeps being looked
at quietly (a reboot can become required during it), and a refusal the broker
gave itself is one log line, not a traceback.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform == "linux":
    import test_auto_reboot as base
    broker = base.broker
else:
    base = broker = None


@unittest.skipUnless(broker, "Linux reboot broker")
class NothingToRebootFor(unittest.TestCase):
    def setUp(self):
        base.RebootBroker.setUp(self)
        installer = broker.SOURCE_DIR / "installer"
        (installer / "auto_reboot.py").write_text("AUTO_REBOOT_PROTOCOL = 1\nSERVICE_REBOOT_PROTOCOL = 1\n")
        (installer / "service_restarts.py").write_text("SERVICE_RESTART_PROTOCOL = 1\n")
        self.reason = patch.object(broker, "service_reboot_reason", return_value=[]).start()
        patch.object(broker, "service_restart_record", return_value={"id": "c" * 32, "enabled": True}).start()
        base.RebootBroker.save(self, allow_service_reboot=True)

    def attempt(self):
        return broker.auto_reboot_record().get("attempt") or {}

    def test_it_is_an_ordinary_answer_with_no_error_and_no_traceback(self):
        with self.assertNoLogs(broker.LOG, level="WARNING"):
            self.assertEqual(broker.auto_reboot_tick(self.now), "not_required")
        attempt = self.attempt()
        self.assertEqual(attempt["state"], "not_required")
        self.assertNotIn("error", attempt)
        self.assertFalse(broker.REBOOT_MARKER.exists())
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())

    def test_the_window_is_not_looked_at_again_for_five_minutes(self):
        broker.auto_reboot_tick(self.now)
        self.assertEqual(broker.auto_reboot_tick(self.now + dt.timedelta(minutes=4)), "waiting")
        self.assertEqual(self.reason.call_count, 1)

    def test_a_reboot_that_becomes_required_during_the_window_is_still_taken(self):
        broker.auto_reboot_tick(self.now)
        broker.REBOOT_REQUIRED_PATH.touch()
        self.assertEqual(broker.auto_reboot_tick(self.now + dt.timedelta(minutes=6)), "scheduled")
        self.assertEqual(self.attempt()["state"], "scheduled")

    def test_deferred_services_still_get_their_reboot(self):
        self.reason.return_value = ["haproxy.service"]
        self.assertEqual(broker.auto_reboot_tick(self.now), "scheduled")

    def test_a_refusal_of_the_brokers_own_is_recorded_and_said_in_one_line(self):
        broker.REBOOT_REQUIRED_PATH.touch()
        broker.haproxy_transaction_active.return_value = True
        with self.assertLogs(broker.LOG, level="WARNING") as logged:
            self.assertEqual(broker.auto_reboot_tick(self.now), "config_pending")
        self.assertEqual(len(logged.records), 1)
        self.assertIsNone(logged.records[0].exc_info)
        attempt = self.attempt()
        self.assertEqual(attempt["state"], "deferred")
        self.assertIn("confirmation", attempt["error"])

    def test_an_unexpected_failure_is_still_raised(self):
        broker.REBOOT_REQUIRED_PATH.touch()
        with patch.object(broker, "request_reboot", side_effect=RuntimeError("no systemd")):
            with self.assertRaises(RuntimeError):
                broker.auto_reboot_tick(self.now)
        self.assertEqual(self.attempt()["state"], "deferred")
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())


if __name__ == "__main__":
    unittest.main()
