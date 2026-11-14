"""Managed OS security that is not running says so, job or no job (N01).

Under a managed policy the native Linux upgrade timer is switched off and the
update broker installs security fixes itself. Its alerts were sent only at
the end of a job, so everything that keeps a job from starting -- a policy
change left half done, a state that cannot be read, a schedule that is
refused every time -- ended in silence: nothing installed, nothing said, and
the earlier alerts going stale after eight days.

Held here: the broker looks at this on every pass of its schedule and reports
`os.security_stalled`, and a gateway Linux manages itself is never reported.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform == "linux":
    from test_haproxy_update_broker import broker
else:
    broker = None

NOW = 1_800_000_000.0
HOUR = 3600


@unittest.skipUnless(broker, "Linux update broker")
class Stalled(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.addCleanup(patch.stopall)
        patch.object(broker, "OS_SECURITY_ROOT", self.root).start()
        patch.object(broker, "active_job", return_value=None).start()
        # The real reader also insists on a root-owned file.
        patch.object(broker, "safe_json_file", side_effect=lambda p: json.loads(p.read_text())).start()
        self.snapshot = {"policy": {"mode": "daily", "interval": 4, "start": 2, "end": 3},
                         "status": {"state": "ready", "last_success": NOW - HOUR}, "recovery_required": False,
                         "available": True}
        patch.object(broker, "os_security_snapshot", side_effect=lambda: dict(self.snapshot)).start()

    def policy(self, mode="daily", phase="ready", updated_at=NOW - 90 * 24 * HOUR, interval=4):
        (self.root / "policy.json").write_text(json.dumps({
            "phase": phase, "updated_at": updated_at,
            "policy": {"mode": mode, "interval": interval, "start": 2, "end": 3}}))

    def test_a_gateway_that_was_never_taken_over_is_not_reported(self):
        self.assertEqual(broker.os_security_stalled(NOW), "")

    def test_linux_managing_itself_is_not_reported(self):
        self.policy(mode="system")
        self.snapshot["status"] = {}
        self.assertEqual(broker.os_security_stalled(NOW), "")

    def test_a_recent_successful_check_is_not_reported(self):
        self.policy()
        self.assertEqual(broker.os_security_stalled(NOW), "")

    def test_a_policy_change_left_half_done_is_reported(self):
        self.policy(phase="recovery_required")
        self.assertIn("needing recovery", broker.os_security_stalled(NOW))

    def test_a_policy_change_in_progress_is_not(self):
        self.policy(phase="configuring")
        broker.active_job.return_value = {"operation": "security-configure", "status": "running"}
        self.assertEqual(broker.os_security_stalled(NOW), "")

    def test_a_policy_that_cannot_be_read_is_reported(self):
        (self.root / "policy.json").write_text("{not json")
        self.assertIn("cannot be read", broker.os_security_stalled(NOW))

    def test_an_invalid_policy_is_reported(self):
        (self.root / "policy.json").write_text(json.dumps({"phase": "ready", "policy": {"mode": "everything"}}))
        self.assertIn("cannot be read", broker.os_security_stalled(NOW))

    def test_a_missing_tool_under_a_managed_policy_is_reported(self):
        self.policy()
        self.snapshot = {"policy": {"mode": "system", "interval": 4, "start": 3, "end": 5}, "status": None,
                         "recovery_required": False, "available": False,
                         "error": "Update host services before using OS security management"}
        self.assertIn("cannot run", broker.os_security_stalled(NOW))

    def test_no_successful_check_for_a_day_is_reported_with_the_last_error(self):
        self.policy()
        self.snapshot["status"] = {"state": "unknown", "last_success": NOW - 30 * HOUR, "error": "APT is busy"}
        reason = broker.os_security_stalled(NOW)
        self.assertIn("for 30 hours", reason)
        self.assertIn("APT is busy", reason)

    def test_a_schedule_that_cannot_start_names_its_answer(self):
        self.policy()
        self.snapshot["status"] = {"state": "ready", "last_success": NOW - 30 * HOUR}
        self.assertIn("config_pending", broker.os_security_stalled(NOW, "config_pending"))

    def test_a_long_interval_gets_three_of_its_own(self):
        self.policy(interval=24)
        self.snapshot["policy"]["interval"] = 24
        self.snapshot["status"] = {"state": "ready", "last_success": NOW - 60 * HOUR}
        self.assertEqual(broker.os_security_stalled(NOW), "")
        self.snapshot["status"]["last_success"] = NOW - 73 * HOUR
        self.assertIn("for 73 hours", broker.os_security_stalled(NOW))

    def test_a_policy_saved_today_is_given_its_first_day(self):
        self.policy(updated_at=NOW - 2 * HOUR)
        self.snapshot["status"] = None
        self.assertEqual(broker.os_security_stalled(NOW), "")


@unittest.skipUnless(broker, "Linux update broker")
class TheWatch(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.alerts = Mock()
        patch.object(broker, "_ALERTS", self.alerts).start()
        patch.dict(broker.OS_SECURITY_WATCH, {"at": 0.0, "reason": None}).start()
        self.reason = patch.object(broker, "os_security_stalled", return_value="").start()

    def test_it_reports_a_healthy_state_too_so_the_alert_can_close(self):
        broker.os_security_watch(NOW)
        call = self.alerts.observe.call_args
        self.assertEqual(call.args[:2], ("os.security_stalled", "host"))
        self.assertFalse(call.kwargs["active"])

    def test_a_stall_is_reported_at_once_and_then_refreshed_not_repeated(self):
        broker.os_security_watch(NOW)
        self.reason.return_value = "No OS security check has succeeded for 30 hours."
        broker.os_security_watch(NOW + 60)
        self.assertTrue(self.alerts.observe.call_args.kwargs["active"])
        self.assertEqual(self.alerts.observe.call_count, 2)
        broker.os_security_watch(NOW + 120)
        self.assertEqual(self.alerts.observe.call_count, 2)
        broker.os_security_watch(NOW + 60 + broker.OS_SECURITY_WATCH_REPEAT_SECONDS)
        self.assertEqual(self.alerts.observe.call_count, 3)

    def test_the_refresh_is_more_frequent_than_the_rule_goes_stale(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py").read_text(encoding="utf-8")
        self.assertIn('Rule("os.security_stalled", KIND_LEVEL, SEVERITY_WARNING,', source)
        self.assertIn("repeat_after=86400, stale_after=3600),", source)
        self.assertLess(broker.OS_SECURITY_WATCH_REPEAT_SECONDS + broker.AUTO_CHECK_POLL_SECONDS, 3600)

    def test_a_failing_alert_engine_does_not_disturb_the_schedule(self):
        self.alerts.observe.side_effect = OSError("alertd is down")
        self.assertEqual(broker.os_security_watch(NOW), "")

    def test_the_schedule_looks_on_every_pass(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py").read_text(encoding="utf-8")
        loop = source[source.index("def auto_check_loop()"):source.index("def update_command(")]
        self.assertIn("answer = os_security_tick()", loop)
        self.assertIn("os_security_watch(last_answer=answer)", loop)


if __name__ == "__main__":
    unittest.main()
