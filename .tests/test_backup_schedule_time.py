"""The hour the backup runs, and running it before the schedule is armed.

Both come from the same session: an operator switched a destination on, saw
no backup appear, pressed "Run it now" and was told "the schedule is off" --
true, unhelpful, and in English. And the hour was never theirs to choose: it
lived in a packaged systemd unit.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-backupd.py"
)
ROUTES = ROOT / "docker" / "app" / "haproxy_admin" / "routes_backup.py"


def load():
    spec = importlib.util.spec_from_file_location("backupd_time", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules["backupd_time"] = module
    spec.loader.exec_module(module)
    return module


backupd = load()
DROPIN_DIR = Path("/tmp/ehp-timer-test")


def patched_paths():
    return (
        mock.patch.object(backupd, "TIMER_DROPIN_DIR", DROPIN_DIR),
        mock.patch.object(backupd, "TIMER_DROPIN_PATH", DROPIN_DIR / "schedule.conf"),
    )


class TimeParsingTests(unittest.TestCase):
    def test_a_plain_time_is_kept(self):
        for value in ("00:00", "03:20", "13:45", "23:59"):
            with self.subTest(value=value):
                self.assertEqual(backupd.schedule_time(value), value)

    def test_an_empty_value_falls_back_to_the_default(self):
        self.assertEqual(backupd.schedule_time(""), backupd.DEFAULT_SCHEDULE_TIME)
        self.assertEqual(backupd.schedule_time(None, default="05:00"), "05:00")

    def test_anything_systemd_would_choke_on_is_refused(self):
        for value in (
            "24:00",
            "3:20",
            "03:60",
            "0320",
            "03:20:00",
            "aa:bb",
            "-1:00",
            "03:20\nOnCalendar=*-*-* 00:00:00",
        ):
            with self.subTest(value=value):
                with self.assertRaises(backupd.BackupdError):
                    backupd.schedule_time(value)

    def test_a_refusal_is_a_validation_error_not_a_crash(self):
        with self.assertRaises(backupd.BackupdError) as caught:
            backupd.schedule_time("25:00")
        self.assertEqual(caught.exception.code, "invalid")


class TimerDropinTests(unittest.TestCase):
    def test_the_dropin_clears_the_packaged_time_before_setting_its_own(self):
        written = {}

        def fake_replace(source, destination):
            written["body"] = Path(source).read_text(encoding="utf-8")

        directory, path = patched_paths()
        with (
            directory,
            path,
            mock.patch.object(backupd.os, "replace", side_effect=fake_replace),
            mock.patch.object(backupd.os, "chmod"),
            mock.patch.object(backupd.subprocess, "run") as run,
        ):
            run.return_value = mock.Mock(returncode=0, stderr=b"")
            backupd.write_timer_time("04:30")

        body = written["body"]
        # systemd treats OnCalendar as a list: without the empty one first the
        # backup would run at the packaged hour as well as the chosen one.
        self.assertIn("OnCalendar=\n", body)
        self.assertIn("OnCalendar=*-*-* 04:30:00", body)
        self.assertLess(body.index("OnCalendar=\n"), body.index("04:30:00"))

    def test_systemd_is_told_to_reload_and_the_timer_restarted(self):
        calls = []
        directory, path = patched_paths()
        with (
            directory,
            path,
            mock.patch.object(backupd.os, "replace"),
            mock.patch.object(backupd.os, "chmod"),
            mock.patch.object(backupd.Path, "write_text"),
            mock.patch.object(backupd.subprocess, "run") as run,
        ):
            run.side_effect = lambda command, **kwargs: (
                calls.append(command) or mock.Mock(returncode=0, stderr=b"")
            )
            backupd.write_timer_time("04:30")

        self.assertIn("daemon-reload", calls[0])
        # A timer recomputes its next elapse only when restarted; reloading
        # alone would leave the change to take effect a day late.
        self.assertIn("restart", calls[1])
        self.assertIn(backupd.BACKUP_TIMER_UNIT, calls[1])

    def test_a_timer_that_will_not_take_the_change_is_reported(self):
        directory, path = patched_paths()
        with (
            directory,
            path,
            mock.patch.object(backupd.os, "replace"),
            mock.patch.object(backupd.os, "chmod"),
            mock.patch.object(backupd.Path, "write_text"),
            mock.patch.object(backupd.subprocess, "run") as run,
        ):
            run.return_value = mock.Mock(returncode=1, stderr=b"unit not found")
            with self.assertRaises(backupd.BackupdError) as caught:
                backupd.write_timer_time("04:30")
        self.assertIn("unit not found", str(caught.exception))


class OnDemandTests(unittest.TestCase):
    """Pressing the button before arming the schedule must still work."""

    def setUp(self):
        self.source = DAEMON.read_text(encoding="utf-8")
        self.block = self.source.split("def run_scheduled_backup")[1]

    def test_the_timer_still_respects_the_off_switch(self):
        self.assertIn('if not schedule["enabled"] and not on_demand:', self.block)
        self.assertIn('"skipped": "the schedule is off"', self.block)

    def test_an_on_demand_run_still_needs_somewhere_to_send_it(self):
        self.assertIn('if on_demand and not schedule["destinations"]:', self.block)

    def test_an_on_demand_run_still_needs_a_passphrase(self):
        # The passphrase check must not be conditional on how the run started.
        guard = self.block.index('if not schedule["passphrase_stored"]:')
        self.assertNotIn("on_demand", self.block[guard:guard + 120])

    def test_the_daemon_accepts_the_flag(self):
        self.assertIn(
            '"run_scheduled": frozenset({"action", "on_demand"}),', self.source
        )

    def test_the_button_sends_it(self):
        routes = ROUTES.read_text(encoding="utf-8")
        self.assertIn('"on_demand": True', routes.split("def run_schedule_view")[1])


class ReportingTests(unittest.TestCase):
    def test_the_schedule_reports_both_the_wish_and_what_systemd_will_do(self):
        block = DAEMON.read_text(encoding="utf-8").split("def load_schedule")[1]
        block = block.split("def ")[0]
        self.assertIn('"time"', block)
        self.assertIn('"next_run"', block)

    def test_a_stopped_timer_reports_no_next_run(self):
        with mock.patch.object(
            backupd,
            "systemctl_properties",
            return_value={"ActiveState": "inactive", "NextElapseUSecRealtime": "x"},
        ):
            self.assertEqual(backupd.timer_next_run(), "")

    def test_an_unreachable_systemd_does_not_break_the_page(self):
        with mock.patch.object(
            backupd, "systemctl_properties", side_effect=OSError("no systemd")
        ):
            self.assertEqual(backupd.timer_next_run(), "")


if __name__ == "__main__":
    unittest.main()
