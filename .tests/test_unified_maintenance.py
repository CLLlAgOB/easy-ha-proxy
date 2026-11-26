"""Maintenance window unit tests for installer/maintenance_window.py.

Runtime maintenance and OS upgrade guard tests moved to
go/agent/internal/hostsec/os_upgrade_guard_test.go. installer/maintenance_window.py
stays until haproxy_package_migrate.py moves to Go in Step 5.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
import maintenance_window as windows  # noqa: E402

REVISION = "a" * 32


def settings(**extra):
    return {
        "auto_install": True,
        "auto_install_unified": True,
        "auto_install_runtime": True,
        "auto_install_os": True,
        "auto_install_start": 1,
        "auto_install_end": 2,
        "maintenance_revision": REVISION,
        "maintenance_updated_at": 1,
        **extra,
    }


class Windows(unittest.TestCase):
    def test_exact_end_is_closed_and_cross_midnight_is_one_window(self):
        value = windows.policy(settings())
        now = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
        self.assertIsNotNone(windows.current(value, now))
        self.assertIsNone(windows.current(value, now.replace(hour=2, minute=0)))
        value.update(start=23, end=2)
        self.assertEqual(windows.current(value, now)["key"], "2026-11-14")
        self.assertEqual(windows.current(value, now.replace(day=14, hour=23))["key"], "2026-11-14")

    def test_a_new_consent_waits_for_the_next_full_window_and_disabled_means_no_admission(self):
        now = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
        value = windows.policy(settings(maintenance_updated_at=now.timestamp()))
        self.assertIsNone(windows.current(value, now))
        self.assertIsNotNone(windows.current(value, now + dt.timedelta(days=1)))
        value["enabled"] = False
        self.assertIsNone(windows.current(value, now + dt.timedelta(days=1)))

    def test_both_repeated_DST_hours_belong_to_a_single_window(self):
        value = windows.policy(settings(auto_install_start=1, auto_install_end=3))
        zone = ZoneInfo("Europe/Warsaw")
        first = dt.datetime(2026, 10, 25, 2, 30, tzinfo=zone, fold=0)
        second = first.replace(fold=1)
        self.assertEqual(windows.current(value, first), windows.current(value, second))

    def test_native_stage_rejects_a_revoked_or_replaced_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "os-security"
            file = root.parent / "settings.json"
            local = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)

            def reader(path):
                return json.loads(path.read_text())

            file.write_text(json.dumps(settings()))
            windows.require(root, reader, REVISION, local)
            for raw in (
                settings(auto_install=False),
                settings(maintenance_revision="c" * 32),
                settings(auto_install_unified=False),
            ):
                file.write_text(json.dumps(raw))
                with self.assertRaisesRegex(ValueError, "window has closed"):
                    windows.require(root, reader, REVISION, local)


if __name__ == "__main__":
    unittest.main()
