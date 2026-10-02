"""The ban list says when an adaptive ban really ends.

Every tbl_ban entry carries the stick table's own expiry, expire 168h. For
bans HAProxy places under its own rules -- codes 10, 20 and 30 -- that is
precisely when they end. For an adaptive ban, code 40, it is not: the engine
keeps a schedule and lifts the ban itself, so on a one-day ladder the list
said "6 days" about bans that were due to lift within hours.

The rule, per row rather than per page: an adaptive ban the engine holds
shows the engine's time, while enforcement is on. Every other row, and every
row when the engine is off, down or unreachable, shows the table's time
exactly as before. The dashboard polls this list, so the engine being absent
must cost it nothing but that fallback.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import guardd_client  # noqa: E402
from haproxy_admin import services  # noqa: E402


NOW = 1_800_000_000


def ban_table(*rows):
    return {
        "headers": ["IP", "Status", "Reason", "Expires"],
        "rows": [list(row) for row in rows],
        "meta": {"name": "tbl_ban", "size": 204800, "used": len(rows)},
    }


def schedule(enforcing=True, bans=None):
    return {
        "ok": True,
        "now": NOW,
        "mode": "enforce" if enforcing else "monitor",
        "enforcing": enforcing,
        "code": 40,
        "bans": bans or {},
    }


class AdaptiveBansShowTheSchedule(unittest.TestCase):
    def apply(self, table, answer=None, error=None):
        if error is not None:
            patcher = mock.patch.object(
                guardd_client, "guardd_ban_schedule", side_effect=error
            )
        else:
            patcher = mock.patch.object(
                guardd_client, "guardd_ban_schedule", return_value=answer
            )
        with patcher as called:
            services._apply_adaptive_expiry(table)
        return called

    def test_an_adaptive_ban_shows_when_the_engine_will_lift_it(self):
        # The reported case: the table says six days, the schedule says two
        # hours, and two hours is the truth.
        table = ban_table(["203.0.113.9", "Blocked", "40", str(6 * 86400)])
        self.apply(table, schedule(bans={"203.0.113.9": NOW + 7200}))
        self.assertEqual(table["rows"][0][3], "7200")
        self.assertEqual(table["meta"]["expiry_from_schedule"], ["203.0.113.9"])

    def test_a_haproxy_ban_keeps_the_tables_time(self):
        # For codes 10/20/30 the table's expiry is the real one. Even if the
        # engine somehow held the same address, this row is HAProxy's.
        table = ban_table(["203.0.113.9", "Blocked", "20", "500000"])
        self.apply(table, schedule(bans={"203.0.113.9": NOW + 60}))
        self.assertEqual(table["rows"][0][3], "500000")

    def test_mixed_rows_are_decided_one_by_one(self):
        table = ban_table(
            ["203.0.113.9", "Blocked", "40", "518400"],
            ["198.51.100.7", "Blocked", "20", "400000"],
        )
        self.apply(table, schedule(bans={"203.0.113.9": NOW + 3600}))
        self.assertEqual(table["rows"][0][3], "3600")
        self.assertEqual(table["rows"][1][3], "400000")
        self.assertEqual(table["meta"]["expiry_from_schedule"], ["203.0.113.9"])

    def test_with_enforcement_off_the_table_time_is_shown(self):
        # Exactly as before, which is what was asked for.
        table = ban_table(["203.0.113.9", "Blocked", "40", "518400"])
        self.apply(
            table, schedule(enforcing=False, bans={"203.0.113.9": NOW + 3600})
        )
        self.assertEqual(table["rows"][0][3], "518400")
        self.assertNotIn("expiry_from_schedule", table["meta"])

    def test_an_address_the_engine_does_not_hold_keeps_the_table_time(self):
        table = ban_table(["203.0.113.9", "Blocked", "40", "518400"])
        self.apply(table, schedule(bans={}))
        self.assertEqual(table["rows"][0][3], "518400")

    def test_an_unreachable_engine_changes_nothing_and_raises_nothing(self):
        table = ban_table(["203.0.113.9", "Blocked", "40", "518400"])
        self.apply(table, error=guardd_client.GuarddUnavailable("socket gone"))
        self.assertEqual(table["rows"][0][3], "518400")

    def test_any_failure_at_all_is_contained(self):
        # The list is polled; an optional daemon must never take it down.
        table = ban_table(["203.0.113.9", "Blocked", "40", "518400"])
        self.apply(table, error=RuntimeError("anything"))
        self.assertEqual(table["rows"][0][3], "518400")

    def test_without_adaptive_bans_the_engine_is_not_asked(self):
        # Most refreshes on most gateways: no reason to spend a round trip.
        table = ban_table(["198.51.100.7", "Blocked", "20", "400000"])
        called = self.apply(table, schedule())
        called.assert_not_called()

    def test_an_empty_list_is_left_alone(self):
        for table in (None, ban_table()):
            with mock.patch.object(
                guardd_client, "guardd_ban_schedule"
            ) as called:
                services._apply_adaptive_expiry(table)
            called.assert_not_called()

    def test_a_ban_past_its_time_reads_zero_not_negative(self):
        # Between the schedule running out and the next lift cycle.
        table = ban_table(["203.0.113.9", "Blocked", "40", "518400"])
        self.apply(table, schedule(bans={"203.0.113.9": NOW - 30}))
        self.assertEqual(table["rows"][0][3], "0")

    def test_the_table_reader_applies_it(self):
        source = (ROOT / "docker/app/haproxy_admin/services.py").read_text(
            encoding="utf-8"
        )
        body = source.split("def get_tables(")[1].split("\ndef ")[0]
        self.assertIn("_apply_adaptive_expiry(ban)", body)


class TheDashboardSaysWhereTheNumberCameFrom(unittest.TestCase):
    def test_the_expiry_cell_names_its_source(self):
        script = (
            ROOT / "docker/app/haproxy_admin/static/js/dashboard.js"
        ).read_text(encoding="utf-8")
        self.assertIn("expiry_from_schedule", script)
        self.assertIn("By the adaptive protection schedule", script)
        self.assertIn("Stick table lifetime", script)


class TheEngineServesTheScheduleCheaply(unittest.TestCase):
    def test_the_endpoint_reads_the_schedule_and_not_the_review(self):
        # The dashboard polls. The shadow review scores up to two hundred
        # addresses to answer a different question; this must not call it.
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        block = source.split('if path == "/api/v1/guard/bans/schedule":')[1]
        block = block.split("        if path ==")[0]
        self.assertIn("scheduled_bans()", block)
        self.assertIn("enforcer.allowed", block)
        self.assertNotIn("shadow_review", block)
        self.assertNotIn("reputation", block)


if __name__ == "__main__":
    unittest.main()
