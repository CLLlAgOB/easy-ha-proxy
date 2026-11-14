"""A scanner that comes back within thirty days is one that came back (P3).

`RECURRING_SCANNER` looked a week back. Measured on a production gateway:
968 addresses in thirty days brought a single probable signature -- WordPress,
an AI endpoint, a survey tool -- and were never banned; 90 of them returned on
other days, half of those more than 7.2 days apart. One day outside the week.

Replayed over the stored findings of two gateways, a thirty-day window bans
57 and 30 more addresses, every one a prober of those categories, none that
ever signed in.

Held here: the window is thirty days and no longer than findings are kept by
default, a return inside it is found, one outside it is not, and the earlier
visit is asked of the index rather than read out of the latest findings.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform != "win32":
    import test_guardd as base
    guardd = base.guardd
else:
    base = guardd = None

DAY = 86400
IP = "203.0.113.9"


@unittest.skipUnless(guardd, "Linux engine")
class TheWindow(unittest.TestCase):
    def setUp(self):
        base.EngineTestCase.setUp(self)

    append = base.EngineTestCase.append if base else None
    events = base.EngineTestCase.events if base else None
    line = base.DetectionTests.line if base else None

    def types(self):
        return [event["event_type"] for event in self.events()]

    def visit(self, now, path="/xmlrpc.php", status=404):
        self.append(self.line(IP, path, status))
        self.engine.ingest_log(now)

    def test_it_is_thirty_days_and_not_longer_than_findings_are_kept(self):
        self.assertEqual(guardd.RECURRING_WINDOW, 30 * DAY)
        self.assertLessEqual(guardd.RECURRING_WINDOW, guardd.GuardConfig().event_retention_days * DAY)

    def test_a_prober_back_after_ten_days_is_banned(self):
        self.visit(1000)
        self.assertLess(self.engine.reputation(IP, 1000)["score"], guardd.WOULD_BAN_SCORE)
        self.visit(1000 + 10 * DAY)
        self.assertIn(guardd.EVENT_RECURRING, self.types())
        self.assertGreaterEqual(self.engine.reputation(IP, 1000 + 10 * DAY)["score"], guardd.WOULD_BAN_SCORE)

    def test_the_finding_says_how_long_it_was_away(self):
        self.visit(1000)
        self.visit(1000 + 10 * DAY)
        found = [e for e in self.events() if e["event_type"] == guardd.EVENT_RECURRING]
        self.assertEqual(found[0]["detail"], "back after 240h")

    def test_back_after_twenty_nine_days_still_counts(self):
        self.visit(1000)
        self.visit(1000 + 29 * DAY)
        self.assertIn(guardd.EVENT_RECURRING, self.types())

    def test_back_after_thirty_one_days_is_a_stranger_again(self):
        self.visit(1000)
        self.visit(1000 + 31 * DAY)
        self.assertNotIn(guardd.EVENT_RECURRING, self.types())

    def test_a_client_with_stale_links_for_three_weeks_never_counts(self):
        for day in range(0, 21, 3):
            for index in range(8):
                self.append(self.line(IP, f"/old-page{index}", 404))
            self.engine.ingest_log(1000 + day * DAY)
        self.assertNotIn(guardd.EVENT_RECURRING, self.types())


@unittest.skipUnless(guardd, "Linux engine")
class TheEarlierVisit(unittest.TestCase):
    def setUp(self):
        base.EngineTestCase.setUp(self)

    def note(self, ts, event_type, ip=IP):
        self.engine._emit(ip, event_type, ts, source="test", category="wordpress", detail=f"{event_type} {ts}",
                          fingerprint=f"{ip}|{event_type}|{ts}")

    def test_only_signatures_inside_the_span_answer(self):
        self.note(100, guardd.EVENT_SCANNER_PATH)
        self.note(500, guardd.EVENT_NOT_FOUND_ENUM)
        self.note(900, guardd.EVENT_SCANNER_DECISIVE)
        self.note(950, guardd.EVENT_SCANNER_PATH, ip="198.51.100.7")
        last = self.database.last_signature
        self.assertEqual(last(IP, 0, 1000), 900)
        self.assertEqual(last(IP, 0, 899), 100)
        self.assertEqual(last(IP, 101, 899), 0)
        self.assertEqual(last("192.0.2.1", 0, 1000), 0)

    def test_a_busy_visit_does_not_hide_the_earlier_one(self):
        # More findings today than any "latest N" would hold.
        self.note(1000, guardd.EVENT_SCANNER_PATH)
        now = 1000 + 5 * DAY
        for index in range(260):
            self.note(now - 60 - index, guardd.EVENT_NOT_FOUND_ENUM)
        self.assertEqual(self.database.last_signature(IP, now - guardd.RECURRING_WINDOW, now - guardd.RECURRING_GAP), 1000)

    def test_the_rule_asks_the_index(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        body = source[source.index("    def _check_recurring("):source.index("    def _check_enumeration_breadth(")]
        self.assertIn("self.database.last_signature(ip, now - RECURRING_WINDOW, now - RECURRING_GAP)", body)
        self.assertNotIn("events_for", body)


if __name__ == "__main__":
    unittest.main()
