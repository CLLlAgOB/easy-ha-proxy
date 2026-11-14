"""The protection reports how it is doing, on its page and once a week (P5).

Reviewing a production gateway took hand-written queries to learn what the
engine had done: 78 bans a day, most within seconds, one address in ten back
after its first ban, four in ten of the banned addresses in fifteen networks
-- and 36 signature candidates nobody had looked at. None of it was shown
anywhere, so no change to a rule could be judged by a number.

Held here: the engine works those numbers out from its own records, without
printing an address; the page asks for them; and the week is reported once,
on Monday morning, through the alert channel, whatever the minimum severity.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform != "win32":
    import test_guardd as base
    guardd = base.guardd
else:
    base = guardd = None

DAY = 86400
NOW = 1_800_000_000
APP = ROOT / "docker/app/haproxy_admin"


@unittest.skipUnless(guardd, "Linux engine")
class TheNumbers(unittest.TestCase):
    def setUp(self):
        base.EngineTestCase.setUp(self)
        self.sequence = 0

    def finding(self, ip, ts, event_type=None):
        self.sequence += 1
        self.engine._emit(ip, event_type or guardd.EVENT_SCANNER_DECISIVE, ts, source="test", category="secrets",
                          detail=f"/.env {self.sequence}", fingerprint=f"{ip}|{ts}|{self.sequence}")

    def ban(self, ip, ts, hours=1, strike=1):
        self.database.record_decision(ip, ts, "applied", "adaptive", "applied", code=guardd.ADAPTIVE_BAN_CODE,
                                      until=ts + hours * 3600, strike=strike, score=60)

    def report(self, days=7):
        return self.database.quality(NOW - days * DAY, NOW)

    def test_bans_and_how_fast_they_were_decided(self):
        self.finding("203.0.113.1", NOW - DAY)
        self.ban("203.0.113.1", NOW - DAY + 5)
        self.finding("203.0.113.2", NOW - DAY - 4000)
        self.finding("203.0.113.2", NOW - DAY - 10)
        self.ban("203.0.113.2", NOW - DAY)
        report = self.report()
        self.assertEqual((report["bans"], report["banned_addresses"]), (2, 2))
        self.assertEqual(report["decided_at_once"], 1)
        self.assertEqual(report["on_a_single_finding"], 1)
        self.assertEqual(report["steps"], {"1": 2})

    def test_who_came_back_after_the_ban_ended(self):
        for index, returns in enumerate((True, False), 1):
            ip = f"203.0.113.{index}"
            self.finding(ip, NOW - 2 * DAY)
            self.ban(ip, NOW - 2 * DAY)
            if returns:
                self.finding(ip, NOW - DAY)
        self.ban("203.0.113.9", NOW - 60, hours=24)  # still serving: not ended
        report = self.report()
        self.assertEqual((report["first_bans_ended"], report["came_back_after_a_ban"]), (2, 1))

    def test_an_operators_lift_is_counted_as_the_sign_of_a_false_ban(self):
        self.ban("203.0.113.1", NOW - DAY)
        self.database.record_decision("203.0.113.1", NOW - DAY + 60, "lifted", "operator", "applied")
        self.database.record_decision("203.0.113.2", NOW - DAY, "lifted", "expiry", "applied")
        self.assertEqual(self.report()["lifted_by_operator"], 1)

    def test_networks_are_named_and_addresses_are_not(self):
        for last in range(1, 5):
            self.ban(f"198.51.100.{last}", NOW - DAY + last)
        self.ban("203.0.113.7", NOW - DAY)
        report = self.report()
        self.assertEqual(report["networks"], [{"network": "198.51.100.0/24", "addresses": 4}])
        self.assertEqual(report["addresses_in_networks"], 4)
        self.assertNotIn("198.51.100.1", json.dumps(report))
        self.assertNotIn("203.0.113.7", json.dumps(report))

    def test_probers_that_were_never_banned(self):
        self.finding("203.0.113.1", NOW - DAY, guardd.EVENT_SCANNER_PATH)
        self.finding("203.0.113.2", NOW - DAY, guardd.EVENT_SCANNER_PATH)
        self.ban("203.0.113.2", NOW - DAY + 1)
        self.finding("203.0.113.3", NOW - DAY, guardd.EVENT_NOT_FOUND_ENUM)
        self.assertEqual(self.report()["probers_never_banned"], 1)

    def test_only_the_asked_days_count(self):
        self.ban("203.0.113.1", NOW - 10 * DAY)
        self.ban("203.0.113.2", NOW - DAY)
        self.assertEqual(self.report(7)["bans"], 1)
        self.assertEqual(self.report(30)["bans"], 2)

    def test_a_rate_needs_at_least_an_hour_of_records(self):
        self.ban("203.0.113.1", NOW - 60)
        self.assertIsNone(self.report()["bans_per_day"])

    def test_an_empty_record_is_a_report_of_zeros(self):
        report = self.report()
        self.assertEqual((report["bans"], report["networks"], report["came_back_after_a_ban"]), (0, [], 0))


@unittest.skipUnless(guardd, "Linux engine")
class TheReport(unittest.TestCase):
    def setUp(self):
        base.EngineTestCase.setUp(self)
        self.engine.alerts = mock.Mock()
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        # A Monday, 09:00 in the zone the tests run in.
        monday = time.strptime("2026-11-09 09:00:00", "%Y-%m-%d %H:%M:%S")
        self.monday = int(time.mktime(monday))

    def test_the_engine_adds_what_waits_for_the_operator(self):
        report = self.engine.quality(7, NOW)
        for key in ("signature_candidates", "trap_candidates", "trap_names", "path_shield", "mode", "days"):
            self.assertIn(key, report)

    def test_it_is_worked_out_once_in_five_minutes(self):
        with mock.patch.object(self.database, "quality", wraps=self.database.quality) as asked:
            self.engine.quality(7, NOW)
            self.engine.quality(7, NOW + 60)
            self.engine.quality(7, NOW + guardd.QUALITY_CACHE_SECONDS + 1)
        self.assertEqual(asked.call_count, 2)

    def test_the_days_are_bounded(self):
        self.assertEqual(self.engine.quality(900, NOW)["days"], guardd.QUALITY_MAX_DAYS)
        self.assertEqual(self.engine.quality(0, NOW)["days"], 1)

    def test_the_week_is_reported_once_on_monday_morning(self):
        self.assertTrue(self.engine.weekly_summary_tick(self.monday))
        call = self.engine.alerts.observe.call_args
        self.assertEqual(call.args[0], "security.weekly_summary")
        self.assertIn("in 7 days", call.kwargs["summary"])
        self.assertIn("Bans:", call.kwargs["detail"])
        self.assertFalse(self.engine.weekly_summary_tick(self.monday + 3600))
        self.assertEqual(self.engine.alerts.observe.call_count, 1)

    def test_not_on_other_days_and_not_before_eight(self):
        self.assertFalse(self.engine.weekly_summary_tick(self.monday - 2 * 3600))
        self.assertFalse(self.engine.weekly_summary_tick(self.monday + DAY))
        self.engine.alerts.observe.assert_not_called()

    def test_the_next_week_is_reported_again(self):
        self.engine.weekly_summary_tick(self.monday)
        self.assertTrue(self.engine.weekly_summary_tick(self.monday + 7 * DAY))

    def test_a_protection_that_is_off_reports_nothing(self):
        self.engine.enforcer.mode = guardd.MODE_OFF
        self.assertFalse(self.engine.weekly_summary_tick(self.monday))

    def test_a_failing_alert_engine_is_tried_again_and_stops_nothing(self):
        self.engine.alerts.observe.side_effect = OSError("alertd is down")
        self.assertFalse(self.engine.weekly_summary_tick(self.monday))
        self.engine.alerts.observe.side_effect = None
        self.assertTrue(self.engine.weekly_summary_tick(self.monday + 60))

    def test_the_text_names_networks_and_what_waits(self):
        report = {**self.engine.quality(7, NOW), "bans": 12, "banned_addresses": 9, "bans_per_day": 1.7,
                  "networks": [{"network": "198.51.100.0/24", "addresses": 4}], "signature_candidates": 3,
                  "trap_candidates": 2}
        summary, detail = self.engine.weekly_summary_text(report)
        self.assertEqual(summary, "Adaptive protection banned 9 addresses in 7 days")
        self.assertIn("198.51.100.0/24 (4)", detail)
        self.assertIn("3 signature candidates and 2 host names that look like traps", detail)

    def test_the_cycle_looks_every_time(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        poll = source[source.index("    def poll(self) -> Dict[str, int]:"):source.index("    def read_tables(self)")]
        self.assertIn("self.weekly_summary_tick(now)", poll)


class TheAlertRule(unittest.TestCase):
    def test_a_report_is_sent_whatever_the_minimum_severity(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py").read_text(encoding="utf-8")
        self.assertIn('Rule("security.weekly_summary", KIND_EVENT, SEVERITY_INFO,', source)
        self.assertIn("auto_clear=6 * 86400, report=True),", source)
        self.assertIn("if not rule.report and _severity_rank(severity) < _severity_rank(self.config.min_severity):", source)
        self.assertEqual(source.count("report=True"), 1)

    def test_its_title_is_translated(self):
        catalogue = json.loads((APP / "translations/ru/alerts.json").read_text(encoding="utf-8"))["messages"]
        self.assertIn("Adaptive protection: the week", catalogue)


class ThePage(unittest.TestCase):
    def test_it_asks_for_the_numbers_and_shows_them(self):
        page = (APP / "templates/adaptive_protection.html").read_text(encoding="utf-8")
        script = (APP / "static/js/adaptive_protection.js").read_text(encoding="utf-8")
        route = (APP / "routes_security.py").read_text(encoding="utf-8")
        self.assertIn('id="ap-quality-card" hidden', page)
        self.assertIn('getJson("/api/security/adaptive/quality", { days: 7 })', script)
        self.assertIn('@bp.get("/api/security/adaptive/quality")', route)

    def test_every_sentence_of_the_card_is_translated_whole(self):
        import re

        script = (APP / "static/js/adaptive_protection.js").read_text(encoding="utf-8")
        block = script[script.index("function renderQuality"):script.index("async function loadQuality")]
        catalogue = {}
        for path in list((APP / "translations/ru").glob("*.json")) + [APP / "translations/ru.json"]:
            data = json.loads(path.read_text(encoding="utf-8"))
            catalogue.update(data.get("messages", data))
        sentences = re.findall(r'uiText\("([^"]+)"\)', block)
        self.assertGreaterEqual(len(sentences), 12)
        for sentence in sentences:
            self.assertIn(sentence, catalogue, sentence)
        self.assertIn("How the protection is doing", catalogue)


if __name__ == "__main__":
    unittest.main()
