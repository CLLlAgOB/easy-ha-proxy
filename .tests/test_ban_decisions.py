"""Why an address was banned outlives the findings that banned it (06.1-06.4).

A ban was written down as one event: "score=90 seconds=86400 [vcs,secrets]".
The findings behind it decay out of the score within hours and are swept
with ordinary events, so the address page could say that a ban existed and
which categories it named, never what the address had actually done. A
manual ban had no record at all.

Every decision is now a row of its own, with the reason as it stood when the
decision was made: the findings that counted, heaviest first, each with its
site and detail. The reason is never rewritten. The ban is recorded before
it is applied and settled after, so a crash between the two is settled by
the next cycle, and the strike counts once.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

import test_guardd as base  # noqa: E402

guardd = base.guardd
IP = "203.0.113.9"


class Decisions(base.EnforcementTestCase):
    def setUp(self):
        super().setUp()
        self.make_hostile(IP)

    def decisions(self, ip=IP):
        return self.database.ban_decisions(ip, limit=50)

    def applied_events(self, ip=IP):
        return [e for e in self.database.events_for(ip, 0) if e["event_type"] == guardd.EVENT_BAN_APPLIED]

    def enforce(self, now=1000):
        self.engine.set_mode(guardd.MODE_ENFORCE, now)


class ABanWritesDownItsReason(Decisions):
    def test_with_the_findings_that_counted(self):
        self.enforce()
        [decision] = self.decisions()
        self.assertEqual((decision["action"], decision["source"], decision["outcome"]),
                         ("applied", "adaptive", "applied"))
        self.assertEqual((decision["code"], decision["strike"], decision["until"]),
                         # A first step is answered with a page (P7).
                         (guardd.ADAPTIVE_PAGE_CODE, 1, 1000 + 300))
        reason = decision["reason"]
        self.assertGreaterEqual(reason["score"], guardd.WOULD_BAN_SCORE)
        self.assertEqual({entry["category"] for entry in reason["evidence"]},
                         {"secrets", "vcs", "wordpress", "database-admin"})
        self.assertTrue(all(entry["points"] > 0 for entry in reason["evidence"]))

    def test_that_outlives_the_findings(self):
        self.enforce()
        # The ordinary findings are swept long before the ban record is.
        with self.database._lock, self.database._conn:
            self.database._conn.execute(
                "DELETE FROM security_events WHERE event_type NOT IN (?, ?)",
                (guardd.EVENT_BAN_APPLIED, guardd.EVENT_BAN_LIFTED),
            )
        [decision] = self.decisions()
        self.assertEqual(len(decision["reason"]["evidence"]), 4)

    def test_the_schedule_the_strike_and_the_outcome_together(self):
        self.enforce()
        self.assertEqual(len(self.applied_events()), 1)
        self.assertGreater(self.database.scheduled_bans()[IP], 1000)

    def test_a_ban_haproxy_refused_is_recorded_as_such_and_counts_nothing(self):
        original = guardd.runtime_command.side_effect

        def refusing(socket_path, command):
            if command.startswith("set table tbl_ban key "):
                return "No such table\n"
            return original(socket_path, command)

        guardd.runtime_command.side_effect = refusing
        self.enforce()
        [decision] = self.decisions()
        self.assertEqual(decision["outcome"], "failed")
        self.assertEqual(self.applied_events(), [])
        self.assertNotIn(IP, self.database.scheduled_bans())


class ACrashBetweenThePhases(Decisions):
    def pending(self, ts=1000):
        return self.database.record_decision(
            IP, ts, "applied", "adaptive", "pending",
            code=guardd.ADAPTIVE_BAN_CODE, until=ts + 300, strike=1, score=70,
            reason={"score": 70, "evidence": []},
        )

    def test_applied_but_not_recorded_is_recorded_once(self):
        self.pending()
        self.table[IP] = {"gpc0": "1", "gpt0": str(guardd.ADAPTIVE_BAN_CODE)}
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        self.engine.apply_enforcement(1000 + guardd.DECISION_PENDING_GRACE + 1)
        self.engine.apply_enforcement(1000 + guardd.DECISION_PENDING_GRACE + 2)
        [decision] = [d for d in self.decisions() if d["action"] == "applied"]
        self.assertEqual(decision["outcome"], "applied")
        self.assertEqual(self.database.scheduled_bans()[IP], 1300)
        self.assertEqual(len(self.applied_events()), 1)

    def test_never_applied_is_abandoned(self):
        self.pending()
        self.engine.apply_enforcement(1000 + guardd.DECISION_PENDING_GRACE + 1)
        self.assertEqual(self.decisions()[-1]["outcome"], "abandoned")
        self.assertNotIn(IP, self.table)

    def test_a_fresh_one_is_left_to_finish(self):
        self.pending(ts=1000)
        self.engine.apply_enforcement(1000 + 5)
        self.assertEqual(self.decisions()[-1]["outcome"], "pending")


class LiftsAreRecordedToo(Decisions):
    def test_when_the_ban_runs_out(self):
        self.enforce()
        self.engine.apply_enforcement(1000 + 301)
        lifted = [d for d in self.decisions() if d["action"] == "lifted"]
        self.assertEqual([(d["source"], d["outcome"]) for d in lifted], [("expiry", "applied")])

    def test_when_an_operator_lifts_it(self):
        self.enforce()
        self.engine.forget_ban(IP, 1010)
        self.assertEqual(self.decisions()[0]["source"], "operator")
        self.assertEqual(self.decisions()[0]["action"], "lifted")

    def test_an_operators_ban_is_recorded_once_when_first_seen(self):
        other = "203.0.113.50"
        rows = {other: {"gpc0": "1", "gpt0": "50", "exp": str(3600 * 1000)}}
        for now in (2000, 2010):
            self.engine.ingest_tables({"tbl_ban": rows, "tbl_ip_auth": {}}, now)
        [decision] = self.decisions(other)
        self.assertEqual((decision["action"], decision["source"], decision["code"], decision["until"]),
                         ("applied", "operator", 50, 2000 + 3600))


class TheRecordIsBounded(Decisions):
    def test_old_and_surplus_rows_go(self):
        for ts in range(10):
            self.database.record_decision(IP, ts, "lifted", "expiry", "applied")
        deleted = self.database.prune_decisions(before=3, keep=4)
        self.assertEqual(deleted, 6)
        self.assertEqual(sorted(d["ts"] for d in self.decisions()), [6, 7, 8, 9])

    def test_a_reason_too_large_is_cut_not_stored_whole(self):
        decision = self.database.record_decision(
            IP, 1, "applied", "adaptive", "applied", reason={"x": "y" * 20000})
        [row] = [d for d in self.decisions() if d["id"] == decision]
        self.assertEqual(row["reason"], {"truncated": True})


class TheAddressPage(unittest.TestCase):
    @staticmethod
    def client():
        # The module object itself: on Python 3.10 a dotted patch target can
        # miss a submodule another test left the package without.
        return importlib.import_module("haproxy_admin.guardd_client")

    def history(self, payload):
        from haproxy_admin import services_live

        with mock.patch.object(self.client(), "guardd_decisions", return_value=payload):
            return services_live.ban_history(IP)

    def test_says_why_with_the_recorded_findings(self):
        history = self.history({"ok": True, "decisions": [
            {"ts": 1_786_000_100, "action": "lifted", "source": "expiry", "outcome": "applied",
             "code": 40, "until": 1_786_000_300, "reason": {}},
            {"ts": 1_786_000_000, "action": "applied", "source": "adaptive", "outcome": "applied",
             "code": 40, "until": 1_786_000_300, "strike": 2, "score": 85, "policy": "u02",
             "reason": {"evidence": [{"ts": 1_786_000_000, "event_type": "SCANNER_PATH_DECISIVE",
                                      "category": "secrets", "points": 60, "site": "shop",
                                      "detail": "/.env"}], "evidence_total": 1}},
        ]})
        self.assertEqual([row["label"] for row in history["decisions"]],
                         ["The ban ran out", "Banned by adaptive protection"])
        self.assertEqual(history["reason"]["strike"], 2)
        [entry] = history["reason"]["evidence"]
        self.assertEqual((entry["finding"], entry["detail"]), ("SCANNER_PATH_DECISIVE (secrets)", "/.env"))

    def test_leaves_the_card_out_when_the_engine_does_not_answer(self):
        from haproxy_admin import services_live

        with mock.patch.object(self.client(), "guardd_decisions", side_effect=OSError("down")):
            self.assertIsNone(services_live.ban_history(IP))

    def test_the_page_has_the_card(self):
        html = (ROOT / "docker/app/haproxy_admin/templates/ip_logs.html").read_text(encoding="utf-8")
        self.assertIn('id="ipp-history"', html)
        self.assertIn("Why it is banned", html)


if __name__ == "__main__":
    unittest.main()
