"""The gateway's own bans are not something the client did (F03).

From the 30 October review, reproduced there on a temporary database: guardd
read the ban table on its next poll, found the adaptive ban it had just
applied (code 40) and wrote it down as LEGACY_HAPROXY_BAN -- worth 30 and a
fresh finding. One finding of 60 gave a one-hour ban; the ban's own
observation took the score to 90 and counted as new evidence, so after the
hour the ladder moved on to a week with no new request at all. A restart
emptied the set of bans already seen, and every standing ban was observed
again.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_guardd import EngineTestCase, guardd  # noqa: E402


def table(code, ip="203.0.113.9"):
    return {"tbl_ban": {ip: {"gpc0": "1", "gpt0": str(code)}}, "tbl_ip_auth": {}}


class SeeingTheTable(EngineTestCase):
    def test_an_adaptive_ban_seen_in_the_table_is_not_a_finding(self):
        self.assertEqual(self.engine.ingest_tables(table(guardd.ADAPTIVE_BAN_CODE), 1000), 0)
        self.assertEqual(self.events(), [])

    def test_nor_is_an_operators_ban(self):
        self.assertEqual(self.engine.ingest_tables(table(guardd.MANUAL_BAN_CODE), 1000), 0)
        self.assertEqual(self.events(), [])

    def test_haproxys_own_rule_bans_are_still_recorded_once(self):
        self.assertEqual(self.engine.ingest_tables(table(10), 1000), 1)
        self.assertEqual(self.engine.ingest_tables(table(10), 1010), 0)

    def test_a_restart_does_not_see_the_standing_bans_again(self):
        self.engine.ingest_tables(table(10), 1000)
        restarted = guardd.GuardEngine(self.config, self.database)
        self.assertEqual(restarted.ingest_tables(table(10), 1100), 0)
        self.assertEqual(len(self.events()), 1)
        # One that appeared while it was down is new.
        both = table(10)
        both["tbl_ban"]["198.51.100.20"] = {"gpc0": "1", "gpt0": "20"}
        self.assertEqual(restarted.ingest_tables(both, 1200), 1)


class TheScore(unittest.TestCase):
    def policy(self):
        return guardd.ScoringPolicy(decay_seconds=0)

    def test_own_ban_observations_recorded_earlier_carry_no_weight(self):
        for code in sorted(guardd.OWN_BAN_CODES):
            with self.subTest(code=code):
                event = [{"ts": 0, "event_type": guardd.EVENT_LEGACY_BAN, "category": "ban",
                          "detail": f"code={code}"}]
                self.assertEqual(guardd.score_events(event, 10, self.policy())["score"], 0)

    def test_haproxys_own_rule_bans_keep_their_weight(self):
        event = [{"ts": 0, "event_type": guardd.EVENT_LEGACY_BAN, "category": "ban", "detail": "code=10"}]
        self.assertEqual(guardd.score_events(event, 10, self.policy())["score"], 30)


class TheLadder(EngineTestCase):
    def test_an_own_ban_seen_after_it_was_applied_is_not_fresh_evidence(self):
        ip = "203.0.113.9"
        self.database.record_events([
            {"ts": 1000, "ip": ip, "event_type": guardd.EVENT_BAN_APPLIED, "category": "ban",
             "detail": "", "source": "guardd"},
            # Written by the old code a poll later.
            {"ts": 1010, "ip": ip, "event_type": guardd.EVENT_LEGACY_BAN, "category": "ban",
             "detail": f"code={guardd.ADAPTIVE_BAN_CODE}", "source": "stick-table"},
        ])
        self.assertLessEqual(self.database.newest_finding_ts(ip), self.database.last_ban_ts(ip))


class ABanHAProxyRefused(EngineTestCase):
    """F07 in guardd: a refused `set table` was counted as an applied ban."""

    def test_is_not_applied(self):
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        with unittest.mock.patch.object(guardd, "runtime_command", return_value="No such table: tbl_ban\n"):
            self.assertFalse(self.engine.enforcer.ban("203.0.113.9"))
        self.assertEqual((self.engine.enforcer.applied, self.engine.enforcer.failed), (0, 1))

    def test_an_empty_answer_is_applied(self):
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        with unittest.mock.patch.object(guardd, "runtime_command", return_value="\n"):
            self.assertTrue(self.engine.enforcer.ban("203.0.113.9"))
        self.assertEqual(self.engine.enforcer.applied, 1)


if __name__ == "__main__":
    unittest.main()
