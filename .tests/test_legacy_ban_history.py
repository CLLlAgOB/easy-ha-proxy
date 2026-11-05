"""HAProxy's own bans in the decision history, as seen (06.5b).

Under the old ban policy HAProxy bans on its own rules -- code 10 for a
site's error limit, 20 for errors on unknown names, 30 for a site's request
rate -- and keeps no record of when or why. The engine saw these bans (an
event, LEGACY_HAPROXY_BAN) but wrote no decision, so the address page had
nothing to say about the bans most common on the production gateways.

Now the first sighting is written as a decision: its code, its expiry, and
the site counters that held the address at that moment -- and nothing made
up: the time HAProxy decided is recorded as unknown. Its end is written
once, whether it ran out, HAProxy restarted, an operator lifted it, or the
new ban policy did.
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
IP = "203.0.113.30"
OTHER = "203.0.113.31"
THRESHOLDS = {"tbl_rate_shop": 200, "tbl_err_shop": 20, "tbl_err_other": 8}


def ban(code, exp_ms=3600 * 1000):
    return {"gpc0": "1", "gpt0": str(code), "exp": str(exp_ms)}


class Seen(base.EnforcementTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(guardd, "read_thresholds", return_value=dict(THRESHOLDS))
        patcher.start()
        self.addCleanup(patcher.stop)

    def cycle(self, bans, now, **counters):
        tables = {"tbl_ban": bans, "tbl_ip_auth": {}}
        tables.update(counters)
        self.engine.ingest_tables(tables, now)

    def decisions(self, ip=IP):
        return [(d["action"], d["source"], d["code"]) for d in reversed(self.database.ban_decisions(ip, limit=50))]


class TheFirstSighting(Seen):
    def test_is_written_with_its_code_expiry_and_counters(self):
        self.cycle({IP: ban(30)}, 2000,
                   tbl_rate_shop={IP: {"http_req_rate(10000)": "350"}},
                   tbl_err_shop={IP: {"http_err_rate(10000)": "3"}},
                   tbl_rate_docs={OTHER: {"http_req_rate(10000)": "900"}})
        [decision] = self.database.ban_decisions(IP, limit=5)
        self.assertEqual((decision["action"], decision["source"], decision["outcome"]),
                         ("observed", "haproxy", "observed"))
        self.assertEqual((decision["code"], decision["ts"], decision["until"]), (30, 2000, 2000 + 3600))
        reason = decision["reason"]
        self.assertEqual(reason["first_seen"], 2000)
        self.assertIsNone(reason["decided_at"])  # HAProxy keeps no record of it
        self.assertEqual(
            [(r["table"], r["value"], r["limit"], r["over"]) for r in reason["readings"]],
            [("tbl_rate_shop", 350, 200, True), ("tbl_err_shop", 3, 20, False)],
        )
        self.assertEqual(reason["readings"][0]["site"], "shop")

    def test_is_written_once_however_often_it_is_seen(self):
        for now in (2000, 2010, 2020):
            self.cycle({IP: ban(10)}, now)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 10)])

    def test_survives_a_restart_of_the_engine_without_a_second_record(self):
        self.cycle({IP: ban(20)}, 2000)
        restarted = guardd.GuardEngine(self.config, self.database)
        restarted.ingest_tables({"tbl_ban": {IP: ban(20)}, "tbl_ip_auth": {}}, 2100)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 20)])
        self.assertEqual(restarted.legacy_observed, {IP: 20})

    def test_a_ban_standing_before_this_record_existed_is_left_alone(self):
        # Already known when the engine started following these: its first
        # sighting is long past and is not made up now.
        self.engine._known_bans = {IP}
        self.cycle({IP: ban(10)}, 2000)
        self.cycle({}, 2010)
        self.assertEqual(self.decisions(), [])

    def test_the_engines_and_the_operators_own_bans_are_not_haproxys(self):
        self.cycle({IP: ban(40), OTHER: ban(50)}, 2000)
        self.assertNotIn(("observed", "haproxy", 40), self.decisions())
        self.assertFalse([d for d in self.decisions(OTHER) if d[1] == "haproxy"])


class ItsEnd(Seen):
    def test_running_out_is_written_once(self):
        self.cycle({IP: ban(30)}, 2000)
        for now in (5700, 5710):
            self.cycle({}, now)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 30), ("ended", "haproxy", 30)])
        self.assertEqual(self.engine.legacy_observed, {})

    def test_a_cleared_entry_ends_it_too(self):
        self.cycle({IP: ban(30)}, 2000)
        self.cycle({IP: {"gpc0": "0", "gpt0": "30", "exp": "100"}}, 2010)
        self.assertEqual(self.decisions()[-1], ("ended", "haproxy", 30))

    def test_another_ban_in_its_place_ends_it(self):
        self.cycle({IP: ban(10)}, 2000)
        self.cycle({IP: ban(30)}, 2010)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 10), ("ended", "haproxy", 10)])

    def test_an_operator_lifting_it_is_the_operators_decision(self):
        self.table[IP] = {"gpc0": "1", "gpt0": "30"}
        self.cycle({IP: ban(30)}, 2000)
        self.engine.forget_ban(IP, 2005)
        self.cycle({}, 2010)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 30), ("lifted", "operator", 30)])
        # The operator's unban takes HAProxy's own ban off too, in the engine
        # (R09): the entry stays with its code, without the ban flag.
        self.assertEqual(self.table[IP], {"gpc0": "0", "gpt0": "30"})

    def test_the_new_policy_lifting_it_is_written_as_that(self):
        self.engine.ban_policy = guardd.BAN_POLICY_U02
        self.table[IP] = {"gpc0": "1", "gpt0": "30"}
        with mock.patch.object(self.engine, "switch_recorded", return_value=True):
            self.cycle({IP: ban(30)}, 2000)
            self.cycle({}, 2010)
        self.assertEqual(self.decisions(), [("observed", "haproxy", 30), ("lifted", "policy", 30)])


class TheAddressPage(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
    def test_it_says_what_was_seen_and_names_the_site(self):
        live = importlib.import_module("haproxy_admin.services_live")
        client = importlib.import_module("haproxy_admin.guardd_client")
        security = importlib.import_module("haproxy_admin.services_security")

        payload = {"decisions": [{
            "ts": 2000, "action": "observed", "source": "haproxy", "outcome": "observed",
            "code": 30, "until": 5600,
            "reason": {"first_seen": 2000, "decided_at": None, "readings": [
                {"table": "tbl_rate_shop", "site": "shop", "counter": "http_req_rate",
                 "value": 350, "limit": 200, "over": True},
                {"table": "tbl_err_other", "site": "other", "counter": "http_err_rate",
                 "value": 2, "limit": 8, "over": False},
            ]},
        }]}
        with mock.patch.object(client, "guardd_decisions", return_value=payload), \
                mock.patch.object(security, "_site_limits",
                                  return_value={"shop": {"site": "shop", "domain": "shop.example.test"}}):
            history = live.ban_history("203.0.113.30")
        self.assertIsNone(history["reason"])
        observed = history["observed"]
        self.assertEqual(observed["rule"], live.BAN_CODE_LABELS["30"])
        self.assertEqual([r["site"] for r in observed["readings"]], ["shop.example.test", "other"])
        self.assertEqual([r["unknown"] for r in observed["readings"]], [False, True])
        self.assertEqual(observed["readings"][0]["counter"], "Request rate")
        self.assertEqual(history["decisions"][0]["label"], "Banned by HAProxy's own rule (first seen)")

    def test_the_card_has_the_observed_block(self):
        page = (ROOT / "docker/app/haproxy_admin/templates/ip_logs.html").read_text(encoding="utf-8")
        block = page.split("{% if history.observed %}")[1].split('<h3 style="margin:14px 0 6px;')[0]
        self.assertIn("HAProxy does not record when it decided", block)
        self.assertIn("history.observed.readings", block)
        self.assertIn("entry.unknown", block)


if __name__ == "__main__":
    unittest.main()
