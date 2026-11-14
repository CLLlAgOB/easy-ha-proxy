"""Every address's ban decisions in one feed, on the live page (06.6).

The decisions were readable one address at a time, on that address's page.
The live page now has a tab with all of them, newest first, read from the
engine's database -- not from the stream of requests, which a busy hour
turns over -- a page at a time below the last id shown, so a decision
written while someone reads never shifts or repeats a row. It says which
sources write into the record, and that Authelia's sign-in bans are not one
of them.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

import test_guardd as base  # noqa: E402
from test_live_memory_budget import Handler  # noqa: E402

guardd = base.guardd


class TheFeed(base.EngineTestCase):
    def setUp(self):
        super().setUp()
        db = self.database
        db.record_decision("203.0.113.1", 1000, "applied", "adaptive", "applied", code=40, until=4600,
                           strike=1, score=95, reason={
                               "categories": {"vcs": 30, "secrets": 60, "wordpress": 10},
                               "evidence": [], "evidence_total": 5})
        db.record_decision("203.0.113.2", 1001, "observed", "haproxy", "observed", code=30, until=9000,
                           reason={"readings": [
                               {"table": "tbl_rate_shop", "site": "shop", "counter": "http_req_rate",
                                "value": 350, "limit": 200, "over": True},
                               {"table": "tbl_err_shop", "site": "shop", "counter": "http_err_rate",
                                "value": 2, "limit": 20, "over": False}]})
        db.record_decision("203.0.113.1", 1002, "lifted", "operator", "applied", code=40)
        db.record_decision("203.0.113.3", 1003, "applied", "operator", "applied", code=50, until=9999)

    def test_newest_first_across_addresses(self):
        rows = self.database.decision_feed(limit=10)
        self.assertEqual([r["ip"] for r in rows], ["203.0.113.3", "203.0.113.1", "203.0.113.2", "203.0.113.1"])

    def test_paged_by_id_without_repeats_while_new_ones_arrive(self):
        first = self.database.decision_feed(limit=2)
        self.assertEqual(len(first), 3)  # one more than asked: there are more
        page = first[:2]
        self.database.record_decision("203.0.113.9", 1004, "applied", "adaptive", "applied", code=40)
        second = self.database.decision_feed(before=page[-1]["id"], limit=2)
        self.assertEqual([r["ip"] for r in second], ["203.0.113.2", "203.0.113.1"])
        self.assertFalse({r["id"] for r in page} & {r["id"] for r in second})

    def test_bans_and_lifts_apart(self):
        bans = self.database.decision_feed(limit=10, actions=guardd.DECISION_FEED_KINDS["bans"])
        lifts = self.database.decision_feed(limit=10, actions=guardd.DECISION_FEED_KINDS["lifts"])
        self.assertEqual({r["action"] for r in bans}, {"applied", "observed"})
        self.assertEqual([r["action"] for r in lifts], ["lifted"])

    def test_the_reason_comes_summarised(self):
        rows = {r["ip"]: r for r in self.database.decision_feed(limit=10) if r["action"] != "lifted"}
        self.assertNotIn("reason", rows["203.0.113.1"])
        self.assertEqual(rows["203.0.113.1"]["summary"],
                         {"categories": ["secrets", "vcs", "wordpress"], "evidence_total": 5})
        self.assertEqual(rows["203.0.113.2"]["summary"]["over"],
                         [{"site": "shop", "counter": "http_req_rate", "value": 350, "limit": 200}])

    def test_a_summary_of_evidence_without_categories(self):
        summary = guardd.decision_summary({"evidence": [
            {"event_type": "SCANNER_PATH", "category": "secrets"},
            {"event_type": "HARD_FLOOR_EPISODE", "category": ""},
            {"event_type": "SCANNER_PATH", "category": "secrets"}]})
        self.assertEqual(summary["categories"], ["secrets", "HARD_FLOOR_EPISODE"])
        self.assertEqual(guardd.decision_summary({}), {})


class TheApi(base.EngineTestCase):
    def call(self, query=""):
        return Handler(self.engine, "GET", f"/api/v1/guard/decisions/feed{query}").sent

    def test_pages_and_sources(self):
        for index in range(5):
            self.database.record_decision(f"203.0.113.{index}", 1000 + index, "applied", "adaptive",
                                          "applied", code=40)
        code, payload = self.call("?limit=3")
        self.assertEqual(code, 200)
        self.assertEqual(len(payload["decisions"]), 3)
        self.assertEqual(payload["next"], payload["decisions"][-1]["id"])
        self.assertIn("haproxy", payload["sources"])
        code, rest = self.call(f"?limit=3&before={payload['next']}")
        self.assertEqual((len(rest["decisions"]), rest["next"]), (2, 0))

    def test_an_unknown_kind_is_refused(self):
        self.assertEqual(self.call("?kind=everything")[0], 400)


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class ThePanel(unittest.TestCase):
    def setUp(self):
        self.live = importlib.import_module("haproxy_admin.services_live")
        self.client = importlib.import_module("haproxy_admin.guardd_client")
        self.security = importlib.import_module("haproxy_admin.services_security")

    def feed(self, args, answer):
        with mock.patch.object(self.client, "guardd_decision_feed", return_value=answer) as daemon, \
                mock.patch.object(self.security, "_site_limits",
                                  return_value={"shop": {"site": "shop", "domain": "shop.example.test"}}), \
                mock.patch.object(self.live, "get_country_code", return_value="NL"):
            return self.live.decision_feed(args), daemon

    def test_rows_say_what_and_why_in_the_panels_words(self):
        answer = {"decisions": [
            {"id": 7, "ts": 1000, "ip": "203.0.113.2", "action": "observed", "source": "haproxy",
             "outcome": "observed", "code": 30, "until": 9000,
             "summary": {"over": [{"site": "shop", "counter": "http_req_rate", "value": 350, "limit": 200}]}},
            {"id": 6, "ts": 990, "ip": "203.0.113.1", "action": "lifted", "source": "operator",
             "outcome": "applied", "code": 40, "until": 4600, "summary": {}},
        ], "next": 6, "sources": ["adaptive", "haproxy"]}
        result, _ = self.feed({}, answer)
        first, second = result["decisions"]
        self.assertEqual(first["label"], "Banned by HAProxy's own rule (first seen)")
        self.assertEqual(first["over"][0]["site"], "shop.example.test")
        self.assertEqual(first["over"][0]["counter"], "Request rate")
        self.assertEqual(first["country"], "NL")
        self.assertEqual(second["until"], "")  # a lift has no "until"
        self.assertEqual(result["next"], 6)

    def test_only_known_kinds_and_a_whole_before_reach_the_engine(self):
        _, daemon = self.feed({"kind": "drop table", "before": "x"}, {"decisions": []})
        self.assertEqual(daemon.call_args.args[0], {"kind": "all", "before": 0, "limit": 50})


class ThePage(unittest.TestCase):
    def setUp(self):
        self.template = (APP / "templates/live_activity.html").read_text(encoding="utf-8")
        self.script = (APP / "static/js/live_activity.js").read_text(encoding="utf-8")
        self.routes = (APP / "routes_monitoring.py").read_text(encoding="utf-8")

    def test_the_tab_and_its_parts(self):
        self.assertIn('data-tab="decisions"', self.template)
        self.assertIn('data-panel="decisions"', self.template)
        for element in ("la-decisions-kind", "la-decisions-body", "la-decisions-more", "la-decisions-empty",
                        "la-decisions-note"):
            self.assertIn(f'id="{element}"', self.template)
        self.assertIn("Authelia keeps only its current list", " ".join(self.template.split()))

    def test_older_pages_go_by_id_and_stay_put(self):
        self.assertIn('params.set("before", String(decisions.next))', self.script)
        block = self.script.split("function refreshDecisions()")[1].split("\n  }\n")[0]
        self.assertIn("decisions.pages > 1", block)

    def test_the_route_is_read_only_and_degrades(self):
        block = self.routes.split('@bp.get("/api/monitoring/live/decisions")')[1].split("\n@bp.")[0]
        self.assertIn("GuarddUnavailable", block)
        self.assertIn("503", block)


if __name__ == "__main__":
    unittest.main()
