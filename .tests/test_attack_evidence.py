"""Attack evidence and telemetry, kept apart (U02, step 04.7b).

The policy set on 31 October: an ordinary excess is answered by refusing
the excess, never by a ban; bans are for evidence of an attack. guardd
scored three readings of ordinary excess -- a site's request counter, its
error counter, and the legacy ban HAProxy wrote for exactly that reading --
each repeating its own cause. On the test gateway a signed-in address that
went over a site's limit twice collected 67 points from those three alone
the moment its sign-in lapsed.

They stay recorded and shown. Under the U02 policy they weigh nothing, and
an address that stays over a hard ceiling -- something no client does --
is the evidence that takes their place. Which weights apply follows the ban
policy HAProxy runs (see test_ban_policy_switch).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402

GUARDD_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"


def load_guardd():
    spec = importlib.util.spec_from_file_location("guardd_for_attack_evidence", GUARDD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()
T0 = 1_786_000_000


def event(event_type, ip="203.0.113.9", ts=T0, category="", detail=""):
    return {"ts": ts, "ip": ip, "event_type": event_type, "source": "test",
            "category": category, "site": "", "detail": detail, "handled": False}


class TheTwoClasses(unittest.TestCase):
    def setUp(self):
        self.now = guardd.ScoringPolicy()
        self.after = guardd.u02_policy(self.now)

    def test_ordinary_excess_is_telemetry(self):
        self.assertEqual(guardd.TELEMETRY_EVENTS, {
            guardd.EVENT_RATE_EXCEEDED, guardd.EVENT_ERROR_RATE_EXCEEDED, guardd.EVENT_LEGACY_BAN,
        })
        for event_type in guardd.TELEMETRY_EVENTS:
            self.assertGreater(self.now.weight(event_type), 0)  # today's policy, unchanged
            self.assertEqual(self.after.weight(event_type), 0)

    def test_every_other_finding_keeps_its_weight(self):
        # The slow scanner first among them: rate-blind on purpose.
        for event_type, weight in guardd.DEFAULT_WEIGHTS.items():
            if event_type in guardd.TELEMETRY_EVENTS or event_type == guardd.EVENT_HARD_FLOOR:
                continue
            self.assertEqual(self.after.weight(event_type), weight, event_type)
        self.assertEqual(self.after.weight(guardd.EVENT_LOW_AND_SLOW), 30)

    def test_a_hard_floor_episode_is_recorded_now_and_weighed_after_the_switch(self):
        self.assertEqual(self.now.weight(guardd.EVENT_HARD_FLOOR), 0)
        self.assertGreaterEqual(self.after.weight(guardd.EVENT_HARD_FLOOR), guardd.WOULD_BAN_SCORE)

    def test_a_trusted_addresss_episode_never_weighs_anything(self):
        self.assertNotIn(guardd.EVENT_HARD_FLOOR_TRUSTED, guardd.DEFAULT_WEIGHTS)
        self.assertEqual(self.after.weight(guardd.EVENT_HARD_FLOOR_TRUSTED), 0)

    def test_a_what_if_weight_is_kept(self):
        tried = guardd.ScoringPolicy(weights={**guardd.DEFAULT_WEIGHTS, guardd.EVENT_HARD_FLOOR: 25},
                                     category_cap=40, decay_seconds=3600)
        after = guardd.u02_policy(tried)
        self.assertEqual(after.weight(guardd.EVENT_HARD_FLOOR), 25)
        self.assertEqual((after.category_cap, after.decay_seconds), (40, 3600))

    def test_the_lapsed_sign_in_scores_nothing_under_u02(self):
        # What the test gateway recorded for one signed-in address on 4 November.
        history = [
            event(guardd.EVENT_LEGACY_BAN, category="ban", detail="code=30"),
            event(guardd.EVENT_RATE_EXCEEDED, ts=T0 + 10, detail="http_req_rate=300 limit=200"),
            event(guardd.EVENT_ERROR_RATE_EXCEEDED, ts=T0 + 10, detail="http_err_rate=200 limit=20"),
        ]
        self.assertGreaterEqual(guardd.score_events(history, T0 + 20, self.now)["score"], 60)
        self.assertEqual(guardd.score_events(history, T0 + 20, self.after)["score"], 0)

    def test_a_scanner_scores_the_same_under_both(self):
        history = [event(guardd.EVENT_SCANNER_DECISIVE, category="secrets"),
                   event(guardd.EVENT_LOW_AND_SLOW, ts=T0 + 5)]
        self.assertEqual(guardd.score_events(history, T0 + 10, self.now)["score"],
                         guardd.score_events(history, T0 + 10, self.after)["score"])

    def test_the_simulator_can_weigh_the_episode(self):
        from haproxy_admin import services_security

        self.assertIn(guardd.EVENT_HARD_FLOOR, services_security.EVENT_TYPES)


def floors(config):
    path = Path(tempfile.mkdtemp()) / "haproxy.cfg"
    path.write_text(config, encoding="utf-8")
    return guardd.read_hard_floor(str(path))


class TheTemplateNamesEveryCeiling(unittest.TestCase):
    def assert_matches_the_rules(self, config, found):
        # Each marker repeats a rule HAProxy really applies, number for number.
        import re

        for table, limits in found.items():
            for counter, limit in limits.items():
                pattern = rf"\bsc\d_{counter}\({re.escape(table)}\)\s+gt\s+{limit}\b"
                self.assertRegex(config, pattern, f"{table} {counter}")

    def test_the_https_entry_alone(self):
        config = render([site("shop", "shop.example.test")], admin_ips_enabled=True)
        found = floors(config)
        self.assertEqual(found, {"fe_https": {"conn_rate": 1000, "conn_cur": 500, "http_req_rate": 1000}})
        self.assert_matches_the_rules(config, found)

    def test_plain_http_and_a_tcp_proxy(self):
        config = render([site("shop", "shop.example.test", redirect_to_https=True)],
                        tcp_proxies=[{"name": "files", "bind_port": 6690,
                                      "backend_host": "10.0.0.20", "backend_port": 22}])
        found = floors(config)
        self.assertEqual(found["fe_http80"], {"conn_rate": 1000, "conn_cur": 500, "http_req_rate": 1000})
        self.assertEqual(found["fe_tcp_files"], {"conn_rate": 1000, "conn_cur": 500})
        self.assert_matches_the_rules(config, found)

    def test_behind_the_router_connections_are_counted_there(self):
        config = render([site("shop", "shop.example.test"),
                         site("files", "files.example.test", tcp_passthrough=True)])
        found = floors(config)
        self.assertEqual(found["tbl_conn_edge"], {"conn_rate": 1000, "conn_cur": 500})
        self.assertEqual(found["fe_https"], {"http_req_rate": 1000})
        self.assert_matches_the_rules(config, found)

    def test_an_operator_value_is_what_guardd_reads(self):
        config = render([site("shop", "shop.example.test")],
                        site_defaults={"hard_req_rate": 3000, "conn_cur_limit": 800})
        found = floors(config)
        self.assertEqual(found["fe_https"]["http_req_rate"], 3000)
        self.assertEqual(found["fe_https"]["conn_cur"], 800)

    def test_no_configuration_means_no_queries(self):
        self.assertEqual(guardd.read_hard_floor(str(Path(tempfile.mkdtemp()) / "missing.cfg")), {})


class AnEpisode(unittest.TestCase):
    KEY = ("203.0.113.9", "fe_https", "http_req_rate")

    def test_needs_two_reads_in_a_row(self):
        watch = guardd.HardFloorWatch()
        self.assertEqual(watch.update({self.KEY: (1500, 1000)}), [])
        self.assertEqual(watch.update({self.KEY: (1800, 1000)}), [(self.KEY, (1800, 1000))])

    def test_a_burst_one_read_saw_is_not_one(self):
        watch = guardd.HardFloorWatch()
        watch.update({self.KEY: (1500, 1000)})
        watch.update({})
        self.assertEqual(watch.update({self.KEY: (1500, 1000)}), [])

    def test_what_it_remembers_is_bounded(self):
        watch = guardd.HardFloorWatch()
        many = {(f"10.0.{index // 256}.{index % 256}", "fe_https", "conn_cur"): (600, 500)
                for index in range(guardd.HARD_FLOOR_MAX_TRACKED + 50)}
        watch.update(many)
        self.assertEqual(watch.summary()["over_now"], guardd.HARD_FLOOR_MAX_TRACKED)


class TheEngineReadsOnlyTheOffenders(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.cfg = root / "haproxy.cfg"
        self.cfg.write_text(render([site("shop", "shop.example.test")]), encoding="utf-8")
        whitelist = root / "whitelist.ip"
        whitelist.write_text("198.51.100.7\n", encoding="utf-8")
        log = root / "haproxy.log"
        log.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(log), whitelist_files=(str(whitelist),))
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(config, self.database)
        self.engine.hard_floor = guardd.HardFloorWatch(str(self.cfg))
        self.asked = []

    def answer(self, socket_path, command):
        self.asked.append(command)
        if command == "show table fe_https data.http_req_rate gt 1000":
            return ("# table: fe_https, type: ip, size:204800, used:2\n"
                    "0x1: key=203.0.113.9 use=0 exp=1 conn_rate(10000)=4 conn_cur=1 http_req_rate(10000)=1734\n"
                    "0x2: key=198.51.100.7 use=0 exp=1 conn_rate(10000)=2 conn_cur=1 http_req_rate(10000)=1201\n")
        if command.startswith("show table fe_https data.conn_cur"):
            raise OSError("socket went away")
        return "# table: fe_https, type: ip, size:204800, used:0\n"

    def read(self, ts):
        with mock.patch.object(guardd, "runtime_command", side_effect=self.answer):
            return self.engine.ingest_hard_floor(ts)

    def test_it_asks_for_each_ceiling_and_nothing_else(self):
        self.read(T0)
        self.assertEqual(sorted(self.asked), [
            "show table fe_https data.conn_cur gt 500",
            "show table fe_https data.conn_rate gt 1000",
            "show table fe_https data.http_req_rate gt 1000",
        ])

    def test_two_reads_make_an_episode_and_trust_decides_its_type(self):
        self.assertEqual(self.read(T0), 0)
        self.assertEqual(self.read(T0 + 10), 2)
        [stranger] = self.database.events_for("203.0.113.9", 0)
        [listed] = self.database.events_for("198.51.100.7", 0)
        self.assertEqual((stranger["event_type"], stranger["category"]),
                         (guardd.EVENT_HARD_FLOOR, "flood"))
        self.assertEqual(stranger["detail"], "http_req_rate=1734 limit=1000 table=fe_https")
        self.assertEqual(listed["event_type"], guardd.EVENT_HARD_FLOOR_TRUSTED)
        self.assertIn("trusted=whitelist", listed["detail"])

    def test_one_record_per_episode_not_per_read(self):
        for step in range(5):
            self.read(T0 + 10 * step)
        self.assertEqual(len(self.database.events_for("203.0.113.9", 0)), 1)

    def test_the_poll_reads_it(self):
        quiet = {"applied": [], "lifted": []}
        with mock.patch.object(self.engine, "read_tables", return_value={}), \
                mock.patch.object(self.engine, "apply_enforcement", return_value=quiet), \
                mock.patch.object(self.engine, "ingest_hard_floor", return_value=0) as floor:
            self.engine.poll()
        floor.assert_called_once()


class ThePanel(unittest.TestCase):
    def test_the_page_has_no_preview_of_the_policy(self):
        # Shown for a day before the switch and dropped at the operator's
        # word (4 November): the policy is chosen in the settings.
        html = (ROOT / "docker/app/haproxy_admin/templates/adaptive_protection.html").read_text(encoding="utf-8")
        script = (ROOT / "docker/app/haproxy_admin/static/js/adaptive_protection.js").read_text(encoding="utf-8")
        self.assertNotIn("ap-u02", html)
        self.assertNotIn("renderU02", script)


if __name__ == "__main__":
    unittest.main()
