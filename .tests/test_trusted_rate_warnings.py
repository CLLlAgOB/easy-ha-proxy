"""Trusted addresses over a site's limit are observed, never acted on (U02, 04.7a).

The plan's rule for an ordinary excess by a trusted address -- signed in,
whitelisted, on the admin list, allowed on the site -- is a warning, not a
refusal. Before HAProxy changes, the engine has to show how often that
actually happens and what the gateway does to those addresses today: HAProxy
still applies a site's limit to a signed-in user (429, and with rate_ban a
week-long ban), while the whitelist is not counted at all.

So the engine counts trusted requests per address and site from the log, the
way HAProxy counts http_req_rate, and keeps one record per episode. It writes
no finding, no score and no strike, and it holds a bounded number of counters.
"""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sqlite3
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
    spec = importlib.util.spec_from_file_location("guardd_for_trusted_rates", GUARDD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()

T0 = 1_786_000_000


def request(ip, host="shop.example.test", ts=T0, status=200, backend="be_shop/srv1",
            term="----", ban_reason=""):
    return guardd.ParsedRequest(
        client_ip=ip, status=status, frontend="fe_https~", backend=backend,
        method="GET", path="/", host=host, ts=ts, term=term, ban_reason=ban_reason,
    )


class Workspace(unittest.TestCase):
    """A rendered configuration, the way the gateway really writes it."""

    sites = None

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cfg = self.root / "haproxy.cfg"
        self.write_config(self.sites or [site("shop", "shop.example.test", max_req_rate=5)])

    def write_config(self, sites, **extra):
        self.cfg.write_text(render(sites, **extra), encoding="utf-8")

    def watch(self, **kwargs):
        rates = guardd.TrustedRates(str(self.cfg), **kwargs)
        rates.reload(force=True)
        return rates


class TheCeilingsComeFromTheGeneratedConfiguration(Workspace):
    sites = [
        site("shop", "shop.example.test", alt_names=["www.shop.example.test"],
             max_req_rate=200, rate_window="20s"),
        site("files", "files.example.test", max_req_rate=0),
        site("office", "office.example.test", allow_ips=["203.0.113.7", "198.51.100.0/24"],
             max_req_rate=50, rate_window="1m"),
        site("closed", "closed.example.test", allow_ips=["203.0.113.7"], max_req_rate=0),
    ]

    def test_each_limited_site_with_its_names_limit_and_window(self):
        ceilings = guardd.read_site_ceilings(str(self.cfg))
        self.assertEqual(set(ceilings), {"shop", "office"})
        shop = ceilings["shop"]
        self.assertEqual(shop.names, ("shop.example.test", "www.shop.example.test"))
        self.assertEqual((shop.limit, shop.window, shop.enforced, shop.allow), (200, 20, True, None))

    def test_a_site_open_to_named_addresses_has_a_warning_only_ceiling(self):
        # The template writes no rate table for it -- a limit there could only
        # throttle the operator -- so it states the limit for guardd alone.
        self.assertIn("# guardd-rate-warning site=office gt 50 per 1m", self.cfg.read_text())
        self.assertNotIn("tbl_rate_office", self.cfg.read_text())
        office = guardd.read_site_ceilings(str(self.cfg))["office"]
        self.assertEqual((office.limit, office.window, office.enforced), (50, 60, False))
        self.assertEqual([str(n) for n in office.allow], ["203.0.113.7/32", "198.51.100.0/24"])

    def test_haproxy_times(self):
        self.assertEqual(guardd.haproxy_seconds("20s"), 20)
        self.assertEqual(guardd.haproxy_seconds("1m"), 60)
        self.assertEqual(guardd.haproxy_seconds("2h"), 7200)
        self.assertEqual(guardd.haproxy_seconds("1500"), 1)  # a bare number is ms
        self.assertEqual(guardd.haproxy_seconds("0s"), 0)
        self.assertEqual(guardd.haproxy_seconds("soon"), 0)

    def test_an_unreadable_configuration_means_no_ceilings(self):
        self.assertEqual(guardd.read_site_ceilings(str(self.root / "absent.cfg")), {})
        rates = guardd.TrustedRates(str(self.root / "absent.cfg"))
        rates.reload(force=True)
        rates.observe(request("198.51.100.7"), "whitelist")
        self.assertEqual(rates.summary()["tracked"], 0)


class TheCounterAgreesWithHaproxy(unittest.TestCase):
    def test_the_previous_period_fades_out_across_the_window(self):
        counter = guardd._TrustedCounter(T0)
        for _ in range(29):
            counter.add(T0, 20)
        self.assertEqual(counter.add(T0, 20), 30)
        # 25 s on: one request in this period plus 30 x 15/20 of the last.
        self.assertEqual(counter.add(T0 + 25, 20), 1 + 30 * 15 // 20)
        # Two whole periods later nothing is left of it.
        self.assertEqual(counter.add(T0 + 65, 20), 1)

    def test_a_line_logged_late_counts_now_not_in_the_past(self):
        counter = guardd._TrustedCounter(T0)
        counter.add(T0 + 30, 20)
        self.assertEqual(counter.add(T0 + 5, 20), 2)


class AnEpisode(Workspace):
    def test_a_whitelisted_address_over_the_limit_is_one_episode(self):
        rates = self.watch()
        for _ in range(8):
            rates.observe(request("198.51.100.7"), "whitelist")
        [episode] = rates.open_episodes()
        self.assertEqual(episode["kind"], "RATE_WARNING")
        self.assertEqual((episode["trust"], episode["site"], episode["limit"], episode["window"]),
                         ("whitelist", "shop", 5, 20))
        # The sixth, seventh and eighth were over a limit of five.
        self.assertEqual((episode["over_limit"], episode["requests"], episode["peak"]), (3, 3, 8))
        self.assertTrue(episode["open"])

    def test_it_ends_when_the_rate_has_stayed_under_for_a_window(self):
        rates = self.watch()
        for _ in range(8):
            rates.observe(request("198.51.100.7"), "whitelist")
        rates.tick(T0 + 20, idle=True)
        self.assertEqual(len(rates.open_episodes()), 1)
        rates.tick(T0 + 21, idle=True)
        self.assertEqual(rates.open_episodes(), [])
        [finished] = rates.take_finished()
        self.assertEqual((finished["started"], finished["ended"]), (T0, T0))

    def test_a_backlog_does_not_close_it_early(self):
        # Reading an hour of backlog: the wall clock is far ahead of the
        # lines, so it must not be what ends an episode.
        rates = self.watch()
        for _ in range(8):
            rates.observe(request("198.51.100.7"), "whitelist")
        rates.tick(T0 + 3600, idle=False)
        self.assertEqual(len(rates.open_episodes()), 1)

    def test_what_the_gateway_did_is_counted(self):
        rates = self.watch()
        for _ in range(6):
            rates.observe(request("203.0.113.9"), "signed-in")
        rates.observe(request("203.0.113.9", status=429, backend="fe_https/<NOSRV>",
                              term="PR--"), "signed-in")
        rates.observe(request("203.0.113.9", status=423, backend="fe_https/<NOSRV>", term="PR--",
                              ban_reason="RATE_LIMIT_SITE name=shop max_req_rate=5"), "signed-in")
        rates.observe(request("203.0.113.9", status=423, backend="fe_https/<NOSRV>", term="PR--",
                              ban_reason="ALREADY_BANNED"), "signed-in")
        [episode] = rates.open_episodes()
        self.assertEqual(episode["trust"], "signed-in")
        self.assertEqual((episode["rate_limited"], episode["banned"]), (1, 2))
        self.assertTrue(episode["rate_ban"])

    def test_a_stranger_is_left_to_haproxy(self):
        rates = self.watch()
        for _ in range(20):
            rates.observe(request("203.0.113.50"), "")
        self.assertEqual(rates.summary()["tracked"], 0)

    def test_a_name_without_a_limit_is_not_counted(self):
        rates = self.watch()
        for _ in range(20):
            rates.observe(request("198.51.100.7", host="auth.example.test"), "whitelist")
            rates.observe(request("198.51.100.7", host="admin.example.test"), "admin")
        self.assertEqual(rates.summary()["tracked"], 0)

    def test_the_port_and_case_of_the_host_do_not_matter(self):
        rates = self.watch()
        for _ in range(6):
            rates.observe(request("198.51.100.7", host="SHOP.example.test:443"), "whitelist")
        self.assertEqual(len(rates.open_episodes()), 1)

    def test_a_changed_limit_ends_the_episode(self):
        rates = self.watch()
        for _ in range(8):
            rates.observe(request("198.51.100.7"), "whitelist")
        self.write_config([site("shop", "shop.example.test", max_req_rate=50)])
        rates.reload(force=True)
        self.assertEqual(rates.open_episodes(), [])
        self.assertEqual(len(rates.take_finished()), 1)


class ASiteOpenToNamedAddresses(Workspace):
    sites = [site("office", "office.example.test", allow_ips=["198.51.100.0/24"], max_req_rate=3)]

    def test_a_listed_address_is_trusted_there(self):
        rates = self.watch()
        for _ in range(5):
            rates.observe(request("198.51.100.20", host="office.example.test"), "")
        [episode] = rates.open_episodes()
        self.assertEqual((episode["trust"], episode["enforced"]), ("site-allow-list", False))

    def test_an_address_off_the_list_is_not(self):
        rates = self.watch()
        for _ in range(5):
            rates.observe(request("203.0.113.50", host="office.example.test", status=403,
                                  backend="fe_https/<NOSRV>"), "")
        self.assertEqual(rates.summary()["tracked"], 0)


class ItIsBounded(Workspace):
    def test_the_least_recently_used_counter_goes_first(self):
        rates = self.watch(max_keys=2)
        for _ in range(8):
            rates.observe(request("198.51.100.1"), "whitelist")
        rates.observe(request("198.51.100.2"), "whitelist")
        rates.observe(request("198.51.100.3"), "whitelist")
        summary = rates.summary()
        self.assertEqual((summary["tracked"], summary["evicted"]), (2, 1))
        # The evicted one's episode is kept, not lost.
        [finished] = rates.take_finished()
        self.assertEqual(finished["ip"], "198.51.100.1")

    def test_finished_episodes_waiting_to_be_written_are_capped(self):
        rates = self.watch()
        with mock.patch.object(guardd, "TRUSTED_RATE_MAX_PENDING", 2):
            for index in range(3):
                for _ in range(6):
                    rates.observe(request(f"198.51.100.{index + 1}"), "whitelist")
            rates.finish_all()
        self.assertEqual(len(rates.take_finished()), 2)
        self.assertEqual(rates.summary()["dropped"], 1)

    def test_quiet_counters_are_forgotten(self):
        rates = self.watch()
        rates.observe(request("198.51.100.7"), "whitelist")
        rates.tick(T0 + 41, idle=True)
        self.assertEqual(rates.summary()["tracked"], 0)


def access_line(ip, *, host="shop.example.test", status=200, backend="be_shop/srv1"):
    return (
        "2026-08-11T07:00:00.000000+00:00 gw haproxy[1]: "
        f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ {backend} "
        f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 {{}} {{}} id=r1 host={host} ua=- "
        "GET / HTTP/1.1"
    )


class TheEngineObservesAndDoesNothingElse(Workspace):
    def setUp(self):
        super().setUp()
        self.log = self.root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        whitelist = self.root / "whitelist.ip"
        whitelist.write_text("198.51.100.7\n", encoding="utf-8")
        admin = self.root / "admin.allow"
        admin.write_text("198.51.100.8\n", encoding="utf-8")
        geo = self.root / "whitelist.geo"
        geo.write_text("192.0.2.0/24\n", encoding="utf-8")
        self.config = guardd.GuardConfig(
            log_file=str(self.log), whitelist_files=(str(whitelist), str(admin), str(geo)),
        )
        self.database = guardd.SecurityDatabase(str(self.root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(self.config, self.database)
        self.engine.trusted_rates = self.watch()
        self.engine.cursor.read(4096)

    def append(self, *lines):
        with self.log.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")

    def test_each_list_is_named_for_what_it_is(self):
        self.engine.exclusions.refresh_authenticated({"203.0.113.9": {"gpc0": "1"}})
        for ip in ("198.51.100.7", "198.51.100.8", "192.0.2.10", "203.0.113.9"):
            self.append(*[access_line(ip)] * 6)
        self.engine.ingest_log(T0)
        trust = {row["ip"]: row["trust"] for row in self.engine.trusted_rates.open_episodes()}
        self.assertEqual(trust, {
            "198.51.100.7": "whitelist", "198.51.100.8": "admin",
            "192.0.2.10": "geo-whitelist", "203.0.113.9": "signed-in",
        })

    def test_its_time_is_the_syslog_stamp_not_haproxys_local_one(self):
        # %t is local time without a zone. Read as UTC, it put a gateway at
        # UTC+1 an hour in the future; the syslog stamp says where it is.
        line = access_line("198.51.100.7").replace(
            "2026-08-11T07:00:00.000000+00:00", "2026-08-11T08:00:00.000000+01:00",
        ).replace("[11/Aug/2026:07:00:00.000]", "[11/Aug/2026:08:00:00.000]")
        self.append(*[line] * 6)
        self.engine.ingest_log(T0)
        [episode] = self.engine.trusted_rates.open_episodes()
        self.assertEqual(episode["started"],
                         int(datetime(2026, 8, 11, 7, tzinfo=timezone.utc).timestamp()))

    def test_no_finding_score_or_memory_comes_of_it(self):
        self.append(*[access_line("198.51.100.7")] * 50)
        self.engine.ingest_log(T0)
        self.engine.flush_rate_warnings(2_000_000_000, idle=True)
        connection = sqlite3.connect(str(self.database.path))
        try:
            events = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            warnings = connection.execute("SELECT COUNT(*) FROM rate_warnings").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual((events, warnings), (0, 1))
        self.assertIsNone(self.engine.memory.get("198.51.100.7"))
        [row] = self.database.rate_warnings()
        self.assertEqual((row["ip"], row["trust"], row["over_limit"], row["open"]),
                         ("198.51.100.7", "whitelist", 45, False))

    def test_the_whole_cycle_writes_finished_episodes(self):
        self.append(*[access_line("198.51.100.7")] * 6)
        quiet = {"applied": [], "lifted": []}
        with mock.patch.object(self.engine, "read_tables", return_value={}), \
                mock.patch.object(self.engine, "apply_enforcement", return_value=quiet):
            self.engine.poll()  # reads the lines; the episode is open
            self.assertEqual(self.database.rate_warnings(), [])
            with mock.patch.object(guardd, "_utc_now", return_value=2_000_000_000):
                self.engine.poll()  # nothing new: the wall clock closes it
        self.assertEqual(len(self.database.rate_warnings()), 1)

    def test_stopping_keeps_an_episode_still_going_on(self):
        self.append(*[access_line("198.51.100.7")] * 6)
        self.engine.ingest_log(T0)
        self.engine.stop()
        self.assertEqual(len(self.database.rate_warnings()), 1)

    def test_the_status_reports_the_counters(self):
        summary = self.engine.health()["rate_warnings"]
        self.assertEqual(summary["sites"], 1)
        self.assertEqual(summary["max_tracked"], guardd.TRUSTED_RATE_MAX_KEYS)

    def test_an_episode_going_on_reaches_the_panel_as_a_row(self):
        # The observer's counters once replaced the "open" list with a
        # number, and the panel's server failed on it.
        from haproxy_admin import services_security

        self.append(*[access_line("198.51.100.7")] * 6)
        self.engine.ingest_log(T0)
        payload = json.loads(json.dumps(
            guardd.rate_warnings_payload(self.engine, self.database, 100, T0 + 1)))
        self.assertEqual([row["ip"] for row in payload["open"]], ["198.51.100.7"])
        self.assertEqual(payload["observer"]["open"], 1)
        with mock.patch.object(services_security, "guardd_rate_warnings", return_value=payload), \
                mock.patch.object(services_security, "_site_limits", return_value={}), \
                mock.patch.object(services_security, "get_country_code", return_value=""):
            result = services_security.rate_warnings({})
        self.assertEqual([row["ip"] for row in result["open"]], ["198.51.100.7"])


class TheTable(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "security.db"

    def episode(self, ended, ip="198.51.100.7"):
        return {"ip": ip, "site": "shop", "trust": "whitelist", "limit": 5, "window": 20,
                "enforced": True, "started": ended - 5, "ended": ended, "peak": 9,
                "over_limit": 4, "requests": 4, "rate_limited": 0, "banned": 0, "rate_ban": False}

    def test_a_database_from_before_gets_the_table_and_keeps_its_version(self):
        database = guardd.SecurityDatabase(str(self.path))
        database.close()
        connection = sqlite3.connect(str(self.path))
        connection.execute("DROP TABLE rate_warnings")
        connection.commit()
        connection.close()
        database = guardd.SecurityDatabase(str(self.path))
        self.addCleanup(database.close)
        database.record_rate_warnings([self.episode(T0)])
        self.assertEqual(len(database.rate_warnings()), 1)
        # No schema step: a daemon rolled back to before this still opens it.
        self.assertEqual(guardd.SCHEMA_VERSION, 3)

    def test_old_and_surplus_rows_are_pruned(self):
        database = guardd.SecurityDatabase(str(self.path))
        self.addCleanup(database.close)
        database.record_rate_warnings([self.episode(T0 - 40 * 86400)] + [
            self.episode(T0 + index) for index in range(5)
        ])
        deleted = database.prune_rate_warnings(before=T0 - 30 * 86400, keep=3)
        self.assertEqual(deleted, 3)
        self.assertEqual([row["ended"] for row in database.rate_warnings()],
                         [T0 + 4, T0 + 3, T0 + 2])
        self.assertEqual(database.rate_warning_count(since=T0 + 3), 2)


class ThePanel(unittest.TestCase):
    def test_rows_carry_the_real_site_and_country(self):
        from haproxy_admin import services_security

        payload = {"ok": True, "open": [{"ip": "198.51.100.7", "site": "shop_example"}],
                   "recent": [{"ip": "203.0.113.9", "site": "gone"}]}
        limits = {"shop_example": {"site": "shop.example", "domain": "shop.example.test"}}
        with mock.patch.object(services_security, "guardd_rate_warnings",
                               return_value=payload) as asked, \
                mock.patch.object(services_security, "_site_limits", return_value=limits), \
                mock.patch.object(services_security, "get_country_code", return_value="NL"):
            result = services_security.rate_warnings({"limit": "9999"})
        asked.assert_called_once_with(500)
        self.assertEqual(result["open"][0]["site_domain"], "shop.example.test")
        self.assertEqual(result["open"][0]["country"], "NL")
        self.assertNotIn("site_domain", result["recent"][0])

    def test_the_page_has_the_card_and_asks_for_it_separately(self):
        html = (ROOT / "docker/app/haproxy_admin/templates/adaptive_protection.html").read_text(encoding="utf-8")
        script = (ROOT / "docker/app/haproxy_admin/static/js/adaptive_protection.js").read_text(encoding="utf-8")
        self.assertIn('id="ap-warnings-card" hidden', html)
        self.assertIn('"/api/security/adaptive/rate-warnings"', script)
        # A daemon from before this answers 404: the card hides, and the
        # "engine is not answering" banner is not raised for it.
        block = script.split("async function loadWarnings")[1].split("async function")[0]
        self.assertIn("renderWarnings(null)", block)
        self.assertNotIn("showUnavailable", block)


if __name__ == "__main__":
    unittest.main()
