"""The live activity page, and what it costs the gateway to show it.

An office lost every site behind one gateway for an hour on the connection
limit, and finding out took SSH, a packet capture and the stick tables read
by hand: a refused connection never becomes an HTTP request, so the access
log had nothing. The live page answers "what is happening now" in one place.

The first version read the access log again on every refresh of every open
page -- 0.1 s for fifteen quiet minutes, several seconds of CPU per refresh
under a flood, exactly when HAProxy needs the CPU. guardd already reads
every line once, within a byte budget, for scoring; the latest requests are
now kept in its memory and the page is answered from there. Following the
log closely while the page is open comes out of the same budget, a flood
larger than the budget makes the page fall behind instead of the gateway,
and guardd runs at a lower priority than HAProxy. The dashboard's top
400/451 addresses, which read the whole day's log on every visit, are
counted on the way past too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
GUARDD_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
CONTROLD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
UNIT = ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-guardd.service.j2"
sys.path.insert(0, str(ROOT / "docker" / "app"))

SPEC = importlib.util.spec_from_file_location("guardd_live", GUARDD_PATH)
guardd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guardd
SPEC.loader.exec_module(guardd)

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_live as live  # noqa: E402
    from haproxy_admin import services as services  # noqa: E402

ZONE = timezone(timedelta(hours=3))


def line(ip, status, *, at, backend="be_shop/srv1", host="shop.example.test",
         request="GET /index.html?x=1 HTTP/1.1", term="-----", ban="", times="0/0/1/20/21"):
    stamp = datetime.fromtimestamp(at, ZONE).isoformat(timespec="microseconds")
    return (
        f"{stamp} gw haproxy[1234]: {ip}:40000 [25/Oct/2026:12:00:00.000] fe_https~ "
        f"{backend} {times} {status} 512 {term}{ban} 5/5/0/0/0 0/0 "
        f"id=11111111-2222 host={host} {request}"
    )


def record(text):
    request = guardd.parse_access_line(text)
    return guardd.live_record(request, guardd.line_epoch(text))


class OneLine(unittest.TestCase):
    def test_what_the_page_needs_comes_from_the_one_parse(self):
        now = time.time()
        r = record(line("203.0.113.9", 200, at=now - 1))
        self.assertEqual(r[guardd.L_IP], "203.0.113.9")
        self.assertEqual(r[guardd.L_HOST], "shop.example.test")
        self.assertEqual(r[guardd.L_PATH], "/index.html")  # no query string
        self.assertEqual(r[guardd.L_DURATION], 21)
        self.assertEqual(r[guardd.L_TERM], "-----")
        # The syslog stamp carries its zone; HAProxy's own does not.
        self.assertAlmostEqual(r[guardd.L_TS], now - 1, places=3)

    def test_a_ban_and_its_reason(self):
        r = record(line(
            "198.51.100.7", 423, at=time.time(), backend="fe_https/<NOSRV>", term="PR--",
            ban=' ban_val=1 ban_code=30 ban_reason="RATE_LIMIT_SITE name=shop max_req_rate=200"',
        ))
        self.assertEqual(r[guardd.L_REFUSAL], "banned")
        self.assertEqual(r[guardd.L_REASON], "RATE_LIMIT_SITE name=shop max_req_rate=200")

    def test_the_gateways_own_refusals_and_nothing_else(self):
        refuse = guardd.live_refusal
        self.assertEqual(refuse(451, "fe_https/<NOSRV>", "PR--", ""), "geo")
        self.assertEqual(refuse(401, "fe_https/<NOSRV>", "PR--", ""), "zero-trust")
        self.assertEqual(refuse(403, "fe_https/<NOSRV>", "PR--", ""), "denied")
        self.assertEqual(refuse(400, "fe_https/<NOSRV>", "PR--", ""), "invalid-request")
        self.assertEqual(refuse(429, "fe_https/<NOSRV>", "PR--", ""), "rate-limited")
        # An application's own refusal, and a redirect, are not the gateway's.
        self.assertEqual(refuse(403, "be_shop/srv1", "----", ""), "")
        self.assertEqual(refuse(301, "fe_http80/<NOSRV>", "LR--", ""), "")


class TheBuffer(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.buffer = guardd.LiveBuffer(1000, 3600)
        self.buffer.started = self.now - 7200

    def fill(self):
        self.buffer.extend([
            record(line("203.0.113.9", 200, at=self.now - 50)),
            record(line("203.0.113.9", 404, at=self.now - 40)),
            record(line("203.0.113.9", 502, at=self.now - 30)),
            record(line("198.51.100.7", 451, at=self.now - 20, backend="fe_https/<NOSRV>",
                        term="PR--", host="calendar.example.test", request="GET /.env HTTP/1.1")),
            record(line("198.51.100.7", 451, at=self.now - 10, backend="fe_https/<NOSRV>",
                        term="PR--", host="calendar.example.test", request="GET /.git/config HTTP/1.1")),
        ])

    def test_the_snapshot(self):
        self.fill()
        data = self.buffer.snapshot({"window": "60"}, now=self.now)
        self.assertEqual(data["totals"]["requests"], 5)
        self.assertEqual(data["totals"]["errors"], 4)
        self.assertEqual(data["totals"]["server_errors"], 1)
        self.assertEqual(data["totals"]["blocked"], 2)
        rows = {row["ip"]: row for row in data["addresses"]}
        self.assertEqual(rows["198.51.100.7"]["reason"], "geo")
        self.assertEqual(rows["198.51.100.7"]["last_path"], "/.git/config")
        self.assertEqual(data["events"][0]["path"], "/.git/config")
        self.assertEqual({row["host"]: row["blocked"] for row in data["sites"]}["calendar.example.test"], 2)
        self.assertEqual(len(data["timeline"]), 60)
        self.assertFalse(data["truncated"])

    def test_filters(self):
        self.fill()
        count = lambda **f: self.buffer.snapshot({"window": "60", **f}, now=self.now)["totals"]["requests"]
        self.assertEqual(count(blocked="1"), 2)
        self.assertEqual(count(ip="203.0.113.9"), 3)
        self.assertEqual(count(status="5xx"), 1)
        self.assertEqual(count(host="calendar.example.test"), 2)
        self.assertEqual(count(q=".GIT"), 1)
        with self.assertRaises(ValueError):
            self.buffer.snapshot({"ip": "1; rm"}, now=self.now)

    def test_it_is_bounded_by_count_and_by_age(self):
        small = guardd.LiveBuffer(3, 3600)
        small.extend([record(line("192.0.2.%d" % i, 200, at=self.now - 10 + i)) for i in range(5)])
        self.assertEqual(small.status()["records"], 3)
        young = guardd.LiveBuffer(1000, 60)
        young.extend([record(line("192.0.2.1", 200, at=self.now - 600)),
                      record(line("192.0.2.2", 200, at=self.now))])
        self.assertEqual(young.status()["records"], 1)

    def test_a_buffer_that_does_not_reach_back_says_how_far_it_does(self):
        small = guardd.LiveBuffer(3, 3600)
        small.started = self.now - 7200
        small.extend([record(line("192.0.2.9", 200, at=self.now - 100 + i)) for i in range(10)])
        data = small.snapshot({"window": "300"}, now=self.now)
        self.assertTrue(data["truncated"])
        self.assertLess(data["covered_seconds"], 300)

    def test_one_computation_for_many_pages(self):
        self.fill()
        with mock.patch.object(guardd, "live_aggregate", wraps=guardd.live_aggregate) as counted:
            for _ in range(5):
                self.buffer.snapshot({"window": "60"})
        self.assertEqual(counted.call_count, 1)

    def test_watching_switches_on_close_following(self):
        self.assertFalse(self.buffer.wanted())
        # Even on a machine that booted a moment ago, where the monotonic
        # clock is still small -- a fresh CI runner is one.
        with mock.patch.object(guardd.time, "monotonic", return_value=30.0):
            self.assertFalse(guardd.LiveBuffer(10, 3600).wanted())
        self.buffer.snapshot({"window": "60"})
        self.assertTrue(self.buffer.wanted())

    def test_the_dashboards_top_400_and_451_are_counted_on_the_way(self):
        self.fill()
        self.buffer.extend([record(line("203.0.113.66", 400, at=self.now - 5, backend="fe_https/<NOSRV>"))])
        top = self.buffer.attackers(now=self.now)
        self.assertEqual(top["code_451"], [{"ip": "198.51.100.7", "count": 2}])
        self.assertEqual(top["code_400"], [{"ip": "203.0.113.66", "count": 1}])


class TheEngine(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        self.config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=())
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(self.config, self.database)
        self.engine.cursor.read(4096)

    def test_the_lines_read_for_scoring_feed_the_buffer(self):
        now = time.time()
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(line("203.0.113.9", 200, at=now - 2) + "\n")
            handle.write(line("203.0.113.9", 404, at=now - 1) + "\n")
        self.engine.ingest_log(int(now))
        self.assertEqual(self.engine.live.status()["records"], 2)

    def test_a_read_is_held_to_its_byte_allowance(self):
        now = time.time()
        with self.log.open("a", encoding="utf-8") as handle:
            for i in range(200):
                handle.write(line("203.0.113.9", 200, at=now - 1) + "\n")
        self.engine.ingest_log(int(now), max_bytes=4096)
        self.assertLessEqual(self.engine._cycle_bytes, 4096)
        self.assertGreater(self.engine.cursor.lag_bytes, 0)

    def test_the_fast_ticks_share_the_cycles_budget(self):
        source = GUARDD_PATH.read_text(encoding="utf-8")
        loop = source.split("def _run(self) -> None:")[1].split("\n    def ")[0]
        self.assertIn("self.live.wanted()", loop)
        self.assertIn("self.config.log_read_bytes_per_cycle - self._cycle_bytes", loop)
        poll = source.split("def poll(self)")[1].split("\n    def ")[0]
        self.assertIn("self.config.log_read_bytes_per_cycle - self._cycle_bytes", poll)

    def test_it_can_be_switched_off(self):
        engine = guardd.GuardEngine(guardd.GuardConfig(log_file=str(self.log), whitelist_files=(), live_buffer_records=0), self.database)
        self.assertIsNone(engine.live)


class TheGatewayComesFirst(unittest.TestCase):
    def test_guardd_runs_below_haproxy(self):
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn("Nice=10", unit)
        self.assertIn("CPUWeight=50", unit)

    def test_the_log_is_no_longer_reread_per_refresh(self):
        source = CONTROLD_PATH.read_text(encoding="utf-8")
        self.assertNotIn("logs-live", source)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePanel(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.allow = Path(temporary.name) / "whitelist.ip"
        self.allow.write_text("10.0.0.0/8\n", encoding="utf-8")
        snapshot = {
            "ok": True, "now": time.time(), "window": 60, "totals": {"requests": 3},
            "addresses": [
                {"ip": "203.0.113.9", "requests": 2, "blocked": 0},
                {"ip": "10.1.2.3", "requests": 1, "blocked": 0},
            ],
            "events": [{"ip": "203.0.113.9"}], "sites": [],
        }
        tables = {"ban": {"rows": [
            ["198.51.100.7", "Blocked", "40", "3600"],
            ["192.0.2.50", "Not blocked", "10", "100"],
        ]}}
        conn = (
            "# table: fe_https, type: ip, size:204800, used:3\n"
            "0x1: key=203.0.113.9 use=0 exp=1000 shard=0 conn_rate(10000)=250 conn_cur=3\n"
            "0x2: key=10.1.2.3 use=0 exp=1000 shard=0 conn_rate(10000)=900 conn_cur=1\n"
        )
        self.guardd = mock.Mock(return_value=snapshot)
        for patcher in (
            mock.patch.object(live, "guardd_live", self.guardd),
            mock.patch.object(live, "get_tables", return_value=tables),
            mock.patch.object(live, "haproxy_runtime_command", return_value=conn),
            mock.patch.object(live, "WHITELIST_GLOBAL_FILE", str(self.allow)),
            mock.patch.object(live, "get_ip_auth_table", return_value={"rows": [["203.0.113.9", "1", "100"]]}),
            mock.patch.object(live, "get_country_code", side_effect=lambda ip: "PL" if ip.startswith("203") else "RU"),
            mock.patch.object(live, "connection_limits", return_value={"burst": 200, "concurrent": 500}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_bans_limits_allow_list_and_country(self):
        data = live.live_view({"window": "60", "blocked": "1", "country": "pl"})
        sent = self.guardd.call_args.args[0]
        self.assertEqual(sent, {"window": 60, "blocked": "1"})  # country stays here
        rows = {row["ip"]: row for row in data["addresses"]}
        self.assertEqual(list(rows), ["203.0.113.9"])
        self.assertTrue(rows["203.0.113.9"]["connection_limited"])
        self.assertTrue(rows["203.0.113.9"]["authorized"])
        self.assertEqual([b["ip"] for b in data["banned"]], ["198.51.100.7"])
        self.assertEqual([r["ip"] for r in data["connection_limited"]], ["203.0.113.9"])
        self.assertEqual(data["current_connections"], 4)

    def test_guardd_down_is_said_plainly(self):
        self.guardd.side_effect = live.GuarddUnavailable("no socket")
        with self.assertRaises(live.LiveUnavailable) as caught:
            live.live_view({})
        self.assertIn("Adaptive protection is not answering", str(caught.exception))


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class BanningByHand(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.allow = Path(temporary.name) / "whitelist.ip"
        self.allow.write_text("10.0.0.0/8\n", encoding="utf-8")
        self.runtime = mock.Mock(return_value="")
        for patcher in (
            mock.patch.object(live, "haproxy_runtime_command", self.runtime),
            mock.patch.object(live, "WHITELIST_GLOBAL_FILE", str(self.allow)),
            # The drop-and-ban path edits the list through the services module,
            # which keeps its own copy of the path and its own file-reload
            # helpers; point them at the throwaway file and stub the reload.
            mock.patch.object(services, "WHITELIST_GLOBAL_FILE", str(self.allow)),
            mock.patch.object(services, "ensure_whitelist_global_file", lambda: None),
            mock.patch.object(services, "_safe_runtime_acl", lambda *a, **k: ""),
            mock.patch.object(services, "_safe_reload_haproxy", lambda *a, **k: ""),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_ban_goes_into_tbl_ban_with_its_own_code(self):
        self.assertTrue(live.ban_address("198.51.100.7", "203.0.113.1")["ok"])
        self.assertEqual(
            self.runtime.call_args.args[0],
            "set table tbl_ban key 198.51.100.7 data.gpc0 1 data.gpt0 50",
        )

    def test_refusals(self):
        for ip, client in (("203.0.113.1", "203.0.113.1"), ("10.4.5.6", ""),
                           ("300.1.1.1", ""), ("2001:db8::1", ""), ("1.2.3.4; clear table", "")):
            with self.subTest(ip=ip):
                self.assertFalse(live.ban_address(ip, client)["ok"])
        self.runtime.assert_not_called()

    def test_a_plain_ban_on_an_allow_listed_address_is_flagged(self):
        # 10.4.5.6 is inside the 10.0.0.0/8 entry the fixture wrote.
        result = live.ban_address("10.4.5.6", "198.51.100.1")
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("allow_listed"))
        self.runtime.assert_not_called()

    def test_drop_and_ban_removes_the_host_entry_then_bans(self):
        self.allow.write_text("10.0.0.0/8\n203.0.113.9/32\n", encoding="utf-8")
        result = live.ban_address("203.0.113.9", "198.51.100.1", drop_allowlist=True)
        self.assertTrue(result["ok"])
        self.assertTrue(result["dropped_from_allowlist"])
        self.assertNotIn("203.0.113.9", self.allow.read_text())
        # The unrelated range is untouched.
        self.assertIn("10.0.0.0/8", self.allow.read_text())
        self.assertEqual(
            self.runtime.call_args.args[0],
            "set table tbl_ban key 203.0.113.9 data.gpc0 1 data.gpt0 50",
        )

    def test_drop_and_ban_removes_a_bare_host_line_too(self):
        # The entry may have been written without a /32, as a bare address.
        self.allow.write_text("203.0.113.9\n", encoding="utf-8")
        result = live.ban_address("203.0.113.9", "198.51.100.1", drop_allowlist=True)
        self.assertTrue(result["ok"])
        self.assertNotIn("203.0.113.9", self.allow.read_text())

    def test_drop_and_ban_refuses_when_only_a_range_covers_the_host(self):
        # A single office machine must not drop the whole office range.
        self.allow.write_text("203.0.113.0/24\n", encoding="utf-8")
        result = live.ban_address("203.0.113.9", "198.51.100.1", drop_allowlist=True)
        self.assertFalse(result["ok"])
        self.assertIn("range", result["error"].lower())
        self.assertIn("203.0.113.0/24", self.allow.read_text())
        self.runtime.assert_not_called()


class ThePage(unittest.TestCase):
    def test_route_navigation_and_audit(self):
        routes = (APP / "routes_monitoring.py").read_text(encoding="utf-8")
        for needle in ('@bp.get("/monitoring/live")', '@bp.get("/api/monitoring/live")',
                       '@bp.post("/api/monitoring/live/ban")', '"ban.place"'):
            self.assertIn(needle, routes)
        nav = (APP / "templates/_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn('("routes.live_activity_page", "Live activity")', nav)

    def test_the_script_sorts_locally_and_says_when_it_falls_behind(self):
        script = (APP / "static/js/live_activity.js").read_text(encoding="utf-8")
        self.assertIn("document.hidden", script)
        self.assertIn("data.lag_seconds", script)
        sort_handler = script.split('document.querySelectorAll("th[data-sort]").forEach')[1].split("});\n    });")[0]
        self.assertIn("render();", sort_handler)
        self.assertNotIn("refresh()", sort_handler)

    def test_the_allow_listed_rows_offer_drop_and_ban(self):
        script = (APP / "static/js/live_activity.js").read_text(encoding="utf-8")
        # The compact control, its handler and the request flag.
        self.assertIn("data-force-ban", script)
        self.assertIn("Drop & ban", script)
        self.assertIn("drop_allowlist: true", script)
        self.assertIn("function forceBan(", script)
        # It is only offered to allow-listed rows.
        self.assertIn("banButton(row.ip, Boolean(row.ban), Boolean(row.allow_listed))", script)
        catalogue = json.loads(
            (APP / "translations/ru/live_activity.json").read_text(encoding="utf-8")
        )["messages"]
        self.assertEqual(catalogue["Drop & ban"], "Снять и бан")
        self.assertIn("Remove from the allow list and ban", catalogue)

    def test_the_dashboard_counts_come_from_guardd_first(self):
        source = (APP / "services.py").read_text(encoding="utf-8")
        body = source.split("def get_attackers():")[1].split("\ndef ")[0]
        self.assertLess(body.index("guardd_attackers()"), body.index("controld_get_attackers()"))


if __name__ == "__main__":
    unittest.main()
