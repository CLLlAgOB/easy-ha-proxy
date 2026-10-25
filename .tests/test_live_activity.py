"""The live activity page: who is hitting the gateway right now.

An office lost every site behind one gateway for an hour on the connection
limit, and finding out took SSH, a packet capture and the stick tables by
hand: the access log had no line about it, because a refused connection
never becomes an HTTP request. This page answers "what is happening now" in
one place -- the last seconds or minutes of the access log by address, site
and status, and beside them what the log cannot show: who is banned and why,
who is over the connection limit, who is allow-listed or signed in.

controld reads the log, by path, so the nightly rotation does not leave it
reading yesterday's file; the panel adds HAProxy's own state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
CONTROLD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
sys.path.insert(0, str(ROOT / "docker" / "app"))

SPEC = importlib.util.spec_from_file_location("controld_live", CONTROLD_PATH)
CONTROLD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLD)

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_live as live  # noqa: E402

NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))


def line(ip, status, *, ago=1.0, backend="be_shop/srv1", host="shop.example.test",
         request="GET /index.html?x=1 HTTP/1.1", term="-----", ban="", bytes_=512, times="0/0/1/20/21"):
    stamp = (NOW - timedelta(seconds=ago)).isoformat(timespec="microseconds")
    return (
        f"{stamp} gw haproxy[1234]: {ip}:40000 [25/Oct/2026:12:00:00.000] fe_https~ "
        f"{backend} {times} {status} {bytes_} {term}{ban} 5/5/0/0/0 0/0 "
        f"id=11111111-2222 host={host} {request}"
    )


class ParsingOneLine(unittest.TestCase):
    def test_an_ordinary_request(self):
        record = CONTROLD.parse_live_line(line("203.0.113.9", 200))
        self.assertEqual(record["ip"], "203.0.113.9")
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["host"], "shop.example.test")
        self.assertEqual(record["path"], "/index.html")  # no query string
        self.assertEqual(record["duration_ms"], 21)
        self.assertEqual(record["frontend"], "fe_https")
        self.assertAlmostEqual(record["ts"], NOW.timestamp() - 1, places=3)

    def test_an_absolute_form_request_line_gives_the_host_and_path(self):
        record = CONTROLD.parse_live_line(line(
            "203.0.113.9", 200, host="-",
            request="POST https://mail.example.test:443/webapi/entry.cgi?a=b HTTP/2.0",
        ))
        self.assertEqual(record["host"], "mail.example.test")
        self.assertEqual(record["path"], "/webapi/entry.cgi")

    def test_a_ban_fragment_is_read(self):
        record = CONTROLD.parse_live_line(line(
            "198.51.100.7", 423, backend="fe_https/<NOSRV>", term="PR--",
            ban=' ban_val=1 ban_code=30 ban_reason="RATE_LIMIT_SITE name=shop max_req_rate=200"',
        ))
        self.assertEqual(record["ban_code"], 30)
        self.assertEqual(record["ban_reason"], "RATE_LIMIT_SITE name=shop max_req_rate=200")

    def test_anything_else_is_not_a_request(self):
        for text in ("", "2026-10-25T12:00:00+03:00 gw haproxy[1]: [WARNING] Server down",
                     "garbage"):
            self.assertIsNone(CONTROLD.parse_live_line(text))


class WhatCountsAsARefusal(unittest.TestCase):
    def refusal(self, status, backend="fe_https/<NOSRV>", **kwargs):
        return CONTROLD.live_refusal(CONTROLD.parse_live_line(
            line("198.51.100.7", status, backend=backend, **kwargs)
        ))

    def test_the_gateways_own_answers(self):
        self.assertEqual(self.refusal(451), "geo")
        self.assertEqual(self.refusal(401), "zero-trust")
        self.assertEqual(self.refusal(403), "denied")
        self.assertEqual(self.refusal(400), "invalid-request")
        self.assertEqual(self.refusal(423), "banned")
        self.assertEqual(self.refusal(429), "rate-limited")

    def test_an_applications_own_refusal_is_not_the_gateways(self):
        self.assertEqual(self.refusal(401, backend="be_shop/srv1"), "")
        self.assertEqual(self.refusal(403, backend="be_shop/srv1"), "")
        self.assertEqual(self.refusal(200, backend="be_shop/srv1"), "")

    def test_a_redirect_from_port_80_is_not_a_refusal(self):
        self.assertEqual(self.refusal(301, backend="fe_http80/<NOSRV>"), "")


class TheSnapshot(unittest.TestCase):
    def snapshot(self, lines, window=60, **filters):
        return CONTROLD.live_snapshot(lines, now=NOW.timestamp(), window=window, filters=filters)

    def lines(self):
        return [
            line("203.0.113.9", 200, ago=50),
            line("203.0.113.9", 404, ago=40),
            line("203.0.113.9", 502, ago=30),
            line("198.51.100.7", 451, ago=20, backend="fe_https/<NOSRV>", term="PR--",
                 host="calendar.example.test", request="GET /.env HTTP/1.1"),
            line("198.51.100.7", 451, ago=10, backend="fe_https/<NOSRV>", term="PR--",
                 host="calendar.example.test", request="GET /.git/config HTTP/1.1"),
            line("192.0.2.1", 200, ago=90),  # outside the window
        ]

    def test_totals_and_addresses(self):
        data = self.snapshot(self.lines())
        self.assertEqual(data["totals"]["requests"], 5)
        self.assertEqual(data["totals"]["errors"], 4)
        self.assertEqual(data["totals"]["server_errors"], 1)
        self.assertEqual(data["totals"]["blocked"], 2)
        self.assertEqual(data["totals"]["addresses"], 2)
        rows = {row["ip"]: row for row in data["addresses"]}
        self.assertNotIn("192.0.2.1", rows)
        self.assertEqual(rows["203.0.113.9"]["requests"], 3)
        self.assertEqual(rows["203.0.113.9"]["server_errors"], 1)
        self.assertEqual(rows["198.51.100.7"]["blocked"], 2)
        self.assertEqual(rows["198.51.100.7"]["reason"], "geo")
        self.assertEqual(rows["198.51.100.7"]["last_path"], "/.git/config")
        self.assertEqual(data["refusals"], {"geo": 2})

    def test_sites_and_the_newest_event_first(self):
        data = self.snapshot(self.lines())
        sites = {row["host"]: row for row in data["sites"]}
        self.assertEqual(sites["calendar.example.test"]["blocked"], 2)
        self.assertEqual(sites["shop.example.test"]["backend"], "be_shop")
        self.assertEqual(data["events"][0]["path"], "/.git/config")
        self.assertEqual(data["events"][0]["refusal"], "geo")

    def test_the_timeline_covers_the_window(self):
        data = self.snapshot(self.lines(), window=60)
        self.assertEqual(data["bucket_seconds"], 1)
        self.assertEqual(len(data["timeline"]), 60)
        self.assertEqual(sum(b["ok"] + b["errors"] + b["blocked"] for b in data["timeline"]), 5)

    def test_filters_narrow_what_is_counted(self):
        self.assertEqual(self.snapshot(self.lines(), blocked=True)["totals"]["requests"], 2)
        self.assertEqual(self.snapshot(self.lines(), ip="203.0.113.9")["totals"]["requests"], 3)
        self.assertEqual(self.snapshot(self.lines(), status="5xx")["totals"]["requests"], 1)
        self.assertEqual(self.snapshot(self.lines(), host="calendar.example.test")["totals"]["requests"], 2)
        self.assertEqual(self.snapshot(self.lines(), q=".git")["totals"]["requests"], 1)

    def test_a_bad_filter_is_refused(self):
        for bad in ({"ip": "1; rm"}, {"host": "a b"}, {"status": "6xx"}):
            with self.assertRaises(ValueError):
                CONTROLD._live_filters(bad)


class ReadingTheWindow(unittest.TestCase):
    def test_it_reads_back_only_as_far_as_the_window_and_across_a_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            current = Path(directory) / "haproxy.log"
            previous = Path(directory) / "haproxy.log.1"
            previous.write_text("\n".join([
                line("192.0.2.1", 200, ago=500), line("192.0.2.2", 200, ago=70),
            ]) + "\n", encoding="utf-8")
            current.write_text("\n".join([
                line("192.0.2.3", 200, ago=50), line("192.0.2.4", 200, ago=5),
            ]) + "\n", encoding="utf-8")
            lines, truncated = CONTROLD.read_live_window(
                [str(current), str(previous)], NOW.timestamp() - 100,
                max_bytes=10_000_000, max_lines=1000,
            )
        ips = [CONTROLD.parse_live_line(text)["ip"] for text in lines]
        self.assertEqual(ips, ["192.0.2.2", "192.0.2.3", "192.0.2.4"])
        self.assertFalse(truncated)

    def test_a_flood_stops_at_the_cap_and_says_so(self):
        with tempfile.TemporaryDirectory() as directory:
            current = Path(directory) / "haproxy.log"
            current.write_text(
                "\n".join(line("192.0.2.9", 200, ago=50 - i * 0.01) for i in range(2000)) + "\n",
                encoding="utf-8",
            )
            lines, truncated = CONTROLD.read_live_window(
                [str(current)], NOW.timestamp() - 100, max_bytes=10_000_000, max_lines=100,
            )
        self.assertTrue(truncated)
        self.assertEqual(len(lines), 100)
        data = CONTROLD.live_snapshot(lines, now=NOW.timestamp(), window=100, filters={}, truncated=True)
        self.assertTrue(data["truncated"])
        self.assertLess(data["covered_seconds"], 100)

    def test_the_command_is_dispatched(self):
        source = CONTROLD_PATH.read_text(encoding="utf-8")
        self.assertIn('if cmd.startswith("logs-live "):', source)
        self.assertIn("[LOG_FILE, LOG_FILE + \".1\"]", source)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePanelAddsWhatTheLogCannotShow(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.allow = Path(temporary.name) / "whitelist.ip"
        self.allow.write_text("10.0.0.0/8\n", encoding="utf-8")
        snapshot = {
            "ok": True, "now": NOW.timestamp(), "window": 60, "totals": {"requests": 3},
            "addresses": [
                {"ip": "203.0.113.9", "requests": 2, "blocked": 0},
                {"ip": "10.1.2.3", "requests": 1, "blocked": 0},
            ],
            "events": [{"ip": "203.0.113.9"}],
            "sites": [],
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
        for patcher in (
            mock.patch.object(live, "fetch_snapshot", return_value=snapshot),
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
        data = live.live_view({"window": "60"})
        rows = {row["ip"]: row for row in data["addresses"]}
        self.assertTrue(rows["203.0.113.9"]["connection_limited"])
        self.assertTrue(rows["203.0.113.9"]["authorized"])
        self.assertEqual(rows["203.0.113.9"]["country"], "PL")
        # The allow list is exempt from the connection limit.
        self.assertTrue(rows["10.1.2.3"]["allow_listed"])
        self.assertFalse(rows["10.1.2.3"]["connection_limited"])
        self.assertEqual([b["ip"] for b in data["banned"]], ["198.51.100.7"])
        self.assertIn("Adaptive", data["banned"][0]["label"])
        self.assertEqual([r["ip"] for r in data["connection_limited"]], ["203.0.113.9"])
        self.assertEqual(data["totals"]["banned_now"], 1)
        self.assertEqual(data["current_connections"], 4)

    def test_the_country_filter_is_applied_here(self):
        data = live.live_view({"window": "60", "country": "pl"})
        self.assertEqual([row["ip"] for row in data["addresses"]], ["203.0.113.9"])
        self.assertEqual(data["countries"], ["PL", "RU"])

    def test_the_request_is_checked_before_it_reaches_controld(self):
        request = live.normalize_request({
            "window": "99999", "ip": "1;rm", "status": "7xx", "blocked": "1", "host": "A.Example",
        })
        self.assertEqual(request, {"window": 3600, "blocked": True, "host": "a.example"})


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
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_ban_goes_into_tbl_ban_with_its_own_code(self):
        result = live.ban_address("198.51.100.7", "203.0.113.1")
        self.assertTrue(result["ok"])
        command = self.runtime.call_args.args[0]
        self.assertEqual(command, "set table tbl_ban key 198.51.100.7 data.gpc0 1 data.gpt0 50")

    def test_the_operators_own_address_is_refused(self):
        result = live.ban_address("203.0.113.1", "203.0.113.1")
        self.assertFalse(result["ok"])
        self.runtime.assert_not_called()

    def test_an_allow_listed_or_invalid_address_is_refused(self):
        for ip in ("10.4.5.6", "300.1.1.1", "2001:db8::1", "1.2.3.4; clear table"):
            with self.subTest(ip=ip):
                self.assertFalse(live.ban_address(ip, "")["ok"])
        self.runtime.assert_not_called()


class ThePage(unittest.TestCase):
    def test_route_navigation_and_audit(self):
        routes = (APP / "routes_monitoring.py").read_text(encoding="utf-8")
        self.assertIn('@bp.get("/monitoring/live")', routes)
        self.assertIn('@bp.get("/api/monitoring/live")', routes)
        self.assertIn('@bp.post("/api/monitoring/live/ban")', routes)
        self.assertIn('"ban.place"', routes)
        nav = (APP / "templates/_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn('("routes.live_activity_page", "Live activity")', nav)

    def test_the_script_sorts_filters_and_refreshes_without_the_server_for_sorting(self):
        script = (APP / "static/js/live_activity.js").read_text(encoding="utf-8")
        self.assertIn("/api/monitoring/live?", script)
        self.assertIn("/api/monitoring/live/ban", script)
        self.assertIn('"/api/unban"', script)
        self.assertIn("document.hidden", script)
        sort_handler = script.split('document.querySelectorAll("th[data-sort]").forEach')[1].split("});\n    });")[0]
        self.assertIn("render();", sort_handler)
        self.assertNotIn("refresh()", sort_handler)


if __name__ == "__main__":
    unittest.main()
