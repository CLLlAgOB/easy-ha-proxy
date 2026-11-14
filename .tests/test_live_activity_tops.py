"""The live page's top lists: what was asked for, what was not found, which
clients, the slowest answers, and each site's requests over the window.

A scanner walking paths that do not exist shows as a column of 404s on
paths nobody else asks for; a script shows as one user agent with many
requests; a slow backend shows as its requests at the top of the slowest.
The page could only say "this address made many requests" before.
"""

from __future__ import annotations

from pathlib import Path
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

from test_live_activity import guardd, line, record  # noqa: E402

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_live as live  # noqa: E402

APP = ROOT / "docker/app/haproxy_admin"


def request(ip, status, *, at, path="/index.html", agent="", ms=20, **extra):
    text = line(ip, status, at=at, request=f"GET {path} HTTP/1.1",
                times=extra.pop("times", f"0/0/1/{ms}/{ms + 1}"), **extra)
    if agent:
        text = text.replace(" GET ", f" ua={agent} GET ", 1)
    return record(text)


def aggregate(records, filters=None, window=600):
    return guardd.live_aggregate(records, now=time.time() + 1, window=window,
                                 filters=guardd.live_filters(filters or {}))


class Paths(unittest.TestCase):
    def test_the_most_requested_come_first_with_how_they_ended(self):
        now = time.time()
        records = (
            [request("203.0.113.9", 200, at=now, path="/") for _ in range(3)]
            + [request("203.0.113.9", 502, at=now, path="/")]
            + [request("203.0.113.9", 200, at=now, path="/about")]
        )
        paths = aggregate(records)["paths"]
        self.assertEqual([(row["path"], row["requests"]) for row in paths], [("/", 4), ("/about", 1)])
        self.assertEqual(paths[0]["host"], "shop.example.test")
        self.assertEqual(paths[0]["server_errors"], 1)
        self.assertEqual(paths[0]["client_errors"], 0)

    def test_not_found_is_its_own_list_and_a_refusal_is_not_a_404(self):
        now = time.time()
        records = (
            [request("192.0.2.66", 404, at=now, path="/.env") for _ in range(5)]
            + [request("192.0.2.66", 404, at=now, path="/wp-login.php") for _ in range(2)]
            + [request("192.0.2.66", 200, at=now, path="/")]
            + [request("192.0.2.66", 451, at=now, path="/.git/config", backend="fe_https/<NOSRV>",
                       times="0/-1/-1/-1/0")]
        )
        data = aggregate(records)
        self.assertEqual([(row["path"], row["not_found"]) for row in data["not_found"]],
                         [("/.env", 5), ("/wp-login.php", 2)])
        refused = next(row for row in data["paths"] if row["path"] == "/.git/config")
        self.assertEqual((refused["blocked"], refused["not_found"]), (1, 0))

    def test_the_lists_are_bounded(self):
        now = time.time()
        records = [request("192.0.2.66", 404, at=now, path=f"/probe/{n}") for n in range(200)]
        data = aggregate(records)
        self.assertEqual(len(data["paths"]), guardd.LIVE_MAX_PATHS)
        self.assertEqual(len(data["not_found"]), guardd.LIVE_MAX_NOT_FOUND)


class Clients(unittest.TestCase):
    def test_each_user_agent_with_its_addresses_and_refusals(self):
        now = time.time()
        records = [
            request("203.0.113.9", 200, at=now, agent="curl/8.5.0"),
            request("203.0.113.10", 200, at=now, agent="curl/8.5.0"),
            request("203.0.113.10", 423, at=now, agent="curl/8.5.0", backend="fe_https/<NOSRV>",
                    term="PR--", ban=' ban_val=1 ban_code=30 ban_reason="RATE_LIMIT_SITE"'),
            request("198.51.100.4", 200, at=now, agent="Mozilla/5.0__Windows_NT_10.0"),
            # No user agent logged: not a client called "".
            request("198.51.100.5", 200, at=now),
        ]
        agents = aggregate(records)["agents"]
        self.assertEqual(agents[0], {"agent": "curl/8.5.0", "requests": 3, "blocked": 1, "addresses": 2})
        self.assertEqual([row["agent"] for row in agents], ["curl/8.5.0", "Mozilla/5.0__Windows_NT_10.0"])

    def test_a_client_filter_finds_it_as_the_log_wrote_it(self):
        now = time.time()
        records = [
            request("203.0.113.9", 200, at=now, agent="curl/8.5.0"),
            request("198.51.100.4", 200, at=now, agent="Mozilla/5.0__Windows_NT_10.0"),
            request("198.51.100.5", 200, at=now),
        ]
        self.assertEqual(aggregate(records, {"agent": "CURL"})["totals"]["requests"], 1)
        # Typed with a space; the log has "_" where the space was.
        found = aggregate(records, {"agent": "Windows NT"})
        self.assertEqual([row["ip"] for row in found["addresses"]], ["198.51.100.4"])
        self.assertEqual(aggregate(records, {"agent": "wget"})["totals"]["requests"], 0)


class Slowest(unittest.TestCase):
    def test_the_slowest_answers_first_and_only_answered_ones(self):
        now = time.time()
        records = [request("203.0.113.9", 200, at=now, ms=ms) for ms in (40, 900, 15, 300)]
        records.append(request("203.0.113.9", 504, at=now, times="0/0/1/-1/30000"))
        slow = aggregate(records)["slow"]
        self.assertEqual([row["response_ms"] for row in slow], [900, 300, 40, 15])
        self.assertEqual(set(slow[0]), set(aggregate(records)["events"][0]))

    def test_the_list_is_bounded_and_keeps_the_slowest(self):
        now = time.time()
        records = [request("203.0.113.9", 200, at=now, ms=ms) for ms in range(1, 201)]
        slow = aggregate(records)["slow"]
        self.assertEqual(len(slow), guardd.LIVE_MAX_SLOW)
        self.assertEqual(slow[0]["response_ms"], 200)
        self.assertEqual(slow[-1]["response_ms"], 200 - guardd.LIVE_MAX_SLOW + 1)


class SiteOverTheWindow(unittest.TestCase):
    def test_each_site_has_its_requests_per_bar(self):
        now = time.time()
        records = [
            request("203.0.113.9", 200, at=now - 500),
            # Both in the last bar of ten seconds.
            request("203.0.113.9", 200, at=now - 3),
            request("203.0.113.9", 200, at=now - 2),
            request("203.0.113.9", 200, at=now - 2, host="other.example.test", backend="be_other/srv1"),
        ]
        data = aggregate(records)
        sites = {row["host"]: row for row in data["sites"]}
        spark = sites["shop.example.test"]["spark"]
        self.assertEqual(len(spark), len(data["timeline"]))
        self.assertEqual(sum(spark), 3)
        self.assertEqual(spark[-1], 2)
        self.assertEqual(sum(sites["other.example.test"]["spark"]), 1)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePanelPassesItOn(unittest.TestCase):
    def test_the_client_filter_is_cleaned_and_sent(self):
        self.assertEqual(live.normalize_request({"agent": "  curl\x00/8 "})["agent"], "curl/8")
        self.assertEqual(len(live.normalize_request({"agent": "x" * 500})["agent"]), 120)
        self.assertNotIn("agent", live.normalize_request({"agent": "  "}))

    def test_the_slowest_get_a_country_and_follow_its_filter(self):
        snapshot = {
            "ok": True, "now": time.time(), "window": 60, "totals": {"requests": 2},
            "addresses": [], "sites": [],
            "events": [{"ip": "203.0.113.9"}, {"ip": "198.51.100.4"}],
            "slow": [{"ip": "203.0.113.9"}, {"ip": "198.51.100.4"}],
        }
        with mock.patch.object(live, "guardd_live", return_value=snapshot), \
             mock.patch.object(live, "get_tables", return_value={"ban": {"rows": []}}), \
             mock.patch.object(live, "haproxy_runtime_command", return_value=""), \
             mock.patch.object(live, "WHITELIST_GLOBAL_FILE", "/nonexistent"), \
             mock.patch.object(live, "get_ip_auth_table", return_value={"rows": []}), \
             mock.patch.object(live, "get_country_code",
                               side_effect=lambda ip: "PL" if ip.startswith("203") else "RU"), \
             mock.patch.object(live, "connection_limits", return_value={"burst": 200, "concurrent": 500}):
            data = live.live_view({"window": "60", "country": "pl"})
        self.assertEqual(data["slow"], [{"ip": "203.0.113.9", "country": "PL"}])
        self.assertEqual([row["ip"] for row in data["events"]], ["203.0.113.9"])


class ThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (APP / "static/js/live_activity.js").read_text(encoding="utf-8")
        cls.template = (APP / "templates/live_activity.html").read_text(encoding="utf-8")

    def test_three_more_tabs_each_with_its_panel(self):
        for tab in ("paths", "agents", "slow"):
            self.assertIn(f'data-tab="{tab}"', self.template)
            self.assertIn(f'data-panel="{tab}"', self.template)
        for body in ("la-paths-body", "la-not-found-body", "la-agents-body", "la-slow-body"):
            self.assertIn(f'id="{body}"', self.template)
            self.assertIn(f'byId("{body}")' if body != "la-slow-body" else '"la-slow-body"', self.script)
        tables = self.script.split("  function renderTables(data) {")[1].split("\n  }\n")[0]
        for renderer in ("renderPaths(data)", "renderAgents(data)", "renderSlow(data)"):
            self.assertIn(renderer, tables)

    def test_a_path_or_a_client_becomes_the_filter(self):
        self.assertIn('id="la-agent"', self.template)
        self.assertIn('byId("la-q").value = path.dataset.filterQ', self.script)
        self.assertIn('byId("la-agent").value = agent.dataset.filterAgent', self.script)
        self.assertIn('agent: byId("la-agent").value', self.script)

    def test_a_slow_request_opens_like_any_other(self):
        rows = self.script.split("  function renderRequestRows(bodyId, emptyId, rows) {")[1].split("\n  }\n")[0]
        self.assertIn("detailsRow(row)", rows)
        self.assertIn("renderSlow(state.data)", self.script)

    def test_sites_draw_their_line(self):
        self.assertIn("Over the window", self.template)
        self.assertIn("${sparkline(row.spark)}", self.script)


if __name__ == "__main__":
    unittest.main()
