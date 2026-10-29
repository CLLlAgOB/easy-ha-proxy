"""The request log's overview and download: what a search finds over its
period and most often, from the store or from memory alike, and the same
rows as a CSV file a spreadsheet opens without running what a visitor
typed.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

from test_request_log import StoreTestCase, guardd  # noqa: E402
from test_request_log_filters import traffic_lines  # noqa: E402

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_security as security  # noqa: E402

SOURCE = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
APP = ROOT / "docker/app/haproxy_admin"
TEN = 1786528800  # 2026-08-12 10:00 UTC, where the traffic starts


class Layout(unittest.TestCase):
    def test_bars_a_person_reads_at_a_glance(self):
        self.assertEqual(guardd.summary_layout(TEN, TEN + 3600), (TEN, 60, 60))
        self.assertEqual(guardd.summary_layout(TEN, TEN + 86400)[1:], (1800, 48))
        self.assertEqual(guardd.summary_layout(TEN, TEN + 3 * 86400)[1:], (3600, 72))

    def test_the_first_bar_starts_on_its_own_boundary(self):
        first, step, bars = guardd.summary_layout(TEN + 1234, TEN + 1234 + 3600)
        self.assertEqual(first % step, 0)
        self.assertLessEqual(first, TEN + 1234)
        self.assertGreaterEqual(first + step * bars, TEN + 1234 + 3600)

    def test_a_moment_is_still_a_minute(self):
        self.assertEqual(guardd.summary_layout(TEN, TEN)[1:], (60, 1))


class TheStoresOverview(StoreTestCase):
    def setUp(self):
        super().setUp()
        for text in traffic_lines():
            self.store.add(guardd.parse_access_line(text), guardd.line_epoch(text))
        self.store.flush(self.now)

    def test_the_period_by_how_requests_ended(self):
        found = self.store.summary(since=TEN, until=TEN + 3600)
        self.assertEqual((found["start"], found["bucket_seconds"]), (TEN, 60))
        totals = [sum(bar[kind] for bar in found["buckets"]) for kind in range(4)]
        # answered, 4xx (404 and the application's own 403), 5xx, refused
        self.assertEqual(totals, [6, 2, 1, 2])
        self.assertEqual(found["counted"], len(traffic_lines()))
        # Minute 4 is the geo refusal: its own bar, as refused.
        self.assertEqual(found["buckets"][4], [0, 0, 0, 1])
        self.assertTrue(found["complete"])

    def test_what_is_most_common(self):
        found = self.store.summary(hide_admin=True)
        self.assertEqual(found["clients"], [{"client": "203.0.113.9", "count": len(traffic_lines()) - 1}])
        statuses = {row["status"]: row["count"] for row in found["statuses"]}
        self.assertEqual(statuses[200], 5)
        paths = {(row["host"], row["path"]): row["count"] for row in found["paths"]}
        # The ban's line names no host, so it is counted apart.
        self.assertEqual(paths[("shop.example.test", "/login")], 6)
        self.assertEqual(paths[("", "/login")], 1)
        self.assertNotIn(("shop.example.test", "/monitoring/live"), paths)

    def test_a_summary_out_of_time_says_how_far_back_it_got(self):
        with mock.patch.object(guardd, "REQUEST_SCAN_STEP", 4):
            found = self.store.summary(seconds=0)
        self.assertFalse(found["complete"])
        self.assertEqual(found["counted"], 4)
        # The newest four (ids 8 to 11) were counted; the oldest of them is
        # the eighth request, at 10:07.
        self.assertEqual(found["reached_to"], TEN + 7 * 60)


class TheSameOverviewFromMemory(StoreTestCase):
    QUERIES = [{}, dict(hide_admin=True), dict(status="4xx"), dict(refused=True), dict(agent="curl"),
               dict(since=TEN + 120, until=TEN + 600)]

    def setUp(self):
        super().setUp()
        self.buffer = guardd.LiveBuffer(1000, 7 * 86400)
        records = []
        for text in traffic_lines():
            request = guardd.parse_access_line(text)
            self.store.add(request, guardd.line_epoch(text))
            records.append(guardd.live_record(request, guardd.line_epoch(text)))
        self.store.flush(self.now)
        self.buffer.extend(records)

    def test_every_filter_gives_the_same_overview(self):
        for filters in self.QUERIES:
            with self.subTest(filters=filters):
                bounded = dict(filters)
                bounded.setdefault("since", TEN)
                bounded.setdefault("until", TEN + 3600)
                stored = self.store.summary(**bounded)
                held = self.buffer.summarize_requests(guardd.RequestQuery.build(**bounded))
                self.assertEqual(held["source"], "memory")
                for key in ("start", "bucket_seconds", "buckets", "counted", "statuses", "clients", "paths"):
                    self.assertEqual(held[key], stored[key], key)


class TheEndpoint(unittest.TestCase):
    def test_the_summary_is_answered_by_the_store_or_by_memory(self):
        block = SOURCE.split('if path in ("/api/v1/guard/requests", "/api/v1/guard/requests/status",')[1][:5000]
        self.assertIn('"/api/v1/guard/requests/summary"', block)
        self.assertIn("memory.summarize_requests(", block)
        self.assertIn("requests.summary(**filters)", block)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheDownload(unittest.TestCase):
    def rows(self, count, start=0):
        return [{"ts": TEN + n, "status": 200, "method": "GET", "host": "shop.example.test",
                 "path": f"/p{n}", "backend": "be_shop", "server": "srv1", "client": "203.0.113.9",
                 "response_ms": 12, "duration_ms": 13, "bytes_out": 512, "term": "----",
                 "times": "0/0/1/12/13", "ban_reason": "", "user_agent": "curl/8.5.0",
                 "request_id": f"id{n}", "refusal": "", "id": 1000 - n} for n in range(start, start + count)]

    def download(self, pages, args=None):
        answers = iter(pages)
        calls = []

        def fake(params):
            calls.append(dict(params))
            return next(answers)

        with mock.patch.object(security, "guardd_requests", side_effect=fake):
            text = "".join(security.requests_csv(args or {}))
        return text.splitlines(), calls

    def test_pages_are_followed_and_the_filters_kept(self):
        lines, calls = self.download(
            [{"requests": self.rows(2), "next": 998}, {"requests": self.rows(1, 2), "next": 0}],
            {"client": "203.0.113.9", "hide_admin": "1", "limit": "5", "before": "7"},
        )
        self.assertEqual(lines[0].split(",")[:4], ["time_utc", "status", "refused", "method"])
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[1].startswith("2026-08-12T10:00:00Z,200,"))
        # The search's filters, its own paging: no limit or cursor from the page.
        self.assertEqual(calls[0], {"client": "203.0.113.9", "hide_admin": "1", "limit": "500", "count": "0"})
        self.assertEqual(calls[1]["before"], "998")

    def test_it_stops_at_the_row_limit(self):
        with mock.patch.object(security, "EXPORT_ROWS", 3):
            lines, calls = self.download([{"requests": self.rows(5), "next": 995}])
        self.assertEqual(len(lines), 4)
        self.assertEqual(len(calls), 1)

    def test_what_a_visitor_typed_stays_text_in_a_spreadsheet(self):
        row = self.rows(1)[0]
        row.update(path="=HYPERLINK(\"http://x\")", user_agent="+cmd|' /C calc'!A0", ban_reason="@SUM(1)",
                   response_ms=-1, term="-----")
        lines, _ = self.download([{"requests": [row], "next": 0}])
        cells = lines[1]
        self.assertIn("'=HYPERLINK", cells)
        self.assertIn("'+cmd", cells)
        self.assertIn("'@SUM", cells)
        # A number stays a number, and a request that ended normally ("-----")
        # stays as HAProxy wrote it.
        self.assertIn(",-1,", cells)
        self.assertIn(",-----,", cells)

    def test_a_daemon_that_stops_answering_ends_the_file(self):
        with mock.patch.object(security, "guardd_requests",
                               side_effect=security.GuarddUnavailable("gone")):
            text = "".join(security.requests_csv({}))
        self.assertEqual(len(text.splitlines()), 1)


class TheRoutes(unittest.TestCase):
    def test_overview_and_download_read_only(self):
        routes = (APP / "routes_security.py").read_text(encoding="utf-8")
        block = routes.split("# Log Explorer")[1]
        self.assertIn('@bp.get("/api/security/requests/summary")', block)
        self.assertIn('@bp.get("/api/security/requests/export")', block)
        self.assertIn("attachment; filename=", block)
        # Flask adds the charset itself; naming it too wrote it twice.
        self.assertIn('mimetype="text/csv",', block)
        self.assertEqual(block.count("@bp.post"), 1)


class ThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (APP / "static/js/request_log.js").read_text(encoding="utf-8")
        cls.template = (APP / "templates/request_log.html").read_text(encoding="utf-8")

    def test_each_new_search_gets_its_overview_and_its_download(self):
        search = self.script.split("  async function search(append) {")[1].split("\n  }\n")[0]
        block = search.split("if (!append || !query) {")[1].split("\n    }\n")[0]
        self.assertIn("summarize(query)", block)
        self.assertIn("/api/security/requests/export?", block)
        self.assertIn('id="rq-export"', self.template)

    def test_dragging_across_the_bars_narrows_the_period(self):
        self.assertIn('svg.addEventListener("pointerup"', self.script)
        self.assertIn("choosePeriod(core.barsSpan(", self.script)
        self.assertIn('id="rq-hist"', self.template)

    def test_the_overviews_values_are_filters_too(self):
        self.assertIn('byId("rq-overview").addEventListener("click"', self.script)
        self.assertIn("button.dataset.host", self.script)
        for body in ("rq-top-clients", "rq-top-paths", "rq-top-statuses"):
            self.assertIn(f'id="{body}"', self.template)

    def test_the_store_line_says_how_far_back(self):
        self.assertIn("core.historyReach(payload", self.script)


if __name__ == "__main__":
    unittest.main()
