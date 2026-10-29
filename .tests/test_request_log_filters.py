"""The request log's filters mean one thing whoever answers: the store, or,
with the record off, the live buffer in memory.

With recording off (the default, and the state of both gateways in use)
the page was empty, so a link from the live page or the charts led to
"requests are not being recorded" -- while guardd held the last hour of
them in memory all along.
"""

from __future__ import annotations

from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_request_log import StoreTestCase, guardd, line  # noqa: E402

SOURCE = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
STAMP = "2026-08-12T10:{minute:02d}:{second:02d}+00:00"

# (request id, overrides): a small gateway's worth of different requests.
TRAFFIC = [
    ("ok", dict()),
    ("missing", dict(status="404", request="GET /wp-login.php HTTP/1.1")),
    ("broken", dict(status="502", backend="be_shop/srv1", times="0/0/1/900/901")),
    ("slow", dict(times="0/0/1/2500/2600", request="GET /report HTTP/1.1")),
    ("geo", dict(status="451", backend="fe_https/<NOSRV>", times="0/-1/-1/-1/0")),
    ("ban", dict(status="423", backend="fe_https/<NOSRV>", times="0/-1/-1/-1/0",
                 extra='id=ban ban_val=1 ban_code=30 ban_reason="RATE_LIMIT_SITE name=shop"')),
    ("app403", dict(status="403")),  # the application's own refusal, not the gateway's
    ("post", dict(request="POST /api/orders HTTP/1.1")),
    ("panel", dict(backend="be_admin/ui", request="GET /monitoring/live HTTP/1.1")),
    ("curl", dict(extra="id=curl host=shop.example.test ua=curl/8.5.0")),
    ("browser", dict(extra="id=browser host=shop.example.test ua=Mozilla/5.0__Windows_NT_10.0;_Win64")),
]


def traffic_lines():
    lines = []
    for n, (request_id, overrides) in enumerate(TRAFFIC):
        overrides = dict(overrides)
        overrides.setdefault("extra", f"id={request_id} host=shop.example.test")
        lines.append(line(at=STAMP.format(minute=n, second=0), **overrides))
    return lines


class Statuses(unittest.TestCase):
    def test_one_a_class_or_several(self):
        self.assertEqual(guardd.parse_statuses("404"), ((404, 405),))
        self.assertEqual(guardd.parse_statuses("5xx"), ((500, 600),))
        self.assertEqual(guardd.parse_statuses("4xx, 500"), ((400, 500), (500, 501)))
        self.assertEqual(guardd.parse_statuses("404 404"), ((404, 405),))

    def test_what_is_not_a_status_is_left_out(self):
        self.assertEqual(guardd.parse_statuses("abc"), ())
        self.assertEqual(guardd.parse_statuses("999, 4xx; 6xx"), ((400, 500),))
        self.assertEqual(guardd.parse_statuses("' OR 1=1"), ())


class TheStore(StoreTestCase):
    def setUp(self):
        super().setUp()
        for text in traffic_lines():
            self.store.add(guardd.parse_access_line(text), guardd.line_epoch(text))
        self.store.flush(self.now)

    def ids(self, **filters):
        return sorted(row["request_id"] for row in self.store.search(**filters)["requests"])

    def test_several_statuses(self):
        self.assertEqual(self.ids(status="404, 5xx"), ["broken", "missing"])

    def test_refused_by_the_gateway_not_by_the_application(self):
        self.assertEqual(self.ids(refused=True), ["ban", "geo"])

    def test_slower_is_the_servers_answer(self):
        self.assertEqual(self.ids(slower=900), ["broken", "slow"])
        self.assertEqual(self.ids(slower=1000), ["slow"])

    def test_a_client_as_typed_finds_it_as_logged(self):
        self.assertEqual(self.ids(agent="Windows NT"), ["browser"])
        self.assertEqual(self.ids(agent="CURL"), ["curl"])
        # "_" is what the log writes for every other character, and it is
        # looked for as itself, not as "any one character" (LIKE's meaning).
        self.assertEqual(self.ids(agent="curl_8"), [])
        self.assertEqual(self.ids(agent="_"), ["browser"])
        # What the log would never contain is looked for as the log writes it.
        self.assertEqual(self.ids(agent="10.0; Win64"), ["browser"])

    def test_a_method(self):
        self.assertEqual(self.ids(method="POST"), ["post"])


class TheSameAnswerFromMemory(StoreTestCase):
    """The parity that matters: whichever answers, the page shows the same."""

    QUERIES = [
        {},
        dict(status="4xx"),
        dict(status="404, 5xx"),
        dict(refused=True),
        dict(slower=900),
        dict(agent="windows nt"),
        dict(agent="curl_8"),
        dict(agent="10.0; Win64"),
        dict(method="POST"),
        dict(path="/api"),
        dict(hide_admin=True),
        dict(hide_admin=True, request_id="panel"),
        dict(hide_admin=True, backend="be_admin"),
        dict(client="203.0.113.9", status="2xx"),
        dict(backend="be_shop"),
        dict(host="other.example.test"),
        dict(since=1786528800 + 5 * 60, until=1786528800 + 8 * 60),
    ]

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

    def test_every_filter_finds_the_same_requests(self):
        for filters in self.QUERIES:
            with self.subTest(filters=filters):
                stored = self.store.search(**filters)
                held = self.buffer.search_requests(guardd.RequestQuery.build(**filters))
                self.assertEqual([row["request_id"] for row in held["requests"]],
                                 [row["request_id"] for row in stored["requests"]])
                self.assertEqual(held["total"], stored["total"])

    def test_a_row_reads_the_same(self):
        stored = {row["request_id"]: row for row in self.store.search()["requests"]}
        held = {row["request_id"]: row for row in
                self.buffer.search_requests(guardd.RequestQuery.build())["requests"]}
        for request_id in ("ok", "broken", "geo", "ban", "browser"):
            with self.subTest(request_id=request_id):
                for key in ("ts", "client", "status", "backend", "server", "method", "host", "path",
                            "bytes_out", "duration_ms", "response_ms", "times", "term", "ban_reason",
                            "user_agent", "refusal", "bad_request"):
                    self.assertEqual(held[request_id][key], stored[request_id][key], key)


class Memory(unittest.TestCase):
    def setUp(self):
        self.buffer = guardd.LiveBuffer(1000, 7 * 86400)

    def records(self, start, count, prefix):
        now = time.time()
        made = []
        for n in range(count):
            text = line(at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now - 3000 + start + n)),
                        extra=f"id={prefix}{n:02d} host=shop.example.test")
            made.append(guardd.live_record(guardd.parse_access_line(text), guardd.line_epoch(text)))
        return made

    def test_pages_carry_on_below_the_last_row_as_new_requests_arrive(self):
        self.buffer.extend(self.records(0, 30, "r"))
        first = self.buffer.search_requests(guardd.RequestQuery.build(), limit=10)
        self.assertEqual(first["source"], "memory")
        self.assertEqual(first["requests"][0]["request_id"], "r29")
        self.buffer.extend(self.records(100, 5, "new"))
        second = self.buffer.search_requests(guardd.RequestQuery.build(), limit=10,
                                              before=first["next"], count=False)
        self.assertEqual(second["requests"][0]["request_id"], "r19")
        self.assertNotIn("total", second)

    def test_ids_hold_when_older_requests_are_read_back_after_a_restart(self):
        self.buffer.extend(self.records(100, 10, "after"))
        first = self.buffer.search_requests(guardd.RequestQuery.build(), limit=5)
        self.buffer.refill(self.records(0, 10, "before"), complete_since=0)
        second = self.buffer.search_requests(guardd.RequestQuery.build(), limit=5, before=first["next"])
        self.assertEqual([row["request_id"] for row in second["requests"]],
                         ["after04", "after03", "after02", "after01", "after00"])
        third = self.buffer.search_requests(guardd.RequestQuery.build(), limit=5, before=second["next"])
        self.assertEqual(third["requests"][0]["request_id"], "before09")
        self.assertTrue(all(row["id"] > 0 for row in third["requests"]))

    def test_the_answer_says_how_far_back_memory_reaches(self):
        self.buffer.extend(self.records(0, 3, "r"))
        found = self.buffer.search_requests(guardd.RequestQuery.build())
        self.assertAlmostEqual(found["reaches_back_to"], time.time() - 3000, delta=5)

    def test_counting_stops_at_the_cap(self):
        self.buffer.extend(self.records(0, 30, "r"))
        original = guardd.REQUEST_COUNT_CAP
        guardd.REQUEST_COUNT_CAP = 12
        try:
            found = self.buffer.search_requests(guardd.RequestQuery.build(), limit=5)
        finally:
            guardd.REQUEST_COUNT_CAP = original
        self.assertEqual((found["total"], found["total_exact"]), (12, False))


class TheEndpoint(unittest.TestCase):
    def test_with_the_record_off_memory_answers(self):
        block = SOURCE.split('if path in ("/api/v1/guard/requests", "/api/v1/guard/requests/status",')[1][:4000]
        self.assertIn("memory = engine.live if requests is None", block)
        self.assertIn("memory.search_requests(", block)
        # The status of the store stays "off": only searching has memory.
        self.assertIn('not path.endswith("/status")', block)
        for name in ('yes("refused")', 'one("slower")', 'one("agent")'):
            self.assertIn(name, block)


if __name__ == "__main__":
    unittest.main()
