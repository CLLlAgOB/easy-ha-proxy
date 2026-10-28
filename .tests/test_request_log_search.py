"""The request log answers in time, pages without repeating itself, keeps
what a request needs to be understood, and stores the time it happened.

Measured on the test gateway's ARM CPU with three days of a small
production gateway's traffic (920 000 requests, 195 MiB): a search for one
site over everything took 3 s, one for a path nobody asked for 9 s -- and
every search held the lock the engine writes through, so for those seconds
the log was not read. "Show more" counted everything again and paged by
offset, so new requests repeated rows. And the stored time was HAProxy's
%t, the host's wall clock read as UTC: three hours in the future on a
gateway on Moscow time, so a link for "these minutes" opened others.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_request_log import StoreTestCase, guardd, line  # noqa: E402

WINDOWS = sys.platform == "win32"
SOURCE = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")


class TheTimeItHappened(StoreTestCase):
    def test_the_syslog_stamp_is_stored_not_the_wall_clock(self):
        # A gateway on Moscow time: %t says 13:00, which is 10:00 UTC.
        self.ingest(at="2026-08-12T13:00:00.000000+03:00", stamp="12/Aug/2026:13:00:00.000")
        stored = self.store.search()["requests"][0]["ts"]
        self.assertEqual(stored, 1786528800)  # 2026-08-12 10:00 UTC
        self.assertEqual(time.strftime("%H:%M", time.gmtime(stored)), "10:00")

    def test_without_a_syslog_stamp_the_wall_clock_is_the_fallback(self):
        record = guardd.parse_access_line(line())
        self.store.add(record, None)
        self.store.flush(self.now)
        self.assertEqual(self.store.search()["requests"][0]["ts"], record.ts)


@unittest.skipIf(WINDOWS, "time zones are switched with tzset")
class StoredTimesMoveOnce(unittest.TestCase):
    """A store written by the first version holds wall-clock times."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "requests.db"
        previous = os.environ.get("TZ")

        def restore():
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            time.tzset()

        self.addCleanup(restore)
        os.environ["TZ"] = "Europe/Moscow"
        time.tzset()
        if time.strftime("%z", time.localtime(1786539600)) != "+0300":
            self.skipTest("no time zone database here")
        old = sqlite3.connect(self.path)
        old.executescript("""
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version VALUES (1);
            CREATE TABLE requests (
                id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, request_id TEXT NOT NULL DEFAULT '',
                client TEXT NOT NULL DEFAULT '', status INTEGER NOT NULL DEFAULT 0,
                frontend TEXT NOT NULL DEFAULT '', backend TEXT NOT NULL DEFAULT '',
                server TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
                bytes_out INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0,
                bad_request INTEGER NOT NULL DEFAULT 0);
        """)
        # 13:00 on the gateway's clock, stored as if it were 13:00 UTC.
        old.execute("INSERT INTO requests (ts, request_id, status) VALUES (?, 'old', 200)",
                    (1786539600,))
        old.commit()
        old.close()

    def open(self):
        store = guardd.RequestLog(str(self.path), guardd.GuardConfig(request_log_enabled=True))
        self.addCleanup(store.close)
        return store

    def test_they_become_utc_and_the_new_columns_appear(self):
        store = self.open()
        row = store.search()["requests"][0]
        self.assertEqual(row["ts"], 1786528800)  # 10:00 UTC
        self.assertEqual(row["response_ms"], -1)
        self.assertEqual(row["user_agent"], "")
        # The indexes set aside for the move are back.
        indexes = {entry[1] for entry in store._conn.execute("PRAGMA index_list(requests)")}
        self.assertTrue({"ix_requests_ts", "ix_requests_client", "ix_requests_status"} <= indexes)

    def test_only_once(self):
        self.open().close()
        self.assertEqual(self.open().search()["requests"][0]["ts"], 1786528800)
        version = sqlite3.connect(self.path).execute("SELECT version FROM schema_version").fetchone()
        self.assertEqual(version[0], guardd.REQUEST_LOG_SCHEMA_VERSION)


class WhatARequestNeedsToBeUnderstood(StoreTestCase):
    def test_the_servers_answer_the_timers_the_ending_and_the_client(self):
        self.ingest(times="0/0/1/20/30000", extra="id=a host=shop.example.test ua=curl/8.5.0")
        row = self.store.search()["requests"][0]
        self.assertEqual(row["response_ms"], 20)
        self.assertEqual(row["duration_ms"], 30000)
        self.assertEqual(row["times"], "0/0/1/20/30000")
        self.assertEqual(row["term"], "----")
        self.assertEqual(row["user_agent"], "curl/8.5.0")
        self.assertEqual(row["refusal"], "")
        self.assertNotIn("agent_id", row)

    def test_a_request_nobody_answered_has_no_answer_time(self):
        self.ingest(status="503", backend="be_shop/<NOSRV>", times="0/0/-1/-1/3000")
        self.assertEqual(self.store.search()["requests"][0]["response_ms"], -1)

    def test_why_the_gateway_turned_it_away(self):
        self.ingest(status="451", backend="fe_https/<NOSRV>", times="0/-1/-1/-1/0", extra="id=geo")
        self.ingest(status="423", backend="fe_https/<NOSRV>", times="0/-1/-1/-1/0",
                    extra='id=ban ban_val=1 ban_code=30 ban_reason="RATE_LIMIT_SITE name=shop"')
        rows = {row["request_id"]: row for row in self.store.search()["requests"]}
        self.assertEqual(rows["geo"]["refusal"], "geo")
        self.assertEqual(rows["ban"]["refusal"], "banned")
        self.assertEqual(rows["ban"]["ban_reason"], "RATE_LIMIT_SITE name=shop")

    def test_a_user_agent_is_kept_once_and_goes_with_its_last_request(self):
        self.ingest(count=5, extra="id=a host=shop.example.test ua=curl/8.5.0")
        self.ingest(count=2, extra="id=b host=shop.example.test ua=Mozilla/5.0_zgrab/0.x")
        agents = self.store._conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        self.assertEqual(agents, 2)
        # Only the zgrab requests remain: curl is referenced by nothing.
        self.store._conn.execute("DELETE FROM requests WHERE request_id = 'a'")
        self.store._conn.commit()
        self.store._conn.execute("UPDATE agents SET last_ts = last_ts - 10 WHERE agent = 'curl/8.5.0'")
        self.store._conn.commit()
        self.store._last_maintenance = 0
        self.store.flush(self.now)
        names = [row[0] for row in self.store._conn.execute("SELECT agent FROM agents")]
        self.assertEqual(names, ["Mozilla/5.0_zgrab/0.x"])
        # And a pruned agent comes back with a new id, not a stale one.
        self.ingest(extra="id=c host=shop.example.test ua=curl/8.5.0")
        self.assertEqual(self.store.search(request_id="c")["requests"][0]["user_agent"], "curl/8.5.0")


class Paging(StoreTestCase):
    def test_more_continues_below_the_last_row_and_new_requests_do_not_repeat_one(self):
        for n in range(30):
            self.ingest(extra=f"id=r{n:02d}")
        first = self.store.search(limit=10)
        self.assertEqual(first["requests"][-1]["request_id"], "r20")
        self.assertTrue(first["next"])
        # Requests arriving between the two pages.
        for n in range(5):
            self.ingest(extra=f"id=new{n}")
        second = self.store.search(limit=10, before=first["next"], count=False)
        self.assertEqual(second["requests"][0]["request_id"], "r19")
        self.assertNotIn("total", second)
        last = self.store.search(limit=10, before=second["next"])
        self.assertEqual(last["requests"][-1]["request_id"], "r00")
        self.assertEqual(last["next"], 0)

    def test_one_address_and_one_request_id_page_too(self):
        for n in range(12):
            self.ingest(client="198.51.100.7", extra=f"id=c{n:02d}")
        self.ingest(client="203.0.113.9", extra="id=other")
        first = self.store.search(client="198.51.100.7", limit=5)
        self.assertEqual(first["total"], 12)
        second = self.store.search(client="198.51.100.7", limit=5, before=first["next"])
        self.assertEqual([row["request_id"] for row in second["requests"]],
                         ["c06", "c05", "c04", "c03", "c02"])


class InTime(StoreTestCase):
    def test_a_search_that_runs_out_of_time_says_how_far_back_it_got(self):
        for n in range(40):
            self.ingest(at=f"2026-08-12T10:{n:02d}:00+00:00", extra=f"id=r{n:02d}",
                        request="GET /common HTTP/1.1")
        with mock.patch.object(guardd, "REQUEST_SCAN_STEP", 10):
            stopped = self.store.search(path="/rare", seconds=0)
        self.assertTrue(stopped["timed_out"])
        self.assertFalse(stopped["complete"])
        self.assertEqual(stopped["requests"], [])
        # The first step was searched: ids 31..40, the oldest of them 10:30.
        self.assertEqual(time.strftime("%H:%M", time.gmtime(stopped["searched_to"])), "10:30")
        self.assertEqual(stopped["next"], 31)

    def test_continuing_after_a_stop_finds_everything_exactly_once(self):
        for n in range(40):
            self.ingest(extra=f"id=r{n:02d}", request=("GET /x HTTP/1.1" if n % 3 else "GET /y HTTP/1.1"))
        seen = []
        before = 0
        with mock.patch.object(guardd, "REQUEST_SCAN_STEP", 7):
            for _ in range(20):
                page = self.store.search(path="/y", limit=3, before=before, count=False, seconds=0)
                seen.extend(row["request_id"] for row in page["requests"])
                before = page["next"]
                if not before:
                    break
        self.assertEqual(seen, [f"r{n:02d}" for n in range(39, -1, -1) if n % 3 == 0])

    def test_counting_stops_at_the_cap(self):
        self.ingest(count=30)
        with mock.patch.object(guardd, "REQUEST_COUNT_CAP", 12):
            found = self.store.search(limit=5)
            by_address = self.store.search(client="203.0.113.9", limit=5)
        self.assertEqual((found["total"], found["total_exact"]), (12, False))
        self.assertEqual((by_address["total"], by_address["total_exact"]), (12, False))
        exact = self.store.search(limit=5)
        self.assertEqual((exact["total"], exact["total_exact"]), (30, True))

    def test_a_search_does_not_wait_for_the_writer(self):
        self.ingest(count=3)
        answers = []
        with self.store._lock:  # the engine in the middle of a write
            worker = threading.Thread(target=lambda: answers.append(self.store.search()))
            worker.start()
            worker.join(5)
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0]["total"], 3)

    def test_the_status_line_does_not_scan_the_table(self):
        self.ingest(count=7)
        self.assertEqual(self.store.status()["rows"], 7)
        block = SOURCE.split("    def status(self)")[1].split("\n\n\n")[0]
        self.assertNotIn("COUNT(", block)


class ThePanelsOwnRequests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.ingest(backend="be_admin/ui", extra="id=panel")
        self.ingest(extra="id=shop")

    def ids(self, **filters):
        return [row["request_id"] for row in self.store.search(**filters)["requests"]]

    def test_they_are_left_out_when_asked(self):
        self.assertEqual(self.ids(hide_admin=True), ["shop"])
        self.assertEqual(self.ids(), ["shop", "panel"])

    def test_asked_for_by_name_they_are_shown(self):
        self.assertEqual(self.ids(hide_admin=True, request_id="panel"), ["panel"])
        self.assertEqual(self.ids(hide_admin=True, backend="be_admin"), ["panel"])


class TheEndpoint(unittest.TestCase):
    def test_it_passes_the_new_choices_and_drops_offset(self):
        block = SOURCE.split('if path in ("/api/v1/guard/requests", "/api/v1/guard/requests/status"):')[1]
        block = block[:3000]
        for name in ('one("hide_admin")', 'one("before")', 'one("count")'):
            self.assertIn(name, block)
        self.assertNotIn('one("offset")', block)


if __name__ == "__main__":
    unittest.main()
