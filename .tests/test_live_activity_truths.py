"""The live page tells the truth about time, about whose traffic it is, and
about what happened before the daemon started.

Measured on the test gateway: a quiet Nextcloud read 12 254 ms -- the mean
of whole requests, long polls and downloads included -- while its server
answered in about 200 ms; the page watching the traffic was all of it (88
of 88 requests in a minute were the panel polling itself); and after every
update the hour window held forty minutes, because the buffer lives in
memory and the restart emptied it.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

from test_live_activity import guardd, line, record  # noqa: E402

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_live as live  # noqa: E402


class TheServersTime(unittest.TestCase):
    def test_the_record_keeps_how_soon_the_server_answered(self):
        now = time.time()
        r = record(line("203.0.113.9", 200, at=now, times="0/0/1/20/30000"))
        self.assertEqual(r[guardd.L_RESPONSE], 20)
        self.assertEqual(r[guardd.L_DURATION], 30000)
        unanswered = record(line("203.0.113.9", 504, at=now, times="0/0/1/-1/30000"))
        self.assertEqual(unanswered[guardd.L_RESPONSE], -1)

    def aggregate(self, records):
        return guardd.live_aggregate(records, now=time.time() + 1, window=600, filters={})

    def test_sites_show_a_median_and_a_p95_of_the_servers_answers(self):
        now = time.time()
        records = [record(line("203.0.113.9", 200, at=now, times=f"0/0/1/{ms}/{ms + 29000}"))
                   for ms in range(10, 210, 10)]  # 10..200 ms, every request a long poll
        records.append(record(line("203.0.113.9", 502, at=now, times="0/0/1/-1/5")))
        site = self.aggregate(records)["sites"][0]
        self.assertEqual(site["p50_ms"], 110)
        self.assertEqual(site["p95_ms"], 190)
        # Not the whole requests' half a minute.
        self.assertLess(site["avg_ms"], 1000)

    def test_a_site_nobody_answered_has_no_time_not_zero(self):
        now = time.time()
        records = [record(line("203.0.113.9", 451, at=now, backend="fe_https/<NOSRV>",
                               times="0/-1/-1/-1/0"))]
        site = self.aggregate(records)["sites"][0]
        self.assertIsNone(site["p50_ms"])
        self.assertIsNone(site["p95_ms"])
        self.assertIsNone(self.aggregate(records)["addresses"][0]["avg_ms"])

    def test_each_request_says_how_soon_the_server_answered(self):
        now = time.time()
        events = self.aggregate([
            record(line("203.0.113.9", 200, at=now, times="0/0/1/20/30000")),
            record(line("203.0.113.9", 504, at=now, times="0/0/1/-1/30000")),
        ])["events"]
        self.assertEqual(sorted(event["response_ms"] is None for event in events), [False, True])


class ThePanelsOwnRequests(unittest.TestCase):
    def test_they_are_left_out_when_asked(self):
        now = time.time()
        records = [
            record(line("198.51.100.4", 200, at=now, backend="be_admin/ui", host="ha.example.test")),
            record(line("203.0.113.9", 200, at=now)),
            # A refusal on the admin host is not the panel's own: it stays.
            record(line("192.0.2.66", 451, at=now, backend="fe_https/<NOSRV>", host="ha.example.test",
                        times="0/-1/-1/-1/0")),
        ]
        hidden = guardd.live_aggregate(records, now=now + 1, window=60,
                                       filters=guardd.live_filters({"hide_admin": "1"}))
        self.assertEqual(hidden["totals"]["requests"], 2)
        self.assertNotIn("198.51.100.4", [row["ip"] for row in hidden["addresses"]])
        shown = guardd.live_aggregate(records, now=now + 1, window=60, filters=guardd.live_filters({}))
        self.assertEqual(shown["totals"]["requests"], 3)

    @unittest.skipIf(WINDOWS, "the panel package needs POSIX modules")
    def test_the_panel_passes_the_choice_on(self):
        self.assertTrue(live.normalize_request({"hide_admin": "1"})["hide_admin"])
        self.assertNotIn("hide_admin", live.normalize_request({}))


class AfterARestart(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.log = root / "haproxy.log"
        self.config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=())
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.now = time.time()

    def write(self, *ages):
        with self.log.open("a", encoding="utf-8") as handle:
            for age in ages:
                handle.write(line("203.0.113.9", 200, at=self.now - age) + "\n")

    def engine(self, cursor=None):
        engine = guardd.GuardEngine(self.config, self.database)
        if cursor is not None:
            engine.cursor.inode, engine.cursor.offset = cursor
        return engine

    def test_the_last_hour_is_read_back_from_the_log(self):
        self.write(7200, 1800, 600, 60)  # one from two hours ago
        engine = self.engine()  # first ever start: the cursor will begin at the end
        self.assertEqual(engine.refill_live(self.now), 3)
        snapshot = engine.live.snapshot({"window": 3600}, now=self.now)
        self.assertEqual(snapshot["totals"]["requests"], 3)
        # It reached back past the hour, so the hour is whole.
        self.assertFalse(snapshot["truncated"])

    def test_only_what_comes_before_where_reading_resumes(self):
        self.write(1800, 600)
        middle = self.log.stat().st_size
        self.write(30, 10)  # after the saved position: the cursor reads these itself
        engine = self.engine(cursor=(self.log.stat().st_ino, middle))
        self.assertEqual(engine.refill_live(self.now), 2)
        engine.ingest_log(int(self.now))
        self.assertEqual(engine.live.snapshot({"window": 3600}, now=self.now)["totals"]["requests"], 4)

    def test_a_rotated_log_is_not_followed_back(self):
        self.write(600)
        engine = self.engine(cursor=(self.log.stat().st_ino + 1, 10))
        self.assertEqual(engine.refill_live(self.now), 0)

    def test_nothing_read_back_is_scored_again(self):
        self.write(600, 300)
        engine = self.engine()
        engine.refill_live(self.now)
        self.assertIsNone(engine.memory.get("203.0.113.9"))
        self.assertEqual(engine.digests.complete(0, int(self.now) + 600), [])

    def test_a_partial_hour_says_how_far_it_reaches(self):
        self.write(600, 300)  # the log itself begins ten minutes ago
        engine = self.engine()
        engine.refill_live(self.now)
        snapshot = engine.live.snapshot({"window": 3600}, now=self.now)
        # The file starts here: nothing older can be vouched for -- but it
        # was read from its start, so the hour is as complete as the log.
        self.assertFalse(snapshot["truncated"])

    def test_read_back_is_bounded(self):
        self.assertLessEqual(guardd.LIVE_REFILL_BYTES, 32 * 1024 * 1024)
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        run = source.split("    def _run(self) -> None:")[1].split("while not self._stop.is_set()")[0]
        self.assertIn("self.refill_live(time.time())", run)


if __name__ == "__main__":
    unittest.main()
