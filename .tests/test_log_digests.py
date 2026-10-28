"""Response time percentiles and refusals, from the access log to the page.

HAProxy's counters average the response time and count refusals by status;
the log says how long each request took and why the gateway turned one
away. guardd reads every line anyway, so it folds each into a digest of its
minute -- a histogram per backend and refusals by reason -- and keeps no
line. metricsd asks for the complete minutes, stores them beside its own
rows, rolls them up and retires them with them, and reads the percentiles
off the summed histograms.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/haproxy-admin/files"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, FILES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load("easy_ha_proxy_guardd_digests", "easy-ha-proxy-guardd.py")
metricsd = load("easy_ha_proxy_metricsd_digests", "easy-ha-proxy-metricsd.py")

# 07:00:30 in the syslog stamp, which carries its zone; HAProxy's own %t is
# local time without one, so it is never what a minute is keyed by.
STAMP = "2026-08-11T07:00:30.000000+00:00"
MINUTE = 1786431600  # 2026-08-11T07:00:00Z


def line(backend="be_shop/srv1", status=200, total_ms=120, stamp=STAMP, extra=""):
    return (
        f"{stamp} host haproxy[1]: 203.0.113.9:1234 [11/Aug/2026:09:00:30.000] "
        f"fe_https~ {backend} 0/0/0/1/{total_ms} {status} 100 ---- {extra}1/1/0/0/0 0/0 "
        "GET /index.html HTTP/1.1"
    )


class TheDigest(unittest.TestCase):
    def setUp(self):
        self.digests = guardd.MinuteDigests()

    def add(self, text, now=MINUTE + 61):
        request = guardd.parse_access_line(text)
        self.digests.add(request, guardd.line_epoch(text), now)

    def test_bounds_are_the_same_on_both_sides(self):
        self.assertEqual(tuple(guardd.DIGEST_BOUNDS_MS), tuple(metricsd.DIGEST_BOUNDS_MS))

    def test_answered_requests_go_into_their_backends_histogram(self):
        self.add(line(total_ms=3))
        self.add(line(total_ms=120))
        self.add(line(total_ms=120))
        self.add(line(backend="be_blog/srv2", total_ms=40000))
        minutes = self.digests.complete(0, MINUTE + 60 + guardd.DIGEST_CLOSE_SECONDS)
        self.assertEqual([minute["ts"] for minute in minutes], [MINUTE])
        shop = minutes[0]["backends"]["be_shop"]
        self.assertEqual(sum(shop), 3)
        self.assertEqual(shop[0], 1)  # <= 5 ms
        self.assertEqual(shop[guardd._digest_bucket(120)], 2)
        # Past the last edge: the bucket above it.
        self.assertEqual(minutes[0]["backends"]["be_blog"][-1], 1)

    def test_refusals_are_counted_by_reason_and_never_timed(self):
        self.add(line(backend="fe_https/<NOSRV>", status=451))
        self.add(line(backend="fe_https/<NOSRV>", status=403))
        self.add(line(backend="be_shop/srv1", status=429))
        self.add(line(backend="be_shop/srv1", status=403, extra='ban_val=1 ban_code=10 ban_reason="x" '))
        minute = self.digests.complete(0, MINUTE + 120)[0]
        self.assertEqual(minute["refused"], {"geo": 1, "banned": 1, "rate": 1, "other": 1})
        self.assertEqual(minute["backends"], {})

    def test_a_minute_is_handed_out_only_when_complete(self):
        self.add(line(), now=MINUTE + 40)
        self.assertEqual(self.digests.complete(0, MINUTE + 60 + guardd.DIGEST_CLOSE_SECONDS - 1), [])
        self.assertEqual(len(self.digests.complete(0, MINUTE + 60 + guardd.DIGEST_CLOSE_SECONDS)), 1)
        # Asked again from where the collector got to: nothing new.
        self.assertEqual(self.digests.complete(MINUTE, MINUTE + 200), [])

    def test_a_line_for_a_minute_already_handed_out_is_dropped(self):
        self.add(line(), now=MINUTE + 60 + guardd.DIGEST_CLOSE_SECONDS)
        self.assertEqual(self.digests.late, 1)
        self.assertEqual(self.digests.complete(0, MINUTE + 300), [])

    def test_old_minutes_are_forgotten(self):
        self.add(line(), now=MINUTE + 61)
        later = MINUTE + guardd.DIGEST_KEEP_SECONDS + 3600
        self.assertEqual(self.digests.complete(0, later), [])

    def test_the_engine_feeds_it_from_the_one_read_of_the_log(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        log = root / "haproxy.log"
        log.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(log), whitelist_files=())
        database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(database.close)
        engine = guardd.GuardEngine(config, database)
        engine.cursor.read(4096)
        with log.open("a", encoding="utf-8") as handle:
            handle.write(line(total_ms=80) + "\n")
        engine.ingest_log(MINUTE + 61)
        minutes = engine.digests.complete(0, MINUTE + 120)
        self.assertEqual(sum(minutes[0]["backends"]["be_shop"]), 1)

    def test_the_daemon_answers_for_it(self):
        source = (FILES / "easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        handler = source.split('if path == "/api/v1/guard/digest":')[1].split("return\n")[0]
        self.assertIn("engine.digests.complete(since, now)", handler)
        self.assertIn('"bounds_ms": list(DIGEST_BOUNDS_MS)', handler)


class Percentiles(unittest.TestCase):
    def test_read_off_the_histogram(self):
        counts = [0] * len(metricsd.HISTOGRAM_COLUMNS)
        # 100 requests between 100 and 150 ms.
        counts[metricsd.DIGEST_BOUNDS_MS.index(150)] = 100
        self.assertEqual(metricsd.histogram_percentile(counts, 0.5), 125)
        self.assertEqual(metricsd.histogram_percentile(counts, 0.95), 148)
        # Nothing counted: no percentile, not 0 ms.
        self.assertIsNone(metricsd.histogram_percentile([0] * len(counts), 0.5))

    def test_a_slow_tail_shows_where_the_average_would_not(self):
        counts = [0] * len(metricsd.HISTOGRAM_COLUMNS)
        counts[metricsd.DIGEST_BOUNDS_MS.index(50)] = 98
        counts[metricsd.DIGEST_BOUNDS_MS.index(5000)] = 2
        self.assertLessEqual(metricsd.histogram_percentile(counts, 0.5), 50)
        self.assertGreater(metricsd.histogram_percentile(counts, 0.99), 3000)

    def test_the_top_bucket_reads_as_at_least_its_lower_edge(self):
        counts = [0] * len(metricsd.HISTOGRAM_COLUMNS)
        counts[-1] = 10
        self.assertEqual(metricsd.histogram_percentile(counts, 0.5), metricsd.DIGEST_BOUNDS_MS[-1])


class Collected(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = metricsd.MetricsDatabase(str(Path(directory.name) / "metrics.db"))
        self.addCleanup(self.database.close)
        self.collector = metricsd.Collector(
            metricsd.load_config("/nonexistent/metricsd.json"), self.database
        )

    def answer(self, *minutes, bounds=None):
        return {
            "ok": True,
            "bounds_ms": list(bounds if bounds is not None else metricsd.DIGEST_BOUNDS_MS),
            "minutes": list(minutes),
        }

    def minute(self, ts, shop=None, refused=None):
        counts = [0] * len(metricsd.HISTOGRAM_COLUMNS)
        counts[metricsd.DIGEST_BOUNDS_MS.index(150)] = shop if shop is not None else 10
        return {
            "ts": ts,
            "backends": {"be_shop": counts, "be_admin": counts},
            "refused": refused or {"geo": 3, "banned": 1, "rate": 0, "other": 2},
        }

    def pull(self, payload, now=MINUTE + 600):
        with mock.patch.object(metricsd, "unix_get_json", return_value=payload) as asked:
            written = self.collector.pull_digests(now)
        return written, asked

    def test_minutes_are_stored_and_the_cursor_moves(self):
        written, asked = self.pull(self.answer(self.minute(MINUTE), self.minute(MINUTE + 60)))
        self.assertIn("since=0", asked.call_args.args[1])
        # be_admin is excluded like everywhere else on the page.
        self.assertEqual(written, 4)
        self.assertEqual(self.database.get_state(metricsd.DIGEST_CURSOR_KEY, ""), str(MINUTE + 60))
        _written, asked = self.pull(self.answer())
        self.assertIn(f"since={MINUTE + 60}", asked.call_args.args[1])

    def test_the_same_minute_twice_is_not_counted_twice(self):
        self.pull(self.answer(self.minute(MINUTE)))
        self.database.set_state(metricsd.DIGEST_CURSOR_KEY, "0")
        self.pull(self.answer(self.minute(MINUTE)))
        payload = self.database.series(chart="refusals", site="", since=MINUTE - 60, until=MINUTE + 3600)
        self.assertEqual(payload["series"]["refused_geo"], [3])
        payload = self.database.series(chart="percentiles", site="be_shop", since=MINUTE - 60, until=MINUTE + 3600)
        self.assertEqual(payload["series"]["p50"], [125])

    def test_a_minute_already_stored_is_never_written_again(self):
        self.pull(self.answer(self.minute(MINUTE), self.minute(MINUTE + 60)))
        changed = self.minute(MINUTE, refused={"geo": 99, "banned": 0, "rate": 0, "other": 0})
        written, _asked = self.pull(self.answer(changed))
        self.assertEqual(written, 0)
        payload = self.database.series(chart="refusals", site="", since=MINUTE - 60, until=MINUTE + 3600)
        self.assertEqual(payload["series"]["refused_geo"][0], 3)

    def test_all_sites_sum_the_backends(self):
        counts = [0] * len(metricsd.HISTOGRAM_COLUMNS)
        counts[metricsd.DIGEST_BOUNDS_MS.index(5000)] = 10
        minute = self.minute(MINUTE)
        minute["backends"]["be_blog"] = counts
        self.pull(self.answer(minute))
        whole = self.database.series(chart="percentiles", site="", since=MINUTE - 60, until=MINUTE + 3600)
        shop = self.database.series(chart="percentiles", site="be_shop", since=MINUTE - 60, until=MINUTE + 3600)
        self.assertGreater(whole["series"]["p95"][0], shop["series"]["p95"][0])

    def test_another_histogram_is_not_mixed_in(self):
        written, _asked = self.pull(self.answer(self.minute(MINUTE), bounds=[1, 2, 3]))
        self.assertEqual(written, 0)

    def test_switched_off_nothing_is_asked(self):
        self.collector.set_monitors({"percentiles": False, "refusals": False})
        written, asked = self.pull(self.answer(self.minute(MINUTE)))
        self.assertEqual(written, 0)
        asked.assert_not_called()

    def test_only_what_is_switched_on_is_stored(self):
        self.collector.set_monitors({"refusals": False})
        written, _asked = self.pull(self.answer(self.minute(MINUTE)))
        self.assertEqual(written, 1)

    def test_a_silent_daemon_is_remembered_for_the_page(self):
        with mock.patch.object(metricsd, "unix_get_json", side_effect=OSError("no socket")):
            with self.assertRaises(OSError):
                self.collector.pull_digests(MINUTE)
        self.assertIs(self.collector.digests_available, False)
        self.pull(self.answer())
        self.assertIs(self.collector.digests_available, True)

    def test_paused_writes_ask_for_nothing(self):
        self.collector.storage.writes_paused = True
        written, asked = self.pull(self.answer(self.minute(MINUTE)))
        self.assertEqual(written, 0)
        asked.assert_not_called()

    def test_hours_are_the_sum_of_their_minutes_and_retire_with_them(self):
        self.pull(self.answer(self.minute(MINUTE, shop=10), self.minute(MINUTE + 60, shop=30)))
        hour = MINUTE - MINUTE % metricsd.HOUR_SECONDS
        self.assertGreater(self.database.rollup_latency_hours(hour + metricsd.HOUR_SECONDS), 0)
        rows = self.database._conn.execute("SELECT h0, h6 FROM latency_1h").fetchall()
        self.assertEqual([tuple(row) for row in rows], [(0, 40), (0, 40)][:len(rows)])
        self.database.apply_retention(
            minute_cutoff=MINUTE + 3600, minute_server_cutoff=MINUTE + 3600,
            hour_cutoff=MINUTE + 7200,
        )
        for table in ("latency_1m", "latency_1h"):
            self.assertEqual(self.database._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_the_rollup_waits_for_late_minutes(self):
        source = (FILES / "easy-ha-proxy-metricsd.py").read_text(encoding="utf-8")
        maintenance = source.split("def run_maintenance(")[1].split("\n    def ")[0]
        self.assertIn("lagged = now - LATENCY_ROLLUP_LAG_SECONDS", maintenance)
        self.assertGreaterEqual(metricsd.LATENCY_ROLLUP_LAG_SECONDS, 60 + 30 + metricsd.DIGEST_PULL_SECONDS)


if __name__ == "__main__":
    unittest.main()
