"""The latest requests in memory, bounded by a budget an operator chooses (07).

guardd keeps the latest requests for the live page and, with recording off,
for the request log's search. Measured on three gateways: 480-575 bytes a
request, the busiest hour about 14 MiB, and on real traffic the hour, not
the 100 000 requests, decides. The operator now chooses memory in MB and is
told roughly how many hours that holds at the current traffic; until then
nothing changes. The size of each request is estimated as it is added, so
the bound never walks the buffer.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

from test_live_activity import guardd, line, record  # noqa: E402

MIB = guardd.MIB
GUARDD_SOURCE = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
APP = ROOT / "docker/app/haproxy_admin"


def held(buffer):
    """The size of what a buffer holds, counted the slow way."""
    return sum(guardd.live_record_bytes(r) for r in buffer._records)


def records_over(now, count, seconds, ip="203.0.113.9"):
    step = seconds / count
    return [record(line(ip, 200, at=now - seconds + i * step)) for i in range(count)]


class TheEstimate(unittest.TestCase):
    def test_a_request_costs_its_own_strings_and_a_fixed_part(self):
        now = time.time()
        r = record(line("203.0.113.9", 200, at=now))
        own = sum(guardd.LIVE_STRING_BYTES + len(r[i])
                  for i in (guardd.L_IP, guardd.L_PATH, guardd.L_REASON, guardd.L_TIMES, guardd.L_REQUEST_ID)
                  if r[i])
        self.assertEqual(guardd.live_record_bytes(r), guardd.LIVE_RECORD_BASE_BYTES + own)
        longer = record(line("203.0.113.9", 200, at=now, request="GET /" + "a" * 300 + " HTTP/1.1"))
        self.assertEqual(guardd.live_record_bytes(longer) - guardd.live_record_bytes(r),
                         len(longer[guardd.L_PATH]) - len(r[guardd.L_PATH]))

    def test_it_lands_where_the_gateways_measured(self):
        # 480-575 bytes a request was measured; an ordinary request must land
        # there, or the hours shown would be wrong by the difference.
        r = record(line("203.0.113.9", 200, at=time.time(), request="GET /index.php/apps/files/ HTTP/1.1"))
        self.assertGreater(guardd.live_record_bytes(r), 400)
        self.assertLess(guardd.live_record_bytes(r), 650)


class TheBuffer(unittest.TestCase):
    def setUp(self):
        self.now = time.time()

    def test_the_count_follows_every_way_a_request_leaves(self):
        buffer = guardd.LiveBuffer(50, 600)
        buffer.extend(records_over(self.now - 1200, 30, 300))  # aged out below
        self.assertEqual(buffer.status()["bytes"], held(buffer))
        buffer.extend(records_over(self.now, 80, 300))  # over the count
        self.assertEqual(buffer.status()["records"], 50)
        self.assertEqual(buffer.status()["bytes"], held(buffer))
        buffer.refill(records_over(self.now - 900, 10, 60), self.now - 2000)
        self.assertEqual(buffer.status()["bytes"], held(buffer))
        buffer.set_budget(8 * 1024)
        self.assertEqual(buffer.status()["bytes"], held(buffer))
        buffer.set_budget(0)
        self.assertEqual(buffer.status()["bytes"], held(buffer))

    def test_without_a_budget_nothing_changes(self):
        buffer = guardd.LiveBuffer(1000, 3600)
        status = buffer.status()
        self.assertEqual((status["max_records"], status["max_seconds"], status["max_bytes"]), (1000, 3600, 0))
        buffer.extend([record(line("203.0.113.9", 200, at=self.now - 5000)),
                       record(line("203.0.113.9", 200, at=self.now))])
        self.assertEqual(buffer.status()["records"], 1)

    def test_a_budget_bounds_by_memory_and_drops_the_oldest(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.extend(records_over(self.now, 200, 600))
        size = buffer.status()["bytes"]
        newest = buffer.status()["newest"]
        dropped = buffer.set_budget(size // 2)
        status = buffer.status()
        self.assertGreater(dropped, 90)
        self.assertLessEqual(status["bytes"], size // 2)
        self.assertEqual(status["newest"], newest)
        self.assertEqual(status["records"], 200 - dropped)
        # Space was what ran out, so the live page says how far it reaches.
        self.assertEqual(buffer.evicted_for_size, dropped)
        buffer.extend(records_over(self.now + 60, 50, 50))
        self.assertLessEqual(buffer.status()["bytes"], size // 2)

    def test_a_budget_may_reach_back_a_day(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.set_budget(64 * MIB)
        buffer.extend([record(line("203.0.113.9", 200, at=self.now - 5 * 3600)),
                       record(line("203.0.113.9", 200, at=self.now))])
        self.assertEqual(buffer.status()["records"], 2)
        self.assertEqual(buffer.status()["max_seconds"], guardd.LIVE_BUDGET_MAX_SECONDS)
        buffer.extend([record(line("203.0.113.9", 200, at=self.now + 20 * 3600))])
        self.assertEqual(buffer.status()["records"], 2)  # the first is now older than a day

    def test_taking_the_budget_away_gives_back_the_profile(self):
        buffer = guardd.LiveBuffer(1000, 3600)
        buffer.set_budget(64 * MIB)
        buffer.extend([record(line("203.0.113.9", 200, at=self.now - 5 * 3600)),
                       record(line("203.0.113.9", 200, at=self.now))])
        self.assertEqual(buffer.set_budget(0), 1)
        status = buffer.status()
        self.assertEqual((status["max_records"], status["max_seconds"], status["max_bytes"]), (1000, 3600, 0))

    def test_rows_keep_their_ids_when_a_budget_cuts(self):
        # The request log pages through memory by id: a cut must not shift them.
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.extend([record(line("203.0.113.9", 200, at=self.now - 100 + i, request=f"GET /p{i} HTTP/1.1"))
                       for i in range(100)])
        query = guardd.RequestQuery.build()
        before = {row["id"]: row["path"] for row in buffer.search_requests(query, limit=500)["requests"]}
        buffer.set_budget(buffer.status()["bytes"] // 3)
        after = buffer.search_requests(query, limit=500)["requests"]
        self.assertTrue(0 < len(after) < 50)
        for row in after:
            self.assertEqual(before[row["id"]], row["path"])
        self.assertEqual(after[0]["path"], "/p99")

    def test_the_live_page_window_stays_an_hour(self):
        # A snapshot walks its whole window; a day of it on a small ARM board
        # would take seconds on every refresh.
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.set_budget(64 * MIB)
        buffer.started = self.now - 10 * 3600
        buffer.extend(records_over(self.now, 50, 5 * 3600))
        snapshot = buffer.snapshot({"window": 5 * 3600}, now=self.now)
        self.assertEqual(snapshot["window"], guardd.LIVE_WINDOW_MAX_SECONDS)
        self.assertEqual(snapshot["window"], 3600)


class TheOverview(unittest.TestCase):
    """With a budget a day of requests can be held; on the test gateway's ARM
    board the overview counted 200 000 of them one by one in 3.7 s."""

    def setUp(self):
        self.now = time.time()
        self.buffer = guardd.LiveBuffer(100_000, 3600)
        self.buffer.set_budget(64 * MIB)
        self.buffer.started = self.now - 2 * 86400
        kinds = [
            dict(status=200), dict(status=404), dict(status=502),
            dict(status=451, backend="fe_https/<NOSRV>", term="PR--"),
            dict(status=200, host="docs.example.test"),
        ]
        records = []
        for i in range(6000):
            extra = dict(kinds[i % len(kinds)])
            status = extra.pop("status")
            records.append(record(line(f"203.0.113.{i % 7}", status, at=self.now - 80000 + i * 13,
                                       request=f"GET /p{i % 11} HTTP/1.1", **extra)))
        self.buffer.extend(records)

    def reference(self, query):
        """The overview counted one request at a time, as it was."""
        records = list(self.buffer._records)
        oldest = records[0][guardd.L_TS]
        start = max(query.since, oldest) if query.since else oldest
        summary = guardd.RequestSummary(*guardd.summary_layout(start, query.until))
        for r in records:
            if not query.matches(r):
                continue
            summary.add((int(r[guardd.L_TS]) - summary.first) // summary.step, r[guardd.L_STATUS],
                        bool(r[guardd.L_REFUSAL]))
            summary.clients[r[guardd.L_IP]] += 1
            summary.paths[(r[guardd.L_HOST], r[guardd.L_PATH])] += 1
        return summary.read()

    def test_counted_in_bulk_it_reads_the_same(self):
        until = int(self.now)
        for query in (guardd.RequestQuery.build(until=until),
                      guardd.RequestQuery.build(until=until, since=until - 3600),
                      guardd.RequestQuery.build(until=until, status="4xx"),
                      guardd.RequestQuery.build(until=until, host="docs.example.test")):
            result = self.buffer.summarize_requests(query)
            self.assertTrue(result.pop("complete"))
            self.assertEqual(result.pop("reached_to"), 0)
            self.assertEqual(result.pop("source"), "memory")
            self.assertEqual(result, self.reference(query))

    def test_out_of_time_it_says_how_far_back_it_got(self):
        with mock.patch.object(guardd, "REQUEST_SUMMARY_SECONDS", -1):
            result = self.buffer.summarize_requests(guardd.RequestQuery.build(until=int(self.now)))
        self.assertFalse(result["complete"])
        self.assertGreater(result["reached_to"], self.buffer.status()["oldest"])
        # The newest part was counted, not the oldest.
        self.assertGreater(result["counted"], 0)
        self.assertLess(result["counted"], 6000)


class TheRate(unittest.TestCase):
    def setUp(self):
        self.now = time.time()

    def test_an_hour_of_traffic(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.started = self.now - 7200
        buffer.extend(records_over(self.now, 120, 3600))
        rate = buffer.status()["rate"]
        self.assertAlmostEqual(rate["records_per_hour"], 120, delta=5)
        self.assertAlmostEqual(rate["bytes_per_hour"], buffer.status()["bytes"], delta=buffer.status()["bytes"] * 0.05)

    def test_a_young_buffer_is_not_taken_for_a_quiet_hour(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.started = self.now - 600
        buffer.extend(records_over(self.now, 20, 600))
        self.assertAlmostEqual(buffer.status()["rate"]["records_per_hour"], 120, delta=8)

    def test_arrivals_count_even_when_the_budget_drops_them(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.started = self.now - 7200
        buffer.set_budget(16 * 1024)
        buffer.extend(records_over(self.now, 120, 3600))
        self.assertLess(buffer.status()["records"], 60)
        self.assertAlmostEqual(buffer.status()["rate"]["records_per_hour"], 120, delta=5)

    def test_the_minutes_kept_stay_few(self):
        buffer = guardd.LiveBuffer(100_000, 3600)
        buffer.set_budget(64 * MIB)
        buffer.extend(records_over(self.now, 600, 10 * 3600))
        self.assertLessEqual(len(buffer._arrivals), guardd.LIVE_RATE_SECONDS // 60 + 10)

    def test_empty(self):
        rate = guardd.LiveBuffer(10, 3600).status()["rate"]
        self.assertEqual(rate, {"records_per_hour": 0, "bytes_per_hour": 0, "measured_seconds": 0})


class TheCeiling(unittest.TestCase):
    def ceiling(self, rss, limit, available, held_bytes=0, host=True):
        with mock.patch.object(guardd, "process_rss_bytes", return_value=rss), \
                mock.patch.object(guardd, "service_memory_limit", return_value=limit), \
                mock.patch.object(guardd, "host_memory_available", return_value=available):
            return guardd.live_budget_ceiling(held_bytes, host=host)

    def test_a_roomy_gateway_gets_the_cap(self):
        self.assertEqual(self.ceiling(40 * MIB, 320 * MIB, 1200 * MIB), (128, "cap"))

    def test_the_service_limit_keeps_a_reserve(self):
        mib, reason = self.ceiling(40 * MIB, 256 * MIB, 4096 * MIB)
        self.assertEqual(reason, "service")
        self.assertEqual(mib % guardd.LIVE_BUDGET_STEP_MIB, 0)
        self.assertLessEqual(mib * MIB * guardd.LIVE_BUDGET_SLACK + 40 * MIB + guardd.LIVE_BUDGET_SERVICE_RESERVE,
                             256 * MIB)

    def test_what_the_buffer_holds_is_not_counted_against_it(self):
        # 100 MiB resident of which 60 are the buffer: the rest of the daemon
        # is about 30, and a budget may replace those 60.
        mib, _ = self.ceiling(100 * MIB, 256 * MIB, 4096 * MIB, held_bytes=60 * MIB)
        alone, _ = self.ceiling(31 * MIB, 256 * MIB, 4096 * MIB)
        self.assertEqual(mib, alone)

    def test_a_tight_host_gets_a_quarter_of_what_is_free(self):
        mib, reason = self.ceiling(40 * MIB, 320 * MIB, 200 * MIB)
        self.assertEqual(reason, "host")
        self.assertLessEqual(mib, 50 / guardd.LIVE_BUDGET_SLACK)

    def test_at_start_the_host_is_not_asked(self):
        self.assertEqual(self.ceiling(20 * MIB, 320 * MIB, 50 * MIB, host=False), (128, "cap"))

    def test_nothing_readable_means_the_cap(self):
        self.assertEqual(self.ceiling(0, 0, 0), (128, "cap"))


class Engines(unittest.TestCase):
    """An engine on a fresh database, on a roomy gateway."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = guardd.GuardConfig(log_file=str(self.root / "haproxy.log"), whitelist_files=())
        self.database = guardd.SecurityDatabase(str(self.root / "security.db"))
        self.addCleanup(self.database.close)
        patches = [
            mock.patch.object(guardd, "process_rss_bytes", return_value=40 * MIB),
            mock.patch.object(guardd, "service_memory_limit", return_value=320 * MIB),
            mock.patch.object(guardd, "host_memory_available", return_value=1200 * MIB),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def engine(self):
        return guardd.GuardEngine(self.config, self.database)


class TheSetting(Engines):
    def test_nothing_chosen_keeps_the_profile(self):
        memory = self.engine().live_memory()
        self.assertEqual((memory["budget_mib"], memory["applied_mib"], memory["revision"]), (0, 0, 0))
        self.assertEqual(memory["default"], {"records": 100_000, "seconds": 3600})
        self.assertEqual(memory["limits"]["max_mib"], 128)

    def test_a_choice_survives_a_restart(self):
        engine = self.engine()
        result = engine.set_live_memory(48, 0)
        self.assertEqual((result["budget_mib"], result["applied_mib"], result["revision"]), (48, 48, 1))
        again = self.engine()
        self.assertEqual(again.live.max_bytes, 48 * MIB)
        self.assertEqual(again.live_memory()["revision"], 1)

    def test_a_stale_page_is_refused(self):
        engine = self.engine()
        engine.set_live_memory(48, 0)
        with self.assertRaises(guardd.LiveBudgetConflict):
            engine.set_live_memory(64, 0)
        self.assertEqual(engine.live.max_bytes, 48 * MIB)

    def test_out_of_range_is_refused(self):
        engine = self.engine()
        for wrong in (8, 129, -1, True, 1.5, None, "lots"):
            with self.assertRaises(ValueError, msg=repr(wrong)):
                engine.set_live_memory(wrong, 0)
        self.assertEqual(engine.live_memory()["revision"], 0)

    def test_more_than_the_gateway_can_give_is_refused_but_less_is_not(self):
        engine = self.engine()
        engine.set_live_memory(96, 0)
        with mock.patch.object(guardd, "host_memory_available", return_value=160 * MIB):
            with self.assertRaises(ValueError):
                engine.set_live_memory(128, 1)
            self.assertEqual(engine.set_live_memory(64, 1)["applied_mib"], 64)

    def test_zero_goes_back_to_the_profile(self):
        engine = self.engine()
        engine.set_live_memory(48, 0)
        result = engine.set_live_memory(0, 1)
        self.assertEqual((result["budget_mib"], result["applied_mib"]), (0, 0))
        self.assertEqual(engine.live.max_records, 100_000)
        self.assertEqual(engine.live.max_seconds, 3600)

    def test_a_lowered_service_limit_is_honoured_at_start(self):
        self.engine().set_live_memory(128, 0)
        with mock.patch.object(guardd, "service_memory_limit", return_value=200 * MIB):
            engine = self.engine()
        self.assertLess(engine.live.max_bytes, 128 * MIB)
        self.assertGreaterEqual(engine.live.max_bytes, guardd.LIVE_BUDGET_MIN_MIB * MIB)
        # The choice itself is kept for when the limit is raised again.
        self.assertEqual(engine.live_memory()["budget_mib"], 128)

    def test_health_says_what_is_held(self):
        engine = self.engine()
        engine.set_live_memory(32, 0)
        live = engine.health()["live_buffer"]
        self.assertEqual((live["budget_mib"], live["max_bytes"]), (32, 32 * MIB))


class Handler(guardd.GuardHandler):
    """The real handler, without a socket: what it would send is kept."""

    def __init__(self, engine, method, path, body=None, token=""):  # pylint: disable=super-init-not-called
        self.server = mock.Mock(engine=engine, database=engine.database, requests=None)
        self.path = path
        raw = json.dumps(body).encode() if body is not None else b""
        self.headers = {"Content-Length": str(len(raw)), "X-Guardd-Token": token}
        self.rfile = io.BytesIO(raw)
        self.sent = None
        getattr(self, f"do_{method}")()

    def _send_json(self, code, payload):
        self.sent = (code, payload)


class TheApi(Engines):
    def setUp(self):
        super().setUp()
        patch = mock.patch.object(guardd, "CONTROL_TOKEN", "token-for-tests")
        patch.start()
        self.addCleanup(patch.stop)

    def call(self, engine, body=None, token="token-for-tests"):
        method = "GET" if body is None else "POST"
        return Handler(engine, method, "/api/v1/guard/live/memory", body, token).sent

    def test_reading_it(self):
        code, payload = self.call(self.engine())
        self.assertEqual(code, 200)
        for key in ("budget_mib", "applied_mib", "revision", "default", "limits", "buffer", "process"):
            self.assertIn(key, payload)
        self.assertIn("rate", payload["buffer"])

    def test_changing_it_needs_the_token(self):
        code, _ = self.call(self.engine(), {"budget_mib": 32, "revision": 0}, token="wrong")
        self.assertEqual(code, 403)

    def test_a_change_and_a_conflict(self):
        engine = self.engine()
        code, payload = self.call(engine, {"budget_mib": 32, "revision": 0})
        self.assertEqual((code, payload["budget_mib"], payload["revision"]), (200, 32, 1))
        code, payload = self.call(engine, {"budget_mib": 64, "revision": 0})
        self.assertEqual(code, 409)
        self.assertTrue(payload["conflict"])
        # What is in force comes back with the refusal.
        self.assertEqual((payload["budget_mib"], payload["revision"]), (32, 1))

    def test_a_wrong_value_is_a_400(self):
        code, payload = self.call(self.engine(), {"budget_mib": 4096, "revision": 0})
        self.assertEqual(code, 400)
        self.assertIn("budget_mib", payload["error"])

    def test_off_is_a_404(self):
        config = guardd.GuardConfig(log_file=str(self.root / "haproxy.log"), whitelist_files=(),
                                    live_buffer_records=0)
        engine = guardd.GuardEngine(config, self.database)
        self.assertEqual(self.call(engine)[0], 404)
        self.assertEqual(self.call(engine, {"budget_mib": 32, "revision": 0})[0], 404)


class ThePanel(unittest.TestCase):
    def test_changing_it_is_superadmin_only_and_audited(self):
        routes = (APP / "routes_security.py").read_text(encoding="utf-8")
        block = routes.split('@bp.post("/api/security/requests/memory")')[1].split("\n@bp.")[0]
        self.assertIn('getattr(g, "is_superadmin", False)', block)
        self.assertIn("RESULT_DENIED", block)
        self.assertIn('"request_log.memory"', block)

    def test_the_client_carries_the_token_and_passes_refusals_on(self):
        client = (APP / "guardd_client.py").read_text(encoding="utf-8")
        block = client.split("def guardd_set_live_memory")[1]
        self.assertIn("with_token=True", block)
        self.assertIn("check_status=False", block)

    def test_the_page_previews_without_asking_and_applies_on_a_button(self):
        script = (APP / "static/js/request_log.js").read_text(encoding="utf-8")
        wiring = script.split("function wireMemory()")[1].split("\n  }\n")[0]
        slider = wiring.split('slider.addEventListener("input"')[1].split("});")[0]
        self.assertNotIn("setMemory", slider)
        self.assertNotIn("fetch", slider)
        self.assertIn('byId("rq-mem-apply").addEventListener("click"', wiring)
        self.assertIn("revision", script.split("async function setMemory")[1])
        self.assertIn("response.status === 409", script)

    def test_the_daemon_keeps_the_choice_where_ansible_does_not_reach(self):
        self.assertIn('LIVE_BUDGET_STATE_KEY = "live_memory_budget"', GUARDD_SOURCE)
        block = GUARDD_SOURCE.split("    def set_live_memory")[1].split("    def _run")[0]
        self.assertIn("self.database.set_state(LIVE_BUDGET_STATE_KEY", block)


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class ThePanelService(unittest.TestCase):
    def setUp(self):
        from haproxy_admin import services_security as security  # pylint: disable=import-outside-toplevel
        self.security = security

    def test_only_two_whole_numbers_are_passed_on(self):
        with mock.patch.object(self.security, "guardd_set_live_memory") as daemon:
            for wrong in (None, [], {"budget_mib": "32", "revision": 0}, {"budget_mib": True, "revision": 0},
                          {"budget_mib": 32}):
                status, _ = self.security.set_live_memory(wrong)
                self.assertEqual(status, 400)
            daemon.assert_not_called()

    def test_the_daemons_answers_keep_their_meaning(self):
        answers = {
            200: {"ok": True, "budget_mib": 32},
            409: {"ok": False, "conflict": True, "budget_mib": 48},
            400: {"ok": False, "error": "at most 64 MiB can be given now (host)"},
        }
        for status, answer in answers.items():
            with mock.patch.object(self.security, "guardd_set_live_memory", return_value=answer):
                self.assertEqual(self.security.set_live_memory({"budget_mib": 32, "revision": 0}),
                                 (status, answer))


if __name__ == "__main__":
    unittest.main()
