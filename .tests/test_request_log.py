"""Regression checks for the bounded request log behind the Log Explorer.

The point of this store is what it refuses to keep: no query strings, a hard
size cap that outranks the retention window, and a free-space reserve that
outranks both.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_request_log", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()

PREFIX = "2026-08-12T10:00:00+00:00 gw haproxy[1234]: "


def line(**overrides):
    fields = {
        "client": "203.0.113.9",
        "stamp": "12/Aug/2026:10:00:00.123",
        "backend": "be_shop/srv1",
        "status": "200",
        "bytes": "4096",
        "times": "0/0/1/12/13",
        "extra": "id=abc-123 host=shop.example.test",
        "request": "GET /login?token=SECRET HTTP/1.1",
    }
    fields.update(overrides)
    return (
        f"{PREFIX}{fields['client']}:51514 [{fields['stamp']}] fe_https~ "
        f"{fields['backend']} {fields['times']} {fields['status']} "
        f"{fields['bytes']} ---- 5/5/0/0/0 0/0 {{}} {{}} "
        f"{fields['extra']} {fields['request']}"
    )


class ParsingTests(unittest.TestCase):
    def test_the_new_fields_are_extracted(self):
        parsed = guardd.parse_access_line(line())
        self.assertEqual(parsed.request_id, "abc-123")
        self.assertEqual(parsed.host, "shop.example.test")
        self.assertEqual(parsed.bytes_out, 4096)
        self.assertEqual(parsed.duration_ms, 13)
        # Assert the decoding rather than a hand-computed constant: the
        # stamp has to come back as the same UTC wall clock it went in as.
        import time

        self.assertEqual(
            time.strftime("%d/%b/%Y:%H:%M:%S", time.gmtime(parsed.ts)),
            "12/Aug/2026:10:00:00",
        )

    def test_the_query_string_never_survives_parsing(self):
        # This is why there is no list of sensitive parameters to maintain.
        parsed = guardd.parse_access_line(line())
        self.assertEqual(parsed.path, "/login")
        self.assertNotIn("SECRET", parsed.path)

    def test_a_line_without_the_new_fields_still_parses(self):
        parsed = guardd.parse_access_line(line(extra="-"))
        self.assertEqual(parsed.request_id, "")
        self.assertEqual(parsed.path, "/login")

    def test_an_unparsable_timestamp_does_not_lose_the_record(self):
        parsed = guardd.parse_access_line(line(stamp="not a date"))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ts, 0)

    def test_an_unknown_total_time_reads_as_zero_not_negative(self):
        parsed = guardd.parse_access_line(line(times="0/-1/-1/-1/-1"))
        self.assertEqual(parsed.duration_ms, 0)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = guardd.GuardConfig(
            request_log_enabled=True,
            request_log_retention_days=3,
            request_log_max_bytes=256 * 1024 * 1024,
            request_log_reserved_free_bytes=512 * 1024 * 1024,
        )
        self.store = guardd.RequestLog(
            str(Path(self.directory.name) / "requests.db"), self.config
        )
        self.addCleanup(self.store.close)
        self.now = 1786600800

    def ingest(self, count=1, **overrides):
        for index in range(count):
            record = guardd.parse_access_line(line(**overrides))
            self.assertIsNotNone(record)
            self.store.add(record)
        return self.store.flush(self.now)


class IngestTests(StoreTestCase):
    def test_records_are_written_in_one_batch_per_cycle(self):
        # One statement per cycle rather than one per line: at the measured
        # 27k lines/s a per-line transaction would dominate the poll budget.
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def flush")[1].split("def _size")[0]
        self.assertIn("executemany", block)
        self.assertNotIn("for ", block)

        self.assertEqual(self.ingest(count=50), 50)
        self.assertEqual(self.store.search()["total"], 50)

    def test_the_backend_and_the_server_are_stored_apart(self):
        self.ingest()
        row = self.store.search()["requests"][0]
        self.assertEqual(row["backend"], "be_shop")
        self.assertEqual(row["server"], "srv1")

    def test_no_server_is_stored_as_empty_not_as_a_placeholder(self):
        self.ingest(backend="be_shop/<NOSRV>", status="503")
        self.assertEqual(self.store.search()["requests"][0]["server"], "")

    def test_a_bad_request_is_kept_and_marked(self):
        self.ingest(request="<BADREQ>", status="400", extra="id=zz")
        row = self.store.search()["requests"][0]
        self.assertEqual(row["bad_request"], 1)
        self.assertEqual(row["status"], 400)


class SearchTests(StoreTestCase):
    def populate(self):
        self.ingest(client="203.0.113.9", status="200")
        self.ingest(client="198.51.100.7", status="404",
                    request="GET /api/users HTTP/1.1", extra="id=find-me")
        self.ingest(client="198.51.100.7", status="503",
                    backend="be_other/srv2",
                    request="POST /api/orders HTTP/1.1", extra="id=other")

    def test_a_request_identifier_finds_exactly_one(self):
        self.populate()
        found = self.store.search(request_id="find-me")
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["requests"][0]["path"], "/api/users")

    def test_a_status_class_matches_the_whole_range(self):
        self.populate()
        self.assertEqual(self.store.search(status="4xx")["total"], 1)
        self.assertEqual(self.store.search(status="5xx")["total"], 1)
        self.assertEqual(self.store.search(status="404")["total"], 1)

    def test_a_path_filter_is_a_prefix(self):
        self.populate()
        self.assertEqual(self.store.search(path="/api")["total"], 2)
        self.assertEqual(self.store.search(path="/api/users")["total"], 1)

    def test_a_wildcard_in_the_path_filter_is_taken_literally(self):
        # Otherwise "%" would scan the whole table and read as a match-all.
        self.populate()
        self.assertEqual(self.store.search(path="%")["total"], 0)
        self.assertEqual(self.store.search(path="/api/_sers")["total"], 0)

    def test_filters_combine(self):
        self.populate()
        found = self.store.search(client="198.51.100.7", status="5xx")
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["requests"][0]["backend"], "be_other")

    def test_a_filter_value_is_a_parameter_not_sql(self):
        self.populate()
        hostile = "' OR 1=1 --"
        self.assertEqual(self.store.search(client=hostile)["total"], 0)
        self.assertEqual(self.store.search(request_id=hostile)["total"], 0)

    def test_the_page_size_is_capped(self):
        self.ingest(count=20)
        self.assertEqual(len(self.store.search(limit=99999)["requests"]), 20)
        self.assertEqual(len(self.store.search(limit=5)["requests"]), 5)
        self.assertEqual(self.store.search(limit=5)["total"], 20)

    def test_the_newest_request_comes_first(self):
        self.ingest(stamp="12/Aug/2026:09:00:00.000", extra="id=older")
        self.ingest(stamp="12/Aug/2026:11:00:00.000", extra="id=newer")
        self.assertEqual(
            self.store.search()["requests"][0]["request_id"], "newer"
        )


class BudgetTests(StoreTestCase):
    def test_records_past_the_retention_window_are_dropped(self):
        self.ingest(stamp="01/Aug/2026:10:00:00.000", extra="id=ancient")
        self.ingest(extra="id=recent")
        self.store._last_maintenance = 0
        self.store.flush(self.now)
        identifiers = [
            row["request_id"] for row in self.store.search()["requests"]
        ]
        self.assertIn("recent", identifiers)
        self.assertNotIn("ancient", identifiers)

    def test_the_size_cap_outranks_the_retention_window(self):
        # Everything here is inside the window; only the cap can remove it.
        self.ingest(count=400)
        before = self.store.search()["total"]
        self.store.config = guardd.GuardConfig(
            request_log_enabled=True,
            request_log_max_bytes=1,
            request_log_reserved_free_bytes=0,
        )
        self.store._last_maintenance = 0
        self.store.flush(self.now)
        self.assertLess(self.store.search()["total"], before)

    def test_writing_stops_when_the_filesystem_reserve_is_reached(self):
        with mock.patch.object(self.store, "_free_bytes", return_value=1024):
            self.store._last_maintenance = 0
            self.store.flush(self.now)
            self.assertTrue(self.store.status()["paused"])
            written = self.ingest(count=10)
        self.assertEqual(written, 0)

    def test_it_resumes_once_space_comes_back(self):
        with mock.patch.object(self.store, "_free_bytes", return_value=1024):
            self.store._last_maintenance = 0
            self.store.flush(self.now)
        self.assertTrue(self.store.status()["paused"])
        with mock.patch.object(
            self.store, "_free_bytes", return_value=10 * 1024 ** 3
        ):
            self.store._last_maintenance = 0
            self.store.flush(self.now + 120)
        self.assertFalse(self.store.status()["paused"])

    def test_the_status_reports_the_budget_it_is_holding(self):
        self.ingest(count=5)
        status = self.store.status()
        self.assertEqual(status["rows"], 5)
        self.assertGreater(status["database_bytes"], 0)
        self.assertEqual(status["retention_days"], 3)
        self.assertEqual(status["max_bytes"], 256 * 1024 * 1024)

    def test_a_write_failure_does_not_take_the_engine_down(self):
        # A closed database is the realistic version of "the write failed";
        # the engine must keep tailing the log either way.
        self.store._conn.close()
        self.assertEqual(self.ingest(count=3), 0)


class WiringTests(unittest.TestCase):
    SOURCE = (
        ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    ).read_text(encoding="utf-8")

    def test_the_store_is_optional_and_off_by_default(self):
        self.assertFalse(guardd.GuardConfig().request_log_enabled)
        defaults = (
            ROOT / "ansible/roles/haproxy-admin/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("guardd_request_log_enabled: false", defaults)

    def test_diagnostics_do_not_depend_on_the_security_mode(self):
        # Turning scoring off must not silently turn the explorer off too.
        self.assertIn(
            "if config.mode == MODE_OFF and not config.request_log_enabled:",
            self.SOURCE,
        )

    def test_the_engine_keeps_what_it_excludes_from_scoring(self):
        # An operator looking for their own failed request has to find it even
        # though their address is on the allow list.
        block = self.SOURCE.split("def ingest_log")[1].split("def observe_request")[0]
        self.assertLess(
            block.index("self.requests.add(request)"),
            block.index("self.observe_request(request, now)"),
        )

    def test_the_query_endpoints_say_so_when_it_is_off(self):
        self.assertIn('"/api/v1/guard/requests"', self.SOURCE)
        self.assertIn('"the request log is off"', self.SOURCE)

    def test_the_daemon_gets_its_own_state_directory(self):
        unit = (
            ROOT
            / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-guardd.service.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("easy-ha-proxy/requests", unit)
        self.assertIn("GUARDD_REQUEST_LOG", unit)


if __name__ == "__main__":
    unittest.main()
