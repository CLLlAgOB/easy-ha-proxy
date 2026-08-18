"""Regression tests for the adaptive protection foundation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_guardd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()


# Captured from the test VM: HAProxy 2.8 behind rsyslog, with the project's
# own log-format. Everything the parser has to cope with is here.
LIVE_LINES = {
    "h2_admin": (
        "2026-08-11T06:18:05.912571+00:00 haproxy-easy haproxy[976]: "
        "192.168.50.186:2160 [11/Aug/2026:06:18:05.863] fe_https~ be_admin/ui "
        "11/0/0/30/47 200 786 ----- 1/1/0/0/0 0/0 "
        "GET https://ha.easy-ha-proxy.test/haproxy/config/state HTTP/2.0"
    ),
    "h1_no_host": (
        "2026-08-11T07:26:51.104063+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60374 [11/Aug/2026:07:26:51.096] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/6 400 58 PR--- 1/1/0/0/0 0/0 GET /.env HTTP/1.1"
    ),
    "h1_geo_denied": (
        "2026-08-11T07:26:51.127725+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60378 [11/Aug/2026:07:26:51.114] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/6 451 76 PR--- 1/1/0/0/0 0/0 GET /.git/config HTTP/1.1"
    ),
    "h1_with_token": (
        "2026-08-11T07:26:51.147284+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:60384 [11/Aug/2026:07:26:51.139] fe_https~ fe_https/<NOSRV> "
        "0/-1/-1/-1/7 451 76 PR--- 1/1/0/0/0 0/0 "
        "GET /reset?token=SECRET123 HTTP/1.1"
    ),
    "h1_404": (
        "2026-08-11T07:26:51.161525+00:00 haproxy-easy haproxy[976]: "
        "127.0.0.1:50588 [11/Aug/2026:07:26:51.159] fe_http80 fe_http80/<NOSRV> "
        "0/-1/-1/-1/0 404 87 LR--- 1/1/0/0/0 0/0 GET /admin HTTP/1.1"
    ),
    "server_up": (
        "2026-08-11T06:03:01.160002+00:00 haproxy-easy haproxy[976]: "
        "[WARNING]  (976) : Server be_oreol2_easy_ha_proxy_test/srv1 is UP, "
        "reason: Layer7 check passed, code: 200, check duration: 800ms."
    ),
    "no_server": (
        "2026-08-11T06:02:53.606589+00:00 haproxy-easy haproxy[976]: "
        "backend be_oreol2_easy_ha_proxy_test has no server available!"
    ),
}

# The ban_log variable is appended straight after %tsc and carries quoted text
# with spaces, so the middle of the line can never be parsed positionally.
BANNED_LINE = (
    "2026-08-11T07:30:00.000000+00:00 haproxy-easy haproxy[976]: "
    "203.0.113.9:5555 [11/Aug/2026:07:30:00.000] fe_https~ be_shop/srv1 "
    "0/0/0/2/2 403 120 PR--- ban_val=1 ban_code=10 "
    'ban_reason="ERR_LIMIT_SITE name=shop.example.com limit=5" '
    "1/1/0/0/0 0/0 GET /wp-login.php HTTP/1.1"
)


class PathSanitizerTests(unittest.TestCase):
    def test_the_query_string_never_survives(self):
        self.assertEqual(
            guardd.normalize_path("/reset?token=SECRET123"), "/reset"
        )
        self.assertEqual(guardd.normalize_path("/api?id=1&key=abc"), "/api")
        self.assertEqual(guardd.normalize_path("/p#frag"), "/p")

    def test_absolute_form_is_reduced_to_the_path(self):
        self.assertEqual(
            guardd.normalize_path("https://example.com/a/b?c=d"), "/a/b"
        )

    def test_traversal_and_duplicate_separators_are_normalised(self):
        self.assertEqual(guardd.normalize_path("//a///b"), "/a/b")
        self.assertEqual(guardd.normalize_path("/a/./b"), "/a/b")
        self.assertEqual(guardd.normalize_path("/a/../b"), "/b")
        self.assertEqual(guardd.normalize_path("/../../etc/passwd"), "/etc/passwd")
        self.assertEqual(guardd.normalize_path("/%2e%2e/secret"), "/secret")

    def test_control_characters_are_stripped(self):
        self.assertEqual(guardd.normalize_path("/a\x00b\nc"), "/abc")

    def test_length_is_capped(self):
        long_path = "/" + ("a" * 5000)
        self.assertLessEqual(
            len(guardd.normalize_path(long_path)), guardd.MAX_PATH_LENGTH
        )

    def test_decoding_happens_once_only(self):
        # %2520 decodes to %20, not to a space: decoding repeatedly would
        # invent a path that was never requested.
        self.assertEqual(guardd.normalize_path("/a%2520b"), "/a%20b")

    def test_empty_and_relative_targets_become_a_path(self):
        self.assertEqual(guardd.normalize_path(""), "/")
        self.assertEqual(guardd.normalize_path("admin"), "/admin")

    def test_host_only_comes_from_absolute_form(self):
        self.assertEqual(
            guardd.extract_host("https://ha.example.test/x"), "ha.example.test"
        )
        self.assertEqual(guardd.extract_host("/x"), "")


class AccessLineParserTests(unittest.TestCase):
    def test_http2_line_yields_client_status_and_host(self):
        request = guardd.parse_access_line(LIVE_LINES["h2_admin"])
        self.assertIsNotNone(request)
        self.assertEqual(request.client_ip, "192.168.50.186")
        self.assertEqual(request.status, 200)
        self.assertEqual(request.frontend, "fe_https~")
        self.assertEqual(request.backend, "be_admin/ui")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/haproxy/config/state")
        self.assertEqual(request.host, "ha.easy-ha-proxy.test")

    def test_http11_line_has_no_host(self):
        request = guardd.parse_access_line(LIVE_LINES["h1_no_host"])
        self.assertEqual(request.path, "/.env")
        self.assertEqual(request.host, "")
        self.assertEqual(request.status, 400)
        # This line is a scanner reaching for /.env, and a 400 is the gateway
        # rejecting one malformed request -- not blocking the address, which
        # goes on being served everything else. Counting it as handled scored
        # the probe at zero, which is how 77% of the evidence on a live
        # gateway came to be discarded.
        self.assertFalse(request.denied_by_gateway)

    def test_a_geo_denial_is_recognised_as_handled_by_the_gateway(self):
        request = guardd.parse_access_line(LIVE_LINES["h1_geo_denied"])
        self.assertEqual(request.status, 451)
        self.assertTrue(request.denied_by_gateway)

    def test_a_token_in_the_request_line_is_dropped_at_parse_time(self):
        request = guardd.parse_access_line(LIVE_LINES["h1_with_token"])
        self.assertEqual(request.path, "/reset")
        self.assertNotIn("SECRET123", request.path)
        self.assertNotIn("SECRET123", repr(request))

    def test_a_404_is_parsed(self):
        request = guardd.parse_access_line(LIVE_LINES["h1_404"])
        self.assertEqual(request.status, 404)
        self.assertEqual(request.path, "/admin")

    def test_non_access_lines_are_ignored(self):
        self.assertIsNone(guardd.parse_access_line(LIVE_LINES["server_up"]))
        self.assertIsNone(guardd.parse_access_line(LIVE_LINES["no_server"]))
        self.assertIsNone(guardd.parse_access_line(""))
        self.assertIsNone(guardd.parse_access_line("nonsense"))

    def test_a_ban_annotation_does_not_shift_the_fields(self):
        request = guardd.parse_access_line(BANNED_LINE)
        self.assertIsNotNone(request)
        self.assertEqual(request.client_ip, "203.0.113.9")
        self.assertEqual(request.status, 403)
        self.assertEqual(request.path, "/wp-login.php")

    def test_a_malformed_request_is_reported_not_dropped(self):
        line = (
            "2026-08-11T07:31:00.000000+00:00 host haproxy[1]: "
            "203.0.113.9:1 [11/Aug/2026:07:31:00.000] fe_https~ fe_https/<NOSRV> "
            "0/-1/-1/-1/0 400 0 PR-- 1/1/0/0/0 0/0 <BADREQ>"
        )
        request = guardd.parse_access_line(line)
        self.assertIsNotNone(request)
        self.assertTrue(request.bad_request)
        self.assertEqual(request.status, 400)

    def test_an_ipv6_client_is_parsed(self):
        line = (
            "2026-08-11T07:32:00.000000+00:00 host haproxy[1]: "
            "[2001:db8::1]:443 [11/Aug/2026:07:32:00.000] fe_https~ be_shop/srv1 "
            "0/0/0/1/1 200 10 ---- 1/1/0/0/0 0/0 GET /x HTTP/1.1"
        )
        request = guardd.parse_access_line(line)
        self.assertEqual(request.client_ip, "2001:db8::1")


class EnforceabilityTests(unittest.TestCase):
    def test_only_ipv4_can_ever_be_banned(self):
        # tbl_ban is an IPv4 stick table and the firewall ruleset is inet.
        self.assertTrue(guardd.enforceable("203.0.113.9"))
        self.assertFalse(guardd.enforceable("2001:db8::1"))
        self.assertFalse(guardd.enforceable("garbage"))


class ConfigTests(unittest.TestCase):
    def write(self, payload):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "guardd.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_every_supported_mode_is_accepted(self):
        for mode in guardd.SUPPORTED_MODES:
            self.assertEqual(guardd.load_config(self.write({"mode": mode})).mode, mode)

    def test_unknown_mode_falls_back_to_monitor(self):
        config = guardd.load_config(self.write({"mode": "whatever"}))
        self.assertEqual(config.mode, guardd.MODE_MONITOR)

    def test_off_is_honoured(self):
        self.assertEqual(guardd.load_config(self.write({"mode": "off"})).mode, "off")

    def test_missing_file_uses_defaults(self):
        config = guardd.load_config("/nonexistent/guardd.json")
        self.assertEqual(config.mode, guardd.MODE_MONITOR)
        self.assertEqual(config.poll_interval_seconds, 10)

    def test_limits_are_clamped(self):
        config = guardd.load_config(
            self.write({"limits": {"max_tracked_ips": 99999999}})
        )
        self.assertEqual(config.max_tracked_ips, 500000)

    def test_the_default_working_set_stays_within_a_small_gateway(self):
        # 4.3 KiB per tracked address, measured on a 2-core/2 GiB gateway. The
        # default has to stay comfortably inside the unit's MemoryMax.
        config = guardd.load_config("/nonexistent/guardd.json")
        projected_mib = config.max_tracked_ips * 4.3 / 1024
        self.assertLess(projected_mib, 64, f"{projected_mib:.0f} MiB working set")


class ExclusionTests(unittest.TestCase):
    def build(self, entries, trusted=()):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "whitelist.ip"
        path.write_text("\n".join(entries) + "\n", encoding="utf-8")
        config = guardd.GuardConfig(
            whitelist_files=(str(path),), trusted_networks=tuple(trusted)
        )
        return guardd.ExclusionModel(config)

    def test_addresses_and_networks_from_acl_files(self):
        model = self.build(["203.0.113.5", "198.51.100.0/24", "# comment", ""])
        self.assertTrue(model.verdict("203.0.113.5").excluded)
        self.assertTrue(model.verdict("198.51.100.77").excluded)
        self.assertFalse(model.verdict("203.0.113.6").excluded)

    def test_a_trailing_label_in_a_pattern_file_is_tolerated(self):
        model = self.build(["203.0.113.5 office"])
        self.assertTrue(model.verdict("203.0.113.5").excluded)

    def test_authenticated_addresses_are_exempt_like_in_haproxy(self):
        model = self.build(["203.0.113.5"])
        self.assertFalse(model.verdict("198.51.100.1").excluded)
        model.refresh_authenticated({"198.51.100.1": {"gpc0": "1"}})
        verdict = model.verdict("198.51.100.1")
        self.assertTrue(verdict.excluded)
        self.assertEqual(verdict.reason, "authenticated")

    def test_a_zero_counter_is_not_an_authorization(self):
        model = self.build(["203.0.113.5"])
        model.refresh_authenticated({"198.51.100.1": {"gpc0": "0"}})
        self.assertFalse(model.verdict("198.51.100.1").excluded)

    def test_loopback_and_unparsable_are_never_acted_on(self):
        model = self.build(["203.0.113.5"])
        self.assertTrue(model.verdict("127.0.0.1").excluded)
        self.assertTrue(model.verdict("not-an-ip").excluded)

    def test_reload_picks_up_a_changed_file(self):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "whitelist.ip"
        path.write_text("203.0.113.5\n", encoding="utf-8")
        model = guardd.ExclusionModel(
            guardd.GuardConfig(whitelist_files=(str(path),))
        )
        self.assertFalse(model.verdict("203.0.113.9").excluded)
        path.write_text("203.0.113.5\n203.0.113.9\n", encoding="utf-8")
        os.utime(path, (0, 0))
        self.assertTrue(model.reload_files())
        self.assertTrue(model.verdict("203.0.113.9").excluded)

    def test_a_missing_file_is_not_fatal(self):
        model = guardd.ExclusionModel(
            guardd.GuardConfig(whitelist_files=("/nonexistent/list",))
        )
        self.assertFalse(model.verdict("203.0.113.9").excluded)


class IpMemoryTests(unittest.TestCase):
    def test_addresses_are_bounded_by_an_lru(self):
        memory = guardd.IpMemory(max_ips=3, max_paths=4)
        for index in range(10):
            memory.touch(f"203.0.113.{index}", 100 + index)
        self.assertEqual(len(memory), 3)
        self.assertEqual(memory.evictions, 7)
        self.assertIsNone(memory.get("203.0.113.0"))
        self.assertIsNotNone(memory.get("203.0.113.9"))

    def test_paths_per_address_are_bounded(self):
        memory = guardd.IpMemory(max_ips=10, max_paths=4)
        activity = memory.touch("203.0.113.1", 100)
        for index in range(20):
            activity.note_path(f"/p{index}", 100, 4)
        self.assertEqual(len(activity.paths), 4)

    def test_a_repeat_path_is_not_reported_as_new(self):
        memory = guardd.IpMemory(max_ips=10, max_paths=8)
        activity = memory.touch("203.0.113.1", 100)
        self.assertTrue(activity.note_path("/.env", 100, 8))
        self.assertFalse(activity.note_path("/.env", 101, 8))
        self.assertTrue(activity.note_path("/.git/config", 102, 8))

    def test_stale_addresses_are_pruned(self):
        memory = guardd.IpMemory(max_ips=10, max_paths=8)
        memory.touch("203.0.113.1", 100)
        memory.touch("203.0.113.2", 5000)
        self.assertEqual(memory.prune(1000), 1)
        self.assertEqual(len(memory), 1)


class LogCursorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "haproxy.log"
        self.path.write_text("old line\n", encoding="utf-8")

    def cursor(self, state=None):
        return guardd.LogCursor(str(self.path), state or {})

    def test_the_first_start_does_not_import_history(self):
        cursor = self.cursor()
        self.assertEqual(cursor.read(4096), [])
        self.assertGreater(cursor.offset, 0)

    def test_new_lines_are_returned_once(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("first\nsecond\n")
        self.assertEqual(cursor.read(4096), ["first", "second"])
        self.assertEqual(cursor.read(4096), [])

    def test_a_partial_line_waits_for_its_newline(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("incomplete")
        self.assertEqual(cursor.read(4096), [])
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(" now complete\n")
        self.assertEqual(cursor.read(4096), ["incomplete now complete"])

    def test_rotation_follows_the_new_file_without_replaying(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("before rotation\n")
        cursor.read(4096)

        self.path.unlink()
        self.path.write_text("after rotation\n", encoding="utf-8")
        lines = cursor.read(4096)
        self.assertEqual(lines, ["after rotation"])
        self.assertEqual(cursor.rotations, 1)

    def test_truncation_in_place_restarts_without_replaying_the_old_tail(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("a line\n")
        cursor.read(4096)
        self.path.write_text("fresh\n", encoding="utf-8")
        self.assertEqual(cursor.read(4096), ["fresh"])
        self.assertEqual(cursor.rotations, 1)

    def test_a_read_budget_leaves_the_rest_for_the_next_cycle(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            for index in range(200):
                handle.write(f"line {index}\n")
        first = cursor.read(64)
        self.assertGreater(len(first), 0)
        self.assertGreater(cursor.lag_bytes, 0)
        second = cursor.read(1 << 20)
        self.assertEqual(len(first) + len(second), 200)

    def test_a_missing_file_is_reported_not_raised(self):
        cursor = self.cursor()
        cursor.read(4096)
        self.path.unlink()
        self.assertEqual(cursor.read(4096), [])
        self.assertIsNotNone(cursor.last_error)

    def test_the_position_survives_a_restart(self):
        cursor = self.cursor()
        cursor.read(4096)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("one\n")
        cursor.read(4096)
        resumed = self.cursor(cursor.state())
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("two\n")
        self.assertEqual(resumed.read(4096), ["two"])


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        self.whitelist = root / "whitelist.ip"
        self.whitelist.write_text("198.51.100.7\n", encoding="utf-8")
        self.config = guardd.GuardConfig(
            log_file=str(self.log),
            whitelist_files=(str(self.whitelist),),
        )
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(self.config, self.database)
        self.engine.cursor.read(4096)

    def append(self, *lines):
        with self.log.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")

    def events(self):
        connection = sqlite3.connect(str(self.database.path))
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(
                "SELECT ts, ip, event_type, source, site, category, detail, handled "
                "FROM security_events ORDER BY id"
            )]
        finally:
            connection.close()


class EngineIngestTests(EngineTestCase):
    def line(self, ip, path, status=200, proto="HTTP/1.1"):
        return (
            f"2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ be_shop/srv1 "
            f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 GET {path} {proto}"
        )

    def test_requests_land_in_bounded_memory(self):
        self.append(
            self.line("203.0.113.9", "/.env", 404),
            self.line("203.0.113.9", "/.git/config", 404),
            self.line("203.0.113.9", "/index.html", 200),
        )
        self.engine.ingest_log(1000)
        activity = self.engine.memory.get("203.0.113.9")
        self.assertEqual(activity.requests, 3)
        self.assertEqual(activity.not_found, 2)
        self.assertEqual(len(activity.paths), 3)

    def test_excluded_addresses_are_not_tracked_at_all(self):
        self.append(self.line("198.51.100.7", "/.env", 404))
        self.engine.ingest_log(1000)
        self.assertIsNone(self.engine.memory.get("198.51.100.7"))
        self.assertEqual(self.engine.excluded_observations, 1)

    def test_an_authenticated_address_stops_being_tracked(self):
        self.engine.exclusions.refresh_authenticated(
            {"203.0.113.9": {"gpc0": "1"}}
        )
        self.append(self.line("203.0.113.9", "/.env", 404))
        self.engine.ingest_log(1000)
        self.assertIsNone(self.engine.memory.get("203.0.113.9"))

    def test_gateway_denials_are_counted_separately_from_errors(self):
        self.append(
            self.line("203.0.113.9", "/a", 451),
            self.line("203.0.113.9", "/b", 403),
            self.line("203.0.113.9", "/c", 500),
        )
        self.engine.ingest_log(1000)
        activity = self.engine.memory.get("203.0.113.9")
        self.assertEqual(activity.gateway_denied, 2)
        self.assertEqual(activity.errors, 1)

    def test_non_access_lines_do_not_count_as_traffic(self):
        self.append(LIVE_LINES["server_up"], LIVE_LINES["no_server"])
        self.engine.ingest_log(1000)
        self.assertEqual(self.engine.lines_parsed, 0)
        self.assertEqual(len(self.engine.memory), 0)

    def test_no_query_string_reaches_the_database_or_memory(self):
        self.append(self.line("203.0.113.9", "/reset?token=SECRET123", 200))
        self.engine.ingest_log(1000)
        blob = json.dumps(self.events()) + str(self.database.path.read_bytes())
        self.assertNotIn("SECRET123", blob)


class EngineTableTests(EngineTestCase):
    def test_a_haproxy_ban_is_recorded_once(self):
        tables = {
            "tbl_ban": {"203.0.113.9": {"gpc0": "1", "gpt0": "10"}},
            "tbl_ip_auth": {},
        }
        self.assertEqual(self.engine.ingest_tables(tables, 1000), 1)
        self.assertEqual(self.engine.ingest_tables(tables, 1010), 0)
        events = self.events()
        self.assertEqual(events[0]["event_type"], "LEGACY_HAPROXY_BAN")
        self.assertEqual(events[0]["detail"], "code=10")

    def test_a_lifted_ban_can_be_recorded_again_later(self):
        banned = {"tbl_ban": {"203.0.113.9": {"gpc0": "1", "gpt0": "10"}}}
        cleared = {"tbl_ban": {"203.0.113.9": {"gpc0": "0", "gpt0": "0"}}}
        self.engine.ingest_tables(banned, 1000)
        self.engine.ingest_tables(cleared, 1010)
        self.engine.ingest_tables(banned, 1020)
        self.assertEqual(len(self.events()), 2)

    def test_authenticated_addresses_are_refreshed_from_the_table(self):
        self.engine.ingest_tables(
            {"tbl_ip_auth": {"203.0.113.9": {"gpc0": "2"}}}, 1000
        )
        self.assertTrue(self.engine.exclusions.verdict("203.0.113.9").excluded)

    def test_ip_state_records_whether_a_ban_could_ever_apply(self):
        self.engine.ingest_tables(
            {"tbl_ban": {"2001:db8::1": {"gpc0": "1", "gpt0": "10"}}}, 1000
        )
        connection = sqlite3.connect(str(self.database.path))
        try:
            row = connection.execute(
                "SELECT family, enforceable FROM ip_state WHERE ip = ?",
                ("2001:db8::1",),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row, (6, 0))


class MonitorGuaranteeTests(EngineTestCase):
    def test_monitor_mode_cannot_reach_haproxy(self):
        with mock.patch.object(guardd, "runtime_command") as runtime:
            self.assertFalse(self.engine.enforcer.ban("203.0.113.9"))
        runtime.assert_not_called()
        self.assertEqual(self.engine.enforcer.refused, 1)

    def test_the_health_report_states_that_enforcement_is_impossible(self):
        health = self.engine.health()
        self.assertEqual(health["mode"], "monitor")
        self.assertFalse(health["enforcement_possible"])

    def test_the_daemon_never_writes_to_a_stick_table_in_this_release(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        # Every mutating runtime command has to live inside Enforcer, which is
        # gated on the mode; nothing else may construct one.
        mutating = [
            line.strip()
            for line in source.splitlines()
            if "set table" in line or "clear table" in line
        ]
        self.assertTrue(mutating)
        enforcer_body = source.split("class Enforcer")[1].split("\nclass ")[0]
        for statement in mutating:
            self.assertIn(statement, enforcer_body, statement)


class PathClassifierTests(unittest.TestCase):
    def test_high_confidence_paths_get_a_category(self):
        self.assertEqual(guardd.classify_path("/.env"), "secrets")
        self.assertEqual(guardd.classify_path("/.git/config"), "vcs")
        self.assertEqual(guardd.classify_path("/wp-login.php"), "wordpress")
        self.assertEqual(guardd.classify_path("/phpmyadmin/index.php"), "database-admin")
        self.assertEqual(guardd.classify_path("/backup.zip"), "backup")
        self.assertEqual(guardd.classify_path("/actuator/health"), "app-framework")

    def test_ordinary_paths_have_no_category(self):
        for path in ("/", "/index.html", "/api/v1/users", "/about"):
            self.assertEqual(guardd.classify_path(path), "", path)

    def test_assets_are_recognised_so_stale_links_score_nothing(self):
        for path in ("/app.css", "/main.JS", "/i/logo.png", "/bundle.js.map"):
            self.assertTrue(guardd.is_asset(path), path)
        for path in ("/.env", "/admin", "/wp-login.php"):
            self.assertFalse(guardd.is_asset(path), path)


class ScoringTests(unittest.TestCase):
    def policy(self, **kwargs):
        return guardd.ScoringPolicy(**kwargs)

    def test_a_single_finding_is_not_enough_to_be_punished(self):
        result = guardd.score_events(
            [{"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
              "category": "secrets"}],
            1000,
            self.policy(),
        )
        self.assertEqual(result["score"], 25)
        self.assertEqual(result["state"], "WATCH")

    def test_combinations_of_categories_are_what_add_up(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH, "category": "secrets"},
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH, "category": "vcs"},
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_MULTI, "category": ""},
            {"ts": 1000, "event_type": guardd.EVENT_NOT_FOUND_ENUM, "category": ""},
        ]
        result = guardd.score_events(events, 1000, self.policy())
        self.assertGreaterEqual(result["score"], 60)
        self.assertIn(result["state"], ("HIGH_RISK", "HOSTILE"))

    def test_one_category_cannot_inflate_the_score(self):
        # Fifty WordPress URLs are one finding, not fifty.
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
             "category": "wordpress"}
            for _ in range(50)
        ]
        result = guardd.score_events(events, 1000, self.policy())
        self.assertEqual(result["score"], guardd.DEFAULT_CATEGORY_CAP)

    def test_an_ordinary_visitor_stays_near_zero(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_NOT_FOUND_ENUM,
             "category": "", "handled": 0},
        ]
        result = guardd.score_events(events, 1000, self.policy())
        self.assertLess(result["score"], 20)
        self.assertEqual(result["state"], "NORMAL")

    def test_requests_the_gateway_already_refused_score_nothing(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
             "category": "secrets", "handled": 1},
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
             "category": "vcs", "handled": 1},
        ]
        result = guardd.score_events(events, 1000, self.policy())
        self.assertEqual(result["score"], 0)
        self.assertTrue(
            all(item["points"] == 0 for item in result["contributions"])
        )

    def test_contributions_fade_with_age(self):
        event = [{"ts": 0, "event_type": guardd.EVENT_LEGACY_BAN, "category": ""}]
        policy = self.policy(decay_seconds=1000)
        self.assertEqual(guardd.score_events(event, 0, policy)["score"], 30)
        self.assertEqual(guardd.score_events(event, 500, policy)["score"], 15)
        self.assertEqual(guardd.score_events(event, 1000, policy)["score"], 0)

    def test_events_outside_the_window_are_ignored(self):
        event = [{"ts": 0, "event_type": guardd.EVENT_LEGACY_BAN, "category": ""}]
        policy = self.policy(window_seconds=100, decay_seconds=0)
        self.assertEqual(guardd.score_events(event, 50, policy)["score"], 30)
        self.assertEqual(guardd.score_events(event, 500, policy)["score"], 0)

    def test_the_score_is_capped_at_one_hundred(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
             "category": f"cat{index}"}
            for index in range(20)
        ]
        self.assertEqual(guardd.score_events(events, 1000, self.policy())["score"], 100)

    def test_retuning_weights_rescores_the_same_history(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_NOT_FOUND_ENUM, "category": ""}
        ]
        default = guardd.score_events(events, 1000, self.policy())["score"]
        louder = guardd.score_events(
            events,
            1000,
            self.policy(weights={guardd.EVENT_NOT_FOUND_ENUM: 90}),
        )["score"]
        self.assertEqual(default, 15)
        # Raising a weight past the category cap has to take effect; the cap
        # limits repetition, not the value of a single finding.
        self.assertEqual(louder, 90)

    def test_repetition_is_still_capped_after_a_weight_change(self):
        events = [
            {"ts": 1000, "event_type": guardd.EVENT_SCANNER_PATH,
             "category": "wordpress"}
            for _ in range(10)
        ]
        policy = self.policy(weights={guardd.EVENT_SCANNER_PATH: 40})
        self.assertEqual(guardd.score_events(events, 1000, policy)["score"], 40)

    def test_states_follow_the_documented_thresholds(self):
        self.assertEqual(guardd.state_for(0), "NORMAL")
        self.assertEqual(guardd.state_for(19), "NORMAL")
        self.assertEqual(guardd.state_for(20), "WATCH")
        self.assertEqual(guardd.state_for(40), "SUSPICIOUS")
        self.assertEqual(guardd.state_for(60), "HIGH_RISK")
        self.assertEqual(guardd.state_for(80), "HOSTILE")


class DetectionTests(EngineTestCase):
    def line(self, ip, path, status=200):
        return (
            f"2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ be_shop/srv1 "
            f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 GET {path} HTTP/1.1"
        )

    def types(self):
        return [event["event_type"] for event in self.events()]

    def test_a_known_scanner_path_is_recorded_with_its_category(self):
        self.append(self.line("203.0.113.9", "/.env", 404))
        self.engine.ingest_log(1000)
        events = self.events()
        self.assertEqual(events[0]["event_type"], guardd.EVENT_SCANNER_PATH)
        self.assertEqual(events[0]["category"], "secrets")
        self.assertEqual(events[0]["detail"], "/.env")

    def test_the_same_category_is_not_re_recorded_inside_its_cooldown(self):
        self.append(
            self.line("203.0.113.9", "/.git/config", 404),
            self.line("203.0.113.9", "/.svn/entries", 404),
        )
        self.engine.ingest_log(1000)
        self.assertEqual(self.types().count(guardd.EVENT_SCANNER_PATH), 1)

    def test_the_slow_scanner_from_the_design_discussion_is_caught(self):
        # Six probes spread over 40 minutes: every rate window in HAProxy sees
        # nothing, which is the entire reason this detection exists.
        probes = [
            "/.env", "/.git/config", "/wp-login.php",
            "/phpmyadmin/", "/backup.zip", "/server-status",
        ]
        for offset, path in enumerate(probes):
            self.append(self.line("203.0.113.9", path, 404))
            self.engine.ingest_log(1000 + offset * 480)
        types = self.types()
        self.assertIn(guardd.EVENT_SCANNER_MULTI, types)
        self.assertIn(guardd.EVENT_LOW_AND_SLOW, types)
        reputation = self.engine.reputation("203.0.113.9", 1000 + 5 * 480)
        self.assertGreaterEqual(reputation["score"], 60)
        self.assertIn(reputation["state"], ("HIGH_RISK", "HOSTILE"))

    def test_two_categories_are_not_yet_a_multi_category_finding(self):
        self.append(self.line("203.0.113.9", "/.env", 404))
        self.engine.ingest_log(1000)
        self.append(self.line("203.0.113.9", "/wp-login.php", 404))
        self.engine.ingest_log(1400)
        self.assertNotIn(guardd.EVENT_SCANNER_MULTI, self.types())

    def test_distinct_404s_are_enumeration_but_assets_are_not(self):
        for index in range(8):
            self.append(self.line("203.0.113.9", f"/missing{index}", 404))
        self.engine.ingest_log(1000)
        self.assertIn(guardd.EVENT_NOT_FOUND_ENUM, self.types())

        other = "203.0.113.10"
        for index in range(12):
            self.append(self.line(other, f"/assets/app{index}.css", 404))
        self.engine.ingest_log(1000)
        self.assertEqual(
            [
                event
                for event in self.events()
                if event["ip"] == other
            ],
            [],
        )

    def test_repeating_one_missing_path_is_not_enumeration(self):
        for _ in range(20):
            self.append(self.line("203.0.113.9", "/missing", 404))
        self.engine.ingest_log(1000)
        self.assertNotIn(guardd.EVENT_NOT_FOUND_ENUM, self.types())

    def test_a_geo_denied_scan_is_recorded_as_already_handled(self):
        self.append(self.line("203.0.113.9", "/.env", 451))
        self.engine.ingest_log(1000)
        self.assertEqual(self.events()[0]["handled"], 1)
        self.assertEqual(self.engine.reputation("203.0.113.9", 1000)["score"], 0)

    def test_invalid_host_activity_needs_repetition(self):
        for index in range(4):
            self.append(self.line("203.0.113.9", "/", 400))
            self.engine.ingest_log(1000 + index)
        self.assertNotIn(guardd.EVENT_INVALID_HOST, self.types())
        self.append(self.line("203.0.113.9", "/", 400))
        self.engine.ingest_log(1005)
        self.assertIn(guardd.EVENT_INVALID_HOST, self.types())

    def test_an_excluded_address_produces_no_findings_at_all(self):
        for path in ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/"):
            self.append(self.line("198.51.100.7", path, 404))
        self.engine.ingest_log(1000)
        self.assertEqual(self.events(), [])

    def test_an_exempt_address_is_reported_with_evidence_but_no_standing(self):
        self.append(self.line("203.0.113.9", "/.env", 404))
        self.engine.ingest_log(1000)
        self.engine.exclusions.refresh_authenticated(
            {"203.0.113.9": {"gpc0": "1"}}
        )
        reputation = self.engine.reputation("203.0.113.9", 1000)
        self.assertEqual(reputation["score"], 0)
        self.assertTrue(reputation["excluded"])
        self.assertEqual(reputation["exclusion_reason"], "authenticated")
        self.assertTrue(reputation["contributions"])

    def test_the_reputation_table_ranks_by_score(self):
        self.append(
            self.line("203.0.113.9", "/.env", 404),
            self.line("203.0.113.9", "/wp-login.php", 404),
            self.line("203.0.113.20", "/missing1", 404),
        )
        self.engine.ingest_log(1000)
        table = self.engine.reputation_table(1000)
        self.assertGreaterEqual(len(table), 1)
        scores = [row["score"] for row in table]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_an_ipv6_scanner_is_scored_but_marked_unenforceable(self):
        line = (
            "2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            "[2001:db8::99]:1 [11/Aug/2026:07:00:00.000] fe_https~ be_shop/srv1 "
            "0/0/0/1/1 404 100 ---- 1/1/0/0/0 0/0 GET /.env HTTP/1.1"
        )
        self.append(line)
        self.engine.ingest_log(1000)
        reputation = self.engine.reputation("2001:db8::99", 1000)
        self.assertGreater(reputation["score"], 0)
        self.assertFalse(reputation["enforceable"])


class RateTableTests(EngineTestCase):
    # Every case here needs the ceilings the generated configuration sets,
    # because a counter reading means nothing without them.
    THRESHOLDS = {
        "tbl_rate_shop": 100,
        "tbl_err_shop": 20,
        "tbl_nosni_tcp": 5,
    }

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(
            guardd, "read_thresholds", return_value=dict(self.THRESHOLDS)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_rate_and_error_tables_become_events_with_their_site(self):
        tables = {
            "tbl_rate_shop": {"203.0.113.9": {"http_req_rate(10s)": "120"}},
            "tbl_err_shop": {"203.0.113.9": {"http_err_rate(20s)": "40"}},
            "tbl_nosni_tcp": {"203.0.113.9": {"conn_rate(20s)": "9"}},
        }
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 3)
        events = {event["event_type"]: event for event in self.events()}
        self.assertIn(guardd.EVENT_RATE_EXCEEDED, events)
        self.assertIn(guardd.EVENT_ERROR_RATE_EXCEEDED, events)
        self.assertIn(guardd.EVENT_NOSNI_PROBING, events)
        self.assertEqual(events[guardd.EVENT_RATE_EXCEEDED]["site"], "shop")
        # Both numbers, so the page can say what was measured against what.
        self.assertEqual(
            events[guardd.EVENT_RATE_EXCEEDED]["detail"],
            "http_req_rate=120 limit=100",
        )

    def test_a_reading_under_the_ceiling_is_not_an_event(self):
        # This is the whole bug. One request against a limit of 400 used to be
        # recorded as RATE_EXCEEDED, and a mail client polling once a minute
        # sat permanently at WATCH because of it.
        tables = {"tbl_rate_shop": {"203.0.113.9": {"http_req_rate(10s)": "1"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 0)

    def test_a_reading_exactly_at_the_ceiling_is_not_an_event(self):
        # HAProxy bans on "gt", so the engine must agree on the boundary.
        tables = {"tbl_rate_shop": {"203.0.113.9": {"http_req_rate(10s)": "100"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 0)

    def test_a_zero_counter_is_not_an_event(self):
        tables = {"tbl_rate_shop": {"203.0.113.9": {"http_req_rate(10s)": "0"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 0)

    def test_a_table_with_no_configured_ceiling_scores_nothing(self):
        # Better silent than inventing a threshold: guessing is what produced
        # a finding for every visitor.
        tables = {"tbl_rate_unknown": {"203.0.113.9": {"http_req_rate(10s)": "9999"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 0)

    def test_one_continuous_incident_does_not_score_every_cycle(self):
        tables = {"tbl_rate_shop": {"203.0.113.9": {"http_req_rate(10s)": "120"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 1)
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1030), 0)
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1100), 1)

    def test_excluded_addresses_are_skipped_in_the_tables_too(self):
        tables = {"tbl_rate_shop": {"198.51.100.7": {"http_req_rate(10s)": "500"}}}
        self.assertEqual(self.engine.ingest_rate_tables(tables, 1000), 0)


class SchemaMigrationTests(unittest.TestCase):
    def test_a_v1_database_gains_the_handled_column_without_losing_events(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = str(Path(directory.name) / "security.db")

        database = guardd.SecurityDatabase(path)
        database.record_events(
            [
                {
                    "ts": 1000,
                    "ip": "203.0.113.9",
                    "event_type": guardd.EVENT_LEGACY_BAN,
                    "source": "stick-table",
                }
            ]
        )
        database.close()

        # Reproduce a genuine v1 file: neither of the later columns exists.
        connection = sqlite3.connect(path)
        try:
            connection.execute("UPDATE schema_version SET version = 1")
            connection.execute("ALTER TABLE security_events DROP COLUMN handled")
            connection.execute("ALTER TABLE ip_state DROP COLUMN authenticated_at")
            connection.commit()
        finally:
            connection.close()

        migrated = guardd.SecurityDatabase(path)
        self.addCleanup(migrated.close)
        self.assertEqual(
            migrated.stats()["schema_version"], guardd.SCHEMA_VERSION
        )
        self.assertEqual(migrated.stats()["events"]["rows"], 1)
        # Pre-existing rows keep counting exactly as they did before.
        self.assertEqual(
            migrated.events_for("203.0.113.9", 0)[0]["handled"], 0
        )

    def test_a_partly_upgraded_database_does_not_break_the_daemon(self):
        # The schema statements create tables in their newest shape, so a file
        # can carry an old version number and a new column at the same time.
        # Re-running the ladder over it must be a no-op, not a startup failure.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = str(Path(directory.name) / "security.db")

        guardd.SecurityDatabase(path).close()
        connection = sqlite3.connect(path)
        try:
            connection.execute("UPDATE schema_version SET version = 1")
            connection.commit()
        finally:
            connection.close()

        migrated = guardd.SecurityDatabase(path)
        self.addCleanup(migrated.close)
        self.assertEqual(
            migrated.stats()["schema_version"], guardd.SCHEMA_VERSION
        )


class EnforcementTestCase(EngineTestCase):
    """Enforcement with the runtime socket faked, so commands are inspectable."""

    def setUp(self):
        super().setUp()
        self.commands = []

        def fake_runtime(socket_path, command):
            self.commands.append(command)
            if command.startswith("show table tbl_ban key "):
                ip = command.rsplit(" ", 1)[-1]
                if ip in self.table:
                    fields = self.table[ip]
                    return (
                        "# table: tbl_ban, type: ip, size:204800, used:1\n"
                        f"0x1: key={ip} use=0 exp=1 shard=0 "
                        f"gpt0={fields['gpt0']} gpc0={fields['gpc0']}\n"
                    )
                return "# table: tbl_ban, type: ip, size:204800, used:0\n"
            if command == "show table tbl_ban":
                lines = ["# table: tbl_ban, type: ip, size:204800, used:0"]
                for ip, fields in self.table.items():
                    lines.append(
                        f"0x1: key={ip} use=0 exp=1 shard=0 "
                        f"gpt0={fields['gpt0']} gpc0={fields['gpc0']}"
                    )
                return "\n".join(lines) + "\n"
            if command.startswith("set table tbl_ban key "):
                parts = command.split()
                self.table[parts[4]] = {
                    "gpc0": parts[parts.index("data.gpc0") + 1],
                    "gpt0": parts[parts.index("data.gpt0") + 1],
                }
                return ""
            if command.startswith("clear table tbl_ban key "):
                self.table.pop(command.rsplit(" ", 1)[-1], None)
                return ""
            return ""

        self.table = {}
        patcher = mock.patch.object(guardd, "runtime_command", side_effect=fake_runtime)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_hostile(self, ip, now=1000):
        """Give an address enough findings to cross the ban threshold."""

        for index, category in enumerate(
            ("secrets", "vcs", "wordpress", "database-admin")
        ):
            self.database.observe_ip(ip, now, guardd.Verdict(False, ""))
            self.database.record_events(
                [
                    {
                        "ts": now,
                        "ip": ip,
                        "event_type": guardd.EVENT_SCANNER_PATH,
                        "source": "haproxy-log",
                        "category": category,
                    }
                ]
            )
        return self.engine.reputation(ip, now)


class EnforcementTests(EnforcementTestCase):
    def test_monitor_mode_bans_nothing_however_hostile(self):
        reputation = self.make_hostile("203.0.113.9")
        self.assertGreaterEqual(reputation["score"], guardd.WOULD_BAN_SCORE)
        result = self.engine.apply_enforcement(1000)
        self.assertEqual(result["applied"], [])
        self.assertEqual(self.table, {})
        self.assertNotIn(
            True, [command.startswith("set table") for command in self.commands]
        )

    def test_enforce_mode_writes_the_adaptive_reason_code(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        result = self.engine.apply_enforcement(1001)
        self.assertIn("203.0.113.9", result["applied"] + list(self.table))
        self.assertEqual(self.table["203.0.113.9"]["gpc0"], "1")
        self.assertEqual(
            self.table["203.0.113.9"]["gpt0"], str(guardd.ADAPTIVE_BAN_CODE)
        )

    def test_an_address_that_ever_authenticated_is_never_banned(self):
        self.make_hostile("203.0.113.9")
        self.database.record_authenticated(["203.0.113.9"], 900)
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        reputation = self.engine.reputation("203.0.113.9", 1001)
        self.assertIn("has authenticated before", reputation["blockers"])
        self.assertFalse(reputation["would_ban"])
        self.engine.apply_enforcement(1001)
        self.assertEqual(self.table, {})

    def test_an_exempt_address_is_never_banned(self):
        self.make_hostile("198.51.100.7")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.assertEqual(self.table, {})

    def test_ipv6_is_never_banned_because_it_cannot_be(self):
        self.make_hostile("2001:db8::99")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        reputation = self.engine.reputation("2001:db8::99", 1001)
        self.assertIn("IPv4-only ban path", reputation["blockers"])
        self.engine.apply_enforcement(1001)
        self.assertEqual(self.table, {})

    def test_bans_get_progressively_longer(self):
        self.assertEqual(self.engine.ban_duration("203.0.113.9", 1000), 300)
        for index, expected in enumerate((1800, 6 * 3600, 24 * 3600, 24 * 3600)):
            self.database.record_events(
                [
                    {
                        "ts": 1000 + index,
                        "ip": "203.0.113.9",
                        "event_type": guardd.EVENT_BAN_APPLIED,
                        "source": "guardd",
                    }
                ]
            )
            self.assertEqual(
                self.engine.ban_duration("203.0.113.9", 2000), expected, index
            )

    def test_a_ban_is_lifted_when_its_time_is_up(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.assertIn("203.0.113.9", self.table)

        result = self.engine.apply_enforcement(1001 + 301)
        self.assertIn("203.0.113.9", result["lifted"])
        self.assertEqual(self.table, {})

    def test_an_expired_ban_is_not_reapplied_on_the_same_evidence(self):
        # The score that justified the ban is still there when it expires;
        # re-banning on it would escalate the ladder by the clock rather than
        # by repeat behaviour.
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.engine.apply_enforcement(1400)
        self.assertEqual(self.table, {})
        self.engine.apply_enforcement(1500)
        self.assertEqual(self.table, {})

    def test_fresh_evidence_after_a_ban_escalates_to_the_next_step(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.engine.apply_enforcement(1400)
        self.assertEqual(self.table, {})

        self.make_hostile("203.0.113.9", now=1500)
        self.engine.apply_enforcement(1501)
        self.assertIn("203.0.113.9", self.table)
        # Second strike, so the next stretch is the longer one.
        self.assertEqual(self.engine.ban_duration("203.0.113.9", 1501), 6 * 3600)

    def test_switching_back_to_monitor_lifts_what_it_applied(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.assertIn("203.0.113.9", self.table)

        result = self.engine.set_mode(guardd.MODE_MONITOR, 1002)
        self.assertIn("203.0.113.9", result["lifted"])
        self.assertEqual(self.table, {})

    def test_a_ban_left_behind_by_a_crash_is_swept_up(self):
        # The stick table keeps the entry for the table's expiry, so an entry
        # can outlive the daemon that placed it.
        self.table["203.0.113.50"] = {
            "gpc0": "1", "gpt0": str(guardd.ADAPTIVE_BAN_CODE)
        }
        self.engine.apply_enforcement(1000)
        self.assertEqual(self.table, {})

    def test_a_ban_haproxy_placed_itself_is_never_touched(self):
        self.table["203.0.113.60"] = {"gpc0": "1", "gpt0": "10"}
        self.engine.set_mode(guardd.MODE_MONITOR, 1000)
        self.engine.apply_enforcement(1001)
        self.assertIn("203.0.113.60", self.table)
        self.assertFalse(self.engine.enforcer.lift("203.0.113.60"))
        self.assertIn("203.0.113.60", self.table)

    def test_the_mode_choice_survives_a_restart(self):
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        restarted = guardd.GuardEngine(self.config, self.database)
        self.assertEqual(restarted.enforcer.mode, guardd.MODE_ENFORCE)
        self.assertTrue(restarted.enforcer.allowed)

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.set_mode("aggressive")
        self.assertEqual(self.engine.enforcer.mode, guardd.MODE_MONITOR)

    def test_ban_and_lift_are_recorded_as_events(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.engine.apply_enforcement(1001 + 400)
        types = [event["event_type"] for event in self.events()]
        self.assertIn(guardd.EVENT_BAN_APPLIED, types)
        self.assertIn(guardd.EVENT_BAN_LIFTED, types)

    def test_ban_actions_carry_no_weight_in_the_score(self):
        # They are a record of what was done, not evidence of wrongdoing.
        for event_type in (guardd.EVENT_BAN_APPLIED, guardd.EVENT_BAN_LIFTED):
            self.assertNotIn(event_type, guardd.DEFAULT_WEIGHTS)
        result = guardd.score_events(
            [{"ts": 1000, "event_type": guardd.EVENT_BAN_APPLIED, "category": ""}],
            1000,
            guardd.ScoringPolicy(),
        )
        self.assertEqual(result["score"], 0)

    def test_the_configured_default_is_reported_alongside_the_override(self):
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        health = self.engine.health()
        self.assertEqual(health["mode"], guardd.MODE_ENFORCE)
        self.assertEqual(health["configured_mode"], guardd.MODE_MONITOR)
        self.assertTrue(health["mode_overridden"])


class RetentionTests(EngineTestCase):
    def test_old_events_are_deleted_and_space_reclaimed(self):
        self.database.record_events(
            [
                {
                    "ts": 1000,
                    "ip": "203.0.113.9",
                    "event_type": "LEGACY_HAPROXY_BAN",
                    "source": "stick-table",
                }
            ]
        )
        deleted = self.database.apply_retention(events_before=2000)
        self.assertEqual(deleted["events"], 1)
        self.assertEqual(self.events(), [])

    def test_cooldowns_suppress_repeats_inside_the_window(self):
        self.assertTrue(self.database.cooldown_passed("ip|site|RATE", 1000, 60))
        self.assertFalse(self.database.cooldown_passed("ip|site|RATE", 1030, 60))
        self.assertTrue(self.database.cooldown_passed("ip|site|RATE", 1100, 60))

    def test_the_daemon_never_issues_a_full_vacuum(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        import re

        for statement in re.findall(
            r"""["']([^"'\n]*vacuum[^"'\n]*)["']""", source, flags=re.IGNORECASE
        ):
            self.assertIn("incremental", statement.lower(), statement)


class TableParserTests(unittest.TestCase):
    def test_show_table_rows_are_parsed(self):
        payload = (
            "# table: tbl_ban, type: ip, size:204800, used:1\n"
            "0x5a14fb66ac88: key=203.0.113.77 use=0 exp=604799978 shard=0 "
            "gpt0=40 gpc0=1\n"
        )
        rows = guardd.parse_table(payload)
        self.assertEqual(rows["203.0.113.77"]["gpc0"], "1")
        self.assertEqual(rows["203.0.113.77"]["gpt0"], "40")

    def test_an_empty_table_yields_nothing(self):
        self.assertEqual(
            guardd.parse_table("# table: tbl_ban, type: ip, size:204800, used:0\n"),
            {},
        )

    def test_table_names_are_listed(self):
        payload = (
            "# table: tbl_ban, type: ip, size:204800, used:0\n"
            "# table: tbl_ip_auth, type: ip, size:204800, used:2\n"
        )
        self.assertEqual(
            guardd.list_tables(payload), ["tbl_ban", "tbl_ip_auth"]
        )


class BanAlertTests(unittest.TestCase):
    """An adaptive ban used to be visible only in the journal."""

    class Recorder:
        def __init__(self):
            self.calls = []

        def observe(self, rule, subject, **kwargs):
            self.calls.append((rule, subject, kwargs))
            return True

    def engine(self, alerts):
        engine = guardd.GuardEngine.__new__(guardd.GuardEngine)
        engine.alerts = alerts
        return engine

    def test_a_ban_is_reported_with_the_address_as_the_subject(self):
        recorder = self.Recorder()
        self.engine(recorder)._report_ban(
            "203.0.113.9", 300, {"score": 100}, "scanner, errors"
        )
        rule, subject, kwargs = recorder.calls[0]
        self.assertEqual(rule, "security.hostile_ip")
        self.assertEqual(subject, "203.0.113.9")
        self.assertIn("300s", kwargs["summary"])
        self.assertIn("scanner", kwargs["detail"])

    def test_a_broken_alert_client_cannot_stop_enforcement(self):
        class Exploding:
            def observe(self, *args, **kwargs):
                raise RuntimeError("alertd is on fire")

        self.engine(Exploding())._report_ban("203.0.113.9", 300, {}, "")

    def test_a_gateway_without_the_alert_daemon_still_bans(self):
        self.engine(None)._report_ban("203.0.113.9", 300, {}, "")

    def test_the_import_is_optional(self):
        # A daemon must not fail to start because the client is not installed.
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        ).read_text(encoding="utf-8")
        self.assertIn("except Exception:  # pragma: no cover", source)
        self.assertIn("AlertClient = None", source)


if __name__ == "__main__":
    unittest.main()
