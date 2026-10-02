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
        "[WARNING]  (976) : Server be_site2_easy_ha_proxy_test/srv1 is UP, "
        "reason: Layer7 check passed, code: 200, check duration: 800ms."
    ),
    "no_server": (
        "2026-08-11T06:02:53.606589+00:00 haproxy-easy haproxy[976]: "
        "backend be_site2_easy_ha_proxy_test has no server available!"
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
        # HAProxy refuses a 403 or 451 with http-request deny, so no server
        # is ever chosen and the line carries <NOSRV>. Every 451 on the
        # production gateway logs exactly that. The engine reads the
        # difference: a refusal only shields an address that has never been
        # past the gateway on anything.
        backend = "fe_https/<NOSRV>" if status in (403, 451) else "be_shop/srv1"
        return (
            f"2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ {backend} "
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
        # Comments are skipped: a comment cannot issue a command, and a
        # guarantee that fires on the prose explaining the mechanism is one
        # that gets edited away rather than obeyed.
        mutating = [
            line.strip()
            for line in source.splitlines()
            if ("set table" in line or "clear table" in line)
            and not line.strip().startswith("#")
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
        # HAProxy refuses a 403 or 451 with http-request deny, so no server
        # is ever chosen and the line carries <NOSRV>. Every 451 on the
        # production gateway logs exactly that. The engine reads the
        # difference: a refusal only shields an address that has never been
        # past the gateway on anything.
        backend = "fe_https/<NOSRV>" if status in (403, 451) else "be_shop/srv1"
        return (
            f"2026-08-11T07:00:00.000000+00:00 host haproxy[1]: "
            f"{ip}:1234 [11/Aug/2026:07:00:00.000] fe_https~ {backend} "
            f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 GET {path} HTTP/1.1"
        )

    def types(self):
        return [event["event_type"] for event in self.events()]

    def test_a_known_scanner_path_is_recorded_with_its_category(self):
        # .env is decisive: no client legitimately asks for one, so a single
        # hit is reported as such rather than as a probable finding.
        self.append(self.line("203.0.113.9", "/.env", 404))
        self.engine.ingest_log(1000)
        events = self.events()
        self.assertEqual(events[0]["event_type"], guardd.EVENT_SCANNER_DECISIVE)
        self.assertEqual(events[0]["category"], "secrets")
        self.assertEqual(events[0]["detail"], "/.env")

    def test_a_path_a_site_might_serve_stays_a_probable_finding(self):
        self.append(self.line("203.0.113.9", "/wp-login.php", 404))
        self.engine.ingest_log(1000)
        events = self.events()
        self.assertEqual(events[0]["event_type"], guardd.EVENT_SCANNER_PATH)
        self.assertEqual(events[0]["category"], "wordpress")

    def test_a_scanner_path_the_application_served_is_not_a_finding(self):
        # A site that really runs WordPress answers this with a login page,
        # and every one of its users would otherwise be filed as scanning.
        self.append(self.line("203.0.113.9", "/wp-login.php", 200))
        self.engine.ingest_log(1000)
        self.assertNotIn(guardd.EVENT_SCANNER_PATH, self.types())

    def test_the_same_category_is_not_re_recorded_inside_its_cooldown(self):
        self.append(
            self.line("203.0.113.9", "/.git/config", 404),
            self.line("203.0.113.9", "/.svn/entries", 404),
        )
        self.engine.ingest_log(1000)
        self.assertEqual(self.types().count(guardd.EVENT_SCANNER_DECISIVE), 1)

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
        # Nothing this address asked for was answered, so a ban would add
        # nothing to the refusal it already gets.
        self.append(self.line("203.0.113.9", "/.env", 451))
        self.engine.ingest_log(1000)
        self.assertEqual(self.events()[0]["handled"], 1)
        self.assertEqual(self.engine.reputation("203.0.113.9", 1000)["score"], 0)

    def test_a_denied_scan_still_counts_once_the_address_gets_answered(self):
        # The refusals are per host. An address turned away from a gated
        # site and answered on another is not walled off, and the ban --
        # applied at connection level across every host and port -- is
        # strictly more coverage than the rule that refused it.
        self.append(self.line("203.0.113.8", "/", 200))
        self.append(self.line("203.0.113.8", "/.env", 451))
        self.engine.ingest_log(1000)
        finding = [e for e in self.events()
                   if e["event_type"] == guardd.EVENT_SCANNER_DECISIVE][0]
        self.assertEqual(finding["handled"], 0)
        self.assertGreater(
            self.engine.reputation("203.0.113.8", 1000)["score"], 0
        )

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

        # These tests are about how escalation behaves, not about which
        # numbers happen to ship. Pinning the ladder here keeps their
        # timings meaningful when the shipped default changes -- which it
        # did, and which silently broke five of them until this was added.
        # What the default *is* has its own test.
        self.engine.ban_durations = (300, 1800, 6 * 3600, 24 * 3600)

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
        # Against the ladder pinned in setUp, not the shipped one. Each step
        # is read just after the ban that earned it: a strike is kept for a
        # multiple of its own ban now rather than for a flat week, so asking
        # from a fixed point far in the future would be asking about an
        # address that had already served its time and been forgiven.
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
                self.engine.ban_duration("203.0.113.9", 1001 + index),
                expected,
                index,
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


class TheBanLadderIsTheOperatorsToSet(EnforcementTestCase):
    """How long a ban lasts stopped being a constant in the source.

    Five minutes is not a deterrent against a scanner that will still be
    there in an hour, and there was nowhere to change it. It is stored in
    guardd's own state rather than in guardd.json, because that file is a
    template Ansible owns and rewrites -- a choice made in the interface
    would not survive the next run.
    """

    def test_the_shipped_default_is_short_first_then_long(self):
        # The shape matters more than the numbers: the first step is the one
        # a single reading reaches, so it is the one a false positive lands
        # on, and it stays cheap. Coming back and doing it again is a much
        # harder thing to do by accident, so the steps after it are not.
        first, *rest = guardd.BAN_DURATIONS
        self.assertLessEqual(first, 86400, "a mistake must stay cheap")
        self.assertGreaterEqual(
            rest[0], 7 * 86400, "a repeat offender should get at least a week"
        )

    def test_the_default_never_goes_backwards(self):
        steps = list(guardd.BAN_DURATIONS)
        self.assertEqual(steps, sorted(steps))

    def test_a_stored_ladder_is_used_instead_of_the_default(self):
        self.engine.set_ban_durations([600, 7 * 86400])
        self.assertEqual(self.engine.ban_duration("203.0.113.9", 1000), 600)

    def test_it_survives_a_restart(self):
        self.engine.set_ban_durations([900, 30 * 86400])
        revived = guardd.GuardEngine(self.config, self.database)
        self.assertEqual(revived.ban_durations, (900, 30 * 86400))

    def test_a_corrupt_stored_ladder_falls_back_rather_than_stopping(self):
        # Never a reason to refuse to start: a daemon that will not come up
        # protects nobody.
        self.database.set_state(guardd.BAN_DURATIONS_KEY, "{not json")
        revived = guardd.GuardEngine(self.config, self.database)
        self.assertEqual(revived.ban_durations, guardd.BAN_DURATIONS)

    def test_bans_already_placed_keep_the_term_they_were_given(self):
        # Changing the rule must not re-sentence anybody: the expiry was
        # written as an absolute time when the ban was applied.
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        scheduled = self.database.scheduled_bans()["203.0.113.9"]

        self.engine.set_ban_durations([90 * 86400])
        self.assertEqual(
            self.database.scheduled_bans()["203.0.113.9"], scheduled
        )

    # -- what the daemon refuses -------------------------------------------

    def test_an_empty_ladder_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([])

    def test_a_step_shorter_than_the_one_before_is_refused(self):
        # Never what anyone meant, and it would quietly reward persistence.
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([7 * 86400, 3600])

    def test_an_absurd_step_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([10 * 365 * 86400])

    def test_a_step_of_seconds_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([5])

    def test_text_is_refused_rather_than_coerced(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations(["3600"])

    def test_a_true_is_not_a_number_of_seconds(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([True])

    def test_too_many_steps_are_refused(self):
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([3600] * 20)

    def test_a_refused_ladder_changes_nothing(self):
        before = self.engine.ban_durations
        with self.assertRaises(ValueError):
            self.engine.set_ban_durations([7 * 86400, 60])
        self.assertEqual(self.engine.ban_durations, before)


class ABanOutlivesTheStickTable(EnforcementTestCase):
    """The schedule here decides when a ban ends -- nothing else.

    tbl_ban expires its own entries after 168h. Once a ladder step can be
    thirty or ninety days, a ban would lapse inside HAProxy while the
    schedule still called it banned, and the address would quietly be let
    back in with nothing logged. The same gap opens when HAProxy restarts or
    the table is cleared by hand.
    """

    def test_a_ban_that_vanished_from_the_table_is_put_back(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.assertIn("203.0.113.9", self.table)

        # However it went: expiry, a restart, a careless clear.
        self.table.clear()
        self.engine.apply_enforcement(1100)
        self.assertIn("203.0.113.9", self.table)

    def test_it_is_put_back_with_our_own_reason_code(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.table.clear()
        self.engine.apply_enforcement(1100)
        self.assertEqual(
            self.table["203.0.113.9"]["gpt0"], str(guardd.ADAPTIVE_BAN_CODE)
        )

    def test_an_expired_ban_is_not_put_back(self):
        # The whole point is the schedule, so a ban past its time must stay
        # gone rather than be restored forever.
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.engine.apply_enforcement(1001 + 301)
        self.assertEqual(self.table, {})
        self.engine.apply_enforcement(1001 + 400)
        self.assertEqual(self.table, {})

    def test_nothing_is_put_back_while_only_observing(self):
        self.make_hostile("203.0.113.9")
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        self.engine.apply_enforcement(1001)
        self.engine.set_mode(guardd.MODE_MONITOR, 1002)
        self.table.clear()
        self.engine.apply_enforcement(1100)
        self.assertEqual(self.table, {})
        self.assertNotIn(
            True,
            [
                command.startswith("set table")
                for command in self.commands[-3:]
            ],
        )


class TheBanListCanNameAnAdaptiveBan(unittest.TestCase):
    """The ban list explains every reason code it can be shown.

    An adaptive ban lands in the same table as the ones HAProxy places under
    its own rules, and is told apart only by its reason code. The dashboard
    had labels for the three HAProxy codes and none for this one, so it fell
    through to printing the bare number -- which explains nothing and reads
    like a fault, on precisely the ban an operator is most likely to
    question, because no rule in the configuration points at it.

    It went unnoticed because a ban lasted five minutes and was gone before
    anybody opened the list. It stops being invisible the moment a ban lasts
    a week.
    """

    def setUp(self):
        self.script = (
            ROOT / "docker/app/haproxy_admin/static/js/dashboard.js"
        ).read_text(encoding="utf-8")

    def test_the_adaptive_code_has_a_label(self):
        table = self.script.split("BAN_REASON_LABELS = {")[1].split("};")[0]
        self.assertIn(f"{guardd.ADAPTIVE_BAN_CODE}:", table)

    def test_the_label_says_which_engine_placed_it(self):
        table = self.script.split("BAN_REASON_LABELS = {")[1].split("};")[0]
        line = [
            row for row in table.splitlines()
            if row.strip().startswith(f"{guardd.ADAPTIVE_BAN_CODE}:")
        ]
        self.assertTrue(line, "no entry for the adaptive code")
        self.assertIn("ADAPTIVE_BAN", line[0])

    def test_the_haproxy_codes_are_still_there(self):
        # The adaptive code must be an addition, not a replacement: these are
        # the reasons for most of what is in the list on a real gateway.
        table = self.script.split("BAN_REASON_LABELS = {")[1].split("};")[0]
        for code in (10, 20, 30):
            self.assertIn(f"{code}:", table)

    def test_the_label_is_translated(self):
        table = self.script.split("BAN_REASON_LABELS = {")[1].split("};")[0]
        line = [
            row for row in table.splitlines()
            if row.strip().startswith(f"{guardd.ADAPTIVE_BAN_CODE}:")
        ][0]
        english = line.split("'")[1]
        catalogue = json.loads(
            (
                ROOT / "docker/app/haproxy_admin/translations/ru.json"
            ).read_text(encoding="utf-8")
        )["messages"]
        self.assertIn(english, catalogue)


class TheStrikeRecordOutlivesTheBanThatMadeIt(EnforcementTestCase):
    """The ladder could not actually be climbed.

    Strikes were counted in a flat seven-day window. That worked while a ban
    lasted five minutes, and stopped working the moment one could last a
    week: the record of the ban aged out while the address was still
    serving it, so every release started again from step one and the rungs
    above the second were unreachable in principle -- present in the
    settings, impossible to arrive at.

    Each strike now carries its own window, measured from the ban that
    created it and scaled by the step it was on, so a long ban keeps its own
    evidence alive. Any fresh activity restarts the countdown: an address
    still probing has served nothing out.
    """

    LADDER = (3600, 7 * 86400, 30 * 86400, 90 * 86400)

    def setUp(self):
        super().setUp()
        self.engine.ban_durations = self.LADDER

    def ban_at(self, ip, ts):
        self.database.record_events(
            [{"ts": ts, "ip": ip, "event_type": guardd.EVENT_BAN_APPLIED,
              "source": "guardd"}]
        )

    def probe_at(self, ip, ts):
        self.database.record_events(
            [{"ts": ts, "ip": ip, "event_type": guardd.EVENT_SCANNER_PATH,
              "source": "guardd"}]
        )

    # -- the window the operator asked for ---------------------------------

    def test_the_first_strike_is_kept_for_twice_its_ban(self):
        self.assertEqual(self.engine.strike_retention(1), 3600 * 2)

    def test_the_second_for_three_times(self):
        self.assertEqual(self.engine.strike_retention(2), 7 * 86400 * 3)

    def test_the_third_for_four_times(self):
        self.assertEqual(self.engine.strike_retention(3), 30 * 86400 * 4)

    def test_every_window_outlasts_its_own_ban(self):
        # The whole point. A window equal to the ban would expire the record
        # at the instant the address became able to earn the next step.
        for level, duration in enumerate(self.LADDER, start=1):
            self.assertGreater(
                self.engine.strike_retention(level), duration, level
            )

    # -- the bug itself ----------------------------------------------------

    def test_a_week_long_ban_does_not_erase_its_own_strike(self):
        base = 1_000_000
        self.ban_at("203.0.113.9", base)                 # step 1, one hour
        self.ban_at("203.0.113.9", base + 7200)          # step 2, one week

        # The week is served. Under the old flat window both strikes were
        # exactly at its edge and the address came back a stranger.
        after = base + 7200 + 7 * 86400 + 60
        self.assertEqual(self.engine.strike_level("203.0.113.9", after), 2)
        self.assertEqual(
            self.engine.ban_duration("203.0.113.9", after), 30 * 86400
        )

    def test_the_ladder_can_be_climbed_to_the_top(self):
        ip = "203.0.113.9"
        ts = 1_000_000
        reached = []
        for _ in range(4):
            duration = self.engine.ban_duration(ip, ts)
            reached.append(duration)
            self.ban_at(ip, ts)
            ts += duration + 60  # released, and straight back to work
        self.assertEqual(reached, list(self.LADDER))

    def test_the_top_rung_is_not_exceeded(self):
        ip = "203.0.113.9"
        ts = 1_000_000
        for _ in range(6):
            duration = self.engine.ban_duration(ip, ts)
            self.ban_at(ip, ts)
            ts += duration + 60
        self.assertEqual(self.engine.ban_duration(ip, ts), self.LADDER[-1])

    # -- and it still forgives ---------------------------------------------

    def test_an_address_that_stays_away_starts_again(self):
        base = 1_000_000
        self.ban_at("203.0.113.9", base)
        # Nothing at all for longer than the first strike is kept.
        quiet = base + 2 * 3600 + 60
        self.assertEqual(self.engine.strike_level("203.0.113.9", quiet), 0)
        self.assertEqual(self.engine.ban_duration("203.0.113.9", quiet), 3600)

    def test_a_broken_chain_starts_the_count_again(self):
        base = 1_000_000
        self.ban_at("203.0.113.9", base)
        # A year later, with nothing in between: unrelated behaviour, not a
        # repeat offence.
        self.ban_at("203.0.113.9", base + 365 * 86400)
        self.assertEqual(
            self.engine.strike_level("203.0.113.9", base + 365 * 86400 + 60), 1
        )

    def test_any_hit_restarts_the_countdown(self):
        # "Любое попадание сбрасывает счётчик от начала": an address still
        # probing has served nothing out, whatever its last ban says.
        base = 1_000_000
        self.ban_at("203.0.113.9", base)
        self.probe_at("203.0.113.9", base + 2 * 3600 - 60)
        # Past the ban's own window, but the probe carried the record.
        later = base + 3 * 3600
        self.assertEqual(self.engine.strike_level("203.0.113.9", later), 1)

    def test_a_hit_does_not_invent_a_strike(self):
        self.probe_at("203.0.113.9", 1_000_000)
        self.assertEqual(self.engine.strike_level("203.0.113.9", 1_000_100), 0)

    def test_an_address_never_banned_is_on_the_first_step(self):
        self.assertEqual(
            self.engine.ban_duration("203.0.113.9", 1_000_000), 3600
        )


class BanRecordsOutliveOrdinaryFindings(EnforcementTestCase):
    """Retention was capping the ladder without saying so.

    Every event was swept at thirty days. The ladder counts bans, so a rung
    further out than the retention period could never be reached -- it would
    sit in the settings looking configurable while the evidence for it was
    deleted underneath.
    """

    def setUp(self):
        super().setUp()
        self.engine.ban_durations = (3600, 7 * 86400, 30 * 86400, 90 * 86400)

    def test_the_sweeper_keeps_bans_as_long_as_the_ladder_needs(self):
        # 90 days at the top rung, kept five times over.
        self.assertEqual(
            self.engine.longest_strike_retention(), 90 * 86400 * 5
        )

    def test_an_old_finding_goes_and_an_old_ban_stays(self):
        old = 1_000_000
        self.database.record_events([
            {"ts": old, "ip": "203.0.113.9",
             "event_type": guardd.EVENT_SCANNER_PATH, "source": "guardd"},
            {"ts": old, "ip": "203.0.113.9",
             "event_type": guardd.EVENT_BAN_APPLIED, "source": "guardd"},
        ])
        self.database.apply_retention(
            events_before=old + 1, bans_before=old - 86400
        )
        self.assertEqual(
            self.database.ban_timestamps("203.0.113.9"), [old]
        )
        self.assertEqual(self.database.newest_finding_ts("203.0.113.9"), 0)

    def test_a_ban_past_even_that_is_swept(self):
        # Kept longer, not kept forever.
        old = 1_000_000
        self.database.record_events([
            {"ts": old, "ip": "203.0.113.9",
             "event_type": guardd.EVENT_BAN_APPLIED, "source": "guardd"},
        ])
        self.database.apply_retention(
            events_before=old + 1, bans_before=old + 1
        )
        self.assertEqual(self.database.ban_timestamps("203.0.113.9"), [])


class TheListOfWhoIsBannedRightNow(EnforcementTestCase):
    """The page could say a lot about scores and nothing about who is held.

    The ban list elsewhere reads the stick table, and a stick table entry
    carries the table's own expiry rather than this daemon's schedule -- so
    with a one-day ladder it reports "6 days" about a ban that lifts within
    the hour, which is the report that prompted this. The schedule is the
    only thing that knows.
    """

    LADDER = (86400, 7 * 86400, 30 * 86400, 90 * 86400)

    def setUp(self):
        super().setUp()
        self.engine.ban_durations = self.LADDER

    def ban_now(self, ip="203.0.113.9", at=1_000_000):
        self.make_hostile(ip, now=at)
        self.engine.set_mode(guardd.MODE_ENFORCE, at)
        self.engine.apply_enforcement(at + 1)
        return at + 1

    def test_it_lists_what_is_held(self):
        now = self.ban_now()
        bans = self.engine.current_bans(now)
        self.assertEqual([row["ip"] for row in bans], ["203.0.113.9"])

    def test_it_reports_the_schedule_not_the_table(self):
        # A day, because that is the first rung -- not the table's week.
        now = self.ban_now()
        left = self.engine.current_bans(now)[0]["seconds_left"]
        self.assertGreater(left, 86400 - 120)
        self.assertLessEqual(left, 86400)

    def test_it_counts_down(self):
        now = self.ban_now()
        later = self.engine.current_bans(now + 3600)[0]["seconds_left"]
        self.assertAlmostEqual(later, 86400 - 3600, delta=120)

    def test_a_served_ban_drops_off_the_list(self):
        now = self.ban_now()
        self.assertEqual(self.engine.current_bans(now + 86400 + 60), [])

    def test_nothing_held_is_an_empty_list(self):
        self.assertEqual(self.engine.current_bans(1_000_000), [])

    def test_it_says_why(self):
        # A list of addresses with no reason beside them is one nobody can
        # act on, and "is this one a mistake?" is the first question asked.
        now = self.ban_now()
        row = self.engine.current_bans(now)[0]
        self.assertGreaterEqual(row["score"], guardd.WOULD_BAN_SCORE)
        self.assertTrue(row["categories"])

    def test_it_says_which_rung(self):
        now = self.ban_now()
        self.assertEqual(self.engine.current_bans(now)[0]["strikes"], 1)

    def test_the_soonest_to_lift_comes_first(self):
        first = self.ban_now("203.0.113.9", at=1_000_000)
        self.make_hostile("203.0.113.10", now=first + 7200)
        self.engine.apply_enforcement(first + 7201)
        bans = self.engine.current_bans(first + 7202)
        self.assertEqual(
            [row["ip"] for row in bans], ["203.0.113.9", "203.0.113.10"]
        )

    def test_an_address_that_went_quiet_is_still_listed(self):
        # The whole reason this is built from the schedule. A banned address
        # stops being seen, falls out of the scoring window, and would
        # disappear from a list built from the reputation table -- while
        # still being banned.
        # Needs a ban longer than the scoring window to be expressible at
        # all: with both set to a day there is no moment that is inside the
        # ban and outside the window.
        self.engine.ban_durations = (7 * 86400,)
        now = self.ban_now()
        much_later = now + int(self.engine.policy.window_seconds) + 3600
        self.assertEqual(
            [row["ip"] for row in self.engine.current_bans(much_later)],
            ["203.0.113.9"],
        )

    def test_the_page_is_given_the_list(self):
        now = self.ban_now()
        review = self.engine.shadow_review(now)
        self.assertIn("bans", review)
        self.assertEqual([row["ip"] for row in review["bans"]], ["203.0.113.9"])


class TheBanListSaysWhatItWasBannedFor(EnforcementTestCase):
    """The list showed "0" and no categories for almost every entry.

    Not a display fault: the score was being recomputed at the moment of
    looking. A banned address is doing nothing by construction -- it is
    blocked at the connection, so it produces no new findings -- and the old
    ones decay and fall out of the twenty-four hour window while it sits
    there. Within hours every ban honestly reported "score 0, no reason",
    which is the correct answer to a question nobody was asking.

    The reason is written down when the ban is applied. That is the one to
    show, and it is the one the operator means by "what did it do".
    """

    LADDER = (86400, 7 * 86400, 30 * 86400, 90 * 86400)

    def setUp(self):
        super().setUp()
        self.engine.ban_durations = self.LADDER

    def ban(self, ip="203.0.113.9", at=1_000_000):
        self.make_hostile(ip, now=at)
        self.engine.set_mode(guardd.MODE_ENFORCE, at)
        self.engine.apply_enforcement(at + 1)
        return at + 1

    def test_the_reason_survives_the_findings_decaying(self):
        now = self.ban()
        # Most of a day later: nothing new, everything old has decayed.
        much_later = now + 20 * 3600
        row = self.engine.current_bans(much_later)[0]
        self.assertGreaterEqual(row["score"], guardd.WOULD_BAN_SCORE)
        self.assertTrue(row["categories"])

    def test_recomputing_would_have_given_nothing(self):
        # The comparison that makes the point: the same address, scored
        # live, has nothing left to say for itself.
        now = self.ban()
        much_later = now + 20 * 3600
        live = self.engine.reputation("203.0.113.9", much_later)
        self.assertEqual(live["score"], 0)
        self.assertEqual(
            self.engine.current_bans(much_later)[0]["score"],
            self.engine._parse_ban_detail(
                self.database.last_ban_detail("203.0.113.9")
            )["score"],
        )

    def test_the_categories_are_the_ones_from_that_moment(self):
        now = self.ban()
        recorded = self.engine._parse_ban_detail(
            self.database.last_ban_detail("203.0.113.9")
        )
        row = self.engine.current_bans(now + 20 * 3600)[0]
        self.assertEqual(row["categories"], recorded["categories"])

    def test_without_a_record_it_falls_back_to_the_live_standing(self):
        # A ban placed by an older build has no detail to read. Showing the
        # live number is worse, but it beats showing nothing at all.
        now = self.ban()
        self.database._conn.execute(
            "UPDATE security_events SET detail = '' WHERE event_type = ?",
            (guardd.EVENT_BAN_APPLIED,),
        )
        self.database._conn.commit()
        row = self.engine.current_bans(now)[0]
        self.assertEqual(row["score"], self.engine.reputation("203.0.113.9", now)["score"])

    # -- reading our own handwriting ---------------------------------------

    def test_it_reads_the_recorded_format(self):
        parsed = self.engine._parse_ban_detail(
            "score=100 seconds=86400 [ERROR_RATE_EXCEEDED, secrets, vcs]"
        )
        self.assertEqual(parsed["score"], 100)
        self.assertEqual(
            parsed["categories"], ["ERROR_RATE_EXCEEDED", "secrets", "vcs"]
        )

    def test_an_empty_category_list_is_not_a_category(self):
        parsed = self.engine._parse_ban_detail("score=60 seconds=86400 []")
        self.assertEqual(parsed["score"], 60)
        self.assertEqual(parsed["categories"], [])

    def test_nothing_recorded_yields_nothing_rather_than_a_guess(self):
        for detail in ("", "nonsense", "score=", "[]"):
            parsed = self.engine._parse_ban_detail(detail)
            self.assertIsNone(parsed["score"], detail)

    def test_the_format_it_reads_is_the_format_it_writes(self):
        # These two live far apart in the file and would drift silently:
        # the reason would keep being written and quietly stop being read.
        self.ban()
        detail = self.database.last_ban_detail("203.0.113.9")
        self.assertTrue(detail)
        parsed = self.engine._parse_ban_detail(detail)
        self.assertIsNotNone(parsed["score"])
        self.assertTrue(parsed["categories"])


class SigningInIsNotReconnaissance(unittest.TestCase):
    """A visitor with a hardware key was banned for logging in.

    Completing a second factor fetches
    /api/secondfactor/webauthn/credentials. The segment rule
    "credentials" -> secrets matched the last word of that path, secrets is
    a decisive category, and one request from a legitimate user was worth an
    immediate ban.

    The rule itself is sound and stays. Over thirty days on the gateway that
    reported this, every other decisive match was genuine -- /.env across
    ninety-one addresses, /.git/config across a hundred and two, and
    /.aws/credentials across eight, which is precisely what the segment
    exists to catch. Weakening it to spare one endpoint would have been the
    wrong trade. The sign-in paths are spared instead.
    """

    @classmethod
    def setUpClass(cls):
        guardd.load_signatures(
            str(ROOT / "ansible/roles/haproxy-admin/files/scanner-signatures.json")
        )

    def test_the_path_that_caused_this_is_not_a_probe(self):
        self.assertEqual(
            guardd.classify_path("/api/secondfactor/webauthn/credentials"), ""
        )

    def test_the_rest_of_the_sign_in_surface_is_spared(self):
        for path in (
            "/api/firstfactor",
            "/api/secondfactor/totp",
            "/api/secondfactor/duo",
            "/api/user/info",
            "/api/state",
            "/api/verify",
            "/api/logout",
            "/api/reset-password/identity/start",
            "/api/checks/safe-redirection",
        ):
            self.assertEqual(guardd.classify_path(path), "", path)

    def test_it_is_not_a_blanket_exemption_for_api(self):
        # Probes for /api/.env are real and frequent on this gateway, and a
        # prefix rule wide enough to spare them would be worse than the bug.
        self.assertEqual(guardd.classify_path("/api/.env"), "secrets")
        self.assertEqual(guardd.classify_path("/api/mcp"), "ai-endpoint")

    def test_the_credentials_segment_still_catches_what_it_is_for(self):
        self.assertEqual(guardd.classify_path("/.aws/credentials"), "secrets")
        self.assertEqual(guardd.classify_path("/vendor/.aws/credentials"), "secrets")

    def test_the_ordinary_probes_are_untouched(self):
        for path, category in (
            ("/.env", "secrets"),
            ("/.git/config", "vcs"),
            ("/wp-login.php", "wordpress"),
            ("/actuator/env", "app-framework"),
        ):
            self.assertEqual(guardd.classify_path(path), category, path)


class AnUnbanHasToReachTheSchedule(EnforcementTestCase):
    """Unbanning by hand undid itself ten seconds later.

    Clearing the stick table is only half of it. This daemon keeps its own
    schedule and treats it as the authority on when a ban ends, so the next
    cycle saw the entry missing and put it straight back -- with a
    re-assert line in the journal as the only sign that anything had
    happened. From the outside the unban button simply did not work.
    """

    def ban(self, ip="203.0.113.9", at=1_000_000):
        self.make_hostile(ip, now=at)
        self.engine.set_mode(guardd.MODE_ENFORCE, at)
        self.engine.apply_enforcement(at + 1)
        return at + 1

    def test_clearing_the_table_alone_is_undone(self):
        # The behaviour that caused the report, kept as a test so the
        # re-assert cannot be blamed for it later: it is doing its job.
        now = self.ban()
        self.table.clear()
        self.engine.apply_enforcement(now + 10)
        self.assertIn("203.0.113.9", self.table)

    def test_telling_the_engine_makes_it_stick(self):
        now = self.ban()
        self.engine.forget_ban("203.0.113.9", now + 5)
        self.engine.apply_enforcement(now + 10)
        self.assertNotIn("203.0.113.9", self.table)

    def test_the_schedule_is_dropped_not_merely_the_entry(self):
        now = self.ban()
        self.engine.forget_ban("203.0.113.9", now + 5)
        self.assertNotIn("203.0.113.9", self.database.scheduled_bans())

    def test_it_lifts_the_table_entry_too(self):
        # So the call is complete on its own rather than depending on what
        # the caller happens to do next.
        now = self.ban()
        self.assertIn("203.0.113.9", self.table)
        self.engine.forget_ban("203.0.113.9", now + 5)
        self.assertNotIn("203.0.113.9", self.table)

    def test_it_says_whether_anything_was_held(self):
        now = self.ban()
        result = self.engine.forget_ban("203.0.113.9", now + 5)
        self.assertTrue(result["was_scheduled"])
        again = self.engine.forget_ban("203.0.113.9", now + 6)
        self.assertFalse(again["was_scheduled"])

    def test_forgetting_an_address_that_was_never_banned_is_harmless(self):
        result = self.engine.forget_ban("198.51.100.7", 1_000_000)
        self.assertTrue(result["ok"])

    def test_an_empty_address_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.forget_ban("", 1_000_000)

    def test_the_lift_is_recorded(self):
        # An address let back in by hand should be answerable for later.
        now = self.ban()
        self.engine.forget_ban("203.0.113.9", now + 5)
        types = [
            row["event_type"]
            for row in self.database.events_for("203.0.113.9", 0)
        ] if hasattr(self.database, "events_for") else []
        if types:
            self.assertIn(guardd.EVENT_BAN_LIFTED, types)

    def test_the_unban_button_tells_the_engine(self):
        # The web layer has to make the call; without it the daemon never
        # hears about the operator's decision.
        services = (
            ROOT / "docker/app/haproxy_admin/services.py"
        ).read_text(encoding="utf-8")
        body = services.split("def unban_ip(")[1].split("\ndef ")[0]
        self.assertIn("guardd_forget_ban", body)
        # Before the table is cleared, so nothing can re-assert in between.
        self.assertLess(
            body.index("guardd_forget_ban"), body.index("data.gpc0 0")
        )


class ChangingTheLadderStartsTheCountingAgain(EnforcementTestCase):
    """Strikes are a position on a scale of punishment, not a tally.

    Found on a live gateway. An address collected two strikes five minutes
    apart while the first two rungs were five and thirty minutes -- one
    continuous scan, and cheap at the time. The rungs then became a day and
    a week; those two strikes came along unchanged, and the address's next
    offence started at the third rung. Thirty days, then ninety. Nobody
    chose ninety days for it, and by the new ladder's own arithmetic getting
    there should take thirty-eight days of serving the rungs below.

    So a strike earned under one ladder is not spent against another.
    """

    OLD = (300, 1800, 6 * 3600, 24 * 3600)
    NEW = (86400, 7 * 86400, 30 * 86400, 90 * 86400)

    def ban_at(self, ts, ip="203.0.113.9"):
        self.database.record_events(
            [{"ts": ts, "ip": ip, "event_type": guardd.EVENT_BAN_APPLIED,
              "source": "guardd"}]
        )

    def test_the_reported_case(self):
        # The four bans exactly as they happened, and the ladder change
        # between the second and the third.
        base = 1_000_000
        self.engine.ban_durations = self.OLD
        self.ban_at(base)                       # 300s rung
        self.ban_at(base + 300)                 # 1800s rung, five minutes on

        self.engine.set_ban_durations(list(self.NEW))
        with mock.patch.object(guardd, "_utc_now", return_value=base + 3600):
            self.engine.set_ban_durations(list(self.NEW))

        # Its next offence, two days later, is its first under this ladder.
        later = base + 3 * 86400
        self.assertEqual(self.engine.strike_level("203.0.113.9", later), 0)
        self.assertEqual(self.engine.ban_duration("203.0.113.9", later), 86400)

    def test_the_second_offence_after_the_change_is_the_second_rung(self):
        base = 1_000_000
        self.engine.ban_durations = self.OLD
        self.ban_at(base)
        self.ban_at(base + 300)
        with mock.patch.object(guardd, "_utc_now", return_value=base + 3600):
            self.engine.set_ban_durations(list(self.NEW))

        self.ban_at(base + 3 * 86400)
        later = base + 5 * 86400
        self.assertEqual(self.engine.strike_level("203.0.113.9", later), 1)
        self.assertEqual(
            self.engine.ban_duration("203.0.113.9", later), 7 * 86400
        )

    def test_strikes_earned_under_the_current_ladder_still_count(self):
        # The rule forgives history, not repetition.
        base = 1_000_000
        with mock.patch.object(guardd, "_utc_now", return_value=base):
            self.engine.set_ban_durations(list(self.NEW))
        self.ban_at(base + 100)
        self.ban_at(base + 2 * 86400)
        later = base + 3 * 86400
        self.assertEqual(self.engine.strike_level("203.0.113.9", later), 2)

    def test_a_ladder_never_changed_counts_everything(self):
        # A gateway that has never touched the setting must behave as before.
        base = 1_000_000
        self.engine.ban_durations = self.NEW
        self.engine.ban_durations_changed_at = 0
        self.ban_at(base)
        self.ban_at(base + 2 * 86400)
        self.assertEqual(
            self.engine.strike_level("203.0.113.9", base + 3 * 86400), 2
        )

    def test_the_moment_of_the_change_is_remembered_across_a_restart(self):
        base = 1_000_000
        with mock.patch.object(guardd, "_utc_now", return_value=base):
            self.engine.set_ban_durations(list(self.NEW))
        revived = guardd.GuardEngine(self.config, self.database)
        self.assertEqual(revived.ban_durations_changed_at, base)

    def test_climbing_to_the_top_still_takes_serving_the_rungs(self):
        # What the operator expected of the ladder in the first place: each
        # rung is reached by coming back after the one below was served.
        base = 1_000_000
        with mock.patch.object(guardd, "_utc_now", return_value=base):
            self.engine.set_ban_durations(list(self.NEW))
        ts = base + 60
        reached = []
        for _ in range(4):
            duration = self.engine.ban_duration("203.0.113.9", ts)
            reached.append(duration)
            self.ban_at(ts)
            ts += duration + 60
        self.assertEqual(reached, list(self.NEW))
        # And that took the sum of the rungs below the last one.
        self.assertGreaterEqual(ts - base, 86400 + 7 * 86400 + 30 * 86400)


class PausingEnforcementIsNotAnAmnesty(EnforcementTestCase):
    """Switching to monitor and back used to forgive everybody.

    Found from a real question: an address that should have been serving a
    thirty day ban was seen hitting the gateway again. It had not broken
    through anything. The mode had been switched to monitor for
    thirty-seven minutes, which lifted every adaptive ban and cleared the
    schedule with it, so switching back to enforce started from nothing.
    Ten addresses were released for good by that pause, and one of them
    came back the next day and was escalated a rung -- punished harder for
    an offence it could only commit because it had been let out.

    Stopping enforcement still stops blocking at once, which is the point of
    the switch. It no longer erases the sentence.
    """

    LADDER = (86400, 7 * 86400, 30 * 86400, 90 * 86400)

    def setUp(self):
        super().setUp()
        self.engine.ban_durations = self.LADDER

    def ban(self, ip="203.0.113.9", at=1_000_000):
        self.make_hostile(ip, now=at)
        self.engine.set_mode(guardd.MODE_ENFORCE, at)
        self.engine.apply_enforcement(at + 1)
        return at + 1

    def test_pausing_stops_blocking_at_once(self):
        # Unchanged, and the reason the switch exists.
        now = self.ban()
        self.assertIn("203.0.113.9", self.table)
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.assertNotIn("203.0.113.9", self.table)

    def test_the_sentence_survives_the_pause(self):
        now = self.ban()
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.assertIn("203.0.113.9", self.database.scheduled_bans())

    def test_enforcing_again_resumes_what_was_left(self):
        now = self.ban()
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.engine.set_mode(guardd.MODE_ENFORCE, now + 120)
        self.assertIn("203.0.113.9", self.table)

    def test_the_term_is_not_extended_by_the_pause(self):
        # It resumes; it does not restart. The expiry was written as an
        # absolute time when the ban was applied.
        now = self.ban()
        before = self.database.scheduled_bans()["203.0.113.9"]
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.engine.set_mode(guardd.MODE_ENFORCE, now + 120)
        self.assertEqual(self.database.scheduled_bans()["203.0.113.9"], before)

    def test_a_ban_that_expired_during_the_pause_stays_gone(self):
        now = self.ban()
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        # A day and a bit later the first rung is served.
        self.engine.set_mode(guardd.MODE_ENFORCE, now + 86400 + 600)
        self.assertNotIn("203.0.113.9", self.database.scheduled_bans())
        self.assertNotIn("203.0.113.9", self.table)

    def test_a_served_ban_is_still_forgotten_while_enforcing(self):
        # The ordinary path has to keep working: nothing accumulates.
        now = self.ban()
        self.engine.apply_enforcement(now + 86400 + 60)
        self.assertNotIn("203.0.113.9", self.database.scheduled_bans())

    def test_an_operator_can_still_forgive_on_purpose(self):
        # The pause is no longer the way to do it; the unban is.
        now = self.ban()
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.engine.forget_ban("203.0.113.9", now + 90)
        self.engine.set_mode(guardd.MODE_ENFORCE, now + 120)
        self.assertNotIn("203.0.113.9", self.table)
        self.assertNotIn("203.0.113.9", self.database.scheduled_bans())

    def test_the_pause_does_not_earn_a_strike(self):
        # Being released and re-caught is a repeat offence; being released
        # by us is not, and must not move the address up the ladder.
        now = self.ban()
        level_before = self.engine.strike_level("203.0.113.9", now + 30)
        self.engine.set_mode(guardd.MODE_MONITOR, now + 60)
        self.engine.set_mode(guardd.MODE_ENFORCE, now + 120)
        self.assertEqual(
            self.engine.strike_level("203.0.113.9", now + 150), level_before
        )


if __name__ == "__main__":
    unittest.main()
