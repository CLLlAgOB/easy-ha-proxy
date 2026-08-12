"""Regression tests for the Authelia bans and log viewer data path."""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app"


def load_services_module():
    package = types.ModuleType("haproxy_admin")
    package.__path__ = [str(APP_DIR / "haproxy_admin")]
    utils = types.ModuleType("haproxy_admin.utils")
    utils.logger = logging.getLogger("authelia-bans-test")
    for name in (
        "run_cmd",
        "haproxy_runtime_command",
        "parse_table_output",
        "parse_sessions",
        "reload_haproxy",
        "ensure_whitelist_file",
        "ensure_whitelist_global_file",
        "controld_get_attackers",
    ):
        setattr(utils, name, lambda *args, **kwargs: "")
    cache = types.ModuleType("haproxy_admin.cache")
    cache.get_country_code = lambda _ip: ""

    sys.modules["haproxy_admin"] = package
    sys.modules["haproxy_admin.utils"] = utils
    sys.modules["haproxy_admin.cache"] = cache

    path = APP_DIR / "haproxy_admin" / "services.py"
    spec = importlib.util.spec_from_file_location(
        "haproxy_admin.services_under_test", path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def load_bansd_module():
    path = ROOT / "ansible" / "roles" / "authelia" / "files" / "authelia-bansd.py"
    spec = importlib.util.spec_from_file_location("authelia_bansd_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class AutheliaBanListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.services = load_services_module()

    def test_no_results_is_a_real_empty_state(self):
        entries, raw = self.services._parse_authelia_ban_list(
            "No results.\n", "Username"
        )
        self.assertEqual(entries, [])
        self.assertEqual(raw, "")

    def test_temporary_and_permanent_rows_use_header_offsets(self):
        temporary = (
            "ID Username            Expires             Source Reason\n"
            "1  easy-ha-proxy-audit 2026-08-02 20:58:31 cli    audit reason\n"
        )
        permanent = (
            "ID Username            Expires Source Reason\n"
            "2  easy-ha-proxy-audit never   cli    permanent audit reason\n"
        )

        temporary_rows, temporary_raw = self.services._parse_authelia_ban_list(
            temporary, "Username"
        )
        permanent_rows, permanent_raw = self.services._parse_authelia_ban_list(
            permanent, "Username"
        )

        self.assertEqual(temporary_raw, "")
        self.assertEqual(temporary_rows[0]["expires"], "2026-08-02 20:58:31")
        self.assertEqual(temporary_rows[0]["reason"], "audit reason")
        self.assertEqual(permanent_raw, "")
        self.assertEqual(permanent_rows[0]["expires"], "never")
        self.assertEqual(permanent_rows[0]["reason"], "permanent audit reason")

    def test_unknown_cli_output_is_preserved_as_raw_fallback(self):
        entries, raw = self.services._parse_authelia_ban_list(
            "A future Authelia output format", "IP"
        )
        self.assertEqual(entries, [])
        self.assertEqual(raw, "A future Authelia output format")

    def test_invalid_ip_is_rejected_before_the_privileged_helper(self):
        original_socket = self.services.AUTHELIA_BANS_SOCKET
        original_command = self.services.AUTHELIA_BANS_CMD
        self.services.AUTHELIA_BANS_SOCKET = ""
        self.services.AUTHELIA_BANS_CMD = ""
        try:
            message, status = self.services.authelia_unban_ip("999.1.1.1")
        finally:
            self.services.AUTHELIA_BANS_SOCKET = original_socket
            self.services.AUTHELIA_BANS_CMD = original_command
        self.assertEqual(status, 400)
        self.assertEqual(message, "Invalid IP/CIDR")

    def test_list_error_preserves_return_code_and_stderr(self):
        message = self.services._authelia_bans_error(
            {
                "error": "failed to list bans",
                "rc_users": 124,
                "rc_ips": 0,
                "stderr_users": "command timed out",
            }
        )

        self.assertIn("users rc=124", message)
        self.assertIn("users: command timed out", message)
        self.assertNotIn("ips rc=0", message)


class AutheliaLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.services = load_services_module()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tempdir.name) / "authelia.log"
        self.services.AUTHELIA_LOG_FILE = str(self.log_path)
        self.services.AUTHELIA_LOG_LIMIT = 200
        self.services.AUTHELIA_LOG_MAX_SCAN_BYTES = 16 * 1024 * 1024

    def tearDown(self):
        self.tempdir.cleanup()

    def write_lines(self, lines):
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_error_cause_and_extra_fields_are_preserved(self):
        self.write_lines(
            [
                json.dumps(
                    {
                        "time": "2026-08-02T20:00:00Z",
                        "level": "error",
                        "msg": "Error occurred performing a startup check",
                        "error": "SMTP connection refused",
                        "provider": "notification",
                        "stack": "frame one\\nframe two",
                    }
                )
            ]
        )

        entries, error = self.services.get_authelia_logs()

        self.assertIsNone(error)
        self.assertEqual(entries[0]["error"], "SMTP connection refused")
        self.assertEqual(
            {item["name"] for item in entries[0]["details"]},
            {"provider", "stack"},
        )

    def test_non_object_json_and_null_fields_do_not_break_the_page(self):
        self.write_lines(
            [
                "[]",
                json.dumps({"time": "t", "level": None, "username": 123, "msg": 7}),
            ]
        )

        entries, error = self.services.get_authelia_logs()
        filtered, filtered_error = self.services.get_authelia_logs(level="error")

        self.assertIsNone(error)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["username"], "123")
        self.assertIsNone(filtered_error)
        self.assertEqual(filtered, [])

    def test_text_format_is_parsed_and_filterable(self):
        self.write_lines(
            [
                'time="2026-08-02T20:00:00Z" level=error '
                'msg="startup failed" error="SMTP unavailable" '
                "provider=notification"
            ]
        )

        entries, error = self.services.get_authelia_logs(level="ERROR")

        self.assertIsNone(error)
        self.assertEqual(entries[0]["msg"], "startup failed")
        self.assertEqual(entries[0]["error"], "SMTP unavailable")

    def test_filter_searches_beyond_the_previous_five_times_window(self):
        lines = [
            json.dumps(
                {
                    "time": f"t{index}",
                    "level": "info",
                    "username": "needle" if index == 0 else "someone",
                    "msg": "event",
                }
            )
            for index in range(40)
        ]
        self.write_lines(lines)

        entries, error = self.services.get_authelia_logs(
            username="needle", limit=2
        )

        self.assertIsNone(error)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["username"], "needle")

    def test_empty_file_is_not_reported_as_unavailable(self):
        self.log_path.write_text("", encoding="utf-8")
        entries, error = self.services.get_authelia_logs()
        self.assertEqual(entries, [])
        self.assertIsNone(error)


class AutheliaBansDaemonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bansd = load_bansd_module()

    def test_privileged_command_has_a_real_timeout(self):
        original = self.bansd.COMMAND_TIMEOUT
        self.bansd.COMMAND_TIMEOUT = 0.05
        started = time.monotonic()
        try:
            # The child sleeps far longer than the budget below, so finishing
            # early can only mean the timeout fired. An earlier version slept
            # two seconds and allowed one, which left the assertion measuring
            # interpreter startup as much as the timeout -- and failing on a
            # loaded machine.
            rc, _stdout, error = self.bansd.run_cmd(
                [sys.executable, "-c", "import time; time.sleep(30)"]
            )
        finally:
            self.bansd.COMMAND_TIMEOUT = original
        self.assertEqual(rc, 124)
        self.assertIn("timed out", error)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_daemon_revalidates_privileged_arguments(self):
        original = self.bansd.SCRIPT_PATH
        self.bansd.SCRIPT_PATH = "/bin/true"
        try:
            user = self.bansd.handle_request(
                {"action": "revoke-user", "username": "invalid user"}
            )
            ip = self.bansd.handle_request(
                {"action": "revoke-ip", "ip": "999.1.1.1"}
            )
        finally:
            self.bansd.SCRIPT_PATH = original
        self.assertFalse(user["ok"])
        self.assertFalse(ip["ok"])


class AutheliaBansTemplateTests(unittest.TestCase):
    def test_template_renders_both_message_and_error_and_uses_prg(self):
        template = (
            APP_DIR / "haproxy_admin" / "templates" / "authelia_bans.html"
        ).read_text(encoding="utf-8")
        route = (APP_DIR / "haproxy_admin" / "routes.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("{% if e.msg %}", template)
        self.assertIn("{% if e.error %}", template)
        self.assertNotIn("{% elif e.error %}", template)
        self.assertIn("bans.users_raw", template)
        self.assertIn("bans.ips_raw", template)
        self.assertIn("code=303", route)


if __name__ == "__main__":
    unittest.main()
