"""Lifting a ban and changing an allow list report what actually happened (F07).

From the 30 October review, reproduced there: unban_ip ignored HAProxy's
answer, so "No such table" came back as OK/200 and was recorded as a lifted
ban; adding to an allow list said "Added" whatever the runtime update and
the reload said; and the routes recorded success whenever nothing raised.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    # Imported by name: Python 3.10's mock.patch does not import a package's
    # submodule from a dotted string.
    from haproxy_admin import guardd_client, routes, services  # noqa: E402

IP = "203.0.113.9"


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class LiftingABan(unittest.TestCase):
    def lift(self, runtime, engine_down=False):
        forget = mock.Mock(side_effect=OSError("down") if engine_down else None)
        with mock.patch.object(guardd_client, "guardd_forget_ban", forget), \
                mock.patch.object(services, "haproxy_runtime_command", **runtime):
            return services.unban_ip(IP)

    def test_an_empty_answer_is_a_lifted_ban(self):
        self.assertEqual(self.lift({"return_value": "\n"}), ("OK", 200))

    def test_haproxys_error_is_a_failure(self):
        text, code = self.lift({"return_value": "No such table: tbl_ban\n"})
        self.assertEqual(code, 502)
        self.assertIn("No such table", text)

    def test_an_unreachable_socket_is_a_failure(self):
        text, code = self.lift({"side_effect": FileNotFoundError("/run/haproxy/admin.sock")})
        self.assertEqual(code, 502)
        self.assertIn("did not lift", text)

    def test_lifted_but_the_engine_did_not_answer_says_so(self):
        text, code = self.lift({"return_value": ""}, engine_down=True)
        self.assertEqual(code, 200)
        self.assertIn("may come back", text)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ChangingAnAllowList(unittest.TestCase):
    def test_reloaded_is_done(self):
        self.assertEqual(services.whitelist_outcome("Added", "192.0.2.1/32", "", "controld reload ok: done"),
                         ("Added: 192.0.2.1/32", 200))

    def test_running_but_not_reloaded_is_partial(self):
        text, code = services.whitelist_outcome("Added", "192.0.2.1/32", "", "controld reload failed: x")
        self.assertEqual(code, 200)
        self.assertIn("reload failed", text)

    def test_neither_is_a_failure(self):
        text, code = services.whitelist_outcome("Added", "192.0.2.1/32", "Unknown ACL", "reload skipped")
        self.assertEqual(code, 502)
        self.assertIn("did not take it", text)

    def test_the_reload_answers_are_read(self):
        for answer in ("controld reload ok: done", "master reload ok", "systemctl reload ok"):
            self.assertTrue(services.reload_ok(answer), answer)
        for answer in ("controld reload failed: x", "master reload error: y", "reload skipped", ""):
            self.assertFalse(services.reload_ok(answer), answer)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheChangeLog(unittest.TestCase):
    def test_a_refusal_is_recorded_as_a_failure(self):
        with mock.patch.object(routes, "record_request") as record:
            routes._record_outcome("ban.lift", IP, ("HAProxy did not lift the ban: x", 502))
            routes._record_outcome("ban.lift", IP, ("OK", 200))
        failed, done = record.call_args_list
        self.assertEqual(failed.kwargs["result"], routes.RESULT_FAILURE)
        self.assertIn("did not lift", failed.kwargs["detail"])
        self.assertEqual(done.kwargs["result"], routes.RESULT_SUCCESS)


if __name__ == "__main__":
    unittest.main()
