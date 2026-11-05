"""Changes to the ban table: confirmed, remembered and serialized (R01-R03).

From the 4 November post-implementation review, reproduced there with the
real engine and runtime fixtures:

- R01: a `clear table` HAProxy refused ("Permission denied") was taken for
  a lift. The schedule was dropped and the history said "lifted" while the
  code-40 entry stayed in the table, and no later cycle took it off.
- R02: a ban placed by hand from the panel was written to HAProxy directly
  and remembered only when the engine next saw it in the table. A restart of
  HAProxy in between lost it for good.
- R03: an expiring adaptive ban was read as code 40, the panel wrote a
  manual 50 in between, and the engine's clear took the manual ban off.

Lifting now checks HAProxy's answer, and a refused lift stays on the
schedule to be tried again. A ban by hand is placed by the engine, under
the lock its own changes take, and remembered before "banned" is answered.
A write to the runtime socket by hand, bypassing the engine, is outside
what this can promise.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

import io  # noqa: E402
import json  # noqa: E402

import test_guardd as base  # noqa: E402

guardd = base.guardd


class Handler(guardd.GuardHandler):
    """This module's handler, without a socket: what it would send is kept."""

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
IP = "203.0.113.9"
OTHER = "203.0.113.50"


class Engine(base.EnforcementTestCase):
    def refuse_clears(self, refusal="Permission denied\n"):
        original = guardd.runtime_command.side_effect

        def refusing(socket_path, command):
            if command.startswith("clear table tbl_ban key "):
                self.commands.append(command)
                return refusal
            return original(socket_path, command)

        guardd.runtime_command.side_effect = refusing
        return original

    def decisions(self, ip=IP):
        return [(d["action"], d["source"], d["outcome"])
                for d in reversed(self.database.ban_decisions(ip, limit=50))]


class ARefusedLift(Engine):
    def setUp(self):
        super().setUp()
        self.make_hostile(IP)
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)

    def test_stays_on_the_schedule_and_is_not_written_as_a_lift(self):
        original = self.refuse_clears()
        result = self.engine.apply_enforcement(1301)
        self.assertEqual(result["lifted"], [])
        self.assertIn(IP, self.database.scheduled_bans())
        self.assertEqual(self.table[IP]["gpt0"], "40")
        self.assertNotIn(("lifted", "expiry", "applied"), self.decisions())
        self.assertEqual(self.engine.enforcer.failed, 1)
        # HAProxy works again: the next cycle lifts it, and writes that once.
        guardd.runtime_command.side_effect = original
        self.assertEqual(self.engine.apply_enforcement(1311)["lifted"], [IP])
        self.assertNotIn(IP, self.table)
        self.assertEqual(self.decisions().count(("lifted", "expiry", "applied")), 1)
        self.assertNotIn(IP, self.database.scheduled_bans())

    def test_a_refused_sweep_with_enforcement_off_does_not_stop_the_cycle(self):
        self.refuse_clears()
        self.engine.set_mode(guardd.MODE_MONITOR, 1100)  # lifts everything it can
        self.assertEqual(self.table[IP]["gpt0"], "40")

    def test_an_operators_unban_is_written_as_refused_and_the_schedule_goes(self):
        self.refuse_clears()
        result = self.engine.forget_ban(IP, 1010)
        self.assertIn("Permission denied", result["refused"])
        self.assertNotIn(IP, self.database.scheduled_bans())
        self.assertEqual(self.decisions()[-1], ("lifted", "operator", "failed"))


class OtherLifts(Engine):
    def test_an_old_haproxy_ban_the_new_policy_could_not_lift_is_tried_again(self):
        self.table[OTHER] = {"gpc0": "1", "gpt0": "20"}
        self.engine.ban_policy = guardd.BAN_POLICY_U02
        self.refuse_clears()
        with mock.patch.object(self.engine, "switch_recorded", return_value=True):
            self.engine.ingest_tables({"tbl_ban": {OTHER: {"gpc0": "1", "gpt0": "20", "exp": "1000"}},
                                       "tbl_ip_auth": {}}, 2000)
        self.assertIn(OTHER, self.table)
        self.assertNotIn(("lifted", "policy", "applied"), self.decisions(OTHER))

    def test_a_manual_ban_whose_lift_was_refused_is_not_forgotten(self):
        self.database.note_manual_ban(OTHER, 1000, 1500)
        self.database.mark_manual_reasserted(OTHER)
        self.table[OTHER] = {"gpc0": "1", "gpt0": "50"}
        self.refuse_clears()
        self.engine.ingest_tables({"tbl_ban": {OTHER: {"gpc0": "1", "gpt0": "50", "exp": "100000"}},
                                   "tbl_ip_auth": {}}, 2000)
        self.assertIn(OTHER, self.database.manual_bans())


class ABanByHand(Engine):
    def setUp(self):
        super().setUp()
        # The table keeps a ban by hand for a week, as the shipped default.
        original = guardd.runtime_command.side_effect
        guardd.runtime_command.side_effect = (
            lambda sock, command: original(sock, command).replace(" exp=1 ", " exp=604800000 ")
        )

    def test_is_remembered_before_it_is_answered(self):
        result = self.engine.place_manual_ban(OTHER, 2000)
        self.assertTrue(result["remembered"])
        self.assertEqual(self.table[OTHER]["gpt0"], "50")
        record = self.database.manual_bans()[OTHER]
        # The end said is the end kept (R07): the table's week.
        self.assertEqual(record["expires_at"], result["until"])
        self.assertEqual(result["until"], 2000 + 604800)
        self.assertEqual(self.decisions(OTHER), [("applied", "operator", "applied")])

    def test_comes_back_after_a_restart_before_the_engine_ever_saw_it(self):
        self.engine.place_manual_ban(OTHER, 2000)
        self.table.clear()  # HAProxy restarted before the next poll
        with mock.patch.object(self.engine.enforcer, "started_at", return_value=2005):
            self.engine.ingest_tables({"tbl_ban": {}, "tbl_ip_auth": {}}, 2010)
        self.assertEqual(self.table[OTHER]["gpt0"], "50")
        # Seen at last: still one decision, not a second "applied".
        self.engine.ingest_tables({"tbl_ban": {OTHER: {"gpc0": "1", "gpt0": "50", "exp": "600000"}},
                                   "tbl_ip_auth": {}}, 2020)
        self.assertEqual(self.decisions(OTHER)[0], ("applied", "operator", "applied"))
        self.assertNotIn(("applied", "operator", "applied"), self.decisions(OTHER)[1:])

    def test_a_cycle_that_read_the_table_before_it_does_not_forget_it(self):
        self.engine.place_manual_ban(OTHER, 2000)
        with mock.patch.object(self.engine.enforcer, "started_at", return_value=1000):
            self.engine.ingest_tables({"tbl_ban": {}, "tbl_ip_auth": {}}, 2000)  # read before the ban
        self.assertIn(OTHER, self.database.manual_bans())

    def test_a_refusal_is_said_and_nothing_is_remembered(self):
        original = guardd.runtime_command.side_effect
        guardd.runtime_command.side_effect = (
            lambda socket, command: "No such table\n" if command.startswith("set table") else original(socket, command)
        )
        with self.assertRaises(guardd.ManualBanRefused):
            self.engine.place_manual_ban(OTHER, 2000)
        self.assertNotIn(OTHER, self.database.manual_bans())

    def test_only_an_ipv4_address(self):
        with self.assertRaises(ValueError):
            self.engine.place_manual_ban("2001:db8::1", 2000)

    def test_the_api_needs_the_token(self):
        with mock.patch.object(guardd, "CONTROL_TOKEN", "t"):
            sent = Handler(self.engine, "POST", "/api/v1/guard/ban/manual", {"ip": OTHER}, token="bad").sent
            self.assertEqual(sent[0], 403)
            code, payload = Handler(self.engine, "POST", "/api/v1/guard/ban/manual", {"ip": OTHER}, token="t").sent
        self.assertEqual((code, payload.get("ok"), payload.get("code")), (200, True, 50), payload)


class NoExpiryClearsAManualBan(Engine):
    """R03 as it happens: the engine lifting an expired adaptive ban, and an
    operator banning the same address by hand at that very moment."""

    def test_the_ban_by_hand_waits_and_then_stands(self):
        self.make_hostile(IP)
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        original = guardd.runtime_command.side_effect
        read = threading.Event()
        go_on = threading.Event()

        def slow_after_reading(socket_path, command):
            answer = original(socket_path, command)
            if command == f"show table tbl_ban key {IP}" and threading.current_thread().name == "expiry":
                read.set()          # the engine has read code 40 ...
                go_on.wait(5)       # ... and the operator acts now
            return answer

        guardd.runtime_command.side_effect = slow_after_reading
        expiry = threading.Thread(target=self.engine.apply_enforcement, args=(1301,), name="expiry")
        expiry.start()
        self.assertTrue(read.wait(5))
        placed = {}
        operator = threading.Thread(target=lambda: placed.update(self.engine.place_manual_ban(IP, 1302)))
        operator.start()
        operator.join(0.3)
        self.assertTrue(operator.is_alive(), "the ban by hand must wait for the expiry to finish")
        go_on.set()
        expiry.join(5)
        operator.join(5)
        self.assertEqual(self.table[IP]["gpt0"], "50")
        self.assertIn(IP, self.database.manual_bans())
        self.assertTrue(placed["ok"])


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class ThePanel(unittest.TestCase):
    def setUp(self):
        self.live = importlib.import_module("haproxy_admin.services_live")
        self.client = importlib.import_module("haproxy_admin.guardd_client")

    def ban(self, answer=None, unavailable=False, runtime=""):
        effect = self.client.GuarddUnavailable("down") if unavailable else None
        with mock.patch.object(self.live, "_networks", return_value=[]), \
                mock.patch.object(self.client, "guardd_manual_ban", return_value=answer,
                                  side_effect=effect) as engine, \
                mock.patch.object(self.live, "haproxy_runtime_command", return_value=runtime) as direct:
            return self.live.ban_address(OTHER, "192.0.2.5"), engine, direct

    def test_the_engine_places_it_and_the_panel_does_not_write_itself(self):
        result, engine, direct = self.ban({"ok": True, "remembered": True, "code": 50})
        self.assertTrue(result["ok"])
        self.assertNotIn("note", result)
        engine.assert_called_once_with(OTHER)
        direct.assert_not_called()

    def test_without_the_engine_haproxy_alone_and_it_says_so(self):
        result, _, direct = self.ban(unavailable=True)
        self.assertTrue(result["ok"])
        self.assertIn("will not come back", result["note"])
        direct.assert_called_once()

    def test_a_refusal_comes_through(self):
        result, _, direct = self.ban({"ok": False, "error": "HAProxy refused the ban on 203.0.113.50"})
        self.assertFalse(result["ok"])
        self.assertIn("refused", result["error"])
        direct.assert_not_called()

    def test_not_remembered_is_said(self):
        result, _, _ = self.ban({"ok": True, "remembered": False})
        self.assertIn("could not remember", result["note"])


if __name__ == "__main__":
    unittest.main()
