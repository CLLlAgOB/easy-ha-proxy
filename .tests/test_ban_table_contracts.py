"""Manual bans, unbans and table reads: what is said is what is kept (R07-R10).

From the second review on 278f836, reproduced again on a8a17ed, each with
the engine's own methods and a fake runtime table:

- R07: a new manual ban was remembered through the helper meant for what is
  seen in the table, which only ever moves an end later and leaves a
  restored copy alone. With a table that keeps bans for less than the
  default week the end said (4600) and the end kept (605800) differed, and
  a ban placed again after a restore ended early.
- R08: a repeated manual ban HAProxy refused forgot the earlier one, still
  standing in the table, so a restart could not bring it back.
- R09: the panel's unban wrote to HAProxy after the engine had let go of its
  lock; a ban placed by another request in between was undone in HAProxy
  but stayed remembered, and came back after a restart.
- R10: a table read that was not the table (an error text) was taken for
  "no such entry" and an expired ban's schedule dropped while the entry
  stayed; an answer larger than the read bound came back cut short as if
  whole.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))

import test_guardd as base  # noqa: E402
from test_ban_decisions_serialized import FakeTable  # noqa: E402

guardd = base.guardd
IP = "203.0.113.9"


class Engine(base.EnforcementTestCase):
    def setUp(self):
        super().setUp()
        self.fake = FakeTable()
        patcher = mock.patch.object(guardd, "runtime_command", side_effect=self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def restart_haproxy(self, started_at, now):
        """The table starts empty; the engine notices on its next pass."""
        self.fake.rows.clear()
        with mock.patch.object(self.engine.enforcer, "started_at", return_value=started_at):
            self.engine.keep_manual_bans({}, now)

    def seen(self, exp_ms):
        return {IP: {"gpc0": "1", "gpt0": "50", "exp": str(exp_ms)}} if IP in self.fake.rows else {}


class AManualBansEnd(Engine):
    def test_is_the_one_the_table_gave_it_and_holds_through_a_restart(self):
        # The fake table keeps entries for an hour, not the default week.
        answer = self.engine.place_manual_ban(IP, 1000)
        self.assertEqual(answer["until"], 4600)
        self.assertEqual(self.database.manual_bans()[IP]["expires_at"], 4600)
        self.restart_haproxy(started_at=1100, now=1110)
        self.assertEqual(self.fake.rows[IP], (1, 50))  # put back
        self.engine.keep_manual_bans(self.seen(3600 * 1000), 4601)
        self.assertNotIn(IP, self.fake.rows)  # and ends when it was said to
        self.assertNotIn(IP, self.database.manual_bans())

    def test_a_ban_placed_again_after_a_restore_keeps_its_new_end(self):
        week = 604_800_000
        original = self.fake.__call__

        def week_long(socket_path, command):
            return original(socket_path, command).replace("exp=3600000", f"exp={week}")

        guardd.runtime_command.side_effect = week_long
        self.engine.place_manual_ban(IP, 1000)
        self.restart_haproxy(started_at=1100, now=1110)
        self.assertEqual(self.database.manual_bans()[IP]["reasserted"], 1)
        again = self.engine.place_manual_ban(IP, 2000)
        record = self.database.manual_bans()[IP]
        self.assertEqual((record["expires_at"], record["reasserted"]), (again["until"], 0))
        # Past the first ban's end, before the second's: still banned.
        self.engine.keep_manual_bans({IP: {"gpc0": "1", "gpt0": "50", "exp": "999000"}}, 605_801)
        self.assertEqual(self.fake.rows[IP], (1, 50))


class ARefusedManualBan(Engine):
    def test_again_keeps_the_one_already_standing(self):
        self.engine.place_manual_ban(IP, 1000)
        before = self.database.manual_bans()[IP]
        original = guardd.runtime_command.side_effect
        guardd.runtime_command.side_effect = (
            lambda sock, command: "Permission denied\n" if command.startswith("set table ") else original(sock, command)
        )
        with self.assertRaises(guardd.ManualBanRefused):
            self.engine.place_manual_ban(IP, 1010)
        self.assertEqual(self.fake.rows[IP], (1, 50))
        self.assertEqual(self.database.manual_bans()[IP], before)

    def test_the_first_time_remembers_nothing(self):
        original = guardd.runtime_command.side_effect
        guardd.runtime_command.side_effect = (
            lambda sock, command: "Permission denied\n" if command.startswith("set table ") else original(sock, command)
        )
        with self.assertRaises(guardd.ManualBanRefused):
            self.engine.place_manual_ban(IP, 1000)
        self.assertEqual(self.database.manual_bans(), {})

    def test_a_lost_answer_puts_the_earlier_record_back(self):
        self.engine.place_manual_ban(IP, 1000)
        before = self.database.manual_bans()[IP]
        original = guardd.runtime_command.side_effect

        def lost(sock, command):
            if command.startswith("set table "):
                raise ConnectionResetError("lost")
            return original(sock, command)

        guardd.runtime_command.side_effect = lost
        with self.assertRaises(OSError):
            self.engine.place_manual_ban(IP, 1010)
        self.assertEqual(self.database.manual_bans()[IP], before)


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class AnUnbanFromThePanel(Engine):
    def setUp(self):
        super().setUp()
        self.services = importlib.import_module("haproxy_admin.services")
        self.live = importlib.import_module("haproxy_admin.services_live")
        self.client = importlib.import_module("haproxy_admin.guardd_client")

    def test_is_done_by_the_engine_and_the_panel_writes_nothing_after(self):
        self.engine.place_manual_ban(IP, 1000)
        other_ban = {}

        def forget_then_another_request_bans(ip):
            answer = self.engine.forget_ban(ip, 1001)
            # Another operator's request, after the engine let go of its lock.
            other_ban.update(self.live.ban_address(ip, "192.0.2.5"))
            return answer

        with mock.patch.object(self.client, "guardd_forget_ban", side_effect=forget_then_another_request_bans), \
                mock.patch.object(self.client, "guardd_manual_ban",
                                  side_effect=lambda ip: self.engine.place_manual_ban(ip, 1002)), \
                mock.patch.object(self.live, "_networks", return_value=[]), \
                mock.patch.object(self.services, "haproxy_runtime_command") as direct:
            result = self.services.unban_ip(IP)
        self.assertEqual(result, ("OK", 200))
        direct.assert_not_called()
        # The later ban stands, in HAProxy and in the record alike.
        self.assertTrue(other_ban["ok"])
        self.assertEqual(self.fake.rows[IP], (1, 50))
        self.assertIn(IP, self.database.manual_bans())

    def test_the_engine_lifts_any_ban_not_only_its_own(self):
        for code in (50, 20):
            with self.subTest(code=code):
                self.fake.rows[IP] = (1, code)
                answer = self.engine.forget_ban(IP, 1001)
                self.assertTrue(answer["cleared"])
                self.assertEqual(self.fake.rows[IP], (0, code))

    def test_a_refusal_is_the_panels_answer_too(self):
        self.fake.rows[IP] = (1, 50)
        refused = {"ok": True, "cleared": False, "refused": "HAProxy refused to lift the ban on x: denied"}
        with mock.patch.object(self.client, "guardd_forget_ban", return_value=refused), \
                mock.patch.object(self.services, "haproxy_runtime_command") as direct:
            message, status = self.services.unban_ip(IP)
        self.assertEqual(status, 502)
        direct.assert_not_called()

    def test_without_the_engine_the_panel_lifts_it_itself(self):
        with mock.patch.object(self.client, "guardd_forget_ban", side_effect=self.client.GuarddUnavailable("down")), \
                mock.patch.object(self.services, "haproxy_runtime_command", return_value="\n") as direct:
            message, status = self.services.unban_ip(IP)
        self.assertEqual(status, 200)
        self.assertIn("did not answer", message)
        direct.assert_called_once()


class ATableReadThatIsNotTheTable(Engine):
    def test_keeps_an_expired_ban_on_the_schedule(self):
        self.make_hostile(IP)
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        original = guardd.runtime_command.side_effect
        guardd.runtime_command.side_effect = (
            lambda sock, command: "Permission denied\n" if command.startswith("show table tbl_ban key ")
            else original(sock, command)
        )
        self.engine.apply_enforcement(1301)
        self.assertIn(IP, self.database.scheduled_bans())
        guardd.runtime_command.side_effect = original
        self.assertEqual(self.engine.apply_enforcement(1311)["lifted"], [IP])
        self.assertNotIn(IP, self.fake.rows)

    def test_is_left_out_of_the_cycle_not_read_as_empty(self):
        self.engine.place_manual_ban(IP, 1000)
        original = guardd.runtime_command.side_effect

        def broken(sock, command):
            if command == "show table":
                return "# table: tbl_ban, type: ip, size:1000, used:1\n# table: tbl_ip_auth, type: ip, size:1000, used:0\n"
            if command == "show table tbl_ban":
                return "No such table\n"
            if command == "show table tbl_ip_auth":
                return "# table: tbl_ip_auth, type: ip, size:1000, used:0\n"
            return original(sock, command)

        guardd.runtime_command.side_effect = broken
        tables = self.engine.read_tables()
        self.assertNotIn("tbl_ban", tables)
        self.assertEqual(self.engine.unreadable_tables, {"tbl_ban"})
        with mock.patch.object(self.engine.enforcer, "started_at", return_value=5000):
            self.engine.ingest_tables(tables, 1010)
        # Not "the table is empty, so put the manual ban back" or forget it.
        self.assertIn(IP, self.database.manual_bans())
        self.assertEqual(self.engine.health()["unreadable_tables"], ["tbl_ban"])

    def test_a_table_too_large_to_read_still_lets_bans_expire(self):
        # The whole table is beyond the read bound; one entry at a time is
        # not. Expiry goes on; what needs the whole table (new bans, putting
        # back missing ones) waits, and the cycle reports it failed -- which
        # is what raises "adaptive protection is not working".
        self.make_hostile(IP)
        self.engine.set_mode(guardd.MODE_ENFORCE, 1000)
        original = guardd.runtime_command.side_effect

        def huge(sock, command):
            if command == "show table tbl_ban":
                raise guardd.RuntimeAnswerTooLarge("larger than 8 MiB")
            return original(sock, command)

        guardd.runtime_command.side_effect = huge
        with self.assertRaises(guardd.RuntimeAnswerTooLarge):
            self.engine.apply_enforcement(1301)
        self.assertNotIn(IP, self.fake.rows)
        self.assertNotIn(IP, self.database.scheduled_bans())

    def test_the_ban_list_for_the_live_page_says_it_cannot_tell(self):
        guardd.runtime_command.side_effect = lambda sock, command: "No such table\n"
        with self.assertRaises(RuntimeError):
            guardd.banned_now("/run/haproxy/admin.sock")


class AnAnswerTooLargeToRead(unittest.TestCase):
    def test_raises_instead_of_coming_back_cut_short(self):
        rows = 150_000
        lines = [f"# table: tbl_ban, type: ip, size:200000, used:{rows}\n"]
        lines += [f"0x{i + 1:x}: key=10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255} use=0 exp=604800000 "
                  f"shard=0 gpc0=1 gpt0=50\n" for i in range(rows)]
        payload = "".join(lines).encode()
        self.assertGreater(len(payload), guardd.RUNTIME_MAX_BYTES)
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "runtime.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path)
                server.listen(1)

                def answer():
                    with server.accept()[0] as connection:
                        connection.recv(4096)
                        try:
                            connection.sendall(payload)
                        except (BrokenPipeError, ConnectionResetError):
                            pass

                thread = threading.Thread(target=answer, daemon=True)
                thread.start()
                with self.assertRaises(guardd.RuntimeAnswerTooLarge):
                    guardd.read_table(path, "tbl_ban")
                thread.join(5)

    def test_a_whole_answer_within_the_bound_is_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "runtime.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path)
                server.listen(1)

                def answer():
                    with server.accept()[0] as connection:
                        connection.recv(4096)
                        connection.sendall(b"# table: tbl_ban, type: ip, size:10, used:1\n"
                                           b"0x1: key=203.0.113.9 use=0 exp=1000 shard=0 gpc0=1 gpt0=40\n\n")

                thread = threading.Thread(target=answer, daemon=True)
                thread.start()
                self.assertEqual(guardd.read_table(path, "tbl_ban")["203.0.113.9"]["gpt0"], "40")
                thread.join(5)


if __name__ == "__main__":
    unittest.main()
