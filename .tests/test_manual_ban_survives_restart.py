"""An operator's ban outlives a restart of HAProxy (U02, step 04.6g).

The ban table lives in HAProxy's memory. A reload hands it to the new
process; a restart or a reboot starts it empty. guardd put its own bans back
from its schedule, but the operator's (code 50) existed only in the table,
so they were gone after the next restart, and the firewall mirror dropped
them from the kernel a moment later.

guardd now remembers every manual ban it sees, with the end the table gave
it, and puts back one that vanished only if HAProxy started after the ban
was last seen. One that vanished while the same HAProxy kept running was
lifted -- from the panel, or by hand -- and is forgotten: an unban must
never undo itself.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GUARDD_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"


def load_guardd():
    spec = importlib.util.spec_from_file_location("guardd_for_manual_bans", GUARDD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()
T0 = 1_786_000_000
WEEK_MS = 7 * 86400 * 1000
IP = "203.0.113.50"


class Gateway(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        log = root / "haproxy.log"
        log.write_text("", encoding="utf-8")
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(guardd.GuardConfig(log_file=str(log)), self.database)
        self.engine.enforcer.mode = guardd.MODE_MONITOR  # not an adaptive decision
        self.started = T0 - 3600
        self.table = {}
        self.commands = []

    def runtime(self, socket_path, command):
        self.commands.append(command)
        if command == "show info":
            return f"Name: HAProxy\nStart_time_sec: {self.started}\nUptime_sec: 1\n"
        if command.startswith("show table tbl_ban key "):
            ip = command.rsplit(" ", 1)[1]
            return self.dump({ip: self.table[ip]} if ip in self.table else {})
        if command.startswith("set table tbl_ban key "):
            parts = command.split()
            self.table[parts[4]] = {"gpc0": parts[6], "gpt0": parts[8], "exp": str(WEEK_MS)}
        if command.startswith("clear table tbl_ban key "):
            self.table.pop(command.rsplit(" ", 1)[1], None)
        return ""

    @staticmethod
    def dump(rows):
        lines = ["# table: tbl_ban, type: ip, size:204800, used:%d" % len(rows)]
        for index, (ip, fields) in enumerate(sorted(rows.items())):
            lines.append(f"0x{index + 1}: key={ip} use=0 exp={fields['exp']} "
                         f"gpt0={fields['gpt0']} gpc0={fields['gpc0']}")
        return "\n".join(lines) + "\n"

    def poll(self, now):
        with mock.patch.object(guardd, "runtime_command", side_effect=self.runtime):
            self.engine.ingest_tables({"tbl_ban": guardd.parse_table(self.dump(self.table)),
                                       "tbl_ip_auth": {}}, now)

    def ban_by_hand(self, ip=IP, exp_ms=WEEK_MS):
        self.table[ip] = {"gpc0": "1", "gpt0": "50", "exp": str(exp_ms)}


class AManualBan(Gateway):
    def test_is_remembered_with_the_end_the_table_gave_it(self):
        self.ban_by_hand(exp_ms=3600 * 1000)
        self.poll(T0)
        record = self.database.manual_bans()[IP]
        self.assertEqual((record["expires_at"], record["seen_at"]), (T0 + 3600, T0))

    def test_comes_back_after_a_restart(self):
        self.ban_by_hand()
        self.poll(T0)
        self.table.clear()           # HAProxy restarted: the table starts empty
        self.started = T0 + 5
        self.poll(T0 + 10)
        self.assertEqual(self.table[IP]["gpt0"], "50")
        self.assertEqual(self.engine.health()["manual_bans"]["restored"], 1)

    def test_comes_back_even_in_monitor_mode(self):
        self.assertFalse(self.engine.enforcer.allowed)
        self.ban_by_hand()
        self.poll(T0)
        self.table.clear()
        self.started = T0 + 5
        self.poll(T0 + 10)
        self.assertIn(IP, self.table)

    def test_lifted_while_haproxy_kept_running_stays_lifted(self):
        self.ban_by_hand()
        self.poll(T0)
        self.table.clear()           # lifted by hand on the socket; no restart
        self.poll(T0 + 10)
        self.assertNotIn(IP, self.table)
        self.assertNotIn(IP, self.database.manual_bans())
        self.started = T0 + 20       # a restart later must not bring it back
        self.poll(T0 + 30)
        self.assertNotIn(IP, self.table)

    def test_an_unban_from_the_panel_is_never_undone(self):
        self.ban_by_hand()
        self.poll(T0)
        with mock.patch.object(guardd, "runtime_command", side_effect=self.runtime):
            self.engine.forget_ban(IP, T0 + 5)
        self.table.clear()
        self.started = T0 + 6        # and HAProxy restarted straight after
        self.poll(T0 + 10)
        self.assertNotIn(IP, self.table)

    def test_ends_when_the_operator_s_ban_would_have(self):
        self.ban_by_hand(exp_ms=600 * 1000)
        self.poll(T0)
        self.table.clear()
        self.started = T0 + 5
        self.poll(T0 + 10)           # put back, with a fresh week in the table
        self.assertIn(IP, self.table)
        self.poll(T0 + 300)          # its fresh expiry must not extend it
        self.assertEqual(self.database.manual_bans()[IP]["expires_at"], T0 + 600)
        self.poll(T0 + 601)
        self.assertNotIn(IP, self.table)
        self.assertNotIn(IP, self.database.manual_bans())

    def test_placed_again_by_hand_the_new_end_counts(self):
        self.ban_by_hand(exp_ms=600 * 1000)
        self.poll(T0)
        self.ban_by_hand(exp_ms=WEEK_MS)   # the operator bans it again
        self.poll(T0 + 300)
        self.assertEqual(self.database.manual_bans()[IP]["expires_at"], T0 + 300 + WEEK_MS // 1000)

    def test_when_the_start_time_cannot_be_read_nothing_is_decided(self):
        self.ban_by_hand()
        self.poll(T0)
        self.table.clear()
        self.started = 0
        original = self.runtime

        def no_info(socket_path, command):
            if command == "show info":
                return "Name: HAProxy\n"
            return original(socket_path, command)

        self.runtime = no_info
        self.poll(T0 + 10)
        self.assertNotIn(IP, self.table)
        self.assertIn(IP, self.database.manual_bans())

    def test_other_bans_are_not_its_business(self):
        self.table["203.0.113.40"] = {"gpc0": "1", "gpt0": "40", "exp": str(WEEK_MS)}
        self.table["203.0.113.10"] = {"gpc0": "1", "gpt0": "10", "exp": str(WEEK_MS)}
        self.poll(T0)
        self.assertEqual(self.database.manual_bans(), {})


if __name__ == "__main__":
    unittest.main()
