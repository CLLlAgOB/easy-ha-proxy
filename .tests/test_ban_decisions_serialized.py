"""Unban, re-assert and an operator's ban do not undo each other (F05, F06).

From the 30 October review, reproduced there: the enforcement cycle read
the schedule, an operator's unban then cleared it and lifted the entry, and
the cycle -- still holding the old schedule -- found the entry missing and
put it back: schedule empty, ban standing, and nothing ever lifted it again
(F05). The same re-assert wrote the adaptive code 40 over an operator's
manual ban (50), so the operator's ban ended with the adaptive one (F06).
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_guardd import EngineTestCase, guardd  # noqa: E402

IP = "203.0.113.9"


class FakeTable:
    """tbl_ban as the Runtime API shows and changes it."""

    def __init__(self):
        self.rows = {}
        self.on_show = None

    def __call__(self, socket_path, command):
        match = re.match(r"set table tbl_ban key (\S+) data\.gpc0 (\d+)(?: data\.gpt0 (\d+))?", command)
        if match:
            ip, gpc0, gpt0 = match.groups()
            old = self.rows.get(ip, (0, 0))
            self.rows[ip] = (int(gpc0), int(gpt0) if gpt0 is not None else old[1])
            return "\n"
        match = re.match(r"clear table tbl_ban key (\S+)", command)
        if match:
            self.rows.pop(match.group(1), None)
            return "\n"
        match = re.match(r"show table tbl_ban(?: key (\S+))?$", command)
        if match:
            if match.group(1) is None and self.on_show is not None:
                hook, self.on_show = self.on_show, None
                hook()
            wanted = match.group(1)
            lines = ["# table: tbl_ban, type: ip, size:1000, used:%d" % len(self.rows)]
            for index, (ip, (gpc0, gpt0)) in enumerate(sorted(self.rows.items())):
                if wanted and ip != wanted:
                    continue
                lines.append(f"0x{index + 1:x}: key={ip} use=0 exp=3600000 shard=0 gpc0={gpc0} gpt0={gpt0}")
            return "\n".join(lines) + "\n"
        return "\n"


class Decisions(EngineTestCase):
    def setUp(self):
        super().setUp()
        self.table = FakeTable()
        patcher = mock.patch.object(guardd, "runtime_command", self.table)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engine.enforcer.mode = guardd.MODE_ENFORCE
        self.now = 1_000_000

    def scheduled(self):
        # A banned address is one the engine has seen.
        self.database.observe_ip(IP, self.now, self.engine.exclusions.verdict(IP))
        self.database.set_ban(IP, self.now + 3600, guardd.ADAPTIVE_BAN_CODE, self.now)
        self.assertIn(IP, self.database.scheduled_bans())
        self.table.rows[IP] = (1, guardd.ADAPTIVE_BAN_CODE)

    def test_an_unban_during_the_cycle_is_not_undone(self):
        self.scheduled()
        unbanned = threading.Event()

        def unban():
            self.engine.forget_ban(IP, now=self.now)
            unbanned.set()

        def interleave():
            # The cycle has read the schedule; an operator unbans now.
            threading.Thread(target=unban, daemon=True).start()
            unbanned.wait(0.5)

        self.table.on_show = interleave
        self.engine.apply_enforcement(self.now + 10)
        self.assertTrue(unbanned.wait(5))
        self.assertEqual(self.database.scheduled_bans(), {})
        self.assertNotIn(IP, self.table.rows)  # no orphan ban left in HAProxy

    def test_an_operators_ban_is_not_overwritten_by_the_re_assert(self):
        self.scheduled()
        self.table.rows[IP] = (1, guardd.MANUAL_BAN_CODE)
        self.engine.apply_enforcement(self.now + 10)
        self.assertEqual(self.table.rows[IP], (1, guardd.MANUAL_BAN_CODE))

    def test_an_adaptive_ban_gone_from_the_table_is_re_asserted(self):
        self.scheduled()
        del self.table.rows[IP]
        self.engine.apply_enforcement(self.now + 10)
        self.assertEqual(self.table.rows[IP], (1, guardd.ADAPTIVE_BAN_CODE))

    def test_the_cycle_unban_and_mode_change_share_one_lock(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        for method in ("def apply_enforcement(", "def forget_ban(", "def set_mode("):
            body = source.split(method)[1].split("\n    def ")[0]
            with self.subTest(method=method):
                self.assertIn("with self._decisions:", body)


if __name__ == "__main__":
    unittest.main()
