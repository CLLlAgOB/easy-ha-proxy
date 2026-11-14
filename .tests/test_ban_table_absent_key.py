"""A key that is not in the ban table is absent, not an unreadable table.

Found on the test gateway on 12 November: an operator's unban of an address
that was no longer in HAProxy's ban table answered "HAProxy refused" and was
recorded as a failed lift. Asked for one key that is not there, HAProxy 2.8,
3.2 and 3.4 all answer with an empty line and no "# table:" header (checked
against the official images), and the header check added for R10 read that
as a table that could not be read.

The test fake answered an absent key with a header, which no HAProxy does, so
the suite never met the case; it now answers as HAProxy does.

Held here: an empty answer to a single-key lookup is "not there"; a missing
table, a refusal, or an empty answer to a whole-table read are still
unreadable, as R10 requires; and the unban completes.
"""

from __future__ import annotations

from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform != "win32":
    import test_guardd as base
    guardd = base.guardd
else:
    base = guardd = None


def answering(payload: bytes):
    """A one-shot runtime socket that answers every command with `payload`."""
    folder = tempfile.TemporaryDirectory()
    path = str(Path(folder.name) / "runtime.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def answer():
        with server.accept()[0] as connection:
            connection.recv(4096)
            connection.sendall(payload)

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    return folder, server, thread, path


@unittest.skipUnless(guardd, "Linux engine")
class TheReader(unittest.TestCase):
    def read(self, payload, selector=""):
        folder, server, thread, path = answering(payload)
        try:
            return guardd.read_table(path, "tbl_ban", selector)
        finally:
            thread.join(5)
            server.close()
            folder.cleanup()

    def test_an_absent_key_is_an_empty_answer(self):
        self.assertEqual(self.read(b"\n", "key 203.0.113.9"), {})

    def test_a_present_key_is_read(self):
        found = self.read(b"# table: tbl_ban, type: ip, size:10, used:1\n"
                          b"0x1: key=203.0.113.9 use=0 exp=1000 shard=0 gpc0=1 gpt0=40\n\n", "key 203.0.113.9")
        self.assertEqual(found["203.0.113.9"]["gpt0"], "40")

    def test_a_missing_table_is_still_unreadable(self):
        with self.assertRaises(guardd.TableUnreadable):
            self.read(b"No such table\n\n", "key 203.0.113.9")

    def test_an_empty_answer_to_a_whole_table_is_still_unreadable(self):
        with self.assertRaises(guardd.TableUnreadable):
            self.read(b"\n")


# The fixture carries no tests of its own, so inheriting it runs only these.
@unittest.skipUnless(guardd, "Linux engine")
class TheUnban(base.EnforcementTestCase if base else unittest.TestCase):
    def test_an_address_held_only_on_the_schedule_is_let_go_cleanly(self):
        # HAProxy restarted and the entry is gone; the schedule still holds it.
        self.engine._emit("203.0.113.9", guardd.EVENT_SCANNER_DECISIVE, 1_800_000_000 - 60, source="test",
                          category="secrets", detail="/.env", fingerprint="absent-key")
        self.database.set_ban("203.0.113.9", 1_800_000_000 + 3600, guardd.ADAPTIVE_BAN_CODE, 1_800_000_000 - 30)
        self.assertIn("203.0.113.9", self.database.scheduled_bans())
        self.table.clear()
        result = self.engine.forget_ban("203.0.113.9", 1_800_000_000)
        self.assertEqual(result["refused"], "")
        self.assertTrue(result["cleared"])
        self.assertEqual(self.database.scheduled_bans(), {})

    def test_an_address_that_was_never_banned_is_not_a_refusal(self):
        result = self.engine.forget_ban("203.0.113.10", 1_800_000_000)
        self.assertEqual((result["refused"], result["cleared"]), ("", True))

    def test_a_ban_that_is_there_is_still_lifted(self):
        self.table["203.0.113.9"] = {"gpc0": "1", "gpt0": str(guardd.ADAPTIVE_BAN_CODE)}
        result = self.engine.forget_ban("203.0.113.9", 1_800_000_000)
        self.assertTrue(result["lifted"])
        self.assertTrue(result["cleared"])


if __name__ == "__main__":
    unittest.main()
