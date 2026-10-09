"""A mistyped backup passphrase is asked for again, not treated as the end.

During a real disaster recovery the restore was started from a workstation:
the archive uploaded, the new host prepared, the passphrase asked for -- and
one slip (a passphrase shorter than twelve characters) ended the run. The
only way back was to start from the top, upload and preparation included.

A person at a terminal is now asked again, for as long as it takes, both
when the passphrase is too short and when it does not open the archive.
Nothing changes for a passphrase that is piped in or supplied by the test
environment: that one is the same on every attempt, so it still fails once
rather than looping.
"""

from __future__ import annotations

import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import full_backup  # noqa: E402


GOOD = "correct horse battery"


def typed(*answers):
    """Patch getpass to hand back these answers in order, and count the asks."""
    return mock.patch.object(full_backup.getpass, "getpass", side_effect=list(answers))


def at_a_terminal(yes=True):
    return mock.patch.object(full_backup, "passphrase_is_typed", return_value=yes)


class TypingThePassphrase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(full_backup.os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        full_backup.os.environ.pop("EASY_HA_PROXY_TEST_PASSPHRASE", None)
        self.errors = io.StringIO()
        err = mock.patch.object(full_backup.sys, "stderr", self.errors)
        err.start()
        self.addCleanup(err.stop)

    def test_a_short_one_is_asked_for_again(self):
        # The reported case.
        with at_a_terminal(), typed("short", "stillshort", GOOD) as asked:
            self.assertEqual(full_backup.read_passphrase(confirm=False), GOOD)
        self.assertEqual(asked.call_count, 3)
        self.assertIn("at least 12 characters", self.errors.getvalue())
        self.assertIn("Try again", self.errors.getvalue())

    def test_a_mismatch_when_setting_one_starts_over(self):
        with at_a_terminal(), typed(GOOD, "something else!!", GOOD, GOOD) as asked:
            self.assertEqual(full_backup.read_passphrase(confirm=True), GOOD)
        self.assertEqual(asked.call_count, 4)
        self.assertIn("do not match", self.errors.getvalue())

    def test_without_a_terminal_it_still_fails_once(self):
        with at_a_terminal(False), typed("short", GOOD) as asked:
            with self.assertRaises(full_backup.BackupError):
                full_backup.read_passphrase(confirm=False)
        self.assertEqual(asked.call_count, 1)

    def test_a_piped_passphrase_is_never_asked_for_twice(self):
        with mock.patch.object(full_backup.sys, "stdin", io.StringIO("short\n")):
            with self.assertRaises(full_backup.BackupError):
                full_backup.read_passphrase(confirm=False, from_stdin=True)
        with mock.patch.object(full_backup.sys, "stdin", io.StringIO(GOOD + "\n")):
            self.assertEqual(
                full_backup.read_passphrase(confirm=False, from_stdin=True), GOOD
            )

    def test_who_counts_as_typing(self):
        tty = mock.Mock()
        tty.isatty.return_value = True
        with mock.patch.object(full_backup.sys, "stdin", tty):
            self.assertTrue(full_backup.passphrase_is_typed(False))
            self.assertFalse(full_backup.passphrase_is_typed(True))
            with mock.patch.dict(
                full_backup.os.environ,
                {"EASY_HA_PROXY_TEST_PASSPHRASE": GOOD, "EASY_HA_PROXY_ALLOW_NON_ROOT": "1"},
            ):
                self.assertFalse(full_backup.passphrase_is_typed(False))
        tty.isatty.return_value = False
        with mock.patch.object(full_backup.sys, "stdin", tty):
            self.assertFalse(full_backup.passphrase_is_typed(False))


class OpeningTheArchive(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.archive = self.work / "backup.tar.gz.enc"
        self.errors = io.StringIO()
        err = mock.patch.object(full_backup.sys, "stderr", self.errors)
        err.start()
        self.addCleanup(err.stop)

    def open(self, outcomes, *, terminal=True, answers=("wrong passphrase!", GOOD)):
        def validate(archive, password, work, *, outer_checksum_verified=False):
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                (work / "bundle.tar.gz").write_bytes(b"half decrypted")
                raise outcome
            return outcome

        with (
            at_a_terminal(terminal),
            typed(*answers) as asked,
            mock.patch.object(full_backup, "validate_backup_archive", side_effect=validate),
        ):
            result = full_backup.open_backup_archive(
                self.archive, self.work, from_stdin=False
            )
        return result, asked

    def test_a_wrong_passphrase_is_asked_for_again(self):
        opened = ({"format": "x"}, self.work / "payload.tar.gz", None)
        result, asked = self.open(
            [full_backup.WrongPassphrase("Cannot decrypt backup"), opened]
        )
        self.assertEqual(result, opened)
        self.assertEqual(asked.call_count, 2)
        self.assertIn("does not open this backup", self.errors.getvalue())
        # The failed attempt left nothing behind for the next one to trip on.
        self.assertFalse((self.work / "bundle.tar.gz").exists())

    def test_without_a_terminal_a_wrong_passphrase_ends_it(self):
        with self.assertRaises(full_backup.WrongPassphrase):
            self.open(
                [full_backup.WrongPassphrase("Cannot decrypt backup")],
                terminal=False,
                answers=(GOOD,),
            )

    def test_any_other_fault_in_the_archive_is_not_retried(self):
        with self.assertRaises(full_backup.BackupError) as raised:
            self.open(
                [full_backup.BackupError("Full-backup manifest is missing")],
                answers=(GOOD,),
            )
        self.assertNotIsInstance(raised.exception, full_backup.WrongPassphrase)

    def test_only_a_failed_decryption_is_called_a_wrong_passphrase(self):
        source = (ROOT / "installer/full_backup.py").read_text(encoding="utf-8")
        crypt = source.split("def openssl_crypt(")[1].split("\ndef ")[0]
        self.assertIn("if decrypt:", crypt)
        self.assertIn("raise WrongPassphrase(", crypt)
        for caller in ("def inspect_backup(", "def restore_backup("):
            body = source.split(caller)[1].split("\ndef ")[0]
            self.assertIn("open_backup_archive(", body)


if __name__ == "__main__":
    unittest.main()
