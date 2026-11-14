"""A log file being written to must not decide whether the backup works.

One backup finished at 17:58 and the next died at 22:56 on the same file
set, minutes apart, with:

    Command '['tar', ...]' returned non-zero exit status 1.

Rehearsing the identical command on the same gateway afterwards exited 0.
Nothing was wrong with the file list: tar exits 1 when a file changed while
it was being read, and this gateway appends to haproxy.log several times a
second. Treating that as failure makes the backup a coin toss.

tar's exit codes say it plainly -- 0 fine, 1 some files differ, 2 fatal --
and the message it printed was thrown away, so the operator saw an exit
status and a hundred-path command line and could not tell which it was.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "installer" / "full_backup.py"


def load():
    spec = importlib.util.spec_from_file_location("full_backup_tar", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["full_backup_tar"] = module
    spec.loader.exec_module(module)
    return module


backup = load()

CHANGED = "tar: var/log/haproxy.log: file changed as we read it\n"
SOCKET = "tar: var/lib/haproxy/dev/log: socket ignored\n"
FATAL = "tar: etc/haproxy: Cannot open: Permission denied\n"


class ExitCodeTests(unittest.TestCase):
    def payload(self, returncode, stderr):
        with (
            mock.patch.object(
                backup,
                "run",
                return_value=subprocess.CompletedProcess(
                    [], returncode, stdout="", stderr=stderr
                ),
            ),
            mock.patch.object(backup.os, "chmod"),
        ):
            return backup.create_payload(Path("/tmp/payload.tar.gz"), ["etc/haproxy"])

    def test_a_clean_run_returns_nothing_to_report(self):
        self.assertEqual(self.payload(0, ""), [])

    def test_a_socket_warning_is_kept_but_not_fatal(self):
        # tar says this on every run of this gateway; it has never been a
        # problem and must not become one.
        self.assertEqual(self.payload(0, SOCKET), [SOCKET.strip()])

    def test_a_file_that_changed_underneath_tar_is_not_a_failure(self):
        warnings = self.payload(1, CHANGED)
        self.assertEqual(warnings, [CHANGED.strip()])

    def test_several_warnings_all_survive(self):
        warnings = self.payload(1, SOCKET + CHANGED)
        self.assertEqual(len(warnings), 2)
        self.assertIn("socket ignored", warnings[0])
        self.assertIn("file changed", warnings[1])

    def test_a_fatal_exit_is_still_a_failure(self):
        with self.assertRaises(backup.BackupError) as caught:
            self.payload(2, FATAL)
        message = str(caught.exception)
        self.assertIn("exit code 2", message)
        # And it now carries what tar actually said, which is the whole point.
        self.assertIn("Permission denied", message)

    def test_a_fatal_exit_with_no_output_still_says_something(self):
        with self.assertRaises(backup.BackupError) as caught:
            self.payload(2, "")
        self.assertIn("no reason", str(caught.exception))

    def test_an_empty_path_list_is_refused_before_tar_runs(self):
        with self.assertRaises(backup.BackupError):
            backup.create_payload(Path("/tmp/x.tar.gz"), [])


class InvocationTests(unittest.TestCase):
    def test_tar_is_asked_for_its_output_and_not_checked_by_subprocess(self):
        with (
            mock.patch.object(
                backup,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ) as runner,
            mock.patch.object(backup.os, "chmod"),
        ):
            backup.create_payload(Path("/tmp/payload.tar.gz"), ["etc/haproxy"])
        kwargs = runner.call_args.kwargs
        # check=False, or subprocess raises before the exit code can be read;
        # capture=True, or there is nothing to put in the message.
        self.assertIs(kwargs["check"], False)
        self.assertIs(kwargs["capture"], True)

    def test_the_archive_is_still_made_root_only(self):
        with (
            mock.patch.object(
                backup,
                "run",
                return_value=subprocess.CompletedProcess([], 1, stdout="", stderr=CHANGED),
            ),
            mock.patch.object(backup.os, "chmod") as chmod,
        ):
            backup.create_payload(Path("/tmp/payload.tar.gz"), ["etc/haproxy"])
        # Even on the warning path: a readable backup payload is a leak.
        self.assertEqual(chmod.call_args.args[1], 0o600)

    def test_a_fatal_run_does_not_chmod_a_file_it_did_not_finish(self):
        with (
            mock.patch.object(
                backup,
                "run",
                return_value=subprocess.CompletedProcess([], 2, stdout="", stderr=FATAL),
            ),
            mock.patch.object(backup.os, "chmod") as chmod,
        ):
            with self.assertRaises(backup.BackupError):
                backup.create_payload(Path("/tmp/payload.tar.gz"), ["etc/haproxy"])
        chmod.assert_not_called()


class ManifestTests(unittest.TestCase):
    def test_the_warnings_are_recorded_for_a_restore_to_see(self):
        source = HELPER.read_text(encoding="utf-8")
        self.assertIn('"payload_warnings": payload_warnings', source)

    def test_the_ssh_payload_warnings_are_collected_too(self):
        source = HELPER.read_text(encoding="utf-8")
        self.assertIn("payload_warnings += create_payload(ssh_payload, ssh)", source)


if __name__ == "__main__":
    unittest.main()
