"""Choosing how hard to work at proving an off-host copy arrived.

A destination restricted to SFTP cannot hash a file for us, so the gateway
falls back to reading the copy back and hashing it here. That is exact, and
it costs the whole transfer a second time plus room on this disk for the
archive to land in -- on a small gateway with a large archive, the second
part is what fails.

`verify: transfer` accepts what sftp reports instead. It is weaker and it is
chosen deliberately, which is why it is a stored setting rather than a
fallback the daemon picks on its own: the checksum file still travels beside
the archive, so a restore can prove the contents later, but nothing proves
them at upload time.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-backupd.py"
)


def load():
    spec = importlib.util.spec_from_file_location("backupd_verify_mode", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules["backupd_verify_mode"] = module
    spec.loader.exec_module(module)
    return module


backupd = load()
DIGEST = "a" * 64
SFTP_ONLY = b"This service allows sftp connections only.\n"


class ModeParsingTests(unittest.TestCase):
    def test_the_two_modes_are_accepted(self):
        self.assertEqual(backupd.verify_mode("auto"), "auto")
        self.assertEqual(backupd.verify_mode("transfer"), "transfer")

    def test_case_and_padding_do_not_matter(self):
        self.assertEqual(backupd.verify_mode("  TRANSFER "), "transfer")

    def test_nothing_supplied_means_the_careful_one(self):
        # The safe default: a destination says nothing, it gets verified.
        self.assertEqual(backupd.verify_mode(None), "auto")
        self.assertEqual(backupd.verify_mode(""), "auto")

    def test_an_existing_choice_is_kept_when_nothing_is_sent(self):
        # Editing a destination without touching this field must not quietly
        # tighten it back to auto.
        self.assertEqual(
            backupd.verify_mode(None, default="transfer"), "transfer"
        )

    def test_anything_else_is_refused_rather_than_guessed(self):
        for wrong in ("none", "off", "skip", "yes", "1"):
            with self.subTest(wrong=wrong):
                with self.assertRaises(backupd.BackupdError):
                    backupd.verify_mode(wrong)


class BehaviourTests(unittest.TestCase):
    def verify(self, mode, ssh_returncode=0, ssh_stdout=SFTP_ONLY):
        record = {"name": "oreol", "host": "h", "port": 22, "user": "u"}
        if mode is not None:
            record["verify"] = mode
        ssh = subprocess.CompletedProcess([], ssh_returncode, stdout=ssh_stdout, stderr=b"")

        def fake_sftp(_record, batch):
            # The real code checks the download landed before hashing it, so
            # a stand-in that only returns zero fails on a different path.
            Path(batch.split('"')[-2]).write_bytes(b"downloaded")
            return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

        with (
            mock.patch.object(backupd, "run_ssh", return_value=ssh) as ssh_call,
            mock.patch.object(
                backupd, "run_sftp", side_effect=fake_sftp
            ) as sftp_call,
            mock.patch.object(backupd, "sha256_file", return_value=DIGEST),
        ):
            result = backupd.verify_remote_copy(record, "/upload/a.enc", DIGEST, 1024)
        return result, ssh_call, sftp_call

    def test_transfer_mode_reads_nothing_back(self):
        (ok, method, detail), ssh_call, sftp_call = self.verify("transfer")
        self.assertTrue(ok)
        self.assertEqual(method, "transfer")
        self.assertEqual(detail, "")
        # The whole point: no second transfer, and no shell round trip either.
        sftp_call.assert_not_called()
        ssh_call.assert_not_called()

    def test_auto_still_reads_it_back(self):
        (ok, method, _), _ssh, sftp_call = self.verify("auto")
        self.assertTrue(ok)
        self.assertEqual(method, "download")
        sftp_call.assert_called_once()

    def test_a_destination_with_no_setting_behaves_as_before(self):
        (_ok, method, _), _ssh, sftp_call = self.verify(None)
        self.assertEqual(method, "download")
        sftp_call.assert_called_once()

    def test_a_far_end_that_can_hash_is_still_asked_first(self):
        (ok, method, _), ssh_call, sftp_call = self.verify(
            "auto", ssh_stdout=f"{DIGEST}  /upload/a.enc\n".encode()
        )
        self.assertTrue(ok)
        self.assertEqual(method, "remote-hash")
        ssh_call.assert_called_once()
        sftp_call.assert_not_called()

    def test_transfer_mode_does_not_disable_the_hash_for_others(self):
        # One destination choosing it must not change another's behaviour.
        self.verify("transfer")
        (_ok, method, _), _ssh, _sftp = self.verify("auto")
        self.assertEqual(method, "download")


class PlumbingTests(unittest.TestCase):
    def setUp(self):
        self.daemon = DAEMON.read_text(encoding="utf-8")
        self.routes = (
            ROOT / "docker" / "app" / "haproxy_admin" / "routes_backup.py"
        ).read_text(encoding="utf-8")
        self.page = (
            ROOT / "docker" / "app" / "haproxy_admin" / "templates"
            / "system_backups.html"
        ).read_text(encoding="utf-8")
        self.script = (
            ROOT / "docker" / "app" / "haproxy_admin" / "static" / "js"
            / "backup_destinations.js"
        ).read_text(encoding="utf-8")

    def test_the_daemon_accepts_and_stores_it(self):
        self.assertIn('"allow_insecure", "verify",', self.daemon)
        self.assertIn('"verify": verify_mode(request.get("verify")', self.daemon)

    def test_the_daemon_reports_it_back(self):
        # Or the page could not show what a destination is set to.
        self.assertIn('"verify": verify_mode(record.get("verify")', self.daemon)

    def test_the_route_passes_it_through(self):
        block = self.routes.split("def save_destination_view")[1]
        self.assertEqual(block.count('"verify"'), 2, "allow-list and copy list")

    def test_the_page_offers_both_choices(self):
        self.assertIn('id="dest-verify"', self.page)
        self.assertIn('value="auto"', self.page)
        self.assertIn('value="transfer"', self.page)

    def test_the_script_sends_and_restores_it(self):
        self.assertIn('body.verify = byId("dest-verify").value;', self.script)
        self.assertIn('byId("dest-verify").value = destination.verify', self.script)


if __name__ == "__main__":
    unittest.main()
