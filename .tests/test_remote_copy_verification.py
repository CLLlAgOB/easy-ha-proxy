"""A banner is not a checksum.

The gateway proves an off-host copy by asking the far end to hash the file.
A destination restricted to SFTP answers every command with a banner and
exits zero:

    $ ssh backup-host sha256sum -- /upload/archive.enc
    This service allows sftp connections only.
    $ echo $?
    0

The old check read the first word of that as a digest, found it was not the
expected one, and reported "the far end reports different content" -- a
mismatch for a copy that was almost certainly perfect. Two of those were
firing on a production gateway. Worse, an unproven copy is deliberately
never pruned, so the far end would have filled up while the page insisted
the backup had failed.
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
    spec = importlib.util.spec_from_file_location("backupd_verify", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules["backupd_verify"] = module
    spec.loader.exec_module(module)
    return module


backupd = load()

DIGEST = "a" * 64
OTHER = "b" * 64
RECORD = {"name": "oreol", "host": "post.example.test", "port": 2222, "user": "u"}
SFTP_ONLY = b"This service allows sftp connections only.\n"


def ssh_reply(returncode, stdout):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"")


class RemoteHashTests(unittest.TestCase):
    def verify(self, ssh_result, *, size=1024, sftp_result=None, local_digest=None):
        """Drive verify_remote_copy with a far end we control.

        The sftp stand-in creates the file it was asked to fetch, because the
        real code checks the download landed before hashing it -- a mock that
        only returns zero would fail on a path this test is not about.
        """

        def fake_sftp(record, batch):
            reply = sftp_result or ssh_reply(1, b"")
            if reply.returncode == 0:
                local = batch.split('"')[-2]
                Path(local).write_bytes(b"downloaded")
            return reply

        with (
            mock.patch.object(backupd, "run_ssh", return_value=ssh_result),
            mock.patch.object(backupd, "run_sftp", side_effect=fake_sftp),
            mock.patch.object(
                backupd, "sha256_file", return_value=local_digest or OTHER
            ),
        ):
            return backupd.verify_remote_copy(RECORD, "/upload/a.enc", DIGEST, size)

    def test_a_matching_digest_is_accepted(self):
        ok, method, _detail = self.verify(ssh_reply(0, f"{DIGEST}  /upload/a.enc\n".encode()))
        self.assertTrue(ok)
        self.assertEqual(method, "remote-hash")

    def test_a_real_mismatch_is_still_caught(self):
        # The check that matters: a far end that genuinely holds other bytes.
        ok, method, detail = self.verify(ssh_reply(0, f"{OTHER}  /upload/a.enc\n".encode()))
        self.assertFalse(ok)
        self.assertEqual(method, "remote-hash")
        self.assertIn("different content", detail)

    def test_an_sftp_only_banner_is_not_read_as_a_digest(self):
        # The production case. It must fall through to the download check
        # rather than declare a mismatch.
        ok, method, _detail = self.verify(
            ssh_reply(0, SFTP_ONLY),
            sftp_result=ssh_reply(0, b""),
            local_digest=DIGEST,
        )
        self.assertTrue(ok, "a banner was mistaken for a checksum")
        self.assertEqual(method, "download")

    def test_other_chatter_is_ignored_too(self):
        for noise in (
            b"Welcome to the backup server!\n",
            b"bash: sha256sum: command not found\n",
            b"\n",
            b"Last login: Mon Aug 18\n",
        ):
            with self.subTest(noise=noise):
                ok, method, _ = self.verify(
                    ssh_reply(0, noise),
                    sftp_result=ssh_reply(0, b""),
                    local_digest=DIGEST,
                )
                self.assertTrue(ok)
                self.assertEqual(method, "download")

    def test_a_shell_that_cannot_hash_still_falls_back(self):
        ok, method, _ = self.verify(
            ssh_reply(127, b""),
            sftp_result=ssh_reply(0, b""),
            local_digest=DIGEST,
        )
        self.assertTrue(ok)
        self.assertEqual(method, "download")

    def test_an_archive_too_large_to_re_read_is_reported_honestly(self):
        ok, method, detail = self.verify(
            ssh_reply(0, SFTP_ONLY),
            size=backupd.VERIFY_DOWNLOAD_MAX_BYTES + 1,
        )
        self.assertFalse(ok)
        self.assertEqual(method, "none")
        self.assertIn("too large", detail)

    def test_a_download_that_does_not_match_is_a_failure(self):
        ok, method, detail = self.verify(
            ssh_reply(0, SFTP_ONLY),
            sftp_result=ssh_reply(0, b""),
            local_digest=OTHER,
        )
        self.assertFalse(ok)
        self.assertEqual(method, "download")
        self.assertIn("does not match", detail)

    def test_a_download_that_fails_is_a_failure(self):
        ok, method, detail = self.verify(
            ssh_reply(0, SFTP_ONLY),
            sftp_result=ssh_reply(1, b""),
        )
        self.assertFalse(ok)
        self.assertIn("could not be read back", detail)


class DigestShapeTests(unittest.TestCase):
    def test_only_a_sha256_shaped_token_counts(self):
        self.assertTrue(backupd._SHA256_RE.fullmatch(DIGEST))
        for wrong in ("This", "a" * 63, "a" * 65, "A" * 64, "g" * 64, ""):
            with self.subTest(wrong=wrong):
                self.assertIsNone(backupd._SHA256_RE.fullmatch(wrong))


class PruningTests(unittest.TestCase):
    """An unproven copy must never cost the last good one."""

    def test_nothing_is_pruned_when_verification_failed(self):
        source = DAEMON.read_text(encoding="utf-8")
        block = source.split('response["ok"] = False')[1][:400]
        self.assertIn("backup.failed", block)
        # The invariant the comment above it states.
        self.assertIn('"pruned": []', source)


if __name__ == "__main__":
    unittest.main()
