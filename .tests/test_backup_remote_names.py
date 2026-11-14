"""Off-host copies carry dated names, so the far end's retention can work.

A destination configured to keep seven daily, four weekly and six monthly
copies held a hundred files after seven weeks: every copy ever made, each
with its checksum. On the gateway an archive is named after its id alone --
"6e4a...41.tar.gz.enc" -- and that name went off-host unchanged. Retention
groups copies by the date in their names and considers only easy-ha-proxy-*
files, so it recognised none of them and pruned nothing, on every
destination. The tests that covered it used a hand-written dated name that
the real code never produced.

Copies now go up as easy-ha-proxy-YYYYMMDD-HHMMSS-<id>.tar.gz.enc, with a
checksum that names that file. Files of any other name in the folder --
earlier undated copies, or a certificate someone keeps there -- are never
touched by retention.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_backupd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
    spec = importlib.util.spec_from_file_location("backupd_remote_names", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backupd = load_backupd()
REAL_SAFE_FILE = backupd.safe_regular_file
BACKUP_ID = "6e4a07ac3316440b852ad70977473241"
CREATED = "2026-10-05T00:38:17+00:00"
DATED = f"easy-ha-proxy-20261005-003817-{BACKUP_ID}.tar.gz.enc"


def as_test_user(path, *, expected_uid, maximum_size):
    if expected_uid == 0:
        expected_uid = os.getuid()
    return REAL_SAFE_FILE(path, expected_uid=expected_uid, maximum_size=maximum_size)


class Gateway(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.backups = base / "backups"
        self.backups.mkdir()
        for name, value in (
            ("BACKUPS_DIR", self.backups),
            ("DESTINATIONS_DIR", base / "dest"),
            ("safe_regular_file", as_test_user),
        ):
            patcher = mock.patch.object(backupd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Named the way the gateway really names them.
        body = b"encrypted archive" * 64
        self.digest = hashlib.sha256(body).hexdigest()
        archive = self.backups / f"{BACKUP_ID}{backupd.ARCHIVE_SUFFIX}"
        archive.write_bytes(body)
        (self.backups / f"{BACKUP_ID}{backupd.CHECKSUM_SUFFIX}").write_text(
            f"{self.digest}  {archive.name}\n", encoding="ascii"
        )
        (self.backups / f"{BACKUP_ID}{backupd.META_SUFFIX}").write_text(
            json.dumps({"id": BACKUP_ID, "size_bytes": len(body),
                        "sha256": self.digest, "created_at": CREATED}),
            encoding="utf-8",
        )
        self.archive = archive


class TheRemoteName(Gateway):
    def test_it_carries_the_date_the_backup_was_made(self):
        self.assertEqual(backupd.remote_archive_name(BACKUP_ID, self.archive), DATED)

    def test_without_a_record_the_file_time_is_used(self):
        (self.backups / f"{BACKUP_ID}{backupd.META_SUFFIX}").unlink()
        stamp = dt.datetime(2026, 9, 1, 3, 20, 5, tzinfo=dt.timezone.utc).timestamp()
        os.utime(self.archive, (stamp, stamp))
        self.assertEqual(
            backupd.remote_archive_name(BACKUP_ID, self.archive),
            f"easy-ha-proxy-20260901-032005-{BACKUP_ID}.tar.gz.enc",
        )

    def test_retention_recognises_it(self):
        # The reported fault: the real name was never a candidate.
        self.assertEqual(backupd.retention_victims([self.archive.name], {"keep_daily": 0}), [])
        names = [
            f"easy-ha-proxy-202608{day:02d}-032000-{BACKUP_ID}.tar.gz.enc"
            for day in range(1, 31)
        ]
        victims = backupd.retention_victims(
            names, {"keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6}
        )
        self.assertTrue(victims)
        self.assertLess(len(names) - len(victims), 7 + 4 + 6 + 1)


class TheSftpCopy(Gateway):
    def setUp(self):
        super().setUp()
        backupd.DESTINATIONS_DIR.mkdir()
        backupd.save_destination({
            "action": "destination_save", "name": "offsite", "type": "sftp",
            "host": "backup.example.test", "port": 2222, "user": "gateway",
            "path": "/upload", "verify": "transfer",
            "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6,
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----",
            "host_key": "backup.example.test ssh-ed25519 AAAAC3Nz",
        })
        # The far end as it was found: undated copies from before the fix,
        # a certificate and its thumbprint, and thirty dated nightly copies.
        self.dated = [
            f"easy-ha-proxy-202609{day:02d}-032000-{'a' * 32}.tar.gz.enc"
            for day in range(1, 31)
        ]
        self.others = [
            f"{'b' * 32}.tar.gz.enc",
            f"{'b' * 32}.tar.gz.enc.sha256",
            "gateway.pfx",
            "gateway.thumbprint.txt",
        ]
        self.batches: list[str] = []
        self.checksum_sent = b""

    def sftp(self, record, batch):
        self.batches.append(batch)
        if batch.startswith("ls -1"):
            listing = "\n".join(
                f"/upload/{name}" for name in self.others + self.dated + [DATED]
            )
            return mock.Mock(returncode=0, stdout=listing.encode(), stderr=b"")
        for line in batch.splitlines():
            if line.startswith("put ") and ".sha256" in line:
                source = line.split('"')[1]
                self.checksum_sent = Path(source).read_bytes()
        return mock.Mock(returncode=0, stdout=b"", stderr=b"")

    def upload(self):
        with mock.patch.object(backupd, "run_sftp", side_effect=self.sftp):
            return backupd.upload_backup(
                {"action": "upload", "backup_id": BACKUP_ID, "destination": "offsite"}
            )

    def test_the_copy_lands_under_its_dated_name_with_a_matching_checksum(self):
        self.upload()
        first = self.batches[0]
        self.assertIn(f'rename "/upload/{DATED}.part" "/upload/{DATED}"', first)
        self.assertIn(f'"/upload/{DATED}.sha256"', first)
        self.assertEqual(self.checksum_sent, f"{self.digest}  {DATED}\n".encode())

    def test_old_dated_copies_are_pruned_and_nothing_else_is_touched(self):
        result = self.upload()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["pruned"])
        prune = self.batches[-1]
        for name in self.others:
            self.assertNotIn(name, prune)
        self.assertNotIn(DATED, prune)
        for name in result["pruned"]:
            self.assertIn(f'-rm "/upload/{name}"', prune)
            self.assertIn(f'-rm "/upload/{name}.sha256"', prune)
        kept = len(self.dated) + 1 - len(result["pruned"])
        self.assertLessEqual(kept, 7 + 4 + 6)


class TheS3Copy(Gateway):
    def test_objects_get_the_dated_name_too(self):
        keys = []

        def request(record, method, key=None, **kwargs):
            keys.append((method, key))
            return 200, {}, b""

        with mock.patch.object(backupd, "s3_request", side_effect=request):
            backupd.s3_upload({}, self.archive, DATED, self.digest)
        self.assertEqual(keys, [("PUT", DATED), ("PUT", DATED + ".sha256")])


if __name__ == "__main__":
    unittest.main()
