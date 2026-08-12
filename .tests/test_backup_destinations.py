"""Regression checks for off-host copies of the disaster-recovery archive.

Most of this is about the two rules that make an off-host copy safe: the far
end is the one the operator pinned, and nothing old is deleted until the new
copy is proven.
"""

from __future__ import annotations

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
    spec = importlib.util.spec_from_file_location("backupd_destinations", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backupd = load_backupd()


class DestinationTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = mock.patch.object(
            backupd, "DESTINATIONS_DIR", Path(self.directory.name) / "dest"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def save(self, **overrides):
        payload = {
            "action": "destination_save",
            "name": "offsite",
            "type": "sftp",
            "host": "backup.example.test",
            "port": 22,
            "user": "gateway",
            "path": "/srv/backups/gw",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----",
            "host_key": "backup.example.test ssh-ed25519 AAAAC3Nz",
        }
        payload.update(overrides)
        return backupd.save_destination(payload)


class ProfileTests(DestinationTestCase):
    def test_the_profile_and_its_key_are_root_only(self):
        self.save()
        for name in ("offsite.json", "offsite.key", "offsite.known_hosts"):
            path = backupd.DESTINATIONS_DIR / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, name)
        self.assertEqual(backupd.DESTINATIONS_DIR.stat().st_mode & 0o777, 0o700)

    def test_the_key_never_comes_back(self):
        self.save()
        listing = backupd.list_destinations({"action": "destinations"})
        blob = json.dumps(listing)
        self.assertNotIn("PRIVATE KEY", blob)
        self.assertNotIn("AAAAC3Nz", blob)
        self.assertTrue(listing["destinations"][0]["has_key"])
        self.assertTrue(listing["destinations"][0]["host_key_pinned"])

    def test_a_destination_without_a_pinned_host_key_is_refused(self):
        # Accepting whatever answers would hand the archive to whoever can
        # answer on that address.
        with self.assertRaises(backupd.BackupdError) as caught:
            self.save(host_key="")
        self.assertIn("host key", str(caught.exception))

    def test_a_destination_without_a_key_is_refused(self):
        with self.assertRaises(backupd.BackupdError):
            self.save(private_key="")

    def test_a_second_save_may_keep_the_stored_key(self):
        self.save()
        self.save(private_key="", host_key="", path="/srv/backups/other")
        record = backupd.load_destination("offsite")
        self.assertEqual(record["path"], "/srv/backups/other")
        self.assertTrue((backupd.DESTINATIONS_DIR / "offsite.key").is_file())

    def test_a_hostile_name_cannot_escape_the_directory(self):
        for hostile in ("../../etc/passwd", "..", "", "with space", "-lead", "a" * 60):
            with self.assertRaises(backupd.BackupdError, msg=hostile):
                backupd.destination_path(hostile)

    def test_the_name_is_case_insensitive(self):
        # The file on disk is lowercase, so a name typed either way has to
        # resolve to the same profile rather than to a missing one.
        self.assertEqual(
            backupd.destination_path("OffSite").name,
            backupd.destination_path("offsite").name,
        )

    def test_a_relative_or_traversing_remote_path_is_refused(self):
        for hostile in ("srv/backups", "/srv/../etc", ""):
            with self.assertRaises(backupd.BackupdError, msg=hostile):
                self.save(path=hostile)

    def test_a_retention_count_of_zero_is_stored_as_zero(self):
        # A live upload kept everything because "or" read a deliberate 0 as
        # "not supplied" and put the default back.
        self.save(keep_daily=1, keep_weekly=0, keep_monthly=0)
        record = backupd.load_destination("offsite")
        self.assertEqual(record["keep_daily"], 1)
        self.assertEqual(record["keep_weekly"], 0)
        self.assertEqual(record["keep_monthly"], 0)

    def test_an_absent_retention_count_falls_back_to_the_default(self):
        self.save()
        record = backupd.load_destination("offsite")
        self.assertEqual(record["keep_daily"], 7)
        self.assertEqual(record["keep_weekly"], 4)
        self.assertEqual(record["keep_monthly"], 6)

    def test_zero_retention_actually_prunes(self):
        self.save(keep_daily=1, keep_weekly=0, keep_monthly=0)
        record = backupd.load_destination("offsite")
        names = [
            "easy-ha-proxy-20260101-120000.tar.gz.enc",
            "easy-ha-proxy-20260812-120000.tar.gz.enc",
        ]
        self.assertEqual(backupd.retention_victims(names, record), [names[0]])

    def test_deleting_removes_the_key_too(self):
        self.save()
        backupd.delete_destination({"action": "destination_delete", "name": "offsite"})
        for name in ("offsite.json", "offsite.key", "offsite.known_hosts"):
            self.assertFalse((backupd.DESTINATIONS_DIR / name).exists(), name)


class TransportTests(DestinationTestCase):
    def test_the_client_is_told_to_verify_the_host_key(self):
        self.save()
        record = backupd.load_destination("offsite")
        command = backupd.sftp_base_command(record, "/usr/bin/sftp")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertTrue(
            any(str(backupd.destination_known_hosts("offsite")) in part for part in command)
        )
        self.assertNotIn("StrictHostKeyChecking=no", " ".join(command))

    def test_a_path_with_a_space_survives_the_batch_language(self):
        quoted = backupd.remote_quote("/srv/my backups/gw")
        self.assertTrue(quoted.startswith('"') and quoted.endswith('"'))
        self.assertIn("my backups", quoted)

    def test_a_quote_in_a_path_cannot_end_the_argument(self):
        self.assertEqual(backupd.remote_quote('a"b'), '"a\\"b"')


class RetentionTests(unittest.TestCase):
    POLICY = {"keep_daily": 2, "keep_weekly": 2, "keep_monthly": 2}

    def names(self, *dates):
        return [f"easy-ha-proxy-{value}-120000.tar.gz.enc" for value in dates]

    def test_the_most_recent_days_are_kept(self):
        names = self.names("20260810", "20260811", "20260812")
        victims = backupd.retention_victims(names, self.POLICY)
        self.assertNotIn(self.names("20260812")[0], victims)
        self.assertNotIn(self.names("20260811")[0], victims)

    def test_older_archives_are_thinned_but_not_erased(self):
        names = self.names(
            "20260601", "20260701", "20260801", "20260805", "20260812"
        )
        kept = set(names) - set(backupd.retention_victims(names, self.POLICY))
        self.assertIn(self.names("20260812")[0], kept)
        # Something older survives as a weekly or monthly rather than all of
        # it disappearing at once.
        self.assertGreater(len(kept), 2)

    def test_nothing_is_kept_when_the_policy_says_nothing(self):
        names = self.names("20260811", "20260812")
        victims = backupd.retention_victims(
            names, {"keep_daily": 0, "keep_weekly": 0, "keep_monthly": 0}
        )
        self.assertEqual(sorted(victims), sorted(names))

    def test_a_file_that_is_not_ours_is_ignored(self):
        victims = backupd.retention_victims(["someone-elses-file.tar.gz.enc"], self.POLICY)
        self.assertEqual(victims, ["someone-elses-file.tar.gz.enc"])


class UploadTests(DestinationTestCase):
    def setUp(self):
        super().setUp()
        self.save()
        self.spool = Path(self.directory.name) / "backups"
        self.spool.mkdir()
        self.archive = self.spool / "easy-ha-proxy-20260812-120000.tar.gz.enc"
        self.archive.write_bytes(b"encrypted-bytes")
        self.digest = backupd.sha256_file(self.archive)
        patchers = (
            mock.patch.object(
                backupd, "backup_archive_path", lambda _id: self.archive
            ),
            mock.patch.object(
                backupd,
                "backup_checksum_path",
                lambda _id: self.spool / "absent.sha256",
            ),
        )
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_upload(self, sftp, ssh):
        with (
            mock.patch.object(backupd, "run_sftp", side_effect=sftp),
            mock.patch.object(backupd, "run_ssh", side_effect=ssh),
        ):
            return backupd.upload_backup(
                {
                    "action": "upload",
                    "backup_id": "0" * 32,
                    "destination": "offsite",
                }
            )

    def test_the_archive_lands_under_a_temporary_name_first(self):
        calls = []

        def sftp(record, batch):
            calls.append(batch)
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        def ssh(record, command):
            return mock.Mock(returncode=0, stdout=f"{self.digest}  x".encode(), stderr=b"")

        self.run_upload(sftp, ssh)
        # An interrupted transfer must not look like a finished backup to
        # whatever prunes next.
        self.assertIn(".part", calls[0])
        self.assertIn("rename", calls[0])

    def test_a_verified_copy_allows_pruning(self):
        listing = "\n".join(
            f"easy-ha-proxy-2026{month:02d}01-120000.tar.gz.enc" for month in range(1, 12)
        )
        batches = []

        def sftp(record, batch):
            batches.append(batch)
            if batch.startswith("ls "):
                return mock.Mock(returncode=0, stdout=listing.encode(), stderr=b"")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        def ssh(record, command):
            return mock.Mock(returncode=0, stdout=f"{self.digest}  x".encode(), stderr=b"")

        result = self.run_upload(sftp, ssh)
        self.assertTrue(result["ok"])
        self.assertEqual(result["verified_by"], "remote-hash")
        self.assertTrue(result["pruned"])
        self.assertTrue(any(batch.startswith("-rm ") for batch in batches))

    def test_an_unverified_copy_prunes_nothing(self):
        # The rule that matters: a broken upload must never be the reason the
        # last good copy disappears.
        batches = []

        def sftp(record, batch):
            batches.append(batch)
            if batch.startswith("get "):
                return mock.Mock(returncode=1, stdout=b"", stderr=b"nope")
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        def ssh(record, command):
            return mock.Mock(returncode=127, stdout=b"", stderr=b"no shell")

        result = self.run_upload(sftp, ssh)
        self.assertFalse(result["ok"])
        self.assertEqual(result["pruned"], [])
        self.assertFalse(any(batch.startswith("-rm ") for batch in batches))

    def test_a_far_end_reporting_different_bytes_is_a_failure(self):
        def sftp(record, batch):
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        def ssh(record, command):
            return mock.Mock(returncode=0, stdout=b"0000  x", stderr=b"")

        result = self.run_upload(sftp, ssh)
        self.assertFalse(result["ok"])
        self.assertIn("different", result["error"])

    def test_a_failed_transfer_raises_rather_than_reporting_success(self):
        def sftp(record, batch):
            return mock.Mock(returncode=1, stdout=b"", stderr=b"permission denied")

        def ssh(record, command):
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        with self.assertRaises(backupd.BackupdError) as caught:
            self.run_upload(sftp, ssh)
        self.assertIn("permission denied", str(caught.exception))

    def test_an_upload_failure_is_reported_to_the_alert_engine(self):
        with mock.patch.object(backupd, "report_alert") as reported:

            def sftp(record, batch):
                return mock.Mock(returncode=1, stdout=b"", stderr=b"denied")

            with self.assertRaises(backupd.BackupdError):
                self.run_upload(sftp, lambda *_a: mock.Mock(returncode=0, stdout=b""))
        self.assertTrue(reported.called)
        self.assertEqual(reported.call_args.args[0], "backup.failed")


class ProtocolTests(unittest.TestCase):
    SOURCE = (
        ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
    ).read_text(encoding="utf-8")

    def test_every_new_action_is_declared_and_dispatched(self):
        for action in (
            "destinations", "destination_save", "destination_delete",
            "destination_test", "upload",
        ):
            self.assertIn(f'"{action}": frozenset', self.SOURCE)
            self.assertIn(f'if action == "{action}"', self.SOURCE)

    def test_only_the_encrypted_archive_is_sent(self):
        # The plan's rule: never upload extracted or plaintext content.
        block = self.SOURCE.split("def upload_backup")[1].split("def test_destination")[0]
        self.assertIn("backup_archive_path", block)
        self.assertNotIn("work_dir", block)
        self.assertNotIn("passphrase", block)


if __name__ == "__main__":
    unittest.main()
