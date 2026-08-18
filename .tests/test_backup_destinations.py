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
            # A real digest that differs. Anything not shaped like one
            # is now treated as chatter from the far end, not an answer.
            return mock.Mock(
                returncode=0, stdout=b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  x", stderr=b""
            )

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


class S3SigningTests(DestinationTestCase):
    """Signing is checked against a real MinIO in the live probe; these lock
    the shapes that make that signature reproducible."""

    def save_s3(self, **overrides):
        payload = {
            "action": "destination_save",
            "name": "objects",
            "type": "s3",
            "endpoint": "https://s3.example.test",
            "region": "eu-central-1",
            "bucket": "gateway-backups",
            "prefix": "gw1",
            "access_key": "AKIAEXAMPLE",
            "secret_key": "s3cr3t-key-value",
        }
        payload.update(overrides)
        return backupd.save_destination(payload)

    def test_the_secret_is_root_only_and_never_returned(self):
        self.save_s3()
        secret = backupd.destination_secret_path("objects")
        self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
        blob = json.dumps(backupd.list_destinations({"action": "destinations"}))
        self.assertNotIn("s3cr3t-key-value", blob)
        self.assertIn("AKIAEXAMPLE", blob)

    def test_plain_http_needs_an_explicit_opt_in(self):
        with self.assertRaises(backupd.BackupdError) as caught:
            self.save_s3(endpoint="http://s3.example.test")
        self.assertIn("http", str(caught.exception))
        self.save_s3(endpoint="http://s3.example.test", allow_insecure=True)

    def test_a_bad_bucket_or_key_is_refused(self):
        for field, value in (
            ("bucket", "Not A Bucket"),
            ("bucket", ""),
            ("access_key", "has space"),
            ("prefix", "../escape"),
            ("endpoint", "s3.example.test"),
        ):
            with self.assertRaises(backupd.BackupdError, msg=f"{field}={value}"):
                self.save_s3(**{field: value})

    def test_the_percent_encoding_follows_sigv4_not_urllib(self):
        # urlencode leaves ~ alone but escapes /, and SigV4 wants the reverse
        # in a path; a mismatch here is a 403 that reads like bad credentials.
        self.assertEqual(backupd.s3_quote("a~b"), "a~b")
        self.assertEqual(backupd.s3_quote("a/b"), "a/b")
        self.assertEqual(backupd.s3_quote("a/b", keep_slash=False), "a%2Fb")
        self.assertEqual(backupd.s3_quote("a b"), "a%20b")
        self.assertEqual(backupd.s3_quote("+"), "%2B")

    def test_the_signing_key_is_derived_in_four_steps(self):
        # The published derivation: date, region, service, aws4_request.
        import hashlib as _hashlib
        import hmac as _hmac

        expected = ("AWS4" + "secret").encode()
        for part in ("20260812", "eu-central-1", "s3", "aws4_request"):
            expected = _hmac.new(expected, part.encode(), _hashlib.sha256).digest()
        self.assertEqual(
            backupd.s3_signing_key("secret", "20260812", "eu-central-1"), expected
        )

    def test_the_same_inputs_always_sign_the_same(self):
        arguments = dict(
            method="PUT",
            canonical_uri="/bucket/key",
            canonical_query="",
            headers={"host": "s3.example.test", "x-amz-date": "20260812T101500Z"},
            payload_sha="a" * 64,
            access_key="AKIAEXAMPLE",
            secret_key="secret",
            region="eu-central-1",
            amz_date="20260812T101500Z",
        )
        first = backupd.s3_authorization(**arguments)
        self.assertEqual(first, backupd.s3_authorization(**arguments))
        self.assertIn("AWS4-HMAC-SHA256", first)
        self.assertIn("20260812/eu-central-1/s3/aws4_request", first)
        self.assertIn("SignedHeaders=host;x-amz-date", first)

    def test_a_changed_body_changes_the_signature(self):
        arguments = dict(
            method="PUT",
            canonical_uri="/bucket/key",
            canonical_query="",
            headers={"host": "s3.example.test"},
            payload_sha="a" * 64,
            access_key="AKIAEXAMPLE",
            secret_key="secret",
            region="us-east-1",
            amz_date="20260812T101500Z",
        )
        other = {**arguments, "payload_sha": "b" * 64}
        self.assertNotEqual(
            backupd.s3_authorization(**arguments),
            backupd.s3_authorization(**other),
        )

    def test_a_bucket_call_addresses_the_bucket_not_the_prefix(self):
        # A live listing came back NoSuchKey because the prefix was put in the
        # path as well as the query.
        self.save_s3()
        record = backupd.load_destination("objects")
        captured = {}

        class FakeResponse:
            status = 200

            def read(self, _size):
                return b"<ListBucketResult></ListBucketResult>"

            def getheaders(self):
                return []

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, target, body=None, headers=None):
                captured["target"] = target

            def getresponse(self):
                return FakeResponse()

            def close(self):
                pass

        import http.client

        with mock.patch.object(http.client, "HTTPSConnection", FakeConnection):
            backupd.s3_request(record, "GET", query={"list-type": "2", "prefix": "gw1/"})
        self.assertTrue(captured["target"].startswith("/gateway-backups?"))
        self.assertNotIn("/gw1?", captured["target"])

        with mock.patch.object(http.client, "HTTPSConnection", FakeConnection):
            backupd.s3_request(record, "GET", "archive.tar.gz.enc")
        self.assertEqual(captured["target"], "/gateway-backups/gw1/archive.tar.gz.enc")

    def test_an_s3_upload_needs_no_second_transfer_to_be_verified(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def s3_upload")[1].split("def s3_prune")[0]
        self.assertIn('"verified_by": "signed-put"', block)
        # The service checks the body against the hash in the signature, which
        # a live probe confirms by watching a tampered PUT get rejected.
        self.assertIn("body_sha=expected", block)


class ScheduleTests(DestinationTestCase):
    def setUp(self):
        super().setUp()
        base = Path(self.directory.name)
        for name, value in (
            ("SCHEDULE_PATH", base / "schedule.json"),
            ("SCHEDULE_PASSPHRASE_PATH", base / "schedule.key"),
        ):
            patcher = mock.patch.object(backupd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.save()

    def test_it_starts_off_and_stores_nothing(self):
        schedule = backupd.load_schedule()
        self.assertFalse(schedule["enabled"])
        self.assertFalse(schedule["passphrase_stored"])
        self.assertEqual(schedule["destinations"], [])

    def test_it_cannot_be_armed_without_a_stored_passphrase(self):
        # An unattended backup has to encrypt with something; refusing is
        # better than quietly making a weaker archive.
        with self.assertRaises(backupd.BackupdError) as caught:
            backupd.save_schedule(
                {"action": "schedule_save", "enabled": True, "destinations": ["offsite"]}
            )
        self.assertIn("passphrase", str(caught.exception))

    def test_it_cannot_be_armed_without_a_destination(self):
        with self.assertRaises(backupd.BackupdError):
            backupd.save_schedule({
                "action": "schedule_save", "enabled": True,
                "destinations": [], "passphrase": "correct horse battery",
            })

    def test_a_destination_that_does_not_exist_is_refused(self):
        with self.assertRaises(backupd.BackupdError):
            backupd.save_schedule({
                "action": "schedule_save", "enabled": True,
                "destinations": ["nowhere"], "passphrase": "correct horse battery",
            })

    def test_arming_it_stores_the_passphrase_root_only(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        self.assertEqual(
            backupd.SCHEDULE_PASSPHRASE_PATH.stat().st_mode & 0o777, 0o600
        )
        self.assertTrue(backupd.load_schedule()["enabled"])

    def test_the_passphrase_never_comes_back(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        blob = json.dumps(backupd.schedule_status({"action": "schedule"}))
        self.assertNotIn("correct horse battery", blob)
        self.assertIn('"passphrase_stored": true', blob)

    def test_clearing_the_passphrase_removes_the_file(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        backupd.save_schedule(
            {"action": "schedule_save", "enabled": False, "passphrase": ""}
        )
        self.assertFalse(backupd.SCHEDULE_PASSPHRASE_PATH.exists())

    def test_a_run_while_switched_off_does_nothing(self):
        result = backupd.run_scheduled_backup({"action": "run_scheduled"})
        self.assertTrue(result["ok"])
        self.assertIn("off", result["skipped"])

    def test_a_backup_that_does_not_finish_is_not_uploaded(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        with (
            mock.patch.object(backupd, "start_backup", return_value={"job_id": "j" * 32}),
            mock.patch.object(
                backupd, "load_job", return_value={"status": "failed", "error": "boom"}
            ),
            mock.patch.object(backupd, "upload_backup") as upload,
            mock.patch.object(backupd, "report_alert") as reported,
            mock.patch.object(backupd.time, "sleep", lambda _seconds: None),
        ):
            result = backupd.run_scheduled_backup({"action": "run_scheduled"})
        self.assertFalse(result["ok"])
        upload.assert_not_called()
        self.assertTrue(reported.called)

    def test_a_finished_backup_is_sent_to_every_destination(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        completed = {
            "status": "completed",
            "output": {"backup_id": "a" * 32},
        }
        with (
            mock.patch.object(backupd, "start_backup", return_value={"job_id": "j" * 32}),
            mock.patch.object(backupd, "load_job", return_value=completed),
            mock.patch.object(
                backupd, "upload_backup", return_value={"ok": True, "pruned": []}
            ) as upload,
            mock.patch.object(backupd.time, "sleep", lambda _seconds: None),
        ):
            result = backupd.run_scheduled_backup({"action": "run_scheduled"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(upload.call_args.args[0]["destination"], "offsite")
        self.assertEqual(upload.call_args.args[0]["backup_id"], "a" * 32)

    def test_the_outcome_is_remembered_for_the_page(self):
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite"], "passphrase": "correct horse battery",
        })
        backupd.record_schedule_outcome("copied to 1 destination(s)")
        schedule = backupd.load_schedule()
        self.assertTrue(schedule["last_run"])
        self.assertIn("copied", schedule["last_result"])
        # And the settings are not lost by writing the outcome.
        self.assertTrue(schedule["enabled"])
        self.assertEqual(schedule["destinations"], ["offsite"])


class ScheduleWiringTests(unittest.TestCase):
    def test_the_timer_asks_the_daemon_rather_than_doing_the_work(self):
        unit = (
            ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-backup.service.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("easy-ha-proxy-backup-run.py", unit)
        self.assertIn("Type=oneshot", unit)
        runner = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backup-run.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"action": "run_scheduled"', runner)
        # Nothing about the backup itself is decided in the runner: it never
        # reads the stored passphrase and never sends one. (The word appears
        # in its docstring, explaining exactly that.)
        self.assertNotIn("SCHEDULE_PASSPHRASE", runner)
        self.assertNotIn('"passphrase"', runner)
        self.assertNotIn("destinations\"]", runner)

    def test_the_timer_is_persistent_so_a_missed_run_still_happens(self):
        timer = (
            ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-backup.timer.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=", timer)


if __name__ == "__main__":
    unittest.main()


class OwnershipGuardTests(unittest.TestCase):
    """The relaxation that lets these tests run must not reach a deployment.

    The daemon chowns its state to root:hadmin. That cannot work when the
    module is exercised by an ordinary user, and the whole suite used to be
    run as root, which hid it -- green locally, red on CI. The fix is to let
    the chown be skipped when the process is not root, and the thing worth
    testing is that it is never skipped when it is.
    """

    def test_a_refused_chown_is_fatal_for_root(self):
        with mock.patch.object(backupd.os, "geteuid", return_value=0),              mock.patch.object(backupd.os, "fchown", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                backupd._set_owner(3, 0, 0, fd=True)

    def test_and_tolerated_for_anyone_else(self):
        with mock.patch.object(backupd.os, "geteuid", return_value=1000),              mock.patch.object(backupd.os, "fchown", side_effect=PermissionError):
            backupd._set_owner(3, 0, 0, fd=True)

    def test_the_file_is_already_restrictive_before_the_chown(self):
        # This is why skipping it is safe: the descriptor is opened 0600, so a
        # chown that does not happen leaves the file stricter, never looser.
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def atomic_json(")[1].split("def ")[0]
        self.assertLess(block.index("0o600"), block.index("_set_owner"))

    def test_the_owner_check_still_demands_root_when_running_as_root(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
        ).read_text(encoding="utf-8")
        block = source.split("def safe_json_file(")[1].split("def ")[0]
        self.assertIn("if expected_uid == 0 and os.geteuid() != 0:", block)
