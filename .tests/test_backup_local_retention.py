"""Old backups on the gateway itself are rotated once their copies are safe.

On a production gateway the nightly backup had been copied off-host every
night, and the far end rotated -- seven daily, four weekly, six monthly. The
local archive of every run stayed where it was made: fifty of them, 1.1 GB,
growing by a day's archive each night, with nothing to remove any. The only
guard was a 512 MiB floor that refuses the next backup outright. And the
page lists fifty, so from the fifty-first on the oldest would have vanished
from the page while still on the disk.

Now a scheduled run keeps the newest N local archives -- 3 unless the
operator says otherwise -- and removes the rest, but only once every
destination holds a verified copy of the new one. Low free space is
reported before the floor is reached, and the page counts every archive,
not just the ones it lists.
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
APP = ROOT / "docker/app/haproxy_admin"


def load_backupd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
    spec = importlib.util.spec_from_file_location("backupd_local_retention", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backupd = load_backupd()
REAL_SAFE_FILE = backupd.safe_regular_file


def as_test_user(path, *, expected_uid, maximum_size):
    # The daemon insists its archives are root's; the test files are ours.
    if expected_uid == 0:
        expected_uid = os.getuid()
    return REAL_SAFE_FILE(path, expected_uid=expected_uid, maximum_size=maximum_size)


class LocalArchives(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.backups = base / "backups"
        self.backups.mkdir()
        (base / "jobs").mkdir()
        for name, value in (
            ("BACKUPS_DIR", self.backups),
            ("JOBS_DIR", base / "jobs"),
            ("SCHEDULE_PATH", base / "schedule.json"),
            ("SCHEDULE_PASSPHRASE_PATH", base / "schedule.key"),
            ("DESTINATIONS_DIR", base / "dest"),
            ("OPERATION_LOCK_PATH", base / "operation.lock"),
            ("safe_regular_file", as_test_user),
        ):
            patcher = mock.patch.object(backupd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.start = dt.datetime(2026, 8, 5, 3, 20, tzinfo=dt.timezone.utc)

    def make(self, day: int) -> str:
        backup_id = hashlib.md5(str(day).encode()).hexdigest()
        body = f"archive {day}".encode() * 10
        archive = self.backups / f"{backup_id}{backupd.ARCHIVE_SUFFIX}"
        archive.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        (self.backups / f"{backup_id}{backupd.CHECKSUM_SUFFIX}").write_text(
            f"{digest}  {archive.name}\n", encoding="ascii"
        )
        (self.backups / f"{backup_id}{backupd.META_SUFFIX}").write_text(
            json.dumps(
                {
                    "id": backup_id,
                    "size_bytes": len(body),
                    "sha256": digest,
                    "created_at": (self.start + dt.timedelta(days=day)).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        return backup_id

    def remaining(self):
        return [item["id"] for item in backupd.all_backups()]


class PruningKeepsTheNewest(LocalArchives):
    def test_only_the_newest_are_kept_with_all_their_files(self):
        ids = [self.make(day) for day in range(6)]
        removed = backupd.prune_local_backups(3)
        self.assertEqual(sorted(removed), sorted(ids[:3]))
        self.assertEqual(self.remaining(), list(reversed(ids[3:])))
        for backup_id in ids[:3]:
            self.assertEqual(list(self.backups.glob(f"{backup_id}*")), [])

    def test_an_archive_a_restore_was_staged_from_is_left_alone(self):
        ids = [self.make(day) for day in range(4)]
        (backupd.JOBS_DIR / f"{backupd.STAGE_RECORD_PREFIX}{'f' * 32}.json").write_text(
            json.dumps({"backup_id": ids[0]}), encoding="utf-8"
        )
        removed = backupd.prune_local_backups(1)
        self.assertNotIn(ids[0], removed)
        self.assertIn(ids[0], self.remaining())

    def test_the_newest_is_never_removed(self):
        ids = [self.make(day) for day in range(3)]
        backupd.prune_local_backups(0)
        self.assertEqual(self.remaining(), [ids[2]])

    def test_archives_past_the_page_limit_are_counted_and_pruned(self):
        # The fifty-first archive used to drop off the page and stay on disk.
        ids = [self.make(day) for day in range(backupd.LIST_LIMIT + 2)]
        self.assertEqual(len(backupd.list_backups()), backupd.LIST_LIMIT)
        self.assertEqual(backupd.local_storage()["count"], backupd.LIST_LIMIT + 2)
        backupd.prune_local_backups(3)
        self.assertEqual(self.remaining(), list(reversed(ids[-3:])))


class TheScheduledRun(LocalArchives):
    def setUp(self):
        super().setUp()
        backupd.DESTINATIONS_DIR.mkdir()
        for name in ("offsite", "second"):
            backupd.save_destination({
                "action": "destination_save", "name": name, "type": "sftp",
                "host": "backup.example.test", "port": 22, "user": "gateway",
                "path": "/srv/backups/gw",
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----",
                "host_key": "backup.example.test ssh-ed25519 AAAAC3Nz",
            })
        backupd.save_schedule({
            "action": "schedule_save", "enabled": True,
            "destinations": ["offsite", "second"],
            "passphrase": "correct horse battery",
        })
        self.ids = [self.make(day) for day in range(5)]

    def run_with(self, uploads, free_bytes=50 * 1024**3, total_bytes=100 * 1024**3):
        completed = {"status": "completed", "output": {"backup_id": self.ids[-1]}}
        usage = mock.Mock(free=free_bytes, total=total_bytes)
        with (
            mock.patch.object(backupd, "start_backup", return_value={"job_id": "j" * 32}),
            mock.patch.object(backupd, "load_job", return_value=completed),
            mock.patch.object(backupd, "upload_backup", side_effect=uploads),
            mock.patch.object(backupd.shutil, "disk_usage", return_value=usage),
            mock.patch.object(backupd, "report_alert") as alert,
            mock.patch.object(backupd.time, "sleep", lambda _seconds: None),
        ):
            result = backupd.run_scheduled_backup({"action": "run_scheduled"})
        return result, alert

    def test_after_verified_copies_everywhere_the_old_local_ones_go(self):
        result, _alert = self.run_with([{"ok": True}, {"ok": True}])
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["pruned"]), 2)
        self.assertEqual(self.remaining(), list(reversed(self.ids[2:])))
        self.assertIn("removed 2 older local backup(s)", backupd.load_schedule()["last_result"])

    def test_one_failed_or_unverified_copy_keeps_everything(self):
        for uploads in (
            [{"ok": True}, {"ok": False, "error": "the copy could not be verified"}],
            [{"ok": True}, backupd.BackupdError("connection refused")],
        ):
            with self.subTest(uploads=uploads):
                result, _alert = self.run_with(uploads)
                self.assertFalse(result["ok"])
                self.assertEqual(result["pruned"], [])
                self.assertEqual(len(self.remaining()), 5)

    def test_the_number_kept_follows_the_schedule(self):
        backupd.save_schedule({"action": "schedule_save", "keep_local": 1})
        self.run_with([{"ok": True}, {"ok": True}])
        self.assertEqual(self.remaining(), [self.ids[-1]])

    def test_low_space_is_reported_before_backups_start_failing(self):
        _result, alert = self.run_with(
            [{"ok": True}, {"ok": True}], free_bytes=1024**3, total_bytes=100 * 1024**3
        )
        alert.assert_called_once()
        self.assertEqual(alert.call_args.args[0], "backup.space_low")

    def test_plenty_of_space_is_not_reported(self):
        _result, alert = self.run_with([{"ok": True}, {"ok": True}])
        alert.assert_not_called()


class TheSetting(LocalArchives):
    def test_three_unless_told_otherwise(self):
        self.assertEqual(backupd.load_schedule()["keep_local"], 3)

    def test_a_deliberate_value_is_kept_and_a_bad_one_refused(self):
        backupd.save_schedule({"action": "schedule_save", "keep_local": 7})
        self.assertEqual(backupd.load_schedule()["keep_local"], 7)
        for bad in (0, -1, 51, "x", 2.5, True):
            with self.subTest(bad=bad), self.assertRaises(backupd.BackupdError):
                backupd.save_schedule({"action": "schedule_save", "keep_local": bad})
        # Saving something else keeps it.
        backupd.save_schedule({"action": "schedule_save", "quiesce": False})
        self.assertEqual(backupd.load_schedule()["keep_local"], 7)

    def test_the_daemon_and_the_page_accept_the_field(self):
        self.assertIn("keep_local", backupd.REQUEST_FIELDS["schedule_save"])
        route = (APP / "routes_backup.py").read_text(encoding="utf-8")
        self.assertIn('command["keep_local"] = keep', route)
        script = (APP / "static/js/backup_schedule.js").read_text(encoding="utf-8")
        self.assertIn('keep_local: Number(byId("schedule-keep-local").value)', script)
        page = (APP / "templates/system_backups.html").read_text(encoding="utf-8")
        self.assertIn('id="schedule-keep-local"', page)
        self.assertIn('id="backup-local-summary"', page)


class TheSummaryReachesThePage(LocalArchives):
    def test_status_counts_every_archive_and_the_space(self):
        for day in range(3):
            self.make(day)
        with mock.patch.object(backupd, "list_uploads", return_value=[]), mock.patch.object(
            backupd, "list_jobs", return_value=[]
        ), mock.patch.object(backupd, "active_job", return_value=None), mock.patch.object(
            backupd, "expire_orphaned_uploads"
        ):
            status = backupd.status_response({"action": "status"})
        local = status["local"]
        self.assertEqual(local["count"], 3)
        self.assertGreater(local["bytes"], 0)
        self.assertIn("free_bytes", local)
        self.assertIn("low", local)

    def test_the_page_renders_it_in_russian(self):
        script = (APP / "static/js/system_backups.js").read_text(encoding="utf-8")
        self.assertIn("renderLocalSummary(payload.local", script)
        catalogue = json.loads(
            (APP / "translations/ru/backup_destinations.json").read_text(encoding="utf-8")
        )["messages"]
        for phrase in (
            "{count} backups on this server use {size}; {free} free on the disk.",
            "Showing the newest {shown}.",
            "Free space is low: below {threshold}.",
            "Keep on this server",
        ):
            self.assertIn(phrase, catalogue)


class TheAlertExists(unittest.TestCase):
    def test_alertd_knows_the_rule(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
        ).read_text(encoding="utf-8")
        self.assertIn('Rule("backup.space_low", KIND_EVENT, SEVERITY_WARNING', source)


if __name__ == "__main__":
    unittest.main()
