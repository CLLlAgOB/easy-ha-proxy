"""SFTP retries cannot destroy a verified copy, including during retention.

The transport model executes actual filesystem copies, renames and deletions.
The pause belongs to the first request alone: a serialized implementation can
finish without waiting for a second request to enter the same critical section.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
from unittest import mock

from test_backup_remote_names import BACKUP_ID, DATED, Gateway, backupd


class SftpUploadSafety(Gateway):
    def setUp(self):
        super().setUp()
        self.remote = self.backups.parent / "remote"
        self.remote.mkdir()
        self.old = "easy-ha-proxy-20261001-003817-" + "a" * 32 + backupd.ARCHIVE_SUFFIX
        (self.remote / self.old).write_bytes(b"previous good encrypted backup")
        (self.remote / (self.old + ".sha256")).write_bytes(b"previous checksum")
        self.record = {
            "name": "offsite", "type": "sftp", "host": "backup.example.test",
            "user": "gateway", "port": 22, "path": "/backup", "verify": "auto",
            "keep_daily": 1, "keep_weekly": 0, "keep_monthly": 0,
        }
        self.overwrite = True
        self.no_shell = False
        self.corrupt_upload = False
        self.upload_timeout = False
        self.row_hook = lambda *_args: None
        self.loaded = lambda *_args: None
        self.batches = []
        for name, value in (
            ("load_destination", self.destination),
            ("run_sftp", self.sftp),
            ("run_ssh", self.ssh),
            ("report_alert", mock.Mock()),
        ):
            patcher = mock.patch.object(backupd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def destination(self, name):
        self.loaded(name)
        return {**self.record, "name": name}

    def remote_path(self, path):
        return self.remote / Path(path).name

    def sftp(self, record, batch):
        self.batches.append(batch)
        for row in batch.splitlines():
            parts = shlex.split(row)
            command = parts[0].lstrip("-")
            try:
                if command == "mkdir":
                    continue
                if command == "put":
                    source, destination = parts[1:]
                    target = self.remote_path(destination)
                    shutil.copyfile(source, target)
                    if ".sha256" not in destination:
                        if self.corrupt_upload:
                            target.write_bytes(b"corrupted transfer")
                        if self.upload_timeout:
                            self.upload_timeout = False
                            raise subprocess.TimeoutExpired(["sftp"], 1)
                elif command == "get":
                    shutil.copyfile(self.remote_path(parts[1]), parts[2])
                elif command == "rm":
                    self.remote_path(parts[1]).unlink()
                elif command == "rename":
                    source, destination = map(self.remote_path, parts[1:])
                    if not self.overwrite and destination.exists():
                        raise FileExistsError("this SFTP server does not support rename-overwrite")
                    source.rename(destination)
                elif command == "ls":
                    listing = "\n".join(path.name for path in self.remote.iterdir())
                    self.row_hook("ls", parts)
                    return subprocess.CompletedProcess([], 0, listing.encode(), b"")
                else:
                    raise AssertionError(f"unexpected SFTP command: {row}")
                self.row_hook(command, parts)
            except OSError as exc:
                if not parts[0].startswith("-"):
                    return subprocess.CompletedProcess([], 1, b"", str(exc).encode())
        return subprocess.CompletedProcess([], 0, b"", b"")

    def ssh(self, record, command):
        if self.no_shell:
            return subprocess.CompletedProcess([], 0, b"This service allows sftp connections only.", b"")
        try:
            digest = hashlib.sha256(self.remote_path(command[-1]).read_bytes()).hexdigest()
        except FileNotFoundError:
            return subprocess.CompletedProcess([], 1, b"", b"file not found")
        self.row_hook("hash", command)
        return subprocess.CompletedProcess([], 0, f"{digest}  {command[-1]}".encode(), b"")

    def upload(self, backup_id=BACKUP_ID, destination="offsite"):
        return backupd.dispatch({
            "action": "upload", "backup_id": backup_id, "destination": destination,
        })

    def second_backup(self):
        backup_id = "b" * 32
        archive = backupd.backup_archive_path(backup_id)
        archive.write_bytes(b"another encrypted archive")
        backupd.backup_meta_path(backup_id).write_text(json.dumps({
            "id": backup_id, "created_at": "2026-10-06T01:02:03+00:00",
        }))
        return backup_id, backupd.remote_archive_name(backup_id, archive)

    def concurrent_uploads(self, *, pause_at, second_id=BACKUP_ID, alias=False):
        first_paused = threading.Event()
        release_first = threading.Event()
        second_loaded = threading.Event()
        second_network = threading.Event()
        outcomes = {}
        failures = {}

        def loaded(_name):
            if threading.current_thread().name == "second-upload":
                second_loaded.set()

        def row_hook(command, parts):
            if threading.current_thread().name == "second-upload":
                second_network.set()
            elif command == pause_at and not first_paused.is_set():
                first_paused.set()
                if not release_first.wait(5):
                    raise AssertionError("first upload was not released")

        def upload(name, backup_id, destination):
            try:
                outcomes[name] = self.upload(backup_id, destination)
            except Exception as exc:  # Include errors for assertion in the main thread.
                failures[name] = exc

        self.loaded = loaded
        self.row_hook = row_hook
        first = threading.Thread(target=upload, args=("first", BACKUP_ID, "offsite"),
                                 name="first-upload")
        second = threading.Thread(target=upload,
                                  args=("second", second_id, "alias" if alias else "offsite"),
                                  name="second-upload")
        first.start()
        try:
            self.assertTrue(first_paused.wait(5), "first upload never reached the pause")
            second.start()
            self.assertTrue(second_loaded.wait(5), "second upload did not start")
            concurrent = second_network.wait(0.2)
        finally:
            release_first.set()
            first.join(5)
            if second.ident is not None:
                second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse(concurrent, "another upload entered before verification/retention finished")
        self.assertEqual(failures, {})
        self.assertTrue(all(outcome["ok"] and outcome["verified"] for outcome in outcomes.values()))
        self.assertEqual(len(outcomes), 2)
        self.assertFalse(list(self.remote.glob("*.part")))
        self.assertFalse((self.remote / self.old).exists())
        return outcomes

    def test_concurrent_retry_keeps_the_verified_archive_and_checksum(self):
        self.concurrent_uploads(pause_at="put")
        self.assertEqual((self.remote / DATED).read_bytes(), self.archive.read_bytes())
        self.assertEqual((self.remote / (DATED + ".sha256")).read_bytes(),
                         backupd.remote_checksum_body(self.digest, DATED))

    def test_different_backups_share_the_lock_until_verification_finishes(self):
        second_id, second_name = self.second_backup()
        self.concurrent_uploads(pause_at="hash", second_id=second_id)
        self.assertEqual(list(self.remote.glob("*" + backupd.ARCHIVE_SUFFIX)),
                         [self.remote / second_name])

    def test_profiles_for_the_same_folder_share_the_lock_through_retention(self):
        self.concurrent_uploads(pause_at="rm", alias=True)
        self.assertEqual((self.remote / DATED).read_bytes(), self.archive.read_bytes())

    def test_a_corrupted_retry_preserves_final_files_and_does_not_prune(self):
        final = self.remote / DATED
        sidecar = self.remote / (DATED + ".sha256")
        final.write_bytes(self.archive.read_bytes())
        sidecar.write_bytes(backupd.remote_checksum_body(self.digest, DATED))
        before = {path.name: path.read_bytes() for path in self.remote.iterdir()}
        self.corrupt_upload = True
        result = self.upload()
        self.assertFalse(result["ok"])
        self.assertEqual(result["pruned"], [])
        self.assertEqual({path.name: path.read_bytes() for path in self.remote.iterdir()}, before)

    def test_a_timed_out_transfer_preserves_existing_copies_and_releases_the_lock(self):
        before = {path.name: path.read_bytes() for path in self.remote.iterdir()}
        self.upload_timeout = True
        with self.assertRaises(backupd.BackupdError):
            self.upload()
        self.assertEqual({path.name: path.read_bytes() for path in self.remote.iterdir()}, before)
        self.assertTrue(self.upload()["ok"])

    def test_no_overwrite_sftp_accepts_an_identical_retry_without_a_shell(self):
        self.assertTrue(self.upload()["ok"])
        self.overwrite = False
        self.no_shell = True
        self.record["verify"] = "transfer"
        self.assertTrue(self.upload()["ok"])
        self.assertEqual((self.remote / DATED).read_bytes(), self.archive.read_bytes())
        self.assertFalse(list(self.remote.glob("*.part")))

    def test_no_overwrite_sftp_refuses_a_different_existing_file_even_in_transfer_mode(self):
        (self.remote / DATED).write_bytes(b"different existing archive")
        before = {path.name: path.read_bytes() for path in self.remote.iterdir()}
        self.overwrite = False
        self.no_shell = True
        self.record["verify"] = "transfer"
        with self.assertRaises(backupd.BackupdError) as caught:
            self.upload()
        self.assertEqual(caught.exception.code, "upstream")
        self.assertEqual({path.name: path.read_bytes() for path in self.remote.iterdir()}, before)

    def test_a_refused_checksum_publication_keeps_the_previous_backup_and_reports_failure(self):
        (self.remote / DATED).write_bytes(self.archive.read_bytes())
        (self.remote / (DATED + ".sha256")).write_bytes(b"a different existing checksum")
        before = {path.name: path.read_bytes() for path in self.remote.iterdir()}
        self.overwrite = False
        self.no_shell = True
        with self.assertRaises(backupd.BackupdError):
            self.upload()
        self.assertEqual({path.name: path.read_bytes() for path in self.remote.iterdir()}, before)
