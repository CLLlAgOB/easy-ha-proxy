"""The monitoring history survives a rebuild from backup.

A gateway rebuilt from its backup came back working -- and with its graphs
gone. The metrics database had been left out of every backup as too large
and not needed for a working gateway. The collector caps its own database,
though, and the history is exactly what an operator wants to compare the
rebuilt gateway against.

It cannot simply be copied by tar: the collector writes every few seconds,
and a file copy can be torn between the database and its write-ahead log.
So the backup takes a consistent snapshot with SQLite's online backup while
the collector keeps running, archives that, and a restore moves it into
place with the collector stopped for the swap. A missing history, a full
disk or an unreadable database costs the history, never the backup.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "installer" / "full_backup.py"
BACKUPD = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
APP = ROOT / "docker/app/haproxy_admin"


def load():
    spec = importlib.util.spec_from_file_location("full_backup_metrics", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["full_backup_metrics"] = module
    spec.loader.exec_module(module)
    return module


backup = load()
SOURCE = HELPER.read_text(encoding="utf-8")


def function(name: str) -> str:
    return SOURCE.split(f"def {name}(")[1].split("\ndef ")[0]


class Gateway(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "metrics" / "metrics.db"
        self.snapshot = self.root / "monitoring-history" / "metrics.db"
        self.database.parent.mkdir()

    def collector(self, rows: int = 50) -> sqlite3.Connection:
        """A database in WAL mode with committed rows not yet checkpointed."""
        connection = sqlite3.connect(str(self.database))
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE metric_1m (bucket_ts INTEGER, value REAL)")
        connection.executemany(
            "INSERT INTO metric_1m VALUES (?, ?)", [(i, i * 1.5) for i in range(rows)]
        )
        connection.commit()
        self.addCleanup(connection.close)
        return connection

    def rows(self, path: Path) -> int:
        connection = sqlite3.connect(str(path))
        try:
            return connection.execute("SELECT COUNT(*) FROM metric_1m").fetchone()[0]
        finally:
            connection.close()


class TakingTheSnapshot(Gateway):
    def test_it_holds_what_the_collector_has_written(self):
        # Including rows still only in the write-ahead log, with the
        # collector's connection open the whole time.
        self.collector(rows=50)
        self.assertTrue(Path(str(self.database) + "-wal").stat().st_size > 0)
        result = backup.snapshot_metrics(self.database, self.snapshot)
        self.assertTrue(result["included"])
        self.assertEqual(self.rows(self.snapshot), 50)
        self.assertEqual(result["snapshot_bytes"], self.snapshot.stat().st_size)

    def test_it_is_one_self_contained_file(self):
        self.collector()
        backup.snapshot_metrics(self.database, self.snapshot)
        self.assertEqual(sorted(p.name for p in self.snapshot.parent.iterdir()), ["metrics.db"])
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o600)

    def test_no_history_is_not_an_error(self):
        result = backup.snapshot_metrics(self.database, self.snapshot)
        self.assertFalse(result["included"])
        self.assertFalse(self.snapshot.parent.exists())

    def test_a_disk_too_full_for_a_copy_costs_the_history_not_the_backup(self):
        self.collector()
        usage = shutil.disk_usage(self.root)._replace(free=1024)
        with mock.patch.object(backup.shutil, "disk_usage", return_value=usage):
            result = backup.snapshot_metrics(self.database, self.snapshot)
        self.assertFalse(result["included"])
        self.assertIn("free space", result["reason"])
        self.assertFalse(self.snapshot.parent.exists())

    def test_an_unreadable_database_leaves_nothing_behind(self):
        self.database.write_bytes(b"not a database at all" * 100)
        result = backup.snapshot_metrics(self.database, self.snapshot)
        self.assertFalse(result["included"])
        self.assertIn("could not be read", result["reason"])
        self.assertFalse(self.snapshot.parent.exists())

    def test_a_leftover_from_an_interrupted_run_is_replaced(self):
        self.collector(rows=7)
        self.snapshot.parent.mkdir()
        self.snapshot.write_bytes(b"stale")
        backup.snapshot_metrics(self.database, self.snapshot)
        self.assertEqual(self.rows(self.snapshot), 7)


class PuttingItBack(Gateway):
    def systemd(self, running: bool):
        calls = []

        def run(argv, check=True, **kwargs):
            calls.append(argv[1:])
            code = 0 if (argv[1] != "is-active" or running) else 3
            return subprocess.CompletedProcess(argv, code, stdout="", stderr="")

        return calls, mock.patch.multiple(
            backup,
            run=mock.Mock(side_effect=run),
            shutil=mock.Mock(which=mock.Mock(return_value="/bin/systemctl")),
        )

    def restored(self, rows: int):
        self.snapshot.parent.mkdir()
        connection = sqlite3.connect(str(self.snapshot))
        connection.execute("CREATE TABLE metric_1m (bucket_ts INTEGER, value REAL)")
        connection.executemany("INSERT INTO metric_1m VALUES (?, ?)", [(i, 0) for i in range(rows)])
        connection.commit()
        connection.close()

    def test_the_restored_history_replaces_the_fresh_one(self):
        self.database.write_bytes(b"")
        for suffix in ("-wal", "-shm"):
            Path(str(self.database) + suffix).write_bytes(b"belongs to the old database")
        self.restored(rows=12)
        calls, patched = self.systemd(running=True)
        with patched:
            self.assertTrue(backup.install_restored_metrics(self.snapshot, self.database))
        self.assertEqual(self.rows(self.database), 12)
        for suffix in ("-wal", "-shm"):
            self.assertFalse(Path(str(self.database) + suffix).exists())
        self.assertFalse(self.snapshot.parent.exists())
        # Stopped for the swap, started again afterwards.
        self.assertEqual(
            calls,
            [
                ["is-active", "--quiet", backup.METRICS_UNIT],
                ["stop", backup.METRICS_UNIT],
                ["start", backup.METRICS_UNIT],
            ],
        )

    def test_a_collector_that_was_not_running_is_not_started(self):
        self.restored(rows=3)
        calls, patched = self.systemd(running=False)
        with patched:
            backup.install_restored_metrics(self.snapshot, self.database)
        self.assertEqual(calls, [["is-active", "--quiet", backup.METRICS_UNIT]])
        self.assertEqual(self.rows(self.database), 3)

    def test_an_archive_without_a_history_changes_nothing(self):
        self.collector(rows=5)
        self.assertFalse(backup.install_restored_metrics(self.snapshot, self.database))
        self.assertEqual(self.rows(self.database), 5)


class TheArchiveCarriesTheSnapshotNotTheLiveFile(unittest.TestCase):
    def test_the_snapshot_is_under_an_archived_root(self):
        self.assertTrue(
            str(backup.METRICS_SNAPSHOT).startswith("/var/lib/easy-ha-proxy/")
        )
        self.assertIn("/var/lib/easy-ha-proxy", backup.CORE_PATHS)

    def test_tar_takes_the_snapshot_and_leaves_the_live_database(self):
        # With the excludes the backup actually passes to tar.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (backup.METRICS_DATABASE, backup.METRICS_SNAPSHOT):
                path = root / str(relative).lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"x")
            archive = root / "payload.tar"
            subprocess.run(
                [
                    "tar", "-cf", str(archive), "-C", str(root),
                    *(f"--exclude={value}" for value in backup.BACKUP_EXCLUDES),
                    "var/lib/easy-ha-proxy",
                ],
                check=True,
            )
            with tarfile.open(archive) as handle:
                names = set(handle.getnames())
        self.assertIn(str(backup.METRICS_SNAPSHOT).lstrip("/"), names)
        self.assertNotIn(str(backup.METRICS_DATABASE).lstrip("/"), names)

    def test_the_backup_takes_it_and_always_cleans_it_up(self):
        create = function("create_backup")
        self.assertLess(create.index("snapshot_metrics()"), create.index("create_payload(payload"))
        cleanup = create.split("finally:")[1].split("payload_expanded_bytes")[0]
        self.assertIn("discard_metrics_snapshot()", cleanup)
        self.assertIn('"metrics": metrics', create)
        self.assertIn('"metrics_included": bool(metrics["included"])', create)

    def test_a_full_restore_puts_it_in_place_right_after_extraction(self):
        restore = function("restore_backup")
        extracted = restore.index("extract_payload(payload)")
        installed = restore.index("install_restored_metrics()")
        self.assertLess(extracted, installed)
        # Before reconciliation starts the services again.
        self.assertLess(installed, restore.index("reconcile_restored_host()"))


class ThePageSaysWhetherItIsThere(unittest.TestCase):
    def test_the_daemon_passes_the_flag_on(self):
        source = BACKUPD.read_text(encoding="utf-8")
        keys = source.split("MANIFEST_KEYS = (")[1].split(")")[0]
        self.assertIn('"metrics_included"', keys)

    def test_the_backup_details_show_it(self):
        page = (APP / "templates/system_backups.html").read_text(encoding="utf-8")
        script = (APP / "static/js/system_backups.js").read_text(encoding="utf-8")
        self.assertIn('id="backup-metrics-state"', page)
        self.assertIn(
            'byId("backup-metrics-state").textContent = manifest.metrics_included ? t("Yes") : t("No");',
            script,
        )


if __name__ == "__main__":
    unittest.main()
