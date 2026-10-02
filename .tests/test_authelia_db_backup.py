"""Authelia's database is copied before a different Authelia image runs on it.

A gateway moved from Authelia 4.39.20 to 4.39.28 through a complete update.
The new version migrated the storage schema from 24 to 29 on first start,
and 4.39.20 refuses a newer schema -- so with no copy of the database taken
beforehand there was no way back. Now the role copies it just before the
stack is recreated on a different image, through SQLite's online backup API,
checks the copy, keeps the newest few, and stops the update if it cannot.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/authelia"
SCRIPT = ROLE / "files/authelia_db_backup.py"


def load_script():
    spec = importlib.util.spec_from_file_location("authelia_db_backup_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKUP = load_script()


def make_database(path: Path, rows: int = 3) -> None:
    with sqlite3.connect(path) as db:
        db.execute("create table migrations (id integer primary key, version_after int)")
        db.executemany(
            "insert into migrations (version_after) values (?)",
            [(version,) for version in range(20, 20 + rows)],
        )


class TheCopy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "db.sqlite3"
        self.directory = self.root / "copies"
        make_database(self.source)

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True,
            text=True,
        )

    def test_the_copy_holds_the_same_rows_and_only_root_can_read_it(self):
        copied = BACKUP.backup(self.source, self.directory, "authelia/authelia:4.39.20", 5)
        with sqlite3.connect(copied) as db:
            rows = db.execute("select version_after from migrations").fetchall()
        self.assertEqual(rows, [(20,), (21,), (22,)])
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        # The label says which version the copy can be restored under.
        self.assertIn("authelia_authelia_4.39.20", copied.name)

    def test_the_copy_is_consistent_while_a_writer_holds_the_database(self):
        # Authelia keeps running while the copy is taken.
        writer = sqlite3.connect(self.source)
        self.addCleanup(writer.close)
        writer.execute("pragma journal_mode=wal")
        writer.execute("insert into migrations (version_after) values (99)")
        writer.commit()
        writer.execute("begin immediate")
        writer.execute("insert into migrations (version_after) values (100)")
        copied = BACKUP.backup(self.source, self.directory, "x", 5)
        with sqlite3.connect(copied) as db:
            versions = [row[0] for row in db.execute("select version_after from migrations")]
        self.assertIn(99, versions)
        self.assertNotIn(100, versions)

    def test_only_the_newest_copies_are_kept(self):
        for _ in range(4):
            BACKUP.backup(self.source, self.directory, "x", 2)
        unrelated = self.directory / "keep-me.txt"
        unrelated.write_text("not ours", encoding="utf-8")
        BACKUP.backup(self.source, self.directory, "x", 2)
        copies = sorted(p.name for p in self.directory.glob("authelia-db-*.sqlite3"))
        self.assertEqual(len(copies), 2)
        self.assertTrue(unrelated.exists())

    def test_no_database_is_not_an_error(self):
        result = self.run_script(self.root / "absent.sqlite3", self.directory, "x", 5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to copy", result.stdout)

    def test_a_damaged_database_stops_the_update_and_leaves_nothing_half_written(self):
        self.source.write_bytes(b"this is not a database" * 100)
        result = self.run_script(self.source, self.directory, "x", 5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Authelia database backup failed", result.stderr)
        self.assertEqual(list(self.directory.glob("*")), [])

    def test_the_script_reports_where_the_copy_went(self):
        result = self.run_script(self.source, self.directory, "authelia/authelia:4.39.20", 5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(Path(result.stdout.strip()).is_file())


class TheRoleTakesItAtTheRightMoment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load((ROLE / "tasks/db_backup.yml").read_text(encoding="utf-8"))
        cls.defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))

    def test_before_every_reconcile_that_can_change_the_image(self):
        for name, reconcile in (
            ("start.yml", "Reconcile the Authelia stack with migration recovery"),
            ("update.yml", "Reconcile the updated Authelia stack with migration recovery"),
        ):
            block = yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8"))[0]["block"]
            names = [task.get("name") for task in block]
            include = next(
                i for i, task in enumerate(block)
                if task.get("ansible.builtin.include_tasks") == "db_backup.yml"
            )
            pull = names.index("Pull Authelia stack images")
            self.assertLess(pull, include, name)
            self.assertLess(include, names.index(reconcile), name)

    def test_only_when_the_image_differs_from_the_running_one(self):
        copy = self.tasks[2]
        self.assertIn("authelia_db_backup.py", " ".join(copy["ansible.builtin.command"]["argv"]))
        conditions = " ".join(copy["when"])
        self.assertIn("authelia_db_backup_running.rc == 0", conditions)
        self.assertIn("!= authelia_db_backup_target.stdout", conditions)
        # A failed copy must stop the update before the migration.
        self.assertNotIn("failed_when", copy)
        self.assertNotIn("ignore_errors", copy)

    def test_the_reads_answer_under_check_mode_and_change_nothing(self):
        for task in self.tasks[:2]:
            self.assertIs(task["check_mode"], False)
            self.assertIs(task["changed_when"], False)

    def test_the_target_is_the_image_the_compose_file_names(self):
        compose = (ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        target = self.tasks[1]["ansible.builtin.command"]["argv"][-1]
        self.assertIn(target, compose)

    def test_where_and_how_many(self):
        self.assertEqual(
            self.defaults["authelia_db_backup_dir"], "/var/backups/easy-ha-proxy/authelia-db"
        )
        self.assertGreaterEqual(int(self.defaults["authelia_db_backup_keep"]), 1)


if __name__ == "__main__":
    unittest.main()
