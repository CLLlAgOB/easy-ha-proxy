"""A change log the panel can read but not write says so, and recovers.

Found on a gateway restored from an archive: the change log's database came
back owned by root with mode 644. SQLite opened it read-only without a word,
the page went on listing the old entries, and for a month every change was
refused with "attempt to write a readonly database" -- seen only in the
container's log. The playbook's ownership step after a restore covered the
panel's other writable directories but not this one.

What is held here:
  - the page is told when new entries cannot be written, and why;
  - once the file can be written again, the next entry is written, without
    a panel restart (the kept read-only connection is dropped);
  - the playbook puts the change log's owner right along with the others.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import audit  # noqa: E402

APP = ROOT / "docker/app/haproxy_admin"
ROOT_USER = (not WINDOWS) and os.geteuid() == 0


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
@unittest.skipIf(ROOT_USER, "root writes a file whatever its mode")
class AReadOnlyLog(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "audit.db"
        # The log as it was before the restore: written, with its WAL files.
        self.earlier = audit.AuditLog(str(self.path))
        self.assertTrue(self.earlier.record("site.update", actor="someone"))
        self.addCleanup(self.earlier._drop_connection)
        self.files = [p for p in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")) if p.exists()]
        self.addCleanup(self._writable)

    def _read_only(self):
        for path in self.files:
            os.chmod(path, 0o444)

    def _writable(self):
        for path in self.files:
            if path.exists():
                os.chmod(path, 0o644)

    def test_it_is_still_read(self):
        self._read_only()
        log = audit.AuditLog(str(self.path))
        found = log.query()
        self.assertTrue(found["available"])
        self.assertEqual(found["total"], 1)

    def test_the_status_says_new_entries_are_not_written_and_why(self):
        self._read_only()
        log = audit.AuditLog(str(self.path))
        state = log.stats()
        self.assertFalse(state["writable"])
        self.assertIn("audit.db", state["write_problem"])
        self.assertIn("mode 444", state["write_problem"])
        self.assertIn(f"the panel runs as uid {os.getuid()}", state["write_problem"])

    def test_a_refused_entry_is_counted(self):
        self._read_only()
        log = audit.AuditLog(str(self.path))
        self.assertFalse(log.record("site.update", actor="someone"))
        self.assertEqual(log.write_failures, 1)
        self.assertIn("readonly", log.last_error)

    def test_once_writable_the_next_entry_is_written_without_a_restart(self):
        self._read_only()
        log = audit.AuditLog(str(self.path))
        log.query()  # a page view keeps a read-only connection
        self.assertFalse(log.record("site.update", actor="refused"))
        self._writable()  # the owner put right by the playbook
        self.assertTrue(log.record("site.update", actor="after the fix"))
        self.assertEqual(log.query()["total"], 2)
        self.assertTrue(log.stats()["writable"])

    def test_a_kept_read_only_connection_does_not_cost_the_first_entry(self):
        self._read_only()
        log = audit.AuditLog(str(self.path))
        log.query()
        self._writable()
        self.assertTrue(log.record("site.update", actor="first after the fix"))
        self.assertEqual(log.write_failures, 0)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class AWritableLog(unittest.TestCase):
    def test_it_reports_no_problem(self):
        with tempfile.TemporaryDirectory() as folder:
            log = audit.AuditLog(str(Path(folder) / "audit.db"))
            self.assertTrue(log.record("site.update", actor="someone"))
            state = log.stats()
            log._drop_connection()
        self.assertEqual((state["writable"], state["write_problem"]), (True, ""))

    def test_a_failed_write_is_a_problem_until_one_succeeds(self):
        with tempfile.TemporaryDirectory() as folder:
            log = audit.AuditLog(str(Path(folder) / "audit.db"))
            log.last_error = "disk I/O error"
            log.last_write_failed_at = 10.0
            self.assertEqual(log.write_problem(), "disk I/O error")
            self.assertTrue(log.record("site.update", actor="someone"))
            self.assertEqual(log.write_problem(), "")
            log._drop_connection()


class ThePage(unittest.TestCase):
    def test_it_asks_and_shows_the_reason(self):
        script = (APP / "static/js/audit.js").read_text(encoding="utf-8")
        page = (APP / "templates/audit.html").read_text(encoding="utf-8")
        self.assertIn('getJson("/api/audit/status", {})', script)
        self.assertIn("notice.hidden = state.writable !== false;", script)
        self.assertIn('id="au-write-problem" hidden', page)
        self.assertIn('id="au-write-detail" data-i18n-skip', page)

    def test_the_sentence_is_translated_whole(self):
        page = (APP / "templates/audit.html").read_text(encoding="utf-8")
        sentence = (
            "New changes are not being recorded: the panel cannot write the change log. "
            "The entries below are the ones written before that."
        )
        self.assertIn(sentence, page)
        import json

        messages = json.loads((APP / "translations/ru/audit.json").read_text(encoding="utf-8"))["messages"]
        self.assertIn(sentence, messages)


class ThePlaybook(unittest.TestCase):
    def test_the_change_log_is_given_back_to_the_panel_after_a_restore(self):
        tasks = yaml.safe_load(
            (ROOT / "ansible/roles/haproxy-admin/tasks/config.yml").read_text(encoding="utf-8")
        )
        step = next(task for task in tasks if "Restore change log ownership" in task.get("name", ""))
        inspect = next(task for task in step["block"] if "ansible.builtin.stat" in task)
        repair = next(task for task in step["block"] if task.get("ansible.builtin.file", {}).get("state") == "file")
        # A shared parent must not hand unrelated daemon state to the panel.
        self.assertEqual(inspect["loop"], [
            "{{ audit_database_path | default('/var/lib/easy-ha-proxy/audit/audit.db') }}" + suffix
            for suffix in ("", "-wal", "-shm")
        ])
        self.assertFalse(inspect["ansible.builtin.stat"]["follow"])
        self.assertEqual(repair["ansible.builtin.file"]["owner"], "{{ app_user }}")
        self.assertFalse(repair["ansible.builtin.file"].get("recurse", False))
        self.assertFalse(repair["ansible.builtin.file"]["follow"])
        self.assertIn("item.stat.isreg | default(false)", repair["when"])
        self.assertNotIn("mode", repair["ansible.builtin.file"])


if __name__ == "__main__":
    unittest.main()
