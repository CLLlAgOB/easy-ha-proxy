"""History tells saved from applied, and a restore loses nothing (F15).

From the 30 October review: the history page called the working YAML files
"Applied now", though they hold whatever an editor saved and nobody has
applied yet -- after a save without Apply the comparison already showed it
as running. A restore wrote over those files, losing that unapplied work
without a word, and wrote them one after another before its guarded part:
a failure on the second left the first already replaced.

Now "applied" reads the snapshot of the last confirmed configuration and
"current" the saved files; a restore holds every source lock, keeps any
unapplied changes before replacing them, and puts all three files in place
or none.
"""

from __future__ import annotations

import fcntl
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_config_history as history  # noqa: E402

APPLIED = {
    "vars.yml": "site_defaults: {}\n",
    "websites.yml": "sites:\n- name: shop\n  domain: shop.example.test\n",
    "tcp.yml": "tcp_proxies: []\n",
}
OLD = {
    "vars.yml": "site_defaults: {}\n",
    "websites.yml": "sites: []\n",
    "tcp.yml": "tcp_proxies: []\n",
}


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class Sources(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        working = self.root / "config"
        applied = self.root / "backups" / "haproxy"
        working.mkdir()
        applied.mkdir(parents=True)
        self.working = {
            "vars.yml": working / "vars.yml",
            "websites.yml": working / "websites.yml",
            "tcp.yml": working / "tcp.yml",
        }
        snapshots = {name: applied / f"last_applied_{name}" for name in self.working}
        for name, text in APPLIED.items():
            self.working[name].write_text(text, encoding="utf-8")
            snapshots[name].write_text(text, encoding="utf-8")
        # The globals of the very module the history service is bound to:
        # other tests swap the package in sys.modules, so a fresh import
        # here could be a different copy.
        self.config = history._current_config_source_paths.__globals__
        patcher = mock.patch.dict(self.config, {
            "CONFIG_YAML": self.working["vars.yml"],
            "WEBSITES_YAML": self.working["websites.yml"],
            "TCP_YAML": self.working["tcp.yml"],
            "HAPROXY_STATE_VARS": snapshots["vars.yml"],
            "HAPROXY_STATE_WEBSITES": snapshots["websites.yml"],
            "HAPROXY_STATE_TCP": snapshots["tcp.yml"],
            "BASE_DIR": self.root,
            "config_transaction_is_pending": lambda: (False, ""),
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def save_without_apply(self):
        ok, message = self.config["update_yaml_file"](
            "websites", "sites:\n- name: shop\n  domain: shop.example.test\n  backend_port: 8443\n")
        self.assertTrue(ok, message)

    def text(self, name):
        return self.working[name].read_text(encoding="utf-8")

    def test_a_save_without_apply_does_not_move_what_is_applied(self):
        self.assertFalse(history.unapplied_changes())
        self.save_without_apply()
        self.assertEqual(history.applied_sources(), APPLIED)
        self.assertTrue(history.unapplied_changes())
        changed = history.diff(history.APPLIED, history.CURRENT)
        self.assertFalse(changed["identical"])

    def test_a_failed_second_file_leaves_the_first_as_it_was(self):
        real_replace = history.os.replace
        calls = []

        def failing(source, target):
            calls.append(target)
            if len(calls) == 2:
                raise OSError("disk full")
            return real_replace(source, target)

        with mock.patch.object(history.os, "replace", side_effect=failing), \
                self.assertRaises(OSError):
            history._write_sources(OLD)
        for name, text in APPLIED.items():
            self.assertEqual(self.text(name), text, name)
        self.assertEqual(sorted(p.name for p in self.working["vars.yml"].parent.glob(".*.restore*")), [])

    def restore(self):
        locked = []

        def begin(_cfg):
            # Another worker's save must wait for the restore to finish.
            lock = self.working["websites.yml"].parent / ".websites.yml.lock"
            with lock.open("a+b") as handle:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    locked.append(True)
            return {"ok": True, "state": "pending_confirmation"}

        # The restore imports these at call time, from whatever sys.modules holds.
        live = "haproxy_admin.services_haproxy_config."
        with mock.patch.object(history, "version_sources", return_value=({"id": "v1"}, OLD)), \
                mock.patch(live + "render_haproxy_cfg", return_value="global\n"), \
                mock.patch(live + "preflight_cfg_confirmation", return_value={"ok": True}), \
                mock.patch(live + "begin_cfg_confirmation", side_effect=begin), \
                mock.patch("haproxy_admin.services_haproxy_vars.validate_admin_access_for_client"):
            result = history.restore("v1", client_ip="203.0.113.5")
        return result, locked

    def test_unapplied_changes_are_kept_before_a_restore(self):
        self.save_without_apply()
        draft = self.text("websites.yml")
        result, _ = self.restore()
        kept = self.root / result["set_aside"]
        self.assertEqual((kept / "websites.yml").read_text(encoding="utf-8"), draft)
        self.assertEqual(self.text("websites.yml"), OLD["websites.yml"])

    def test_nothing_is_set_aside_when_nothing_was_unapplied(self):
        result, _ = self.restore()
        self.assertNotIn("set_aside", result)

    def test_a_restore_holds_the_editors_off(self):
        _, locked = self.restore()
        self.assertEqual(locked, [True])


if __name__ == "__main__":
    unittest.main()
