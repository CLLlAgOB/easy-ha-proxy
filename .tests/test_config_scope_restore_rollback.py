"""A failed configuration-scope restore leaves the fixed roots as they were.

The rollback used to remove and bring back only the roots that existed
before. One the failed attempt created -- /etc/letsencrypt, say, with the
archive's certificates and keys in it -- survived a rollback that said the
previous configuration was restored. Archive extraction and the apply step
are stood in for; the removal and the rollback logic are the real ones.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import full_backup  # noqa: E402


class AFailedConfigRestore(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = Path(folder.name)
        self.existing = base / "haproxy"
        self.absent = base / "letsencrypt"
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(full_backup, "CONFIG_SCOPE_PATHS", (str(self.existing), str(self.absent))).start()
        mock.patch.object(full_backup, "config_scope_members", return_value=["haproxy", "letsencrypt"]).start()
        mock.patch.object(full_backup, "preflight_restore_control_plane").start()
        mock.patch.object(full_backup, "normalize_restored_config_permissions").start()
        mock.patch.object(full_backup, "validate_rollback_payload").start()
        mock.patch.object(full_backup, "cleanup_pre_restore_backup").start()
        mock.patch.object(full_backup, "reconcile_restored_configuration",
                          side_effect=[RuntimeError("apply failed"), None]).start()
        mock.patch.object(full_backup, "extract_payload", side_effect=self.extract).start()
        self.args = argparse.Namespace(yes=True, apply=True)

    def extract(self, archive, members=None):
        if members is not None:  # the candidate: changes one root, creates the other
            self.existing.mkdir(exist_ok=True)
            (self.existing / "haproxy.cfg").write_text("from the archive\n")
            self.absent.mkdir()
            (self.absent / "privkey.pem").write_text("archive key\n")
        else:  # the rollback archive holds what existed: the first root only
            self.existing.mkdir(exist_ok=True)
            (self.existing / "haproxy.cfg").write_text("original\n")

    def restore(self):
        with mock.patch("builtins.print"):
            with self.assertRaises(full_backup.BackupError) as raised:
                full_backup.restore_config_scope(self.args, {}, Path("candidate.tar.gz"))
        return str(raised.exception)

    def test_a_root_the_attempt_created_is_gone_after_the_rollback(self):
        self.existing.mkdir()
        (self.existing / "haproxy.cfg").write_text("original\n")
        mock.patch.object(full_backup, "create_pre_restore_backup", return_value=Path("previous-state.tar.gz")).start()
        message = self.restore()
        self.assertIn("restored automatically", message)
        self.assertEqual((self.existing / "haproxy.cfg").read_text(), "original\n")
        self.assertFalse(self.absent.exists())

    def test_with_no_root_before_everything_written_is_removed(self):
        message = self.restore()  # the real create_pre_restore_backup: nothing to keep, no archive
        self.assertIn("removed again", message)
        self.assertFalse(self.existing.exists())
        self.assertFalse(self.absent.exists())


if __name__ == "__main__":
    unittest.main()
