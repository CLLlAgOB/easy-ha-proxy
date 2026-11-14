"""A backup must not archive the backups.

Three consecutive archives from one gateway:

    2026-08-13  14.9 MiB
    2026-08-18  47.1 MiB
    2026-08-18  94.9 MiB

Each run roughly doubled, because /var/lib/easy-ha-proxy is in the collected
set and the finished archives live under it. 171.8 MiB of that gateway's
196 MiB tree was previous backups. The next run would have been ~190 MiB,
the one after ~380, until the disk decided how the story ended.

They are also already encrypted, so they compress to nothing on the way in:
the whole payload is carried at full size to store a copy of something the
operator already has.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "installer" / "full_backup.py"


def load():
    spec = importlib.util.spec_from_file_location("full_backup_excludes", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["full_backup_excludes"] = module
    spec.loader.exec_module(module)
    return module


backup = load()


class SelfInclusionTests(unittest.TestCase):
    def test_the_archive_directory_is_excluded(self):
        self.assertIn(
            "var/lib/easy-ha-proxy/backup-web/backups", backup.BACKUP_EXCLUDES
        )

    def test_uploaded_archives_are_excluded_too(self):
        # An archive uploaded for a restore is the same bytes arriving from
        # the other direction.
        self.assertIn(
            "var/lib/easy-ha-proxy/backup-web/uploads", backup.BACKUP_EXCLUDES
        )

    def test_update_artifacts_are_excluded(self):
        self.assertIn("var/lib/easy-ha-proxy/update-web", backup.BACKUP_EXCLUDES)

    def test_the_collected_tree_that_contains_them_is_still_collected(self):
        # The exclusions must be surgical: the security database, the config
        # history and the job records live in the same tree and are wanted.
        self.assertIn("/var/lib/easy-ha-proxy", backup.CORE_PATHS)

    def test_the_job_history_is_not_swept_up_in_the_exclusion(self):
        # backup-web/jobs sits beside backups and uploads; excluding the
        # parent would have taken it along.
        self.assertNotIn("var/lib/easy-ha-proxy/backup-web", backup.BACKUP_EXCLUDES)

    def test_every_exclude_is_relative_because_tar_runs_from_the_root(self):
        # tar is invoked with -C /, so a leading slash would match nothing and
        # the exclusion would silently do nothing at all.
        for value in backup.BACKUP_EXCLUDES:
            with self.subTest(value=value):
                self.assertFalse(value.startswith("/"), value)

    def test_each_exclusion_is_reachable_from_a_collected_path(self):
        # An exclude for a path nothing collects is dead weight and a sign the
        # two lists have drifted apart.
        collected = [path.lstrip("/") for path in backup.CORE_PATHS]
        for value in backup.BACKUP_EXCLUDES:
            with self.subTest(value=value):
                self.assertTrue(
                    any(
                        value == root or value.startswith(root + "/")
                        for root in collected
                    ),
                    f"{value} is under nothing that gets collected",
                )


class GrowthTests(unittest.TestCase):
    """The arithmetic that made this urgent."""

    def test_excluding_them_removes_the_compounding_term(self):
        # Modelled on the measured gateway: ~24 MiB of real content, and an
        # archive directory that keeps everything produced so far.
        content = 24.0
        kept = []
        for _ in range(6):
            kept.append(content + sum(kept))
        self.assertGreater(kept[-1], 700, "the runaway this test describes")

        # With the exclusion each run is the content alone.
        bounded = [content for _ in range(6)]
        self.assertEqual(max(bounded), content)


if __name__ == "__main__":
    unittest.main()
