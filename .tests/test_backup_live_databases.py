"""The disaster-recovery archive holds whole databases, not torn ones.

Checked after a run of changes: the monitoring history was already copied
through SQLite's online backup, but the security engine's database and the
alert history were archived by tar while their daemons wrote to them -- on
the test gateway each had a write-ahead log larger than the database (4 MiB
beside 1.4 MiB and 0.4 MiB), and a copy of one taken a moment after the
other restores as a torn file. The new request log (up to 256 MiB of every
visitor's address and user agent, written every second) went in the same
way.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "installer"))

import full_backup as backup  # noqa: E402

FILES = ROOT / "ansible/roles/haproxy-admin/files"


class LiveDatabases(unittest.TestCase):
    def test_their_writers_are_stopped_for_the_archive_and_the_restore(self):
        for unit in ("easy-ha-proxy-guardd.service", "easy-ha-proxy-alertd.service"):
            self.assertIn(unit, backup.QUIESCE_UNITS)


if __name__ == "__main__":
    unittest.main()
