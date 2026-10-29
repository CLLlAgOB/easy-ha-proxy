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
sys.path.insert(0, str(ROOT / "installer"))

import full_backup as backup  # noqa: E402

FILES = ROOT / "ansible/roles/haproxy-admin/files"


class LiveDatabases(unittest.TestCase):
    def test_their_writers_are_stopped_for_the_archive_and_the_restore(self):
        for unit in ("easy-ha-proxy-guardd.service", "easy-ha-proxy-alertd.service"):
            self.assertIn(unit, backup.QUIESCE_UNITS)

    def test_the_databases_they_write_are_where_the_archive_looks(self):
        guardd = (FILES / "easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        alertd = (FILES / "easy-ha-proxy-alertd.py").read_text(encoding="utf-8")
        self.assertIn('"/var/lib/easy-ha-proxy/security/security.db"', guardd)
        self.assertIn('"/var/lib/easy-ha-proxy/alerts/alerts.db"', alertd)
        self.assertIn("/var/lib/easy-ha-proxy", backup.CORE_PATHS)
        for kept in ("var/lib/easy-ha-proxy/security", "var/lib/easy-ha-proxy/alerts"):
            self.assertFalse(any(kept.startswith(value) for value in backup.BACKUP_EXCLUDES), kept)

    def test_the_request_log_stays_out(self):
        guardd = (FILES / "easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        self.assertIn('"/var/lib/easy-ha-proxy/requests/requests.db"', guardd)
        self.assertIn("var/lib/easy-ha-proxy/requests", backup.BACKUP_EXCLUDES)
        # Its switch lives in the security database, which is archived.
        self.assertIn('REQUEST_LOG_OVERRIDE_KEY = "request_log_override"', guardd)

    def test_the_daemons_close_their_databases_when_stopped(self):
        # systemd stops a unit with SIGTERM; without a handler Python ends
        # where it stands and the finally that closes the databases never runs.
        for name in ("easy-ha-proxy-guardd.py", "easy-ha-proxy-alertd.py"):
            source = (FILES / name).read_text(encoding="utf-8")
            with self.subTest(name=name):
                self.assertIn("for signal_number in (signal.SIGTERM, signal.SIGINT):", source)
                self.assertIn("threading.Thread(target=server.shutdown, daemon=True).start()", source)
        guardd = (FILES / "easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        tail = guardd.split("def main() -> None:")[1]
        closing = tail.split("finally:")[-1]
        # The request log's last cycle is written, in the store in use now.
        self.assertIn('store = getattr(server, "requests", None)', closing)
        self.assertLess(closing.index("store.flush()"), closing.index("store.close()"))
        self.assertIn("database.close()", closing)


if __name__ == "__main__":
    unittest.main()
