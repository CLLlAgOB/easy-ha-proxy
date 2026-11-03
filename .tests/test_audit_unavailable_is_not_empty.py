"""A change log that cannot be read is not shown as an empty one (F28).

From the 30 October review: AuditLog.query answered a missing connection or
a SQLite error with total 0 and no events, the route added ok=True, and the
page said "Nothing has been recorded for this period".
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import audit  # noqa: E402

APP = ROOT / "docker/app/haproxy_admin"


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheQuery(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.log = audit.AuditLog(str(Path(folder.name) / "audit.db"))

    def test_a_readable_log_says_so(self):
        self.assertTrue(self.log.query()["available"])

    def test_no_connection_is_unavailable(self):
        with mock.patch.object(self.log, "_connect", return_value=None):
            found = self.log.query()
        self.assertFalse(found["available"])
        self.assertTrue(found["error"])

    def test_a_failing_query_is_unavailable_with_its_reason(self):
        broken = mock.Mock()
        broken.execute.side_effect = audit.sqlite3.OperationalError("database disk image is malformed")
        with mock.patch.object(self.log, "_connect", return_value=broken):
            found = self.log.query()
        self.assertEqual((found["available"], found["events"]), (False, []))
        self.assertIn("malformed", found["error"])


class ThePage(unittest.TestCase):
    def test_it_says_unavailable_rather_than_empty(self):
        script = (APP / "static/js/audit.js").read_text(encoding="utf-8")
        self.assertIn("if (payload.available === false) {", script)
        self.assertIn('t("The change log cannot be read now")', script)


if __name__ == "__main__":
    unittest.main()
