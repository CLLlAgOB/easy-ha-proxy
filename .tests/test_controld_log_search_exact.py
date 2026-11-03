"""controld's log searches find the right lines and stop (F10).

From the 30 October review, reproduced there: the search for an address
used `ip in line`, so 203.0.113.1 also found 203.0.113.10; the threat
totals took any " 400 " for a 400, so a 200 answer of 400 bytes counted;
and the tail read had no limit (0), so an address that was not there read
the whole file for every request.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = sys.platform == "win32"


def load():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
    spec = importlib.util.spec_from_file_location("controld_log_search_exact", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def line(ip, status, size, path="/"):
    return (f"2026-11-03T10:00:00+01:00 gw haproxy[1]: {ip}:40000 [03/Nov/2026:10:00:00.000] "
            f"fe_https~ be_shop/srv1 0/0/1/12/13 {status} {size} ---- 5/5/0/0/0 0/0 "
            f"id=x host=shop.example.test GET {path} HTTP/1.1")


@unittest.skipIf(WINDOWS, "controld needs POSIX modules")
class TheSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controld = load()

    def test_an_address_is_matched_whole(self):
        has = self.controld._line_has_ip
        self.assertTrue(has(line("203.0.113.1", 200, 512), "203.0.113.1"))
        self.assertFalse(has(line("203.0.113.10", 200, 512), "203.0.113.1"))
        self.assertFalse(has(line("1203.0.113.1", 200, 512), "203.0.113.1"))
        self.assertFalse(has("2001:db8::10 GET /", "2001:db8::1"))
        self.assertTrue(has("[2001:db8::1]:443 GET /", "2001:db8::1"))

    def test_the_tail_search_finds_only_that_address(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "haproxy.log"
            log.write_text("\n".join([line("203.0.113.1", 200, 512), line("203.0.113.10", 200, 512),
                                      line("203.0.113.100", 200, 512), line("203.0.113.1", 404, 128)]) + "\n",
                           encoding="utf-8")
            with mock.patch.object(self.controld, "LOG_FILE", str(log)):
                found = self.controld._file_tail_for_ip("203.0.113.1", limit=10)
        self.assertEqual(len(found), 2)
        self.assertTrue(all("203.0.113.1:" in text for text in found))

    def test_the_tail_read_is_bounded_by_default(self):
        self.assertGreater(self.controld.LOG_FILE_TAIL_MAX_BYTES, 0)

    def test_the_threat_totals_read_the_status_field(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "haproxy.log"
            log.write_text("\n".join([
                line("198.51.100.1", 200, 400),   # 400 bytes, not a 400
                line("198.51.100.2", 400, 0),
                line("198.51.100.2", 400, 0),
                line("198.51.100.3", 451, 0),
                line("198.51.100.4", 200, 451, path="/a 451 b"),
            ]) + "\n", encoding="utf-8")
            with mock.patch.object(self.controld, "LOG_FILE", str(log)):
                totals = self.controld.logs_attackers()
        self.assertEqual(totals["code_400"], [{"ip": "198.51.100.2", "count": 2}])
        self.assertEqual(totals["code_451"], [{"ip": "198.51.100.3", "count": 1}])
        self.assertFalse(totals["diagnostic"]["partial"])

    def test_the_threat_totals_read_only_the_tail(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "haproxy.log"
            old = line("198.51.100.9", 400, 0)
            log.write_text((old + "\n") * 50 + line("198.51.100.2", 400, 0) + "\n", encoding="utf-8")
            with mock.patch.object(self.controld, "LOG_FILE", str(log)), \
                    mock.patch.object(self.controld, "LOG_FILE_TAIL_MAX_BYTES", len(old) * 3):
                totals = self.controld.logs_attackers()
        self.assertTrue(totals["diagnostic"]["partial"])
        self.assertLessEqual(totals["diagnostic"]["total_lines"], 3)


if __name__ == "__main__":
    unittest.main()
