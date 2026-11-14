"""certd checks certificate expiry by itself, once, for as long as it runs.

From the 30 October review, confirmed on a production gateway: the expiry
watch was started by every reading of the certificate-authorities list.
A gateway nobody looked at never checked; each visit to the certificates
page added a thread and an immediate scan, and the scans' warnings went
out by email in step with the visits. The watch's stop event was named
`_stop`, shadowing the threading.Thread method join() relies on.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
SPEC = importlib.util.spec_from_file_location("haproxy_certd_watch_lifecycle", CERTD_PATH)
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)


class ReadingTheList(unittest.TestCase):
    def test_starts_no_watch(self):
        started = []

        class Counting:
            def __init__(self):
                started.append(self)

            def start(self):
                pass

        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(CERTD, "CertificateExpiryWatch", Counting), \
                mock.patch.object(CERTD, "_prepare_ca_root", return_value=Path(folder)), \
                mock.patch.object(CERTD, "_get_ca_root_dir", return_value=Path(folder)), \
                mock.patch.object(CERTD, "_load_client_auth_ids", return_value=[]):
            for _ in range(2):
                try:
                    CERTD._list_certificate_authorities()
                except Exception:  # noqa: BLE001 - only the count matters here
                    pass
        self.assertEqual(started, [])


class TheWatch(unittest.TestCase):
    def test_one_is_started_by_the_daemon_and_stopped_with_it(self):
        source = CERTD_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("CertificateExpiryWatch()"), 1)
        main = source.split("\ndef main() -> None:")[1]
        self.assertIn("expiry_watch = CertificateExpiryWatch()", main)
        start = main.index("expiry_watch.start()")
        self.assertLess(start, main.index("server.serve_forever()"))
        self.assertGreater(main.index("expiry_watch.stop()"), main.index("finally:"))

    def test_it_stops_and_can_be_joined(self):
        scans = threading.Event()

        def scan(_self):
            scans.set()
            return 0

        with mock.patch.object(CERTD, "_ALERTS", object()), \
                mock.patch.object(CERTD.CertificateExpiryWatch, "scan", scan):
            watch = CERTD.CertificateExpiryWatch()
            watch.start()
            self.assertTrue(scans.wait(5))
            watch.stop()
            watch.join(5)  # raised TypeError while `_stop` was an Event
        self.assertFalse(watch.is_alive())


if __name__ == "__main__":
    unittest.main()
