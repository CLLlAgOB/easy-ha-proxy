"""One visitor has one download at a time, and a download has a time limit (N06).

The panel gives downloads four transfers at once -- two in each of its two
workers -- so that administration always keeps threads of its own. Nothing
bounded how long a transfer took or how many one visitor held: four slow
clients, or one visitor four times, left everyone else at "downloads are
busy" for as long as they liked.

Held here: a second download by the same visitor is refused while the first
runs, another visitor is not affected, a transfer ends when its time is up or
when the visitor stops taking data, and everything a transfer held is given
back exactly once.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
sys.path.insert(0, str(ROOT / ".tests"))
if sys.platform != "win32":
    from haproxy_admin import access_portal as store
    from haproxy_admin import routes_access_portal as routes
    import test_access_portal as base
else:
    store = routes = base = None


@unittest.skipUnless(store, "Linux file locking")
class OneAtATime(unittest.TestCase):
    def setUp(self):
        base.PortalTests.setUp(self)
        value = store.upload("support", "helper.exe", io.BytesIO(b"fixture bytes"))
        base.PortalTests.enable(self, value)
        self.url = "/access-portal/downloads/" + value["files"][0]["id"]
        self.other = {**self.user, "Remote-User": "someone-else"}

    def test_a_second_download_by_the_same_visitor_waits_for_the_first(self):
        first = self.client.get(self.url, headers=self.user, buffered=False)
        try:
            second = self.client.get(self.url, headers=self.user)
            self.assertEqual(second.status_code, 429)
            self.assertEqual(second.headers["Retry-After"], "10")
            self.assertIn("already have a download in progress", second.get_data(as_text=True))
        finally:
            first.close()
        again = self.client.get(self.url, headers=self.user)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.data, b"fixture bytes")
        again.close()

    def test_another_visitor_is_not_kept_waiting_by_it(self):
        first = self.client.get(self.url, headers=self.user, buffered=False)
        try:
            other = self.client.get(self.url, headers=self.other)
            self.assertEqual(other.status_code, 200)
            other.close()
        finally:
            first.close()

    def test_the_turn_is_kept_across_worker_processes(self):
        # Another worker is another holder of the same lock file.
        held = store.download_turn("person")
        self.addCleanup(lambda: os.close(held) if held is not None else None)
        self.assertIsNotNone(held)
        self.assertEqual(self.client.get(self.url, headers=self.user).status_code, 429)
        os.close(held)
        held = None
        response = self.client.get(self.url, headers=self.user)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_the_refusal_is_in_the_language_of_the_page(self):
        store.configure("support", {**{k: store.settings("support")[k] for k in ("enabled", "text")},
                                    "files": [{k: f[k] for k in ("id", "title", "description")} for f in store.settings("support")["files"]],
                                    "revision": store.settings("support")["revision"], "language": "ru"})
        held = store.download_turn("person")
        self.addCleanup(os.close, held)
        response = self.client.get(self.url, headers=self.user)
        self.assertIn("У вас уже идёт загрузка.", response.get_data(as_text=True))

    def test_a_missing_file_and_a_full_house_give_the_turn_back(self):
        self.assertEqual(self.client.get("/access-portal/downloads/" + "0" * 32, headers=self.user).status_code, 404)
        with patch.object(routes, "_DOWNLOAD_SLOTS", threading.BoundedSemaphore(0)):
            self.assertEqual(self.client.get(self.url, headers=self.user).status_code, 429)
        response = self.client.get(self.url, headers=self.user)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_the_names_of_visitors_do_not_become_file_names(self):
        turn = store.download_turn("../../etc/passwd")
        self.addCleanup(os.close, turn)
        names = os.listdir(self.root / "portals" / ".downloads")
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^[a-f0-9]{64}$")


@unittest.skipUnless(routes, "Linux application imports")
class TheLease(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.slots = threading.BoundedSemaphore(1)
        patch.object(routes, "_DOWNLOAD_SLOTS", self.slots).start()
        self.slots.acquire()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.turn = os.open(Path(folder.name) / "turn", os.O_CREAT | os.O_RDWR)
        self.sock = Mock()
        self.sock.gettimeout.return_value = None

    def test_a_transfer_past_its_time_is_ended(self):
        lease = routes._DownloadLease(io.BytesIO(b"data"), self.turn, self.sock, seconds=-1)
        self.addCleanup(lease.close)
        with self.assertRaises(TimeoutError):
            lease.read(4)

    def test_a_transfer_within_its_time_reads_as_usual(self):
        lease = routes._DownloadLease(io.BytesIO(b"data"), self.turn, self.sock)
        self.addCleanup(lease.close)
        self.assertEqual(lease.read(2), b"da")
        self.assertGreater(lease.deadline, time.monotonic() + routes.DOWNLOAD_SECONDS - 5)

    def test_the_server_is_not_offered_a_descriptor_to_hand_to_the_kernel(self):
        with tempfile.TemporaryFile() as stream:
            lease = routes._DownloadLease(stream, self.turn, self.sock)
            self.addCleanup(lease.close)
            self.assertFalse(hasattr(lease, "fileno"))
            self.assertTrue(hasattr(lease, "seek"))

    def test_a_visitor_who_stops_taking_data_is_not_waited_for_longer_than_a_minute(self):
        lease = routes._DownloadLease(io.BytesIO(b"data"), self.turn, self.sock)
        self.sock.settimeout.assert_called_once_with(routes.DOWNLOAD_STALL_SECONDS)
        lease.close()
        self.assertEqual(self.sock.settimeout.call_args.args, (None,))

    def test_everything_is_given_back_once_however_often_it_is_closed(self):
        lease = routes._DownloadLease(io.BytesIO(b"data"), self.turn, self.sock)
        lease.close()
        lease.close()
        self.assertTrue(self.slots.acquire(blocking=False))
        with self.assertRaises(OSError):
            os.fstat(self.turn)

    def test_a_socket_that_cannot_be_timed_does_not_stop_the_download(self):
        self.sock.gettimeout.side_effect = OSError("not a socket")
        lease = routes._DownloadLease(io.BytesIO(b"data"), self.turn, self.sock)
        self.assertEqual(lease.read(), b"data")
        lease.close()
        self.sock.settimeout.assert_not_called()

    def test_an_hour_carries_the_largest_attachment_over_a_slow_link(self):
        needed = store.MAX_FILE_BYTES * 8 / routes.DOWNLOAD_SECONDS / 1e6
        self.assertLess(needed, 0.35)


if __name__ == "__main__":
    unittest.main()
