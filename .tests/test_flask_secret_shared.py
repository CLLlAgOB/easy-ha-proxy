"""Every panel worker signs with one Flask secret, from the first start (F11).

From the 30 October review: on a first start both gunicorn workers found
no secret file, each made a key and wrote it, and the last writer won --
after the other had already taken its own. Until the next restart one
worker rejected the sessions and form tokens the other had signed. A file
that could not be written left each worker with a key of its own.

The key is now made under a lock, written whole and moved into place, so
the workers agree; when it cannot be kept the panel does not start.
"""

from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    import haproxy_admin  # noqa: E402

ROUNDS = 20


def worker(path, start, results):
    start.wait()
    results.put(haproxy_admin._shared_secret_key(path))


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheKey(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_two_workers_on_a_first_start_take_one_key(self):
        context = multiprocessing.get_context("fork")
        for number in range(ROUNDS):
            path = str(self.root / f"round{number}" / "secret_key")
            start = context.Barrier(2)
            results = context.Queue()
            workers = [context.Process(target=worker, args=(path, start, results)) for _ in range(2)]
            for process in workers:
                process.start()
            keys = [results.get(timeout=30) for _ in workers]
            for process in workers:
                process.join(30)
            stored = Path(path).read_text(encoding="utf-8").strip()
            self.assertEqual(keys, [stored, stored], f"round {number}")

    def test_a_kept_key_is_read_back_after_a_restart(self):
        path = str(self.root / "secret_key")
        first = haproxy_admin._shared_secret_key(path)
        self.assertEqual(haproxy_admin._shared_secret_key(path), first)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes anywhere")
    def test_a_key_that_cannot_be_kept_stops_the_start(self):
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        with mock.patch.dict(os.environ, {"HAPROXY_ADMIN_SECRET_FILE": str(locked / "secret_key"),
                                          "HAPROXY_ADMIN_SECRET_KEY": ""}):
            with self.assertRaises(RuntimeError):
                haproxy_admin._get_or_create_secret_key()

    def test_the_default_lives_where_the_image_can_write(self):
        self.assertEqual(haproxy_admin._DEFAULT_SECRET_FILE, "/var/lib/haproxy-admin/secret_key")


if __name__ == "__main__":
    unittest.main()
