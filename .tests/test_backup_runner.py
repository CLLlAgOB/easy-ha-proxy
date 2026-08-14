"""The scheduled backup runner, tested over a real socket.

The runner sent its request without a trailing newline, and the daemon
refuses anything that is not exactly one newline-terminated JSON line. So
every scheduled backup on a live gateway failed with "request must contain
exactly one JSON line" and the operator had a timer that ran nightly and
never produced anything.

The existing tests covered `run_scheduled_backup` inside the daemon and never
the runner that calls it, so the wire format between them was the one thing
nobody looked at. These tests speak the daemon's side of that wire.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backup-run.py"


class FakeBackupd:
    """Accepts a connection and applies the daemon's own framing rule."""

    def __init__(self, path: str, answer: dict):
        self.path = path
        self.answer = answer
        self.received = b""
        self.error = ""
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        connection, _ = self.server.accept()
        with connection:
            connection.settimeout(10)
            data = b""
            while b"\n" not in data and len(data) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.received = data
            # Exactly the check easy-ha-proxy-backupd makes.
            if not data.endswith(b"\n") or data.count(b"\n") != 1:
                self.error = "request must contain exactly one JSON line"
                payload = {"ok": False, "error": self.error}
            else:
                payload = self.answer
            connection.sendall((json.dumps(payload) + "\n").encode())

    def close(self):
        self.server.close()
        with contextlib_suppress():
            os.unlink(self.path)


class contextlib_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


class RunnerTests(unittest.TestCase):
    def run_runner(self, answer):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "backupd.sock")
        daemon = FakeBackupd(path, answer)
        try:
            result = subprocess.run(
                [sys.executable, str(RUNNER)],
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "BACKUPD_SOCKET_PATH": path},
            )
        finally:
            daemon.thread.join(timeout=5)
            daemon.close()
        return result, daemon

    def test_the_request_is_one_newline_terminated_line(self):
        result, daemon = self.run_runner({"ok": True, "backup_id": "abc", "uploads": ["x"]})
        self.assertEqual(daemon.error, "", daemon.received[:120])
        self.assertTrue(daemon.received.endswith(b"\n"), daemon.received[:120])
        self.assertEqual(daemon.received.count(b"\n"), 1, daemon.received[:120])
        self.assertEqual(
            json.loads(daemon.received.decode()), {"action": "run_scheduled"}
        )

    def test_a_successful_backup_exits_zero(self):
        result, _ = self.run_runner({"ok": True, "backup_id": "abc", "uploads": ["x"]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("abc", result.stdout)

    def test_a_skipped_run_is_not_a_failure(self):
        # The timer fires nightly whether or not the schedule is armed.
        result, _ = self.run_runner({"ok": True, "skipped": "the schedule is off"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("the schedule is off", result.stdout)

    def test_a_refused_backup_exits_non_zero(self):
        result, _ = self.run_runner({"ok": False, "error": "no destination"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("no destination", result.stderr)

    def test_an_absent_daemon_is_reported_rather_than_traced(self):
        directory = tempfile.mkdtemp()
        result = subprocess.run(
            [sys.executable, str(RUNNER)],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ,
                 "BACKUPD_SOCKET_PATH": os.path.join(directory, "absent.sock")},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unreachable", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
