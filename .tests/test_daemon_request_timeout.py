"""A connection that goes quiet does not hold a daemon's handler thread.

certd, healthd, alertd, guardd and metricsd answer HTTP on a Unix socket,
one thread per connection, and none of them limited how long a connection
could keep that thread waiting. A caller that connected and sent nothing,
or half a request, held its thread for as long as it stayed connected. Each
handler now carries a socket timeout. These start each daemon's own server
on a socket in a temporary directory.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/haproxy-admin/files"
POSIX = hasattr(socket, "AF_UNIX") and os.name == "posix"

# daemon file -> (server class, handler class, how many extra server arguments)
DAEMONS = {
    "haproxy-certd.py": ("UnixHTTPServer", "CertdHandler", 0),
    "haproxy-healthd.py": ("HealthServer", "HealthHandler", 1),
    "easy-ha-proxy-alertd.py": ("AlertServer", "AlertHandler", 1),
    "easy-ha-proxy-guardd.py": ("GuardServer", "GuardHandler", 2),
    "easy-ha-proxy-metricsd.py": ("MetricsServer", "MetricsHandler", 2),
}


def load(name):
    spec = importlib.util.spec_from_file_location(
        "request_timeout_" + name.replace("-", "_").removesuffix(".py"), FILES / name
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULES = {name: load(name) for name in DAEMONS} if POSIX else {}


def handler_of(name):
    return getattr(MODULES[name], DAEMONS[name][1])


@unittest.skipUnless(POSIX, "Unix sockets")
class EveryHandlerHasATimeout(unittest.TestCase):
    def test_each_handler_carries_its_daemons_limit(self):
        for name, module in MODULES.items():
            with self.subTest(daemon=name):
                limit = module.REQUEST_TIMEOUT_SECONDS
                self.assertTrue(0 < limit <= 60, limit)
                self.assertEqual(handler_of(name).timeout, limit)


@unittest.skipUnless(POSIX, "Unix sockets")
class AQuietConnectionIsClosed(unittest.TestCase):
    def serve(self, name):
        server_name, handler_name, extra = DAEMONS[name]
        module = MODULES[name]
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, "d.sock")
        server = getattr(module, server_name)(
            path, getattr(module, handler_name), *[mock.MagicMock() for _ in range(extra)]
        )
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(5)

        self.addCleanup(stop)
        return path

    @staticmethod
    def connect(path):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect(path)
        return client

    @staticmethod
    def read_until_closed(client):
        data = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return data
            data += chunk

    def test_nothing_sent_and_half_a_request_are_both_let_go(self):
        for name in DAEMONS:
            with self.subTest(daemon=name), mock.patch.object(handler_of(name), "timeout", 0.5):
                path = self.serve(name)
                silent = self.connect(path)
                half = self.connect(path)
                half.sendall(b"GET /health HTTP/1.0\r\nHost: x\r\n")
                started = time.monotonic()
                try:
                    self.assertEqual(self.read_until_closed(silent), b"")
                    self.assertEqual(self.read_until_closed(half), b"")
                finally:
                    silent.close()
                    half.close()
                self.assertLess(time.monotonic() - started, 8)

    def test_a_request_sent_in_time_is_still_answered(self):
        for name in DAEMONS:
            with self.subTest(daemon=name):
                path = self.serve(name)
                client = self.connect(path)
                try:
                    client.sendall(b"GET /no-such-path HTTP/1.0\r\nHost: x\r\n\r\n")
                    answer = self.read_until_closed(client)
                finally:
                    client.close()
                self.assertRegex(answer, rb"^HTTP/1\.[01] \d{3} ")

    def test_the_threads_of_quiet_connections_end(self):
        name = "easy-ha-proxy-alertd.py"
        with mock.patch.object(handler_of(name), "timeout", 0.5):
            path = self.serve(name)
            before = threading.active_count()
            clients = [self.connect(path) for _ in range(5)]
            try:
                deadline = time.monotonic() + 3
                while threading.active_count() < before + 5 and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertGreaterEqual(threading.active_count(), before + 5)
                for client in clients:
                    self.assertEqual(self.read_until_closed(client), b"")
            finally:
                for client in clients:
                    client.close()
            deadline = time.monotonic() + 5
            while threading.active_count() > before and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertLessEqual(threading.active_count(), before)


if __name__ == "__main__":
    unittest.main()
