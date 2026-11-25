"""The Rust guardd-core daemon and parser, driven from outside.

The daemon tests start the real binary against fake HAProxy and alert
sockets: it must drain an active request on SIGTERM and keep answering its
API while HAProxy or the alert engine block. The parser test replays access
lines whose expected fields the Python guardd, the reference the Rust port
matched field for field, recorded before it was removed
(fixtures/guardd_parse_vectors.json).
"""

from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIGNATURES_PATH = ROOT / "ansible" / "roles" / "haproxy-admin" / "files" / "scanner-signatures.json"
VECTORS = Path(__file__).resolve().parent / "fixtures" / "guardd_parse_vectors.json"


def _find_rust_bin() -> Path | None:
    env = os.environ.get("GUARDD_RUST_BIN")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in (
        ROOT / "rust" / "guardd" / "target" / "release" / "guardd-core",
        ROOT / "rust" / "guardd" / "target" / "debug" / "guardd-core",
    ):
        if candidate.is_file():
            return candidate
    return None


class RustGuarddTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux Unix sockets")
    def test_daemon_drains_an_active_request_on_sigterm(self):
        import grp

        rust = _find_rust_bin()
        if rust is None:
            self.skipTest("guardd-core binary was not built")

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            runtime = root / "runtime.sock"
            api = root / "api.sock"
            log = root / "access.log"
            log.touch()
            config = root / "guard.json"
            config.write_text(json.dumps({
                "mode": "monitor",
                "sources": {"haproxy_socket": str(runtime), "log_file": str(log)},
            }), encoding="utf-8")
            listener = stack.enter_context(socket.socket(socket.AF_UNIX))
            listener.settimeout(6)
            listener.bind(str(runtime))
            listener.listen()
            with subprocess.Popen(
                [str(rust), "serve", "--config", str(config), "--socket", str(api),
                 "--database", str(root / "security.db"), "--signatures", str(SIGNATURES_PATH)],
                env={**os.environ, "GUARDD_SOCKET_GROUP": grp.getgrgid(os.getegid()).gr_name,
                     "GUARDD_TOKEN": "local-test-token", "ALERTD_TOKEN": ""},
                stderr=subprocess.DEVNULL,
            ) as daemon:
                try:
                    poll, _ = listener.accept()
                    stack.enter_context(poll)
                    poll.settimeout(3)
                    self.assertEqual(poll.recv(256).strip(), b"show table")
                    deadline = time.monotonic() + 6
                    while not api.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertEqual(stat.S_IMODE(api.stat().st_mode), 0o660)

                    def connect():
                        stream = stack.enter_context(socket.socket(socket.AF_UNIX))
                        stream.settimeout(2)
                        stream.connect(str(api))
                        return stream

                    health = connect()
                    health.sendall(b"GET /api/v1/guard/health HTTP/1.0\r\n\r\n")
                    self.assertIn(b"200 OK", health.recv(256))

                    bad = connect()
                    bad.sendall(b"POST /api/v1/guard/mode HTTP/1.0\r\nContent-Length: 5\r\n\r\n")
                    self.assertIn(b"403 Forbidden", bad.recv(256))

                    idle = connect()
                    idle.sendall(b"GET ")
                    active = connect()
                    active.sendall(b"GET /api/v1/guard/live?banned=1 HTTP/1.0\r\n\r\n")
                    reply, _ = listener.accept()
                    stack.enter_context(reply)
                    reply.settimeout(3)
                    self.assertEqual(reply.recv(256).strip(), b"show table tbl_ban")

                    daemon.terminate()
                    deadline = time.monotonic() + 3
                    while api.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertFalse(api.exists())
                    poll.close()
                    self.assertIsNone(daemon.poll())
                    reply.sendall(b"# table: tbl_ban, type: ip, size:1024, used:0\n")
                    reply.close()
                    self.assertIn(b"200 OK", active.recv(256))
                    self.assertEqual(idle.recv(16), b"")
                    self.assertEqual(daemon.wait(timeout=3), 0)
                finally:
                    if daemon.poll() is None:
                        daemon.kill()

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux Unix sockets")
    def test_api_responds_while_enforcement_io_is_blocked(self):
        import grp

        rust = _find_rust_bin()
        if rust is None:
            self.skipTest("guardd-core binary was not built")

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            runtime = root / "runtime.sock"
            api = root / "api.sock"
            log = root / "access.log"
            log.touch()
            config = root / "guard.json"
            config.write_text(json.dumps({
                "mode": "enforce",
                "poll_interval_seconds": 1,
                "sources": {"haproxy_socket": str(runtime), "log_file": str(log)},
            }), encoding="utf-8")
            listener = stack.enter_context(socket.socket(socket.AF_UNIX))
            listener.settimeout(6)
            listener.bind(str(runtime))
            listener.listen(16)
            with subprocess.Popen(
                [str(rust), "serve", "--config", str(config), "--socket", str(api),
                 "--database", str(root / "security.db"), "--signatures", str(SIGNATURES_PATH)],
                env={**os.environ, "GUARDD_SOCKET_GROUP": grp.getgrgid(os.getegid()).gr_name,
                     "GUARDD_TOKEN": "local-test-token", "ALERTD_TOKEN": ""},
                stderr=subprocess.DEVNULL,
            ) as daemon:
                try:
                    # 1. read_tables: "show table"
                    c1, _ = listener.accept()
                    stack.enter_context(c1)
                    c1.settimeout(3)
                    self.assertEqual(c1.recv(256).strip(), b"show table")
                    c1.sendall(b"# table: tbl_ban, type: ip, size:1024, used:0\n")
                    c1.close()

                    # 2. read_tables: "show table tbl_ban"
                    c2, _ = listener.accept()
                    stack.enter_context(c2)
                    c2.settimeout(3)
                    self.assertEqual(c2.recv(256).strip(), b"show table tbl_ban")
                    c2.sendall(b"# table: tbl_ban, type: ip, size:1024, used:0\n")
                    c2.close()

                    # 3. apply_enforcement: "show table tbl_ban" (active_bans) — HOLD OPEN!
                    blocked, _ = listener.accept()
                    stack.enter_context(blocked)
                    blocked.settimeout(3)
                    cmd = blocked.recv(256).strip()
                    self.assertEqual(cmd, b"show table tbl_ban")

                    deadline = time.monotonic() + 6
                    while not api.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(api.exists())

                    # While enforcement HAProxy I/O is blocked, API read endpoints
                    # must answer immediately without waiting for enforcement.
                    for path in ("/api/v1/guard/health", "/api/v1/guard/reputation", "/api/v1/guard/bans/schedule"):
                        t0 = time.monotonic()
                        stream = stack.enter_context(socket.socket(socket.AF_UNIX))
                        stream.settimeout(1.0)
                        stream.connect(str(api))
                        stream.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
                        reply = stream.recv(512)
                        elapsed = time.monotonic() - t0
                        self.assertIn(b"200 OK", reply, f"{path} failed: {reply!r}")
                        self.assertLess(elapsed, 1.0, f"{path} took {elapsed:.2f}s while enforcement blocked")

                    blocked.sendall(b"# table: tbl_ban, type: ip, size:1024, used:0\n")
                    blocked.close()
                    daemon.terminate()
                    self.assertEqual(daemon.wait(timeout=5), 0)
                finally:
                    if daemon.poll() is None:
                        daemon.kill()

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux Unix sockets")
    def test_api_responds_while_alertd_io_is_blocked(self):
        import grp

        rust = _find_rust_bin()
        if rust is None:
            self.skipTest("guardd-core binary was not built")

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            missing_runtime = root / "missing-runtime.sock"
            alert_sock = root / "alertd.sock"
            api = root / "api.sock"
            log = root / "access.log"
            log.touch()
            config = root / "guard.json"
            config.write_text(json.dumps({
                "mode": "monitor",
                "poll_interval_seconds": 1,
                "sources": {"haproxy_socket": str(missing_runtime), "log_file": str(log)},
            }), encoding="utf-8")
            alert_ln = stack.enter_context(socket.socket(socket.AF_UNIX))
            alert_ln.settimeout(20)
            alert_ln.bind(str(alert_sock))
            alert_ln.listen(4)
            with subprocess.Popen(
                [str(rust), "serve", "--config", str(config), "--socket", str(api),
                 "--database", str(root / "security.db"), "--signatures", str(SIGNATURES_PATH)],
                env={**os.environ, "GUARDD_SOCKET_GROUP": grp.getgrgid(os.getegid()).gr_name,
                     "GUARDD_TOKEN": "local-test-token",
                     "ALERTD_SOCKET_PATH": str(alert_sock),
                     "ALERTD_TOKEN": "alert-test-token"},
                stderr=subprocess.DEVNULL,
            ) as daemon:
                try:
                    # Wait for engine_failing alert after consecutive poll failures, then HOLD OPEN!
                    stalled, _ = alert_ln.accept()
                    stack.enter_context(stalled)
                    stalled.settimeout(3)
                    req = stalled.recv(4096)
                    self.assertIn(b"security.engine_failing", req)

                    t0 = time.monotonic()
                    stream = stack.enter_context(socket.socket(socket.AF_UNIX))
                    stream.settimeout(1.0)
                    stream.connect(str(api))
                    stream.sendall(b"GET /api/v1/guard/health HTTP/1.0\r\n\r\n")
                    reply = stream.recv(512)
                    elapsed = time.monotonic() - t0
                    self.assertIn(b"200 OK", reply)
                    self.assertLess(elapsed, 1.0)

                    stalled.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    stalled.close()
                    daemon.terminate()
                    self.assertEqual(daemon.wait(timeout=5), 0)
                finally:
                    if daemon.poll() is None:
                        daemon.kill()

    def test_parser_matches_the_recorded_reference(self) -> None:
        rust_bin = _find_rust_bin()
        if rust_bin is None:
            self.skipTest("Rust guardd-core binary not built")
        cases = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]
        proc = subprocess.run(
            [str(rust_bin), "parse", "--signatures", str(SIGNATURES_PATH)],
            input="\n".join(case["line"] for case in cases) + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), len(cases))
        for index, (case, row) in enumerate(zip(cases, rows, strict=True)):
            with self.subTest(index=index, line=case["line"][:80]):
                self.assertEqual(row["parsed"], case["parsed"])
                if case["parsed"] is not None:
                    self.assertEqual(row["path_category"], case["path_category"])
                    self.assertEqual(row["ua_token"], case["ua_token"])
                    self.assertEqual(row["ua_category"], case["ua_category"])


if __name__ == "__main__":
    unittest.main()
