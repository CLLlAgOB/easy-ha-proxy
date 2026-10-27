"""Every command certd runs is bounded in time, and a timeout stops all of it.

A certbot that hung kept its request thread and its lock for good: every
later issuance, and the snap's renewal timer, then failed with "another
instance is already running" until certd was restarted. certbot comes from a
snap, so the process a plain subprocess timeout kills is `snap run`; the
certbot under it would live on. These tests run real processes.
"""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"


def load_certd():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_certd_bounded", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


certd = load_certd()
POSIX = hasattr(os, "killpg") and shutil.which("sh") is not None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers; read its state where /proc exists.
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        return "\nState:\tZ" not in status.read_text()
    return True


def wait_gone(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


@unittest.skipUnless(POSIX, "needs a POSIX shell and process groups")
class RunningBounded(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_a_command_that_finishes_is_answered_as_it_was(self):
        result = certd._run_bounded(["sh", "-c", "echo out; echo err >&2; exit 3"], timeout=10)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")

    def test_a_timeout_stops_the_command_and_what_it_started(self):
        # The shell stands in for `snap run`, the background sleep for the
        # certbot under it.
        pidfile = self.root / "child.pid"
        started = time.monotonic()
        result = certd._run_bounded(
            ["sh", "-c", f"echo begun; sleep 30 & echo $! > {pidfile}; wait"],
            timeout=1,
        )
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(result.returncode, certd.TIMED_OUT_RC)
        self.assertEqual(result.stdout, "begun\n")
        self.assertIn("did not finish within 1 seconds and was stopped", result.stderr)
        child = int(pidfile.read_text())
        self.assertTrue(wait_gone(child), "the grandchild outlived the timeout")

    def test_one_that_left_the_group_does_not_hold_certd_too(self):
        # A descendant in a session of its own escapes the kill and keeps
        # the output pipe open; certd stops reading instead of waiting on it.
        if shutil.which("setsid") is None:
            self.skipTest("needs setsid")
        pidfile = self.root / "escaped.pid"
        started = time.monotonic()
        result = certd._run_bounded(
            ["sh", "-c", f"setsid sh -c 'echo $$ > {pidfile}; exec sleep 30' & sleep 30"],
            timeout=1,
        )
        try:
            self.assertLess(time.monotonic() - started, 15)
            self.assertEqual(result.returncode, certd.TIMED_OUT_RC)
            self.assertIn("was stopped", result.stderr)
        finally:
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), 9)
                except (ProcessLookupError, ValueError):
                    pass

    def test_bytes_in_bytes_out(self):
        result = certd._run_bounded(["sh", "-c", "printf 'a'; sleep 30"], timeout=1, text=False)
        self.assertEqual(result.stdout, b"a")
        self.assertIn(b"was stopped", result.stderr)

    def test_a_missing_program_is_the_error_it_always_was(self):
        with self.assertRaises(FileNotFoundError):
            certd._run_bounded([str(self.root / "no-such-program")], timeout=5)


class EveryCommandIsBounded(unittest.TestCase):
    def test_certd_runs_nothing_around_the_bounded_runner(self):
        tree = ast.parse(DAEMON.read_text(encoding="utf-8"))
        direct = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"run", "call", "check_call", "check_output", "Popen"}
            ):
                direct.append((node.func.attr, node.lineno))
        runner = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_run_bounded"
        )
        inside = {
            (call.func.attr, call.lineno)
            for call in ast.walk(runner)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        self.assertEqual([item for item in direct if item not in inside], [])

    def test_certbot_gets_its_dns_wait_on_top_of_its_own_time(self):
        self.assertEqual(certd._certbot_timeout("", None), certd.CERTBOT_TIMEOUT_SECONDS)
        self.assertEqual(
            certd._certbot_timeout("cloudflare-main", 300), certd.CERTBOT_TIMEOUT_SECONDS + 300
        )
        self.assertEqual(
            certd._certbot_timeout("cloudflare-main", "junk"),
            certd.CERTBOT_TIMEOUT_SECONDS + certd.DNS_PROPAGATION_DEFAULT,
        )
        self.assertEqual(
            certd._certbot_timeout("cloudflare-main", 10 ** 6),
            certd.CERTBOT_TIMEOUT_SECONDS + certd.DNS_PROPAGATION_MAX,
        )


class ATimeoutIsAFailureSaidPlainly(unittest.TestCase):
    def stopped(self, argv, **_kwargs):
        import subprocess

        return subprocess.CompletedProcess(
            argv, certd.TIMED_OUT_RC, "", f"{Path(argv[0]).name} did not finish within 600 seconds and was stopped"
        )

    def test_issuance_reports_the_stopped_certbot(self):
        with mock.patch.object(certd, "_run_bounded", side_effect=self.stopped):
            result = certd._run_certbot_for_lineage(
                lineage="shop", domain="shop.example.com", alt_names=[],
                key_type="ecdsa", email="a@example.com", rsa_key_size=2048,
                ecdsa_curve="secp256r1",
            )
        self.assertEqual(result["rc"], certd.TIMED_OUT_RC)
        self.assertIn("was stopped", result["stderr"])

    def test_a_reload_that_hangs_is_a_failed_reload(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "haproxy"
            config = Path(temporary) / "haproxy.cfg"
            binary.write_text("", encoding="utf-8")
            config.write_text("", encoding="utf-8")
            calls = []

            def run(argv, **kwargs):
                calls.append((argv[0], kwargs["timeout"]))
                if argv[0] == "systemctl":
                    return self.stopped(argv)
                import subprocess

                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                mock.patch.object(certd, "CERTD_DRY_RUN", False),
                mock.patch.object(certd, "HAPROXY_BIN", binary),
                mock.patch.object(certd, "HAPROXY_CFG", config),
                mock.patch.object(certd, "_run_bounded", side_effect=run),
            ):
                rc, _stdout, stderr = certd._reload_haproxy()
        self.assertEqual(rc, certd.TIMED_OUT_RC)
        self.assertIn("was stopped", stderr)
        self.assertEqual(
            calls,
            [(str(binary), certd.HAPROXY_CHECK_TIMEOUT_SECONDS),
             ("systemctl", certd.HAPROXY_RELOAD_TIMEOUT_SECONDS)],
        )


if __name__ == "__main__":
    unittest.main()
