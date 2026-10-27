"""The panel's own commands are bounded, and a failed port check is not "free".

Where the control socket is missing, the panel runs `systemctl reload
haproxy` and `haproxy -c` itself, with no time limit. run_cmd killed a
command that ran out of time but never reaped it. And the certificate
role's check that port 8000 is free piped ss into grep with "|| echo FREE":
an ss that failed read as a free port.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "docker" / "app" / "haproxy_admin"
PORT_CHECK = ROOT / "ansible/roles/cert/tasks/renew__10_nat_on.yml"
POSIX = os.name == "posix" and shutil.which("sh") is not None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType("panel_limits")
package.__path__ = [str(PACKAGE_ROOT)]
i18n = types.ModuleType("panel_limits.i18n")
i18n.translate = lambda value, **_kwargs: value
cache = types.ModuleType("panel_limits.cache")
cache.get_country_code = lambda *_args, **_kwargs: None
with mock.patch.dict(sys.modules, {
    "panel_limits": package, "panel_limits.i18n": i18n, "panel_limits.cache": cache,
}):
    load("panel_limits.validation", PACKAGE_ROOT / "validation.py")
    config_service = load("panel_limits.services_haproxy_config", PACKAGE_ROOT / "services_haproxy_config.py")
    utils = load("panel_limits.utils", PACKAGE_ROOT / "utils.py")


@unittest.skipUnless(POSIX, "runs fake commands as real processes")
class TheFallbacksAreBounded(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        environment = mock.patch.dict(os.environ, {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def script(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_a_reload_that_hangs_is_a_failed_reload(self):
        self.script("systemctl", "exec sleep 60\n")
        started = time.monotonic()
        with (
            mock.patch.object(config_service, "HAPROXY_CONTROL_SOCKET", str(self.root / "absent.sock")),
            mock.patch.object(config_service, "HAPROXY_RELOAD_TIMEOUT_SECONDS", 1),
        ):
            ok, _stdout, stderr = config_service.reload_haproxy()
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(ok)
        self.assertIn("did not finish within 1 seconds", stderr)

    def test_a_reload_that_finishes_is_answered_as_before(self):
        self.script("systemctl", 'echo "$@"\n')
        with mock.patch.object(config_service, "HAPROXY_CONTROL_SOCKET", str(self.root / "absent.sock")):
            self.assertEqual(config_service.reload_haproxy(), (True, "reload haproxy\n", ""))

    def check(self, haproxy):
        with (
            mock.patch.object(config_service, "HAPROXY_CONTROL_SOCKET", str(self.root / "absent.sock")),
            mock.patch.object(config_service, "HAPROXY_CFG_PATH", self.root / "no-active.cfg"),
            mock.patch.object(config_service, "HAP_CHECK_CMD", [str(haproxy), "-c", "-f"]),
            mock.patch.object(config_service, "HAPROXY_CHECK_TIMEOUT_SECONDS", 1),
        ):
            return config_service.check_cfg("global\n")

    def test_a_local_config_check_that_hangs_is_a_failed_check(self):
        started = time.monotonic()
        rc, _stdout, stderr = self.check(self.script("haproxy", "exec sleep 60\n"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(rc, 124)
        self.assertIn("did not finish within 1 seconds", stderr)

    def test_a_local_config_check_that_finishes_is_answered_as_before(self):
        rc, stdout, stderr = self.check(self.script("haproxy", 'echo "$1 $2"; echo warn >&2; exit 2\n'))
        self.assertEqual((rc, stdout, stderr), (2, "-c -f\n", "warn\n"))

    def test_run_cmd_answers_as_before(self):
        self.assertEqual(utils.run_cmd(["sh", "-c", "echo hi"]), "hi\n")
        self.assertEqual(utils.run_cmd("sh -c 'echo no >&2; exit 3'"), "Command failed (3): no")
        self.assertTrue(utils.run_cmd([str(self.root / "missing")]).startswith("Command error: "))

    def test_run_cmd_reaps_what_it_kills(self):
        started = []
        real_popen = subprocess.Popen

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            started.append(process)
            return process

        moment = time.monotonic()
        with (
            mock.patch.object(utils, "RUN_CMD_TIMEOUT_SECONDS", 0.5),
            mock.patch.object(utils.subprocess, "Popen", side_effect=popen),
        ):
            self.assertEqual(utils.run_cmd(["sleep", "30"]), "Command timed out")
        self.assertLess(time.monotonic() - moment, 10)
        self.assertEqual(len(started), 1)
        # Reaped: the exit status was collected, so no zombie stays behind.
        self.assertIsNotNone(started[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(started[0].pid, os.WNOHANG)


def port_check_tasks():
    tasks = yaml.safe_load(PORT_CHECK.read_text(encoding="utf-8"))
    names = ("Ensure port 8000 is FREE (only if we have issue targets)", "Fail if 8000 is BUSY")
    chosen = [task for task in tasks if task.get("name") in names]
    assert len(chosen) == 2, chosen
    return chosen


FAKE_SS = """\
#!/bin/sh
echo "$@" >> "$SS_LOG"
case "$SS_MODE" in
  fail) echo "Cannot open netlink socket" >&2; exit 1 ;;
  busy) echo "LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:*" ;;
  free) ;;
esac
"""


@unittest.skipIf(shutil.which("ansible-playbook") is None or not POSIX, "ansible-playbook is not installed")
class APortCheckThatFailsIsNotAFreePort(unittest.TestCase):
    def run_check(self, mode, targets=1):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        ss = bin_dir / "ss"
        ss.write_text(FAKE_SS, encoding="utf-8")
        ss.chmod(0o755)
        log = root / "ss.log"
        log.touch()
        (root / "tasks.yml").write_text(yaml.safe_dump(port_check_tasks()), encoding="utf-8")
        (root / "pb.yml").write_text(
            "- hosts: localhost\n  gather_facts: false\n"
            f"  vars:\n    issue_targets_count: {targets}\n"
            "  tasks:\n    - ansible.builtin.include_tasks: tasks.yml\n",
            encoding="utf-8",
        )
        environment = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "SS_MODE": mode,
            "SS_LOG": str(log),
            "ANSIBLE_LOCAL_TEMP": str(root / "tmp"),
            "ANSIBLE_CALLBACKS_ENABLED": "",
        }
        completed = subprocess.run(
            ["ansible-playbook", "-i", "localhost,", "-c", "local", "pb.yml"],
            cwd=root, env=environment, capture_output=True, text=True, timeout=180,
        )
        return completed.returncode, completed.stdout + completed.stderr, log.read_text().splitlines()

    def test_a_free_port_passes(self):
        rc, output, calls = self.run_check("free")
        self.assertEqual(rc, 0, output)
        self.assertEqual(calls, ["-Hltn sport = :8000"])

    def test_a_busy_port_stops_the_run(self):
        rc, output, _ = self.run_check("busy")
        self.assertNotEqual(rc, 0)
        self.assertIn("Port 8000 is in use", output)

    def test_an_ss_that_fails_stops_the_run_too(self):
        rc, output, _ = self.run_check("fail")
        self.assertNotEqual(rc, 0)
        self.assertNotIn("Port 8000 is in use", output)
        self.assertIn("Cannot open netlink socket", output)

    def test_nothing_to_issue_checks_nothing(self):
        rc, output, calls = self.run_check("fail", targets=0)
        self.assertEqual(rc, 0, output)
        self.assertEqual(calls, [])


class TheTimeoutsReadInRussian(unittest.TestCase):
    def test_every_stopped_command_is_translated(self):
        import json

        fake_flask = types.ModuleType("flask")
        fake_flask.Request = object
        fake_flask.current_app = types.SimpleNamespace(json=types.SimpleNamespace(dumps=json.dumps))
        fake_flask.g = types.SimpleNamespace(language="ru")
        fake_flask.has_request_context = lambda: False
        fake_flask.request = types.SimpleNamespace()
        with mock.patch.dict(sys.modules, {"flask": fake_flask}):
            catalogue = load("panel_limits_i18n", PACKAGE_ROOT / "i18n.py")
        expected = {
            "the reload did not finish within 120 seconds and was stopped":
                "перезагрузка не завершилась за 120 секунд; выполнение остановлено",
            "haproxy -c did not finish within 30 seconds and was stopped":
                "haproxy -c не завершился за 30 секунд; выполнение остановлено",
            "certbot did not finish within 600 seconds and was stopped":
                "certbot не завершился за 600 секунд; выполнение остановлено",
        }
        for message, russian in expected.items():
            with self.subTest(message=message):
                self.assertEqual(catalogue.translate(message, "ru"), russian)


if __name__ == "__main__":
    unittest.main()
