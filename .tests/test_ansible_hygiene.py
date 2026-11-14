"""The roles report failures and changes as they happen.

ignore_errors let a helper that failed to stop count as removed, and on a
handler with no fallback it let a failed HAProxy reload pass. Command tasks
without changed_when reported a change on every run, the PEM build most of
all: it rewrote every certificate file on every apply. Handlers nothing
notified were kept as if they did something.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from jinja2 import Environment
import yaml


ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
COMMANDS = {"command", "shell", "raw", "ansible.builtin.command", "ansible.builtin.shell",
            "ansible.builtin.raw", "ansible.legacy.command", "ansible.legacy.shell"}


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))
Loader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))


def role_files():
    for path in sorted(ANSIBLE.rglob("*.yml")):
        if "tasks" in path.parts or "handlers" in path.parts:
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
            if isinstance(data, list):
                yield path, data


def tasks_in(items):
    for task in items or []:
        if isinstance(task, dict):
            yield task
            for key in ("block", "rescue", "always"):
                yield from tasks_in(task.get(key))


def walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


class FailuresAreNotSwallowed(unittest.TestCase):
    def test_the_only_ignore_errors_is_the_reload_with_a_fallback(self):
        found = [
            (path.relative_to(ROOT).as_posix(), task.get("name"))
            for path, data in role_files()
            for task in tasks_in(data)
            if task.get("ignore_errors")
        ]
        self.assertEqual(
            found,
            [("ansible/roles/haproxy/handlers/main.yml", "apply validated HAProxy configuration")],
        )
        handlers = yaml.safe_load((ANSIBLE / "roles/haproxy/handlers/main.yml").read_text(encoding="utf-8"))
        fallback = next(h for h in handlers if h.get("name") == "hard restart haproxy if reload failed")
        self.assertIn("reload_res is failed", fallback["when"])
        self.assertEqual(fallback["service"]["state"], "restarted")

    def test_authelia_removal_skips_only_helpers_that_were_never_installed(self):
        tasks = list(tasks_in(yaml.safe_load(
            (ANSIBLE / "roles/authelia/tasks/remove.yml").read_text(encoding="utf-8")
        )))
        names = [task.get("name") for task in tasks]
        facts = names.index("Collect the services systemd knows")
        stop = names.index("Stop and disable the Authelia helper services")
        self.assertLess(facts, stop)
        task = tasks[stop]
        self.assertEqual(task["when"], "item in ansible_facts.services")
        self.assertEqual(
            task["loop"],
            ["authelia-configd.service", "authelia-usersd.service", "authelia-bansd.service"],
        )
        self.assertNotIn("failed_when", task)


class ChangesAreReported(unittest.TestCase):
    def test_every_command_says_when_it_changed_something(self):
        missing = []
        for path, data in role_files():
            for task in tasks_in(data):
                module = next((key for key in task if key in COMMANDS), None)
                if not module:
                    continue
                body = task[module] if isinstance(task[module], dict) else {}
                args = task.get("args") or {}
                guarded = {"creates", "removes"} & (set(body) | set(args))
                if "changed_when" not in task and not guarded:
                    missing.append(f"{path.relative_to(ROOT).as_posix()}: {task.get('name')}")
        self.assertEqual(missing, [])

    def test_every_handler_is_notified_by_something(self):
        notified = set()
        handlers = []
        for path in sorted(ANSIBLE.rglob("*.yml")):
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
            for node in walk(data):
                value = node.get("notify")
                notified.update([value] if isinstance(value, str) else list(value or []))
            if "handlers" in path.parts and isinstance(data, list):
                handlers += [(path, handler) for handler in data if isinstance(handler, dict)]
        self.assertTrue(handlers)
        unused = []
        for path, handler in handlers:
            listen = handler.get("listen")
            topics = {handler.get("name")} | ({listen} if isinstance(listen, str) else set(listen or []))
            if not topics & notified:
                unused.append(f"{path.relative_to(ROOT).as_posix()}: {handler.get('name')}")
        self.assertEqual(unused, [])


FAKE_STAT = """#!/bin/sh
# Report the real mode, and the owner the handler expects, as a root run would.
mode="$(/usr/bin/stat -c %a "$3")"
echo "$mode root:root"
"""


@unittest.skipUnless(os.name == "posix" and shutil.which("bash") and os.path.exists("/usr/bin/stat"),
                     "runs the handler's script with bash")
class ThePEMBuildRewritesOnlyWhatChanged(unittest.TestCase):
    """Runs the handler's own script, with the Let's Encrypt directory moved
    into a temporary one and chown/stat standing in for a root run."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        handlers = yaml.safe_load((ANSIBLE / "roles/cert/handlers/main.yml").read_text(encoding="utf-8"))
        task = next(h for h in handlers if h.get("name", "").startswith("Build PEMs (sites without key_types"))
        self.changed_when = task["changed_when"]
        script = Environment().from_string(task["ansible.builtin.shell"]).render(
            lineage="shop.example.com",
            dest=str(self.root / "certs" / "shop.example.com.pem"),
            haproxy_certs_available_dir=str(self.root / "available"),
        )
        self.script = script.replace("/etc/letsencrypt/live/", f"{self.root}/live/")
        self.live = self.root / "live" / "shop.example.com"
        self.dest = self.root / "certs" / "shop.example.com.pem"
        (self.root / "certs").mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "chown").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (bin_dir / "stat").write_text(FAKE_STAT, encoding="utf-8")
        for tool in bin_dir.iterdir():
            tool.chmod(0o755)
        self.environment = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

    def issue(self, text):
        self.live.mkdir(parents=True, exist_ok=True)
        (self.live / "fullchain.pem").write_text(f"CERT {text}\n", encoding="utf-8")
        (self.live / "privkey.pem").write_text(f"KEY {text}\n", encoding="utf-8")

    def build(self):
        done = subprocess.run(["bash", "-c", self.script], capture_output=True, text=True,
                              env=self.environment, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return "PEM written:" in done.stdout

    def test_a_new_certificate_is_written_and_reported(self):
        self.issue("one")
        self.assertTrue(self.build())
        self.assertEqual(self.dest.read_text(), "CERT one\nKEY one\n")
        self.assertEqual(self.dest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.changed_when, "'PEM written:' in _pem_build.stdout")

    def test_the_same_certificate_is_left_alone(self):
        self.issue("one")
        self.build()
        before = self.dest.stat().st_mtime_ns
        self.assertFalse(self.build())
        self.assertEqual(self.dest.stat().st_mtime_ns, before)
        self.assertEqual(sorted(path.name for path in (self.root / "certs").iterdir()), [self.dest.name])

    def test_a_renewed_certificate_or_loose_permissions_are_rewritten(self):
        self.issue("one")
        self.build()
        self.issue("two")
        self.assertTrue(self.build())
        self.assertEqual(self.dest.read_text(), "CERT two\nKEY two\n")
        self.dest.chmod(0o644)
        self.assertTrue(self.build())
        self.assertEqual(self.dest.stat().st_mode & 0o777, 0o600)

    def test_a_held_name_and_a_missing_certificate_change_nothing(self):
        self.assertFalse(self.build())
        self.assertFalse(self.dest.exists())
        self.issue("one")
        pin = self.root / "available" / "shop.example.com" / ".pinned"
        pin.parent.mkdir(parents=True)
        pin.write_text("standby", encoding="utf-8")
        self.assertFalse(self.build())
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()
