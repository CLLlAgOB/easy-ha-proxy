"""Exercise the real Ansible tasks with an isolated Docker/systemctl fixture.

No Docker daemon or system service is modified by these tests. The fixture
models validation, asynchronous configuration reload and failure recovery.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible/roles/docker/tasks/live_restore.yml"
ANSIBLE = shutil.which("ansible-playbook")
if not ANSIBLE:
    candidate = Path(sys.executable).with_name("ansible-playbook")
    ANSIBLE = str(candidate) if candidate.exists() else None

ENGINE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["DOCKER_FIXTURE"])
p = root / "state.json"
s = json.loads(p.read_text())
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as f:
    f.write(json.dumps([tool, args]) + "\n")
if tool == "dockerd":
    config = json.loads(Path(args[args.index("--config-file") + 1]).read_text())
    sys.exit(1 if s.get("reject") and config.get("live-restore") else 0)
if tool == "systemctl":
    if args[0] == "show":
        properties = [p for arg in args if arg.startswith("--property=") for p in arg.split("=", 1)[1].split(",")]
        if "ActiveState" in properties:
            print("ActiveState=" + ("active" if s["active"] else "inactive"))
        if "ExecStart" in properties:
            print("ExecStart={ argv[]=/usr/bin/dockerd " + s.get("flags", "") + " ; }")
        sys.exit(0)
    if args[0] != "reload":
        sys.exit("Only reload is allowed")
    if s.get("fail_reload"):
        s["fail_reload"] = False
        p.write_text(json.dumps(s))
        sys.exit(1)
    if not s["active"]:
        sys.exit(1)
    config = root / "etc/docker/daemon.json"
    s["live"] = json.loads(config.read_text()).get("live-restore", False) if config.exists() else False
    p.write_text(json.dumps(s))
    sys.exit(0)
if not s["active"]:
    sys.exit("Docker is stopped")
if args[-1] == "{{json .}}":
    print(json.dumps({"LiveRestoreEnabled": s["live"], "Swarm": {"LocalNodeState": s.get("swarm", "inactive")}}))
else:
    print(str(s["live"]).lower())
'''


class Wiring(unittest.TestCase):
    def test_system_upgrade_configures_continuity_before_apt_can_restart_docker(self):
        tasks = yaml.safe_load((ROOT / "ansible/roles/update_packages/tasks/main.yml").read_text())
        imported = next(i for i, t in enumerate(tasks)
                        if t.get("ansible.builtin.import_role", {}).get("tasks_from") == "live_restore")
        upgrade = next(i for i, t in enumerate(tasks) if t.get("apt", {}).get("upgrade"))
        self.assertLess(imported, upgrade)
        install = yaml.safe_load((ROOT / "ansible/roles/docker/tasks/main.yml").read_text())
        self.assertTrue(any(t.get("ansible.builtin.import_tasks") == "live_restore.yml" for t in install))


@unittest.skipUnless(os.name == "posix" and ANSIBLE, "requires Ansible on POSIX")
class LiveRestore(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ehp-live-restore-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("docker", "dockerd", "systemctl"):
            p = self.bin / name
            p.write_text(ENGINE)
            p.chmod(0o755)
        self.config = self.root / "etc/docker/daemon.json"
        self.config.parent.mkdir(parents=True)
        self.original = '{"registry-mirrors":["https://registry.example.test"],"log-driver":"local"}\n'
        self.config.write_text(self.original)
        self.config.chmod(0o600)
        self.state = {"active": True, "live": False, "containers": {"panel": 123, "auth": 456}}
        self.save_state()

    def save_state(self):
        (self.root / "state.json").write_text(json.dumps(self.state))

    def calls(self):
        p = self.root / "calls.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def apply(self, *, enabled=True, success=True, check=False):
        def isolate(value, key=""):
            if isinstance(value, dict):
                return {k: isolate(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [isolate(v, key) for v in value]
            if not isinstance(value, str):
                return value
            for original, replacement in (("/usr/bin/dockerd", str(self.bin / "dockerd")),
                                          ("/usr/bin/docker", str(self.bin / "docker")),
                                          ("/etc/docker", str(self.config.parent))):
                value = value.replace(original, replacement)
            if value == "systemctl":
                return str(self.bin / "systemctl")
            if key in ("owner", "group"):
                uid = os.getuid() if key == "owner" else os.getgid()
                value = str(uid) if value == "root" else value.replace("default(0)", f"default({uid})")
            return value

        play = [{"hosts": "all", "connection": "local", "gather_facts": False,
                 "vars": {"docker_live_restore_enabled": enabled, "ansible_python_interpreter": sys.executable},
                 "tasks": isolate(yaml.safe_load(TASKS.read_text()))}]
        path = self.root / "play.yml"
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        env = dict(os.environ, DOCKER_FIXTURE=str(self.root), ANSIBLE_NOCOLOR="1",
                   ANSIBLE_LOCAL_TEMP=str(self.root / "ansible-local"),
                   ANSIBLE_REMOTE_TEMP=str(self.root / "ansible-remote"))
        args = [ANSIBLE, "-i", "localhost,", str(path)] + (["--check"] if check else [])
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
        if success:
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-7000:])
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(any("restart" in args or "start" in args for _, args in self.calls()))
        return result

    def test_merge_reload_and_second_apply_preserve_settings_permissions_and_containers(self):
        self.apply()
        config = json.loads(self.config.read_text())
        self.assertTrue(config.pop("live-restore"))
        self.assertEqual(config, json.loads(self.original))
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        state = json.loads((self.root / "state.json").read_text())
        self.assertTrue(state["live"])
        self.assertEqual(state["containers"], self.state["containers"])
        before = self.config.stat().st_mtime_ns
        self.apply()
        self.assertEqual(self.config.stat().st_mtime_ns, before)
        self.assertEqual(sum(args[:1] == ["reload"] for _, args in self.calls()), 1)

    def test_matching_file_with_stale_runtime_is_reloaded(self):
        self.config.write_text('{"live-restore": true}\n')
        self.apply()
        self.assertTrue(json.loads((self.root / "state.json").read_text())["live"])

    def test_rejected_config_restores_original_bytes_and_permissions(self):
        self.state["reject"] = True
        self.save_state()
        self.apply(success=False)
        self.assertEqual(self.config.read_text(), self.original)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertFalse(json.loads((self.root / "state.json").read_text())["live"])

    def test_failed_reload_rolls_back_and_leaves_containers_running(self):
        self.state["fail_reload"] = True
        self.save_state()
        self.apply(success=False)
        self.assertEqual(self.config.read_text(), self.original)
        state = json.loads((self.root / "state.json").read_text())
        self.assertFalse(state["live"])
        self.assertEqual(state["containers"], self.state["containers"])

    def test_fresh_or_inactive_docker_is_not_started(self):
        self.state["active"] = False
        self.save_state()
        self.config.unlink()
        self.apply()
        self.assertTrue(json.loads(self.config.read_text())["live-restore"])
        self.assertFalse(json.loads((self.root / "state.json").read_text())["active"])
        self.assertFalse(any(args[:1] == ["reload"] for _, args in self.calls()))

    def test_swarm_is_rejected_and_explicit_disable_is_supported(self):
        self.state.update(swarm="active", live=True)
        self.save_state()
        self.apply(success=False)
        self.assertEqual(self.config.read_text(), self.original)
        self.apply(enabled=False)
        self.assertFalse(json.loads(self.config.read_text())["live-restore"])
        self.assertFalse(json.loads((self.root / "state.json").read_text())["live"])

    def test_cli_setting_is_verified_without_writing_a_duplicate_option(self):
        self.state.update(flags="--live-restore=true", live=True)
        self.save_state()
        self.apply()
        self.assertEqual(self.config.read_text(), self.original)
        self.assertFalse(any(args[:1] == ["reload"] for _, args in self.calls()))
        self.apply(enabled=False, success=False)
        self.assertEqual(self.config.read_text(), self.original)

    def test_custom_config_path_and_symlinks_are_not_overwritten(self):
        self.state["flags"] = "--config-file=/custom/docker.json"
        self.save_state()
        self.apply(success=False)
        self.assertEqual(self.config.read_text(), self.original)
        self.state["flags"] = ""
        self.save_state()
        target = self.root / "original.json"
        self.config.rename(target)
        self.config.symlink_to(target)
        self.apply(success=False)
        self.assertTrue(self.config.is_symlink())
        self.assertEqual(target.read_text(), self.original)

    def test_check_mode_does_not_change_config_or_reload(self):
        self.apply(check=True)
        self.assertEqual(self.config.read_text(), self.original)
        self.assertFalse(any(args[:1] == ["reload"] for _, args in self.calls()))


if __name__ == "__main__":
    unittest.main()
