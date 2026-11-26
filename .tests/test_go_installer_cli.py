"""The CLI runs the playbook with the installer agent: the installed one when
it can, else the one built for the source revision."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import easy_ha_proxy


class GoInstallerSwitch(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.agent = self.root / "easy-ha-proxy-agent"
        self.agent.write_text("#!/bin/sh\n")
        self.config = self.root / "config"
        self.config.mkdir()
        for name in ("inventory.ini", "vars.yml", "secrets.yml"):
            (self.config / name).write_text("{}\n")
        self.probes: list[list[str]] = []
        self.supported = 0
        self.parts = '{"parts":{"native":{}}}'
        self.fetched = self.root / "staged-agent"
        self.fetched.write_text("#!/bin/sh\n")
        source = self.root / "source/ansible"
        source.mkdir(parents=True)
        (source / "easy-ha-proxy.yml").write_text("[]\n")

    def fake_probe(self, command, **_kwargs):
        self.probes.append(command)
        if command[2] == "parts":
            return subprocess.CompletedProcess(command, 0, self.parts, "")
        return subprocess.CompletedProcess(command, self.supported, "", "not in the Go installer yet: a new entry\n")

    def play(self, tags: str, **kwargs) -> list[list[str]]:
        runs: list[list[str]] = []
        with (
            mock.patch.object(easy_ha_proxy, "AGENT_BINARY", self.agent),
            mock.patch.object(easy_ha_proxy.subprocess, "run", side_effect=self.fake_probe),
            mock.patch.object(easy_ha_proxy, "run", side_effect=lambda command, **_: runs.append(command)),
            mock.patch.object(easy_ha_proxy, "source_dir", return_value=self.root / "source"),
            mock.patch.object(easy_ha_proxy, "offer_pending_reboot"),
            mock.patch.object(easy_ha_proxy, "fetch_runner", return_value=self.fetched) as self.fetch,
        ):
            easy_ha_proxy.run_playbook(tags, directory=self.config, **kwargs)
        return runs

    def test_the_agent_runs_what_it_supports_after_installing_itself(self) -> None:
        runs = self.play("ha-adm-native,ha-cfg,status")
        self.assertEqual([command[1:4] for command in runs], [["apply", "run", "--part"], ["apply", "playbook", "--tags"]])
        self.assertEqual(runs[0][4], "native")
        self.assertIn("status_check_fail_on_error=true", runs[1])
        self.assertNotIn("--check", runs[1])

    def test_a_run_without_the_native_stage_uses_the_installed_agent(self) -> None:
        runs = self.play("aut-update,status")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][1:3], ["apply", "playbook"])

    def test_a_plan_is_a_check_and_installs_nothing(self) -> None:
        runs = self.play("ha-adm-native,status", check_mode=True)
        self.assertEqual(len(runs), 1)
        self.assertIn("--check", runs[0])

    def test_an_agent_older_than_the_playbook_command_is_replaced_for_the_run(self) -> None:
        self.supported = 2  # usage: no "apply playbook" yet
        runs = self.play("status")
        self.assertEqual(runs, [[str(self.fetched), "apply", "playbook", "--tags", "status",
                                 "--source", str(self.root / "source"), "--config", str(self.config),
                                 "--extra", "status_check_fail_on_error=true"]])

    def test_a_plan_on_a_host_without_an_agent_fetches_one_too(self) -> None:
        self.agent.unlink()
        runs = self.play("status", check_mode=True)
        self.assertEqual(runs[0][0], str(self.fetched))
        self.assertIn("--check", runs[0])

    def test_an_incomplete_configuration_is_refused_before_anything_runs(self) -> None:
        (self.config / "secrets.yml").unlink()
        with self.assertRaisesRegex(easy_ha_proxy.InstallerError, "Configuration is incomplete"):
            self.play("status")
        self.assertEqual(self.probes, [])

    def test_a_fresh_host_runs_the_agent_fetched_for_this_revision(self) -> None:
        self.agent.unlink()
        runs = self.play("docker,ha-adm-native,status")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][0], str(self.fetched))
        self.assertEqual(runs[0][1:3], ["apply", "playbook"])

    def test_an_agent_older_than_the_native_part_is_not_bootstrapped(self) -> None:
        self.parts = ""
        runs = self.play("ha-adm-native,status")
        self.assertEqual([command[1:3] for command in runs], [["apply", "playbook"]])


class TheVenvLosesAnsible(unittest.TestCase):
    """An update removes what earlier installers put in the private venv."""

    def sync(self, installed: bool) -> tuple[list[list[str]], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name)
        (home / "venv/bin").mkdir(parents=True)
        (home / "venv/bin/pip").write_text("#!/bin/sh\n")
        (home / "tmp/ansible/leftover").mkdir(parents=True)
        source = home / "source"
        (source / "installer").mkdir(parents=True)
        (source / "installer/requirements.txt").write_text("PyYAML~=6.0\n")
        runs: list[list[str]] = []
        shown = subprocess.CompletedProcess([], 0 if installed else 1, "", "")
        with (
            mock.patch.object(easy_ha_proxy, "install_home", return_value=home),
            mock.patch.object(easy_ha_proxy, "source_dir", return_value=source),
            mock.patch.object(easy_ha_proxy, "run", side_effect=lambda command, **_: runs.append(command)),
            mock.patch.object(easy_ha_proxy.subprocess, "run", return_value=shown),
        ):
            easy_ha_proxy.sync_runtime_dependencies()
        return runs, home

    def test_ansible_core_is_uninstalled_when_present(self) -> None:
        runs, home = self.sync(installed=True)
        self.assertEqual([command[1] for command in runs], ["install", "uninstall"])
        self.assertEqual(runs[1][-2:], ["--yes", "ansible-core"])
        self.assertFalse((home / "tmp/ansible").exists())

    def test_a_clean_venv_only_installs(self) -> None:
        runs, _ = self.sync(installed=False)
        self.assertEqual([command[1] for command in runs], ["install"])


if __name__ == "__main__":
    unittest.main()
