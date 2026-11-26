"""The CLI runs the playbook with the Go installer when the agent can, and
with Ansible otherwise."""

from __future__ import annotations

import os
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

    def fake_probe(self, command, **_kwargs):
        self.probes.append(command)
        if command[2] == "parts":
            return subprocess.CompletedProcess(command, 0, self.parts, "")
        return subprocess.CompletedProcess(command, self.supported, "", "not in the Go installer yet: cert (rdg)\n")

    def play(self, tags: str, **kwargs) -> list[list[str]]:
        runs: list[list[str]] = []
        with (
            mock.patch.object(easy_ha_proxy, "AGENT_BINARY", self.agent),
            mock.patch.object(easy_ha_proxy.subprocess, "run", side_effect=self.fake_probe),
            mock.patch.object(easy_ha_proxy, "run", side_effect=lambda command, **_: runs.append(command)),
            mock.patch.object(easy_ha_proxy, "playbook_command", return_value=["ansible-playbook"]),
            mock.patch.object(easy_ha_proxy, "ansible_environment", return_value={}),
            mock.patch.object(easy_ha_proxy, "source_dir", return_value=self.root / "source"),
            mock.patch.object(easy_ha_proxy, "offer_pending_reboot"),
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

    def test_an_entry_not_moved_yet_falls_back_to_ansible(self) -> None:
        self.supported = 3
        runs = self.play("crt-rdg")
        self.assertEqual(runs, [["ansible-playbook"]])

    def test_ansible_on_request_or_without_an_agent(self) -> None:
        with mock.patch.dict(os.environ, {"EASY_HA_PROXY_ANSIBLE": "1"}):
            self.assertEqual(self.play("status"), [["ansible-playbook"]])
        self.assertEqual(self.play("status", extra_vars={"easy_ha_proxy_go_installer": "false"}), [["ansible-playbook"]])
        self.agent.unlink()
        self.assertEqual(self.play("status"), [["ansible-playbook"]])
        self.assertEqual(self.probes, [])

    def test_an_agent_older_than_the_native_part_is_not_bootstrapped(self) -> None:
        self.parts = ""
        runs = self.play("ha-adm-native,status")
        self.assertEqual([command[1:3] for command in runs], [["apply", "playbook"]])


if __name__ == "__main__":
    unittest.main()
