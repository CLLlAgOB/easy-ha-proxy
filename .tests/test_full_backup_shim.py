"""The encrypted full backup is the host agent's "full-backup" command.

The backup and restore themselves are tested with the agent. These tests
cover the two ways the installer side reaches it: installer/full_backup.py,
which brokers installed before the move (and operators) still run, and the
installer's own "backup-full" and "restore-full" commands, which use the
agent built for the source when the installed one is older than the command
or there is none (a recovery onto a fresh machine).
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "installer/full_backup.py"


def load_shim():
    spec = importlib.util.spec_from_file_location("full_backup_shim_test", SHIM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TheOldPath(unittest.TestCase):
    def setUp(self):
        self.shim = load_shim()

    def test_the_command_line_is_handed_to_the_agent_unchanged(self):
        argv = ["restore", "/var/lib/x.tar.gz.enc", "--mode", "overlay", "--apply", "--yes", "--passphrase-stdin"]
        with mock.patch.object(self.shim.os.path, "isfile", return_value=True), \
                mock.patch.object(self.shim.os, "execv") as execv:
            self.shim.main(argv)
        execv.assert_called_once_with(self.shim.AGENT, [self.shim.AGENT, "full-backup", *argv])

    def test_without_the_agent_it_fails_as_the_helper_did(self):
        with mock.patch.object(self.shim.os.path, "isfile", return_value=False), \
                mock.patch.object(self.shim.os, "execv") as execv, \
                mock.patch("builtins.print") as printed:
            self.assertEqual(self.shim.main(["inspect", "x"]), 2)
        execv.assert_not_called()
        self.assertIn("not installed", printed.call_args.args[0])


class TheInstallersCommands(unittest.TestCase):
    def setUp(self):
        import easy_ha_proxy

        self.cli = easy_ha_proxy
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.agent = self.root / "easy-ha-proxy-agent"
        self.agent.write_text("", encoding="utf-8")
        self.staged = self.root / "staged-agent"
        patcher = mock.patch.object(easy_ha_proxy, "AGENT_BINARY", self.agent)
        patcher.start()
        self.addCleanup(patcher.stop)

    def probe(self, stderr):
        return mock.patch("easy_ha_proxy.subprocess.run", return_value=subprocess.CompletedProcess([], 2, "", stderr))

    def test_the_installed_agent_is_used_when_it_has_the_command(self):
        with self.probe("usage: easy-ha-proxy-agent full-backup backup ...\n"), \
                mock.patch.object(self.cli, "fetch_runner") as fetch:
            self.assertEqual(self.cli.full_backup_command(), [str(self.agent), "full-backup"])
        fetch.assert_not_called()

    def test_an_older_agent_leaves_it_to_the_one_built_for_the_source(self):
        with self.probe("usage: easy-ha-proxy-agent <healthd|apply|version> [flags]\n"), \
                mock.patch.object(self.cli, "fetch_runner", return_value=self.staged) as fetch:
            self.assertEqual(self.cli.full_backup_command(), [str(self.staged), "full-backup"])
        fetch.assert_called_once()

    def test_a_fresh_machine_fetches_the_agent(self):
        self.agent.unlink()
        with mock.patch.object(self.cli, "fetch_runner", return_value=self.staged):
            self.assertEqual(self.cli.full_backup_command(), [str(self.staged), "full-backup"])

    def test_restore_full_runs_the_agents_restore(self):
        args = argparse.Namespace(archive="/root/backup.enc", mode="auto", restore_ssh=False, skip_ssh=True, apply=True)
        with mock.patch.object(self.cli, "require_root"), mock.patch.object(self.cli, "hold_maintenance_lock"), \
                mock.patch.object(self.cli, "full_backup_command", return_value=["agent", "full-backup"]), \
                mock.patch.object(self.cli, "run") as run:
            self.cli.command_restore_full(args)
        self.assertEqual(run.call_args.args[0], ["agent", "full-backup", "restore", "/root/backup.enc", "--mode", "auto",
                                                 "--replace-managed", "--skip-ssh", "--apply"])

    def test_a_missing_configuration_does_not_stop_the_fetch(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        body = source.split("def fetch_runner(")[1].split("\ndef ")[0]
        self.assertIn('load_yaml_mapping(vars_file) if vars_file.is_file() else {}', body)


if __name__ == "__main__":
    unittest.main()
