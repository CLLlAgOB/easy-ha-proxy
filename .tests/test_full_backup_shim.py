"""Transitional installer shims forward directly to easy-ha-proxy-agent.

The full backup, CLI, and legacy-config implementations and unit tests live
in go/agent/internal/fullbackup and go/agent/internal/cli.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_shim(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FullBackupShimTests(unittest.TestCase):
    def setUp(self):
        self.shim = load_shim("installer/full_backup.py", "full_backup_shim_test")

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


class InstallerCLIShimTests(unittest.TestCase):
    def test_easy_ha_proxy_shim_forwards_to_capable_agent(self):
        shim = load_shim("installer/easy_ha_proxy.py", "cli_shim_test")
        argv = ["update", "--component", "changes", "--no-fetch"]
        with mock.patch.object(shim, "_agent_supports_cli", side_effect=[True]), \
                mock.patch.object(shim.os, "execv") as execv:
            shim.main(argv)
        execv.assert_called_once_with(shim.AGENT, [shim.AGENT, "cli", *argv])

    def test_prepare_legacy_config_shim_forwards_to_agent(self):
        shim = load_shim("installer/prepare_legacy_config.py", "legacy_shim_test")
        argv = ["--live-dir", "/tmp/live", "--controller-dir", "/tmp/src", "--output-dir", "/tmp/out"]
        with mock.patch.object(shim.os.path, "isfile", return_value=True), \
                mock.patch.object(shim.os, "execv") as execv:
            shim.main(argv)
        execv.assert_called_once_with(shim.AGENT, [shim.AGENT, "prepare-legacy-config", *argv])


if __name__ == "__main__":
    unittest.main()
