"""Transitional shim tests for the Step 4 host security helpers.

The OS upgrade guard, OS security updates, service restarts, automatic reboots,
and SSH protection moved into easy-ha-proxy-agent (go/agent/internal/hostsec),
and the CLI --automatic-os forwarding moved into go/agent/internal/cli. This
file verifies that each transitional installer/*.py shim preserves its protocol
markers and forwards its command line to easy-ha-proxy-agent unchanged.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_shim(filename: str):
    path = ROOT / "installer" / filename
    spec = importlib.util.spec_from_file_location(f"shim_test_{filename[:-3]}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostSecurityShims(unittest.TestCase):
    SHIMS = (
        ("os_security.py", "os-security", {"PROTOCOL": 1, "SETTINGS_PROTOCOL": 1}),
        ("service_restarts.py", "service-restarts", {"SERVICE_RESTART_PROTOCOL": 1}),
        ("auto_reboot.py", "auto-reboot", {"AUTO_REBOOT_PROTOCOL": 1, "SERVICE_REBOOT_PROTOCOL": 1}),
        ("os_upgrade_guard.py", "os-upgrade-guard", {}),
        ("ssh_protection.py", "ssh-protection", {}),
    )

    def test_each_shim_preserves_protocol_markers_and_forwards_to_agent(self):
        for filename, subcmd, markers in self.SHIMS:
            with self.subTest(filename=filename):
                mod = load_shim(filename)
                for key, expected in markers.items():
                    self.assertEqual(getattr(mod, key), expected)
                argv = ["--state-root", "/tmp/example", "inspect"]
                with patch.object(mod.os.path, "isfile", return_value=True), \
                        patch.object(mod.os, "execv") as execv:
                    mod.main(argv)
                execv.assert_called_once_with(mod.AGENT, [mod.AGENT, subcmd, *argv])

    def test_missing_agent_exits_with_code_2(self):
        for filename, _, _ in self.SHIMS:
            with self.subTest(filename=filename):
                mod = load_shim(filename)
                with patch.object(mod.os.path, "isfile", return_value=False), \
                        patch.object(mod.os, "execv") as execv, \
                        patch("builtins.print") as printed:
                    self.assertEqual(mod.main(["status"]), 2)
                execv.assert_not_called()
                self.assertIn("not installed", printed.call_args.args[0])

    def test_os_security_keeps_read_json_and_local_time_for_migration_helper(self):
        mod = load_shim("os_security.py")
        self.assertIsNotNone(mod.local_time().tzinfo)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state.json"
            p.write_text(json.dumps({"phase": "ready"}), encoding="utf-8")
            st = p.lstat()
            if st.st_uid == 0:
                self.assertEqual(mod.read_json(p), {"phase": "ready"})
            else:
                with self.assertRaises(ValueError):
                    mod.read_json(p)


if __name__ == "__main__":
    unittest.main()
