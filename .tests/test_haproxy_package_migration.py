"""Transitional shim tests for installer/haproxy_package_migrate.py.

The HAProxy migration, patching, rollback, and recovery engine moved to
easy-ha-proxy-agent (go/agent/internal/haproxymigrate), where its unit tests
and disposable Ubuntu 24.04 smoke tests now live.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "installer/haproxy_package_migrate.py"


def load_shim():
    spec = importlib.util.spec_from_file_location("haproxy_migrate_shim_test", SHIM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HAProxyMigrationShimTests(unittest.TestCase):
    def test_shim_preserves_protocol_markers_and_forwards_to_agent(self):
        mod = load_shim()
        self.assertEqual(mod.WEB_MIGRATION_PROTOCOL, 1)
        self.assertEqual(mod.AUTOMATIC_MIGRATION_PROTOCOL, 1)
        argv = ["patch", "--expected-version", "3.4.8-1", "--web-progress"]
        with patch.object(mod.os.path, "isfile", return_value=True), \
                patch.object(mod.os, "execv") as execv:
            mod.main(argv)
        execv.assert_called_once_with(mod.AGENT, [mod.AGENT, "haproxy-migrate", *argv])

    def test_missing_agent_exits_with_code_2(self):
        mod = load_shim()
        with patch.object(mod.os.path, "isfile", return_value=False), \
                patch.object(mod.os, "execv") as execv, \
                patch("builtins.print") as printed:
            self.assertEqual(mod.main(["prepare"]), 2)
        execv.assert_not_called()
        self.assertIn("not installed", printed.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
