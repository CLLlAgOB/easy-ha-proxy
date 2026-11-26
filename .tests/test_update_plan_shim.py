"""The update brokers installed before the checker moved still find it.

The checker is the host agent's "update-plan" command. A gateway's update
broker installed before that -- the Python broker of the 1.1 releases, or the
Go broker of earlier 1.2.0-alpha builds -- checks the update it has just
applied by running installer/update_plan.py from the source that update
installed. Without the file that check failed an update that had worked;
the file now hands the request to the agent the same update installed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "installer/update_plan.py"


def load_shim():
    spec = importlib.util.spec_from_file_location("update_plan_shim_test", SHIM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TheOldBrokersCheck(unittest.TestCase):
    def setUp(self):
        self.shim = load_shim()

    def test_it_is_handed_to_the_agent(self):
        with mock.patch.object(self.shim.os.path, "isfile", return_value=True), \
                mock.patch.object(self.shim.os, "execv") as execv:
            self.shim.main(["--format", "json", "--image-channel", "alpha", "--branch", "alpha"])
        execv.assert_called_once_with(self.shim.AGENT, [
            self.shim.AGENT, "update-plan", "--format", "json", "--image-channel", "alpha", "--branch", "alpha",
            "--haproxy-status"])

    def test_the_haproxy_component_is_asked_for_once(self):
        # Those brokers asked for it whenever haproxy_update_status.py was in
        # the source; it is gone, so the shim asks.
        with mock.patch.object(self.shim.os.path, "isfile", return_value=True), \
                mock.patch.object(self.shim.os, "execv") as execv:
            self.shim.main(["--format", "json", "--haproxy-status"])
        self.assertEqual(execv.call_args.args[1].count("--haproxy-status"), 1)

    def test_without_the_agent_the_check_fails_plainly(self):
        with mock.patch.object(self.shim.os.path, "isfile", return_value=False), \
                mock.patch.object(self.shim.os, "execv") as execv, \
                mock.patch("builtins.print") as printed:
            self.assertEqual(self.shim.main(["--format", "json"]), 1)
        execv.assert_not_called()
        self.assertIn("not installed", printed.call_args.args[0])

    def test_the_brokers_still_find_it_where_they_look(self):
        # Both broker generations run it with a Python interpreter from the
        # source's installer directory, and refuse a symbolic link.
        self.assertTrue(SHIM.is_file())
        self.assertFalse(SHIM.is_symlink())
        self.assertEqual(self.shim.AGENT, "/usr/local/sbin/easy-ha-proxy-agent")


if __name__ == "__main__":
    unittest.main()
