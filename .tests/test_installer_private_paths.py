"""Shell launchers never use predictable fixed paths under /tmp.

The CA export path and symlink-safety tests now live in
go/agent/internal/cli/wizard_test.go.
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SHELL_SCRIPTS = ("install.sh", "install-local.sh", "install-remote.sh", "easy-ha-proxy-helper.sh")


class NoFixedDirectoryInTmp(unittest.TestCase):
    def test_no_script_names_a_fixed_directory_in_tmp(self):
        for name in SHELL_SCRIPTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("/tmp/easy-ha-proxy-ansible", text, name)
            self.assertNotIn("/tmp/easy-ha-proxy-internal-ca", text, name)


if __name__ == "__main__":
    unittest.main()
