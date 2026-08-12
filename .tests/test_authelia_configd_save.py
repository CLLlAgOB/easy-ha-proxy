"""Regression test for the authelia-configd atomic config write.

The Authelia config is validated by running `authelia config validate` inside
the Authelia container (uid != root). If the temp file is left root-owned until
after validation, the container cannot read it and every config edit — including
saving access_control rules from the web UI — fails with "permission denied".
Ownership and mode must therefore be set on the temp file before validation and
the rename.
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/authelia/files/authelia-configd.py"
SOURCE = DAEMON.read_text(encoding="utf-8")


class ConfigdSaveContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.body = SOURCE.split("def _save_config_data", 1)[1].split(
            "\ndef ", 1
        )[0]

    def test_ownership_and_mode_precede_validation_and_rename(self) -> None:
        chown_at = self.body.find("os.chown(tmp_path")
        chmod_at = self.body.find("os.chmod(tmp_path")
        validate_at = self.body.find("_validate_config_via_authelia(tmp_path)")
        replace_at = self.body.find("os.replace(tmp_path")
        self.assertGreater(chown_at, 0, "temp config must be chowned")
        self.assertGreater(chmod_at, 0, "temp config must be chmodded")
        self.assertGreater(validate_at, 0)
        self.assertGreater(replace_at, 0)
        self.assertLess(chown_at, validate_at, "chown must precede validation")
        self.assertLess(chmod_at, validate_at, "chmod must precede validation")
        self.assertLess(validate_at, replace_at)

    def test_falls_back_to_authelia_account_when_no_previous_file(self) -> None:
        self.assertIn('pwd.getpwnam("authelia")', self.body)


if __name__ == "__main__":
    unittest.main()
