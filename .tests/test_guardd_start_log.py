"""guardd's start line names the mode in force.

It printed the configuration file's mode: "mode=monitor" on the test
gateway, which the panel had set to enforce -- and that line was enough to
mislead a check of which bans were live.
"""

from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")


class TheStartLine(unittest.TestCase):
    def test_it_prints_the_mode_in_force_and_the_configured_one(self):
        start = SOURCE.split('"Starting easy-ha-proxy-guardd: mode=%s (configured %s)')[1].split(")\n")[0]
        arguments = [part.strip() for part in start.split("\n") if part.strip().endswith(",")]
        self.assertEqual(arguments[1:3], ["engine.enforcer.mode,", "config.mode,"])


if __name__ == "__main__":
    unittest.main()
