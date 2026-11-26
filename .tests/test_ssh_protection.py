"""Cross-component contracts for SSH protection (logic tested in go/agent/internal/hostsec)."""
from __future__ import annotations

from pathlib import Path
import unittest

import ssh_protection as ssh

ROOT = Path(__file__).resolve().parents[1]


class SshProtectionContractTests(unittest.TestCase):
    def test_hp_ban_rules_only_touch_http_and_https_with_safe_verdicts(self):
        rules = (ROOT / "ansible/roles/haproxy-admin/files/haproxy_ban.rules").read_text(encoding="utf-8")
        verdicts = [line.split(" -j ", 1)[1].split()[0] for line in rules.splitlines() if line.startswith("-A HP_BAN ")]
        self.assertTrue(verdicts and set(verdicts) <= {"DROP", "REJECT", "RETURN"})
        self.assertTrue(
            all("--dport 80 " in line or "--dport 443 " in line for line in rules.splitlines() if line.startswith("-A HP_BAN "))
        )

    def test_broker_shortcut_paths_match_ssh_protection_constants(self):
        broker = (ROOT / "go/agent/internal/updated/api.go").read_text(encoding="utf-8")
        self.assertIn(f'fail2banClientPath = "{ssh.CLIENT}"', broker)
        self.assertIn(f'fail2banDropInPath = "{ssh.DROP_IN}"', broker)


if __name__ == "__main__":
    unittest.main()
