"""Cross-component contracts for SSH protection (logic tested in go/agent/internal/hostsec)."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

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
        protection = (ROOT / "go/agent/internal/hostsec/ssh_protection.go").read_text(encoding="utf-8")
        client = re.search(r'sshDefaultClient\s*=\s*"([^"]+)"', protection).group(1)
        config_dir = re.search(r'sshDefaultConfigDir\s*=\s*"([^"]+)"', protection).group(1)
        drop_in = re.search(r'sshDropInPath\s*=\s*filepath\.Join\(sshDefaultConfigDir, "jail\.d", "([^"]+)"\)', protection).group(1)
        broker = (ROOT / "go/agent/internal/updated/api.go").read_text(encoding="utf-8")
        self.assertIn(f'fail2banClientPath = "{client}"', broker)
        self.assertIn(f'fail2banDropInPath = "{config_dir}/jail.d/{drop_in}"', broker)


if __name__ == "__main__":
    unittest.main()
