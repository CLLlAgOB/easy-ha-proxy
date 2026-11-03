"""The ban loader touches its own chain only (F01).

From the 30 October review, confirmed on the test gateway's own
iptables-legacy in a separate network namespace: the loader ran
`iptables-legacy-restore` without --noflush, which empties the whole filter
table it restores -- a rule of the host's in INPUT, one in FORWARD and a
chain of someone else's (Docker's, on a legacy host) were gone, and only
HP_BAN was left. With --noflush and the jump added once, both survive two
runs, HP_BAN holds its two rules and INPUT one jump into it.
"""

from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = (ROOT / "ansible/roles/haproxy-admin/templates/iptables-haproxy-ban.service.j2").read_text(encoding="utf-8")
RULES = (ROOT / "ansible/roles/haproxy-admin/files/haproxy_ban.rules").read_text(encoding="utf-8")


class TheLoader(unittest.TestCase):
    def test_it_restores_without_flushing_the_table(self):
        start = next(line for line in UNIT.splitlines() if line.startswith("ExecStart="))
        self.assertIn("iptables-legacy-restore --noflush /etc/iptables/haproxy_ban.rules", start)

    def test_the_jump_is_added_once(self):
        post = next(line for line in UNIT.splitlines() if line.startswith("ExecStartPost="))
        self.assertIn("iptables-legacy -C INPUT -j HP_BAN", post)
        self.assertIn("|| /usr/sbin/iptables-legacy -I INPUT 1 -j HP_BAN", post)

    def test_the_rules_declare_only_their_own_chain(self):
        self.assertNotIn("-I INPUT", RULES)
        self.assertNotIn("-A INPUT", RULES)
        chains = [line for line in RULES.splitlines() if line.startswith(":")]
        self.assertEqual(chains, [":HP_BAN - [0:0]"])
        self.assertTrue(all(line.startswith(("-A HP_BAN", ":", "*filter", "COMMIT"))
                            for line in RULES.splitlines() if line.strip()))


if __name__ == "__main__":
    unittest.main()
