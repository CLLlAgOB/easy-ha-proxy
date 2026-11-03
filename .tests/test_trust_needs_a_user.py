"""An address is trusted only after a user really signed in (U02, step 04.4a).

The Lua forward-auth marks a request successful on any 2xx from Authelia,
and the template then marked the client's address in tbl_ip_auth -- which
lets it through the zero-trust TCP and UDP proxies and exempts it from the
error bans. Authelia answers a "bypass" rule with 200 and no user. Checked
on the test host's HAProxy 2.8.30 with the real auth-request.lua and an
auth server answering 200 with and without Remote-User: before, both
addresses were marked; with the condition below, only the signed-in one.
The request itself is let through either way -- only the trust changed.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402

SIGNED_IN = "{ var(req.auth_response_header.remote_user) -m len gt 0 }"


class TheMark(unittest.TestCase):
    def setUp(self):
        self.config = render([site("shop", "shop.example.test", authelia_enabled=True),
                              site("gate", "gate.example.test", access_gate=True)])
        self.marks = [line.strip() for line in self.config.splitlines()
                      if "src_inc_gpc0(tbl_ip_auth)" in line]

    def test_every_mark_needs_a_signed_in_user(self):
        self.assertGreaterEqual(len(self.marks), 2)
        for line in self.marks:
            self.assertIn("{ var(txn.auth_response_successful) -m bool }", line)
            self.assertIn(SIGNED_IN, line)

    def test_nothing_else_writes_the_table(self):
        template = (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(encoding="utf-8")
        self.assertEqual(template.count("src_inc_gpc0(tbl_ip_auth)"), 2)

    def test_access_is_unchanged(self):
        # Only the mark moved: an allowed request is still let through.
        self.assertIn("http-request deny status 503 if authelia_protected", self.config)
        self.assertNotIn(f"deny status 503 if authelia_protected !admin_control_plane_probe {SIGNED_IN}", self.config)


if __name__ == "__main__":
    unittest.main()
