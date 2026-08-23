"""An alert has to name a gateway its reader recognises.

Every alert this gateway sent carried its machine name in the subject line:

    [vm4a7c19be2f08d3] WORSE critical: Site is down (mail.example.com)

That is what a cloud provider generated, not anything the operator ever
chose, and it identifies nothing to the person reading the mail at midnight.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "haproxy-admin"
DAEMON = ROLE / "files" / "easy-ha-proxy-alertd.py"
UNIT = ROLE / "templates" / "easy-ha-proxy-alertd.service.j2"


class GatewayNameTests(unittest.TestCase):
    def setUp(self):
        self.source = DAEMON.read_text(encoding="utf-8")

    def test_the_name_can_be_configured(self):
        self.assertIn('os.environ.get("ALERTD_GATEWAY_NAME", "")', self.source)

    def test_the_machine_name_is_still_the_fallback(self):
        # An unconfigured gateway must keep saying something rather than
        # sending mail with an empty bracket in the subject.
        self.assertIn("or os.uname().nodename", self.source)

    def test_a_blank_setting_does_not_win_over_the_fallback(self):
        # Environment variables that exist but are empty are the normal way a
        # template with no value renders, so "" must not be treated as a name.
        block = self.source.split("self.hostname = ")[1][:200]
        self.assertIn(".strip() or", block)

    def test_the_unit_passes_it_through(self):
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn("ALERTD_GATEWAY_NAME=", unit)

    def test_the_unit_defaults_to_something_meaningful(self):
        unit = UNIT.read_text(encoding="utf-8")
        line = [
            row for row in unit.splitlines()
            if "ALERTD_GATEWAY_NAME=" in row
        ][0]
        # The admin domain is a name the operator chose and already knows.
        self.assertIn("haproxy_admin_domain", line)

    def test_the_name_reaches_the_subject_line(self):
        self.assertIn("head = f\"[{self.hostname}]", self.source)


if __name__ == "__main__":
    unittest.main()
