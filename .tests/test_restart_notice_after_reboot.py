"""The restart notice page wording after a night that rebooted.

Container inspection tests (container without health check, with health check,
and unverifiable record) moved to go/agent/internal/hostsec/os_upgrade_guard_test.go
alongside os-upgrade-guard.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ThePage(unittest.TestCase):
    def test_the_page_says_the_finding_and_the_run_predate_the_reboot(self):
        script = (ROOT / "go/panel/web/static/js/os_security.js").read_text(encoding="utf-8")
        self.assertIn("restart.before_boot ?", script)
        self.assertIn("const earlierBoot =", script)
        catalog = json.loads((ROOT / "go/panel/web/translations/ru/maintenance_window.json")
                             .read_text(encoding="utf-8"))["messages"]
        for sentence in ("The last check was made before the server rebooted, and the reboot restarted every service. "
                         "A new check runs shortly after startup.",
                         "The last service restart run was before the server rebooted, and the reboot restarted every service."):
            self.assertIn(sentence, script)
            self.assertIn(sentence, catalog)


if __name__ == "__main__":
    unittest.main()
