"""Contract test for the HAProxy handler chain.

`apply haproxy` is notified by tasks that change files referenced by the config
(the maintenance / access-granted error pages) without notifying
`validate haproxy`, so `haproxy_cfg_test` can be undefined when the apply/restart
handlers evaluate it. They must tolerate that instead of erroring with
"'haproxy_cfg_test' is undefined".
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLERS = (
    ROOT / "ansible/roles/haproxy/handlers/main.yml"
).read_text(encoding="utf-8")


class HaproxyHandlerTests(unittest.TestCase):
    def test_apply_handlers_tolerate_undefined_syntax_check(self) -> None:
        # Every reference to haproxy_cfg_test.rc in the apply/restart handlers
        # must be defaulted so an apply-only notification cannot crash the play.
        self.assertNotIn("when: haproxy_cfg_test.rc == 0", HANDLERS)
        self.assertIn("haproxy_cfg_test.rc | default(0) == 0", HANDLERS)

    def test_hard_restart_guards_reload_result_presence(self) -> None:
        block = HANDLERS.split("hard restart haproxy if reload failed", 1)[1]
        self.assertIn("reload_res is defined", block)
        self.assertIn("reload_res is failed", block)


if __name__ == "__main__":
    unittest.main()
