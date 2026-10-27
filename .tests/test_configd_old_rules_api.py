"""authelia-configd no longer takes access rules through the old JSON API.

rules_list and rules_save were the first way the panel read and wrote
Authelia's access rules. The panel has long used rules_get and rules_set,
which validate the YAML it sends; nothing called the old pair, and
rules_save still wrote whatever list it was handed into configuration.yml.
Both are now unknown actions, refused before any file is read or written.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/authelia/files/authelia-configd.py"
CLIENT = ROOT / "docker/app/haproxy_admin/authelia_config_client.py"


def load_daemon():
    spec = importlib.util.spec_from_file_location("authelia_configd_old_rules_api", DAEMON)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TheOldRulesAPIIsGone(unittest.TestCase):
    def test_both_actions_are_refused_without_touching_the_configuration(self):
        try:
            configd = load_daemon()
        except ImportError as exc:  # the daemon's own dependencies
            self.skipTest(f"daemon dependencies unavailable: {exc}")
        untouchable = AssertionError("the configuration must not be touched")
        with (
            mock.patch.object(configd, "_load_config_data", side_effect=untouchable),
            mock.patch.object(configd, "_save_config_data", side_effect=untouchable),
        ):
            for request in (
                {"action": "rules_list"},
                {"action": "rules_save", "rules": [{"domain": "*", "policy": "bypass"}]},
            ):
                with self.subTest(action=request["action"]):
                    self.assertEqual(
                        configd.handle_request(request),
                        {"ok": False, "error": f"unknown action: {request['action']!r}"},
                    )

    def test_the_rules_the_panel_uses_are_still_there(self):
        source = DAEMON.read_text(encoding="utf-8")
        self.assertIn('if action == "rules_get":', source)
        self.assertIn('if action == "rules_set":', source)

    def test_the_panel_client_asks_for_neither(self):
        client = CLIENT.read_text(encoding="utf-8")
        self.assertNotIn('"rules_list"', client)
        self.assertNotIn('"rules_save"', client)


if __name__ == "__main__":
    unittest.main()
