"""Access rules added in the panel survive a full update and a restore.

A site was put behind Authelia in the panel, with a rule letting the admins
group in. The panel saved that rule into the configuration Authelia runs
with. A few days later a full update rendered that file again from the
managed authelia.yml -- which the panel had never written to -- and the rule
was gone. The default policy being deny, the site answered 403 to its owner.

Before the playbook renders, the installer now copies the rules Authelia is
running with into the managed file, the way sites and TCP proxies edited in
the panel were already carried across.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import easy_ha_proxy  # noqa: E402
from easy_ha_proxy import sync_runtime_authelia_rules_to_managed  # noqa: E402


ADMIN = {"domain": "ha.example.test", "policy": "one_factor", "subject": ["group:admins"]}
ADDED_IN_PANEL = {
    "domain": "docker.example.test",
    "policy": "two_factor",
    "subject": ["group:admins"],
}


class Gateway(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.managed_dir = root / "etc"
        self.managed_dir.mkdir()
        self.managed = self.managed_dir / "authelia.yml"
        self.runtime = root / "configuration.yml"
        (self.managed_dir / "metadata.yml").write_text("{}\n", encoding="utf-8")
        self.write_managed([ADMIN])
        self.write_runtime([ADMIN, ADDED_IN_PANEL])
        self.out = mock.patch("builtins.print")
        self.out.start()
        self.addCleanup(self.out.stop)

    def write_managed(self, rules, **extra):
        data = {"authelia_enabled": True, "authelia_access_control_rules": rules}
        data.update(extra)
        self.managed.write_text(yaml.safe_dump(data), encoding="utf-8")

    def write_runtime(self, rules, text=None):
        if text is None:
            text = yaml.safe_dump(
                {"access_control": {"default_policy": "deny", "rules": rules}}
            )
        self.runtime.write_text(text, encoding="utf-8")

    def managed_rules(self):
        return yaml.safe_load(self.managed.read_text(encoding="utf-8"))[
            "authelia_access_control_rules"
        ]

    def sync(self):
        return sync_runtime_authelia_rules_to_managed(
            self.managed_dir, runtime_config=self.runtime
        )


class RulesFromThePanelAreCarriedAcross(Gateway):
    def test_a_rule_only_authelia_knows_reaches_the_managed_file(self):
        # The reported case.
        self.assertTrue(self.sync())
        self.assertEqual(self.managed_rules(), [ADMIN, ADDED_IN_PANEL])

    def test_the_rest_of_the_managed_file_is_left_alone(self):
        self.write_managed([ADMIN], authelia_totp_issuer="example")
        self.sync()
        data = yaml.safe_load(self.managed.read_text(encoding="utf-8"))
        self.assertEqual(data["authelia_totp_issuer"], "example")
        self.assertIs(data["authelia_enabled"], True)

    def test_a_copy_of_the_managed_files_is_kept_first(self):
        self.sync()
        backups = list((self.managed_dir / "backups").glob("*/authelia.yml"))
        self.assertEqual(len(backups), 1)
        kept = yaml.safe_load(backups[0].read_text(encoding="utf-8"))
        self.assertEqual(kept["authelia_access_control_rules"], [ADMIN])

    def test_a_rule_removed_in_the_panel_is_removed_here_too(self):
        self.write_managed([ADMIN, ADDED_IN_PANEL])
        self.write_runtime([ADMIN])
        self.assertTrue(self.sync())
        self.assertEqual(self.managed_rules(), [ADMIN])

    def test_nothing_to_do_is_nothing_written(self):
        self.write_runtime([ADMIN])
        before = self.managed.stat().st_mtime_ns
        self.assertFalse(self.sync())
        self.assertEqual(self.managed.stat().st_mtime_ns, before)
        self.assertFalse((self.managed_dir / "backups").exists())


class DamageIsNotMistakenForIntent(Gateway):
    def test_an_empty_rule_list_never_wipes_the_managed_one(self):
        # It would deny every site at once.
        self.write_runtime([])
        self.assertFalse(self.sync())
        self.assertEqual(self.managed_rules(), [ADMIN])

    def test_a_broken_or_odd_file_changes_nothing(self):
        for text in (
            "access_control: [not, a, mapping]\n",
            "access_control:\n  rules: nope\n",
            "access_control:\n  rules:\n    - just a string\n",
            "{{ this is not yaml",
            "- a list at the top\n",
        ):
            with self.subTest(text=text):
                self.write_runtime(None, text=text)
                self.assertFalse(self.sync())
                self.assertEqual(self.managed_rules(), [ADMIN])

    def test_no_authelia_on_this_gateway_is_not_an_error(self):
        self.runtime.unlink()
        self.assertFalse(self.sync())
        self.managed.unlink()
        self.write_runtime([ADMIN])
        self.assertFalse(self.sync())

    def test_a_pending_reconfiguration_keeps_the_managed_file_in_charge(self):
        with mock.patch.object(
            easy_ha_proxy, "managed_configuration_is_pending", return_value=True
        ):
            self.assertFalse(self.sync())
        self.assertEqual(self.managed_rules(), [ADMIN])


class ItRunsBeforeThePlaybookRenders(unittest.TestCase):
    def test_on_an_update_and_on_a_restore(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        update = source.split("def command_update(")[1].split("\ndef ")[0]
        restore = source.split("def command_apply_restored(")[1].split("\ndef ")[0]
        for name, body in (("update", update), ("restore", restore)):
            with self.subTest(path=name):
                self.assertIn("sync_runtime_authelia_rules_to_managed(directory)", body)
                self.assertLess(
                    body.rindex("sync_runtime_authelia_rules_to_managed(directory)"),
                    body.rindex("run_playbook("),
                )


if __name__ == "__main__":
    unittest.main()
