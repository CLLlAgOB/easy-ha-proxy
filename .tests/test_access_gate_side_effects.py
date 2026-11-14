"""Saving an access gate says what it changes in Authelia at once (F16).

From the 30 October review: a site save is a draft until the HAProxy apply,
but saving an access gate adds a one_factor rule to Authelia and restarts
it there and then -- the restart also brings in other saved Authelia
changes, and rolling HAProxy back leaves the rule. The same word "Save"
gave no hint of it, and the result said nothing when it worked.

The mitigation the plan asks for first: the forms say so before the save,
and the result says what happened to Authelia, whichever way it went.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_haproxy_sites as sites  # noqa: E402


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheResult(unittest.TestCase):
    outcome = staticmethod(lambda *args: sites._with_gate_rule_outcome(*args))

    def test_an_added_rule_says_it_is_live_already(self):
        message = self.outcome("Saved.", "gate.example.test", True, "rule added")
        self.assertIn("restarted", message)
        self.assertIn("before the HAProxy apply", message)

    def test_a_rule_that_was_there_adds_nothing(self):
        self.assertEqual(self.outcome("Saved.", "gate.example.test", True, "already present"), "Saved.")

    def test_a_failed_restart_is_said(self):
        message = self.outcome("Saved.", "gate.example.test", True,
                               "rule saved; restart Authelia to activate it (timeout)")
        self.assertIn("could not be restarted", message)

    def test_a_rule_that_could_not_be_added_is_said(self):
        message = self.outcome("Saved.", "gate.example.test", False, "configd down")
        self.assertIn("could not be added", message)


class TheForms(unittest.TestCase):
    def test_both_forms_say_it_before_the_save(self):
        for name in ('access_portal_settings.html', 'access_sites.html'):
            source = (APP / 'templates' / name).read_text(encoding='utf-8')
            self.assertIn('may restart Authelia immediately', source)
            self.assertIn('include "_access_site_auth_note.html"', source)
        note = (APP / 'templates/_access_site_auth_note.html').read_text(encoding='utf-8')
        self.assertIn('does not remove the login rule', note)
        self.assertIn('also loads other saved Authelia changes', note)

    def test_the_notes_translate_whole(self):
        try:
            spec = importlib.util.spec_from_file_location("gate_side_effects_i18n", APP / "i18n.py")
            i18n = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(i18n)
        except ImportError:
            self.skipTest("the panel's dependencies are not installed here")
        catalogue = i18n.get_messages('ru')
        notes = [key for key in catalogue if 'may restart Authelia immediately' in key or 'Rolling back HAProxy does not remove the login rule' in key]
        self.assertGreaterEqual(len(notes), 3)
        for message in notes:
            self.assertEqual(i18n.translate(message, 'ru'), catalogue[message])


if __name__ == "__main__":
    unittest.main()
