"""Saving Authelia's settings keeps the session cookies the form does not show (F22).

From the 30 October review, reproduced there with the real
save_settings_from_form and configd's _deep_update: the form edits three
fields of the first cookie and sent `cookies: [cookie]`; configd replaces a
list whole, so any save -- a change of log_level included -- dropped every
other cookie domain and the first cookie's own name, same_site and
lifetimes. Sites on another domain then lost their sign-in.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import services_authelia_settings as settings  # noqa: E402

STORED = {
    "ok": True,
    "config": {"session": {"cookies": [
        {"domain": "example.test", "authelia_url": "https://auth.example.test",
         "default_redirection_url": "https://www.example.test", "same_site": "strict", "name": "first"},
        {"domain": "other.test", "authelia_url": "https://auth.other.test", "inactivity": "5m"},
    ]}},
}
FORM = {
    "log_level": "debug",
    "cookie_domain": "example.test",
    "cookie_authelia_url": "https://auth.example.test",
    "cookie_default_redirection_url": "https://portal.example.test",
}


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class Saving(unittest.TestCase):
    def save(self, stored):
        sent = []
        with mock.patch.object(settings, "get_config_without_rules", return_value=stored), \
                mock.patch.object(settings, "update_settings",
                                  side_effect=lambda cfg: sent.append(cfg) or {"ok": True}):
            ok, message = settings.save_settings_from_form(FORM)
        return ok, message, sent

    def test_the_other_cookies_and_fields_are_kept(self):
        ok, _message, sent = self.save(STORED)
        self.assertTrue(ok)
        cookies = sent[0]["session"]["cookies"]
        self.assertEqual(len(cookies), 2)
        self.assertEqual(cookies[0]["default_redirection_url"], "https://portal.example.test")
        self.assertEqual((cookies[0]["same_site"], cookies[0]["name"]), ("strict", "first"))
        self.assertEqual(cookies[1], STORED["config"]["session"]["cookies"][1])

    def test_a_first_save_creates_the_one_cookie(self):
        ok, _message, sent = self.save({"ok": True, "config": {"session": {}}})
        self.assertTrue(ok)
        self.assertEqual(len(sent[0]["session"]["cookies"]), 1)

    def test_unreadable_cookies_are_not_written_over(self):
        ok, message, sent = self.save({"ok": False, "error": "configd down"})
        self.assertFalse(ok)
        self.assertEqual(sent, [])
        self.assertIn("not saved", message)


if __name__ == "__main__":
    unittest.main()
