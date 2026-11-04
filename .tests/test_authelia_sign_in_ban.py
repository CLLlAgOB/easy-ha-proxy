"""Authelia's own ban on an address, on the address page (06.5c).

Authelia bans an address from signing in after too many failed attempts.
That is all it blocks: HAProxy does not refuse the address, and a site that
needs no sign-in still answers it. The address page now says so, from the
list the panel already reads for the Authelia bans page -- apart from the
HAProxy ban, never as one, and nothing at all when the list cannot be read.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))


def listing(*entries, error=None):
    return {
        "users": [],
        "ips": [
            {"id": str(index + 1), "subject": subject, "expires": expires, "source": "regulation",
             "reason": reason}
            for index, (subject, expires, reason) in enumerate(entries)
        ],
        "users_raw": "",
        "ips_raw": "",
        "error": error,
    }


@unittest.skipIf(sys.platform == "win32", "the panel imports need a POSIX host")
class TheLookup(unittest.TestCase):
    def setUp(self):
        self.live = importlib.import_module("haproxy_admin.services_live")
        self.services = importlib.import_module("haproxy_admin.services")
        self.live._authelia_bans_cache.update({"at": float("-inf"), "value": None})
        self.addCleanup(self.live._authelia_bans_cache.update, {"at": float("-inf"), "value": None})

    def ban(self, ip, payload):
        self.live._authelia_bans_cache.update({"at": float("-inf"), "value": None})
        with mock.patch.object(self.services, "get_authelia_bans", return_value=payload):
            return self.live.authelia_sign_in_ban(ip)

    def test_an_address_banned_by_name(self):
        found = self.ban("203.0.113.9", listing(("203.0.113.9", "Thu, 05 Nov 2026 03:00:00 UTC", "")))
        self.assertEqual(found["expires"], "Thu, 05 Nov 2026 03:00:00 UTC")
        self.assertFalse(found["network"])

    def test_an_address_inside_a_banned_network(self):
        found = self.ban("198.51.100.77", listing(("198.51.100.0/24", "never", "brute force")))
        self.assertTrue(found["network"])
        self.assertEqual((found["subject"], found["reason"]), ("198.51.100.0/24", "brute force"))

    def test_ipv6_and_mixed_families(self):
        payload = listing(("2001:db8::/64", "never", ""), ("203.0.113.0/24", "never", ""))
        self.assertIsNotNone(self.ban("2001:db8::5", payload))
        self.assertIsNone(self.ban("2001:db9::5", payload))

    def test_not_listed_is_none(self):
        self.assertIsNone(self.ban("192.0.2.1", listing(("203.0.113.9", "never", ""))))

    def test_an_unreadable_list_says_nothing_rather_than_not_banned(self):
        self.assertIsNone(self.ban("203.0.113.9", listing(("203.0.113.9", "never", ""),
                                                         error="authelia-bansd is not running")))

    def test_the_list_is_read_once_for_a_run_of_pages(self):
        with mock.patch.object(self.services, "get_authelia_bans",
                               return_value=listing(("203.0.113.9", "never", ""))) as read:
            for ip in ("203.0.113.9", "192.0.2.1", "203.0.113.9"):
                self.live.authelia_sign_in_ban(ip)
        self.assertEqual(read.call_count, 1)

    def test_a_bad_address_asks_nothing(self):
        with mock.patch.object(self.services, "get_authelia_bans") as read:
            self.assertIsNone(self.live.authelia_sign_in_ban("not-an-address"))
        read.assert_not_called()


class ThePage(unittest.TestCase):
    def setUp(self):
        self.template = (APP / "templates/ip_logs.html").read_text(encoding="utf-8")
        self.routes = (APP / "routes.py").read_text(encoding="utf-8")

    def test_it_is_shown_apart_from_haproxys_ban(self):
        block = self.template.split("{% if authelia_ban %}")[1].split("{% endif %}\n\n")[0]
        self.assertIn("Sign-in blocked by Authelia", block)
        self.assertIn("HAProxy does not refuse this address", block)
        self.assertNotIn("data-ipp-action", block)  # no ban or unban of the address here
        self.assertIn("routes.authelia_bans", block)
        status = self.template.split('id="ipp-status"')[1].split("{% if authelia_ban %}")[0]
        self.assertNotIn("authelia", status.lower())

    def test_a_failure_to_read_it_never_costs_the_page(self):
        route = self.routes.split("def view_ip_logs")[1].split("\n@bp.")[0]
        block = route.split("authelia_sign_in_ban")[0].rsplit("try:", 1)[1]
        self.assertIn("from . import services_live", block)
        self.assertIn("except Exception", route.split("authelia_sign_in_ban")[1])


if __name__ == "__main__":
    unittest.main()
