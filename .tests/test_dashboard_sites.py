"""The dashboard's list of sites: names open the site, ports do not, and the
gateway's own services stay out of the way.

Each row is a HAProxy backend with its servers up out of total. A site's
names became links to https://<name> in a new tab; a TCP proxy is a port, so
it stays text, and so does a wildcard, which has nothing to open. The
gateway's own backends (Authelia's) are left out while healthy -- but a
broken one is still listed, because a dashboard that hides an Authelia
outage is worse than one with an extra line.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
WINDOWS = sys.platform == "win32"
sys.path.insert(0, str(ROOT / "docker" / "app"))

if not WINDOWS:
    from haproxy_admin import services  # noqa: E402


def stat_csv(*rows):
    lines = ["# pxname,svname,status"]
    lines.extend(",".join(row) for row in rows)
    return "\n".join(lines) + "\n"


DISPLAY = {
    "be_shop": "shop.example.test, WWW.shop.example.test, *.shop.example.test",
    "be_mail_tcp": "mail.example.test",
    "be_tcp_rdp": "rdp:3389",
}


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheRows(unittest.TestCase):
    def status(self, *rows):
        with mock.patch.object(services, "_admin_sockets", return_value=["/run/haproxy/admin.sock"]), \
                mock.patch.object(services, "_show_stat", return_value=stat_csv(*rows)), \
                mock.patch.object(services, "_load_display_map_from_cfg", return_value=DISPLAY):
            return {item["backend"]: item for item in services.get_backends_status()["items"]}

    def test_a_sites_names_are_links_and_a_port_is_not(self):
        items = self.status(
            ("be_shop", "srv1", "UP"), ("be_shop", "srv2", "UP"),
            ("be_mail_tcp", "srv1", "UP"),
            ("be_tcp_rdp", "srv1", "UP"),
        )
        self.assertEqual(items["be_shop"]["kind"], "site")
        # Lower-cased, de-duplicated, and the wildcard left out.
        self.assertEqual(items["be_shop"]["hosts"], ["shop.example.test", "www.shop.example.test"])
        self.assertEqual(items["be_shop"]["up"], 2)
        # A TLS-passthrough site is still a site.
        self.assertEqual(items["be_mail_tcp"]["hosts"], ["mail.example.test"])
        self.assertEqual(items["be_tcp_rdp"]["kind"], "tcp")
        self.assertEqual(items["be_tcp_rdp"]["hosts"], [])

    def test_the_gateways_own_backends_stay_out_while_healthy(self):
        items = self.status(("be_shop", "srv1", "UP"), ("authelia_backend", "authelia", "UP"))
        self.assertNotIn("authelia_backend", items)

    def test_a_broken_one_is_still_listed(self):
        items = self.status(("be_shop", "srv1", "UP"), ("authelia_backend", "authelia", "DOWN"))
        row = items["authelia_backend"]
        self.assertEqual((row["kind"], row["status"], row["site"]), ("system", "red", "Authelia"))
        self.assertEqual(row["hosts"], [])

    def test_only_plain_host_names_become_links(self):
        self.assertEqual(services.site_hosts("a.example.test, b.example.test."),
                         ["a.example.test", "b.example.test"])
        for odd in ("*.example.test", "203.0.113.5", "localhost", "a b.example.test",
                    "javascript:alert(1)", "a.example.test/path", ""):
            with self.subTest(odd=odd):
                self.assertEqual(services.site_hosts(odd), [])


class ThePage(unittest.TestCase):
    def test_links_open_the_site_in_a_new_tab_and_nothing_else_links(self):
        script = (APP / "static/js/sites.js").read_text(encoding="utf-8")
        self.assertIn("it.kind === 'site' && Array.isArray(it.hosts)", script)
        self.assertIn("link.href = `https://${host}/`", script)
        self.assertIn("link.target = '_blank'", script)
        self.assertIn("link.rel = 'noopener noreferrer'", script)
        # The text is set as text, never as markup.
        self.assertIn("link.textContent = host", script)
        self.assertNotIn("innerHTML = `<a", script)


if __name__ == "__main__":
    unittest.main()
