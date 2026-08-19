"""The header must not cost three rows, and must not lose a page doing it.

Eighteen buttons wrapped onto three lines on a wide screen and pushed the
page itself below the fold. Grouping them into menus is only worth doing if
every destination survives the move, so that is what these check: the same
set of pages, each in exactly one place, and the machinery that makes a
<details> behave like a menu actually wired up.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
NAV = APP / "templates" / "_haproxy_nav.html"
BASE = APP / "templates" / "base.html"
SCRIPT = APP / "static" / "js" / "nav.js"
STYLES = APP / "static" / "css" / "styles.css"

# Every destination the header offers. The first four rows were the flat
# button row on the HAProxy pages; the rest were reachable only from the
# dashboard or only from the Authelia pages, which is why one nav now
# carries them all.
EXPECTED_ENDPOINTS = {
    "routes.haproxy_sites_page",
    "routes.haproxy_tcp_page",
    "routes.haproxy_udp_page",
    "routes.haproxy_config_page",
    "routes.config_history_page",
    "routes.haproxy_geoip_page",
    "routes.haproxy_certs_page",
    "routes.dns_providers_page",
    "routes.mail_settings_page",
    "routes.haproxy_backends_page",
    "routes.monitoring_page",
    "routes.adaptive_protection_page",
    "routes.request_log_page",
    "routes.alerts_page",
    "routes.audit_page",
    "routes.system_health_page",
    "system_updates.page",
    "system_backups.page",
    "routes.haproxy_stats_page",
    "authelia_acl.edit_rules",
    "routes.authelia_users",
    "routes.authelia_bans",
    "authelia_settings.edit_settings",
    # Only rendered when debug routes are switched on.
    "routes.debug",
    "routes.index",
}


def nav_source() -> str:
    return NAV.read_text(encoding="utf-8")


def grouped_endpoints() -> list[str]:
    """Endpoints named inside the group definitions, in order."""
    block = nav_source().split("set nav_groups")[1].split("%}")[0]
    return re.findall(r'\("([a-z_]+\.[a-z_]+)"', block)


class DestinationTests(unittest.TestCase):
    def test_no_page_was_lost_in_the_regrouping(self):
        source = nav_source()
        present = set(re.findall(r"url_for\('([^']+)'\)", source))
        present |= set(grouped_endpoints())
        self.assertEqual(present, EXPECTED_ENDPOINTS)

    def test_each_destination_appears_once(self):
        # Twice in two menus is a menu nobody trusts.
        endpoints = grouped_endpoints()
        duplicates = {e for e in endpoints if endpoints.count(e) > 1}
        self.assertEqual(duplicates, set())

    def test_the_dashboard_stays_a_link_rather_than_hiding_in_a_menu(self):
        # It is where people go when they are lost; burying it in a menu is
        # the opposite of that.
        self.assertNotIn("routes.index", grouped_endpoints())
        self.assertIn("url_for('routes.index')", nav_source())

    def test_authelia_is_reachable_from_every_page(self):
        # It used to be one button on the dashboard, so arriving on any
        # HAProxy page meant going Home before you could reach it.
        self.assertIn("authelia_acl.edit_rules", grouped_endpoints())

    def test_one_nav_serves_the_whole_application(self):
        pages = ROOT / "docker" / "app" / "haproxy_admin" / "templates"
        for name in ("index.html", "_authelia_nav.html"):
            with self.subTest(page=name):
                markup = (pages / name).read_text(encoding="utf-8")
                self.assertIn("_haproxy_nav.html", markup)

    def test_the_row_is_short_enough_to_be_worth_it(self):
        # Six menus plus Home. More than about eight and the header wraps
        # again, which is the problem this replaced.
        source = nav_source()
        groups = source.count('"label":')
        self.assertLessEqual(groups + 1, 9, "the header will wrap again")
        self.assertGreater(groups, 1, "grouping that groups nothing")


class BehaviourTests(unittest.TestCase):
    def setUp(self):
        self.source = nav_source()
        self.script = SCRIPT.read_text(encoding="utf-8")
        self.styles = STYLES.read_text(encoding="utf-8")

    def test_it_works_without_the_script(self):
        # <details> opens and closes on its own; the script is only for the
        # conveniences. Anything that made opening depend on JS would leave
        # the whole section unreachable when it fails to load.
        self.assertIn("<details", self.source)
        self.assertIn("<summary", self.source)

    def test_the_script_is_loaded_for_every_page(self):
        self.assertIn("js/nav.js", BASE.read_text(encoding="utf-8"))

    def test_opening_one_menu_closes_the_others(self):
        self.assertIn('addEventListener("toggle"', self.script)
        self.assertIn("closeAll", self.script)

    def test_escape_closes_and_returns_focus(self):
        self.assertIn('event.key !== "Escape"', self.script)
        self.assertIn("summary.focus()", self.script)

    def test_clicking_away_closes_it(self):
        self.assertIn('document.addEventListener("click"', self.script)

    def test_the_current_page_is_marked(self):
        # The row of buttons told you nothing about where you were either,
        # but a menu that hides its contents has to.
        self.assertIn("nav-group-current", self.source)
        self.assertIn('aria-current="page"', self.source)
        self.assertIn(".nav-group-current", self.styles)

    def test_the_section_is_named_for_a_screen_reader(self):
        self.assertIn('aria-label="Administration sections"', self.source)

    def test_the_panel_is_positioned_and_layered(self):
        for rule in (".nav-group-items", "position: absolute", "z-index"):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.styles)

    def test_the_menus_nearest_the_edge_open_inward(self):
        # Otherwise a right-hand panel leaves the viewport and the whole page
        # gains a horizontal scrollbar.
        self.assertIn(".nav-group:nth-last-of-type(-n+2) .nav-group-items", self.styles)

    def test_navigation_is_quieter_than_an_action_button(self):
        # Seven solid accent pills read as seven competing calls to action.
        # The summary deliberately does not carry .btn.
        self.assertNotIn('class="btn nav-group-summary"', self.source)
        self.assertIn(".nav-group-summary", self.styles)

    def test_a_link_shaped_like_a_button_is_not_underlined(self):
        # Mixing <a class="btn"> and <button class="btn"> in one row showed
        # the browser default underline on half of them.
        block = self.styles.split("a.btn,")[1][:400]
        self.assertIn("text-decoration: none", block)

    def test_a_narrow_screen_gets_a_stacked_menu(self):
        self.assertIn("@media (max-width: 720px)", self.styles)
        narrow = self.styles.split("@media (max-width: 720px)")[1][:600]
        self.assertIn("position: static", narrow)


class TranslationTests(unittest.TestCase):
    def test_every_group_label_has_russian(self):
        import json

        messages = {}
        base = APP / "translations" / "ru.json"
        if base.is_file():
            messages.update(
                json.loads(base.read_text(encoding="utf-8")).get("messages", {})
            )
        for path in sorted((APP / "translations" / "ru").glob("*.json")):
            messages.update(
                json.loads(path.read_text(encoding="utf-8")).get("messages", {})
            )
        labels = re.findall(r'"label": "([^"]+)"', nav_source())
        self.assertTrue(labels)
        missing = [label for label in labels if label not in messages]
        self.assertEqual(missing, [], "group labels with no Russian")


if __name__ == "__main__":
    unittest.main()
