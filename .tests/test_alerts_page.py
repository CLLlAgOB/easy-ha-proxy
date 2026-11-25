"""Regression checks for the Alerts page and its routes."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"
sys.path.insert(0, str(ROOT / "docker" / "app"))


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (_WEB_DIR / "templates" / "alerts.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (_WEB_DIR / "static" / "js" / "alerts.js").read_text(
            encoding="utf-8"
        )

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])

    def test_stored_payloads_are_excluded_from_dom_translation(self):
        for element_id in (
            "al-active-body", "al-history-body", "al-status", "al-channels",
        ):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))

    def test_the_secret_fields_start_empty_rather_than_prefilled(self):
        # The daemon returns them shortened; putting that in the value would
        # let a save write the mask back as the real setting.
        self.assertIn('url.value = "";', self.javascript)
        self.assertIn('secret.value = "";', self.javascript)
        self.assertIn("url.placeholder = config.webhook_url", self.javascript)

    def test_an_untouched_secret_is_not_sent_back(self):
        block = self.javascript.split("function deliveryPayload")[1].split("function ")[0]
        self.assertIn("if (url) payload.webhook_url = url;", block)
        self.assertIn("if (secret) payload.webhook_header_value = secret;", block)

    def test_writes_carry_the_csrf_token(self):
        self.assertIn('"X-CSRFToken": csrfToken()', self.javascript)

    def test_an_event_cannot_be_given_a_delay_in_the_form(self):
        self.assertIn('delay.disabled = rule.kind === "event";', self.javascript)

    def test_a_stopped_daemon_is_shown_rather_than_a_blank_page(self):
        self.assertIn('id="al-unavailable"', self.template)
        self.assertIn("setUnavailable(Boolean(error.unavailable))", self.javascript)

    def test_the_page_is_reachable_from_the_navigation(self):
        nav = (_WEB_DIR / "templates" / "_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn("routes.alerts_page", nav)

    def test_the_container_is_given_the_socket_and_the_token(self):
        env = (
            ROOT / "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("ALERTD_SOCKET_PATH=", env)
        self.assertIn("ALERTD_TOKEN=", env)


if __name__ == "__main__":
    unittest.main()
