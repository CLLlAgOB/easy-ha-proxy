"""Regression checks for the Alerts page and its routes."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))


class RouteGuardTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "routes_alerts.py").read_text(encoding="utf-8")

    def test_both_mutating_routes_require_superadmin(self):
        self.assertEqual(self.source.count("@bp.post"), 2)
        # Once in the helper, once per mutating route.
        self.assertEqual(self.source.count("_superadmin()"), 3)

    def test_reads_stay_open_like_the_other_monitoring_pages(self):
        for route in ("/api/alerts/state", "/api/alerts/health", "/api/alerts/history"):
            self.assertIn(route, self.source)
        block = self.source.split("def api_alerts_state")[1].split("@bp.")[0]
        self.assertNotIn("_superadmin", block)

    def test_a_stopped_daemon_degrades_instead_of_erroring(self):
        self.assertIn("AlertdUnavailable", self.source)
        self.assertIn('"unavailable": True', self.source)
        self.assertIn("503", self.source)

    def test_both_mutating_routes_are_audited(self):
        for action in ("alerts.config", "alerts.test"):
            self.assertIn(f'"{action}"', self.source)
        self.assertIn("RESULT_DENIED", self.source)
        self.assertIn("RESULT_FAILURE", self.source)

    def test_the_audit_record_names_fields_and_never_values(self):
        # The payload carries the webhook URL and its header secret.
        block = self.source.split("def api_alerts_config")[1]
        self.assertIn('"fields: " + ", ".join(sorted(str(key) for key in payload))', block)
        self.assertNotIn("summary=str(payload)", block)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "alertd_client.py").read_text(encoding="utf-8")

    def test_the_token_travels_only_on_writes(self):
        self.assertIn("X-Alertd-Token", self.source)
        read_block = self.source.split("def _get_json")[1].split("def _post_json")[0]
        self.assertNotIn("X-Alertd-Token", read_block)

    def test_a_rejected_setting_is_read_as_a_message_not_an_exception(self):
        # The daemon answers 400 with the reason; raising on status would turn
        # "that URL is not https" into "alertd is unavailable".
        block = self.source.split("def _post_json")[1].split("def alertd_health")[0]
        self.assertNotIn("raise_for_status", block)

    def test_the_test_call_gets_a_longer_budget_than_a_save(self):
        self.assertIn("TEST_TIMEOUT", self.source)
        self.assertIn("timeout=TEST_TIMEOUT", self.source)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "alerts.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "alerts.js").read_text(
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
        nav = (APP_DIR / "templates" / "_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn("routes.alerts_page", nav)

    def test_the_container_is_given_the_socket_and_the_token(self):
        env = (
            ROOT / "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("ALERTD_SOCKET_PATH=", env)
        self.assertIn("ALERTD_TOKEN=", env)

    def test_the_module_is_registered(self):
        package = (APP_DIR / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("from . import routes_alerts", package)


if __name__ == "__main__":
    unittest.main()
