"""Regression checks for the Log Explorer page and its routes."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.routes = (APP_DIR / "routes_security.py").read_text(encoding="utf-8")
        self.service = (APP_DIR / "services_security.py").read_text(encoding="utf-8")
        self.client = (APP_DIR / "guardd_client.py").read_text(encoding="utf-8")

    def test_the_explorer_reads_and_never_deletes(self):
        block = self.routes.split("# Log Explorer")[1]
        self.assertNotIn("@bp.delete", block)
        # Exactly one thing in this section changes anything: the switch that
        # decides whether requests are recorded at all.
        self.assertEqual(block.count("@bp.post"), 1)
        self.assertIn('@bp.post("/api/security/requests/enabled")', block)

    def test_the_recording_switch_is_guarded_like_a_mutation(self):
        # It decides whether the gateway keeps a record of what every visitor
        # asked for, so it is superadmin-only and it lands in the change log.
        block = self.routes.split('@bp.post("/api/security/requests/enabled")')[1]
        block = block.split("@bp.get")[0]
        self.assertIn('getattr(g, "is_superadmin", False)', block)
        self.assertIn("RESULT_DENIED", block)
        self.assertIn('"request_log.enabled"', block)

    def test_the_page_offers_the_switch_instead_of_naming_a_variable(self):
        page = (APP_DIR / "templates" / "request_log.html").read_text(encoding="utf-8")
        script = (APP_DIR / "static" / "js" / "request_log.js").read_text(encoding="utf-8")
        # The old notice told the operator to set guardd_request_log_enabled
        # and gave them no way to do it.
        self.assertNotIn("guardd_request_log_enabled", page)
        self.assertIn('id="rq-enable"', page)
        self.assertIn('id="rq-disable"', page)
        self.assertIn("/api/security/requests/enabled", script)
        self.assertIn('"X-CSRFToken"', script)

    def test_a_stopped_daemon_degrades_instead_of_erroring(self):
        self.assertIn("GuarddUnavailable", self.routes)
        self.assertIn("unavailable_payload", self.routes)

    def test_switched_off_is_not_reported_as_unavailable(self):
        # The daemon answers 404 with a body when the store is off; raising on
        # status would turn "the feature is off" into "guardd is down".
        block = self.client.split("def _request_log_get")[1].split("def guardd_requests")[0]
        self.assertNotIn("raise_for_status", block)
        self.assertIn("404", (APP_DIR / "static/js/request_log.js").read_text(encoding="utf-8"))

    def test_the_filter_set_is_closed(self):
        # An unknown query parameter is dropped rather than forwarded.
        self.assertIn("REQUEST_FILTERS", self.service)
        block = self.service.split("def requests(")[1].split("def requests_status")[0]
        self.assertIn("for key in REQUEST_FILTERS", block)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "request_log.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "request_log.js").read_text(
            encoding="utf-8"
        )

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])

    def test_stored_request_data_is_excluded_from_dom_translation(self):
        # Paths and hostnames are data, not interface language.
        tag = re.search(r'<[^>]+id="rq-body"[^>]*>', self.template)
        self.assertIsNotNone(tag)
        self.assertIn("data-i18n-skip", tag.group(0))

    def test_the_page_offers_every_filter_the_plan_asks_for(self):
        for element_id in (
            "rq-range", "rq-status", "rq-client", "rq-host", "rq-backend",
            "rq-path", "rq-request-id",
        ):
            self.assertIn(f'id="{element_id}"', self.template)

    def test_the_two_failure_modes_are_shown_apart(self):
        self.assertIn('id="rq-disabled"', self.template)
        self.assertIn('id="rq-unavailable"', self.template)
        self.assertIn('setNotice("rq-disabled", true)', self.javascript)
        self.assertIn('setNotice("rq-unavailable", true)', self.javascript)

    def test_the_page_says_what_the_store_costs(self):
        self.assertIn('id="rq-store"', self.template)
        self.assertIn("database_bytes", self.javascript)
        self.assertIn("max_bytes", self.javascript)

    def test_the_privacy_rule_is_stated_on_the_page(self):
        self.assertIn("query string is dropped", self.template)
        self.assertIn("no header, cookie or body", self.template)

    def test_it_is_reachable_from_the_navigation(self):
        nav = (APP_DIR / "templates" / "_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn("routes.request_log_page", nav)


if __name__ == "__main__":
    unittest.main()
