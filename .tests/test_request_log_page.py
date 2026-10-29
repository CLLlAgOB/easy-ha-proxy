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
        filters = self.service.split("REQUEST_FILTERS = (")[1].split(")")[0]
        for name in ('"before"', '"count"', '"hide_admin"'):
            self.assertIn(name, filters)
        self.assertNotIn('"offset"', filters)
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
        # The one header kept is said by name.
        self.assertIn("only the User-Agent is kept", self.template)
        self.assertIn("no cookie or body", self.template)

    def test_show_more_carries_on_where_the_search_on_screen_stopped(self):
        # Not by offset: new requests would repeat rows, and filters typed
        # since the search would mix two searches in one table.
        self.assertNotIn("offset", self.javascript)
        self.assertIn('params.set("before", String(next))', self.javascript)
        self.assertIn("const params = new URLSearchParams(query);", self.javascript)
        self.assertIn("if (mine !== sequence) return;", self.javascript)

    def test_the_panels_own_requests_are_hidden_unless_asked_for(self):
        self.assertIn('id="rq-admin"', self.template)
        self.assertIn('byId("rq-admin").checked', self.javascript)
        core = (APP_DIR / "static" / "js" / "request_log_core.js").read_text(encoding="utf-8")
        self.assertIn('if (!view.admin) params.hide_admin = "1";', core)

    def test_the_time_shown_is_the_servers_answer(self):
        self.assertIn("Server answer", self.template)
        self.assertIn("entry.response_ms", self.javascript)
        self.assertIn("The whole request", self.javascript)

    def test_a_search_that_ran_out_of_time_says_so(self):
        self.assertIn('id="rq-stopped"', self.template)
        self.assertIn("payload.timed_out", self.javascript)
        self.assertIn("payload.searched_to", self.javascript)
        self.assertIn("payload.total_exact === false", self.javascript)

    def test_the_search_on_screen_is_in_the_address(self):
        # A reload, a bookmark or a link opens the same search; Back
        # returns to the one before.
        self.assertIn("window.history.pushState", self.javascript)
        self.assertIn('window.addEventListener("popstate"', self.javascript)
        self.assertIn("core.viewFromQuery(window.location.search)", self.javascript)
        self.assertIn("run(false)", self.javascript)

    def test_the_cores_load_before_the_page(self):
        order = [self.template.index(f"js/{name}") for name in
                 ("live_activity_core.js", "request_log_core.js", "request_log.js")]
        self.assertEqual(order, sorted(order))

    def test_a_value_in_the_table_narrows_the_search_to_itself(self):
        for name in ("status", "method", "host", "path", "backend", "client"):
            self.assertIn(f'filterButton("{name}"', self.javascript)
        self.assertIn('event.target.closest("[data-filter]")', self.javascript)

    def test_a_row_opens_what_the_live_page_shows_of_a_request(self):
        details = self.javascript.split("  function detailsRow(entry) {")[1].split("\n  }\n")[0]
        for part in ("live.termination(entry.term)", "live.timers(entry.times)", "entry.user_agent",
                     "entry.ban_reason", "/monitoring/live?ip="):
            self.assertIn(part, details)

    def test_the_new_filters_are_offered(self):
        for element_id in ("rq-method", "rq-agent", "rq-slower", "rq-refused"):
            self.assertIn(f'id="{element_id}"', self.template)

    def test_switched_off_shows_no_stop_button_and_no_empty_store(self):
        # The status route answers "off" with a 200 and enabled: false; read
        # by its status alone, the page offered to stop a record that was not
        # running and showed "0 records · 0 / 0 MiB · 0 days".
        block = self.javascript.split("async function refreshStore()")[1].split("\n  }\n")[0]
        self.assertIn("payload.enabled !== false", block)
        self.assertIn('byId("rq-disable").hidden = !recording;', block)

    def test_memory_is_said_to_be_memory(self):
        self.assertIn('id="rq-memory"', self.template)
        self.assertIn('payload.source === "memory"', self.javascript)
        self.assertIn("payload.reaches_back_to", self.javascript)

    def test_it_is_reachable_from_the_navigation(self):
        nav = (APP_DIR / "templates" / "_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn("routes.request_log_page", nav)


if __name__ == "__main__":
    unittest.main()
