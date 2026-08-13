"""Regression checks for the off-host destination routes and page."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "routes_backup.py").read_text(encoding="utf-8")

    def test_every_destination_route_exists(self):
        for route in (
            "/api/destinations",
            "/api/destinations/delete",
            "/api/destinations/test",
            "/api/destinations/upload",
        ):
            self.assertIn(f'"{route}"', self.source)

    def test_the_name_is_validated_before_it_reaches_the_daemon(self):
        # It becomes a file name in a root-owned directory on the other side.
        self.assertIn("DESTINATION_NAME_RE", self.source)
        self.assertIn("_destination_name(payload[", self.source)

    def test_the_request_body_is_a_closed_set(self):
        block = self.source.split("def save_destination_view")[1].split("@bp_")[0]
        self.assertIn("_json_payload(", block)
        self.assertIn("for key in (", block)

    def test_every_destination_action_is_audited(self):
        for action in (
            "backup_destination.save",
            "backup_destination.delete",
            "backup_destination.test",
            "backup.upload",
        ):
            self.assertIn(f'"{action}"', self.source)

    def test_the_audit_summary_cannot_carry_the_key(self):
        # The saved fields include private_key; only the harmless ones are
        # named in the record.
        block = self.source.split("AUDITED_ACTIONS = {")[1].split("}")[0]
        self.assertNotIn("private_key", block)
        self.assertNotIn("host_key", block)

    def test_an_upload_gets_a_budget_that_fits_a_transfer(self):
        block = self.source.split("def upload_backup_view")[1]
        self.assertIn("timeout=1800.0", block)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "system_backups.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (
            APP_DIR / "static" / "js" / "backup_destinations.js"
        ).read_text(encoding="utf-8")

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertTrue(referenced)
        self.assertEqual(sorted(referenced - template_ids), [])

    def test_the_secrets_start_empty_and_are_only_sent_when_typed(self):
        # The daemon never returns them, so an untouched field must mean
        # "keep what is stored" rather than "clear it".
        self.assertIn('byId("dest-key").value = "";', self.javascript)
        self.assertIn('byId("dest-host-key").value = "";', self.javascript)
        self.assertIn("if (key) body.private_key = key;", self.javascript)
        self.assertIn("if (hostKey) body.host_key = hostKey;", self.javascript)

    def test_writes_carry_the_csrf_token(self):
        self.assertIn('options.headers["X-CSRFToken"] = csrfToken();', self.javascript)
        # And only writes: a GET must not be turned into one by accident.
        block = self.javascript.split("async function api")[1].split("function status")[0]
        self.assertIn("if (body !== undefined)", block)

    def test_the_destination_list_is_not_run_through_the_translator(self):
        tag = re.search(
            r'<[^>]+id="backup-destinations-body"[^>]*>', self.template
        )
        self.assertIsNotNone(tag)
        self.assertIn("data-i18n-skip", tag.group(0))

    def test_the_page_explains_why_the_host_key_matters(self):
        self.assertIn("whoever answers on that address", self.template)
        self.assertIn("ssh-keyscan", self.template)

    def test_the_script_is_loaded(self):
        self.assertIn("js/backup_destinations.js", self.template)


if __name__ == "__main__":
    unittest.main()
