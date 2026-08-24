"""Regression checks for the administrative change log."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import audit  # noqa: E402


class RedactionTests(unittest.TestCase):
    def test_sensitive_keys_lose_their_values(self):
        clean = audit.redact(
            {
                "username": "alice",
                "password": "hunter2",
                "api_token": "abc",
                "client_secret": "s3cr3t",
                "passphrase": "open sesame",
                "private_key": "-----BEGIN",
                "session_id": "xyz",
            }
        )
        self.assertEqual(clean["username"], "alice")
        for key in (
            "password", "api_token", "client_secret", "passphrase",
            "private_key", "session_id",
        ):
            self.assertEqual(clean[key], "***", key)

    def test_redaction_reaches_nested_structures(self):
        clean = audit.redact(
            {"site": {"tls": {"private_key": "x"}, "servers": [{"token": "y"}]}}
        )
        self.assertEqual(clean["site"]["tls"]["private_key"], "***")
        self.assertEqual(clean["site"]["servers"][0]["token"], "***")

    def test_an_absent_secret_is_not_reported_as_present(self):
        clean = audit.redact({"password": "", "token": None})
        self.assertIsNone(clean["password"])
        self.assertIsNone(clean["token"])

    def test_recursion_and_size_are_bounded(self):
        deep = current = {}
        for _ in range(30):
            current["next"] = {}
            current = current["next"]
        self.assertIn("...", json.dumps(audit.redact(deep)))
        self.assertLessEqual(len(audit.redact({"a": ["x"] * 500})["a"]), 100)
        self.assertTrue(audit.redact("y" * 5000).endswith("…"))

    def test_a_secret_never_reaches_the_stored_json(self):
        payload = audit._dump({"password": "hunter2", "nested": {"token": "abc"}})
        self.assertNotIn("hunter2", payload)
        self.assertNotIn("abc", payload)

    def test_the_summary_says_a_secret_changed_but_not_what_to(self):
        summary = audit.summarize(
            {"name": "old", "password": "before"},
            {"name": "new", "password": "after"},
        )
        self.assertIn("name:", summary)
        self.assertIn("password: changed", summary)
        self.assertNotIn("before", summary)
        self.assertNotIn("after", summary)

    def test_a_change_hidden_inside_a_redacted_value_is_still_reported(self):
        # Both sides redact to the same text, so comparing the redacted copies
        # would call this "unchanged".
        summary = audit.summarize(
            {"tls": {"private_key": "old"}}, {"tls": {"private_key": "new"}}
        )
        self.assertIn("tls: changed", summary)
        self.assertNotIn("old", summary)
        self.assertNotIn("new", summary)

    def test_an_untouched_secret_is_not_reported_as_changed(self):
        summary = audit.summarize(
            {"password": "same", "port": 80}, {"password": "same", "port": 443}
        )
        self.assertNotIn("password", summary)
        self.assertIn("port:", summary)

    def test_the_summary_marks_additions_and_removals(self):
        summary = audit.summarize({"a": 1, "b": 2}, {"a": 1, "c": 3})
        self.assertIn("-b", summary)
        self.assertIn("+c", summary)
        self.assertNotIn("a:", summary)


class AuditLogTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "audit.db"
        self.log = audit.AuditLog(str(self.path))

    def rows(self):
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in connection.execute(
                "SELECT * FROM audit_events ORDER BY id")]
        finally:
            connection.close()


class WritingTests(AuditLogTestCase):
    def test_a_record_captures_who_what_and_the_outcome(self):
        self.assertTrue(
            self.log.record(
                "site.update",
                actor="alice",
                source_ip="203.0.113.5",
                object_type="site",
                object_id="shop.example.com",
                before={"backend": "10.0.0.1"},
                after={"backend": "10.0.0.2"},
            )
        )
        row = self.rows()[0]
        self.assertEqual(row["actor"], "alice")
        self.assertEqual(row["action"], "site.update")
        self.assertEqual(row["object_id"], "shop.example.com")
        self.assertEqual(row["result"], "success")
        self.assertIn("backend:", row["summary"])
        self.assertIn("10.0.0.2", row["after_json"])

    def test_failures_and_denials_are_recorded_too(self):
        # A refused attempt is exactly what an audit trail is for.
        self.log.record("site.delete", result=audit.RESULT_DENIED, actor="bob")
        self.log.record("site.delete", result=audit.RESULT_FAILURE, actor="bob")
        self.assertEqual(
            [row["result"] for row in self.rows()], ["denied", "failure"]
        )

    def test_an_unknown_result_falls_back_rather_than_being_stored_raw(self):
        self.log.record("x", result="whatever")
        self.assertEqual(self.rows()[0]["result"], "success")

    def test_oversized_fields_are_truncated(self):
        self.log.record(
            "x" * 500,
            actor="y" * 500,
            object_id="z" * 900,
            after={"blob": "q" * 50000},
        )
        row = self.rows()[0]
        self.assertLessEqual(len(row["action"]), 120)
        self.assertLessEqual(len(row["actor"]), 120)
        self.assertLessEqual(len(row["object_id"]), 200)
        self.assertLessEqual(len(row["after_json"]), audit.MAX_JSON_BYTES)

    def test_an_unserialisable_payload_does_not_lose_the_record(self):
        self.assertTrue(self.log.record("x", after={"obj": object()}))
        self.assertEqual(len(self.rows()), 1)

    def test_a_broken_database_never_raises_into_the_operation(self):
        # The operation being audited must not fail because auditing failed.
        broken = audit.AuditLog("/proc/nonexistent/audit.db")
        self.assertFalse(broken.record("site.update", actor="alice"))
        self.assertGreater(broken.write_failures, 0)
        self.assertFalse(broken.stats()["available"])


class QueryTests(AuditLogTestCase):
    def setUp(self):
        super().setUp()
        for index, (actor, action, kind, result, ts) in enumerate(
            [
                ("alice", "site.update", "site", "success", 1000),
                ("bob", "site.delete", "site", "denied", 2000),
                ("alice", "backend.state", "server", "success", 3000),
                ("system", "cert.renew", "certificate", "failure", 4000),
            ]
        ):
            self.log.record(
                action, actor=actor, object_type=kind, result=result, ts=ts
            )

    def test_the_newest_record_comes_first(self):
        events = self.log.query()["events"]
        self.assertEqual([e["ts"] for e in events], [4000, 3000, 2000, 1000])

    def test_every_filter_narrows_the_result(self):
        self.assertEqual(self.log.query(actor="alice")["total"], 2)
        self.assertEqual(self.log.query(action="cert.renew")["total"], 1)
        self.assertEqual(self.log.query(object_type="site")["total"], 2)
        self.assertEqual(self.log.query(result="denied")["total"], 1)
        self.assertEqual(self.log.query(since=3000)["total"], 2)
        self.assertEqual(self.log.query(until=2000)["total"], 2)

    def test_filters_are_parameters_not_sql(self):
        for hostile in ("' OR 1=1 --", "alice'; DROP TABLE audit_events; --"):
            self.assertEqual(self.log.query(actor=hostile)["total"], 0)
        # The table is still there.
        self.assertEqual(self.log.query()["total"], 4)

    def test_paging_reports_the_full_total(self):
        page = self.log.query(limit=2)
        self.assertEqual(page["total"], 4)
        self.assertEqual(len(page["events"]), 2)
        second = self.log.query(limit=2, offset=2)
        self.assertEqual(
            [e["ts"] for e in second["events"]], [2000, 1000]
        )

    def test_the_page_size_is_capped(self):
        self.assertLessEqual(len(self.log.query(limit=100000)["events"]), 500)

    def test_distinct_only_answers_for_known_columns(self):
        self.assertEqual(self.log.distinct("actor"), ["alice", "bob", "system"])
        self.assertEqual(self.log.distinct("result"), [])
        self.assertEqual(self.log.distinct("id; DROP TABLE audit_events"), [])


class RetentionTests(AuditLogTestCase):
    def test_records_past_the_retention_window_are_removed(self):
        self.log.record("old", ts=1000)
        self.log.record("new", ts=100 * 86400)
        removed = self.log.apply_retention(now=100 * 86400, days=30)
        self.assertEqual(removed, 1)
        self.assertEqual([r["action"] for r in self.rows()], ["new"])

    def test_a_hard_row_cap_bounds_the_file(self):
        for index in range(50):
            self.log.record("x", ts=100 * 86400 + index)
        self.log.apply_retention(now=100 * 86400 + 100, days=365, max_rows=1000)
        self.assertEqual(len(self.rows()), 50)


class InstrumentationTests(unittest.TestCase):
    """The routes that change something must say so."""

    def source(self, name):
        return (APP_DIR / name).read_text(encoding="utf-8")

    def test_runtime_operations_are_audited(self):
        text = self.source("routes_runtime.py")
        self.assertIn("record_request", text)
        for action in ("backend.state", "backend.weight"):
            self.assertIn(f'"{action}"', text)
        # Refusals and failures are recorded, not just the happy path.
        self.assertIn("RESULT_DENIED", text)
        self.assertIn("RESULT_FAILURE", text)

    def test_the_adaptive_mode_switch_is_audited(self):
        text = self.source("routes_security.py")
        self.assertIn('"adaptive.mode"', text)
        self.assertIn("RESULT_DENIED", text)
        self.assertIn("RESULT_FAILURE", text)

    # Every route module that changes something, and the action names it is
    # expected to record. A shipped audit page that logs almost nothing is
    # worse than none, so this is a coverage floor, not a sample.
    EXPECTED = {
        "routes.py": (
            "ban.lift", "whitelist.add", "user.create", "user.update",
            "user.delete", "authelia_ban.lift",
        ),
        "routes_haproxy_sites.py": (
            "site.create", "site.update", "site.delete", "certificate.upload",
        ),
        "routes_haproxy_tcp.py": (
            "tcp_proxy.create", "tcp_proxy.update", "tcp_proxy.delete",
        ),
        "routes_haproxy_udp.py": (
            "udp_forward.create", "udp_forward.update", "udp_forward.delete",
        ),
        "routes_geoip.py": ("geoip.update", "geoip.countries", "geoip.schedule"),
        "routes_health.py": ("service.control",),
        "routes_security.py": ("adaptive.mode", "request_log.enabled"),
        "routes_cert_delivery.py": (
            "cert_delivery.save", "cert_delivery.delete", "cert_delivery.test",
        ),
        "routes_authelia_settings.py": (
            "authelia_mail.update", "authelia_mail.test",
            "authelia_settings.update",
        ),
        "routes_haproxy_config.py": (
            "config.apply", "config.confirm", "config.rollback",
            "config.revert", "config.upload", "vars.update",
            "certificate.issue", "certificate.delete", "certificate.export",
            "certificate.restore", "ca.create", "ca.rotate", "ca.delete",
            "ca.import", "ca.client_auth", "ca.revoke_client",
            "acme_email.update", "site.create", "site.update",
            "site.delete", "tcp_proxy.create", "tcp_proxy.delete",
        ),
        "routes_backup.py": (
            "backup.start", "restore.start", "backup.delete",
            "backup_destination.save", "backup_destination.delete",
            "backup_destination.test", "backup.upload",
        ),
        "routes_updates.py": (
            "update.channels", "update.apply", "system.reboot",
            "system.reboot_cancel",
        ),
        "routes_runtime.py": ("backend.state", "backend.weight"),
        "routes_security.py": ("adaptive.mode",),
        "routes_config_history.py": ("config.restore",),
        "routes_dns_providers.py": ("dns_provider.save", "dns_provider.delete"),
        "routes_alerts.py": ("alerts.config", "alerts.test"),
    }

    def test_every_mutating_module_records_its_actions(self):
        for module, actions in sorted(self.EXPECTED.items()):
            text = self.source(module)
            self.assertIn("record_request", text, module)
            for action in actions:
                self.assertIn(f'"{action}"', text, f"{module}: {action}")

    def test_no_mutating_route_module_is_left_out(self):
        # A new routes_*.py with a POST handler has to be added above, or the
        # audit page silently stops telling the truth about the gateway.
        skip = {"routes_audit.py", "routes_monitoring.py"}
        for path in sorted(APP_DIR.glob("routes*.py")):
            if path.name in skip or path.name in self.EXPECTED:
                continue
            text = path.read_text(encoding="utf-8")
            mutating = (
                "@bp.post" in text
                or "@bp_" in text and ".post(" in text
                or '"POST"' in text
            )
            self.assertFalse(mutating, f"{path.name} mutates but is unaudited")

    def test_a_failure_is_recorded_and_not_only_the_happy_path(self):
        for module in ("routes_haproxy_sites.py", "routes_haproxy_config.py",
                       "routes_backup.py", "routes_updates.py",
                       "routes_health.py"):
            self.assertIn("RESULT_FAILURE", self.source(module), module)

    def test_the_identity_comes_from_the_authenticated_boundary(self):
        # g.remote_user is what security.py sets; anything else is a typo that
        # would silently record an empty actor.
        self.assertIn('getattr(g, "remote_user"', audit.__file__ and
                      (APP_DIR / "audit.py").read_text(encoding="utf-8"))
        for path in sorted(APP_DIR.glob("routes*.py")):
            self.assertNotIn(
                'g, "username"', path.read_text(encoding="utf-8"), path.name
            )


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "audit.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "audit.js").read_text(
            encoding="utf-8"
        )
        self.routes = (APP_DIR / "routes_audit.py").read_text(encoding="utf-8")

    def test_the_log_is_read_only(self):
        # No route may create, edit or delete a record from the interface.
        self.assertNotIn("@bp.post", self.routes)
        self.assertNotIn("@bp.delete", self.routes)
        self.assertNotIn('method: "POST"', self.javascript)

    def test_stored_payloads_are_excluded_from_dom_translation(self):
        self.assertIn('block.setAttribute("data-i18n-skip", "")', self.javascript)
        for element_id in ("au-body", "au-detail-meta", "au-detail-title"):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])

    def test_the_page_explains_the_redaction_guarantee(self):
        self.assertIn("Secrets are replaced before anything is stored", self.template)


class DeploymentTests(unittest.TestCase):
    def test_the_container_can_write_the_log_and_nothing_else_new(self):
        compose = (
            ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("AUDIT_DATABASE", compose)
        self.assertIn("audit_database_path", compose)
        # The mount is the audit directory, not the whole of /var/lib.
        self.assertNotIn('- "/var/lib:/var/lib:rw"', compose)

    def test_the_directory_is_created_with_a_shared_group(self):
        fs_tasks = (
            ROOT / "ansible/roles/haproxy-admin/tasks/fs.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Ensure audit dir exists", fs_tasks)
        self.assertIn('mode: "0770"', fs_tasks)

    def test_the_log_is_in_the_disaster_recovery_archive(self):
        backup = (ROOT / "installer" / "full_backup.py").read_text(encoding="utf-8")
        self.assertIn('"/var/lib/easy-ha-proxy"', backup)
        # Metrics live under the same root and must stay out: they are large
        # and not needed to restore a working gateway.
        self.assertIn('"var/lib/easy-ha-proxy/metrics"', backup)


if __name__ == "__main__":
    unittest.main()
