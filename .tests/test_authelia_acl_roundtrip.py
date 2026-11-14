"""Exercise the actual ACL form, RBAC, CSRF, and local configd transaction.

Only a temporary configuration is written; validation and restart are stubbed.
"""

from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from html.parser import HTMLParser
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/app"))
import haproxy_admin
from haproxy_admin import authelia_acl


class ACLForm(HTMLParser):
    """Read the successful controls from the rendered form, as a browser does."""

    def __init__(self, html):
        super().__init__()
        self.active = False
        self.form = {}
        self.capture = None
        self.select = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.active = attrs.get("id") == "authelia-acl-form"
        if not self.active or "disabled" in attrs:
            return
        if tag == "input" and attrs.get("name"):
            kind = attrs.get("type", "text")
            if kind != "checkbox" or "checked" in attrs:
                self.form[attrs["name"]] = attrs.get("value", "on" if kind == "checkbox" else "")
        if tag == "select":
            self.select = attrs.get("name")
        if tag == "option" and self.select and "selected" in attrs:
            self.form[self.select] = attrs.get("value", "")
        if tag == "textarea":
            self.capture = attrs.get("name")
            if self.capture:
                self.form[self.capture] = ""

    def handle_data(self, value):
        if self.capture:
            self.form[self.capture] += value

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = False
        if tag == "select":
            self.select = None
        if tag == "textarea":
            self.capture = None


class ACLRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.path = directory / "configuration.yml"
        self.original = [
            {"domain": "simple.example.test", "policy": "one_factor"},
            {"domain": "finance.example.test", "policy": "two_factor",
             "subject": [["group:employees", "group:finance"], "user:auditor"],
             "networks": ["10.0.0.0/8"], "methods": ["GET"],
             "resources": ["^/reports$", "^/exports$"]},
            {"domain_regex": "^app[0-9]+\\.example\\.test$", "policy": "deny",
             "query": [{"key": "admin", "operator": "present"}]},
            {"domain": "legacy.example.test", "policy": "one_factor",
             "subject": ["group:authenticated"]},
        ]
        self.write_rules(self.original)
        spec = importlib.util.spec_from_file_location(
            "acl_roundtrip_configd", ROOT / "ansible/roles/authelia/files/authelia-configd.py"
        )
        self.daemon = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.daemon)
        self.daemon.CONFIG_FILE = str(self.path)
        self.stack.enter_context(patch.object(self.daemon, "_validate_config_via_authelia"))
        self.stack.enter_context(patch.dict(os.environ, {
            "HAPROXY_ADMIN_SECRET_KEY": "acl-test-session-secret",
            "HAPROXY_ADMIN_PROXY_SECRET": "acl-test-proxy-secret",
            "EASY_HA_PROXY_PROTECTED_DOMAINS": "",
        }))
        for name in ("ensure_whitelist_file", "init_cache"):
            self.stack.enter_context(patch.object(haproxy_admin, name))
        self.stack.enter_context(patch.object(haproxy_admin.updates_badge, "current_level", return_value=None))
        self.stack.enter_context(patch.object(haproxy_admin.build_info, "footer", return_value={}))
        self.rpc = self.stack.enter_context(patch.object(
            authelia_acl, "_configd_request", side_effect=self.dispatch
        ))
        self.stack.enter_context(patch.object(authelia_acl, "_wait_for_authelia_healthy", return_value=True))
        self.app = haproxy_admin.create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.headers = {
            "X-Easy-HA-Proxy-Secret": "acl-test-proxy-secret",
            "Remote-User": "operator",
            "Remote-Groups": "superadmin",
            "Referer": "https://localhost/authelia/acl/",
        }

    def write_rules(self, rules):
        self.path.write_text(yaml.safe_dump({"access_control": {
            "default_policy": "deny", "rules": rules,
        }}), encoding="utf-8")

    def saved_rules(self):
        return yaml.safe_load(self.path.read_text())["access_control"]["rules"]

    def dispatch(self, payload):
        if payload["action"] == "rules_get":
            return self.daemon._handle_rules_get(payload)
        if payload["action"] == "rules_set":
            return self.daemon._handle_rules_set(payload)
        if payload["action"] == "restart":
            return {"ok": True}
        raise AssertionError(payload)

    def get_form(self, client=None):
        response = (client or self.client).get(
            "/authelia/acl/", headers=self.headers, base_url="https://localhost"
        )
        self.assertEqual(response.status_code, 200)
        return ACLForm(response.get_data(as_text=True)).form

    def post(self, form, *, client=None, headers=None):
        return (client or self.client).post(
            "/authelia/acl/", data=form, headers=headers or self.headers,
            base_url="https://localhost",
        )

    def assert_not_saved(self):
        self.assertEqual(self.saved_rules(), self.original)
        self.assertFalse(any(c.args[0]["action"] in {"rules_set", "restart"}
                             for c in self.rpc.call_args_list))

    def test_edit_other_domain_preserves_all_advanced_rules_and_restarts(self):
        form = self.get_form()
        self.assertTrue(form["acl_snapshot"])
        form.update({"rule-0-policy": "two_factor", "submit_action": "apply"})
        response = self.post(form)
        self.assertEqual(response.status_code, 302)
        expected = deepcopy(self.original)
        expected[0]["policy"] = "two_factor"
        self.assertEqual(self.saved_rules(), expected)
        self.assertEqual(self.rpc.call_args.args[0]["action"], "restart")

    def test_simple_form_edits_groups_users_anonymous_and_resources(self):
        form = self.get_form()
        form.update({"rule-0-groups": "staff, support", "rule-0-users": "alice",
                     "rule-0-flag_anonymous": "on", "rule-0-resources": "^/a$\r\n^/b$",
                     "submit_action": "save"})
        self.assertEqual(self.post(form).status_code, 302)
        self.assertEqual(self.saved_rules()[0], {
            "domain": "simple.example.test", "policy": "one_factor",
            "subject": ["group:staff", "group:support", "user:alice", "group:anonymous"],
            "resources": ["^/a$", "^/b$"],
        })
        self.assertEqual(self.saved_rules()[1:], self.original[1:])

    def test_untouched_scalar_and_singleton_subjects_preserve_original_structure(self):
        extra = [
            {"domain": ["one.example.test"], "policy": "one_factor", "subject": "user:alice",
             "resources": "^/private$"},
            {"domain": "two.example.test", "policy": "one_factor", "subject": [["group:staff"]]},
        ]
        self.write_rules(self.original + extra)
        form = self.get_form()
        form["submit_action"] = "save"
        self.assertEqual(self.post(form).status_code, 302)
        self.assertEqual(self.saved_rules(), self.original + extra)

    def test_policy_edit_keeps_untouched_field_shapes(self):
        original = [{
            "domain": ["scalar.example.test"], "policy": "one_factor",
            "subject": "user:alice", "resources": "^/first$",
        }]
        self.write_rules(original)
        form = self.get_form()
        form.update({"rule-0-policy": "two_factor", "submit_action": "save"})
        self.assertEqual(self.post(form).status_code, 302)
        original[0]["policy"] = "two_factor"
        self.assertEqual(self.saved_rules(), original)

    def test_russian_advanced_rule_rejection_is_visible(self):
        form = self.get_form()
        form.update({"rule-1-groups": "employees", "submit_action": "save"})
        response = self.post(form, headers={**self.headers, "Accept-Language": "ru"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("расширенные правила нельзя редактировать", response.get_data(as_text=True))
        self.assert_not_saved()

    def test_advanced_rule_changes_are_rejected_server_side(self):
        for field, value in (("groups", "employees"), ("policy", "bypass"),
                             ("domains", "other.example.test"), ("resources", "")):
            with self.subTest(field=field):
                form = self.get_form()
                form.update({f"rule-1-{field}": value, "submit_action": "apply"})
                response = self.post(form)
                self.assertEqual(response.status_code, 200)
                self.assertIn("advanced rules cannot be edited", response.get_data(as_text=True))
                self.assert_not_saved()

    def test_hidden_original_json_cannot_replace_trusted_backend_rule(self):
        form = self.get_form()
        form.update({"rule-1-original": '{"domain":"finance.example.test","policy":"bypass"}',
                     "original_rules": "[]", "submit_action": "save"})
        self.assertEqual(self.post(form).status_code, 302)
        self.assertEqual(self.saved_rules(), self.original)

    def test_source_reference_tampering_cannot_downgrade_advanced_rules(self):
        for value in ("", "0", "900", "not-an-index"):
            with self.subTest(value=value):
                form = self.get_form()
                form.update({"rule-1-source_index": value, "submit_action": "save"})
                self.assertEqual(self.post(form).status_code, 400)
                self.assert_not_saved()

    def test_missing_or_tampered_snapshot_is_rejected(self):
        for token in ("", "invalid-token"):
            form = self.get_form()
            form.update({"acl_snapshot": token, "submit_action": "save"})
            self.assertEqual(self.post(form).status_code, 400)
            self.assert_not_saved()

    def test_snapshot_is_bound_to_session(self):
        form = self.get_form()
        other_client = self.app.test_client()
        other_form = self.get_form(other_client)
        form.update({"csrf_token": other_form["csrf_token"], "submit_action": "save"})
        self.assertEqual(self.post(form, client=other_client).status_code, 400)
        self.assert_not_saved()

    def test_snapshot_is_bound_to_authenticated_user(self):
        form = self.get_form()
        form["submit_action"] = "save"
        self.assertEqual(self.post(form, headers={**self.headers, "Remote-User": "another"}).status_code, 400)
        self.assert_not_saved()

    def test_real_csrf_rbac_and_trusted_proxy_checks_still_apply(self):
        form = self.get_form()
        form["submit_action"] = "save"
        self.assertEqual(self.post(form, headers={**self.headers, "Remote-Groups": "admins"}).status_code, 403)
        self.assertEqual(self.post(form, headers={**self.headers, "X-Easy-HA-Proxy-Secret": "wrong"}).status_code, 403)
        del form["csrf_token"]
        self.assertEqual(self.post(form).status_code, 400)
        self.assert_not_saved()

    def test_stale_page_is_rejected_before_saving(self):
        form = self.get_form()
        changed = deepcopy(self.original)
        changed[0]["policy"] = "deny"
        self.write_rules(changed)
        form.update({"rule-0-policy": "bypass", "submit_action": "apply"})
        response = self.post(form)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Reload before editing", response.get_data(as_text=True))
        self.assertEqual(self.saved_rules(), changed)
        self.assertFalse(any(c.args[0]["action"] in {"rules_set", "restart"}
                             for c in self.rpc.call_args_list))

    def test_configd_cas_rejects_change_between_post_load_and_save(self):
        form = self.get_form()
        changed = deepcopy(self.original)
        changed[0]["policy"] = "deny"

        def race(payload):
            if payload["action"] == "rules_set":
                self.write_rules(changed)
            return self.dispatch(payload)

        self.rpc.side_effect = race
        form.update({"rule-0-policy": "bypass", "submit_action": "apply"})
        response = self.post(form)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Reload before editing", response.get_data(as_text=True))
        self.assertEqual(self.saved_rules(), changed)
        self.assertFalse(any(c.args[0]["action"] == "restart" for c in self.rpc.call_args_list))

    def test_add_move_delete_keep_original_rule_identity(self):
        form = self.get_form()
        form["move_rule_up"] = "1"
        response = self.post(form)
        form = ACLForm(response.get_data(as_text=True)).form
        self.assertEqual(form["rule-0-source_index"], "1")
        form["add_rule"] = "1"
        response = self.post(form)
        form = ACLForm(response.get_data(as_text=True)).form
        self.assertEqual(form["total_rules"], "5")
        form["rule-4-domains"] = "new.example.test"
        form["delete_rule"] = "1"
        response = self.post(form)
        form = ACLForm(response.get_data(as_text=True)).form
        form["submit_action"] = "save"
        self.assertEqual(self.post(form).status_code, 302)
        self.assertEqual(self.saved_rules(), self.original[1:] + [
            {"domain": "new.example.test", "policy": "one_factor"},
        ])

    def test_validation_error_keeps_source_metadata_for_retry(self):
        form = self.get_form()
        form.update({"rule-0-domains": "", "rule-0-groups": "staff", "submit_action": "save"})
        response = self.post(form)
        self.assertEqual(response.status_code, 200)
        self.assert_not_saved()
        form = ACLForm(response.get_data(as_text=True)).form
        form.update({"rule-0-domains": "fixed.example.test", "submit_action": "save"})
        self.assertEqual(self.post(form).status_code, 302)
        self.assertEqual(self.saved_rules()[1:], self.original[1:])

    def test_load_failure_disables_post_instead_of_overwriting(self):
        form = self.get_form()
        self.rpc.side_effect = lambda payload: {"ok": False, "error": "temporary read failure"}
        form["submit_action"] = "save"
        response = self.post(form)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('id="authelia-acl-form"', response.get_data(as_text=True))
        self.assert_not_saved()

    def test_invalid_backend_element_disables_editor_instead_of_dropping_it(self):
        self.write_rules(self.original + ["invalid rule"])
        response = self.client.get("/authelia/acl/", headers=self.headers, base_url="https://localhost")
        self.assertNotIn('id="authelia-acl-form"', response.get_data(as_text=True))
        self.assertEqual(self.saved_rules(), self.original + ["invalid rule"])

    def test_configd_optional_revision_preserves_legacy_client_compatibility(self):
        result = self.daemon._handle_rules_set({"rules_yaml": yaml.safe_dump(self.original)})
        self.assertTrue(result["ok"], result)
        view = self.daemon._handle_rules_get({})
        self.assertEqual(view["revision"], authelia_acl._rules_revision(self.original))
        result = self.daemon._handle_rules_set({
            "rules_yaml": yaml.safe_dump(self.original), "expected_revision": view["revision"],
        })
        self.assertTrue(result["ok"], result)

    def test_configd_invalid_and_stale_revisions_do_not_write(self):
        for revision in (None, 12, [], "obsolete", "устарело"):
            with self.subTest(revision=revision):
                result = self.daemon._handle_rules_set({
                    "rules_yaml": "[]", "expected_revision": revision,
                })
                self.assertFalse(result["ok"])
                self.assertTrue(result["conflict"])
                self.assertEqual(self.saved_rules(), self.original)


if __name__ == "__main__":
    unittest.main()
