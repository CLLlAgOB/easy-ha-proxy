"""Regression checks for the configuration history page and its diff."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_config_history as history  # noqa: E402


WEBSITES_BEFORE = """
sites:
  - name: shop
    domain: shop.example.com
    backend_ip: 192.168.1.10
    backend_port: 443
  - name: blog
    domain: blog.example.com
    backend_ip: 192.168.1.20
"""

WEBSITES_AFTER = """
sites:
  - name: blog
    domain: blog.example.com
    backend_ip: 192.168.1.20
  - name: shop
    domain: shop.example.com
    backend_ip: 192.168.1.11
    backend_port: 443
  - name: docs
    domain: docs.example.com
    backend_ip: 192.168.1.30
"""


def sources(websites="sites: []", tcp="tcp_proxies: []", variables="a: 1"):
    return {"websites.yml": websites, "tcp.yml": tcp, "vars.yml": variables}


class DiffTests(unittest.TestCase):
    def compare(self, before, after):
        return history.compare(before, after)

    def test_a_changed_backend_is_reported_against_its_site(self):
        result = self.compare(
            sources(websites=WEBSITES_BEFORE), sources(websites=WEBSITES_AFTER)
        )
        by_name = {c["name"]: c for c in result["changes"]}
        self.assertEqual(by_name["shop"]["change"], "modified")
        self.assertTrue(
            any("192.168.1.10" in f and "192.168.1.11" in f
                for f in by_name["shop"]["fields"]),
            by_name["shop"]["fields"],
        )

    def test_additions_and_removals_are_named(self):
        result = self.compare(
            sources(websites=WEBSITES_BEFORE), sources(websites=WEBSITES_AFTER)
        )
        by_name = {c["name"]: c["change"] for c in result["changes"]}
        self.assertEqual(by_name["docs"], "added")
        self.assertNotIn("blog", by_name)

    def test_reordering_is_not_a_change(self):
        # The file order carries no meaning, and reporting it would bury the
        # one edit that does.
        reordered = """
sites:
  - name: blog
    domain: blog.example.com
    backend_ip: 192.168.1.20
  - name: shop
    domain: shop.example.com
    backend_ip: 192.168.1.10
    backend_port: 443
"""
        result = self.compare(
            sources(websites=WEBSITES_BEFORE), sources(websites=reordered)
        )
        self.assertTrue(result["identical"], result["changes"])

    def test_tcp_proxies_are_compared_under_either_root_key(self):
        for key in ("tcp_proxies", "tcp"):
            result = self.compare(
                sources(tcp=f"{key}:\n  - name: db\n    port: 5432\n"),
                sources(tcp=f"{key}:\n  - name: db\n    port: 5433\n"),
            )
            names = [c["name"] for c in result["changes"]]
            self.assertEqual(names, ["db"], key)

    def test_variables_are_compared_as_a_mapping(self):
        result = self.compare(
            sources(variables="max_req_rate: 10\nother: keep\n"),
            sources(variables="max_req_rate: 25\nother: keep\n"),
        )
        self.assertEqual(len(result["changes"]), 1)
        self.assertIn("max_req_rate", result["changes"][0]["fields"][0])

    def test_identical_sources_report_no_change(self):
        same = sources(websites=WEBSITES_BEFORE)
        result = self.compare(same, dict(same))
        self.assertTrue(result["identical"])
        self.assertEqual(result["files_changed"], [])

    def test_which_files_moved_is_reported(self):
        result = self.compare(
            sources(websites=WEBSITES_BEFORE), sources(websites=WEBSITES_AFTER)
        )
        self.assertEqual(result["files_changed"], ["websites.yml"])

    def test_invalid_yaml_does_not_raise(self):
        result = self.compare(sources(websites=": : ["), sources())
        self.assertIsInstance(result["changes"], list)

    def test_long_values_are_shortened_for_display(self):
        result = self.compare(
            sources(variables="note: " + "x" * 500),
            sources(variables="note: " + "y" * 500),
        )
        line = result["changes"][0]["fields"][0]
        self.assertLess(len(line), 200)
        self.assertIn("…", line)


class ClientTests(unittest.TestCase):
    def test_versions_come_from_the_control_daemon(self):
        with mock.patch.object(
            history,
            "_controld_json_request",
            return_value={"ok": True, "versions": [{"id": "v1"}]},
        ) as call:
            self.assertEqual(history.list_versions(10), [{"id": "v1"}])
        self.assertEqual(call.call_args.args[0], "config-versions 10")

    def test_the_limit_is_bounded_before_it_leaves_the_application(self):
        with mock.patch.object(
            history, "_controld_json_request", return_value={"ok": True, "versions": []}
        ) as call:
            history.list_versions(100000)
        self.assertEqual(call.call_args.args[0], f"config-versions {history.MAX_VERSIONS}")

    def test_an_unavailable_daemon_raises_a_typed_error(self):
        with mock.patch.object(
            history, "_controld_json_request", return_value={"ok": False, "error": "no"}
        ):
            with self.assertRaises(history.HistoryUnavailable):
                history.list_versions()

    def test_sources_are_decoded_and_filtered_to_the_managed_files(self):
        payload = {
            "ok": True,
            "version": {
                "id": "v1",
                "sources": {
                    "websites.yml": base64.b64encode(b"sites: []").decode(),
                    "unexpected.yml": base64.b64encode(b"x").decode(),
                },
            },
        }
        with mock.patch.object(
            history, "_controld_json_request", return_value=payload
        ):
            meta, decoded = history.version_sources("v1")
        self.assertEqual(meta["id"], "v1")
        self.assertEqual(decoded, {"websites.yml": "sites: []"})

    def test_comparing_against_current_reads_the_live_configuration(self):
        with (
            mock.patch.object(
                history, "current_sources", return_value=sources(websites=WEBSITES_AFTER)
            ),
            mock.patch.object(
                history,
                "version_sources",
                return_value=({"id": "v1"}, sources(websites=WEBSITES_BEFORE)),
            ),
        ):
            payload = history.diff("v1", history.CURRENT)
        self.assertEqual(payload["right"]["id"], history.CURRENT)
        self.assertFalse(payload["identical"])


class RestoreTests(unittest.TestCase):
    """Restore must reuse the guarded path and leave nothing behind on failure."""

    def setUp(self):
        self.original = sources(websites="sites: [current]\n")
        self.stored = sources(websites="sites: [old]\n")
        self.written = []

        patchers = [
            mock.patch.object(history, "current_sources", return_value=self.original),
            mock.patch.object(
                history,
                "version_sources",
                return_value=({"id": "v1"}, self.stored),
            ),
            mock.patch.object(
                history, "_write_sources", side_effect=self.written.append
            ),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_config_module(self, **overrides):
        module = mock.MagicMock()
        module.CONFIG_YAML = "vars.yml"
        module._load_yaml.return_value = {"a": 1}
        module.render_haproxy_cfg.return_value = "global\n"
        module.preflight_cfg_confirmation.return_value = {"ok": True}
        module.begin_cfg_confirmation.return_value = {
            "ok": True, "state": "pending_confirmation"
        }
        for key, value in overrides.items():
            setattr(module, key, value)
        return module

    def run_restore(self, config_module=None, guard=None):
        config_module = config_module or self.fake_config_module()
        vars_module = mock.MagicMock()
        vars_module.validate_admin_access_for_client = guard or (lambda *a, **k: None)
        with mock.patch.dict(
            sys.modules,
            {
                "haproxy_admin.services_haproxy_config": config_module,
                "haproxy_admin.services_haproxy_vars": vars_module,
            },
        ):
            return history.restore("v1", client_ip="203.0.113.5")

    def test_a_successful_restore_hands_off_to_the_guarded_apply(self):
        module = self.fake_config_module()
        result = self.run_restore(module)
        self.assertTrue(result["ok"])
        self.assertEqual(result["restored_version"], "v1")
        module.begin_cfg_confirmation.assert_called_once()
        # Written once: the stored version. No revert was needed.
        self.assertEqual(self.written, [self.stored])

    def test_the_admin_lockout_guard_runs_before_anything_is_applied(self):
        module = self.fake_config_module()

        def refuse(_data, _ip):
            raise ValueError("your address would lose administrative access")

        with self.assertRaises(history.RestoreError) as caught:
            self.run_restore(module, guard=refuse)
        self.assertIn("administrative access", str(caught.exception))
        module.begin_cfg_confirmation.assert_not_called()
        # Written, then put back.
        self.assertEqual(self.written, [self.stored, self.original])

    def test_a_refused_preflight_puts_the_previous_sources_back(self):
        module = self.fake_config_module()
        module.preflight_cfg_confirmation.return_value = {
            "ok": False, "error": "the candidate is invalid",
            "error_code": "config_invalid",
        }
        with self.assertRaises(history.RestoreError) as caught:
            self.run_restore(module)
        self.assertEqual(caught.exception.error_code, "config_invalid")
        module.begin_cfg_confirmation.assert_not_called()
        self.assertEqual(self.written, [self.stored, self.original])

    def test_a_failing_render_puts_the_previous_sources_back(self):
        module = self.fake_config_module()
        module.render_haproxy_cfg.side_effect = ValueError("template broke")
        with self.assertRaises(history.RestoreError):
            self.run_restore(module)
        self.assertEqual(self.written, [self.stored, self.original])

    def test_an_incomplete_version_is_refused_before_anything_is_written(self):
        with mock.patch.object(
            history,
            "version_sources",
            return_value=({"id": "v1"}, {"websites.yml": "sites: []"}),
        ):
            with self.assertRaises(history.RestoreError) as caught:
                self.run_restore()
        self.assertEqual(caught.exception.error_code, "version_incomplete")
        self.assertEqual(self.written, [])

    def test_a_revert_that_also_fails_is_reported_as_dirty(self):
        module = self.fake_config_module()
        module.render_haproxy_cfg.side_effect = ValueError("template broke")
        with mock.patch.object(
            history, "_write_sources", side_effect=[None, OSError("read-only")]
        ):
            with self.assertRaises(history.RestoreError) as caught:
                self.run_restore(module)
        self.assertEqual(caught.exception.error_code, "restore_dirty")
        self.assertIn("inspect it on the server", str(caught.exception))


class SourcePathTests(unittest.TestCase):
    def test_restore_writes_the_working_files_not_the_rollback_snapshot(self):
        # `_applied_config_source_paths()` returns backups/haproxy/
        # last_applied_*.yml — the safe snapshot the guarded apply rolls back
        # to. Writing there would destroy the very thing that makes a failed
        # apply recoverable, while leaving the real configuration untouched.
        source = (APP_DIR / "services_config_history.py").read_text(encoding="utf-8")
        self.assertNotIn("_applied_config_source_paths", source)
        self.assertIn("_current_config_source_paths", source)

    def test_the_two_accessors_really_are_different_files(self):
        from haproxy_admin.services_haproxy_config import (
            _applied_config_source_paths,
            _current_config_source_paths,
        )

        applied = _applied_config_source_paths()
        current = _current_config_source_paths()
        self.assertNotEqual(applied, current)
        self.assertIn("last_applied", str(applied["vars.yml"]))
        self.assertNotIn("last_applied", str(current["vars.yml"]))


class RestoreRouteTests(unittest.TestCase):
    def setUp(self):
        self.routes = (APP_DIR / "routes_config_history.py").read_text(
            encoding="utf-8"
        )

    def test_restore_is_the_only_mutating_route_and_it_is_guarded(self):
        self.assertEqual(self.routes.count("@bp.post"), 1)
        self.assertIn("versions/restore", self.routes)
        self.assertIn('getattr(g, "is_superadmin", False)', self.routes)

    def test_every_outcome_is_audited(self):
        self.assertIn('"config.restore"', self.routes)
        self.assertIn("RESULT_DENIED", self.routes)
        self.assertIn("RESULT_FAILURE", self.routes)
        # A started restore is not a finished one: it still needs confirming.
        self.assertIn("awaiting confirmation", self.routes)

    def test_the_client_address_is_passed_to_the_lockout_guard(self):
        self.assertIn("client_ip=_client_ip()", self.routes)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "config_history.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "config_history.js").read_text(
            encoding="utf-8"
        )
        self.routes = (APP_DIR / "routes_config_history.py").read_text(encoding="utf-8")

    def test_a_version_cannot_be_created_or_deleted_through_the_interface(self):
        # A version exists because a change was confirmed. Restore replays one;
        # nothing writes or removes history itself.
        self.assertNotIn("@bp.delete", self.routes)
        for forbidden in ("versions/create", "versions/delete"):
            self.assertNotIn(forbidden, self.routes, forbidden)
            self.assertNotIn(forbidden, self.javascript, forbidden)

    def test_restoring_needs_a_confirmation_and_carries_the_csrf_token(self):
        self.assertIn('id="ch-confirm"', self.template)
        self.assertIn("askRestore", self.javascript)
        self.assertIn("commitRestore", self.javascript)
        self.assertIn('"X-CSRFToken": csrfToken()', self.javascript)

    def test_restore_is_only_offered_against_the_running_configuration(self):
        # "Make this the running configuration" is meaningless when the
        # comparison is between two old versions.
        self.assertIn("right.value === CURRENT", self.javascript)

    def test_identifiers_and_values_are_excluded_from_dom_translation(self):
        for element_id in ("ch-list", "ch-left", "ch-right"):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.template)
            self.assertIsNotNone(tag, element_id)
            self.assertIn("data-i18n-skip", tag.group(0))
        self.assertIn('fields.setAttribute("data-i18n-skip", "")', self.javascript)

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])

    def test_the_page_explains_what_is_compared(self):
        self.assertIn("managed model", self.template)
        self.assertIn("not the generated HAProxy file", self.template)


class CatalogTests(unittest.TestCase):
    def test_the_diff_vocabulary_is_translated(self):
        shared = set()
        for path in (APP_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["meta"]["code"] == "ru":
                shared |= set(data["messages"])
        # These come back from the service as values, not as interface text.
        for token in ("site", "tcp", "variable", "added", "removed", "modified"):
            self.assertIn(token, shared, token)


if __name__ == "__main__":
    unittest.main()
