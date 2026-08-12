"""Regression tests for the server-authoritative HAProxy status indicator."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "docker" / "app" / "haproxy_admin"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PACKAGE_NAME = "easy_ha_global_config_state_test"
package = types.ModuleType(PACKAGE_NAME)
package.__path__ = [str(PACKAGE_ROOT)]
sys.modules.setdefault(PACKAGE_NAME, package)
load_module(f"{PACKAGE_NAME}.validation", PACKAGE_ROOT / "validation.py")
i18n = types.ModuleType(f"{PACKAGE_NAME}.i18n")
i18n.translate = lambda value, **_kwargs: value
sys.modules[f"{PACKAGE_NAME}.i18n"] = i18n
config_service = load_module(
    f"{PACKAGE_NAME}.services_haproxy_config",
    PACKAGE_ROOT / "services_haproxy_config.py",
)


def summary(*, source=False, rendered=False, applied=True):
    return {
        "server_differs": rendered,
        "has_applied_state": applied,
        "source_has_changes": source,
        "has_changes": source or rendered,
        "sites_added": ["private.example.test"] if source else [],
        "sites_removed": [],
        "sites_changed": {},
        "tcp_added": [],
        "tcp_removed": [],
        "tcp_changed": {},
        "global_changed_keys": ["enable_geoip"] if source else [],
    }


class ConfigurationStateServiceTests(unittest.TestCase):
    def state(self, diff, transaction=None):
        with (
            mock.patch.object(
                config_service, "render_haproxy_cfg", return_value="rendered\n"
            ),
            mock.patch.object(
                config_service, "get_config_diff_summary", return_value=diff
            ),
            mock.patch.object(
                config_service,
                "get_config_transaction_status",
                return_value=transaction or {"ok": True, "state": "none"},
            ),
            mock.patch.object(
                config_service,
                "ensure_applied_state_baseline",
                return_value=False,
            ) as ensure_baseline,
        ):
            result = config_service.get_haproxy_configuration_state()
        self.ensure_baseline = ensure_baseline
        return result

    def test_clean_state_is_reported_without_configuration_values(self):
        result = self.state(summary())

        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "clean")
        self.assertFalse(result["pending"])
        self.assertEqual(result["changes"]["total"], 0)
        self.assertNotIn("private.example.test", repr(result))
        self.assertNotIn("enable_geoip", repr(result))
        self.assertFalse(any("hash" in key for key in result))

    def test_semantic_source_change_is_unapplied_even_when_render_is_current(self):
        result = self.state(summary(source=True, rendered=False))

        self.assertEqual(result["state"], "unapplied")
        self.assertTrue(result["source_has_changes"])
        self.assertFalse(result["rendered_differs"])
        self.assertTrue(result["pending"])
        self.assertEqual(result["changes"], {
            "sites": 1,
            "tcp": 0,
            "global": 1,
            "total": 2,
        })

    def test_semantically_unchanged_formatting_does_not_create_warning(self):
        # The public state consumes parsed semantic deltas, not source byte
        # hashes, so YAML comments and formatting are intentionally ignored.
        result = self.state(summary(source=False, rendered=False))

        self.assertEqual(result["state"], "clean")
        self.assertFalse(result["pending"])

    def test_live_difference_without_source_changes_is_runtime_drift(self):
        result = self.state(summary(source=False, rendered=True))

        self.assertEqual(result["state"], "runtime_drift")
        self.assertTrue(result["rendered_differs"])
        self.assertTrue(result["pending"])

    def test_pending_confirmation_has_precedence_over_source_state(self):
        result = self.state(
            summary(source=True),
            {"ok": True, "state": "pending", "transaction_id": "secret-id"},
        )

        self.assertEqual(result["state"], "pending_confirmation")
        self.assertEqual(result["transaction_state"], "pending_confirmation")
        self.assertNotIn("secret-id", repr(result))

    def test_unavailable_transaction_state_never_looks_clean(self):
        result = self.state(
            summary(),
            {"ok": False, "error": "/private/socket: permission denied"},
        )

        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["status_available"])
        self.assertNotIn("/private/socket", repr(result))

    def test_missing_apply_history_is_unknown_not_clean(self):
        result = self.state(summary(applied=False))

        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["status_available"])

    def test_missing_history_is_seeded_only_after_a_safe_live_match(self):
        before = summary(applied=False)
        after = summary(applied=True)
        with (
            mock.patch.object(
                config_service, "render_haproxy_cfg", return_value="same\n"
            ),
            mock.patch.object(
                config_service,
                "get_config_diff_summary",
                side_effect=[before, after],
            ) as read_summary,
            mock.patch.object(
                config_service,
                "get_config_transaction_status",
                return_value={"ok": True, "state": "none"},
            ),
            mock.patch.object(
                config_service,
                "ensure_applied_state_baseline",
                return_value=True,
            ) as ensure_baseline,
        ):
            result = config_service.get_haproxy_configuration_state()

        ensure_baseline.assert_called_once_with("same\n")
        self.assertEqual(read_summary.call_count, 2)
        self.assertEqual(result["state"], "clean")
        self.assertTrue(result["has_applied_state"])

    def test_live_difference_is_never_accepted_as_an_initial_baseline(self):
        result = self.state(summary(rendered=True, applied=False))

        self.ensure_baseline.assert_not_called()
        self.assertEqual(result["state"], "runtime_drift")
        self.assertFalse(result["has_applied_state"])

    def test_pending_transaction_is_never_accepted_as_an_initial_baseline(self):
        result = self.state(
            summary(applied=False),
            {"ok": True, "state": "pending"},
        )

        self.ensure_baseline.assert_not_called()
        self.assertEqual(result["state"], "pending_confirmation")

    def test_existing_semantic_change_is_not_rebased_by_global_status(self):
        result = self.state(summary(source=True, applied=True))

        self.ensure_baseline.assert_not_called()
        self.assertEqual(result["state"], "unapplied")


class ConfigurationStateUiTests(unittest.TestCase):
    def test_superadmin_badge_uses_backend_state_without_browser_authority(self):
        template = (PACKAGE_ROOT / "templates" / "base.html").read_text(
            encoding="utf-8"
        )
        javascript = (PACKAGE_ROOT / "static" / "js" / "config_state.js").read_text(
            encoding="utf-8"
        )
        routes = (PACKAGE_ROOT / "routes_haproxy_config.py").read_text(
            encoding="utf-8"
        )
        mutation_scripts = "\n".join(
            (PACKAGE_ROOT / "static" / "js" / name).read_text(encoding="utf-8")
            for name in (
                "haproxy_config.js",
                "haproxy_site_edit.js",
                "haproxy_sites.js",
                "haproxy_tcp.js",
            )
        )

        self.assertIn("{% if g.is_superadmin %}", template)
        self.assertIn('id="global-config-state"', template)
        self.assertIn("routes.haproxy_configuration_state", template)
        self.assertIn('fetch(indicator.dataset.stateEndpoint', javascript)
        self.assertIn('cache: "no-store"', javascript)
        self.assertIn('document.addEventListener(CHANGE_EVENT, refreshState)', javascript)
        self.assertIn("refreshQueued = true", javascript)
        self.assertNotIn("localStorage", javascript)
        self.assertNotIn("sessionStorage", javascript)
        self.assertIn('@bp.get("/haproxy/config/state")', routes)
        self.assertGreaterEqual(
            mutation_scripts.count(
                'new CustomEvent("easy-ha-proxy:config-state-changed")'
            ),
            4,
        )

    def test_confirmation_edges_refresh_the_global_and_local_statuses(self):
        javascript = (PACKAGE_ROOT / "static" / "js" / "haproxy_config.js").read_text(
            encoding="utf-8"
        )

        failed_block = javascript.split(
            "function failTransaction(data) {", 1
        )[1].split("function acceptPendingTransaction(data) {", 1)[0]
        pending_block = javascript.split(
            "function acceptPendingTransaction(data) {", 1
        )[1].split("function updatePendingFromServer(data) {", 1)[0]

        self.assertIn("notifyConfigStateChanged();", failed_block)
        self.assertIn("void refreshConfigurationSummary();", failed_block)
        # Both the malformed-response branch and the accepted-pending branch
        # must refresh the authoritative badge immediately.
        self.assertGreaterEqual(
            pending_block.count("notifyConfigStateChanged();"), 2
        )
        self.assertGreaterEqual(
            pending_block.count("void refreshConfigurationSummary();"), 2
        )

    def test_non_pending_apply_outcomes_refresh_authoritative_statuses(self):
        javascript = (PACKAGE_ROOT / "static" / "js" / "haproxy_config.js").read_text(
            encoding="utf-8"
        )

        apply_block = javascript.split(
            "async function applyConfig(options) {", 1
        )[1].split("async function validateAndApplyConfig() {", 1)[0]
        terminal_block = apply_block.split(
            "const result = Object.assign({}, data, { ok: response.ok && !!data.ok });",
            1,
        )[1].split("} catch (error) {", 1)[0]
        transport_failure_block = apply_block.split(
            "} catch (error) {", 1
        )[1].split("} finally {", 1)[0]

        for block in (terminal_block, transport_failure_block):
            self.assertIn("notifyConfigStateChanged();", block)
            self.assertIn("void refreshConfigurationSummary();", block)


if __name__ == "__main__":
    unittest.main()
