"""Regression tests for the revision-safe vars.yml configuration editor."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from jinja2 import Environment, FileSystemLoader
import yaml


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker" / "app"
PACKAGE_ROOT = APP_ROOT / "haproxy_admin"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType("haproxy_admin")
package.__path__ = [str(PACKAGE_ROOT)]
sys.modules.setdefault("haproxy_admin", package)
validation = _load_module("haproxy_admin.validation", PACKAGE_ROOT / "validation.py")
i18n = types.ModuleType("haproxy_admin.i18n")
i18n.translate = lambda value, **_kwargs: value
sys.modules["haproxy_admin.i18n"] = i18n
config_service = _load_module(
    "haproxy_admin.services_haproxy_config",
    PACKAGE_ROOT / "services_haproxy_config.py",
)
vars_service = _load_module(
    "haproxy_admin.services_haproxy_vars",
    PACKAGE_ROOT / "services_haproxy_vars.py",
)
certd_client = types.ModuleType("haproxy_admin.certd_client")
certd_client.get_cert_status_for_domain = lambda *_args, **_kwargs: {}
certd_client.issue_cert_for_domain = lambda *_args, **_kwargs: {}
certd_client.issue_internal_cert_for_domain = lambda *_args, **_kwargs: {}
sys.modules["haproxy_admin.certd_client"] = certd_client
sites_service = _load_module(
    "haproxy_admin.services_haproxy_sites",
    PACKAGE_ROOT / "services_haproxy_sites.py",
)


BASE_VARS = {
    "root_domain": "example.test",
    "admin_domain": "ha.example.test",
    "aut_domain": "aut.example.test",
    "enable_http80": True,
    "site_defaults": {
        "balance": "roundrobin",
        "backend_port": 80,
        "rate_window": "20s",
    },
    "future_unknown_setting": {"preserve": True},
}


class VarsEditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.vars_path = Path(self.temporary.name) / "vars.yml"
        self.vars_path.write_text(
            yaml.safe_dump(BASE_VARS, sort_keys=False), encoding="utf-8"
        )
        self.path_patch = mock.patch.object(
            vars_service, "CONFIG_YAML", self.vars_path
        )
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.pending_patch = mock.patch.object(
            vars_service,
            "config_transaction_is_pending",
            return_value=(False, ""),
        )
        self.pending_patch.start()
        self.addCleanup(self.pending_patch.stop)

    def revision(self) -> str:
        return hashlib.sha256(self.vars_path.read_bytes()).hexdigest()

    def test_model_exposes_guided_fields_and_advanced_yaml(self) -> None:
        model = vars_service.get_vars_editor_model()
        fields = {
            field["path"]: field
            for section in model["sections"]
            for field in section["fields"]
        }

        self.assertEqual(model["revision"], self.revision())
        self.assertIn("future_unknown_setting", model["yaml"])
        self.assertTrue(fields["root_domain"]["readonly"])
        self.assertFalse(fields["site_defaults.balance"]["readonly"])
        self.assertEqual(fields["site_defaults.backend_port"]["value"], 80)
        self.assertEqual(fields["site_defaults.hsts"]["value"], 15_552_000)
        self.assertFalse(fields["site_defaults.hsts"]["present"])
        self.assertFalse(fields["enable_geoip"]["value"])
        self.assertFalse(fields["enable_geoip"]["present"])
        self.assertEqual(fields["geoip_mode"]["value"], "allow")
        self.assertFalse(fields["geoip_mode"]["present"])
        self.assertTrue(fields["site_defaults.enable_geoip"]["value"])
        self.assertFalse(fields["site_defaults.enable_geoip"]["present"])
        self.assertTrue(fields["admin_authelia_enabled"]["value"])
        self.assertTrue(fields["admin_authelia_enabled"]["effective_value"])
        self.assertTrue(fields["admin_authelia_enabled"]["inherited"])
        self.assertTrue(fields["admin_authelia_enabled"]["readonly"])
        self.assertFalse(fields["admin_authelia_enabled"]["present"])
        self.assertNotIn("admin_authelia_enabled", vars_service.EDITABLE_FIELDS)
        self.assertEqual(fields["admin_ips_enabled"]["admin_ip_count"], 0)
        self.assertEqual(fields["admin_allowed_ips"]["value"], "")
        self.assertFalse(fields["admin_allowed_ips"]["present"])
        self.assertNotIn("site_defaults.geo_mode", fields)

        template = (
            PACKAGE_ROOT / "templates" / "haproxy_config.html"
        ).read_text(encoding="utf-8")
        self.assertIn('min="{{ field.minimum }}"', template)
        self.assertIn('max="{{ field.maximum }}"', template)
        self.assertIn('step="1"', template)
        self.assertIn('pattern="{{ field.pattern }}"', template)

    def test_admin_authelia_always_inherits_global_state(self) -> None:
        variables = dict(BASE_VARS)
        variables["authelia_enabled"] = False
        self.vars_path.write_text(
            yaml.safe_dump(variables, sort_keys=False), encoding="utf-8"
        )

        model = vars_service.get_vars_editor_model()
        fields = {
            field["path"]: field
            for section in model["sections"]
            for field in section["fields"]
        }
        self.assertFalse(fields["admin_authelia_enabled"]["value"])
        self.assertFalse(fields["admin_authelia_enabled"]["effective_value"])
        self.assertTrue(fields["admin_authelia_enabled"]["inherited"])
        self.assertTrue(fields["admin_authelia_enabled"]["readonly"])

        variables["authelia_enabled"] = True
        variables["admin_authelia_enabled"] = False
        variables["admin_allowed_ips"] = ["192.0.2.10", "198.51.100.0/24"]
        self.vars_path.write_text(
            yaml.safe_dump(variables, sort_keys=False), encoding="utf-8"
        )
        model = vars_service.get_vars_editor_model()
        fields = {
            field["path"]: field
            for section in model["sections"]
            for field in section["fields"]
        }
        self.assertTrue(fields["admin_authelia_enabled"]["value"])
        self.assertTrue(fields["admin_authelia_enabled"]["effective_value"])
        self.assertTrue(fields["admin_authelia_enabled"]["inherited"])
        self.assertTrue(fields["admin_authelia_enabled"]["readonly"])
        self.assertTrue(fields["admin_authelia_enabled"]["present"])
        self.assertEqual(fields["admin_ips_enabled"]["admin_ip_count"], 2)

    def test_hsts_default_legacy_normalization_and_explicit_disable(self) -> None:
        variables = dict(BASE_VARS)
        variables["site_defaults"] = dict(BASE_VARS["site_defaults"])
        variables["site_defaults"]["hsts"] = "365d"
        self.vars_path.write_text(
            yaml.safe_dump(variables, sort_keys=False), encoding="utf-8"
        )

        model = vars_service.get_vars_editor_model()
        fields = {
            field["path"]: field
            for section in model["sections"]
            for field in section["fields"]
        }
        self.assertEqual(fields["site_defaults.hsts"]["value"], 31_536_000)

        migrated = vars_service.save_guided_vars(
            {"site_defaults.hsts": fields["site_defaults.hsts"]["value"]},
            self.revision(),
        )
        self.assertTrue(migrated["ok"], migrated)
        saved = yaml.safe_load(self.vars_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["site_defaults"]["hsts"], 31_536_000)

        disabled = vars_service.save_guided_vars(
            {"site_defaults.hsts": 0}, self.revision()
        )
        self.assertTrue(disabled["ok"], disabled)
        saved = yaml.safe_load(self.vars_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["site_defaults"]["hsts"], 0)

    def test_blank_hsts_uses_safe_default_instead_of_validation_error(self) -> None:
        result = vars_service.save_guided_vars(
            {"site_defaults.hsts": None}, self.revision()
        )

        self.assertTrue(result["ok"], result)
        saved = yaml.safe_load(self.vars_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["site_defaults"]["hsts"], 15_552_000)

    def test_admin_allowlist_is_normalized_and_prevents_current_client_lockout(self) -> None:
        saved_list = vars_service.save_guided_vars(
            {
                "admin_allowed_ips": (
                    "192.0.2.25\n198.51.100.42/24\n192.0.2.25"
                )
            },
            self.revision(),
            client_ip="192.0.2.25",
        )
        self.assertTrue(saved_list["ok"], saved_list)
        saved = yaml.safe_load(self.vars_path.read_text(encoding="utf-8"))
        self.assertEqual(
            saved["admin_allowed_ips"],
            ["192.0.2.25", "198.51.100.0/24"],
        )

        enabled = vars_service.save_guided_vars(
            {"admin_ips_enabled": True},
            self.revision(),
            client_ip="192.0.2.25",
        )
        self.assertTrue(enabled["ok"], enabled)

        lockout = vars_service.save_guided_vars(
            {"admin_allowed_ips": ["198.51.100.0/24"]},
            self.revision(),
            client_ip="192.0.2.25",
        )
        self.assertFalse(lockout["ok"])
        self.assertIn("current connection IP", lockout["error"])
        self.assertIn("admin_allowed_ips", lockout["field_errors"])

        invalid = vars_service.save_guided_vars(
            {"admin_allowed_ips": ["not-an-ip"]},
            self.revision(),
            client_ip="192.0.2.25",
        )
        self.assertFalse(invalid["ok"])
        self.assertIn("invalid IP/network", invalid["error"])

    def test_site_editor_preserves_explicit_hsts_disable(self) -> None:
        template = (
            PACKAGE_ROOT / "templates" / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        javascript = (
            PACKAGE_ROOT / "static" / "js" / "haproxy_site_edit.js"
        ).read_text(encoding="utf-8")

        self.assertIn("site.hsts is defined and site.hsts is not none", template)
        self.assertIn("{% else %}15552000{% endif %}", template)
        self.assertIn('site.hsts = Number.parseInt(normalizedHsts, 10)', javascript)
        self.assertIn('normalizedHsts === "true"', javascript)
        self.assertIn('normalizedHsts === "false"', javascript)

    def test_guided_save_preserves_unknown_and_read_only_values(self) -> None:
        result = vars_service.save_guided_vars(
            {
                "enable_http80": False,
                "geoip_mode": "deny",
                "site_defaults.balance": "leastconn",
                "site_defaults.backend_port": 8443,
            },
            self.revision(),
        )

        self.assertTrue(result["ok"], result)
        self.assertIn("vars_yaml", result)
        saved = yaml.safe_load(self.vars_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["root_domain"], "example.test")
        self.assertEqual(saved["future_unknown_setting"], {"preserve": True})
        self.assertFalse(saved["enable_http80"])
        self.assertEqual(saved["geoip_mode"], "deny")
        self.assertEqual(saved["site_defaults"]["balance"], "leastconn")
        self.assertEqual(saved["site_defaults"]["backend_port"], 8443)

    def test_read_only_unknown_and_invalid_values_are_rejected(self) -> None:
        for values, expected in (
            ({"root_domain": "attacker.test"}, "read-only"),
            ({"site_defaults.balance": "unsupported"}, "unsupported value"),
            ({"site_defaults.backend_port": 70000}, "maximum value"),
            ({"site_defaults.rate_window": "forever"}, "use a value"),
        ):
            with self.subTest(values=values):
                result = vars_service.save_guided_vars(values, self.revision())
                self.assertFalse(result["ok"])
                self.assertIn(expected, result["error"])

    def test_stale_revision_cannot_overwrite_a_newer_file(self) -> None:
        stale = self.revision()
        self.vars_path.write_text(
            self.vars_path.read_text(encoding="utf-8") + "new_key: true\n",
            encoding="utf-8",
        )
        result = vars_service.save_guided_vars(
            {"enable_http80": False}, stale
        )
        self.assertFalse(result["ok"])
        self.assertTrue(result["conflict"])
        self.assertIn("new_key: true", self.vars_path.read_text(encoding="utf-8"))

    def test_pending_confirmation_blocks_both_editor_modes(self) -> None:
        with mock.patch.object(
            vars_service,
            "config_transaction_is_pending",
            return_value=(True, "confirmation pending"),
        ):
            guided = vars_service.save_guided_vars(
                {"enable_http80": False}, self.revision()
            )
            raw = vars_service.save_raw_vars(
                self.vars_path.read_text(encoding="utf-8"), self.revision()
            )
        self.assertTrue(guided["pending"])
        self.assertTrue(raw["pending"])
        self.assertIn("confirmation pending", guided["error"])

    def test_raw_editor_validates_yaml_and_root_type(self) -> None:
        malformed = vars_service.save_raw_vars("root: [\n", self.revision())
        self.assertFalse(malformed["ok"])
        self.assertIn("not valid YAML", malformed["error"])

        sequence = vars_service.save_raw_vars("- one\n- two\n", self.revision())
        self.assertFalse(sequence["ok"])
        self.assertIn("root must be a mapping", sequence["error"])

    def test_saved_vars_refresh_local_and_global_pending_indicators(self) -> None:
        template = (
            PACKAGE_ROOT / "templates" / "haproxy_config.html"
        ).read_text(encoding="utf-8")
        javascript = (
            PACKAGE_ROOT / "static" / "js" / "haproxy_config.js"
        ).read_text(encoding="utf-8")

        self.assertIn('id="config-server-status"', template)
        self.assertIn('id="config-pending-status"', template)
        self.assertIn('id="config-change-details"', template)
        self.assertIn('id="config-change-list"', template)
        self.assertIn("source_has_changes", template)
        self.assertIn('requestJson("/haproxy/config/diff"', javascript)
        self.assertGreaterEqual(
            javascript.count("await refreshConfigurationSummary()"), 3
        )
        self.assertIn(
            'new CustomEvent("easy-ha-proxy:config-state-changed")', javascript
        )

    def test_unsaved_guided_settings_are_saved_before_validation(self) -> None:
        template = (
            PACKAGE_ROOT / "templates" / "haproxy_config.html"
        ).read_text(encoding="utf-8")
        javascript = (
            PACKAGE_ROOT / "static" / "js" / "haproxy_config.js"
        ).read_text(encoding="utf-8")

        self.assertIn('id="vars-unsaved-notice"', template)
        self.assertIn("function guidedHasUnsavedChanges()", javascript)
        self.assertIn(
            "async function savePendingGuidedSettingsBeforeValidation()",
            javascript,
        )
        check_block = javascript.split(
            "async function checkConfig(options) {", 1
        )[1].split("async function revertConfig() {", 1)[0]
        self.assertIn(
            "await savePendingGuidedSettingsBeforeValidation()", check_block
        )
        self.assertLess(
            check_block.index("await savePendingGuidedSettingsBeforeValidation()"),
            check_block.index('requestJson("/haproxy/config/check"'),
        )
        self.assertIn("const saved = await saveGuidedVars(null);", javascript)
        self.assertIn(
            "The advanced YAML editor has unsaved changes.", javascript
        )

    def test_geoip_mode_controls_match_the_global_template_contract(self) -> None:
        editor = (
            PACKAGE_ROOT / "templates" / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        sites = (
            PACKAGE_ROOT / "templates" / "haproxy_sites.html"
        ).read_text(encoding="utf-8")
        javascript = (
            PACKAGE_ROOT / "static" / "js" / "haproxy_site_edit.js"
        ).read_text(encoding="utf-8")

        self.assertNotIn('id="geo_mode"', editor)
        self.assertNotIn('getElementById("geo_mode")', javascript)
        self.assertIn("config_vars.geoip_mode|default('allow')", sites)
        self.assertNotIn("eff.geo_mode", sites)
        self.assertNotIn("site_defaults.geo_mode", sites)
        self.assertIn('id="geo_countries"', editor)
        self.assertIn('text("geo_countries")', javascript)
        self.assertIn("site.geo_countries = geoCountries", javascript)
        self.assertIn("delete site.geo_countries", javascript)


class SiteGeoIPSaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.vars_path = root / "vars.yml"
        self.websites_path = root / "websites.yml"
        self.vars_path.write_text(
            "geoip_country_codes: [PL, DE]\n", encoding="utf-8"
        )
        self.websites_path.write_text(
            "sites:\n"
            "  - name: app\n"
            "    domain: app.example.test\n"
            "    backend_ip: 127.0.0.1\n"
            "    backend_port: 8080\n",
            encoding="utf-8",
        )
        patches = (
            mock.patch.object(sites_service, "CONFIG_YAML", self.vars_path),
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites_path),
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites_path),
            mock.patch.object(
                config_service,
                "config_transaction_is_pending",
                return_value=(False, ""),
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def site_payload(geo_countries):
        return {
            "name": "app",
            "domain": "app.example.test",
            "backend_ip": "127.0.0.1",
            "backend_port": 8080,
            "geo_countries": geo_countries,
        }

    def test_site_country_override_is_normalized_and_deduplicated(self) -> None:
        ok, message = sites_service.save_site_from_json(
            self.site_payload(["pl", "DE", "PL"]), original_name="app"
        )
        self.assertTrue(ok, message)
        saved = yaml.safe_load(self.websites_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["sites"][0]["geo_countries"], ["DE", "PL"])

    def test_site_country_override_must_be_globally_selected(self) -> None:
        before = self.websites_path.read_bytes()
        ok, message = sites_service.save_site_from_json(
            self.site_payload(["US"]), original_name="app"
        )
        self.assertFalse(ok)
        self.assertIn("global GeoIP page first: US", message)
        self.assertEqual(self.websites_path.read_bytes(), before)


class AppliedStateTests(unittest.TestCase):
    def test_current_spec_supports_canonical_tcp_proxies_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sites = root / "websites.yml"
            tcp = root / "tcp.yml"
            variables = root / "vars.yml"
            sites.write_text("sites: []\n", encoding="utf-8")
            tcp.write_text(
                "tcp_proxies:\n  - name: ssh\n    bind_port: 2222\n",
                encoding="utf-8",
            )
            variables.write_text("enable_http80: true\n", encoding="utf-8")
            with (
                mock.patch.object(config_service, "WEBSITES_YAML", sites),
                mock.patch.object(config_service, "TCP_YAML", tcp),
                mock.patch.object(config_service, "CONFIG_YAML", variables),
            ):
                spec = config_service._get_current_spec()
        self.assertEqual(spec["tcp"][0]["name"], "ssh")

    def test_baseline_is_seeded_only_when_render_matches_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "haproxy.cfg"
            state = root / "state.json"
            active.write_text("active\n", encoding="utf-8")
            with (
                mock.patch.object(config_service, "HAPROXY_CFG_PATH", active),
                mock.patch.object(config_service, "HAPROXY_STATE_PATH", state),
                mock.patch.object(config_service, "save_applied_state_strict") as save,
            ):
                self.assertFalse(config_service.ensure_applied_state_baseline("other\n"))
                save.assert_not_called()
                self.assertTrue(config_service.ensure_applied_state_baseline("active\n"))
                save.assert_called_once_with("active\n")

    def test_baseline_does_not_accept_semantic_source_only_geoip_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "haproxy.cfg"
            sites = root / "websites.yml"
            tcp = root / "tcp.yml"
            variables = root / "vars.yml"
            active.write_text("same render\n", encoding="utf-8")
            sites.write_text("sites: []\n", encoding="utf-8")
            tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
            variables.write_text("enable_geoip: true\n", encoding="utf-8")
            previous_state = {
                "sites": [],
                "tcp": [],
                "config_vars": {"enable_geoip": False},
                "source_sha256": {},
            }
            with (
                mock.patch.object(config_service, "HAPROXY_CFG_PATH", active),
                mock.patch.object(config_service, "WEBSITES_YAML", sites),
                mock.patch.object(config_service, "TCP_YAML", tcp),
                mock.patch.object(config_service, "CONFIG_YAML", variables),
                mock.patch.object(
                    config_service, "_load_applied_state", return_value=previous_state
                ),
                mock.patch.object(config_service, "save_applied_state_strict") as save,
            ):
                reconciled = config_service.ensure_applied_state_baseline(
                    "same render\n"
                )

        self.assertFalse(reconciled)
        save.assert_not_called()

    def test_baseline_reconciles_formatting_only_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "haproxy.cfg"
            sites = root / "websites.yml"
            tcp = root / "tcp.yml"
            variables = root / "vars.yml"
            active.write_text("same render\n", encoding="utf-8")
            sites.write_text("sites: []\n", encoding="utf-8")
            tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
            # The bytes differ from the stored source hash, while the parsed
            # configuration remains identical to the confirmed state.
            variables.write_text("enable_geoip: true  # enabled\n", encoding="utf-8")
            previous_state = {
                "sites": [],
                "tcp": [],
                "config_vars": {"enable_geoip": True},
                "source_sha256": {},
            }
            with (
                mock.patch.object(config_service, "HAPROXY_CFG_PATH", active),
                mock.patch.object(config_service, "WEBSITES_YAML", sites),
                mock.patch.object(config_service, "TCP_YAML", tcp),
                mock.patch.object(config_service, "CONFIG_YAML", variables),
                mock.patch.object(
                    config_service, "_load_applied_state", return_value=previous_state
                ),
                mock.patch.object(config_service, "save_applied_state_strict") as save,
            ):
                reconciled = config_service.ensure_applied_state_baseline(
                    "same render\n"
                )

        self.assertTrue(reconciled)
        save.assert_called_once_with("same render\n")

    def test_baseline_never_reconciles_while_confirmation_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            active = root / "haproxy.cfg"
            sites = root / "websites.yml"
            tcp = root / "tcp.yml"
            variables = root / "vars.yml"
            active.write_text("candidate render\n", encoding="utf-8")
            sites.write_text("sites: []\n", encoding="utf-8")
            tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
            variables.write_text(
                "enable_geoip: true  # formatting-only candidate edit\n",
                encoding="utf-8",
            )
            previous_state = {
                "sites": [],
                "tcp": [],
                "config_vars": {"enable_geoip": True},
                "source_sha256": {},
            }
            with (
                mock.patch.object(config_service, "HAPROXY_CFG_PATH", active),
                mock.patch.object(config_service, "WEBSITES_YAML", sites),
                mock.patch.object(config_service, "TCP_YAML", tcp),
                mock.patch.object(config_service, "CONFIG_YAML", variables),
                mock.patch.object(
                    config_service, "_load_applied_state", return_value=previous_state
                ),
                mock.patch.object(
                    config_service,
                    "config_transaction_is_pending",
                    return_value=(True, "confirmation pending"),
                ) as pending_check,
                mock.patch.object(config_service, "save_applied_state_strict") as save,
            ):
                reconciled = config_service.ensure_applied_state_baseline(
                    "candidate render\n"
                )

        self.assertFalse(reconciled)
        pending_check.assert_called_once_with()
        save.assert_not_called()

    def test_diff_separates_source_changes_from_live_server_drift(self) -> None:
        confirmed = {
            "sites": [],
            "tcp": [],
            "config_vars": {"enable_geoip": False},
        }
        current = {
            "sites": [],
            "tcp": [],
            "config_vars": {"enable_geoip": True},
        }
        with (
            mock.patch.object(config_service, "_read_file_text", return_value="same\n"),
            mock.patch.object(config_service, "_load_applied_state", return_value=confirmed),
            mock.patch.object(config_service, "_get_current_spec", return_value=current),
        ):
            source_only = config_service.get_config_diff_summary("same\n")

        self.assertFalse(source_only["server_differs"])
        self.assertTrue(source_only["source_has_changes"])
        self.assertTrue(source_only["has_changes"])
        self.assertEqual(source_only["global_changed_keys"], ["enable_geoip"])

        with (
            mock.patch.object(config_service, "_read_file_text", return_value="external\n"),
            mock.patch.object(config_service, "_load_applied_state", return_value=confirmed),
            mock.patch.object(config_service, "_get_current_spec", return_value=confirmed),
        ):
            server_only = config_service.get_config_diff_summary("rendered\n")

        self.assertTrue(server_only["server_differs"])
        self.assertFalse(server_only["source_has_changes"])
        self.assertTrue(server_only["has_changes"])

    def test_generation_header_only_does_not_create_runtime_drift(self) -> None:
        confirmed = {
            "sites": [],
            "tcp": [],
            "config_vars": {"enable_geoip": False},
        }
        prefix = (
            "frontend fe_https\n"
            "    http-request set-header "
            "X-Easy-HAProxy-Config-Generation "
        )
        suffix = " if host_admin\n    default_backend be_admin\n"
        active = prefix + ("a" * 64) + suffix
        rendered = prefix + ("b" * 64) + suffix
        with (
            mock.patch.object(config_service, "_read_file_text", return_value=active),
            mock.patch.object(config_service, "_load_applied_state", return_value=confirmed),
            mock.patch.object(config_service, "_get_current_spec", return_value=confirmed),
        ):
            result = config_service.get_config_diff_summary(rendered)

        self.assertFalse(result["server_differs"])
        self.assertFalse(result["source_has_changes"])
        self.assertFalse(result["has_changes"])
        html = config_service.make_cfg_html_diff(active, rendered)
        self.assertNotIn("a" * 64, html)
        self.assertNotIn("b" * 64, html)

    def test_generation_header_condition_change_remains_runtime_drift(self) -> None:
        confirmed = {"sites": [], "tcp": [], "config_vars": {}}
        active = (
            "    http-request set-header X-Easy-HAProxy-Config-Generation "
            + ("a" * 64)
            + " if host_admin\n"
        )
        rendered = (
            "    http-request set-header X-Easy-HAProxy-Config-Generation "
            + ("b" * 64)
            + " if host_authelia\n"
        )
        with (
            mock.patch.object(config_service, "_read_file_text", return_value=active),
            mock.patch.object(config_service, "_load_applied_state", return_value=confirmed),
            mock.patch.object(config_service, "_get_current_spec", return_value=confirmed),
        ):
            result = config_service.get_config_diff_summary(rendered)

        self.assertTrue(result["server_differs"])
        self.assertTrue(result["has_changes"])

    def test_apply_preflight_rejects_candidate_source_race(self) -> None:
        bundle = {
            "vars.yml": b"maxconn: 200\n",
            "websites.yml": b"sites: []\n",
            "tcp.yml": b"tcp_proxies: []\n",
        }
        with (
            mock.patch.object(
                config_service,
                "_read_config_source_bundle",
                return_value=bundle,
            ),
            mock.patch.object(
                config_service,
                "_render_haproxy_cfg_from_source_bundle",
                return_value="newer render\n",
            ),
            mock.patch.object(
                config_service, "_reconcile_applied_state_for_candidate"
            ) as reconcile,
        ):
            result = config_service.preflight_cfg_confirmation("older render\n")
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["error_code"], "haproxy_config_sources_changed"
        )
        reconcile.assert_not_called()

    def test_baseline_edit_validate_and_begin_apply_reconciles_legacy_hash(self) -> None:
        """Editing vars must not invalidate the still-running safe baseline."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_dir = root / "config"
            backup_dir = root / "backups"
            template_dir = root / "templates"
            config_dir.mkdir()
            backup_dir.mkdir()
            template_dir.mkdir()

            variables = config_dir / "vars.yml"
            websites = config_dir / "websites.yml"
            tcp = config_dir / "tcp.yml"
            active = root / "haproxy.cfg"
            state = backup_dir / "last_applied_state.json"
            state_vars = backup_dir / "last_applied_vars.yml"
            state_websites = backup_dir / "last_applied_websites.yml"
            state_tcp = backup_dir / "last_applied_tcp.yml"
            pending_marker = backup_dir / "pending.json"
            template = template_dir / "haproxy.cfg.j2"

            variables.write_text("maxconn: 100\n", encoding="utf-8")
            websites.write_text("sites: []\n", encoding="utf-8")
            tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
            template.write_text(
                "global\n    maxconn {{ maxconn }}\n",
                encoding="utf-8",
            )
            environment = Environment(
                loader=FileSystemLoader(str(template_dir)),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            captured: dict[str, str] = {}

            def fake_control_request(command: str, **_kwargs):
                captured["command"] = command
                return {
                    "ok": True,
                    "state": "pending_confirmation",
                    "transaction_id": "safe-transaction-id-1234",
                    "candidate_sha256": "a" * 64,
                    "confirm_by": 9999999999,
                }

            with (
                mock.patch.object(config_service, "CONFIG_YAML", variables),
                mock.patch.object(config_service, "WEBSITES_YAML", websites),
                mock.patch.object(config_service, "TCP_YAML", tcp),
                mock.patch.object(config_service, "HAPROXY_CFG_PATH", active),
                mock.patch.object(config_service, "HAPROXY_STATE_PATH", state),
                mock.patch.object(config_service, "HAPROXY_STATE_VARS", state_vars),
                mock.patch.object(
                    config_service, "HAPROXY_STATE_WEBSITES", state_websites
                ),
                mock.patch.object(config_service, "HAPROXY_STATE_TCP", state_tcp),
                mock.patch.object(
                    config_service,
                    "HAPROXY_PENDING_TRANSACTION_PATH",
                    pending_marker,
                ),
                mock.patch.object(config_service, "HAP_TEMPLATE", template),
                mock.patch.object(config_service, "JINJA_ENV", environment),
                mock.patch.object(
                    config_service, "check_cfg", return_value=(0, "valid", "")
                ),
                mock.patch.object(
                    config_service,
                    "_critical_control_plane_checks",
                    return_value=[
                        {"service": "admin", "domain": "ha.example.test"},
                        {"service": "authelia", "domain": "aut.example.test"},
                    ],
                ),
                mock.patch.object(
                    config_service,
                    "_controld_json_request",
                    side_effect=fake_control_request,
                ),
            ):
                previous_cfg = config_service.render_haproxy_cfg()
                active.write_text(previous_cfg, encoding="utf-8")
                config_service.save_applied_state_strict(previous_cfg)

                # Simulate metadata written by an older release, then make a
                # legitimate vars.yml edit while HAProxy still runs baseline.
                legacy_state = json.loads(state.read_text(encoding="utf-8"))
                legacy_state["haproxy_cfg_sha256"] = "0" * 64
                legacy_state.pop("source_sha256", None)
                state.write_text(json.dumps(legacy_state), encoding="utf-8")
                variables.write_text("maxconn: 200\n", encoding="utf-8")
                candidate_cfg = config_service.render_haproxy_cfg()

                result = config_service.begin_cfg_confirmation(candidate_cfg)

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["baseline_reconciled"])
            self.assertEqual(result["baseline_source"], "saved_render")
            parts = captured["command"].split()
            source_payload = json.loads(
                base64.b64decode(parts[3], validate=True).decode("utf-8")
            )
            candidate_vars = base64.b64decode(
                source_payload["candidate"]["vars.yml"], validate=True
            )
            previous_vars = base64.b64decode(
                source_payload["previous"]["vars.yml"], validate=True
            )
            self.assertEqual(candidate_vars, b"maxconn: 200\n")
            self.assertEqual(previous_vars, b"maxconn: 100\n")
            self.assertEqual(
                source_payload["geoip_selection"],
                {
                    "version": 1,
                    "countries": [],
                    "access_filter_enabled": False,
                },
            )
            pending_state = json.loads(pending_marker.read_text(encoding="utf-8"))
            self.assertEqual(
                pending_state["config_generation"],
                config_service.config_source_generation(
                    {
                        name: base64.b64decode(encoded, validate=True)
                        for name, encoded in source_payload["candidate"].items()
                    }
                ),
            )
            reconciled_state = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(
                reconciled_state["haproxy_cfg_sha256"],
                hashlib.sha256(previous_cfg.encode("utf-8")).hexdigest(),
            )
            self.assertIn("source_sha256", reconciled_state)

    def test_unknown_active_config_drift_remains_blocked_with_stable_code(self) -> None:
        bundle = {
            "vars.yml": b"maxconn: 100\n",
            "websites.yml": b"sites: []\n",
            "tcp.yml": b"tcp_proxies: []\n",
        }
        state = {
            "haproxy_cfg_sha256": "0" * 64,
            "sites": [],
            "tcp": [],
            "config_vars": {"maxconn": 100},
        }
        with (
            mock.patch.object(
                config_service, "_read_file_text", return_value="unknown drift\n"
            ),
            mock.patch.object(config_service, "_load_applied_state", return_value=state),
            mock.patch.object(
                config_service,
                "_render_haproxy_cfg_from_source_bundle",
                side_effect=["saved render\n", "candidate render\n"],
            ),
        ):
            with self.assertRaises(config_service.ConfigApplyPreparationError) as raised:
                config_service._reconcile_applied_state_for_candidate(
                    "candidate render\n", bundle, bundle
                )
        self.assertEqual(
            raised.exception.error_code,
            "haproxy_config_unknown_drift",
        )
        self.assertTrue(
            raised.exception.details["external_drift_confirmation_required"]
        )
        active_hash = hashlib.sha256(b"unknown drift\n").hexdigest()
        self.assertEqual(
            raised.exception.details["active_cfg_sha256"], active_hash
        )

        with (
            mock.patch.object(
                config_service, "_read_file_text", return_value="unknown drift\n"
            ),
            mock.patch.object(config_service, "_load_applied_state", return_value=state),
            mock.patch.object(
                config_service,
                "_render_haproxy_cfg_from_source_bundle",
                side_effect=["saved render\n", "candidate render\n"],
            ),
        ):
            rollback_bundle, source = (
                config_service._reconcile_applied_state_for_candidate(
                    "candidate render\n",
                    bundle,
                    bundle,
                    allow_external_drift=True,
                    expected_active_sha256=active_hash,
                )
            )
        self.assertEqual(source, "external_drift_override")
        self.assertEqual(rollback_bundle, bundle)

        with (
            mock.patch.object(
                config_service, "_read_file_text", return_value="changed again\n"
            ),
            mock.patch.object(config_service, "_load_applied_state", return_value=state),
            mock.patch.object(
                config_service,
                "_render_haproxy_cfg_from_source_bundle",
                side_effect=["saved render\n", "candidate render\n"],
            ),
        ):
            with self.assertRaises(
                config_service.ConfigApplyPreparationError
            ) as changed:
                config_service._reconcile_applied_state_for_candidate(
                    "candidate render\n",
                    bundle,
                    bundle,
                    allow_external_drift=True,
                    expected_active_sha256=active_hash,
                )
        self.assertNotEqual(
            changed.exception.details["active_cfg_sha256"], active_hash
        )

        with (
            mock.patch.object(
                config_service, "check_cfg", return_value=(0, "valid", "")
            ),
            mock.patch.object(
                config_service,
                "_critical_control_plane_checks",
                return_value=[],
            ),
            mock.patch.object(
                config_service,
                "_config_source_payload",
                return_value=(
                    {"candidate": {}, "previous": {}},
                    "external_drift_override",
                ),
            ),
            mock.patch.object(
                config_service,
                "_read_file_text",
                return_value="changed before root transaction\n",
            ),
            mock.patch.object(config_service, "_controld_json_request") as control,
        ):
            changed_before_root = config_service.begin_cfg_confirmation(
                "candidate render\n",
                allow_external_drift=True,
                expected_active_sha256=active_hash,
            )
        self.assertFalse(changed_before_root["ok"])
        self.assertTrue(
            changed_before_root["external_drift_confirmation_required"]
        )
        control.assert_not_called()

        with (
            mock.patch.object(
                config_service, "check_cfg", return_value=(0, "valid", "")
            ),
            mock.patch.object(
                config_service,
                "_critical_control_plane_checks",
                return_value=[],
            ),
            mock.patch.object(
                config_service,
                "_config_source_payload",
                side_effect=config_service.ConfigApplyPreparationError(
                    "HAProxy configuration drift requires reconciliation.",
                    error_code="haproxy_config_unknown_drift",
                ),
            ),
        ):
            result = config_service.begin_cfg_confirmation("candidate render\n")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "haproxy_config_unknown_drift")

    def test_routes_use_confirmation_before_advancing_applied_state(self) -> None:
        source = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py"
        ).read_text(encoding="utf-8")
        apply_block = source.split(
            'def haproxy_config_apply():', 1
        )[1].split('@bp.get("/haproxy/config/apply-status")', 1)[0]

        self.assertIn("begin_cfg_confirmation(", apply_block)
        self.assertIn("preflight_cfg_confirmation(", apply_block)
        self.assertIn("allow_external_drift=allow_external_drift", apply_block)
        self.assertIn("expected_active_sha256=expected_active_sha256", apply_block)
        self.assertLess(
            apply_block.index("preflight_cfg_confirmation("),
            apply_block.index("ensure_certs_before_apply()"),
        )
        self.assertNotIn("save_applied_state", apply_block)
        self.assertIn('@bp.post("/haproxy/config/confirm")', source)
        self.assertIn("save_applied_state_strict(cfg_text)", source)
        self.assertIn('@bp.post("/haproxy/config/vars")', source)
        self.assertIn('@bp.post("/haproxy/config/vars/raw")', source)


class AnsibleRuntimeSourceTests(unittest.TestCase):
    def test_config_generation_uses_exact_source_bytes_and_matches_ansible_framing(self) -> None:
        bundle = {
            "vars.yml": "name: café\r\n".encode("utf-8"),
            "websites.yml": b"sites: []\n\n",
            "tcp.yml": b"tcp_proxies: []\n",
        }
        framed = (
            "easy-ha-proxy-config-generation-v1|"
            + "|".join(
                f"{name}:{base64.b64encode(bundle[name]).decode('ascii')}"
                for name in ("vars.yml", "websites.yml", "tcp.yml")
            )
        )
        expected = hashlib.sha256(framed.encode("ascii")).hexdigest()

        generation = config_service.config_source_generation(bundle)

        self.assertEqual(generation, expected)
        self.assertRegex(generation, r"^[0-9a-f]{64}$")
        semantically_equal = dict(bundle)
        semantically_equal["websites.yml"] = b"sites: [ ]\n"
        self.assertNotEqual(
            generation,
            config_service.config_source_generation(semantically_equal),
        )

    def test_config_geoip_selection_is_canonical_and_fail_closed(self) -> None:
        bundle = {
            "vars.yml": (
                b"enable_geoip: true\n"
                b"geoip_country_codes: [ru, PL, RU]\n"
            ),
            "websites.yml": b"sites: []\n",
            "tcp.yml": b"tcp_proxies: []\n",
        }
        self.assertEqual(
            config_service.config_geoip_selection(bundle),
            {
                "version": 1,
                "countries": ["PL", "RU"],
                "access_filter_enabled": True,
            },
        )
        bundle["websites.yml"] = (
            b"sites:\n"
            b"  - name: app\n"
            b"    domain: app.example.test\n"
            b"    geo_countries: [PL]\n"
        )
        self.assertEqual(
            config_service.config_geoip_selection(bundle)["countries"],
            ["PL", "RU"],
        )
        bundle["websites.yml"] = (
            b"sites:\n"
            b"  - name: app\n"
            b"    domain: app.example.test\n"
            b"    geo_countries: [DE]\n"
        )
        with self.assertRaisesRegex(ValueError, "not selected globally: DE"):
            config_service.config_geoip_selection(bundle)

        with self.assertRaisesRegex(ValueError, "uppercase ISO alpha-2"):
            validation.validate_config_data(
                "websites",
                {
                    "sites": [
                        {
                            "name": "app",
                            "domain": "app.example.test",
                            "geo_countries": ["pl"],
                        }
                    ]
                },
            )

        bundle["websites.yml"] = b"sites: []\n"
        bundle["vars.yml"] = b"enable_geoip: true\ngeoip_country_codes: []\n"
        with self.assertRaisesRegex(ValueError, "Select at least one"):
            config_service.config_geoip_selection(bundle)

    def test_config_admin_allowlist_is_canonical_and_optional(self) -> None:
        bundle = {
            "vars.yml": (
                b"admin_allowed_ips:\n"
                b"  - 192.0.2.10\n"
                b"  - 198.51.100.42/24\n"
                b"  - 192.0.2.10\n"
            ),
            "websites.yml": b"sites: []\n",
            "tcp.yml": b"tcp_proxies: []\n",
        }
        self.assertEqual(
            config_service.config_admin_allowlist(bundle),
            ["192.0.2.10", "198.51.100.0/24"],
        )
        bundle["vars.yml"] = b"admin_ips_enabled: false\n"
        self.assertIsNone(config_service.config_admin_allowlist(bundle))
        bundle["vars.yml"] = b"admin_allowed_ips: [invalid]\n"
        with self.assertRaisesRegex(ValueError, "Invalid admin_allowed_ips"):
            config_service.config_admin_allowlist(bundle)

    def test_pending_marker_keeps_generation_private_and_requires_exact_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "pending.json"
            transaction_id = "transaction-generation-1234"
            generation = "b" * 64
            with mock.patch.object(
                config_service, "HAPROXY_PENDING_TRANSACTION_PATH", marker
            ):
                config_service._write_pending_transaction_marker(
                    {
                        "transaction_id": transaction_id,
                        "candidate_sha256": "a" * 64,
                        "confirm_by": "2099-01-01T00:00:00Z",
                    },
                    generation,
                )
                persisted = json.loads(marker.read_text(encoding="utf-8"))
                self.assertEqual(persisted["config_generation"], generation)
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                self.assertTrue(
                    config_service.candidate_request_reachable(
                        transaction_id, generation.upper()
                    )
                )
                self.assertFalse(
                    config_service.candidate_request_reachable(
                        transaction_id, "c" * 64
                    )
                )
                self.assertFalse(
                    config_service.candidate_request_reachable(
                        "different-transaction-1234", generation
                    )
                )
                with mock.patch.object(
                    config_service,
                    "_controld_json_request",
                    return_value={
                        "ok": True,
                        "state": "pending_confirmation",
                        "transaction_id": transaction_id,
                    },
                ):
                    public_status = config_service.get_config_transaction_status(
                        transaction_id
                    )
                self.assertNotIn("config_generation", public_status)
                self.assertNotIn(generation, json.dumps(public_status))

    def test_routes_require_candidate_generation_before_root_confirmation(self) -> None:
        source = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py"
        ).read_text(encoding="utf-8")
        status_block = source.split(
            "def haproxy_config_apply_status():", 1
        )[1].split('@bp.post("/haproxy/config/confirm")', 1)[0]
        confirm_block = source.split(
            "def haproxy_config_confirm():", 1
        )[1].split('@bp.post("/haproxy/config/rollback-pending")', 1)[0]

        self.assertIn('result["candidate_reachable"]', status_block)
        self.assertIn("request.headers.get(CONFIG_GENERATION_HEADER", status_block)
        self.assertIn("candidate_request_reachable(", confirm_block)
        self.assertIn('"retryable": True', confirm_block)
        self.assertIn('"candidate_reachable": False', confirm_block)
        self.assertLess(
            confirm_block.index("candidate_request_reachable("),
            confirm_block.index("confirm_cfg_transaction("),
        )
        self.assertNotIn('"config_generation"', status_block)

    def test_template_and_ansible_share_generation_and_strip_spoofed_header(self) -> None:
        tasks = (
            ROOT / "ansible/roles/haproxy/tasks/config.yml"
        ).read_text(encoding="utf-8")
        template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        routes = (ROOT / "docker/app/haproxy_admin/routes.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("easy-ha-proxy-config-generation-v1|", tasks)
        self.assertIn("haproxy_runtime_source_raw.results[0].content", tasks)
        self.assertIn("haproxy_managed_source_raw.results[0].content", tasks)
        self.assertIn("| hash('sha256')", tasks)
        delete_rule = "http-request del-header X-Easy-HAProxy-Config-Generation"
        set_rule = (
            "http-request set-header X-Easy-HAProxy-Config-Generation "
            "{{ config_generation }} if host_admin"
        )
        self.assertIn(delete_rule, template)
        self.assertIn(set_rule, template)
        self.assertLess(template.index(delete_rule), template.index(set_rule))
        self.assertIn('"x-easy-haproxy-config-generation"', routes)

    def test_browser_waits_for_candidate_generation_before_enabling_confirm(self) -> None:
        javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/haproxy_config.js"
        ).read_text(encoding="utf-8")

        self.assertIn("candidate_reachable: combined.candidate_reachable === true", javascript)
        self.assertIn("confirmButton.disabled = !reachable", javascript)
        self.assertIn("if (!pendingTransaction.candidate_reachable)", javascript)
        self.assertIn(
            "Waiting for a fresh connection through the candidate HAProxy configuration…",
            javascript,
        )

    def test_ansible_render_uses_runtime_sites_tcp_and_haproxy_allowlist(self) -> None:
        template = ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        environment = Environment(
            loader=FileSystemLoader(str(template.parent)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = config_service.jinja_regex_replace
        environment.filters["combine"] = config_service.jinja_combine
        managed_vars = {
            "admin_domain": "ha.managed.example.test",
            "aut_domain": "aut.managed.example.test",
            "authelia_enabled": True,
            "enable_http80": False,
            "haproxy_socket": "/run/haproxy/admin.sock",
            "haproxy_socket_group": "hadmin",
            "site_defaults": {},
        }
        runtime_vars = {
            # A legacy runtime override must not disable authentication for the
            # privileged administration control plane.
            "admin_authelia_enabled": False,
            "enable_http80": True,
            "enable_geoip": True,
            "haproxy_nbthread": 1,
            "site_defaults": {},
            # Installer-owned values in runtime vars.yml must never override
            # their managed counterparts during a root Ansible run.
            "admin_domain": "ha.runtime.example.test",
            "haproxy_admin_image": "example.invalid/admin:latest",
        }
        runtime_websites = {
            "sites": [
                {
                    "name": "runtime-site",
                    "domain": "runtime-site.example.test",
                    "backend_ip": "127.0.0.1",
                    "backend_port": 8080,
                }
            ]
        }
        runtime_tcp = {
            "tcp_proxies": [
                {
                    "name": "runtime-ssh",
                    "bind_port": 2222,
                    "backend_host": "127.0.0.1",
                    "backend_port": 22,
                }
            ]
        }
        context = dict(managed_vars)
        context.update(
            {
                "sites": [],
                "tcp_proxies": [],
                "easy_ha_proxy_runtime_vars": runtime_vars,
                "easy_ha_proxy_runtime_websites": runtime_websites,
                "easy_ha_proxy_runtime_tcp": runtime_tcp,
                "easy_ha_proxy_config_generation": "d" * 64,
            }
        )

        rendered = environment.get_template(template.name).render(**context)

        self.assertIn("frontend fe_http80", rendered)
        self.assertIn("runtime-site.example.test", rendered)
        self.assertIn("frontend fe_tcp_runtime_ssh", rendered)
        self.assertIn("ha.managed.example.test", rendered)
        self.assertIn(
            "acl authelia_protected hdr(host) -i ha.managed.example.test",
            rendered,
        )
        self.assertNotIn("ha.runtime.example.test", rendered)
        self.assertNotIn("example.invalid/admin:latest", rendered)
        self.assertIn(
            "http-request del-header X-Easy-HAProxy-Config-Generation",
            rendered,
        )
        self.assertIn(
            "http-request set-header X-Easy-HAProxy-Config-Generation "
            + ("d" * 64)
            + " if host_admin",
            rendered,
        )
        self.assertIn(
            'Strict-Transport-Security "max-age=15552000; includeSubDomains"',
            rendered,
        )

        geo_acl = next(
            line for line in rendered.splitlines()
            if "acl geo_filter_domains" in line
        )
        self.assertIn("runtime-site.example.test", geo_acl)
        self.assertNotIn("ha.managed.example.test", geo_acl)
        self.assertNotIn("aut.managed.example.test", geo_acl)
        global_geo_rule = next(
            line for line in rendered.splitlines()
            if "if geo_filter_domains !geo_allowed" in line
        )
        self.assertIn("!ip_auth_ok", global_geo_rule)

        runtime_websites["sites"][0]["geo_countries"] = ["PL", "RU"]
        per_site_geo = environment.get_template(template.name).render(**context)
        self.assertNotIn("acl geo_filter_domains", per_site_geo)
        self.assertIn(
            "acl geo_allowed_runtime_site src -f "
            "/etc/haproxy/geoip/current/PL.cidr",
            per_site_geo,
        )
        self.assertIn(
            "acl geo_allowed_runtime_site src -f "
            "/etc/haproxy/geoip/current/RU.cidr",
            per_site_geo,
        )
        per_site_rule = next(
            line for line in per_site_geo.splitlines()
            if "if host_runtime_site !geo_allowed_runtime_site" in line
        )
        self.assertIn("!ip_auth_ok", per_site_rule)
        runtime_websites["sites"][0].pop("geo_countries")

        runtime_vars["geoip_mode"] = "deny"
        # Legacy per-site values must not pretend to override the global rule.
        runtime_websites["sites"][0]["geo_mode"] = "allow"
        geo_deny = environment.get_template(template.name).render(**context)
        self.assertIn("if geo_filter_domains  geo_allowed", geo_deny)
        self.assertNotIn("if geo_filter_domains !geo_allowed", geo_deny)
        global_deny_rule = next(
            line for line in geo_deny.splitlines()
            if "if geo_filter_domains  geo_allowed" in line
        )
        self.assertIn("!ip_auth_ok", global_deny_rule)
        runtime_websites["sites"][0]["geo_countries"] = ["PL"]
        per_site_deny = environment.get_template(template.name).render(**context)
        per_site_deny_rule = next(
            line for line in per_site_deny.splitlines()
            if "if host_runtime_site  geo_allowed_runtime_site" in line
        )
        self.assertIn("!ip_auth_ok", per_site_deny_rule)
        runtime_websites["sites"][0].pop("geo_countries")
        runtime_vars.pop("geoip_mode")
        runtime_websites["sites"][0].pop("geo_mode")

        context["authelia_enabled"] = False
        without_authelia = environment.get_template(template.name).render(**context)
        unauthenticated_geo_rule = next(
            line for line in without_authelia.splitlines()
            if "if geo_filter_domains !geo_allowed" in line
        )
        self.assertNotIn("ip_auth_ok", unauthenticated_geo_rule)
        context["authelia_enabled"] = True

        runtime_vars["site_defaults"] = {"enable_geoip": False}
        geo_disabled_by_default = environment.get_template(template.name).render(
            **context
        )
        self.assertNotIn("acl geo_filter_domains", geo_disabled_by_default)
        self.assertIn(
            "acl geo_bypass hdr(host) -i runtime-site.example.test",
            geo_disabled_by_default,
        )

        runtime_websites["sites"][0]["geo"] = True
        geo_enabled_for_site = environment.get_template(template.name).render(
            **context
        )
        self.assertIn(
            "acl geo_filter_domains hdr(host) -i runtime-site.example.test",
            geo_enabled_for_site,
        )
        runtime_websites["sites"][0].pop("geo")

        runtime_vars["site_defaults"] = {"hsts": 0}
        hsts_disabled = environment.get_template(template.name).render(**context)
        self.assertNotIn("Strict-Transport-Security", hsts_disabled)

        runtime_vars["site_defaults"] = {"hsts": "365d"}
        legacy_hsts = environment.get_template(template.name).render(**context)
        self.assertIn(
            'Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            legacy_hsts,
        )

    def test_runtime_loader_is_namespaced_and_hardened(self) -> None:
        tasks = (
            ROOT / "ansible/roles/haproxy/tasks/config.yml"
        ).read_text(encoding="utf-8")
        template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("easy_ha_proxy_runtime_vars", tasks)
        self.assertIn("haproxy_runtime_source_count | int in [0, 3]", tasks)
        self.assertIn("not (item.stat.islnk | default(false))", tasks)
        self.assertIn("item.stat.size | int <= 2097152", tasks)
        self.assertIn("haproxy_admin_sync_managed_config", tasks)
        self.assertIn("runtime_vars.get('enable_http80'", template)
        self.assertIn("runtime_websites.get('sites'", template)
        self.assertIn("runtime_tcp.get('tcp_proxies'", template)
        self.assertNotIn("runtime_vars.get('admin_authelia_enabled'", template)
        self.assertIn("{% set admin_authelia_enabled = authelia_enabled %}", template)
        self.assertNotIn("runtime_vars.get('haproxy_admin_image'", template)
        self.assertNotIn("runtime_vars.get('admin_domain'", template)

    def test_intentional_managed_replacements_bypass_runtime_source(self) -> None:
        installer = (ROOT / "installer/easy_ha_proxy.py").read_text(
            encoding="utf-8"
        )
        install_block = installer.split("def command_install", 1)[1].split(
            "def command_plan", 1
        )[0]
        restore_block = installer.split("def command_apply_restored", 1)[1].split(
            "def command_configure", 1
        )[0]
        configure_block = installer.split("def command_configure", 1)[1].split(
            "def build_parser", 1
        )[0]

        self.assertIn("if args.reconfigure", install_block)
        self.assertIn(
            '"haproxy_admin_sync_managed_config": "true"', install_block
        )
        self.assertIn(
            '"haproxy_admin_sync_managed_config": "true"', restore_block
        )
        self.assertIn(
            '"haproxy_admin_sync_managed_config": "true"', configure_block
        )

    def test_ui_renderer_cannot_inject_the_ansible_runtime_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            template_dir = Path(temporary)
            template = template_dir / "haproxy.cfg.j2"
            template.write_text(
                "{% set runtime = easy_ha_proxy_runtime_vars | default({}) %}"
                "{{ runtime.get('marker', marker) }}\n",
                encoding="utf-8",
            )
            environment = Environment(loader=FileSystemLoader(str(template_dir)))
            with (
                mock.patch.object(config_service, "HAP_TEMPLATE", template),
                mock.patch.object(config_service, "JINJA_ENV", environment),
            ):
                rendered = config_service._render_haproxy_cfg_from_documents(
                    {"sites": []},
                    {"tcp_proxies": []},
                    {
                        "marker": "safe",
                        "easy_ha_proxy_runtime_vars": {"marker": "injected"},
                    },
                )

        self.assertEqual(rendered.strip(), "safe")

        javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/haproxy_config.js"
        ).read_text(encoding="utf-8")
        self.assertIn('error_code === "haproxy_config_unknown_drift"', javascript)
        self.assertIn("window.confirm", javascript)
        self.assertIn("active_cfg_sha256", javascript)


if __name__ == "__main__":
    unittest.main()
