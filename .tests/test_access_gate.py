"""Contract tests for the zero-trust access-gate site type."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app"

_spec = importlib.util.spec_from_file_location(
    "eha_validation", APP / "haproxy_admin/validation.py"
)
_validation = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_validation)
validate_config_data = _validation.validate_config_data

TEMPLATE = (
    ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
).read_text(encoding="utf-8")
EDITOR_TEMPLATE = (
    APP / "haproxy_admin/templates/haproxy_site_edit.html"
).read_text(encoding="utf-8")
EDITOR_SCRIPT = (
    APP / "haproxy_admin/static/js/haproxy_site_edit.js"
).read_text(encoding="utf-8")


def _site(**overrides) -> dict:
    site = {"name": "a.example.test", "domain": "a.example.test"}
    site.update(overrides)
    return site


class AccessGateTemplateTests(unittest.TestCase):
    def test_stub_gate_routes_to_the_static_access_granted_backend(self) -> None:
        self.assertIn("elif gate_stub", TEMPLATE)
        self.assertIn(
            "use_backend be_access_granted if host_{{ id }}",
            TEMPLATE,
        )

    def test_gate_sites_are_always_authelia_protected(self) -> None:
        self.assertIn(
            "(s.authelia_enabled | default(false)) or (s.access_gate | default(false))",
            TEMPLATE,
        )

    def test_only_backendless_gates_skip_backend_and_nbsrv(self) -> None:
        # A gate with configured servers/backend proxies like a normal site;
        # only the pure stub skips backend generation and the nbsrv ACL.
        self.assertEqual(
            TEMPLATE.count(
                "not (s.tcp_passthrough | default(false)) and not gate_stub"
            ),
            2,
        )
        self.assertGreaterEqual(TEMPLATE.count("set gate_stub ="), 3)

    def test_gate_disables_geo_by_default_but_allows_override(self) -> None:
        self.assertEqual(
            TEMPLATE.count("{% elif s.access_gate | default(false) %}"),
            3,
            "all three geo_disabled decisions honor the gate default",
        )

    def test_authelia_template_injects_gate_login_rules(self) -> None:
        # A full apply re-renders configuration.yml from the template, so gate
        # domains must get a one_factor rule there or Authelia's default deny
        # would break them after every update.
        authelia_tpl = (
            ROOT / "ansible/roles/authelia/templates/configuration.yml.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("_site.access_gate | default(false)", authelia_tpl)
        self.assertIn("policy: one_factor", authelia_tpl)
        self.assertIn("_managed_domains", authelia_tpl)

    def test_web_save_auto_adds_and_activates_gate_rule(self) -> None:
        services = (
            APP / "haproxy_admin/services_haproxy_sites.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_ensure_access_gate_authelia_rule", services)
        # The rule is only effective after Authelia reloads, so a restart is
        # requested (matching the manual ACL editor).
        self.assertIn('_configd_request({"action": "restart"})', services)

    def test_zero_trust_deny_never_locks_out_the_gate_itself(self) -> None:
        self.assertIn(
            "(s.zero_trust | default(false)) and not (s.access_gate | default(false))",
            TEMPLATE,
        )

    def test_site_editor_exposes_the_flag(self) -> None:
        self.assertIn('id="access_gate"', EDITOR_TEMPLATE)
        self.assertIn('tristateSelectValue("access_gate")', EDITOR_SCRIPT)
        self.assertIn("delete site.access_gate;", EDITOR_SCRIPT)

    def test_editor_locks_authelia_and_zero_trust_for_gates(self) -> None:
        # When the gate is on, Authelia is forced on and zero_trust forced off,
        # both in the live UI lock and in the persisted payload.
        self.assertIn("applyAccessGateLock", EDITOR_SCRIPT)
        self.assertIn("site.authelia_enabled = true;", EDITOR_SCRIPT)
        self.assertIn("site.zero_trust = false;", EDITOR_SCRIPT)

    def test_installer_offers_the_optional_gate(self) -> None:
        installer = (ROOT / "installer/easy_ha_proxy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("access-gate login site", installer)
        self.assertIn('"access_gate": True', installer)


class AccessGateValidationTests(unittest.TestCase):
    def test_boolean_flag_is_accepted(self) -> None:
        validate_config_data("websites", {"sites": [_site(access_gate=True)]})
        validate_config_data("websites", {"sites": [_site(access_gate=False)]})

    def test_non_boolean_flag_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_config_data(
                "websites", {"sites": [_site(access_gate="yes")]}
            )

    def test_gate_site_needs_no_backend_fields(self) -> None:
        validate_config_data(
            "websites",
            {"sites": [_site(access_gate=True, authelia_enabled=True, geo=False)]},
        )


if __name__ == "__main__":
    unittest.main()
