"""Regression tests for the non-network security boundaries."""
from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_security_module():
    """Load the Flask boundary with a minimal dependency-free Flask stub."""
    package_name = "easy_ha_security_test_package"
    package = types.ModuleType(package_name)
    package.__path__ = []

    flask_module = types.ModuleType("flask")
    flask_module.request = types.SimpleNamespace(
        headers={}, method="GET", path="/", is_json=False
    )
    flask_module.g = types.SimpleNamespace()
    flask_module.jsonify = lambda payload: payload

    def fake_abort(status, description=None):
        raise RuntimeError(f"abort {status}: {description}")

    flask_module.abort = fake_abort

    i18n_module = types.ModuleType(f"{package_name}.i18n")
    i18n_module.translate = lambda value: value
    modules = {
        package_name: package,
        f"{package_name}.i18n": i18n_module,
        "flask": flask_module,
    }
    with mock.patch.dict(sys.modules, modules):
        security = load_module(
            f"{package_name}.security",
            ROOT / "docker/app/haproxy_admin/security.py",
        )
    return security, flask_module.request, flask_module.g


class ConfigurationValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validation = load_module(
            "easy_ha_validation",
            ROOT / "docker/app/haproxy_admin/validation.py",
        )

    def test_rejects_haproxy_directive_injection(self) -> None:
        with self.assertRaises(ValueError):
            self.validation.validate_config_data(
                "websites",
                {
                    "sites": [
                        {
                            "name": "safe\nprogram injected",
                            "domain": "safe.example.test",
                            "backend_ip": "127.0.0.1",
                            "backend_port": 8080,
                        }
                    ]
                },
            )

    def test_accepts_test_domain_and_backend(self) -> None:
        self.validation.validate_config_data(
            "websites",
            {
                "sites": [
                    {
                        "name": "home-assistant",
                        "domain": "ha.easy-ha-proxy.test",
                        "backend_ip": "192.168.56.10",
                        "backend_port": 8123,
                    }
                ]
            },
        )

    def test_rejects_control_plane_domain_replacement(self) -> None:
        active = """
frontend fe_https
    acl host_admin hdr(host) -i ha.easy-ha-proxy.test
    acl host_authelia hdr(host) -i aut.easy-ha-proxy.test
"""
        candidate = """
frontend fe_https
    acl host_admin hdr(host) -i ha.example.com
    acl host_authelia hdr(host) -i aut.example.com
"""
        with self.assertRaisesRegex(ValueError, "The change was blocked"):
            self.validation.validate_control_plane_transition(active, candidate)

    def test_accepts_control_plane_domains_with_new_site(self) -> None:
        active = """
frontend fe_https
    acl host_admin hdr(host) -i ha.easy-ha-proxy.test
    acl host_authelia hdr(host) -i aut.easy-ha-proxy.test
"""
        candidate = active + """
    acl host_app hdr(host) -i app.easy-ha-proxy.test
"""
        self.validation.validate_control_plane_transition(active, candidate)


class HAProxyControlPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controld = load_module(
            "easy_ha_controld",
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py",
        )
        cls.base = (
            b"global\n"
            b"    chroot /var/lib/haproxy\n"
            b"    user haproxy\n"
            b"    group haproxy\n"
            b"    daemon\n\n"
            b"defaults\n"
            b"    mode http\n"
        )

    def test_accepts_privilege_drop(self) -> None:
        self.controld._enforce_config_policy(self.base)

    def test_rejects_program_section(self) -> None:
        with self.assertRaises(ValueError):
            self.controld._enforce_config_policy(
                self.base + b"\nprogram injected\n    command /bin/sh\n"
            )

    def test_rejects_root_runtime_user(self) -> None:
        with self.assertRaises(ValueError):
            self.controld._enforce_config_policy(
                self.base.replace(b"user haproxy", b"user root")
            )

    def test_rejects_a_server_state_file_outside_the_chroot(self) -> None:
        # Allowing the directive must not mean allowing any path: HAProxy
        # reads this file at startup, and the policy already pins the chroot.
        elsewhere = self.base.replace(
            b"    daemon", b"    daemon\n    server-state-file /etc/shadow"
        )
        with self.assertRaisesRegex(ValueError, "server state file"):
            self.controld._enforce_config_policy(elsewhere)

    def test_accepts_the_state_file_inside_the_chroot(self) -> None:
        inside = self.base.replace(
            b"    daemon",
            b"    daemon\n    server-state-file /var/lib/haproxy/server-state",
        )
        self.controld._enforce_config_policy(inside)


class GeneratedConfigurationPassesItsOwnPolicyTests(unittest.TestCase):
    """The product must not generate a configuration it then refuses.

    Both the check button and every apply run the candidate through
    _enforce_config_policy. A global directive that the template emits but the
    policy does not list blocks the entire configuration editor -- which is
    how `server-state-file` shipped broken for a day: the drain feature added
    it to the template, the allow-list beside it was never touched, and the
    hand-written fixtures above never noticed because they are not the
    configuration the product actually writes.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.controld = load_module(
            "easy_ha_controld_generated",
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py",
        )

    def render(self, **flags) -> bytes:
        import re as _re

        from jinja2 import Environment, FileSystemLoader

        def combine(value, other, recursive=False):
            base = {} if value is None else dict(value)
            for key, item in dict(other or {}).items():
                if recursive and isinstance(base.get(key), dict) and isinstance(item, dict):
                    base[key] = combine(base[key], item, recursive=True)
                else:
                    base[key] = item
            return base

        environment = Environment(
            loader=FileSystemLoader(
                str(ROOT / "ansible/roles/haproxy/templates")
            ),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = (
            lambda value, pattern, repl: "" if value is None else _re.sub(
                pattern, repl, str(value)
            )
        )
        environment.filters["combine"] = combine
        context = {
            "sites": [
                {
                    "name": "shop",
                    "domain": "shop.example.test",
                    "backend_ip": "10.0.0.10",
                    "backend_port": 8080,
                }
            ],
            "tcp_proxies": [],
            "tcp": [],
            "site_defaults": {},
            "haproxy_threads": 2,
            "admin_domain": "ha.example.test",
            "aut_domain": "aut.example.test",
            "easy_ha_proxy_runtime_vars": {},
            "easy_ha_proxy_runtime_websites": {},
            "easy_ha_proxy_runtime_tcp": {},
        }
        context.update(flags)
        return environment.get_template("haproxy.cfg.j2").render(
            **context
        ).encode("utf-8")

    def test_every_shipped_combination_survives_the_policy(self) -> None:
        for label, flags in (
            ("defaults", {}),
            ("server state off", {"haproxy_server_state_enabled": False}),
            ("authelia off", {"authelia_enabled": False}),
            ("geoip on", {"enable_geoip": True}),
            ("metrics on", {"metrics_export_enabled": True}),
            (
                "everything on",
                {
                    "authelia_enabled": True,
                    "enable_geoip": True,
                    "metrics_export_enabled": True,
                    "enable_http80": True,
                },
            ),
        ):
            with self.subTest(label):
                self.controld._enforce_config_policy(self.render(**flags))

    def test_the_state_file_the_template_writes_is_the_one_allowed(self) -> None:
        # Not just "some path is accepted": the default the role ships has to
        # be inside the directory the policy pins.
        rendered = self.render().decode("utf-8")
        line = next(
            item.strip()
            for item in rendered.splitlines()
            if item.strip().startswith("server-state-file")
        )
        self.assertTrue(line.endswith("/var/lib/haproxy/server-state"), line)


class ApplicationSecurityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.security, cls.request, cls.identity = load_security_module()

    def setUp(self) -> None:
        self.request.headers = {
            "X-Easy-HA-Proxy-Secret": "test-proxy-secret",
            "Remote-User": "easy-ha-proxy-healthcheck",
            "Remote-Groups": "healthcheck",
        }
        self.request.method = "GET"
        self.request.path = "/api/control-plane-health"
        self.request.is_json = False
        self.identity.__dict__.clear()

    def enforce(self):
        with mock.patch.dict(
            os.environ,
            {"HAPROXY_ADMIN_PROXY_SECRET": "test-proxy-secret"},
        ):
            return self.security.enforce_proxy_and_role()

    def test_accepts_exact_least_privilege_healthcheck(self) -> None:
        self.assertIsNone(self.enforce())
        self.assertEqual(self.identity.remote_user, "easy-ha-proxy-healthcheck")
        self.assertEqual(self.identity.remote_groups, frozenset({"healthcheck"}))
        self.assertFalse(self.identity.is_superadmin)

    def test_rejects_healthcheck_identity_on_another_path(self) -> None:
        self.request.path = "/api/health/status"
        response, status = self.enforce()
        self.assertEqual(status, 403)
        self.assertFalse(response["ok"])

    def test_rejects_healthcheck_identity_for_another_method(self) -> None:
        self.request.method = "POST"
        response, status = self.enforce()
        self.assertEqual(status, 403)
        self.assertFalse(response["ok"])

    def test_reserved_healthcheck_identity_cannot_gain_admin_group(self) -> None:
        self.request.headers["Remote-Groups"] = "healthcheck,superadmin"
        response, status = self.enforce()
        self.assertEqual(status, 403)
        self.assertFalse(response["ok"])

    def test_global_configuration_state_requires_superadmin(self) -> None:
        self.request.path = "/haproxy/config/state"
        self.request.is_json = True
        self.request.headers.update(
            {
                "Remote-User": "administrator",
                "Remote-Groups": "admins",
            }
        )
        response, status = self.enforce()
        self.assertEqual(status, 403)
        self.assertFalse(response["ok"])

        self.request.headers["Remote-Groups"] = "superadmin"
        self.assertIsNone(self.enforce())
        self.assertTrue(self.identity.is_superadmin)


class DeploymentRegressionTests(unittest.TestCase):
    def test_backend_status_uses_only_configured_admin_sockets(self) -> None:
        services = (
            ROOT / "docker/app/haproxy_admin/services.py"
        ).read_text(encoding="utf-8")
        admin_socket_helper = services.split(
            "def _admin_sockets()", maxsplit=1
        )[1].split("def _show_stat", maxsplit=1)[0]

        self.assertIn("return _all_admin_sockets()", admin_socket_helper)
        self.assertNotIn('endswith(".sock")', admin_socket_helper)

    def test_site_issue_buttons_send_the_requested_certificate_source(self) -> None:
        javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/haproxy_site_edit.js"
        ).read_text(encoding="utf-8")
        route = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py"
        ).read_text(encoding="utf-8")

        self.assertIn('issueCertificate("letsencrypt")', javascript)
        self.assertIn('issueCertificate("internal")', javascript)
        self.assertIn("source: requestedSource", javascript)
        self.assertIn('payload.get("source")', route)

    def test_remote_sync_can_apply_local_source_with_alpha_image(self) -> None:
        remote = (ROOT / "install-remote.sh").read_text(encoding="utf-8")

        self.assertIn("--apply", remote)
        self.assertIn("--source-channel local", remote)
        self.assertIn("--image-channel ${image_channel}", remote)

    def test_ui_update_deploys_compatible_certificate_daemon(self) -> None:
        installer = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        ui_tags = installer.split("UI_TAGS =", maxsplit=1)[1].split(
            "DAEMON_TAGS =", maxsplit=1
        )[0]

        self.assertIn('"ha-adm-daemons"', ui_tags)

    def test_authelia_keeps_supported_container_hardening(self) -> None:
        compose = (
            ROOT / "ansible/roles/authelia/templates/docker-compose.yml.j2"
        ).read_text(encoding="utf-8")
        authelia_service = compose.split(
            "  {{ authelia_container_name }}:", maxsplit=1
        )[1].split("\nnetworks:", maxsplit=1)[0]

        self.assertNotIn("read_only: true", authelia_service)
        self.assertIn("cap_drop:\n      - ALL", authelia_service)
        self.assertIn("no-new-privileges:true", authelia_service)

    def test_proxy_secret_header_is_valid_without_systemd_environment(self) -> None:
        haproxy_template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        admin_environment = (
            ROOT
            / "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "%[env(HAPROXY_ADMIN_PROXY_SECRET)]",
            haproxy_template,
        )
        self.assertIn(
            "HAPROXY_ADMIN_PROXY_SECRET={{ haproxy_admin_proxy_secret",
            admin_environment,
        )

    def test_control_plane_probe_has_least_privilege_identity(self) -> None:
        haproxy_template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        application_security = (
            ROOT / "docker/app/haproxy_admin/security.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "bool(true) if host_admin local_control_plane_probe "
            "admin_control_plane_probe_path admin_control_plane_probe_method",
            haproxy_template,
        )
        self.assertIn(
            "Remote-Groups healthcheck if host_admin admin_control_plane_probe",
            haproxy_template,
        )
        self.assertNotIn(
            "Remote-Groups superadmin if host_admin admin_control_plane_probe",
            haproxy_template,
        )
        self.assertIn(
            'CONTROL_PLANE_HEALTHCHECK_GROUPS: FrozenSet[str] = '
            'frozenset({"healthcheck"})',
            application_security,
        )
        self.assertIn('request.method == "GET"', application_security)
        self.assertIn(
            "request.path == CONTROL_PLANE_HEALTHCHECK_PATH",
            application_security,
        )
        self.assertIn("groups == CONTROL_PLANE_HEALTHCHECK_GROUPS", application_security)

    def test_haproxy_environment_change_forces_service_restart(self) -> None:
        tasks = (
            ROOT / "ansible/roles/haproxy/tasks/config.yml"
        ).read_text(encoding="utf-8")
        handlers = (
            ROOT / "ansible/roles/haproxy/handlers/main.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("register: haproxy_runtime_environment", tasks)
        self.assertIn("haproxy_runtime_environment.changed", handlers)
        self.assertIn("haproxy_secret_dropin.changed", handlers)
        self.assertIn("'restarted'", handlers)

    def test_disabled_debug_routes_are_not_advertised(self) -> None:
        routes = (
            ROOT / "docker/app/haproxy_admin/routes.py"
        ).read_text(encoding="utf-8")
        index = (
            ROOT / "docker/app/haproxy_admin/templates/index.html"
        ).read_text(encoding="utf-8")
        disabled_page = (
            ROOT / "docker/app/haproxy_admin/templates/debug_disabled.html"
        ).read_text(encoding="utf-8")
        environment = (
            ROOT
            / "ansible/roles/haproxy-admin/templates/haproxy-admin.env.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("debug_routes_enabled=_debug_routes_enabled()", routes)
        self.assertIn('render_template("debug_disabled.html")', routes)
        self.assertIn("{% if debug_routes_enabled %}", index)
        self.assertIn("haproxy_admin_debug_routes: true", disabled_page)
        self.assertIn("HAPROXY_ADMIN_DEBUG_ROUTES=", environment)

    def test_runtime_config_is_seeded_from_managed_config(self) -> None:
        tasks = (
            ROOT / "ansible/roles/haproxy-admin/tasks/config.yml"
        ).read_text(encoding="utf-8")
        installer = (
            ROOT / "installer/easy_ha_proxy.py"
        ).read_text(encoding="utf-8")
        config_service = (
            ROOT
            / "docker/app/haproxy_admin/services_haproxy_config.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "Seed runtime config from the managed config",
            tasks,
        )
        self.assertIn(
            "easy_ha_proxy_config_dir | default(playbook_dir)",
            tasks,
        )
        self.assertIn(
            "Calculate effective HAProxy thread count for the UI renderer",
            tasks,
        )
        self.assertIn(
            "haproxy_nbthread: {{ haproxy_effective_nbthread }}",
            tasks,
        )
        self.assertIn('"aut_domain": authelia_domain', installer)
        self.assertIn('"authelia_enabled": True', installer)
        self.assertIn(
            "validate_control_plane_transition(active_cfg, cfg_text)",
            config_service,
        )


if __name__ == "__main__":
    unittest.main()
