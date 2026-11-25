"""Regression tests for the non-network security boundaries."""
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentRegressionTests(unittest.TestCase):


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


if __name__ == "__main__":
    unittest.main()
