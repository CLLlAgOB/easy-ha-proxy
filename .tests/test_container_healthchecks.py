#!/usr/bin/env python3
"""Regression tests for container-level application readiness checks."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ContainerHealthcheckTests(unittest.TestCase):
    def test_admin_healthcheck_uses_the_authenticated_minimal_endpoint(self) -> None:
        compose = (
            ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"
        ).read_text(encoding="utf-8")

        self.assertIn('"http://127.0.0.1:5000/api/control-plane-health"', compose)
        self.assertIn(
            '"X-Easy-HA-Proxy-Secret": '
            'os.environ["HAPROXY_ADMIN_PROXY_SECRET"]',
            compose,
        )
        self.assertIn('"Remote-User": "easy-ha-proxy-healthcheck"', compose)
        self.assertIn('"Remote-Groups": "healthcheck"', compose)
        self.assertIn('payload.get("ok") is True', compose)

    def test_admin_health_endpoint_remains_behind_the_request_boundary(self) -> None:
        application = (
            ROOT / "docker/app/haproxy_admin/__init__.py"
        ).read_text(encoding="utf-8")
        security = (
            ROOT / "docker/app/haproxy_admin/security.py"
        ).read_text(encoding="utf-8")

        self.assertIn("app.before_request(enforce_proxy_and_role)", application)
        self.assertIn(
            "groups == CONTROL_PLANE_HEALTHCHECK_GROUPS",
            security,
        )
        self.assertIn('request.method == "GET"', security)

    def test_start_and_update_wait_for_docker_health(self) -> None:
        start = (
            ROOT / "ansible/roles/haproxy-admin/tasks/start.yml"
        ).read_text(encoding="utf-8")
        update = (
            ROOT / "ansible/roles/haproxy-admin/tasks/update_haproxy_admin.yml"
        ).read_text(encoding="utf-8")
        wait = (
            ROOT
            / "ansible/roles/haproxy-admin/tasks/wait_haproxy_admin_healthy.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("wait_haproxy_admin_healthy.yml", start)
        self.assertIn("wait_haproxy_admin_healthy.yml", update)
        self.assertNotIn("ansible.builtin.wait_for:", start)
        self.assertIn(".State.Health.Status", wait)
        self.assertIn('== "healthy"', wait)
        self.assertIn("Docker health details", wait)

    def test_redis_has_a_native_ping_healthcheck(self) -> None:
        compose = (
            ROOT / "ansible/roles/authelia/templates/docker-compose.yml.j2"
        ).read_text(encoding="utf-8")
        redis_service = compose.split("  authelia-redis:", maxsplit=1)[1].split(
            "\n\n{% if mail_relay_server", maxsplit=1
        )[0]

        self.assertIn('test: ["CMD", "redis-cli", "ping"]', redis_service)
        self.assertIn("start_period: 5s", redis_service)


if __name__ == "__main__":
    unittest.main()
