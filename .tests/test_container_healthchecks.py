#!/usr/bin/env python3
"""Regression tests for container-level application readiness checks."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ADMIN_COMPOSE = ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"


def admin_healthcheck() -> str:
    """Just the healthcheck stanza of the admin service."""

    compose = ADMIN_COMPOSE.read_text(encoding="utf-8")
    return compose.split("healthcheck:")[1].split("networks:")[0]


class ContainerHealthcheckTests(unittest.TestCase):
    def test_admin_healthcheck_uses_the_authenticated_minimal_endpoint(self) -> None:
        # The point of the check: it goes through the same authenticated
        # boundary HAProxy uses, rather than some separate unauthenticated
        # readiness path that would prove less. The panel binary's own
        # subcommand makes that request.
        healthcheck = admin_healthcheck()
        self.assertIn("- /usr/local/bin/easy-ha-proxy-panel", healthcheck)
        self.assertIn("- healthcheck", healthcheck)
        main = (ROOT / "go/panel/cmd/easy-ha-proxy-panel/main.go").read_text(encoding="utf-8")
        check = main.split("func runHealthcheck() error {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("HAPROXY_ADMIN_PROXY_SECRET", check)
        self.assertIn("security.ControlPlaneHealthPath", check)
        self.assertIn("security.ControlPlaneHealthUser", check)
        self.assertIn("security.ControlPlaneHealthGroup", check)
        self.assertIn('payload["ok"]', check)

    def test_the_unhealthy_window_is_unchanged(self) -> None:
        """Asking less often must not mean noticing later.

        It was twelve attempts ten seconds apart. Any pair multiplying to
        the same two minutes is fine; a pair that does not changes how long
        a wedged container stays in service, and that should be a decision
        rather than a side effect of tuning CPU.
        """

        healthcheck = admin_healthcheck()
        interval = int(re.search(r"interval:\s*(\d+)s", healthcheck).group(1))
        retries = int(re.search(r"retries:\s*(\d+)", healthcheck).group(1))
        self.assertEqual(interval * retries, 120)


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
