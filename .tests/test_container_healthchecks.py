#!/usr/bin/env python3
"""Regression tests for container-level application readiness checks."""

from __future__ import annotations

import pathlib
import re
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ADMIN_COMPOSE = ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"


def admin_healthcheck() -> str:
    """Just the healthcheck stanza of the admin service."""

    compose = ADMIN_COMPOSE.read_text(encoding="utf-8")
    return compose.split("healthcheck:")[1].split("networks:")[0]


def embedded_program() -> str:
    """The Python the healthcheck actually runs, lifted out of the YAML."""

    lines = ADMIN_COMPOSE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- |-")
    indent = len(lines[start]) - len(lines[start].lstrip())
    body = [
        line
        for line in lines[start + 1:]
        if not (line.strip() and (len(line) - len(line.lstrip())) <= indent)
    ]
    return textwrap.dedent("\n".join(body))


class ContainerHealthcheckTests(unittest.TestCase):
    def test_admin_healthcheck_uses_the_authenticated_minimal_endpoint(self) -> None:
        # The point of the check: it goes through the same authenticated
        # boundary HAProxy uses, rather than some separate unauthenticated
        # readiness path that would prove less.
        healthcheck = admin_healthcheck()

        self.assertIn("GET /api/control-plane-health HTTP/1.0", healthcheck)
        self.assertIn('os.environ["HAPROXY_ADMIN_PROXY_SECRET"]', healthcheck)
        self.assertIn("X-Easy-HA-Proxy-Secret: ", healthcheck)
        self.assertIn("Remote-User: easy-ha-proxy-healthcheck", healthcheck)
        self.assertIn("Remote-Groups: healthcheck", healthcheck)
        self.assertIn('"ok": true', healthcheck)
        self.assertIn('== b"200"', healthcheck)

    def test_the_check_does_not_pay_for_urllib(self) -> None:
        """Importing urllib.request was almost the entire cost of this check.

        Measured on a live gateway as container CPU per run: 329 ms with
        urllib, 111 ms writing the request onto a socket by hand.
        urllib.request drags in http.client, email and ssl in order to send
        eleven lines of plain HTTP, and a bare interpreter start is 17 ms,
        so nearly all of the difference was the import.

        At the interval it ran on, that was around 2800 core-seconds a day
        -- very nearly the whole CPU consumption of this container, which
        measured 4154 core-seconds over 36 hours.
        """

        healthcheck = admin_healthcheck()
        self.assertNotIn("urllib", healthcheck)
        self.assertIn("socket.create_connection", healthcheck)

    def test_the_embedded_program_is_valid_python(self) -> None:
        """It is only a string in a YAML file until the day it runs.

        Nothing else here would catch a mangled escape or a stray indent:
        the template renders, the container starts, and the check simply
        fails from then on. Two attempts at writing this one were lost to
        exactly that, both times by a shell eating a backslash.
        """

        source = embedded_program()
        compile(source, "healthcheck", "exec")
        # The line terminators have to survive as two characters rather than
        # becoming real newlines, which is how both attempts died.
        self.assertIn("\\r\\n", source)
        self.assertNotIn("\r", source)

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
