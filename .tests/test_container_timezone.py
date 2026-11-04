"""The panel and Authelia containers keep the gateway's time.

Both roles defaulted their containers to Europe/Moscow whatever the host
said. On a gateway in another zone every time the panel wrote itself -- the
build footer first -- was hours off, while the host daemons beside it were
right. The playbook now reads the gateway's zone, and a container takes it
unless the operator chose one.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Environment
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import easy_ha_proxy  # noqa: E402

ADMIN_ROLE = ROOT / "ansible/roles/haproxy-admin"
AUTHELIA_ROLE = ROOT / "ansible/roles/authelia"
PLAYBOOK = ROOT / "ansible/easy-ha-proxy.yml"


def environment() -> Environment:
    env = Environment()
    # The Ansible filters these templates use, as far as rendering needs them.
    env.filters["dirname"] = os.path.dirname
    env.filters["bool"] = lambda value: str(value).strip().lower() in {"1", "true", "yes", "on"}
    return env


def admin_tz(**variables) -> str:
    text = (ADMIN_ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
    compose = yaml.safe_load(environment().from_string(text).render(**variables))
    return compose["services"]["haproxy-admin"]["environment"]["TZ"]


def authelia_tz(**variables) -> set:
    text = (AUTHELIA_ROLE / "templates/docker-compose.yml.j2").read_text(encoding="utf-8")
    variables = {"authelia_container_name": "authelia", "authelia_docker_network": "authelia_net",
                 **variables}
    compose = yaml.safe_load(environment().from_string(text).render(**variables))
    zones = set()
    for service in compose["services"].values():
        for entry in service.get("environment") or []:
            if entry.startswith("TZ="):
                zones.add(entry[3:])
    return zones


class TheContainersFollowTheGateway(unittest.TestCase):
    def test_no_role_names_a_zone_of_its_own(self):
        admin = yaml.safe_load((ADMIN_ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        authelia = yaml.safe_load((AUTHELIA_ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertEqual(admin["haproxy_admin_timezone"], "")
        self.assertEqual(authelia["authelia_timezone"], "")
        for template in (ADMIN_ROLE / "templates/docker-compose.yml.j2",
                         AUTHELIA_ROLE / "templates/docker-compose.yml.j2"):
            self.assertNotIn("Europe/Moscow", template.read_text(encoding="utf-8"))

    def test_the_panel_takes_the_gateways_zone(self):
        self.assertEqual(admin_tz(haproxy_admin_timezone="",
                                  easy_ha_proxy_host_timezone="Europe/Warsaw"), "Europe/Warsaw")

    def test_an_operators_choice_wins(self):
        self.assertEqual(admin_tz(haproxy_admin_timezone="Asia/Tokyo",
                                  easy_ha_proxy_host_timezone="Europe/Warsaw"), "Asia/Tokyo")

    def test_nothing_known_is_utc(self):
        self.assertEqual(admin_tz(), "UTC")

    def test_every_authelia_container_takes_the_same_zone(self):
        self.assertEqual(authelia_tz(authelia_timezone="",
                                     easy_ha_proxy_host_timezone="Europe/Warsaw",
                                     mail_notify_enabled=True), {"Europe/Warsaw"})
        self.assertEqual(authelia_tz(authelia_timezone="Asia/Tokyo",
                                     easy_ha_proxy_host_timezone="Europe/Warsaw"), {"Asia/Tokyo"})
        self.assertEqual(authelia_tz(), {"UTC"})


def playbook_task(name: str) -> dict:
    play = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
    return next(task for task in play["pre_tasks"] if task.get("name") == name)


class ThePlaybookReadsTheZoneOnTheGateway(unittest.TestCase):
    def test_on_every_run_without_counting_as_a_change(self):
        probe = playbook_task("Read the gateway's time zone")
        remember = playbook_task("Remember the gateway's time zone")
        # A shell task runs on the gateway; a lookup would read the machine
        # the playbook was started from.
        self.assertIn("ansible.builtin.shell", probe)
        self.assertIs(probe["changed_when"], False)
        self.assertIs(probe["check_mode"], False)
        self.assertEqual((probe["tags"], remember["tags"]), ("always", "always"))
        self.assertIn("easy_ha_proxy_host_timezone", remember["ansible.builtin.set_fact"])

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_it_takes_what_timedatectl_says_and_nothing_odd(self):
        script = playbook_task("Read the gateway's time zone")["ansible.builtin.shell"]
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "timedatectl"

            def zone(said: str) -> str:
                fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{said}'\n", encoding="utf-8")
                fake.chmod(0o755)
                result = subprocess.run(
                    ["bash", "-c", script], capture_output=True, text=True, check=True,
                    env={**os.environ, "PATH": f"{directory}:{os.environ.get('PATH', '')}"},
                )
                return result.stdout.strip()

            self.assertEqual(zone("Europe/Warsaw"), "Europe/Warsaw")
            self.assertEqual(zone("America/Argentina/Buenos_Aires"), "America/Argentina/Buenos_Aires")
            self.assertEqual(zone("Etc/GMT+3"), "Etc/GMT+3")
            for odd in ("Europe/Warsaw x", "../../etc/passwd", "/etc/localtime", "Europe/"):
                self.assertEqual(zone(odd), "UTC", odd)


class TheInstallerOffersTheSameZone(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.timezone = self.root / "timezone"
        self.localtime = self.root / "localtime"

    def detect(self) -> str:
        return easy_ha_proxy.detect_timezone(self.timezone, self.localtime)

    def link(self, target: str) -> None:
        try:
            os.symlink(target, self.localtime)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are not available here")

    def test_debian_names_it_in_etc_timezone(self):
        self.timezone.write_text("Europe/Warsaw\n", encoding="utf-8")
        self.assertEqual(self.detect(), "Europe/Warsaw")

    def test_elsewhere_the_localtime_link_names_it(self):
        self.link("../usr/share/zoneinfo/posix/Asia/Tokyo")
        self.assertEqual(self.detect(), "Asia/Tokyo")

    def test_a_host_that_says_nothing_or_nonsense_gets_utc(self):
        self.assertEqual(self.detect(), "UTC")
        self.timezone.write_text("Europe/Warsaw; true\n", encoding="utf-8")
        self.assertEqual(self.detect(), "UTC")


if __name__ == "__main__":
    unittest.main()
