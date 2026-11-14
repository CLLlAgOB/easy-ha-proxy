"""The panel image carries no firewall or socket tools it does not use (N08).

The image installed socat, ipset, iptables and iproute2 from the time the
panel itself wrote to the HAProxy socket and the firewall. That work moved to
the host daemons long ago: the panel reaches them over Unix sockets, and its
container runs read-only with every capability dropped, so the tools could
not do anything there -- except be available to whoever got into it.

Held here: the image installs only certificates and the zone database, and
the panel's code starts no such tool, so the two cannot drift apart unnoticed.

The base image stays pinned by its patch tag, not by digest, on purpose: the
image is rebuilt on every publish, and a tag picks up the base's security
rebuilds by itself, while a digest would wait for someone to merge an update.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app"
TOOLS = ("socat", "ipset", "iptables", "iproute2", "nft", "conntrack")


class TheImage(unittest.TestCase):
    def setUp(self):
        self.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def installed(self):
        joined = self.dockerfile.replace(chr(92) + chr(10), " ")
        packages = []
        for line in joined.splitlines():
            if "apt-get install" in line:
                tail = line.split("apt-get install", 1)[1].split("&&", 1)[0]
                packages.extend(word for word in tail.split() if not word.startswith("-"))
        return packages

    def test_only_certificates_and_the_zone_database_are_installed(self):
        self.assertEqual(sorted(self.installed()), ["ca-certificates", "tzdata"])

    def test_the_base_is_one_patch_release_of_python(self):
        self.assertRegex(self.dockerfile, r"(?m)^FROM python:3[.]12[.][0-9]+-slim-[a-z]+$")

    def test_it_still_runs_as_an_unprivileged_user(self):
        self.assertIn("USER haproxyadmin", self.dockerfile)

    def test_the_panel_starts_none_of_those_tools(self):
        started = re.compile(r"""["'](?:/usr/s?bin/|/s?bin/)?(%s)["'\s]""" % "|".join(TOOLS))
        for path in sorted(APP.rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                # A command line is a list or a string handed to run_cmd / subprocess.
                if ("subprocess" in code or "run_cmd" in code or "Popen" in code) and started.search(code):
                    self.fail(f"{path.relative_to(ROOT)}:{number} starts a system tool: {line.strip()[:100]}")

    def test_the_container_could_not_use_them_anyway(self):
        compose = (ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2").read_text(encoding="utf-8")
        self.assertIn("cap_drop:\n      - ALL", compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("no-new-privileges:true", compose)


if __name__ == "__main__":
    unittest.main()
