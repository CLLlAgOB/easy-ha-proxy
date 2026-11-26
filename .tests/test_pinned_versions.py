"""Watching what Dependabot cannot read.

Dependabot proposes updates for the requirements files, the Dockerfile and
the workflows -- against alpha, since main is moved to alpha after testing.
The versions pinned as role variables (Authelia, Redis, the mail relay,
the GeoIP packages) are compared with their registries by a weekly job that
keeps one issue open while anything is behind. A separate weekly audit reports known vulnerabilities
without blocking CI. Dependabot itself is told not to offer what cannot be
taken: a new Python for the image, a raised floor on a range that already
allows the release.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/pinned_versions.py"


def load():
    spec = importlib.util.spec_from_file_location("pinned_versions_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pinned = load()


class Versions(unittest.TestCase):
    def test_parsing(self):
        self.assertEqual(pinned.parse_version("7.4.9-alpine"), ((7, 4, 9), "-alpine"))
        self.assertEqual(pinned.parse_version("v4.39.28"), ((4, 39, 28), ""))
        for odd in ("latest", "8.0-rc1", "2.0.0-beta.2", "alpine", ""):
            with self.subTest(tag=odd):
                self.assertIsNone(pinned.parse_version(odd))

    def test_same_series_and_newest_of_the_same_shape(self):
        tags = ["7.4.9-alpine", "7.4.12-alpine", "7.4.13", "8.2.1-alpine", "8.2-alpine",
                "8.4.0-rc1-alpine", "latest", "7.2.99-alpine"]
        self.assertEqual(pinned.newer_releases("7.4.9-alpine", tags),
                         {"series": "7.4.12-alpine", "latest": "8.2.1-alpine"})
        self.assertEqual(pinned.newer_releases("8.2.1-alpine", tags), {"series": None, "latest": None})

    def test_reading_pins(self):
        text = 'authelia_version: "4.39.28"\nmail_relay_image: juanluisbaptiste/postfix:1.9.0  # relay\n'
        self.assertEqual(pinned.read_pin(text, "authelia_version"), "4.39.28")
        self.assertEqual(pinned.read_pin(text, "mail_relay_image"), "juanluisbaptiste/postfix:1.9.0")
        self.assertEqual(pinned.split_image("redis:7.4.9-alpine"), ("redis", "7.4.9-alpine"))

    def test_every_pin_is_found_and_one_registry_down_is_one_line(self):
        def fetch(url):
            if "pypi.org" in url:
                raise OSError("pypi unreachable")
            return {"results": [{"name": "99.0.0"}, {"name": "99.0.0-alpine"}], "next": None}

        rows = {row["variable"]: row for row in pinned.check(fetch=fetch)}
        self.assertEqual(set(rows), {variable for _, variable, _, _ in pinned.PINS})
        self.assertTrue(all(row["pinned"] for row in rows.values()))
        self.assertEqual(rows["authelia_version"]["latest"], "99.0.0")
        self.assertEqual(rows["authelia_redis_image"]["latest"], "99.0.0-alpine")
        self.assertTrue(pinned.behind(list(rows.values())))
        self.assertIn("| `authelia_version` (authelia/authelia) |", pinned.report(list(rows.values())))


def dependabot_entries(config):
    """Each (ecosystem, directory) with its entry; `directories` lists several."""
    entries = {}
    for item in config["updates"]:
        for directory in item.get("directories") or [item["directory"]]:
            entries[(item["package-ecosystem"], directory)] = item
    return entries


class TheConfiguration(unittest.TestCase):
    def test_dependabot_targets_alpha_everywhere(self):
        config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"))
        ecosystems = set(dependabot_entries(config))
        self.assertEqual(ecosystems, {("pip", "/installer"), ("docker", "/go/panel"),
                                      ("github-actions", "/"),
                                      ("gomod", "/go/agent"), ("gomod", "/go/panel"),
                                      ("cargo", "/rust/guardd")})
        self.assertTrue(all(item["target-branch"] == "alpha" for item in config["updates"]))

    def test_dependabot_offers_only_what_can_be_taken(self):
        config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"))
        entries = dependabot_entries(config)

        # The installer's ranges move only when a release falls outside them.
        installer = entries[("pip", "/installer")]
        self.assertEqual(installer["versioning-strategy"], "increase-if-necessary")
        requirements = (ROOT / "installer/requirements.txt").read_text(encoding="utf-8")
        self.assertNotIn("ansible-core", requirements)

        # Every action in one pull request.
        actions = entries[("github-actions", "/")]
        self.assertEqual(actions["groups"]["actions"]["patterns"], ["*"])

    def test_the_weekly_job_writes_issues_and_nothing_else(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/dependencies.yml").read_text(encoding="utf-8"))
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["jobs"]["pinned"]["permissions"], {"contents": "read", "issues": "write"})
        audit = "\n".join(step.get("run", "") for step in workflow["jobs"]["audit"]["steps"])
        self.assertIn("pip-audit", audit)
        # Nothing is ignored since the gateways stopped installing ansible-core.
        self.assertNotIn("--ignore-vuln", audit)


if __name__ == "__main__":
    unittest.main()
