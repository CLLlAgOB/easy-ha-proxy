"""The update check says when upstream has released past a pinned image (U01).

The checks so far said whether a pinned tag's content moved, and the source
update said when the project pinned a newer image. Nothing said that Redis
upstream had released something newer the project had not taken up -- the
operator had to go and look. The check now asks the registry, for an
allow-listed repository, and reports it as information: no pull, no pin, no
button, and outside the components an installation is held to. A list the
registry cuts short, or no answer, is "unknown", never "nothing newer".
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import update_plan  # noqa: E402

TAGS = ["8.10.3-alpine", "8.10.4-alpine", "8.12.0-alpine", "8.12-alpine", "8-alpine", "alpine",
        "8.14.0-rc1-alpine", "8.14.0-alpine3.22", "8.12.1", "9.0.0-alpine", "9.0.0-M01-alpine",
        "7.4.6-alpine"]


class Registry:
    def __init__(self, tags=TAGS, *, link=False, error=None):
        self.tags = tags
        self.link = link
        self.error = error
        self.asked = []

    def __call__(self, url, headers):
        self.asked.append(url)
        if self.error:
            raise self.error
        if url.startswith("https://auth.docker.io/"):
            return json.dumps({"token": "t"}).encode(), {}
        assert headers.get("Authorization") == "Bearer t"
        return json.dumps({"tags": self.tags}).encode(), ({"link": "<next>"} if self.link else {})


def probe(image, registry, pinned_by="project"):
    return update_plan._upstream_release(image, pinned_by=pinned_by, fetch=registry)


class TheReleases(unittest.TestCase):
    def test_a_newer_release_in_the_same_flavour_is_reported(self):
        entry = probe("redis:8.10.3-alpine", Registry())
        self.assertEqual(entry["state"], "newer")
        self.assertEqual(entry["newest_same_major"], "8.12.0-alpine")
        self.assertEqual(entry["newest"], "9.0.0-alpine")
        self.assertEqual(entry["current"], "8.10.3-alpine")

    def test_prereleases_and_other_flavours_do_not_count(self):
        entry = probe("redis:8.12.0-alpine", Registry([t for t in TAGS if not t.startswith("9.")]))
        self.assertEqual(entry["state"], "none")
        self.assertIsNone(entry["newest"])

    def test_a_whole_list_with_nothing_newer_is_none(self):
        self.assertEqual(probe("redis:9.0.0-alpine", Registry())["state"], "none")

    def test_a_list_cut_short_is_not_none(self):
        entry = probe("redis:9.0.0-alpine", Registry(link=True))
        self.assertEqual(entry["state"], "unknown")
        self.assertEqual(entry["reason"], "tag-list-incomplete")

    def test_but_what_it_did_see_is_still_news(self):
        self.assertEqual(probe("redis:8.10.3-alpine", Registry(link=True))["state"], "newer")

    def test_no_registry_is_unknown(self):
        entry = probe("redis:8.10.3-alpine", Registry(error=urllib.error.URLError("offline")))
        self.assertEqual(entry["state"], "unknown")
        self.assertEqual(entry["reason"], "registry-unavailable")

    def test_only_allow_listed_repositories_are_asked(self):
        registry = Registry()
        self.assertIsNone(probe("authelia/authelia:4.39.28", registry))
        self.assertIsNone(probe("redis@sha256:" + "a" * 64, registry))
        self.assertEqual(registry.asked, [])

    def test_a_pin_that_is_not_a_release_is_unknown(self):
        self.assertEqual(probe("redis:alpine", Registry())["reason"], "pin-is-not-a-release")

    def test_who_pinned_it_is_said(self):
        components = [{"id": "authelia-container", "details": {"images": [
            {"image": "redis:8.10.3-alpine"}, {"image": "authelia/authelia:4.39.28"}]}}]
        found = update_plan._upstream_releases(
            components, {"authelia_redis_image": "redis:8.10.3-alpine"}, Registry())
        self.assertEqual([(e["repository"], e["pinned_by"], e["component"]) for e in found],
                         [("redis", "override", "authelia-container")])


class ThePlan(unittest.TestCase):
    def test_it_sits_outside_what_an_installation_is_held_to(self):
        broker = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py").read_text(encoding="utf-8")
        digest = broker.split("def plan_digest")[1].split("\ndef ")[0]
        self.assertNotIn("upstream", digest)
        self.assertIn('"components": payload.get("components")', digest)

    def test_only_the_checker_itself_asks_the_registry(self):
        source = (ROOT / "installer/update_plan.py").read_text(encoding="utf-8")
        main = source.split("def main(argv")[1]
        self.assertIn("upstream_fetch=_http_get", main)
        self.assertIn("if upstream_fetch is not None", source)

    def test_the_page_shows_it(self):
        script = (ROOT / "docker/app/haproxy_admin/static/js/system_updates.js").read_text(encoding="utf-8")
        self.assertIn("renderUpstream(plan);", script)
        self.assertIn('"Newer upstream release, not yet tested by this project:"', script)
        catalogue = json.loads((ROOT / "docker/app/haproxy_admin/translations/ru/updates.json")
                               .read_text(encoding="utf-8"))["messages"]
        for label in ("Newer upstream release, not yet tested by this project:",
                      "No newer upstream release:", "Upstream releases could not be checked:"):
            self.assertIn(label, catalogue)


if __name__ == "__main__":
    unittest.main()
