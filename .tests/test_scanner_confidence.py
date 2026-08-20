"""Not every scanner path is worth the same, and a served path is not one.

The file has described "three tiers of confidence" in its comments since it
was written, and had one: every category weighed 25, so asking for /.env
scored exactly what asking for /wp-admin scored. But there is no browser, no
framework and no crawler that fetches an .env file, a git object store or a
database dump -- one request is not a hint, it is the whole answer -- while a
site may perfectly well run WordPress.

The second half is the mirror image. classify_path ran on every request
regardless of the response, so a site that really serves /wp-login.php filed
each of its own users as scanning for WordPress. On one gateway 488 of 1157
WordPress-shaped hits were answered 2xx: the application, not reconnaissance.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARDD = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-guardd.py"
)


def load():
    spec = importlib.util.spec_from_file_location("guardd_confidence", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_confidence"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class TierTests(unittest.TestCase):
    def test_the_categories_no_client_ever_wants_are_decisive(self):
        for category in ("secrets", "vcs", "backup"):
            with self.subTest(category=category):
                self.assertTrue(guardd.category_is_decisive(category))

    def test_a_category_a_site_might_genuinely_serve_is_not(self):
        # A site may run WordPress, publish server-status or have a /vendor
        # tree. One hit there means little on its own.
        for category in (
            "wordpress", "app-framework", "dependency", "database-admin",
            "server-info", "legacy-cgi", "config",
        ):
            with self.subTest(category=category):
                self.assertFalse(guardd.category_is_decisive(category))

    def test_the_decisive_paths_classify_into_decisive_categories(self):
        for path in ("/.env", "/.git/config", "/.aws/credentials",
                     "/.ssh/id_rsa", "/.git/HEAD", "/dump.sql"):
            with self.subTest(path=path):
                category = guardd.classify_path(path)
                self.assertTrue(category, f"{path} is not recognised at all")
                self.assertTrue(
                    guardd.category_is_decisive(category),
                    f"{path} classified as {category}, which is not decisive",
                )

    def test_one_decisive_hit_reaches_the_ban_line_by_itself(self):
        # The whole point of the tier: a single request for a file nobody
        # legitimately wants must not need corroboration.
        weight = guardd.DEFAULT_WEIGHTS[guardd.EVENT_SCANNER_DECISIVE]
        self.assertGreaterEqual(weight, guardd.WOULD_BAN_SCORE)

    def test_a_probable_hit_still_needs_company(self):
        weight = guardd.DEFAULT_WEIGHTS[guardd.EVENT_SCANNER_PATH]
        self.assertLess(weight, guardd.WOULD_BAN_SCORE)

    def test_both_events_are_in_the_weight_table(self):
        # An event the policy does not know scores zero and is invisible.
        for event in (guardd.EVENT_SCANNER_PATH, guardd.EVENT_SCANNER_DECISIVE):
            with self.subTest(event=event):
                self.assertIn(event, guardd.DEFAULT_WEIGHTS)


class ServedPathTests(unittest.TestCase):
    def test_a_served_response_is_the_application_answering(self):
        for status in (200, 201, 204, 301, 302, 304):
            with self.subTest(status=status):
                self.assertTrue(guardd.is_served(status))

    def test_a_refusal_is_not(self):
        for status in (400, 401, 403, 404, 423, 451, 500, 502):
            with self.subTest(status=status):
                self.assertFalse(guardd.is_served(status))

    def test_the_rule_is_applied_before_a_finding_is_emitted(self):
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split("category = classify_path(request.path)")[1][:400]
        self.assertIn("is_served(request.status)", block)
        # It must clear the category, not merely skip the weight, or the
        # request would still count towards the multi-category finding.
        self.assertIn('category = ""', block)

    def test_the_emitted_event_follows_the_tier(self):
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split("activity.note_category(category, now)")[1][:400]
        self.assertIn("category_is_decisive(category)", block)
        self.assertIn("EVENT_SCANNER_DECISIVE", block)

    def test_the_fingerprint_follows_the_event(self):
        # Sharing one fingerprint across both tiers would let a decisive
        # finding be swallowed by the cooldown of a probable one.
        source = GUARDD.read_text(encoding="utf-8")
        self.assertIn('fingerprint=f"{ip}|{event}|{category}"', source)


if __name__ == "__main__":
    unittest.main()
