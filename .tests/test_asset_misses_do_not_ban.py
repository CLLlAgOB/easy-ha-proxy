"""A missing logo must not get anyone banned.

203.0.113.46 fetched the front page of example.com and then went looking
for its icon, the way a link preview does: /logo.png, /logo.svg,
/images/logo.png, /images/logo.svg, /assets/logo.png, /assets/logo.svg,
/static/logo.png, /static/logo.svg, /favicon.ico, /favicon.png,
/favicon-192x192.png, /apple-touch-icon.png, /styles/images/logo_small.gif.

The site has none of them. Thirty 404s, and `src_http_err_rate` over the
site's limit of twenty, so HAProxy banned it for a week -- ban_code=10,
ERR_LIMIT_SITE. Not one attack path in the list, and the adaptive engine had
recorded nothing at all about the address: is_asset() has always treated a
missing asset as a broken page rather than reconnaissance.

That was the whole fault. The layer that understands the traffic does not
ban, and the layer that bans did not understand it. The error counter now
skips static assets too.

It is deliberately a narrower list than the engine's. The engine also
forgives .json, .xml and .txt; the counter must not, because /config.json
and /.env.txt are plausible targets and tracking is decided from the path
before the response status is known.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "ansible" / "roles" / "haproxy" / "templates" / "haproxy.cfg.j2"
)


class TheAclExists(unittest.TestCase):
    def setUp(self):
        self.source = TEMPLATE.read_text(encoding="utf-8")
        self.acl_lines = [
            line for line in self.source.splitlines()
            if line.strip().startswith("acl err_asset_path")
        ]

    def suffixes(self):
        found = set()
        for line in self.acl_lines:
            found.update(re.findall(r"\.[a-z0-9]+", line.split("-i", 1)[1]))
        return found

    def test_it_is_declared(self):
        self.assertTrue(self.acl_lines, "no err_asset_path acl in the template")

    def test_it_matches_on_the_end_of_the_path(self):
        # path_beg would exempt /css-admin/, and a regex would cost a match
        # per request for no gain.
        for line in self.acl_lines:
            with self.subTest(line=line.strip()[:50]):
                self.assertIn("path_end", line)

    def test_it_covers_everything_that_caused_the_ban(self):
        for suffix in (".png", ".svg", ".ico", ".gif"):
            with self.subTest(suffix=suffix):
                self.assertIn(suffix, self.suffixes())

    def test_it_covers_the_rest_of_the_ordinary_asset_types(self):
        for suffix in (".css", ".js", ".map", ".woff2", ".jpg", ".webp"):
            with self.subTest(suffix=suffix):
                self.assertIn(suffix, self.suffixes())

    def test_it_does_not_forgive_the_plausible_targets(self):
        # Wider than the engine here would be a way to hide from the counter
        # by naming a probe /config.json or /.env.txt.
        for suffix in (".json", ".xml", ".txt", ".php", ".env", ".sql"):
            with self.subTest(suffix=suffix):
                self.assertNotIn(suffix, self.suffixes())


class ItIsAppliedToBothCounters(unittest.TestCase):
    def setUp(self):
        self.source = TEMPLATE.read_text(encoding="utf-8")

    def test_the_per_site_counter_skips_assets(self):
        self.assertIn(
            "set-var(txn.site_{{ id }}_excl) bool(true) if err_asset_path",
            self.source,
        )

    def test_the_catch_all_counter_skips_assets(self):
        self.assertIn(
            "set-var(txn.other_excl) bool(true) if err_asset_path",
            self.source,
        )

    def test_the_exclusion_is_set_after_the_flag_is_cleared(self):
        # bool(false) then bool(true): the other way round clears it again
        # and the whole thing does nothing, which is exactly how err_exclude
        # spent months doing nothing.
        for var in ("txn.other_excl", "txn.site_{{ id }}_excl"):
            with self.subTest(var=var):
                cleared = self.source.index(f"set-var({var}) bool(false)")
                asset = self.source.index(
                    f"set-var({var}) bool(true) if err_asset_path")
                self.assertLess(cleared, asset)

    def test_a_configured_exclusion_still_works_alongside_it(self):
        # The per-site err_exclude rules must still be rendered; the asset
        # rule is an addition, not a replacement.
        self.assertIn("site_{{ id }}_ex{{ rule }}_path", self.source)


class TheTwoLayersAgree(unittest.TestCase):
    """The engine and the counter should not disagree about what an asset is."""

    def test_every_suffix_the_counter_forgives_the_engine_forgives_too(self):
        import importlib.util
        import sys

        guardd_path = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
            / "easy-ha-proxy-guardd.py"
        )
        spec = importlib.util.spec_from_file_location("guardd_assets",
                                                      guardd_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["guardd_assets"] = module
        spec.loader.exec_module(module)

        source = TEMPLATE.read_text(encoding="utf-8")
        counter = set()
        for line in source.splitlines():
            if line.strip().startswith("acl err_asset_path"):
                counter.update(
                    re.findall(r"\.[a-z0-9]+", line.split("-i", 1)[1])
                )
        engine = set(module.ASSET_SUFFIXES)
        # The counter may forgive less than the engine, never more: anything
        # it waves through must already be something the engine ignores.
        self.assertEqual(counter - engine, set())


if __name__ == "__main__":
    unittest.main()
