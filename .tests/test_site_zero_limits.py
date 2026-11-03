"""A zero in a site's limits survives the editor (F08).

From the 30 October review: the editor wrote `site.max_req_rate or ''`,
so a stored 0 showed as an empty field, the editor then left the key out,
and saving brought the inherited limit back -- while for HAProxy a site's
max_req_rate of 0 means no limit at all. The help text said "0 or empty --
the default", which matched neither.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402

APP = ROOT / "docker/app/haproxy_admin"


class TheEditor(unittest.TestCase):
    """The value attribute, rendered from the template's own expression."""

    def value(self, stored):
        source = (APP / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        line = next(text for text in source.splitlines()
                    if 'value="{{ site.max_req_rate' in text)
        expression = line.split('value="')[1].rsplit('"', 1)[0]
        return Environment().from_string(expression).render(site=stored)

    def test_a_stored_zero_shows_as_zero(self):
        self.assertEqual(self.value({"max_req_rate": 0}), "0")

    def test_nothing_stored_shows_as_empty(self):
        self.assertEqual(self.value({}), "")
        self.assertEqual(self.value({"max_req_rate": None}), "")

    def test_a_number_shows_as_itself(self):
        self.assertEqual(self.value({"max_req_rate": 150}), "150")

    def test_err_limit_keeps_its_zero_too(self):
        source = (APP / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        self.assertIn("site.err_limit if site.err_limit is defined and site.err_limit is not none", source)
        self.assertNotIn("site.err_limit or ''", source)

    def test_the_editor_keeps_a_typed_zero(self):
        script = (APP / "static/js/haproxy_site_edit.js").read_text(encoding="utf-8")
        number = script.split("function numField(id) {")[1].split("}")[0]
        # Only an empty field means "inherit"; "0" parses to a number.
        self.assertIn("if (!s) return undefined;", number)


class WhatZeroMeans(unittest.TestCase):
    def test_zero_is_no_limit_and_empty_is_the_default(self):
        limited = render([site("shop", "shop.example.test")], site_defaults={"max_req_rate": 200})
        unlimited = render([site("shop", "shop.example.test", max_req_rate=0)],
                           site_defaults={"max_req_rate": 200})
        self.assertIn("tbl_rate_shop", limited)
        self.assertNotIn("too_fast_shop", unlimited)
        self.assertNotIn("tbl_rate_shop", unlimited)
        help_text = (APP / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        self.assertIn("0 — no limit for this site", help_text)
        self.assertNotIn("0 or empty", help_text)


if __name__ == "__main__":
    unittest.main()
