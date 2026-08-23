"""An exclusion the page offers has to reach the configuration.

A real user was banned for a week. Their mail client asked for a dozen
inline images that were not on the server, retried each four times, and
produced 71 errors in ten seconds against a limit of 50. The site edit page
has an editor for exactly this -- "Error accounting exclusions (err_exclude)"
with exact, prefix and regular-expression matching -- and the tracking rule
in the template has always consulted a variable named for it:

    http-request track-sc1 src table tbl_err_x if host_x ... !{ var(txn.site_x_excl) -m bool }

Nothing ever set that variable. It was initialised to false once per site
and left there, so a rule could be written, saved, redisplayed on the page
and rendered into websites.yml while changing nothing whatsoever.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ansible" / "roles" / "haproxy" / "templates"
TEMPLATE = TEMPLATES / "haproxy.cfg.j2"
sys.path.insert(0, str(ROOT / "docker" / "app"))

try:
    from jinja2 import Environment, FileSystemLoader

    # The same two filters Ansible supplies; the repository already exposes
    # them for exactly this purpose.
    from haproxy_admin.services_haproxy_config import (
        jinja_combine,
        jinja_regex_replace,
    )
except ImportError:  # pragma: no cover
    Environment = None


@unittest.skipIf(Environment is None, "jinja2 is not installed")
class RenderTests(unittest.TestCase):
    """Render the real template and read what HAProxy would be given."""

    def render(self, err_exclude):
        environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = jinja_regex_replace
        environment.filters["combine"] = jinja_combine
        site = {
            "name": "mail.example.com",
            "domain": "mail.example.com",
            "backend_ip": "10.0.0.1",
            "backend_port": 5010,
            "err_limit": 250,
        }
        if err_exclude is not None:
            site["err_exclude"] = err_exclude
        return environment.get_template("haproxy.cfg.j2").render(
            sites=[site],
            tcp_proxies=[],
            tcp=[],
            site_defaults={},
            admin_domain="admin.example.test",
            aut_domain="auth.example.test",
            authelia_enabled=True,
            enable_geoip=True,
            easy_ha_proxy_runtime_vars={},
            easy_ha_proxy_runtime_websites={},
            easy_ha_proxy_runtime_tcp={},
        )

    def setUp(self):
        try:
            self.baseline = self.render(None)
        except Exception as exc:  # pragma: no cover - template needs more vars
            raise unittest.SkipTest(f"cannot render the template alone: {exc}")

    def test_a_site_without_exclusions_declares_none(self):
        self.assertIn("set-var(txn.site_mail_example_com_excl) bool(false)", self.baseline)
        self.assertNotIn("site_mail_example_com_ex1_path", self.baseline)

    def test_an_exact_path_rule_is_rendered(self):
        rendered = self.render([{"path": "/", "methods": ["GET"]}])
        self.assertIn("acl site_mail_example_com_ex1_path path -i /", rendered)
        self.assertIn("acl site_mail_example_com_ex1_meth method GET", rendered)

    def test_a_prefix_rule_uses_path_beg(self):
        # The shape the banned user needed: every attachment under one path.
        rendered = self.render([{"path_beg": "/webapi/entry.cgi"}])
        self.assertIn(
            "acl site_mail_example_com_ex1_path path_beg -i /webapi/entry.cgi",
            rendered,
        )

    def test_a_regular_expression_rule_uses_path_reg(self):
        rendered = self.render([{"path_reg": "^/static/"}])
        self.assertIn(
            "acl site_mail_example_com_ex1_path path_reg -i ^/static/", rendered
        )

    def test_the_variable_is_actually_set(self):
        # The whole defect: the rule existed and nothing ever set it true.
        rendered = self.render([{"path_beg": "/webapi/entry.cgi"}])
        self.assertIn(
            "set-var(txn.site_mail_example_com_excl) bool(true)", rendered
        )

    def test_the_rule_is_scoped_to_its_own_site(self):
        # Without the host guard one site's exclusion would silence errors
        # for every other site sharing the frontend.
        rendered = self.render([{"path_beg": "/webapi/entry.cgi"}])
        # The configured rule specifically. The same variable is also set
        # for any static asset, which is a separate line and deliberately
        # not host-scoped: it applies to every site.
        line = [
            row for row in rendered.splitlines()
            if "site_mail_example_com_excl) bool(true)" in row
            and "_ex1_path" in row
        ][0]
        self.assertIn("host_mail_example_com", line)

    def test_methods_are_optional(self):
        rendered = self.render([{"path_beg": "/webapi/"}])
        self.assertNotIn("site_mail_example_com_ex1_meth", rendered)
        line = [
            row for row in rendered.splitlines()
            if "site_mail_example_com_excl) bool(true)" in row
            and "_ex1_path" in row
        ][0]
        self.assertTrue(line.rstrip().endswith("_ex1_path"))

    def test_several_rules_get_distinct_names(self):
        rendered = self.render([
            {"path": "/", "methods": ["GET"]},
            {"path_beg": "/webapi/entry.cgi"},
        ])
        self.assertIn("site_mail_example_com_ex1_path", rendered)
        self.assertIn("site_mail_example_com_ex2_path", rendered)

    def test_an_empty_rule_renders_nothing(self):
        # A row left blank on the page must not produce an acl matching all.
        rendered = self.render([{"path": "", "methods": ["GET"]}, {}])
        self.assertNotIn("site_mail_example_com_ex1_path", rendered)
        self.assertNotIn("site_mail_example_com_ex2_path", rendered)

    def test_the_exclusion_still_gates_the_tracking_rule(self):
        rendered = self.render([{"path_beg": "/webapi/entry.cgi"}])
        tracking = [
            row for row in rendered.splitlines()
            if "track-sc1 src table tbl_err_mail_example_com" in row
        ]
        self.assertTrue(tracking)
        self.assertIn("site_mail_example_com_excl", tracking[0])


class SourceTests(unittest.TestCase):
    """Readable without a Jinja environment, so it runs everywhere."""

    def setUp(self):
        self.source = TEMPLATE.read_text(encoding="utf-8")

    def test_the_template_knows_the_three_shapes_the_page_offers(self):
        for key in ("ex.path", "ex.path_beg", "ex.path_reg"):
            with self.subTest(key=key):
                self.assertIn(key, self.source)

    def test_the_page_and_the_template_agree_on_the_shapes(self):
        page = (
            ROOT / "docker" / "app" / "haproxy_admin" / "templates"
            / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        offered = set(re.findall(r'<option value="(path[a-z_]*)"', page))
        self.assertEqual(offered, {"path", "path_beg", "path_reg"})
        for key in offered:
            self.assertIn(f"ex.{key}", self.source)


if __name__ == "__main__":
    unittest.main()
