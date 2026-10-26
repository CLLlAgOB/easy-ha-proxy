"""A site without an icon of its own gets a neutral one.

Browsers ask every site for /favicon.ico on every page view. A site that has
none answers 404 each time: no icon in the tab and a 404 line in the log for
every visit. The 404 never counted toward a ban -- .ico is an asset -- so this
was only ever noise, but noise on every page.

The gateway now answers that one 404 with a neutral icon. Only the 404 is
replaced, so a site's own icon always wins and a site that is down still
answers 503. On by default, switched off per site or for all sites with
`default_favicon: false`.
"""

from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "ansible/roles/haproxy/templates"
ICON = ROOT / "ansible/roles/haproxy/files/default-favicon.ico"
DEPLOYED = "/etc/haproxy/errors/default-favicon.ico"
sys.path.insert(0, str(ROOT / "docker" / "app"))
sys.path.insert(0, str(ROOT / "installer"))

from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine,
    jinja_regex_replace,
)


def render(site_defaults, **site):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)), trim_blocks=True, lstrip_blocks=True
    )
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    entry = {"name": "shop", "domain": "shop.example.test",
             "backend_ip": "10.0.0.10", "backend_port": 8080}
    entry.update(site)
    return environment.get_template("haproxy.cfg.j2").render(
        sites=[entry],
        tcp_proxies=[], tcp=[], site_defaults=site_defaults,
        admin_domain="admin.example.test", aut_domain="auth.example.test",
        authelia_enabled=True, enable_geoip=False,
        easy_ha_proxy_runtime_vars={}, easy_ha_proxy_runtime_websites={},
        easy_ha_proxy_runtime_tcp={},
    )


def site_backend(config):
    return config.split("\nbackend be_shop\n")[1].split("\nbackend ")[0]


class TheRule(unittest.TestCase):
    def test_on_by_default_and_only_for_a_404_on_favicon(self):
        backend = site_backend(render({}))
        self.assertIn(
            "http-request set-var(txn.favicon_req) bool(true) if { path /favicon.ico }",
            backend,
        )
        rule = [line for line in backend.splitlines() if "http-response return" in line]
        self.assertEqual(len(rule), 1)
        self.assertIn(f"file {DEPLOYED}", rule[0])
        self.assertIn('content-type "image/x-icon"', rule[0])
        self.assertIn("{ status 404 }", rule[0])
        self.assertIn("{ var(txn.favicon_req) -m bool }", rule[0])
        self.assertIn('Cache-Control "public, max-age=86400"', rule[0])

    def test_a_site_can_switch_it_off(self):
        self.assertNotIn("favicon", site_backend(render({}, default_favicon=False)))

    def test_it_can_be_switched_off_for_every_site(self):
        self.assertNotIn("favicon", site_backend(render({"default_favicon": False})))

    def test_a_site_setting_wins_over_the_default(self):
        backend = site_backend(render({"default_favicon": False}, default_favicon=True))
        self.assertIn("default-favicon.ico", backend)


class NoTcpRuleBelowAnHttpRule(unittest.TestCase):
    """HAProxy runs tcp-request rules before http-request ones whatever the
    order, and warns about every tcp-request written below an http-request.
    The favicon rule first went in at the top of each site backend, above
    the ban check, and produced one warning per site on the next config
    check. Checked over every section, so the next such slip is caught too.
    """

    def sections(self, config):
        current, found = None, {}
        for line in config.splitlines():
            if line and not line[0].isspace() and line.split()[0] in (
                "frontend", "backend", "listen", "defaults",
            ):
                current = line.strip()
                found[current] = []
            elif current and line.strip() and not line.strip().startswith("#"):
                found[current].append(line.strip())
        return found

    def test_every_section_keeps_tcp_request_rules_on_top(self):
        for site_defaults, site in (
            ({}, {}),
            ({}, {"authelia_enabled": True}),
            ({"default_favicon": False}, {}),
        ):
            config = render(site_defaults, **site)
            for name, rules in self.sections(config).items():
                http = [i for i, r in enumerate(rules) if r.startswith("http-request ")]
                tcp = [i for i, r in enumerate(rules) if r.startswith("tcp-request ")]
                if http and tcp:
                    with self.subTest(section=name, site=site, defaults=site_defaults):
                        self.assertLess(max(tcp), min(http))


class ThePanelKeepsTheSetting(unittest.TestCase):
    """The site form builds a site from scratch, so a key it does not know is
    dropped on the next save. The switch has to live in the form."""

    def test_the_site_form_offers_and_sends_it(self):
        app = ROOT / "docker/app/haproxy_admin"
        page = (app / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        script = (app / "static/js/haproxy_site_edit.js").read_text(encoding="utf-8")
        self.assertIn('<select id="default_favicon" name="default_favicon"', page)
        self.assertIn('tristateSelectValue("default_favicon")', script)
        self.assertIn("site.default_favicon = favicon;", script)
        # Meaningless for TCP passthrough, like HSTS.
        self.assertIn("delete site.default_favicon;", script)
        self.assertIn('getElementById("row-default-favicon")', script)

    def test_the_defaults_editor_offers_the_global_switch(self):
        source = (ROOT / "docker/app/haproxy_admin/services_haproxy_vars.py").read_text(
            encoding="utf-8"
        )
        block = source.split('"site_defaults.default_favicon"')[1].split("),")[0]
        self.assertIn('"boolean"', block)
        self.assertIn("default=True", block)


class TheFile(unittest.TestCase):
    def test_the_role_deploys_it_where_the_template_reads_it(self):
        tasks = (ROOT / "ansible/roles/haproxy/tasks/install.yml").read_text(encoding="utf-8")
        block = tasks.split("- name: Deploy the default favicon")[1].split("- name:")[0]
        self.assertIn("src: default-favicon.ico", block)
        self.assertIn(f"dest: {DEPLOYED}", block)
        self.assertIn('mode: "0644"', block)
        # In the same block as the error pages the template already names,
        # so it is in place before any configuration that names it.
        self.assertLess(
            tasks.index("Deploy access granted page"),
            tasks.index("Deploy the default favicon"),
        )

    def test_it_is_a_valid_small_icon(self):
        data = ICON.read_bytes()
        reserved, kind, count = struct.unpack("<HHH", data[:6])
        self.assertEqual((reserved, kind), (0, 1))
        self.assertGreaterEqual(count, 1)
        width, height, _, _, _, _, size, offset = struct.unpack("<BBBBHHII", data[6:22])
        self.assertEqual((width, height), (32, 32))
        payload = data[offset:offset + size]
        self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")
        # HAProxy keeps a `return file` in one buffer; stay far below it.
        self.assertLess(len(data), 4096)


if __name__ == "__main__":
    unittest.main()
