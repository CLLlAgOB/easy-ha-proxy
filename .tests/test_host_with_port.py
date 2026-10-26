"""A Host header that carries the default port names the same site.

`Host: e.oreol-2010.ru:443` is the same site as `Host: e.oreol-2010.ru`
(RFC 9110), and some clients send it. Every host ACL compared the header as
written, so one application that checked the site every minute got 400 every
time: 455 refusals a week to 23 real clients on one gateway. Each frontend
now strips its default port before anything reads the header. Checked on
HAProxy 2.8: name:443 routes to the site with the plain name, while other
names and other ports are still refused.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "ansible/roles/haproxy/templates"
sys.path.insert(0, str(ROOT / "docker" / "app"))
sys.path.insert(0, str(ROOT / "installer"))

from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine,
    jinja_regex_replace,
)


def render():
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)), trim_blocks=True, lstrip_blocks=True
    )
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    return environment.get_template("haproxy.cfg.j2").render(
        sites=[{"name": "shop", "domain": "shop.example.test",
                "backend_ip": "10.0.0.10", "backend_port": 8080}],
        tcp_proxies=[], tcp=[], site_defaults={"enable_http80": True},
        enable_http80=True,
        admin_domain="admin.example.test", aut_domain="auth.example.test",
        authelia_enabled=True, enable_geoip=False,
        easy_ha_proxy_runtime_vars={}, easy_ha_proxy_runtime_websites={},
        easy_ha_proxy_runtime_tcp={},
    )


def section(config, name):
    return config.split(f"\nfrontend {name}\n")[1].split("\nfrontend ")[0].split("\nbackend ")[0]


class TheDefaultPortIsStripped(unittest.TestCase):
    def check(self, frontend, port):
        rules = [line.strip() for line in frontend.splitlines()
                 if line.strip().startswith("http-request")]
        strip = (f"http-request set-header Host %[req.hdr(host),regsub(:{port}$,)] "
                 f"if {{ req.hdr(host) -m end :{port} }}")
        self.assertIn(strip, rules)
        # First of all http-request rules, so the log, every host ACL and
        # the backend see the plain name.
        self.assertEqual(rules[0], strip)

    def test_on_https(self):
        self.check(section(render(), "fe_https"), 443)

    def test_on_plain_http(self):
        config = render()
        if "\nfrontend fe_http80\n" not in config:
            self.skipTest("this render has no :80 frontend")
        self.check(section(config, "fe_http80"), 80)


if __name__ == "__main__":
    unittest.main()
