"""Connection limits fit how people actually use the gateway.

An office lost every site behind one gateway for an hour: a monitoring
dashboard reconnecting pushed its one address past 40 new connections in ten
seconds, every further attempt was refused before TLS and counted again, and
nothing reached the log. On a second gateway a user loading a web
application had sat exactly at 40 -- one request per connection, because an
idle browser connection was closed after five seconds and every poll opened
a new one.

The defaults are now 200 new connections per window and 500 open ones, and
an idle browser connection is kept for 30 seconds so it gets reused. A flood
still runs to thousands. Everywhere a default lives says the same number.
"""

from __future__ import annotations

from pathlib import Path
import re
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


def render(site_defaults):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)), trim_blocks=True, lstrip_blocks=True
    )
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    return environment.get_template("haproxy.cfg.j2").render(
        sites=[{"name": "shop", "domain": "shop.example.test",
                "backend_ip": "10.0.0.10", "backend_port": 8080}],
        tcp_proxies=[], tcp=[], site_defaults=site_defaults,
        admin_domain="admin.example.test", aut_domain="auth.example.test",
        authelia_enabled=True, enable_geoip=False,
        easy_ha_proxy_runtime_vars={}, easy_ha_proxy_runtime_websites={},
        easy_ha_proxy_runtime_tcp={},
    )


def https_frontend(config):
    return config.split("\nfrontend fe_https\n")[1].split("\nfrontend ")[0]


class TheRenderedConfiguration(unittest.TestCase):
    def test_a_gateway_with_no_setting_gets_the_new_limits(self):
        frontend = https_frontend(render({}))
        self.assertIn("sc0_conn_rate(fe_https) gt 200", frontend)
        self.assertIn("sc0_conn_cur(fe_https)  gt 500", frontend)
        self.assertIn("timeout http-keep-alive 30s", frontend)

    def test_a_value_set_by_the_operator_still_wins(self):
        frontend = https_frontend(render({
            "conn_rate_burst": 40, "conn_cur_limit": 100,
            "frontend_keepalive_timeout": "10s",
        }))
        self.assertIn("sc0_conn_rate(fe_https) gt 40", frontend)
        self.assertIn("sc0_conn_cur(fe_https)  gt 100", frontend)
        self.assertIn("timeout http-keep-alive 10s", frontend)


class EveryDefaultSaysTheSame(unittest.TestCase):
    def test_the_installer_writes_the_new_values(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        self.assertIn('"conn_rate_burst": 200,', source)
        self.assertIn('"conn_cur_limit": 500,', source)
        self.assertIn('"frontend_keepalive_timeout": "30s",', source)
        self.assertNotRegex(source, r'"conn_rate_burst": 40\b')

    def test_the_settings_page_shows_and_edits_them(self):
        source = (ROOT / "docker/app/haproxy_admin/services_haproxy_vars.py").read_text(
            encoding="utf-8"
        )
        for path, default in (
            ("site_defaults.conn_rate_burst", "default=200"),
            ("site_defaults.conn_cur_limit", "default=500"),
            ("site_defaults.frontend_keepalive_timeout", 'default="30s"'),
        ):
            with self.subTest(path=path):
                block = source.split(f'"{path}"')[1].split("),")[0]
                self.assertIn(default, block)

    def test_no_template_default_is_left_behind(self):
        template = (TEMPLATE_DIR / "haproxy.cfg.j2").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"conn_rate_burst \| default\(40\)", template))
        self.assertIsNone(re.search(r"conn_cur_limit \| default\(100\)", template))


if __name__ == "__main__":
    unittest.main()
