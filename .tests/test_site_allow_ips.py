"""A site reachable only from named addresses.

The point of the mode is not just the deny: it is that naming the addresses
*is* the access policy, so the gates that exist to sort strangers out stop
applying. Most of these tests are therefore about what the configuration no
longer contains.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "ansible/roles/haproxy/templates"
APP_DIR = ROOT / "docker/app/haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import validation  # noqa: E402
from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine,
    jinja_regex_replace,
)
from haproxy_admin.services_haproxy_sites import _normalize_allow_ips  # noqa: E402


def render(sites, **extra):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    context = {
        "sites": sites,
        "tcp_proxies": [],
        "tcp": [],
        "site_defaults": {},
        "admin_domain": "admin.example.test",
        "aut_domain": "auth.example.test",
        "authelia_enabled": True,
        "enable_geoip": True,
        "easy_ha_proxy_runtime_vars": {},
        "easy_ha_proxy_runtime_websites": {},
        "easy_ha_proxy_runtime_tcp": {},
    }
    context.update(extra)
    return environment.get_template("haproxy.cfg.j2").render(**context)


def site(name, domain, **extra):
    base = {
        "name": name,
        "domain": domain,
        "backend_ip": "10.0.0.10",
        "backend_port": 8080,
    }
    base.update(extra)
    return base


LOCKED = dict(
    allow_ips=["203.0.113.7", "198.51.100.0/24"],
    authelia_enabled=True,
    zero_trust=True,
    geo_countries=["RU"],
    rate_ban=True,
    max_req_rate=100,
)


class GateTests(unittest.TestCase):
    def rendered(self):
        return render([
            site("locked", "locked.example.test", **LOCKED),
            site("open", "open.example.test", authelia_enabled=True, zero_trust=True),
        ])

    def test_only_the_named_addresses_are_let_in(self):
        config = self.rendered()
        self.assertIn(
            "acl site_ips_locked src 203.0.113.7 198.51.100.0/24", config
        )
        self.assertIn(
            "http-request deny status 403 if host_locked !site_ips_locked", config
        )

    def test_a_site_without_a_list_is_untouched(self):
        config = self.rendered()
        self.assertNotIn("site_ips_open", config)

    def test_the_country_filter_no_longer_applies(self):
        config = self.rendered()
        self.assertNotIn("geo_allowed_locked", config)
        for line in config.splitlines():
            if "status 451" in line:
                self.assertNotIn("host_locked", line, line)

    def test_authelia_is_not_asked(self):
        # Naming the address is the authorisation. Leaving forward-auth on
        # would demand a login from someone already vouched for by name.
        config = self.rendered()
        protected = next(
            line for line in config.splitlines()
            if line.strip().startswith("acl authelia_protected")
        )
        self.assertNotIn("locked.example.test", protected)
        self.assertIn("open.example.test", protected)

    def test_zero_trust_is_not_applied(self):
        config = self.rendered()
        for line in config.splitlines():
            if "ip_auth_ok" in line and "deny" in line:
                self.assertNotIn("host_locked", line, line)

    def test_the_adaptive_counters_leave_it_alone(self):
        # One monitoring check that 404s ten times would otherwise ban an
        # address the operator listed on purpose.
        config = self.rendered()
        self.assertNotIn("tbl_err_locked", config)
        self.assertNotIn("tbl_rate_locked", config)
        self.assertIn("tbl_err_open", config)

    def test_the_refusal_comes_before_the_backend_is_chosen(self):
        config = self.rendered()
        deny = config.index("deny status 403 if host_locked !site_ips_locked")
        backend = config.index("use_backend be_locked")
        self.assertLess(deny, backend)

    def test_a_network_and_a_host_can_be_mixed(self):
        config = render([site("x", "x.example.test", allow_ips=["10.0.0.0/8", "1.2.3.4"])])
        self.assertIn("acl site_ips_x src 10.0.0.0/8 1.2.3.4", config)


class NormalisationTests(unittest.TestCase):
    def test_a_host_written_as_a_network_becomes_the_host(self):
        # "10.0.0.5/32" is a host; "10.0.0.5/24" is almost certainly a typo
        # for one, and HAProxy would read it as the whole network.
        self.assertEqual(_normalize_allow_ips(["10.0.0.5/32"]), ["10.0.0.5"])

    def test_a_network_keeps_its_canonical_form(self):
        self.assertEqual(_normalize_allow_ips(["10.0.0.5/24"]), ["10.0.0.0/24"])

    def test_text_from_a_textarea_is_accepted(self):
        self.assertEqual(
            _normalize_allow_ips("203.0.113.7\n 198.51.100.9 ,10.0.0.0/8"),
            ["203.0.113.7", "198.51.100.9", "10.0.0.0/8"],
        )

    def test_duplicates_are_dropped_and_order_is_kept(self):
        self.assertEqual(
            _normalize_allow_ips(["1.2.3.4", "5.6.7.8", "1.2.3.4"]),
            ["1.2.3.4", "5.6.7.8"],
        )

    def test_ipv6_is_accepted(self):
        self.assertEqual(_normalize_allow_ips(["2001:db8::1"]), ["2001:db8::1"])

    def test_nonsense_is_refused(self):
        for bad in ("not-an-ip", "999.1.1.1", "10.0.0.1/33", "1.2.3.4 evil"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _normalize_allow_ips([bad])

    def test_an_empty_list_means_the_mode_is_off(self):
        self.assertEqual(_normalize_allow_ips([]), [])
        self.assertEqual(_normalize_allow_ips(None), [])


class ValidationTests(unittest.TestCase):
    def test_the_site_validator_refuses_a_bad_entry(self):
        with self.assertRaises(ValueError):
            validation._validate_site(
                {"name": "x", "domain": "x.example.test", "allow_ips": ["nope"]}, 0
            )

    def test_and_accepts_addresses_and_networks(self):
        validation._validate_site(
            {
                "name": "x",
                "domain": "x.example.test",
                "allow_ips": ["203.0.113.7", "2001:db8::/32"],
            },
            0,
        )

    def test_the_list_is_bounded(self):
        with self.assertRaises(ValueError):
            validation._validate_site(
                {
                    "name": "x",
                    "domain": "x.example.test",
                    "allow_ips": [f"10.0.0.{n}" for n in range(70)],
                },
                0,
            )


if __name__ == "__main__":
    unittest.main()
