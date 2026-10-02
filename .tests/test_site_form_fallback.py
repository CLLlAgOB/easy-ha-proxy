"""The no-JavaScript site save must overlay the form, not replace the site.

The editor normally saves through JavaScript, which posts the whole site as
JSON. The plain HTML form carries only its own controls, so a save that built
the site from those alone silently dropped everything else it held.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker" / "app"
PACKAGE_ROOT = APP_ROOT / "haproxy_admin"
sys.path.insert(0, str(APP_ROOT))

# services.py imports fcntl, so the package only loads on a POSIX host. Any
# other import failure is a real one and must not be hidden behind a skip.
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import routes_haproxy_config as routes_config
    from haproxy_admin import services_haproxy_config as config_service
    from haproxy_admin import services_haproxy_sites as sites_service


STORED_SITE = {
    "name": "shop",
    "domain": "shop.example.test",
    "backend_ip": "10.0.0.5",
    "backend_port": 8080,
    "certificate_source": "external",
    "external_ca_id": "corp-ca",
    "le_managed": False,
    "key_types": ["ecdsa", "rsa"],
    "servers": [
        {"name": "srv1", "host": "10.0.0.5", "port": 8080},
        {"name": "srv2", "host": "10.0.0.6", "port": 8080},
    ],
    "err_exclude": [{"path_beg": "/health"}],
    "geo_countries": ["DE", "PL"],
    "access_gate": False,
    "alert_enabled": True,
    "alert_mode": "down",
    "alert_after": "5m",
    "alert_email": "ops@example.test",
    "balance": "leastconn",
    "sticky": "cookie",
    "compress": True,
    "health_uri": "/healthz",
}


def form(**overrides):
    """What the browser actually posts for this site with JavaScript off."""
    submitted = {
        "action": "save",
        "domain": "shop.example.test",
        "backend_ip": "10.0.0.5",
        "backend_port": "8080",
        "alt_names": "",
        "acme_challenge": "http-01",
        "dns_profile": "",
        "cert_alt_names": "",
        "backend_host": "",
        "health_uri": "/healthz",
        "hsts": "",
        "waf": "",
        "max_req_rate": "",
        "health_status": "",
        "compress": "true",
        "redirect_to_https": "",
        "authelia_enabled": "",
        "zero_trust": "",
        "backend_ssl": "",
        "backend_ssl_verify": "",
        "maintenance": "",
        "rate_ban": "",
    }
    submitted.update(overrides)
    return submitted


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class MergeTests(unittest.TestCase):
    def merge(self, **overrides):
        site, error = routes_haproxy_merge(**overrides)
        self.assertEqual(error, "", error)
        return site

    def test_a_port_change_keeps_everything_the_form_cannot_express(self):
        site = self.merge(backend_port="9090")
        self.assertEqual(site["backend_port"], 9090)
        for key in (
            "certificate_source",
            "external_ca_id",
            "le_managed",
            "key_types",
            "servers",
            "err_exclude",
            "geo_countries",
            "alert_enabled",
            "alert_email",
            "balance",
            "sticky",
        ):
            self.assertEqual(site[key], STORED_SITE[key], key)

    def test_an_absent_control_leaves_its_key_alone(self):
        # A form that never carried health_uri must not clear it.
        submitted = form()
        submitted.pop("health_uri")
        site, error = routes_config.merge_site_from_edit_form(
            "shop", STORED_SITE, submitted
        )
        self.assertEqual(error, "")
        self.assertEqual(site["health_uri"], "/healthz")

    def test_an_empty_control_clears_its_key(self):
        # Emptying a field is how the operator returns it to the site default,
        # so this has to stay distinguishable from the case above.
        site = self.merge(health_uri="")
        self.assertNotIn("health_uri", site)

    def test_a_tristate_returns_to_the_default_when_left_unset(self):
        site = self.merge(compress="")
        self.assertNotIn("compress", site)

    def test_a_tristate_can_be_switched_off(self):
        site = self.merge(compress="false")
        self.assertIs(site["compress"], False)

    def test_the_stored_site_is_not_mutated(self):
        before = yaml.safe_dump(STORED_SITE, sort_keys=True)
        self.merge(backend_port="9090", health_uri="")
        self.assertEqual(yaml.safe_dump(STORED_SITE, sort_keys=True), before)

    def test_the_required_fields_are_still_required(self):
        for field in ("domain", "backend_ip", "backend_port"):
            site, error = routes_config.merge_site_from_edit_form(
                "shop", STORED_SITE, form(**{field: ""})
            )
            self.assertEqual(site, {}, field)
            self.assertIn("required", error)

    def test_a_rejected_save_produces_no_site_at_all(self):
        # Returning a half-merged site would let the caller persist it.
        for overrides, needle in (
            ({"backend_port": "not-a-number"}, "backend_port"),
            ({"backend_port": "70000"}, "backend_port"),
            ({"max_req_rate": "lots"}, "max_req_rate"),
            ({"health_status": "OK"}, "health_status"),
        ):
            site, error = routes_config.merge_site_from_edit_form(
                "shop", STORED_SITE, form(**overrides)
            )
            self.assertEqual(site, {}, str(overrides))
            self.assertIn(needle, error)

    def test_no_checkbox_backed_key_is_touched(self):
        # An unchecked checkbox is simply absent, which is indistinguishable
        # from a form that never carried it, so the fallback must not try.
        handled = set(routes_config.FORM_TEXT_FIELDS)
        handled |= set(routes_config.FORM_NUMBER_FIELDS)
        handled |= set(routes_config.FORM_TRISTATE_FIELDS)
        template = (
            PACKAGE_ROOT / "templates" / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        for field in sorted(handled):
            control = _control_for(template, field)
            self.assertIsNotNone(control, field)
            self.assertNotIn('type="checkbox"', control, field)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class DnsProfileTests(unittest.TestCase):
    def test_switching_to_http_drops_the_profile_and_the_wildcard(self):
        stored = dict(STORED_SITE)
        stored["dns_profile"] = "my-cloudflare"
        stored["cert_alt_names"] = ["*.shop.example.test"]
        site, error = routes_config.merge_site_from_edit_form(
            "shop", stored, form(acme_challenge="http-01")
        )
        self.assertEqual(error, "")
        self.assertNotIn("dns_profile", site)
        # The wildcard only existed because DNS-01 could validate it.
        self.assertNotIn("cert_alt_names", site)

    def test_choosing_dns_without_a_profile_stores_neither(self):
        site, error = routes_config.merge_site_from_edit_form(
            "shop",
            STORED_SITE,
            form(
                acme_challenge="dns-01",
                dns_profile="",
                cert_alt_names="*.shop.example.test",
            ),
        )
        self.assertEqual(error, "")
        self.assertNotIn("dns_profile", site)
        self.assertNotIn("cert_alt_names", site)

    def test_a_profile_and_its_wildcard_are_stored_together(self):
        site, error = routes_config.merge_site_from_edit_form(
            "shop",
            STORED_SITE,
            form(
                acme_challenge="dns-01",
                dns_profile="my-cloudflare",
                cert_alt_names="*.shop.example.test\n",
            ),
        )
        self.assertEqual(error, "")
        self.assertEqual(site["dns_profile"], "my-cloudflare")
        self.assertEqual(site["cert_alt_names"], ["*.shop.example.test"])

    def test_an_absent_challenge_control_leaves_the_profile_alone(self):
        stored = dict(STORED_SITE)
        stored["dns_profile"] = "my-cloudflare"
        submitted = form()
        submitted.pop("acme_challenge")
        site, error = routes_config.merge_site_from_edit_form(
            "shop", stored, submitted
        )
        self.assertEqual(error, "")
        self.assertEqual(site["dns_profile"], "my-cloudflare")


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class PersistenceTests(unittest.TestCase):
    """The merged site has to survive the writer and the whole-file validator."""

    def setUp(self):
        import tempfile

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.websites = Path(self.temporary.name) / "websites.yml"
        self.websites.write_text(
            yaml.safe_dump({"sites": [dict(STORED_SITE)]}, sort_keys=False),
            encoding="utf-8",
        )
        patches = (
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "BASE_DIR", Path(self.temporary.name)),
            mock.patch.object(
                config_service,
                "config_transaction_is_pending",
                return_value=(False, ""),
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        return yaml.safe_load(self.websites.read_text(encoding="utf-8"))["sites"][0]

    def test_a_port_only_save_round_trips_through_the_file(self):
        site, error = routes_config.merge_site_from_edit_form(
            "shop", STORED_SITE, form(backend_port="9090")
        )
        self.assertEqual(error, "")
        ok, message = sites_service.save_site_raw("shop", site)
        self.assertTrue(ok, message)

        stored = self.saved()
        self.assertEqual(stored["backend_port"], 9090)
        self.assertEqual(stored["certificate_source"], "external")
        self.assertEqual(stored["external_ca_id"], "corp-ca")
        self.assertEqual(stored["key_types"], ["ecdsa", "rsa"])
        self.assertEqual(len(stored["servers"]), 2)
        self.assertEqual(stored["err_exclude"], [{"path_beg": "/health"}])
        self.assertEqual(stored["geo_countries"], ["DE", "PL"])
        self.assertEqual(stored["alert_email"], "ops@example.test")


class RouteWiringTests(unittest.TestCase):
    """Readable without importing the package, so it runs on any host."""

    def setUp(self):
        self.source = (PACKAGE_ROOT / "routes_haproxy_config.py").read_text(
            encoding="utf-8"
        )

    def test_the_save_branch_overlays_the_stored_site(self):
        branch = self.source.split('elif action == "save":')[1].split(
            "\n    # ВАЖНО"
        )[0]
        self.assertIn(
            "merge_site_from_edit_form(\n                name, site_raw, request.form\n            )",
            branch,
        )
        # The old branch built a fresh dict; nothing may reintroduce that.
        self.assertNotIn('new_site = {', branch)

    def test_the_partial_save_says_so(self):
        self.assertIn("JavaScript was unavailable", self.source)


def _control_for(template: str, field: str):
    import re

    match = re.search(
        rf"<(?:input|select|textarea)[^>]*\bname=\"{re.escape(field)}\"[^>]*>",
        template,
    )
    return match.group(0) if match else None


def routes_haproxy_merge(**overrides):
    return routes_config.merge_site_from_edit_form(
        "shop", STORED_SITE, form(**overrides)
    )


if __name__ == "__main__":
    unittest.main()
