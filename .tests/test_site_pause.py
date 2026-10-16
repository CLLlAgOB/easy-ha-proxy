"""A site can be paused without being deleted.

A site's name was pointed straight at its server for a while, past the
gateway. The only ways to stop the gateway serving it -- and renewing its
certificate on a challenge that would now fail -- were to delete the site
and lose its configuration, or to leave everything running and watch the
renewal fail.

Two independent pauses now exist. "paused" takes the site out of HAProxy
entirely while keeping its settings; "cert_renewal_paused" stops its
certificate being renewed by certbot or reissued by the panel and the
installer. Only an explicit true pauses, so every site written before this
is unaffected.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from jinja2 import Environment, FileSystemLoader
import yaml


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "ansible/roles/haproxy/templates"
APP_DIR = ROOT / "docker/app/haproxy_admin"
CERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
HEALTHD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-healthd.py"
CERT_TARGETS = ROOT / "ansible/roles/cert/tasks/renew__00_targets.yml"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin.services_haproxy_config import (  # noqa: E402
    jinja_combine,
    jinja_regex_replace,
)

WINDOWS = sys.platform == "win32"
if not WINDOWS:
    from haproxy_admin import routes_haproxy_config as routes_config  # noqa: E402
    from haproxy_admin import services_haproxy_config as config_service  # noqa: E402
    from haproxy_admin import services_haproxy_sites as sites_service  # noqa: E402

SPEC = importlib.util.spec_from_file_location("haproxy_certd_pause", CERTD_PATH)
CERTD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTD)


def render(sites):
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["regex_replace"] = jinja_regex_replace
    environment.filters["combine"] = jinja_combine
    return environment.get_template("haproxy.cfg.j2").render(
        sites=sites,
        tcp_proxies=[],
        tcp=[],
        site_defaults={},
        admin_domain="admin.example.test",
        aut_domain="auth.example.test",
        authelia_enabled=True,
        enable_geoip=False,
        easy_ha_proxy_runtime_vars={},
        easy_ha_proxy_runtime_websites={},
        easy_ha_proxy_runtime_tcp={},
    )


def site(name, domain, **extra):
    base = {"name": name, "domain": domain, "backend_ip": "10.0.0.10", "backend_port": 8080}
    base.update(extra)
    return base


class APausedSiteIsNotPublished(unittest.TestCase):
    def test_it_disappears_from_haproxy_and_the_others_stay(self):
        config = render([
            site("live", "live.example.test"),
            site("quiet", "quiet.example.test", paused=True),
        ])
        self.assertIn("live.example.test", config)
        self.assertIn("backend be_live", config)
        self.assertNotIn("quiet.example.test", config)
        self.assertNotIn("be_quiet", config)

    def test_only_an_explicit_true_pauses(self):
        for value in (False, "true", "yes", 1, None):
            with self.subTest(value=value):
                config = render([site("shop", "shop.example.test", paused=value)])
                self.assertIn("backend be_shop", config)

    def test_a_passthrough_site_is_paused_too(self):
        config = render([
            site("live", "live.example.test"),
            site("tunnel", "tunnel.example.test", tcp_passthrough=True, paused=True),
        ])
        self.assertNotIn("tunnel.example.test", config)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePanelDoesNotIssueForAPausedSite(unittest.TestCase):
    def test_neither_pause_lets_the_pre_apply_check_issue(self):
        missing = {"state": "missing"}
        items = [
            {"raw": site("a", "a.example.test", paused=True), "effective": site("a", "a.example.test")},
            {"raw": site("b", "b.example.test", cert_renewal_paused=True), "effective": site("b", "b.example.test")},
            {"raw": site("c", "c.example.test"), "effective": site("c", "c.example.test")},
        ]
        with (
            mock.patch.object(sites_service, "get_sites_and_defaults_for_ui", return_value=({}, items)),
            mock.patch.object(sites_service, "get_cert_status_for_site", return_value=missing),
            mock.patch.object(sites_service, "issue_cert_for_domain", return_value={"ok": True}) as issue,
        ):
            result = sites_service.ensure_certs_before_apply()
        self.assertTrue(result["ok"])
        self.assertEqual([call.args[0] for call in issue.call_args_list], ["c.example.test"])


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class StoringThePauses(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.websites = Path(temporary.name) / "websites.yml"
        self.write([site("shop", "shop.example.test", paused=True, cert_renewal_paused=True)])
        for patcher in (
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(sites_service, "update_yaml_file", side_effect=self.save),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, sites):
        self.websites.write_text(yaml.safe_dump({"sites": sites}), encoding="utf-8")

    def save(self, kind, content):
        self.assertEqual(kind, "websites")
        self.websites.write_text(content, encoding="utf-8")
        return True, "saved"

    def stored(self):
        return yaml.safe_load(self.websites.read_text(encoding="utf-8"))["sites"][0]

    def test_an_editor_save_that_does_not_mention_them_keeps_them(self):
        # A page loaded before the pauses existed must not resume a site.
        ok, _ = sites_service.save_site_from_json(
            site("shop", "shop.example.test", backend_port=9090), original_name="shop"
        )
        self.assertTrue(ok)
        self.assertIs(self.stored()["paused"], True)
        self.assertIs(self.stored()["cert_renewal_paused"], True)
        self.assertEqual(self.stored()["backend_port"], 9090)

    def test_false_resumes_and_leaves_no_key_behind(self):
        sites_service.save_site_from_json(
            site("shop", "shop.example.test", paused=False, cert_renewal_paused=False),
            original_name="shop",
        )
        self.assertNotIn("paused", self.stored())
        self.assertNotIn("cert_renewal_paused", self.stored())

    def test_the_list_buttons_set_one_pause_and_keep_the_rest(self):
        self.write([site("shop", "shop.example.test", alert_enabled=True)])
        ok, _ = sites_service.set_site_pause("shop", "cert_renewal_paused", True)
        self.assertTrue(ok)
        self.assertIs(self.stored()["cert_renewal_paused"], True)
        self.assertIs(self.stored()["alert_enabled"], True)
        self.assertNotIn("paused", self.stored())
        sites_service.set_site_pause("shop", "cert_renewal_paused", False)
        self.assertNotIn("cert_renewal_paused", self.stored())

    def test_an_unknown_setting_or_site_is_refused(self):
        self.assertFalse(sites_service.set_site_pause("shop", "backend_port", True)[0])
        self.assertFalse(sites_service.set_site_pause("nope", "paused", True)[0])

    def test_certd_is_given_the_renewal_paused_domains(self):
        self.write([
            site("a", "A.example.test", cert_renewal_paused=True),
            site("b", "b.example.test", paused=True),
            site("c", "c.example.test"),
        ])
        self.assertEqual(sites_service.renewal_paused_domains(), ["a.example.test"])
        # Other tests stand a stub in for the client module; patch whichever
        # module the package hands out, creating the name on a stub.
        from haproxy_admin import certd_client

        with mock.patch.object(
            certd_client, "set_renewal_pauses", side_effect=OSError("down"), create=True
        ):
            self.assertFalse(sites_service.sync_renewal_pauses()["ok"])
        with mock.patch.object(
            certd_client, "set_renewal_pauses", return_value={"ok": True}, create=True
        ) as told:
            sites_service.sync_renewal_pauses()
        told.assert_called_once_with(["a.example.test"])

    def test_the_plain_form_carries_them(self):
        form = {
            "domain": "shop.example.test", "backend_ip": "10.0.0.10",
            "backend_port": "8080", "paused": "true", "cert_renewal_paused": "false",
        }
        merged, error = routes_config.merge_site_from_edit_form(
            "shop", site("shop", "shop.example.test", cert_renewal_paused=True), form
        )
        self.assertEqual(error, "")
        self.assertIs(merged["paused"], True)
        self.assertNotIn("cert_renewal_paused", merged)

    def test_the_list_actions_map_to_the_keys(self):
        self.assertEqual(
            routes_config.PAUSE_ACTIONS,
            {
                "pause": ("paused", True),
                "resume": ("paused", False),
                "pause_renewal": ("cert_renewal_paused", True),
                "resume_renewal": ("cert_renewal_paused", False),
            },
        )

    def test_every_apply_restates_the_renewal_pauses(self):
        source = (APP_DIR / "routes_haproxy_config.py").read_text(encoding="utf-8")
        apply = source.split("def haproxy_config_apply(")[1].split("\ndef ")[0]
        self.assertLess(apply.index("sync_renewal_pauses()"), apply.index("ensure_certs_before_apply()"))


RENEWAL = """version = 2.11.0
archive_dir = /etc/letsencrypt/archive/{name}
cert = /etc/letsencrypt/live/{name}/cert.pem

# Options used in the renewal process
[renewalparams]
account = 0123456789abcdef
authenticator = webroot
server = https://acme-v02.api.letsencrypt.org/directory
"""


class CertbotIsToldToSkipIt(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.renewal = root / "renewal"
        self.renewal.mkdir()
        patcher = mock.patch.object(CERTD, "LETSENCRYPT_ROOT_DIR", root)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("shop.example.test-ecdsa", "shop.example.test-rsa-0001",
                     "blog.example.test", "example.test"):
            self.write(name, RENEWAL.format(name=name))

    def write(self, name, text):
        path = self.renewal / f"{name}.conf"
        path.write_text(text, encoding="utf-8")
        os.chmod(path, 0o640)

    def read(self, name):
        return (self.renewal / f"{name}.conf").read_text(encoding="utf-8")

    def paused(self, name):
        params = self.read(name).split("[renewalparams]")[1]
        return "autorenew = False" in params

    def test_every_lineage_of_the_domain_is_paused_and_nothing_else(self):
        result = CERTD.sync_renewal_pauses(["shop.example.test"])
        self.assertTrue(self.paused("shop.example.test-ecdsa"))
        self.assertTrue(self.paused("shop.example.test-rsa-0001"))
        self.assertFalse(self.paused("blog.example.test"))
        # A lineage named after the parent domain may be a wildcard shared by
        # other sites; it is not this site's to pause.
        self.assertFalse(self.paused("example.test"))
        self.assertEqual(
            result["paused"], ["shop.example.test-ecdsa", "shop.example.test-rsa-0001"]
        )

    def test_the_switch_is_inside_renewalparams_where_certbot_reads_it(self):
        CERTD.sync_renewal_pauses(["blog.example.test"])
        text = self.read("blog.example.test")
        self.assertLess(text.index("[renewalparams]"), text.index("autorenew = False"))
        self.assertIn(CERTD.RENEWAL_PAUSE_MARKER, text)

    def test_resuming_restores_the_file_exactly(self):
        before = self.read("blog.example.test")
        CERTD.sync_renewal_pauses(["blog.example.test"])
        CERTD.sync_renewal_pauses([])
        self.assertEqual(self.read("blog.example.test"), before)

    def test_running_it_again_changes_nothing(self):
        CERTD.sync_renewal_pauses(["blog.example.test"])
        again = CERTD.sync_renewal_pauses(["blog.example.test"])
        self.assertEqual(again["changed"], [])
        self.assertEqual(self.read("blog.example.test").count("autorenew"), 1)

    def test_an_operators_own_switch_is_left_alone(self):
        text = RENEWAL.format(name="blog.example.test") + "autorenew = False\n"
        self.write("blog.example.test", text)
        CERTD.sync_renewal_pauses([])
        self.assertEqual(self.read("blog.example.test"), text)

    def test_the_file_keeps_its_permissions(self):
        CERTD.sync_renewal_pauses(["blog.example.test"])
        mode = (self.renewal / "blog.example.test.conf").stat().st_mode & 0o777
        self.assertEqual(mode, 0o640)
        self.assertEqual([p.name for p in self.renewal.iterdir() if p.name.startswith(".")], [])

    def test_a_domain_without_a_lineage_of_its_own_is_reported(self):
        result = CERTD.sync_renewal_pauses(["new.example.test"])
        self.assertEqual(result["without_lineage"], ["new.example.test"])

    def test_a_bad_request_is_refused(self):
        self.assertEqual(CERTD.handle_renewal_pauses({"domains": "x"})[0], 400)
        self.assertEqual(CERTD.handle_renewal_pauses({"domains": ["../etc"]})[0], 400)

    def test_the_route_exists(self):
        source = CERTD_PATH.read_text(encoding="utf-8")
        self.assertIn('elif path == "/api/v1/certs/renewal-pauses":', source)


class NothingElseKeepsItAlive(unittest.TestCase):
    def test_availability_alerts_skip_a_paused_site(self):
        source = HEALTHD_PATH.read_text(encoding="utf-8")
        loader = source.split("def _load_sites(")[1].split("\n    def ")[0]
        self.assertIn('site.get("paused") is not True', loader)

    def test_the_installer_does_not_issue_for_a_renewal_paused_site(self):
        text = CERT_TARGETS.read_text(encoding="utf-8")
        self.assertIn("s.cert_renewal_paused is not sameas true", text)

    def test_the_page_shows_and_offers_both(self):
        page = (APP_DIR / "templates/haproxy_sites.html").read_text(encoding="utf-8")
        for value in ("pause", "resume", "pause_renewal", "resume_renewal"):
            self.assertIn(f'name="action" value="{value}"', page)
        # Kept in a menu, so the actions column stays one button wide.
        menu = page.split('<details class="site-more">')[1].split("</details>")[0]
        self.assertIn('class="site-more-menu"', menu)
        self.assertIn('value="pause_renewal"', menu)
        # And no wider than the buttons above it: a long label wraps instead.
        styles = (APP_DIR / "static/css/styles.css").read_text(encoding="utf-8")
        rule = styles.split(".site-more-menu {")[1].split("}")[0]
        self.assertIn("width: 0;", rule)
        self.assertIn("min-width: 100%;", rule)
        editor = (APP_DIR / "templates/haproxy_site_edit.html").read_text(encoding="utf-8")
        self.assertIn('id="paused"', editor)
        self.assertIn('id="cert_renewal_paused"', editor)
        script = (APP_DIR / "static/js/haproxy_site_edit.js").read_text(encoding="utf-8")
        self.assertIn('["paused", "cert_renewal_paused"].forEach', script)


if __name__ == "__main__":
    unittest.main()
