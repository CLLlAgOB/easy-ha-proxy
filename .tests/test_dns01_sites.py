"""Regression checks for DNS-01 and wildcard names on a site."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "docker" / "app"
PACKAGE_ROOT = APP_ROOT / "haproxy_admin"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType("haproxy_admin")
package.__path__ = [str(PACKAGE_ROOT)]
sys.modules.setdefault("haproxy_admin", package)
validation = _load_module("haproxy_admin.validation", PACKAGE_ROOT / "validation.py")
i18n = types.ModuleType("haproxy_admin.i18n")
i18n.translate = lambda value, **_kwargs: value
sys.modules["haproxy_admin.i18n"] = i18n
config_service = _load_module(
    "haproxy_admin.services_haproxy_config",
    PACKAGE_ROOT / "services_haproxy_config.py",
)
certd_calls: list[dict] = []
certd_client = types.ModuleType("haproxy_admin.certd_client")
certd_client.get_cert_status_for_domain = lambda *_a, **_k: {}
certd_client.issue_internal_cert_for_domain = lambda *_a, **_k: {"ok": True}


def _record_issue(domain, alt_names, key_types, dns_profile="", dns_propagation=None):
    certd_calls.append(
        {
            "domain": domain,
            "alt_names": list(alt_names or []),
            "key_types": list(key_types or []),
            "dns_profile": dns_profile,
            "dns_propagation": dns_propagation,
        }
    )
    return {"ok": True}


certd_client.issue_cert_for_domain = _record_issue
sys.modules["haproxy_admin.certd_client"] = certd_client
sites_service = _load_module(
    "haproxy_admin.services_haproxy_sites",
    PACKAGE_ROOT / "services_haproxy_sites.py",
)


BASE_VARS = {
    "root_domain": "example.test",
    "site_defaults": {"balance": "roundrobin", "backend_port": 80},
}


class SiteFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.vars_path = root / "vars.yml"
        self.websites_path = root / "websites.yml"
        self.vars_path.write_text(
            yaml.safe_dump(BASE_VARS, sort_keys=False), encoding="utf-8"
        )
        self.websites_path.write_text(
            yaml.safe_dump(
                {
                    "sites": [
                        {
                            "name": "app",
                            "domain": "app.example.test",
                            "backend_ip": "127.0.0.1",
                            "backend_port": 8080,
                        }
                    ]
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        patches = (
            mock.patch.object(sites_service, "CONFIG_YAML", self.vars_path),
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites_path),
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites_path),
            mock.patch.object(
                config_service,
                "config_transaction_is_pending",
                return_value=(False, ""),
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, **overrides):
        payload = {
            "name": "app",
            "domain": "app.example.test",
            "backend_ip": "127.0.0.1",
            "backend_port": 8080,
            "certificate_source": "letsencrypt",
        }
        payload.update(overrides)
        return sites_service.save_site_from_json(payload, original_name="app")

    def saved_site(self):
        data = yaml.safe_load(self.websites_path.read_text(encoding="utf-8"))
        return data["sites"][0]


class SiteSchemaTests(SiteFixture):
    def test_a_profile_and_a_wildcard_are_stored(self):
        ok, message = self.save(
            dns_profile="my-cloudflare",
            cert_alt_names=["*.app.example.test"],
        )
        self.assertTrue(ok, message)
        site = self.saved_site()
        self.assertEqual(site["dns_profile"], "my-cloudflare")
        self.assertEqual(site["cert_alt_names"], ["*.app.example.test"])

    def test_a_wildcard_without_a_profile_is_refused(self):
        # Only DNS-01 can validate one, and the profile is what selects it.
        ok, message = self.save(cert_alt_names=["*.app.example.test"])
        self.assertFalse(ok)
        self.assertIn("wildcard", message.lower())

    def test_a_wildcard_is_refused_among_the_routing_names(self):
        # HAProxy matches hdr(host) literally, so this would build a
        # configuration that passes haproxy -c and routes nothing.
        ok, message = self.save(
            dns_profile="my-cloudflare", alt_names=["*.app.example.test"]
        )
        self.assertFalse(ok)
        self.assertIn("wildcard", message.lower())

    def test_the_primary_domain_may_not_be_a_wildcard(self):
        ok, message = self.save(domain="*.example.test")
        self.assertFalse(ok)
        self.assertIn("wildcard", message.lower())

    def test_a_hostile_profile_name_is_refused(self):
        for hostile in ("../../etc/passwd", "with space", "a" * 60, "-lead"):
            ok, message = self.save(dns_profile=hostile)
            self.assertFalse(ok, hostile)
            self.assertIn("profile", message.lower())

    def test_a_profile_name_is_matched_case_insensitively(self):
        # The stored file name is lowercase, so a name typed in raw YAML has to
        # resolve to the same profile rather than to a missing one.
        ok, message = self.save(dns_profile="My-Cloudflare")
        self.assertTrue(ok, message)
        self.assertEqual(self.saved_site()["dns_profile"], "my-cloudflare")

    def test_clearing_the_profile_also_clears_the_extra_names(self):
        self.save(
            dns_profile="my-cloudflare", cert_alt_names=["*.app.example.test"]
        )
        ok, message = self.save()
        self.assertTrue(ok, message)
        site = self.saved_site()
        self.assertNotIn("dns_profile", site)
        self.assertNotIn("cert_alt_names", site)

    def test_the_profile_belongs_to_lets_encrypt_only(self):
        ok, message = self.save(
            certificate_source="internal", dns_profile="my-cloudflare"
        )
        self.assertTrue(ok, message)
        self.assertNotIn("dns_profile", self.saved_site())

    def test_extra_names_are_refused_for_an_external_authority(self):
        ok, message = self.save(
            certificate_source="external",
            external_ca_id="corp",
            cert_alt_names=["extra.example.test"],
        )
        self.assertFalse(ok)
        self.assertIn("external", message.lower())

    def test_routing_names_are_validated_and_deduplicated(self):
        ok, message = self.save(
            alt_names=["WWW.app.example.test", "www.app.example.test", "app.example.test"]
        )
        self.assertTrue(ok, message)
        self.assertEqual(self.saved_site()["alt_names"], ["www.app.example.test"])

    def test_a_name_that_would_reach_the_configuration_verbatim_is_refused(self):
        ok, message = self.save(
            alt_names=["ok.example.test\n    http-request deny"]
        )
        self.assertFalse(ok)
        self.assertIn("alt_names", message)

    def test_an_extra_name_that_duplicates_a_routing_name_is_dropped(self):
        ok, message = self.save(
            dns_profile="my-cloudflare",
            alt_names=["www.app.example.test"],
            cert_alt_names=["www.app.example.test", "*.app.example.test"],
        )
        self.assertTrue(ok, message)
        self.assertEqual(
            self.saved_site()["cert_alt_names"], ["*.app.example.test"]
        )


class IssuanceWiringTests(SiteFixture):
    def setUp(self) -> None:
        super().setUp()
        certd_calls.clear()

    def test_apply_sends_the_profile_and_the_extra_names(self):
        self.save(
            dns_profile="my-cloudflare",
            alt_names=["www.app.example.test"],
            cert_alt_names=["*.app.example.test"],
        )
        with mock.patch.object(
            sites_service,
            "get_cert_status_for_site",
            return_value={"state": "missing"},
        ):
            result = sites_service.ensure_certs_before_apply()
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(certd_calls), 1)
        call = certd_calls[0]
        self.assertEqual(call["dns_profile"], "my-cloudflare")
        self.assertEqual(
            call["alt_names"], ["www.app.example.test", "*.app.example.test"]
        )

    def test_without_a_profile_nothing_extra_is_sent(self):
        self.save(alt_names=["www.app.example.test"])
        with mock.patch.object(
            sites_service,
            "get_cert_status_for_site",
            return_value={"state": "missing"},
        ):
            sites_service.ensure_certs_before_apply()
        self.assertEqual(certd_calls[0]["dns_profile"], "")
        self.assertEqual(certd_calls[0]["alt_names"], ["www.app.example.test"])


class WholeFileValidationTests(unittest.TestCase):
    @staticmethod
    def site(**overrides):
        payload = {"name": "app", "domain": "app.example.test"}
        payload.update(overrides)
        return {"sites": [payload]}

    def test_a_wildcard_routing_name_is_refused_in_an_upload(self):
        with self.assertRaises(ValueError) as caught:
            validation.validate_config_data(
                "websites",
                self.site(dns_profile="cf", alt_names=["*.app.example.test"]),
            )
        self.assertIn("alt_names", str(caught.exception))

    def test_a_wildcard_extra_name_needs_a_profile_in_an_upload(self):
        with self.assertRaises(ValueError):
            validation.validate_config_data(
                "websites", self.site(cert_alt_names=["*.app.example.test"])
            )
        validation.validate_config_data(
            "websites",
            self.site(dns_profile="cf", cert_alt_names=["*.app.example.test"]),
        )

    def test_a_hostile_profile_name_is_refused_in_an_upload(self):
        with self.assertRaises(ValueError):
            validation.validate_config_data(
                "websites", self.site(dns_profile="../../etc/passwd")
            )

    def test_a_wildcard_primary_domain_is_refused_in_an_upload(self):
        with self.assertRaises(ValueError):
            validation.validate_config_data(
                "websites", {"sites": [{"name": "app", "domain": "*.example.test"}]}
            )


class ClientPayloadTests(unittest.TestCase):
    def test_the_profile_only_travels_when_one_is_selected(self):
        source = (PACKAGE_ROOT / "certd_client.py").read_text(encoding="utf-8")
        block = source.split("def issue_cert_for_domain(")[1].split("\n\n\ndef ")[0]
        self.assertIn("dns_profile: str = \"\"", block)
        self.assertIn("if dns_profile:", block)
        self.assertIn('payload["dns_profile"]', block)
        # Sending an empty profile would read on the daemon side as an explicit
        # request for DNS-01 with no profile.
        self.assertNotIn('payload = {\n        "domain"', block.replace("\r\n", "\n"))


class AnsibleIssuancePathTests(unittest.TestCase):
    """The install-time path must not quietly issue over the wrong challenge."""

    def setUp(self):
        self.role = ROOT / "ansible" / "roles" / "cert"

    def test_the_san_flags_include_the_certificate_only_names(self):
        import re as _re

        from jinja2 import Environment, FileSystemLoader

        environment = Environment(
            loader=FileSystemLoader(str(self.role / "templates"))
        )
        environment.filters["regex_replace"] = lambda value, pattern, repl: _re.sub(
            pattern, repl.replace("\\\\", "\\"), value
        )
        rendered = environment.get_template("_san_flags.j2").render(
            obj={
                "domain": "app.example.test",
                "alt_names": ["www.app.example.test"],
                "cert_alt_names": ["*.app.example.test"],
            }
        )
        self.assertEqual(
            rendered,
            "-d app.example.test -d www.app.example.test -d *.app.example.test",
        )

    def test_a_site_without_extra_names_renders_as_before(self):
        import re as _re

        from jinja2 import Environment, FileSystemLoader

        environment = Environment(
            loader=FileSystemLoader(str(self.role / "templates"))
        )
        environment.filters["regex_replace"] = lambda value, pattern, repl: _re.sub(
            pattern, repl.replace("\\\\", "\\"), value
        )
        rendered = environment.get_template("_san_flags.j2").render(
            obj={"domain": "app.example.test"}
        )
        self.assertEqual(rendered, "-d app.example.test")

    def test_the_certificate_only_names_never_reach_haproxy(self):
        # This is the whole reason they are a separate field: every name the
        # HAProxy template consumes ends up in a literal ACL match.
        template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("cert_alt_names", template)
        self.assertNotIn("dns_profile", template)

    def test_dns01_targets_are_excluded_from_the_standalone_path(self):
        # This role only knows --standalone, and the plugin snaps are installed
        # by a role that runs later, so a DNS-01 site issued here would use
        # HTTP-01 and lose its wildcard.
        source = (self.role / "tasks" / "renew__15_dns_check.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("_dns01_lineages", source)
        self.assertIn("site.dns_profile | default('')", source)
        self.assertIn(
            "_planned_lineages: \"{{ _all_planned_lineages | reject('in',"
            " _dns01_lineages) | list }}\"",
            source,
        )
        issue = (self.role / "tasks" / "renew__20_issue.yml").read_text(
            encoding="utf-8"
        )
        # The loops still consume only what the readiness stage let through.
        self.assertIn("issue_targets_explicit", issue)
        self.assertIn("issue_targets_single", issue)


class RenewalDurabilityTests(unittest.TestCase):
    """Certbot records the credentials path in renewal.conf, so it must survive."""

    CREDENTIALS_DIR = "/etc/easy-ha-proxy/dns-providers"

    def test_the_daemon_the_unit_and_ansible_agree_on_the_path(self):
        certd = (
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
        ).read_text(encoding="utf-8")
        unit = (
            ROOT
            / "ansible/roles/haproxy-admin/templates/haproxy-certd.service.j2"
        ).read_text(encoding="utf-8")
        defaults = (
            ROOT / "ansible/roles/haproxy-admin/defaults/main.yml"
        ).read_text(encoding="utf-8")
        for source in (certd, unit, defaults):
            self.assertIn(self.CREDENTIALS_DIR, source)

    def test_the_directory_is_ensured_without_replacing_its_contents(self):
        tasks = (
            ROOT / "ansible/roles/haproxy-admin/tasks/dns-plugins.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("state: directory", tasks)
        self.assertIn('mode: "0700"', tasks)
        # Anything that empties or recreates the directory would break every
        # renewal that points at a file inside it.
        for destructive in ("state: absent", "force: true", "recurse: yes"):
            self.assertNotIn(destructive, tasks)

    def test_disaster_recovery_carries_the_credentials(self):
        backup = (ROOT / "installer" / "full_backup.py").read_text(encoding="utf-8")
        self.assertIn('"/etc/easy-ha-proxy",', backup)
        # And nothing excludes the profiles from the archive.
        excludes = backup.split("BACKUP_EXCLUDES = (")[1].split(")")[0]
        self.assertNotIn("dns-providers", excludes)


class SiteEditorUiTests(unittest.TestCase):
    def setUp(self):
        self.template = (
            PACKAGE_ROOT / "templates" / "haproxy_site_edit.html"
        ).read_text(encoding="utf-8")
        self.javascript = (
            PACKAGE_ROOT / "static" / "js" / "haproxy_site_edit.js"
        ).read_text(encoding="utf-8")

    def test_the_editor_offers_the_challenge_the_profile_and_the_names(self):
        for needle in (
            'id="acme_challenge_http"',
            'id="acme_challenge_dns"',
            'id="dns_profile"',
            'id="field-cert-alt-names"',
            'id="block-dns-01"',
        ):
            self.assertIn(needle, self.template, needle)

    def test_the_dns_block_is_hidden_until_dns_is_chosen(self):
        self.assertIn(
            '{% if not current_dns_profile %} display:none;{% endif %}',
            self.template,
        )
        self.assertIn("function updateChallengeUI()", self.javascript)
        self.assertIn('blockDns.style.display = useDns ? "" : "none";', self.javascript)

    def test_a_profile_name_is_never_run_through_the_translator(self):
        # It is an operator-chosen identifier, not interface text.
        options = re.findall(r"<option[^>]*profile\.name[^>]*>", self.template)
        self.assertTrue(options)
        for option in options:
            self.assertIn('translate="no"', option)
            self.assertIn("data-i18n-skip", option)

    def test_the_payload_carries_the_profile_only_with_dns_selected(self):
        self.assertIn("site.dns_profile = dnsProfileEl.value;", self.javascript)
        self.assertIn("dnsChallengeEl.checked", self.javascript)
        self.assertIn("site.cert_alt_names = certAltLines;", self.javascript)

    def test_tcp_passthrough_drops_both_fields(self):
        # They are meaningless without HTTP termination, and a stale profile
        # would silently change how a later certificate is validated.
        self.assertIn("delete site.dns_profile;", self.javascript)
        self.assertIn("delete site.cert_alt_names;", self.javascript)

    def test_issuance_is_audited_with_the_challenge_but_no_credential(self):
        routes = (PACKAGE_ROOT / "routes_haproxy_config.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"certificate.issue"', routes)
        self.assertIn('challenge = "dns-01" if eff.get("dns_profile")', routes)


if __name__ == "__main__":
    unittest.main()
