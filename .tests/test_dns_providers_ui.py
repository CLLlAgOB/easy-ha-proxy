"""Regression checks for the DNS provider profile page and its routes."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import routes_dns_providers as routes  # noqa: E402


class ProviderTableTests(unittest.TestCase):
    def test_the_application_and_the_daemon_agree_on_the_providers(self):
        # The page can only offer what certd will accept.
        certd = (
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
        ).read_text(encoding="utf-8")
        block = certd.split("DNS_PROVIDERS: Dict[str, Dict[str, Any]] = {")[1]
        block = block.split("\n}")[0]
        declared = set(re.findall(r'^\s{4}"([a-z0-9]+)":', block, flags=re.MULTILINE))
        self.assertEqual(declared, set(routes.PROVIDERS))

    def test_the_profile_pattern_matches_the_daemon(self):
        certd = (
            ROOT / "ansible/roles/haproxy-admin/files/haproxy-certd.py"
        ).read_text(encoding="utf-8")
        self.assertIn(r'DNS_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")', certd)
        self.assertEqual(routes.PROFILE_RE.pattern, r"^[a-z0-9][a-z0-9-]{0,39}$")


class RouteGuardTests(unittest.TestCase):
    def setUp(self):
        self.source = (APP_DIR / "routes_dns_providers.py").read_text(encoding="utf-8")

    def test_both_mutating_routes_require_superadmin(self):
        self.assertEqual(self.source.count("@bp.post"), 2)
        self.assertEqual(self.source.count("_superadmin()"), 3)

    def test_every_outcome_is_audited(self):
        for action in ("dns_provider.save", "dns_provider.delete"):
            self.assertIn(f'"{action}"', self.source)
        self.assertIn("RESULT_DENIED", self.source)
        self.assertIn("RESULT_FAILURE", self.source)

    def test_the_audit_record_never_carries_a_credential(self):
        # The summary states that credentials changed, never what to.
        self.assertIn("credentials: changed", self.source)
        self.assertNotIn("credentials=credentials", self.source.split("record_request")[1])


class ValidationTests(unittest.TestCase):
    def test_profile_names_are_constrained(self):
        for good in ("a", "my-cloudflare", "cf1", "a" * 40):
            self.assertTrue(routes.PROFILE_RE.match(good), good)
        for bad in ("", "-lead", "UPPER", "with space", "a" * 41, "../x", "x/y", "a.b"):
            self.assertFalse(routes.PROFILE_RE.match(bad), bad)


class PageTests(unittest.TestCase):
    def setUp(self):
        self.template = (APP_DIR / "templates" / "dns_providers.html").read_text(
            encoding="utf-8"
        )
        self.javascript = (APP_DIR / "static" / "js" / "dns_providers.js").read_text(
            encoding="utf-8"
        )

    def test_credential_fields_never_start_populated(self):
        # The server does not return saved secrets, so the form must not
        # pretend to hold one.
        self.assertIn('input.type = "password"', self.javascript)
        self.assertIn('input.placeholder = uiText("unchanged")', self.javascript)
        self.assertNotIn("input.value = profile", self.javascript)

    def test_the_page_states_that_a_secret_is_never_returned(self):
        self.assertIn("never sent back to this page", self.template)

    def test_mutating_requests_carry_the_csrf_token(self):
        self.assertEqual(self.javascript.count('"X-CSRFToken": csrfToken()'), 2)

    def test_a_missing_plugin_is_explained_with_what_to_do(self):
        self.assertIn("dns_plugins_enabled", self.javascript)
        self.assertIn("spec.snap", self.javascript)

    def test_every_element_the_script_writes_to_exists(self):
        referenced = set(re.findall(r'byId\("([a-z0-9-]+)"\)', self.javascript))
        template_ids = set(re.findall(r'id="([a-z0-9-]+)"', self.template))
        self.assertEqual(sorted(referenced - template_ids), [])


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tasks = (
            ROOT / "ansible/roles/haproxy-admin/tasks/dns-plugins.yml"
        ).read_text(encoding="utf-8")

    def test_plugins_are_installed_as_snaps_not_apt_packages(self):
        # certbot itself comes from snap here, so its plugins must too, at a
        # matching version.
        self.assertIn("snap install certbot-dns-", self.tasks)
        self.assertIn("snap set certbot trust-plugin-with-root=ok", self.tasks)
        self.assertIn("snap connect certbot:plugin", self.tasks)
        # Look for the module being used, not the word: the file explains in a
        # comment why apt is the wrong mechanism here.
        for module in ("ansible.builtin.apt", "ansible.builtin.package", "\n  apt:"):
            self.assertNotIn(module, self.tasks, module)
        self.assertNotIn("install python3-certbot-dns", self.tasks)

    def test_the_credentials_directory_is_root_only(self):
        self.assertIn('mode: "0700"', self.tasks)

    def test_nothing_is_installed_unless_a_provider_was_asked_for(self):
        defaults = (
            ROOT / "ansible/roles/haproxy-admin/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("dns_plugins_enabled: []", defaults)

    def test_the_install_retries_the_version_mismatch(self):
        self.assertIn("retries: 3", self.tasks)

    def test_certd_is_told_where_the_credentials_live(self):
        unit = (
            ROOT / "ansible/roles/haproxy-admin/templates/haproxy-certd.service.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("HAPROXY_DNS_CREDENTIALS_DIR", unit)


class CatalogTests(unittest.TestCase):
    def test_the_page_vocabulary_is_translated(self):
        shared = set()
        for path in (APP_DIR / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["meta"]["code"] == "ru":
                shared |= set(data["messages"])
        for token in ("DNS providers", "Profiles", "Save profile", "unchanged",
                      "plugin ready", "plugin missing"):
            self.assertIn(token, shared, token)


if __name__ == "__main__":
    unittest.main()
