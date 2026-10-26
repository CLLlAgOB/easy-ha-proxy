"""Signatures mined from a week of two gateways' logs (2026-10-26).

Replaying a week of Oreol and privatnet with the shipped signature file left
these unmatched although 6-15 addresses a week asked for each and no client
ever did:

- secrets under endless new names: /.env.anthropic, /.env-example,
  /.env.yml, /.env.production.local, /.git-credentials, /.netrc, /.pypirc.
  A segment token ending in "*" now matches by prefix, so ".env*" covers the
  next invented name too;
- device and product exploits: Cisco ASA /+CSCOE+/, GPON /GponForm/, D-Link
  /HNAP1, Fortinet /remote/login, Tomcat /manager/html, /hudson.

/v2/_catalog was asked for as well but is left out: a gateway serving a
Docker registry gets it from its own clients.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIGNATURES = ROOT / "ansible/roles/haproxy-admin/files/scanner-signatures.json"


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_mined_signatures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()


class WithTheShippedFile(unittest.TestCase):
    def setUp(self):
        self.assertTrue(guardd.load_signatures(str(SIGNATURES)))
        self.addCleanup(guardd.apply_overrides, {})

    def test_every_env_variant_is_a_decisive_secrets_probe(self):
        for path in ("/.env.anthropic", "/.env-example", "/.env.yml",
                     "/.env.production.local", "/app/.env.bak", "/.ENV.local"):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), "secrets")
                self.assertTrue(guardd.category_is_decisive("secrets"))

    def test_a_static_file_named_like_it_is_still_a_static_file(self):
        self.assertEqual(guardd.classify_path("/assets/.env.config.js"), "")

    def test_other_secret_files(self):
        for path in ("/.git-credentials", "/.netrc", "/.pypirc", "/.npmrc"):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), "secrets")

    def test_device_and_product_exploits(self):
        self.assertEqual(guardd.classify_path("/+CSCOE+/logon.html"), "known-exploit")
        self.assertEqual(guardd.classify_path("/GponForm/diag_Form"), "known-exploit")
        self.assertEqual(guardd.classify_path("/HNAP1"), "known-exploit")
        # A site could really have these, so they stay non-decisive and the
        # site serving them excuses the request.
        for path in ("/remote/login", "/manager/html"):
            with self.subTest(path=path):
                category = guardd.classify_path(path)
                self.assertEqual(category, "app-framework")
                self.assertFalse(guardd.category_is_decisive(category))

    def test_the_registry_listing_is_left_alone(self):
        self.assertEqual(guardd.classify_path("/v2/_catalog"), "")

    def test_an_operator_can_switch_the_prefix_off(self):
        guardd.apply_overrides({"disabled": [".env*"]})
        self.assertEqual(guardd.classify_path("/.env.anthropic"), "")
        # The exact token stays.
        self.assertEqual(guardd.classify_path("/.env"), "secrets")

    def test_an_operator_can_add_a_prefix_of_their_own(self):
        guardd.apply_overrides({"added": {"wlwmanifest*": "wordpress"}})
        self.assertEqual(guardd.classify_path("/blog/wlwmanifest.xml.bak"), "wordpress")


class WithoutTheFile(unittest.TestCase):
    def test_the_built_in_fallback_knows_the_prefix_too(self):
        module = load_guardd()
        self.assertEqual(module.classify_path("/.env.anthropic"), "secrets")


if __name__ == "__main__":
    unittest.main()
