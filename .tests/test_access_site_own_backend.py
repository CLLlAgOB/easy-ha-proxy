"""A gate that proxies to its own backend can have that backend changed (N05).

Service sites were separated from proxy sites: the proxy editor no longer
opens a gate, and the compact service-site editor changes only the DNS name
and publication. HAProxy still supports a gate with a backend of its own, so
such a site -- one made before the split -- kept working but could no longer
have its backend changed from the panel at all.

Held here: the compact editor shows and saves the address and port of a single
backend the site already has, nothing else about proxying, and a service site
without a backend cannot be given one there.
"""

from __future__ import annotations

import copy
from contextlib import nullcontext
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    from haproxy_admin import services_haproxy_config as config
    from haproxy_admin import services_haproxy_sites as sites
else:
    config = sites = None

APP = ROOT / "docker/app/haproxy_admin"


@unittest.skipUnless(sites, "Linux application imports")
class TheService(unittest.TestCase):
    def setUp(self):
        self.data = {"sites": [
            {"name": "legacy", "domain": "legacy.example.test", "access_gate": True, "authelia_enabled": True,
             "backend_ip": "192.0.2.10", "backend_port": 8080, "balance": "leastconn"},
            {"name": "stub", "domain": "stub.example.test", "access_gate": True, "authelia_enabled": True},
            {"name": "pool", "domain": "pool.example.test", "access_gate": True, "authelia_enabled": True,
             "servers": [{"name": "a", "host": "192.0.2.1", "port": 80}, {"name": "b", "host": "192.0.2.2", "port": 80}]},
        ]}
        self.addCleanup(patch.stopall)
        patch.object(sites, "source_lock", side_effect=lambda _kind: nullcontext()).start()
        patch.object(sites, "_load_yaml", side_effect=lambda _path: copy.deepcopy(self.data)).start()
        patch.object(sites, "update_yaml_file", side_effect=self.save).start()
        patch.object(sites, "_ensure_access_gate_authelia_rule", return_value=(True, "")).start()

    def save(self, _kind, text):
        self.data = yaml.safe_load(text)
        return True, "saved"

    def site(self, name):
        return next(item for item in self.data["sites"] if item["name"] == name)

    def change(self, name, **more):
        raw = self.site(name)
        return sites.save_access_site_identity(name, raw["domain"], False, config.entry_revision(raw), **more)

    def test_the_backend_of_a_legacy_gate_is_changed_and_nothing_else(self):
        ok, _message = self.change("legacy", backend=("192.0.2.77", "9443"))
        self.assertTrue(ok)
        site = self.site("legacy")
        self.assertEqual((site["backend_ip"], site["backend_port"]), ("192.0.2.77", 9443))
        self.assertEqual((site["access_gate"], site["authelia_enabled"], site["balance"]), (True, True, "leastconn"))

    def test_a_host_name_is_as_good_as_an_address(self):
        self.assertTrue(self.change("legacy", backend=("app.internal.example", 8080))[0])
        self.assertEqual(self.site("legacy")["backend_ip"], "app.internal.example")

    def test_a_bad_address_or_port_is_refused_and_nothing_is_saved(self):
        for backend in (("192.0.2.77; rm", "80"), ("192.0.2.77", "0"), ("192.0.2.77", "70000"), ("", "80"), ("192.0.2.77", "")):
            with self.subTest(backend=backend):
                ok, _message = self.change("legacy", backend=backend)
                self.assertFalse(ok)
                self.assertEqual(self.site("legacy")["backend_ip"], "192.0.2.10")

    def test_a_service_site_without_a_backend_cannot_be_given_one(self):
        ok, message = self.change("stub", backend=("192.0.2.77", "80"))
        self.assertFalse(ok)
        self.assertIn("no single backend", message)
        self.assertNotIn("backend_ip", self.site("stub"))

    def test_several_backends_are_left_to_themselves(self):
        ok, _message = self.change("pool", backend=("192.0.2.77", "80"))
        self.assertFalse(ok)
        self.assertEqual(len(self.site("pool")["servers"]), 2)

    def test_saving_without_backend_fields_keeps_the_backend(self):
        self.assertTrue(self.change("legacy")[0])
        self.assertEqual(self.site("legacy")["backend_ip"], "192.0.2.10")


class ThePage(unittest.TestCase):
    def test_the_fields_appear_only_for_a_single_backend_of_the_sites_own(self):
        page = (APP / "templates/access_portal_settings.html").read_text(encoding="utf-8")
        self.assertIn("{% if site.backend_ip and not site.servers %}", page)
        self.assertIn('name="backend_ip" required value="{{ site.backend_ip }}"', page)
        self.assertIn('name="backend_port" type="number" min="1" max="65535" required', page)
        self.assertIn("{% elif site.servers %}", page)

    def test_the_route_takes_the_two_fields_only_for_such_a_site(self):
        route = (APP / "routes_access_portal.py").read_text(encoding="utf-8")
        self.assertIn("allowed = {'action', 'domain', 'paused', 'revision', 'csrf_token'}", route)
        self.assertIn("if site.get('backend_ip') and not site.get('servers'):", route)
        self.assertIn("allowed |= {'backend_ip', 'backend_port'}", route)
        self.assertIn("backend=backend)", route)

    def test_every_new_sentence_is_translated_whole(self):
        import json

        page = (APP / "templates/access_portal_settings.html").read_text(encoding="utf-8")
        catalogue = json.loads((APP / "translations/ru/access_portal.json").read_text(encoding="utf-8"))["messages"]
        for sentence in (
            "This service site also proxies to a backend of its own, from before service sites were separated from proxy sites. Its other proxy settings are kept as they are.",
            "This service site also proxies to several backends of its own. They are kept as they are and cannot be changed in this editor.",
        ):
            self.assertIn(sentence, page)
            self.assertIn(sentence, catalogue)
        self.assertIn("This service site has no single backend of its own to change", catalogue)


if __name__ == "__main__":
    unittest.main()
