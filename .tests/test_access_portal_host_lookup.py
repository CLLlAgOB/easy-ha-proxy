"""Which site an access-page host belongs to is worked out once, not per request (N04).

Every page view and every download asked `site_by_host`, and each time it
read and parsed websites.yml and vars.yml. That happened in the
administration panel's own eight worker threads, for any visitor who had
signed in to an access page: frequent requests from one of them could slow
the panel for its administrators. It also read the draft configuration,
while HAProxy routes the applied one.

Held here: the files are parsed once per version, a changed file is read
again at once, and the applied configuration answers first.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    from haproxy_admin import access_portal as store
    from haproxy_admin import services_haproxy_config as config
else:
    store = config = None


def gate(name, domain, **more):
    return {"name": name, "domain": domain, "access_gate": True, **more}


@unittest.skipUnless(store, "Linux application imports")
class TheLookup(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.addCleanup(patch.stopall)
        self.draft = self.root / "websites.yml"
        self.draft_vars = self.root / "vars.yml"
        self.applied = self.root / "last_applied_websites.yml"
        self.applied_vars = self.root / "last_applied_vars.yml"
        patch.object(config, "WEBSITES_YAML", self.draft).start()
        patch.object(config, "CONFIG_YAML", self.draft_vars).start()
        patch.object(config, "HAPROXY_STATE_WEBSITES", self.applied).start()
        patch.object(config, "HAPROXY_STATE_VARS", self.applied_vars).start()
        patch.dict(store._HOSTS, clear=True).start()
        self.reads = []
        real = config._load_yaml
        patch.object(config, "_load_yaml", side_effect=lambda path: self.reads.append(Path(path).name) or real(path)).start()
        self.clock = 1_800_000_000

    def write(self, path, sites=None, defaults=None):
        text = yaml.safe_dump({"sites": sites} if sites is not None else {"site_defaults": defaults or {}})
        path.write_text(text, encoding="utf-8")
        # A second version written within the same clock tick must still differ.
        self.clock += 1
        os.utime(path, (self.clock, self.clock))

    def test_a_hundred_visitors_cost_one_reading_of_each_file(self):
        self.write(self.applied, [gate("support", "support.example.test")])
        self.write(self.applied_vars)
        for _ in range(100):
            self.assertEqual(store.site_by_host("support.example.test")["name"], "support")
        self.assertEqual(sorted(self.reads), ["last_applied_vars.yml", "last_applied_websites.yml"])

    def test_a_changed_file_is_read_again_at_once(self):
        self.write(self.applied, [gate("support", "support.example.test")])
        self.write(self.applied_vars)
        store.site_by_host("support.example.test")
        self.write(self.applied, [gate("support", "help.example.test")])
        self.assertEqual(store.site_by_host("help.example.test")["name"], "support")
        with self.assertRaises(FileNotFoundError):
            store.site_by_host("support.example.test")

    def test_the_applied_configuration_answers_before_the_draft(self):
        # The domain was changed in the draft and not applied yet: HAProxy
        # still routes the old one, so the old one still has its page.
        self.write(self.applied, [gate("support", "old.example.test")])
        self.write(self.applied_vars)
        self.write(self.draft, [gate("support", "new.example.test")])
        self.write(self.draft_vars)
        self.assertEqual(store.site_by_host("old.example.test")["name"], "support")
        self.assertEqual(store.site_by_host("new.example.test")["name"], "support")

    def test_a_gateway_with_no_applied_copy_uses_the_draft(self):
        self.write(self.draft, [gate("support", "support.example.test", alt_names=["alias.example.test"])])
        self.write(self.draft_vars)
        self.assertEqual(store.site_by_host("ALIAS.example.test")["name"], "support")

    def test_only_enabled_gate_sites_answer(self):
        self.write(self.applied, [gate("off", "off.example.test", enabled=False),
                                  {"name": "plain", "domain": "plain.example.test", "backend_ip": "192.0.2.1"}])
        self.write(self.applied_vars)
        for host in ("off.example.test", "plain.example.test", "nobody.example.test"):
            with self.assertRaises(FileNotFoundError):
                store.site_by_host(host)

    def test_a_gate_switched_on_by_the_defaults_counts(self):
        self.write(self.applied, [{"name": "support", "domain": "support.example.test"}])
        self.write(self.applied_vars, defaults={"access_gate": True})
        self.assertEqual(store.site_by_host("support.example.test")["name"], "support")

    def test_the_caller_gets_a_copy(self):
        self.write(self.applied, [gate("support", "support.example.test")])
        self.write(self.applied_vars)
        store.site_by_host("support.example.test")["name"] = "changed"
        self.assertEqual(store.site_by_host("support.example.test")["name"], "support")

    def test_a_host_that_is_not_a_name_is_refused_before_any_file_is_read(self):
        for host in ("support.example.test:443", "", "../etc"):
            with self.assertRaises((ValueError, FileNotFoundError)):
                store.site_by_host(host)
        self.assertEqual(self.reads, [])


if __name__ == "__main__":
    unittest.main()
