"""Two sites or TCP proxies cannot claim the same name, host or port (F27).

From the 30 October review, accepted there by the real validator: creating
a site checked its name, but renaming one onto another's name did not;
nothing stopped two sites routing one domain, or shop.a beside shop-a --
names the template writes as the same be_shop_a. HAProxy caught a
duplicate backend only at Apply, and a shared domain not at all: the first
site took every request.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"

from haproxy_admin import validation  # noqa: E402

if not WINDOWS:
    from haproxy_admin import services_haproxy_config as config_service  # noqa: E402
    from haproxy_admin import services_haproxy_sites as sites_service  # noqa: E402
    from haproxy_admin import services_haproxy_tcp as tcp_service  # noqa: E402


def real_translate():
    # Other tests leave a stub in place of haproxy_admin.i18n; read the real one.
    path = ROOT / "docker/app/haproxy_admin/i18n.py"
    spec = importlib.util.spec_from_file_location("identity_conflicts_i18n", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.translate


def site(name, domain=None, **extra):
    base = {"name": name, "domain": domain or f"{name}.example.test",
            "backend_ip": "10.0.0.10", "backend_port": 8080}
    base.update(extra)
    return base


def proxy(name, port, address="0.0.0.0"):
    return {"name": name, "bind_ip": address, "bind_port": port,
            "backend_host": "10.0.0.20", "backend_port": 22}


class TheRules(unittest.TestCase):
    conflict = staticmethod(validation.site_identity_conflict)

    def test_a_name_is_one_site_s(self):
        self.assertIn("already exists", self.conflict(site("shop", "a.example.test"), [site("shop")]))

    def test_names_haproxy_writes_alike_clash(self):
        message = self.conflict(site("shop-a"), [site("shop.a")])
        self.assertIn("same HAProxy backend name as the site 'shop.a'", message)

    def test_a_domain_is_served_by_one_site(self):
        message = self.conflict(site("new", "Shop.Example.Test"), [site("shop", "shop.example.test")])
        self.assertIn("'shop.example.test' belongs to the site 'shop'", message)

    def test_an_alias_counts_as_a_domain(self):
        candidate = site("new", "new.example.test", alt_names=["www.example.test"])
        other = site("www", "www.example.test")
        self.assertIsNotNone(self.conflict(candidate, [other]))

    def test_a_paused_site_lends_its_domain(self):
        self.assertIsNone(self.conflict(site("new", "shop.example.test"),
                                        [site("shop", "shop.example.test", paused=True)]))
        self.assertIsNone(self.conflict(site("old", "shop.example.test", paused=True),
                                        [site("shop", "shop.example.test")]))

    def test_distinct_sites_pass(self):
        self.assertIsNone(self.conflict(site("shop"), [site("blog"), site("api")]))

    def test_a_tcp_port_is_one_proxy_s_on_any_address(self):
        message = validation.tcp_identity_conflict(proxy("b", 6690, "10.0.0.1"), [proxy("a", 6690)])
        self.assertIn("belongs to the TCP proxy 'a'", message)

    def test_two_addresses_may_share_a_port(self):
        self.assertIsNone(validation.tcp_identity_conflict(
            proxy("b", 6690, "10.0.0.2"), [proxy("a", 6690, "10.0.0.1")]))

    def test_tcp_names_haproxy_writes_alike_clash(self):
        self.assertIn("same HAProxy backend name",
                      validation.tcp_identity_conflict(proxy("files-1", 1), [proxy("files.1", 2)]))

    def test_an_uploaded_file_with_alike_names_is_refused(self):
        with self.assertRaises(ValueError):
            validation.validate_config_data("websites", {"sites": [site("shop.a"), site("shop-a", "b.example.test")]})


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheSaves(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "config").mkdir()
        self.websites = root / "config" / "websites.yml"
        self.tcp = root / "config" / "tcp.yml"
        self.websites.write_text(yaml.safe_dump({"sites": [
            site("shop", "shop.example.test"), site("blog", "blog.example.test"),
            site("old", "old.example.test", paused=True),
        ]}), encoding="utf-8")
        self.tcp.write_text(yaml.safe_dump({"tcp_proxies": [proxy("files", 6690)]}), encoding="utf-8")
        for patcher in (
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "TCP_YAML", self.tcp),
            mock.patch.object(config_service, "BASE_DIR", root),
            mock.patch.object(config_service, "config_transaction_is_pending", return_value=(False, "")),
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(tcp_service, "TCP_YAML", self.tcp),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def names(self):
        return [s["name"] for s in yaml.safe_load(self.websites.read_text(encoding="utf-8"))["sites"]]

    def test_a_rename_onto_another_site_is_refused(self):
        ok, message = sites_service.save_site_from_json(site("blog", "shop.example.test"), "shop")
        self.assertFalse(ok)
        self.assertIn("already exists", message)
        self.assertEqual(self.names(), ["shop", "blog", "old"])

    def test_a_new_site_on_a_served_domain_is_refused(self):
        ok, message = sites_service.save_site_from_json(site("shop2", "shop.example.test"))
        self.assertFalse(ok)
        self.assertIn("belongs to the site 'shop'", message)

    def test_a_site_may_keep_its_own_domain(self):
        ok, _ = sites_service.save_site_from_json(site("shop", "shop.example.test", backend_port=8081), "shop")
        self.assertTrue(ok)

    def test_resuming_onto_a_taken_domain_is_refused(self):
        sites_service.save_site_from_json(site("new", "old.example.test"))
        ok, message = sites_service.set_site_pause("old", "paused", False)
        self.assertFalse(ok)
        self.assertIn("belongs to the site 'new'", message)

    def test_a_tcp_proxy_on_a_taken_port_is_refused(self):
        ok, message = tcp_service.save_tcp_from_json(proxy("backup", 6690, "10.0.0.1"))
        self.assertFalse(ok)
        self.assertIn("'files'", message)

    def test_the_messages_translate_whole(self):
        translate = real_translate()
        for message in (
            validation.site_identity_conflict(site("shop-a"), [site("shop.a")]),
            validation.site_identity_conflict(site("new", "shop.example.test"), [site("shop", "shop.example.test")]),
            validation.tcp_identity_conflict(proxy("b", 6690), [proxy("a", 6690)]),
            validation.tcp_identity_conflict(proxy("b-1", 1), [proxy("b.1", 2)]),
        ):
            translated = translate(message, "ru")
            self.assertNotEqual(translated, message)
            self.assertNotRegex(translated, r"\b(Choose|served|belongs|gives|listening)\b")


if __name__ == "__main__":
    unittest.main()
