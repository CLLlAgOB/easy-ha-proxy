"""Backend sets: named address lists that sites, TCP proxies and UDP forwards pick.

An operator with two uplinks typed the same two addresses and roles into
every site, TCP proxy and UDP forward, and changed them everywhere when an
uplink's address changed. A set lives once in vars.yml; an entry names it
and gets the addresses expanded into its own fields when it is saved, so
HAProxy, the UDP rules and the daemons read what they always read. Saving
the set expands it again in every entry that names it.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    # Bound at import: test_authelia_bans later swaps a stub in for the package.
    from haproxy_admin import create_app  # noqa: E402
    from haproxy_admin import backend_presets as sets  # noqa: E402
    from haproxy_admin import services_haproxy_config as config_service  # noqa: E402
    from haproxy_admin import services_haproxy_sites as sites_service  # noqa: E402
    from haproxy_admin import services_haproxy_tcp as tcp_service  # noqa: E402
    from haproxy_admin import services_haproxy_udp as udp_service  # noqa: E402
    # The real panel modules, as they are now. test_authelia_bans leaves stubs
    # under these names for every later test; the page tests put these back.
    REAL_MODULES = {name: module for name, module in sys.modules.items()
                    if name == "haproxy_admin" or name.startswith("haproxy_admin.")}

UPLINKS = {"name": "Two uplinks", "servers": [
    {"host": "198.51.100.10", "role": "primary", "weight": 50, "note": "first uplink"},
    {"host": "203.0.113.20", "role": "backup"},
]}


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheSet(unittest.TestCase):
    def test_a_set_needs_a_primary_and_distinct_valid_addresses(self):
        self.assertEqual(sets.normalize_preset(UPLINKS)["name"], "Two uplinks")
        self.assertEqual(sets.normalize_preset({**UPLINKS, "name": "\u0414\u0432\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430"})["name"], "\u0414\u0432\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430")
        for broken in (
            {**UPLINKS, "name": ""},
            {**UPLINKS, "name": "-dash first"},
            {"name": "x", "servers": []},
            {"name": "x", "servers": [{"host": "198.51.100.10", "role": "backup"}]},
            {"name": "x", "servers": [{"host": "198.51.100.10"}, {"host": "198.51.100.10"}]},
            {"name": "x", "servers": [{"host": "198.51.100.10", "weight": 999}]},
            {"name": "x", "servers": [{"host": "198.51.100.10", "role": "spare"}]},
            {"name": "x", "servers": [{"host": "bad host!"}]},
        ):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                sets.normalize_preset(broken)

    def test_empty_rows_are_skipped_and_notes_are_one_line(self):
        preset = sets.normalize_preset({"name": "x", "servers": [
            {"host": ""}, {"host": "198.51.100.10", "note": "  a\nb  "}]})
        self.assertEqual(preset["servers"], [{"host": "198.51.100.10", "role": "primary", "note": "a b"}])

    def test_expansion_names_primaries_and_backups_and_carries_the_port(self):
        servers = sets.expand_servers(sets.normalize_preset(UPLINKS), 8443)
        self.assertEqual(servers, [
            {"name": "srv1", "host": "198.51.100.10", "port": 8443, "weight": 50},
            {"name": "backup1", "host": "203.0.113.20", "port": 8443, "backup": True},
        ])
        self.assertNotIn("weight", sets.expand_servers(sets.normalize_preset(UPLINKS), 22, weights=False)[0])


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class AnEntryNamingASet(unittest.TestCase):
    presets = [sets.normalize_preset(UPLINKS)] if not WINDOWS else []

    def test_a_site_gets_the_servers_and_loses_the_single_backend(self):
        site = {"name": "app", "backend_ip": "10.0.0.1", "backend_port": 80,
                "servers_preset": "Two uplinks", "servers_preset_port": "8080"}
        sets.apply_to_site(site, self.presets)
        self.assertEqual([s["host"] for s in site["servers"]], ["198.51.100.10", "203.0.113.20"])
        self.assertEqual(site["servers_preset_port"], 8080)
        self.assertNotIn("backend_ip", site)

    def test_a_tcp_proxy_gets_servers_without_weights(self):
        proxy = {"name": "rdp", "servers_preset": "Two uplinks", "servers_preset_port": 3389,
                 "backend_host": "10.0.0.1", "backend_port": 3389}
        sets.apply_to_tcp(proxy, self.presets)
        self.assertEqual(proxy["servers"][0], {"name": "srv1", "host": "198.51.100.10", "port": 3389})
        self.assertNotIn("backend_host", proxy)

    def test_a_udp_forward_takes_the_first_primary_and_the_first_backup(self):
        forward = {"name": "wg", "servers_preset": "Two uplinks", "backend_host": "10.0.0.1"}
        sets.apply_to_udp(forward, self.presets)
        self.assertEqual((forward["backend_host"], forward["backup_host"]), ("198.51.100.10", "203.0.113.20"))
        lone = [sets.normalize_preset({"name": "one", "servers": [{"host": "198.51.100.10"}]})]
        forward = {"name": "wg", "servers_preset": "one", "backup_host": "10.0.0.9", "health_check": "tcp"}
        sets.apply_to_udp(forward, lone)
        self.assertNotIn("backup_host", forward)
        self.assertNotIn("health_check", forward)

    def test_no_set_leaves_the_entry_alone_and_a_missing_one_is_refused(self):
        site = {"name": "app", "backend_ip": "10.0.0.1", "backend_port": 80, "servers_preset": ""}
        sets.apply_to_site(site, self.presets)
        self.assertEqual(site, {"name": "app", "backend_ip": "10.0.0.1", "backend_port": 80})
        with self.assertRaises(ValueError):
            sets.apply_to_site({"servers_preset": "gone", "servers_preset_port": 80}, self.presets)
        with self.assertRaises(ValueError):
            sets.apply_to_site({"servers_preset": "Two uplinks"}, self.presets)  # no port


class _Files(unittest.TestCase):
    """Temporary vars, websites, tcp and udp files with the services pointed at them."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "config").mkdir()
        self.vars = root / "config" / "vars.yml"
        self.websites = root / "config" / "websites.yml"
        self.tcp = root / "config" / "tcp.yml"
        self.udp = root / "config" / "udp.yml"
        self.vars.write_text("site_defaults: {}\n", encoding="utf-8")
        self.websites.write_text("sites: []\n", encoding="utf-8")
        self.tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
        self.udp.write_text("udp_forwards: []\n", encoding="utf-8")
        self.applied = []
        patches = [
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "TCP_YAML", self.tcp),
            mock.patch.object(config_service, "UDP_YAML", self.udp),
            mock.patch.object(config_service, "CONFIG_YAML", self.vars),
            mock.patch.object(config_service, "BASE_DIR", root),
            mock.patch.object(config_service, "config_transaction_is_pending", return_value=(False, "")),
            mock.patch.object(sets, "WEBSITES_YAML", self.websites),
            mock.patch.object(sets, "TCP_YAML", self.tcp),
            mock.patch.object(sets, "UDP_YAML", self.udp),
            mock.patch.object(sets, "CONFIG_YAML", self.vars),
            mock.patch.object(sets, "config_transaction_is_pending", return_value=(False, "")),
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(sites_service, "CONFIG_YAML", self.vars),
            mock.patch.object(tcp_service, "TCP_YAML", self.tcp),
            mock.patch.object(udp_service, "UDP_YAML", self.udp),
            mock.patch.object(udp_service, "_write_and_apply", side_effect=self.fake_udp_apply),
            mock.patch.object(udp_service, "udp_listen_port_conflict", return_value=None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_udp_apply(self, data):
        self.applied.append(data)
        self.udp.write_text(yaml.safe_dump(data), encoding="utf-8")
        return True, "applied"

    def load(self, path):
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class SavingASet(_Files):
    def test_a_site_tcp_and_udp_follow_a_changed_address(self):
        ok, message = sets.save_preset(UPLINKS)
        self.assertTrue(ok, message)
        ok, message = sites_service.save_site_from_json({
            "name": "app.example.test", "domain": "app.example.test",
            "servers_preset": "Two uplinks", "servers_preset_port": 8080,
            "backend_ip": "10.9.9.9", "backend_port": 1})
        self.assertTrue(ok, message)
        ok, message = tcp_service.save_tcp_from_json({
            "name": "rdp", "bind_port": 13389, "servers_preset": "Two uplinks", "servers_preset_port": 3389})
        self.assertTrue(ok, message)
        ok, message = udp_service.save_udp_from_json({
            "name": "wg", "listen_port": "51820", "backend_port": "51820", "servers_preset": "Two uplinks"})
        self.assertTrue(ok, message)

        site = self.load(self.websites)["sites"][0]
        self.assertEqual(site["servers"][0]["host"], "198.51.100.10")
        self.assertNotIn("backend_ip", site)
        self.assertEqual(self.load(self.udp)["udp_forwards"][0]["servers_preset"], "Two uplinks")

        changed = {"name": "Uplinks", "servers": [
            {"host": "198.51.100.77", "role": "primary"}, {"host": "203.0.113.20", "role": "backup"}]}
        revision = sets.preset_revision(sets.load_presets()[0])
        ok, message = sets.save_preset(changed, "Two uplinks", revision)
        self.assertTrue(ok, message)

        site = self.load(self.websites)["sites"][0]
        proxy = self.load(self.tcp)["tcp_proxies"][0]
        forward = self.load(self.udp)["udp_forwards"][0]
        self.assertEqual(site["servers_preset"], "Uplinks")  # the rename reached it
        self.assertEqual([s["host"] for s in site["servers"]], ["198.51.100.77", "203.0.113.20"])
        self.assertEqual(site["servers"][0]["port"], 8080)
        self.assertEqual(proxy["servers"][0], {"name": "srv1", "host": "198.51.100.77", "port": 3389})
        self.assertEqual((forward["backend_host"], forward["servers_preset"]), ("198.51.100.77", "Uplinks"))
        self.assertEqual(len(self.applied), 2)  # the UDP save, then the set's change

    def test_a_set_in_use_cannot_be_deleted_and_a_stale_form_is_refused(self):
        self.assertTrue(sets.save_preset(UPLINKS)[0])
        self.assertTrue(sites_service.save_site_from_json({
            "name": "app.example.test", "domain": "app.example.test",
            "servers_preset": "Two uplinks", "servers_preset_port": 80})[0])
        ok, message = sets.delete_preset("Two uplinks")
        self.assertFalse(ok)
        self.assertIn("app.example.test", message)
        ok, message = sets.save_preset(UPLINKS, "Two uplinks", "stale")
        self.assertFalse(ok)
        ok, message = sites_service.save_site_from_json(
            {"name": "app.example.test", "domain": "app.example.test",
             "servers": [{"host": "10.0.0.5", "port": 80}]},
            "app.example.test", sites_service.site_revision("app.example.test"))
        self.assertTrue(ok, message)
        site = self.load(self.websites)["sites"][0]
        self.assertNotIn("servers_preset", site)  # manual addresses drop the reference
        self.assertEqual(sets.usage(), {})
        self.assertTrue(sets.delete_preset("Two uplinks")[0])
        self.assertNotIn("backend_presets", self.load(self.vars))
        self.assertEqual(self.load(self.vars)["site_defaults"], {})

    def test_a_duplicate_name_is_refused(self):
        self.assertTrue(sets.save_preset(UPLINKS)[0])
        self.assertFalse(sets.save_preset(UPLINKS)[0])


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class ThePages(_Files):
    """The real pages render with sets in them, and the set form saves."""

    def setUp(self):
        super().setUp()
        import os
        root = self.vars.parent.parent
        environment = mock.patch.dict(os.environ, {
            "HAPROXY_ADMIN_PROXY_SECRET": "sets-test-proxy",
            "HAPROXY_ADMIN_SECRET_KEY": "sets-test-session",
            "AUDIT_DATABASE": str(root / "audit.db"),
            "HAPROXY_ADMIN_PORTAL_DIR": str(root / "portals"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        modules = mock.patch.dict(sys.modules, REAL_MODULES)
        modules.start()
        self.addCleanup(modules.stop)
        with mock.patch("haproxy_admin.ensure_whitelist_file"):
            app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()
        self.headers = {"X-Easy-HA-Proxy-Secret": "sets-test-proxy", "Remote-User": "admin",
                        "Remote-Groups": "admins,superadmin"}

    def test_the_set_page_creates_a_set_and_the_tcp_page_offers_it(self):
        page = self.client.get("/haproxy/backend-sets", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn("No backend sets yet", page.get_data(as_text=True))
        saved = self.client.post("/haproxy/backend-sets", headers=self.headers, data={
            "action": "save", "name": "Two uplinks",
            "server_host": ["198.51.100.10", "203.0.113.20"],
            "server_role": ["primary", "backup"],
            "server_weight": ["", ""], "server_note": ["first", ""],
        })
        self.assertEqual(saved.status_code, 302)
        self.assertEqual(sets.load_presets()[0]["servers"][1]["role"], "backup")
        listing = self.client.get("/haproxy/backend-sets", headers=self.headers).get_data(as_text=True)
        self.assertIn("203.0.113.20", listing)
        self.assertIn("Not used", listing)
        tcp_page = self.client.get("/haproxy/tcp", headers=self.headers)
        self.assertEqual(tcp_page.status_code, 200)
        self.assertIn('<option value="Two uplinks"', tcp_page.get_data(as_text=True))

    def test_a_tcp_proxy_with_a_set_opens_in_its_editor(self):
        self.assertTrue(sets.save_preset(UPLINKS)[0])
        self.assertTrue(tcp_service.save_tcp_from_json({
            "name": "rdp", "bind_port": 13389, "servers_preset": "Two uplinks",
            "servers_preset_port": 3389})[0])
        editor = self.client.get("/haproxy/tcp/rdp/edit", headers=self.headers)
        self.assertEqual(editor.status_code, 200)
        html = editor.get_data(as_text=True)
        self.assertIn('<option value="Two uplinks" selected', html)
        self.assertIn('value="3389"', html)
        listing = self.client.get("/haproxy/backend-sets", headers=self.headers).get_data(as_text=True)
        self.assertIn("/haproxy/tcp/rdp/edit", listing)


class TheWiring(unittest.TestCase):
    def test_editors_lists_and_forms_offer_the_sets(self):
        for name in ("haproxy_site_edit.html", "haproxy_tcp_edit.html"):
            text = (APP / "templates" / name).read_text(encoding="utf-8")
            self.assertIn('{% include "_backend_set_picker.html" %}', text, name)
            self.assertIn('<div id="backend-manual">', text, name)
        for name in ("haproxy_sites.html", "haproxy_tcp.html", "haproxy_udp.html"):
            text = (APP / "templates" / name).read_text(encoding="utf-8")
            self.assertIn('name="servers_preset"', text, name)
            self.assertIn("js/backend_sets.js", text, name)
        nav = (APP / "templates" / "_haproxy_nav.html").read_text(encoding="utf-8")
        self.assertIn('"routes.backend_presets_page"', nav)
        for name in ("haproxy_site_edit.js", "haproxy_tcp.js"):
            self.assertIn("window.backendSetChoice", (APP / "static" / "js" / name).read_text(encoding="utf-8"))

    def test_the_page_and_picker_translate_whole(self):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("backend_sets_i18n", APP / "i18n.py")
            i18n = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(i18n)
        except ImportError:
            self.skipTest("the panel's dependencies are not installed here")
        for text in ("Backend sets", "Backend set", "Manual addresses", "Manage backend sets",
                     "Type the address", "Type the addresses", "Save backend set",
                     "Set the backend port for the backend set (1-65535)",
                     "Changing a set changes every entry that uses it. Sites and TCP proxies take the "
                     "change when the HAProxy configuration is validated and applied; UDP forwards are "
                     "applied at once."):
            self.assertNotEqual(i18n.translate(text, "ru"), text)


if __name__ == "__main__":
    unittest.main()
