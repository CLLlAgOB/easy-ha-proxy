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
    from haproxy_admin import create_app  # noqa: E402
    from haproxy_admin import backend_presets as sets  # noqa: E402
    from haproxy_admin import services_haproxy_config as config_service  # noqa: E402
    from haproxy_admin import services_haproxy_sites as sites_service  # noqa: E402
    from haproxy_admin import services_haproxy_tcp as tcp_service  # noqa: E402
    from haproxy_admin import services_haproxy_udp as udp_service  # noqa: E402

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
class UdpStaysInStep(_Files):
    """UDP rules are applied at once; vars.yml goes back with the HAProxy sources.

    A review found three ways the two drifted apart: a rename whose UDP apply
    failed, a rename or address change taken back by a rollback of vars.yml,
    and a set deleted while a UDP forward naming it was saved alongside.
    """

    def setUp(self):
        self.fail_udp = False
        super().setUp()
        self.assertTrue(sets.save_preset(UPLINKS)[0])
        self.assertTrue(sites_service.save_site_from_json({
            "name": "app.example.test", "domain": "app.example.test",
            "servers_preset": "Two uplinks", "servers_preset_port": 80})[0])
        ok, message = udp_service.save_udp_from_json({
            "name": "wg", "listen_port": "51820", "backend_port": "51820", "servers_preset": "Two uplinks"})
        self.assertTrue(ok, message)

    def fake_udp_apply(self, data):
        if self.fail_udp:
            return False, "nft refused the rules"
        return super().fake_udp_apply(data)

    def renamed(self):
        return {"name": "Uplinks", "servers": [
            {"host": "198.51.100.77", "role": "primary"}, {"host": "203.0.113.20", "role": "backup"}]}

    def forward(self, name="wg"):
        return next(f for f in self.load(self.udp)["udp_forwards"] if f["name"] == name)

    def revision(self):
        return sets.preset_revision(sets.load_presets()[0])

    def test_a_forward_keeps_the_id_of_its_set(self):
        preset_id = sets.load_presets()[0]["id"]
        self.assertRegex(preset_id, r"^[0-9a-f]{12}$")
        self.assertEqual(self.forward()["servers_preset_id"], preset_id)

    def test_a_rename_whose_udp_apply_fails_changes_nothing(self):
        before = {path: path.read_bytes() for path in (self.vars, self.websites, self.tcp, self.udp)}
        revision = self.revision()
        self.fail_udp = True
        ok, message = sets.save_preset(self.renamed(), "Two uplinks", revision)
        self.assertFalse(ok)
        self.assertIn("nft refused the rules", message)
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw, path.name)
        # The same form saves once the rules can be applied again.
        self.fail_udp = False
        ok, message = sets.save_preset(self.renamed(), "Two uplinks", revision)
        self.assertTrue(ok, message)
        self.assertEqual((self.forward()["servers_preset"], self.forward()["backend_host"]),
                         ("Uplinks", "198.51.100.77"))

    def test_a_forward_the_new_set_does_not_fit_stops_the_save_before_any_write(self):
        before = {path: path.read_bytes() for path in (self.vars, self.websites, self.udp)}
        revision = self.revision()
        with mock.patch.object(udp_service, "_normalize_udp_entry", return_value=(False, "no room", None)):
            ok, message = sets.save_preset(self.renamed(), "Two uplinks", revision)
        self.assertFalse(ok)
        self.assertIn("wg", message)
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw, path.name)

    def applied_now(self):
        """Record the current sources as the last applied state."""
        state = self.vars.parent.parent / "applied"
        state.mkdir(exist_ok=True)
        targets = {
            "HAPROXY_STATE_PATH": state / "state.json",
            "HAPROXY_STATE_VARS": state / "vars.yml",
            "HAPROXY_STATE_WEBSITES": state / "websites.yml",
            "HAPROXY_STATE_TCP": state / "tcp.yml",
        }
        targets["HAPROXY_STATE_PATH"].write_text("{}", encoding="utf-8")
        targets["HAPROXY_STATE_VARS"].write_bytes(self.vars.read_bytes())
        targets["HAPROXY_STATE_WEBSITES"].write_bytes(self.websites.read_bytes())
        targets["HAPROXY_STATE_TCP"].write_bytes(self.tcp.read_bytes())
        for name, value in targets.items():
            patcher = mock.patch.object(config_service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_discarding_a_rename_takes_the_forward_back_to_the_old_name_and_address(self):
        self.applied_now()
        self.assertTrue(sets.save_preset(self.renamed(), "Two uplinks", self.revision())[0])
        self.assertEqual(self.forward()["servers_preset"], "Uplinks")

        ok, message = config_service.revert_to_last_applied_state()
        self.assertTrue(ok, message)
        self.assertIn("UDP forward", message)
        forward = self.forward()
        self.assertEqual((forward["servers_preset"], forward["backend_host"]), ("Two uplinks", "198.51.100.10"))
        ok, message = sets.delete_preset("Two uplinks")
        self.assertFalse(ok)
        self.assertIn("wg", message)
        # Nothing to follow the second time round: no write, no apply.
        applied = len(self.applied)
        self.assertEqual(sets.reconcile_udp(), (True, 0, ""))
        self.assertEqual(len(self.applied), applied)

    def test_a_forward_whose_set_was_taken_back_keeps_its_addresses(self):
        self.applied_now()
        self.assertTrue(sets.save_preset({"name": "Spare", "servers": [{"host": "192.0.2.9", "role": "primary"}]})[0])
        ok, message = udp_service.save_udp_from_json({
            "name": "dns", "listen_port": "5353", "backend_port": "53", "servers_preset": "Spare"})
        self.assertTrue(ok, message)
        self.assertTrue(config_service.revert_to_last_applied_state()[0])
        dns = self.forward("dns")
        self.assertEqual(dns["backend_host"], "192.0.2.9")
        self.assertNotIn("servers_preset", dns)
        self.assertNotIn("servers_preset_id", dns)

    def test_a_forward_named_by_a_stale_name_still_counts_for_its_set(self):
        forward = self.forward()
        forward["servers_preset"] = "Old name"
        self.udp.write_text(yaml.safe_dump({"udp_forwards": [forward]}), encoding="utf-8")
        users = sets.usage()["Two uplinks"]
        self.assertEqual([u["name"] for u in users if u["kind"] == "udp"], ["wg"])

    def test_deleting_checks_the_forwards_with_udp_yml_locked(self):
        held = []
        real_usage = sets.usage

        def watching(*args, **kwargs):
            held.append(set(getattr(config_service._SOURCE_LOCKS_HELD, "kinds", set())))
            return real_usage(*args, **kwargs)

        with mock.patch.object(sets, "usage", side_effect=watching):
            ok, _message = sets.delete_preset("Two uplinks")
        self.assertFalse(ok)
        self.assertIn("udp", held[0])

    def test_a_transaction_that_settles_brings_the_forwards_along(self):
        transaction = "a" * 20
        settled = {"ok": True, "state": "rolled_back", "transaction_id": transaction}
        with mock.patch.object(config_service, "_read_pending_transaction_marker",
                               return_value={"transaction_id": transaction}), \
                mock.patch.object(config_service, "_clear_pending_transaction_marker"), \
                mock.patch.object(config_service, "_controld_json_request", return_value=settled), \
                mock.patch.object(sets, "reconcile_udp_quietly", return_value="") as follow:
            config_service.get_config_transaction_status(transaction)
        follow.assert_called_once()
        with mock.patch.object(config_service, "_read_pending_transaction_marker", return_value={}), \
                mock.patch.object(config_service, "_controld_json_request",
                                  return_value={"ok": True, "state": "none"}), \
                mock.patch.object(sets, "reconcile_udp_quietly", return_value="") as follow:
            config_service.get_config_transaction_status()
        follow.assert_not_called()


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

    def test_the_picker_hides_the_manual_table_and_shows_the_set_read_only(self):
        # The picker (and its script) sits above the manual table, so the
        # script must wait for the page: run at once it found no table to hide,
        # and the old addresses stayed editable under a chosen set.
        script = (APP / "static" / "js" / "backend_sets.js").read_text(encoding="utf-8")
        self.assertIn("DOMContentLoaded", script)
        self.assertIn(".backend-set-port", script)
        picker = (APP / "templates" / "_backend_set_picker.html").read_text(encoding="utf-8")
        self.assertIn("backend-set-view", picker)
        self.assertIn('class="form-input backend-set-port" disabled', picker)
        self.assertIn("{% if picker_weights %}", picker)
        site = (APP / "templates" / "haproxy_site_edit.html").read_text(encoding="utf-8")
        tcp = (APP / "templates" / "haproxy_tcp_edit.html").read_text(encoding="utf-8")
        self.assertIn("{% set picker_weights = true %}", site)
        self.assertIn("{% set picker_weights = false %}", tcp)

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
                     "The addresses, roles and weights below come from the set and are changed on the "
                     "backend sets page; only the port is chosen here.",
                     "The addresses and roles below come from the set and are changed on the backend "
                     "sets page; only the port is chosen here.",
                     "Changing a set changes every entry that uses it. Sites and TCP proxies take the "
                     "change when the HAProxy configuration is validated and applied; UDP forwards are "
                     "applied at once."):
            self.assertNotEqual(i18n.translate(text, "ru"), text)


if __name__ == "__main__":
    unittest.main()
