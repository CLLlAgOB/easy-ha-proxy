"""Trap names: hostnames that point at the gateway and serve no site.

Scanners find a gateway's names in public certificate logs and walk them.
A name with a DNS record but no site gets nothing but that: on privatnet a
week brought 61 addresses to one such name and 57 to another. The operator
marks a name as a trap; a request for it bans the address at once.

Measured first: among those visitors were a few real clients -- people with
old bookmarks. An address that otherwise uses the gateway like a client is
therefore spared and only counted, and the page shows, per name, how many
client-like addresses ask for it before anyone makes it a trap. A name that
serves a site can never be a trap.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_traps", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()

CONFIG = """
frontend fe_https
    acl valid_host hdr(host) -i ha.example.test shop.example.test www.shop.example.test
"""


def line(ip, host, path="/", status=400, server="fe_https/<NOSRV>"):
    return (
        f"2026-10-26T07:00:00.000000+00:00 host haproxy[1]: "
        f"{ip}:1234 [26/Oct/2026:07:00:00.000] fe_https~ {server} "
        f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 host={host} GET {path} HTTP/1.1"
    )


class Names(unittest.TestCase):
    def test_site_names_come_from_the_valid_host_acl(self):
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as handle:
            handle.write(CONFIG)
        self.addCleanup(Path(handle.name).unlink)
        self.assertEqual(
            guardd.read_site_names(handle.name),
            {"ha.example.test", "shop.example.test", "www.shop.example.test"},
        )
        self.assertEqual(guardd.read_site_names("/nonexistent/haproxy.cfg"), set())

    def test_normalize_host(self):
        self.assertEqual(guardd.normalize_host("Old.Example.Test:443"), "old.example.test")
        for odd in ("", "-", "203.0.113.5", "203.0.113.5:80", "[::1]:443", "bad_name!", "single"):
            with self.subTest(host=odd):
                self.assertEqual(guardd.normalize_host(odd), "")

    def test_a_site_name_can_never_be_a_trap(self):
        sites = {"shop.example.test"}
        with self.assertRaises(ValueError):
            guardd.validate_trap_hosts(["Shop.Example.Test"], sites)
        with self.assertRaises(ValueError):
            guardd.validate_trap_hosts(["203.0.113.5"], sites)
        self.assertEqual(
            guardd.validate_trap_hosts(["old.example.test", "OLD.example.test:443"], sites),
            ["old.example.test"],
        )


class Engine(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.cfg = root / "haproxy.cfg"
        self.cfg.write_text(CONFIG, encoding="utf-8")
        patcher = mock.patch.object(guardd, "HAPROXY_CONFIG_PATH", str(self.cfg))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        whitelist = root / "whitelist.ip"
        whitelist.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=(str(whitelist),))
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(config, self.database)
        self.engine.cursor.read(4096)

    def feed(self, *lines, now=1000):
        with self.log.open("a", encoding="utf-8") as handle:
            for text in lines:
                handle.write(text + "\n")
        self.engine.ingest_log(now)

    def listing(self):
        return {row["host"]: row for row in self.engine.unknown_hosts.listing()}

    def test_names_without_a_site_are_counted_and_site_names_are_not(self):
        self.feed(line("203.0.113.1", "freepbx.example.test"),
                  line("203.0.113.2", "freepbx.example.test:443"),
                  line("203.0.113.3", "shop.example.test", status=200, server="be_shop/srv1"),
                  line("203.0.113.4", "198.51.100.1"))
        rows = self.listing()
        self.assertEqual(set(rows), {"freepbx.example.test"})
        self.assertEqual(rows["freepbx.example.test"]["addresses"], 2)

    def test_a_trap_bans_a_stranger(self):
        self.engine.set_trap_hosts(["freepbx.example.test"])
        self.feed(line("203.0.113.9", "freepbx.example.test"))
        events = self.database.events_for("203.0.113.9", 0)
        self.assertEqual([(e["event_type"], e["category"]) for e in events],
                         [(guardd.EVENT_SCANNER_DECISIVE, "trap")])
        self.assertGreaterEqual(
            self.engine.reputation("203.0.113.9", 1000)["score"], guardd.WOULD_BAN_SCORE
        )

    def test_a_client_with_an_old_bookmark_is_spared_and_counted(self):
        self.engine.set_trap_hosts(["freepbx.example.test"])
        client = "198.51.100.50"
        self.feed(*[line(client, "shop.example.test", f"/p{n}", 200, "be_shop/srv1") for n in range(25)])
        self.feed(line(client, "freepbx.example.test"))
        self.assertEqual(self.database.events_for(client, 0), [])
        self.assertEqual(self.listing()["freepbx.example.test"]["clients"], 1)

    def test_a_site_name_is_refused_as_a_trap(self):
        with self.assertRaises(ValueError):
            self.engine.set_trap_hosts(["www.shop.example.test"])

    def test_without_the_site_list_nothing_is_called_unknown(self):
        self.cfg.unlink()
        self.engine._site_names_checked = -1e9
        self.feed(line("203.0.113.1", "anything.example.test"))
        self.assertEqual(self.listing(), {})

    def test_trap_names_survive_a_restart(self):
        self.engine.set_trap_hosts(["freepbx.example.test"])
        again = guardd.GuardEngine(self.engine.config, self.database)
        self.assertEqual(again.trap_hosts, {"freepbx.example.test"})


class ThePage(unittest.TestCase):
    def test_card_routes_and_guarding(self):
        page = (APP / "templates/detection_rules.html").read_text(encoding="utf-8")
        script = (APP / "static/js/detection_rules.js").read_text(encoding="utf-8")
        routes = (APP / "routes_security.py").read_text(encoding="utf-8")
        self.assertIn('id="dr-traps"', page)
        self.assertIn('id="dr-unknown-hosts"', page)
        self.assertIn('fetch("/api/security/traps"', script)
        self.assertIn('@bp.get("/api/security/traps")', routes)
        self.assertIn('@bp.post("/api/security/traps")', routes)
        setter = routes.split("def api_set_traps")[1].split("@bp.")[0]
        self.assertIn("is_superadmin", setter)
        self.assertIn('"adaptive.rules"', setter)
        # Asking first when clients use the name too.
        self.assertIn("window.confirm", script.split("function addTrap")[1].split("function ")[0])


if __name__ == "__main__":
    unittest.main()
