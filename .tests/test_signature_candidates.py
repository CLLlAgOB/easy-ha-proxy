"""Signatures the traffic suggests.

Mining a week of two gateways by hand found probes no rule matched -- Cisco
ASA, GPON, new .env names -- each refused to 6-15 addresses and served to
nobody. The engine now keeps that tally itself: a path no signature matches,
refused (401/403/404/410) to at least three different addresses and never
served, is offered on the detection rules page to add as a signature or to
hide. A path that ordinary clients asked for too sinks to the bottom and is
marked, because that is more likely a broken link than a probe.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_candidates", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()


def line(ip, path, status=404, size=100, host="shop.example.test"):
    backend = "fe_https/<NOSRV>" if status in (403, 451) else "be_shop/srv1"
    return (
        f"2026-10-26T07:00:00.000000+00:00 host haproxy[1]: "
        f"{ip}:1234 [26/Oct/2026:07:00:00.000] fe_https~ {backend} "
        f"0/0/0/1/1 {status} {size} ---- 1/1/0/0/0 0/0 host={host} GET {path} HTTP/1.1"
    )


class Engine(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        whitelist = root / "whitelist.ip"
        whitelist.write_text("", encoding="utf-8")
        self.config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=(str(whitelist),))
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(self.config, self.database)
        self.engine.cursor.read(4096)

    def feed(self, *lines, now=1000):
        with self.log.open("a", encoding="utf-8") as handle:
            for text in lines:
                handle.write(text + "\n")
        self.engine.ingest_log(now)

    def suggested(self):
        return {row["path"]: row for row in self.engine.candidates.suggestions(set())}


class WhatIsSuggested(Engine):
    def test_three_addresses_make_a_suggestion_two_do_not(self):
        self.feed(line("203.0.113.1", "/+NEWVPN+/logon.html"),
                  line("203.0.113.2", "/+NEWVPN+/logon.html"))
        self.assertNotIn("/+NEWVPN+/logon.html", self.suggested())
        self.feed(line("203.0.113.3", "/+NEWVPN+/logon.html", status=403))
        row = self.suggested()["/+NEWVPN+/logon.html"]
        self.assertEqual(row["addresses"], 3)
        self.assertEqual(row["status"], {"404": 2, "403": 1})
        self.assertEqual(row["hosts"], ["shop.example.test"])

    def test_one_address_asking_many_times_is_one_address(self):
        self.feed(*[line("203.0.113.1", "/probe-me") for _ in range(20)])
        self.assertNotIn("/probe-me", self.suggested())

    def test_a_path_the_site_serves_is_never_suggested(self):
        self.feed(*[line(f"203.0.113.{n}", "/old-page") for n in range(1, 6)])
        self.assertIn("/old-page", self.suggested())
        self.feed(line("198.51.100.9", "/old-page", status=200))
        self.assertNotIn("/old-page", self.suggested())
        # And it stays out when the refusals go on.
        self.feed(*[line(f"203.0.113.{n}", "/old-page") for n in range(10, 15)])
        self.assertNotIn("/old-page", self.suggested())

    def test_a_path_a_rule_already_matches_is_not_suggested(self):
        self.feed(*[line(f"203.0.113.{n}", "/.git/config") for n in range(1, 6)])
        self.assertNotIn("/.git/config", self.suggested())

    def test_assets_and_the_root_are_never_suggested(self):
        self.feed(*[line(f"203.0.113.{n}", "/img/missing.png") for n in range(1, 6)])
        self.feed(*[line(f"203.0.113.{n}", "/") for n in range(1, 6)])
        self.assertEqual(self.suggested(), {})

    def test_a_hidden_suggestion_stays_hidden(self):
        self.feed(*[line(f"203.0.113.{n}", "/remoteDesktopGateway", status=401) for n in range(1, 6)])
        guardd.dismiss_candidate(self.database, "/remoteDesktopGateway")
        dismissed = set(guardd._dismissed_candidates(self.database))
        self.assertNotIn("/remoteDesktopGateway",
                         {r["path"] for r in self.engine.candidates.suggestions(dismissed)})
        guardd.dismiss_candidate(self.database, "/remoteDesktopGateway", restore=True)
        self.assertEqual(guardd._dismissed_candidates(self.database), [])

    def test_clients_asking_too_sink_to_the_bottom_and_are_counted(self):
        client = "198.51.100.50"
        self.feed(*[line(client, f"/page{n}", status=200) for n in range(25)])
        self.feed(*[line(f"203.0.113.{n}", "/broken-link") for n in range(1, 4)],
                  line(client, "/broken-link"))
        self.feed(*[line(f"203.0.113.{n}", "/probe") for n in range(1, 4)])
        rows = self.engine.candidates.suggestions(set())
        self.assertEqual([r["path"] for r in rows], ["/probe", "/broken-link"])
        self.assertEqual(rows[1]["clients"], 1)


class ItSurvivesARestart(Engine):
    def test_the_tally_is_kept_in_the_database(self):
        # Real time: maintenance prunes anything older than a week by the clock.
        import time
        now = int(time.time())
        self.feed(*[line(f"203.0.113.{n}", "/persisted") for n in range(1, 4)], now=now)
        self.engine.run_maintenance()
        again = guardd.GuardEngine(self.config, self.database)
        again.cursor.read(1 << 20)
        self.assertIn("/persisted", {r["path"] for r in again.candidates.suggestions(set())})
        # The same addresses after the restart are still three, not six.
        with self.log.open("a", encoding="utf-8") as handle:
            for n in range(1, 4):
                handle.write(line(f"203.0.113.{n}", "/persisted") + "\n")
        again.ingest_log(now + 60)
        rows = {r["path"]: r for r in again.candidates.suggestions(set())}
        self.assertEqual(rows["/persisted"]["addresses"], 3)

    def test_the_address_key_is_stable(self):
        # crc32, not hash(): hash() of a string changes with every process.
        import zlib
        self.assertEqual(guardd._address_key("203.0.113.1"), zlib.crc32(b"203.0.113.1"))


class OperatorPrefixes(unittest.TestCase):
    def test_a_trailing_star_is_accepted_on_a_segment(self):
        self.assertEqual(guardd.validate_token(".env*"), ".env*")
        self.assertEqual(guardd.validate_token("wlwmanifest*"), "wlwmanifest*")

    def test_too_broad_or_misplaced_prefixes_are_refused(self):
        for token in ("a*", "ab*", "/admin*", "*", "a*b"):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    guardd.validate_token(token)


class ThePage(unittest.TestCase):
    def test_the_card_and_its_endpoints(self):
        page = (APP / "templates/detection_rules.html").read_text(encoding="utf-8")
        script = (APP / "static/js/detection_rules.js").read_text(encoding="utf-8")
        routes = (APP / "routes_security.py").read_text(encoding="utf-8")
        self.assertIn('id="dr-suggestions"', page)
        self.assertIn('id="dr-suggest-category"', page)
        self.assertIn("/api/security/detection-rules/candidates", script)
        self.assertIn("/api/security/detection-rules/candidates/dismiss", script)
        self.assertIn('@bp.get("/api/security/detection-rules/candidates")', routes)
        self.assertIn('@bp.post("/api/security/detection-rules/candidates/dismiss")', routes)
        dismiss = routes.split("def api_dismiss_detection_rule_candidate")[1].split("@bp.")[0]
        self.assertIn('is_superadmin', dismiss)
        self.assertIn('"adaptive.rules"', dismiss)

    def test_the_new_words_are_translated(self):
        catalogue = json.loads(
            (APP / "translations/ru/detection_rules.json").read_text(encoding="utf-8")
        )["messages"]
        for key in ("Suggested by traffic", "Add as", "Client-like", "Status codes",
                    "No suggestions right now", "Hidden",
                    "last {days} days, at least {count} different addresses"):
            self.assertIn(key, catalogue)


if __name__ == "__main__":
    unittest.main()
