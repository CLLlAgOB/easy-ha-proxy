"""Saves of sites and TCP proxies from several sessions do not lose each other (F17).

From the 30 October review, reproduced there with two threads on the real
save_site_raw: each save read the whole websites.yml, changed one site and
wrote the file back, so two saves of different sites both succeeded and one
change was gone. A form left open while someone else saved the same site
wrote over that save unseen. TCP proxies used the same scheme.

Every read-change-write of websites.yml and tcp.yml now holds a lock that
all panel worker processes share, and an edit form carries a fingerprint
of the entry it loaded: a save from a page older than the stored entry is
refused with 409 instead of writing over it.
"""

from __future__ import annotations

import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))
WINDOWS = sys.platform == "win32"
if not WINDOWS:
    import flask

    from haproxy_admin import routes_haproxy_sites as site_routes  # noqa: E402
    from haproxy_admin import services_haproxy_config as config_service  # noqa: E402
    from haproxy_admin import services_haproxy_sites as sites_service  # noqa: E402
    from haproxy_admin import services_haproxy_tcp as tcp_service  # noqa: E402

ROUNDS = 25


def site(name, port=8080):
    return {"name": name, "domain": f"{name}.example.test", "backend_ip": "10.0.0.10",
            "backend_port": port}


def proxy(name, port=7000):
    return {"name": name, "bind_port": port, "backend_host": "10.0.0.20", "backend_port": 22}


def add_sites(prefix, start):
    start.wait()
    for number in range(ROUNDS):
        ok, message = sites_service.save_site_from_json(site(f"{prefix}{number}"))
        if not ok:
            raise SystemExit(message)


def add_proxies(prefix, start):
    start.wait()
    first_port = 7000 if prefix == "a" else 8000
    for number in range(ROUNDS):
        ok, message = tcp_service.save_tcp_from_json(proxy(f"{prefix}{number}", first_port + number))
        if not ok:
            raise SystemExit(message)


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class Sources(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "config").mkdir()
        self.websites = root / "config" / "websites.yml"
        self.tcp = root / "config" / "tcp.yml"
        self.websites.write_text("sites: []\n", encoding="utf-8")
        self.tcp.write_text("tcp_proxies: []\n", encoding="utf-8")
        for patcher in (
            mock.patch.object(config_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(config_service, "TCP_YAML", self.tcp),
            mock.patch.object(config_service, "CONFIG_YAML", root / "config" / "vars.yml"),
            mock.patch.object(config_service, "BASE_DIR", root),
            mock.patch.object(config_service, "config_transaction_is_pending", return_value=(False, "")),
            mock.patch.object(sites_service, "WEBSITES_YAML", self.websites),
            mock.patch.object(tcp_service, "TCP_YAML", self.tcp),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def stored_sites(self):
        return {s["name"]: s for s in yaml.safe_load(self.websites.read_text(encoding="utf-8"))["sites"]}

    def stored_proxies(self):
        return {p["name"]: p for p in yaml.safe_load(self.tcp.read_text(encoding="utf-8"))["tcp_proxies"]}

    def race(self, target):
        context = multiprocessing.get_context("fork")
        start = context.Barrier(2)
        workers = [context.Process(target=target, args=(prefix, start)) for prefix in ("a", "b")]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(120)
        self.assertEqual([worker.exitcode for worker in workers], [0, 0])

    def test_two_processes_adding_sites_keep_every_one(self):
        self.race(add_sites)
        names = set(self.stored_sites())
        expected = {f"{prefix}{number}" for prefix in "ab" for number in range(ROUNDS)}
        self.assertEqual(expected - names, set())

    def test_two_processes_adding_tcp_proxies_keep_every_one(self):
        self.race(add_proxies)
        names = set(self.stored_proxies())
        expected = {f"{prefix}{number}" for prefix in "ab" for number in range(ROUNDS)}
        self.assertEqual(expected - names, set())

    def test_a_form_older_than_the_site_is_refused(self):
        sites_service.save_site_from_json(site("shop"))
        loaded = sites_service.site_revision("shop")
        ok, _ = sites_service.save_site_from_json(site("shop", 8081), "shop", loaded)
        self.assertTrue(ok)
        with self.assertRaises(config_service.StaleEntry):
            sites_service.save_site_from_json(site("shop", 9090), "shop", loaded)
        self.assertEqual(self.stored_sites()["shop"]["backend_port"], 8081)

    def test_the_fingerprint_after_a_save_allows_the_next_one(self):
        sites_service.save_site_from_json(site("shop"))
        ok, _ = sites_service.save_site_from_json(site("shop", 8081), "shop",
                                                  sites_service.site_revision("shop"))
        self.assertTrue(ok)
        ok, _ = sites_service.save_site_from_json(site("shop", 8082), "shop",
                                                  sites_service.site_revision("shop"))
        self.assertTrue(ok)
        self.assertEqual(self.stored_sites()["shop"]["backend_port"], 8082)

    def test_a_save_of_another_site_does_not_make_a_form_stale(self):
        sites_service.save_site_from_json(site("shop"))
        sites_service.save_site_from_json(site("blog"))
        loaded = sites_service.site_revision("shop")
        sites_service.save_site_from_json(site("blog", 8090), "blog")
        ok, _ = sites_service.save_site_from_json(site("shop", 8081), "shop", loaded)
        self.assertTrue(ok)
        self.assertEqual(self.stored_sites()["blog"]["backend_port"], 8090)

    def test_a_tcp_form_older_than_the_proxy_is_refused(self):
        tcp_service.save_tcp_from_json(proxy("files"))
        loaded = tcp_service.tcp_revision("files")
        tcp_service.save_tcp_from_json(proxy("files", 7001), "files", loaded)
        with self.assertRaises(config_service.StaleEntry):
            tcp_service.save_tcp_from_json(proxy("files", 7002), "files", loaded)
        self.assertEqual(self.stored_proxies()["files"]["bind_port"], 7001)

    def test_the_save_route_answers_409_and_hands_back_the_fingerprint(self):
        sites_service.save_site_from_json(site("shop"))
        loaded = sites_service.site_revision("shop")
        app = flask.Flask(__name__)

        def post(port, revision):
            body = {"site": site("shop", port), "original_name": "shop", "revision": revision}
            with app.test_request_context("/haproxy/sites/save", method="POST", json=body), \
                    mock.patch.object(site_routes, "record_request"):
                answer = site_routes.haproxy_site_save()
            response, status = answer if isinstance(answer, tuple) else (answer, 200)
            return status, response.get_json()

        status, first = post(8081, loaded)
        self.assertEqual(status, 200)
        self.assertEqual(first["revision"], sites_service.site_revision("shop"))
        status, stale = post(9090, loaded)
        self.assertEqual(status, 409)
        self.assertTrue(stale["conflict"])
        status, _ = post(8082, first["revision"])
        self.assertEqual(status, 200)
        self.assertEqual(self.stored_sites()["shop"]["backend_port"], 8082)

    def test_the_lock_can_be_taken_again_by_its_holder(self):
        with config_service.source_lock("websites"):
            ok, _ = sites_service.save_site_from_json(site("shop"))
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
