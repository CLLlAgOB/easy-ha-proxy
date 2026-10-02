"""The signature list lives beside the daemon, and matches anywhere in a path.

Two things came out of replaying 713,945 requests from live gateways.

The list was matched against the first path segment only, and the single most
common attack in that traffic -- CVE-2017-9841, the phpunit eval-stdin.php
remote execution -- almost never arrives at the first segment. It comes as
/laravel/vendor/phpunit/..., /lib/phpunit/..., /api/vendor/phpunit/... Of the
thirty-odd variants mined, exactly one began with /vendor and was caught.

And the list was compiled into the daemon, so keeping up with what is
actually being probed meant rebuilding an image. It is a JSON file next to
the daemon now, replaceable the way the GeoIP database already is.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
GUARDD = FILES / "easy-ha-proxy-guardd.py"
SIGNATURES = FILES / "scanner-signatures.json"


def load():
    spec = importlib.util.spec_from_file_location("guardd_signatures", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_signatures"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class FileTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(SIGNATURES.read_text(encoding="utf-8"))

    def test_it_is_versioned(self):
        # Without a version nobody can tell which list a gateway is running.
        self.assertTrue(str(self.data.get("version") or "").strip())

    def test_every_category_used_is_declared_somewhere(self):
        used = set(self.data["segments"].values()) | set(self.data["paths"].values())
        self.assertTrue(used)
        # decisive is a subset of what is actually used; a decisive category
        # nothing maps to would silently do nothing.
        unknown = set(self.data["decisive"]) - used - {"trap"}
        self.assertEqual(unknown, set(), "decisive categories nothing produces")

    def test_the_decisive_categories_are_ones_no_client_wants(self):
        for category in ("secrets", "vcs", "backup", "rce-probe"):
            with self.subTest(category=category):
                self.assertIn(category, self.data["decisive"])

    def test_a_category_a_site_might_serve_is_not_decisive(self):
        for category in ("wordpress", "dependency", "app-framework", "config"):
            with self.subTest(category=category):
                self.assertNotIn(category, self.data["decisive"])

    def test_every_exact_path_is_absolute(self):
        for path in self.data["paths"]:
            with self.subTest(path=path):
                self.assertTrue(path.startswith("/"))


class LoadingTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(guardd.load_signatures, str(SIGNATURES))
        guardd.load_signatures(str(SIGNATURES))

    def test_the_shipped_file_loads(self):
        self.assertTrue(guardd.load_signatures(str(SIGNATURES)))
        self.assertNotEqual(guardd.SIGNATURE_VERSION, "built-in")

    def test_a_missing_file_keeps_the_built_in_list(self):
        # Protection that fails closed on a bad download is worse than
        # protection running yesterday's list.
        self.assertFalse(guardd.load_signatures("/nonexistent/signatures.json"))
        self.assertTrue(guardd.classify_path("/.env"))

    def test_a_broken_file_keeps_the_built_in_list(self):
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("{ not json at all")
            broken = handle.name
        self.addCleanup(lambda: Path(broken).unlink(missing_ok=True))
        self.assertFalse(guardd.load_signatures(broken))
        self.assertTrue(guardd.classify_path("/.env"))

    def test_an_empty_file_is_refused_rather_than_obeyed(self):
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump({"segments": {}, "paths": {}, "decisive": []}, handle)
            empty = handle.name
        self.addCleanup(lambda: Path(empty).unlink(missing_ok=True))
        # A list that matches nothing would silently switch scanning off.
        self.assertFalse(guardd.load_signatures(empty))
        self.assertTrue(guardd.classify_path("/.env"))

    def test_a_trap_becomes_a_decisive_path(self):
        import tempfile

        data = json.loads(SIGNATURES.read_text(encoding="utf-8"))
        data["traps"] = ["/only-a-scanner-would-ask"]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(data, handle)
            trapped = handle.name
        self.addCleanup(lambda: Path(trapped).unlink(missing_ok=True))
        self.assertTrue(guardd.load_signatures(trapped))
        category = guardd.classify_path("/only-a-scanner-would-ask")
        self.assertEqual(category, "trap")
        self.assertTrue(guardd.category_is_decisive(category))


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(guardd.load_signatures, str(SIGNATURES))
        guardd.load_signatures(str(SIGNATURES))

    def test_the_attack_is_caught_under_every_prefix_it_arrives_with(self):
        # Every one of these was mined from real traffic; first-segment
        # matching saw only the first.
        for path in (
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/lib/phpunit/src/Util/PHP/eval-stdin.php",
            "/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        ):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), "rce-probe")

    def test_a_secret_under_a_prefix_is_still_a_secret(self):
        self.assertEqual(guardd.classify_path("/.github/.env"), "secrets")

    def test_the_most_confident_match_wins_not_the_leftmost(self):
        # Both segments match; taking the first gave the same attack two
        # different verdicts depending on the prefix it arrived with.
        path = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        self.assertEqual(guardd.classify_path(path), "rce-probe")

    def test_an_asset_is_never_a_finding(self):
        # Matching every segment would otherwise turn a stylesheet a deploy
        # renamed under /vendor/ into reconnaissance.
        for path in (
            "/static/vendor/jquery.min.js",
            "/assets/vendor/bootstrap.css",
            "/wp-content/themes/x/style.css",
        ):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), "")

    def test_ordinary_paths_stay_ordinary(self):
        for path in ("/", "/api/users", "/webapi/entry.cgi", "/login"):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), "")

    def test_the_scan_is_bounded(self):
        # A hostile path can be made to have a thousand segments.
        deep = "/" + "/".join(f"s{n}" for n in range(500)) + "/.env"
        guardd.classify_path(deep)  # must simply return, quickly
        self.assertLessEqual(guardd.MAX_MATCHED_SEGMENTS, 32)


class DeploymentTests(unittest.TestCase):
    def test_ansible_ships_the_file_beside_the_daemon(self):
        tasks = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "tasks" / "guardd.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("scanner-signatures.json", tasks)
        self.assertIn("register: guardd_signatures", tasks)
        # And a new list restarts the daemon, or it would keep the old one
        # until something unrelated changed.
        self.assertIn("guardd_signatures.changed", tasks)

    def test_the_daemon_loads_it_before_reading_any_log(self):
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split("def main()")[1][:600]
        self.assertIn("load_signatures()", block)


if __name__ == "__main__":
    unittest.main()
