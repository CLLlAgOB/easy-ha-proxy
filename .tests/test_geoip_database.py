"""Regression tests for the local GeoIP database and derived HAProxy ACL."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
UPDATER_PATH = ROOT / "ansible/roles/geoip_acl/files/update_geoip.py"
CACHE_PATH = ROOT / "docker/app/haproxy_admin/cache.py"


class FakeMetadata:
    database_type = "DBIP-Country-Lite"
    node_count = 700_000
    build_epoch = 1_700_000_000
    ip_version = 6


class FakeReader:
    def __init__(self, records=(), country="US"):
        self.records = list(records)
        self.country = country
        self.closed = False

    def __iter__(self):
        return iter(self.records)

    def metadata(self):
        return FakeMetadata()

    def get(self, _address):
        return {"country": {"iso_code": self.country}}

    def close(self):
        self.closed = True


def load_module(name: str, path: Path, maxminddb_module):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"maxminddb": maxminddb_module}):
        spec.loader.exec_module(module)
    return module


def fake_maxminddb(open_database=None):
    module = types.ModuleType("maxminddb")
    module.MODE_MMAP = 1
    module.MODE_AUTO = 0
    module.open_database = open_database or (lambda _path, mode=None: FakeReader())
    return module


class GeoIPACLTests(unittest.TestCase):
    def test_mmdb_generates_selected_ipv4_and_ipv6_only(self) -> None:
        records = [
            (ipaddress.ip_network("8.8.8.0/24"), {"country": {"iso_code": "US"}}),
            (ipaddress.ip_network("2001:4860::/32"), {"country": {"iso_code": "US"}}),
            (ipaddress.ip_network("1.1.1.0/24"), {"country": {"iso_code": "AU"}}),
            (ipaddress.ip_network("2606:4700::/32"), {"country": {"iso_code": "AU"}}),
        ]

        def opener(_path, mode=None):
            self.assertEqual(mode, 0)
            return FakeReader(records)

        updater = load_module("geoip_updater_acl", UPDATER_PATH, fake_maxminddb(opener))
        updater.MIN_DATABASE_NODES = 1
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "country.mmdb"
            database.write_bytes(b"test")
            allowed, countries, counts, _, record_count = updater.derive_acl(
                database, ("US",)
            )

        self.assertEqual(record_count, 4)
        self.assertEqual(
            [str(network) for network in allowed],
            ["8.8.8.0/24", "2001:4860::/32"],
        )
        self.assertEqual([str(value) for value in countries["US"]], [
            "8.8.8.0/24", "2001:4860::/32"
        ])
        self.assertEqual(counts["US"], {"ipv4": 1, "ipv6": 1})

    def test_missing_selected_country_rejects_release(self) -> None:
        records = [
            (ipaddress.ip_network("8.8.8.0/24"), {"country": {"iso_code": "US"}}),
            (ipaddress.ip_network("2001:4860::/32"), {"country": {"iso_code": "US"}}),
        ]
        updater = load_module(
            "geoip_updater_missing",
            UPDATER_PATH,
            fake_maxminddb(lambda _path, mode=None: FakeReader(records)),
        )
        updater.MIN_DATABASE_NODES = 1
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "country.mmdb"
            database.write_bytes(b"test")
            with self.assertRaisesRegex(
                updater.GeoIPUpdateError, "selected countries are absent"
            ):
                updater.derive_acl(database, ("PL",))

    def _old_release(self, updater, root: Path) -> None:
        release = root / "releases/old"
        release.mkdir(parents=True)
        (release / updater.DATABASE_NAME).write_bytes(b"old-database")
        (release / updater.ALLOWED_NAME).write_text("192.0.2.0/24\n", encoding="ascii")
        (release / updater.STATE_NAME).write_text(
            json.dumps(
                {
                    "release_format_version": updater.RELEASE_FORMAT_VERSION,
                    "source_period": "2020-01",
                    "source_url": "old",
                    "countries": ["US"],
                    "access_filter_enabled": True,
                    "database_sha256": updater.sha256_file(
                        release / updater.DATABASE_NAME
                    ),
                    "allowed_sha256": updater.sha256_file(
                        release / updater.ALLOWED_NAME
                    ),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.symlink("releases/old", root / "current")

    def _args(self, root: Path, *, skip_reload: bool) -> argparse.Namespace:
        return argparse.Namespace(
            directory=root,
            base_url="https://download.invalid/free",
            country=["US"],
            access_filter_enabled=True,
            force_download=True,
            skip_reload=skip_reload,
            haproxy="/usr/sbin/haproxy",
            haproxy_config=root / "haproxy.cfg",
            systemctl="/usr/bin/systemctl",
        )

    def _new_database(self, build_dir: Path):
        path = build_dir / "download.mmdb"
        path.write_bytes(b"new-database")
        return path, "2030-02", "https://download.invalid/new", FakeMetadata()

    def _new_acl(self):
        network = ipaddress.ip_network("203.0.113.0/24")
        return (
            [network],
            {"US": [network]},
            {"US": {"ipv4": 1, "ipv6": 0}},
            FakeMetadata(),
            700_000,
        )

    def test_release_activation_switches_mmdb_and_acl_together(self) -> None:
        updater = load_module("geoip_updater_activate", UPDATER_PATH, fake_maxminddb())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._old_release(updater, root)
            (root / "US.cidr").write_text("192.0.2.0/24\n", encoding="ascii")
            (root / "custom-country.cidr").write_text(
                "192.0.2.0/24\n", encoding="ascii"
            )
            with (
                mock.patch.object(
                    updater,
                    "download_database",
                    side_effect=lambda _url, build, _periods: self._new_database(build),
                ),
                mock.patch.object(updater, "derive_acl", return_value=self._new_acl()),
            ):
                updater.update(self._args(root, skip_reload=True))

            current = (root / "current").resolve()
            self.assertEqual((current / updater.DATABASE_NAME).read_bytes(), b"new-database")
            self.assertEqual(
                (current / updater.ALLOWED_NAME).read_text(encoding="ascii"),
                "203.0.113.0/24\n",
            )
            self.assertEqual((root / updater.DATABASE_NAME).resolve(), current / updater.DATABASE_NAME)
            self.assertEqual((root / updater.ALLOWED_NAME).resolve(), current / updater.ALLOWED_NAME)
            self.assertEqual(os.readlink(root / "previous"), "releases/old")
            self.assertFalse((root / "US.cidr").exists())
            self.assertTrue((root / "custom-country.cidr").is_file())

    def test_unchanged_current_month_is_a_fast_no_op(self) -> None:
        updater = load_module("geoip_updater_noop", UPDATER_PATH, fake_maxminddb())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._old_release(updater, root)
            period = updater.month_candidates(datetime.now(timezone.utc))[0]
            state = {
                "release_format_version": updater.RELEASE_FORMAT_VERSION,
                "source_period": period,
                "countries": ["US"],
                "access_filter_enabled": True,
                "database_sha256": updater.sha256_file(
                    root / "releases/old" / updater.DATABASE_NAME
                ),
                "allowed_sha256": updater.sha256_file(
                    root / "releases/old" / updater.ALLOWED_NAME
                ),
            }
            (root / "releases/old" / updater.STATE_NAME).write_text(
                json.dumps(state), encoding="utf-8"
            )
            with (
                mock.patch.object(updater, "download_database") as download,
                mock.patch.object(updater, "derive_acl") as derive,
            ):
                args = self._args(root, skip_reload=True)
                args.force_download = False
                updater.update(args)
            download.assert_not_called()
            derive.assert_not_called()
            self.assertEqual(os.readlink(root / "current"), "releases/old")

    def test_checksum_mismatch_publishes_repaired_release(self) -> None:
        updater = load_module("geoip_updater_repair", UPDATER_PATH, fake_maxminddb())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._old_release(updater, root)
            release = root / "releases/old"
            period = updater.month_candidates(datetime.now(timezone.utc))[0]
            expected_allowed = updater.hashlib.sha256(
                b"203.0.113.0/24\n"
            ).hexdigest()
            database_sha256 = updater.sha256_file(release / updater.DATABASE_NAME)
            config_hash = updater.hashlib.sha256(
                json.dumps(
                    {
                        "release_format_version": updater.RELEASE_FORMAT_VERSION,
                        "countries": ("US",),
                        "access_filter_enabled": True,
                        "allowed_sha256": expected_allowed,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            release_id = f"{period}-{database_sha256[:12]}-{config_hash[:12]}"
            collision = root / "releases" / release_id
            release.rename(collision)
            (root / "current").unlink()
            os.symlink(f"releases/{release_id}", root / "current")
            release = collision
            state = {
                "release_format_version": updater.RELEASE_FORMAT_VERSION,
                "source_period": period,
                "source_url": "https://download.invalid/current",
                "countries": ["US"],
                "access_filter_enabled": True,
                "database_sha256": database_sha256,
                "allowed_sha256": expected_allowed,
            }
            (release / updater.STATE_NAME).write_text(
                json.dumps(state), encoding="utf-8"
            )
            (release / updater.ALLOWED_NAME).write_text(
                "198.51.100.0/24\n", encoding="ascii"
            )

            with (
                mock.patch.object(updater, "download_database") as download,
                mock.patch.object(
                    updater, "derive_acl", return_value=self._new_acl()
                ),
            ):
                args = self._args(root, skip_reload=True)
                args.force_download = False
                updater.update(args)

            download.assert_not_called()
            repaired = (root / "current").resolve()
            self.assertNotEqual(repaired, release.resolve())
            self.assertIn("-repair-", repaired.name)
            self.assertEqual(
                (repaired / updater.ALLOWED_NAME).read_text(encoding="ascii"),
                "203.0.113.0/24\n",
            )
            self.assertFalse((root / "previous").exists())

    def test_failed_control_plane_check_restores_previous_release(self) -> None:
        updater = load_module("geoip_updater_rollback", UPDATER_PATH, fake_maxminddb())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._old_release(updater, root)
            legacy_country = root / "US.cidr"
            legacy_country.write_text("192.0.2.0/24\n", encoding="ascii")
            with (
                mock.patch.object(
                    updater,
                    "download_database",
                    side_effect=lambda _url, build, _periods: self._new_database(build),
                ),
                mock.patch.object(updater, "derive_acl", return_value=self._new_acl()),
                mock.patch.object(updater, "haproxy_is_active", return_value=True),
                mock.patch.object(
                    updater,
                    "validate_reload_and_probe",
                    side_effect=[(False, "admin returned 503"), (True, "recovered")],
                ),
            ):
                with self.assertRaisesRegex(updater.GeoIPUpdateError, "rollback succeeded"):
                    updater.update(self._args(root, skip_reload=False))

            self.assertEqual(os.readlink(root / "current"), "releases/old")
            self.assertEqual(
                (root / updater.ALLOWED_NAME).read_text(encoding="ascii"),
                "192.0.2.0/24\n",
            )
            self.assertTrue(legacy_country.is_file())

    def test_legacy_haproxy_config_skips_guarded_probe(self) -> None:
        updater = load_module(
            "geoip_updater_legacy_probe", UPDATER_PATH, fake_maxminddb()
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "haproxy.cfg"
            config.write_text(
                "frontend fe_https\n"
                "    acl host_admin hdr(host) -i ha.example.test\n"
                "    acl host_authelia hdr(host) -i aut.example.test\n",
                encoding="utf-8",
            )
            with mock.patch.object(updater, "probe") as probe:
                ok, detail = updater.verify_control_plane(config)

        self.assertTrue(ok)
        self.assertIn("probe is unavailable", detail)
        probe.assert_not_called()

    def test_current_haproxy_config_enables_guarded_probe(self) -> None:
        updater = load_module(
            "geoip_updater_current_probe", UPDATER_PATH, fake_maxminddb()
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "haproxy.cfg"
            config.write_text(
                "frontend fe_https\n"
                "    acl host_admin hdr(host) -i ha.example.test\n"
                "    acl host_authelia hdr(host) -i aut.example.test\n"
                "    acl local_control_plane_probe src 127.0.0.1\n"
                "    acl admin_control_plane_probe_path path -i "
                "/api/control-plane-health\n"
                "    acl admin_control_plane_probe "
                "var(txn.admin_control_plane_probe) -m bool\n"
                "    http-request set-header Remote-User "
                "easy-ha-proxy-healthcheck if host_admin "
                "admin_control_plane_probe\n",
                encoding="utf-8",
            )

            self.assertEqual(
                updater.control_plane_checks(config),
                [
                    ("admin", "ha.example.test", "/api/control-plane-health"),
                    ("authelia", "aut.example.test", "/api/health"),
                ],
            )


class LocalLookupTests(unittest.TestCase):
    def test_reader_reopens_after_atomic_database_replacement(self) -> None:
        opened: list[FakeReader] = []

        def opener(path, mode=None):
            country = Path(path).read_text(encoding="ascii").strip()
            if country == "BAD":
                raise ValueError("corrupt database")
            reader = FakeReader(country=country)
            opened.append(reader)
            return reader

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "country.mmdb"
            database.write_text("US", encoding="ascii")
            with mock.patch.dict(
                os.environ,
                {
                    "HAPROXY_ADMIN_GEOIP_DB": str(database),
                    "HAPROXY_ADMIN_GEOIP_STAT_INTERVAL": "1",
                },
            ):
                cache = load_module("geoip_cache_reload", CACHE_PATH, fake_maxminddb(opener))
            cache.COUNTRY_DATABASE_STAT_INTERVAL = 0
            cache.init_cache()
            self.assertEqual(cache.get_country_code("8.8.8.8"), "US")

            replacement = database.with_suffix(".new")
            replacement.write_text("PL", encoding="ascii")
            os.replace(replacement, database)
            self.assertEqual(cache.get_country_code("8.8.8.8"), "PL")
            self.assertTrue(opened[0].closed)

            replacement.write_text("BAD", encoding="ascii")
            os.replace(replacement, database)
            self.assertEqual(cache.get_country_code("8.8.8.8"), "PL")
            self.assertFalse(opened[-1].closed)
            cache.close_country_database()

    def test_reader_is_not_closed_during_concurrent_lookup(self) -> None:
        lookup_started = threading.Event()
        allow_lookup_to_finish = threading.Event()
        old_reader_closed = threading.Event()
        opened: list[FakeReader] = []

        class BlockingReader(FakeReader):
            def get(self, _address):
                lookup_started.set()
                if not allow_lookup_to_finish.wait(timeout=2):
                    raise TimeoutError("test lookup was not released")
                if self.closed:
                    raise RuntimeError("reader was closed while get() was running")
                return {"country": {"iso_code": self.country}}

            def close(self):
                super().close()
                old_reader_closed.set()

        def opener(path, mode=None):
            country = Path(path).read_text(encoding="ascii").strip()
            reader = (
                BlockingReader(country=country)
                if not opened
                else FakeReader(country=country)
            )
            opened.append(reader)
            return reader

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "country.mmdb"
            database.write_text("US", encoding="ascii")
            with mock.patch.dict(
                os.environ,
                {
                    "HAPROXY_ADMIN_GEOIP_DB": str(database),
                    "HAPROXY_ADMIN_GEOIP_STAT_INTERVAL": "1",
                },
            ):
                cache = load_module(
                    "geoip_cache_concurrency", CACHE_PATH, fake_maxminddb(opener)
                )
            cache.COUNTRY_DATABASE_STAT_INTERVAL = 0
            cache.init_cache()

            results: dict[str, str] = {}
            first = threading.Thread(
                target=lambda: results.setdefault(
                    "first", cache.get_country_code("8.8.8.8")
                )
            )
            first.start()
            self.assertTrue(lookup_started.wait(timeout=1))

            replacement = database.with_suffix(".new")
            replacement.write_text("PL", encoding="ascii")
            os.replace(replacement, database)
            second_started = threading.Event()

            def second_lookup() -> None:
                second_started.set()
                results["second"] = cache.get_country_code("8.8.8.8")

            second = threading.Thread(target=second_lookup)
            second.start()
            self.assertTrue(second_started.wait(timeout=1))
            try:
                self.assertFalse(old_reader_closed.wait(timeout=0.2))
            finally:
                allow_lookup_to_finish.set()

            first.join(timeout=2)
            second.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(results, {"first": "US", "second": "PL"})
            self.assertTrue(old_reader_closed.is_set())
            cache.close_country_database()

    def test_private_addresses_do_not_reach_the_reader(self) -> None:
        calls = []

        def opener(_path, mode=None):
            calls.append(True)
            return FakeReader(country="US")

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "country.mmdb"
            database.write_text("US", encoding="ascii")
            with mock.patch.dict(os.environ, {"HAPROXY_ADMIN_GEOIP_DB": str(database)}):
                cache = load_module("geoip_cache_private", CACHE_PATH, fake_maxminddb(opener))
            self.assertEqual(cache.get_country_code("127.0.0.1"), "??")
            self.assertEqual(calls, [])


class DeploymentAssertions(unittest.TestCase):
    def test_no_runtime_geoip_or_flag_service_remains(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [
                ROOT / "docker/app/haproxy_admin/cache.py",
                ROOT / "docker/app/haproxy_admin/static/js/dashboard.js",
                ROOT / "docker/app/haproxy_admin/static/js/connections.js",
                ROOT / "docker/app/haproxy_admin/security.py",
            ]
        )
        self.assertNotIn("ip-api.com", sources)
        self.assertNotIn("ipapi.co", sources)
        self.assertNotIn("flagcdn.com", sources)
        self.assertNotIn("requests.get", sources)

    def test_local_flags_and_licenses_are_present(self) -> None:
        flags = ROOT / "docker/app/haproxy_admin/static/vendor/flag-icons/flags/4x3"
        two_letter = [path for path in flags.glob("??.svg") if path.stem.isalpha()]
        self.assertGreaterEqual(len(two_letter), 249)
        for code in ("ru", "pl", "us"):
            self.assertTrue((flags / f"{code}.svg").is_file())
        self.assertTrue((ROOT / "LICENSES/flag-icons-MIT.txt").is_file())
        self.assertTrue(
            (ROOT / "docker/app/haproxy_admin/static/vendor/flag-icons/LICENSE").is_file()
        )
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("DB-IP Country Lite", notices)
        self.assertIn("CC BY 4.0", notices)
        self.assertIn("flag-icons", notices)
        self.assertIn("*.mmdb", gitignore)
        self.assertIn("docker/app/**/*.mmdb", dockerignore)

    def test_geoip_timer_and_oneshot_have_correct_monitoring_semantics(self) -> None:
        healthd_config = (
            ROOT / "ansible/roles/haproxy-admin/templates/healthd.json.j2"
        ).read_text(encoding="utf-8")
        healthcheck_defaults = (
            ROOT / "ansible/roles/healthcheck/defaults/main.yml"
        ).read_text(encoding="utf-8")
        health_javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/health.js"
        ).read_text(encoding="utf-8")
        healthcheck_tasks = (
            ROOT / "ansible/roles/healthcheck/tasks/main.yml"
        ).read_text(encoding="utf-8")

        for unit in (
            "easy-ha-proxy-geoip-update.service",
            "easy-ha-proxy-geoip-update.timer",
        ):
            self.assertIn(unit, healthd_config)
        self.assertIn(
            'timer: "easy-ha-proxy-geoip-update.timer"', healthcheck_defaults
        )
        self.assertIn(
            'service: "easy-ha-proxy-geoip-update.service"', healthcheck_defaults
        )
        self.assertIn("unit.healthy", health_javascript)
        self.assertIn("^ActiveState=failed$", healthcheck_tasks)
        self.assertIn("^Result=(?!(?:success)?$).+$", healthcheck_tasks)
        self.assertIn("status_check_systemd_jobs_never_run", healthcheck_tasks)

    def test_deployment_uses_local_release_and_systemd_timer(self) -> None:
        compose = (
            ROOT / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2"
        ).read_text(encoding="utf-8")
        haproxy = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        tasks = (
            ROOT / "ansible/roles/geoip_acl/tasks/main.yml"
        ).read_text(encoding="utf-8")
        defaults = (
            ROOT / "ansible/roles/geoip_acl/defaults/main.yml"
        ).read_text(encoding="utf-8")
        wrapper = (
            ROOT / "ansible/roles/geoip_acl/templates/update-geoip.sh.j2"
        ).read_text(encoding="utf-8")
        updater = UPDATER_PATH.read_text(encoding="utf-8")
        app_start = (
            ROOT / "ansible/roles/haproxy-admin/tasks/start.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("HAPROXY_ADMIN_GEOIP_DB", compose)
        self.assertIn("/etc/haproxy:/etc/haproxy:ro", compose)
        self.assertIn("current/allowed.geo", haproxy)
        self.assertIn("easy-ha-proxy-geoip-update.timer", tasks)
        self.assertIn("Validate local GeoIP database settings", tasks)
        self.assertIn("ansible.builtin.assert", tasks)
        self.assertIn(
            "Build the current local GeoIP release through its systemd unit",
            tasks,
        )
        self.assertIn("easy-ha-proxy-geoip-update.service", tasks)
        self.assertIn("python3-venv", tasks)
        self.assertIn("ansible.builtin.pip", tasks)
        self.assertIn("maxminddb=={{ geoip_maxminddb_version }}", tasks)
        self.assertIn("geoip_runtime_venv", defaults)
        self.assertIn("geoip_runtime_venv", wrapper)
        self.assertIn(
            "geoip_runtime_venv | default('/usr/local/lib/easy-ha-proxy/geoip-venv')",
            wrapper,
        )
        self.assertNotIn("ansible_playbook_python", defaults + wrapper)
        self.assertNotIn("ipverse", updater.lower())
        self.assertNotIn("ipdeny", updater.lower())
        self.assertIn("country_cache.json", app_start)


if __name__ == "__main__":
    unittest.main()
