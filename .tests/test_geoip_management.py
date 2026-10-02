"""Regression tests for the privileged GeoIP management API boundary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
UPDATER_PATH = ROOT / "ansible/roles/geoip_acl/files/update_geoip.py"
CONTROLD_PATH = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"


class FakeReader:
    def metadata(self):
        return types.SimpleNamespace(
            database_type="DBIP-Country-Lite", node_count=20_000, build_epoch=1
        )

    def close(self):
        return None


def load_module(name: str, path: Path, replacements=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    if replacements:
        previous = {key: sys.modules.get(key) for key in replacements}
        sys.modules.update(replacements)
    else:
        previous = {}
    try:
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        for key, value in previous.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


def fake_maxminddb():
    return types.SimpleNamespace(
        MODE_AUTO=0,
        open_database=lambda *_args, **_kwargs: FakeReader(),
    )


class GeoIPSelectionTransactionTests(unittest.TestCase):
    def setUp(self):
        self.updater = load_module(
            f"geoip_manage_updater_{id(self)}",
            UPDATER_PATH,
            {"maxminddb": fake_maxminddb()},
        )

    @staticmethod
    def _args(root: Path, countries: list[str]) -> argparse.Namespace:
        return argparse.Namespace(
            directory=root / "geoip",
            selection_file=root / "geoip/selection.json",
            vars_file=root / "config/vars.yml",
            country=countries,
            access_filter_enabled=False,
            force_download=False,
            skip_reload=True,
            haproxy="/usr/sbin/haproxy",
            haproxy_config=root / "haproxy.cfg",
            systemctl="/usr/bin/systemctl",
            base_url="https://download.invalid",
            configure_selection=True,
        )

    @staticmethod
    def _seed(root: Path) -> tuple[bytes, bytes]:
        (root / "geoip").mkdir()
        (root / "config").mkdir()
        values = {
            "enable_geoip": True,
            "geoip_mode": "deny",
            "geoip_country_codes": ["US"],
            "unrelated": {"keep": "value"},
        }
        vars_raw = yaml.safe_dump(values, sort_keys=False).encode()
        selection_raw = (
            json.dumps(
                {
                    "version": 1,
                    "countries": ["US"],
                    "access_filter_enabled": True,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        (root / "config/vars.yml").write_bytes(vars_raw)
        (root / "geoip/selection.json").write_bytes(selection_raw)
        return vars_raw, selection_raw

    def test_configure_keeps_enable_and_mode_and_syncs_both_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._seed(root)
            observed = []

            def observe(args, **_kwargs):
                observed.append(
                    (
                        yaml.safe_load(args.vars_file.read_text()),
                        json.loads(args.selection_file.read_text()),
                    )
                )

            with mock.patch.object(self.updater, "update", side_effect=observe):
                self.updater.configure_selection(self._args(root, ["pl", "RU", "PL"]))

            values, selection = observed[0]
            self.assertEqual(values["geoip_country_codes"], ["PL", "RU"])
            self.assertTrue(values["enable_geoip"])
            self.assertEqual(values["geoip_mode"], "deny")
            self.assertEqual(values["unrelated"], {"keep": "value"})
            self.assertEqual(selection["countries"], ["PL", "RU"])
            self.assertTrue(selection["access_filter_enabled"])

    def test_failed_update_restores_vars_selection_and_active_acl(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_vars, old_selection = self._seed(root)
            calls = []

            def fail_then_restore(args, **_kwargs):
                calls.append(json.loads(args.selection_file.read_text())["countries"])
                if len(calls) == 1:
                    raise self.updater.GeoIPUpdateError("selected country missing")

            with mock.patch.object(self.updater, "update", side_effect=fail_then_restore):
                with self.assertRaisesRegex(
                    self.updater.GeoIPUpdateError,
                    "previous selection and active ACL were restored",
                ):
                    self.updater.configure_selection(self._args(root, ["PL"]))

            self.assertEqual(calls, [["PL"], ["US"]])
            self.assertEqual((root / "config/vars.yml").read_bytes(), old_vars)
            self.assertEqual((root / "geoip/selection.json").read_bytes(), old_selection)

    def test_empty_selection_is_rejected_while_filter_is_enabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._seed(root)
            with mock.patch.object(self.updater, "update") as update:
                with self.assertRaisesRegex(
                    self.updater.GeoIPUpdateError, "at least one country"
                ):
                    self.updater.configure_selection(self._args(root, []))
            update.assert_not_called()

    def test_selection_loader_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual.json"
            actual.write_text(
                '{"version":1,"countries":["US"],"access_filter_enabled":true}'
            )
            link = root / "selection.json"
            link.symlink_to(actual)
            with self.assertRaisesRegex(
                self.updater.GeoIPUpdateError, "regular file"
            ):
                self.updater.load_selection(link)

    @staticmethod
    def _write_transaction_state(path: Path, state: str, transaction_id: str) -> None:
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "state": state,
                    "transaction_id": transaction_id,
                }
            ),
            encoding="utf-8",
        )

    def test_active_config_transaction_without_matching_id_blocks_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "transaction.json"
            self._write_transaction_state(
                state_path, "pending_confirmation", "transaction-under-test"
            )

            with self.assertRaisesRegex(
                self.updater.GeoIPUpdateError,
                "configuration transaction is active",
            ):
                self.updater.verify_config_transaction_access(state_path, "")

    def test_matching_active_config_transaction_id_permits_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "transaction.json"
            transaction_id = "transaction-under-test"
            self._write_transaction_state(
                state_path, "prepared", transaction_id
            )

            self.updater.verify_config_transaction_access(
                state_path, transaction_id
            )

    def test_settled_or_missing_config_transaction_state_permits_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing_state = root / "missing.json"
            self.updater.verify_config_transaction_access(missing_state, "")

            settled_state = root / "transaction.json"
            self._write_transaction_state(
                settled_state, "confirmed", "settled-transaction"
            )
            self.updater.verify_config_transaction_access(settled_state, "")

    def test_unsafe_or_invalid_config_transaction_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual_state = root / "actual.json"
            self._write_transaction_state(
                actual_state, "pending_confirmation", "active-transaction"
            )
            linked_state = root / "transaction-link.json"
            linked_state.symlink_to(actual_state)

            with self.assertRaisesRegex(
                self.updater.GeoIPUpdateError, "transaction state is unsafe"
            ):
                self.updater.verify_config_transaction_access(linked_state, "")

            invalid_state = root / "invalid.json"
            invalid_state.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(
                self.updater.GeoIPUpdateError, "transaction state is invalid"
            ):
                self.updater.verify_config_transaction_access(invalid_state, "")

    def test_config_transaction_cli_arguments_are_parsed(self):
        state_path = Path("/var/lib/easy-ha-proxy/guard/transaction.json")
        args = self.updater.parse_args(
            [
                "--config-transaction-state",
                str(state_path),
                "--config-transaction-id",
                "transaction-under-test",
            ]
        )

        self.assertEqual(args.config_transaction_state, state_path)
        self.assertEqual(args.config_transaction_id, "transaction-under-test")


class GeoIPControlDaemonTests(unittest.TestCase):
    def setUp(self):
        self.controld = load_module(f"geoip_manage_controld_{id(self)}", CONTROLD_PATH)

    def test_status_reports_release_counts_sizes_integrity_and_schedule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root / "releases"
            release = releases / "2026-07-release"
            release.mkdir(parents=True)
            database = release / "dbip-country-lite.mmdb"
            allowed = release / "allowed.geo"
            database.write_bytes(b"database")
            allowed.write_text("192.0.2.0/24\n")
            state = {
                "release_format_version": 1,
                "provider": "DB-IP Country Lite",
                "source_period": "2026-07",
                "activated_at": "2026-07-17T16:12:19+00:00",
                "database_build_epoch": 1,
                "database_records": 123456,
                "database_sha256": hashlib.sha256(b"database").hexdigest(),
                "allowed_sha256": hashlib.sha256(b"192.0.2.0/24\n").hexdigest(),
                "allowed_networks": 42,
                "countries": ["PL", "RU"],
                "country_networks": {"PL": {"ipv4": 20, "ipv6": 2}},
                "access_filter_enabled": True,
            }
            (release / "state.json").write_text(json.dumps(state))
            (root / "current").symlink_to("releases/2026-07-release")
            selection_raw = b'{"access_filter_enabled":true,"countries":["PL","RU"],"version":1}\n'
            (root / "selection.json").write_bytes(selection_raw)

            def properties(unit, _names):
                if unit.endswith(".timer"):
                    return {
                        "ActiveState": "active",
                        "SubState": "waiting",
                        "UnitFileState": "enabled",
                        "LastTriggerUSec": "Thu 2026-07-17 16:12:18 UTC",
                        "NextElapseUSecRealtime": "Fri 2026-07-18 18:00:00 UTC",
                    }
                return {
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "Result": "success",
                    "ExecMainStatus": "0",
                    "InactiveExitTimestamp": "Thu 2026-07-17 16:12:19 UTC",
                }

            with (
                mock.patch.object(self.controld, "GEOIP_DIRECTORY", root),
                mock.patch.object(self.controld, "GEOIP_RELEASES_PATH", releases),
                mock.patch.object(
                    self.controld, "GEOIP_SELECTION_PATH", root / "selection.json"
                ),
                mock.patch.object(
                    self.controld, "_systemd_properties", side_effect=properties
                ),
                mock.patch.object(
                    self.controld, "_geoip_journal_tail", return_value=["finished"]
                ),
                mock.patch.object(
                    self.controld, "_geoip_schedule_current", return_value="weekly"
                ),
            ):
                result = self.controld.geoip_status()

            self.assertEqual(result["timer"]["schedule"], "weekly")
            self.assertTrue(result["ok"])
            self.assertTrue(result["selection_applied"])
            self.assertEqual(result["database"]["records"], 123456)
            self.assertEqual(result["database"]["allowed_networks"], 42)
            self.assertEqual(result["database"]["size_bytes"], 8)
            self.assertTrue(result["database"]["integrity_ok"])
            self.assertEqual(result["service"]["result"], "success")
            self.assertEqual(
                result["timer"]["next_run_at"], "Fri 2026-07-18 18:00:00 UTC"
            )
            self.assertEqual(result["journal_tail"], ["finished"])

    def test_stale_revision_does_not_run_privileged_updater(self):
        with tempfile.TemporaryDirectory() as temporary:
            selection = Path(temporary) / "selection.json"
            selection.write_bytes(
                b'{"access_filter_enabled":true,"countries":["US"],"version":1}\n'
            )
            with (
                mock.patch.object(self.controld, "GEOIP_SELECTION_PATH", selection),
                mock.patch.object(self.controld, "_run_geoip_command") as command,
                mock.patch.object(self.controld, "geoip_status", return_value={"ok": True}),
            ):
                result = self.controld.geoip_configure(["PL"], "0" * 64)
            self.assertFalse(result["ok"])
            self.assertTrue(result["conflict"])
            command.assert_not_called()

    def test_set_schedule_rejects_non_whitelisted_value(self):
        with mock.patch.object(self.controld, "_run_geoip_command") as command:
            result = self.controld.geoip_set_schedule("hourly")
        self.assertFalse(result["ok"])
        self.assertIn("daily", result["error"])
        command.assert_not_called()  # never touched systemd for a bad value

    def test_set_schedule_writes_dropin_and_reloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            dropin = Path(temporary) / "timer.d" / "zz-web-schedule.conf"
            with (
                mock.patch.object(self.controld, "GEOIP_TIMER_DROPIN", dropin),
                mock.patch.object(
                    self.controld, "_run_geoip_command", return_value=(True, "")
                ) as command,
                mock.patch.object(
                    self.controld, "geoip_status", return_value={"ok": True}
                ),
            ):
                result = self.controld.geoip_set_schedule("monthly")
            self.assertTrue(result["ok"])
            self.assertEqual(result["schedule"], "monthly")
            content = dropin.read_text(encoding="ascii")
            # Clears the base OnCalendar then sets exactly the chosen cadence.
            self.assertIn("OnCalendar=\nOnCalendar=monthly", content)
            self.assertEqual(command.call_count, 2)  # daemon-reload + restart


class GeoIPWebServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        package_name = "geoip_web_test_package"
        package = types.ModuleType(package_name)
        package.__path__ = []
        config = types.ModuleType(f"{package_name}.services_haproxy_config")
        config.CONFIG_YAML = Path("/nonexistent/vars.yml")
        config.WEBSITES_YAML = Path("/nonexistent/websites.yml")
        config._controld_json_request = lambda *_args, **_kwargs: {}
        config.config_transaction_is_pending = lambda: (False, "")
        cls.service = load_module(
            f"{package_name}.services_geoip",
            ROOT / "docker/app/haproxy_admin/services_geoip.py",
            {
                package_name: package,
                f"{package_name}.services_haproxy_config": config,
            },
        )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        websites = Path(self.temporary.name) / "websites.yml"
        websites.write_text("sites: []\n", encoding="utf-8")
        self.websites_patch = mock.patch.object(
            self.service, "WEBSITES_YAML", websites
        )
        self.websites_patch.start()
        self.addCleanup(self.websites_patch.stop)

    def test_service_sends_canonical_countries_and_revision(self):
        revision = "a" * 64
        with mock.patch.object(
            self.service,
            "_request",
            return_value={"ok": True, "status": {}},
        ) as request:
            result = self.service.configure_geoip_countries(
                ["ru", "PL", "RU"], revision
            )
        self.assertTrue(result["ok"])
        request.assert_called_once_with(
            "geoip-configure",
            {"countries": ["PL", "RU"], "revision": revision},
        )

    def test_service_rejects_invalid_country_without_control_request(self):
        with mock.patch.object(self.service, "_request") as request:
            result = self.service.configure_geoip_countries(["RUS"], "a" * 64)
        self.assertFalse(result["ok"])
        self.assertTrue(result["validation_error"])
        request.assert_not_called()

    def test_service_cannot_remove_country_used_by_site_override(self):
        self.service.WEBSITES_YAML.write_text(
            "sites:\n"
            "  - name: app\n"
            "    domain: app.example.test\n"
            "    geo_countries: [PL, DE]\n",
            encoding="utf-8",
        )
        with mock.patch.object(self.service, "_request") as request:
            result = self.service.configure_geoip_countries(["DE"], "a" * 64)
        self.assertFalse(result["ok"])
        self.assertTrue(result["validation_error"])
        self.assertIn("PL (app.example.test)", result["error"])
        request.assert_not_called()

    def test_country_change_is_blocked_during_config_confirmation(self):
        with (
            mock.patch.object(
                self.service,
                "config_transaction_is_pending",
                return_value=(True, "A configuration confirmation is pending"),
            ),
            mock.patch.object(self.service, "_request") as request,
        ):
            result = self.service.configure_geoip_countries(["RU"], "a" * 64)
        self.assertFalse(result["ok"])
        self.assertTrue(result["conflict"])
        request.assert_not_called()

    def test_runtime_countries_are_canonical_before_sync_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            vars_file = Path(temporary) / "vars.yml"
            vars_file.write_text(
                "enable_geoip: true\n"
                "geoip_mode: allow\n"
                "geoip_country_codes: [RU, pl, RU]\n"
            )
            with mock.patch.object(self.service, "CONFIG_YAML", vars_file):
                result = self.service._runtime_geoip_config()
        self.assertTrue(result["available"])
        self.assertEqual(result["countries"], ["PL", "RU"])

    def test_reconcile_does_not_write_when_runtime_is_already_in_sync(self):
        status = {
            "ok": True,
            "runtime_config_in_sync": True,
            "runtime_config": {
                "available": True,
                "enable_geoip": True,
                "countries": ["RU"],
            },
            "selection": {"revision": "a" * 64},
        }
        with (
            mock.patch.object(self.service, "get_geoip_status", return_value=status),
            mock.patch.object(self.service, "configure_geoip_countries") as configure,
        ):
            result = self.service.reconcile_geoip_runtime()
        self.assertTrue(result["ok"])
        self.assertTrue(result["unchanged"])
        configure.assert_not_called()

    def test_reconcile_uses_current_vars_countries_and_selection_revision(self):
        revision = "b" * 64
        status = {
            "ok": True,
            "runtime_config_in_sync": False,
            "runtime_config": {
                "available": True,
                "enable_geoip": False,
                "countries": ["PL", "RU"],
            },
            "selection": {"revision": revision},
        }
        with (
            mock.patch.object(self.service, "get_geoip_status", return_value=status),
            mock.patch.object(
                self.service,
                "configure_geoip_countries",
                return_value={"ok": True},
            ) as configure,
        ):
            result = self.service.reconcile_geoip_runtime()
        self.assertTrue(result["ok"])
        configure.assert_called_once_with(["PL", "RU"], revision)


class GeoIPDeploymentAssertions(unittest.TestCase):
    def test_runtime_selection_is_synchronized_and_used_by_every_update(self):
        tasks = (ROOT / "ansible/roles/geoip_acl/tasks/main.yml").read_text()
        wrapper = (
            ROOT / "ansible/roles/geoip_acl/templates/update-geoip.sh.j2"
        ).read_text()
        defaults = (ROOT / "ansible/roles/geoip_acl/defaults/main.yml").read_text()
        init_source = (ROOT / "docker/app/haproxy_admin/__init__.py").read_text()
        self.assertIn("Synchronize the runtime GeoIP country selection", tasks)
        self.assertIn("geoip_runtime_vars_raw", tasks)
        self.assertIn("haproxy_admin_sync_managed_config", tasks)
        self.assertIn("default(geoip_country_codes | default([]))", tasks)
        self.assertIn("default(enable_geoip | default(false))", tasks)
        self.assertNotIn("default(geoip_country_codes | default([]), true)", tasks)
        self.assertNotIn("default(enable_geoip | default(false), true)", tasks)
        self.assertNotIn(
            "Synchronize the runtime GeoIP country selection\n  ansible.builtin.copy:\n"
            "    force: false",
            tasks,
        )
        self.assertIn("--selection-file /etc/haproxy/geoip/selection.json", wrapper)
        self.assertIn(
            "--config-transaction-state "
            "/var/lib/easy-ha-proxy/haproxy-config-guard/transaction.json",
            wrapper,
        )
        self.assertIn("PyYAML=={{ geoip_pyyaml_version }}", tasks)
        self.assertIn("import maxminddb, yaml", wrapper)
        self.assertLess(wrapper.index("rm -f --"), wrapper.index("import maxminddb, yaml"))
        self.assertIn("geoip_pyyaml_version", defaults)
        self.assertIn("routes_geoip", init_source)

    def test_geoip_page_exposes_status_country_management_and_async_updates(self):
        template = (
            ROOT / "docker/app/haproxy_admin/templates/haproxy_geoip.html"
        ).read_text()
        javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/geoip.js"
        ).read_text()
        navigation = (
            ROOT / "docker/app/haproxy_admin/templates/_haproxy_nav.html"
        ).read_text()

        self.assertIn('id="geoip-db-records"', template)
        self.assertIn('id="geoip-allowed-networks"', template)
        self.assertIn('id="geoip-save-countries"', template)
        self.assertIn('id="geoip-next-run"', template)
        self.assertIn('id="geoip-journal"', template)
        self.assertIn('/haproxy/geoip/status', javascript)
        self.assertIn('/haproxy/geoip/update', javascript)
        self.assertIn('/haproxy/geoip/countries', javascript)
        self.assertIn('revision: selectionRevision', javascript)
        self.assertIn('UPDATE_POLL_INTERVAL_MS', javascript)
        self.assertIn('payload.update_running', javascript)
        self.assertIn("routes.haproxy_geoip_page", navigation)

    def test_web_worker_allows_long_geoip_acl_rebuilds(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        # Keep the worker alive longer than the bounded configd mail/GeoIP
        # operation while still finishing before HAProxy's 15-minute timeout.
        self.assertIn('"--timeout", "870"', dockerfile)

    def test_confirmed_haproxy_apply_is_commit_only(self):
        routes = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py"
        ).read_text()
        confirm_start = routes.index("def haproxy_config_confirm")
        confirm_end = routes.index("def haproxy_config_rollback_pending")
        confirm_source = routes[confirm_start:confirm_end]

        root_commit_position = confirm_source.index("confirm_cfg_transaction(")
        snapshot_position = confirm_source.index("save_applied_state_strict(cfg_text)")
        self.assertLess(root_commit_position, snapshot_position)
        self.assertNotIn("reconcile_geoip_runtime", confirm_source)
        self.assertNotIn("configure_geoip_countries", confirm_source)
        self.assertNotIn("reload_haproxy", confirm_source)
        self.assertEqual(confirm_source.count("render_haproxy_cfg()"), 1)
        self.assertIn('response["warnings"] = warnings', confirm_source)

    def test_confirmation_pauses_status_polling_while_commit_is_in_flight(self):
        javascript = (
            ROOT / "docker/app/haproxy_admin/static/js/haproxy_config.js"
        ).read_text()
        confirm_source = javascript.split(
            "async function confirmPendingConfiguration()", 1
        )[1].split("async function rollbackPendingConfiguration()", 1)[0]
        poll_source = javascript.split(
            "async function pollTransactionStatus()", 1
        )[1].split("async function confirmPendingConfiguration()", 1)[0]

        self.assertLess(
            confirm_source.index("transactionActionInFlight = true"),
            confirm_source.index('requestJson("/haproxy/config/confirm"'),
        )
        self.assertLess(
            confirm_source.index("pauseTransactionPolling()"),
            confirm_source.index('requestJson("/haproxy/config/confirm"'),
        )
        self.assertIn(
            "if (!pendingTransaction || transactionActionInFlight) return",
            poll_source,
        )
        self.assertIn(
            "pollGeneration !== transactionPollGeneration",
            poll_source,
        )
        self.assertIn(
            'return ["rollback_failed", "failed"].includes(state)',
            javascript,
        )
        self.assertIn("setButtonLoading(rollbackButton, false)", javascript)
        self.assertIn("scheduleTransactionPoll(0)", confirm_source)


if __name__ == "__main__":
    unittest.main()
