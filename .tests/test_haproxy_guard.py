"""Regression tests for transactional HAProxy config apply and rollback."""

from __future__ import annotations

import base64
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_controld():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_controld_guard", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GuardedConfigApplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controld = load_controld()

    @staticmethod
    def checks_b64() -> str:
        checks = [
            {"service": "admin", "domain": "ha.example.test"},
            {"service": "authelia", "domain": "aut.example.test"},
        ]
        return base64.b64encode(json.dumps(checks).encode("utf-8")).decode("ascii")

    def run_guarded(self, check_side_effect):
        protected_acls = (
            b"    acl host_admin hdr(host) -i ha.example.test\n"
            b"    acl host_authelia hdr(host) -i aut.example.test\n"
        )
        previous = b"global\n    user haproxy\n# previous\n" + protected_acls
        candidate = b"global\n    user haproxy\n# candidate\n" + protected_acls
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "haproxy.cfg"
            backup_dir = Path(tmp) / "backups"
            config_path.write_bytes(previous)

            def fake_write(payload: str) -> None:
                config_path.write_bytes(base64.b64decode(payload))

            with (
                mock.patch.object(self.controld, "HAPROXY_CFG_PATH", str(config_path)),
                mock.patch.object(self.controld, "CONFIG_BACKUP_DIR", backup_dir),
                mock.patch.object(
                    self.controld,
                    "haproxy_write_config_from_b64",
                    side_effect=fake_write,
                ) as write_config,
                mock.patch.object(
                    self.controld,
                    "cmd_reload",
                    return_value=(True, "reloaded"),
                ) as reload_config,
                mock.patch.object(
                    self.controld,
                    "_run_control_plane_checks",
                    side_effect=check_side_effect,
                ) as run_checks,
            ):
                result = self.controld.haproxy_apply_config_guarded(
                    base64.b64encode(candidate).decode("ascii"),
                    self.checks_b64(),
                )
                final_config = config_path.read_bytes()
                backups = list(backup_dir.glob("haproxy.cfg.pre-apply.*"))
                backup_contents = [path.read_bytes() for path in backups]

        return {
            "result": result,
            "final_config": final_config,
            "backups": backup_contents,
            "write_count": write_config.call_count,
            "reload_count": reload_config.call_count,
            "check_count": run_checks.call_count,
            "previous": previous,
            "candidate": candidate,
        }

    def test_success_keeps_candidate_after_both_services_pass(self) -> None:
        passed = [[
            {
                "service": "admin",
                "domain": "ha.example.test",
                "ok": True,
                "status": 200,
                "failure": "",
            },
            {
                "service": "authelia",
                "domain": "aut.example.test",
                "ok": True,
                "status": 200,
                "failure": "",
            },
        ]]
        outcome = self.run_guarded(passed)

        self.assertTrue(outcome["result"]["ok"])
        self.assertTrue(outcome["result"]["applied"])
        self.assertFalse(outcome["result"]["rolled_back"])
        self.assertEqual(outcome["final_config"], outcome["candidate"])
        self.assertEqual(outcome["backups"], [outcome["previous"]])
        self.assertEqual(outcome["write_count"], 1)
        self.assertEqual(outcome["reload_count"], 1)
        self.assertEqual(outcome["check_count"], 1)

    def test_failed_admin_check_restores_and_verifies_previous_config(self) -> None:
        candidate_failed = [{
            "service": "admin",
            "domain": "ha.example.test",
            "ok": False,
            "status": 503,
            "failure": "expected HTTP 200, received HTTP 503",
        }]
        rollback_passed = [{
            "service": "admin",
            "domain": "ha.example.test",
            "ok": True,
            "status": 200,
            "failure": "",
        }]
        outcome = self.run_guarded([candidate_failed, rollback_passed])

        self.assertFalse(outcome["result"]["ok"])
        self.assertTrue(outcome["result"]["rolled_back"])
        self.assertTrue(outcome["result"]["rollback_ok"])
        self.assertIn("admin (ha.example.test)", outcome["result"]["failure"])
        self.assertEqual(outcome["final_config"], outcome["previous"])
        self.assertEqual(outcome["write_count"], 2)
        self.assertEqual(outcome["reload_count"], 2)
        self.assertEqual(outcome["check_count"], 2)

    def test_check_payload_requires_admin_and_rejects_invalid_domains(self) -> None:
        authelia_only = base64.b64encode(json.dumps([
            {"service": "authelia", "domain": "aut.example.test"},
        ]).encode("utf-8")).decode("ascii")
        with self.assertRaisesRegex(ValueError, "Admin check is required"):
            self.controld._decode_control_plane_checks(authelia_only)

        invalid_domain = base64.b64encode(json.dumps([
            {"service": "admin", "domain": "ha.example.test\r\nHost: attacker"},
        ]).encode("utf-8")).decode("ascii")
        with self.assertRaisesRegex(ValueError, "invalid control-plane domain"):
            self.controld._decode_control_plane_checks(invalid_domain)

    def test_root_daemon_rejects_protected_domain_replacement(self) -> None:
        previous = (
            b"acl host_admin hdr(host) -i ha.example.test\n"
            b"acl host_authelia hdr(host) -i aut.example.test\n"
        )
        candidate = (
            b"acl host_admin hdr(host) -i ha.default.invalid\n"
            b"acl host_authelia hdr(host) -i aut.default.invalid\n"
        )
        checks = self.controld._decode_control_plane_checks(self.checks_b64())
        with self.assertRaisesRegex(ValueError, "protected HAProxy Admin/Authelia"):
            self.controld._validate_guarded_control_plane_transition(
                previous,
                candidate,
                checks,
            )

    def test_template_and_route_expose_local_admin_probe_only(self) -> None:
        template = (
            ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
        ).read_text(encoding="utf-8")
        routes = (
            ROOT / "docker/app/haproxy_admin/routes_health.py"
        ).read_text(encoding="utf-8")
        config_routes = (
            ROOT / "docker/app/haproxy_admin/routes_haproxy_config.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "acl local_control_plane_probe src 127.0.0.1",
            template,
        )
        self.assertIn(
            "acl admin_control_plane_probe_method method GET",
            template,
        )
        self.assertIn(
            "bool(true) if host_admin local_control_plane_probe "
            "admin_control_plane_probe_path admin_control_plane_probe_method",
            template,
        )
        self.assertIn("if host_admin admin_control_plane_probe", template)
        self.assertIn(
            "Remote-Groups healthcheck if host_admin "
            "admin_control_plane_probe",
            template,
        )
        self.assertNotIn(
            "Remote-Groups superadmin if host_admin "
            "admin_control_plane_probe",
            template,
        )
        self.assertIn('@bp.get("/api/control-plane-health")', routes)
        self.assertTrue(
            "apply_result = apply_cfg_guarded(cfg_text)" in config_routes
            or "apply_result = begin_cfg_confirmation(" in config_routes
        )


class ConfirmableConfigTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controld = load_controld()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "haproxy.cfg"
        self.source_dir = self.root / "config"
        self.backup_dir = self.root / "backups"
        self.transaction_dir = self.root / "transaction"
        self.geoip_dir = self.root / "geoip"
        self.geoip_releases_dir = self.geoip_dir / "releases"
        self.geoip_selection_path = self.geoip_dir / "selection.json"
        self.admin_allowlist_path = self.root / "admin.allow"
        self.source_dir.mkdir()
        self.geoip_releases_dir.mkdir(parents=True)

        protected_acls = (
            b"    acl host_admin hdr(host) -i ha.example.test\n"
            b"    acl host_authelia hdr(host) -i aut.example.test\n"
        )
        self.previous_config = (
            b"global\n    user haproxy\n# previous\n" + protected_acls
        )
        self.candidate_config = (
            b"global\n    user haproxy\n# candidate\n" + protected_acls
        )
        self.config_path.write_bytes(self.previous_config)
        self.candidate_sources = {
            "vars.yml": b"admin_ips_enabled: true\n",
            "websites.yml": b"sites: []\n",
            "tcp.yml": b"tcp: []\n",
        }
        self.previous_sources = {
            "vars.yml": b"admin_ips_enabled: false\n",
            "websites.yml": b"sites: []\n# previous\n",
            "tcp.yml": b"tcp: []\n# previous\n",
        }
        for filename, content in self.candidate_sources.items():
            (self.source_dir / filename).write_bytes(content)

        self.previous_geoip_selection = {
            "version": 1,
            "countries": ["US"],
            "access_filter_enabled": True,
        }
        self.candidate_geoip_selection = {
            "version": 1,
            "countries": ["PL", "RU"],
            "access_filter_enabled": True,
        }
        self.previous_geoip_raw = self._selection_raw(
            self.previous_geoip_selection
        )
        self.geoip_selection_path.write_bytes(self.previous_geoip_raw)
        self.previous_admin_allowlist_raw = b"192.0.2.10\n"
        self.admin_allowlist_path.write_bytes(self.previous_admin_allowlist_raw)
        self._write_geoip_release(
            "previous-release",
            self.previous_geoip_selection,
            database=b"previous database",
            allowed=b"192.0.2.0/24\n",
        )
        (self.geoip_dir / "current").symlink_to(
            "releases/previous-release"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _selection_raw(selection: dict[str, object]) -> bytes:
        return (
            json.dumps(selection, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")

    def _write_geoip_release(
        self,
        name: str,
        selection: dict[str, object],
        *,
        database: bytes,
        allowed: bytes,
    ) -> Path:
        release = self.geoip_releases_dir / name
        release.mkdir()
        (release / "dbip-country-lite.mmdb").write_bytes(database)
        (release / "allowed.geo").write_bytes(allowed)
        state = {
            "release_format_version": 1,
            "countries": list(selection["countries"]),
            "access_filter_enabled": selection["access_filter_enabled"],
            "database_sha256": hashlib.sha256(database).hexdigest(),
            "allowed_sha256": hashlib.sha256(allowed).hexdigest(),
        }
        (release / "state.json").write_text(
            json.dumps(state, sort_keys=True), encoding="utf-8"
        )
        return release

    def _activate_geoip_release(self, name: str) -> None:
        current = self.geoip_dir / "current"
        current.unlink(missing_ok=True)
        current.symlink_to(f"releases/{name}")

    def _assert_previous_geoip_runtime(self) -> None:
        self.assertEqual(
            self.geoip_selection_path.read_bytes(), self.previous_geoip_raw
        )
        self.assertEqual(
            (self.geoip_dir / "current").resolve(),
            (self.geoip_releases_dir / "previous-release").resolve(),
        )

    def _assert_no_private_transaction_snapshots(
        self, result: dict[str, object]
    ) -> None:
        private_keys = {
            "previous_config_b64",
            "previous_sources",
            "control_plane_checks",
            "backup_path",
            "geoip",
            "candidate_selection",
            "candidate_selection_sha256",
            "candidate_fingerprint",
            "previous_selection_present",
            "previous_selection_b64",
            "previous_release",
            "geoip_update_output",
            "admin_allowlist",
            "previous_present",
            "previous_b64",
        }

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(private_keys.isdisjoint(value))
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(result)
        self.assertNotIn(
            base64.b64encode(self.previous_geoip_raw).decode("ascii"),
            json.dumps(result, sort_keys=True),
        )

    @staticmethod
    def _checks_b64() -> str:
        checks = [
            {"service": "admin", "domain": "ha.example.test"},
            {"service": "authelia", "domain": "aut.example.test"},
        ]
        return base64.b64encode(json.dumps(checks).encode("utf-8")).decode("ascii")

    def _sources_b64(
        self,
        *,
        candidate: dict[str, bytes] | None = None,
        previous: dict[str, bytes] | None = None,
        geoip_selection: dict[str, object] | None = None,
        admin_allowlist: list[str] | None = None,
    ) -> str:
        payload = {
            "candidate": {
                filename: base64.b64encode(content).decode("ascii")
                for filename, content in (candidate or self.candidate_sources).items()
            },
            "previous": {
                filename: base64.b64encode(content).decode("ascii")
                for filename, content in (previous or self.previous_sources).items()
            },
        }
        if geoip_selection is not None:
            payload["geoip_selection"] = geoip_selection
        if admin_allowlist is not None:
            payload["admin_allowlist"] = admin_allowlist
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    @staticmethod
    def _passed_checks():
        return [
            {
                "service": "admin",
                "domain": "ha.example.test",
                "path": "/api/control-plane-health",
                "ok": True,
                "status": 200,
                "failure": "",
            },
            {
                "service": "authelia",
                "domain": "aut.example.test",
                "path": "/api/health",
                "ok": True,
                "status": 200,
                "failure": "",
            },
        ]

    @contextmanager
    def _environment(self, *, check_side_effect=None):
        def fake_write(payload: str) -> None:
            self.config_path.write_bytes(base64.b64decode(payload))

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                self.controld, "HAPROXY_CFG_PATH", str(self.config_path)
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "CONFIG_BACKUP_DIR", self.backup_dir
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "CONFIG_SOURCE_DIR", self.source_dir
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "CONFIG_TRANSACTION_DIR", self.transaction_dir
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "ADMIN_ALLOWLIST_PATH", self.admin_allowlist_path
            ))
            stack.enter_context(mock.patch.object(
                self.controld,
                "haproxy_write_config_from_b64",
                side_effect=fake_write,
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "cmd_reload", return_value=(True, "reloaded")
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "_schedule_config_transaction_watchdog"
            ))
            if check_side_effect is None:
                stack.enter_context(mock.patch.object(
                    self.controld,
                    "_run_control_plane_checks",
                    return_value=self._passed_checks(),
                ))
            else:
                stack.enter_context(mock.patch.object(
                    self.controld,
                    "_run_control_plane_checks",
                    side_effect=check_side_effect,
                ))
            yield

    @contextmanager
    def _geoip_environment(self, *, events: list[str] | None = None):
        observed = events if events is not None else []

        def fake_updater(argv: list[str]):
            selection = json.loads(
                self.geoip_selection_path.read_text(encoding="utf-8")
            )
            self._write_geoip_release(
                "candidate-release",
                selection,
                database=b"candidate database",
                allowed=b"198.51.100.0/24\n",
            )
            self._activate_geoip_release("candidate-release")
            observed.append("geoip_finished")
            return True, "GeoIP candidate prepared"

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                self.controld, "GEOIP_DIRECTORY", self.geoip_dir
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "GEOIP_SELECTION_PATH", self.geoip_selection_path
            ))
            stack.enter_context(mock.patch.object(
                self.controld, "GEOIP_RELEASES_PATH", self.geoip_releases_dir
            ))
            stack.enter_context(mock.patch.object(
                self.controld,
                "_systemd_properties",
                return_value={"ActiveState": "inactive", "SubState": "dead"},
            ))
            updater = stack.enter_context(mock.patch.object(
                self.controld, "_run_geoip_command", side_effect=fake_updater
            ))
            yield updater

    def _begin(
        self,
        timeout: int = 120,
        *,
        geoip_selection: dict[str, object] | None = None,
        admin_allowlist: list[str] | None = None,
    ):
        return self.controld.begin_config_transaction(
            base64.b64encode(self.candidate_config).decode("ascii"),
            self._checks_b64(),
            self._sources_b64(
                geoip_selection=geoip_selection,
                admin_allowlist=admin_allowlist,
            ),
            str(timeout),
        )

    def test_begin_persists_private_pending_state_and_confirm_commits(self) -> None:
        with self._environment():
            pending = self._begin()

            self.assertTrue(pending["ok"])
            self.assertTrue(pending["pending"])
            self.assertEqual(pending["state"], "pending_confirmation")
            self.assertEqual(self.config_path.read_bytes(), self.candidate_config)
            self.assertNotIn("previous_config_b64", pending)
            self.assertNotIn("previous_sources", pending)
            state_path = self.transaction_dir / "transaction.json"
            self.assertEqual(stat.S_IMODE(self.transaction_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)

            confirmed = self.controld.confirm_config_transaction(
                pending["transaction_id"], pending["candidate_sha256"]
            )
            self.assertTrue(confirmed["ok"])
            self.assertFalse(confirmed["pending"])
            self.assertEqual(confirmed["state"], "confirmed")
            persisted = self.controld._load_config_transaction()
            self.assertNotIn("previous_config_b64", persisted)
            self.assertNotIn("previous_sources", persisted)
            self.assertEqual(self.config_path.read_bytes(), self.candidate_config)

            repeated = self.controld.confirm_config_transaction(
                pending["transaction_id"], pending["candidate_sha256"]
            )
            self.assertTrue(repeated["ok"])
            self.assertEqual(repeated["state"], "confirmed")

    def test_admin_allowlist_is_committed_with_confirmed_configuration(self) -> None:
        candidate = ["198.51.100.42/24", "2001:db8::10"]
        expected = b"198.51.100.0/24\n2001:db8::10\n"
        with self._environment():
            pending = self._begin(admin_allowlist=candidate)
            self.assertEqual(self.admin_allowlist_path.read_bytes(), expected)

            confirmed = self.controld.confirm_config_transaction(
                pending["transaction_id"], pending["candidate_sha256"]
            )

        self.assertEqual(confirmed["state"], "confirmed")
        self.assertEqual(self.admin_allowlist_path.read_bytes(), expected)
        persisted = self.controld._load_config_transaction()
        if persisted is not None:
            self.assertNotIn("admin_allowlist", persisted)
        self._assert_no_private_transaction_snapshots(confirmed)

    def test_admin_allowlist_is_restored_on_rollback_and_candidate_drift(self) -> None:
        with self._environment():
            pending = self._begin(admin_allowlist=["198.51.100.0/24"])
            rolled_back = self.controld.rollback_config_transaction(
                pending["transaction_id"]
            )
        self.assertEqual(rolled_back["state"], "rolled_back")
        self.assertTrue(rolled_back["rollback"]["admin_allowlist_ok"])
        self.assertEqual(
            self.admin_allowlist_path.read_bytes(),
            self.previous_admin_allowlist_raw,
        )

        self.config_path.write_bytes(self.previous_config)
        for filename, content in self.candidate_sources.items():
            (self.source_dir / filename).write_bytes(content)
        with self._environment():
            pending = self._begin(admin_allowlist=["198.51.100.0/24"])
            self.admin_allowlist_path.write_bytes(b"203.0.113.0/24\n")
            with self.assertRaisesRegex(RuntimeError, "candidate changed"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )

        self.assertEqual(
            self.admin_allowlist_path.read_bytes(),
            self.previous_admin_allowlist_raw,
        )

    def test_admin_allowlist_payload_rejects_invalid_entries(self) -> None:
        with self._environment(), self.assertRaisesRegex(
            ValueError, "invalid admin allow list entry"
        ):
            self._begin(admin_allowlist=["not-an-ip"])

    def test_geoip_updater_and_final_checks_finish_before_pending(self) -> None:
        events: list[str] = []
        persist_transaction = self.controld._persist_config_transaction

        def record_persist(state: dict[str, object]) -> None:
            if state.get("state") == "pending_confirmation":
                events.append("pending")
            persist_transaction(state)

        def record_reload():
            events.append("reload")
            self.assertEqual(
                (self.geoip_dir / "current").resolve(),
                (self.geoip_releases_dir / "candidate-release").resolve(),
            )
            return True, "reloaded"

        def record_checks(_checks):
            events.append("checks")
            self.assertEqual(
                json.loads(self.geoip_selection_path.read_text(encoding="utf-8")),
                self.candidate_geoip_selection,
            )
            return self._passed_checks()

        def record_watchdog(_transaction_id, _deadline):
            events.append("watchdog")

        with (
            self._environment(),
            self._geoip_environment(events=events) as updater,
            mock.patch.object(
                self.controld, "cmd_reload", side_effect=record_reload
            ),
            mock.patch.object(
                self.controld,
                "_run_control_plane_checks",
                side_effect=record_checks,
            ),
            mock.patch.object(
                self.controld,
                "_persist_config_transaction",
                side_effect=record_persist,
            ),
            mock.patch.object(
                self.controld,
                "_schedule_config_transaction_watchdog",
                side_effect=record_watchdog,
            ),
        ):
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )

        self.assertTrue(pending["ok"], pending)
        self.assertEqual(pending["state"], "pending_confirmation")
        self.assertEqual(
            events,
            ["geoip_finished", "reload", "checks", "pending", "watchdog"],
        )
        updater.assert_called_once_with([
            self.controld.GEOIP_UPDATE_COMMAND,
            "--skip-reload",
            "--config-transaction-id",
            pending["transaction_id"],
        ])
        self.assertEqual(
            [item["service"] for item in pending["checks"]],
            ["admin", "authelia"],
        )
        self._assert_no_private_transaction_snapshots(pending)

    def test_successful_geoip_confirmation_is_commit_only(self) -> None:
        with (
            self._environment(),
            self._geoip_environment() as updater,
            mock.patch.object(
                self.controld, "cmd_reload", return_value=(True, "reloaded")
            ) as reload_config,
            mock.patch.object(
                self.controld,
                "_run_control_plane_checks",
                return_value=self._passed_checks(),
            ) as run_checks,
        ):
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            updater.reset_mock()
            reload_config.reset_mock()
            run_checks.reset_mock()

            confirmed = self.controld.confirm_config_transaction(
                pending["transaction_id"], pending["candidate_sha256"]
            )

            updater.assert_not_called()
            reload_config.assert_not_called()
            run_checks.assert_not_called()
            self.assertEqual(confirmed["state"], "confirmed")
            self.assertEqual(self.config_path.read_bytes(), self.candidate_config)
            self.assertEqual(
                json.loads(self.geoip_selection_path.read_text(encoding="utf-8")),
                self.candidate_geoip_selection,
            )
            self.assertEqual(
                (self.geoip_dir / "current").resolve(),
                (self.geoip_releases_dir / "candidate-release").resolve(),
            )
            self.assertNotIn(
                "geoip", self.controld._load_config_transaction()
            )
            self._assert_no_private_transaction_snapshots(confirmed)

    def test_manual_rollback_restores_previous_geoip_runtime(self) -> None:
        with self._environment(), self._geoip_environment():
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            rolled_back = self.controld.rollback_config_transaction(
                pending["transaction_id"]
            )

            self.assertEqual(rolled_back["state"], "rolled_back")
            self.assertTrue(rolled_back["rollback"]["geoip_ok"])
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            self._assert_previous_geoip_runtime()
            self._assert_no_private_transaction_snapshots(rolled_back)

    def test_expired_transaction_restores_previous_geoip_runtime(self) -> None:
        with self._environment(), self._geoip_environment():
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            state = self.controld._load_config_transaction()
            state["deadline_epoch"] = 1
            self.controld._persist_config_transaction(state)

            expired = self.controld.config_transaction_status(
                pending["transaction_id"]
            )

            self.assertEqual(expired["state"], "rolled_back")
            self.assertTrue(expired["rollback"]["geoip_ok"])
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            self._assert_previous_geoip_runtime()
            self._assert_no_private_transaction_snapshots(expired)

    def test_geoip_selection_drift_before_confirm_triggers_rollback(self) -> None:
        with self._environment(), self._geoip_environment():
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            self.geoip_selection_path.write_bytes(self._selection_raw({
                "version": 1,
                "countries": ["DE"],
                "access_filter_enabled": True,
            }))

            with self.assertRaisesRegex(RuntimeError, "candidate changed"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )

            self.assertEqual(
                self.controld._load_config_transaction()["state"], "rolled_back"
            )
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            self._assert_previous_geoip_runtime()

    def test_geoip_release_drift_before_confirm_triggers_rollback(self) -> None:
        with self._environment(), self._geoip_environment():
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            self._write_geoip_release(
                "external-release",
                self.candidate_geoip_selection,
                database=b"externally replaced database",
                allowed=b"203.0.113.0/24\n",
            )
            self._activate_geoip_release("external-release")

            with self.assertRaisesRegex(RuntimeError, "candidate changed"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )

            self.assertEqual(
                self.controld._load_config_transaction()["state"], "rolled_back"
            )
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            self._assert_previous_geoip_runtime()

    def test_geoip_public_status_never_exposes_private_snapshots(self) -> None:
        with self._environment(), self._geoip_environment():
            pending = self._begin(
                geoip_selection=self.candidate_geoip_selection
            )
            status = self.controld.config_transaction_status(
                pending["transaction_id"]
            )
            confirmed = self.controld.confirm_config_transaction(
                pending["transaction_id"], pending["candidate_sha256"]
            )

        for result in (pending, status, confirmed):
            with self.subTest(state=result["state"]):
                self._assert_no_private_transaction_snapshots(result)

    def test_status_confirm_and_rollback_do_not_wait_behind_busy_operation(self) -> None:
        with self._environment():
            pending = self._begin()

            class BusyLock:
                def acquire(self, blocking=True):
                    if blocking:
                        raise AssertionError("transaction operation used a blocking lock")
                    return False

                def release(self):  # pragma: no cover - must never be called
                    raise AssertionError("an unacquired lock was released")

            busy_lock = BusyLock()
            with mock.patch.object(self.controld, "_GUARDED_APPLY_LOCK", busy_lock):
                status = self.controld.config_transaction_status(
                    pending["transaction_id"]
                )
            self.assertTrue(status["ok"])
            self.assertTrue(status["busy"])
            self.assertEqual(status["state"], "pending_confirmation")

            with mock.patch.object(self.controld, "_GUARDED_APPLY_LOCK", busy_lock):
                confirmed = self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )
            self.assertFalse(confirmed["ok"])
            self.assertTrue(confirmed["busy"])
            self.assertTrue(confirmed["retryable"])
            self.assertEqual(confirmed["state"], "pending_confirmation")

            with mock.patch.object(self.controld, "_GUARDED_APPLY_LOCK", busy_lock):
                rolled_back = self.controld.rollback_config_transaction(
                    pending["transaction_id"]
                )
            self.assertFalse(rolled_back["ok"])
            self.assertTrue(rolled_back["busy"])
            self.assertTrue(rolled_back["retryable"])
            self.assertEqual(rolled_back["state"], "pending_confirmation")

            class FakeConnection:
                def __init__(self, command: str):
                    self.requests = [command.encode("ascii") + b"\n"]
                    self.responses = []

                def settimeout(self, _timeout):
                    return None

                def recv(self, _size):
                    return self.requests.pop(0) if self.requests else b""

                def sendall(self, value):
                    self.responses.append(value)

            connection = FakeConnection(
                "confirm-config-transaction "
                f"{pending['transaction_id']} {pending['candidate_sha256']}"
            )
            with mock.patch.object(self.controld, "_GUARDED_APPLY_LOCK", busy_lock):
                self.controld.handle_client(connection)
            self.assertTrue(b"".join(connection.responses).startswith(b"ERROR "))

    def test_expired_transaction_restores_config_and_all_sources(self) -> None:
        with self._environment(
            check_side_effect=[self._passed_checks(), self._passed_checks()]
        ):
            pending = self._begin()
            state = self.controld._load_config_transaction()
            state["deadline_epoch"] = 1
            self.controld._persist_config_transaction(state)

            expired = self.controld.config_transaction_status(
                pending["transaction_id"]
            )

            self.assertTrue(expired["ok"])
            self.assertEqual(expired["state"], "rolled_back")
            self.assertTrue(expired["rollback"]["ok"])
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            for filename, content in self.previous_sources.items():
                self.assertEqual((self.source_dir / filename).read_bytes(), content)

    def test_wrong_or_late_confirmation_and_concurrent_begin_fail_closed(self) -> None:
        with self._environment(
            check_side_effect=[self._passed_checks(), self._passed_checks()]
        ):
            pending = self._begin()
            with self.assertRaisesRegex(ValueError, "id does not match"):
                self.controld.confirm_config_transaction(
                    "wrong-token", pending["candidate_sha256"]
                )
            with self.assertRaisesRegex(ValueError, "candidate hash"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], "0" * 64
                )
            with self.assertRaisesRegex(RuntimeError, "still active"):
                self._begin()

            state = self.controld._load_config_transaction()
            state["deadline_epoch"] = 1
            self.controld._persist_config_transaction(state)
            with self.assertRaisesRegex(RuntimeError, "too late"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )
            self.assertEqual(
                self.controld._load_config_transaction()["state"], "rolled_back"
            )
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)

    def test_pending_candidate_drift_rolls_back_and_blocks_legacy_writes(self) -> None:
        with self._environment(
            check_side_effect=[
                self._passed_checks(),
                self._passed_checks(),
                self._passed_checks(),
                self._passed_checks(),
            ]
        ):
            pending = self._begin()
            with self.assertRaisesRegex(RuntimeError, "still active"):
                self.controld.haproxy_write_config_serialized(
                    base64.b64encode(self.previous_config).decode("ascii")
                )
            with self.assertRaisesRegex(RuntimeError, "still active"):
                self.controld.haproxy_apply_config_guarded(
                    base64.b64encode(self.candidate_config).decode("ascii"),
                    self._checks_b64(),
                )

            self.config_path.write_bytes(b"unexpected external change\n")
            with self.assertRaisesRegex(RuntimeError, "candidate changed"):
                self.controld.confirm_config_transaction(
                    pending["transaction_id"], pending["candidate_sha256"]
                )
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            self.assertEqual(
                self.controld._load_config_transaction()["state"], "rolled_back"
            )

            for filename, content in self.candidate_sources.items():
                (self.source_dir / filename).write_bytes(content)
            second = self._begin()
            (self.source_dir / "vars.yml").write_bytes(b"external: change\n")
            with self.assertRaisesRegex(RuntimeError, "candidate changed"):
                self.controld.confirm_config_transaction(
                    second["transaction_id"], second["candidate_sha256"]
                )
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)
            for filename, content in self.previous_sources.items():
                self.assertEqual((self.source_dir / filename).read_bytes(), content)

    def test_manual_rollback_and_restart_recovery_are_idempotent(self) -> None:
        with self._environment(
            check_side_effect=[
                self._passed_checks(),
                self._passed_checks(),
                self._passed_checks(),
                self._passed_checks(),
            ]
        ):
            first = self._begin()
            rolled_back = self.controld.rollback_config_transaction(
                first["transaction_id"]
            )
            self.assertEqual(rolled_back["state"], "rolled_back")
            repeated_rollback = self.controld.rollback_config_transaction(
                first["transaction_id"]
            )
            self.assertTrue(repeated_rollback["ok"])
            self.assertEqual(repeated_rollback["state"], "rolled_back")

            for filename, content in self.candidate_sources.items():
                (self.source_dir / filename).write_bytes(content)
            self.config_path.write_bytes(self.previous_config)
            second = self._begin()
            state = self.controld._load_config_transaction()
            state["state"] = "prepared"
            self.controld._persist_config_transaction(state)
            self.controld.recover_config_transaction()

            recovered = self.controld.config_transaction_status(
                second["transaction_id"]
            )
            self.assertEqual(recovered["state"], "rolled_back")
            self.assertEqual(self.config_path.read_bytes(), self.previous_config)

    def test_source_mismatch_symlink_and_unsupported_filename_are_rejected(self) -> None:
        with self._environment():
            (self.source_dir / "vars.yml").write_bytes(b"changed: true\n")
            with self.assertRaisesRegex(ValueError, "changed before"):
                self._begin()

            (self.source_dir / "vars.yml").unlink()
            target = self.root / "outside.yml"
            target.write_bytes(self.candidate_sources["vars.yml"])
            (self.source_dir / "vars.yml").symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "unavailable or unsafe"):
                self._begin()

            bad_candidate = dict(self.candidate_sources)
            bad_candidate["../../etc/shadow"] = b"nope\n"
            with self.assertRaisesRegex(ValueError, "unsupported filename"):
                self.controld._decode_config_transaction_sources(
                    self._sources_b64(
                        candidate=bad_candidate,
                        previous={**self.previous_sources, "../../etc/shadow": b"nope\n"},
                    )
                )


if __name__ == "__main__":
    unittest.main()
