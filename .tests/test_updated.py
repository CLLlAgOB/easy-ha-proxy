"""Focused security and lifecycle regressions for the web update broker."""

from __future__ import annotations

import ast
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON_PATH = (
    ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
)
UNIT_PATH = (
    ROOT
    / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-updated.service.j2"
)
TASK_PATH = ROOT / "ansible/roles/haproxy-admin/tasks/updated.yml"
BACKUPD_PATH = (
    ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"
)
BACKUPD_UNIT_PATH = (
    ROOT
    / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-backupd.service.j2"
)

DAEMON_SOURCE = DAEMON_PATH.read_text(encoding="utf-8")
UNIT_SOURCE = UNIT_PATH.read_text(encoding="utf-8")
TASK_SOURCE = TASK_PATH.read_text(encoding="utf-8")
BACKUPD_SOURCE = BACKUPD_PATH.read_text(encoding="utf-8")
BACKUPD_UNIT_SOURCE = BACKUPD_UNIT_PATH.read_text(encoding="utf-8")


def load_daemon():
    name = "easy_ha_proxy_updated_test"
    spec = importlib.util.spec_from_file_location(name, DAEMON_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {DAEMON_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


UPDATED = load_daemon()


def valid_plan(*components: dict) -> dict:
    return {
        "id": "a" * 32,
        "source_channel": "github",
        "image_channel": "latest",
        "components": list(components),
        "expires_at": "2999-01-01T00:00:00+00:00",
    }


def available(component_id: str, candidate: str = "new") -> dict:
    return {
        "id": component_id,
        "state": "available",
        "actionable": True,
        "installed": "old",
        "available": candidate,
    }


class UpdateBrokerProtocolTests(unittest.TestCase):
    def test_request_fields_and_component_allowlist_are_exact(self) -> None:
        self.assertEqual(
            UPDATED.REQUEST_FIELDS,
            {
                "status": frozenset({"action", "job_id"}),
                "start_check": frozenset(
                    {"action", "image_channel", "source_channel", "release_channel"}
                ),
                "start_apply": frozenset(
                    {"action", "plan_id", "components", "confirmation"}
                ),
                "set_channels": frozenset(
                    {"action", "image_channel", "source_channel", "release_channel"}
                ),
                "reboot": frozenset(
                    {"action", "confirmation", "expected_boot_id", "actor"}
                ),
                "cancel_reboot": frozenset(
                    {"action", "expected_boot_id", "actor"}
                ),
            },
        )
        self.assertEqual(
            UPDATED.ALLOWED_COMPONENTS,
            frozenset(
                {
                    "all",
                    "services",
                    "daemons",
                    "authelia-container",
                    "admin-container",
                    "os",
                }
            ),
        )
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.dispatch({"action": "status", "command": "id"})
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.selected_components(["admin-container;id"])
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.selected_components(["os", "os"])

    def test_checker_cannot_introduce_an_unknown_component(self) -> None:
        payload = {
            "source_channel": "github",
            "image_channel": "latest",
            "components": [available("arbitrary-command")],
        }
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.parse_checker_output(json.dumps(payload))

    def test_components_have_fixed_order_and_os_is_last(self) -> None:
        selected = UPDATED.selected_components(
            ["os", "admin-container", "daemons", "authelia-container", "services"]
        )
        self.assertEqual(
            selected,
            [
                "services",
                "daemons",
                "authelia-container",
                "admin-container",
                "os",
            ],
        )

    def test_all_supersedes_source_and_container_components_but_not_os(self) -> None:
        selected = UPDATED.selected_components(
            [
                "os",
                "admin-container",
                "services",
                "all",
                "authelia-container",
                "daemons",
            ]
        )
        self.assertEqual(selected, ["all", "os"])

    def test_expired_or_changed_plan_is_rejected(self) -> None:
        expired = valid_plan(available("admin-container"))
        expired["expires_at"] = "2000-01-01T00:00:00+00:00"
        self.assertTrue(UPDATED.plan_is_expired(expired))

        stored = valid_plan(available("admin-container", "sha256:old-target"))
        fresh = valid_plan(available("admin-container", "sha256:new-target"))
        with self.assertRaises(UPDATED.UpdatedError) as raised:
            UPDATED.validate_fresh_candidates(
                stored,
                fresh,
                ["admin-container"],
            )
        self.assertEqual(raised.exception.code, "stale_plan")

        with (
            mock.patch.object(UPDATED, "load_latest_plan", return_value=expired),
            self.assertRaises(UPDATED.UpdatedError) as stale,
        ):
            UPDATED.start_apply(
                {
                    "action": "start_apply",
                    "plan_id": expired["id"],
                    "components": ["admin-container"],
                    "confirmation": "UPDATE",
                }
            )
        self.assertEqual(stale.exception.code, "stale_plan")

    def test_digest_change_is_stale_even_when_update_count_is_unchanged(self) -> None:
        before = available("admin-container", "1")
        before["details"] = {
            "images": [
                {
                    "image": "example/admin:latest",
                    "state": "available",
                    "current_digest": "sha256:" + "1" * 64,
                    "available_digest": "sha256:" + "2" * 64,
                }
            ]
        }
        after = json.loads(json.dumps(before))
        after["details"]["images"][0]["available_digest"] = (
            "sha256:" + "3" * 64
        )
        with self.assertRaises(UPDATED.UpdatedError) as stale:
            UPDATED.validate_fresh_candidates(
                valid_plan(before),
                valid_plan(after),
                ["admin-container"],
            )
        self.assertEqual(stale.exception.code, "stale_plan")

    def test_update_command_is_fixed_argv_and_never_uses_a_shell(self) -> None:
        self.assertEqual(
            UPDATED.update_command(
                "admin-container",
                source_channel="github",
                image_channel="alpha",
            ),
            [
                "/usr/local/bin/easy-ha-proxy",
                "update",
                "--component",
                "admin-container",
                "--source-channel",
                "github",
                "--image-channel",
                "alpha",
            ],
        )
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.update_command(
                "--help",
                source_channel="github",
                image_channel="latest",
            )

        revision = "a" * 40
        self.assertEqual(
            UPDATED.update_command(
                "services",
                source_channel="github",
                image_channel="latest",
                expected_source_revision=revision,
            )[-2:],
            ["--expected-source-revision", revision],
        )
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.update_command(
                "services",
                source_channel="github",
                image_channel="latest",
            )

        tree = ast.parse(DAEMON_SOURCE)
        process_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"Popen", "run"}
            ):
                process_calls.append(node)
        self.assertTrue(process_calls)
        for call in process_calls:
            with self.subTest(line=call.lineno):
                shell = next(
                    (keyword.value for keyword in call.keywords if keyword.arg == "shell"),
                    None,
                )
                self.assertTrue(
                    shell is None
                    or (isinstance(shell, ast.Constant) and shell.value is False),
                    "privileged update subprocess must never enable a shell",
                )

    def test_all_pins_source_and_verifies_both_reviewed_container_digests(self) -> None:
        revision = "a" * 40

        def image_component(component_id: str, image: str, digest: str) -> dict:
            item = available(component_id, digest)
            item["details"] = {
                "images": [
                    {
                        "image": image,
                        "target_image": image,
                        "available_digest": digest,
                        "current_digest": digest,
                    }
                ]
            }
            return item

        source = available("all", revision)
        admin = image_component(
            "admin-container", "example/admin:latest", "sha256:" + "1" * 64
        )
        authelia = image_component(
            "authelia-container", "authelia/authelia:4", "sha256:" + "2" * 64
        )
        plan = valid_plan(source, admin, authelia)

        self.assertEqual(UPDATED.reviewed_source_revision(plan, ["all"]), revision)
        UPDATED.validate_reviewed_container_candidates(plan, plan, ["all"])
        UPDATED.validate_applied_container_digests(plan, plan, ["all"])

        drifted = json.loads(json.dumps(plan))
        drifted["components"][2]["details"]["images"][0]["current_digest"] = (
            "sha256:" + "3" * 64
        )
        with self.assertRaises(UPDATED.UpdatedError) as raised:
            UPDATED.validate_applied_container_digests(plan, drifted, ["all"])
        self.assertEqual(raised.exception.code, "verification_failed")


class UpdateBrokerBoundaryTests(unittest.TestCase):
    def test_peer_uid_comes_from_so_peercred_and_missing_support_fails_closed(self) -> None:
        expected_uid = 12345

        class Peer:
            def getsockopt(self, level, option, size):
                self.assertions = (level, option, size)
                return struct.pack("3i", 91, expected_uid, 23456)

        peer = Peer()
        self.assertEqual(UPDATED.peer_uid(peer), expected_uid)
        self.assertEqual(peer.assertions[0], socket.SOL_SOCKET)
        self.assertEqual(peer.assertions[1], socket.SO_PEERCRED)

        without_peercred = types.SimpleNamespace()
        with (
            mock.patch.object(UPDATED, "socket", without_peercred),
            self.assertRaises(UPDATED.UpdatedError),
        ):
            UPDATED.peer_uid(peer)

        self.assertIn("peer_uid(connection) not in {0, APP_UID}", DAEMON_SOURCE)

    def test_update_and_backup_share_the_same_cross_process_lock(self) -> None:
        expected = "/run/easy-ha-proxy/easy-ha-proxy-backupd.operation.lock"
        self.assertEqual(str(UPDATED.MAINTENANCE_LOCK_PATH), expected)
        self.assertIn(expected, BACKUPD_SOURCE)
        self.assertIn(
            "updated_maintenance_lock_path | default('" + expected + "')",
            UNIT_SOURCE,
        )

        with tempfile.TemporaryDirectory() as raw:
            lock_path = Path(raw) / "maintenance.lock"
            external = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(external, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (
                    mock.patch.object(UPDATED, "MAINTENANCE_LOCK_PATH", lock_path),
                    self.assertRaises(UPDATED.UpdatedError) as busy,
                ):
                    UPDATED.acquire_operation()
                self.assertEqual(busy.exception.code, "busy")
                self.assertFalse(UPDATED.OPERATION_THREAD_LOCK.locked())
            finally:
                fcntl.flock(external, fcntl.LOCK_UN)
                os.close(external)

    def test_sanitized_output_obeys_the_byte_cap(self) -> None:
        with mock.patch.object(UPDATED, "MAX_CAPTURE_BYTES", 40):
            result = UPDATED.sanitize_log("before\x00\r\n" + "Я" * 100)
        self.assertNotIn("\x00", result)
        self.assertNotIn("\r", result)
        self.assertTrue(result.startswith("[output truncated]\n"))
        self.assertLessEqual(len(result.encode("utf-8")), 40)

    def test_authoritative_haproxy_transaction_is_fail_closed(self) -> None:
        with (
            mock.patch.object(UPDATED.os.path, "lexists", side_effect=[False, True]),
            mock.patch.object(
                UPDATED,
                "safe_json_file",
                return_value={"state": "pending_confirmation"},
            ),
        ):
            self.assertTrue(UPDATED.haproxy_transaction_active())

        with (
            mock.patch.object(UPDATED.os.path, "lexists", side_effect=[False, True]),
            mock.patch.object(
                UPDATED,
                "safe_json_file",
                return_value={"state": "confirmed"},
            ),
        ):
            self.assertFalse(UPDATED.haproxy_transaction_active())

        with (
            mock.patch.object(UPDATED.os.path, "lexists", side_effect=[False, True]),
            mock.patch.object(
                UPDATED,
                "safe_json_file",
                side_effect=ValueError("broken state"),
            ),
        ):
            self.assertTrue(UPDATED.haproxy_transaction_active())

    def test_deferred_restart_marker_is_removed_only_after_systemctl_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "restart.requested"
            marker.write_text("requested\n", encoding="utf-8")
            with (
                mock.patch.object(UPDATED, "RESTART_REQUEST_MARKER", marker),
                mock.patch.object(
                    UPDATED.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(returncode=0),
                ) as run,
            ):
                UPDATED.request_self_restart_if_needed()
            self.assertFalse(marker.exists())
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/usr/bin/systemctl",
                    "try-restart",
                    "--no-block",
                    "easy-ha-proxy-updated.service",
                ],
            )
            self.assertNotIn("shell", run.call_args.kwargs)

            marker.write_text("requested\n", encoding="utf-8")
            with (
                mock.patch.object(UPDATED, "RESTART_REQUEST_MARKER", marker),
                mock.patch.object(
                    UPDATED.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(returncode=1),
                ),
            ):
                UPDATED.request_self_restart_if_needed()
            self.assertTrue(marker.exists())


class SetChannelsTests(unittest.TestCase):
    def test_set_channels_requires_a_valid_channel_selection(self) -> None:
        for request in (
            {"action": "set_channels"},
            {"action": "set_channels", "source_channel": "gitlab"},
            {"action": "set_channels", "image_channel": "nightly"},
            {"action": "set_channels", "source_channel": 1},
            {"action": "set_channels", "command": "id"},
        ):
            with self.subTest(request=request):
                with self.assertRaises(UPDATED.UpdatedError):
                    UPDATED.dispatch(request)

    def test_set_channels_runs_fixed_cli_argv_and_drops_cached_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "latest-plan.json"
            plan_path.write_text("{}\n", encoding="utf-8")
            lock_path = Path(temporary) / "operation.lock"
            with (
                mock.patch.object(UPDATED, "LATEST_PLAN_PATH", plan_path),
                mock.patch.object(UPDATED, "MAINTENANCE_LOCK_PATH", lock_path),
                mock.patch.object(
                    UPDATED,
                    "read_deployment",
                    return_value={"source_channel": "local"},
                ),
                mock.patch.object(
                    UPDATED.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(returncode=0, stdout=b""),
                ) as run,
            ):
                response = UPDATED.set_channels(
                    {"source_channel": "local", "image_channel": "latest"}
                )
            self.assertTrue(response["ok"])
            self.assertEqual(
                response["deployment"], {"source_channel": "local"}
            )
            self.assertEqual(
                run.call_args.args[0],
                [
                    str(UPDATED.CLI_PATH),
                    "set-channels",
                    "--source-channel",
                    "local",
                    "--image-channel",
                    "latest",
                ],
            )
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertFalse(plan_path.exists())

    def test_set_channels_failure_is_a_bounded_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "latest-plan.json"
            plan_path.write_text("{}\n", encoding="utf-8")
            lock_path = Path(temporary) / "operation.lock"
            with (
                mock.patch.object(UPDATED, "LATEST_PLAN_PATH", plan_path),
                mock.patch.object(UPDATED, "MAINTENANCE_LOCK_PATH", lock_path),
                mock.patch.object(
                    UPDATED.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(
                        returncode=1, stdout=b"boom\n"
                    ),
                ),
            ):
                with self.assertRaises(UPDATED.UpdatedError):
                    UPDATED.set_channels({"source_channel": "github"})
            self.assertTrue(plan_path.exists())


class UpdateBrokerAnsibleContractTests(unittest.TestCase):
    def test_units_keep_nnp_because_children_run_as_transient_units(self) -> None:
        # NoNewPrivileges would be inherited by every directly spawned child
        # and break APT's `_apt` privilege drop plus the snap AppArmor profile
        # transition of certbot. The brokers therefore launch privileged jobs
        # through PID 1 (systemd-run transient units) and keep the sandbox.
        self.assertIn("NoNewPrivileges=yes", UNIT_SOURCE)
        self.assertIn("NoNewPrivileges=yes", BACKUPD_UNIT_SOURCE)
        self.assertIn("RestrictSUIDSGID=yes", UNIT_SOURCE)
        self.assertIn("RestrictSUIDSGID=yes", BACKUPD_UNIT_SOURCE)
        for source in (DAEMON_SOURCE, BACKUPD_SOURCE):
            self.assertIn("systemd-run", source)
            self.assertIn("--no-block", source)
            self.assertIn("def transient_jobs_supported", source)
            self.assertIn("stop_orphan_transient_jobs()", source)

    def test_unit_role_private_values_have_inline_defaults(self) -> None:
        references = set(re.findall(r"\b(updated_[a-z0-9_]+)\b", UNIT_SOURCE))
        self.assertTrue(references)
        for name in sorted(references):
            with self.subTest(variable=name):
                expressions = re.findall(
                    rf"\{{\{{[^}}]*\b{re.escape(name)}\b[^}}]*\}}\}}",
                    UNIT_SOURCE,
                )
                self.assertTrue(expressions, f"missing Jinja expression for {name}")
                self.assertTrue(
                    all(re.search(r"\|\s*default\s*\(", expr) for expr in expressions),
                    f"{name} must have an inline default in every expression",
                )

    def test_ansible_defers_changed_broker_restart_while_marker_exists(self) -> None:
        self.assertIn('path: "{{ updated_active_marker }}"', TASK_SOURCE)
        self.assertIn('path: "{{ updated_restart_request_marker }}"', TASK_SOURCE)
        self.assertIn("- updated_active.stat.exists", TASK_SOURCE)
        self.assertIn("- not updated_active.stat.exists", TASK_SOURCE)
        self.assertIn("- updated_script.changed or updated_unit.changed", TASK_SOURCE)


class RebootActionTests(unittest.TestCase):
    """Guards around the web-triggered reboot (transient systemd timer)."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.reboot_required = root / "reboot-required"
        self.reboot_required.write_text("1", encoding="ascii")
        self.restore_marker = root / "restore.active"  # absent unless a test creates it
        self.marker = root / "reboot.json"
        patches = [
            mock.patch.object(UPDATED, "REBOOT_REQUIRED_PATH", self.reboot_required),
            mock.patch.object(
                UPDATED, "BACKUPD_RESTORE_ACTIVE_MARKER", self.restore_marker
            ),
            mock.patch.object(UPDATED, "REBOOT_MARKER", self.marker),
            mock.patch.object(UPDATED, "acquire_operation", return_value=-1),
            mock.patch.object(UPDATED, "release_operation"),
            mock.patch.object(UPDATED, "fsync_directory"),
            mock.patch.object(
                UPDATED, "request_identity", return_value=("boot-id", "tester")
            ),
            mock.patch.object(UPDATED, "haproxy_transaction_active", return_value=False),
            # The real helper chowns the marker to root, which needs privileges
            # the test runner does not have; record the write instead.
            mock.patch.object(
                UPDATED,
                "atomic_json",
                side_effect=lambda path, payload: Path(path).write_text(
                    json.dumps(payload), encoding="utf-8"
                ),
            ),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def _request(self) -> dict:
        return {"action": "reboot", "confirmation": "REBOOT"}

    def test_reboot_requires_explicit_confirmation(self) -> None:
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.request_reboot({"action": "reboot"})
        with self.assertRaises(UPDATED.UpdatedError):
            UPDATED.request_reboot({"action": "reboot", "confirmation": "nope"})

    def test_reboot_refused_when_the_os_does_not_require_one(self) -> None:
        self.reboot_required.unlink()
        with mock.patch.object(UPDATED.subprocess, "run") as run:
            with self.assertRaises(UPDATED.UpdatedError) as caught:
                UPDATED.request_reboot(self._request())
        self.assertEqual(caught.exception.code, "not_required")
        run.assert_not_called()

    def test_reboot_refused_while_a_restore_is_active(self) -> None:
        self.restore_marker.write_text("1", encoding="ascii")
        with mock.patch.object(UPDATED.subprocess, "run") as run:
            with self.assertRaises(UPDATED.UpdatedError) as caught:
                UPDATED.request_reboot(self._request())
        self.assertEqual(caught.exception.code, "operation_active")
        run.assert_not_called()

    def test_reboot_refused_while_a_config_confirmation_is_active(self) -> None:
        with (
            mock.patch.object(UPDATED, "haproxy_transaction_active", return_value=True),
            mock.patch.object(UPDATED.subprocess, "run") as run,
        ):
            with self.assertRaises(UPDATED.UpdatedError) as caught:
                UPDATED.request_reboot(self._request())
        self.assertEqual(caught.exception.code, "config_pending")
        run.assert_not_called()

    def test_reboot_schedules_a_delayed_transient_timer(self) -> None:
        with mock.patch.object(
            UPDATED.subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        ) as run:
            result = UPDATED.request_reboot(self._request())
        self.assertTrue(result["ok"])
        self.assertTrue(result["reboot_scheduled"])
        argv = run.call_args.args[0]
        # A delayed transient unit, not an immediate reboot, so it stays
        # cancelable while the response reaches the browser.
        self.assertTrue(any(str(arg).startswith("--on-active=") for arg in argv))
        self.assertTrue(
            any(str(arg).startswith(f"--unit={UPDATED.REBOOT_UNIT_PREFIX}") for arg in argv)
        )
        self.assertIn("reboot", argv)
        # The guard marker is published so other operations stay out.
        self.assertTrue(self.marker.exists())

    def test_reboot_is_idempotent_while_one_is_already_scheduled(self) -> None:
        with mock.patch.object(
            UPDATED, "reboot_marker_state", return_value={"unit": "u", "boot_id": "b"}
        ):
            with mock.patch.object(UPDATED.subprocess, "run") as run:
                result = UPDATED.request_reboot(self._request())
        self.assertTrue(result["ok"])
        self.assertTrue(result["reboot_scheduled"])
        run.assert_not_called()  # never schedules a second timer

    def test_cancel_reboot_stops_the_unit_and_clears_the_marker(self) -> None:
        self.marker.write_text('{"unit": "easy-ha-proxy-web-reboot-abc"}', encoding="ascii")
        with (
            mock.patch.object(
                UPDATED,
                "reboot_marker_state",
                return_value={"unit": "easy-ha-proxy-web-reboot-abc"},
            ),
            mock.patch.object(UPDATED, "stop_reboot_unit") as stop,
        ):
            result = UPDATED.cancel_reboot({"action": "cancel_reboot"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["reboot_scheduled"])
        stop.assert_called_once_with("easy-ha-proxy-web-reboot-abc")
        self.assertFalse(self.marker.exists())

    def test_cancel_reboot_without_a_scheduled_reboot_is_reported(self) -> None:
        with mock.patch.object(UPDATED, "reboot_marker_state", return_value=None):
            with self.assertRaises(UPDATED.UpdatedError) as caught:
                UPDATED.cancel_reboot({"action": "cancel_reboot"})
        self.assertEqual(caught.exception.code, "not_found")

    def test_dispatch_routes_the_reboot_actions(self) -> None:
        with mock.patch.object(UPDATED, "request_reboot", return_value={"ok": True}) as rb:
            UPDATED.dispatch({"action": "reboot", "confirmation": "REBOOT"})
        rb.assert_called_once()
        with mock.patch.object(UPDATED, "cancel_reboot", return_value={"ok": True}) as cr:
            UPDATED.dispatch({"action": "cancel_reboot"})
        cr.assert_called_once()


if __name__ == "__main__":
    unittest.main()
