"""Regression tests for the guarded latest-only Authelia notification UI."""

from __future__ import annotations

import ast
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
DAEMON_PATH = ROOT / "ansible/roles/authelia/files/authelia-configd.py"
ROUTES = (APP / "routes_authelia_settings.py").read_text(encoding="utf-8")
CLIENT = (APP / "authelia_config_client.py").read_text(encoding="utf-8")
SERVICES = (APP / "services_authelia_settings.py").read_text(encoding="utf-8")
SECURITY = (APP / "security.py").read_text(encoding="utf-8")
TEMPLATE = (APP / "templates/mail_settings.html").read_text(encoding="utf-8")
JAVASCRIPT = (APP / "static/js/authelia_notifications.js").read_text(
    encoding="utf-8"
)


def load_daemon():
    name = f"authelia_configd_notification_test_{id(object())}"
    spec = importlib.util.spec_from_file_location(name, DAEMON_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_web_service_modules():
    package_name = "haproxy_admin_notification_contract_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(APP)]
    sys.modules[package_name] = package

    client_name = f"{package_name}.authelia_config_client"
    client_spec = importlib.util.spec_from_file_location(
        client_name, APP / "authelia_config_client.py"
    )
    assert client_spec and client_spec.loader
    client = importlib.util.module_from_spec(client_spec)
    sys.modules[client_name] = client
    client_spec.loader.exec_module(client)

    service_name = f"{package_name}.services_authelia_settings"
    service_spec = importlib.util.spec_from_file_location(
        service_name, APP / "services_authelia_settings.py"
    )
    assert service_spec and service_spec.loader
    service = importlib.util.module_from_spec(service_spec)
    sys.modules[service_name] = service
    service_spec.loader.exec_module(service)
    return client, service


WEB_CLIENT, WEB_SERVICES = load_web_service_modules()


class LatestNotificationDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.runtime = root / "runtime"
        self.managed = root / "managed"
        self.state = root / "state"
        self.runtime.mkdir()
        self.managed.mkdir()
        self.state.mkdir(mode=0o700)
        self.daemon = load_daemon()
        self.daemon.CONFIG_FILE = str(self.runtime / "configuration.yml")
        self.daemon.NOTIFICATION_ROOT_DIR = str(self.runtime)
        self.daemon.MANAGED_CONFIG_DIR = str(self.managed)
        self.daemon.NOTIFICATION_STATE_FILE = str(
            self.state / "authelia-notification-state.json"
        )
        self.daemon.NOTIFICATION_EXPECTED_UID = os.getuid()
        self.daemon.NOTIFICATION_REVISION_KEY = b"notification-test-key" * 2
        self.daemon.MAIL_LOCK_FILE = str(root / "run" / "mail.lock")
        self.daemon.NOTIFICATION_REVEALED_AT.clear()
        self._write_config("filesystem")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_config(self, mode: str) -> None:
        notifier = (
            {"filesystem": {"filename": "/config/notification.log"}}
            if mode == "filesystem"
            else {"smtp": {"address": "smtp://mail_relay:25"}}
        )
        Path(self.daemon.CONFIG_FILE).write_text(
            yaml.safe_dump(
                {
                    "notifier": notifier,
                    "access_control": {"rules": []},
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    def _write_notification(self, suffix: str = "one") -> str:
        content = (
            "Date: 2026-07-18 12:00:00 +0000 UTC\n"
            "Recipient: Example User <alice@example.com>\n"
            "Subject: Reset your password\n\n"
            f"Use this one-time value ({suffix}) in your own session:\n"
            f"https://auth.example.com/reset?token={suffix}\n"
        )
        path = self.runtime / "notification.log"
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return content

    def _request(self, payload: dict, *, peer_uid: int | None = 0):
        return self.daemon.handle_request(payload, peer_uid=peer_uid)

    def test_get_returns_latest_metadata_only_and_masks_recipient(self) -> None:
        self._write_notification()
        result = self._request({"action": "notification_latest"})

        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "filesystem")
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["latest"]["recipient_masked"], "a***@example.com")
        self.assertFalse(result["latest"]["handled"])
        self.assertNotIn("content", result["latest"])
        self.assertNotIn("subject", result["latest"])
        self.assertNotIn("alice@example.com", json.dumps(result))
        self.assertNotIn("path", json.dumps(result))
        self.assertRegex(result["latest"]["id"], r"^[a-f0-9]{64}$")
        self.assertRegex(result["latest"]["revision"], r"^[a-f0-9]{64}$")

    def test_reveal_requires_exact_reference_and_is_rate_limited(self) -> None:
        content = self._write_notification()
        latest = self._request(
            {"action": "notification_latest"}
        )["latest"]
        request = {
            "action": "notification_reveal",
            "id": latest["id"],
            "revision": latest["revision"],
            "actor": "root-admin",
        }

        forbidden = self._request(request, peer_uid=None)
        self.assertTrue(forbidden["forbidden"])
        self.assertNotIn("token=one", json.dumps(forbidden))

        revealed = self._request(request)
        self.assertTrue(revealed["ok"])
        self.assertEqual(revealed["content"], content)
        limited = self._request(request)
        self.assertFalse(limited["ok"])
        self.assertTrue(limited["rate_limited"])
        self.assertGreaterEqual(limited["retry_after"], 1)

        stale = dict(request, revision="0" * 64, actor="other-admin")
        conflict = self._request(stale)
        self.assertFalse(conflict["ok"])
        self.assertTrue(conflict["conflict"])

    def test_mark_handled_writes_only_a_root_private_tombstone(self) -> None:
        content = self._write_notification()
        latest = self._request(
            {"action": "notification_latest"}
        )["latest"]
        missing_confirmation = self._request(
            {
                "action": "notification_handle",
                "id": latest["id"],
                "revision": latest["revision"],
                "actor": "root-admin",
            }
        )
        self.assertTrue(missing_confirmation["validation_error"])
        negative_confirmation = self._request(
            {
                "action": "notification_handle",
                "id": latest["id"],
                "revision": latest["revision"],
                "handled": False,
                "actor": "root-admin",
            }
        )
        self.assertTrue(negative_confirmation["validation_error"])
        self.assertFalse(Path(self.daemon.NOTIFICATION_STATE_FILE).exists())
        result = self._request(
            {
                "action": "notification_handle",
                "id": latest["id"],
                "revision": latest["revision"],
                "handled": True,
                "actor": "root-admin",
            }
        )

        self.assertTrue(result["ok"])
        self.assertTrue(result["latest"]["handled"])
        self.assertEqual(result["latest"]["id"], latest["id"])
        self.assertEqual(result["latest"]["revision"], latest["revision"])
        self.assertEqual(
            (self.runtime / "notification.log").read_text(encoding="utf-8"),
            content,
        )
        state_path = Path(self.daemon.NOTIFICATION_STATE_FILE)
        state_text = state_path.read_text(encoding="utf-8")
        self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("token=one", state_text)
        self.assertNotIn("Reset your password", state_text)
        self.assertNotEqual(
            json.loads(state_text)["source_key"],
            hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )

        repeated = self._request(
            {
                "action": "notification_handle",
                "id": latest["id"],
                "revision": latest["revision"],
                "handled": True,
                "actor": "root-admin",
            }
        )
        self.assertTrue(repeated["ok"])
        self.assertTrue(repeated["latest"]["handled"])

    def test_overwrite_creates_a_new_pending_latest_item(self) -> None:
        self._write_notification("first")
        first = self._request(
            {"action": "notification_latest"}
        )["latest"]
        self._request(
            {
                "action": "notification_handle",
                "id": first["id"],
                "revision": first["revision"],
                "handled": True,
                "actor": "root-admin",
            }
        )
        self._write_notification("second")
        second = self._request(
            {"action": "notification_latest"}
        )["latest"]
        self.assertNotEqual(second["id"], first["id"])
        self.assertFalse(second["handled"])

    def test_empty_or_relay_mode_never_exposes_a_notification(self) -> None:
        notification = self.runtime / "notification.log"
        notification.write_text("", encoding="utf-8")
        notification.chmod(0o600)
        empty = self._request({"action": "notification_latest"})
        self.assertTrue(empty["ok"])
        self.assertEqual(empty["status"], "empty")
        self.assertIsNone(empty["latest"])

        self._write_notification()
        self._write_config("relay")
        relay = self._request({"action": "notification_latest"})
        self.assertTrue(relay["ok"])
        self.assertEqual(relay["status"], "disabled")
        self.assertIsNone(relay["latest"])

    def test_nested_or_traversing_source_path_is_refused(self) -> None:
        Path(self.daemon.CONFIG_FILE).write_text(
            yaml.safe_dump(
                {
                    "notifier": {
                        "filesystem": {
                            "filename": "/config/../secrets.yml"
                        }
                    },
                    "access_control": {"rules": []},
                }
            ),
            encoding="utf-8",
        )
        result = self._request({"action": "notification_latest"})
        self.assertFalse(result["ok"])
        self.assertNotIn("secrets.yml", result["error"])

    def test_unsafe_mode_symlink_and_oversized_source_are_refused(self) -> None:
        path = self.runtime / "notification.log"
        secret = self._write_notification()
        path.chmod(0o640)
        unsafe_mode = self._request({"action": "notification_latest"})
        self.assertFalse(unsafe_mode["ok"])
        self.assertNotIn("token=one", json.dumps(unsafe_mode))

        path.unlink()
        target = self.runtime / "target.txt"
        target.write_text(secret, encoding="utf-8")
        target.chmod(0o600)
        path.symlink_to(target.name)
        unsafe_link = self._request({"action": "notification_latest"})
        self.assertFalse(unsafe_link["ok"])
        self.assertNotIn("token=one", json.dumps(unsafe_link))

        path.unlink()
        path.write_bytes(b"x" * (self.daemon.NOTIFICATION_MAX_BYTES + 1))
        path.chmod(0o600)
        oversized = self._request({"action": "notification_latest"})
        self.assertFalse(oversized["ok"])

    def test_ansible_precreates_private_file_and_systemd_uses_state_directory(self) -> None:
        filesystem_tasks = (
            ROOT / "ansible/roles/authelia/tasks/fs.yml"
        ).read_text(encoding="utf-8")
        unit = (
            ROOT / "ansible/roles/authelia/templates/authelia-configd.service.j2"
        ).read_text(encoding="utf-8")
        remove_tasks = (
            ROOT / "ansible/roles/authelia/tasks/remove.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("{{ authelia_root_dir }}/notification.log", filesystem_tasks)
        self.assertIn('mode: "0600"', filesystem_tasks)
        self.assertIn("StateDirectory=easy-ha-proxy", unit)
        self.assertIn("StateDirectoryMode=0700", unit)
        self.assertIn("AUTHELIA_NOTIFICATION_UID={{ authelia_uid }}", unit)
        self.assertIn(
            "/var/lib/easy-ha-proxy/authelia-notification-state.json",
            remove_tasks,
        )

    def test_sensitive_actions_use_kernel_unix_peer_credentials(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer_uid = self.daemon._socket_peer_uid(left)
        finally:
            left.close()
            right.close()
        if peer_uid is None:
            self.skipTest("SO_PEERCRED is blocked by this test sandbox")
        self.assertEqual(peer_uid, os.getuid())
        self.assertTrue(self.daemon._notification_peer_allowed(0))
        denied = self._request(
            {
                "action": "notification_handle",
                "id": "0" * 64,
                "revision": "0" * 64,
                "handled": True,
                "actor": "root-admin",
            },
            peer_uid=None,
        )
        self.assertTrue(denied["forbidden"])


class LatestNotificationWebContractTests(unittest.TestCase):
    def test_metadata_and_handle_responses_drop_unexpected_secret_fields(self) -> None:
        metadata = {
            "id": "a" * 64,
            "revision": "b" * 64,
            "received_at": "2026-07-18T12:00:00+00:00",
            "recipient_masked": "a***@example.com",
            "size": 123,
            "handled": False,
            "handled_at": None,
            "content": "reset-token",
            "raw": "raw reset-token",
            "url": "https://auth.example/reset-token",
            "code": "123456",
            "future_secret": "do-not-forward",
        }
        daemon_response = {
            "ok": True,
            "mode": "filesystem",
            "status": "pending",
            "latest": metadata,
            "content": "top-level-token",
            "raw": "top-level-raw",
            "url": "https://auth.example/top-level-token",
            "code": "654321",
        }
        with mock.patch.object(
            WEB_SERVICES,
            "get_latest_notification",
            return_value=daemon_response,
        ):
            latest = WEB_SERVICES.load_latest_local_notification()
        self.assertEqual(
            set(latest), {"ok", "mode", "status", "latest"}
        )
        self.assertEqual(
            set(latest["latest"]),
            WEB_SERVICES._NOTIFICATION_METADATA_FIELDS,
        )
        self.assertNotIn("reset-token", json.dumps(latest))
        self.assertNotIn("123456", json.dumps(latest))

        handled_response = dict(
            daemon_response,
            status="handled",
            latest=dict(metadata, handled=True),
        )
        with mock.patch.object(
            WEB_SERVICES,
            "set_latest_notification_handled",
            return_value=handled_response,
        ):
            handled = WEB_SERVICES.mark_local_notification(
                notification_id="a" * 64,
                revision="b" * 64,
                actor="root-admin",
            )
        self.assertEqual(set(handled), {"ok", "status", "latest"})
        self.assertEqual(
            set(handled["latest"]),
            WEB_SERVICES._NOTIFICATION_METADATA_FIELDS,
        )
        self.assertNotIn("reset-token", json.dumps(handled))
        self.assertNotIn("123456", json.dumps(handled))

    def test_invalid_daemon_json_never_returns_the_raw_line(self) -> None:
        class FakeSocket:
            def __init__(self, *_args, **_kwargs):
                self.responses = [b'{"content":"reset-token"', b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def connect(self, _path):
                pass

            def sendall(self, _payload):
                pass

            def recv(self, _size):
                return self.responses.pop(0)

        with mock.patch.object(WEB_CLIENT.socket, "socket", FakeSocket):
            result = WEB_CLIENT._send_request({"action": "notification_latest"})
        self.assertFalse(result["ok"])
        self.assertNotIn("raw", result)
        self.assertNotIn("reset-token", json.dumps(result))

    def test_routes_are_latest_only_csrf_protected_and_actor_is_server_derived(self) -> None:
        self.assertIn('@bp_authelia_settings.get("/notifications/latest")', ROUTES)
        self.assertIn(
            '@bp_authelia_settings.post("/notifications/latest/reveal")', ROUTES
        )
        self.assertIn(
            '@bp_authelia_settings.post("/notifications/latest/handled")', ROUTES
        )
        self.assertIn('set(payload) != {"id", "revision"}', ROUTES)
        self.assertNotIn('"id", "revision", "handled"', ROUTES)
        self.assertIn('actor=getattr(g, "remote_user", "")', ROUTES)
        self.assertIn('elif result.get("rate_limited"):', ROUTES)
        self.assertIn('elif result.get("conflict"):', ROUTES)
        self.assertNotIn("csrf.exempt", ROUTES)
        security_tree = ast.parse(SECURITY)
        prefix_assignment = next(
            node
            for node in security_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "SUPERADMIN_PREFIXES"
                for target in node.targets
            )
        )
        superadmin_prefixes = ast.literal_eval(prefix_assignment.value)
        self.assertIn("/authelia", superadmin_prefixes)

    def test_configd_contract_never_mounts_or_reads_the_runtime_path_in_flask(self) -> None:
        for action in (
            "notification_latest",
            "notification_reveal",
            "notification_handle",
        ):
            self.assertIn(f'"action": "{action}"', CLIENT)
        self.assertIn("get_latest_notification", SERVICES)
        self.assertIn("reveal_latest_notification", SERVICES)
        self.assertIn("set_latest_notification_handled", SERVICES)
        self.assertIn('current.recipient_masked || "—"', JAVASCRIPT)
        self.assertNotIn("current.subject", JAVASCRIPT)
        self.assertIn('"handled": True', CLIENT)
        self.assertNotIn("handled: true", JAVASCRIPT)
        self.assertNotIn("/opt/authelia", CLIENT)
        self.assertNotIn("/opt/authelia", SERVICES)

    def test_card_warns_about_latest_only_and_has_no_secret_navigation(self) -> None:
        self.assertIn('id="authelia-notification-card"', TEMPLATE)
        self.assertIn("Latest-only: Authelia overwrites", TEMPLATE)
        self.assertIn("Authelia restart can clear it", TEMPLATE)
        self.assertIn("does not use or revoke", TEMPLATE)
        self.assertIn('id="authelia-notification-content"', TEMPLATE)
        self.assertIn('id="authelia-notification-copy"', TEMPLATE)
        self.assertIn('id="authelia-notification-handled"', TEMPLATE)
        notification_card = TEMPLATE[TEMPLATE.index('id="authelia-notification-card"'):]
        self.assertNotIn("href=", notification_card)
        self.assertNotIn("download", notification_card.lower())
        self.assertNotIn("approve", notification_card.lower())

    def test_plaintext_is_text_only_and_removed_on_timeout_or_page_hide(self) -> None:
        self.assertIn("elements.content.textContent = revealedText", JAVASCRIPT)
        self.assertIn('elements.content.textContent = ""', JAVASCRIPT)
        self.assertNotIn("innerHTML", JAVASCRIPT)
        self.assertNotIn("window.open", JAVASCRIPT)
        self.assertNotIn("linkify", JAVASCRIPT.lower())
        self.assertNotIn("download", JAVASCRIPT.lower())
        self.assertIn("const REVEAL_TTL_MS = 60 * 1000", JAVASCRIPT)
        self.assertIn('window.addEventListener("pagehide"', JAVASCRIPT)
        self.assertIn('document.visibilityState === "hidden"', JAVASCRIPT)
        self.assertIn("new AbortController()", JAVASCRIPT)
        self.assertIn("signal: controller.signal", JAVASCRIPT)
        self.assertIn("revealGeneration += 1", JAVASCRIPT)
        self.assertIn("generation !== revealGeneration", JAVASCRIPT)
        self.assertIn("navigator.clipboard.writeText(revealedText)", JAVASCRIPT)
        self.assertIn('method: "POST"', JAVASCRIPT)

    def test_conflict_refresh_preserves_the_operator_warning(self) -> None:
        warning = (
            'setResult(t("The notification changed. Metadata has been refreshed."), '
            '"warning")'
        )
        self.assertEqual(JAVASCRIPT.count("await loadLatest(true);"), 3)
        self.assertEqual(JAVASCRIPT.count(warning), 2)
        reveal_conflict = JAVASCRIPT[JAVASCRIPT.index("async function revealLatest()"):
                                     JAVASCRIPT.index("async function copyFullNotification()")]
        handled_conflict = JAVASCRIPT[JAVASCRIPT.index("async function markHandled()"):
                                      JAVASCRIPT.index('document.addEventListener("DOMContentLoaded"')]
        for source in (reveal_conflict, handled_conflict):
            self.assertLess(source.index("await loadLatest(true);"), source.index(warning))

    def test_all_notification_source_strings_have_russian_translations(self) -> None:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate key: {key}")
                result[key] = value
            return result

        messages = json.loads(
            (APP / "translations/ru.json").read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )["messages"]
        source_strings = (
            "Latest local notification",
            "Manual fallback for Authelia when email delivery is disabled.",
            "Latest-only: Authelia overwrites the previous local notification, and an Authelia restart can clear it. Refresh and handle the current notification promptly.",
            "This plaintext may contain a short-lived password-reset link or one-time security code. Verify the requester through a trusted channel, never use the secret as the administrator, and do not share it with anyone except the intended user. Authelia recommends SMTP instead of filesystem notifications for production.",
            "Refresh metadata",
            "No current local notification.",
            "Reveal plaintext",
            "Mark handled",
            "Mark handled changes only the dashboard status. It does not use or revoke the password-reset link or one-time code.",
            "Plain text preview",
            "Automatically hidden after 60 seconds.",
            "Copy full notification",
            "Hide preview",
            "Plaintext preview was hidden automatically.",
            "No pending notification",
            "Handled",
            "Pending",
            "Action required",
            "Loading local notification metadata…",
            "Failed to load local notification",
            "Revealing the current notification…",
            "Plaintext revealed. It will be hidden after 60 seconds.",
            "The notification changed. Metadata has been refreshed.",
            "Please wait before revealing the notification again.",
            "Failed to reveal local notification",
            "Full notification copied to the clipboard.",
            "Clipboard access failed. Select the plaintext manually.",
            "Marking the notification handled…",
            "Notification marked handled.",
            "Failed to update notification status",
        )
        for source in source_strings:
            with self.subTest(source=source):
                self.assertIn(source, messages)
                self.assertNotEqual(messages[source], source)


if __name__ == "__main__":
    unittest.main()
