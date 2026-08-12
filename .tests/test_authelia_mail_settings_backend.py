"""Regression tests for relay-only Authelia and certificate mail delivery."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
DAEMON_PATH = ROOT / "ansible/roles/authelia/files/authelia-configd.py"


def load_daemon():
    name = f"authelia_configd_mail_test_{id(object())}"
    spec = importlib.util.spec_from_file_location(name, DAEMON_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MailDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.runtime = root / "runtime"
        self.managed = root / "managed"
        self.runtime.mkdir()
        self.managed.mkdir()

        self.daemon = load_daemon()
        self.daemon.CONFIG_FILE = str(self.runtime / "configuration.yml")
        self.daemon.ENV_FILE = str(self.runtime / ".env")
        self.daemon.COMPOSE_FILE = str(self.runtime / "docker-compose.yml")
        self.daemon.MANAGED_CONFIG_DIR = str(self.managed)
        self.daemon.MANAGED_VARS_FILE = str(self.managed / "vars.yml")
        self.daemon.MANAGED_AUTHELIA_FILE = str(self.managed / "authelia.yml")
        self.daemon.MANAGED_SECRETS_FILE = str(self.managed / "secrets.yml")
        self.daemon.MAIL_NOTIFY_STATE_FILE = str(self.managed / "mail-notify.json")
        self.daemon.MAIL_LOCK_FILE = str(root / "run" / "mail.lock")
        self.daemon.MAIL_REVISION_KEY = b"test-revision-key"
        self.daemon.VALIDATE_CONFIG = False
        self.daemon.RESTART_TIMEOUT = 1
        self._write_initial_state()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_yaml(self, path: Path, value: dict) -> None:
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    def _write_initial_state(self, *, address: str = "smtp://mail_relay:25") -> None:
        self._write_yaml(
            Path(self.daemon.CONFIG_FILE),
            {
                "server": {"address": "tcp://0.0.0.0:9091"},
                "notifier": {
                    "disable_startup_check": False,
                    "template_path": "/config/email_templates",
                    "smtp": {
                        "address": address,
                        "username": "" if "mail_relay" in address else "legacy-user",
                        "password": "" if "mail_relay" in address else "legacy-secret",
                        "timeout": "10s",
                        "sender": "authelia@example.com",
                        "subject": "[Authelia] {title}",
                        "startup_check_address": "admin@example.com",
                    },
                },
                "access_control": {"rules": []},
            },
        )
        Path(self.daemon.ENV_FILE).write_text(
            "SMTP_SERVER=\"smtp.example.com\"\n"
            "SMTP_PORT=\"587\"\n"
            "SMTP_USERNAME=\"relay-user\"\n"
            "SMTP_PASSWORD=\"old-secret\"\n"
            "EASY_HA_PROXY_SMTP_TLS_MODE=\"starttls\"\n",
            encoding="utf-8",
        )
        self._write_yaml(
            Path(self.daemon.COMPOSE_FILE),
            {"services": {"mail_relay": {"image": "postfix"}, "authelia": {"image": "authelia"}}},
        )
        self._write_yaml(
            Path(self.daemon.MANAGED_VARS_FILE),
            {
                "root_domain": "example.com",
                "mail_notify_enabled": True,
                "mail_notify_from": "authelia@example.com",
                "mail_notify_to": "admin@example.com",
                "mail_smtp_host": "smtp.example.com",
                "mail_smtp_port": 587,
                "mail_smtp_user": "relay-user",
                "mail_smtp_ssl_mode": "starttls",
                "mail_smtp_tls_skip_verify": False,
            },
        )
        self._write_yaml(
            Path(self.daemon.MANAGED_AUTHELIA_FILE),
            {
                "mail_relay_server": True,
                "authelia_notifier_type": "smtp",
                "mail_subject": "[Authelia] {title}",
                "mail_smtp_timeout": "10s",
            },
        )
        self._write_yaml(
            Path(self.daemon.MANAGED_SECRETS_FILE),
            {"mail_smtp_pass": "old-secret"},
        )
        Path(self.daemon.MAIL_NOTIFY_STATE_FILE).write_text(
            json.dumps(
                {
                    "enabled": True,
                    "from": "authelia@example.com",
                    "to": "admin@example.com",
                    "only_for": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def payload(self, **changes):
        value = {
            "mode": "relay",
            "host": "smtp.example.com",
            "port": 587,
            "username": "relay-user",
            "password_action": "keep",
            "password": "",
            "sender": "authelia@example.com",
            "recipient": "admin@example.com",
            "subject": "[Authelia] {title}",
            "timeout": "10s",
            "tls_mode": "starttls",
            "tls_skip_verify": False,
        }
        value.update(changes)
        return value

    def view(self):
        return self.daemon._handle_mail_view({"action": "mail_view"})

    def update(self, settings=None, *, revision=None, apply=True):
        if revision is None:
            revision = self.view()["revision"]
        return self.daemon._handle_mail_update(
            {
                "action": "mail_update",
                "settings": settings or self.payload(),
                "apply": apply,
                "revision": revision,
            }
        )

    def test_view_redacts_password_and_reports_internal_relay(self) -> None:
        result = self.view()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["settings"]["mode"], "relay")
        self.assertTrue(result["settings"]["password_configured"])
        self.assertNotIn("password", result["settings"])
        self.assertFalse(result["capabilities"]["legacy_direct"])

    def test_legacy_direct_is_only_a_migration_capability(self) -> None:
        self._write_initial_state(address="smtp://legacy.example.com:587")
        result = self.view()
        self.assertEqual(result["settings"]["mode"], "relay")
        self.assertTrue(result["capabilities"]["legacy_direct"])
        with self.assertRaisesRegex(self.daemon.MailSettingsError, "filesystem or relay"):
            self.daemon._validate_mail_payload(self.payload(mode="direct"))

    def test_apply_false_and_stale_revision_are_rejected_without_writes(self) -> None:
        before = Path(self.daemon.MANAGED_VARS_FILE).read_bytes()
        rejected = self.update(self.payload(host="new.example.com"), apply=False)
        self.assertTrue(rejected["validation_error"])
        stale = self.update(self.payload(host="new.example.com"), revision="0" * 64)
        self.assertTrue(stale["conflict"])
        self.assertEqual(Path(self.daemon.MANAGED_VARS_FILE).read_bytes(), before)

    def test_relay_apply_updates_all_canonical_sources_without_exposing_secret(self) -> None:
        settings = self.payload(
            host="smtp2.example.com",
            port=465,
            username="new-user",
            password_action="replace",
            password="new-secret",
            sender="security@example.com",
            recipient="ops@example.com",
            tls_mode="smtps",
        )
        with mock.patch.object(
            self.daemon, "_apply_mail_stack", return_value={"relay_state": "running"}
        ) as apply_stack:
            result = self.update(settings)
        self.assertTrue(result["ok"], result)
        apply_stack.assert_called_once_with("relay", recreate_relay=True)
        config = yaml.safe_load(Path(self.daemon.CONFIG_FILE).read_text(encoding="utf-8"))
        self.assertEqual(config["notifier"]["smtp"]["address"], "smtp://mail_relay:25")
        self.assertEqual(config["notifier"]["smtp"]["password"], "")
        managed = yaml.safe_load(Path(self.daemon.MANAGED_VARS_FILE).read_text(encoding="utf-8"))
        self.assertEqual(managed["mail_smtp_host"], "smtp2.example.com")
        secrets = yaml.safe_load(Path(self.daemon.MANAGED_SECRETS_FILE).read_text(encoding="utf-8"))
        self.assertEqual(secrets["mail_smtp_pass"], "new-secret")
        state = json.loads(Path(self.daemon.MAIL_NOTIFY_STATE_FILE).read_text(encoding="utf-8"))
        self.assertEqual((state["from"], state["to"]), ("security@example.com", "ops@example.com"))
        self.assertNotIn("new-secret", json.dumps(result))

    def test_recipient_only_change_does_not_recreate_relay(self) -> None:
        with mock.patch.object(
            self.daemon, "_apply_mail_stack", return_value={"relay_state": "unchanged"}
        ) as apply_stack:
            result = self.update(self.payload(recipient="other@example.com"))
        self.assertTrue(result["ok"], result)
        apply_stack.assert_called_once_with("relay", recreate_relay=False)

    def test_password_replace_always_recreates_without_equality_oracle(self) -> None:
        state = self.daemon._load_mail_state()
        self.assertTrue(
            self.daemon._mail_transport_changed(
                state,
                self.payload(password_action="replace", password="old-secret"),
            )
        )

    def test_filesystem_mode_preserves_credentials_and_disables_cert_notifications(self) -> None:
        with mock.patch.object(
            self.daemon,
            "_apply_mail_stack",
            return_value={"relay_state": "left_running", "warning": "queue draining"},
        ):
            result = self.update(
                self.payload(
                    mode="filesystem",
                    host="",
                    port=25,
                    username="",
                    sender="",
                    recipient="",
                    subject="",
                )
            )
        self.assertTrue(result["ok"], result)
        state = json.loads(Path(self.daemon.MAIL_NOTIFY_STATE_FILE).read_text(encoding="utf-8"))
        self.assertFalse(state["enabled"])
        secrets = yaml.safe_load(Path(self.daemon.MANAGED_SECRETS_FILE).read_text(encoding="utf-8"))
        self.assertEqual(secrets["mail_smtp_pass"], "old-secret")

    def test_legacy_nonempty_queue_blocks_recreation_before_stopping_authelia(self) -> None:
        with mock.patch.object(self.daemon, "_relay_spool_status", return_value="legacy"), mock.patch.object(
            self.daemon, "_relay_queue_status", return_value="nonempty"
        ), mock.patch.object(self.daemon.subprocess, "run") as run:
            with self.assertRaisesRegex(self.daemon.MailRelayQueueSafetyError, "queued messages"):
                self.daemon._apply_mail_stack("relay", recreate_relay=True)
        run.assert_not_called()

    def test_final_legacy_queue_check_closes_the_authelia_race(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(self.daemon, "_relay_spool_status", return_value="legacy"), mock.patch.object(
            self.daemon, "_relay_queue_status", side_effect=["empty", "nonempty"]
        ), mock.patch.object(self.daemon.subprocess, "run", return_value=completed) as run:
            with self.assertRaises(self.daemon.MailRelayQueueSafetyError) as raised:
                self.daemon._apply_mail_stack("relay", recreate_relay=True)
        self.assertTrue(raised.exception.authelia_stopped)
        self.assertEqual(run.call_args_list[0].args[0], ["docker", "stop", "authelia"])

    def test_managed_volume_can_be_recreated_even_with_a_deferred_queue(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(self.daemon, "_relay_spool_status", return_value="managed"), mock.patch.object(
            self.daemon, "_relay_queue_status"
        ) as queue, mock.patch.object(
            self.daemon.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(
            self.daemon, "_container_health", return_value=True
        ), mock.patch.object(
            self.daemon, "_handle_restart", return_value={"ok": True}
        ):
            result = self.daemon._apply_mail_stack("relay", recreate_relay=True)
        self.assertEqual(result["relay_state"], "running")
        queue.assert_not_called()
        compose_argv = run.call_args_list[1].args[0]
        self.assertEqual(
            compose_argv,
            [
                "docker", "compose", "-f", self.daemon.COMPOSE_FILE,
                "--profile", "mail-relay", "up", "-d",
                "--force-recreate", "mail_relay",
            ],
        )

    def test_disabling_leaves_a_nonempty_queue_running(self) -> None:
        with mock.patch.object(self.daemon, "_handle_restart", return_value={"ok": True}), mock.patch.object(
            self.daemon, "_relay_queue_status", return_value="nonempty"
        ), mock.patch.object(self.daemon.subprocess, "run") as run:
            result = self.daemon._apply_mail_stack("filesystem")
        self.assertEqual(result["relay_state"], "left_running")
        self.assertIn("drain", result["warning"])
        run.assert_not_called()

    def test_test_message_uses_fixed_sendmail_argv_and_stdin(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(self.daemon, "_container_health", return_value=True), mock.patch.object(
            self.daemon.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(
            self.daemon,
            "_wait_for_mail_test_delivery",
            return_value="relay_accepted",
        ) as wait:
            result = self.daemon._send_relay_mail_test(
                {"sender": "authelia@example.com"}, "ops@example.com"
            )
        self.assertEqual(result, "relay_accepted")
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            [
                "docker", "exec", "-i", "mail_relay", "/usr/sbin/sendmail",
                "-i", "-f", "authelia@example.com", "--", "ops@example.com",
            ],
        )
        self.assertIn(b"easy-ha-proxy email test", run.call_args.kwargs["input"])
        self.assertIn(b"Message-ID:", run.call_args.kwargs["input"])
        self.assertIn(b"<easy-ha-proxy-test-", run.call_args.kwargs["input"])
        self.assertNotIn("shell", run.call_args.kwargs)
        wait.assert_called_once()

    def test_mail_log_result_distinguishes_upstream_outcomes(self) -> None:
        message_id = "<easy-ha-proxy-test-abc123@easy-ha-proxy.invalid>"
        prefix = (
            "2026-07-18T10:00:00Z postfix/cleanup[10]: 4ABC123: "
            f"message-id={message_id}\n"
        )
        queue_id, state = self.daemon._parse_mail_test_delivery(
            prefix
            + "2026-07-18T10:00:01Z postfix/smtp[11]: 4ABC123: "
            "to=<private@example.com>, relay=smtp.example.com, status=sent "
            "(250 accepted)\n",
            message_id,
        )
        self.assertEqual((queue_id, state), ("4ABC123", "relay_accepted"))

        _queue_id, state = self.daemon._parse_mail_test_delivery(
            prefix
            + "2026-07-18T10:00:01Z postfix/smtp[11]: 4ABC123: "
            "to=<private@example.com>, status=deferred (authentication failed)\n",
            message_id,
        )
        self.assertEqual(state, "deferred")

        _queue_id, state = self.daemon._parse_mail_test_delivery(
            prefix
            + "2026-07-18T10:00:01Z postfix/smtp[11]: 4ABC123: "
            "to=<private@example.com>, status=bounced (sender rejected)\n",
            message_id,
        )
        self.assertEqual(state, "rejected")

    def test_mail_log_result_does_not_guess_without_correlation(self) -> None:
        queue_id, state = self.daemon._parse_mail_test_delivery(
            "postfix/smtp[11]: OTHER: status=sent (250 accepted)",
            "<easy-ha-proxy-test-missing@easy-ha-proxy.invalid>",
        )
        self.assertEqual((queue_id, state), ("", "queued"))

    def test_mail_test_rejection_response_has_no_addresses_or_smtp_text(self) -> None:
        revision = self.view()["revision"]
        with mock.patch.object(
            self.daemon, "_send_relay_mail_test", return_value="rejected"
        ):
            result = self.daemon._handle_mail_test(
                {
                    "action": "mail_test",
                    "revision": revision,
                    "recipient": "private@example.com",
                }
            )
        rendered = json.dumps(result)
        self.assertFalse(result["ok"])
        self.assertEqual(result["delivery_status"], "rejected")
        self.assertNotIn("private@example.com", rendered)
        self.assertNotIn("smtp.example.com", rendered)

    def test_mail_test_reports_upstream_acceptance_without_inbox_claim(self) -> None:
        revision = self.view()["revision"]
        with mock.patch.object(
            self.daemon,
            "_send_relay_mail_test",
            return_value="relay_accepted",
        ):
            result = self.daemon._handle_mail_test(
                {
                    "action": "mail_test",
                    "revision": revision,
                    "recipient": "private@example.com",
                }
            )
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["upstream_accepted"])
        self.assertFalse(result["delivery_guaranteed"])
        self.assertIn("external SMTP relay accepted", result["message"])
        self.assertIn("cannot be guaranteed", result["message"])

    def test_restart_waits_for_http_health_and_haproxy_backend(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            self.daemon.subprocess, "run", return_value=completed
        ), mock.patch.object(
            self.daemon, "_wait_for_authelia_ready", return_value=True
        ) as wait:
            result = self.daemon._handle_restart({})
        self.assertTrue(result["ok"], result)
        wait.assert_called_once_with(self.daemon.RESTART_TIMEOUT)

    def test_readiness_requires_health_and_haproxy_recovery_together(self) -> None:
        with mock.patch.object(
            self.daemon,
            "_authelia_health_ready",
            side_effect=[False, True, True],
        ) as health, mock.patch.object(
            self.daemon,
            "_haproxy_authelia_backend_up",
            side_effect=[False, True],
        ) as backend, mock.patch.object(self.daemon.time, "sleep"):
            ready = self.daemon._wait_for_authelia_ready(1, interval=0)
        self.assertTrue(ready)
        self.assertEqual(health.call_count, 3)
        self.assertEqual(backend.call_count, 2)

    def test_haproxy_stats_parser_requires_exact_authelia_server_up(self) -> None:
        header = "# pxname,svname,status,check_status,\n"
        self.assertTrue(
            self.daemon._haproxy_stats_report_backend_up(
                header + "authelia_backend,authelia,UP,L4OK,\n"
            )
        )
        self.assertFalse(
            self.daemon._haproxy_stats_report_backend_up(
                header + "authelia_backend,authelia,DOWN 1/2,L4OK,\n"
            )
        )
        self.assertFalse(
            self.daemon._haproxy_stats_report_backend_up(
                header + "unrelated,authelia,UP,L4OK,\n"
            )
        )

    def test_malformed_secret_yaml_does_not_leak_its_line(self) -> None:
        secret = "DO-NOT-LEAK-this-secret"
        Path(self.daemon.MANAGED_SECRETS_FILE).write_text(
            f"mail_smtp_pass: [\"{secret}\"\n", encoding="utf-8"
        )
        result = self.view()
        self.assertFalse(result["ok"])
        self.assertNotIn(secret, json.dumps(result))


class MailDeploymentContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_authelia_role_supplies_inert_defaults_for_new_relay_fields(self) -> None:
        defaults = yaml.safe_load(
            self.read("ansible/roles/authelia/defaults/main.yml")
        )
        cert_defaults = yaml.safe_load(
            self.read("ansible/roles/cert/defaults/main.yml")
        )
        required = {
            "mail_notify_enabled",
            "mail_notify_to",
            "mail_notify_from",
            "mail_notify_only_for",
            "mail_relay_server",
            "mail_smtp_host",
            "mail_smtp_port",
            "mail_smtp_user",
            "mail_smtp_pass",
            "mail_smtp_server",
            "mail_smtp_username",
            "mail_smtp_password",
            "mail_smtp_ssl_mode",
            "mail_smtp_tls_skip_verify",
            "mail_smtp_timeout",
        }
        self.assertTrue(required.issubset(defaults), required - set(defaults))
        self.assertFalse(defaults["mail_notify_enabled"])
        self.assertFalse(defaults["mail_relay_server"])
        self.assertTrue(defaults["mail_smtp_host"].endswith(".invalid"))
        self.assertNotEqual(defaults["mail_smtp_pass"], "CHANGE_ME")
        for key in (
            "mail_notify_enabled",
            "mail_notify_to",
            "mail_notify_from",
            "mail_notify_only_for",
            "mail_smtp_host",
            "mail_smtp_port",
            "mail_smtp_user",
            "mail_smtp_pass",
            "mail_smtp_ssl_mode",
        ):
            self.assertEqual(defaults[key], cert_defaults[key], key)

    def test_compose_uses_a_private_persistent_relay_without_exposing_credentials(self) -> None:
        compose = self.read("ansible/roles/authelia/templates/docker-compose.yml.j2")
        relay_start = compose.index("  mail_relay:")
        authelia_start = compose.index("  {{ authelia_container_name }}:")
        relay = compose[relay_start:authelia_start]
        authelia = compose[authelia_start:]
        self.assertIn("mail_relay_spool:/var/spool/postfix", relay)
        self.assertIn("name: easy-ha-proxy-mail-relay-spool", compose)
        self.assertNotIn("ports:", relay)
        self.assertIn("env_file:", relay)
        self.assertNotIn("env_file:", authelia)
        self.assertIn('profiles: ["mail-relay"]', relay)

    def test_templates_have_no_direct_application_smtp_path(self) -> None:
        config = self.read("ansible/roles/authelia/templates/configuration.yml.j2")
        self.assertIn("address: 'smtp://mail_relay:25'", config)
        self.assertIn("disable_starttls: true", config)
        self.assertNotIn("mail_smtp_password", config)

    def test_forward_auth_failure_cannot_redirect_without_a_location(self) -> None:
        config = self.read("ansible/roles/haproxy/templates/haproxy.cfg.j2")
        redirects = [
            line.strip()
            for line in config.splitlines()
            if line.strip().startswith(
                "http-request redirect location %[var(txn.auth_response_location)]"
            )
        ]
        self.assertEqual(len(redirects), 2)
        for redirect in redirects:
            self.assertIn("{ var(txn.auth_response_location) -m found }", redirect)
        self.assertEqual(config.count("http-request deny status 503 if"), 2)

        unit = self.read(
            "ansible/roles/authelia/templates/authelia-configd.service.j2"
        )
        self.assertIn("AUTHELIA_HAPROXY_SOCKET={{ haproxy_socket", unit)

    def test_cert_hook_reads_dynamic_state_and_uses_the_same_queue(self) -> None:
        hook = self.read("ansible/roles/cert/templates/910-mail-notify.sh.j2")
        self.assertIn("mail-notify.json", hook)
        self.assertIn("flock -s -w 30", hook)
        self.assertIn("docker exec -i mail_relay /usr/sbin/sendmail", hook)
        self.assertNotIn("127.0.0.1:2525", hook)
        self.assertNotIn("msmtp", hook)
        self.assertNotIn("eval ", hook)

    def test_spool_migration_is_locked_quiesced_and_fail_closed(self) -> None:
        guard = self.read("ansible/roles/authelia/tasks/mail_relay_spool.yml")
        self.assertIn("flock --exclusive --wait 30", guard)
        self.assertGreaterEqual(guard.count("postqueue -p"), 2)
        self.assertIn("docker stop \"{{ authelia_container_name }}\"", guard)
        self.assertIn("trap recover EXIT", guard)
        self.assertIn("easy-ha-proxy-mail-relay-spool", guard)

    def test_targeted_update_renders_new_compose_before_migrating_spool(self) -> None:
        update = self.read("ansible/roles/authelia/tasks/update.yml")
        render = update.index("Render the current Authelia Compose definition before migration")
        guard = update.index("Run the fail-closed mail relay spool migration guard")
        reconcile = update.index("Reconcile the updated Authelia stack")
        self.assertLess(render, guard)
        self.assertLess(guard, reconcile)

    def test_clean_install_starts_relay_before_first_certificate_renewal(self) -> None:
        playbook = self.read("ansible/easy-ha-proxy.yml")
        authelia = playbook.index("task_stage: install\n      tags:\n        - authelia")
        renew = playbook.index("task_stage: renew", authelia)
        haproxy_config = playbook.index("task_stage: config", renew)
        self.assertLess(authelia, renew)
        self.assertLess(renew, haproxy_config)

    def test_installer_and_legacy_adoption_enable_only_the_relay(self) -> None:
        installer = self.read("installer/easy_ha_proxy.py")
        migration = self.read("installer/prepare_legacy_config.py")
        self.assertIn("Configure email notifications through the internal relay", installer)
        self.assertNotIn("Configure direct SMTP notifications", installer)
        self.assertIn('result["mail_relay_server"] = True', migration)

    def test_new_install_does_not_add_msmtp_or_a_host_smtp_listener(self) -> None:
        notify = self.read("ansible/roles/cert/tasks/notify.yml")
        compose = self.read("ansible/roles/authelia/templates/docker-compose.yml.j2")
        self.assertNotIn("msmtp-mta", notify)
        self.assertNotIn("mail_smtp_pass | string", notify)
        self.assertIn("set_from_header on", notify)
        self.assertNotIn("127.0.0.1:2525", compose)
        self.assertFalse((ROOT / "ansible/roles/cert/templates/msmtprc.j2").exists())


if __name__ == "__main__":
    unittest.main()
