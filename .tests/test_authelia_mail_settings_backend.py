"""Regression tests for relay-only Authelia and certificate mail delivery."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

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
        # The agent validates the state (go/agent/internal/tools/cert_notify.go);
        # the host has no Python for it.
        self.assertIn('"${AGENT}" cert-notify-state "${STATE_FILE}" "${RENEWED_DOMAINS}"', hook)
        self.assertNotIn("python", hook)

    def test_clean_install_starts_relay_before_first_certificate_renewal(self) -> None:
        playbook = self.read("ansible/easy-ha-proxy.yml")
        authelia = playbook.index("task_stage: install\n      tags:\n        - authelia")
        renew = playbook.index("task_stage: renew", authelia)
        haproxy_config = playbook.index("task_stage: config", renew)
        self.assertLess(authelia, renew)
        self.assertLess(renew, haproxy_config)

    def test_installer_and_legacy_adoption_enable_only_the_relay(self) -> None:
        installer = self.read("go/agent/internal/cli/wizard.go")
        migration = self.read("go/agent/internal/cli/legacy_config.go")
        self.assertIn("Configure email notifications through the internal relay", installer)
        self.assertNotIn("Configure direct SMTP notifications", installer)
        self.assertIn('result.Set("mail_relay_server", true)', migration)

if __name__ == "__main__":
    unittest.main()
