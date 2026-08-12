"""Tests for fresh installations using the built-in certificate authority."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
import yaml

from easy_ha_proxy import (
    INTERNAL_CA_INSTALL_TAGS,
    InstallerError,
    UPDATE_TAGS,
    configure_interactively,
    configured_certificate_source,
    generate_internal_certificate,
)


class InternalCaInstallTests(unittest.TestCase):
    def test_reconfigure_preserves_existing_sites_and_tcp_proxies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "metadata.yml").write_text(
                "test_mode: true\n"
                "installation_complete: true\n"
                "configuration_pending: false\n",
                encoding="utf-8",
            )
            (directory / "vars.yml").write_text(
                "root_domain: easy-ha-proxy.test\n"
                "admin_domain: ha.easy-ha-proxy.test\n"
                "aut_domain: aut.easy-ha-proxy.test\n"
                "certbot_email: admin@example.test\n",
                encoding="utf-8",
            )
            (directory / "authelia.yml").write_text(
                "aut_domain: aut.easy-ha-proxy.test\n",
                encoding="utf-8",
            )
            (directory / "websites.yml").write_text(
                "sites:\n"
                "  - name: app\n"
                "    domain: app.easy-ha-proxy.test\n"
                "    backend_ip: 192.168.56.20\n",
                encoding="utf-8",
            )
            (directory / "tcp.yml").write_text(
                "tcp_proxies:\n"
                "  - name: ssh\n"
                "    bind_port: 2222\n"
                "    backend_ip: 192.168.56.20\n"
                "    backend_port: 22\n",
                encoding="utf-8",
            )
            (directory / "authelia_users_initial.yml").write_text(
                "authelia_users:\n"
                "  admin:\n"
                "    password: hash\n",
                encoding="utf-8",
            )
            (directory / "secrets.yml").write_text(
                "authelia_session_secret: existing\n",
                encoding="utf-8",
            )
            prompt_values = iter(
                (
                    "easy-ha-proxy.test",
                    "ha.easy-ha-proxy.test",
                    "aut.easy-ha-proxy.test",
                    "admin@example.test",
                    "UTC",
                    "192.168.56.10",
                )
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_CONFIG_DIR": str(directory),
                        "EASY_HA_PROXY_ALLOW_STDIN": "1",
                    },
                ),
                mock.patch(
                    "easy_ha_proxy.prompt",
                    side_effect=lambda *args, **kwargs: next(prompt_values),
                ),
                mock.patch("builtins.input", side_effect=("", "")),
                mock.patch("easy_ha_proxy.prompt_bool", return_value=False),
                mock.patch("easy_ha_proxy.backup_configuration"),
            ):
                configure_interactively(
                    overwrite=True,
                    test_mode=True,
                    certificate_source="internal",
                    image_channel="alpha",
                    source_channel="local",
                )

            websites = yaml.safe_load((directory / "websites.yml").read_text())
            tcp = yaml.safe_load((directory / "tcp.yml").read_text())
            metadata = yaml.safe_load((directory / "metadata.yml").read_text())
            self.assertEqual(websites["sites"][0]["name"], "app")
            self.assertEqual(tcp["tcp_proxies"][0]["name"], "ssh")
            self.assertTrue(metadata["installation_complete"])
            self.assertTrue(metadata["configuration_pending"])

    def test_reconfigure_preserves_existing_managed_and_future_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            variables_before = {
                "root_domain": "example.com",
                "admin_domain": "ha.example.com",
                "aut_domain": "aut.example.com",
                "certbot_email": "ops@example.com",
                "haproxy_admin_timezone": "Europe/Warsaw",
                "admin_ips_enabled": False,
                "admin_allowed_ips": [],
                "enable_geoip": True,
                "geoip_country_codes": ["PL", "DE"],
                "mail_notify_enabled": True,
                "mail_notify_from": "proxy@example.com",
                "mail_notify_to": "ops@example.com",
                "mail_smtp_host": "smtp.example.com",
                "mail_smtp_port": 587,
                "mail_smtp_user": "relay@example.com",
                "mail_smtp_auth": "on",
                "site_defaults": {
                    "hsts": 31_536_000,
                    "add_headers": {"X-Custom": "kept"},
                    "custom_site_option": "future-value",
                    "certificate_source": "letsencrypt",
                    "le_managed": True,
                },
                "custom_future_option": {"enabled": True},
            }
            access_rules = [
                {
                    "domain": "private.example.com",
                    "subject": ["group:operators"],
                    "policy": "two_factor",
                }
            ]
            authelia_before = {
                "aut_domain": "aut.example.com",
                "authelia_timezone": "Europe/Warsaw",
                "authelia_cookie_domain": "example.com",
                "authelia_portal_url": "https://aut.example.com",
                "authelia_default_redirection_url": (
                    "https://aut.example.com/access_granted"
                ),
                "mail_relay_server": True,
                "authelia_notifier_type": "smtp",
                "mail_subject": "Custom security subject",
                "authelia_access_control_rules": access_rules,
                "custom_authelia_option": {"future": "kept"},
            }
            secrets_before = {
                "authelia_session_secret": "session-secret",
                "authelia_jwt_secret": "jwt-secret",
                "authelia_storage_key": "storage-secret",
                "haproxy_admin_proxy_secret": "proxy-secret",
                "mail_smtp_pass": "smtp-secret",
                "custom_future_secret": "must-not-rotate",
            }
            metadata_before = {
                "product": "easy-ha-proxy",
                "repository": "https://git.example.org/custom/easy-ha-proxy.git",
                "test_mode": False,
                "certificate_source": "internal",
                "source_channel": "local",
                "image_channel": "latest",
                "admin_domain": "ha.example.com",
                "authelia_domain": "aut.example.com",
                "installation_complete": True,
                "configuration_pending": False,
                "custom_metadata": {"owner": "operations"},
            }
            for name, data in (
                ("vars.yml", variables_before),
                ("authelia.yml", authelia_before),
                ("secrets.yml", secrets_before),
                ("metadata.yml", metadata_before),
                ("authelia_users_initial.yml", {"authelia_users": {"admin": {"password": "hash"}}}),
                ("websites.yml", {"sites": [{"name": "custom-site"}]}),
                ("tcp.yml", {"tcp_proxies": [{"name": "custom-tcp"}]}),
            ):
                (directory / name).write_text(
                    yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
                )

            prompt_defaults: dict[str, str | None] = {}

            def accept_default(
                label: str, *, default: str | None = None, **_kwargs: object
            ) -> str:
                prompt_defaults[label] = default
                if default is None:
                    raise AssertionError(f"Missing existing default for {label}")
                return default

            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_CONFIG_DIR": str(directory),
                        "EASY_HA_PROXY_ALLOW_STDIN": "1",
                    },
                ),
                mock.patch("easy_ha_proxy.prompt", side_effect=accept_default),
                mock.patch("builtins.input", side_effect=("", "")),
                mock.patch(
                    "easy_ha_proxy.prompt_bool",
                    side_effect=AssertionError(
                        "Existing mail settings must be managed through the web UI"
                    ),
                ),
                mock.patch("easy_ha_proxy.backup_configuration") as backup,
            ):
                configure_interactively(
                    overwrite=True,
                    test_mode=None,
                    certificate_source="internal",
                    image_channel="latest",
                    source_channel="local",
                )

            variables = yaml.safe_load((directory / "vars.yml").read_text())
            authelia = yaml.safe_load((directory / "authelia.yml").read_text())
            secret_values = yaml.safe_load((directory / "secrets.yml").read_text())
            metadata = yaml.safe_load((directory / "metadata.yml").read_text())

            self.assertEqual(prompt_defaults["Root domain"], "example.com")
            self.assertEqual(
                prompt_defaults["Administration domain"], "ha.example.com"
            )
            self.assertEqual(
                prompt_defaults["Authelia portal domain"], "aut.example.com"
            )
            self.assertEqual(
                prompt_defaults["Let's Encrypt / administrator email"],
                "ops@example.com",
            )
            self.assertEqual(prompt_defaults["Timezone"], "Europe/Warsaw")
            self.assertEqual(variables["admin_allowed_ips"], [])
            self.assertFalse(variables["admin_ips_enabled"])
            self.assertEqual(variables["geoip_country_codes"], ["PL", "DE"])
            self.assertTrue(variables["mail_notify_enabled"])
            self.assertEqual(variables["mail_smtp_host"], "smtp.example.com")
            self.assertEqual(variables["mail_smtp_user"], "relay@example.com")
            self.assertEqual(
                variables["site_defaults"]["custom_site_option"], "future-value"
            )
            self.assertEqual(
                variables["site_defaults"]["add_headers"], {"X-Custom": "kept"}
            )
            self.assertNotIn("enable_geoip", variables["site_defaults"])
            self.assertEqual(
                variables["site_defaults"]["certificate_source"], "letsencrypt"
            )
            self.assertTrue(variables["site_defaults"]["le_managed"])
            self.assertEqual(
                variables["custom_future_option"], {"enabled": True}
            )
            self.assertNotIn("haproxy_socket", variables)
            self.assertEqual(authelia["authelia_access_control_rules"], access_rules)
            self.assertEqual(authelia["mail_subject"], "Custom security subject")
            self.assertEqual(
                authelia["custom_authelia_option"], {"future": "kept"}
            )
            self.assertNotIn("authelia_log_level", authelia)
            self.assertEqual(secret_values, secrets_before)
            self.assertEqual(
                metadata["repository"], metadata_before["repository"]
            )
            self.assertEqual(
                metadata["custom_metadata"], {"owner": "operations"}
            )
            self.assertTrue(metadata["installation_complete"])
            self.assertTrue(metadata["configuration_pending"])
            self.assertNotIn("installer_language", metadata)
            backup.assert_called_once_with(directory)

    def test_reconfigure_fails_closed_for_invalid_managed_yaml(self) -> None:
        valid_files = {
            "metadata.yml": {
                "test_mode": False,
                "certificate_source": "internal",
                "installation_complete": True,
            },
            "vars.yml": {
                "root_domain": "example.com",
                "admin_domain": "ha.example.com",
                "aut_domain": "aut.example.com",
                "certbot_email": "admin@example.com",
            },
            "authelia.yml": {"aut_domain": "aut.example.com"},
            "secrets.yml": {"authelia_session_secret": "keep-me"},
        }
        for invalid_name in valid_files:
            with self.subTest(file=invalid_name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for name, data in valid_files.items():
                    (directory / name).write_text(
                        "[unterminated\n"
                        if name == invalid_name
                        else yaml.safe_dump(data, sort_keys=False),
                        encoding="utf-8",
                    )
                contents_before = {
                    path.name: path.read_bytes() for path in directory.iterdir()
                }
                with (
                    mock.patch.dict(
                        os.environ,
                        {
                            "EASY_HA_PROXY_CONFIG_DIR": str(directory),
                            "EASY_HA_PROXY_ALLOW_STDIN": "1",
                        },
                    ),
                    mock.patch("easy_ha_proxy.backup_configuration") as backup,
                ):
                    with self.assertRaises(InstallerError):
                        configure_interactively(
                            overwrite=True,
                            test_mode=None,
                            certificate_source="internal",
                            image_channel="latest",
                            source_channel="local",
                        )
                self.assertEqual(
                    {path.name: path.read_bytes() for path in directory.iterdir()},
                    contents_before,
                )
                backup.assert_not_called()

    def test_reconfigure_uses_live_ui_owned_haproxy_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "managed"
            runtime = root / "runtime"
            directory.mkdir()
            runtime.mkdir()
            managed_documents = {
                "metadata.yml": {
                    "test_mode": False,
                    "certificate_source": "internal",
                    "source_channel": "local",
                    "image_channel": "latest",
                    "configuration_pending": False,
                },
                "vars.yml": {
                    "root_domain": "example.com",
                    "admin_domain": "ha.example.com",
                    "aut_domain": "aut.example.com",
                    "certbot_email": "admin@example.com",
                    "haproxy_admin_timezone": "UTC",
                    "enable_http80": False,
                    "mail_notify_enabled": True,
                    "mail_smtp_host": "smtp.example.com",
                    "site_defaults": {"hsts": 15_552_000},
                },
                "authelia.yml": {
                    "aut_domain": "aut.example.com",
                    "authelia_timezone": "UTC",
                    "mail_relay_server": True,
                },
                "secrets.yml": {
                    "authelia_session_secret": "existing-session-secret",
                    "mail_smtp_pass": "existing-mail-secret",
                },
                "authelia_users_initial.yml": {
                    "authelia_users": {"admin": {"password": "hash"}}
                },
                "websites.yml": {"sites": [{"name": "managed-site"}]},
                "tcp.yml": {"tcp_proxies": [{"name": "managed-tcp"}]},
            }
            runtime_documents = {
                "vars.yml": {
                    "enable_http80": True,
                    "site_defaults": {"hsts": 31_536_000},
                    # Installer-owned values from runtime must have no authority.
                    "mail_notify_enabled": False,
                },
                "websites.yml": {"sites": [{"name": "runtime-site"}]},
                "tcp.yml": {"tcp_proxies": [{"name": "runtime-tcp"}]},
            }
            for name, data in managed_documents.items():
                (directory / name).write_text(
                    yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
                )
            for name, data in runtime_documents.items():
                (runtime / name).write_text(
                    yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
                )

            def accept_default(
                _label: str, *, default: str | None = None, **_kwargs: object
            ) -> str:
                if default is None:
                    raise AssertionError("Existing wizard value has no default")
                return default

            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_CONFIG_DIR": str(directory),
                        "EASY_HA_PROXY_ALLOW_STDIN": "1",
                    },
                ),
                mock.patch(
                    "easy_ha_proxy.RUNTIME_HAPROXY_CONFIG_DIR", runtime
                ),
                mock.patch("easy_ha_proxy.prompt", side_effect=accept_default),
                mock.patch("builtins.input", side_effect=("", "")),
                mock.patch("easy_ha_proxy.backup_configuration"),
            ):
                configure_interactively(
                    overwrite=True,
                    test_mode=None,
                    certificate_source="internal",
                    image_channel="latest",
                    source_channel="local",
                )

            variables = yaml.safe_load((directory / "vars.yml").read_text())
            websites = yaml.safe_load((directory / "websites.yml").read_text())
            tcp = yaml.safe_load((directory / "tcp.yml").read_text())
            self.assertTrue(variables["enable_http80"])
            self.assertEqual(variables["site_defaults"]["hsts"], 31_536_000)
            self.assertTrue(variables["mail_notify_enabled"])
            self.assertEqual(variables["mail_smtp_host"], "smtp.example.com")
            self.assertEqual(websites["sites"][0]["name"], "runtime-site")
            self.assertEqual(tcp["tcp_proxies"][0]["name"], "runtime-tcp")

    def test_internal_initial_certificate_keeps_certbot_installed(self) -> None:
        install_tags = set(INTERNAL_CA_INSTALL_TAGS.split(","))
        update_tags = set(UPDATE_TAGS.split(","))
        self.assertTrue({"crt-install", "crt-hooks", "crt-notify"} <= install_tags)
        self.assertNotIn("crt-renew", install_tags)
        self.assertTrue({"crt-install", "crt-hooks", "crt-notify"} <= update_tags)

    def test_legacy_test_mode_defaults_to_internal_ca(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "metadata.yml").write_text(
                "test_mode: true\n", encoding="utf-8"
            )
            self.assertEqual(configured_certificate_source(directory), "internal")

    def test_wizard_persists_internal_ca_as_stack_and_site_default(self) -> None:
        class PasswordHasher:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def hash(self, _password: str) -> str:
                return "$argon2id$test-hash"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prompt_values = iter(
                (
                    "example.test",
                    "ha.example.test",
                    "aut.example.test",
                    "admin@example.test",
                    "UTC",
                    "admin",
                    "Administrator",
                    "admin@example.test",
                )
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_CONFIG_DIR": str(directory),
                        "EASY_HA_PROXY_ALLOW_STDIN": "1",
                    },
                ),
                mock.patch(
                    "easy_ha_proxy.prompt", side_effect=lambda *args, **kwargs: next(prompt_values)
                ),
                mock.patch("builtins.input", side_effect=("", "")),
                mock.patch("easy_ha_proxy.prompt_password", return_value="safe-password"),
                mock.patch("easy_ha_proxy.prompt_bool", return_value=False),
                mock.patch.dict(
                    sys.modules,
                    {"argon2": types.SimpleNamespace(PasswordHasher=PasswordHasher)},
                ),
            ):
                configure_interactively(
                    overwrite=False,
                    test_mode=False,
                    certificate_source="internal",
                    image_channel="latest",
                    source_channel="local",
                )

            variables = yaml.safe_load((directory / "vars.yml").read_text())
            metadata = yaml.safe_load((directory / "metadata.yml").read_text())
            self.assertEqual(metadata["certificate_source"], "internal")
            self.assertEqual(
                variables["easy_ha_proxy_certificate_source"], "internal"
            )
            self.assertEqual(
                variables["site_defaults"]["certificate_source"], "internal"
            )
            self.assertFalse(variables["site_defaults"]["le_managed"])
            self.assertFalse(variables["enable_geoip"])
            self.assertEqual(variables["geoip_mode"], "allow")
            self.assertTrue(variables["site_defaults"]["enable_geoip"])
            self.assertEqual(
                variables["haproxy_admin_image"],
                "clllagob/haproxy-admin-ui:latest",
            )
            self.assertEqual(
                variables["haproxy_socket"], "/run/haproxy/admin.sock"
            )
            self.assertEqual(variables["haproxy_socket_group"], "hadmin")
            self.assertEqual(metadata["source_channel"], "local")
            self.assertEqual(metadata["image_channel"], "latest")

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required")
    def test_initial_leaf_uses_the_same_ca_as_certificate_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            certs = root / "certs"
            ca_root = root / "certificate-authorities"
            export = root / "internal-ca.crt"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "admin_domain: ha.example.test\n"
                "authelia_domain: aut.example.test\n"
                "certificate_source: internal\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "EASY_HA_PROXY_CERT_DIR": str(certs),
                    "HAPROXY_CA_ROOT_DIR": str(ca_root),
                    "EASY_HA_PROXY_CA_EXPORT": str(export),
                },
            ):
                ca_path = generate_internal_certificate(config)

            self.assertEqual(ca_path, ca_root / "internal" / "ca.crt")
            self.assertTrue((ca_root / "internal" / "ca.key").is_file())
            self.assertEqual(
                (ca_root / "internal" / "ca.key").stat().st_mode & 0o777,
                0o600,
            )
            self.assertTrue(export.is_file())

            ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
            leaf = x509.load_pem_x509_certificate(
                (certs / "easy-ha-proxy-internal.pem").read_bytes()
            )
            ca.public_key().verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf.signature_hash_algorithm,
            )
            self.assertTrue(
                ca.extensions.get_extension_for_class(x509.BasicConstraints)
                .value.ca
            )
            names = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            self.assertEqual(
                names, ["ha.example.test", "aut.example.test"]
            )


if __name__ == "__main__":
    unittest.main()
