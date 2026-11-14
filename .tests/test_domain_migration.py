import argparse
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from easy_ha_proxy import (
    INTERNAL_CA_INSTALL_TAGS,
    command_migrate_domain,
    domain_migration_dns_names,
    replace_domain_in_data,
    replace_domain_text,
)


class DomainMigrationTests(unittest.TestCase):
    def test_domain_replacement_respects_token_boundaries(self) -> None:
        self.assertEqual(
            replace_domain_text(
                "https://app.old.example.com/ old.example.com notold.example.com",
                "old.example.com",
                "new.example.net",
            ),
            "https://app.new.example.net/ new.example.net notold.example.com",
        )

    def test_replaces_nested_managed_domain_values(self) -> None:
        source = {
            "root_domain": "old.example.com",
            "url": "https://aut.old.example.com/access_granted",
            "sites": [
                {
                    "domain": "app.old.example.com",
                    "backend": "127.0.0.1",
                },
                {
                    "domain": "www.example.org",
                },
            ],
        }
        changes: list[tuple[str, str, str]] = []

        migrated = replace_domain_in_data(
            source,
            "old.example.com",
            "new.example.net",
            path="vars.yml",
            changes=changes,
        )

        self.assertEqual(migrated["root_domain"], "new.example.net")
        self.assertEqual(
            migrated["url"],
            "https://aut.new.example.net/access_granted",
        )
        self.assertEqual(
            migrated["sites"][0]["domain"],
            "app.new.example.net",
        )
        self.assertEqual(migrated["sites"][1]["domain"], "www.example.org")
        self.assertEqual(len(changes), 3)

    def test_collects_only_names_under_new_root(self) -> None:
        names = domain_migration_dns_names(
            {"admin_domain": "ha.new.example.net"},
            {"aut_domain": "aut.new.example.net"},
            {
                "sites": [
                    {
                        "domain": "app.new.example.net",
                        "alt_names": [
                            "data.new.example.net",
                            "external.example.org",
                        ],
                    },
                    {"domain": "www.example.org"},
                ]
            },
            "new.example.net",
        )

        self.assertEqual(
            names,
            [
                "app.new.example.net",
                "aut.new.example.net",
                "data.new.example.net",
                "ha.new.example.net",
            ],
        )

    def test_plan_only_does_not_modify_managed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = {
                "vars.yml": {
                    "root_domain": "old.example.com",
                    "admin_domain": "ha.old.example.com",
                },
                "authelia.yml": {
                    "aut_domain": "aut.old.example.com",
                    "authelia_cookie_domain": "old.example.com",
                },
                "websites.yml": {
                    "sites": [{"domain": "app.old.example.com"}],
                },
                "tcp.yml": {"tcp_proxies": []},
                "metadata.yml": {
                    "test_mode": False,
                    "admin_domain": "ha.old.example.com",
                    "authelia_domain": "aut.old.example.com",
                },
                "secrets.yml": {"secret": "unchanged"},
                "authelia_users_initial.yml": {"authelia_users": {}},
            }
            for name, data in files.items():
                (directory / name).write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )
            (directory / "inventory.ini").write_text(
                "[easy_ha_proxy]\nlocalhost ansible_connection=local\n",
                encoding="utf-8",
            )
            original = {
                path.name: path.read_bytes() for path in directory.iterdir()
            }
            args = argparse.Namespace(
                new_domain="new.example.net",
                skip_dns_check=True,
                plan_only=True,
            )

            with (
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.syntax_check") as syntax,
                mock.patch("easy_ha_proxy.run_playbook") as playbook,
            ):
                command_migrate_domain(args)

            syntax.assert_called_once()
            playbook.assert_called_once()
            self.assertTrue(playbook.call_args.kwargs["check_mode"])
            self.assertEqual(
                original,
                {path.name: path.read_bytes() for path in directory.iterdir()},
            )

    def test_test_mode_can_be_promoted_without_reinstalling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = {
                "vars.yml": {
                    "root_domain": "easy-ha-proxy.test",
                    "admin_domain": "ha.easy-ha-proxy.test",
                    "easy_ha_proxy_test_mode": True,
                    "easy_ha_proxy_test_ip": "192.168.56.10",
                    "easy_ha_proxy_certificate_source": "internal",
                    "haproxy_admin_image": "clllagob/haproxy-admin-ui:alpha",
                    "site_defaults": {
                        "certificate_source": "internal",
                        "le_managed": False,
                    },
                },
                "authelia.yml": {
                    "aut_domain": "aut.easy-ha-proxy.test",
                    "authelia_cookie_domain": "easy-ha-proxy.test",
                },
                "websites.yml": {
                    "sites": [
                        {
                            "name": "app",
                            "domain": "app.easy-ha-proxy.test",
                            "backend_ip": "192.168.56.20",
                        }
                    ],
                },
                "tcp.yml": {"tcp_proxies": []},
                "metadata.yml": {
                    "test_mode": True,
                    "test_server_ip": "192.168.56.10",
                    "certificate_source": "internal",
                    "image_channel": "alpha",
                    "admin_domain": "ha.easy-ha-proxy.test",
                    "authelia_domain": "aut.easy-ha-proxy.test",
                    "installation_complete": True,
                    "configuration_pending": False,
                },
                "secrets.yml": {"secret": "unchanged"},
                "authelia_users_initial.yml": {
                    "authelia_users": {"admin": {"password": "hash"}}
                },
            }
            for name, data in files.items():
                (directory / name).write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )
            (directory / "inventory.ini").write_text(
                "[easy_ha_proxy]\nlocalhost ansible_connection=local\n",
                encoding="utf-8",
            )
            original = {
                path.name: path.read_bytes() for path in directory.iterdir()
            }
            captured = {}

            def capture_plan(tags, **kwargs):
                preview = kwargs["directory"]
                captured["tags"] = tags
                captured["vars"] = yaml.safe_load(
                    (preview / "vars.yml").read_text(encoding="utf-8")
                )
                captured["sites"] = yaml.safe_load(
                    (preview / "websites.yml").read_text(encoding="utf-8")
                )
                captured["metadata"] = yaml.safe_load(
                    (preview / "metadata.yml").read_text(encoding="utf-8")
                )

            args = argparse.Namespace(
                new_domain="example.com",
                skip_dns_check=True,
                plan_only=True,
                promote_production=True,
                certificate_source="internal",
                image_channel="latest",
            )
            with (
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.syntax_check"),
                mock.patch("easy_ha_proxy.run_playbook", side_effect=capture_plan),
            ):
                command_migrate_domain(args)

            self.assertEqual(captured["tags"], INTERNAL_CA_INSTALL_TAGS)
            self.assertFalse(captured["vars"]["easy_ha_proxy_test_mode"])
            self.assertEqual(
                captured["vars"]["haproxy_admin_image"],
                "clllagob/haproxy-admin-ui:latest",
            )
            self.assertEqual(
                captured["sites"]["sites"][0]["domain"],
                "app.example.com",
            )
            self.assertEqual(
                captured["sites"]["sites"][0]["backend_ip"],
                "192.168.56.20",
            )
            self.assertFalse(captured["metadata"]["test_mode"])
            self.assertTrue(captured["metadata"]["configuration_pending"])
            self.assertEqual(
                original,
                {path.name: path.read_bytes() for path in directory.iterdir()},
            )


if __name__ == "__main__":
    unittest.main()
