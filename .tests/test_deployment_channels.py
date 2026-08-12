"""Regression tests for source and container image deployment channels."""

from __future__ import annotations

from argparse import Namespace
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from easy_ha_proxy import (
    InstallerError,
    UPDATE_SOURCE_REFRESHED_ENV,
    command_update,
    dns_preflight,
    mark_installation_complete,
    persist_deployment_channels,
    reexec_after_source_update,
    release_channel_from_settings,
    sync_runtime_haproxy_config_to_managed,
    update_managed_source,
)


ROOT = Path(__file__).resolve().parents[1]


class ReleaseChannelTests(unittest.TestCase):
    def _config(self, tmp: Path) -> Path:
        directory = tmp / "config"
        directory.mkdir()
        (directory / "vars.yml").write_text("haproxy_admin_image: repo:latest\n")
        (directory / "metadata.yml").write_text("product: easy-ha-proxy\n")
        return directory

    def _persist(self, directory: Path, **kwargs) -> tuple[dict, dict]:
        with mock.patch("easy_ha_proxy.backup_configuration"):
            persist_deployment_channels(directory=directory, **kwargs)
        variables = yaml.safe_load((directory / "vars.yml").read_text())
        metadata = yaml.safe_load((directory / "metadata.yml").read_text())
        return variables, metadata

    def test_alpha_channel_binds_branch_and_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = self._config(Path(tmp))
            variables, metadata = self._persist(directory, release_channel="alpha")
            self.assertEqual(metadata["source_channel"], "github")
            self.assertEqual(metadata["branch"], "alpha")
            self.assertEqual(metadata["image_channel"], "alpha")
            self.assertTrue(variables["haproxy_admin_image"].endswith(":alpha"))

    def test_stable_channel_binds_main_and_latest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = self._config(Path(tmp))
            # Start from alpha, then switch back to stable.
            self._persist(directory, release_channel="alpha")
            variables, metadata = self._persist(directory, release_channel="stable")
            self.assertEqual(metadata["branch"], "main")
            self.assertEqual(metadata["image_channel"], "latest")
            self.assertTrue(variables["haproxy_admin_image"].endswith(":latest"))

    def test_local_channel_only_sets_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = self._config(Path(tmp))
            self._persist(directory, release_channel="alpha")
            variables, metadata = self._persist(directory, release_channel="local")
            self.assertEqual(metadata["source_channel"], "local")
            # Branch/image are left as they were (alpha), not reset.
            self.assertEqual(metadata["branch"], "alpha")
            self.assertEqual(metadata["image_channel"], "alpha")

    def test_invalid_release_channel_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = self._config(Path(tmp))
            with self.assertRaises(InstallerError):
                self._persist(directory, release_channel="nightly")

    def test_derivation_is_keyed_off_image_and_source(self) -> None:
        self.assertEqual(
            release_channel_from_settings(
                source_channel="github", branch="main", image_channel="alpha"
            ),
            "alpha",
        )
        self.assertEqual(
            release_channel_from_settings(
                source_channel="github", branch="main", image_channel="latest"
            ),
            "stable",
        )
        self.assertEqual(
            release_channel_from_settings(
                source_channel="local", branch="main", image_channel="latest"
            ),
            "local",
        )


class DeploymentChannelTests(unittest.TestCase):
    def test_managed_git_update_resets_exact_reviewed_fetch_head(self) -> None:
        expected = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / "source"
            (source / ".git").mkdir(parents=True)
            with (
                mock.patch("easy_ha_proxy.install_home", return_value=home),
                mock.patch("easy_ha_proxy.source_dir", return_value=source),
                mock.patch("easy_ha_proxy.git_revision", return_value=expected),
                mock.patch("easy_ha_proxy.run") as run,
                mock.patch("easy_ha_proxy.ensure_source_executables"),
            ):
                self.assertTrue(update_managed_source(expected))

        self.assertEqual(
            run.call_args_list[0].args[0],
            ["git", "-C", str(source), "fetch", "--depth=1", "origin", "main"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["git", "-C", str(source), "reset", "--hard", expected],
        )

    def test_managed_git_update_rejects_revision_changed_after_check(self) -> None:
        expected = "a" * 40
        changed = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            source = home / "source"
            (source / ".git").mkdir(parents=True)
            with (
                mock.patch("easy_ha_proxy.install_home", return_value=home),
                mock.patch("easy_ha_proxy.source_dir", return_value=source),
                mock.patch("easy_ha_proxy.git_revision", return_value=changed),
                mock.patch("easy_ha_proxy.run") as run,
                self.assertRaisesRegex(InstallerError, "changed after the update check"),
            ):
                update_managed_source(expected)

        self.assertEqual(run.call_count, 1)
        self.assertIn("fetch", run.call_args.args[0])
        self.assertNotIn("reset", run.call_args.args[0])

    def test_runtime_haproxy_sync_preserves_installer_owned_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "managed"
            runtime = root / "runtime"
            managed.mkdir()
            runtime.mkdir()
            (managed / "metadata.yml").write_text(
                "configuration_pending: false\n", encoding="utf-8"
            )
            (managed / "vars.yml").write_text(
                "admin_domain: ha.managed.example.test\n"
                "admin_authelia_enabled: true\n"
                "haproxy_admin_image: example/admin:alpha\n"
                "enable_http80: false\n"
                "export_prometheus: true\n",
                encoding="utf-8",
            )
            (managed / "websites.yml").write_text("sites: []\n", encoding="utf-8")
            (managed / "tcp.yml").write_text("tcp_proxies: []\n", encoding="utf-8")
            (runtime / "vars.yml").write_text(
                "admin_domain: ha.stale.example.test\n"
                "admin_authelia_enabled: false\n"
                "haproxy_admin_image: example/admin:latest\n"
                "enable_http80: true\n"
                "geoip_country_codes: [PL, RU]\n",
                encoding="utf-8",
            )
            (runtime / "websites.yml").write_text(
                "sites:\n"
                "  - name: app\n"
                "    domain: app.example.test\n"
                "    geo_countries: [PL]\n",
                encoding="utf-8",
            )
            (runtime / "tcp.yml").write_text(
                "tcp_proxies:\n  - name: ssh\n    bind_port: 2222\n",
                encoding="utf-8",
            )

            changed = sync_runtime_haproxy_config_to_managed(
                managed, runtime_directory=runtime
            )

            self.assertTrue(changed)
            variables = yaml.safe_load((managed / "vars.yml").read_text())
            websites = yaml.safe_load((managed / "websites.yml").read_text())
            tcp = yaml.safe_load((managed / "tcp.yml").read_text())
            self.assertTrue(variables["enable_http80"])
            self.assertEqual(variables["geoip_country_codes"], ["PL", "RU"])
            self.assertEqual(variables["admin_domain"], "ha.managed.example.test")
            self.assertTrue(variables["admin_authelia_enabled"])
            self.assertEqual(variables["haproxy_admin_image"], "example/admin:alpha")
            self.assertNotIn("export_prometheus", variables)
            self.assertEqual(websites["sites"][0]["name"], "app")
            self.assertEqual(websites["sites"][0]["geo_countries"], ["PL"])
            self.assertEqual(tcp["tcp_proxies"][0]["name"], "ssh")

    def test_runtime_sync_rejects_unknown_root_keys_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "managed"
            runtime = root / "runtime"
            managed.mkdir()
            runtime.mkdir()
            (managed / "metadata.yml").write_text(
                "configuration_pending: false\n", encoding="utf-8"
            )
            (managed / "vars.yml").write_text(
                "root_domain: example.test\n", encoding="utf-8"
            )
            (managed / "websites.yml").write_text(
                "sites: []\n", encoding="utf-8"
            )
            (managed / "tcp.yml").write_text(
                "tcp_proxies: []\n", encoding="utf-8"
            )
            (runtime / "vars.yml").write_text(
                "enable_http80: true\n", encoding="utf-8"
            )
            (runtime / "websites.yml").write_text(
                "sites: []\nfuture_ansible_override: blocked\n", encoding="utf-8"
            )
            (runtime / "tcp.yml").write_text(
                "tcp_proxies: []\n", encoding="utf-8"
            )
            before = {
                name: (managed / name).read_bytes()
                for name in ("vars.yml", "websites.yml", "tcp.yml")
            }

            with self.assertRaisesRegex(
                InstallerError, "Unsupported top-level key.*future_ansible_override"
            ):
                sync_runtime_haproxy_config_to_managed(
                    managed, runtime_directory=runtime
                )

            self.assertEqual(
                before,
                {
                    name: (managed / name).read_bytes()
                    for name in ("vars.yml", "websites.yml", "tcp.yml")
                },
            )

    def test_github_update_reexecutes_before_running_config_migrations(self) -> None:
        args = Namespace(
            ui_only=False,
            component="all",
            source_channel="github",
            no_fetch=False,
            image_channel=None,
        )
        with (
            mock.patch("easy_ha_proxy.require_root"),
            mock.patch("easy_ha_proxy.update_managed_source", return_value=True),
            mock.patch(
                "easy_ha_proxy.reexec_after_source_update",
                side_effect=RuntimeError("reexec"),
            ) as reexec,
            mock.patch("easy_ha_proxy.ensure_security_secrets") as migrate,
            self.assertRaisesRegex(RuntimeError, "reexec"),
        ):
            command_update(args)

        reexec.assert_called_once_with()
        migrate.assert_not_called()

    def test_refreshed_github_update_runs_new_migrations_without_refetch(self) -> None:
        args = Namespace(
            ui_only=False,
            component="all",
            source_channel="github",
            no_fetch=False,
            image_channel=None,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (
                mock.patch.dict(os.environ, {UPDATE_SOURCE_REFRESHED_ENV: "1"}),
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.update_managed_source") as update_source,
                mock.patch("easy_ha_proxy.ensure_security_secrets") as migrate,
                mock.patch("easy_ha_proxy.persist_deployment_channels"),
                mock.patch(
                    "easy_ha_proxy.managed_configuration_is_pending",
                    return_value=False,
                ),
                mock.patch("easy_ha_proxy.sync_runtime_haproxy_config_to_managed"),
                mock.patch("easy_ha_proxy.sync_runtime_dependencies"),
                mock.patch("easy_ha_proxy.syntax_check"),
                mock.patch("easy_ha_proxy.run_playbook"),
                mock.patch("easy_ha_proxy.mark_installation_complete"),
            ):
                command_update(args)

        update_source.assert_not_called()
        migrate.assert_called_once_with(directory)

    def test_targeted_no_fetch_does_not_change_the_saved_source_channel(self) -> None:
        args = Namespace(
            ui_only=False,
            component="os",
            source_channel=None,
            no_fetch=True,
            image_channel=None,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.load_metadata", return_value={"source_channel": "github"}),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.ensure_security_secrets"),
                mock.patch("easy_ha_proxy.persist_deployment_channels") as persist,
                mock.patch("easy_ha_proxy.managed_configuration_is_pending", return_value=False),
                mock.patch("easy_ha_proxy.sync_runtime_haproxy_config_to_managed"),
                mock.patch("easy_ha_proxy.syntax_check"),
                mock.patch("easy_ha_proxy.run_playbook"),
                mock.patch("easy_ha_proxy.mark_installation_complete"),
            ):
                command_update(args)

        persist.assert_called_once_with(source_channel=None, image_channel=None)

    def test_source_reexec_preserves_arguments_and_sets_one_shot_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entrypoint = root / "installer/easy-ha-proxy"
            entrypoint.parent.mkdir()
            entrypoint.write_text("#!/bin/sh\n", encoding="utf-8")
            with (
                mock.patch("easy_ha_proxy.source_dir", return_value=root),
                mock.patch(
                    "easy_ha_proxy.sys.argv",
                    ["easy-ha-proxy", "update", "--source-channel", "github"],
                ),
                mock.patch("easy_ha_proxy.os.execve") as execve,
                self.assertRaisesRegex(
                    InstallerError, "Could not restart the refreshed installer"
                ),
            ):
                reexec_after_source_update()

        executable, arguments, environment = execve.call_args.args
        self.assertEqual(executable, str(entrypoint))
        self.assertEqual(
            arguments,
            [str(entrypoint), "update", "--source-channel", "github"],
        )
        self.assertEqual(environment[UPDATE_SOURCE_REFRESHED_ENV], "1")

    def test_plan_does_not_persist_runtime_configuration(self) -> None:
        installer = (ROOT / "installer/easy_ha_proxy.py").read_text(
            encoding="utf-8"
        )
        plan_block = installer.split("def command_plan", 1)[1].split(
            "def update_tags_for_args", 1
        )[0]
        self.assertNotIn("sync_runtime_haproxy_config_to_managed", plan_block)

    def test_pending_managed_configuration_is_not_replaced_from_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "managed"
            runtime = root / "runtime"
            managed.mkdir()
            runtime.mkdir()
            (managed / "metadata.yml").write_text(
                "configuration_pending: true\n", encoding="utf-8"
            )
            (managed / "vars.yml").write_text(
                "enable_http80: false\n", encoding="utf-8"
            )
            (managed / "websites.yml").write_text("sites: []\n", encoding="utf-8")
            (managed / "tcp.yml").write_text("tcp_proxies: []\n", encoding="utf-8")
            (runtime / "vars.yml").write_text(
                "enable_http80: true\n", encoding="utf-8"
            )
            (runtime / "websites.yml").write_text("sites: []\n", encoding="utf-8")
            (runtime / "tcp.yml").write_text("tcp_proxies: []\n", encoding="utf-8")

            changed = sync_runtime_haproxy_config_to_managed(
                managed, runtime_directory=runtime
            )

            self.assertFalse(changed)
            variables = yaml.safe_load((managed / "vars.yml").read_text())
            self.assertFalse(variables["enable_http80"])

    def test_successful_apply_marks_interrupted_installation_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "metadata.yml").write_text(
                "product: easy-ha-proxy\n"
                "installation_complete: false\n"
                "configuration_pending: true\n",
                encoding="utf-8",
            )

            mark_installation_complete(directory)

            metadata = yaml.safe_load((directory / "metadata.yml").read_text())
            self.assertTrue(metadata["installation_complete"])
            self.assertFalse(metadata["configuration_pending"])
            self.assertIn("installation_completed_at", metadata)

    def test_unresolved_dns_is_a_warning_not_an_installer_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "vars.yml").write_text(
                "admin_domain: ha.private.example\n",
                encoding="utf-8",
            )
            (directory / "authelia.yml").write_text(
                "aut_domain: aut.private.example\n",
                encoding="utf-8",
            )
            with mock.patch(
                "easy_ha_proxy.socket.getaddrinfo",
                side_effect=socket.gaierror("not found"),
            ):
                ready = dns_preflight(directory)

            self.assertFalse(ready)

    def test_channel_selection_updates_only_deployment_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "vars.yml").write_text(
                "root_domain: example.test\n"
                "haproxy_admin_image: clllagob/haproxy-admin-ui:latest\n",
                encoding="utf-8",
            )
            (directory / "metadata.yml").write_text(
                "product: easy-ha-proxy\n"
                "source_channel: github\n"
                "image_channel: latest\n",
                encoding="utf-8",
            )

            with mock.patch("easy_ha_proxy.backup_configuration") as backup:
                persist_deployment_channels(
                    source_channel="local",
                    image_channel="alpha",
                    directory=directory,
                )

            variables = yaml.safe_load((directory / "vars.yml").read_text())
            metadata = yaml.safe_load((directory / "metadata.yml").read_text())
            self.assertEqual(variables["root_domain"], "example.test")
            self.assertEqual(
                variables["haproxy_admin_image"],
                "clllagob/haproxy-admin-ui:alpha",
            )
            self.assertEqual(metadata["product"], "easy-ha-proxy")
            self.assertEqual(metadata["source_channel"], "local")
            self.assertEqual(metadata["image_channel"], "alpha")
            backup.assert_called_once_with(directory)

    def test_remote_dry_run_reports_local_alpha_workflow(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                str(ROOT / "install-remote.sh"),
                "--host",
                "192.0.2.10",
                "--user",
                "admin",
                "--sync-source",
                str(ROOT),
                "--apply",
                "--image",
                "alpha",
                "--dry-run",
            ],
            check=True,
            text=True,
            capture_output=True,
        )

        self.assertIn("Action: sync-source", completed.stdout)
        self.assertIn("Source channel: local", completed.stdout)
        self.assertIn("Image channel: alpha", completed.stdout)
        self.assertIn("Apply after sync: yes", completed.stdout)

    def test_local_source_bundle_excludes_machine_configuration(self) -> None:
        remote = (ROOT / "install-remote.sh").read_text(encoding="utf-8")
        archive_block = remote.split("build_source_archive() {", 1)[1].split(
            "installer_fingerprint()", 1
        )[0]
        for path in (
            "ansible/inventory.ini",
            "ansible/vars.yml",
            "ansible/websites.yml",
            "ansible/tcp.yml",
            "ansible/authelia_users_initial.yml",
            "ansible/roles/cert/files/*.pem",
        ):
            self.assertIn(f"--exclude='{path}'", archive_block)

    def test_geoip_filtering_is_opt_in_for_legacy_configuration(self) -> None:
        for defaults_path in (
            ROOT / "ansible/roles/haproxy/defaults/main.yml",
            ROOT / "ansible/roles/geoip_acl/defaults/main.yml",
        ):
            defaults = yaml.safe_load(defaults_path.read_text(encoding="utf-8"))
            self.assertIs(defaults["enable_geoip"], False, defaults_path)
        geoip_defaults = yaml.safe_load(
            (
                ROOT / "ansible/roles/geoip_acl/defaults/main.yml"
            ).read_text(encoding="utf-8")
        )
        self.assertIs(geoip_defaults["geoip_database_enabled"], True)

    def test_remote_installer_fingerprint_preflight_is_nounset_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *'/opt/easy-ha-proxy/source'*'sha256sum'*)\n"
                "    printf '%064d\\n' 0\n"
                "    ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_scp = fake_bin / "scp"
            fake_scp.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_ssh.chmod(0o755)
            fake_scp.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            completed = subprocess.run(
                [
                    "bash",
                    str(ROOT / "install-remote.sh"),
                    "--host",
                    "192.0.2.10",
                    "--user",
                    "admin",
                    "--action",
                    "repair",
                ],
                check=False,
                text=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=environment,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("installer source on the server differs", completed.stderr)
            self.assertNotIn("unbound variable", completed.stderr)


if __name__ == "__main__":
    unittest.main()
