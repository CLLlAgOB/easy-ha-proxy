from __future__ import annotations

from contextlib import redirect_stdout
from pathlib import Path
import argparse
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import full_backup
from full_backup import (
    activate_recovery_source,
    BackupError,
    create_backup,
    disable_restored_runtime_firewall_state,
    extract_bundle,
    inspect_backup,
    openssl_crypt,
    recovery_source_archive_path,
    restore_backup,
    sha256_file,
    validate_bundle_member,
    validate_payload,
)


class FullBackupTests(unittest.TestCase):
    PASSPHRASE = "correct horse battery"

    @staticmethod
    def _write_regular_tar(
        path: Path,
        entries: list[tuple[str, bytes]],
    ) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, content in entries:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

    def _create_test_archive(
        self,
        root: Path,
        *,
        include_ssh: bool = False,
        ssh_checksum: str | None = None,
        manifest_updates: dict[str, object] | None = None,
        core_entries: list[tuple[str, bytes]] | None = None,
        ssh_entries: list[tuple[str, bytes]] | None = None,
        duplicate_outer: str | None = None,
        extra_outer: tuple[str, bytes] | None = None,
        omit_expanded_metadata: bool = False,
    ) -> tuple[Path, dict[str, object]]:
        payload = root / "payload.tar.gz"
        effective_core_entries = (
            core_entries
            if core_entries is not None
            else [("etc/easy-ha-proxy/state.txt", b"managed state\n")]
        )
        self._write_regular_tar(
            payload,
            effective_core_entries,
        )

        ssh_payload = root / "ssh.tar.gz"
        effective_ssh_entries = (
            ssh_entries
            if ssh_entries is not None
            else [("root/.ssh/authorized_keys", b"ssh-ed25519 test-key\n")]
        )
        if include_ssh:
            self._write_regular_tar(
                ssh_payload,
                effective_ssh_entries,
            )

        manifest: dict[str, object] = {
            "format": "easy-ha-proxy-full-backup",
            "format_version": full_backup.FORMAT_VERSION,
            "created_at": "20260718T120000Z",
            "hostname": "proxy.example.test",
            "machine": "x86_64",
            "core_paths": ["/etc/easy-ha-proxy"],
            "runtime_excludes": list(full_backup.BACKUP_EXCLUDES),
            "ssh_included": include_ssh,
            "ssh_paths": ["/root/.ssh"] if include_ssh else [],
            "quiesced": True,
            "payload_sha256": sha256_file(payload),
            "ssh_payload_sha256": (
                ssh_checksum or sha256_file(ssh_payload)
                if include_ssh
                else None
            ),
            "payload_expanded_bytes": sum(
                len(content) for _name, content in effective_core_entries
            ),
            "ssh_payload_expanded_bytes": (
                sum(len(content) for _name, content in effective_ssh_entries)
                if include_ssh
                else None
            ),
        }
        if omit_expanded_metadata:
            manifest.pop("payload_expanded_bytes")
            manifest.pop("ssh_payload_expanded_bytes")
        if manifest_updates:
            manifest.update(manifest_updates)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        state_path = root / "system-state.txt"
        state_path.write_text("test system\n", encoding="utf-8")

        bundle = root / "bundle.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            archive.add(manifest_path, arcname="manifest.json")
            archive.add(state_path, arcname="system-state.txt")
            archive.add(payload, arcname="payload.tar.gz")
            if include_ssh:
                archive.add(ssh_payload, arcname="ssh.tar.gz")
            if duplicate_outer:
                duplicate_sources = {
                    "manifest.json": manifest_path,
                    "system-state.txt": state_path,
                    "payload.tar.gz": payload,
                    "ssh.tar.gz": ssh_payload,
                }
                archive.add(
                    duplicate_sources[duplicate_outer],
                    arcname=duplicate_outer,
                )
            if extra_outer:
                name, content = extra_outer
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

        encrypted = root / "easy-ha-proxy-full-test.tar.gz.enc"
        openssl_crypt(bundle, encrypted, self.PASSPHRASE, decrypt=False)
        Path(str(encrypted) + ".sha256").write_text(
            f"{sha256_file(encrypted)}  {encrypted.name}\n",
            encoding="ascii",
        )
        return encrypted, manifest

    def _inspect_with_stdin(self, encrypted: Path) -> dict[str, object]:
        args = argparse.Namespace(
            archive=str(encrypted),
            passphrase_stdin=True,
        )
        with mock.patch.object(
            sys,
            "stdin",
            io.StringIO(self.PASSPHRASE + "\n"),
        ):
            return inspect_backup(args)

    def test_geoip_timer_is_quiesced_before_updater_service(self) -> None:
        timer = full_backup.QUIESCE_UNITS.index(
            "easy-ha-proxy-geoip-update.timer"
        )
        service = full_backup.QUIESCE_UNITS.index(
            "easy-ha-proxy-geoip-update.service"
        )
        self.assertLess(timer, service)

    def test_encryption_round_trip(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            encrypted = root / "backup.enc"
            restored = root / "restored.bin"
            source.write_bytes(b"easy-ha-proxy backup test\n" * 32)
            openssl_crypt(source, encrypted, "correct horse battery", decrypt=False)
            self.assertNotEqual(sha256_file(source), sha256_file(encrypted))
            openssl_crypt(encrypted, restored, "correct horse battery", decrypt=True)
            self.assertEqual(source.read_bytes(), restored.read_bytes())

    def test_passphrase_stdin_takes_precedence_and_reads_one_line(self) -> None:
        stdin = io.StringIO(self.PASSPHRASE + "  \nunused second line\n")
        with (
            mock.patch.object(sys, "stdin", stdin),
            mock.patch.dict(
                os.environ,
                {
                    "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                    "EASY_HA_PROXY_TEST_PASSPHRASE": "environment passphrase",
                },
                clear=False,
            ),
            mock.patch.object(
                full_backup.getpass,
                "getpass",
                side_effect=AssertionError("getpass must not be used"),
            ),
        ):
            password = full_backup.read_passphrase(
                confirm=True,
                from_stdin=True,
            )

        self.assertEqual(password, self.PASSPHRASE + "  ")
        self.assertEqual(stdin.readline(), "unused second line\n")

    def test_interactive_passphrase_still_confirms_by_default(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(
                full_backup.getpass,
                "getpass",
                side_effect=[self.PASSPHRASE, self.PASSPHRASE],
            ) as getpass_mock,
        ):
            password = full_backup.read_passphrase(confirm=True)

        self.assertEqual(password, self.PASSPHRASE)
        self.assertEqual(getpass_mock.call_count, 2)

    def test_web_safe_cli_flags_are_available_on_each_command(self) -> None:
        parser = full_backup.build_parser()
        backup = parser.parse_args(["backup", "--passphrase-stdin"])
        restore = parser.parse_args(
            [
                "restore",
                "/tmp/backup.enc",
                "--passphrase-stdin",
                "--replace-managed",
                "--yes",
            ]
        )
        inspect = parser.parse_args(
            ["inspect", "/tmp/backup.enc", "--passphrase-stdin"]
        )

        self.assertTrue(backup.passphrase_stdin)
        self.assertTrue(restore.passphrase_stdin)
        self.assertTrue(restore.replace_managed)
        self.assertTrue(restore.yes)
        self.assertTrue(inspect.passphrase_stdin)

    def test_quiesce_unwinds_services_after_partial_entry_failure(self) -> None:
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            if argv == ["systemctl", "stop", "second.service"]:
                raise OSError("simulated stop failure")
            return mock.Mock(returncode=0)

        quiesce = full_backup.Quiesce(True)
        with (
            mock.patch.object(
                full_backup,
                "QUIESCE_UNITS",
                ("first.service", "second.service"),
            ),
            mock.patch.object(
                full_backup.shutil,
                "which",
                side_effect=lambda command: (
                    "/bin/systemctl" if command == "systemctl" else None
                ),
            ),
            mock.patch.object(full_backup, "run", side_effect=fake_run),
            self.assertRaisesRegex(OSError, "simulated stop failure"),
        ):
            quiesce.__enter__()

        self.assertIn(["systemctl", "start", "first.service"], calls)
        self.assertEqual(quiesce.units, [])
        self.assertEqual(quiesce.containers, [])

    def test_safe_letsencrypt_relative_symlink_is_allowed(self) -> None:
        member = tarfile.TarInfo("etc/letsencrypt/live/example/cert.pem")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../archive/example/cert1.pem"
        validate_bundle_member(member)

    def test_escaping_symlink_is_rejected(self) -> None:
        member = tarfile.TarInfo("etc/easy-ha-proxy/escape")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../../../etc/shadow"
        with self.assertRaises(BackupError):
            validate_bundle_member(member)

    def test_absolute_symlink_and_escaping_hardlink_are_rejected(self) -> None:
        absolute = tarfile.TarInfo("etc/easy-ha-proxy/absolute")
        absolute.type = tarfile.SYMTYPE
        absolute.linkname = "/etc/shadow"
        escaping = tarfile.TarInfo("etc/easy-ha-proxy/hardlink")
        escaping.type = tarfile.LNKTYPE
        escaping.linkname = "../etc/shadow"

        for member in (absolute, escaping):
            with self.subTest(member=member.name), self.assertRaises(BackupError):
                validate_bundle_member(member)

    def test_devices_and_fifo_are_rejected(self) -> None:
        for member_type in (
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
            tarfile.FIFOTYPE,
        ):
            member = tarfile.TarInfo("etc/easy-ha-proxy/special")
            member.type = member_type
            with self.subTest(member_type=member_type), self.assertRaises(BackupError):
                validate_bundle_member(member)

    def test_parent_path_is_rejected(self) -> None:
        member = tarfile.TarInfo("../etc/shadow")
        with self.assertRaises(BackupError):
            validate_bundle_member(member)

    def test_create_encrypted_bundle_with_manifest(self) -> None:
        if not shutil.which("openssl") or not shutil.which("tar"):
            self.skipTest("openssl and tar are required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            data = root / "data"
            config.mkdir()
            data.mkdir()
            (config / "metadata.yml").write_text("mode: production\n")
            (data / "secret.txt").write_text("secret\n")
            args = argparse.Namespace(
                output_dir=str(root / "backups"),
                include_ssh=False,
                quiesce=False,
                passphrase_stdin=True,
            )
            environment = {
                "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                "EASY_HA_PROXY_CONFIG_DIR": str(config),
            }
            backup_output = io.StringIO()
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(full_backup, "CORE_PATHS", (str(data),)),
                mock.patch.object(full_backup, "CORE_GLOBS", ()),
                mock.patch.object(
                    full_backup,
                    "CORE_DIRECTORY_PATHS",
                    frozenset({str(data)}),
                ),
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                mock.patch.object(
                    full_backup.getpass,
                    "getpass",
                    side_effect=AssertionError("getpass must not be used"),
                ),
                redirect_stdout(backup_output),
            ):
                encrypted = create_backup(args)

            decrypted = root / "decrypted.tar.gz"
            extracted = root / "extracted"
            extracted.mkdir()
            openssl_crypt(
                encrypted,
                decrypted,
                self.PASSPHRASE,
                decrypt=True,
            )
            extract_bundle(decrypted, extracted)
            manifest = json.loads(
                (extracted / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["format_version"], 1)
            self.assertEqual(manifest["core_paths"], [str(data)])
            self.assertEqual(
                manifest["runtime_excludes"],
                list(full_backup.BACKUP_EXCLUDES),
            )
            self.assertFalse(manifest["ssh_included"])
            self.assertEqual(manifest["payload_expanded_bytes"], 7)
            self.assertIsNone(manifest["ssh_payload_expanded_bytes"])
            marker = "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
            marker_lines = [
                line
                for line in backup_output.getvalue().splitlines()
                if line.startswith(marker)
            ]
            self.assertEqual(len(marker_lines), 1)
            self.assertEqual(json.loads(marker_lines[0][len(marker):]), manifest)

    def test_inspect_prints_one_compact_manifest_marker_without_prompt(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encrypted, expected_manifest = self._create_test_archive(root)
            before = set(root.iterdir())
            output = io.StringIO()
            args = argparse.Namespace(
                archive=str(encrypted),
                passphrase_stdin=True,
            )
            with (
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                mock.patch.object(
                    full_backup.getpass,
                    "getpass",
                    side_effect=AssertionError("getpass must not be used"),
                ),
                mock.patch("builtins.input", side_effect=AssertionError("input must not be used")),
                redirect_stdout(output),
            ):
                manifest = inspect_backup(args)

            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            prefix = "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
            self.assertTrue(lines[0].startswith(prefix))
            self.assertEqual(json.loads(lines[0][len(prefix):]), expected_manifest)
            self.assertEqual(manifest, expected_manifest)
            self.assertEqual(set(root.iterdir()), before)

    def test_inspect_enriches_older_v1_manifest_with_measured_sizes(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, original_manifest = self._create_test_archive(
                Path(temporary),
                omit_expanded_metadata=True,
            )

            manifest = self._inspect_with_stdin(encrypted)

            self.assertNotIn("payload_expanded_bytes", original_manifest)
            self.assertEqual(manifest["payload_expanded_bytes"], len(b"managed state\n"))
            self.assertIsNone(manifest["ssh_payload_expanded_bytes"])

    def test_inspect_rejects_declared_expanded_size_mismatch(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, _manifest = self._create_test_archive(
                Path(temporary),
                manifest_updates={"payload_expanded_bytes": 1},
            )

            with self.assertRaisesRegex(BackupError, "expanded-size verification"):
                self._inspect_with_stdin(encrypted)

    def test_inspect_rejects_an_invalid_ssh_payload_checksum(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, _manifest = self._create_test_archive(
                Path(temporary),
                include_ssh=True,
                ssh_checksum="0" * 64,
            )
            args = argparse.Namespace(
                archive=str(encrypted),
                passphrase_stdin=True,
            )
            with (
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                self.assertRaisesRegex(BackupError, "SSH payload checksum"),
            ):
                inspect_backup(args)

    def test_inspect_rejects_core_member_outside_fixed_allowlist(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, _manifest = self._create_test_archive(
                Path(temporary),
                core_entries=[("etc/shadow", b"root:*:0:0\n")],
            )
            with self.assertRaisesRegex(BackupError, "outside managed paths"):
                self._inspect_with_stdin(encrypted)

    def test_inspect_rejects_manifest_core_path_outside_fixed_allowlist(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, _manifest = self._create_test_archive(
                Path(temporary),
                manifest_updates={"core_paths": ["/etc"]},
            )
            with self.assertRaisesRegex(BackupError, "unmanaged core_paths"):
                self._inspect_with_stdin(encrypted)

    def test_inspect_rejects_ssh_member_outside_fixed_allowlist(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            encrypted, _manifest = self._create_test_archive(
                Path(temporary),
                include_ssh=True,
                ssh_entries=[("etc/shadow", b"not an SSH key\n")],
            )
            with self.assertRaisesRegex(BackupError, "outside allowed paths"):
                self._inspect_with_stdin(encrypted)

    def test_inspect_rejects_duplicate_and_unknown_outer_members(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        cases = (
            ({"duplicate_outer": "manifest.json"}, "Duplicate outer backup"),
            ({"extra_outer": ("unexpected.txt", b"unexpected\n")}, "Unexpected outer"),
        )
        for options, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                encrypted, _manifest = self._create_test_archive(
                    Path(temporary),
                    **options,
                )
                with self.assertRaisesRegex(BackupError, message):
                    self._inspect_with_stdin(encrypted)

    def test_core_payload_enforces_member_count_and_expanded_size_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload.tar.gz"
            self._write_regular_tar(
                payload,
                [
                    ("etc/easy-ha-proxy/one", b"1"),
                    ("etc/easy-ha-proxy/two", b"22"),
                ],
            )
            with (
                mock.patch.object(full_backup, "MAX_CORE_MEMBERS", 1),
                self.assertRaisesRegex(BackupError, "member-count limit"),
            ):
                validate_payload(payload)
            with (
                mock.patch.object(full_backup, "MAX_CORE_EXPANDED_BYTES", 2),
                self.assertRaisesRegex(BackupError, "expanded-size limit"),
            ):
                validate_payload(payload)

    def test_outer_and_ssh_archives_use_their_own_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if shutil.which("openssl"):
                self._create_test_archive(root)
                destination = root / "extract"
                destination.mkdir()
                with (
                    mock.patch.object(full_backup, "MAX_OUTER_MEMBERS", 2),
                    self.assertRaisesRegex(BackupError, "member-count limit"),
                ):
                    extract_bundle(root / "bundle.tar.gz", destination)
                with (
                    mock.patch.object(full_backup, "MAX_OUTER_EXPANDED_BYTES", 1),
                    self.assertRaisesRegex(BackupError, "expanded-size limit"),
                ):
                    extract_bundle(root / "bundle.tar.gz", destination)

            ssh_payload = root / "ssh.tar.gz"
            self._write_regular_tar(
                ssh_payload,
                [
                    ("root/.ssh/authorized_keys", b"one"),
                    ("home/operator/.ssh/authorized_keys", b"two"),
                ],
            )
            validate_payload(ssh_payload, ssh=True)
            with (
                mock.patch.object(full_backup, "MAX_SSH_MEMBERS", 1),
                self.assertRaisesRegex(BackupError, "member-count limit"),
            ):
                validate_payload(ssh_payload, ssh=True)
            with (
                mock.patch.object(full_backup, "MAX_SSH_EXPANDED_BYTES", 5),
                self.assertRaisesRegex(BackupError, "expanded-size limit"),
            ):
                validate_payload(ssh_payload, ssh=True)

    def test_outer_bundle_checks_temporary_space_before_extraction(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._create_test_archive(root)
            destination = root / "extract-low-space"
            destination.mkdir()

            with (
                mock.patch.object(
                    full_backup.shutil,
                    "disk_usage",
                    return_value=mock.Mock(free=0),
                ),
                self.assertRaisesRegex(BackupError, "temporary disk space"),
            ):
                extract_bundle(root / "bundle.tar.gz", destination)

            self.assertEqual(list(destination.iterdir()), [])

    def test_core_payload_allows_ancestors_and_letsencrypt_relative_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload.tar.gz"
            with tarfile.open(payload, "w:gz") as archive:
                for name in ("etc", "etc/letsencrypt"):
                    directory = tarfile.TarInfo(name)
                    directory.type = tarfile.DIRTYPE
                    archive.addfile(directory)
                certificate = tarfile.TarInfo(
                    "etc/letsencrypt/archive/example/cert1.pem"
                )
                certificate.size = 4
                archive.addfile(certificate, io.BytesIO(b"cert"))
                link = tarfile.TarInfo(
                    "etc/letsencrypt/live/example/cert.pem"
                )
                link.type = tarfile.SYMTYPE
                link.linkname = "../../archive/example/cert1.pem"
                archive.addfile(link)
                for name in (
                    "etc/systemd/system/haproxy-certd.service",
                    "usr/local/sbin/haproxy-healthd.py",
                    "etc/rsyslog.d/49-haproxy.conf",
                ):
                    managed_file = tarfile.TarInfo(name)
                    managed_file.size = 1
                    archive.addfile(managed_file, io.BytesIO(b"x"))

            validate_payload(payload)

    def test_core_payload_allows_children_of_a_managed_glob_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload.tar.gz"
            self._write_regular_tar(
                payload,
                [
                    (
                        "etc/systemd/system/haproxy.service.d/override.conf",
                        b"[Service]\nEnvironment=TEST=1\n",
                    )
                ],
            )

            self.assertGreater(validate_payload(payload), 0)

    def test_rollback_payload_can_contain_core_and_opted_in_ssh_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "rollback.tar.gz"
            self._write_regular_tar(
                payload,
                [
                    ("etc/easy-ha-proxy/vars.yml", b"root_domain: example.test\n"),
                    ("root/.ssh/authorized_keys", b"ssh-ed25519 test-key\n"),
                ],
            )

            full_backup.validate_rollback_payload(payload, include_ssh=True)
            with self.assertRaisesRegex(BackupError, "outside managed paths"):
                full_backup.validate_rollback_payload(payload, include_ssh=False)

    def test_remove_paths_deletes_only_explicit_targets_without_following_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            managed = root / "managed"
            unrelated = root / "unrelated"
            managed.mkdir()
            unrelated.mkdir()
            (managed / "stale.txt").write_text("stale\n", encoding="utf-8")
            (unrelated / "keep.txt").write_text("keep\n", encoding="utf-8")
            link = root / "managed-link"
            link.symlink_to(unrelated, target_is_directory=True)

            full_backup.remove_paths([str(managed), str(link)])

            self.assertFalse(managed.exists())
            self.assertFalse(os.path.lexists(link))
            self.assertEqual(
                (unrelated / "keep.txt").read_text(encoding="utf-8"),
                "keep\n",
            )

    def test_restore_capacity_scan_does_not_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unrelated = root / "unrelated"
            unrelated.mkdir()
            (unrelated / "large.bin").write_bytes(b"x" * 4096)
            link = root / "managed-link"
            link.symlink_to(unrelated, target_is_directory=True)

            expanded, members, _devices = full_backup.managed_paths_apparent_usage(
                [str(link)]
            )

            self.assertEqual(members, 1)
            self.assertLess(expanded, 4096)

    def test_restore_preflight_rejects_insufficient_rollback_space(self) -> None:
        manifest = {
            "payload_expanded_bytes": 100,
            "ssh_payload_expanded_bytes": None,
        }
        with (
            mock.patch.object(
                full_backup,
                "managed_paths_apparent_usage",
                return_value=(50, 2, {7}),
            ),
            mock.patch.object(
                full_backup,
                "_existing_ancestor",
                side_effect=[Path("/"), Path("/var")],
            ),
            mock.patch.object(
                full_backup.os,
                "stat",
                side_effect=[mock.Mock(st_dev=7), mock.Mock(st_dev=7)],
            ),
            mock.patch.object(
                full_backup.shutil,
                "disk_usage",
                side_effect=[mock.Mock(free=199), mock.Mock(free=199)],
            ),
            mock.patch.object(full_backup, "RESTORE_MIN_FREE_BYTES", 100),
            mock.patch.object(full_backup, "ROLLBACK_BASE_OVERHEAD_BYTES", 20),
            mock.patch.object(full_backup, "ROLLBACK_MEMBER_OVERHEAD_BYTES", 5),
            self.assertRaisesRegex(BackupError, "Not enough free space"),
        ):
            # Exact replacement reclaims 50 bytes, but rollback (80), growth
            # (50), and reserve (100) still require 230 bytes.
            full_backup.preflight_restore_space(
                manifest,
                ["/managed"],
                replace_managed=True,
                restore_ssh=False,
            )

    def test_restore_yes_skips_restore_confirmation(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encrypted, _manifest = self._create_test_archive(root)
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text("mode: production\n")
            args = argparse.Namespace(
                archive=str(encrypted),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=False,
                passphrase_stdin=True,
                yes=True,
                replace_managed=False,
            )
            environment = {
                "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                "EASY_HA_PROXY_CONFIG_DIR": str(config),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                mock.patch("builtins.input", side_effect=AssertionError("input must not be used")),
                mock.patch.object(full_backup, "create_pre_restore_backup", return_value=None),
                mock.patch.object(full_backup, "managed_state_paths", return_value=[]),
                mock.patch.object(full_backup, "Quiesce"),
                mock.patch.object(full_backup, "extract_payload") as extract_mock,
                mock.patch.object(full_backup, "disable_restored_runtime_firewall_state"),
                redirect_stdout(io.StringIO()),
            ):
                restore_backup(args)

            extract_mock.assert_called_once()

    def test_restore_preflights_control_plane_before_quiesce_and_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "backup.enc"
            archive.write_bytes(b"encrypted")
            payload = root / "payload.tar.gz"
            payload.write_bytes(b"payload")
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "mode: production\n", encoding="utf-8"
            )
            args = argparse.Namespace(
                archive=str(archive),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=True,
                passphrase_stdin=True,
                yes=True,
                replace_managed=True,
            )
            manifest = {
                "hostname": "proxy.example.test",
                "created_at": "20260718T120000Z",
                "payload_expanded_bytes": 1,
                "ssh_payload_expanded_bytes": None,
            }
            events: list[str] = []

            class RecordingQuiesce:
                def __init__(self, *_args, **_kwargs):
                    events.append("quiesce-created")

                def __enter__(self):
                    events.append("quiesce-entered")
                    return self

                def resume_units(self):
                    events.append("quiesce-units-resumed")

                def __exit__(self, *_args):
                    events.append("quiesce-exited")
                    return False

            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                        "EASY_HA_PROXY_CONFIG_DIR": str(config),
                    },
                    clear=False,
                ),
                mock.patch.object(full_backup, "verify_encrypted_archive"),
                mock.patch.object(full_backup, "read_passphrase", return_value="secret"),
                mock.patch.object(
                    full_backup,
                    "validate_backup_archive",
                    return_value=(manifest, payload, None),
                ),
                mock.patch.object(
                    full_backup,
                    "preflight_restore_control_plane",
                    side_effect=lambda: events.append("control-plane-preflight"),
                ),
                mock.patch.object(
                    full_backup,
                    "managed_state_paths",
                    side_effect=lambda **_kwargs: events.append("managed-paths") or [
                        "/trusted/current-state"
                    ],
                ),
                mock.patch.object(
                    full_backup,
                    "preflight_restore_space",
                    side_effect=lambda *_args, **_kwargs: events.append("space-preflight"),
                ),
                mock.patch.object(full_backup, "Quiesce", RecordingQuiesce),
                mock.patch.object(
                    full_backup,
                    "create_pre_restore_backup",
                    side_effect=lambda *_args: events.append("rollback-snapshot") or None,
                ),
                mock.patch.object(
                    full_backup,
                    "remove_paths",
                    side_effect=lambda *_args: events.append("remove-managed"),
                ),
                mock.patch.object(
                    full_backup,
                    "extract_payload",
                    side_effect=lambda *_args: events.append("extract-candidate"),
                ),
                mock.patch.object(full_backup, "disable_restored_runtime_firewall_state"),
                mock.patch.object(full_backup, "normalize_restored_config_permissions"),
                mock.patch.object(
                    full_backup,
                    "reconcile_restored_host",
                    side_effect=lambda **_kwargs: events.append("reconcile-candidate"),
                ),
                redirect_stdout(io.StringIO()),
            ):
                restore_backup(args)

            self.assertLess(
                events.index("control-plane-preflight"),
                events.index("quiesce-created"),
            )
            self.assertLess(
                events.index("control-plane-preflight"),
                events.index("rollback-snapshot"),
            )
            self.assertLess(
                events.index("control-plane-preflight"),
                events.index("remove-managed"),
            )
            self.assertLess(
                events.index("control-plane-preflight"),
                events.index("extract-candidate"),
            )
            # Reconciliation ends with a status check that requires the
            # quiesced timers (for example snap.certbot.renew.timer) to be
            # active again, so they must be resumed first.
            self.assertLess(
                events.index("quiesce-units-resumed"),
                events.index("reconcile-candidate"),
            )
            self.assertLess(
                events.index("reconcile-candidate"),
                events.index("quiesce-exited"),
            )

    def test_restore_control_plane_preflight_failure_leaves_state_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "backup.enc"
            archive.write_bytes(b"encrypted")
            payload = root / "payload.tar.gz"
            payload.write_bytes(b"payload")
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "mode: production\n", encoding="utf-8"
            )
            args = argparse.Namespace(
                archive=str(archive),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=True,
                passphrase_stdin=True,
                yes=True,
                replace_managed=True,
            )
            manifest = {
                "hostname": "proxy.example.test",
                "created_at": "20260718T120000Z",
                "payload_expanded_bytes": 1,
                "ssh_payload_expanded_bytes": None,
            }
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                        "EASY_HA_PROXY_CONFIG_DIR": str(config),
                    },
                    clear=False,
                ),
                mock.patch.object(full_backup, "verify_encrypted_archive"),
                mock.patch.object(full_backup, "read_passphrase", return_value="secret"),
                mock.patch.object(
                    full_backup,
                    "validate_backup_archive",
                    return_value=(manifest, payload, None),
                ),
                mock.patch.object(
                    full_backup,
                    "preflight_restore_control_plane",
                    side_effect=BackupError(
                        "Restore control-plane Python dependency check failed "
                        "with exit code 100: _apt setresuid EPERM"
                    ),
                ),
                mock.patch.object(full_backup, "Quiesce") as quiesce,
                mock.patch.object(full_backup, "managed_state_paths") as managed_paths,
                mock.patch.object(full_backup, "create_pre_restore_backup") as snapshot,
                mock.patch.object(full_backup, "remove_paths") as remove_paths,
                mock.patch.object(full_backup, "extract_payload") as extract_payload,
                redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(
                    BackupError,
                    r"exit code 100: _apt setresuid EPERM",
                ),
            ):
                restore_backup(args)

            quiesce.assert_not_called()
            managed_paths.assert_not_called()
            snapshot.assert_not_called()
            remove_paths.assert_not_called()
            extract_payload.assert_not_called()

    def test_restore_stage_preserves_stage_exit_code_and_stderr_tail(self) -> None:
        failure = full_backup.subprocess.CalledProcessError(
            100,
            ["apt-get", "update"],
            output="ordinary output",
            stderr="E: setresuid 42 failed: Operation not permitted",
        )
        with (
            mock.patch.object(full_backup, "run", side_effect=failure),
            self.assertRaisesRegex(
                BackupError,
                r"Restore dependency check failed with exit code 100: "
                r"E: setresuid 42 failed: Operation not permitted",
            ),
        ):
            full_backup._restore_stage(
                "Restore dependency check",
                ["apt-get", "update"],
                capture=True,
            )

    def test_reconcile_rollback_reuses_prepared_control_plane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            installer = source / "install-local.sh"
            installer.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            with (
                mock.patch.object(
                    full_backup,
                    "activate_recovery_source",
                    return_value=source,
                ),
                mock.patch.object(full_backup, "_restore_stage") as run_stage,
            ):
                full_backup.reconcile_restored_host(prepare_entrypoints=True)
                candidate_calls = list(run_stage.call_args_list)
                run_stage.reset_mock()
                full_backup.reconcile_restored_host(prepare_entrypoints=False)
                rollback_calls = list(run_stage.call_args_list)

            self.assertEqual(len(candidate_calls), 2)
            candidate_installer_argv = candidate_calls[0].args[1]
            self.assertEqual(
                candidate_installer_argv[-2:],
                ["--prepare-only", "--skip-bootstrap-dependencies"],
            )
            self.assertNotIn("apt-get", candidate_installer_argv)
            self.assertEqual(len(rollback_calls), 1)
            self.assertEqual(
                rollback_calls[0].args[1],
                ["/usr/local/bin/easy-ha-proxy", "apply-restored"],
            )

    def test_broker_offline_mode_reaches_candidate_and_rollback_reconcile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "install-local.sh").write_text(
                "#!/usr/bin/env bash\n", encoding="utf-8"
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {full_backup.OFFLINE_RESTORE_ENV: "1"},
                    clear=False,
                ),
                mock.patch.object(
                    full_backup,
                    "activate_recovery_source",
                    return_value=source,
                ),
                mock.patch.object(full_backup, "_restore_stage") as run_stage,
            ):
                full_backup.reconcile_restored_host(prepare_entrypoints=True)
                candidate = list(run_stage.call_args_list)
                run_stage.reset_mock()
                full_backup.reconcile_restored_host(prepare_entrypoints=False)
                rollback = list(run_stage.call_args_list)

        self.assertEqual(
            candidate[-1].args[1],
            ["/usr/local/bin/easy-ha-proxy", "apply-restored", "--offline"],
        )
        self.assertEqual(
            rollback[-1].args[1],
            ["/usr/local/bin/easy-ha-proxy", "apply-restored", "--offline"],
        )

    def test_recovery_source_archive_path_avoids_fast_restore_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            managed = Path(temporary) / "source"
            first = recovery_source_archive_path(
                managed,
                timestamp="20260719T080000000000Z",
                pid=123,
            )
            first.mkdir()
            second = recovery_source_archive_path(
                managed,
                timestamp="20260719T080000000000Z",
                pid=123,
            )

        self.assertEqual(second, Path(f"{first}.1"))

    def test_candidate_failure_rolls_back_without_repeating_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "backup.enc"
            archive.write_bytes(b"encrypted")
            payload = root / "payload.tar.gz"
            payload.write_bytes(b"payload")
            rollback = root / "previous-state.tar.gz"
            rollback.write_bytes(b"rollback")
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "mode: production\n", encoding="utf-8"
            )
            args = argparse.Namespace(
                archive=str(archive),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=True,
                passphrase_stdin=True,
                yes=True,
                replace_managed=True,
            )
            manifest = {
                "hostname": "proxy.example.test",
                "created_at": "20260718T120000Z",
                "payload_expanded_bytes": 1,
                "ssh_payload_expanded_bytes": None,
            }
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                        "EASY_HA_PROXY_CONFIG_DIR": str(config),
                    },
                    clear=False,
                ),
                mock.patch.object(full_backup, "verify_encrypted_archive"),
                mock.patch.object(full_backup, "read_passphrase", return_value="secret"),
                mock.patch.object(
                    full_backup,
                    "validate_backup_archive",
                    return_value=(manifest, payload, None),
                ),
                mock.patch.object(full_backup, "preflight_restore_control_plane") as preflight,
                mock.patch.object(full_backup, "managed_state_paths", return_value=[]),
                mock.patch.object(full_backup, "preflight_restore_space"),
                mock.patch.object(full_backup, "Quiesce"),
                mock.patch.object(
                    full_backup,
                    "create_pre_restore_backup",
                    return_value=rollback,
                ),
                mock.patch.object(full_backup, "remove_paths"),
                mock.patch.object(full_backup, "extract_payload") as extract_payload,
                mock.patch.object(full_backup, "disable_restored_runtime_firewall_state"),
                mock.patch.object(full_backup, "normalize_restored_config_permissions"),
                mock.patch.object(full_backup, "validate_rollback_payload"),
                mock.patch.object(full_backup, "remove_managed_state"),
                mock.patch.object(
                    full_backup,
                    "reconcile_restored_host",
                    side_effect=[BackupError("candidate apply failed"), None],
                ) as reconcile,
                mock.patch.object(full_backup, "cleanup_pre_restore_backup") as cleanup,
                redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(
                    BackupError,
                    r"previous managed state was restored automatically",
                ) as raised,
            ):
                restore_backup(args)

            preflight.assert_called_once_with()
            self.assertEqual(
                reconcile.call_args_list,
                [mock.call(), mock.call(prepare_entrypoints=False)],
            )
            self.assertEqual(
                extract_payload.call_args_list,
                [mock.call(payload), mock.call(rollback)],
            )
            cleanup.assert_called_once_with(rollback)
            self.assertNotIn("automatic rollback also failed", str(raised.exception))

    def test_replace_restore_uses_trusted_paths_and_rolls_back_apply_failure(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encrypted, _manifest = self._create_test_archive(root)
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text("mode: production\n")
            rollback = root / "previous-state.tar.gz"
            rollback.write_bytes(b"rollback")
            args = argparse.Namespace(
                archive=str(encrypted),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=True,
                passphrase_stdin=True,
                yes=True,
                replace_managed=True,
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                        "EASY_HA_PROXY_CONFIG_DIR": str(config),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                mock.patch.object(full_backup, "Quiesce"),
                mock.patch.object(
                    full_backup,
                    "managed_state_paths",
                    return_value=["/trusted/current-state"],
                ),
                mock.patch.object(
                    full_backup,
                    "create_pre_restore_backup",
                    return_value=rollback,
                ),
                mock.patch.object(full_backup, "preflight_restore_control_plane"),
                mock.patch.object(full_backup, "remove_paths") as remove_mock,
                mock.patch.object(full_backup, "extract_payload"),
                mock.patch.object(full_backup, "disable_restored_runtime_firewall_state"),
                mock.patch.object(full_backup, "normalize_restored_config_permissions"),
                mock.patch.object(
                    full_backup,
                    "reconcile_restored_host",
                    side_effect=RuntimeError("candidate apply failed"),
                ),
                mock.patch.object(full_backup, "restore_previous_state") as restore_previous,
                mock.patch.object(full_backup, "cleanup_pre_restore_backup") as cleanup,
                redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(BackupError, "restored automatically"),
            ):
                restore_backup(args)

            remove_mock.assert_called_once_with(["/trusted/current-state"])
            restore_previous.assert_called_once_with(
                rollback,
                restore_ssh=False,
                apply=True,
            )
            cleanup.assert_called_once_with(rollback)

    def test_failed_automatic_rollback_preserves_safety_archive(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encrypted, _manifest = self._create_test_archive(root)
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text("mode: production\n")
            rollback = root / "previous-state.tar.gz"
            rollback.write_bytes(b"rollback")
            args = argparse.Namespace(
                archive=str(encrypted),
                mode="overlay",
                restore_ssh=False,
                skip_ssh=True,
                apply=False,
                passphrase_stdin=True,
                yes=True,
                replace_managed=True,
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "EASY_HA_PROXY_ALLOW_NON_ROOT": "1",
                        "EASY_HA_PROXY_CONFIG_DIR": str(config),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "stdin",
                    io.StringIO(self.PASSPHRASE + "\n"),
                ),
                mock.patch.object(full_backup, "Quiesce"),
                mock.patch.object(full_backup, "managed_state_paths", return_value=[]),
                mock.patch.object(
                    full_backup,
                    "create_pre_restore_backup",
                    return_value=rollback,
                ),
                mock.patch.object(full_backup, "remove_paths"),
                mock.patch.object(
                    full_backup,
                    "extract_payload",
                    side_effect=RuntimeError("candidate extraction failed"),
                ),
                mock.patch.object(
                    full_backup,
                    "restore_previous_state",
                    side_effect=RuntimeError("rollback extraction failed"),
                ),
                mock.patch.object(full_backup, "cleanup_pre_restore_backup") as cleanup,
                redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(BackupError, "automatic rollback also failed") as raised,
            ):
                restore_backup(args)

            self.assertIn(str(rollback), str(raised.exception))
            cleanup.assert_not_called()

    def test_notification_secrets_are_excluded_from_payload(self) -> None:
        if not shutil.which("tar"):
            self.skipTest("tar is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authelia = root / "opt/authelia"
            state_file = (
                root
                / "var/lib/easy-ha-proxy/authelia-notification-state.json"
            )
            authelia.mkdir(parents=True)
            state_file.parent.mkdir(parents=True)
            (authelia / "configuration.yml").write_text(
                "notifier: {}\n", encoding="utf-8"
            )
            (authelia / "notification.log").write_text(
                "one-time reset link\n", encoding="utf-8"
            )
            state_file.write_text(
                '{"content":"one-time code"}\n', encoding="utf-8"
            )
            payload = root / "payload.tar.gz"

            with mock.patch.object(
                full_backup,
                "BACKUP_EXCLUDES",
                (
                    str(authelia / "notification.log").lstrip("/"),
                    str(state_file).lstrip("/"),
                ),
            ):
                full_backup.create_payload(
                    payload,
                    [str(authelia), str(state_file.parent)],
                )

            with tarfile.open(payload, "r:gz") as archive:
                names = set(archive.getnames())
            self.assertIn(str(authelia / "configuration.yml").lstrip("/"), names)
            self.assertNotIn(str(authelia / "notification.log").lstrip("/"), names)
            self.assertNotIn(str(state_file).lstrip("/"), names)

    def test_activate_recovery_source_preserves_archived_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recovery = root / "recovery"
            managed = root / "managed-source"
            for relative in (
                "install-local.sh",
                "installer/easy_ha_proxy.py",
                "ansible/easy-ha-proxy.yml",
                "ansible/requirements.yml",
            ):
                path = recovery / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"recovery: {relative}\n", encoding="utf-8")
            managed.mkdir()
            (managed / "archived.txt").write_text("from backup\n", encoding="utf-8")

            environment = {"EASY_HA_PROXY_SOURCE_DIR": str(recovery)}
            real_path = Path

            def mapped_path(value: str) -> Path:
                if value == "/opt/easy-ha-proxy/source":
                    return managed
                return real_path(value)

            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(full_backup, "Path", side_effect=mapped_path),
                mock.patch.object(full_backup, "run") as run_mock,
            ):
                result = activate_recovery_source()

            self.assertEqual(result, managed)
            self.assertTrue((managed / "installer/easy_ha_proxy.py").is_file())
            preserved = list(root.glob("source.from-backup.*"))
            self.assertEqual(len(preserved), 1)
            self.assertEqual(
                (preserved[0] / "archived.txt").read_text(encoding="utf-8"),
                "from backup\n",
            )
            run_mock.assert_called_once()

    def test_disable_restored_runtime_firewall_state_preserves_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iptables = root / "etc/iptables"
            iptables.mkdir(parents=True)
            rules_v4 = iptables / "rules.v4"
            rules_v6 = iptables / "rules.v6"
            haproxy_rules = iptables / "haproxy_ban.rules"
            rules_v4.write_text("*nat\n:DOCKER - [0:0]\nCOMMIT\n", encoding="utf-8")
            rules_v6.write_text("*filter\nCOMMIT\n", encoding="utf-8")
            haproxy_rules.write_text("*filter\n:HP_BAN - [0:0]\nCOMMIT\n", encoding="utf-8")

            disabled = disable_restored_runtime_firewall_state(root)

            self.assertEqual(len(disabled), 2)
            self.assertFalse(rules_v4.exists())
            self.assertFalse(rules_v6.exists())
            self.assertTrue(haproxy_rules.exists())
            self.assertTrue(list(iptables.glob("rules.v4.restored-disabled.*")))
            self.assertTrue(list(iptables.glob("rules.v6.restored-disabled.*")))


if __name__ == "__main__":
    unittest.main()
