"""Regression tests for shell/Ansible deployment channel contracts.

The CLI unit tests for release channels, runtime HAProxy sync, git source
updates, and re-exec now live in go/agent/internal/cli/*_test.go.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class DeploymentChannelShellTests(unittest.TestCase):
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
                "  *'mktemp -d /tmp/easy-ha-proxy-stage'*)\n"
                "    printf '/tmp/easy-ha-proxy-stage.test01\\n'\n"
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
