"""The installer keeps its files out of names any local user can take first.

It runs as root. It wrote the public internal CA to
/tmp/easy-ha-proxy-internal-ca.crt and gave Ansible
/tmp/easy-ha-proxy-ansible to work in: fixed names in a directory everyone
may write to. A symlink planted at the first had root write through it;
whoever created the second owned it, and could swap the modules Ansible
writes there before root ran them. The restore also extracted a backup
bundle with no extraction filter of its own.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import easy_ha_proxy
import full_backup


ROOT = Path(__file__).resolve().parents[1]
SHELL_SCRIPTS = ("install.sh", "install-local.sh", "install-remote.sh", "easy-ha-proxy-helper.sh")


class TheCAExportLivesUnderTheInstallHome(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()

    def environment(self, **extra):
        values = {"EASY_HA_PROXY_HOME": str(self.home), **extra}
        patcher = mock.patch.dict(os.environ, values)
        patcher.start()
        self.addCleanup(patcher.stop)
        if "EASY_HA_PROXY_CA_EXPORT" not in extra:
            os.environ.pop("EASY_HA_PROXY_CA_EXPORT", None)

    def test_the_default_is_the_install_home_and_an_override_still_wins(self):
        self.environment()
        self.assertEqual(easy_ha_proxy.internal_ca_export_path(), self.home / "internal-ca.crt")
        self.environment(EASY_HA_PROXY_CA_EXPORT=str(self.root / "elsewhere.crt"))
        self.assertEqual(easy_ha_proxy.internal_ca_export_path(), self.root / "elsewhere.crt")

    @unittest.skipUnless(shutil.which("openssl") and os.name == "posix", "needs openssl")
    def test_a_link_at_the_export_is_replaced_not_written_through(self):
        config = self.root / "config"
        config.mkdir()
        (config / "metadata.yml").write_text(
            "admin_domain: ha.example.test\nauthelia_domain: aut.example.test\n"
            "certificate_source: internal\n",
            encoding="utf-8",
        )
        victim = self.root / "victim"
        victim.write_text("keep me\n", encoding="utf-8")
        export = self.home / "internal-ca.crt"
        export.symlink_to(victim)
        self.environment(
            EASY_HA_PROXY_CERT_DIR=str(self.root / "certs"),
            HAPROXY_CA_ROOT_DIR=str(self.root / "authorities"),
        )
        ca_path = easy_ha_proxy.generate_internal_certificate(config)
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")
        self.assertFalse(export.is_symlink())
        self.assertEqual(export.read_bytes(), ca_path.read_bytes())
        self.assertEqual(export.stat().st_mode & 0o777, 0o644)
        self.assertNotIn(b"PRIVATE KEY", export.read_bytes())


class AnsibleWorksInARootOwnedDirectory(unittest.TestCase):
    def test_the_installer_points_ansible_under_the_install_home(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"EASY_HA_PROXY_HOME": home}):
            os.environ.pop("ANSIBLE_LOCAL_TEMP", None)
            environment = easy_ha_proxy.ansible_environment()
        self.assertEqual(environment["ANSIBLE_LOCAL_TEMP"], str(Path(home) / "tmp" / "ansible"))

    def test_an_explicit_choice_is_kept(self):
        with mock.patch.dict(os.environ, {"ANSIBLE_LOCAL_TEMP": "/srv/ansible-tmp"}):
            self.assertEqual(easy_ha_proxy.ansible_environment()["ANSIBLE_LOCAL_TEMP"], "/srv/ansible-tmp")

    def test_no_script_names_a_fixed_directory_in_tmp(self):
        assignment = re.compile(r"ANSIBLE_LOCAL_TEMP=(\S+)")
        allowed = {'"${ansible_temp}"', '"${install_root}/tmp/ansible"'}
        found = []
        for name in SHELL_SCRIPTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("/tmp/easy-ha-proxy-ansible", text, name)
            self.assertNotIn("/tmp/easy-ha-proxy-internal-ca", text, name)
            found += [(name, value) for value in assignment.findall(text)]
        self.assertTrue(found)
        self.assertEqual([item for item in found if item[1] not in allowed], [])

    def test_the_controller_takes_a_private_directory_and_removes_it(self):
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('ansible_temp="$(mktemp -d -t easy-ha-proxy-ansible.XXXXXX)"', text)
        self.assertIn('temporary_directories+=("${ansible_temp}")', text)
        cleanup = re.search(r"^cleanup\(\) \{\n(.*?)^\}", text, re.MULTILINE | re.DOTALL).group(1)
        self.assertIn('for path in "${temporary_directories[@]}"; do\n    rm -rf -- "${path}"', cleanup)


def bundle_with(mode: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in sorted(full_backup.OUTER_REQUIRED_MEMBERS):
            data = b"{}" if name == "manifest.json" else b"x"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@unittest.skipUnless(hasattr(tarfile, "data_filter") and os.name == "posix", "needs tarfile filters")
class TheBundleIsExtractedThroughTheDataFilter(unittest.TestCase):
    def test_setuid_and_world_write_bits_do_not_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle.tar.gz"
            bundle.write_bytes(bundle_with(0o4777))
            destination = root / "work"
            destination.mkdir()
            with mock.patch.object(full_backup, "RESTORE_MIN_FREE_BYTES", 0):
                full_backup.extract_bundle(bundle, destination)
            for name in full_backup.OUTER_REQUIRED_MEMBERS:
                with self.subTest(member=name):
                    mode = (destination / name).stat().st_mode
                    self.assertEqual(mode & 0o4000, 0)
                    self.assertEqual(mode & 0o022, 0)


if __name__ == "__main__":
    unittest.main()
