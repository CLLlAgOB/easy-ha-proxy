"""The installer keeps its files out of names any local user can take first.

It runs as root. It wrote the public internal CA to
/tmp/easy-ha-proxy-internal-ca.crt and gave Ansible
/tmp/easy-ha-proxy-ansible to work in: fixed names in a directory everyone
may write to. A symlink planted at the first had root write through it;
whoever created the second owned it, and could swap the modules Ansible
writes there before root ran them. (How a restore extracts a backup bundle
is tested with the agent's full-backup command.)
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import easy_ha_proxy


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


class NoFixedDirectoryInTmp(unittest.TestCase):
    def test_no_script_names_a_fixed_directory_in_tmp(self):
        for name in SHELL_SCRIPTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("/tmp/easy-ha-proxy-ansible", text, name)
            self.assertNotIn("/tmp/easy-ha-proxy-internal-ca", text, name)


if __name__ == "__main__":
    unittest.main()
