"""A fresh private checkout must still start the privileged CLI wrapper."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = ("install.sh", "install-local.sh", "install-remote.sh",
               "easy-ha-proxy-helper.sh", "installer/easy-ha-proxy")


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "requires POSIX Git checkout")
class SourceEntrypointTests(unittest.TestCase):
    def test_private_checkout_keeps_launchers_executable_and_cli_can_start(self):
        with tempfile.TemporaryDirectory(prefix="ehp-private-checkout-") as directory:
            root = Path(directory)
            source = root / "source"
            previous_umask = os.umask(0o077)
            try:
                subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(ROOT),
                                "checkout-index", "--prefix=" + str(source) + "/", "--", *ENTRYPOINTS],
                               check=True, capture_output=True, text=True)
            finally:
                os.umask(previous_umask)
            for relative in ENTRYPOINTS:
                self.assertTrue(os.access(source / relative, os.X_OK), relative)
            home = root / "home"
            interpreter = home / "venv/bin/python"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_text("#!/bin/sh\nprintf 'entrypoint-started\\n'\n")
            interpreter.chmod(0o700)
            result = subprocess.run([str(source / "installer/easy-ha-proxy"), "--help"],
                env={**os.environ, "EASY_HA_PROXY_HOME": str(home), "EASY_HA_PROXY_SOURCE_DIR": str(source)},
                check=False, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "entrypoint-started\n")


if __name__ == "__main__":
    unittest.main()
