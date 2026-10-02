"""A pasted key must become a file OpenSSH will open.

An operator pinned a host key, saved an SFTP destination, pressed Test and
got:

    Load key "/etc/easy-ha-proxy/backup-destinations/offsite.key":
    error in libcrypto

The key was not corrupt. It was 398 bytes, header and footer intact, line
widths 35/70/70/70/70/44/33, clean base64, no carriage returns -- and no
terminating newline, because the browser sends a trimmed textarea and the
daemon wrote the value verbatim. Copying the same bytes with one newline
appended made ssh-keygen read it immediately. The line directly below it in
the daemon, the one that stores the host key, had been appending that
newline all along.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DAEMON = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-backupd.py"
)


def load():
    spec = importlib.util.spec_from_file_location("backupd_keys", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules["backupd_keys"] = module
    spec.loader.exec_module(module)
    return module


backupd = load()

# A real, throwaway ed25519 key, generated for this test and used nowhere.
# Its shape is the point: 70-character body lines and a short final one.
KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
ZWQyNTUxOQAAACDPRhV/dQ3xY6Sk8h5oXQ1cQK0nJ0YvXQnJHV3nJ4pQOgAAAJgxk0lLMZNJ
SwAAAAtzc2gtZWQyNTUxOQAAACDPRhV/dQ3xY6Sk8h5oXQ1cQK0nJ0YvXQnJHV3nJ4pQOg
AAAEDMxYQZ8mVQF3Jx0OQqzYRZ8mVQF3Jx0OQqzYRZ8mVQF89GFX91DfFjpKTyHmhdDVxA
rScnRi9dCckdXecnilA6AAAAEXRlc3RAZXhhbXBsZS50ZXN0AQIDBA==
-----END OPENSSH PRIVATE KEY-----"""


class NormalisationTests(unittest.TestCase):
    def test_a_trimmed_paste_gains_its_terminator(self):
        # Exactly what the browser sends: no newline after the footer.
        result = backupd.normalize_private_key(KEY)
        self.assertTrue(result.endswith(b"-----END OPENSSH PRIVATE KEY-----\n"))

    def test_a_key_that_already_ends_properly_is_left_alone(self):
        self.assertEqual(
            backupd.normalize_private_key(KEY + "\n"),
            backupd.normalize_private_key(KEY),
        )

    def test_a_pile_of_trailing_newlines_becomes_one(self):
        self.assertEqual(
            backupd.normalize_private_key(KEY + "\n\n\n\n"),
            backupd.normalize_private_key(KEY),
        )

    def test_windows_line_endings_are_flattened(self):
        # A key copied out of a Windows terminal, which is where this
        # operator's key came from.
        crlf = KEY.replace("\n", "\r\n")
        result = backupd.normalize_private_key(crlf)
        self.assertNotIn(b"\r", result)
        self.assertEqual(result, backupd.normalize_private_key(KEY))

    def test_old_mac_line_endings_too(self):
        self.assertEqual(
            backupd.normalize_private_key(KEY.replace("\n", "\r")),
            backupd.normalize_private_key(KEY),
        )

    def test_the_body_itself_is_not_touched(self):
        result = backupd.normalize_private_key(KEY).decode()
        self.assertEqual(result.splitlines(), KEY.splitlines())

    def test_the_result_is_bytes_ready_for_write_private(self):
        self.assertIsInstance(backupd.normalize_private_key(KEY), bytes)


class CallSiteTests(unittest.TestCase):
    def setUp(self):
        self.source = DAEMON.read_text(encoding="utf-8")

    def test_the_stored_key_goes_through_normalisation(self):
        self.assertIn(
            "write_private(destination_key_path(name), normalize_private_key(key))",
            self.source,
        )

    def test_the_host_key_still_gets_its_newline(self):
        # The line that was right all along; it must stay right.
        self.assertIn('(host_key + "\\n").encode("utf-8")', self.source)


@unittest.skipUnless(
    subprocess.run(
        ["sh", "-c", "command -v ssh-keygen"], capture_output=True
    ).returncode
    == 0,
    "ssh-keygen is not installed",
)
class OpenSshTests(unittest.TestCase):
    """The only opinion that counts is OpenSSH's."""

    def key_pair(self):
        """A genuine key, so the parser is exercised rather than a fixture."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "probe", "-f", str(path)],
            capture_output=True,
            check=True,
        )
        return path

    def reads(self, path: Path) -> tuple[bool, str]:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0, (result.stdout or result.stderr).strip()

    def test_a_trimmed_key_is_rejected_and_the_normalised_one_is_not(self):
        original = self.key_pair()
        material = original.read_text(encoding="utf-8")

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        trimmed = Path(directory.name) / "trimmed"
        trimmed.write_text(material.strip(), encoding="utf-8")
        trimmed.chmod(0o600)

        fixed = Path(directory.name) / "fixed"
        fixed.write_bytes(backupd.normalize_private_key(material.strip()))
        fixed.chmod(0o600)

        trimmed_ok, trimmed_says = self.reads(trimmed)
        fixed_ok, fixed_says = self.reads(fixed)

        # The production symptom, reproduced.
        self.assertFalse(trimmed_ok, f"a trimmed key was accepted: {trimmed_says}")
        self.assertIn("libcrypto", trimmed_says)

        self.assertTrue(fixed_ok, f"the normalised key was refused: {fixed_says}")
        self.assertTrue(fixed_says.startswith("ssh-ed25519 "))

    def test_a_crlf_key_is_also_repaired(self):
        original = self.key_pair()
        material = original.read_text(encoding="utf-8").replace("\n", "\r\n")

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        fixed = Path(directory.name) / "fixed"
        fixed.write_bytes(backupd.normalize_private_key(material))
        fixed.chmod(0o600)

        ok, says = self.reads(fixed)
        self.assertTrue(ok, f"a CRLF key was not repaired: {says}")


if __name__ == "__main__":
    unittest.main()
