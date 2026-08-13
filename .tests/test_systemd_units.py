"""Regression tests for the systemd hardening on the helper daemons.

Sandboxing a daemon is only free until the daemon has to run something that
disagrees with the sandbox. ``haproxy-certd`` runs snap-confined certbot, and
snapd insists on creating a per-user data directory under the home of the
account it runs as -- ``/root`` -- which it reads from the passwd entry and
not from ``$HOME``. ``ProtectHome=yes`` mounts ``/root`` read-only, so certbot
died with

    cannot create snap home dir: mkdir /root/snap: read-only file system

and no certificate could be issued from the web interface at all. The setting
looked entirely reasonable in review; only running it against a real snap
shows the problem, which is what this test stands in for.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
UNIT_DIR = ROOT / "ansible/roles/haproxy-admin/templates"
DAEMON_DIR = ROOT / "ansible/roles/haproxy-admin/files"

# ProtectHome=yes and =read-only both make /root unwritable. Only tmpfs both
# hides the real home directories and leaves somewhere for snapd to write.
BLOCKS_SNAP = ("yes", "true", "on", "read-only")


def units_running_certbot() -> list[Path]:
    """Unit templates whose daemon executes certbot.

    Derived rather than listed, so a second daemon that starts shelling out to
    certbot is covered the day it does.
    """
    units: list[Path] = []
    for daemon in sorted(DAEMON_DIR.glob("*.py")):
        source = daemon.read_text(encoding="utf-8")
        # Naming the binary, not merely mentioning certbot in a comment.
        if "CERTBOT_BIN" not in source:
            continue
        unit = UNIT_DIR / f"{daemon.stem}.service.j2"
        if unit.is_file():
            units.append(unit)
    return units


def protect_home(unit: Path) -> str:
    match = re.search(
        r"^ProtectHome\s*=\s*(\S+)", unit.read_text(encoding="utf-8"), re.MULTILINE
    )
    return match.group(1).strip().lower() if match else ""


class CertbotSandboxTests(unittest.TestCase):
    def test_the_certificate_daemon_is_among_them(self) -> None:
        # If this ever finds nothing, the test below is vacuously true and
        # would keep passing while protecting nothing.
        names = [unit.name for unit in units_running_certbot()]
        self.assertIn("haproxy-certd.service.j2", names, names)

    def test_no_unit_that_runs_certbot_makes_root_unwritable(self) -> None:
        for unit in units_running_certbot():
            with self.subTest(unit=unit.name):
                self.assertNotIn(
                    protect_home(unit),
                    BLOCKS_SNAP,
                    f"{unit.name} runs snap-confined certbot; ProtectHome must "
                    "not make /root read-only or snapd cannot create /root/snap",
                )

    def test_home_directories_are_still_hidden(self) -> None:
        # The fix must not decay into "drop the protection". Removing the
        # setting altogether would also make certbot work, and would also
        # expose every real home directory to this daemon.
        certd = UNIT_DIR / "haproxy-certd.service.j2"
        self.assertEqual(protect_home(certd), "tmpfs")


if __name__ == "__main__":
    unittest.main()
