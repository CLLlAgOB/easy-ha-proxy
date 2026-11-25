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
AGENT_DIR = ROOT / "go/agent/internal"
# The unit each agent package's daemon runs in.
UNIT_FOR_PACKAGE = {"certd": "haproxy-certd.service.j2"}

# ProtectHome=yes and =read-only both make /root unwritable. Only tmpfs both
# hides the real home directories and leaves somewhere for snapd to write.
BLOCKS_SNAP = ("yes", "true", "on", "read-only")


def units_running_certbot() -> list[Path]:
    """Unit templates whose daemon executes certbot.

    Derived rather than listed, so a second daemon that starts shelling out to
    certbot is covered the day it does.
    """
    units: list[Path] = []
    for package in sorted(p for p in AGENT_DIR.iterdir() if p.is_dir()):
        sources = [f for f in package.glob("*.go") if not f.name.endswith("_test.go")]
        # Reading the binary's setting, not merely mentioning certbot.
        if not any('"CERTBOT_BIN"' in f.read_text(encoding="utf-8") for f in sources):
            continue
        name = UNIT_FOR_PACKAGE.get(package.name)
        if name is None:
            raise AssertionError(f"{package.name} runs certbot; add its unit to UNIT_FOR_PACKAGE")
        units.append(UNIT_DIR / name)
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


def unit_setting(unit: Path, name: str) -> list[str]:
    """Every value of a setting, split on whitespace (systemd list syntax)."""
    text = unit.read_text(encoding="utf-8")
    values: list[str] = []
    for match in re.finditer(rf"^{name}\s*=\s*(.*)$", text, re.MULTILINE):
        values.extend(match.group(1).split())
    return values


class HealthdRunDirectoryTests(unittest.TestCase):
    """ProtectSystem=strict mounts /run read-only except the unit's own
    RuntimeDirectory= entries. healthd keeps the journalctl --cursor-file
    state of its "follow" log mode in /run/haproxy-healthd-cursors, outside
    its socket directory; with only easy-ha-proxy listed, journalctl could
    not save the cursor and the mode answered errors."""

    UNIT = UNIT_DIR / "haproxy-healthd.service.j2"

    @staticmethod
    def cursor_default() -> str:
        go = (AGENT_DIR / "healthd/state.go").read_text(encoding="utf-8")
        match = re.search(r'envOr\("HEALTHD_CURSOR_DIR",\s*"([^"]+)"\)', go)
        if match is None:
            raise AssertionError("cursor directory default not found in healthd")
        return match.group(1)

    def test_the_unit_is_strict(self) -> None:
        # Without strict the directories below need not be listed, and this
        # test would protect nothing.
        self.assertEqual(unit_setting(self.UNIT, "ProtectSystem"), ["strict"])

    def test_cursor_directory_is_a_runtime_directory(self) -> None:
        runtime = {f"/run/{name}" for name in unit_setting(self.UNIT, "RuntimeDirectory")}
        # A leading "-" only makes a missing path non-fatal.
        writable = {p.lstrip("-") for p in unit_setting(self.UNIT, "ReadWritePaths")}
        path = self.cursor_default()
        self.assertTrue(
            path in runtime or path in writable,
            f"healthd writes cursors to {path}, which ProtectSystem=strict "
            f"leaves read-only (RuntimeDirectory: {sorted(runtime)})",
        )

    def test_socket_directory_is_still_listed(self) -> None:
        self.assertIn("easy-ha-proxy", unit_setting(self.UNIT, "RuntimeDirectory"))


if __name__ == "__main__":
    unittest.main()
