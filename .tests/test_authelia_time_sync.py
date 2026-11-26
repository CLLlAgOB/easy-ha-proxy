#!/usr/bin/env python3
"""Regression checks for the Authelia host-time deployment guard."""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
AUTHELIA_ROLE = ROOT / "ansible" / "roles" / "authelia"
DEFAULTS = AUTHELIA_ROLE / "defaults" / "main.yml"
VAGRANTFILE = ROOT / ".Vagrant" / "Vagrantfile"
HEALTHCHECK_DEFAULTS = (
    ROOT / "ansible" / "roles" / "healthcheck" / "defaults" / "main.yml"
)


class AutheliaTimeSynchronizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        cls.vagrantfile = (
            VAGRANTFILE.read_text(encoding="utf-8")
            if VAGRANTFILE.is_file()
            else None
        )
        cls.healthcheck_defaults = HEALTHCHECK_DEFAULTS.read_text(
            encoding="utf-8"
        )

    def test_vagrant_uses_guest_ntp_without_stopping_guest_additions(self) -> None:
        if self.vagrantfile is None:
            self.skipTest("the intentionally local .Vagrant/Vagrantfile is absent")

        self.assertIn('"setextradata", :id', self.vagrantfile)
        self.assertIn(
            "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled",
            self.vagrantfile,
        )
        self.assertIn(
            '"/EasyHAProxy/GuestNTP", "systemd-timesyncd-v1"',
            self.vagrantfile,
        )
        self.assertIn('"--flags", "RDONLYGUEST"', self.vagrantfile)
        self.assertIn(
            "vboxadd-service.service.d/easy-ha-proxy-timesync.conf",
            self.vagrantfile,
        )
        self.assertIn("'Conflicts='", self.vagrantfile)
        self.assertIn("'Conflicts=shutdown.target'", self.vagrantfile)
        self.assertIn(
            "systemctl restart vboxadd-service.service", self.vagrantfile
        )
        self.assertIn(
            "systemctl restart systemd-timesyncd.service", self.vagrantfile
        )
        self.assertIn(
            "timedatectl show --property=NTPSynchronized --value",
            self.vagrantfile,
        )
        self.assertNotIn("disable --now vboxadd-service", self.vagrantfile)

    def test_default_timesyncd_recovery_window_is_two_minutes(self) -> None:
        retries = int(self.defaults["authelia_test_time_sync_retries"])
        delay = int(self.defaults["authelia_test_time_sync_delay"])

        self.assertEqual(retries * delay, 120)

    def test_healthcheck_has_no_virtualbox_tracking(self) -> None:
        # Time synchronization is still monitored, but nothing VirtualBox.
        self.assertIn('- name: "systemd-timesyncd.service"', self.healthcheck_defaults)
        for needle in (
            "vboxadd-service",
            "VirtualBox",
            "status_check_virtualbox",
            "authelia_vbox_time_provider",
        ):
            self.assertNotIn(needle, self.healthcheck_defaults)

if __name__ == "__main__":
    unittest.main()
