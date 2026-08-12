#!/usr/bin/env python3
"""Regression checks for the Authelia host-time deployment guard."""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
AUTHELIA_ROLE = ROOT / "ansible" / "roles" / "authelia"
INSTALL_TASKS = AUTHELIA_ROLE / "tasks" / "install.yml"
START_TASKS = AUTHELIA_ROLE / "tasks" / "start.yml"
DEFAULTS = AUTHELIA_ROLE / "defaults" / "main.yml"
VAGRANTFILE = ROOT / ".Vagrant" / "Vagrantfile"
HEALTHCHECK_DEFAULTS = (
    ROOT / "ansible" / "roles" / "healthcheck" / "defaults" / "main.yml"
)


class AutheliaTimeSynchronizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = INSTALL_TASKS.read_text(encoding="utf-8")
        cls.start_tasks = START_TASKS.read_text(encoding="utf-8")
        cls.defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        cls.vagrantfile = (
            VAGRANTFILE.read_text(encoding="utf-8")
            if VAGRANTFILE.is_file()
            else None
        )
        cls.healthcheck_defaults = HEALTHCHECK_DEFAULTS.read_text(
            encoding="utf-8"
        )

    def test_guard_runs_for_every_enabled_authelia_installation(self) -> None:
        guard = self.tasks.split(
            "# -------- HOST TIME SYNCHRONIZATION --------", maxsplit=1
        )[1].split(
            "- name: Install Authelia host-side maintenance dependencies",
            maxsplit=1,
        )[0]

        self.assertIn("--property=NTPSynchronized", guard)
        self.assertIn("Verify final host NTP synchronization state", guard)
        self.assertIn(
            "Stop before deploying Authelia with an inaccurate clock", guard
        )

    def test_drifted_clock_is_force_synchronized_provider_agnostically(self) -> None:
        sync = self.tasks.split(
            "- name: Synchronize the host clock when it has drifted", maxsplit=1
        )[1].split(
            "- name: Verify final host NTP synchronization state", maxsplit=1
        )[0]
        # Only runs when the clock is not already synchronized.
        self.assertIn(
            "when: authelia_initial_time_sync.stdout | default('') | trim != 'yes'",
            sync,
        )
        # Requires a provider, then forces synchronization and waits.
        self.assertIn("Require a time synchronization provider", sync)
        self.assertIn("set-ntp", sync)
        self.assertIn("state: restarted", sync)
        self.assertIn("until: authelia_time_sync.stdout | trim == 'yes'", sync)

    def test_no_virtualbox_specific_handling_in_the_role(self) -> None:
        # The host-time logic must not special-case VirtualBox anymore.
        for needle in (
            "vboxadd-service",
            "VirtualBox",
            "VBoxControl",
            "guest_ntp",
            "ansible_virtualization_type",
        ):
            self.assertNotIn(needle, self.tasks)

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

    def test_failures_explain_how_to_recover_time_synchronization(self) -> None:
        self.assertIn("Require a time synchronization provider", self.tasks)
        self.assertIn("timedatectl timesync-status", self.tasks)
        self.assertIn("Stop before deploying Authelia", self.tasks)

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

    def test_failed_start_reports_sanitized_logs_and_time_status(self) -> None:
        self.assertIn(
            "Collect recent Authelia logs when startup fails", self.start_tasks
        )
        self.assertIn(
            "Collect host time status when Authelia startup fails",
            self.start_tasks,
        )
        self.assertIn('- "80"', self.start_tasks)
        self.assertIn("timedatectl status:", self.start_tasks)
        self.assertIn("sanitized docker logs", self.start_tasks)
        self.assertIn("| reject(", self.start_tasks)
        log_collection = self.start_tasks.split(
            "- name: Collect recent Authelia logs when startup fails", maxsplit=1
        )[1].split(
            "- name: Collect host time status when Authelia startup fails",
            maxsplit=1,
        )[0]
        self.assertIn("no_log: true", log_collection)
        for sensitive in ("authorization", "password", "secret", "token"):
            self.assertIn(sensitive, self.start_tasks)


if __name__ == "__main__":
    unittest.main()
