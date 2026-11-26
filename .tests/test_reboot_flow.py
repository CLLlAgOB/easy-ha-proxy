"""Regression tests for shell launcher reboot handling.

Unit tests for CLI reboot scheduling and markers now live in
go/agent/internal/cli/lock_reboot_test.go.
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RebootIntegrationTests(unittest.TestCase):
    def test_helper_exits_cleanly_and_remote_launcher_waits_for_reboot(self) -> None:
        helper = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")
        remote = (ROOT / "install-remote.sh").read_text(encoding="utf-8")
        launcher = (ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertIn('reboot_schedule_marker="/run/easy-ha-proxy/reboot-scheduled"', helper)
        self.assertIn('8) perform_action reboot', helper)
        self.assertIn(
            'if [[ "${status}" -eq 0 && -f "${reboot_schedule_marker}" ]]',
            helper,
        )
        self.assertIn('if [[ "${action_name}" == "os" ]]', helper)
        self.assertIn('if [[ "${has_full}" == true ]]', helper)
        self.assertIn("run_smart_managed_action os", helper)
        self.assertIn("wait_for_remote_reboot()", remote)
        self.assertIn("prepare_remote_reboot_monitoring()", remote)
        self.assertIn("prepare_remote_reboot_monitoring\n", remote)
        self.assertIn("/proc/sys/kernel/random/boot_id", remote)
        self.assertIn('"${current_boot_id}" != "${reboot_monitor_boot_id}"', remote)
        self.assertIn("EASY_HA_PROXY_REBOOT_SCHEDULED", remote)
        self.assertIn("reboot|configure|language", remote)
        self.assertIn("update-containers|reboot|configure", launcher)


if __name__ == "__main__":
    unittest.main()
