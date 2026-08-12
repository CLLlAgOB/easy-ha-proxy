"""Regression tests for controlled reboot handling after OS upgrades."""

from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import easy_ha_proxy


ROOT = Path(__file__).resolve().parents[1]


class RebootPromptTests(unittest.TestCase):
    def test_upgrade_playbook_offers_reboot_only_after_real_apply(self) -> None:
        with (
            mock.patch("easy_ha_proxy.playbook_command", return_value=["ansible-playbook"]),
            mock.patch("easy_ha_proxy.ansible_environment", return_value={}),
            mock.patch("easy_ha_proxy.run"),
            mock.patch("easy_ha_proxy.offer_pending_reboot") as offer,
        ):
            easy_ha_proxy.run_playbook("upgrade,status")
            offer.assert_called_once_with()

            offer.reset_mock()
            easy_ha_proxy.run_playbook("status")
            offer.assert_not_called()

            easy_ha_proxy.run_playbook("upgrade,status", check_mode=True)
            offer.assert_not_called()

    def test_reboot_prompt_defaults_to_deferred(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("easy_ha_proxy.reboot_required", return_value=True),
            mock.patch("easy_ha_proxy.sys.stdin.isatty", return_value=True),
            mock.patch("easy_ha_proxy.prompt_bool", return_value=False) as prompt,
            mock.patch("easy_ha_proxy.schedule_server_reboot") as schedule,
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("sys.stdout", output),
        ):
            os.environ.pop("EASY_HA_PROXY_REBOOT_DECISION", None)
            accepted = easy_ha_proxy.offer_pending_reboot()

        self.assertFalse(accepted)
        prompt.assert_called_once_with("Reboot the server now", default=False)
        schedule.assert_not_called()
        self.assertIn("Reboot deferred", output.getvalue())

    def test_noninteractive_reboot_is_deferred_unless_explicit(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("easy_ha_proxy.reboot_required", return_value=True),
            mock.patch("easy_ha_proxy.sys.stdin.isatty", return_value=False),
            mock.patch("easy_ha_proxy.schedule_server_reboot") as schedule,
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch("sys.stdout", output),
        ):
            os.environ.pop("EASY_HA_PROXY_REBOOT_DECISION", None)
            self.assertFalse(easy_ha_proxy.offer_pending_reboot())
            schedule.assert_not_called()

            with mock.patch.dict(
                os.environ,
                {"EASY_HA_PROXY_REBOOT_DECISION": "yes"},
            ):
                self.assertTrue(easy_ha_proxy.offer_pending_reboot())
            schedule.assert_called_once_with()

    def test_schedules_delayed_systemd_reboot_and_writes_marker(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "run/easy-ha-proxy/reboot-scheduled"

            def executable(name: str) -> str:
                return f"/usr/bin/{name}"

            with (
                mock.patch.object(easy_ha_proxy, "REBOOT_SCHEDULE_MARKER", marker),
                mock.patch("easy_ha_proxy.shutil.which", side_effect=executable),
                mock.patch("easy_ha_proxy.run") as run,
                mock.patch("sys.stdout", output),
            ):
                easy_ha_proxy.schedule_server_reboot()

            command = run.call_args.args[0]
            self.assertEqual(command[0], "/usr/bin/systemd-run")
            self.assertRegex(
                next(item for item in command if item.startswith("--unit=")),
                r"^--unit=easy-ha-proxy-reboot-[0-9]{14}-[0-9]+-[0-9a-f]{8}$",
            )
            self.assertIn("--on-active=30s", command)
            self.assertEqual(command[-2:], ["/usr/bin/systemctl", "reboot"])
            self.assertTrue(marker.is_file())
            self.assertIn("EASY_HA_PROXY_REBOOT_SCHEDULED=1", output.getvalue())

    def test_stale_schedule_marker_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "run/easy-ha-proxy/reboot-scheduled"
            marker.parent.mkdir(parents=True)
            marker.write_text(
                "unit=easy-ha-proxy-reboot-20260715090000-123-deadbeef\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(easy_ha_proxy, "REBOOT_SCHEDULE_MARKER", marker),
                mock.patch("easy_ha_proxy.shutil.which", return_value="/usr/bin/systemctl"),
                mock.patch(
                    "easy_ha_proxy.subprocess.run",
                    return_value=mock.Mock(returncode=3),
                ),
            ):
                self.assertFalse(easy_ha_proxy.reboot_schedule_is_active())

            self.assertFalse(marker.exists())

    def test_failed_systemd_schedule_removes_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "run/easy-ha-proxy/reboot-scheduled"

            def fail_after_marker(_command: list[str]) -> None:
                self.assertTrue(marker.exists())
                raise RuntimeError("systemd-run failed")

            with (
                mock.patch.object(easy_ha_proxy, "REBOOT_SCHEDULE_MARKER", marker),
                mock.patch(
                    "easy_ha_proxy.shutil.which",
                    side_effect=lambda name: f"/usr/bin/{name}",
                ),
                mock.patch("easy_ha_proxy.run", side_effect=fail_after_marker),
            ):
                with self.assertRaisesRegex(RuntimeError, "systemd-run failed"):
                    easy_ha_proxy.schedule_server_reboot()

            self.assertFalse(marker.exists())


class RebootIntegrationTests(unittest.TestCase):
    def test_local_ansible_connection_never_uses_reboot_module(self) -> None:
        tasks = (
            ROOT / "ansible/roles/update_packages/tasks/main.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("easy_ha_proxy_reboot_after_upgrade", tasks)
        self.assertIn("(ansible_connection | default('smart')) != 'local'", tasks)
        self.assertIn("Explain why a local Ansible connection is not rebooted", tasks)
        self.assertNotIn("Reboot if kernel is updated", tasks)

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
