"""Regression tests for the local GeoIP database and derived HAProxy ACL."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentAssertions(unittest.TestCase):


    def test_geoip_timer_and_oneshot_have_correct_monitoring_semantics(self) -> None:
        healthd_config = (
            ROOT / "ansible/roles/haproxy-admin/templates/healthd.json.j2"
        ).read_text(encoding="utf-8")
        healthcheck_defaults = (
            ROOT / "ansible/roles/healthcheck/defaults/main.yml"
        ).read_text(encoding="utf-8")
        health_javascript = (
            ROOT / "go/panel/web/static/js/health.js"
        ).read_text(encoding="utf-8")
        healthcheck_tasks = (
            ROOT / "ansible/roles/healthcheck/tasks/status.yml"
        ).read_text(encoding="utf-8")

        for unit in (
            "easy-ha-proxy-geoip-update.service",
            "easy-ha-proxy-geoip-update.timer",
        ):
            self.assertIn(unit, healthd_config)
        self.assertIn(
            'timer: "easy-ha-proxy-geoip-update.timer"', healthcheck_defaults
        )
        self.assertIn(
            'service: "easy-ha-proxy-geoip-update.service"', healthcheck_defaults
        )
        self.assertIn("unit.healthy", health_javascript)
        self.assertIn("^ActiveState=failed$", healthcheck_tasks)
        self.assertIn("^Result=(?!(?:success)?$).+$", healthcheck_tasks)
        self.assertIn("status_check_systemd_jobs_never_run", healthcheck_tasks)


if __name__ == "__main__":
    unittest.main()
