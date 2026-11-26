"""Live-restore is configured before apt can restart Docker.

The stage itself runs against a Docker/systemctl stand-in in
go/agent/internal/apply/stages/live_restore_test.go.
"""
from __future__ import annotations

from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class Wiring(unittest.TestCase):
    def test_system_upgrade_configures_continuity_before_apt_can_restart_docker(self):
        tasks = yaml.safe_load((ROOT / "ansible/roles/update_packages/tasks/upgrade.yml").read_text())
        imported = next(i for i, t in enumerate(tasks)
                        if t.get("ansible.builtin.import_role", {}).get("tasks_from") == "live_restore")
        upgrade = next(i for i, t in enumerate(tasks) if t.get("apt", {}).get("upgrade"))
        self.assertLess(imported, upgrade)
        install = yaml.safe_load((ROOT / "ansible/roles/docker/tasks/docker.yml").read_text())
        self.assertTrue(any(t.get("ansible.builtin.import_tasks") == "live_restore.yml" for t in install))


if __name__ == "__main__":
    unittest.main()
