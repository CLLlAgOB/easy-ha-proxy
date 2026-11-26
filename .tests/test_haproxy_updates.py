"""The HAProxy protection order.

APT metadata freshness, the HAProxy version status and the OS package
isolation are tested in the host agent (tools/apt_metadata_test.go and
updateplan)."""
from __future__ import annotations

from pathlib import Path
import unittest

import yaml


class OsIsolation(unittest.TestCase):
    def test_existing_core_is_protected_before_the_first_package_install_and_status_stays_read_only(self):
        play = yaml.safe_load((Path(__file__).resolve().parents[1] / 'ansible/easy-ha-proxy.yml').read_text(encoding='utf-8'))[0]
        # The pre-task is the installer agent's haproxy/protection part.
        protection = next(task for task in play['pre_tasks'] if task.get('ansible.builtin.import_role', {}).get('tasks_from') == 'protection')
        self.assertEqual(protection['ansible.builtin.import_role']['name'], 'haproxy')
        self.assertEqual(set(protection['tags']), {'ha-install', 'upgrade'})


if __name__ == "__main__":
    unittest.main()
