"""A preview reads the container's health instead of timing out on it.

"easy-ha-proxy plan" runs the playbook in check mode. The wait for the admin
container read its health with a command, and Ansible does not run commands
in check mode: the status came back empty, never equal to "healthy", so the
preview waited out the whole timeout and then failed, reporting a container
that had been healthy for hours as one that never became healthy.

Reading the status changes nothing, so both reads now run in check mode too.
"""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible/roles/haproxy-admin/tasks/wait_haproxy_admin_healthy.yml"


class TheHealthReadsRunInAPreview(unittest.TestCase):
    def setUp(self):
        text = TASKS.read_text(encoding="utf-8").replace("!unsafe ", "")
        (self.block,) = yaml.safe_load(text)

    def commands(self):
        for task in self.block["block"] + self.block["rescue"]:
            if "ansible.builtin.command" in task:
                yield task

    def test_both_reads_are_exempt_from_check_mode(self):
        tasks = list(self.commands())
        self.assertEqual(len(tasks), 2)
        for task in tasks:
            with self.subTest(task=task["name"]):
                self.assertIs(task.get("check_mode"), False)

    def test_they_only_read(self):
        for task in self.commands():
            with self.subTest(task=task["name"]):
                argv = task["ansible.builtin.command"]["argv"]
                self.assertEqual(argv[:3], ["docker", "container", "inspect"])
                self.assertIs(task.get("changed_when"), False)


if __name__ == "__main__":
    unittest.main()
