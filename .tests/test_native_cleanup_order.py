"""The former Python daemons go last, and only when no installed unit names them.

The native stage used to remove /usr/local/sbin/*.py before the later stages
rewrote the units. A run from 1.1.x that stopped in between (a certificate
issue, a refused HAProxy configuration) left units starting scripts that were
gone, the update broker's own among them.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "ansible" / "roles" / "haproxy-admin" / "tasks"
PLAYBOOK = ROOT / "ansible" / "easy-ha-proxy.yml"


def stage_positions():
    text = PLAYBOOK.read_text(encoding="utf-8")
    first_play = text.split("\n- hosts:", 2)[1]
    return {m.group(1): m.start() for m in re.finditer(r"task_stage: ([\w-]+)", first_play)}


class NativeCleanupOrder(unittest.TestCase):
    def test_the_native_stage_removes_no_python_daemon(self):
        native = (ADMIN / "native.yml").read_text(encoding="utf-8")
        self.assertNotIn("/usr/local/sbin/easy-ha-proxy-updated.py", native)
        self.assertNotIn("libguardd_core.so", native)

    def test_the_cleanup_runs_after_every_unit_stage(self):
        positions = stage_positions()
        cleanup = positions["native-cleanup"]
        for stage in ("native", "healthd", "controld", "backupd", "updated", "alertd", "metricsd", "guardd",
                      "start"):
            self.assertLess(positions[stage], cleanup, stage)

    def test_a_file_an_installed_unit_names_is_kept(self):
        cleanup = (ADMIN / "native-cleanup.yml").read_text(encoding="utf-8")
        check = cleanup.index('grep -rqsF -- "$path" /etc/systemd/system')
        self.assertLess(check, cleanup.index('rm -rf -- "$path"'))
        self.assertIn("/usr/local/sbin/easy-ha-proxy-updated.py", cleanup)

    def test_the_changes_map_knows_the_cleanup(self):
        scope = (ROOT / "installer" / "update_scope.py").read_text(encoding="utf-8")
        self.assertIn('tasks/native-cleanup.yml", ("ha-adm-native",)', scope)


class NeedrestartKeepsTheUpdateJob(unittest.TestCase):
    """needrestart must not stop the transient unit an OS update runs in."""

    JOB = "easy-ha-proxy-updated-job-[0-9a-f]{12}"

    def test_every_place_that_writes_exclusions_names_the_job_unit(self):
        role = (ROOT / "ansible" / "roles" / "update_packages" / "tasks" / "main.yml").read_text(encoding="utf-8")
        os_security = (ROOT / "installer" / "os_security.py").read_text(encoding="utf-8")
        restarts = (ROOT / "installer" / "service_restarts.py").read_text(encoding="utf-8")
        for name, text in (("update_packages", role), ("os_security", os_security), ("service_restarts", restarts)):
            self.assertIn(self.JOB, text, name)


if __name__ == "__main__":
    unittest.main()
