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
PLAYBOOK = ROOT / "ansible" / "easy-ha-proxy.yml"


def stage_positions():
    text = PLAYBOOK.read_text(encoding="utf-8")
    first_play = text.split("\n- hosts:", 2)[1]
    return {m.group(1): m.start() for m in re.finditer(r"task_stage: ([\w-]+)", first_play)}


class NativeCleanupOrder(unittest.TestCase):
    def test_the_cleanup_runs_after_every_unit_stage(self):
        positions = stage_positions()
        cleanup = positions["native-cleanup"]
        for stage in ("native", "healthd", "controld", "backupd", "updated", "alertd", "metricsd", "guardd",
                      "start"):
            self.assertLess(positions[stage], cleanup, stage)

class NeedrestartKeepsTheUpdateJob(unittest.TestCase):
    """needrestart must not stop the transient unit an OS update runs in."""

    JOB = "easy-ha-proxy-updated-job-[0-9a-f]{12}"

    def test_every_place_that_writes_exclusions_names_the_job_unit(self):
        agent = (ROOT / "go" / "agent" / "internal" / "apply" / "stages" / "update_packages.go").read_text(encoding="utf-8")
        os_security = (ROOT / "installer" / "os_security.py").read_text(encoding="utf-8")
        restarts = (ROOT / "installer" / "service_restarts.py").read_text(encoding="utf-8")
        for name, text in (("installer agent", agent), ("os_security", os_security), ("service_restarts", restarts)):
            self.assertIn(self.JOB, text, name)


if __name__ == "__main__":
    unittest.main()
