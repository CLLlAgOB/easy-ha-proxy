"""The former Python daemons go last, and only when no installed unit names them.

The native stage used to remove /usr/local/sbin/*.py before the later stages
rewrote the units. A run from 1.1.x that stopped in between (a certificate
issue, a refused HAProxy configuration) left units starting scripts that were
gone, the update broker's own among them.
"""

from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from jinja2 import Environment
import yaml

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

    def test_the_list_names_the_update_broker(self):
        cleanup = (ADMIN / "native-cleanup.yml").read_text(encoding="utf-8")
        self.assertIn("/usr/local/sbin/easy-ha-proxy-updated.py", cleanup)

    def test_the_changes_map_knows_the_cleanup(self):
        scope = (ROOT / "installer" / "update_scope.py").read_text(encoding="utf-8")
        self.assertIn('tasks/native-cleanup.yml", ("ha-adm-native",)', scope)


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class TheCleanupScript(unittest.TestCase):
    """Runs the task's own script on files and units in a temporary directory."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.units = self.root / "units"
        self.units.mkdir()
        task = yaml.safe_load((ADMIN / "native-cleanup.yml").read_text(encoding="utf-8"))[0]
        self.legacy = [self.root / "easy-ha-proxy-guardd.py", self.root / "easy_ha_proxy_alert_client.py",
                       self.root / "updated"]
        environment = Environment()
        environment.filters["quote"] = shlex.quote  # Ansible's quote filter
        script = environment.from_string(task["ansible.builtin.shell"]).render(
            native_legacy_paths=[str(path) for path in self.legacy])
        self.script = script.replace("/etc/systemd/system /run/systemd/system /usr/lib/systemd/system",
                                     str(self.units))
        self.assertIn(str(self.units), self.script)

    def run_cleanup(self):
        done = subprocess.run(["bash", "-c", self.script], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def place_legacy_files(self):
        self.legacy[0].write_text("daemon\n", encoding="utf-8")
        self.legacy[1].write_text("client\n", encoding="utf-8")
        self.legacy[2].mkdir()

    def test_nothing_goes_while_a_unit_still_starts_a_former_daemon(self):
        self.place_legacy_files()
        (self.units / "easy-ha-proxy-guardd.service").write_text(
            f"[Service]\nExecStart=/usr/bin/python3 {self.legacy[0]}\n", encoding="utf-8")
        self.assertNotIn("removed:", self.run_cleanup())
        # The daemon a unit starts keeps the client it imports, which no unit names.
        self.assertTrue(all(path.exists() for path in self.legacy))

    def test_everything_goes_once_no_unit_names_it(self):
        self.place_legacy_files()
        (self.units / "easy-ha-proxy-guardd.service").write_text(
            "[Service]\nExecStart=/usr/local/sbin/guardd-core serve\n", encoding="utf-8")
        self.assertIn("removed:", self.run_cleanup())
        self.assertFalse(any(path.exists() for path in self.legacy))

    def test_a_cleaned_gateway_reports_no_change(self):
        self.assertEqual(self.run_cleanup(), "")


class NeedrestartKeepsTheUpdateJob(unittest.TestCase):
    """needrestart must not stop the transient unit an OS update runs in."""

    JOB = "easy-ha-proxy-updated-job-[0-9a-f]{12}"

    def test_every_place_that_writes_exclusions_names_the_job_unit(self):
        role = (ROOT / "ansible" / "roles" / "update_packages" / "tasks" / "upgrade.yml").read_text(encoding="utf-8")
        agent = (ROOT / "go" / "agent" / "internal" / "apply" / "stages" / "update_packages.go").read_text(encoding="utf-8")
        os_security = (ROOT / "installer" / "os_security.py").read_text(encoding="utf-8")
        restarts = (ROOT / "installer" / "service_restarts.py").read_text(encoding="utf-8")
        for name, text in (("update_packages", role), ("Go installer", agent), ("os_security", os_security), ("service_restarts", restarts)):
            self.assertIn(self.JOB, text, name)


if __name__ == "__main__":
    unittest.main()
