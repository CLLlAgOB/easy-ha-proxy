"""Status lists the alert engine and the backup schedule (F26).

From the 30 October review: the default inventory had backupd, updated,
metricsd and guardd, but not easy-ha-proxy-alertd.service nor the backup
schedule (easy-ha-proxy-backup.service/.timer), and the haproxy-* /
authelia-* globs do not reach them. The alerts badge could say the engine
was down while Status had no row, journal or restart for it.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ansible/roles/haproxy-admin/templates"


def inventory(**variables):
    environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
    environment.filters["bool"] = lambda value: str(value).lower() in ("1", "true", "yes", "on")
    rendered = environment.get_template("healthd.json.j2").render(**variables)
    return json.loads(rendered)["systemd"]["units"]


def healthd():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-healthd.py"
    spec = importlib.util.spec_from_file_location("healthd_status_units", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TheInventory(unittest.TestCase):
    def test_the_alert_engine_and_the_backup_schedule_are_listed(self):
        units = inventory()
        for unit in ("easy-ha-proxy-alertd.service", "easy-ha-proxy-backup.service",
                     "easy-ha-proxy-backup.timer"):
            self.assertIn(unit, units)

    def test_a_disabled_schedule_is_not_shown_as_a_failure(self):
        units = inventory(backup_schedule_enabled=False)
        self.assertNotIn("easy-ha-proxy-backup.timer", units)
        self.assertIn("easy-ha-proxy-alertd.service", units)


@unittest.skipIf(sys.platform == "win32", "healthd needs POSIX modules")
class TheActions(unittest.TestCase):
    def test_the_backup_job_is_shown_but_never_started_from_status(self):
        module = healthd()
        self.assertEqual(module._control_allowed_actions("systemd", "easy-ha-proxy-backup.service"), ())
        self.assertIn("restart", module._control_allowed_actions("systemd", "easy-ha-proxy-backup.timer"))
        self.assertIn("restart", module._control_allowed_actions("systemd", "easy-ha-proxy-alertd.service"))


if __name__ == "__main__":
    unittest.main()
