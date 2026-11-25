"""The helper does not count a switched-off Authelia's daemons as a pending update.

Authelia's daemons are installed only where Authelia (and that daemon) is on.
The helper treated every missing unit as "an update is available", so a
gateway without Authelia was told so after every update.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = (ROOT / "easy-ha-proxy-helper.sh").read_text(encoding="utf-8")


def function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", HELPER, re.M | re.S)
    if match is None:
        raise AssertionError(f"helper has no {name}")
    return match.group(0)


@unittest.skipIf(shutil.which("bash") is None, "bash is required")
class UnitExpected(unittest.TestCase):
    def expected(self, unit, vars_text=None, authelia_text=None):
        with tempfile.TemporaryDirectory() as config:
            if vars_text is not None:
                Path(config, "vars.yml").write_text(vars_text, encoding="utf-8")
            if authelia_text is not None:
                Path(config, "authelia.yml").write_text(authelia_text, encoding="utf-8")
            script = "\n".join([function("yaml_scalar"), function("config_switch"), function("unit_expected"),
                                f'config_dir="{config}"', f'unit_expected "{unit}"'])
            return subprocess.run(["bash", "-c", script], check=False).returncode == 0

    def test_authelia_daemons_follow_their_switches(self):
        on = "authelia_enabled: true\n"
        self.assertTrue(self.expected("authelia-usersd.service", on))
        self.assertTrue(self.expected("authelia-bansd.service", on))
        self.assertFalse(self.expected("authelia-usersd.service", "authelia_enabled: false\n"))
        self.assertFalse(self.expected("authelia-usersd.service"))
        self.assertTrue(self.expected("authelia-usersd.service", "root_domain: example.com\n", on))
        # authelia.yml is read after vars.yml and wins, as in the playbook.
        self.assertFalse(self.expected("authelia-usersd.service", on, "authelia_enabled: false\n"))
        self.assertTrue(self.expected("authelia-usersd.service", "authelia_enabled: false\n", on))
        self.assertFalse(self.expected("authelia-bansd.service", on + "authelia_bans_daemon_enabled: false\n"))
        self.assertFalse(self.expected("authelia-configd.service", on + "authelia_configd_enabled: false\n"))
        self.assertTrue(self.expected("authelia-configd.service", on + "authelia_bans_daemon_enabled: false\n"))

    def test_the_other_daemons_are_always_expected(self):
        self.assertTrue(self.expected("haproxy-controld.service"))
        self.assertTrue(self.expected("easy-ha-proxy-guardd.service", "authelia_enabled: false\n"))


if __name__ == "__main__":
    unittest.main()
