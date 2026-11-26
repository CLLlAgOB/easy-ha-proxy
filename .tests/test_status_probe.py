"""The status check's one-pass probe (roles/healthcheck/files/status_probe.py)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "ansible/roles/healthcheck/files/status_probe.py"
TASKS = ROOT / "ansible/roles/healthcheck/tasks/status.yml"


def fake(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


@unittest.skipIf(sys.platform == "win32", "shell stand-ins for the host tools")
class StatusProbeTests(unittest.TestCase):
    def probe(self, spec):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            # "flaky" turns active on its second probe, as a unit restarted
            # moments before the check does.
            fake(root, "systemctl", f'echo "$*" >> {calls}\n'
                 'case "$2" in\n'
                 '  ok) echo active;;\n'
                 f'  flaky) if grep -q "is-active flaky" {calls}.seen 2>/dev/null; then echo active; '
                 f'else echo "is-active flaky" >> {calls}.seen; echo activating; exit 3; fi;;\n'
                 '  *) echo inactive; exit 3;;\n'
                 'esac\n')
            fake(root, "dpkg-query", 'case "$3" in haproxy) echo 3.2.1-1;; *) '
                 'echo "dpkg-query: no packages found matching $3" >&2; exit 1;; esac\n')
            fake(root, "apt-cache", 'echo "haproxy:"; echo "  Installed: 3.2.1-1"; echo "  Candidate: 3.2.2-1"\n'
                 'echo "ipset:"; echo "  Installed: (none)"; echo "  Candidate: 7.15-1"\n')
            fake(root, "docker", 'echo \'[{"Name": "/authelia", "State": {"Status": "running", '
                 '"Health": {"Status": "healthy"}}}]\'; echo "Error: No such container: redis" >&2; exit 1\n')
            fake(root, "snap", 'if [ "$2" = certbot ]; then echo "Name Version"; echo "certbot 5.1.0"; '
                 'else echo "error: no matching snaps installed" >&2; exit 1; fi\n')
            env = dict(os.environ, PATH=f"{root}{os.pathsep}{os.environ['PATH']}")
            result = subprocess.run([sys.executable, str(PROBE), json.dumps(spec)], env=env,
                                    capture_output=True, text=True, timeout=30, check=True)
            return json.loads(result.stdout), calls.read_text().splitlines()

    def test_every_part_has_the_shape_the_loops_registered(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("v1\n")
        self.addCleanup(os.unlink, handle.name)
        report, calls = self.probe({
            "units": [{"name": "ok", "label": "OK"}, {"name": "flaky"}, {"name": "gone"}],
            "retries": 2, "delay": 0,
            "daemon_files": [{"name": "ok", "version_file": handle.name}],
            "artifacts": [{"name": "missing", "path": "/nonexistent/file"}],
            "apt": ["haproxy", "ipset"],
            "docker": [{"name": "authelia"}, {"name": "redis"}],
            "snaps": ["certbot", "lego"],
        })

        units = {r["item"]["name"]: (r["rc"], r["stdout"]) for r in report["systemd"]["results"]}
        self.assertEqual(units, {"ok": (0, "active"), "flaky": (0, "active"), "gone": (3, "inactive")})
        self.assertEqual(report["systemd"]["results"][0]["item"], {"name": "ok", "label": "OK"})
        # Only units not yet active are asked again, at most `retries` times.
        self.assertEqual(calls.count("is-active ok"), 1)
        self.assertEqual(calls.count("is-active flaky"), 2)
        self.assertEqual(calls.count("is-active gone"), 3)

        self.assertEqual(report["daemon_versions"]["results"][0]["stat"]["checksum"],
                         hashlib.sha256(b"v1\n").hexdigest())
        self.assertEqual(report["artifacts"]["results"][0]["stat"], {"exists": False})

        installed = report["apt_installed"]["results"]
        self.assertEqual([(r["item"], r["rc"], r["stdout"]) for r in installed],
                         [("haproxy", 0, "3.2.1-1"), ("ipset", 1, "")])
        policy = {r["item"]: r["stdout"] for r in report["apt_candidate"]["results"]}
        self.assertIn("Candidate: 3.2.2-1", policy["haproxy"])
        self.assertNotIn("7.15-1", policy["haproxy"])
        self.assertIn("Candidate: 7.15-1", policy["ipset"])

        containers = {r["item"]["name"]: r for r in report["docker"]["results"]}
        self.assertTrue(containers["authelia"]["exists"])
        self.assertEqual(containers["authelia"]["container"]["State"]["Health"]["Status"], "healthy")
        self.assertFalse(containers["redis"]["exists"])

        snaps = {r["item"]: r for r in report["snaps"]["results"]}
        self.assertEqual((snaps["certbot"]["rc"], snaps["certbot"]["stdout_lines"][-1]), (0, "certbot 5.1.0"))
        self.assertNotEqual(snaps["lego"]["rc"], 0)

    def test_the_role_no_longer_loops_over_hosts_tools(self):
        tasks = TASKS.read_text()
        self.assertIn("status_probe.py", tasks)
        for module in ("community.docker.docker_container_info", "cmd: \"systemctl is-active",
                       "- apt-cache", "- dpkg-query\n      - --show\n      - \"--showformat=${Version}\""):
            self.assertNotIn(module, tasks)


if __name__ == "__main__":
    unittest.main()
