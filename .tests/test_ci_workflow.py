"""The CI workflow: linters, and the panel and native images published from
the commit CI has just tested.

The fingerprint step cannot run outside GitHub, so its script is taken out of
the workflow and run here: the fingerprint must be the one gateways compute,
or they would never pair the panel image with its source.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]
sys.path.insert(0, str(ROOT / "installer"))


def step(job: str, name: str) -> dict:
    return next(item for item in JOBS[job]["steps"] if item.get("name") == name)


class TheLinters(unittest.TestCase):
    def test_ruff_and_shellcheck_run(self):
        self.assertIn("ruff check", step("lint", "Ruff")["run"])
        self.assertIn("shellcheck -S warning", step("shell", "ShellCheck")["run"])
        config = (ROOT / "ruff.toml").read_text(encoding="utf-8")
        self.assertIn('select = ["F", "E9", "B"]', config)

    def test_every_script_is_parsed_and_the_js_tests_run(self):
        self.assertIn("node --check", step("javascript", "Parse every script")["run"])
        self.assertIn("node --test .tests/js/", step("javascript", "Behaviour tests")["run"])
        self.assertTrue(list((ROOT / ".tests/js").glob("*.test.js")))

    def test_eslint_runs_pinned_over_the_panel_and_its_tests(self):
        run = step("javascript", "ESLint")["run"]
        for pin in ("eslint@9.39.1", "@eslint/js@9.39.1", "globals@16.4.0"):
            self.assertIn(pin, run)
        self.assertIn("--no-save", run)
        self.assertIn("eslint go/panel/web/static/js .tests/js", run)
        self.assertTrue((ROOT / "eslint.config.mjs").is_file())

    def test_the_whole_history_is_searched_for_secrets(self):
        job = JOBS["secrets"]
        checkout = job["steps"][0]
        self.assertEqual(checkout["with"]["fetch-depth"], 0)
        run = step("secrets", "gitleaks")["run"]
        self.assertIn("ghcr.io/gitleaks/gitleaks:v8.28.0", run)
        self.assertIn("gitleaks git /repo", run)
        self.assertIn("--gitleaks-ignore-path /repo/.gitleaksignore", run)
        self.assertIn("--redact", run)
        acknowledged = [
            line for line in (ROOT / ".gitleaksignore").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        # Six fixture lines and one exact public checksum; additions require
        # review. Each is file:rule:line with no commit, so it holds in every
        # commit -- which is why a fixture that moved keeps its old line too
        # (the standby-certificate PEM marker: 1113 in earlier commits, 1145
        # since).
        public_checksum = "ansible/roles/haproxy/defaults/main.yml:generic-api-key:12"
        self.assertEqual(len(acknowledged), 7)
        self.assertIn(public_checksum, acknowledged)
        self.assertTrue(all(len(line.split(":")) == 3 for line in acknowledged))
        fixtures = [line for line in acknowledged if line != public_checksum]
        self.assertEqual(len(fixtures), 6)
        self.assertTrue(all(line.startswith(".tests/") for line in fixtures))

    def test_the_names_come_from_a_secret(self):
        guard = step("secrets", "Names of installations")
        self.assertEqual(guard["env"]["NAME_GUARD_WORDS"], "${{ secrets.NAME_GUARD_WORDS }}")
        self.assertEqual(guard["run"], "python3 .github/scripts/name_guard.py")

    def test_the_python_matrix_covers_every_supported_host(self):
        versions = JOBS["python"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(versions, ["3.10", "3.11", "3.12", "3.13", "3.14"])

    def test_a_pull_request_builds_the_panel_image_without_publishing_it(self):
        build = step("go-panel", "Build Go panel container image (smoke + live healthcheck + size)")["run"]
        self.assertIn("docker build -f go/panel/Dockerfile", build)
        self.assertNotIn("push", build)


class ThePublishing(unittest.TestCase):
    def test_only_a_tested_push_to_a_release_branch_publishes(self):
        every_check = {"python", "shell", "lint", "javascript", "udp-forwarding",
                       "server-state", "secrets"}
        for name in ("go-panel-image", "native-release-image"):
            with self.subTest(job=name):
                job = JOBS[name]
                self.assertLessEqual(every_check - {"javascript"}, set(job["needs"]))
                self.assertIn("github.event_name == 'push'", job["if"])
                self.assertIn("refs/heads/alpha", job["if"])
                self.assertIn("refs/heads/main", job["if"])
        self.assertIn("javascript", JOBS["go-panel-image"]["needs"])

    @unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
    def test_the_fingerprint_is_the_one_gateways_compute(self):
        import update_plan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "go/panel/web/templates").mkdir(parents=True)
            (root / "VERSION").write_text("1.2.0\n", encoding="utf-8")
            (root / "go/panel/main.go").write_text("package main\n", encoding="utf-8")
            (root / "go/panel/web/templates/base.html").write_text("<html></html>\n", encoding="utf-8")
            (root / "installer").mkdir()
            (root / "installer/other.py").write_text("VALUE = 1\n", encoding="utf-8")
            environment = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
                           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
            for command in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", str(root), *command], check=True,
                               capture_output=True, env=environment)
            output = root / "output"
            subprocess.run(
                ["bash", "-c", step("go-panel-image", "Fingerprint the Go web panel")["run"]],
                cwd=root, check=True, capture_output=True,
                env={**environment, "GITHUB_OUTPUT": str(output), "GITHUB_REF_NAME": "alpha"},
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            expected = update_plan._web_tree(root, update_plan.SubprocessRunner())
        self.assertEqual(values["tree"], expected)
        self.assertEqual(values["key"], f"go-alpha-{expected}")
        self.assertEqual(values["channel"], "go-alpha")

    def test_the_broker_fingerprints_the_same_inputs(self):
        import update_plan

        config = (ROOT / "go/agent/internal/updated/config.go").read_text(encoding="utf-8")
        listed = config.split("goWebTreeInputs = []string{", 1)[1].split("}", 1)[0]
        self.assertEqual(tuple(item.strip().strip('"') for item in listed.split(",")),
                         update_plan.GO_WEB_TREE_INPUTS)


class TheRunners(unittest.TestCase):
    """Every job names the runner image it was written for.

    ubuntu-latest moves to a new release on GitHub's schedule, not this
    project's: jobs that install packages or rely on the runner's tools would
    change their operating system unannounced. The gateways run Ubuntu 24.04,
    and so do the runners; a move is a decision made in this file.
    """

    def test_no_job_follows_ubuntu_latest(self):
        import yaml

        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            jobs = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("jobs") or {}
            for name, job in jobs.items():
                runner = str(job.get("runs-on", ""))
                with self.subTest(workflow=path.name, job=name):
                    self.assertNotIn("latest", runner)

    def test_all_actions_are_pinned_to_full_commit_shas(self):
        import re

        sha_pin = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            jobs = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("jobs") or {}
            for job_name, job in jobs.items():
                for step_def in job.get("steps") or []:
                    uses = step_def.get("uses")
                    if not uses or uses.startswith("./"):
                        continue
                    with self.subTest(workflow=path.name, job=job_name, uses=uses):
                        self.assertRegex(uses, sha_pin)


if __name__ == "__main__":
    unittest.main()
