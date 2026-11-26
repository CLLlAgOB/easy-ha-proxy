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
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]


def step(job: str, name: str) -> dict:
    return next(item for item in JOBS[job]["steps"] if item.get("name") == name)


def go_web_tree_inputs(relative: str) -> tuple[str, ...]:
    """The panel's build inputs as a Go file lists them (goWebTreeInputs)."""
    source = (ROOT / relative).read_text(encoding="utf-8")
    listed = source.split("goWebTreeInputs = []string{", 1)[1].split("}", 1)[0]
    return tuple(item.strip().strip('"') for item in listed.split(","))


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

    def test_one_python_runs_the_contract_tests(self):
        # No gateway runs Python, so no host interpreter has to be covered.
        versions = JOBS["python"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(versions, ["3.12"])
        steps = "\n".join(item.get("run", "") for item in JOBS["python"]["steps"])
        self.assertIn("pip install -r .tests/requirements.txt", steps)
        self.assertNotIn("installer", steps)

    def test_the_server_state_smoke_runs_the_agent_built_here(self):
        build = step("server-state", "Build the agent")["run"]
        self.assertIn("go build", build)
        steps = "\n".join(item.get("run", "") for item in JOBS["server-state"]["steps"])
        self.assertIn("--normalizer /usr/local/sbin/easy-ha-proxy-agent", steps)

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

    def test_the_agent_release_holds_what_installers_fetch(self):
        job = JOBS["agent-release-assets"]
        # Published only from what the image is published from.
        self.assertEqual(set(job["needs"]), set(JOBS["native-release-image"]["needs"]))
        self.assertEqual(job["if"], JOBS["native-release-image"]["if"])
        self.assertEqual(job["permissions"], {"contents": "write"})
        self.assertEqual(job["env"]["RELEASE_TAG"], "agent-builds")
        upload = step("agent-release-assets", "Upload this commit's agent")["run"]
        # The names installer/agent-fetch.sh asks for.
        self.assertIn('name="easy-ha-proxy-agent-${GITHUB_SHA}-linux-${arch}"', upload)
        self.assertIn('sha256sum "${name}" > "${name}.sha256"', upload)
        fetch = (ROOT / "installer/agent-fetch.sh").read_text(encoding="utf-8")
        self.assertIn("releases/download/agent-builds", fetch)
        self.assertIn('name="easy-ha-proxy-agent-${revision}-linux-${arch}"', fetch)
        prune = step("agent-release-assets", "Keep the newest builds")
        self.assertTrue(prune["continue-on-error"])
        self.assertIn("grep -vxF -f tagged", prune["run"])

    @unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
    def test_the_fingerprint_is_the_one_gateways_compute(self):
        import hashlib

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
            # What the update checker on a gateway computes (updateplan.webTree).
            listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "--full-tree", "HEAD", "--",
                                      *go_web_tree_inputs("go/agent/internal/updateplan/source.go")],
                                     check=True, capture_output=True, text=True).stdout
            expected = hashlib.sha256(listing.encode("utf-8")).hexdigest()
        self.assertEqual(values["tree"], expected)
        self.assertEqual(values["key"], f"go-alpha-{expected}")
        self.assertEqual(values["channel"], "go-alpha")

    def test_the_broker_fingerprints_the_same_inputs(self):
        # The footer (the broker) and the update checker read the same paths.
        self.assertEqual(go_web_tree_inputs("go/agent/internal/updated/config.go"),
                         go_web_tree_inputs("go/agent/internal/updateplan/source.go"))
        self.assertEqual(go_web_tree_inputs("go/agent/internal/updateplan/source.go"), ("VERSION", "go/panel"))


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
