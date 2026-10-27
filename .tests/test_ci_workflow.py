"""The CI workflow: linters, and the web application image published from the
commit CI has just tested.

The publish step cannot run outside GitHub, so its scripts are taken out of
the workflow and run here against a fake `docker`: the fingerprint must be
the one gateways compute (or they would never pair the image with its
source), an image built from the same web files is reused rather than
rebuilt, main promotes the alpha build when there is one, and a fresh build
carries the labels the update check reads.
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


FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
if [ "$1" = "run" ] && [ -n "$FAKE_BROKEN" ]; then
  exit 1
fi
if [ "$1 $2 $3" = "buildx imagetools inspect" ]; then
  case " $FAKE_EXISTING " in
    *" $4 "*) exit 0 ;;
  esac
  exit 1
fi
exit 0
"""


class TheLinters(unittest.TestCase):
    def test_ruff_and_shellcheck_run(self):
        self.assertIn("ruff check", step("lint", "Ruff")["run"])
        self.assertIn("shellcheck -S warning", step("shell", "ShellCheck")["run"])
        config = (ROOT / "ruff.toml").read_text(encoding="utf-8")
        self.assertIn('select = ["F", "E9"]', config)

    def test_every_script_is_parsed_and_the_js_tests_run(self):
        self.assertIn("node --check", step("javascript", "Parse every script")["run"])
        self.assertIn("node --test .tests/js/", step("javascript", "Behaviour tests")["run"])
        self.assertTrue(list((ROOT / ".tests/js").glob("*.test.js")))

    def test_the_python_matrix_covers_every_supported_host(self):
        versions = JOBS["python"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(versions, ["3.10", "3.11", "3.12", "3.13", "3.14"])

    def test_a_pull_request_builds_the_image_without_publishing_it(self):
        job = JOBS["image-check"]
        self.assertEqual(job["if"], "github.event_name == 'pull_request'")
        # Skipped on every push; the name says so, or a grey mark next to
        # "Publish" reads as "published without building".
        self.assertIn("pull requests", job["name"])
        build = step("image-check", "Build")["run"]
        self.assertIn("docker build", build)
        self.assertNotIn("push", build)
        self.assertIn('import app', step("image-check", "Smoke test")["run"])


class ThePublishing(unittest.TestCase):
    def test_only_a_tested_push_to_a_release_branch_publishes(self):
        image = JOBS["image"]
        self.assertEqual(set(image["needs"]), {"python", "shell", "ansible", "lint", "javascript"})
        self.assertIn("github.event_name == 'push'", image["if"])
        self.assertIn("refs/heads/alpha", image["if"])
        self.assertIn("refs/heads/main", image["if"])

    @unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
    def test_the_fingerprint_is_the_one_gateways_compute(self):
        import update_plan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docker/app").mkdir(parents=True)
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (root / ".dockerignore").write_text("**\n", encoding="utf-8")
            (root / "docker/app/app.py").write_text("VALUE = 1\n", encoding="utf-8")
            environment = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
                           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
            for command in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", str(root), *command], check=True,
                               capture_output=True, env=environment)
            output = root / "output"
            subprocess.run(
                ["bash", "-c", step("image", "Fingerprint the web application")["run"]],
                cwd=root, check=True, capture_output=True,
                env={**environment, "GITHUB_OUTPUT": str(output), "GITHUB_REF_NAME": "alpha"},
            )
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            expected = update_plan._web_tree(root, update_plan.SubprocessRunner())
        self.assertEqual(values["tree"], expected)
        self.assertEqual(values["key"], f"alpha-{expected}")
        self.assertEqual(values["channel"], "alpha")

    def run_publish(self, channel, existing, broken=False):
        tree = "a" * 64
        key = f"source-{tree}" if channel == "latest" else f"alpha-{tree}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            docker = root / "bin/docker"
            docker.write_text(FAKE_DOCKER, encoding="utf-8")
            docker.chmod(0o755)
            log = root / "docker.log"
            summary = root / "summary.md"
            environment = {
                **os.environ,
                "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
                "FAKE_DOCKER_LOG": str(log),
                "FAKE_EXISTING": " ".join(f"example/ui:{tag}" for tag in existing),
                "REPOSITORY": "example/ui", "TREE": tree, "KEY": key, "CHANNEL": channel,
                "GITHUB_SHA": "f" * 40, "GITHUB_SERVER_URL": "https://github.example.test",
                "GITHUB_REPOSITORY": "owner/repo", "GITHUB_STEP_SUMMARY": str(summary),
                "FAKE_BROKEN": "1" if broken else "",
            }
            result = subprocess.run(["bash", "-c", step("image", "Publish")["run"]], cwd=root,
                                    check=not broken, capture_output=True, env=environment)
            if broken:
                self.assertNotEqual(result.returncode, 0)
            return log.read_text(encoding="utf-8"), tree

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_a_fresh_build_is_tried_on_each_platform_before_it_is_pushed(self):
        # A push straight to alpha or main never had the pull-request build.
        log, _ = self.run_publish("alpha", existing=[])
        lines = log.splitlines()
        pushed = next(index for index, line in enumerate(lines) if "--push" in line)
        for platform in ("linux/amd64", "linux/arm64"):
            tried = next(
                index for index, line in enumerate(lines)
                if line.startswith(f"run --rm --platform {platform} ")
            )
            self.assertLess(tried, pushed, platform)
            self.assertIn("pip check", lines[tried])
            self.assertIn("import app", lines[tried])
            self.assertIn(f"buildx build --platform {platform} --load", log)

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_an_image_that_does_not_start_is_never_pushed(self):
        log, _ = self.run_publish("alpha", existing=[], broken=True)
        self.assertIn("run --rm --platform linux/amd64", log)
        self.assertNotIn("--push", log)
        self.assertNotIn("imagetools create", log)

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_a_fresh_build_carries_the_pairing_labels(self):
        log, tree = self.run_publish("alpha", existing=[])
        self.assertIn("buildx build", log)
        self.assertIn(f"--label io.easy-ha-proxy.source-tree={tree}", log)
        self.assertIn("--label org.opencontainers.image.revision=" + "f" * 40, log)
        self.assertIn(f"--tag example/ui:alpha-{tree} --tag example/ui:alpha", log)
        self.assertIn("--platform linux/amd64,linux/arm64", log)

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_the_same_web_files_are_not_built_twice(self):
        tree = "a" * 64
        log, _ = self.run_publish("alpha", existing=[f"alpha-{tree}"])
        self.assertNotIn("buildx build", log)
        self.assertIn(f"imagetools create --tag example/ui:alpha example/ui:alpha-{tree}", log)

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_main_promotes_the_alpha_build(self):
        tree = "a" * 64
        log, _ = self.run_publish("latest", existing=[f"alpha-{tree}"])
        self.assertNotIn("buildx build", log)
        self.assertIn(
            f"imagetools create --tag example/ui:source-{tree} --tag example/ui:latest example/ui:alpha-{tree}",
            log,
        )


if __name__ == "__main__":
    unittest.main()
