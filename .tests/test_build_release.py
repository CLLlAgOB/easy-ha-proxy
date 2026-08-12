from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "build_and_publish_latest.sh"
TEST_BUILD_SCRIPT = ROOT / "build_and_publish_alpha.sh"


FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
if [ "$1 $2 $3" = "buildx imagetools inspect" ]; then
  if [ "${FAKE_INSPECT_ERROR:-0}" = 1 ]; then
    printf '%s\n' 'dial tcp: DNS server failure' >&2
    exit 1
  fi
  case "$4" in
    *:latest) [ "${FAKE_LATEST_EXISTS:-0}" = 1 ] && exit 0 ;;
    *:source-*) [ "${FAKE_SOURCE_EXISTS:-0}" = 1 ] && exit 0 ;;
    *:alpha-*) [ "${FAKE_ALPHA_EXISTS:-0}" = 1 ] && exit 0 ;;
    *) [ "${FAKE_TAG_EXISTS:-0}" = 1 ] && exit 0 ;;
  esac
  printf '%s\n' 'manifest unknown' >&2
  exit 1
fi
if [ "$1 $2" = "buildx build" ]; then
  exit "${FAKE_BUILD_RC:-0}"
fi
exit 0
"""


class BuildReleaseTests(unittest.TestCase):
    def run_build(
        self,
        current_version: str,
        *arguments: str,
        build_rc: int = 0,
        tag_exists: bool = False,
        latest_exists: bool = False,
        source_exists: bool = False,
        alpha_exists: bool = False,
        inspect_error: bool = False,
        script: Path = BUILD_SCRIPT,
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            docker = binary_dir / "docker"
            docker.write_text(FAKE_DOCKER, encoding="utf-8")
            docker.chmod(0o755)
            version_file = root / "IMAGE_VERSION"
            version_file.write_text(current_version + "\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (root / ".dockerignore").write_text(".git\n", encoding="utf-8")
            app_dir = root / "docker" / "app"
            app_dir.mkdir(parents=True)
            (app_dir / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            log_file = root / "docker.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{binary_dir}:{environment['PATH']}",
                    "FAKE_DOCKER_LOG": str(log_file),
                    "FAKE_BUILD_RC": str(build_rc),
                    "FAKE_TAG_EXISTS": "1" if tag_exists else "0",
                    "FAKE_LATEST_EXISTS": "1" if latest_exists else "0",
                    "FAKE_SOURCE_EXISTS": "1" if source_exists else "0",
                    "FAKE_ALPHA_EXISTS": "1" if alpha_exists else "0",
                    "FAKE_INSPECT_ERROR": "1" if inspect_error else "0",
                    "HAPROXY_ADMIN_IMAGE_REPOSITORY": "example/ui",
                    "HAPROXY_ADMIN_VERSION_FILE": str(version_file),
                    "HAPROXY_ADMIN_BUILD_CONTEXT": str(root),
                }
            )
            result = subprocess.run(
                [str(script), *arguments],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            recorded = version_file.read_text(encoding="utf-8").strip()
            docker_log = (
                log_file.read_text(encoding="utf-8") if log_file.exists() else ""
            )
            return result, recorded, docker_log

    def test_success_publishes_numbered_and_latest_tags(self) -> None:
        result, recorded, docker_log = self.run_build("0.0")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, "0.1")
        self.assertIn("--tag example/ui:0.1", docker_log)
        self.assertIn("--tag example/ui:latest", docker_log)
        self.assertIn("--tag example/ui:source-", docker_log)
        self.assertIn("--platform linux/amd64,linux/arm64", docker_log)

    def test_failed_build_does_not_advance_version(self) -> None:
        result, recorded, _ = self.run_build("0.7", build_rc=17)

        self.assertEqual(result.returncode, 17)
        self.assertEqual(recorded, "0.7")

    def test_existing_remote_tag_is_not_overwritten(self) -> None:
        result, recorded, docker_log = self.run_build("0.2", tag_exists=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(recorded, "0.2")
        self.assertIn("Remote tag already exists", result.stderr)
        self.assertNotIn("buildx build", docker_log)

    def test_unchanged_source_does_not_rotate_release(self) -> None:
        result, recorded, docker_log = self.run_build(
            "0.8", source_exists=True
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, "0.8")
        self.assertIn("No Docker source changes", result.stdout)
        self.assertNotIn("buildx build", docker_log)

    def test_registry_error_does_not_rotate_release(self) -> None:
        result, recorded, docker_log = self.run_build(
            "0.8", inspect_error=True
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(recorded, "0.8")
        self.assertIn("Failed to inspect remote tag", result.stderr)
        self.assertNotIn("buildx build", docker_log)

    def test_explicit_version_must_move_forward(self) -> None:
        result, recorded, docker_log = self.run_build(
            "1.4", "--version", "1.4"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(recorded, "1.4")
        self.assertEqual(docker_log, "")

    def test_existing_latest_can_be_adopted_as_first_numbered_release(self) -> None:
        result, recorded, docker_log = self.run_build(
            "0.0", "--adopt-latest", latest_exists=True
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, "0.1")
        self.assertIn(
            "buildx imagetools create --tag example/ui:0.1 example/ui:latest",
            docker_log,
        )
        self.assertNotIn("buildx build", docker_log)

    def test_alpha_build_never_changes_production_version(self) -> None:
        result, recorded, docker_log = self.run_build(
            "0.9", script=TEST_BUILD_SCRIPT
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, "0.9")
        self.assertIn("--tag example/ui:alpha-", docker_log)
        self.assertIn("--tag example/ui:alpha", docker_log)
        self.assertNotIn("example/ui:latest", docker_log)

    def test_unchanged_alpha_build_is_a_no_op(self) -> None:
        result, recorded, docker_log = self.run_build(
            "0.9", alpha_exists=True, script=TEST_BUILD_SCRIPT
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, "0.9")
        self.assertIn("already published", result.stdout)
        self.assertNotIn("buildx build", docker_log)


if __name__ == "__main__":
    unittest.main()
