"""Focused tests for the read-only machine-readable update checker."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import update_plan
from update_plan import CommandResult, DAEMON_ARTIFACTS, build_update_plan


LOCAL_REVISION = "1" * 40
REMOTE_REVISION = "2" * 40
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class FakeRunner:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def run(self, argv, *, timeout):
        command = tuple(argv)
        self.calls.append((command, timeout))
        return self.handler(command)


def prepare_source(root: Path) -> Path:
    source = root / "source"
    (source / ".git").mkdir(parents=True)
    (source / "ansible").mkdir(exist_ok=True)
    (source / "ansible/easy-ha-proxy.yml").write_text(
        "---\n- hosts: easy_ha_proxy\n", encoding="utf-8"
    )
    for _, _, _, relative in DAEMON_ARTIFACTS:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"managed:{relative}\n", encoding="utf-8")
    return source


def prepare_installed_daemons(root: Path, source: Path):
    installed = root / "installed"
    for _, _, absolute, relative in DAEMON_ARTIFACTS:
        target = installed / absolute.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / relative).read_bytes())
    return lambda absolute: installed / absolute.relative_to("/")


def git_handler(command: tuple[str, ...]) -> CommandResult:
    if command[-2:] == ("rev-parse", "HEAD"):
        return CommandResult(0, LOCAL_REVISION + "\n")
    if "status" in command:
        return CommandResult(0, "")
    if command[-3:] == ("remote", "get-url", "origin"):
        return CommandResult(0, "https://example.test/easy-ha-proxy.git\n")
    if command[:3] == ("git", "ls-remote", "--heads"):
        return CommandResult(0, REMOTE_REVISION + "\trefs/heads/main\n")
    if command[:2] == ("git", "clone"):
        return CommandResult(1, stderr="candidate unavailable")
    if command == ("apt-get", "-s", "upgrade"):
        return CommandResult(0, "")
    raise AssertionError(f"Unexpected command: {command!r}")


class UpdatePlanTests(unittest.TestCase):
    def test_local_source_channel_never_contacts_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                raise AssertionError(f"Local channel ran unexpected command: {command!r}")

            runner = FakeRunner(handler)
            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="local",
                runner=runner,
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "blocked")
        self.assertEqual(
            components["all"]["details"]["reason"], "local-source-channel"
        )
        self.assertEqual(components["services"]["state"], "blocked")
        self.assertEqual(components["daemons"]["state"], "current")
        self.assertFalse(any(call[0][0] == "git" for call in runner.calls))

    def test_available_daemons_summary_names_the_outdated_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            artifact_id, label, installed_path, _relative = DAEMON_ARTIFACTS[0]
            # Make exactly one installed daemon differ from the managed source.
            installed(installed_path).write_text("stale\n", encoding="utf-8")

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                raise AssertionError(f"unexpected command: {command!r}")

            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="local",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        daemons = {item["id"]: item for item in plan["components"]}["daemons"]
        self.assertEqual(daemons["state"], "available")
        # The summary names the candidate rather than dumping every digest.
        self.assertIn(label, daemons["summary"])
        self.assertNotIn("digest", daemons["summary"].lower())
        outdated = [
            item for item in daemons["details"]["artifacts"]
            if item["state"] == "available"
        ]
        self.assertEqual([item["id"] for item in outdated], [artifact_id])

    def test_git_check_ignores_file_mode_only_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            runner = FakeRunner(git_handler)
            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=runner,
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "blocked")
        self.assertEqual(
            components["all"]["details"]["reason"],
            "container-candidate-unavailable",
        )
        self.assertEqual(components["all"]["available_version"], REMOTE_REVISION)
        status_commands = [
            command for command, _ in runner.calls if "status" in command
        ]
        self.assertEqual(len(status_commands), 1)
        self.assertIn("core.fileMode=false", status_commands[0])
        self.assertNotIn("--ignore-submodules=dirty", status_commands[0])

    def _marker_source(self, root: Path, revision: str, dirty: bool) -> Path:
        source = prepare_source(root)
        shutil.rmtree(source / ".git")  # tarball install: no checkout
        (source / ".easy-ha-proxy-source-revision").write_text(
            f"revision={revision}\ndirty={'true' if dirty else 'false'}\n",
            encoding="utf-8",
        )
        return source

    def test_recorded_revision_detects_remote_update_without_git_checkout(self) -> None:
        # A synced tarball has no .git; the recorded marker lets the github
        # channel still compare against the remote branch.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._marker_source(root, LOCAL_REVISION, dirty=False)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command[:3] == ("git", "ls-remote", "--heads"):
                    return CommandResult(0, REMOTE_REVISION + "\trefs/heads/main\n")
                if command[:2] == ("git", "clone"):
                    shutil.copytree(source, Path(command[-1]))
                    return CommandResult(0)
                if command[-2:] == ("rev-parse", "HEAD"):
                    return CommandResult(0, REMOTE_REVISION + "\n")
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                raise AssertionError(f"Unexpected command: {command!r}")

            runner = FakeRunner(handler)
            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=runner,
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        # The source revision was compared to the remote branch (not "unknown").
        self.assertEqual(components["all"]["available_version"], REMOTE_REVISION)
        self.assertNotEqual(components["all"]["state"], "unknown")
        # No working-tree git commands were attempted against the source (there
        # is no checkout); rev-parse on the temporary candidate clone is fine.
        source_git = [
            c for c, _ in runner.calls
            if c[0] == "git" and str(source) in c
            and ("rev-parse" in c or "status" in c or "remote" in c)
        ]
        self.assertEqual(source_git, [])
        self.assertTrue(
            any(c[:3] == ("git", "ls-remote", "--heads") for c, _ in runner.calls)
        )

    def test_recorded_revision_is_current_when_matching_remote(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._marker_source(root, REMOTE_REVISION, dirty=False)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command[:3] == ("git", "ls-remote", "--heads"):
                    return CommandResult(0, REMOTE_REVISION + "\trefs/heads/main\n")
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                raise AssertionError(f"Unexpected command: {command!r}")

            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "current")
        # Daemons are still compared against the on-disk source and match.
        self.assertEqual(components["daemons"]["state"], "current")

    def test_recorded_dirty_source_is_blocked_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._marker_source(root, LOCAL_REVISION, dirty=True)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                if command[0] == "git":
                    raise AssertionError("dirty source must not contact git")
                raise AssertionError(f"Unexpected command: {command!r}")

            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "blocked")
        self.assertEqual(
            components["all"]["details"]["reason"], "recorded-source-dirty"
        )

    def test_missing_marker_and_git_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            shutil.rmtree(source / ".git")  # neither checkout nor marker

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                if command[0] == "git":
                    raise AssertionError("must not contact git without a revision")
                raise AssertionError(f"Unexpected command: {command!r}")

            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=FakeRunner(handler),
                artifact_path=prepare_installed_daemons(root, source),
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "unknown")
        self.assertEqual(
            components["all"]["details"]["reason"], "not-a-git-checkout"
        )

    def test_content_changes_block_automatic_source_replacement(self) -> None:
        def handler(command):
            if "status" in command:
                return CommandResult(0, " M installer/easy_ha_proxy.py\n")
            return git_handler(command)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        component = next(item for item in plan["components"] if item["id"] == "all")
        self.assertEqual(component["state"], "blocked")
        self.assertFalse(component["actionable"])
        self.assertEqual(component["details"]["reason"], "local-source-changes")

    def test_remote_source_change_does_not_create_component_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command[:2] == ("git", "clone"):
                    shutil.copytree(source, Path(command[-1]))
                    return CommandResult(0)
                if (
                    command[-2:] == ("rev-parse", "HEAD")
                    and Path(command[2]) != source
                ):
                    return CommandResult(0, REMOTE_REVISION + "\n")
                return git_handler(command)

            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "blocked")
        self.assertEqual(
            components["all"]["details"]["reason"],
            "container-candidate-unavailable",
        )
        self.assertEqual(components["all"]["available_version"], REMOTE_REVISION)
        self.assertEqual(components["services"]["state"], "current")
        self.assertEqual(components["daemons"]["state"], "current")
        self.assertNotIn("services", plan["actionable_components"])
        self.assertNotIn("daemons", plan["actionable_components"])

    def test_plan_reports_only_managed_compose_stacks_without_pulling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "source_channel: github\nimage_channel: alpha\n",
                encoding="utf-8",
            )
            authelia_compose = root / "opt/authelia/docker-compose.yml"
            admin_compose = root / "opt/haproxy-admin/docker-compose.yml"
            authelia_compose.parent.mkdir(parents=True)
            admin_compose.parent.mkdir(parents=True)
            authelia_compose.write_text("services: {}\n", encoding="utf-8")
            admin_compose.write_text("services: {}\n", encoding="utf-8")

            def handler(command):
                if command[:2] == ("git", "clone"):
                    candidate = Path(command[-1])
                    shutil.copytree(source, candidate)
                    (candidate / "ansible/easy-ha-proxy.yml").write_text(
                        "---\n- hosts: easy_ha_proxy\n  gather_facts: true\n",
                        encoding="utf-8",
                    )
                    return CommandResult(0)
                if (
                    command[-2:] == ("rev-parse", "HEAD")
                    and Path(command[2]) != source
                ):
                    return CommandResult(0, REMOTE_REVISION + "\n")
                if command[0] == "git":
                    return git_handler(command)
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(
                        0,
                        "Inst openssl [3.0.0] (3.0.1 Debian:stable)\n"
                        "Inst docker-ce [1] (2 Docker)\n",
                    )
                if command == (
                    "docker",
                    "compose",
                    "-f",
                    str(authelia_compose),
                    "config",
                    "--images",
                ):
                    return CommandResult(
                        0,
                        "authelia/authelia:4.39.20\n"
                        f"redis@{DIGEST_A}\n"
                        "authelia/authelia:4.39.20\n",
                    )
                if command == (
                    "docker",
                    "compose",
                    "-f",
                    str(admin_compose),
                    "config",
                    "--images",
                ):
                    return CommandResult(0, "example/haproxy-admin:alpha\n")
                if command[:3] == ("docker", "image", "inspect"):
                    image = command[3]
                    digest = DIGEST_A if image.startswith("authelia/") else DIGEST_A
                    return CommandResult(0, json.dumps([f"{image.split(':')[0]}@{digest}"]))
                if command[:4] == ("docker", "buildx", "imagetools", "inspect"):
                    image = command[4]
                    digest = DIGEST_A if image.startswith("authelia/") else DIGEST_B
                    return CommandResult(0, f"Name: {image}\nDigest: {digest}\n")
                raise AssertionError(f"Unexpected command: {command!r}")

            runner = FakeRunner(handler)
            plan = build_update_plan(
                source_dir=source,
                config_dir=config,
                authelia_compose=authelia_compose,
                admin_compose=admin_compose,
                runner=runner,
                artifact_path=installed,
                now=dt.datetime(2026, 7, 19, 12, 0, tzinfo=dt.timezone.utc),
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["authelia-container"]["state"], "current")
        self.assertEqual(components["admin-container"]["state"], "available")
        self.assertEqual(components["os"]["available_version"], 2)
        self.assertEqual(components["os"]["installed"], None)
        self.assertEqual(components["os"]["available"], 2)
        self.assertEqual(components["os"]["candidate"], 2)
        self.assertEqual(plan["source_channel"], "github")
        self.assertEqual(plan["image_channel"], "alpha")
        self.assertEqual(plan["generated_at"], "2026-07-19T12:00:00Z")
        self.assertEqual(
            set(plan["actionable_components"]),
            {"all", "services", "os", "admin-container"},
        )
        self.assertEqual(json.loads(json.dumps(plan)), plan)

        compose_paths = {
            command[3]
            for command, _ in runner.calls
            if command[:3] == ("docker", "compose", "-f")
        }
        self.assertEqual(
            compose_paths,
            {str(authelia_compose), str(admin_compose)},
        )
        flattened = [value for command, _ in runner.calls for value in command]
        self.assertNotIn("pull", flattened)

    def test_probe_timeout_is_reported_without_failing_the_plan(self) -> None:
        def handler(command):
            if command[-2:] == ("rev-parse", "HEAD"):
                return CommandResult(0, LOCAL_REVISION + "\n")
            if "status" in command:
                return CommandResult(0, "")
            if command[-3:] == ("remote", "get-url", "origin"):
                return CommandResult(0, "https://example.test/repository.git\n")
            if command[:3] == ("git", "ls-remote", "--heads"):
                return CommandResult(124, error="timeout")
            if command == ("apt-get", "-s", "upgrade"):
                return CommandResult(124, error="timeout")
            raise AssertionError(f"Unexpected command: {command!r}")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            plan = build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                runner=FakeRunner(handler),
                artifact_path=installed,
            )

        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "unknown")
        self.assertEqual(components["os"]["state"], "unknown")
        self.assertFalse(plan["has_updates"])

    def test_requested_admin_channel_checks_target_tag_without_pull(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            config = root / "config"
            config.mkdir()
            (config / "metadata.yml").write_text(
                "source_channel: local\nimage_channel: latest\n",
                encoding="utf-8",
            )
            (config / "vars.yml").write_text(
                "haproxy_admin_image: registry.example/admin:latest\n",
                encoding="utf-8",
            )
            admin_compose = root / "admin/docker-compose.yml"
            admin_compose.parent.mkdir()
            admin_compose.write_text("services: {}\n", encoding="utf-8")

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                if command == (
                    "docker",
                    "compose",
                    "-f",
                    str(admin_compose),
                    "config",
                    "--images",
                ):
                    return CommandResult(0, "registry.example/admin:latest\n")
                if command[:3] == ("docker", "image", "inspect"):
                    self.assertEqual(command[3], "registry.example/admin:latest")
                    return CommandResult(
                        0, json.dumps([f"registry.example/admin@{DIGEST_A}"])
                    )
                if command[:4] == (
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                ):
                    self.assertEqual(command[4], "registry.example/admin:alpha")
                    return CommandResult(0, f"Digest: {DIGEST_B}\n")
                raise AssertionError(f"Unexpected command: {command!r}")

            runner = FakeRunner(handler)
            plan = build_update_plan(
                source_dir=source,
                config_dir=config,
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=admin_compose,
                source_channel="local",
                image_channel="alpha",
                runner=runner,
                artifact_path=installed,
            )

        admin = next(
            item for item in plan["components"] if item["id"] == "admin-container"
        )
        self.assertEqual(admin["state"], "available")
        self.assertEqual(admin["details"]["configured_channel"], "latest")
        self.assertEqual(admin["details"]["target_channel"], "alpha")
        self.assertEqual(
            admin["details"]["images"][0]["target_image"],
            "registry.example/admin:alpha",
        )
        flattened = [value for command, _ in runner.calls for value in command]
        self.assertNotIn("pull", flattened)

    def test_cli_emits_json_and_returns_zero_for_unknown_components(self) -> None:
        payload = {
            "schema_version": 1,
            "generated_at": "2026-07-19T12:00:00Z",
            "source_channel": "github",
            "image_channel": "latest",
            "components": [{"id": "all", "state": "unknown"}],
        }
        output = io.StringIO()
        with (
            mock.patch("update_plan.build_update_plan", return_value=payload),
            contextlib.redirect_stdout(output),
        ):
            result = update_plan.main(["--format", "json"])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), payload)

    def test_subprocess_errors_redact_uri_credentials_and_tokens(self) -> None:
        error = update_plan._short_error(  # noqa: SLF001 - security regression
            CommandResult(
                1,
                stderr=(
                    "fatal: https://alice:private-token@example.test/repository"
                    "?access_token=also-private could not be read"
                ),
            )
        )

        self.assertNotIn("private-token", error)
        self.assertNotIn("also-private", error)
        self.assertIn("https://***@example.test", error)
        self.assertIn("access_token=***", error)


if __name__ == "__main__":
    unittest.main()
