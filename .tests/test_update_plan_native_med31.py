"""MED-31 regression tests for update_scope and update_plan native binary tracking."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

import update_plan
import update_scope

REV_OLD = "a" * 40
REV_NEW = "b" * 40


class FakeRunner:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def run(self, argv, *, timeout):
        command = tuple(argv)
        self.calls.append((command, timeout))
        return self.handler(command)


def _seed_tree(root: Path, *, go_panel="v1", go_agent="v1", rust_guardd="v1", native_default=True) -> None:
    (root / ".git").mkdir(parents=True, exist_ok=True)
    defaults = root / update_plan.ADMIN_DEFAULTS
    defaults.parent.mkdir(parents=True, exist_ok=True)
    defaults.write_text("app_group: hadmin\n", encoding="utf-8")
    del native_default
    panel = root / "go/panel/cmd/easy-ha-proxy-panel/main.go"
    panel.parent.mkdir(parents=True, exist_ok=True)
    panel.write_text(f"// {go_panel}\n", encoding="utf-8")
    agent = root / "go/agent/cmd/easy-ha-proxy-agent/main.go"
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text(f"// {go_agent}\n", encoding="utf-8")
    guardd = root / "rust/guardd/src/main.rs"
    guardd.parent.mkdir(parents=True, exist_ok=True)
    guardd.write_text(f"// {rust_guardd}\n", encoding="utf-8")


def _seed_installed(root: Path, source: Path, *, installed_rev: str | None = REV_OLD, missing_agent: bool = False):
    fs_root = root / "installed"
    for artifact_id, _, installed_path, _ in update_plan.NATIVE_DAEMON_ARTIFACTS:
        if missing_agent and artifact_id == "easy-ha-proxy-agent":
            continue
        dest = fs_root / installed_path.relative_to("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ELF")
    if installed_rev is not None:
        meta = fs_root / update_plan.NATIVE_STAGING_METADATA.relative_to("/")
        meta.parent.mkdir(parents=True, exist_ok=True)
        meta.write_text(json.dumps({"revision": installed_rev}) + "\n", encoding="utf-8")

    def resolve(path: Path) -> Path:
        return fs_root / path.relative_to("/")

    return resolve


class NativeUpdateScopeAndPlanTests(unittest.TestCase):
    def test_scope_only_panel_changed_skips_host_native_stage(self) -> None:
        scope = update_scope.scope_for(["go/panel/internal/app/app.go"])
        self.assertFalse(scope["full"])
        self.assertEqual(scope["tags"], [])
        self.assertEqual(scope["steps"], [])

    def test_scope_agent_and_guardd_changes_target_ha_adm_native_with_label(self) -> None:
        for path in ("go/agent/internal/alertd/engine.go", "rust/guardd/src/engine.rs"):
            with self.subTest(path=path):
                scope = update_scope.scope_for([path])
                self.assertFalse(scope["full"])
                self.assertEqual(scope["tags"], ["ha-adm-native", "status"])
                self.assertEqual(scope["steps"], ["Native host binaries"])

    def _run_plan(self, *, go_panel_new="v1", go_agent_new="v1", rust_guardd_new="v1",
                  remote_rev=REV_NEW, installed_rev=REV_OLD, missing_agent=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            candidate = root / "candidate"
            _seed_tree(source)
            _seed_tree(candidate, go_panel=go_panel_new, go_agent=go_agent_new, rust_guardd=rust_guardd_new)
            resolve = _seed_installed(root, source, installed_rev=installed_rev, missing_agent=missing_agent)

            def handler(cmd):
                if cmd[-2:] == ("rev-parse", "HEAD"):
                    if str(source) in cmd:
                        return update_plan.CommandResult(0, REV_OLD + "\n")
                    return update_plan.CommandResult(0, remote_rev + "\n")
                if "status" in cmd:
                    return update_plan.CommandResult(0, "")
                if "remote" in cmd and "get-url" in cmd:
                    return update_plan.CommandResult(0, update_plan.DEFAULT_REPOSITORY + "\n")
                if cmd[:3] == ("git", "ls-remote", "--heads"):
                    return update_plan.CommandResult(0, remote_rev + "\trefs/heads/alpha\n")
                if cmd[:2] == ("git", "clone"):
                    shutil.copytree(candidate, Path(cmd[-1]))
                    return update_plan.CommandResult(0)
                if cmd == ("apt-get", "-s", "upgrade"):
                    return update_plan.CommandResult(0, "")
                return update_plan.CommandResult(1, stderr=f"unexpected {cmd}")

            plan = update_plan.build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                branch="alpha",
                runner=FakeRunner(handler),
                artifact_path=resolve,
            )
            return {c["id"]: c for c in plan["components"]}

    def test_only_panel_changed_does_not_mark_services_available(self) -> None:
        comps = self._run_plan(go_panel_new="v2", remote_rev=REV_NEW, installed_rev=REV_OLD)
        self.assertEqual(comps["services"]["state"], "current")

    def test_agent_changed_marks_services_and_daemons_available(self) -> None:
        comps = self._run_plan(go_agent_new="v2", remote_rev=REV_NEW, installed_rev=REV_OLD)
        self.assertEqual(comps["services"]["state"], "available")
        self.assertEqual(comps["daemons"]["state"], "available")
        artifacts = {a["id"]: a for a in comps["daemons"]["details"]["artifacts"]}
        self.assertEqual(artifacts["easy-ha-proxy-agent"]["state"], "available")
        self.assertEqual(artifacts["easy-ha-proxy-agent"]["reason"], "native-source-changed")

    def test_guardd_changed_marks_services_and_daemons_available(self) -> None:
        comps = self._run_plan(rust_guardd_new="v2", remote_rev=REV_NEW, installed_rev=REV_OLD)
        self.assertEqual(comps["services"]["state"], "available")
        self.assertEqual(comps["daemons"]["state"], "available")
        artifacts = {a["id"]: a for a in comps["daemons"]["details"]["artifacts"]}
        self.assertEqual(artifacts["guardd-core"]["state"], "available")
        self.assertEqual(artifacts["guardd-core"]["reason"], "native-source-changed")

    def test_sources_fresh_binary_stale_marks_daemons_available(self) -> None:
        # Source HEAD matches remote HEAD (REV_OLD == REV_OLD), but installed native metadata has a different revision.
        comps = self._run_plan(remote_rev=REV_OLD, installed_rev="c" * 40)
        self.assertEqual(comps["all"]["state"], "current")
        self.assertEqual(comps["services"]["state"], "current")
        self.assertEqual(comps["daemons"]["state"], "available")
        artifacts = {a["id"]: a for a in comps["daemons"]["details"]["artifacts"]}
        self.assertEqual(artifacts["easy-ha-proxy-agent"]["reason"], "revision-mismatch")

        # Also when native binary file itself is missing on disk.
        comps_missing = self._run_plan(remote_rev=REV_OLD, installed_rev=REV_OLD, missing_agent=True)
        self.assertEqual(comps_missing["daemons"]["state"], "available")
        artifacts_m = {a["id"]: a for a in comps_missing["daemons"]["details"]["artifacts"]}
        self.assertEqual(artifacts_m["easy-ha-proxy-agent"]["reason"], "installed-file-missing")


if __name__ == "__main__":
    unittest.main()
