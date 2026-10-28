"""Updates that run only the playbook steps their changed files need.

A full update ran every stage -- certificates, the HAProxy package, AppArmor,
GeoIP, Docker, Authelia, every daemon -- to deliver one changed daemon and a
template. "Only what changed" compares the source an update would install with
the record of the last complete update and maps each changed file to the
stage that deploys it. A file the map does not know means the full stack,
never a skipped step.

The map is only worth anything if it is right, so every rule that names a
stage is checked here against that stage's own task files.
"""

from __future__ import annotations

from argparse import Namespace
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

import update_scope


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
PLAYBOOK = ROOT / "ansible/easy-ha-proxy.yml"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"


def tracked_files() -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=False
        )
    except OSError:  # no git in a slim test image
        completed = None
    if completed is None or completed.returncode != 0:
        return [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                if p.is_file() and ".git" not in p.parts]
    return [line for line in completed.stdout.splitlines() if line]


def playbook_entries() -> list[tuple[str, str, set[str]]]:
    """(role, task_stage, tags) for every role entry in the main playbook."""
    entries = []
    for play in yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8")):
        for role in play.get("roles") or []:
            if not isinstance(role, dict):
                continue
            tags = role.get("tags") or []
            tags = {tags} if isinstance(tags, str) else set(tags)
            entries.append((role["role"], str(role.get("task_stage") or "main"), tags))
    return entries


_IMPORT_RE = re.compile(r"(?:import_tasks|include_tasks):\s*['\"]?([\w./-]+\.yml)")


def stage_text(role: str, stage: str, seen: set | None = None) -> tuple[str, set[str]]:
    """The stage's task file with everything it imports, and the file names."""
    seen = seen if seen is not None else set()
    path = ROOT / "ansible/roles" / role / "tasks" / f"{stage}.yml"
    if path in seen or not path.is_file():
        return "", set()
    seen.add(path)
    text = path.read_text(encoding="utf-8")
    names = {f"{stage}.yml"}
    for imported in _IMPORT_RE.findall(text):
        more, more_names = stage_text(role, imported[:-4], seen)
        text += "\n" + more
        names |= more_names
    return text, names


class TheMapMatchesTheRoles(unittest.TestCase):
    def setUp(self):
        self.entries = playbook_entries()
        self.all_tags = set().union(*(tags for _, _, tags in self.entries))

    def stages_for(self, tag):
        return [(role, stage) for role, stage, tags in self.entries if tag in tags]

    def test_every_tag_the_map_uses_exists_in_the_playbook(self):
        for pattern, tags in update_scope.RULES:
            for tag in tags:
                if tag == update_scope.FULL:
                    continue
                with self.subTest(pattern=pattern, tag=tag):
                    self.assertIn(tag, self.all_tags)

    def test_every_named_file_exists(self):
        # A rule for a file that is gone is a rule nobody will notice is wrong.
        files = set(tracked_files())
        for pattern, _ in update_scope.RULES:
            if any(c in pattern for c in "*?["):
                self.assertTrue(
                    any(update_scope.fnmatchcase(f, pattern) for f in files),
                    f"{pattern} matches nothing",
                )
            else:
                self.assertIn(pattern, files)

    def test_each_mapped_file_is_deployed_by_the_stage_it_names(self):
        for pattern, tags in update_scope.RULES:
            if not tags or update_scope.FULL in tags or any(c in pattern for c in "*?["):
                continue
            match = re.match(r"ansible/roles/([^/]+)/(files|templates|tasks)/(.+)$", pattern)
            if not match:
                continue
            role, kind, name = match.groups()
            for tag in tags:
                with self.subTest(file=pattern, tag=tag):
                    texts, task_files = "", set()
                    for stage_role, stage in self.stages_for(tag):
                        text, names = stage_text(stage_role, stage)
                        texts += text
                        if stage_role == role:
                            task_files |= names
                    if kind == "tasks":
                        self.assertIn(name, task_files, f"{tag} does not run {name}")
                    else:
                        self.assertIn(Path(name).name, texts, f"{tag} does not deploy {name}")

    def test_the_whole_roles_mapped_to_one_stage_have_only_that_stage(self):
        for role, tag in (("geoip_acl", "geo"), ("docker", "docker")):
            with self.subTest(role=role):
                self.assertEqual({r for r, _, tags in self.entries if tag in tags}, {role})


class WhatAChangeNeeds(unittest.TestCase):
    def test_a_daemon_change_runs_its_stage(self):
        scope = update_scope.scope_for([
            "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py",
            "ansible/roles/haproxy-admin/files/scanner-signatures.json",
            ".tests/test_guardd.py",
            "README.md",
        ])
        self.assertFalse(scope["full"])
        self.assertEqual(scope["tags"], ["ha-adm-guardd", "status"])
        self.assertEqual(scope["steps"], ["Adaptive protection"])
        self.assertEqual(scope["changed"], 4)

    def test_the_template_refreshes_haproxy_and_the_web_applications_copy(self):
        scope = update_scope.scope_for(["ansible/roles/haproxy/templates/haproxy.cfg.j2"])
        self.assertEqual(scope["tags"], ["ha-adm-cfg", "ha-cfg", "status"])

    def test_documentation_tests_and_the_web_application_deploy_nothing(self):
        scope = update_scope.scope_for([
            "README.ru.md", ".tests/test_x.py", ".github/workflows/ci.yml",
            "docker/app/haproxy_admin/static/js/live_activity.js", "Dockerfile",
            "installer/easy_ha_proxy.py",
            "ansible/callback_plugins/easy_ha_proxy_progress.py",
        ])
        self.assertFalse(scope["full"])
        self.assertEqual(scope["tags"], [])

    def test_anything_unknown_or_structural_means_the_full_stack(self):
        for path in (
            "ansible/easy-ha-proxy.yml",
            "ansible/requirements.yml",
            "installer/requirements.txt",
            "ansible/roles/haproxy-admin/defaults/main.yml",
            "ansible/roles/haproxy-admin/handlers/main.yml",
            "ansible/roles/haproxy-admin/tasks/main.yml",
            "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2",
            "ansible/roles/haproxy-admin/tasks/start.yml",
            "ansible/roles/authelia/templates/configuration.yml.j2",
            "ansible/roles/cert/defaults/main.yml",
            "some/new/thing.py",
        ):
            with self.subTest(path=path):
                scope = update_scope.scope_for([path, "README.md"])
                self.assertTrue(scope["full"])
                self.assertEqual(scope["tags"], [])
                self.assertIn(path, scope["unmapped"])


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"})


class TheRecord(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.config = self.root / "config"
        guardd = self.source / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        guardd.parent.mkdir(parents=True)
        guardd.write_text("v1\n", encoding="utf-8")
        (self.source / "README.md").write_text("docs\n", encoding="utf-8")

    def test_without_a_record_the_full_stack_is_needed(self):
        scope = update_scope.plan_scope(self.config, self.source)
        self.assertFalse(scope["ready"])
        self.assertEqual(scope["reason"], "no-applied-record")

    def test_a_record_then_a_change(self):
        update_scope.write_applied(self.config, self.source, "a" * 40)
        self.assertEqual(update_scope.read_applied(self.config)["revision"], "a" * 40)
        self.assertEqual(update_scope.plan_scope(self.config, self.source)["tags"], [])
        guardd = self.source / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
        guardd.write_text("v2\n", encoding="utf-8")
        scope = update_scope.plan_scope(self.config, self.source)
        self.assertTrue(scope["ready"])
        self.assertEqual(scope["tags"], ["ha-adm-guardd", "status"])

    def test_a_removed_file_is_not_a_change(self):
        update_scope.write_applied(self.config, self.source)
        (self.source / "README.md").unlink()
        self.assertEqual(update_scope.plan_scope(self.config, self.source)["changed"], 0)

    def test_files_the_installation_writes_into_its_source_never_count(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        git(self.source, "init", "-q")
        git(self.source, "add", "-A")
        git(self.source, "commit", "-q", "-m", "x")
        update_scope.write_applied(self.config, self.source)
        cache = self.source / "ansible/cache/facts"
        cache.parent.mkdir(parents=True)
        cache.write_text("{}", encoding="utf-8")
        (self.source / "ansible/new-untracked.yml").write_text("x", encoding="utf-8")
        self.assertEqual(update_scope.plan_scope(self.config, self.source)["changed"], 0)

    def test_a_staged_bundle_skips_known_runtime_files(self):
        manifest_before = update_scope.source_manifest(self.source)
        pem = self.source / "ansible/roles/cert/files/site.pem"
        pem.parent.mkdir(parents=True)
        pem.write_text("secret", encoding="utf-8")
        (self.source / "ansible/tcp.yml").write_text("x", encoding="utf-8")
        self.assertEqual(update_scope.source_manifest(self.source), manifest_before)

    def test_a_damaged_record_is_no_record(self):
        self.config.mkdir()
        (self.config / update_scope.APPLIED_SOURCE_FILE).write_text("{not json", encoding="utf-8")
        self.assertIsNone(update_scope.read_applied(self.config))
        self.assertFalse(update_scope.plan_scope(self.config, self.source)["ready"])


class ThePlanCarriesIt(unittest.TestCase):
    def test_the_source_component_says_what_a_changes_only_update_would_run(self):
        import test_update_plan as fakes
        from update_plan import CommandResult, build_update_plan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fakes.prepare_source(root)
            installed = fakes.prepare_installed_daemons(root, source)
            config = root / "config"
            update_scope.write_applied(config, source, fakes.LOCAL_REVISION)

            def handler(command):
                if command[:2] == ("git", "clone"):
                    shutil.copytree(source, Path(command[-1]))
                    changed = Path(command[-1]) / "ansible/roles/haproxy-admin/files/scanner-signatures.json"
                    changed.parent.mkdir(parents=True, exist_ok=True)
                    changed.write_text("{}", encoding="utf-8")
                    return CommandResult(0)
                if command[-2:] == ("rev-parse", "HEAD") and Path(command[2]) != source:
                    return CommandResult(0, fakes.REMOTE_REVISION + "\n")
                return fakes.git_handler(command)

            plan = build_update_plan(
                source_dir=source, config_dir=config,
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                runner=fakes.FakeRunner(handler), artifact_path=installed,
            )
        source_component = {item["id"]: item for item in plan["components"]}["all"]
        scope = source_component["details"]["scope"]
        self.assertTrue(scope["ready"])
        self.assertEqual(scope["tags"], ["ha-adm-guardd", "status"])
        self.assertEqual(scope["changed"], 1)


class TheInstaller(unittest.TestCase):
    """`easy-ha-proxy update --component changes`."""

    def run_update(self, scope, *, pending=False, no_fallback=False):
        import easy_ha_proxy
        args = Namespace(ui_only=False, component="changes", source_channel="github",
                         no_fetch=False, image_channel=None, no_full_fallback=no_fallback)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (
                mock.patch.dict(os.environ, {easy_ha_proxy.UPDATE_SOURCE_REFRESHED_ENV: "1"}),
                mock.patch("easy_ha_proxy.require_root"),
                mock.patch("easy_ha_proxy.hold_maintenance_lock"),
                mock.patch("easy_ha_proxy.config_dir", return_value=directory),
                mock.patch("easy_ha_proxy.ensure_security_secrets"),
                mock.patch("easy_ha_proxy.persist_deployment_channels"),
                mock.patch("easy_ha_proxy.managed_configuration_is_pending", return_value=pending),
                mock.patch("easy_ha_proxy.sync_runtime_haproxy_config_to_managed"),
                mock.patch("easy_ha_proxy.sync_runtime_authelia_rules_to_managed"),
                mock.patch("easy_ha_proxy.sync_runtime_dependencies") as deps,
                mock.patch("easy_ha_proxy.syntax_check"),
                mock.patch("easy_ha_proxy.run_playbook") as playbook,
                mock.patch("easy_ha_proxy.mark_installation_complete"),
                mock.patch("easy_ha_proxy.changes_scope", return_value=scope),
                mock.patch("easy_ha_proxy.record_applied_source") as record,
            ):
                easy_ha_proxy.command_update(args)
        return playbook, record, deps

    def test_only_the_needed_steps_run_and_the_record_moves_on(self):
        playbook, record, deps = self.run_update(
            {"full": False, "ready": True, "tags": ["ha-adm-guardd", "status"], "steps": [], "changed": 2}
        )
        self.assertEqual(playbook.call_args.args[0], "ha-adm-guardd,status")
        record.assert_called_once()
        deps.assert_not_called()

    def test_by_hand_it_falls_back_to_the_full_stack(self):
        import easy_ha_proxy
        playbook, record, deps = self.run_update(
            {"full": True, "ready": False, "tags": [], "unmapped": ["ansible/easy-ha-proxy.yml"], "changed": 1}
        )
        self.assertEqual(playbook.call_args.args[0], easy_ha_proxy.UPDATE_TAGS)
        record.assert_called_once()
        deps.assert_called_once()

    def test_the_broker_never_gets_a_full_stack_it_did_not_approve(self):
        import easy_ha_proxy
        for scope, pending in (
            ({"full": True, "ready": False, "tags": [], "changed": 1}, False),
            ({"full": False, "ready": True, "tags": ["ha-cfg", "status"], "changed": 1}, True),
        ):
            with self.subTest(pending=pending):
                with self.assertRaises(easy_ha_proxy.InstallerError):
                    self.run_update(scope, pending=pending, no_fallback=True)

    def test_changes_refresh_the_source_like_the_other_source_updates(self):
        import easy_ha_proxy
        self.assertIn("changes", easy_ha_proxy.SOURCE_UPDATE_COMPONENTS)
        self.assertIn("changes", easy_ha_proxy.UPDATE_COMPONENT_TAGS)

    def test_complete_updates_record_what_they_applied(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        for command in ("def command_install(", "def command_configure("):
            body = source.split(command)[1].split("\ndef ")[0]
            with self.subTest(command=command):
                self.assertIn("record_applied_source(directory)", body)


def load_broker():
    name = "easy_ha_proxy_updated_scope_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(sys.platform == "win32", "the broker needs fcntl")
class TheBroker(unittest.TestCase):
    def setUp(self):
        self.broker = load_broker()

    def plan(self, ready=True):
        return {
            "id": "a" * 32, "source_channel": "github", "image_channel": "latest",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "components": [{
                "id": "all", "state": "available", "actionable": True,
                "installed": "1" * 40, "available": "2" * 40,
                "details": {"scope": {"ready": ready, "tags": ["ha-cfg", "status"] if ready else []}},
            }],
        }

    def test_it_replaces_the_narrower_source_updates_but_not_containers(self):
        self.assertEqual(
            self.broker.selected_components(["os", "services", "changes", "admin-container", "daemons"]),
            ["changes", "admin-container", "os"],
        )
        self.assertEqual(self.broker.selected_components(["changes", "all"]), ["all"])

    def test_it_is_checked_against_the_source_components_scope(self):
        with (
            mock.patch.object(self.broker, "validate_plan_channel"),
            mock.patch.object(self.broker, "CONFIG_DIR", Path(tempfile.mkdtemp())),
            mock.patch.object(self.broker, "haproxy_transaction_active", return_value=False),
        ):
            (self.broker.CONFIG_DIR / "metadata.yml").write_text("configuration_pending: false\n")
            self.broker.validate_selection(self.plan(), ["changes"])
            with self.assertRaises(self.broker.UpdatedError):
                self.broker.validate_selection(self.plan(ready=False), ["changes"])

    def test_a_scope_that_moved_since_the_check_is_stale(self):
        fresh = self.plan()
        fresh["components"][0]["details"]["scope"]["tags"] = ["ha-cfg", "ha-install", "status"]
        with self.assertRaises(self.broker.UpdatedError) as caught:
            self.broker.validate_fresh_candidates(self.plan(), fresh, ["changes"])
        self.assertEqual(caught.exception.code, "stale_plan")
        self.broker.validate_fresh_candidates(self.plan(), self.plan(), ["changes"])

    def test_the_command_pins_the_revision_and_forbids_the_fallback(self):
        command = self.broker.update_command(
            "changes", source_channel="github", image_channel="latest",
            expected_source_revision="2" * 40,
        )
        self.assertEqual(command[:4], ["/usr/local/bin/easy-ha-proxy", "update", "--component", "changes"])
        self.assertIn("--expected-source-revision", command)
        self.assertEqual(command[-1], "--no-full-fallback")
        self.assertNotIn("--image-channel", command)

    def test_a_checker_cannot_offer_it_as_a_component_of_its_own(self):
        payload = {"source_channel": "github", "image_channel": "latest",
                   "components": [{"id": "changes", "state": "available"}]}
        with self.assertRaises(self.broker.UpdatedError):
            self.broker.parse_checker_output(json.dumps(payload))


class ThePage(unittest.TestCase):
    def test_route_and_script(self):
        routes = (APP / "routes_updates.py").read_text(encoding="utf-8")
        script = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")
        self.assertIn('"changes",', routes.split("UPDATE_COMPONENTS = frozenset(")[1].split(")")[0])
        self.assertIn('"changes"', routes.split("CONFIG_SENSITIVE_COMPONENTS")[1].split("\n")[0])
        core = (APP / "static/js/updates_core.js").read_text(encoding="utf-8")
        self.assertIn("withChangesRow(normalizeComponents(plan))", script)
        self.assertIn('changes: "Only what changed"', core)
        # The scope is its own row, not a dump inside the source row.
        self.assertIn('!["scope", "changelog", "requires"].includes(key)', script)

    def test_the_words_are_translated(self):
        catalogue = json.loads((APP / "translations/ru/updates.json").read_text(encoding="utf-8"))["messages"]
        for key in ("Only what changed", "{count} changed file(s). Steps to run: {steps}",
                    "These changes need the complete stack: {paths}",
                    "Available after the next complete update: there is no record of the last one yet."):
            self.assertIn(key, catalogue)
        merged = {}
        for path in (APP / "translations").rglob("*.json"):
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if "ru" in path.parts or path.name == "ru.json":
                merged.update(loaded.get("messages", loaded))
        for label in update_scope.TAG_LABELS.values():
            with self.subTest(label=label):
                self.assertIn(label, merged)


class TimingInTheLog(unittest.TestCase):
    def test_every_update_log_shows_where_the_time_went(self):
        config = (ROOT / "ansible/ansible.cfg").read_text(encoding="utf-8")
        self.assertIn("callbacks_enabled = ansible.posix.profile_tasks", config)
        requirements = (ROOT / "ansible/requirements.yml").read_text(encoding="utf-8")
        self.assertIn("ansible.posix", requirements)


if __name__ == "__main__":
    unittest.main()
