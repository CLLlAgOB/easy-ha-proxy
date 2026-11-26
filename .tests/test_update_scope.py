"""Updates that run only the steps their changed files need: the installer side.

"Only what changed" compares the source an update would install with the
record of the last complete update and maps each changed file to the stage
that deploys it; the host agent decides it ("easy-ha-proxy-agent
update-scope", tested with the agent). These tests cover what the installer
does with the answer, and that it asks the agent at all.
"""

from __future__ import annotations

from argparse import Namespace
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


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


class TheAgentDecides(unittest.TestCase):
    """The installer asks the host agent and never guesses a narrower scope."""

    def setUp(self):
        import easy_ha_proxy

        self.cli = easy_ha_proxy
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.agent = self.root / "easy-ha-proxy-agent"
        self.agent.write_text("", encoding="utf-8")
        for patch in (mock.patch.object(easy_ha_proxy, "AGENT_BINARY", self.agent),
                      mock.patch.object(easy_ha_proxy, "source_dir", return_value=self.root / "source")):
            patch.start()
            self.addCleanup(patch.stop)

    def answer(self, code=0, stdout="", stderr=""):
        return mock.patch("easy_ha_proxy.subprocess.run",
                          return_value=subprocess.CompletedProcess([], code, stdout, stderr))

    def test_the_scope_is_the_agents(self):
        with self.answer(stdout='{"full": false, "ready": true, "tags": ["ha-cfg", "status"]}') as run:
            scope = self.cli.changes_scope(self.root / "config")
        self.assertEqual(scope["tags"], ["ha-cfg", "status"])
        command = run.call_args.args[0]
        self.assertEqual(command[:3], [str(self.agent), "update-scope", "plan"])
        self.assertEqual(command[command.index("--config") + 1], str(self.root / "config"))
        self.assertEqual(command[command.index("--source") + 1], str(self.root / "source"))

    def test_without_an_answer_it_is_the_full_stack(self):
        for answer in (self.answer(code=2, stderr="usage: ..."), self.answer(stdout="not json"),
                       self.answer(stdout="[]")):
            with self.subTest(answer=answer), answer:
                scope = self.cli.changes_scope(self.root)
            self.assertTrue(scope["full"])
            self.assertFalse(scope["ready"])
            self.assertEqual(scope["reason"], "scope-unavailable")
        self.agent.unlink()
        with mock.patch("easy_ha_proxy.subprocess.run") as run:
            self.assertEqual(self.cli.changes_scope(self.root)["reason"], "scope-unavailable")
        run.assert_not_called()

    def test_an_unavailable_scope_says_so(self):
        with mock.patch("builtins.print") as printed:
            self.cli.describe_changes_scope(dict(self.cli.SCOPE_UNAVAILABLE))
        self.assertIn("could not work out the changed files", printed.call_args.args[0])

    def test_the_record_names_the_revision(self):
        with mock.patch("easy_ha_proxy.git_revision", return_value="a" * 40), self.answer() as run:
            self.cli.record_applied_source(self.root / "config")
        command = run.call_args.args[0]
        self.assertEqual(command[:3], [str(self.agent), "update-scope", "record"])
        self.assertEqual(command[command.index("--revision") + 1], "a" * 40)

    def test_a_failed_record_is_only_a_warning(self):
        with mock.patch("easy_ha_proxy.git_revision", return_value=""), \
                self.answer(code=1, stderr="could not record the applied source: read-only\n"), \
                mock.patch("builtins.print") as printed:
            self.cli.record_applied_source(self.root)
        self.assertIn("Warning: could not record the applied source", printed.call_args.args[0])
        self.assertIn("read-only", printed.call_args.args[0])

    def test_nothing_imports_a_python_scope_any_more(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        self.assertNotIn("import update_scope", source)
        self.assertFalse((ROOT / "installer/update_scope.py").exists())


if __name__ == "__main__":
    unittest.main()
