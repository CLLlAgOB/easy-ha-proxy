"""Regression checks for persisted HAProxy server state."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HAPROXY_ROLE = ROOT / "ansible" / "roles" / "haproxy"
TEMPLATE = HAPROXY_ROLE / "templates" / "haproxy.cfg.j2"
DUMPER = HAPROXY_ROLE / "templates" / "haproxy-state-dump.sh.j2"
CONFIG_TASKS = HAPROXY_ROLE / "tasks" / "config.yml"
DEFAULTS = HAPROXY_ROLE / "defaults" / "main.yml"


def load_controld():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_controld", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE.read_text(encoding="utf-8")

    def test_the_state_file_is_declared_in_global(self):
        self.assertIn("server-state-file", self.template)
        # Without the loader the dump would be written and never read.
        self.assertIn("load-server-state-from-file global", self.template)

    def test_both_halves_are_behind_the_same_switch(self):
        # Shipping one without the other is the failure that looks like it
        # works: the dump is written and nothing ever restores from it, or the
        # loader points at a file nobody maintains.
        block = re.compile(
            r"\{%\s*if\s+haproxy_server_state_enabled.*?%\}(.*?)\{%\s*endif\s*%\}",
            re.DOTALL,
        )
        guarded = "\n".join(block.findall(self.template))
        unguarded = block.sub("", self.template)
        for directive in ("server-state-file", "load-server-state-from-file global"):
            self.assertIn(directive, guarded, directive)
            self.assertNotIn(directive, unguarded, directive)

    def test_the_state_file_lives_inside_the_chroot_directory(self):
        defaults = DEFAULTS.read_text(encoding="utf-8")
        self.assertIn('haproxy_server_state_file: "{{ haproxy_chroot }}/server-state"',
                      defaults)
        self.assertIn("haproxy_server_state_enabled: true", defaults)

    def test_the_dumper_is_installed_before_the_configuration_reads_it(self):
        tasks = CONFIG_TASKS.read_text(encoding="utf-8")
        dumper = tasks.index("haproxy-state-dump.sh.j2")
        config = tasks.index("src: haproxy.cfg.j2")
        self.assertLess(dumper, config)

    def test_the_timer_is_enabled(self):
        tasks = CONFIG_TASKS.read_text(encoding="utf-8")
        self.assertIn("haproxy-state-dump.timer", tasks)
        self.assertIn("enabled: true", tasks)


class DumperScriptTests(unittest.TestCase):
    def setUp(self):
        self.script = DUMPER.read_text(encoding="utf-8")

    def test_the_write_is_atomic(self):
        # HAProxy reads this at startup; a half-written file is worse than a
        # stale one.
        self.assertIn("TMP_FILE", self.script)
        self.assertRegex(self.script, r"mv -f \"\$TMP_FILE\" \"\$STATE_FILE\"")
        self.assertNotRegex(self.script, r">\s*\"\$STATE_FILE\"")

    def test_a_short_reply_never_overwrites_a_good_file(self):
        self.assertIn('wc -l < "$TMP_FILE"', self.script)
        self.assertIn("-lt 2", self.script)

    def test_a_missing_socket_is_not_an_error(self):
        self.assertIn('if [ ! -S "$SOCKET" ]', self.script)
        self.assertIn("exit 0", self.script)

    def test_the_temporary_file_is_cleaned_up_on_failure(self):
        self.assertIn('trap \'rm -f "$TMP_FILE"\'', self.script)

    def test_the_script_never_exits_non_zero_on_a_runtime_problem(self):
        # A failed dump must not turn into a failed reload.
        self.assertNotIn("exit 1", self.script)


class ControldHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controld = load_controld()

    def test_reload_dumps_the_state_first(self):
        calls = []
        with (
            mock.patch.object(
                self.controld, "dump_server_state",
                side_effect=lambda: calls.append("dump"),
            ),
            mock.patch.object(
                self.controld.subprocess, "run",
                side_effect=lambda *a, **k: calls.append("reload")
                or mock.Mock(returncode=0, stdout="reloaded", stderr=""),
            ),
        ):
            ok, _ = self.controld.cmd_reload()
        self.assertTrue(ok)
        self.assertEqual(calls, ["dump", "reload"])

    def test_a_failed_dump_does_not_block_the_reload(self):
        with (
            mock.patch.object(self.controld.os.path, "exists", return_value=True),
            mock.patch.object(
                self.controld.subprocess, "run", side_effect=OSError("boom")
            ),
        ):
            # Must not raise: the timer keeps the file fresh anyway.
            self.controld.dump_server_state()

    def test_a_missing_dumper_is_skipped_quietly(self):
        with (
            mock.patch.object(self.controld.os.path, "exists", return_value=False),
            mock.patch.object(self.controld.subprocess, "run") as run,
        ):
            self.controld.dump_server_state()
        run.assert_not_called()


class DocumentationTests(unittest.TestCase):
    def test_both_readmes_stop_calling_the_state_temporary(self):
        for name in ("README.md", "README.ru.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("no server state file", text, name)


if __name__ == "__main__":
    unittest.main()
