"""Regression checks for persisted HAProxy server state."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HAPROXY_ROLE = ROOT / "ansible" / "roles" / "haproxy"
TEMPLATE = HAPROXY_ROLE / "templates" / "haproxy.cfg.j2"
DUMPER = HAPROXY_ROLE / "templates" / "haproxy-state-dump.sh.j2"
DEFAULTS = HAPROXY_ROLE / "defaults" / "main.yml"


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
        self.assertIn('trap \'rm -f "$TMP_FILE" "$FILTERED_FILE"\'', self.script)

    def test_the_script_never_exits_non_zero_on_a_runtime_problem(self):
        # A failed dump must not turn into a failed reload.
        self.assertNotRegex(self.script, r"(?m)^\s*exit [1-9][0-9]*\s*$")

    def test_the_dumper_names_the_agent(self):
        from jinja2 import Environment
        template = Environment().from_string(DUMPER.read_text())
        for context, agent in (({}, "/usr/local/sbin/easy-ha-proxy-agent"),
                               ({"native_agent_bin": "/opt/agent"}, "/opt/agent")):
            lines = [line for line in template.render(**context).splitlines() if line.startswith("AGENT=")]
            self.assertEqual(lines, [f'AGENT="{agent}"'], context)


# How the dumper behaves with a real normalizer -- the TLS suffix, ports,
# DNS, invalid replies, permissions -- is tested with the agent, in
# go/agent/internal/tools/server_state_dump_test.go.


class DocumentationTests(unittest.TestCase):
    def test_both_readmes_stop_calling_the_state_temporary(self):
        for name in ("docs/guide.md", "docs/guide.ru.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("no server state file", text, name)


if __name__ == "__main__":
    unittest.main()
