"""Regression checks for persisted HAProxy server state."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import unittest
import os
import socket
import subprocess
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HAPROXY_ROLE = ROOT / "ansible" / "roles" / "haproxy"
TEMPLATE = HAPROXY_ROLE / "templates" / "haproxy.cfg.j2"
DUMPER = HAPROXY_ROLE / "templates" / "haproxy-state-dump.sh.j2"
NORMALIZER = ROOT / "installer" / "haproxy_server_state.py"
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
        self.assertIn('trap \'rm -f "$TMP_FILE" "$FILTERED_FILE"\'', self.script)

    def test_the_script_never_exits_non_zero_on_a_runtime_problem(self):
        # A failed dump must not turn into a failed reload.
        self.assertNotRegex(self.script, r"(?m)^\s*exit [1-9][0-9]*\s*$")



@unittest.skipIf(sys.platform == "win32", "the installed dumper is POSIX")
class DumpedTransportTests(unittest.TestCase):
    HEADER = "be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port"
    ROW = "36 target 1 main 127.0.0.1 2 1 17 100 10 15 3 4 6 0 0 0 - 1025 - 0 0 - - 0"

    def dump(self, reply, online=True, config=None, previous="previous-state\n", mode=0o644):
        from jinja2 import Template
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.write_text(previous if online else reply)
            state.chmod(mode)
            owner = (state.stat().st_uid, state.stat().st_gid)
            payload = root / "reply"
            payload.write_text(reply)
            helper = root / "socat"
            helper.write_text('#!/bin/sh\ncat "$STATE_REPLY"\n')
            helper.chmod(0o700)
            script = root / "dump.sh"
            script.write_text(Template(DUMPER.read_text()).render(haproxy_socket=str(root / "socket"), haproxy_server_state_file=str(state)))
            config_path = root / "haproxy.cfg"
            if config is not None:
                config_path.write_text(config)
            with socket.socket(socket.AF_UNIX) as server:
                if online:
                    server.bind(str(root / "socket"))
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], STATE_REPLY=str(payload))
                result = subprocess.run(["sh", str(script), str(config_path), str(NORMALIZER)], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(state.stat().st_mode & 0o777, mode)
            self.assertEqual((state.stat().st_uid, state.stat().st_gid), owner)
            self.assertEqual(list(root.glob("state.tmp.*")), [])
            return state.read_text()

    def test_tls_suffix_is_omitted_without_changing_maintenance_or_weights(self):
        for tls in ("0", "1"):
            fields = self.ROW.split()
            fields[20] = tls
            result = self.dump("1\n# " + self.HEADER + "\n" + " ".join(fields) + "\n")
            lines = result.splitlines()
            self.assertEqual(lines[2].split(), fields[:20])
            self.assertEqual(lines[1].split()[1:], self.HEADER.split()[:20])
            self.assertEqual(lines[2].split()[6:9], ["1", "17", "100"])

    def test_older_twenty_field_format_is_kept(self):
        row = " ".join(self.ROW.split()[:20])
        reply = "1\n# " + " ".join(self.HEADER.split()[:20]) + "\n" + row + "\n"
        self.assertEqual(self.dump(reply), reply)

    def test_stopped_gateway_also_cleans_its_previous_state_before_start(self):
        reply = "1\n# " + self.HEADER + "\n" + self.ROW + "\n"
        self.assertEqual(len(self.dump(reply, online=False).splitlines()[2].split()), 20)

    def test_configured_port_wins_without_changing_administration_or_weights(self):
        reply = "1\n# " + self.HEADER + "\n" + self.ROW + "\n"
        for online in (True, False):
            for endpoint in ("127.0.0.1:1026", "[::1]:1026", "mesh.example.test:1026"):
                with self.subTest(online=online, endpoint=endpoint):
                    config = "backend target\n    server main " + endpoint + " weight 100 check\n"
                    row = self.dump(reply, online=online, config=config).splitlines()[2].split()
                    self.assertEqual(row[18], "1026")
                    self.assertEqual(row[6:9], self.ROW.split()[6:9])

    def test_ports_are_matched_by_both_backend_and_server_name(self):
        second = self.ROW.replace("36 target ", "37 other ")
        reply = "1\n# " + self.HEADER + "\n" + self.ROW + "\n" + second + "\n"
        config = "backend target\n server main 127.0.0.1:1026\nbackend other\n server main 127.0.0.1:1043\n"
        rows = self.dump(reply, config=config).splitlines()[2:]
        self.assertEqual([row.split()[18] for row in rows], ["1026", "1043"])

    def test_dns_srv_port_is_preserved_without_an_explicit_configured_port(self):
        row = self.ROW.split()
        row[17] = "target.example.test"
        row[19] = "_service._tcp.example.test"
        reply = "1\n# " + self.HEADER + "\n" + " ".join(row) + "\n"
        config = "backend target\n server main _service._tcp.example.test resolvers dns\n"
        row = self.dump(reply, config=config).splitlines()[2].split()
        self.assertEqual(row[18], "1025")

    def test_ansible_refreshes_after_render_and_before_first_start(self):
        tasks = CONFIG_TASKS.read_text()
        self.assertGreater(tasks.index('Refresh administrative state'), tasks.index('src: haproxy.cfg.j2'))
        self.assertLess(tasks.index('Refresh administrative state'), tasks.index('Ensure HAProxy is enabled and running'))

    def test_shared_normalizer_is_installed_before_dumper_and_start_guard(self):
        tasks = CONFIG_TASKS.read_text()
        self.assertLess(tasks.index('Install the shared state normalizer'), tasks.index('Install the dump script'))
        self.assertLess(tasks.index('Install the dump script'), tasks.index('Normalize state before every cold start'))
        self.assertIn('ExecStartPre=-/usr/local/sbin/haproxy-state-dump', tasks)

    def test_invalid_version_header_or_partial_row_never_replaces_state(self):
        for reply in ("2\n# " + self.HEADER + "\n" + self.ROW + "\n",
                      "1\n# wrong header\n" + self.ROW + "\n",
                      "1\n# " + self.HEADER + "\n36 target 1 main\n",
                      "permission denied\n"):
            self.assertEqual(self.dump(reply), "previous-state\n")

    def test_runtime_errors_still_reconcile_the_last_valid_snapshot(self):
        previous = "1\n# " + self.HEADER + "\n" + self.ROW + "\n"
        config = "backend target\n server main 127.0.0.1:1026 check\n"
        for reply in ("", "permission denied\n", "1\n# " + self.HEADER + "\ntruncated\n"):
            with self.subTest(reply=reply):
                row = self.dump(reply, config=config, previous=previous).splitlines()[2].split()
                self.assertEqual(row[18], "1026")
                self.assertEqual(row[6:9], self.ROW.split()[6:9])

    def test_cold_start_normalization_does_not_weaken_private_snapshot_permissions(self):
        reply = "1\n# " + self.HEADER + "\n" + self.ROW + "\n"
        self.dump(reply, online=False, mode=0o600)


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
        for name in ("docs/guide.md", "docs/guide.ru.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("no server state file", text, name)


if __name__ == "__main__":
    unittest.main()
