"""controld keeps the ban and authorized-IP ipsets in step with HAProxy's
tables in one `ipset restore` per pass, and every command it runs is bounded
in time.

The sync used to run one process per address, with no time limit: a ban wave
of a few thousand addresses meant thousands of processes every ten seconds,
and one ipset, systemctl or `haproxy -c` that hung kept its thread -- the
sync loop itself, or a control request -- for good. The fake ipset below
keeps its sets in a JSON file and behaves like ipset 7.19 does: a batch with
a line it cannot parse is dropped as a whole.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/haproxy-controld.py"
POSIX = os.name == "posix" and shutil.which("sh") is not None


def load_controld():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_controld_ipset", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


controld = load_controld()


FAKE_IPSET = """\
import ipaddress, json, os, sys, time

state_path = os.environ["FAKE_IPSET_STATE"]
args = sys.argv[1:]
stdin = sys.stdin.read() if "restore" in args else ""
with open(os.environ["FAKE_IPSET_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"argv": args, "stdin": stdin}) + "\\n")
if os.environ.get("FAKE_IPSET_HANG") in args:
    time.sleep(60)
with open(state_path, encoding="utf-8") as fh:
    sets = json.load(fh)

def fail(message):
    print("ipset v7.19: " + message, file=sys.stderr)
    sys.exit(1)

if args[0] == "create":
    sets.setdefault(args[1], [])
elif args[0] == "list":
    if args[1] not in sets:
        fail("The set with the given name does not exist")
    print("Name: " + args[1])
    print("Type: hash:ip")
    print("Members:")
    for member in sets[args[1]]:
        print(member)
    sys.exit(0)
elif args == ["-exist", "restore"]:
    changed = {name: list(members) for name, members in sets.items()}
    for number, line in enumerate(stdin.splitlines(), 1):
        command, name, entry = line.split()
        try:
            ipaddress.IPv4Address(entry)
        except ValueError:
            fail(f"Error in line {number}: Syntax error: cannot parse {entry}")
        if name not in changed:
            fail(f"Error in line {number}: The set with the given name does not exist")
        if command == "add" and entry not in changed[name]:
            changed[name].append(entry)
        elif command == "del" and entry in changed[name]:
            changed[name].remove(entry)
    sets = changed
else:
    fail("unexpected command " + " ".join(args))
with open(state_path, "w", encoding="utf-8") as fh:
    json.dump(sets, fh)
"""


@unittest.skipUnless(POSIX, "runs a fake ipset as a real process")
class FakeIpsetCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "ipset"
        fake.write_text(f"#!{sys.executable}\n" + FAKE_IPSET, encoding="utf-8")
        fake.chmod(0o755)
        self.state = self.root / "state.json"
        self.log = self.root / "calls.jsonl"
        self.log.write_text("", encoding="utf-8")
        self.sets({})
        environment = mock.patch.dict(
            os.environ,
            {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "FAKE_IPSET_STATE": str(self.state),
                "FAKE_IPSET_LOG": str(self.log),
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

    def sets(self, value=None):
        if value is not None:
            self.state.write_text(json.dumps(value), encoding="utf-8")
        return {name: set(members) for name, members in json.loads(self.state.read_text()).items()}

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def banned(self, addresses):
        return mock.patch.object(controld, "get_banned_ips_from_haproxy", return_value=set(addresses))

    def authorized(self, addresses):
        return mock.patch.object(controld, "get_authorized_ips_from_haproxy", return_value=addresses)


@unittest.skipUnless(POSIX, "runs a fake ipset as a real process")
class IpsetSync(FakeIpsetCase):
    def test_the_whole_difference_goes_in_one_restore(self):
        ban = controld.IPSET_NAME
        self.sets({ban: ["192.0.2.3", "192.0.2.4"]})
        with self.banned({"192.0.2.1", "192.0.2.2", "192.0.2.3"}):
            controld.sync_bans_once()
        self.assertEqual(self.sets()[ban], {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        calls = self.calls()
        self.assertEqual([call["argv"] for call in calls], [["list", ban], ["-exist", "restore"]])
        # Deletions first, so a full set makes room before it takes new entries.
        self.assertEqual(
            calls[1]["stdin"],
            f"del {ban} 192.0.2.4\nadd {ban} 192.0.2.1\nadd {ban} 192.0.2.2\n",
        )

    def test_a_set_in_step_is_only_read(self):
        ban = controld.IPSET_NAME
        self.sets({ban: ["192.0.2.1"]})
        with self.banned({"192.0.2.1"}):
            controld.sync_bans_once()
        self.assertEqual([call["argv"] for call in self.calls()], [["list", ban]])

    def test_one_malformed_address_does_not_cost_the_rest(self):
        ban = controld.IPSET_NAME
        self.sets({ban: []})
        with self.banned({"192.0.2.1", "999.1.1.1"}), self.assertLogs("haproxy-controld", "WARNING") as logs:
            controld.sync_bans_once()
        self.assertEqual(self.sets()[ban], {"192.0.2.1"})
        self.assertIn("999.1.1.1", "\n".join(logs.output))

    def test_a_refused_batch_is_logged_not_raised(self):
        # The set is gone: the listing fails and so does the batch.
        with self.banned({"192.0.2.1"}), self.assertLogs("haproxy-controld", "WARNING") as logs:
            controld.sync_bans_once()
        self.assertTrue(any("Failed to update ipset" in line for line in logs.output))
        self.assertFalse(any("Sync done" in line for line in logs.output))

    def test_a_hung_ipset_does_not_hold_the_sync(self):
        ban = controld.IPSET_NAME
        self.sets({ban: []})
        for hung in ("restore", "list"):
            with self.subTest(hung=hung):
                started = time.monotonic()
                with (
                    mock.patch.dict(os.environ, {"FAKE_IPSET_HANG": hung}),
                    mock.patch.object(controld, "IPSET_TIMEOUT_SECONDS", 1),
                    self.banned({"192.0.2.1"}),
                    self.assertLogs("haproxy-controld", "WARNING"),
                ):
                    controld.sync_bans_once()
                self.assertLess(time.monotonic() - started, 10)

    def test_the_authorized_set_is_kept_the_same_way(self):
        auth = controld.AUTH_IPSET
        self.sets({auth: ["192.0.2.2", "192.0.2.3"]})
        with self.authorized({"192.0.2.1", "192.0.2.2"}):
            controld.sync_auth_once()
        self.assertEqual(self.sets()[auth], {"192.0.2.1", "192.0.2.2"})
        self.assertEqual(
            [call["argv"] for call in self.calls()], [["list", auth], ["-exist", "restore"]]
        )

    def test_a_failed_table_read_leaves_the_authorized_set_alone(self):
        self.sets({controld.AUTH_IPSET: ["192.0.2.2"]})
        with self.authorized(None):
            controld.sync_auth_once()
        self.assertEqual(self.calls(), [])

    def test_the_sets_are_created_and_a_hung_create_gives_up(self):
        controld.ensure_ipset()
        controld.ensure_auth_ipset()
        self.assertEqual(set(self.sets()), {controld.IPSET_NAME, controld.AUTH_IPSET})
        started = time.monotonic()
        with (
            mock.patch.dict(os.environ, {"FAKE_IPSET_HANG": "create"}),
            mock.patch.object(controld, "IPSET_TIMEOUT_SECONDS", 1),
        ):
            with self.assertRaises(controld.subprocess.TimeoutExpired):
                controld.ensure_auth_ipset()
        self.assertLess(time.monotonic() - started, 10)


FAKE_SOCAT = """\
import os, sys
request = sys.stdin.read().split()
table = request[2] if len(request) > 2 else ""
mode = os.environ.get("FAKE_SOCAT_MODE", "ok")
if mode == "fail":
    print("socat: connect: No such file or directory", file=sys.stderr)
    sys.exit(1)
if mode == "missing":
    print("No such table")
    print()
    sys.exit(0)
print(f"# table: {table}, type: ip, size:204800, used:3")
if mode == "ok":
    print("0x1: key=192.0.2.1 use=0 exp=1000 shard=0 gpt0=40 gpc0=1")
    print("0x2: key=192.0.2.2 use=0 exp=1000 shard=0 gpt0=0 gpc0=0")
    print("0x3: key=192.0.2.3 use=0 exp=1000 shard=0 gpt0=40 gpc0=2")
"""


class AnUnreadTableIsNotAnEmptyOne(FakeIpsetCase):
    """HAProxy's answer decides the sets only when it is the table itself."""

    def setUp(self):
        super().setUp()
        socat = Path(os.environ["PATH"].split(os.pathsep)[0]) / "socat"
        socat.write_text(f"#!{sys.executable}\n" + FAKE_SOCAT, encoding="utf-8")
        socat.chmod(0o755)

    def sync(self, mode):
        with mock.patch.dict(os.environ, {"FAKE_SOCAT_MODE": mode}):
            controld.sync_bans_once()
            controld.sync_auth_once()

    def test_the_table_decides_both_sets(self):
        self.sets({controld.IPSET_NAME: ["192.0.2.9"], controld.AUTH_IPSET: ["192.0.2.9"]})
        self.sync("ok")
        wanted = {"192.0.2.1", "192.0.2.3"}
        self.assertEqual(self.sets(), {controld.IPSET_NAME: wanted, controld.AUTH_IPSET: wanted})

    def test_an_empty_table_empties_the_sets(self):
        self.sets({controld.IPSET_NAME: ["192.0.2.9"], controld.AUTH_IPSET: ["192.0.2.9"]})
        self.sync("empty")
        self.assertEqual(self.sets(), {controld.IPSET_NAME: set(), controld.AUTH_IPSET: set()})

    def test_no_such_table_or_a_failed_read_changes_nothing(self):
        for mode in ("missing", "fail"):
            with self.subTest(mode=mode):
                before = {controld.IPSET_NAME: ["192.0.2.9"], controld.AUTH_IPSET: ["192.0.2.8"]}
                self.sets(before)
                self.log.write_text("", encoding="utf-8")
                with self.assertLogs("haproxy-controld", "WARNING"):
                    self.sync(mode)
                self.assertEqual(self.sets(), {name: set(v) for name, v in before.items()})
                self.assertEqual(self.calls(), [])


@unittest.skipUnless(POSIX, "runs fake commands as real processes")
class ReloadAndCheckAreBounded(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def script(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)
        return path

    def reload_with(self, systemctl):
        with (
            mock.patch.object(controld, "SYSTEMCTL_CMD", f"{systemctl} reload haproxy"),
            mock.patch.object(controld, "STATE_DUMP_CMD", str(self.root / "no-state-dump")),
            mock.patch.object(controld, "HAPROXY_RELOAD_TIMEOUT_SECONDS", 1),
        ):
            return controld.cmd_reload()

    def test_a_reload_that_hangs_is_a_failed_reload(self):
        started = time.monotonic()
        ok, message = self.reload_with(self.script("systemctl", "exec sleep 60\n"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(ok)
        self.assertIn("did not finish within 1 seconds", message)

    def test_a_reload_that_finishes_is_answered_as_before(self):
        self.assertEqual(self.reload_with(self.script("systemctl", "echo reloaded\n")), (True, "reloaded"))
        ok, message = self.reload_with(self.script("systemctl", "echo broken >&2; exit 1\n"))
        self.assertEqual((ok, message), (False, "broken"))

    def check_with(self, haproxy):
        config = base64.b64encode(b"global\n").decode("ascii")
        with (
            mock.patch.object(controld, "HAPROXY_BIN", str(haproxy)),
            mock.patch.object(controld, "HAPROXY_CHECK_TIMEOUT_SECONDS", 1),
            mock.patch.object(controld, "_enforce_config_policy"),
        ):
            return controld.haproxy_check_config_from_b64(config)

    def test_a_config_check_that_hangs_is_a_failed_check(self):
        started = time.monotonic()
        rc, _stdout, stderr = self.check_with(self.script("haproxy", "exec sleep 60\n"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(rc, 124)
        self.assertIn("did not finish within 1 seconds", stderr)

    def test_a_config_check_that_finishes_is_answered_as_before(self):
        haproxy = self.script("haproxy", 'echo "$1 $2"; echo warn >&2; exit 2\n')
        self.assertEqual(self.check_with(haproxy), (2, "-c -f\n", "warn\n"))


class EveryCommandIsBounded(unittest.TestCase):
    def test_controld_runs_nothing_without_a_time_limit(self):
        tree = ast.parse(DAEMON.read_text(encoding="utf-8"))
        unbounded = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_subprocess = (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in {"run", "call", "check_call", "check_output", "Popen"}
            )
            is_runner = isinstance(func, ast.Name) and func.id == "run_cmd"
            if (is_subprocess or is_runner) and not any(k.arg == "timeout" for k in node.keywords):
                unbounded.append(node.lineno)
        self.assertEqual(unbounded, [])

    def test_ipset_is_never_run_once_per_address(self):
        source = DAEMON.read_text(encoding="utf-8")
        self.assertNotIn('"ipset", "add"', source)
        self.assertNotIn('"ipset", "del"', source)


if __name__ == "__main__":
    unittest.main()
