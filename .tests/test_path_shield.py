"""HAProxy refuses a decisive signature itself, from lists the engine keeps (P4).

A ban follows the log: by the time it lands, the request that earned it has
been answered. For a decisive category -- an .env file, a git store, a
database dump -- that first request is the one that matters: if a site really
does serve the file, the probe has it before the address is banned. Measured
on a production gateway, an address makes up to eleven findings in the ten
seconds before its ban.

HAProxy now refuses those requests itself, from three lists it reads at
request time. Held here: the lists are exactly what a single request is
banned for anyway and nothing at all unless the engine is enforcing; a list
is replaced whole; a failure never stops a cycle; and the configuration names
the lists where the engine looks for them.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
sys.path.insert(0, str(ROOT / "docker" / "app"))
if sys.platform != "win32":
    import test_guardd as base
    guardd = base.guardd
    # Taken when this module loads, as the other panel tests do: some tests
    # put a stand-in package under this name while they run.
    import haproxy_admin as panel
    from haproxy_admin import create_app, routes_security, services_security
else:
    base = guardd = panel = create_app = routes_security = services_security = None

FILES = {"segments": "/etc/haproxy/guardd-shield-segments.lst", "paths": "/etc/haproxy/guardd-shield-paths.lst",
         "exempt": "/etc/haproxy/guardd-shield-exempt.lst"}
MARKER = "    # guardd-shield segments={segments} paths={paths} exempt={exempt}\n".format(**FILES)
NOW = 1_800_000_000


class FakeHAProxy:
    """The runtime socket, as far as lists go: show, prepare, add, commit."""

    def __init__(self):
        self.lists = {name: set() for name in FILES.values()}
        self.staged = {}
        self.commands = []
        self.fail_on = None

    def __call__(self, _socket, command):
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            raise OSError("the runtime socket is gone")
        words = command.split()
        if words[:2] == ["show", "acl"]:
            if words[2] not in self.lists:
                return "Unknown ACL identifier. Please use #<id> or <file>.\n"
            return "".join(f"0x{index:012x} {value}\n" for index, value in enumerate(sorted(self.lists[words[2]]), 1))
        if words[:2] == ["prepare", "acl"]:
            version = len(self.staged) + 1
            self.staged[str(version)] = set()
            return f"New version created: {version}\n"
        if words[:2] == ["add", "acl"]:
            self.staged[words[2].lstrip("@")].add(words[4])
            return ""
        if words[:2] == ["commit", "acl"]:
            self.lists[words[3]] = self.staged.pop(words[2].lstrip("@"))
            return ""
        return "Unknown command.\n"

    def writes(self):
        return [c for c in self.commands if not c.startswith("show ")]


@unittest.skipUnless(guardd, "Linux engine")
class WhatIsRefused(unittest.TestCase):
    def entries(self, mode="enforce", enabled=True, modes=None, exceptions=()):
        return guardd.shield_entries(mode, enabled, modes or {}, list(exceptions), NOW)

    def test_the_decisive_signatures_and_only_those(self):
        found = self.entries()
        self.assertIn(".env", found["segments"])
        self.assertIn(".git", found["segments"])
        self.assertIn("/.git/config", found["paths"])
        for probable in ("wp-login.php", "phpmyadmin", "actuator", "cgi-bin", "vendor"):
            self.assertNotIn(probable, found["segments"])
        for token in found["segments"]:
            category = guardd.SCANNER_SEGMENTS.get(token) or next(
                c for t, c in guardd.SCANNER_SEGMENTS.items() if t.lower() == token)
            self.assertTrue(guardd.category_is_decisive(category), token)

    def test_nothing_unless_the_engine_is_enforcing(self):
        for mode in ("monitor", "off"):
            found = self.entries(mode=mode)
            self.assertEqual((found["segments"], found["paths"], found["exempt"]), (set(), set(), set()), mode)

    def test_nothing_when_the_shield_is_switched_off(self):
        self.assertEqual(self.entries(enabled=False)["segments"], set())

    def test_a_rule_the_operator_only_observes_is_not_refused(self):
        found = self.entries(modes={"path:vcs": "observe"})
        self.assertNotIn(".git", found["segments"])
        self.assertIn(".env", found["segments"])

    def test_a_site_with_an_exception_for_a_decisive_rule_is_left_out_whole(self):
        exception = {"rule": "path:vcs", "hosts": ["docker.example.test"], "expires": 0}
        expired = {"rule": "path:secrets", "hosts": ["old.example.test"], "expires": NOW - 1}
        probable = {"rule": "path:wordpress", "hosts": ["blog.example.test"], "expires": 0}
        found = self.entries(exceptions=[exception, expired, probable])
        self.assertEqual(found["exempt"], {"docker.example.test"})

    def test_a_suppressed_signature_leaves_the_shield_with_it(self):
        with mock.patch.dict(guardd.SCANNER_SEGMENTS, clear=False) as live:
            live.pop(".env")
            self.assertNotIn(".env", self.entries()["segments"])

    def test_an_operators_decisive_signature_joins_it(self):
        with mock.patch.dict(guardd.SCANNER_SEGMENTS, {"Acme-Console": "secrets"}), \
                mock.patch.dict(guardd.SCANNER_PATHS, {"/private/export": "backup"}):
            found = self.entries()
        self.assertIn("acme-console", found["segments"])
        self.assertIn("/private/export", found["paths"])

    def test_nothing_the_runtime_socket_would_read_as_its_own_gets_in(self):
        hostile = {"a b": "secrets", "x;clear table tbl_ban": "secrets", "dump*": "backup", "ok.sql": "backup"}
        with mock.patch.dict(guardd.SCANNER_SEGMENTS, hostile), \
                mock.patch.dict(guardd.SCANNER_PATHS, {"/a b": "secrets", "/x;y": "secrets", "/fine.sql": "backup"}):
            found = self.entries()
        self.assertIn("ok.sql", found["segments"])
        self.assertIn("/fine.sql", found["paths"])
        for value in found["segments"] | found["paths"]:
            self.assertNotRegex(value, r"[\s;*]")
        self.assertIn("a b", found["skipped"])
        self.assertNotIn("dump*", found["skipped"])  # a wildcard is the engine's, not an error

    def test_an_absurd_list_is_refused_rather_than_sent(self):
        many = {f"secret-{index}": "secrets" for index in range(guardd.SHIELD_MAX_ENTRIES + 1)}
        with mock.patch.dict(guardd.SCANNER_SEGMENTS, many):
            with self.assertRaises(ValueError):
                self.entries()


@unittest.skipUnless(guardd, "Linux engine")
class KeepingHAProxyInStep(unittest.TestCase):
    def setUp(self):
        base.EngineTestCase.setUp(self)
        self.cfg = Path(self.log).with_name("haproxy.cfg")
        self.cfg.write_text("frontend fe_https\n" + MARKER, encoding="utf-8")
        self.engine.shield.config_path = str(self.cfg)
        self.haproxy = FakeHAProxy()
        patcher = mock.patch.object(guardd, "runtime_command", self.haproxy)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engine.enforcer.mode = guardd.MODE_ENFORCE

    def test_enforcing_fills_the_lists(self):
        state = self.engine.sync_shield(NOW)
        self.assertTrue(state["configured"])
        self.assertTrue(state["active"])
        self.assertIsNone(state["error"])
        self.assertIn(".env", self.haproxy.lists[FILES["segments"]])
        self.assertIn("/.git/config", self.haproxy.lists[FILES["paths"]])
        self.assertEqual(state["segments"], len(self.haproxy.lists[FILES["segments"]]))

    def test_a_list_already_in_step_is_not_touched(self):
        self.engine.sync_shield(NOW)
        written = len(self.haproxy.writes())
        self.engine.sync_shield(NOW + 10)
        self.assertEqual(len(self.haproxy.writes()), written)

    def test_a_reloaded_haproxy_is_filled_again(self):
        self.engine.sync_shield(NOW)
        for name in self.haproxy.lists:
            self.haproxy.lists[name] = set()  # what a reload leaves: the empty files
        self.engine.sync_shield(NOW + 10)
        self.assertIn(".env", self.haproxy.lists[FILES["segments"]])

    def test_a_list_is_replaced_whole_and_at_once(self):
        self.haproxy.lists[FILES["segments"]] = {"stale-entry"}
        self.engine.sync_shield(NOW)
        self.assertNotIn("stale-entry", self.haproxy.lists[FILES["segments"]])
        segment_writes = [c for c in self.haproxy.writes() if FILES["segments"] in c]
        self.assertTrue(segment_writes[0].startswith("prepare acl "))
        self.assertTrue(segment_writes[-1].startswith("commit acl @"))
        self.assertTrue(all(c.startswith("add acl @") for c in segment_writes[1:-1]))

    def test_leaving_enforce_empties_them_before_the_switch_answers(self):
        self.engine.sync_shield(NOW)
        # The ban table is another test's subject; here only the lists matter.
        with mock.patch.object(self.engine, "_apply_enforcement", return_value={"applied": [], "lifted": []}):
            self.engine.set_mode("monitor", NOW + 1)
        self.assertEqual(self.haproxy.lists[FILES["segments"]], set())
        self.assertEqual(self.haproxy.lists[FILES["paths"]], set())
        self.assertFalse(self.engine.shield_state()["active"])

    def test_the_switch_is_remembered_and_acts_at_once(self):
        self.engine.sync_shield(NOW)
        state = self.engine.set_shield(False, NOW + 1)
        self.assertFalse(state["enabled"])
        self.assertEqual(self.haproxy.lists[FILES["segments"]], set())
        self.assertEqual(self.database.get_state(guardd.SHIELD_ENABLED_KEY, ""), "0")
        again = guardd.GuardEngine(self.config, self.database)
        self.assertFalse(again.shield_enabled)
        self.engine.set_shield(True, NOW + 2)
        self.assertIn(".env", self.haproxy.lists[FILES["segments"]])

    def test_only_true_or_false_switches_it(self):
        for value in (1, "on", None, "true"):
            with self.assertRaises(ValueError):
                self.engine.set_shield(value)

    def test_a_configuration_without_the_shield_is_left_alone(self):
        self.cfg.write_text("frontend fe_https\n", encoding="utf-8")
        state = self.engine.sync_shield(NOW)
        self.assertFalse(state["configured"])
        self.assertEqual(self.haproxy.commands, [])

    def test_a_socket_that_fails_is_reported_and_stops_nothing(self):
        self.haproxy.fail_on = "prepare acl"
        state = self.engine.sync_shield(NOW)
        self.assertIn("runtime socket", state["error"])
        self.assertFalse(state["active"])
        self.haproxy.fail_on = None
        self.assertIsNone(self.engine.sync_shield(NOW + 10)["error"])

    def test_a_list_haproxy_does_not_know_is_an_error_not_an_empty_list(self):
        del self.haproxy.lists[FILES["paths"]]
        state = self.engine.sync_shield(NOW)
        self.assertIn("did not return the list", state["error"])

    def test_exemptions_arrive_before_the_lists_that_refuse(self):
        self.engine.detection.config = guardd.validate_detection_config({
            "version": 1, "exceptions": [{"id": "exception:docker", "rule": "path:vcs",
                                           "hosts": ["docker.example.test"], "match": "prefix", "value": "/repos",
                                           "reason": "A git server behind the gateway"}]})
        self.engine.sync_shield(NOW)
        self.assertEqual(self.haproxy.lists[FILES["exempt"]], {"docker.example.test"})
        commits = [c for c in self.haproxy.writes() if c.startswith("commit acl")]
        self.assertIn(FILES["exempt"], commits[0])

    def test_health_says_what_the_shield_holds(self):
        self.engine.sync_shield(NOW)
        state = self.engine.health()["path_shield"]
        self.assertEqual((state["enabled"], state["mode"], state["active"]), (True, "enforce", True))
        self.assertGreater(state["segments"], 0)

    def test_the_cycle_keeps_it_in_step(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        poll = source[source.index("    def poll(self) -> Dict[str, int]:"):source.index("    def read_tables(self)")]
        self.assertIn("self.sync_shield(now)", poll)


class OnlyTheShieldChangesAList(unittest.TestCase):
    def test_list_commands_live_in_one_class(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py").read_text(encoding="utf-8")
        start = source.index("class PathShield:")
        end = source.index("class Enforcer:")
        outside = source[:start] + source[end:]
        for line in outside.splitlines():
            code = line.split("#", 1)[0]
            for command in ("prepare acl", "commit acl", "add acl", "del acl", "clear acl"):
                self.assertNotIn(command, code, line.strip()[:100])


class TheConfiguration(unittest.TestCase):
    def setUp(self):
        self.template = (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(encoding="utf-8")
        self.block = self.template[self.template.index("{% if guardd_shield | default(true) %}"):]
        self.block = self.block[:self.block.index("{% endif %}\n", self.block.index("guardd_shield_path !guardd_shield_exempt")) + 12]

    def test_it_names_the_lists_where_the_engine_looks(self):
        self.assertIn("# guardd-shield segments={{ shield_dir }}/guardd-shield-segments.lst "
                      "paths={{ shield_dir }}/guardd-shield-paths.lst exempt={{ shield_dir }}/guardd-shield-exempt.lst",
                      self.block)
        if guardd:
            rendered = MARKER
            self.assertEqual(guardd.SHIELD_MARKER.search(rendered).groupdict(), FILES)

    def test_it_matches_as_the_engine_does(self):
        # A whole segment in any case after one decoding; a whole path exactly.
        self.assertIn("acl guardd_shield_segment path,url_dec -m dir -i -f", self.block)
        self.assertIn("acl guardd_shield_path path,url_dec -m str -f", self.block)
        self.assertIn("acl guardd_shield_exempt req.hdr(host),lower,field(1,:) -m str -f", self.block)

    def test_whoever_is_not_banned_is_not_refused(self):
        trusted = ("!guardd_shield_exempt !ip_whitelist{% if admin_ips_enabled %} !allowed_admin{% endif %}"
                   "{% if authelia_enabled %} !ip_auth_ok{% endif %}")
        self.assertEqual(self.block.count("http-request deny deny_status 404 if guardd_shield_"), 2)
        self.assertEqual(self.block.count(trusted), 2)

    def test_it_sits_in_the_https_frontend_after_the_lists_it_needs(self):
        frontend = self.template[self.template.index("frontend fe_https"):self.template.index("frontend fe_http80")]
        self.assertLess(frontend.index("acl ip_auth_ok"), frontend.index("guardd_shield_segment"))
        self.assertLess(frontend.index("guardd_shield_segment"), frontend.index("use_backend"))

    def test_the_lists_exist_before_the_configuration_is_checked(self):
        import yaml

        tasks = yaml.safe_load((ROOT / "ansible/roles/haproxy/tasks/config.yml").read_text(encoding="utf-8"))
        names = [task.get("name", "") for task in tasks]
        make = names.index("path shield | Ensure the empty list files exist")
        self.assertLess(make, names.index("Copy HAProxy configuration"))
        task = tasks[make]
        self.assertEqual(sorted(task["loop"]),
                         ["guardd-shield-exempt.lst", "guardd-shield-paths.lst", "guardd-shield-segments.lst"])
        self.assertIs(task["ansible.builtin.copy"]["force"], False)
        self.assertEqual(task["ansible.builtin.copy"]["content"], "")

    def test_the_package_smoke_test_makes_them_too(self):
        smoke = (ROOT / ".tests/integration/haproxy_package_smoke.py").read_text(encoding="utf-8")
        for name in ("guardd-shield-segments.lst", "guardd-shield-paths.lst", "guardd-shield-exempt.lst"):
            self.assertIn(name, smoke)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(sys.platform == "win32", "the admin package needs fcntl")
class ThePanel(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile

        self.routes = routes_security
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        env = mock.patch.dict(os.environ, {"HAPROXY_ADMIN_PROXY_SECRET": "shield-test-proxy",
                                           "HAPROXY_ADMIN_SECRET_KEY": "shield-test-session",
                                           "AUDIT_DATABASE": str(Path(folder.name) / "audit.db")})
        env.start()
        self.addCleanup(env.stop)
        with mock.patch.object(panel, "ensure_whitelist_file"):
            app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()
        self.superadmin = {"X-Easy-HA-Proxy-Secret": "shield-test-proxy", "Remote-User": "root-admin",
                           "Remote-Groups": "superadmin"}
        self.admin = {**self.superadmin, "Remote-User": "helper", "Remote-Groups": "admins"}
        self.state = {"ok": True, "path_shield": {"enabled": False, "segments": 0, "paths": 0}}
        self.real_set_shield = routes_security.security.set_shield
        patcher = mock.patch.object(routes_security.security, "set_shield", return_value=self.state)
        self.set_shield = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(routes_security, "record_request")
        self.record = patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, body, headers=None):
        return self.client.post("/api/security/adaptive/shield", json=body, headers=headers or self.superadmin)

    def test_a_superadmin_switches_it_and_the_change_is_recorded(self):
        response = self.post({"enabled": False})
        self.assertEqual(response.status_code, 200)
        self.set_shield.assert_called_once_with(False)
        self.assertEqual(self.record.call_args.args[0], "adaptive.shield")
        self.assertEqual(self.record.call_args.kwargs["after"], {"enabled": False})

    def test_an_ordinary_administrator_cannot(self):
        response = self.post({"enabled": False}, self.admin)
        self.assertEqual(response.status_code, 403)
        self.set_shield.assert_not_called()

    def test_anything_but_true_or_false_is_refused_before_the_engine_is_asked(self):
        with mock.patch.object(services_security, "guardd_set_shield") as engine:
            for value in ("yes", 1, None):
                with self.assertRaises(ValueError):
                    self.real_set_shield(value)
            engine.assert_not_called()
            self.real_set_shield(True)
            engine.assert_called_once_with(True)

    def test_the_page_has_the_switch_and_its_sentences_are_translated_whole(self):
        import json

        app = ROOT / "docker/app/haproxy_admin"
        page = (app / "templates/adaptive_protection.html").read_text(encoding="utf-8")
        script = (app / "static/js/adaptive_protection.js").read_text(encoding="utf-8")
        catalogue = json.loads((app / "translations/ru/adaptive_protection.json").read_text(encoding="utf-8"))["messages"]
        self.assertIn('id="ap-shield-toggle"', page)
        self.assertIn('fetch("/api/security/adaptive/shield"', script)
        import re

        for sentence in re.findall(r'uiText\(\s*(?:state\.enabled \? )?"([^"]+)"(?: : "([^"]+)")?', script[script.index("function renderShield"):script.index("async function loadShield")]):
            for part in sentence:
                if part:
                    self.assertIn(part, catalogue, part)
        self.assertIn("First-request shield", catalogue)
