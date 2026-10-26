"""The User-Agent in the access log, and the scanners that name themselves.

Plenty of attack tools announce themselves -- sqlmap, nikto, nuclei -- and the
log never carried the header, so the engine could not see it. The template
now logs it as one labelled word before the request line: everything outside
[A-Za-z0-9./;:_-] becomes "_", so a hostile header cannot split the line or
forge another field, and it is cut to 128 characters.

req.fhdr, not req.hdr: req.hdr splits a header at commas and returns the last
piece, which for every browser is "like Gecko) Chrome/..." -- found by
sending a real browser string through HAProxy 2.8.

An attack tool is decisive. An internet-wide survey only counts towards a
ban. Generic libraries such as curl are not scored at all: monitors use them.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
TEMPLATE = (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(encoding="utf-8")
SIGNATURES = ROOT / "ansible/roles/haproxy-admin/files/scanner-signatures.json"


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_user_agent", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()


def line(ip, ua=None, path="/", status=404, uri=None):
    agent = "" if ua is None else f" ua={ua}"
    return (
        f"2026-10-26T07:00:00.000000+00:00 host haproxy[1]: "
        f"{ip}:1234 [26/Oct/2026:07:00:00.000] fe_https~ be_shop/srv1 "
        f"0/0/0/1/1 {status} 100 ---- 1/1/0/0/0 0/0 id=abc host=shop.example.test{agent} "
        f"GET {uri or path} HTTP/1.1"
    )


class Parser(unittest.TestCase):
    def test_the_field_is_read(self):
        parsed = guardd.parse_access_line(line("203.0.113.1", "sqlmap/1.7.2_stable__https://sqlmap.org_"))
        self.assertEqual(parsed.user_agent, "sqlmap/1.7.2_stable__https://sqlmap.org_")
        self.assertEqual(parsed.host, "shop.example.test")
        self.assertEqual(parsed.request_id, "abc")
        self.assertEqual(parsed.path, "/")

    def test_an_older_line_without_the_field_still_parses(self):
        parsed = guardd.parse_access_line(line("203.0.113.1"))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.user_agent, "")

    def test_no_header_is_empty(self):
        self.assertEqual(guardd.parse_access_line(line("203.0.113.1", "-")).user_agent, "")

    def test_the_request_line_cannot_supply_one(self):
        parsed = guardd.parse_access_line(line("203.0.113.1", uri="/x?a=1&ua=sqlmap"))
        self.assertEqual(parsed.user_agent, "")


class Classify(unittest.TestCase):
    def test_attack_tools_are_decisive(self):
        for value in ("sqlmap/1.7.2_stable__https://sqlmap.org_",
                      "Mozilla/5.00__Nikto/2.5.0",
                      "Fuzz_Faster_U_Fool_v2.1.0",
                      "Mozilla/5.0__compatible;_Nmap_Scripting_Engine;_https://nmap.org/book/nse.html_"):
            with self.subTest(value=value):
                token, category = guardd.classify_user_agent(value)
                self.assertTrue(token)
                self.assertTrue(guardd.category_is_decisive(category))

    def test_surveys_are_only_probable(self):
        token, category = guardd.classify_user_agent("Mozilla/5.0_zgrab/0.x")
        self.assertEqual(category, "survey")
        self.assertFalse(guardd.category_is_decisive(category))

    def test_browsers_and_libraries_are_not_scored(self):
        for value in ("Mozilla/5.0__Windows_NT_10.0;_Win64;_x64__AppleWebKit/537.36__KHTML__like_Gecko__Chrome/120.0.0.0_Safari/537.36",
                      "curl/8.5.0", "python-requests/2.31.0", "Go-http-client/1.1", "", "-"):
            with self.subTest(value=value):
                self.assertEqual(guardd.classify_user_agent(value), ("", ""))

    def test_tokens_too_short_to_be_safe_are_dropped(self):
        compiled = guardd._compile_user_agents({"ab": "scanner-tool", "sqlmap": "scanner-tool"})
        self.assertEqual(list(compiled), ["sqlmap"])


class ShippedFile(unittest.TestCase):
    def test_the_file_carries_the_list_and_scanner_tool_is_decisive(self):
        data = json.loads(SIGNATURES.read_text(encoding="utf-8"))
        self.assertIn("scanner-tool", data["decisive"])
        self.assertNotIn("survey", data["decisive"])
        self.assertIn("sqlmap", data["user_agents"])
        # The file and the built-in fallback say the same thing.
        self.assertEqual(data["user_agents"], guardd.DEFAULT_USER_AGENTS)

    def test_loading_the_file_publishes_it_in_the_summary(self):
        self.assertTrue(guardd.load_signatures(str(SIGNATURES)))
        rules = {r["token"]: r for r in guardd.signature_summary()["user_agents"]}
        self.assertTrue(rules["sqlmap"]["decisive"])
        self.assertFalse(rules["zgrab"]["decisive"])

    def test_a_file_without_the_key_keeps_the_built_ins(self):
        data = json.loads(SIGNATURES.read_text(encoding="utf-8"))
        del data["user_agents"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(data, handle)
        self.addCleanup(Path(handle.name).unlink)
        self.assertTrue(guardd.load_signatures(handle.name))
        self.assertEqual(guardd.classify_user_agent("sqlmap/1.7")[1], "scanner-tool")


class Engine(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.log = root / "haproxy.log"
        self.log.write_text("", encoding="utf-8")
        whitelist = root / "whitelist.ip"
        whitelist.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(self.log), whitelist_files=(str(whitelist),))
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.engine = guardd.GuardEngine(config, self.database)
        self.engine.cursor.read(4096)

    def feed(self, *lines, now=1000):
        with self.log.open("a", encoding="utf-8") as handle:
            for text in lines:
                handle.write(text + "\n")
        self.engine.ingest_log(now)

    def events(self, ip):
        return [(e["event_type"], e["category"]) for e in self.database.events_for(ip, 0)]

    def test_one_sqlmap_request_reaches_the_ban_line(self):
        self.feed(line("203.0.113.9", "sqlmap/1.7.2_stable__https://sqlmap.org_", status=200))
        self.assertEqual(self.events("203.0.113.9"),
                         [(guardd.EVENT_SCANNER_DECISIVE, "scanner-tool")])
        self.assertGreaterEqual(
            self.engine.reputation("203.0.113.9", 1000)["score"], guardd.WOULD_BAN_SCORE
        )

    def test_a_run_of_requests_is_one_finding(self):
        self.feed(*[line("203.0.113.9", "sqlmap/1.7", path="/index.php") for _ in range(30)])
        found = [e for e in self.events("203.0.113.9") if e[1] == "scanner-tool"]
        self.assertEqual(len(found), 1)

    def test_a_survey_alone_does_not_ban(self):
        self.feed(line("203.0.113.10", "Mozilla/5.0_zgrab/0.x"))
        self.assertEqual(self.events("203.0.113.10"), [(guardd.EVENT_SCANNER_PATH, "survey")])
        self.assertLess(self.engine.reputation("203.0.113.10", 1000)["score"], guardd.WOULD_BAN_SCORE)

    def test_curl_is_left_alone(self):
        self.feed(*[line("198.51.100.5", "curl/8.5.0", status=200) for _ in range(5)])
        self.assertEqual(self.events("198.51.100.5"), [])


class Template(unittest.TestCase):
    def log_format(self):
        return re.search(r'log-format "([^"]*)"', TEMPLATE).group(1)

    def test_the_field_sits_between_host_and_the_request_line(self):
        fmt = self.log_format()
        self.assertLess(fmt.index("host="), fmt.index(" ua="))
        self.assertLess(fmt.index(" ua="), fmt.rindex(" %r"))
        self.assertTrue(fmt.endswith(" %r"))
        self.assertIn("{% if log_user_agent | default(true) %} ua=%[var(txn.log_ua)]{% endif %}", fmt)

    def test_both_frontends_capture_the_whole_header_as_one_word(self):
        captures = re.findall(r"http-request set-var\(txn\.log_ua\) (\S+)", TEMPLATE)
        self.assertEqual(len(captures), 2)
        for capture in captures:
            with self.subTest(capture=capture):
                # fhdr: hdr would split "(KHTML, like Gecko)" at the comma.
                self.assertTrue(capture.startswith("req.fhdr(user-agent)"))
                self.assertIn("bytes(0,128)", capture)
                self.assertIn("regsub([^A-Za-z0-9./;:_-],_,g)", capture)

    def test_the_switch_is_declared(self):
        defaults = (ROOT / "ansible/roles/haproxy/defaults/main.yml").read_text(encoding="utf-8")
        self.assertIn("log_user_agent: true", defaults)


class Rendered(unittest.TestCase):
    def render(self, **extra):
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:  # pragma: no cover - the CI image has it
            self.skipTest("jinja2 is not installed")
        sys.path.insert(0, str(ROOT / "docker" / "app"))
        sys.path.insert(0, str(ROOT / "installer"))
        from haproxy_admin.services_haproxy_config import jinja_combine, jinja_regex_replace

        environment = Environment(
            loader=FileSystemLoader(str(ROOT / "ansible/roles/haproxy/templates")),
            trim_blocks=True, lstrip_blocks=True,
        )
        environment.filters["regex_replace"] = jinja_regex_replace
        environment.filters["combine"] = jinja_combine
        site = {"name": "shop", "domain": "shop.example.test",
                "backend_ip": "10.0.0.10", "backend_port": 8080}
        return environment.get_template("haproxy.cfg.j2").render(
            sites=[site], tcp_proxies=[], tcp=[], site_defaults={},
            admin_domain="admin.example.test", aut_domain="auth.example.test",
            authelia_enabled=True, enable_geoip=False,
            easy_ha_proxy_runtime_vars={}, easy_ha_proxy_runtime_websites={},
            # Port 80 on too, so both frontends are rendered.
            easy_ha_proxy_runtime_tcp={}, enable_http80=True, **extra,
        )

    def test_on_by_default(self):
        config = self.render()
        self.assertIn(" ua=%[var(txn.log_ua)] %r", config)
        self.assertEqual(config.count("set-var(txn.log_ua)"), 2)

    def test_switched_off_it_leaves_no_trace(self):
        config = self.render(log_user_agent=False)
        self.assertNotIn("ua=", config)
        self.assertNotIn("txn.log_ua", config)
        self.assertIn(" host=%[var(txn.log_host)] %r", config)


class ThePage(unittest.TestCase):
    def test_the_rules_page_lists_them(self):
        page = (APP / "templates/detection_rules.html").read_text(encoding="utf-8")
        script = (APP / "static/js/detection_rules.js").read_text(encoding="utf-8")
        self.assertIn('id="dr-agents"', page)
        self.assertIn("signatures.user_agents", script)
        self.assertIn("renderAgents(signatures)", script)


if __name__ == "__main__":
    unittest.main()
