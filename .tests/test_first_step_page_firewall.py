"""The first step of an adaptive ban reaches HAProxy's page; the rest are dropped (P7).

A dropped connection says nothing to the person behind it: a false positive
looked like "the site is down", and was only ever found by a complaint. The
first step of an adaptive ban (reason code 41) is now answered by HAProxy
with a page naming the address, the time and a request code.

For that the firewall has to let it through. Every ban stays in the
haproxy_ban set -- the UDP forwards drop all of them -- and first steps are
also put in haproxy_ban_page, which the TCP rule for 80/443 leaves out.
Held here: the sets, the order they change in, the rule, and that a gateway
whose pieces are not all updated drops the address as before.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))
import test_controld_ipset as base  # noqa: E402

controld = base.controld
ROLE = ROOT / "ansible/roles/haproxy-admin"


class TheSets(base.FakeIpsetCase):
    def codes(self, mapping):
        return mock.patch.object(controld, "get_ban_codes_from_haproxy", return_value=dict(mapping))

    def test_a_first_step_is_in_both_sets_and_a_later_one_only_in_the_ban_set(self):
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: [], page: []})
        with self.codes({"192.0.2.1": 41, "192.0.2.2": 40, "192.0.2.3": 50}):
            controld.sync_bans_once()
        sets = self.sets()
        self.assertEqual(sets[ban], {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        self.assertEqual(sets[page], {"192.0.2.1"})

    def test_the_page_set_is_filled_before_the_ban_set(self):
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: [], page: []})
        with self.codes({"192.0.2.1": 41}):
            controld.sync_bans_once()
        restores = [call["stdin"] for call in self.calls() if call["argv"] == ["-exist", "restore"]]
        self.assertEqual(restores, [f"add {page} 192.0.2.1\n", f"add {ban} 192.0.2.1\n"])

    def test_a_first_step_going_on_to_the_next_leaves_the_page_set_last(self):
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: ["192.0.2.1"], page: ["192.0.2.1"]})
        with self.codes({"192.0.2.1": 40}):
            controld.sync_bans_once()
        self.assertEqual(self.sets()[page], set())
        self.assertEqual(self.sets()[ban], {"192.0.2.1"})

    def test_a_lifted_first_step_leaves_both(self):
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: ["192.0.2.1"], page: ["192.0.2.1"]})
        with self.codes({}), mock.patch.object(controld, "haproxy_uptime", return_value=3600):
            controld.sync_bans_once()
        restores = [call["stdin"] for call in self.calls() if call["argv"] == ["-exist", "restore"]]
        self.assertEqual(restores, [f"del {ban} 192.0.2.1\n", f"del {page} 192.0.2.1\n"])

    def test_after_a_restart_of_haproxy_a_first_step_is_dropped_rather_than_let_in(self):
        # The ban set is held for a minute after a restart; the page set is
        # not, so the address is dropped until it is put back -- never served.
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: ["192.0.2.1"], page: ["192.0.2.1"]})
        with self.codes({}), mock.patch.object(controld, "haproxy_uptime", return_value=5):
            controld.sync_bans_once()
        self.assertEqual(self.sets()[ban], {"192.0.2.1"})
        self.assertEqual(self.sets()[page], set())

    def test_an_unread_table_changes_neither_set(self):
        ban, page = controld.IPSET_NAME, controld.PAGE_IPSET
        self.sets({ban: ["192.0.2.1"], page: ["192.0.2.1"]})
        with mock.patch.object(controld, "get_ban_codes_from_haproxy", return_value=None):
            controld.sync_bans_once()
        self.assertEqual(self.calls(), [])


class TheTableReading(unittest.TestCase):
    def test_codes_are_read_from_the_same_answer(self):
        answer = ("# table: tbl_ban, type: ip, size:204800, used:3\n"
                  "0x1: key=192.0.2.1 use=0 exp=1000 shard=0 gpt0=41 gpc0=1\n"
                  "0x2: key=192.0.2.2 use=0 exp=1000 shard=0 gpt0=40 gpc0=0\n"
                  "0x3: key=192.0.2.3 use=0 exp=2000 shard=0 gpt0=40 gpc0=1\n")
        with mock.patch.object(controld, "run_cmd", return_value=mock.Mock(stdout=answer)):
            self.assertEqual(controld.get_ban_codes_from_haproxy(), {"192.0.2.1": 41, "192.0.2.3": 40})
            self.assertEqual(controld.get_banned_ips_from_haproxy(), {"192.0.2.1", "192.0.2.3"})


class TheFirewall(unittest.TestCase):
    def test_the_tcp_rule_drops_bans_that_are_not_first_steps(self):
        rules = (ROLE / "files/haproxy_ban.rules").read_text(encoding="utf-8")
        for port in ("80 ", "443"):
            self.assertIn(f"-A HP_BAN -p tcp -m set --match-set haproxy_ban src -m set ! --match-set haproxy_ban_page src --dport {port}", rules)
        self.assertEqual(rules.count("-j DROP"), 2)

    def test_the_page_set_exists_before_the_rules_are_loaded(self):
        unit = (ROLE / "templates/iptables-haproxy-ban.service.j2").read_text(encoding="utf-8")
        pre = [line for line in unit.splitlines() if line.startswith("ExecStartPre=")]
        self.assertIn("ExecStartPre=/usr/sbin/ipset create haproxy_ban_page hash:ip family inet -exist", pre)
        self.assertLess(unit.index("haproxy_ban_page hash:ip"), unit.index("ExecStart=/usr/sbin/iptables-legacy-restore"))
        tasks = (ROLE / "tasks/iptables-ban.yml").read_text(encoding="utf-8")
        self.assertLess(tasks.index("ipset create haproxy_ban_page"), tasks.index("Copy iptables rules file"))

    def test_udp_forwards_still_drop_every_ban(self):
        udp = (ROLE / "files/haproxy-udp-forward.py").read_text(encoding="utf-8")
        self.assertIn('BAN_SET = os.environ.get("HP_UDP_BAN_SET", "haproxy_ban")', udp)


class TheProxy(unittest.TestCase):
    def setUp(self):
        self.template = (ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2").read_text(encoding="utf-8")

    def test_the_router_lets_only_a_first_step_through(self):
        router = self.template[self.template.index("frontend fe_tls_router"):self.template.index("frontend fe_https")]
        self.assertIn("tcp-request connection reject if { src_get_gpc0(tbl_ban) gt 0 } !{ src_get_gpt0(tbl_ban) eq 41 }", router)

    def test_https_answers_a_first_step_with_the_page_before_refusing(self):
        https = self.template[self.template.index("frontend fe_https"):self.template.index("frontend fe_http80")]
        page = https.index("lf-file /etc/haproxy/errors/ban-first-step.html if already_banned ban_first_step")
        self.assertLess(page, https.index("http-request deny status 423 if already_banned"))
        self.assertIn("acl ban_first_step src_get_gpt0(tbl_ban) eq 41", https)
        self.assertIn('http-request return status 403 content-type "text/html; charset=utf-8" hdr Cache-Control no-store', https)

    def test_a_passthrough_site_refuses_every_ban_itself(self):
        start = self.template.index("backend be_{{ id }}_tcp")
        backend = self.template[start:self.template.index("{% endfor %}", start)]
        self.assertIn("tcp-request content reject if { src_get_gpc0(tbl_ban) gt 0 } !ip_whitelist", backend)
        self.assertNotIn("eq 41", backend)

    def test_a_rendered_passthrough_backend_keeps_each_directive_on_its_own_line(self):
        # Found on the test gateway: trim_blocks ate the newline after the
        # rule's closing {% endif %}, the next directive joined it, and
        # HAProxy refused the configuration ("no such ACL: 'default-server'").
        from test_site_allow_ips import render, site

        for options in ({"admin_ips_enabled": True, "authelia_enabled": True},
                        {"admin_ips_enabled": False, "authelia_enabled": False}):
            with self.subTest(options=options):
                config = render([site("files", "files.example.test", tcp_passthrough=True,
                                      backend_ip="192.0.2.10", backend_port=443)], **options)
                start = config.index("\nbackend be_files_tcp\n")
                backend = config[start:config.index("\nbackend ", start + 10)]
                [rule] = [line for line in backend.splitlines() if "tcp-request content reject" in line]
                self.assertTrue(rule.rstrip().endswith(("!ip_whitelist", "!ip_auth_ok", "!allowed_admin")), rule)
                self.assertIn("\n    default-server inter 3s rise 2 fall 3", backend)

    def test_tcp_proxies_still_refuse_every_ban(self):
        tcp = self.template[self.template.index("frontend fe_tcp_{{ san(t.name) }}"):]
        line = next(line for line in tcp.splitlines() if "tcp-request connection reject if { src_get_gpc0(tbl_ban)" in line)
        self.assertNotIn("eq 41", line)


class ThePage(unittest.TestCase):
    def render(self, language):
        from jinja2 import Environment

        source = (ROOT / "ansible/roles/haproxy/templates/ban_first_step.html.j2").read_text(encoding="utf-8")
        return Environment().from_string(source).render(haproxy_admin_default_language=language)

    def test_it_names_the_address_the_time_and_the_request_code(self):
        page = self.render("en")
        for field in ("%[src]", "%[date,http_date]", "%[unique-id]"):
            self.assertIn(field, page)
        self.assertIn("Access temporarily restricted", page)

    def test_it_follows_the_panel_language(self):
        self.assertIn("Доступ временно ограничен", self.render("ru"))
        self.assertIn('lang="en"', self.render("de"))

    def test_no_stray_percent_sign_breaks_the_log_format(self):
        page = self.render("en")
        stripped = page.replace("%[src]", "").replace("%[date,http_date]", "").replace("%[unique-id]", "")
        self.assertNotIn("%", stripped)

    def test_it_is_deployed_before_the_configuration_that_names_it(self):
        tasks = (ROOT / "ansible/roles/haproxy/tasks/install.yml").read_text(encoding="utf-8")
        self.assertIn("src: ban_first_step.html.j2", tasks)
        self.assertIn("dest: /etc/haproxy/errors/ban-first-step.html", tasks)
        smoke = (ROOT / ".tests/integration/haproxy_package_smoke.py").read_text(encoding="utf-8")
        self.assertIn("ban-first-step.html", smoke)


if __name__ == "__main__":
    unittest.main()
