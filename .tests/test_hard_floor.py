"""A hard floor on the HTTPS entry holds for everyone (U02, step 04.6b).

The plan's base rule, set by the operator on 31 October: trust changes the
answer to an ordinary excess, never the emergency protection -- a trusted
machine can be infected too. Before this the connection limits exempted the
whitelist and the admin addresses entirely, and there was no request ceiling
at all above the per-site soft limits.

The numbers were chosen on 3 November from a week of real traffic, where the
busiest legitimate address made 216 requests in 10 s with up to 98 in flight:
1000 requests in 10 s per address across all sites, 500 open connections,
and new connections in 10 s -- 200 for anonymous addresses as before, 1000
for trusted ones. The excess is refused at once; nobody is banned. Checked on
HAProxy 2.8.30 on the test host: the request counter of the connection-
tracked table counts every request on one keep-alive HTTP/1.1 connection and
every HTTP/2 stream (a ceiling of 5 refused the sixth request either way).
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402


def frontend(config, name="fe_https"):
    start = config.index(f"\nfrontend {name}\n")
    return config[start:].split("\nfrontend ", 2)[1]


def lines_with(block, text):
    return [line.strip() for line in block.splitlines() if text in line]


class TheFloor(unittest.TestCase):
    def setUp(self):
        self.config = render([site("shop", "shop.example.test", max_req_rate=200)],
                             admin_ips_enabled=True)
        self.https = frontend(self.config)

    def test_the_request_ceiling_is_for_everyone(self):
        [line] = lines_with(self.https, "sc0_http_req_rate(fe_https)")
        self.assertEqual(line, "http-request deny status 429 if { sc0_http_req_rate(fe_https) gt 1000 }")
        self.assertIn("http_req_rate(10s)", lines_with(self.https, "stick-table type ip")[0])

    def test_the_connection_ceilings_have_no_exemption(self):
        self.assertIn("tcp-request connection reject if conn_too_many", self.https)
        self.assertIn("tcp-request connection reject if conn_rate_hard", self.https)
        self.assertIn("acl conn_rate_hard  sc0_conn_rate(fe_https) gt 1000", self.https)
        for line in lines_with(self.https, "reject if conn_too_many") + lines_with(self.https, "reject if conn_rate_hard"):
            self.assertNotIn("!ip_whitelist", line)

    def test_the_ordinary_burst_spares_the_trusted(self):
        [line] = lines_with(self.https, "reject if conn_rate_burst")
        for trusted in ("!ip_whitelist", "!allowed_admin", "!ip_auth_ok"):
            self.assertIn(trusted, line)

    def test_it_comes_before_the_error_counters_and_the_sign_in(self):
        ceiling = self.https.index("sc0_http_req_rate(fe_https) gt")
        self.assertLess(ceiling, self.https.index("track-sc1"))
        self.assertLess(ceiling, self.https.index("lua."))

    def test_zero_never_switches_it_off(self):
        config = render([site("shop", "shop.example.test")],
                        site_defaults={"hard_req_rate": 0, "conn_rate_burst_trusted": 0, "conn_cur_limit": 0})
        https = frontend(config)
        self.assertIn("gt 1000 }", lines_with(https, "sc0_http_req_rate(fe_https)")[0])
        self.assertIn("acl conn_rate_hard  sc0_conn_rate(fe_https) gt 1000", https)
        self.assertIn("acl conn_too_many  sc0_conn_cur(fe_https)  gt 500", https)

    def test_an_operator_value_is_used(self):
        config = render([site("shop", "shop.example.test")],
                        site_defaults={"hard_req_rate": 3000, "hard_req_window": "20s"})
        https = frontend(config)
        self.assertIn("gt 3000 }", lines_with(https, "sc0_http_req_rate(fe_https)")[0])
        self.assertIn("http_req_rate(20s)", https)

    def test_without_a_router_fe_https_counts_connections_itself(self):
        self.assertIn("tcp-request connection track-sc0 src", self.https)
        self.assertNotIn("tbl_conn_edge", self.config)

    def test_the_settings_page_shows_and_edits_it(self):
        source = (ROOT / "docker/app/haproxy_admin/services_haproxy_vars.py").read_text(encoding="utf-8")
        for key in ("site_defaults.hard_req_rate", "site_defaults.hard_req_window",
                    "site_defaults.conn_rate_burst_trusted"):
            self.assertIn(f'"{key}"', source)

    def test_it_bans_nobody(self):
        self.assertIsNone(re.search(r"sc0_http_req_rate\(fe_https\).*(tbl_ban|ban_code)", self.https))


class TheOtherEntries(unittest.TestCase):
    """Plain HTTP on :80 and each generic TCP proxy had no limit of their own
    (04.6c); they take their connections straight from clients, so their own
    tables see the real address."""

    def setUp(self):
        self.config = render([site("shop", "shop.example.test", redirect_to_https=True)],
                             admin_ips_enabled=True,
                             tcp_proxies=[{"name": "files", "bind_port": 6690,
                                           "backend_host": "10.0.0.20", "backend_port": 22}])

    def check_floor(self, block, table):
        self.assertIn("tcp-request connection track-sc0 src", block)
        [burst] = lines_with(block, f"sc0_conn_rate({table}) gt 200")
        for trusted in ("!ip_whitelist", "!allowed_admin", "!ip_auth_ok"):
            self.assertIn(trusted, burst)
        self.assertIn(f"tcp-request connection reject if {{ sc0_conn_rate({table}) gt 1000 }}", block)
        self.assertIn(f"tcp-request connection reject if {{ sc0_conn_cur({table}) gt 500 }}", block)

    def test_plain_http_has_the_floor_and_the_request_ceiling(self):
        http80 = frontend(self.config, "fe_http80")
        self.check_floor(http80, "fe_http80")
        self.assertIn("http-request deny status 429 if { sc0_http_req_rate(fe_http80) gt 1000 }", http80)

    def test_a_tcp_proxy_has_the_connection_floor(self):
        tcp = frontend(self.config, "fe_tcp_files")
        self.check_floor(tcp, "fe_tcp_files")
        self.assertIn("stick-table type ip size 100k", tcp)


class BehindTheRouter(unittest.TestCase):
    """With a passthrough site an SNI router takes :443 and hands fe_https its
    connections from 127.0.0.1 with a PROXY header. At fe_https's connection
    stage the source is still 127.0.0.1: on the test host its table had one
    row, key 127.0.0.1, so every client shared one connection counter -- and
    the first version of this floor one request counter for the whole
    gateway. The router now counts connections by the client's address in a
    table of its own (a request tracked in fe_https's table counts as a
    connection too: 3 connections of 4 requests read conn_rate=15 there), and
    fe_https counts requests once the PROXY header has been read."""

    def setUp(self):
        self.config = render([site("shop", "shop.example.test"),
                              site("files", "files.example.test", tcp_passthrough=True)],
                             admin_ips_enabled=True)
        self.router = frontend(self.config, "fe_tls_router")
        self.https = frontend(self.config)

    def test_the_router_counts_connections_by_the_client(self):
        self.assertIn("backend tbl_conn_edge", self.config)
        self.assertIn("tcp-request connection track-sc1 src table tbl_conn_edge", self.router)
        [burst] = lines_with(self.router, "sc1_conn_rate(tbl_conn_edge) gt 200")
        for trusted in ("!ip_whitelist", "!allowed_admin", "!ip_auth_ok"):
            self.assertIn(trusted, burst)
        self.assertIn("tcp-request connection reject if { sc1_conn_rate(tbl_conn_edge) gt 1000 }", self.router)
        self.assertIn("tcp-request connection reject if { sc1_conn_cur(tbl_conn_edge) gt 500 }", self.router)

    def test_fe_https_no_longer_counts_its_127_0_0_1(self):
        self.assertNotIn("tcp-request connection track-sc0", self.https)
        self.assertNotIn("reject if conn_", self.https)

    def test_requests_are_counted_by_the_client_before_the_ceiling(self):
        track = self.https.index("http-request track-sc0 src")
        ceiling = self.https.index("sc0_http_req_rate(fe_https) gt 1000")
        self.assertLess(track, ceiling)

    def test_the_live_page_reads_the_routers_table_first(self):
        source = (ROOT / "docker/app/haproxy_admin/services_live.py").read_text(encoding="utf-8")
        self.assertIn('for table in ("tbl_conn_edge", "fe_https")', source)


if __name__ == "__main__":
    unittest.main()
