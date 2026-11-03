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

    def test_it_bans_nobody(self):
        self.assertIsNone(re.search(r"sc0_http_req_rate\(fe_https\).*(tbl_ban|ban_code)", self.https))


if __name__ == "__main__":
    unittest.main()
