"""The gateway's own refusals do not count as the client's errors (F04).

From the 30 October review, confirmed on the installed HAProxy 2.8.30: the
error table a site tracks counts the gateway's own "deny status 429" as an
HTTP error. With a rate limit of 3, six requests -- three real 404s and three
of our 429s -- gave http_err_cnt=6; three 423s to a banned address gave 3
more. The rate limit thereby fed the error limit: a busy but honest client
was banned with code 10, and guardd scored ERROR_RATE_EXCEEDED from the same
table. With these exclusions the same run counted only the three real 404s,
and the 423s were not tracked at all.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".tests"))

from test_site_allow_ips import render, site  # noqa: E402


def tracking(config, table):
    return [line.strip() for line in config.splitlines()
            if line.strip().startswith("http-request track-sc1") and f"table {table} " in line]


class TheErrorCounter(unittest.TestCase):
    def test_a_request_about_to_be_rate_limited_is_not_an_error(self):
        config = render([site("shop", "shop.example.test", max_req_rate=120)])
        [line] = tracking(config, "tbl_err_shop")
        self.assertIn("!{ src_http_req_rate(tbl_rate_shop) ge 120 }", line)
        # the 429 itself still comes after the rate table counted the request
        self.assertIn("http-request deny status 429 if host_shop too_fast_shop", config)

    def test_a_banned_address_is_not_counted_again(self):
        config = render([site("shop", "shop.example.test", max_req_rate=120)])
        for table in ("tbl_err_shop", "tbl_err_other"):
            for line in tracking(config, table):
                self.assertIn("!{ src_get_gpc0(tbl_ban) gt 0 }", line, table)

    def test_without_a_rate_limit_no_rate_table_is_named(self):
        config = render([site("shop", "shop.example.test", max_req_rate=0)])
        [line] = tracking(config, "tbl_err_shop")
        self.assertNotIn("tbl_rate_shop", line)
        self.assertIsNone(re.search(r"backend tbl_rate_shop\b", config))

    def test_the_condition_matches_the_refusal(self):
        # The refusal is "rate after counting > limit", taken after track-sc3;
        # the tracking is decided before it, where that reads ">= limit".
        config = render([site("shop", "shop.example.test", max_req_rate=50)])
        self.assertIn("acl too_fast_shop src_http_req_rate(tbl_rate_shop) gt 50", config)
        self.assertLess(config.index("table tbl_err_shop"), config.index("table tbl_rate_shop if"))


if __name__ == "__main__":
    unittest.main()
