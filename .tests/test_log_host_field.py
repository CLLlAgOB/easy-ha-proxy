"""The access log says which site a request was for.

A request the gateway refuses itself -- a GeoIP 451, a zero-trust 401, a
ban -- is logged against <NOSRV>: no backend was chosen, so the backend name
that normally gives the site away is not there. An operator looking at a
scanner's 451s could not tell which of the sites it had been sent to.

The reader was ready long before the writer: the adaptive protection engine
already looks for a labelled host= field, and the request log already has a
Host column. Only the frontend never wrote the field.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
).read_text(encoding="utf-8")
CAPTURE = (
    "http-request set-var(txn.log_host) "
    "req.hdr(host),lower,regsub([^a-z0-9.:_-],_,g),bytes(0,128)"
)


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_for_log_host", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()

PREFIX = "2026-10-13T11:11:02.423732+03:00 gw haproxy[34199]: "


def frontend(name: str) -> str:
    return TEMPLATE.split(f"\nfrontend {name}\n")[1].split("\nfrontend ")[0]


class TheFrontendWritesIt(unittest.TestCase):
    def setUp(self):
        self.format = next(
            row for row in TEMPLATE.splitlines() if row.strip().startswith("log-format ")
        )

    def test_the_field_is_in_the_log_format(self):
        self.assertIn(" host=%[var(txn.log_host)] ", self.format)

    def test_it_sits_before_the_request_line_and_after_the_identifier(self):
        # Before %r, or the parser's tail anchor stops matching. After the
        # identifier, so nothing a client sends can be read as one.
        position = self.format.index("host=%[var(txn.log_host)]")
        self.assertLess(position, self.format.rindex("%r"))
        self.assertLess(self.format.index("id=%ID"), position)

    def test_it_is_written_whether_or_not_request_ids_are_on(self):
        self.assertIn("{% endif %} host=%[var(txn.log_host)] %r", self.format)

    def test_both_http_frontends_capture_it_before_any_rule_can_refuse(self):
        for name in ("fe_https", "fe_http80"):
            with self.subTest(frontend=name):
                rules = [
                    row.strip() for row in frontend(name).splitlines()
                    if row.strip().startswith(("http-request ", "tcp-request "))
                ]
                http_rules = [row for row in rules if row.startswith("http-request ")]
                # Only the default-port strip may come first: it rewrites the
                # Host header so the log records the plain name, and it never
                # refuses anything.
                if http_rules[0].startswith("http-request set-header Host "):
                    self.assertNotIn("deny", http_rules[0])
                    http_rules = http_rules[1:]
                self.assertEqual(http_rules[0], CAPTURE)

    def test_no_tcp_rule_is_written_below_it(self):
        # HAProxy runs tcp-request rules first wherever they are written, and
        # warns on every configuration check when one follows an http-request
        # rule -- three warnings an operator then has to learn to ignore.
        for name in ("fe_https", "fe_http80"):
            with self.subTest(frontend=name):
                rules = [
                    row.strip() for row in frontend(name).splitlines()
                    if row.strip().startswith(("http-request ", "tcp-request "))
                ]
                after = rules[rules.index(CAPTURE):]
                self.assertEqual(
                    [row for row in after if row.startswith("tcp-request ")], []
                )

    def test_what_is_logged_is_reduced_to_hostname_characters(self):
        # The header is whatever the client chose to send, and the line it
        # lands in is parsed by field.
        self.assertIn("regsub([^a-z0-9.:_-],_,g)", CAPTURE)
        self.assertIn("bytes(0,128)", CAPTURE)


class TheEngineReadsIt(unittest.TestCase):
    def parse(self, middle: str, backend: str = "fe_https/<NOSRV>", status: int = 451):
        return guardd.parse_access_line(
            PREFIX
            + f"198.51.100.7:27216 [13/Oct/2026:11:11:02.379] fe_https~ {backend} "
            + f"0/-1/-1/-1/43 {status} 76 PR--- 17/17/0/0/0 0/0 "
            + middle
            + " GET /htdocs/.git-credentials HTTP/1.1"
        )

    def test_a_refused_request_names_its_site(self):
        # The reported case: 451 against <NOSRV>, and no way to tell the site.
        parsed = self.parse("id=86f8d037-9496-4bd9-b55b-b59a26d07031 host=shop.example.test")
        self.assertEqual(parsed.status, 451)
        self.assertEqual(parsed.backend, "fe_https/<NOSRV>")
        self.assertEqual(parsed.host, "shop.example.test")
        self.assertEqual(parsed.request_id, "86f8d037-9496-4bd9-b55b-b59a26d07031")
        self.assertEqual(parsed.path, "/htdocs/.git-credentials")

    def test_no_host_header_is_no_host(self):
        # HAProxy writes "-" for an unset variable.
        self.assertEqual(self.parse("id=1111 host=-").host, "")

    def test_a_line_from_before_the_change_still_parses(self):
        parsed = self.parse("id=1111")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.host, "")

    def test_a_bad_request_is_still_recognised_as_one(self):
        parsed = guardd.parse_access_line(
            PREFIX
            + "198.51.100.7:27216 [13/Oct/2026:11:11:02.379] fe_https~ fe_https/<NOSRV> "
            + "-1/-1/-1/-1/0 400 0 PR--- 1/1/0/0/0 0/0 id=- host=- <BADREQ>"
        )
        self.assertTrue(parsed.bad_request)

    def test_an_absurdly_long_name_is_cut(self):
        parsed = self.parse("id=1111 host=" + "a" * 500)
        self.assertEqual(len(parsed.host), guardd.MAX_HOST_LENGTH)


if __name__ == "__main__":
    unittest.main()
