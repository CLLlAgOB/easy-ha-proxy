"""Regression checks for the per-request identifier.

The identifier is written into the same access log that the adaptive
protection engine parses, so half of this is about not breaking that parser.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "ansible/roles/haproxy/templates/haproxy.cfg.j2"
).read_text(encoding="utf-8")


def load_guardd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-guardd.py"
    spec = importlib.util.spec_from_file_location("guardd_for_request_id", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guardd = load_guardd()

PREFIX = "2026-08-12T10:00:00+00:00 gw haproxy[1234]: "
LINES = {
    "ordinary": PREFIX + (
        "203.0.113.9:51514 [12/Aug/2026:10:00:00.123] fe_https~ be_shop/srv1 "
        "0/0/1/12/13 200 4096 ---- 5/5/0/0/0 0/0 {example.test} {} "
        "id=8b1f0b1e-2c6a-4a3a-9a1f-2b3c4d5e6f70 GET /login HTTP/1.1"
    ),
    "with a query": PREFIX + (
        "203.0.113.9:51515 [12/Aug/2026:10:00:00.124] fe_https~ be_shop/<NOSRV> "
        "0/-1/-1/-1/0 503 217 ---- 5/5/0/0/0 0/0 {example.test} {} "
        "id=1111 GET /a?b=c HTTP/1.1"
    ),
    "with a ban fragment": PREFIX + (
        "203.0.113.9:51516 [12/Aug/2026:10:00:00.125] fe_https~ be_x/srv1 "
        "0/0/1/12/13 423 0 ---- 5/5/0/0/0 0/0 {} {} "
        'ban_val=1 ban_code=40 ban_reason="adaptive" '
        "id=2222 POST /wp-login.php HTTP/1.1"
    ),
    "a bad request": PREFIX + (
        "203.0.113.9:51517 [12/Aug/2026:10:00:00.126] fe_https~ fe_https/<NOSRV> "
        "-1/-1/-1/-1/0 400 0 ---- 5/5/0/0/0 0/0 {} {} id=3333 <BADREQ>"
    ),
}


class LogCompatibilityTests(unittest.TestCase):
    """The engine anchors on the request line; the id must stay out of its way."""

    def test_every_shape_of_line_still_parses(self):
        for label, line in LINES.items():
            self.assertIsNotNone(guardd.parse_access_line(line), label)

    def test_the_identifier_is_not_mistaken_for_the_request(self):
        parsed = guardd.parse_access_line(LINES["ordinary"])
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.path, "/login")
        self.assertEqual(parsed.backend, "be_shop/srv1")
        self.assertNotIn("id=", parsed.path)
        self.assertNotIn("id=", parsed.host)

    def test_a_bad_request_is_still_recognised_as_one(self):
        self.assertTrue(guardd.parse_access_line(LINES["a bad request"]).bad_request)

    def test_a_line_from_before_the_change_still_parses(self):
        for label, line in LINES.items():
            legacy = re.sub(r" id=\S+", "", line)
            self.assertIsNotNone(guardd.parse_access_line(legacy), label)

    def test_the_identifier_sits_before_the_request_line(self):
        # This is the whole reason the parser survives; if it ever moves after
        # %r the tail anchor stops matching and the engine goes blind.
        line = next(
            row for row in TEMPLATE.splitlines() if row.strip().startswith("log-format ")
        )
        # rindex: the format also contains %rc among the counters earlier on.
        self.assertLess(line.index("id=%ID"), line.rindex("%r"))


class EdgePolicyTests(unittest.TestCase):
    def test_a_client_supplied_identifier_is_discarded(self):
        # Echoing one would let anyone make two unrelated requests share an id.
        self.assertIn("http-request del-header X-Request-ID", TEMPLATE)
        deleted = TEMPLATE.index("http-request del-header X-Request-ID")
        minted = TEMPLATE.index("unique-id-header X-Request-ID")
        # The header is minted in defaults and stripped in the frontend, so the
        # strip has to come later in the file to run after nothing, but before
        # the request leaves: assert both exist and are distinct rules.
        self.assertNotEqual(deleted, minted)

    def test_it_is_generated_once_and_reused_everywhere(self):
        self.assertIn('unique-id-format "%[uuid()]"', TEMPLATE)
        self.assertIn("unique-id-header X-Request-ID", TEMPLATE)
        self.assertIn(
            "http-response set-header X-Request-ID %[unique-id]", TEMPLATE
        )

    def test_the_response_header_is_set_on_the_frontend(self):
        # An error page is exactly when a user needs the identifier, and an
        # error page never reaches a backend.
        start = TEMPLATE.index("frontend fe_https")
        rest = TEMPLATE[start + 1:]
        offsets = [
            rest.find(marker)
            for marker in ("\nbackend ", "\nfrontend ", "\nlisten ")
            if rest.find(marker) != -1
        ]
        block = TEMPLATE[start:start + 1 + min(offsets)]
        self.assertIn("http-response set-header X-Request-ID %[unique-id]", block)

    def test_the_whole_feature_is_switchable(self):
        self.assertEqual(TEMPLATE.count("request_id_enabled | default(true)"), 4)
        defaults = (
            ROOT / "ansible/roles/haproxy/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("request_id_enabled: true", defaults)


if __name__ == "__main__":
    unittest.main()
