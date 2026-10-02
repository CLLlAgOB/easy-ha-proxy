"""An operator's own rules, and why they cannot live in the shipped file.

The signature list is a file Ansible writes on every deploy. A rule typed
into it survives exactly until the next one, and -- worse -- a shipped
signature deleted because it caused a false positive comes straight back
with the next release, silently, banning the same person again.

So the operator's rules live where the enforcement mode and the request-log
switch already live: guardd's state table, applied on top of the shipped
list each time it loads. Suppression is by token rather than by deletion,
which is the whole point of the arrangement.
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
    spec = importlib.util.spec_from_file_location("guardd_overrides", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_overrides"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class Store:
    """Just the two methods the override code uses."""

    def __init__(self, value: str = ""):
        self.value = value

    def get_state(self, key: str, default: str = "") -> str:
        return self.value or default

    def set_state(self, key: str, value: str) -> None:
        self.value = value


class Base(unittest.TestCase):
    def setUp(self):
        def restore():
            guardd.load_signatures(str(SIGNATURES))
            guardd.apply_overrides({"added": {}, "disabled": []})

        self.addCleanup(restore)
        guardd.load_signatures(str(SIGNATURES))
        guardd.apply_overrides({"added": {}, "disabled": []})


class AddingARule(Base):
    def test_a_path_becomes_a_path_signature(self):
        guardd.store_overrides(Store(), {"added": {"/my-honeypot": "custom"}})
        self.assertEqual(guardd.classify_path("/my-honeypot"), "custom")

    def test_a_bare_word_becomes_a_segment_signature(self):
        # Matched anywhere in the path, which is the reason segments exist.
        guardd.store_overrides(Store(), {"added": {"acme-admin": "custom"}})
        self.assertEqual(guardd.classify_path("/x/acme-admin/login"), "custom")

    def test_it_can_be_filed_under_a_decisive_category(self):
        # An operator who knows nothing legitimate asks for a path should be
        # able to say so, and have one hit be enough.
        guardd.store_overrides(Store(), {"added": {"/private.key": "secrets"}})
        category = guardd.classify_path("/private.key")
        self.assertEqual(category, "secrets")
        self.assertTrue(guardd.category_is_decisive(category))


class SuppressingARule(Base):
    def test_a_shipped_signature_stops_matching(self):
        self.assertEqual(guardd.classify_path("/mcp"), "ai-endpoint")
        guardd.store_overrides(Store(), {"disabled": ["/mcp"]})
        self.assertEqual(guardd.classify_path("/mcp"), "")

    def test_a_shipped_segment_stops_matching(self):
        self.assertEqual(guardd.classify_path("/wp-admin/x"), "wordpress")
        guardd.store_overrides(Store(), {"disabled": ["wp-admin"]})
        self.assertEqual(guardd.classify_path("/wp-admin/x"), "")

    def test_it_does_not_come_back_when_the_shipped_list_reloads(self):
        """The reason suppression is by token and not by deletion.

        A signature turned off because it banned a real user must not
        reappear with the next release.
        """
        guardd.store_overrides(Store(), {"disabled": ["/mcp"]})
        self.assertEqual(guardd.classify_path("/mcp"), "")
        guardd.load_signatures(str(SIGNATURES))   # as a deploy would
        guardd.apply_overrides()
        self.assertEqual(guardd.classify_path("/mcp"), "")

    def test_re_enabling_brings_it_back(self):
        store = Store()
        guardd.store_overrides(store, {"disabled": ["/mcp"]})
        self.assertEqual(guardd.classify_path("/mcp"), "")
        guardd.store_overrides(store, {"disabled": []})
        self.assertEqual(guardd.classify_path("/mcp"), "ai-endpoint")


class WhatIsRefused(Base):
    def test_a_signature_of_slash_would_match_everything(self):
        for token in ("/", "//", "///"):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    guardd.validate_token(token)

    def test_an_empty_signature(self):
        for token in ("", "   "):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    guardd.validate_token(token)

    def test_characters_that_cannot_appear_in_a_path_segment(self):
        for token in ("a b", "x\ty", "drop\ntable", "*", "a|b", "'; --"):
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    guardd.validate_token(token)

    def test_something_absurdly_long(self):
        with self.assertRaises(ValueError):
            guardd.validate_token("a" * 5000)

    def test_a_category_name_that_is_not_one(self):
        with self.assertRaises(ValueError):
            guardd.validate_overrides({"added": {"/x": "Not A Category!"}})

    def test_more_rules_than_anyone_needs(self):
        many = {f"/p{n}": "custom" for n in range(guardd.MAX_CUSTOM_RULES + 1)}
        with self.assertRaises(ValueError):
            guardd.validate_overrides({"added": many})

    def test_a_rejected_document_changes_nothing(self):
        store = Store()
        with self.assertRaises(ValueError):
            guardd.store_overrides(store, {"added": {"bad token": "custom"}})
        self.assertEqual(store.value, "")
        self.assertEqual(guardd.classify_path("/mcp"), "ai-endpoint")

    def test_a_document_that_is_not_one(self):
        for payload in ([], "text", 7, None):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    guardd.validate_overrides(payload)


class SurvivingARestart(Base):
    def test_the_rules_are_read_back_from_the_store(self):
        store = Store()
        guardd.store_overrides(
            store, {"added": {"/trap": "custom"}, "disabled": ["/mcp"]}
        )
        # As a restart would: shipped list, then whatever was stored.
        guardd.load_signatures(str(SIGNATURES))
        guardd.apply_overrides(guardd.load_overrides(store))
        self.assertEqual(guardd.classify_path("/trap"), "custom")
        self.assertEqual(guardd.classify_path("/mcp"), "")

    def test_a_corrupt_document_is_ignored_rather_than_fatal(self):
        # Protection that refuses to start because one stored string is
        # broken is worse than protection running the shipped list.
        loaded = guardd.load_overrides(Store("{ not json"))
        self.assertEqual(loaded, {"added": {}, "disabled": []})

    def test_an_empty_store_is_not_an_error(self):
        self.assertEqual(guardd.load_overrides(Store()),
                         {"added": {}, "disabled": []})


class TheSummaryShowsThem(Base):
    def test_it_reports_what_the_operator_changed(self):
        guardd.store_overrides(
            Store(), {"added": {"/trap": "custom"}, "disabled": ["/mcp"]}
        )
        summary = guardd.signature_summary()
        self.assertEqual(summary["added"], {"/trap": "custom"})
        self.assertEqual(summary["disabled"], ["/mcp"])

    def test_an_added_rule_appears_in_its_category(self):
        guardd.store_overrides(Store(), {"added": {"/trap": "custom"}})
        summary = guardd.signature_summary()
        custom = [c for c in summary["categories"] if c["name"] == "custom"]
        self.assertTrue(custom, "the custom category is not listed")
        self.assertIn("/trap", custom[0]["paths"])


class PublishedInOneStep(unittest.TestCase):
    """The log reader is on another thread and must never see a half state."""

    def setUp(self):
        guardd.load_signatures(str(SIGNATURES))
        guardd.apply_overrides({"added": {}, "disabled": []})
        self.addCleanup(guardd.load_signatures, str(SIGNATURES))

    def test_reloading_the_shipped_list_never_revives_a_suppressed_rule(self):
        # The window this closes: reload, then re-apply, left a moment in
        # which a signature the operator switched off was matching again --
        # exactly what they switched it off to stop.
        guardd.store_overrides(Store(), {"disabled": ["/mcp"]})
        before = guardd.SCANNER_PATHS
        guardd.load_signatures(str(SIGNATURES))
        self.assertIsNot(guardd.SCANNER_PATHS, before, "tables were not swapped")
        self.assertNotIn("/mcp", guardd.SCANNER_PATHS)

    def test_a_reader_holding_the_old_table_still_sees_a_whole_one(self):
        held = guardd.SCANNER_PATHS
        guardd.store_overrides(Store(), {"added": {"/late": "custom"}})
        # The old mapping is untouched rather than emptied, so a lookup that
        # started before the change still answers from a complete list.
        self.assertIn("/.env", held)
        self.assertNotIn("/late", held)
        self.assertIn("/late", guardd.SCANNER_PATHS)

    def test_the_publisher_builds_new_tables_rather_than_clearing(self):
        source = GUARDD.read_text(encoding="utf-8")
        body = source.split("def publish_signatures()")[1].split(
            "def apply_overrides")[0]
        self.assertIn("global SCANNER_SEGMENTS, SCANNER_PATHS", body)
        self.assertNotIn("SCANNER_PATHS.clear()", body)
        self.assertNotIn("SCANNER_SEGMENTS.clear()", body)


class TheSocketOffersIt(unittest.TestCase):
    def test_both_verbs_are_routed(self):
        source = GUARDD.read_text(encoding="utf-8")
        self.assertIn('if path == "/api/v1/guard/signatures":', source)
        # Reading is open to the same caller as the rest of the page data;
        # writing is not.
        write = source.split('if path == "/api/v1/guard/signatures":')[2]
        self.assertIn("_control_auth_ok()", write[:400])

    def test_a_typo_is_reported_as_such_not_as_a_fault(self):
        source = GUARDD.read_text(encoding="utf-8")
        write = source.split('if path == "/api/v1/guard/signatures":')[2][:1400]
        self.assertIn("except ValueError as exc:", write)
        self.assertIn('"error": str(exc)', write)

    def test_startup_applies_the_file_before_the_overrides(self):
        source = GUARDD.read_text(encoding="utf-8")
        main = source.split("def main()")[1]
        self.assertLess(main.index("load_signatures()"),
                        main.index("apply_overrides(load_overrides"))


if __name__ == "__main__":
    unittest.main()
