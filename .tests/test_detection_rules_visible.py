"""The page could say "banned" without ever saying what the address did.

Adaptive protection showed a score, a band and a verdict. What it never
showed was the rules that produced any of it: which paths are matched, which
categories end an argument on their own, and -- since the list became a
replaceable file -- which version of it the gateway is actually running.

That last one is the reason this is a test and not a nicety. A signature
file that failed to load leaves the daemon on its built-in list, quietly,
and without the version on screen there is no way to tell from the outside.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
GUARDD = FILES / "easy-ha-proxy-guardd.py"
SIGNATURES = FILES / "scanner-signatures.json"
APP = ROOT / "docker" / "app" / "haproxy_admin"
PAGE = APP / "templates" / "detection_rules.html"
SCRIPT = APP / "static" / "js" / "detection_rules.js"


def load():
    spec = importlib.util.spec_from_file_location("guardd_rules", GUARDD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guardd_rules"] = module
    spec.loader.exec_module(module)
    return module


guardd = load()


class TheDaemonReportsWhatItLoaded(unittest.TestCase):
    """The daemon applies the rules, so the daemon is what reports them."""

    def setUp(self):
        self.addCleanup(guardd.load_signatures, str(SIGNATURES))
        guardd.load_signatures(str(SIGNATURES))
        self.summary = guardd.signature_summary()

    def test_it_names_the_version_in_use(self):
        self.assertTrue(str(self.summary["version"]).strip())
        self.assertNotEqual(self.summary["version"], "built-in")

    def test_a_daemon_that_never_read_a_file_says_so(self):
        # The quiet failure this exists to expose: a gateway whose signature
        # file did not load runs the compiled-in list, and from the outside
        # that looks exactly like a gateway running the current one.
        fresh = load()
        fresh.load_signatures("/nonexistent/signatures.json")
        self.assertEqual(fresh.signature_summary()["version"], "built-in")

    def test_the_version_always_describes_the_rules_in_memory(self):
        # A failed reload keeps the rules it already had -- protection that
        # fails closed on a bad download is worse than yesterday's list --
        # so the version must keep describing those, not the file that
        # failed.
        guardd.load_signatures("/nonexistent/signatures.json")
        self.assertEqual(guardd.signature_summary()["version"],
                         guardd.SIGNATURE_VERSION)
        self.assertIn("/remote/fgt_lang", guardd.SCANNER_PATHS)

    def test_every_category_carries_its_own_tokens(self):
        self.assertTrue(self.summary["categories"])
        for category in self.summary["categories"]:
            with self.subTest(category=category["name"]):
                tokens = category["segments"] + category["paths"]
                self.assertTrue(tokens, "a category with nothing in it")

    def test_the_decisive_ones_are_marked(self):
        decisive = {c["name"] for c in self.summary["categories"] if c["decisive"]}
        for name in ("secrets", "vcs", "backup"):
            with self.subTest(name=name):
                self.assertIn(name, decisive)

    def test_it_carries_the_numbers_needed_to_explain_a_ban(self):
        # Without these the page can list rules but not say what they cost.
        self.assertGreaterEqual(self.summary["decisive_weight"],
                                self.summary["would_ban_score"])
        self.assertLess(self.summary["probable_weight"],
                        self.summary["would_ban_score"])

    def test_the_query_rules_are_named_but_the_patterns_are_not(self):
        self.assertTrue(self.summary["query_rules"])
        for name in self.summary["query_rules"]:
            with self.subTest(name=name):
                # A name, not a regex. The page is not the place to teach
                # anyone to read one.
                self.assertNotIn("\\", name)
                self.assertNotIn("(", name)

    def test_no_signature_leaks_a_query_pattern(self):
        # The patterns match values that can carry a token; the names do not.
        text = repr(self.summary)
        self.assertNotIn("%2e%2e", text)


class ThePageShowsThem(unittest.TestCase):
    def setUp(self):
        self.page = PAGE.read_text(encoding="utf-8")
        self.script = SCRIPT.read_text(encoding="utf-8")

    def test_the_page_exists(self):
        self.assertIn('id="dr-shipped"', self.page)
        self.assertIn("Detection rules", self.page)

    def test_the_version_has_somewhere_to_go(self):
        self.assertIn('id="dr-version"', self.page)

    def test_the_rules_page_is_reachable_from_the_navigation(self):
        nav = (APP / "templates" / "_haproxy_nav.html").read_text(
            encoding="utf-8")
        self.assertIn("routes.detection_rules_page", nav)

    def test_the_page_that_reports_a_ban_points_at_the_rules(self):
        adaptive = (APP / "templates" / "adaptive_protection.html").read_text(
            encoding="utf-8")
        self.assertIn("routes.detection_rules_page", adaptive)

    def test_the_rules_are_written_as_text_not_markup(self):
        # A signature is attacker-influenced only in the sense that a
        # downloaded list could carry anything; textContent keeps it inert.
        self.assertIn("textContent", self.script)
        self.assertNotIn("innerHTML", self.script)

    def test_the_file_path_is_not_offered_for_translation(self):
        # The DOM translator walks text nodes one at a time, so a path
        # inside a sentence breaks the lookup for the whole sentence. The
        # path stands alone, in a paragraph the translator is told to skip.
        paragraph = self.page.split('id="dr-source"')[0].rsplit("<p", 1)[-1]
        self.assertIn("data-i18n-skip", paragraph)

    def test_no_sentence_hides_a_word_inside_markup(self):
        # Every prose paragraph must be one text node, or half of it goes
        # untranslated. An anchor or code element has to be the whole
        # paragraph, not a word in the middle of one.
        import re as _re

        for match in _re.finditer(
            r'<p class="mon-sub"(?![^>]*data-i18n-skip)[^>]*>(.*?)</p>',
            self.page, _re.S,
        ):
            body = match.group(1).strip()
            if "<" not in body:
                continue
            with self.subTest(body=body[:60]):
                self.assertTrue(
                    _re.fullmatch(r"<(a|code)[^>]*>[^<]*</(a|code)>", body),
                    "markup inside a sentence breaks the translator",
                )


class TheProseIsTranslated(unittest.TestCase):
    def test_every_new_string_has_a_russian_counterpart(self):
        import json
        import re

        fragment = (APP / "translations" / "ru" / "detection_rules.json")
        messages = json.loads(fragment.read_text(encoding="utf-8"))["messages"]
        for english in (
            "Detection rules",
            "Signature list",
            "You have not changed any rules yet",
            "points — one request is enough",
            "points — takes N different categories to ban",
            "points each",
            "Switch off",
            "Switch back on",
            "Query strings are checked by what the value looks like, never by "
            "the parameter name",
        ):
            with self.subTest(english=english):
                key = re.sub(r"\s+", " ", english).strip()
                self.assertIn(key, messages)


if __name__ == "__main__":
    unittest.main()
