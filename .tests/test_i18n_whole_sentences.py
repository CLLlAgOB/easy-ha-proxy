"""A sentence is translated whole or left whole in English, on the server too.

The page's translator replaced the words it knew one by one; the alerts'
history read "the правило is switched выкл". The rule now, in the browser
and on the server alike: when an English word is left after the known
pieces are put in, the sentence stays in English. Names a translation keeps
(Authelia, Let's Encrypt), acronyms, numbers, placeholders, paths and
domains are not words left untranslated.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import i18n  # noqa: E402


class OnTheServer(unittest.TestCase):
    def test_a_sentence_made_of_known_pieces_is_translated(self):
        translated = i18n.translate(
            "Let's Encrypt cannot issue certificates for reserved/private domains: "
            "app.example.test. Select Internal CA for this site.",
            "ru",
        )
        self.assertIn("не может выпускать сертификаты", translated)
        self.assertIn("app.example.test", translated)

    def test_a_sentence_known_in_part_stays_in_english(self):
        sentence = (
            "Let's Encrypt cannot issue certificates for reserved/private domains: "
            "app.example.test, so this setting was ignored."
        )
        self.assertEqual(i18n.translate(sentence, "ru"), sentence)

    def test_a_known_sentence_and_an_unknown_one(self):
        self.assertEqual(i18n.translate("CSRF validation failed", "ru"),
                         i18n.get_messages("ru")["CSRF validation failed"])
        unknown = "an applied image digest differs from the reviewed update plan"
        self.assertEqual(i18n.translate(unknown, "ru"), unknown)

    def test_what_is_not_a_word_left_over(self):
        self.assertFalse(i18n._partly_known("Бэкенд: shop.example.test, HAProxy 2.8, {count}", "ru"))
        self.assertFalse(i18n._partly_known("Путь /usr/local/bin и update.available", "ru"))
        # What someone typed, quoted, and a field's path are not words.
        self.assertFalse(i18n._partly_known(
            "sites[0].cookie_attrs: неизвестный параметр cookie 'bogus value'", "ru"))
        self.assertFalse(i18n._partly_known('значение "quoted text" и «other words»', "ru"))
        # An apostrophe inside a word is not a quote.
        self.assertTrue(i18n._partly_known("it's half translated: мост", "ru"))
        self.assertTrue(i18n._partly_known("ниже the настроено minimum severity", "ru"))
        self.assertTrue(i18n._partly_known("the правило is switched выкл", "ru"))


class InTheBrowser(unittest.TestCase):
    def test_both_translators_carry_the_rule(self):
        script = (ROOT / "docker/app/haproxy_admin/static/js/i18n.js").read_text(encoding="utf-8")
        self.assertIn("if (result !== source && partlyKnown(result)) result = source;", script)
        server = (ROOT / "docker/app/haproxy_admin/i18n.py").read_text(encoding="utf-8")
        self.assertIn("if translated != message and _partly_known(translated, selected):", server)


if __name__ == "__main__":
    unittest.main()
