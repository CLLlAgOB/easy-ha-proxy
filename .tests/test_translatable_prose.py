"""Prose that has a translation must be able to find it.

The DOM translator walks text nodes and looks each one up whole. Putting a
tag inside a sentence therefore splits it into fragments that match no key,
and the fallback substitutes word by word: an operator saw

    One поле для все из it. Choose a PEM, a DER файл, или a PKCS#12 bundle

which is neither language. The catalog entry was correct; the paragraph it
was written for no longer existed as one piece.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
TEMPLATES = APP / "templates"
FRAGMENTS = APP / "translations" / "ru"


def catalog() -> dict:
    messages = {}
    base = APP / "translations" / "ru.json"
    if base.is_file():
        messages.update(json.loads(base.read_text(encoding="utf-8")).get("messages", {}))
    for path in sorted(FRAGMENTS.glob("*.json")):
        messages.update(json.loads(path.read_text(encoding="utf-8")).get("messages", {}))
    return messages


def text_nodes(markup: str) -> list[str]:
    """The pieces the translator will actually be handed, near enough.

    Tags split the text and whitespace is collapsed, the way i18n.js sees it.
    Jinja block statements split it too -- only one branch of an if/else is
    ever in the document -- while an interpolation stays inside its node,
    because that is exactly what makes such a paragraph untranslatable.
    """
    markup = re.sub(r"\{\{.*?\}\}", "\x00", markup, flags=re.DOTALL)
    pieces = re.split(r"<[^>]+>|\{%.*?%\}", markup, flags=re.DOTALL)
    return [" ".join(piece.split()) for piece in pieces if piece.strip()]


class ProseTests(unittest.TestCase):
    """Each sentence a translation was written for must survive as one node."""

    # Only the prose this project added recently and translated deliberately.
    # A blanket rule over every string in the application would fail on the
    # many that are intentionally untranslated.
    EXPECTED = {
        "haproxy_certs.html": [
            "One field for all of it.",
            "An authority listed above only vouches for servers.",
            "Refuses one certificate without discarding the authority",
        ],
        "haproxy_site_edit.html": [
            "A separate layer from Authelia, not a replacement for it",
            "One address or network per line.",
            "Only this authority is accepted for this site.",
        ],
    }

    def setUp(self):
        self.messages = catalog()

    def test_each_translated_paragraph_survives_as_one_text_node(self):
        for name, openings in self.EXPECTED.items():
            markup = (TEMPLATES / name).read_text(encoding="utf-8")
            nodes = text_nodes(markup)
            for opening in openings:
                with self.subTest(template=name, opening=opening):
                    matching = [node for node in nodes if node.startswith(opening)]
                    self.assertTrue(
                        matching,
                        f"{opening!r} is not a whole text node in {name}; a tag "
                        "inside the sentence has split it",
                    )
                    node = matching[0]
                    self.assertIn(
                        node,
                        self.messages,
                        f"no Russian for this node in {name}:\n{node}",
                    )

    def test_the_catalog_has_no_entry_that_nothing_can_match(self):
        # An entry whose text no longer appears anywhere is dead weight and,
        # worse, hides that the live text is going untranslated.
        # Raw markup, not text nodes: placeholders and titles are translated
        # too, and they live in attributes.
        haystack = "\n".join(
            " ".join(path.read_text(encoding="utf-8").split())
            for path in TEMPLATES.glob("*.html")
        )
        scripts = "\n".join(
            " ".join(path.read_text(encoding="utf-8").split())
            for path in (APP / "static" / "js").glob("*.js")
        )
        stale = []
        for name in ("client_certificates.json",):
            fragment = json.loads(
                (FRAGMENTS / name).read_text(encoding="utf-8")
            )["messages"]
            for key in fragment:
                if len(key) < 40:
                    continue  # short labels also come from Python and JS
                flat = " ".join(key.split())
                if flat not in haystack and flat not in scripts:
                    stale.append(flat[:70])
        self.assertEqual(stale, [], "catalog entries nothing will ever match")


if __name__ == "__main__":
    unittest.main()
