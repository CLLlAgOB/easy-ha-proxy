"""Every sentence the update checker can show has a Russian translation.

The updates page translates a component's summary in the browser, and a
sentence with no catalogue entry falls back to word-by-word substitution.
On a gateway whose Authelia stack could not be fully checked the page read
"One или больше managed Docker image versions could не быть checked; the
stack cannot быть обновлён partially." Twelve of the checker's forty-six
summaries had no entry. This keeps the count at zero.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CATALOGS = ROOT / "docker/app/haproxy_admin/translations"


def russian_messages() -> dict[str, str]:
    messages: dict[str, str] = {}
    for path in [CATALOGS / "ru.json", *sorted((CATALOGS / "ru").glob("*.json"))]:
        messages.update(json.loads(path.read_text(encoding="utf-8"))["messages"])
    return messages


def checker_summaries() -> set[str]:
    tree = ast.parse((ROOT / "installer/update_plan.py").read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "_component"
            and len(node.args) >= 3
            and isinstance(node.args[2], ast.Constant)
            and isinstance(node.args[2].value, str)
        ):
            found.add(node.args[2].value)
    return found


class EveryCheckerSummaryIsTranslated(unittest.TestCase):
    def test_the_checker_still_has_summaries_to_check(self):
        self.assertGreater(len(checker_summaries()), 30)

    def test_none_is_left_to_word_by_word_substitution(self):
        messages = russian_messages()
        missing = sorted(text for text in checker_summaries() if text not in messages)
        self.assertEqual(missing, [], "update checker summaries with no Russian")

    def test_the_reported_sentence_reads_whole(self):
        messages = russian_messages()
        sentence = (
            "One or more managed Docker image versions could not be checked; "
            "the stack cannot be updated partially."
        )
        self.assertTrue(messages[sentence].startswith("Не удалось проверить"))


if __name__ == "__main__":
    unittest.main()
