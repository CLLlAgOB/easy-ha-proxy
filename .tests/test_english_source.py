"""Comments, docstrings and the daemons' messages are written in English.

The repository is public and English; the panel's Russian lives in the
translation catalogues. Comments had drifted the other way -- half of them
Russian, some machine-translated into a mix of both ("run when готовности
DOM"), and a few host daemons answered the panel in Russian, which an
English-speaking operator could not read and the catalogue could not
translate back.

Russian stays where it belongs: the catalogues, the Russian documentation,
the Russian e-mail templates, the bilingual installer and helper, and the
handful of comments and tests that quote what an operator was actually
shown -- those are listed below by name.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path
import re
import tokenize
import unittest


ROOT = Path(__file__).resolve().parents[1]
CYRILLIC = re.compile(r"[Ѐ-ӿ]")

SCANNED = ("ansible/roles", "docker/app/haproxy_admin", "installer", ".tests", ".github")

# Comments that quote a mistranslation or a Russian page on purpose: the
# point of them is the Russian text.
QUOTES_RUSSIAN = {
    ".tests/test_api_error_shape.py",
    ".tests/test_backup_schedule_page.py",
    ".tests/test_english_source.py",
    ".tests/test_guardd.py",
    ".tests/test_i18n.py",
    ".tests/test_machine_output_not_translated.py",
    ".tests/test_translatable_prose.py",
    ".tests/test_update_channel_mismatch.py",
    ".tests/test_update_plan_translations.py",
    "docker/app/haproxy_admin/api_errors.py",
    "docker/app/haproxy_admin/static/js/detection_rules.js",
    "docker/app/haproxy_admin/templates/detection_rules.html",
    "docker/app/haproxy_admin/templates/haproxy_certs.html",
}

TEMPLATE_COMMENT = re.compile(r"\{#.*?#\}|<!--.*?-->", re.S)
HASH_SUFFIXES = {".yml", ".yaml", ".sh", ".j2", ".cfg", ".service", ".timer", ".conf"}


def files():
    for top in SCANNED:
        for path in sorted((ROOT / top).rglob("*")):
            relative = path.relative_to(ROOT).as_posix()
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if "/translations/" in relative or ".ru." in path.name:
                continue
            yield relative, path


def python_comments(text):
    """Comment tokens and docstrings, with their line numbers."""
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            yield token.start[0], token.string
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                yield body[0].value.lineno, body[0].value.value


def line_comments(text, markers):
    """Whole-line comments: the line starts with one of the markers."""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(markers) and not stripped.startswith(("#}", "#!")):
            yield number, stripped


def template_comments(text):
    for match in TEMPLATE_COMMENT.finditer(text):
        yield text.count("\n", 0, match.start()) + 1, match.group(0)


def comments_of(relative, path):
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix
    if suffix == ".py":
        yield from python_comments(text)
    elif suffix in (".js", ".css"):
        yield from line_comments(text, ("//", "/*", "*"))
    elif suffix == ".html":
        yield from template_comments(text)
    elif suffix in HASH_SUFFIXES:
        if suffix == ".j2":
            yield from template_comments(text)
        yield from line_comments(text, ("#",))


class CommentsAreEnglish(unittest.TestCase):
    def test_no_russian_in_comments_or_docstrings(self):
        found = []
        for relative, path in files():
            if relative in QUOTES_RUSSIAN:
                continue
            for number, comment in comments_of(relative, path):
                if CYRILLIC.search(comment):
                    found.append(f"{relative}:{number}: {comment.strip()[:90]}")
        self.assertEqual(found, [], "Russian comments:\n" + "\n".join(found))

    def test_the_quoting_files_still_quote(self):
        # A file that no longer needs its exemption should lose it.
        for relative in sorted(QUOTES_RUSSIAN - {".tests/test_english_source.py"}):
            with self.subTest(file=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertRegex(text, CYRILLIC)


class DaemonMessagesAreEnglish(unittest.TestCase):
    def test_host_daemons_answer_in_english(self):
        # What a daemon returns reaches the panel, which translates English
        # into the operator's language -- never the other way round.
        found = []
        for path in sorted((ROOT / "ansible/roles").glob("*/files/*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = {
                id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and id(node) not in docstrings and CYRILLIC.search(node.value):
                    found.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}: {node.value[:80]}")
        self.assertEqual(found, [], "Russian daemon strings:\n" + "\n".join(found))

    def test_the_moved_messages_are_translated_for_russian_operators(self):
        import json

        catalogue = json.loads(
            (ROOT / "docker/app/haproxy_admin/translations/ru/backend.json").read_text(encoding="utf-8")
        )["messages"]
        for message in ("Failed to save configuration.yml: ", "rules_yaml must be a YAML list",
                        "The password must be 8 to 1024 characters long", "Log file not found"):
            with self.subTest(message=message):
                self.assertRegex(catalogue[message], CYRILLIC)


if __name__ == "__main__":
    unittest.main()
