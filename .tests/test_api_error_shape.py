"""An API must answer in the language its caller parses.

Saving an off-host backup destination was refused fourteen times in a row on
a production gateway and the operator was shown "Не сохранено" every time.
The server knew exactly what was wrong and said so -- `abort(400,
description="the destination name may use a-z, 0-9 and dashes")` -- but
Flask renders an abort as an HTML page, the browser does
`response.json().catch(() => ({}))`, and the reason became an empty object.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Free of Flask on purpose, so the rule can be tested without one.
api_errors = load("easy_ha_api_errors", APP / "api_errors.py")


class WhoGetsJsonTests(unittest.TestCase):
    def test_the_api_prefixes_get_json(self):
        for path in (
            "/api/country-batch",
            "/system/backups/api/destinations",
            "/system/updates/api/status",
        ):
            with self.subTest(path=path):
                self.assertTrue(api_errors.caller_parses_json(path))

    def test_a_page_does_not(self):
        for path in ("/", "/system/backups/", "/haproxy/certs", "/apiary/"):
            with self.subTest(path=path):
                self.assertFalse(api_errors.caller_parses_json(path))

    def test_anything_sent_as_json_is_answered_as_json(self):
        self.assertTrue(api_errors.caller_parses_json("/haproxy/sites", True))

    def test_the_prefixes_match_the_csrf_handler(self):
        # Two handlers deciding "is this an API?" differently would answer
        # one caller two ways depending on which error it hit.
        source = (APP / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("caller_parses_json(request.path, request.is_json)", source)
        uses = [
            line.strip()
            for line in source.splitlines()
            if "_caller_parses_json()" in line and not line.strip().startswith("def ")
        ]
        self.assertEqual(len(uses), 2, f"both handlers must use it, found {uses}")


class ReasonTests(unittest.TestCase):
    def test_the_description_wins_because_it_is_the_actionable_part(self):
        self.assertEqual(
            api_errors.error_reason("the destination name may use a-z", "Bad Request"),
            "the destination name may use a-z",
        )

    def test_a_bare_abort_falls_back_to_the_status_text(self):
        self.assertEqual(api_errors.error_reason(None, "Not Found"), "Not Found")

    def test_something_is_always_said(self):
        self.assertTrue(api_errors.error_reason(None, None).strip())
        self.assertTrue(api_errors.error_reason("", "   ").strip())

    def test_whitespace_is_collapsed_so_the_key_can_be_translated(self):
        self.assertEqual(api_errors.error_reason("a\n   b", None), "a b")


class WiringTests(unittest.TestCase):
    """The handler has to be registered, or none of the above runs."""

    def setUp(self):
        self.source = (APP / "__init__.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_the_handler_is_registered_for_every_http_error(self):
        self.assertIn("@app.errorhandler(HTTPException)", self.source)
        self.assertIn("from werkzeug.exceptions import HTTPException", self.source)

    def test_a_page_request_is_handed_back_to_flask_untouched(self):
        # Returning the exception lets Flask render its normal page. Without
        # this the handler would turn the whole site into an API.
        handler = self.source.split("def handle_api_error")[1]
        self.assertIn("return exc", handler.split("return jsonify")[0])

    def test_the_status_code_is_preserved(self):
        handler = self.source.split("def handle_api_error")[1]
        self.assertIn("exc.code", handler)


class TranslationTests(unittest.TestCase):
    """A reason nobody can read is the bug all over again."""

    def test_every_backup_abort_reason_has_russian(self):
        catalogue = json.loads(
            (APP / "translations" / "ru" / "backup_destinations.json").read_text(
                encoding="utf-8"
            )
        )["messages"]
        source = (APP / "routes_backup.py").read_text(encoding="utf-8")
        # Not anchored on the closing paren: three of these are wrapped onto
        # their own line, and those were the ones left untranslated.
        described = set(re.findall(r'description=\s*"([^"]+)"', source))
        self.assertTrue(described, "the routes stopped using abort descriptions")
        missing = sorted(text for text in described if text not in catalogue)
        self.assertEqual(missing, [], "abort reasons with no Russian")

    def test_the_name_rule_is_stated_the_way_the_regex_enforces_it(self):
        source = (APP / "routes_backup.py").read_text(encoding="utf-8")
        pattern = re.search(r'DESTINATION_NAME_RE = re\.compile\(r"([^"]+)"\)', source)
        self.assertIsNotNone(pattern)
        rule = re.compile(pattern.group(1))
        # What the message promises must actually be accepted.
        for good in ("nas", "nas-backup", "n1", "a" * 40):
            self.assertTrue(rule.fullmatch(good), good)
        # And what an operator is likely to type must be what it rejects,
        # since that is the message they will be shown.
        for bad in ("nas_backup", "NAS", "почта", "nas.local", "-nas", "a" * 41, ""):
            self.assertFalse(rule.fullmatch(bad), bad)


if __name__ == "__main__":
    unittest.main()
