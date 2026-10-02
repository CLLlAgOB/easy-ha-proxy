"""Regression tests for versioned static URLs.

The app appends a content version to every ``url_for('static', ...)`` so
released assets can be cached immutably. One caller builds a *directory* URL
and appends the file name in JavaScript, so versioning a directory would move
the query string in front of the file name and break those requests.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest


APP_DIR = (Path(__file__).resolve().parents[1]
           / "docker" / "app" / "haproxy_admin")
INIT_PY = APP_DIR / "__init__.py"


def load_static_version():
    """Execute just the helper, which needs no Flask import."""
    tree = ast.parse(INIT_PY.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_static_version":
            namespace: dict = {
                "os": os,
                "stat": stat,
                "hashlib": hashlib,
                "_STATIC_VERSIONS": {},
            }
            exec(  # noqa: S102 - executing our own source under test
                compile(ast.Module(body=[node], type_ignores=[]), str(INIT_PY), "exec"),
                namespace,
            )
            return namespace["_static_version"]
    raise AssertionError("_static_version not found in the app factory")


class StaticVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.version = load_static_version()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "css").mkdir()
        (self.root / "css" / "styles.css").write_text("body{}", encoding="utf-8")
        (self.root / "flags").mkdir()

    def test_regular_file_gets_a_version(self) -> None:
        self.assertRegex(self.version(str(self.root), "css/styles.css"), r"^[0-9a-f]{12}$")

    def test_directory_is_never_versioned(self) -> None:
        # A query string here would land before the file name the browser
        # appends, producing /flags/?v=abcus.svg instead of /flags/us.svg.
        self.assertEqual(self.version(str(self.root), "flags/"), "")
        self.assertEqual(self.version(str(self.root), "flags"), "")

    def test_missing_file_is_not_versioned(self) -> None:
        self.assertEqual(self.version(str(self.root), "css/nope.css"), "")

    def test_version_changes_when_the_file_changes(self) -> None:
        first = self.version(str(self.root), "css/styles.css")
        target = self.root / "css" / "styles.css"
        target.write_text("body{color:red}", encoding="utf-8")
        os.utime(target, (0, 0))
        # A fresh helper avoids the per-process cache from the first call.
        second = load_static_version()(str(self.root), "css/styles.css")
        self.assertNotEqual(first, second)


class FlagBaseTemplateTests(unittest.TestCase):
    def test_flag_base_is_still_a_directory_url(self) -> None:
        base = (APP_DIR / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("HAPROXY_ADMIN_FLAG_BASE", base)
        # Documents the shape the versioning helper must tolerate.
        self.assertIn("flags/4x3/", base)


if __name__ == "__main__":
    unittest.main()
