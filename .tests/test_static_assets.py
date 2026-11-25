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
import unittest


APP_DIR = (Path(__file__).resolve().parents[1]
           / "docker" / "app" / "haproxy_admin")
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"
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


class FlagBaseTemplateTests(unittest.TestCase):
    def test_flag_base_is_still_a_directory_url(self) -> None:
        base = (_WEB_DIR / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("HAPROXY_ADMIN_FLAG_BASE", base)
        # Documents the shape the versioning helper must tolerate.
        self.assertIn("flags/4x3/", base)


if __name__ == "__main__":
    unittest.main()
