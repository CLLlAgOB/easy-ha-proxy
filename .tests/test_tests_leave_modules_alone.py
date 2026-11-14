"""No test leaves its own module under a real haproxy_admin name.

Every test file is imported before any test runs, and they share one
sys.modules. A test that put a stub package under "haproxy_admin" (or a
fresh copy of a panel module under its real name) and kept it there broke
every later test that imported the panel at run time -- in the full run
only, in alphabetical order, never when the test was run on its own. Twice
in one week a new test failed in CI that way.

So a test may register a module under a real haproxy_admin name only
inside ``mock.patch.dict(sys.modules, ...)``, which puts everything back
when the block ends. Private names (``dns01_sites_test.validation``) are
the test's own business and are not checked.
"""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

TESTS = Path(__file__).resolve().parent
REAL = "haproxy_admin"


def _real_name(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and (node.value == REAL or node.value.startswith(REAL + "."))
    )


def _is_sys_modules(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _restores_modules(item: ast.withitem) -> bool:
    """A ``with`` item that is patch.dict(sys.modules, ...)."""
    call = item.context_expr
    if not isinstance(call, ast.Call) or not call.args:
        return False
    func = call.func
    named_dict = isinstance(func, ast.Attribute) and func.attr == "dict"
    return named_dict and _is_sys_modules(call.args[0])


def leaks(tree: ast.AST) -> list[int]:
    """Line numbers where a real panel name is registered outside a restoring block."""
    found: list[int] = []

    def visit(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, (ast.With, ast.AsyncWith)):
            guarded = guarded or any(_restores_modules(item) for item in node.items)
        if not guarded:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript) and _is_sys_modules(target.value)
                            and _real_name(target.slice)):
                        found.append(node.lineno)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func = node.func
                if (func.attr in ("setdefault", "__setitem__") and _is_sys_modules(func.value)
                        and node.args and _real_name(node.args[0])):
                    found.append(node.lineno)
                # A module created under a real name is meant to be registered.
                if func.attr == "spec_from_file_location" and node.args and _real_name(node.args[0]):
                    found.append(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, guarded)

    visit(tree, False)
    return found


class TheTests(unittest.TestCase):
    def test_no_test_keeps_a_module_under_a_real_panel_name(self):
        found = []
        for path in sorted(TESTS.glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            found += [f"{path.name}:{line}" for line in leaks(tree)]
        self.assertEqual(found, [], "register real panel modules inside "
                         "mock.patch.dict(sys.modules, ...):\n" + "\n".join(found))

    def test_the_check_tells_a_leak_from_a_guarded_load(self):
        leaky = ast.parse(
            "import sys\n"
            "sys.modules['haproxy_admin'] = object()\n"
            "sys.modules.setdefault('haproxy_admin.utils', object())\n"
            "spec = importlib.util.spec_from_file_location('haproxy_admin.cache', p)\n"
            "sys.modules['private_test.utils'] = object()\n"
        )
        self.assertEqual(leaks(leaky), [2, 3, 4])
        guarded = ast.parse(
            "import sys\n"
            "with mock.patch.dict(sys.modules, {'haproxy_admin': object()}):\n"
            "    sys.modules['haproxy_admin.utils'] = object()\n"
            "    spec = importlib.util.spec_from_file_location('haproxy_admin.cache', p)\n"
        )
        self.assertEqual(leaks(guarded), [])


if __name__ == "__main__":
    unittest.main()
