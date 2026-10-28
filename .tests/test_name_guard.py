"""The name guard finds a guarded word in the tree and in pushed messages,
and never repeats the word it found."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/name_guard.py"
WORD = "zebracorp"  # a made-up name standing in for a real one


def load():
    spec = importlib.util.spec_from_file_location("name_guard_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = load()


@unittest.skipUnless(shutil.which("git"), "needs git")
class TheGuard(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q")
        (self.root / "clean.txt").write_text("nothing to see\n", encoding="utf-8")
        self.commit("first")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
             "-c", "commit.gpgsign=false", *args],
            capture_output=True, text=True, check=True,
        ).stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_guard(self, words=WORD, base="", head=""):
        environment = {"NAME_GUARD_WORDS": words, "NAME_GUARD_ROOT": str(self.root),
                       "NAME_GUARD_BASE": base, "NAME_GUARD_HEAD": head}
        out = mock.patch("sys.stdout", new_callable=lambda: __import__("io").StringIO())
        with mock.patch.dict(os.environ, environment), out as printed:
            code = guard.main()
        return code, printed.getvalue()

    def test_a_clean_tree_passes(self):
        self.assertEqual(self.run_guard()[0], 0)

    def test_a_name_in_a_file_is_reported_by_place_not_by_word(self):
        (self.root / "notes.md").write_text("line one\nthanks to ZebraCorp ops\n", encoding="utf-8")
        self.commit("add notes")
        code, printed = self.run_guard(words=f"\n  {WORD.upper()}  \nother\n")
        self.assertEqual(code, 1)
        self.assertIn("notes.md:2", printed)
        self.assertNotIn(WORD, printed.casefold())

    def test_an_untracked_file_is_not_the_repository(self):
        (self.root / "inventory.ini").write_text(f"{WORD}.example\n", encoding="utf-8")
        self.assertEqual(self.run_guard()[0], 0)

    def test_a_name_in_a_pushed_message_is_reported_by_commit(self):
        (self.root / "clean.txt").write_text("still nothing\n", encoding="utf-8")
        self.commit(f"Fix the gateway for {WORD}")
        head = self.git("rev-parse", "HEAD").strip()
        code, printed = self.run_guard(base=self.base, head=head)
        self.assertEqual(code, 1)
        self.assertIn(f"commit {head[:12]}", printed)
        self.assertNotIn(WORD, printed.casefold())
        # A new branch has no "before": only the tree is checked.
        self.assertEqual(self.run_guard(base="0" * 40, head=head)[0], 0)

    def test_without_the_secret_it_says_so_and_passes(self):
        (self.root / "notes.md").write_text(f"{WORD}\n", encoding="utf-8")
        self.commit("add notes")
        code, printed = self.run_guard(words="")
        self.assertEqual(code, 0)
        self.assertIn("NAME_GUARD_WORDS is not set", printed)


if __name__ == "__main__":
    unittest.main()
