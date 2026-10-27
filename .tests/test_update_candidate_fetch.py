"""How the update checker gets the candidate source, and what it says without it.

A gateway with a slow route to GitHub could not clone the next revision
within the minute it was given. The plan then did not know the complete
update re-pinned Redis; the update was offered anyway, installed, and failed
the check after it on an image the plan had never named. Two checks a few
minutes apart also disagreed, one with the candidate and one without, and
the apply refused with "the update candidate changed".

The candidate is now fetched on top of the installed checkout, which already
holds almost all of it, and a plan without it offers nothing to install.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import update_plan  # noqa: E402
from update_plan import CommandResult, build_update_plan  # noqa: E402
from test_update_plan import (  # noqa: E402
    REMOTE_REVISION,
    FakeRunner,
    git_handler,
    prepare_installed_daemons,
    prepare_source,
)

GIT = shutil.which("git")
IDENTITY = ("-c", "user.name=Test", "-c", "user.email=test@example.test")


def git(*args: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *IDENTITY, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    return completed.stdout.strip()


def commit_files(repository: Path, files: dict[str, str], message: str) -> str:
    for name, text in files.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git("add", "--all", cwd=repository)
    git("commit", "--quiet", "-m", message, cwd=repository)
    return git("rev-parse", "HEAD", cwd=repository)


def tree_files(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file() and ".git" not in path.relative_to(root).parts
    }


@unittest.skipIf(GIT is None, "needs git")
class FetchingOnTopOfTheInstalledCheckout(unittest.TestCase):
    """With real Git: an installed shallow checkout, then a new revision."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.remote = root / "remote"
        self.remote.mkdir()
        git("init", "--quiet", cwd=self.remote)
        git("symbolic-ref", "HEAD", "refs/heads/main", cwd=self.remote)
        # History before the installed revision, which a depth-1 checkout
        # does not have: Git must be told where the installed history stops.
        commit_files(self.remote, {"README.md": "older\n"}, "older revision")
        # Enough unchanged files that borrowing them is visible.
        base = {f"ansible/roles/role{index}/tasks/main.yml": f"- name: task {index}\n" * 40
                for index in range(30)}
        base["ansible/roles/authelia/defaults/main.yml"] = 'authelia_redis_image: "redis:7.4.12-alpine"\n'
        commit_files(self.remote, base, "installed revision")
        self.url = self.remote.resolve().as_uri()
        # What the update leaves on a gateway: a depth-1 checkout.
        self.installed = root / "installed"
        git("clone", "--quiet", "--depth=1", "--branch", "main", self.url, str(self.installed), cwd=root)
        self.new_revision = commit_files(
            self.remote,
            {
                "ansible/roles/authelia/defaults/main.yml": 'authelia_redis_image: "redis:8.10.3-alpine"\n',
                "installer/new_file.py": "print('new')\n",
            },
            "next revision",
        )
        self.destination = root / "scratch" / "source"
        self.destination.parent.mkdir()

    def fetch(self):
        return update_plan._remote_candidate(
            source_dir=self.installed,
            repository=self.url,
            branch="main",
            expected_revision=self.new_revision,
            destination=self.destination,
            runner=update_plan.SubprocessRunner(),
        )

    def test_the_candidate_is_the_new_revision_file_for_file(self):
        candidate, error = self.fetch()
        self.assertIsNone(error)
        self.assertEqual(candidate, self.destination)
        expected = Path(self.temporary.name) / "expected"
        git("clone", "--quiet", "--depth=1", "--branch", "main", self.url, str(expected),
            cwd=Path(self.temporary.name))
        self.assertEqual(tree_files(candidate), tree_files(expected))
        self.assertIn("redis:8.10.3-alpine", (candidate / "ansible/roles/authelia/defaults/main.yml").read_text())

    def test_only_what_changed_is_transferred(self):
        candidate, error = self.fetch()
        self.assertIsNone(error)
        alternates = (candidate / ".git/objects/info/alternates").read_text(encoding="utf-8")
        self.assertEqual(Path(alternates.strip()), (self.installed / ".git/objects").resolve())
        stored = {
            line.split(": ")[0]: int(line.split(": ")[1])
            for line in git("count-objects", "-v", cwd=candidate).splitlines()
            if line.split(": ")[0] in {"count", "in-pack"}
        }
        held = stored["count"] + stored["in-pack"]
        total = len(git("rev-list", "--objects", "HEAD", cwd=candidate).splitlines())
        # The new commit, its changed trees and two files -- not the 31 others.
        self.assertLess(held, 12, stored)
        self.assertGreater(total, 30)

    def test_the_installed_checkout_is_only_read(self):
        def snapshot():
            git_dir = self.installed / ".git"
            return (
                git("rev-parse", "HEAD", cwd=self.installed),
                git("for-each-ref", cwd=self.installed),
                (git_dir / "shallow").read_text(encoding="utf-8"),
                sorted(path.relative_to(git_dir).as_posix() for path in git_dir.rglob("*")),
            )

        before = snapshot()
        candidate, error = self.fetch()
        self.assertIsNone(error)
        self.assertEqual(snapshot(), before)
        self.assertEqual(git("status", "--porcelain", cwd=self.installed), "")

    def test_a_moved_branch_is_still_refused(self):
        commit_files(self.remote, {"README.md": "moved\n"}, "pushed during the check")
        candidate, error = self.fetch()
        self.assertIsNone(candidate)
        self.assertEqual(error, "candidate-revision-changed-during-check")


class WhenTheFetchDoesNotWork(unittest.TestCase):
    """The order of attempts, with the network scripted."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source = root / "source"
        (self.source / ".git/objects").mkdir(parents=True)
        self.destination = root / "candidate"

    def run_with(self, handler):
        runner = FakeRunner(handler)
        result = update_plan._remote_candidate(
            source_dir=self.source,
            repository="https://example.test/r.git",
            branch="main",
            expected_revision=REMOTE_REVISION,
            destination=self.destination,
            runner=runner,
        )
        return result, [command for command, _ in runner.calls]

    @staticmethod
    def origin(command):
        if command[-3:] == ("remote", "get-url", "origin"):
            return CommandResult(0, "https://example.test/r.git\n")
        return None

    def test_a_timed_out_fetch_is_not_followed_by_a_larger_clone(self):
        def handler(command):
            if self.origin(command):
                return self.origin(command)
            if command[:2] == ("git", "init"):
                Path(command[-1]).mkdir(parents=True, exist_ok=True)
                return CommandResult(0)
            if "fetch" in command:
                return CommandResult(124, error="timeout")
            raise AssertionError(f"unexpected command: {command!r}")

        (candidate, error), commands = self.run_with(handler)
        self.assertIsNone(candidate)
        self.assertTrue(error.startswith("candidate-fetch-timed-out"), error)
        self.assertFalse(any(command[:2] == ("git", "clone") for command in commands))

    def test_any_other_failure_falls_back_to_a_clean_full_clone(self):
        seen = {}

        def handler(command):
            if self.origin(command):
                return self.origin(command)
            if command[:2] == ("git", "init"):
                Path(command[-1]).mkdir(parents=True, exist_ok=True)
                return CommandResult(0)
            if "fetch" in command:
                return CommandResult(128, stderr="fatal: shallow file has changed")
            if command[:2] == ("git", "clone"):
                # The half-made scratch repository is gone before the clone.
                seen["existed"] = Path(command[-1]).exists()
                Path(command[-1]).mkdir(parents=True)
                return CommandResult(0)
            if command[-2:] == ("rev-parse", "HEAD"):
                return CommandResult(0, REMOTE_REVISION + "\n")
            raise AssertionError(f"unexpected command: {command!r}")

        (candidate, error), commands = self.run_with(handler)
        self.assertIsNone(error)
        self.assertEqual(candidate, self.destination)
        self.assertFalse(seen["existed"])
        clone = next(command for command in commands if command[:2] == ("git", "clone"))
        self.assertIn("--depth=1", clone)

    def test_a_tarball_install_goes_straight_to_the_clone(self):
        shutil.rmtree(self.source / ".git")

        def handler(command):
            if command[:2] == ("git", "clone"):
                Path(command[-1]).mkdir(parents=True)
                return CommandResult(0)
            if command[-2:] == ("rev-parse", "HEAD"):
                return CommandResult(0, REMOTE_REVISION + "\n")
            raise AssertionError(f"unexpected command: {command!r}")

        (candidate, error), commands = self.run_with(handler)
        self.assertIsNone(error)
        self.assertFalse(any(command[:2] == ("git", "init") for command in commands))

    def test_a_timed_out_clone_says_so(self):
        shutil.rmtree(self.source / ".git")

        def handler(command):
            if command[:2] == ("git", "clone"):
                return CommandResult(124, error="timeout")
            raise AssertionError(f"unexpected command: {command!r}")

        (candidate, error), _ = self.run_with(handler)
        self.assertIsNone(candidate)
        self.assertTrue(error.startswith("candidate-clone-timed-out"), error)

    def test_the_candidate_has_longer_than_the_changelog(self):
        self.assertGreater(update_plan.CANDIDATE_TIMEOUT, update_plan.CLONE_TIMEOUT)
        self.assertLess(update_plan.CANDIDATE_TIMEOUT, 10 * 60)


class APlanWithoutTheCandidate(unittest.TestCase):
    def build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            runner = FakeRunner(git_handler)
            return build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="github",
                runner=runner,
                artifact_path=installed,
            )

    def test_offers_nothing_to_install_and_says_why(self):
        plan = self.build()
        components = {item["id"]: item for item in plan["components"]}
        source = components["all"]
        self.assertEqual(source["state"], "blocked")
        self.assertFalse(source["actionable"])
        self.assertEqual(source["details"]["reason"], "candidate-unavailable")
        self.assertIn("candidate unavailable", source["details"]["candidate_error"])
        # Still says there is something newer, and which revision.
        self.assertEqual(source["available_version"], REMOTE_REVISION)
        self.assertNotIn("all", plan["actionable_components"])
        self.assertFalse(components["services"]["actionable"])
        self.assertFalse(components["daemons"]["actionable"])

    def test_the_reason_is_in_russian(self):
        summary = self.build()["components"][0]["summary"]
        catalogue = json.loads(
            (ROOT / "docker/app/haproxy_admin/translations/ru/updates.json").read_text(encoding="utf-8")
        )["messages"]
        self.assertIn(summary, catalogue)
        self.assertIn("скачать новую версию", catalogue[summary])


if __name__ == "__main__":
    unittest.main()
