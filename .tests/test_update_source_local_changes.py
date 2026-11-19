"""Files changed by hand on a gateway block its update only when they matter.

The reported case, on the test gateway: two fixes were tried there by editing
the installed source by hand, then committed exactly as tried. From then on
every check said "The managed source has local content changes and will not
be replaced automatically." The complete update could not be installed, and
the nightly OS install kept failing on the bug the second fix had already
corrected.

The update replaces the source with the next revision. Files the next revision
already holds byte for byte lose nothing, so they no longer block it. A file
that differs, staged changes, a rename, or changes on top of the newest
revision still block, and the blocked plan now names the files.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import update_plan  # noqa: E402
from update_plan import build_update_plan  # noqa: E402
from test_update_candidate_fetch import commit_files, git  # noqa: E402
from test_update_plan import (  # noqa: E402
    LOCAL_REVISION,
    REMOTE_REVISION,
    FakeRunner,
    git_handler,
    prepare_installed_daemons,
    prepare_source,
)

GIT = shutil.which("git")
FIX = "def restore():\n    return 'all services'\n"
REDIRECT = "acl host_admin hdr(host) -i admin.example.test\n"


@unittest.skipIf(GIT is None, "needs git")
class WithRealGit(unittest.TestCase):
    """An installed depth-1 checkout, and a next revision with two fixes."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        git("init", "--quiet", cwd=self.remote)
        git("symbolic-ref", "HEAD", "refs/heads/main", cwd=self.remote)
        commit_files(self.remote, {"installer/guard.py": "def restore():\n    return 'some'\n",
                                   "ansible/haproxy.cfg.j2": "frontend fe_http80\n",
                                   "README.md": "readme\n"}, "installed")
        self.url = self.remote.resolve().as_uri()
        self.installed = self.root / "installed"
        git("clone", "--quiet", "--depth=1", "--branch", "main", self.url, str(self.installed), cwd=self.root)
        self.installed_revision = git("rev-parse", "HEAD", cwd=self.installed)
        self.next_revision = commit_files(self.remote, {"installer/guard.py": FIX,
                                                        "ansible/haproxy.cfg.j2": REDIRECT}, "two fixes")

    def edit(self, files):
        for name, text in files.items():
            path = self.installed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def probe(self):
        return update_plan._probe_source(source_dir=self.installed, channel="github", branch="main",
                                         repository=self.url, runner=update_plan.SubprocessRunner())

    def candidate(self):
        destination = self.root / "scratch" / "source"
        destination.parent.mkdir(exist_ok=True)
        found, error = update_plan._remote_candidate(
            source_dir=self.installed, repository=self.url, branch="main",
            expected_revision=self.next_revision, destination=destination,
            runner=update_plan.SubprocessRunner())
        self.assertIsNone(error)
        return found

    def test_a_blocked_source_names_its_files_and_still_learns_the_next_revision(self):
        self.edit({"installer/guard.py": FIX, "ansible/haproxy.cfg.j2": REDIRECT})
        component = self.probe()
        self.assertEqual(component["state"], "blocked")
        self.assertEqual(component["details"]["changed_files"], ["ansible/haproxy.cfg.j2", "installer/guard.py"])
        self.assertEqual(component["current_version"], self.installed_revision)
        self.assertEqual(component["available_version"], self.next_revision)
        self.assertEqual(sorted(path for _, path in component["_local_changes"]),
                         ["ansible/haproxy.cfg.j2", "installer/guard.py"])

    def test_changes_the_next_revision_holds_are_upstream(self):
        self.edit({"installer/guard.py": FIX, "ansible/haproxy.cfg.j2": REDIRECT})
        entries = self.probe()["_local_changes"]
        self.assertTrue(update_plan._local_changes_upstream(self.installed, self.candidate(), entries))

    def test_one_file_that_differs_keeps_the_block(self):
        self.edit({"installer/guard.py": FIX, "ansible/haproxy.cfg.j2": REDIRECT + "# mine\n"})
        entries = self.probe()["_local_changes"]
        self.assertFalse(update_plan._local_changes_upstream(self.installed, self.candidate(), entries))

    def test_a_new_file_the_next_revision_lacks_keeps_the_block(self):
        self.edit({"installer/guard.py": FIX, "ansible/haproxy.cfg.j2": REDIRECT, "notes/todo.txt": "x\n"})
        entries = self.probe()["_local_changes"]
        self.assertIn(("??", "notes/todo.txt"), entries)
        self.assertFalse(update_plan._local_changes_upstream(self.installed, self.candidate(), entries))

    def test_a_deleted_file_the_next_revision_keeps_keeps_the_block(self):
        (self.installed / "README.md").unlink()
        entries = self.probe()["_local_changes"]
        self.assertFalse(update_plan._local_changes_upstream(self.installed, self.candidate(), entries))

    def test_changes_on_top_of_the_newest_revision_stay_blocked_without_a_fetch(self):
        # What the update itself does: fetch the branch and reset to it.
        git("fetch", "--quiet", "--depth=1", "origin", "main", cwd=self.installed)
        git("reset", "--quiet", "--hard", "FETCH_HEAD", cwd=self.installed)
        self.edit({"installer/guard.py": "mine\n"})
        component = self.probe()
        self.assertEqual(component["state"], "blocked")
        self.assertNotIn("_local_changes", component)
        self.assertIsNone(component.get("available_version"))

    def test_a_rename_is_never_taken_as_upstream(self):
        git("mv", "README.md", "README.txt", cwd=self.installed)
        component = self.probe()
        self.assertEqual(component["state"], "blocked")
        self.assertNotIn("_local_changes", component)

    def test_staged_content_is_not_discarded_when_worktree_matches_upstream(self):
        self.edit({"installer/guard.py": "private staged change\n"})
        git("add", "installer/guard.py", cwd=self.installed)
        self.edit({"installer/guard.py": FIX})
        component = self.probe()
        self.assertEqual(component["state"], "blocked")
        self.assertNotIn("_local_changes", component)
        self.assertEqual(git("show", ":installer/guard.py", cwd=self.installed), "private staged change")

    def test_a_staged_deletion_with_a_recreated_file_stays_blocked(self):
        git("rm", "installer/guard.py", cwd=self.installed)
        self.edit({"installer/guard.py": FIX})
        self.assertNotIn("_local_changes", self.probe())


class TheStatusEntries(unittest.TestCase):
    def test_entries_are_read_from_nul_separated_output(self):
        self.assertEqual(update_plan._status_entries(" M a.py\0?? new dir/b.txt\0 D c.py\0"),
                         [(" M", "a.py"), ("??", "new dir/b.txt"), (" D", "c.py")])

    def test_renames_copies_and_odd_paths_are_refused(self):
        self.assertIsNone(update_plan._status_entries("R  new.py\0old.py\0"))
        self.assertIsNone(update_plan._status_entries("C  new.py\0old.py\0"))
        self.assertIsNone(update_plan._status_entries(" M ../outside\0"))
        self.assertIsNone(update_plan._status_entries(" M /etc/passwd\0"))
        self.assertIsNone(update_plan._status_entries("bad\0"))

    def test_staged_changes_and_unmerged_entries_stay_blocked(self):
        for status in ("MM", "M ", "AM", "D ", "UU", "AA", "UD"):
            with self.subTest(status=status):
                self.assertIsNone(update_plan._status_entries(status + " a.py\0"))


class ThePlan(unittest.TestCase):
    """build_update_plan turns a blocked source into an update when it can."""

    def build(self, *, upstream):
        dirty = update_plan._component(
            "all", "blocked",
            "The managed source has local content changes and will not be replaced automatically.",
            current_version=LOCAL_REVISION, available_version=REMOTE_REVISION,
            details={"reason": "local-source-changes", "branch": "main", "changed_paths": 1,
                     "changed_files": ["installer/guard.py"], "network_checked": True})
        dirty["_local_changes"] = [(" M", "installer/guard.py")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)
            candidate = prepare_source(root / "candidate")
            with mock.patch.object(update_plan, "_probe_source", return_value=dirty), \
                    mock.patch.object(update_plan, "_remote_candidate", return_value=(candidate, None)), \
                    mock.patch.object(update_plan, "_local_changes_upstream", return_value=upstream) as compared:
                plan = build_update_plan(
                    source_dir=source, config_dir=root / "config",
                    authelia_compose=root / "missing-authelia.yml", admin_compose=root / "missing-admin.yml",
                    source_channel="github", runner=FakeRunner(git_handler), artifact_path=installed)
        self.assertEqual(compared.call_args.args[2], [(" M", "installer/guard.py")])
        return next(item for item in plan["components"] if item["id"] == "all")

    def test_changes_already_upstream_make_it_an_ordinary_update(self):
        component = self.build(upstream=True)
        # Past the local changes: what holds it now is only that this test
        # has no container stacks to verify, as in the plan tests next door.
        self.assertEqual(component["details"]["reason"], "container-candidate-unavailable")
        self.assertEqual(component["details"]["local_changes"], "in-candidate")
        self.assertEqual(component["available_version"], REMOTE_REVISION)
        self.assertIn("scope", component["details"])
        self.assertNotIn("_local_changes", component)

    def test_the_healed_source_is_the_usual_available_update(self):
        captured = {}
        original = update_plan._probe_services

        def services(source, *args, **kwargs):
            captured.update(source)
            return original(source, *args, **kwargs)

        with mock.patch.object(update_plan, "_probe_services", side_effect=services):
            self.build(upstream=True)
        self.assertEqual(captured["state"], "available")
        self.assertTrue(captured["actionable"])
        self.assertEqual(captured["summary"], "A different remote managed source revision is available.")

    def test_other_changes_keep_the_block_and_name_the_files(self):
        component = self.build(upstream=False)
        self.assertEqual(component["state"], "blocked")
        self.assertFalse(component["actionable"])
        self.assertEqual(component["details"]["changed_files"], ["installer/guard.py"])
        self.assertNotIn("_local_changes", component)


if __name__ == "__main__":
    unittest.main()
