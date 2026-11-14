"""Bootstrap must apply the fetched branch even in a single-branch clone."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BootstrapBranchSwitch(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.origin = self.root / "origin"
        self.source = self.root / "installed"
        self.origin.mkdir()
        self.git("init", "--quiet", "-b", "main", cwd=self.origin)
        self.commit("main")
        self.git("checkout", "--quiet", "-b", "alpha", cwd=self.origin)
        self.commit("alpha")
        self.alpha = self.git("rev-parse", "HEAD", cwd=self.origin).stdout.strip()
        self.git("clone", "--quiet", "--depth=1", "--branch", "main",
                 self.origin.as_uri(), str(self.source))

    def git(self, *args, cwd=None, check=True):
        return subprocess.run(["git", *args], cwd=cwd, check=check, text=True,
                              capture_output=True)

    def commit(self, content):
        (self.origin / "payload").write_text(content + "\n", encoding="utf-8")
        self.git("add", "payload", cwd=self.origin)
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--quiet", "-m", content, cwd=self.origin)

    def update(self, branch):
        # Execute the checkout-update block from the real bootstrap. Nothing
        # outside this block (APT, venv setup, entrypoints or services) runs.
        source = (ROOT / "install-local.sh").read_text(encoding="utf-8")
        block = source.split('elif [[ -d "${source_dir}/.git" ]]; then\n', 1)[1]
        block = block.split('elif [[ -e "${source_dir}" ]]; then', 1)[0]
        return subprocess.run(
            ["bash", "-c", "set -Eeuo pipefail\nlog() { :; }\n" + block],
            env={**os.environ, "source_dir": str(self.source), "branch": branch},
            text=True, capture_output=True,
        )

    def test_switches_to_a_branch_absent_from_the_clone_refspec(self):
        self.assertIn("refs/heads/main", self.git("config", "--get", "remote.origin.fetch",
                                               cwd=self.source).stdout)
        self.assertNotEqual(self.git("rev-parse", "--verify", "refs/remotes/origin/alpha",
                                     cwd=self.source, check=False).returncode, 0)
        result = self.update("alpha")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.source).stdout.strip(), self.alpha)
        self.assertEqual((self.source / "payload").read_text(), "alpha\n")

    def test_does_not_reset_to_a_stale_remote_tracking_ref(self):
        self.git("fetch", "origin", "alpha:refs/remotes/origin/alpha", cwd=self.source)
        old_alpha = self.git("rev-parse", "origin/alpha", cwd=self.source).stdout.strip()
        self.commit("new alpha")
        current_alpha = self.git("rev-parse", "HEAD", cwd=self.origin).stdout.strip()
        result = self.update("alpha")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(old_alpha, current_alpha)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.source).stdout.strip(), current_alpha)

    def test_failed_fetch_leaves_the_current_checkout_untouched(self):
        before = self.git("rev-parse", "HEAD", cwd=self.source).stdout
        result = self.update("missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.source).stdout, before)
        self.assertEqual((self.source / "payload").read_text(), "main\n")


if __name__ == "__main__":
    unittest.main()
