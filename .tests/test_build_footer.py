"""Every page offers the panel and host builds, with a mismatch warning.

The operator keeps several gateways and could not tell, from the panel,
which had which change. The footer keeps details of two builds -- the host's
managed source, which the update broker reads, and the panel image's, which
CI bakes in -- each as its commit's time and short hash, under one date. The hosts hold a
shallow clone, so a commit count would always be 1. When the panel was
built from other web files than the host has, the footer says so: the same
`git ls-tree` fingerprint CI labels the image with is compared on both sides.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
WINDOWS = sys.platform == "win32"
sys.path.insert(0, str(ROOT / "docker" / "app"))
if not WINDOWS:
    from haproxy_admin import build_info  # noqa: E402

TREE_A = "a" * 64
TREE_B = "b" * 64


def load_broker():
    name = "easy_ha_proxy_updated_build_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def git(root, *args):
    environment = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.test",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.test",
                       GIT_COMMITTER_DATE="2026-11-03T15:16:44+01:00")
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          text=True, env=environment).stdout


@unittest.skipIf(WINDOWS, "the broker needs fcntl")
@unittest.skipUnless(shutil.which("git"), "git is not installed here")
class TheHostBuild(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "docker/app").mkdir(parents=True)
        (self.root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (self.root / ".dockerignore").write_text("*.pyc\n", encoding="utf-8")
        (self.root / "docker/app/app.py").write_text("print()\n", encoding="utf-8")
        (self.root / "README.md").write_text("not a web file\n", encoding="utf-8")
        git(self.root, "init", "-q")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "one")
        self.broker = load_broker()
        patcher = mock.patch.object(self.broker, "SOURCE_DIR", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_it_names_the_commit_its_time_and_its_web_files(self):
        build = self.broker._read_host_build()
        self.assertEqual(build["revision"], git(self.root, "rev-parse", "HEAD").strip())
        self.assertEqual(build["committed_at"], "2026-11-03T14:16:44+00:00")
        # The very sum CI computes: git ls-tree ... | sha256sum
        listing = git(self.root, "ls-tree", "-r", "--full-tree", "HEAD", "--",
                      "Dockerfile", ".dockerignore", "docker/app")
        self.assertEqual(build["web_tree"], hashlib.sha256(listing.encode("utf-8")).hexdigest())

    def test_the_summary_carries_it_and_reads_git_once_a_minute(self):
        with mock.patch.object(self.broker, "_read_host_build", wraps=self.broker._read_host_build) as read:
            first = self.broker.summary_payload(None)["build"]
            self.broker.summary_payload(None)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(first["revision"], git(self.root, "rev-parse", "HEAD").strip())

    def test_no_checkout_is_no_build(self):
        with mock.patch.object(self.broker, "SOURCE_DIR", self.root / "absent"):
            self.assertIsNone(self.broker._read_host_build())

    def test_ci_and_the_broker_fingerprint_the_same_files(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("git ls-tree -r --full-tree HEAD -- Dockerfile .dockerignore docker/app", workflow)
        self.assertEqual(self.broker.WEB_TREE_INPUTS, ("Dockerfile", ".dockerignore", "docker/app"))


@unittest.skipIf(WINDOWS, "the admin package needs fcntl")
class TheFooter(unittest.TestCase):
    def footer(self, host, *, tree=TREE_A):
        env = {"EHP_BUILD_REVISION": "0bf3ce31f3841e86dcb2bb682861f7d895365217",
               "EHP_BUILD_DATE": "2026-11-03T15:16:44+01:00", "EHP_SOURCE_TREE": tree}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(build_info.updates_badge, "host_build", return_value=host):
            return build_info.footer()

    def test_both_builds_and_a_match(self):
        footer = self.footer({"revision": "b9ebe91648a0227fbbe4da629896b64c5cf3ac9b",
                              "committed_at": "2026-11-03T16:00:00+00:00", "web_tree": TREE_A})
        self.assertEqual(footer["panel"]["revision"], "0bf3ce3")
        self.assertEqual(footer["host"]["revision"], "b9ebe91")
        self.assertEqual(footer["panel"]["when"], "2026-11-03 14:16 UTC")
        self.assertIs(footer["match"], True)

    def test_build_dates_are_identical_across_gateway_timezones(self):
        for zone in ('Europe/Moscow', 'Europe/Warsaw'):
            with self.subTest(zone=zone), mock.patch.dict(os.environ, TZ=zone):
                self.assertEqual(build_info._when('2026-11-05T14:12:01+01:00'),
                                 '2026-11-05 13:12 UTC')

    def test_other_web_files_are_a_mismatch(self):
        footer = self.footer({"revision": "b9ebe91", "committed_at": "", "web_tree": TREE_B})
        self.assertIs(footer["match"], False)

    def test_an_unknown_side_is_not_called_a_mismatch(self):
        self.assertIsNone(self.footer(None)["match"])
        self.assertIsNone(self.footer({"revision": "b9ebe91", "web_tree": ""})["match"])
        self.assertIsNone(self.footer({"revision": "b9ebe91", "web_tree": TREE_A}, tree="")["match"])

    def test_a_hand_built_image_shows_no_panel_build(self):
        with mock.patch.dict(os.environ, {"EHP_BUILD_REVISION": ""}), \
                mock.patch.object(build_info.updates_badge, "host_build", return_value=None):
            self.assertIsNone(build_info.footer()["panel"])


class TheWiring(unittest.TestCase):
    def render(self, match, *, same_revision=False):
        environment = Environment(loader=FileSystemLoader(APP / 'templates'), autoescape=True)
        return environment.get_template('base.html').render(
            build=dict(match=match,
                       host=dict(revision='aaaaaaa', when='2026-11-05 10:00 UTC'),
                       panel=dict(revision='aaaaaaa' if same_revision else 'bbbbbbb', when='2026-11-04 10:00 UTC')),
            g=SimpleNamespace(is_superadmin=False),
            request=SimpleNamespace(full_path='/', endpoint='routes.index'),
            url_for=lambda name, **kwargs: '/' + name, csrf_token=lambda: 'test',
            i18n_config={}, supported_languages=[], current_language='en',
        )

    def test_reused_images_are_explained_without_an_update_warning(self):
        html = self.render(True)
        self.assertIn('Panel files match the host. The existing image was reused.', html)
        self.assertNotIn('<span class="footer-build-mismatch">', html)
        self.assertIn('2026-11-05 10:00 UTC', html)

    def test_real_mismatches_and_unverifiable_builds_stay_distinct(self):
        html = self.render(False)
        self.assertIn('<span class="footer-build-mismatch">', html)
        self.assertNotIn('The existing image was reused.', html)
        html = self.render(None)
        self.assertIn('Build comparison is unavailable.', html)
        self.assertNotIn('The existing image was reused.', html)
        self.assertNotIn('<span class="footer-build-mismatch">', html)

    def test_identical_revisions_do_not_claim_image_reuse(self):
        self.assertNotIn('The existing image was reused.', self.render(True, same_revision=True))

    def test_the_image_and_ci_carry_the_build(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        for name in ("EHP_BUILD_REVISION", "EHP_BUILD_DATE", "EHP_SOURCE_TREE"):
            self.assertIn(f"ARG {name}=", dockerfile)
            self.assertIn(f"{name}=${{{name}}}", dockerfile)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('--build-arg "EHP_BUILD_REVISION=${GITHUB_SHA}"', workflow)
        self.assertIn('--build-arg "EHP_SOURCE_TREE=${TREE}"', workflow)

    def test_the_footer_keeps_details_and_translates_whole(self):
        base = (APP / "templates/base.html").read_text(encoding="utf-8")
        self.assertIn("build.host.when", base)
        self.assertIn("build.panel.revision", base)
        self.assertIn("build.match is sameas false", base)
        try:
            spec = importlib.util.spec_from_file_location("build_footer_i18n", APP / "i18n.py")
            i18n = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(i18n)
        except ImportError:
            self.skipTest("the panel's dependencies are not installed here")
        for text in ("Build", "Show build details", "Date unavailable", "Host build", "Panel build",
                     "Build comparison is unavailable.",
                     "Panel files match the host. The existing image was reused.",
                     "Build times use UTC on every gateway.",
                     "Host and panel files differ. Check the update status."):
            self.assertNotEqual(i18n.translate(text, "ru"), text)


if __name__ == "__main__":
    unittest.main()
