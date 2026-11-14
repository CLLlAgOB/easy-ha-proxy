"""A tag the registry published again, with the same image for this platform.

The reported failure, on an ARM gateway: the sessions Redis tag was published
again upstream. Its index got a new digest, but the image for arm64 did not
change. The check offered the Redis update. Installing it pulled the new
index, and Docker filed it as a second digest of the image already there:
one image ID, two RepoDigests. The check after the install read only the first
of them, still the old index, and the install failed with "an applied image
digest differs from the reviewed update plan". Every later check would have
offered the same update again, and every install would have failed the same way.

The local image is now current when any of its digests is the one the
registry offers.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import update_plan  # noqa: E402
from update_plan import CommandResult  # noqa: E402


IMAGE = "example/sessions:8.1-alpine"
OLD = "sha256:" + "7" * 64
NEW = "sha256:" + "a" * 64


class Docker:
    def __init__(self, *, local, registry):
        self.local, self.registry = local, registry

    def run(self, argv, timeout=None):
        if tuple(argv[:3]) == ("docker", "buildx", "imagetools"):
            return self.registry
        return self.local


def registry(digest):
    return CommandResult(0, stdout=f"Name: {IMAGE}\nMediaType: application/vnd.oci.image.index.v1+json\nDigest: {digest}\n")


def repo_digests(*digests):
    return CommandResult(0, stdout="[" + ",".join(f'"example/sessions@{d}"' for d in digests) + "]\n")


class TheImageCarriesBothDigests(unittest.TestCase):
    def test_it_is_current_whichever_digest_docker_lists_first(self):
        for order in ((OLD, NEW), (NEW, OLD)):
            result = update_plan._probe_image(IMAGE, Docker(local=repo_digests(*order), registry=registry(NEW)))
            self.assertEqual(result["state"], "current", order)
            self.assertEqual(result["current_digest"], NEW)
            self.assertEqual(result["available_digest"], NEW)

    def test_an_image_without_the_offered_digest_still_has_an_update(self):
        result = update_plan._probe_image(IMAGE, Docker(local=repo_digests(OLD), registry=registry(NEW)))
        self.assertEqual(result["state"], "available")
        self.assertEqual(result["current_digest"], OLD)

    def test_without_the_registry_the_first_digest_is_reported_as_before(self):
        self.assertEqual(update_plan._local_digest(repo_digests(OLD, NEW).stdout), OLD)
        self.assertEqual(update_plan._local_digest(repo_digests(OLD, NEW).stdout, None), OLD)
        self.assertIsNone(update_plan._local_digest("[]\n", NEW))

    def test_a_digest_listed_twice_is_one_digest(self):
        self.assertEqual(update_plan._local_digests(repo_digests(OLD, OLD, NEW).stdout), [OLD, NEW])

    def test_the_panel_image_is_read_the_same_way(self):
        source = (ROOT / "installer/update_plan.py").read_text(encoding="utf-8")
        start = source.index("def _probe_admin_compose(")
        body = source[start:source.index("\ndef ", start + 1)]
        self.assertIn("_local_digest(local_result.stdout, candidate)", body)


class TheCheckAfterTheInstall(unittest.TestCase):
    """The broker compares the reviewed plan with the check after the install."""

    def test_the_reviewed_digest_is_found_after_the_pull(self):
        reviewed = update_plan._probe_image(IMAGE, Docker(local=repo_digests(OLD), registry=registry(NEW)))
        after = update_plan._probe_image(IMAGE, Docker(local=repo_digests(OLD, NEW), registry=registry(NEW)))
        self.assertEqual(reviewed["available_digest"], after["current_digest"])


if __name__ == "__main__":
    unittest.main()
