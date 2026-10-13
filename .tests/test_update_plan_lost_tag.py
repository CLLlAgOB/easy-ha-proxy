"""A pinned image whose local tag went missing does not block every update.

On a gateway the mail relay was running from a pinned tag. Something -- a
cleanup tool, a pull of another tag of the same image -- dropped that tag
while the image itself stayed, kept alive by its container and still listed
under another name. Asked for by tag, Docker answered "No such image" about
an image that was running, the update check could not read its digest, and
because the stack is never updated partially that one lost label blocked the
complete update for good.

The registry had already said what the tag points to. The check now asks
Docker for that content by digest: if it is on the machine, the image is
current, whatever name it is filed under.
"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import update_plan  # noqa: E402
from update_plan import CommandResult  # noqa: E402


IMAGE = "example/relay:1.9.0"
DIGEST = "sha256:" + "9" * 64
OTHER = "sha256:" + "1" * 64
NO_SUCH = CommandResult(1, stderr=f"Error response from daemon: No such image: {IMAGE}")


class Docker:
    """Answers the three questions the probe asks, and records them."""

    def __init__(self, *, by_tag, registry, by_content=None):
        self.answers = {"tag": by_tag, "registry": registry, "content": by_content}
        self.asked = []

    def run(self, argv, timeout=None):
        argv = tuple(argv)
        self.asked.append(argv)
        if argv[:3] == ("docker", "buildx", "imagetools"):
            return self.answers["registry"]
        if "@sha256:" in argv[3]:
            return self.answers["content"] or CommandResult(1, stderr="No such image")
        return self.answers["tag"]


def registry(digest):
    return CommandResult(0, stdout=f"Name: {IMAGE}\nDigest: {digest}\n")


def local(digest):
    return CommandResult(0, stdout=f'["example/relay@{digest}"]\n')


class TheTagIsGoneButTheImageIsHere(unittest.TestCase):
    def test_the_image_is_current(self):
        # The reported case.
        docker = Docker(by_tag=NO_SUCH, registry=registry(DIGEST), by_content=local(DIGEST))
        result = update_plan._probe_image(IMAGE, docker)
        self.assertEqual(result["state"], "current")
        self.assertEqual(result["current_digest"], DIGEST)
        self.assertEqual(result["available_digest"], DIGEST)
        self.assertEqual(result["reason"], "local-tag-missing")
        self.assertNotIn("error", result)

    def test_it_is_looked_up_by_what_the_registry_offers(self):
        docker = Docker(by_tag=NO_SUCH, registry=registry(DIGEST), by_content=local(DIGEST))
        update_plan._probe_image(IMAGE, docker)
        self.assertIn(
            ("docker", "image", "inspect", f"example/relay@{DIGEST}",
             "--format", "{{json .RepoDigests}}"),
            docker.asked,
        )


class NothingElseChanges(unittest.TestCase):
    def test_an_image_that_really_is_absent_is_still_unknown(self):
        docker = Docker(by_tag=NO_SUCH, registry=registry(DIGEST))
        result = update_plan._probe_image(IMAGE, docker)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "local-digest-unavailable")
        self.assertIn("No such image", result["error"])

    def test_a_tag_that_is_there_is_not_asked_about_twice(self):
        docker = Docker(by_tag=local(DIGEST), registry=registry(DIGEST))
        self.assertEqual(update_plan._probe_image(IMAGE, docker)["state"], "current")
        self.assertEqual(len(docker.asked), 2)

    def test_a_newer_image_in_the_registry_is_still_an_update(self):
        docker = Docker(by_tag=local(OTHER), registry=registry(DIGEST))
        result = update_plan._probe_image(IMAGE, docker)
        self.assertEqual(result["state"], "available")
        self.assertEqual(result["current_digest"], OTHER)

    def test_without_the_registry_there_is_nothing_to_look_up(self):
        docker = Docker(by_tag=NO_SUCH, registry=CommandResult(1, stderr="timeout"))
        result = update_plan._probe_image(IMAGE, docker)
        self.assertEqual(result["reason"], "local-digest-unavailable")
        self.assertEqual(len(docker.asked), 2)


if __name__ == "__main__":
    unittest.main()
