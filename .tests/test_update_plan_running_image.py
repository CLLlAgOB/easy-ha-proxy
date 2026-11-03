"""An image counts as current only when its container runs it (F31).

From the 30 October review, reproduced there with the real _probe_image: it
read the local tag and the registry, never the running container. After a
pull the tag names the new image while the container keeps the old one --
running A, downloaded B, registry B -- and the check said "current", so
nothing offered to recreate the container and a check after an update could
not tell a recreated container from a cached download.

The stack's running containers are now read too and held against the tag by
content (filesystem layers), because the IDs come in kinds that do not
compare: on one gateway a running Redis showed one ID and its tag another
for the very same layers. Unreadable running metadata is "unknown", not an
invented "current".
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import update_plan  # noqa: E402
from update_plan import CommandResult  # noqa: E402

IMAGE = "example/cache:8.1-alpine"
DIGEST = "sha256:" + "b" * 64
CONTAINER = "c" * 64
NEW_ID = "sha256:" + "2" * 64
OLD_ID = "sha256:" + "1" * 64
OTHER_KIND_ID = "sha256:" + "3" * 64
NEW_LAYERS = ["sha256:" + "a" * 64, "sha256:" + "e" * 64]
OLD_LAYERS = ["sha256:" + "a" * 64, "sha256:" + "d" * 64]


class Docker:
    def __init__(self, *, running_id, layers, ps=None):
        self.running_id = running_id
        self.layers = layers
        self.ps = ps

    def run(self, argv, timeout=None):
        argv = tuple(argv)
        if argv[-2:] == ("config", "--images"):
            return CommandResult(0, IMAGE + "\n")
        if argv[-2:] == ("ps", "-q"):
            return self.ps or CommandResult(0, CONTAINER + "\n")
        if argv[:2] == ("docker", "inspect"):
            return CommandResult(0, f"{json.dumps(IMAGE)} {json.dumps(self.running_id)}\n")
        if argv[:3] == ("docker", "buildx", "imagetools"):
            return CommandResult(0, f"Name: {IMAGE}\nDigest: {DIGEST}\n")
        if argv[:3] == ("docker", "image", "inspect") and argv[-1] == "{{json .RepoDigests}}":
            return CommandResult(0, f'["example/cache@{DIGEST}"]\n')
        if argv[:3] == ("docker", "image", "inspect") and argv[-1] == "{{json .RootFS.Layers}}":
            layers = self.layers.get(argv[3])
            return CommandResult(0, json.dumps(layers)) if layers else CommandResult(1, stderr="No such image")
        return CommandResult(1, stderr="unexpected " + " ".join(argv))


class TheStack(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.compose = Path(directory.name) / "docker-compose.yml"
        self.compose.write_text("services: {}\n", encoding="utf-8")

    def probe(self, docker):
        component = update_plan._probe_compose("authelia-container", self.compose, docker)
        return component, component["details"]["images"][0]

    def test_a_container_on_the_old_image_is_not_current(self):
        # running A, downloaded B, registry B: the reported case.
        docker = Docker(running_id=OLD_ID, layers={IMAGE: NEW_LAYERS, OLD_ID: OLD_LAYERS})
        component, image = self.probe(docker)
        self.assertEqual(component["state"], "available")
        self.assertEqual(image["reason"], "running-older-image")
        self.assertEqual(image["running_image"], OLD_ID)

    def test_the_same_content_under_another_kind_of_id_is_current(self):
        docker = Docker(running_id=OTHER_KIND_ID, layers={IMAGE: NEW_LAYERS, OTHER_KIND_ID: NEW_LAYERS})
        component, image = self.probe(docker)
        self.assertEqual(component["state"], "current")
        self.assertEqual(image["running"], "same-content")

    def test_running_metadata_that_cannot_be_read_is_unknown(self):
        docker = Docker(running_id=OLD_ID, layers={IMAGE: NEW_LAYERS})
        component, image = self.probe(docker)
        self.assertEqual(component["state"], "unknown")
        self.assertEqual(image["reason"], "running-image-unreadable")

    def test_a_stack_that_cannot_be_listed_says_so(self):
        docker = Docker(running_id=OLD_ID, layers={}, ps=CommandResult(1, stderr="daemon down"))
        component, image = self.probe(docker)
        self.assertEqual(component["state"], "current")
        self.assertEqual(image["running"], "unchecked")

    def test_a_stopped_stack_is_judged_by_its_tag(self):
        docker = Docker(running_id=OLD_ID, layers={}, ps=CommandResult(0, ""))
        component, _ = self.probe(docker)
        self.assertEqual(component["state"], "current")


class TheAdminImage(unittest.TestCase):
    def test_a_panel_still_on_the_old_image_is_offered_the_new(self):
        image = "ghcr.io/example/haproxy-admin-ui:alpha"

        class AdminDocker(Docker):
            def run(self, argv, timeout=None):
                argv = tuple(argv)
                if argv[-2:] == ("config", "--images"):
                    return CommandResult(0, image + "\n")
                if argv[-2:] == ("ps", "-q"):
                    return CommandResult(0, CONTAINER + "\n")
                if argv[:2] == ("docker", "inspect"):
                    return CommandResult(0, f"{json.dumps(image)} {json.dumps(OLD_ID)}\n")
                if argv[:3] == ("docker", "image", "inspect") and argv[-1] == "{{json .RootFS.Layers}}":
                    return CommandResult(0, json.dumps(NEW_LAYERS if argv[3] == image else OLD_LAYERS))
                if argv[:3] == ("docker", "image", "inspect") and argv[-1] == "{{json .RepoDigests}}":
                    return CommandResult(0, f'["ghcr.io/example/haproxy-admin-ui@{DIGEST}"]\n')
                if argv[:3] == ("docker", "buildx", "imagetools"):
                    return CommandResult(0, f"Name: {image}\nDigest: {DIGEST}\n")
                return CommandResult(1, stderr="not asked")

        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            component = update_plan._probe_admin_compose(
                compose, AdminDocker(running_id=OLD_ID, layers={}),
                configured_image=image, configured_channel="alpha", target_channel="alpha",
            )
        self.assertEqual(component["state"], "available")
        self.assertEqual(component["details"]["images"][0]["reason"], "running-older-image")


if __name__ == "__main__":
    unittest.main()
