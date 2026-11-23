"""A gateway running the Go panel is checked against the Go panel's tag.

The deployment picks "<repo>:go-<channel>" when haproxy_admin_use_go_panel
is set, while vars.yml keeps "<repo>:<channel>". The check used to target
the plain tag, offered a "channel change" every night that the deployment
then undid, and the applied digest never matched the reviewed plan.
"""
from pathlib import Path
import json
import tempfile
import unittest

import update_plan
from update_plan import CommandResult

DIGEST = "sha256:" + "2" * 64
OTHER = "sha256:" + "9" * 64


class Docker:
    def __init__(self, running_image):
        self.running_image = running_image
        self.inspected = []

    def run(self, argv, *, timeout):
        args = tuple(argv)
        if args[-2:] == ("config", "--images"):
            return CommandResult(0, self.running_image + "\n")
        if args[-2:] == ("ps", "-q"):
            return CommandResult(0, "")
        if args[:3] == ("docker", "buildx", "imagetools"):
            self.inspected.append(args[-1])
            if args[-1] == "{{json .Image}}":
                return CommandResult(0, json.dumps({"config": {"Labels": {}}}))
            digest = DIGEST if args[4].endswith(":go-alpha") else OTHER
            return CommandResult(0, "Digest: " + digest)
        if args[:3] == ("docker", "image", "inspect"):
            if args[-1] == "{{json .RepoDigests}}":
                return CommandResult(0, json.dumps(["example/panel@" + DIGEST]))
            return CommandResult(0, "{}")
        return CommandResult(1, stderr="unexpected probe")


def probe(docker, configured="example/panel:alpha"):
    with tempfile.TemporaryDirectory() as directory:
        compose = Path(directory) / "compose.yml"
        compose.write_text("services: {}\n", encoding="utf-8")
        return update_plan._probe_admin_compose(
            compose, docker, configured_image=configured,
            configured_channel="alpha", target_channel="alpha",
        )


class GoPanelFlavour(unittest.TestCase):
    def test_go_panel_is_compared_with_its_own_tag(self):
        panel = probe(Docker("example/panel:go-alpha"))
        image = panel["details"]["images"][0]
        self.assertEqual(image["target_image"], "example/panel:go-alpha")
        self.assertNotEqual(image.get("reason"), "image-channel-change")
        self.assertEqual(image["state"], "current")

    def test_flask_panel_keeps_the_plain_tag(self):
        panel = probe(Docker("example/panel:alpha"))
        self.assertEqual(panel["details"]["images"][0]["target_image"], "example/panel:alpha")

    def test_flavour_helpers(self):
        self.assertEqual(update_plan._panel_flavour("r/p:go-alpha"), "go-")
        self.assertEqual(update_plan._panel_flavour("r/p:go-nightly"), "")
        self.assertEqual(update_plan._panel_flavour("r/p:alpha"), "")
        self.assertEqual(update_plan._flavoured("r/p:latest", "go-"), "r/p:go-latest")
        self.assertEqual(update_plan._flavoured("r/p:go-latest", "go-"), "r/p:go-latest")


if __name__ == "__main__":
    unittest.main()
