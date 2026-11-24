"""The native binaries come from the image CI built for the installed revision."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible/roles/haproxy-admin/tasks/native.yml"
REV = "0123456789abcdef0123456789abcdef01234567"

# A stand-in for the docker CLI: knows the images in $IMAGES (JSON: tag ->
# revision label), logs every call to $CALLS, and fakes the bundle files.
FAKE_DOCKER = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
images = json.loads(os.environ["IMAGES"])
with open(os.environ["CALLS"], "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
cmd = sys.argv[1:]
if cmd[0] == "pull":
    sys.exit(0 if cmd[1] in images else 1)
if cmd[:2] == ["image", "inspect"]:
    fmt, img = cmd[3], cmd[4]
    if "RepoDigests" in fmt:
        print(img.split(":")[0] + "@sha256:" + hashlib.sha256(img.encode()).hexdigest())
    else:
        print(images[img])
    sys.exit(0)
if cmd[0] == "create":
    print("cid-1")
    sys.exit(0)
if cmd[0] == "cp":
    src, dest = cmd[1].split(":", 1)[1], cmd[2]
    stage = os.path.dirname(dest)
    if src == "/SHA256SUMS":
        with open(dest, "w") as out:
            for d in ("sbin", "lib"):
                for name in sorted(os.listdir(os.path.join(stage, d))):
                    data = open(os.path.join(stage, d, name), "rb").read()
                    out.write("%s  %s/%s\n" % (hashlib.sha256(data).hexdigest(), d, name))
    else:
        os.makedirs(dest)
        open(os.path.join(dest, "easy-ha-proxy-agent" if src == "/sbin" else "libguardd_core.so"), "w").write(src)
    sys.exit(0)
sys.exit(0)
'''


def pull_script() -> str:
    for block in yaml.safe_load(TASKS.read_text(encoding="utf-8")):
        for task in block.get("block", [block]):
            if task.get("name") == "native-daemons | Pull and verify native binary bundle from OCI image":
                return task["ansible.builtin.shell"]
    raise AssertionError("pull task not found")


@unittest.skipIf(sys.platform == "win32", "runs the rendered bash script")
class NativePinningTests(unittest.TestCase):
    def run_pull(self, images, revision_rc=0):
        from jinja2 import Environment
        env = Environment()
        env.filters["quote"] = lambda value: shlex.quote(str(value))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            stage.mkdir()
            script = env.from_string(pull_script()).render(
                native_release_image="clllagob/haproxy-admin-ui:native-alpha",
                _native_source_revision={"rc": revision_rc, "stdout": REV + "\n"},
            ).replace("/var/lib/easy-ha-proxy/native-staging", str(stage))
            bindir = root / "bin"
            bindir.mkdir()
            (bindir / "docker").write_text(FAKE_DOCKER)
            (bindir / "docker").chmod(0o755)
            calls = root / "calls"
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, timeout=30,
                env=dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                         IMAGES=json.dumps(images), CALLS=str(calls)))
            image_json = (stage / "image.json").read_text() if (stage / "image.json").exists() else ""
            return result, calls.read_text().splitlines() if calls.exists() else [], image_json

    def test_the_commit_image_is_pulled_checked_and_copied_by_digest(self):
        pinned = "clllagob/haproxy-admin-ui:native-alpha-" + REV[:12]
        result, calls, image_json = self.run_pull({pinned: REV, "clllagob/haproxy-admin-ui:native-alpha": "other"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pull " + pinned, calls)
        self.assertNotIn("pull clllagob/haproxy-admin-ui:native-alpha", calls)
        created = next(c for c in calls if c.startswith("create "))
        self.assertIn("@sha256:", created)
        record = json.loads(image_json)
        self.assertEqual((record["image"], record["revision"]), (pinned, REV))
        self.assertTrue(record["digest"].startswith("clllagob/haproxy-admin-ui@sha256:"))

    def test_an_image_built_from_another_commit_is_refused(self):
        pinned = "clllagob/haproxy-admin-ui:native-alpha-" + REV[:12]
        result, calls, _ = self.run_pull({pinned: "f" * 40})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not " + REV, result.stderr)
        self.assertFalse(any(c.startswith("create ") for c in calls))

    def test_an_unpublished_commit_stops_rather_than_taking_the_channel_tag(self):
        result, calls, _ = self.run_pull({"clllagob/haproxy-admin-ui:native-alpha": "other"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not published", result.stderr)
        self.assertEqual([c for c in calls if c.startswith("pull ")],
                         ["pull clllagob/haproxy-admin-ui:native-alpha-" + REV[:12]])

    def test_without_a_git_checkout_the_channel_tag_is_used(self):
        result, calls, _ = self.run_pull({"clllagob/haproxy-admin-ui:native-alpha": "whatever"}, revision_rc=128)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pull clllagob/haproxy-admin-ui:native-alpha", calls)


if __name__ == "__main__":
    unittest.main()
