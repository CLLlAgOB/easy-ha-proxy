"""A source update that re-pins an image is named in the plan it is applied by.

The reported failure: a complete update on a gateway brought a source tree
that moved Authelia from one pinned version to the next. The plan had probed
the Compose file Ansible rendered from the installed source, so it listed the
old version as current. Ansible installed the new one -- correctly -- and the
check after the update found a digest the reviewed plan never mentioned and
reported "an applied image digest differs from the reviewed update plan" for
an update that had succeeded. The page then showed that message with two
words of it in Russian.

So the checker compares the Authelia role defaults of the installed and the
candidate source, probes the image each re-pinned reference will become,
lists the change against the complete update, and stops offering the
container update on its own -- which keeps the old pins and could never
deliver it. And the server translator substitutes only catalogue entries
written as sentence fragments, not two-word labels.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))

import update_plan  # noqa: E402
from update_plan import CommandResult, build_update_plan  # noqa: E402
from test_update_plan import (  # noqa: E402
    REMOTE_REVISION,
    FakeRunner,
    git_handler,
    prepare_installed_daemons,
    prepare_source,
)


DAEMON_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
I18N_PATH = ROOT / "docker/app/haproxy_admin/i18n.py"
UPDATES_JS = ROOT / "docker/app/haproxy_admin/static/js/system_updates.js"
DEFAULTS = "ansible/roles/authelia/defaults/main.yml"
OLD = "authelia/authelia:4.39.20"
NEW = "authelia/authelia:4.39.28"
OLD_DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64
REDIS = "redis:7.4.9-alpine"
REDIS_DIGEST = "sha256:" + "c" * 64
ADMIN_DIGEST = "sha256:" + "d" * 64


def load_daemon():
    name = "easy_ha_proxy_updated_repin_test"
    spec = importlib.util.spec_from_file_location(name, DAEMON_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


UPDATED = load_daemon()


def write_defaults(root: Path, version: str) -> None:
    path = root / DEFAULTS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'authelia_version: "{version}"\n'
        f'authelia_redis_image: "{REDIS}"\n',
        encoding="utf-8",
    )


class TheSourceImageChangesAreRead(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.installed = Path(temporary.name) / "installed"
        self.candidate = Path(temporary.name) / "candidate"
        write_defaults(self.installed, "4.39.20")
        write_defaults(self.candidate, "4.39.28")

    def test_a_new_pin_is_a_change_from_the_old_reference_to_the_new(self):
        self.assertEqual(
            update_plan._source_image_changes(self.installed, self.candidate, {}),
            {OLD: NEW},
        )

    def test_an_operator_override_wins_over_both_defaults(self):
        # Ansible applies vars.yml over the role defaults, so the rendered
        # file keeps the operator's version whatever the source pins.
        self.assertEqual(
            update_plan._source_image_changes(
                self.installed, self.candidate, {"authelia_version": "4.39.15"}
            ),
            {},
        )

    def test_no_candidate_or_no_change_is_no_change(self):
        self.assertEqual(
            update_plan._source_image_changes(self.installed, None, {}), {}
        )
        write_defaults(self.candidate, "4.39.20")
        self.assertEqual(
            update_plan._source_image_changes(self.installed, self.candidate, {}),
            {},
        )

    def test_an_unreadable_tree_is_no_change_rather_than_an_error(self):
        (self.candidate / DEFAULTS).unlink()
        self.assertEqual(
            update_plan._source_image_changes(self.installed, self.candidate, {}),
            {},
        )


def gateway(root: Path, *, compose_images: str, candidate_version: str):
    """Build a plan on a GitHub-channel gateway whose source is behind."""

    source = prepare_source(root)
    write_defaults(source, "4.39.20")
    installed = prepare_installed_daemons(root, source)
    config = root / "config"
    config.mkdir(exist_ok=True)
    (config / "metadata.yml").write_text(
        "source_channel: github\nimage_channel: alpha\n", encoding="utf-8"
    )
    authelia_compose = root / "opt/authelia/docker-compose.yml"
    admin_compose = root / "opt/haproxy-admin/docker-compose.yml"
    for path in (authelia_compose, admin_compose):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("services: {}\n", encoding="utf-8")

    local = {OLD: OLD_DIGEST, NEW: NEW_DIGEST, REDIS: REDIS_DIGEST}
    remote = {OLD: OLD_DIGEST, NEW: NEW_DIGEST, REDIS: REDIS_DIGEST}

    def handler(command):
        if command[:2] == ("git", "clone"):
            candidate = Path(command[-1])
            shutil.copytree(source, candidate)
            write_defaults(candidate, candidate_version)
            return CommandResult(0)
        if command[-2:] == ("rev-parse", "HEAD") and Path(command[2]) != source:
            return CommandResult(0, REMOTE_REVISION + "\n")
        if command[0] == "git":
            return git_handler(command)
        if command == ("apt-get", "-s", "upgrade"):
            return CommandResult(0, "")
        if command[:3] == ("docker", "compose", "-f"):
            if Path(command[3]) == authelia_compose:
                return CommandResult(0, compose_images)
            return CommandResult(0, "example/haproxy-admin:alpha\n")
        if command[:3] == ("docker", "image", "inspect"):
            image = command[3]
            digest = local.get(image, ADMIN_DIGEST)
            return CommandResult(0, json.dumps([f"{image.split(':')[0]}@{digest}"]))
        if command[:4] == ("docker", "buildx", "imagetools", "inspect"):
            image = command[4]
            digest = remote.get(image, ADMIN_DIGEST)
            return CommandResult(0, f"Name: {image}\nDigest: {digest}\n")
        raise AssertionError(f"unexpected command: {command!r}")

    return build_update_plan(
        source_dir=source,
        config_dir=config,
        authelia_compose=authelia_compose,
        admin_compose=admin_compose,
        runner=FakeRunner(handler),
        artifact_path=installed,
    )


class ThePlanNamesTheRepinAndTheCheckAfterAgrees(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def reviewed(self):
        return gateway(
            self.root / "before",
            compose_images=f"{OLD}\n{REDIS}\n",
            candidate_version="4.39.28",
        )

    def test_the_change_is_listed_against_the_complete_update(self):
        plan = self.reviewed()
        components = {item["id"]: item for item in plan["components"]}
        self.assertEqual(components["all"]["state"], "available")
        self.assertEqual(components["all"]["details"]["image_changes"], {OLD: NEW})
        authelia = components["authelia-container"]
        self.assertEqual(authelia["state"], "available")
        self.assertIs(authelia["actionable"], False)
        self.assertEqual(authelia["details"]["depends_on"], "all")
        images = {item["image"]: item for item in authelia["details"]["images"]}
        self.assertEqual(images[OLD]["target_image"], NEW)
        self.assertEqual(images[OLD]["current_digest"], OLD_DIGEST)
        self.assertEqual(images[OLD]["available_digest"], NEW_DIGEST)
        self.assertNotIn("target_image", images[REDIS])
        self.assertNotIn("authelia-container", plan["actionable_components"])

    def test_the_container_update_alone_is_not_offered(self):
        # It keeps the old pins, so it could never deliver the new version.
        plan = self.reviewed()
        with (
            mock.patch.object(UPDATED, "validate_plan_channel"),
            self.assertRaises(UPDATED.UpdatedError) as raised,
        ):
            UPDATED.validate_selection(plan, ["authelia-container"])
        self.assertEqual(raised.exception.code, "stale_plan")

    def test_the_check_after_a_successful_update_passes(self):
        # The reported case, end to end: what the gateway runs afterwards is
        # exactly what the reviewed plan said it would.
        reviewed = self.reviewed()
        applied = gateway(
            self.root / "after",
            compose_images=f"{NEW}\n{REDIS}\n",
            candidate_version="4.39.20",
        )
        UPDATED.validate_applied_container_digests(reviewed, applied, ["all"])

    def test_the_check_still_catches_a_different_image(self):
        reviewed = self.reviewed()
        applied = gateway(
            self.root / "after",
            compose_images=f"{OLD}\n{REDIS}\n",
            candidate_version="4.39.20",
        )
        with self.assertRaises(UPDATED.UpdatedError) as raised:
            UPDATED.validate_applied_container_digests(reviewed, applied, ["all"])
        self.assertEqual(raised.exception.code, "verification_failed")

    def test_without_a_repin_nothing_changes(self):
        plan = gateway(
            self.root / "same",
            compose_images=f"{OLD}\n{REDIS}\n",
            candidate_version="4.39.20",
        )
        components = {item["id"]: item for item in plan["components"]}
        self.assertNotIn("image_changes", components["all"]["details"])
        self.assertEqual(components["authelia-container"]["state"], "current")
        self.assertNotIn("depends_on", components["authelia-container"]["details"])


class ThePageNamesTheRepin(unittest.TestCase):
    def test_the_complete_update_row_lists_the_images(self):
        script = UPDATES_JS.read_text(encoding="utf-8")
        reason = script.split("function componentReason(")[1].split("\n  function ")[0]
        self.assertIn("image_changes", reason)
        sentence = (
            "A different remote managed source revision is available. "
            "It also changes these images: {images}"
        )
        self.assertIn(sentence, reason)
        catalogue = json.loads(
            (ROOT / "docker/app/haproxy_admin/translations/ru/updates.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(sentence, catalogue["messages"])


def load_i18n():
    fake_flask = types.ModuleType("flask")
    fake_flask.Request = object
    fake_flask.current_app = types.SimpleNamespace(
        json=types.SimpleNamespace(dumps=json.dumps)
    )
    fake_flask.g = types.SimpleNamespace(language="ru")
    fake_flask.has_request_context = lambda: True
    fake_flask.request = types.SimpleNamespace()
    spec = importlib.util.spec_from_file_location(
        "haproxy_admin_i18n_repin_test", I18N_PATH
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"flask": fake_flask}):
        spec.loader.exec_module(module)
    return module


I18N = load_i18n()


class ShortLabelsStayOutOfDaemonMessages(unittest.TestCase):
    def test_the_reported_message_stays_whole(self):
        message = "an applied image digest differs from the reviewed update plan"
        self.assertEqual(I18N.translate(message, "ru"), message)

    def test_sentence_fragments_still_substitute_around_a_name(self):
        translated = I18N.translate(
            "Let's Encrypt cannot issue certificates for reserved/private "
            "domains: app.example.test. Select Internal CA for this site.",
            "ru",
        )
        self.assertIn("не может выпускать сертификаты", translated)
        self.assertIn("Выберите Internal CA", translated)

    def test_what_counts_as_a_fragment(self):
        fragment = I18N._sentence_fragment
        self.assertTrue(fragment("cannot issue certificates for these domains: "))
        self.assertTrue(fragment(". Select Internal CA for this site."))
        self.assertFalse(fragment("differs from"))
        self.assertFalse(fragment("Apply failed:"))
        self.assertFalse(fragment("Access rules"))


if __name__ == "__main__":
    unittest.main()
