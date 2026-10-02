"""An update checked for one channel cannot be applied on another.

The reported failure: a gateway on the alpha channel had its update check run
with the stable channel selected on the page but not saved. Applying it
failed with "the update candidate changed for all; check again" -- and would
have again after every check. The apply-time recheck fell back to the branch
in the gateway's metadata, alpha, and found a different candidate from the
main-branch one the plan had been built on. Had it followed the plan instead,
the gateway would have been moved to main without its channel being saved.

Three separate things went wrong, and each is pinned here:

* the plan did not record its branch, and applying it was not refused when
  its channel differed from the gateway's;
* docker compose lists images in no fixed order, so an unchanged stack could
  change its plan signature between two checks all by itself;
* the server translated the broker's error word by word, turning it into
  "the update candidate changed для все; проверки again".
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
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
    FakeRunner,
    prepare_installed_daemons,
    prepare_source,
)


DAEMON_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
I18N_PATH = ROOT / "docker/app/haproxy_admin/i18n.py"
UPDATES_JS = ROOT / "docker/app/haproxy_admin/static/js/system_updates.js"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def load_daemon():
    name = "easy_ha_proxy_updated_channel_test"
    spec = importlib.util.spec_from_file_location(name, DAEMON_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


UPDATED = load_daemon()


def deployment(source="github", image="latest", branch="main"):
    return {
        "source_channel": source,
        "image_channel": image,
        "branch": branch,
        "release_channel": UPDATED.derive_release_channel(source, branch, image),
    }


def plan(source="github", image="latest", branch="main"):
    result = {
        "id": "a" * 32,
        "source_channel": source,
        "image_channel": image,
        "components": [
            {
                "id": "admin-container",
                "state": "available",
                "actionable": True,
                "installed": "old",
                "available": "new",
            }
        ],
        "expires_at": "2999-01-01T00:00:00+00:00",
    }
    if branch is not None:
        result["branch"] = branch
    return result


class APlanFromAnotherChannelIsRefused(unittest.TestCase):
    def check(self, the_plan, the_deployment):
        with mock.patch.object(
            UPDATED, "read_deployment", return_value=the_deployment
        ):
            UPDATED.validate_plan_channel(the_plan)

    def assertRefused(self, the_plan, the_deployment):
        with self.assertRaises(UPDATED.UpdatedError) as raised:
            self.check(the_plan, the_deployment)
        self.assertEqual(raised.exception.code, "channel_mismatch")
        self.assertIn("Save the channel first", str(raised.exception))

    def test_the_reported_case_a_stable_check_on_an_alpha_gateway(self):
        self.assertRefused(
            plan(image="latest", branch="main"),
            deployment(image="alpha", branch="alpha"),
        )

    def test_the_other_way_round_too(self):
        self.assertRefused(
            plan(image="alpha", branch="alpha"),
            deployment(image="latest", branch="main"),
        )

    def test_the_same_image_on_another_branch_is_still_another_channel(self):
        self.assertRefused(
            plan(image="alpha", branch="main"),
            deployment(image="alpha", branch="alpha"),
        )

    def test_a_local_check_on_a_github_gateway(self):
        self.assertRefused(
            plan(source="local", branch=None), deployment(source="github")
        )

    def test_a_plan_for_the_saved_channel_is_accepted(self):
        self.check(
            plan(image="alpha", branch="alpha"),
            deployment(image="alpha", branch="alpha"),
        )
        self.check(plan(), deployment())

    def test_a_local_gateway_has_no_branch_to_compare(self):
        self.check(
            plan(source="local", branch="whatever"),
            deployment(source="local", branch="main"),
        )

    def test_a_plan_written_before_plans_recorded_a_branch_still_applies(self):
        # A plan cached by the previous broker has no branch key. It is
        # judged by the channels it does record, not refused outright.
        self.check(plan(branch=None), deployment())

    def test_applying_refuses_before_taking_the_maintenance_lock(self):
        stale = plan(image="latest", branch="main")
        with (
            mock.patch.object(UPDATED, "load_latest_plan", return_value=stale),
            mock.patch.object(
                UPDATED,
                "read_deployment",
                return_value=deployment(image="alpha", branch="alpha"),
            ),
            mock.patch.object(UPDATED, "acquire_operation") as lock,
            self.assertRaises(UPDATED.UpdatedError) as raised,
        ):
            UPDATED.start_apply(
                {
                    "action": "start_apply",
                    "plan_id": stale["id"],
                    "components": ["admin-container"],
                    "confirmation": "UPDATE",
                }
            )
        self.assertEqual(raised.exception.code, "channel_mismatch")
        lock.assert_not_called()

    def test_the_worker_checks_again_and_rechecks_on_the_plans_branch(self):
        source = DAEMON_PATH.read_text(encoding="utf-8")
        worker = source.split("def apply_worker(")[1].split("\ndef ")[0]
        self.assertIn("validate_selection(plan, components)", worker)
        recheck = worker.split("fresh = execute_checker(")[1].split(")\n")[0]
        self.assertIn('plan["branch"]', recheck)
        body = source.split("def validate_selection(")[1].split("\ndef ")[0]
        self.assertIn("validate_plan_channel(plan)", body)


class ThePlanRecordsItsBranch(unittest.TestCase):
    def build(self, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = prepare_source(root)
            installed = prepare_installed_daemons(root, source)

            def handler(command):
                if command == ("apt-get", "-s", "upgrade"):
                    return CommandResult(0, "")
                raise AssertionError(f"unexpected command: {command!r}")

            return build_update_plan(
                source_dir=source,
                config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                source_channel="local",
                runner=FakeRunner(handler),
                artifact_path=installed,
                **kwargs,
            )

    def test_an_explicit_branch_is_recorded(self):
        self.assertEqual(self.build(branch="alpha")["branch"], "alpha")

    def test_without_one_the_default_is_recorded(self):
        self.assertEqual(self.build()["branch"], update_plan.DEFAULT_BRANCH)


class ImageOrderDoesNotChangeThePlan(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # One file for both listings, so its path is not the difference.
        self.compose = Path(temporary.name) / "docker-compose.yml"
        self.compose.write_text("services: {}\n", encoding="utf-8")

    def probe(self, listing):
        def handler(command):
            if command[:3] == ("docker", "compose", "-f"):
                return CommandResult(0, listing)
            if command[:3] == ("docker", "image", "inspect"):
                image = command[3]
                return CommandResult(
                    0, json.dumps([f"{image.split(':')[0]}@{DIGEST_A}"])
                )
            if command[:4] == ("docker", "buildx", "imagetools", "inspect"):
                return CommandResult(0, f"Name: {command[4]}\nDigest: {DIGEST_B}\n")
            raise AssertionError(f"unexpected command: {command!r}")

        return update_plan._probe_compose(
            "authelia-container", self.compose, FakeRunner(handler)
        )

    def test_the_same_stack_listed_in_another_order_is_the_same_component(self):
        # The order two back-to-back checks on a live gateway produced.
        first = self.probe(
            "example/mail:1\nexample/auth:4\nexample/cache:7\n"
        )
        second = self.probe(
            "example/auth:4\nexample/mail:1\nexample/cache:7\n"
        )
        self.assertEqual(first, second)
        self.assertEqual(
            UPDATED.component_signature(first),
            UPDATED.component_signature(second),
        )


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
        "haproxy_admin_i18n_channel_test", I18N_PATH
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"flask": fake_flask}):
        spec.loader.exec_module(module)
    return module


I18N = load_i18n()


class ServerMessagesAreNotTranslatedWordByWord(unittest.TestCase):
    def localize(self, payload):
        class Response:
            is_json = True
            data = ""

            def get_json(self, silent=False):
                return payload

            def set_data(self, value):
                self.data = value

        response = I18N.localize_json_response(Response())
        return json.loads(response.data)

    def test_the_reported_message_stays_whole(self):
        message = "the update candidate changed for all; check again"
        self.assertEqual(I18N.translate(message, "ru"), message)
        job = self.localize({"job": {"error": message}})
        self.assertEqual(job["job"]["error"], message)

    def test_a_known_sentence_is_still_translated_whole(self):
        self.assertEqual(
            I18N.translate(UPDATED.CHANNEL_MISMATCH_MESSAGE, "ru"),
            "Эта проверка сделана для другого канала выпуска, чем тот, что "
            "сохранён на шлюзе. Сначала сохраните канал или запустите "
            "проверку заново.",
        )
        self.assertEqual(
            self.localize({"error": UPDATED.CHANNEL_MISMATCH_MESSAGE})["error"][:4],
            "Эта ",
        )

    def test_a_single_word_is_still_translated_when_it_is_the_whole_message(self):
        self.assertEqual(I18N.translate("all", "ru"), "все")

    def test_phrase_fragments_around_a_name_still_translate(self):
        translated = I18N.translate(
            "Let's Encrypt cannot issue certificates for reserved/private "
            "domains: app.example.test. Select Internal CA for this site.",
            "ru",
        )
        self.assertIn("не может выпускать сертификаты", translated)
        self.assertIn("Выберите Internal CA", translated)
        self.assertIn("app.example.test", translated)


class ThePageDoesNotOfferToApplyAnotherChannel(unittest.TestCase):
    def test_every_usable_plan_check_excludes_another_channel(self):
        script = UPDATES_JS.read_text(encoding="utf-8")
        self.assertIn("function planForOtherChannel(plan)", script)
        usable = script.split("const planUsable = Boolean(")[1:]
        self.assertEqual(len(usable), 2)
        for expression in usable:
            self.assertIn(
                "planForOtherChannel(currentPlan)", expression.split(");")[0]
            )
        render = script.split("function renderPlan(")[1].split("\n  function ")[0]
        self.assertIn("planForOtherChannel(plan)", render)
        self.assertIn(
            "This check previews a release channel that is not saved on this "
            "gateway.",
            render,
        )

    def test_the_warning_is_in_the_russian_catalogue(self):
        catalogue = json.loads(
            (
                ROOT / "docker/app/haproxy_admin/translations/ru/updates.json"
            ).read_text(encoding="utf-8")
        )
        messages = catalogue.get("messages", catalogue)
        self.assertIn(UPDATED.CHANNEL_MISMATCH_MESSAGE, messages)
        self.assertIn(
            "This check previews a release channel that is not saved on this "
            "gateway. Save the channel before applying these updates.",
            messages,
        )


if __name__ == "__main__":
    unittest.main()
