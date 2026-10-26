"""The host and the web application are installed as one version.

The web application talks to the host's daemons and renders HAProxy's
configuration from the host's template, so installing one without the other
can break the panel. Each published image is labelled with the fingerprint of
its build inputs as Git stores them (`git ls-tree` over Dockerfile,
.dockerignore and docker/app), which a gateway can compute from any source
tree it has. The update check compares three values -- the running image,
the offered image and the source the host would move to -- and turns them
into pairs ("installed together with") or holds a component back; the broker
enforces the pairs, so the page cannot be talked out of them.

The same page now sets how often the broker checks by itself, without Ansible.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import update_plan
from update_plan import CommandResult


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
SCRIPT = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")
TEMPLATE = (APP / "templates/system_updates.html").read_text(encoding="utf-8")
ROUTES = (APP / "routes_updates.py").read_text(encoding="utf-8")

OLD = "a" * 64
NEW = "b" * 64
OTHER = "c" * 64


def components(*, source="available", scope_ready=True, services="current", admin="available",
               running=OLD, offered=NEW):
    return [
        {"id": "all", "state": source, "actionable": source == "available",
         "details": {"scope": {"ready": scope_ready, "tags": ["ha-cfg", "status"]}}},
        {"id": "services", "state": services, "actionable": services == "available", "details": {}},
        {"id": "daemons", "state": "current", "actionable": False, "details": {}},
        {"id": "os", "state": "current", "actionable": False, "details": {}},
        {"id": "authelia-container", "state": "current", "actionable": False, "details": {}},
        {"id": "admin-container", "state": admin, "actionable": admin == "available",
         "details": {"images": [{"current_source_tree": running, "available_source_tree": offered}]}},
    ]


def by_id(items):
    return {item["id"]: item for item in items}


class TheRules(unittest.TestCase):
    def test_a_host_only_change_goes_alone(self):
        items = components(admin="current", running=OLD, offered=OLD)
        update_plan.link_web_application(items, OLD)
        found = by_id(items)
        self.assertEqual(found["all"]["state"], "available")
        self.assertNotIn("requires", found["all"]["details"]["scope"])

    def test_a_web_change_with_its_image_published_is_a_pair(self):
        items = components(services="available", running=OLD, offered=NEW)
        update_plan.link_web_application(items, NEW)
        found = by_id(items)
        self.assertEqual(found["all"]["details"]["scope"]["requires"], [["admin-container"]])
        self.assertEqual(found["services"]["details"]["requires"], [["admin-container"]])
        # The full stack pulls the image itself.
        self.assertNotIn("requires", found["all"]["details"])
        self.assertEqual(found["admin-container"]["details"]["requires"], [["changes", "all", "services"]])

    def test_a_web_change_without_its_image_waits(self):
        items = components(services="available", admin="current", running=OLD, offered=OLD)
        update_plan.link_web_application(items, NEW)
        found = by_id(items)
        for component_id in ("all", "services"):
            with self.subTest(component=component_id):
                self.assertEqual(found[component_id]["state"], "blocked")
                self.assertFalse(found[component_id]["actionable"])
                self.assertEqual(found[component_id]["details"]["reason"], "web-application-not-published")
        scope = found["all"]["details"]["scope"]
        self.assertFalse(scope["ready"])
        self.assertEqual(scope["reason"], "web-application-not-published")

    def test_an_image_published_ahead_of_its_source_is_not_offered(self):
        items = components(source="current", scope_ready=False, running=OLD, offered=NEW)
        update_plan.link_web_application(items, OLD)
        admin = by_id(items)["admin-container"]
        self.assertEqual(admin["state"], "blocked")
        self.assertEqual(admin["details"]["reason"], "web-application-without-source")

    def test_an_image_rebuilt_from_the_same_files_goes_alone(self):
        items = components(source="current", scope_ready=False, running=OLD, offered=OLD)
        update_plan.link_web_application(items, OLD)
        admin = by_id(items)["admin-container"]
        self.assertEqual(admin["state"], "available")
        self.assertNotIn("requires", admin["details"])

    def test_a_lagging_web_application_catches_up_alone(self):
        # The host already has the source this image was built from.
        items = components(source="current", scope_ready=False, running=OLD, offered=NEW)
        update_plan.link_web_application(items, NEW)
        admin = by_id(items)["admin-container"]
        self.assertEqual(admin["state"], "available")
        self.assertNotIn("requires", admin["details"])

    def test_without_labels_both_go_together(self):
        for running, offered, target in ((None, NEW, NEW), (OLD, None, NEW), (OLD, NEW, None)):
            with self.subTest(running=running, offered=offered, target=target):
                items = components(running=running, offered=offered)
                update_plan.link_web_application(items, target)
                found = by_id(items)
                self.assertEqual(found["all"]["details"]["scope"]["requires"], [["admin-container"]])
                self.assertEqual(found["admin-container"]["details"]["requires"], [["changes", "all"]])
                self.assertEqual(found["all"]["state"], "available")


class TheFingerprints(unittest.TestCase):
    def test_the_tree_is_the_sha256_of_ls_tree(self):
        listing = "100644 blob 1111111111111111111111111111111111111111\tDockerfile\n"
        calls = []

        def run(argv, timeout):
            calls.append(tuple(argv))
            return CommandResult(0, listing)

        runner = mock.Mock(run=run)
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / ".git").mkdir()
            self.assertEqual(update_plan._web_tree(Path(temporary), runner),
                             hashlib.sha256(listing.encode()).hexdigest())
            self.assertIsNone(update_plan._web_tree(Path(temporary) / "no-git", runner))
        self.assertEqual(calls[0][3:], ("ls-tree", "-r", "--full-tree", "HEAD", "--", "Dockerfile", ".dockerignore", "docker/app"))

    def test_labels_of_a_multi_platform_index_and_a_single_image(self):
        index = {"linux/amd64": {"config": {"Labels": {update_plan.WEB_TREE_LABEL: NEW}}},
                 "linux/arm64": {"config": {"Labels": {update_plan.WEB_TREE_LABEL: NEW}}}}
        single = {"config": {"Labels": {update_plan.WEB_TREE_LABEL: OLD}}}
        for payload, expected in ((index, NEW), (single, OLD), ({"config": {"Labels": {}}}, None)):
            runner = mock.Mock(run=lambda argv, timeout, payload=payload: CommandResult(0, json.dumps(payload)))
            with self.subTest(expected=expected):
                self.assertEqual(update_plan._remote_web_tree("example/ui:alpha", runner), expected)
        local = mock.Mock(run=lambda argv, timeout: CommandResult(0, json.dumps({update_plan.WEB_TREE_LABEL: OLD})))
        self.assertEqual(update_plan._local_web_tree("example/ui:alpha", local), OLD)
        broken = mock.Mock(run=mock.Mock(side_effect=RuntimeError("no docker")))
        self.assertIsNone(update_plan._local_web_tree("example/ui:alpha", broken))


def load_broker():
    name = "easy_ha_proxy_updated_pairing_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(sys.platform == "win32", "the broker needs fcntl")
class TheBroker(unittest.TestCase):
    def setUp(self):
        self.broker = load_broker()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, value in (
            ("SETTINGS_PATH", self.root / "settings.json"),
            ("LATEST_PLAN_PATH", self.root / "latest-plan.json"),
        ):
            patcher = mock.patch.object(self.broker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, replacement in (
            ("atomic_json", lambda path, payload: Path(path).write_text(json.dumps(payload))),
            ("safe_json_file", lambda path: json.loads(Path(path).read_text())),
        ):
            patcher = mock.patch.object(self.broker, name, side_effect=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def plan_map(self):
        items = components(running=OLD, offered=NEW)
        update_plan.link_web_application(items, NEW)
        return {item["id"]: item for item in items}

    def test_one_half_alone_is_refused(self):
        for selection in (["changes"], ["admin-container"]):
            with self.subTest(selection=selection):
                with self.assertRaises(self.broker.UpdatedError) as caught:
                    self.broker.validate_requirements(self.plan_map(), selection)
                self.assertEqual(caught.exception.code, "dependency")

    def test_both_halves_or_the_full_stack_pass(self):
        self.broker.validate_requirements(self.plan_map(), ["changes", "admin-container"])
        self.broker.validate_requirements(self.plan_map(), ["all"])

    def test_the_refusal_is_part_of_validating_a_selection(self):
        source = BROKER_PATH.read_text(encoding="utf-8")
        body = source.split("def validate_selection(")[1].split("\ndef ")[0]
        self.assertIn("validate_requirements(available, components)", body)

    def test_the_interval_is_set_from_the_page_and_wins_over_the_default(self):
        self.assertEqual(self.broker.auto_check_hours(), self.broker.AUTO_CHECK_HOURS)
        result = self.broker.set_settings({"action": "set_settings", "auto_check_hours": 168})
        self.assertEqual(result["settings"]["auto_check_hours"], 168)
        self.assertEqual(self.broker.auto_check_hours(), 168)
        self.broker.set_settings({"action": "set_settings", "auto_check_hours": 0})
        self.assertIsNone(self.broker.seconds_until_auto_check(0.0))

    def test_only_the_offered_intervals_are_accepted(self):
        for value in (5, -1, True, "24", None, 10_000):
            with self.subTest(value=value):
                with self.assertRaises(self.broker.UpdatedError):
                    self.broker.set_settings({"action": "set_settings", "auto_check_hours": value})

    def test_a_damaged_settings_file_falls_back_to_the_default(self):
        self.broker.SETTINGS_PATH.write_text("{not json")
        self.assertEqual(self.broker.auto_check_hours(), self.broker.AUTO_CHECK_HOURS)

    def test_the_status_carries_the_settings_and_the_schedule_always_runs(self):
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertIn('"settings": settings_payload()', source)
        serve = source.split("def serve() -> None:")[1].split("\ndef ")[0]
        self.assertIn("threading.Thread(target=auto_check_loop", serve)
        self.assertNotIn("if AUTO_CHECK_HOURS > 0", serve)
        self.assertEqual(self.broker.REQUEST_FIELDS["set_settings"], frozenset({"action", "auto_check_hours"}))


class ThePage(unittest.TestCase):
    def test_pairs_are_kept_on_the_page(self):
        self.assertIn("function enforceRequirements(changedId)", SCRIPT)
        self.assertIn("enforceRequirements(changedId);", SCRIPT)
        self.assertIn("requirementNote(component)", SCRIPT)
        self.assertIn('id="updates-pairing-note"', TEMPLATE)
        # A clause naming the web application is met by the full stack.
        self.assertIn('id === "admin-container" && checked.has("all")', SCRIPT)

    def test_the_settings_are_saved_through_the_broker(self):
        self.assertIn('@bp_system_updates.post("/api/settings")', ROUTES)
        self.assertIn('"set_settings": ("update.settings", ("auto_check_hours",))', ROUTES)
        self.assertIn('"dependency",', ROUTES)
        self.assertIn('data-settings-url="{{ url_for(\'system_updates.save_settings\') }}"', TEMPLATE)
        self.assertIn('id="updates-auto-check"', TEMPLATE)
        self.assertIn("postJson(endpoints.settings, {auto_check_hours: value})", SCRIPT)

    def test_the_new_words_are_translated(self):
        merged = {}
        for path in (APP / "translations").rglob("*.json"):
            if path.name == "ru.json" or path.parent.name == "ru":
                merged.update(json.loads(path.read_text(encoding="utf-8")).get("messages", {}))
        for key in ("Installed together with: {components}", "Automatic check", "Every week",
                    "Next automatic check: {time}", "Alert settings",
                    "This version also changes the web application, and its image is not published yet. Check again once it is."):
            with self.subTest(key=key):
                self.assertIn(key, merged)


if __name__ == "__main__":
    unittest.main()
