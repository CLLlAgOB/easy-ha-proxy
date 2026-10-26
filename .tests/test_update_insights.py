"""What is new, how long is left, and a word when updates appear.

Three things the updates page lacked:

- "What's new": the commit subjects between the installed and the candidate
  revision. The check reads them from a history-only clone (no files, no
  trees, at most 200 commits); failing to read them never costs the plan.
- How long is left: each installation records how long each component took,
  and the page estimates the rest -- the running component by its own pace,
  the ones after it by history.
- A daily read-only check by the update broker that keeps an
  "update.available" alert in step: raised when something can be installed,
  resolved by the check after it was. It does not hold the maintenance lock,
  so a nightly backup starting meanwhile is never refused as "busy", and a
  failed scheduled check is not reported as a failed update.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

import update_plan
from update_plan import CommandResult


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
ALERTD_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
SCRIPT = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")
TEMPLATE = (APP / "templates/system_updates.html").read_text(encoding="utf-8")

INSTALLED = "1" * 40
CANDIDATE = "2" * 40
MIDDLE = "3" * 40
OLDER = "4" * 40


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeRunner:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def run(self, argv, *, timeout):
        self.calls.append(tuple(argv))
        return self.handler(tuple(argv))


def history(*revisions_and_subjects):
    return "".join(f"{rev}\x1f{subject}\n" for rev, subject in revisions_and_subjects)


class WhatsNew(unittest.TestCase):
    def changelog(self, handler):
        with tempfile.TemporaryDirectory() as temporary:
            runner = FakeRunner(handler)
            result = update_plan._changelog(
                source_dir=Path(temporary) / "tarball", repository="https://example.test/r.git",
                branch="main", installed_revision=INSTALLED, candidate_revision=CANDIDATE,
                destination=Path(temporary) / "history", runner=runner,
            )
        return result, runner.calls

    def test_the_commits_since_the_installed_revision_newest_first(self):
        def handler(command):
            if command[:2] == ("git", "clone"):
                return CommandResult(0)
            return CommandResult(0, history((CANDIDATE, "Second"), (MIDDLE, "First\x07"),
                                             (INSTALLED, "Already installed"), (OLDER, "Older")))
        result, calls = self.changelog(handler)
        self.assertEqual(result, {"count": 2, "complete": True, "commits": [
            {"revision": CANDIDATE[:12], "subject": "Second"},
            {"revision": MIDDLE[:12], "subject": "First"},
        ]})
        clone = calls[0]
        # History only: no files, no trees, bounded depth.
        self.assertIn("--bare", clone)
        self.assertIn("--filter=tree:0", clone)
        self.assertIn(f"--depth={update_plan.CHANGELOG_DEPTH}", clone)
        self.assertEqual(calls[1][-1], CANDIDATE)

    def test_an_installed_revision_beyond_the_history_is_at_least(self):
        def handler(command):
            if command[:2] == ("git", "clone"):
                return CommandResult(0)
            return CommandResult(0, history((CANDIDATE, "Only one read")))
        result, _ = self.changelog(handler)
        self.assertFalse(result["complete"])
        self.assertEqual(result["count"], 1)

    def test_any_failure_leaves_it_out(self):
        for handler in (
            lambda command: CommandResult(128, stderr="no network"),
            lambda command: (_ for _ in ()).throw(RuntimeError("boom")),
        ):
            with self.subTest(handler=handler):
                self.assertIsNone(self.changelog(handler)[0])

    def test_the_plan_carries_it_in_the_source_component(self):
        import test_update_plan as fakes

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = fakes.prepare_source(root)
            installed = fakes.prepare_installed_daemons(root, source)

            def handler(command):
                if command[:2] == ("git", "clone"):
                    if "--bare" not in command:
                        shutil.copytree(source, Path(command[-1]))
                    return CommandResult(0)
                if "log" in command:
                    return CommandResult(0, history((fakes.REMOTE_REVISION, "The new thing"),
                                                     (fakes.LOCAL_REVISION, "Installed")))
                if command[-2:] == ("rev-parse", "HEAD") and Path(command[2]) != source:
                    return CommandResult(0, fakes.REMOTE_REVISION + "\n")
                return fakes.git_handler(command)

            plan = update_plan.build_update_plan(
                source_dir=source, config_dir=root / "config",
                authelia_compose=root / "missing-authelia.yml",
                admin_compose=root / "missing-admin.yml",
                runner=fakes.FakeRunner(handler), artifact_path=installed,
            )
        source_component = {item["id"]: item for item in plan["components"]}["all"]
        self.assertEqual(source_component["details"]["changelog"]["commits"],
                         [{"revision": fakes.REMOTE_REVISION[:12], "subject": "The new thing"}])


class TheAlert(unittest.TestCase):
    def setUp(self):
        self.alertd = load(ALERTD_PATH, "alertd_insights_test")

    def test_the_rule_is_a_level_that_outlives_a_day_of_silence(self):
        rule = self.alertd.RULES_BY_NAME["update.available"]
        self.assertEqual(rule.kind, self.alertd.KIND_LEVEL)
        self.assertEqual(rule.severity, self.alertd.SEVERITY_INFO)
        self.assertGreater(rule.stale_after, 24 * 3600)
        self.assertLessEqual(rule.repeat_after, 7 * 86400)

    def test_the_schedule_is_configurable(self):
        unit = (ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-updated.service.j2").read_text(encoding="utf-8")
        defaults = (ROOT / "ansible/roles/haproxy-admin/defaults/main.yml").read_text(encoding="utf-8")
        self.assertIn('UPDATED_AUTO_CHECK_HOURS={{ updates_auto_check_hours | default(24) }}', unit)
        self.assertIn("updates_auto_check_hours: 24", defaults)


@unittest.skipIf(sys.platform == "win32", "the broker needs fcntl")
class TheBroker(unittest.TestCase):
    def setUp(self):
        self.broker = load(BROKER_PATH, "updated_insights_test")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "jobs").mkdir()
        for name, value in (
            ("JOBS_DIR", root / "jobs"),
            ("MAINTENANCE_LOCK_PATH", root / "maintenance.lock"),
            ("ACTIVE_MARKER", root / "active"),
            ("LATEST_PLAN_PATH", root / "latest-plan.json"),
        ):
            patcher = mock.patch.object(self.broker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The real state files are root-owned and checked for it; a test run
        # is not root, so plain JSON stands in for them.
        for name, replacement in (
            ("reboot_guard_present", lambda: False),
            ("atomic_json", lambda path, payload: Path(path).write_text(json.dumps(payload))),
            ("safe_json_file", lambda path: json.loads(Path(path).read_text())),
        ):
            patcher = mock.patch.object(self.broker, name, side_effect=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def plan(self, *states, changelog=None):
        components = []
        for component_id, state in states:
            item = {"id": component_id, "state": state, "actionable": state == "available", "details": {}}
            components.append(item)
        if changelog:
            components[0]["details"]["changelog"] = changelog
        return {"components": components}

    def test_what_the_alert_says(self):
        report = self.broker.availability_report(self.plan(
            ("all", "available"), ("admin-container", "available"), ("os", "current"),
            changelog={"count": 3, "complete": False, "commits": [{"revision": "abc", "subject": "New ban rule"}]},
        ))
        active, summary, detail = report
        self.assertTrue(active)
        self.assertIn("a new source revision", summary)
        self.assertIn("the web application", summary)
        self.assertIn("3+ new change(s)", detail)
        self.assertIn("- New ban rule", detail)

    def test_nothing_to_install_resolves_it_and_an_incomplete_check_says_nothing(self):
        self.assertEqual(self.broker.availability_report(self.plan(("all", "current")))[0], False)
        self.assertIsNone(self.broker.availability_report(self.plan(("all", "current"), ("os", "unknown"))))

    def test_every_check_and_the_recheck_after_an_installation_report(self):
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertIn("report_availability(plan)", source.split("def run_check(")[1].split("\ndef ")[0])
        self.assertIn("report_availability(refreshed)", source)

    def test_a_scheduled_check_leaves_the_maintenance_lock_free(self):
        seen = {}

        def fake_run_check(job_id, *args, **kwargs):
            seen["lock_busy"] = self.broker.maintenance_lock_busy()
            seen["alert_on_failure"] = kwargs.get("alert_on_failure")
            seen["job"] = json.loads((self.broker.JOBS_DIR / f"{job_id}.json").read_text())
            return True

        with mock.patch.object(self.broker, "run_check", side_effect=fake_run_check):
            self.assertEqual(self.broker.auto_check_once(), "done")
        self.assertFalse(seen["lock_busy"])
        self.assertIs(seen["alert_on_failure"], False)
        self.assertTrue(seen["job"]["scheduled"])
        self.assertFalse(self.broker.OPERATION_THREAD_LOCK.locked())

    def test_it_steps_aside_for_anything_running(self):
        import fcntl
        import os
        descriptor = os.open(self.broker.MAINTENANCE_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        with mock.patch.object(self.broker, "run_check") as run_check:
            self.assertEqual(self.broker.auto_check_once(), "busy")
        run_check.assert_not_called()
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.broker.OPERATION_THREAD_LOCK.acquire()
        try:
            self.assertEqual(self.broker.auto_check_once(), "busy")
        finally:
            self.broker.OPERATION_THREAD_LOCK.release()

    def test_the_schedule_counts_from_the_newest_check(self):
        now = time.time()
        self.assertEqual(self.broker.seconds_until_auto_check(now), 0)
        created = self.broker.dt.datetime.fromtimestamp(now - 3600, self.broker.dt.timezone.utc).isoformat()
        self.broker.LATEST_PLAN_PATH.write_text(json.dumps({"id": "a" * 32, "created_at": created}))
        self.assertAlmostEqual(
            self.broker.seconds_until_auto_check(now), (self.broker.AUTO_CHECK_HOURS - 1) * 3600, delta=5
        )

    def test_a_failed_scheduled_check_is_not_a_failed_update(self):
        job = self.broker.new_job("check", scheduled=True)
        with mock.patch.object(self.broker, "report_alert") as report:
            self.broker.finish_failed(job["id"], RuntimeError("no network"), alert=False)
        report.assert_not_called()
        self.assertEqual(self.broker.load_job(job["id"])["status"], "failed")
        self.assertTrue(self.broker.load_job(job["id"])["scheduled"])

    def test_each_component_is_timed(self):
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertIn('"component_seconds": component_seconds', source)
        self.assertIn("component_started_at=utc_now()", source)
        public = self.broker.public_job({"id": "a" * 32, "component_started_at": "2026-10-26T10:00:00+00:00"})
        self.assertEqual(public["component_started_at"], "2026-10-26T10:00:00+00:00")


class ThePage(unittest.TestCase):
    def test_the_changelog_is_shown_as_written(self):
        tag = TEMPLATE.split('id="updates-changelog-list"')[1].split(">")[0]
        self.assertIn("notranslate", tag)
        self.assertIn("data-i18n-skip", tag)
        self.assertIn("renderChangelog(components)", SCRIPT)
        # Kept out of the raw "versions" dump of the source row.
        self.assertIn('!["scope", "changelog"].includes(key)', SCRIPT)

    def test_the_estimate_uses_pace_then_history(self):
        body = SCRIPT.split("function remainingSeconds(")[1].split("\n  }\n")[0]
        self.assertIn("fraction >= 0.25", body)
        self.assertIn("typicalSeconds(later)", body)
        self.assertIn("typicalCheckSeconds()", body)
        self.assertIn('id="updates-progress-eta"', TEMPLATE)

    def test_scheduled_checks_are_named_in_the_history(self):
        self.assertIn('job.scheduled ? t("Scheduled check")', SCRIPT)

    def test_the_new_words_are_translated(self):
        catalogue = json.loads((APP / "translations/ru/updates.json").read_text(encoding="utf-8"))["messages"]
        for key in ("What's new: {count} change(s)", "What's new: more than {count} change(s)",
                    "Scheduled check", "less than a minute left", "about {minutes} min left"):
            with self.subTest(key=key):
                self.assertIn(key, catalogue)


if __name__ == "__main__":
    unittest.main()
