"""The schedule has to be reachable from the interface.

The daemon has carried `schedule`, `schedule_save` and `run_scheduled` since
the destinations were built, and the systemd timer has fired nightly all
along. Nothing exposed any of it, so an operator could say where a copy
should go and never say when -- and every firing found the schedule off and
exited having done nothing. A destination that was configured, tested and
correct produced no backups for as long as anyone cared to wait.
"""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
ROUTES = APP / "routes_backup.py"
TEMPLATE = APP / "templates" / "system_backups.html"
SCRIPT = APP / "static" / "js" / "backup_schedule.js"
DAEMON = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-backupd.py"
)
RU_FRAGMENTS = APP / "translations" / "ru"
RU_BASE = APP / "translations" / "ru.json"


def catalogue() -> dict:
    """The merged catalogue, which is what the browser actually gets.

    A key may live in any fragment -- and must live in exactly one, since
    a duplicate across fragments is a hard error elsewhere in the suite.
    """
    messages = {}
    if RU_BASE.is_file():
        messages.update(
            json.loads(RU_BASE.read_text(encoding="utf-8")).get("messages", {})
        )
    for path in sorted(RU_FRAGMENTS.glob("*.json")):
        messages.update(
            json.loads(path.read_text(encoding="utf-8")).get("messages", {})
        )
    return messages


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.source = ROUTES.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def routes(self):
        found = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                attribute = decorator.func
                if not isinstance(attribute, ast.Attribute):
                    continue
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    found[(attribute.attr, decorator.args[0].value)] = node.name
        return found

    def test_the_schedule_can_be_read_and_written_and_run(self):
        routes = self.routes()
        self.assertIn(("get", "/api/schedule"), routes)
        self.assertIn(("post", "/api/schedule"), routes)
        self.assertIn(("post", "/api/schedule/run"), routes)

    def test_every_action_the_daemon_offers_now_has_a_way_in(self):
        # The gap this test exists to keep closed: an action implemented in
        # the daemon that nothing can reach.
        daemon = DAEMON.read_text(encoding="utf-8")
        actions = set(
            re.findall(r'if action == "([a-z_]+)":', daemon)
        )
        reachable = set(re.findall(r'"action": "([a-z_]+)"', self.source))
        unreachable = actions - reachable
        self.assertEqual(
            unreachable, set(), "daemon actions the interface cannot reach"
        )

    def test_running_it_by_hand_is_given_time_to_finish(self):
        # A full backup plus an upload against the ten-second default would
        # report a failure for a job that is still running.
        block = self.source.split("def run_schedule_view")[1]
        timeout = re.search(r"timeout=(\d+)", block)
        self.assertIsNotNone(timeout)
        self.assertGreaterEqual(int(timeout.group(1)), 600)

    def test_the_passphrase_is_validated_but_an_empty_one_still_passes_through(self):
        block = self.source.split("def save_schedule_view")[1]
        self.assertIn("_passphrase(supplied)", block)
        # "" is how the page asks for the stored passphrase to be forgotten;
        # validating it as a new one would make that impossible.
        self.assertIn('if supplied == "":', block)

    def test_the_schedule_changes_are_audited(self):
        self.assertIn('"schedule_save": ("backup_schedule.save"', self.source)
        self.assertIn('"run_scheduled": ("backup_schedule.run"', self.source)

    def test_the_passphrase_never_reaches_the_audit_summary(self):
        # record_request builds its summary from these named fields only.
        entry = re.search(
            r'"schedule_save": \("backup_schedule\.save", \(([^)]*)\)', self.source
        )
        self.assertIsNotNone(entry)
        self.assertNotIn("passphrase", entry.group(1))


class PageTests(unittest.TestCase):
    def setUp(self):
        self.markup = TEMPLATE.read_text(encoding="utf-8")
        self.script = SCRIPT.read_text(encoding="utf-8")

    def test_the_page_carries_the_schedule_controls(self):
        for element in (
            'id="backup-schedule-form"',
            'id="schedule-enabled"',
            'id="schedule-destinations"',
            'id="schedule-passphrase"',
            'id="schedule-save"',
            'id="schedule-run"',
        ):
            with self.subTest(element=element):
                self.assertIn(element, self.markup)

    def test_the_script_is_loaded(self):
        self.assertIn("js/backup_schedule.js", self.markup)

    def test_an_empty_passphrase_field_is_not_sent(self):
        # Sending "" would delete the stored passphrase, which would disable
        # the schedule for someone who only meant to tick a box.
        self.assertIn("if (passphrase) body.passphrase = passphrase;", self.script)

    def test_the_passphrase_field_is_a_password_field(self):
        block = self.markup.split('id="schedule-passphrase"')[1][:200]
        self.assertIn('type="password"', self.markup.split(
            'id="schedule-passphrase"')[0].rsplit("<input", 1)[1] + block)

    def test_machine_output_is_not_run_through_the_translator(self):
        # The same trap that turned a daemon's file path into
        # "бэкап-destinations/oreol.ключ".
        for element in ("schedule-status", "schedule-last-run", "schedule-last-result"):
            with self.subTest(element=element):
                block = self.markup.split(f'id="{element}"')[1][:160]
                self.assertIn("data-i18n-skip", block)
                self.assertIn('translate="no"', block)


class TranslationTests(unittest.TestCase):
    def test_the_new_prose_is_translated_whole(self):
        messages = catalogue()
        markup = TEMPLATE.read_text(encoding="utf-8")
        section = markup.split('id="backup-schedule"')[1].split("</section>")[0]
        # Every paragraph of prose in the section, whichever helper class
        # it carries. The one placeholder the script replaces is inside a
        # translate="no" block and is skipped below.
        paragraphs = re.findall(
            r"<p class=\"(?:muted|table-meta|vars-field-help)\">(.*?)</p>",
            section,
            re.DOTALL,
        )
        self.assertTrue(paragraphs)
        for paragraph in paragraphs:
            flat = " ".join(paragraph.split())
            if flat in ("Loading…",):
                continue  # replaced by the script before anyone reads it
            with self.subTest(paragraph=flat[:50]):
                self.assertNotIn("<", flat, "a tag inside a sentence splits it")
                self.assertIn(flat, messages)

    def test_the_strings_the_script_shows_are_translated(self):
        messages = catalogue()
        script = SCRIPT.read_text(encoding="utf-8")
        missing = [
            text
            # Not a bare t(: createElement("p") ends in a t and would
            # otherwise be read as a translated string.
            for text in re.findall(r'(?<![A-Za-z0-9_])t\("([^"]+)"\)', script)
            if text not in messages
        ]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
