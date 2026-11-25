"""The schedule has to be reachable from the interface.

The daemon has carried `schedule`, `schedule_save` and `run_scheduled` since
the destinations were built, and the systemd timer has fired nightly all
along. Nothing exposed any of it, so an operator could say where a copy
should go and never say when -- and every firing found the schedule off and
exited having done nothing. A destination that was configured, tested and
correct produced no backups for as long as anyone cared to wait.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
_WEB_DIR = Path(__file__).resolve().parents[1] / "go" / "panel" / "web"
ROUTES = APP / "routes_backup.py"
TEMPLATE = _WEB_DIR / "templates" / "system_backups.html"
SCRIPT = _WEB_DIR / "static" / "js" / "backup_schedule.js"
DAEMON = (
    ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
    / "easy-ha-proxy-backupd.py"
)
RU_FRAGMENTS = _WEB_DIR / "translations" / "ru"
RU_BASE = _WEB_DIR / "translations" / "ru.json"


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
        # "бэкап-destinations/offsite.ключ".
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
