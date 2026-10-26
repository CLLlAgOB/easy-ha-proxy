"""A progress bar for updates, with the log one click away.

The updates page used to put the whole Ansible log in front of the operator
for the length of an update. It now shows a bar, the step and the elapsed
time, hides the list of updates while a job runs, and folds the log behind a
small "Show details".

The bar needs numbers. An Ansible callback plugin prints
"EHP-PROGRESS done/total task" before each task -- the total counted the way
`ansible-playbook --list-tasks` counts, tags applied -- and the installer
prints "EHP-PROGRESS phase=..." for its own steps. Both only when the update
broker asks (EASY_HA_PROXY_PROGRESS=1), so a terminal run looks as before. The
broker keeps the newest marker as a small `progress` field on the job, which
the page reads from the job list without downloading the log.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker/app/haproxy_admin"
PLUGIN = ROOT / "ansible/callback_plugins/easy_ha_proxy_progress.py"
BROKER_PATH = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"
TEMPLATE = (APP / "templates/system_updates.html").read_text(encoding="utf-8")
SCRIPT = (APP / "static/js/system_updates.js").read_text(encoding="utf-8")


def load_broker():
    name = "easy_ha_proxy_updated_progress_test"
    spec = importlib.util.spec_from_file_location(name, BROKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PLAYBOOK = """
- hosts: localhost
  gather_facts: false
  tasks:
    - name: tagged a
      debug: msg=a
      tags: a
    - name: tagged b
      debug: msg=b
      tags: b
    - block:
        - name: in a block
          debug: msg=x
          tags: a
  roles:
    - role: r
      tags: a
- hosts: localhost
  gather_facts: false
  tasks:
    - name: second play
      debug: msg=y
      tags: a
"""


@unittest.skipIf(shutil.which("ansible-playbook") is None, "ansible-playbook is not installed")
class TheCallback(unittest.TestCase):
    def run_playbook(self, progress):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(ROOT / "ansible/ansible.cfg", root / "ansible.cfg")
            shutil.copytree(ROOT / "ansible/callback_plugins", root / "callback_plugins")
            tasks = root / "roles/r/tasks"
            tasks.mkdir(parents=True)
            (tasks / "main.yml").write_text(
                "- name: role task\n  debug: msg=one\n- import_tasks: more.yml\n", encoding="utf-8"
            )
            (tasks / "more.yml").write_text("- name: imported task\n  debug: msg=imp\n", encoding="utf-8")
            (root / "pb.yml").write_text(PLAYBOOK, encoding="utf-8")
            environment = {**os.environ, "ANSIBLE_CONFIG": str(root / "ansible.cfg")}
            # profile_tasks lives in ansible.posix, which a bare test image may lack.
            environment["ANSIBLE_CALLBACKS_ENABLED"] = "easy_ha_proxy_progress"
            if progress:
                environment["EASY_HA_PROXY_PROGRESS"] = "1"
            else:
                environment.pop("EASY_HA_PROXY_PROGRESS", None)
            completed = subprocess.run(
                ["ansible-playbook", "-i", "localhost,", "-c", "local", "pb.yml", "--tags", "a"],
                cwd=root, env=environment, capture_output=True, text=True, timeout=180,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return [line for line in completed.stdout.splitlines() if line.startswith("EHP-PROGRESS")]

    def test_it_counts_the_tagged_tasks_across_plays_roles_imports_and_blocks(self):
        self.assertEqual(self.run_playbook(True), [
            "EHP-PROGRESS 0/5",
            "EHP-PROGRESS 1/5 r : role task",
            "EHP-PROGRESS 2/5 r : imported task",
            "EHP-PROGRESS 3/5 tagged a",
            "EHP-PROGRESS 4/5 in a block",
            "EHP-PROGRESS 5/5 second play",
        ])

    def test_a_terminal_run_is_unchanged(self):
        self.assertEqual(self.run_playbook(False), [])


class TheConfiguration(unittest.TestCase):
    def test_the_plugin_is_enabled_next_to_the_playbook(self):
        config = (ROOT / "ansible/ansible.cfg").read_text(encoding="utf-8")
        enabled = re.search(r"^callbacks_enabled\s*=\s*(.+)$", config, re.M).group(1)
        self.assertIn("easy_ha_proxy_progress", [item.strip() for item in enabled.split(",")])
        self.assertIn("callback_plugins = ./callback_plugins", config)
        self.assertTrue(PLUGIN.is_file())

    def test_the_plugin_is_silent_unless_asked(self):
        source = PLUGIN.read_text(encoding="utf-8")
        self.assertIn('os.environ.get("EASY_HA_PROXY_PROGRESS") == "1"', source)
        # A broken count must never fail an update.
        self.assertIn("except Exception", source)


class TheInstaller(unittest.TestCase):
    def test_phase_markers_only_for_the_broker(self):
        import easy_ha_proxy
        for value, expected in (("1", "EHP-PROGRESS phase=source\n"), ("", "")):
            with self.subTest(value=value):
                out = io.StringIO()
                with mock.patch.dict(os.environ, {"EASY_HA_PROXY_PROGRESS": value}), \
                        contextlib.redirect_stdout(out):
                    easy_ha_proxy.progress_phase("source")
                self.assertEqual(out.getvalue(), expected)

    def test_the_update_marks_its_steps_in_order(self):
        source = (ROOT / "installer/easy_ha_proxy.py").read_text(encoding="utf-8")
        body = source.split("def command_update(")[1].split("\ndef ")[0]
        positions = [body.index(f'progress_phase("{name}")') for name in ("source", "prepare", "syntax", "playbook")]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(body.index('progress_phase("playbook")'), body.index("run_playbook("))


@unittest.skipIf(sys.platform == "win32", "the broker needs fcntl")
class TheBroker(unittest.TestCase):
    def setUp(self):
        self.broker = load_broker()

    def test_the_child_is_asked_for_markers(self):
        self.assertEqual(self.broker.child_environment()["EASY_HA_PROXY_PROGRESS"], "1")

    def test_the_newest_marker_of_the_running_component_wins(self):
        log = (
            "=== Applying component: changes ===\n"
            "EHP-PROGRESS phase=source\nEHP-PROGRESS 0/40\nEHP-PROGRESS 40/40 last task\n"
            "=== Applying component: admin-container ===\n"
            "EHP-PROGRESS phase=prepare\nok: [gw]\n"
        )
        self.assertEqual(self.broker.parse_progress(log), {"phase": "prepare"})
        log += "EHP-PROGRESS 3/12 haproxy-admin : Pull the image\nTASK [x] ***\n"
        self.assertEqual(self.broker.parse_progress(log), {
            "phase": "playbook", "done": 3, "total": 12, "task": "haproxy-admin : Pull the image",
        })

    def test_no_marker_and_unknown_phases_are_nothing(self):
        self.assertIsNone(self.broker.parse_progress("=== Applying component: os ===\nTASK [x]\n"))
        self.assertIsNone(self.broker.parse_progress("EHP-PROGRESS phase=rm-rf\n"))
        self.assertIsNone(self.broker.parse_progress("say EHP-PROGRESS 1/2 not at a line start\n"))

    def test_the_job_carries_only_the_known_shape(self):
        public = self.broker.public_job({
            "id": "a" * 32, "status": "running", "component_index": 1,
            "progress": {"phase": "playbook", "done": 5, "total": 9, "task": "t\x07ask", "extra": "x"},
        })
        self.assertEqual(public["progress"], {"phase": "playbook", "done": 5, "total": 9, "task": "task"})
        self.assertEqual(public["component_index"], 1)
        self.assertIsNone(self.broker.public_job({"id": "a" * 32, "progress": {"phase": "evil"}})["progress"])

    def test_the_progress_is_published_with_the_log(self):
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("publish_output(job_id, read_"), 2)
        self.assertIn('progress={"phase": "verifying"}', source)
        self.assertIn('progress={"phase": "rechecking"}', source)
        self.assertIn("component_index=index", source)


class ThePage(unittest.TestCase):
    def test_one_confirmation_instead_of_three(self):
        self.assertIn('id="updates-confirm-modal"', TEMPLATE)
        self.assertNotIn('id="updates-confirmation"', TEMPLATE)
        self.assertNotIn('id="updates-impact-confirm"', TEMPLATE)
        self.assertNotIn("window.confirm(t(\"Apply the selected", SCRIPT)
        self.assertIn('byId("updates-apply").addEventListener("click", openConfirm)', SCRIPT)
        self.assertIn('byId("updates-confirm-go").addEventListener("click", applyUpdates)', SCRIPT)

    def test_a_running_job_owns_the_page(self):
        view = SCRIPT.split("function renderView()")[1].split("\n  }\n")[0]
        self.assertIn('byId("updates-plan-card").hidden = running', view)
        self.assertIn('byId("updates-check").hidden = running', view)
        self.assertIn('byId("updates-log-wrap").hidden = !open', view)

    def test_the_log_is_folded_and_only_downloaded_when_shown(self):
        self.assertRegex(TEMPLATE, r'<div id="updates-log-wrap"[^>]*hidden')
        self.assertIn('id="updates-details-toggle"', TEMPLATE)
        shown = SCRIPT.split("async function renderShownJob(")[1].split("\n  }\n")[0]
        self.assertIn("if (!detailsOpen ||", shown)
        # Starting a job does not unfold its log.
        focus = SCRIPT.split("function focusJobLog(")[1].split("\n  }\n")[0]
        self.assertNotIn("setDetailsOpen(true)", focus)

    def test_the_markers_feed_the_bar_and_stay_out_of_the_log(self):
        self.assertIn('!line.startsWith("EHP-PROGRESS")', SCRIPT)
        model = SCRIPT.split("function progressModel(")[1].split("\n  }\n")[0]
        self.assertIn("progress.done", model)
        self.assertIn("highestPercent", model)

    def test_history_and_channel_fold_away(self):
        self.assertRegex(TEMPLATE, r'<details class="card updates-fold" id="updates-history">')
        self.assertRegex(TEMPLATE, r'<details class="card updates-fold" id="updates-settings">')

    def test_the_new_words_are_translated(self):
        import json
        merged = {}
        for path in (APP / "translations").rglob("*.json"):
            if path.name == "ru.json" or path.parent.name == "ru":
                merged.update(json.loads(path.read_text(encoding="utf-8")).get("messages", {}))
        for key in ("Show details", "Hide details", "Install these updates?", "Recommended",
                    "Installing {component} ({index} of {total})", "Updates installed in {time}.",
                    "Downloading the new version…", "Checking the result…"):
            with self.subTest(key=key):
                self.assertIn(key, merged)


if __name__ == "__main__":
    unittest.main()
