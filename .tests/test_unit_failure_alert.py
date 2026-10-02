"""A job that dies before reaching its daemon must still be reported.

easy-ha-proxy-backup.service failed every night for weeks. backupd was never
asked to do anything, so backupd had no failure to report, so backup.failed
never fired -- the one part of the system that knew was systemd. This is the
bridge, and these tests fix its shape: what it will report, what it refuses
to report, and that reporting can never itself become a failure.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
TEMPLATES = ROOT / "ansible" / "roles" / "haproxy-admin" / "templates"


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, FILES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reporter = load("unit_failed", "easy-ha-proxy-unit-failed.py")
alertd = load("alertd_unit_failed", "easy-ha-proxy-alertd.py")


class FakeClient:
    def __init__(self, configured=True, accept=True):
        self.configured = configured
        self.accept = accept
        self.calls = []

    def observe(self, rule, subject, **kwargs):
        self.calls.append((rule, subject, kwargs))
        return self.accept


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        patcher = mock.patch.object(
            reporter, "AlertClient", lambda **_: self.client
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # No shelling out to journalctl or systemctl from a unit test.
        mock.patch.object(
            reporter,
            "_properties",
            lambda unit: {"Result": "exit-code", "InvocationID": "abc123"},
        ).start()
        mock.patch.object(
            reporter,
            "_last_words",
            lambda unit, invocation="": "request must contain one JSON line",
        ).start()
        self.addCleanup(mock.patch.stopall)

    def test_the_backup_failure_reaches_the_engine(self):
        code = reporter.main(["prog", "easy-ha-proxy-backup.service"])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.client.calls), 1)
        rule, subject, kwargs = self.client.calls[0]
        self.assertEqual(rule, "backup.failed")
        self.assertEqual(subject, "easy-ha-proxy-backup.service")
        self.assertIn("exit-code", kwargs["summary"])
        # The journal tail is the whole point: it says what actually broke.
        self.assertIn("JSON line", kwargs["detail"])

    def test_the_rule_it_sends_is_one_the_engine_knows(self):
        for rule, _title in reporter.RULES.values():
            self.assertIn(rule, alertd.RULES_BY_NAME, rule)
            # An event, because the job has already failed; a level would
            # never be resolved by anything.
            self.assertEqual(alertd.RULES_BY_NAME[rule].kind, alertd.KIND_EVENT)

    def test_an_unmapped_unit_is_refused_rather_than_guessed(self):
        code = reporter.main(["prog", "cups.service"])
        self.assertEqual(code, 0)
        self.assertEqual(self.client.calls, [])

    def test_an_unconfigured_engine_is_not_an_error(self):
        self.client.configured = False
        code = reporter.main(["prog", "easy-ha-proxy-backup.service"])
        self.assertEqual(code, 0)
        self.assertEqual(self.client.calls, [])

    def test_a_rejected_report_is_visible_but_survivable(self):
        # Exit 1 records that the notification was lost. The unit template
        # accepts it so systemd does not start chasing the reporter itself.
        self.client.accept = False
        self.assertEqual(
            reporter.main(["prog", "easy-ha-proxy-backup.service"]), 1
        )

    def test_it_needs_exactly_one_argument(self):
        self.assertEqual(reporter.main(["prog"]), 2)
        self.assertEqual(reporter.main(["prog", "a", "b"]), 2)


def journal(*entries) -> str:
    """journalctl --output json: one JSON object per line."""
    return "\n".join(json.dumps(entry) for entry in entries) + "\n"


class SubprocessTests(unittest.TestCase):
    """The two shell-outs, checked without a running systemd."""

    # Taken from a real failed run on the test machine. The point of the
    # sample is the priorities: the job's own message arrives at INFO and
    # systemd's narration at warning and error, which is why an earlier
    # version of this reporter kept the noise and dropped the cause.
    REAL_RUN = (
        {"SYSLOG_IDENTIFIER": "systemd", "PRIORITY": "6",
         "MESSAGE": "Starting easy-ha-proxy-backup.service..."},
        {"SYSLOG_IDENTIFIER": "python3", "PRIORITY": "6",
         "MESSAGE": "the backup daemon is unreachable: [Errno 2]"},
        {"SYSLOG_IDENTIFIER": "systemd", "PRIORITY": "5",
         "MESSAGE": "Main process exited, code=exited, status=2"},
        {"SYSLOG_IDENTIFIER": "systemd", "PRIORITY": "4",
         "MESSAGE": "Failed with result 'exit-code'."},
        {"SYSLOG_IDENTIFIER": "systemd", "PRIORITY": "3",
         "MESSAGE": "Failed to start easy-ha-proxy-backup.service."},
    )

    def run_returning(self, stdout):
        return mock.patch.object(
            subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=stdout),
        )

    def test_it_reports_what_the_job_said_not_what_systemd_said(self):
        with self.run_returning(journal(*self.REAL_RUN)):
            detail = reporter._last_words("x.service", "abc")
        self.assertEqual(detail, "the backup daemon is unreachable: [Errno 2]")

    def test_several_lines_from_the_job_are_joined(self):
        with self.run_returning(
            journal(
                {"SYSLOG_IDENTIFIER": "python3", "MESSAGE": "first"},
                {"SYSLOG_IDENTIFIER": "systemd", "MESSAGE": "narration"},
                {"SYSLOG_IDENTIFIER": "python3", "MESSAGE": "second"},
            )
        ):
            self.assertEqual(
                reporter._last_words("x.service", "abc"), "first | second"
            )

    def test_it_reads_only_the_run_that_just_failed(self):
        with self.run_returning(journal({"MESSAGE": "x"})) as run:
            reporter._last_words("x.service", "invocation-42")
        self.assertIn("_SYSTEMD_INVOCATION_ID=invocation-42", run.call_args.args[0])

    def test_without_an_invocation_id_it_falls_back_to_the_unit(self):
        with self.run_returning(journal({"MESSAGE": "x"})) as run:
            reporter._last_words("x.service", "")
        self.assertIn("--unit", run.call_args.args[0])

    def test_a_binary_message_is_skipped_rather_than_mangled(self):
        # journald hands back an array of bytes for non-UTF-8 output.
        with self.run_returning(
            journal(
                {"SYSLOG_IDENTIFIER": "python3", "MESSAGE": [1, 2, 3]},
                {"SYSLOG_IDENTIFIER": "python3", "MESSAGE": "readable"},
            )
        ):
            self.assertEqual(reporter._last_words("x.service", "a"), "readable")

    def test_a_flood_of_output_is_capped(self):
        entries = [
            {"SYSLOG_IDENTIFIER": "python3", "MESSAGE": "x" * 500}
            for _ in range(40)
        ]
        with self.run_returning(journal(*entries)):
            detail = reporter._last_words("x.service", "a")
        self.assertLessEqual(len(detail), reporter.MAX_DETAIL_CHARS)

    def test_unparseable_output_is_ignored_line_by_line(self):
        with self.run_returning(
            '{"MESSAGE": "kept"}\nnot json at all\n{"MESSAGE": "also kept"}\n'
        ):
            self.assertEqual(
                reporter._last_words("x.service", "a"), "kept | also kept"
            )

    def test_the_properties_are_parsed_into_a_map(self):
        with self.run_returning("Result=exit-code\nInvocationID=deadbeef\n"):
            self.assertEqual(
                reporter._properties("x.service"),
                {"Result": "exit-code", "InvocationID": "deadbeef"},
            )

    def test_a_journal_that_will_not_answer_costs_nothing(self):
        with mock.patch.object(subprocess, "run", side_effect=OSError("no journal")):
            self.assertEqual(reporter._last_words("x.service", "a"), "")
            self.assertEqual(reporter._properties("x.service"), {})
            self.assertEqual(reporter._result("x.service"), "")

    def test_a_hung_journal_cannot_hold_the_reporter_open(self):
        with self.run_returning("") as run:
            reporter._last_words("x.service", "a")
            self.assertIn("timeout", run.call_args.kwargs)
            self.assertLessEqual(run.call_args.kwargs["timeout"], 30)


class UnitTests(unittest.TestCase):
    """The wiring, read straight out of the templates."""

    def test_the_backup_unit_asks_for_the_reporter_on_failure(self):
        unit = (TEMPLATES / "easy-ha-proxy-backup.service.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnFailure=easy-ha-proxy-unit-failed@%n.service", unit)

    def test_the_reporter_unit_carries_a_token_and_forgives_itself(self):
        unit = (TEMPLATES / "easy-ha-proxy-unit-failed@.service.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("ALERTD_TOKEN=", unit)
        self.assertIn("ALERTD_SOCKET_PATH=", unit)
        self.assertIn("easy-ha-proxy-unit-failed.py %i", unit)
        # Without this, a lost notification marks the reporter failed, and
        # a unit with OnFailure pointing at itself is a loop waiting to run.
        self.assertIn("SuccessExitStatus=0 1", unit)
        directives = [
            line.strip() for line in unit.splitlines()
            if not line.lstrip().startswith("#")
        ]
        # A failure handler that has its own failure handler is a loop.
        self.assertEqual(
            [line for line in directives if line.startswith("OnFailure=")], []
        )

    def test_ansible_installs_both_halves(self):
        tasks = (
            ROOT / "ansible" / "roles" / "haproxy-admin" / "tasks" / "backupd.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("easy-ha-proxy-unit-failed.py", tasks)
        self.assertIn("easy-ha-proxy-unit-failed@.service.j2", tasks)


if __name__ == "__main__":
    unittest.main()
