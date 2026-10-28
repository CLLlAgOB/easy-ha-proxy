"""Mail held back is sent as soon as the relay can, and the alerts page speaks
one language.

On a gateway updated with the relay's trust fixed, 31 messages that had
waited thirty hours kept waiting: Postfix retries deferred mail with a pause
that grows to about an hour, and the alert about them stayed lit. The update
now asks the relay to send at once, and the alert has a "retry now".

The history's delivery column read "the правило is switched выкл": a phrase
from the daemon went through the general translator, which replaces the
words it knows one by one. Phrases are translated whole or left alone.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"


def load():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_alertd_retry", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


alertd = load()


class RetryNow(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = alertd.AlertDatabase(str(Path(directory.name) / "alerts.db"))
        self.addCleanup(self.database.close)
        self.engine = alertd.AlertEngine(alertd.AlertConfig(), self.database, [])

    def test_the_relay_is_asked_to_send_and_the_alert_is_checked_again(self):
        done = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(alertd.subprocess, "run", return_value=done) as run, \
                mock.patch.object(alertd.threading, "Timer") as timer:
            result = self.engine.retry_mail()
        self.assertEqual(run.call_args.args[0][-3:], ["mail_relay", "postqueue", "-f"])
        timer.assert_called_once_with(alertd.MAIL_RETRY_RECHECK_SECONDS, self.engine._recheck_mail)
        timer.return_value.start.assert_called_once()
        self.assertTrue(result["retried"])

    def test_a_relay_that_cannot_be_asked_says_so(self):
        failed = subprocess.CompletedProcess([], 1, b"", b"no such container")
        with mock.patch.object(alertd.subprocess, "run", return_value=failed), \
                mock.patch.object(alertd.threading, "Timer") as timer:
            with self.assertRaises(RuntimeError):
                self.engine.retry_mail()
        timer.assert_not_called()

    def test_the_daemon_and_the_panel_route_it(self):
        source = DAEMON.read_text(encoding="utf-8")
        post = source.split("def do_POST(")[1]
        self.assertIn('"/api/v1/alerts/mail/retry": engine.retry_mail', post)
        routes = (APP / "routes_alerts.py").read_text(encoding="utf-8")
        block = routes.split("def api_alerts_mail_retry")[1].split("@bp.")[0]
        self.assertIn('"alerts.mail_retry"', block)
        self.assertNotIn("_superadmin", block)
        page = (APP / "static/js/alerts.js").read_text(encoding="utf-8")
        self.assertIn('entry.rule === "mail.delivery_failed"', page)
        self.assertIn('act("/api/alerts/mail/retry", {})', page)


class AfterAnUpdate(unittest.TestCase):
    def test_the_relay_is_flushed_after_every_start_of_the_stack(self):
        flush = (ROOT / "ansible/roles/authelia/tasks/mail_relay_flush.yml").read_text(encoding="utf-8")
        self.assertIn("- postqueue\n      - -f", flush)
        self.assertIn("failed_when: false", flush)
        for flow, after in (("start.yml", "Reconcile"), ("update.yml", "Reconcile the updated Authelia stack")):
            text = (ROOT / "ansible/roles/authelia/tasks" / flow).read_text(encoding="utf-8")
            self.assertIn("include_tasks: mail_relay_flush.yml", text, flow)
            self.assertLess(text.index("docker\n              - compose") if "docker\n              - compose" in text
                            else text.index(after), text.index("mail_relay_flush.yml"), flow)


class OneLanguage(unittest.TestCase):
    # Every reason the daemon writes into the delivery column.
    REASONS = (
        "alerting is switched off",
        "the rule is switched off",
        "below the configured minimum severity",
        "acknowledged",
        "email delivery is disabled",
        "no channel is configured",
    )

    @classmethod
    def setUpClass(cls):
        cls.catalog = {}
        for path in (APP / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("meta", {}).get("code") == "ru":
                cls.catalog.update(data["messages"])
        cls.daemon = DAEMON.read_text(encoding="utf-8")
        cls.page = (APP / "static/js/alerts.js").read_text(encoding="utf-8")

    def test_every_reason_the_daemon_writes_is_translated_whole(self):
        for reason in self.REASONS:
            with self.subTest(reason=reason):
                self.assertIn(f'"{reason}"', self.daemon)
                self.assertIn(reason, self.catalog)
        self.assertIn("more than {count} notifications in {minutes} minutes", self.catalog)
        self.assertIn('f"more than {STORM_MAX_NOTIFICATIONS} notifications in "', self.daemon)

    def test_nothing_from_the_daemon_goes_through_the_word_by_word_translator(self):
        self.assertIn("span.textContent = known(text);", self.page)
        self.assertIn("cell(tr, known(event.transition));", self.page)
        known = self.page.split("function known(")[1].split("\n  }\n")[0]
        self.assertIn("hasOwnProperty.call(messages, value)", known)
        self.assertNotIn("t(value)", known)


if __name__ == "__main__":
    unittest.main()
