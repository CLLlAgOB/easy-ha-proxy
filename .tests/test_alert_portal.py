"""Alerts in the panel itself, and the operator's hand on them.

When mail does not leave -- a relay that cannot verify its upstream, say --
the alert about it waits in the same queue. So the alerts above information
also show in the panel's header on every page; an operator can acknowledge
one (quiet until it recovers), mute it for a while, dismiss an event, and
delete history. Information-only alerts are no longer mailed by default.
The relay's queue is watched for mail that does not leave.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"


def load():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_alertd_portal", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


alertd = load()


class Recording(alertd.Channel):
    name = "recording"

    def __init__(self):
        self.sent = []

    def available(self, config):
        return True

    def send(self, config, subject, body):
        self.sent.append(subject)
        return True, ""


class Engine(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        patcher = mock.patch.object(alertd, "CONFIG_PATH", str(self.directory / "alertd.json"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.database = alertd.AlertDatabase(str(self.directory / "alerts.db"))
        self.addCleanup(self.database.close)
        self.channel = Recording()
        self.engine = alertd.AlertEngine(alertd.AlertConfig(), self.database, [self.channel])
        self.now = 1_700_000_000
        clock = mock.patch.object(alertd, "_utc_now", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    def fire(self, rule="site.down", subject="shop", severity=None):
        payload = {"rule": rule, "subject": subject, "active": True}
        if severity:
            payload["severity"] = severity
        self.engine.observe(payload)
        rule_settings = self.engine.config.settings_for(alertd.RULES_BY_NAME[rule])
        if alertd.RULES_BY_NAME[rule].kind == alertd.KIND_LEVEL and rule_settings.trigger_delay:
            self.now += rule_settings.trigger_delay
            self.engine.observe(payload)

    def recover(self, rule="site.down", subject="shop"):
        self.engine.observe({"rule": rule, "subject": subject, "active": False})

    def portal(self):
        return [(item["rule"], item["subject"]) for item in self.engine.portal()["items"]]

    def transitions(self):
        return [(row["transition"], row["delivery_error"]) for row in
                reversed(self.database.events(limit=100)["events"])]


class WhatIsMailed(unittest.TestCase):
    def write(self, payload):
        path = Path(tempfile.mkstemp(suffix=".json")[1])
        self.addCleanup(path.unlink)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return alertd.load_config(str(path))

    def test_information_is_not_mailed_by_default(self):
        self.assertEqual(alertd.AlertConfig().min_severity, "warning")
        self.assertEqual(alertd.load_config("/nonexistent/alertd.json").min_severity, "warning")

    def test_a_file_from_before_reads_its_old_default_as_the_new_one(self):
        # "info" was only ever there because it was the default.
        self.assertEqual(self.write({"min_severity": "info"}).min_severity, "warning")
        self.assertEqual(self.write({"min_severity": "critical"}).min_severity, "critical")

    def test_a_choice_saved_since_is_kept(self):
        config = self.write({"min_severity": "info", "config_version": 2})
        self.assertEqual(config.min_severity, "info")
        self.assertEqual(config.as_dict()["config_version"], 2)

    def test_the_panel_has_its_own_floor(self):
        self.assertEqual(alertd.AlertConfig().portal_min_severity, "warning")
        self.assertEqual(self.write({"portal_min_severity": "critical"}).portal_min_severity, "critical")
        self.assertEqual(self.write({"portal_min_severity": "loud"}).portal_min_severity, "warning")


class SettingTheFloors(Engine):
    def test_both_floors_are_checked_and_saved(self):
        config = self.engine.update_config({"portal_min_severity": "critical", "min_severity": "info"})
        self.assertEqual((config.portal_min_severity, config.min_severity), ("critical", "info"))
        stored = json.loads((self.directory / "alertd.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["portal_min_severity"], "critical")
        self.assertEqual(stored["config_version"], 2)
        with self.assertRaises(ValueError):
            self.engine.update_config({"portal_min_severity": "loud"})


class InformationByMail(Engine):
    """Information is news when it appears: titled as information, and
    nothing is sent when it ends. On a gateway mailing information, every
    release sent "ALERT ... updates are available" and then "RESOLVED"."""

    def setUp(self):
        super().setUp()
        self.engine.config.min_severity = "info"

    def test_it_is_called_information_not_an_alert(self):
        self.fire("update.available", "software")
        self.assertEqual(len(self.channel.sent), 1)
        self.assertIn(" INFO info: ", self.channel.sent[0])
        self.assertNotIn("ALERT", self.channel.sent[0])

    def test_its_end_sends_nothing_and_is_still_written_down(self):
        self.fire("update.available", "software")
        self.recover("update.available", "software")
        self.assertEqual(len(self.channel.sent), 1)
        self.assertEqual(self.transitions()[-1],
                         ("recovered", "information: no message when it ends"))

    def test_a_warning_still_announces_its_recovery(self):
        self.fire("response.slow", "be_blog")
        self.recover("response.slow", "be_blog")
        self.assertEqual(len(self.channel.sent), 2)
        self.assertIn("RESOLVED", self.channel.sent[1])
        self.assertIn("ALERT", self.channel.sent[0])


class TheHeader(Engine):
    def test_it_shows_what_fires_at_or_above_its_floor(self):
        self.fire("site.down", "shop")
        self.fire("update.available", "software")
        self.fire("response.slow", "be_blog")
        payload = self.engine.portal()
        # Critical first; information stays out.
        self.assertEqual([item["rule"] for item in payload["items"]], ["site.down", "response.slow"])
        self.assertEqual((payload["total"], payload["critical"]), (2, 1))
        self.assertEqual(payload["items"][0]["title"], "Site is down")
        self.engine.config.portal_min_severity = "critical"
        self.assertEqual(self.portal(), [("site.down", "shop")])

    def test_pending_and_recovered_alerts_are_not_there(self):
        self.engine.observe({"rule": "site.down", "subject": "shop", "active": True})
        self.assertEqual(self.portal(), [])
        self.fire()
        self.recover()
        self.assertEqual(self.portal(), [])


class Acknowledging(Engine):
    def test_an_acknowledged_alert_leaves_the_header_and_sends_no_reminder(self):
        self.fire()
        self.engine.quieten({"rule": "site.down", "subject": "shop", "mode": "acknowledge", "by": "anna"})
        payload = self.engine.portal()
        self.assertEqual((payload["items"], payload["quiet"]), ([], 1))
        sent = len(self.channel.sent)
        self.now += 7 * 3600
        self.engine.observe({"rule": "site.down", "subject": "shop", "active": True})
        self.assertEqual(len(self.channel.sent), sent)
        self.assertEqual(self.transitions()[-1], ("repeated", "acknowledged"))

    def test_it_lasts_for_one_occurrence(self):
        self.fire()
        self.engine.quieten({"rule": "site.down", "subject": "shop", "mode": "acknowledge"})
        self.recover()
        # Recovery is always announced.
        self.assertEqual(self.transitions()[-1], ("recovered", ""))
        self.fire()
        self.assertEqual(self.portal(), [("site.down", "shop")])

    def test_only_an_alert_that_exists(self):
        with self.assertRaises(LookupError):
            self.engine.quieten({"rule": "site.down", "subject": "nowhere", "mode": "acknowledge"})
        with self.assertRaises(ValueError):
            self.engine.quieten({"rule": "nonsense", "subject": "shop", "mode": "acknowledge"})
        self.fire()
        with self.assertRaises(ValueError):
            self.engine.quieten({"rule": "site.down", "subject": "shop", "mode": "forever"})


class Muting(Engine):
    def test_a_muted_alert_sends_nothing_until_its_time(self):
        self.fire("response.slow", "be_blog")
        self.engine.quieten({"rule": "response.slow", "subject": "be_blog", "mode": "mute", "seconds": 3600})
        self.assertEqual(self.portal(), [])
        self.recover("response.slow", "be_blog")
        sent = len(self.channel.sent)
        # Firing again inside the hour: recorded, not sent.
        self.fire("response.slow", "be_blog")
        self.assertEqual(len(self.channel.sent), sent)
        self.assertTrue(self.transitions()[-1][1].startswith("muted until "))
        self.assertEqual(self.portal(), [])
        # After the hour it is back in the header.
        self.now += 3601
        self.assertEqual(self.portal(), [("response.slow", "be_blog")])

    def test_a_mute_is_bounded_and_can_be_undone(self):
        self.fire()
        result = self.engine.quieten({"rule": "site.down", "subject": "shop", "mode": "mute",
                                      "seconds": 10 ** 9})
        self.assertEqual(result["muted_until"], self.now + alertd.MAX_MUTE_SECONDS)
        self.engine.quieten({"rule": "site.down", "subject": "shop", "mode": "clear"})
        self.assertEqual(self.portal(), [("site.down", "shop")])


class Dismissing(Engine):
    def test_an_event_is_closed_and_the_history_says_who(self):
        self.fire("update.failed", "job-1")
        self.assertEqual(self.portal(), [("update.failed", "job-1")])
        self.engine.dismiss({"rule": "update.failed", "subject": "job-1", "by": "anna"})
        self.assertEqual(self.portal(), [])
        self.assertIsNone(self.database.get_state("update.failed", "job-1"))
        last = self.database.events(limit=1)["events"][0]
        self.assertEqual((last["transition"], last["detail"]), ("dismissed", "dismissed by anna"))

    def test_a_condition_that_still_holds_is_muted_instead(self):
        self.fire()
        with self.assertRaises(ValueError):
            self.engine.dismiss({"rule": "site.down", "subject": "shop"})
        with self.assertRaises(LookupError):
            self.engine.dismiss({"rule": "update.failed", "subject": "never"})


class DeletingHistory(Engine):
    def setUp(self):
        super().setUp()
        for ts in (100, 200, 300):
            self.database.add_event({"ts": ts, "rule": "site.down", "subject": "shop",
                                     "transition": "fired", "severity": "critical", "summary": "",
                                     "detail": "", "delivered": "", "delivery_error": ""})
        self.ids = [row["id"] for row in self.database.events(limit=10)["events"]]

    def remaining(self):
        return sorted(row["ts"] for row in self.database.events(limit=10)["events"])

    def test_chosen_rows(self):
        self.assertEqual(self.engine.delete_history({"ids": [self.ids[0]]}), 1)
        self.assertEqual(self.remaining(), [100, 200])

    def test_older_than(self):
        self.assertEqual(self.engine.delete_history({"before": 250}), 2)
        self.assertEqual(self.remaining(), [300])

    def test_everything(self):
        self.assertEqual(self.engine.delete_history({"all": True}), 3)
        self.assertEqual(self.remaining(), [])

    def test_nothing_named_is_an_error(self):
        for payload in ({}, {"ids": []}, {"ids": ["x"]}, {"all": "yes"}):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.engine.delete_history(payload)


class AnOlderDatabase(unittest.TestCase):
    def test_it_gains_the_columns_and_keeps_its_rows(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "alerts.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO schema_version VALUES (1)")
        conn.execute(
            "CREATE TABLE alert_state (rule TEXT NOT NULL, subject TEXT NOT NULL, state TEXT NOT NULL, "
            "severity TEXT NOT NULL DEFAULT 'warning', since_ts INTEGER NOT NULL, first_seen_ts INTEGER NOT NULL, "
            "last_seen_ts INTEGER NOT NULL, last_notified_ts INTEGER NOT NULL DEFAULT 0, "
            "notify_count INTEGER NOT NULL DEFAULT 0, summary TEXT NOT NULL DEFAULT '', "
            "detail TEXT NOT NULL DEFAULT '', trigger_delay INTEGER, recipient TEXT NOT NULL DEFAULT '', "
            "PRIMARY KEY (rule, subject))"
        )
        conn.execute("INSERT INTO alert_state (rule, subject, state, since_ts, first_seen_ts, last_seen_ts) "
                     "VALUES ('site.down', 'shop', 'firing', 1, 1, 1)")
        conn.commit()
        conn.close()
        database = alertd.AlertDatabase(str(path))
        self.addCleanup(database.close)
        row = database.get_state("site.down", "shop")
        self.assertEqual((row["acknowledged_ts"], row["muted_until"]), (0, 0))
        version = sqlite3.connect(path).execute("SELECT version FROM schema_version").fetchone()[0]
        self.assertEqual(version, alertd.SCHEMA_VERSION)


QUEUE = "\n".join(json.dumps(item) for item in (
    {"queue_name": "deferred", "queue_id": "A1", "arrival_time": 1_700_000_000 - 3600,
     "recipients": [{"address": "ops@example.com", "delay_reason": "Server certificate not verified"}]},
    {"queue_name": "deferred", "queue_id": "A2", "arrival_time": 1_700_000_000 - 60,
     "recipients": [{"address": "ops@example.com", "delay_reason": "connection refused"}]},
    {"queue_name": "active", "queue_id": "A3", "arrival_time": 1_700_000_000 - 7200, "recipients": []},
)) + "\nnot json\n"


class TheRelaysQueue(Engine):
    def test_only_messages_waiting_long_count(self):
        stuck = alertd.mail_queue_stuck(QUEUE, 1_700_000_000)
        self.assertEqual(len(stuck), 1)
        self.assertEqual(stuck[0]["reason"], "Server certificate not verified")
        self.assertEqual(alertd.mail_queue_stuck("", 1_700_000_000), [])

    def run_check(self, output="", code=0, available=True, error=None):
        completed = subprocess.CompletedProcess([], code, output.encode("utf-8"), b"")
        with mock.patch.object(alertd.EmailChannel, "available", return_value=available), \
                mock.patch.object(alertd.subprocess, "run",
                                  side_effect=error, return_value=completed) as run:
            result = self.engine.check_mail_queue(self.now)
        return result, run

    def test_mail_stuck_in_the_queue_is_critical_and_shows_in_the_header(self):
        result, run = self.run_check(QUEUE)
        self.assertTrue(result)
        self.assertEqual(run.call_args.args[0][-3:], ["mail_relay", "postqueue", "-j"])
        state = self.database.get_state("mail.delivery_failed", "relay")
        self.assertEqual((state["state"], state["severity"]), ("firing", "critical"))
        self.assertIn("1 message(s) waiting, the oldest for 60 min", state["summary"])
        self.assertIn("Server certificate not verified", state["detail"])
        self.assertEqual(self.portal(), [("mail.delivery_failed", "relay")])

    def test_an_empty_queue_clears_it(self):
        self.run_check(QUEUE)
        result, _run = self.run_check("")
        self.assertFalse(result)
        self.assertEqual(self.database.get_state("mail.delivery_failed", "relay")["state"], "ok")

    def test_nothing_is_concluded_without_an_answer_or_without_mail(self):
        for kwargs in ({"available": False}, {"code": 1}, {"error": OSError("no docker")}):
            with self.subTest(**{key: str(value) for key, value in kwargs.items()}):
                result, _run = self.run_check(QUEUE, **kwargs)
                self.assertIsNone(result)
                self.assertIsNone(self.database.get_state("mail.delivery_failed", "relay"))


class TheDaemonAnswers(unittest.TestCase):
    def test_the_actions_need_the_token_and_the_header_does_not(self):
        source = DAEMON.read_text(encoding="utf-8")
        post = source.split("def do_POST(")[1].split("def ")[0]
        for path in ("/api/v1/alerts/quieten", "/api/v1/alerts/dismiss", "/api/v1/alerts/history/delete"):
            self.assertIn(f'"{path}"', post)
        self.assertLess(post.index("if not self._auth_ok():"), post.index("actions = {"))
        get = source.split("def do_GET(")[1].split("def do_POST(")[0]
        self.assertIn('"/api/v1/alerts/portal"', get)


if __name__ == "__main__":
    unittest.main()
