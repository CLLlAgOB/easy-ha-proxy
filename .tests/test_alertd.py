"""Regression checks for the alert engine.

The engine's whole job is deciding when *not* to speak, so most of these
exercise the silences: before the trigger delay, inside the repeat window,
below the configured severity, and during a storm.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_alertd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_alertd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


alertd = load_alertd()


class RecordingChannel(alertd.Channel):
    """A channel that always works and remembers what it was handed."""

    name = "recording"

    def __init__(self, ok=True, error=""):
        self.sent = []
        self.ok = ok
        self.error = error

    def available(self, config):
        return True

    def send(self, config, subject, body):
        self.sent.append((subject, body))
        return self.ok, self.error


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_path = Path(self.directory.name) / "alertd.json"
        patcher = mock.patch.object(alertd, "CONFIG_PATH", str(self.config_path))
        patcher.start()
        self.addCleanup(patcher.stop)

        self.database = alertd.AlertDatabase(
            str(Path(self.directory.name) / "alerts.db")
        )
        self.addCleanup(self.database.close)
        self.channel = RecordingChannel()
        self.engine = alertd.AlertEngine(
            alertd.AlertConfig(), self.database, [self.channel]
        )
        self.now = 1_700_000_000
        clock = mock.patch.object(alertd, "_utc_now", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    def advance(self, seconds):
        self.now += seconds

    def observe(self, rule, subject="app.example.test", active=True, **kwargs):
        payload = {"rule": rule, "subject": subject, "active": active}
        payload.update(kwargs)
        return self.engine.observe(payload)

    def history(self):
        return self.database.events(limit=100)["events"]


class LevelConditionTests(EngineTestCase):
    def test_nothing_is_sent_before_the_trigger_delay(self):
        # site.down waits five minutes; a blip must not wake anyone.
        result = self.observe("site.down")
        self.assertEqual(result["state"], "pending")
        self.assertEqual(self.channel.sent, [])

    def test_it_fires_once_the_delay_has_passed(self):
        self.observe("site.down")
        self.advance(299)
        self.observe("site.down")
        self.assertEqual(self.channel.sent, [])
        self.advance(2)
        result = self.observe("site.down")
        self.assertEqual(result["state"], "firing")
        self.assertEqual(len(self.channel.sent), 1)
        self.assertIn("ALERT", self.channel.sent[0][0])

    def test_a_blip_that_clears_first_notifies_nothing(self):
        self.observe("site.down")
        self.advance(60)
        self.observe("site.down", active=False)
        self.advance(600)
        self.assertEqual(self.channel.sent, [])
        # And no recovery is announced for something that never fired.
        self.assertEqual(
            [row["transition"] for row in self.history()], []
        )

    def test_continued_reports_do_not_repeat_the_email(self):
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        for _ in range(20):
            self.advance(60)
            self.observe("site.down")
        self.assertEqual(len(self.channel.sent), 1)

    def test_it_repeats_once_the_repeat_window_has_passed(self):
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        self.advance(6 * 3600 + 1)
        self.observe("site.down")
        self.assertEqual(len(self.channel.sent), 2)
        self.assertIn("STILL", self.channel.sent[1][0])

    def test_recovery_is_announced_once(self):
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        self.advance(60)
        self.observe("site.down", active=False)
        self.assertEqual(len(self.channel.sent), 2)
        self.assertIn("RESOLVED", self.channel.sent[1][0])
        self.advance(60)
        self.observe("site.down", active=False)
        self.assertEqual(len(self.channel.sent), 2)

    def test_a_second_outage_fires_again(self):
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        self.observe("site.down", active=False)
        self.advance(3600)
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        transitions = [row["transition"] for row in self.history()]
        self.assertEqual(transitions.count("fired"), 2)

    def test_subjects_are_tracked_independently(self):
        for host in ("a.example.test", "b.example.test"):
            self.observe("site.down", subject=host)
        self.advance(301)
        for host in ("a.example.test", "b.example.test"):
            self.observe("site.down", subject=host)
        self.assertEqual(len(self.channel.sent), 2)


    def test_a_condition_inside_its_delay_is_visible_before_it_fires(self):
        # Otherwise the page shows nothing while a site is already down.
        self.observe("site.down")
        snapshot = self.engine.snapshot()
        self.assertEqual(snapshot["active"], [])
        self.assertEqual(len(snapshot["pending"]), 1)
        self.assertEqual(snapshot["pending"][0]["subject"], "app.example.test")

    def test_once_it_fires_it_moves_out_of_pending(self):
        self.observe("site.down")
        self.advance(301)
        self.observe("site.down")
        snapshot = self.engine.snapshot()
        self.assertEqual(snapshot["pending"], [])
        self.assertEqual(len(snapshot["active"]), 1)


class EventConditionTests(EngineTestCase):
    def test_an_event_fires_immediately(self):
        result = self.observe("backup.failed", subject="nightly")
        self.assertEqual(result["state"], "firing")
        self.assertEqual(len(self.channel.sent), 1)

    def test_an_event_needs_no_active_flag(self):
        # A producer reporting a failure should not have to say "active": true.
        self.engine.observe({"rule": "update.failed", "subject": "os"})
        self.assertEqual(len(self.channel.sent), 1)

    def test_a_repeat_of_the_same_event_is_held_back(self):
        self.observe("backup.failed", subject="nightly")
        self.advance(600)
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(len(self.channel.sent), 1)

    def test_an_event_clears_itself_on_the_sweep(self):
        # Nothing will ever report a finished backup failure as resolved.
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(len(self.database.active_alerts()), 1)
        self.advance(6 * 3600 + 1)
        self.engine.sweep()
        self.assertEqual(self.database.active_alerts(), [])
        # Clearing is silent: there is no recovery to announce.
        self.assertEqual(len(self.channel.sent), 1)

    def test_after_clearing_the_next_occurrence_fires_again(self):
        self.observe("backup.failed", subject="nightly")
        self.advance(6 * 3600 + 1)
        self.engine.sweep()
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(len(self.channel.sent), 2)


class StaleReportTests(EngineTestCase):
    def test_a_level_nobody_reports_any_more_recovers(self):
        # The producer may have died; leaving the alert firing would be a lie.
        self.observe("authelia.unavailable", subject="authelia")
        self.advance(121)
        self.observe("authelia.unavailable", subject="authelia")
        self.assertEqual(len(self.channel.sent), 1)
        self.advance(901)
        self.engine.sweep()
        self.assertEqual(len(self.channel.sent), 2)
        self.assertIn("RESOLVED", self.channel.sent[1][0])
        self.assertEqual(self.database.active_alerts(), [])

    def test_a_pending_level_that_goes_quiet_is_dropped_silently(self):
        self.observe("site.down")
        self.advance(901)
        self.engine.sweep()
        self.assertEqual(self.channel.sent, [])
        self.assertEqual(self.database.open_states(), [])


class StormControlTests(EngineTestCase):
    """The uplink dies and every site goes down in the same minute."""

    def hosts(self, count, start=0):
        return [f"host{index}.example.test" for index in range(start, start + count)]

    def outage(self, hosts):
        for host in hosts:
            self.observe("site.down", subject=host)
        self.advance(301)
        for host in hosts:
            self.observe("site.down", subject=host)

    def test_a_burst_is_capped(self):
        self.outage(self.hosts(15))
        self.assertEqual(len(self.channel.sent), alertd.STORM_MAX_NOTIFICATIONS)

    def test_the_suppressed_ones_are_still_in_the_history(self):
        self.outage(self.hosts(15))
        suppressed = [
            row for row in self.history() if row["transition"] == "suppressed"
        ]
        self.assertEqual(len(suppressed), 15 - alertd.STORM_MAX_NOTIFICATIONS)
        self.assertIn("notifications in", suppressed[0]["delivery_error"])

    def test_a_recovery_is_never_suppressed(self):
        # Being told it is over matters most exactly when a storm happened.
        self.outage(self.hosts(15))
        sent_before = len(self.channel.sent)
        self.observe("site.down", subject="host0.example.test", active=False)
        self.assertEqual(len(self.channel.sent), sent_before + 1)

    def test_the_cap_lifts_once_the_window_moves_on(self):
        self.outage(self.hosts(15))
        self.advance(alertd.STORM_WINDOW_SECONDS + 1)
        self.outage(self.hosts(1, start=99))
        self.assertEqual(
            len(self.channel.sent), alertd.STORM_MAX_NOTIFICATIONS + 1
        )

    def test_a_slow_trickle_is_never_capped(self):
        # Fifteen alerts spread over hours are not a storm.
        for index in range(15):
            host = f"slow{index}.example.test"
            self.observe("site.down", subject=host)
            self.advance(301)
            self.observe("site.down", subject=host)
            self.advance(alertd.STORM_WINDOW_SECONDS)
        self.assertEqual(len(self.channel.sent), 15)


class GatingTests(EngineTestCase):
    def test_alerting_switched_off_sends_nothing_but_records_everything(self):
        self.engine.config.enabled = False
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(self.channel.sent, [])
        row = self.history()[0]
        self.assertEqual(row["transition"], "fired")
        self.assertIn("switched off", row["delivery_error"])

    def test_a_single_rule_can_be_switched_off(self):
        self.engine.config.rules["security.hostile_ip"] = alertd.RuleSettings(
            enabled=False, trigger_delay=0, repeat_after=3600
        )
        self.observe("security.hostile_ip", subject="203.0.113.9")
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(len(self.channel.sent), 1)

    def test_the_minimum_severity_filters_the_noise(self):
        self.engine.config.min_severity = "critical"
        self.observe("security.hostile_ip", subject="203.0.113.9")  # info
        self.assertEqual(self.channel.sent, [])
        self.observe("backup.failed", subject="nightly")  # critical
        self.assertEqual(len(self.channel.sent), 1)


class DeliveryTests(EngineTestCase):
    def test_a_failing_channel_does_not_lose_the_alert(self):
        self.engine.channels = [RecordingChannel(ok=False, error="relay is down")]
        self.observe("backup.failed", subject="nightly")
        row = self.history()[0]
        self.assertEqual(row["transition"], "fired")
        self.assertEqual(row["delivered"], "")
        self.assertIn("relay is down", row["delivery_error"])

    def test_a_channel_that_raises_cannot_take_the_alert_with_it(self):
        class Exploding(alertd.Channel):
            name = "boom"

            def available(self, config):
                return True

            def send(self, config, subject, body):
                raise RuntimeError("kaboom")

        self.engine.channels = [Exploding()]
        self.observe("backup.failed", subject="nightly")
        self.assertEqual(len(self.database.active_alerts()), 1)
        self.assertIn("kaboom", self.history()[0]["delivery_error"])

    def test_with_no_channel_at_all_the_reason_is_recorded(self):
        self.engine.channels = []
        self.observe("backup.failed", subject="nightly")
        self.assertIn("no channel", self.history()[0]["delivery_error"])

    def test_the_message_names_the_gateway_the_rule_and_the_subject(self):
        self.observe("backup.failed", subject="nightly")
        subject, body = self.channel.sent[0]
        self.assertIn(self.engine.hostname, subject)
        self.assertIn("Backup job failed", subject)
        self.assertIn("nightly", subject)
        self.assertIn("backup.failed", body)


class InputTests(EngineTestCase):
    def test_an_unknown_rule_is_refused(self):
        with self.assertRaises(ValueError):
            self.engine.observe({"rule": "made.up", "subject": "x", "active": True})

    def test_a_level_needs_an_explicit_active_flag(self):
        with self.assertRaises(ValueError):
            self.engine.observe({"rule": "site.down", "subject": "x"})

    def test_a_hostile_subject_is_refused(self):
        for hostile in ("../../etc/passwd", "a\nb", "<script>", ""):
            with self.assertRaises(ValueError, msg=hostile):
                self.engine.observe(
                    {"rule": "site.down", "subject": hostile, "active": True}
                )

    def test_a_newline_cannot_inject_a_mail_header(self):
        # The summary is producer-supplied and lands next to the headers.
        self.observe(
            "backup.failed",
            subject="nightly",
            summary="fine\r\nBcc: attacker@example.com",
        )
        subject, body = self.channel.sent[0]
        self.assertNotIn("\r", subject)
        self.assertNotIn("\n", subject)
        self.assertNotIn("Bcc:", subject)

    def test_producer_text_is_bounded(self):
        self.observe("backup.failed", subject="nightly", detail="x" * 99999)
        self.assertLessEqual(
            len(self.history()[0]["detail"]), alertd.MAX_TEXT_CHARS
        )

    def test_an_unknown_severity_falls_back_to_the_rule_default(self):
        self.observe("backup.failed", subject="nightly", severity="apocalyptic")
        self.assertEqual(self.history()[0]["severity"], "critical")


class ConfigurationTests(EngineTestCase):
    def test_a_missing_file_means_defaults_rather_than_a_dead_daemon(self):
        config = alertd.load_config(str(Path(self.directory.name) / "nope.json"))
        self.assertTrue(config.enabled)

    def test_a_broken_file_means_defaults_too(self):
        broken = Path(self.directory.name) / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        self.assertTrue(alertd.load_config(str(broken)).enabled)

    def test_settings_round_trip_through_the_file(self):
        self.engine.update_config(
            {
                "recipient": "ops@example.test",
                "min_severity": "warning",
                "rules": {"site.down": {"trigger_delay": 60, "enabled": False}},
            }
        )
        stored = alertd.load_config(str(self.config_path))
        self.assertEqual(stored.recipient, "ops@example.test")
        self.assertEqual(stored.min_severity, "warning")
        self.assertEqual(stored.rules["site.down"].trigger_delay, 60)
        self.assertFalse(stored.rules["site.down"].enabled)

    def test_a_changed_delay_takes_effect_without_a_restart(self):
        self.engine.update_config({"rules": {"site.down": {"trigger_delay": 30}}})
        self.observe("site.down")
        self.advance(31)
        self.observe("site.down")
        self.assertEqual(len(self.channel.sent), 1)

    def test_invalid_settings_are_refused_rather_than_stored(self):
        for payload in (
            {"recipient": "not-an-address"},
            {"min_severity": "loud"},
            {"rules": {"made.up": {"enabled": False}}},
            {"rules": "everything"},
        ):
            with self.assertRaises(ValueError, msg=str(payload)):
                self.engine.update_config(payload)
        self.assertFalse(self.config_path.exists())

    def test_out_of_range_numbers_are_clamped_not_rejected(self):
        self.engine.update_config({"rules": {"site.down": {"repeat_after": 1}}})
        stored = alertd.load_config(str(self.config_path))
        self.assertEqual(stored.rules["site.down"].repeat_after, 300)


class StorageTests(EngineTestCase):
    def test_the_history_is_bounded_by_age(self):
        self.observe("backup.failed", subject="old")
        self.advance(alertd.RETENTION_DAYS * 86400 + 1)
        self.observe("backup.failed", subject="new")
        self.database.prune()
        subjects = [row["subject"] for row in self.history()]
        self.assertIn("new", subjects)
        self.assertNotIn("old", subjects)

    def test_the_database_reports_what_is_firing(self):
        self.observe("backup.failed", subject="nightly")
        stats = self.database.stats()
        self.assertEqual(stats["firing"], 1)
        self.assertGreaterEqual(stats["database_bytes"], 0)

    def test_a_rule_removed_from_the_catalogue_does_not_wedge_the_sweep(self):
        self.observe("backup.failed", subject="nightly")
        with mock.patch.dict(
            alertd.RULES_BY_NAME, clear=False
        ) as catalogue:
            catalogue.pop("backup.failed")
            self.engine.sweep()
        self.assertEqual(self.database.open_states(), [])


class CatalogueTests(unittest.TestCase):
    def test_every_rule_is_a_level_or_an_event(self):
        for rule in alertd.RULES:
            self.assertIn(rule.kind, (alertd.KIND_LEVEL, alertd.KIND_EVENT), rule.name)
            self.assertIn(rule.severity, alertd.SEVERITIES, rule.name)
            self.assertTrue(rule.title, rule.name)

    def test_only_levels_carry_a_trigger_delay(self):
        # An event has already happened; waiting to see if it keeps happening
        # is meaningless and would delay the one notification that matters.
        for rule in alertd.RULES:
            if rule.kind == alertd.KIND_EVENT:
                self.assertEqual(rule.trigger_delay, 0, rule.name)

    def test_the_plan_conditions_are_all_present(self):
        expected = {
            "site.down", "backend.no_servers", "http.error_ratio",
            "response.slow", "security.burst", "security.hostile_ip",
            "monitoring.storage", "monitoring.paused", "certificate.expiring",
            "certificate.renewal_failed", "backup.failed", "restore.failed",
            "update.failed", "authelia.unavailable", "config.apply_failed",
        }
        self.assertEqual(set(alertd.RULES_BY_NAME), expected)


class MailChannelTests(EngineTestCase):
    def setUp(self):
        super().setUp()
        self.state_path = Path(self.directory.name) / "mail-notify.json"
        patcher = mock.patch.object(
            alertd, "MAIL_STATE_PATH", str(self.state_path)
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # The relay serialises on a lock under /run, which exists for the root
        # daemon and for nobody else. Without redirecting it the tests fail on
        # the lock before they reach what they are actually about.
        lock = mock.patch.object(
            alertd,
            "MAIL_LOCK_PATH",
            str(Path(self.directory.name) / "mail.lock"),
        )
        lock.start()
        self.addCleanup(lock.stop)
        self.channel = alertd.EmailChannel()

    def write_state(self, **overrides):
        state = {"enabled": True, "from": "gw@example.test", "to": "ops@example.test"}
        state.update(overrides)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def test_delivery_is_skipped_while_email_is_disabled(self):
        self.write_state(enabled=False)
        self.assertFalse(self.channel.available(self.engine.config))

    def test_a_missing_state_file_is_not_an_error(self):
        self.assertFalse(self.channel.available(self.engine.config))
        ok, error = self.channel.send(self.engine.config, "s", "b")
        self.assertFalse(ok)
        self.assertIn("disabled", error)

    def test_the_configured_recipient_wins_over_the_shared_one(self):
        self.write_state()
        self.engine.config.recipient = "oncall@example.test"
        with mock.patch.object(alertd.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stderr=b"")
            self.channel.send(self.engine.config, "subject", "body")
        message = run.call_args.kwargs["input"].decode("utf-8")
        self.assertIn("To: oncall@example.test", message)
        self.assertIn("gw@example.test", run.call_args.args[0])

    def test_a_relay_failure_is_reported_not_raised(self):
        self.write_state()
        with mock.patch.object(alertd.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=67, stderr=b"no such user")
            ok, error = self.channel.send(self.engine.config, "subject", "body")
        self.assertFalse(ok)
        self.assertIn("67", error)

    def test_a_timeout_is_reported_not_raised(self):
        self.write_state()
        with mock.patch.object(
            alertd.subprocess, "run",
            side_effect=alertd.subprocess.TimeoutExpired("sendmail", 30),
        ):
            ok, error = self.channel.send(self.engine.config, "subject", "body")
        self.assertFalse(ok)
        self.assertIn("failed", error)


class DeploymentTests(unittest.TestCase):
    """The daemon is only useful if it is actually installed and started."""

    def setUp(self):
        self.role = ROOT / "ansible" / "roles" / "haproxy-admin"
        self.unit = (
            self.role / "templates" / "easy-ha-proxy-alertd.service.j2"
        ).read_text(encoding="utf-8")
        self.tasks = (self.role / "tasks" / "alertd.yml").read_text(encoding="utf-8")

    def test_the_stage_is_reachable_from_the_playbook_and_the_bundle(self):
        playbook = (ROOT / "ansible" / "easy-ha-proxy.yml").read_text(encoding="utf-8")
        self.assertIn("task_stage: alertd", playbook)
        self.assertIn("ha-adm-alertd", playbook)
        daemons = (self.role / "tasks" / "daemons.yml").read_text(encoding="utf-8")
        self.assertIn("import_tasks: alertd.yml", daemons)

    def test_every_installer_tag_list_carries_the_stage(self):
        # A daemon missing from one list is a daemon that silently never
        # updates on that workflow.
        installer = (ROOT / "installer" / "easy_ha_proxy.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            installer.count('"ha-adm-alertd"'),
            installer.count('"ha-adm-guardd"'),
        )

    def test_operator_settings_are_never_overwritten_by_an_update(self):
        # The daemon owns this file once an operator has touched a threshold.
        block = self.tasks.split("Seed the settings file")[1].split("register:")[0]
        self.assertIn("force: false", block)

    def test_the_unit_is_sandboxed(self):
        for directive in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "MemoryDenyWriteExecute=yes",
            "RestrictSUIDSGID=yes",
            "MemoryMax=",
        ):
            self.assertIn(directive, self.unit, directive)

    def test_the_state_and_the_settings_are_the_only_writable_paths(self):
        self.assertIn("StateDirectory=easy-ha-proxy/alerts", self.unit)
        self.assertIn("ReadWritePaths=", self.unit)
        self.assertIn("ReadOnlyPaths=", self.unit)

    def test_submitting_an_observation_needs_the_shared_token(self):
        self.assertIn("ALERTD_TOKEN=", self.unit)
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
        ).read_text(encoding="utf-8")
        self.assertIn("hmac.compare_digest", source)
        # Reads stay open to the group; only the three mutating paths are gated.
        self.assertIn('"/api/v1/alerts/notify"', source)
        self.assertIn("if not self._auth_ok():", source)

    def test_a_restart_does_not_leave_a_dead_socket_behind(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-alertd.py"
        ).read_text(encoding="utf-8")
        self.assertIn("signal.SIGTERM", source)
        self.assertIn("server.shutdown", source)

    def test_the_alert_history_is_in_the_disaster_recovery_archive(self):
        backup = (ROOT / "installer" / "full_backup.py").read_text(encoding="utf-8")
        self.assertIn('"/var/lib/easy-ha-proxy",', backup)
        excludes = backup.split("BACKUP_EXCLUDES = (")[1].split(")")[0]
        self.assertNotIn("alerts", excludes)


class AlertClientTests(unittest.TestCase):
    """The reporting side that every producer daemon imports."""

    def setUp(self):
        path = ROOT / "ansible/roles/haproxy-admin/files/easy_ha_proxy_alert_client.py"
        spec = importlib.util.spec_from_file_location("alert_client", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.module = module
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.socket_path = str(Path(self.directory.name) / "alertd.sock")

    def client(self, token="secret"):
        return self.module.AlertClient(self.socket_path, token, source="test")

    def test_without_a_token_nothing_is_sent(self):
        # An unconfigured gateway must not spend a syscall per cycle trying.
        client = self.client(token="")
        self.assertFalse(client.configured)
        with mock.patch.object(self.module.socket, "socket") as sock:
            self.assertFalse(client.observe("site.down", "x", active=True))
        sock.assert_not_called()

    def test_a_dead_socket_is_reported_as_false_not_raised(self):
        # The producer is mid-cycle; an exception here would cost a real sample.
        client = self.client()
        self.assertFalse(client.observe("site.down", "x", active=True))

    def test_the_outage_is_logged_once_not_every_cycle(self):
        client = self.client()
        with self.assertLogs(self.module.LOG, level="WARNING") as captured:
            client.observe("site.down", "a", active=True)
            client.observe("site.down", "b", active=True)
            client.observe("site.down", "c", active=True)
        self.assertEqual(len(captured.records), 1)

    def test_an_unchanged_observation_is_not_resent_immediately(self):
        client = self.client()
        with mock.patch.object(client, "_post", return_value=True) as post:
            for _ in range(10):
                client.observe("monitoring.storage", "metrics", active=False)
        self.assertEqual(post.call_count, 1)

    def test_a_changed_observation_goes_straight_out(self):
        client = self.client()
        with mock.patch.object(client, "_post", return_value=True) as post:
            client.observe("monitoring.storage", "metrics", active=False)
            client.observe("monitoring.storage", "metrics", active=True)
        self.assertEqual(post.call_count, 2)

    def test_the_deduplication_map_cannot_grow_without_limit(self):
        client = self.client()
        with mock.patch.object(client, "_post", return_value=True):
            for index in range(2500):
                client.observe("security.hostile_ip", f"10.0.0.{index}")
        self.assertLessEqual(len(client._last), 2000)

    def test_per_subject_policy_is_forwarded(self):
        # healthd passes the site's own alert_after and alert_email through
        # here; a signature mismatch made the whole call fail silently once.
        client = self.client()
        with mock.patch.object(client, "_post", return_value=True) as post:
            client.observe(
                "site.down",
                "shop.example.test",
                active=True,
                trigger_delay=60,
                recipient="ops@example.test",
            )
        payload = post.call_args.args[1]
        self.assertEqual(payload["trigger_delay"], 60)
        self.assertEqual(payload["recipient"], "ops@example.test")

    def test_a_changed_recipient_is_not_treated_as_unchanged(self):
        client = self.client()
        with mock.patch.object(client, "_post", return_value=True) as post:
            client.observe("site.down", "a", active=True, recipient="one@example.test")
            client.observe("site.down", "a", active=True, recipient="two@example.test")
        self.assertEqual(post.call_count, 2)

    def test_the_request_carries_the_token_and_the_payload(self):
        client = self.client()
        captured = {}

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, value):
                pass

            def connect(self, path):
                captured["path"] = path

            def sendall(self, data):
                captured["data"] = data

            def recv(self, size):
                if "data" not in captured or captured.get("read"):
                    return b""
                captured["read"] = True
                return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

        with mock.patch.object(self.module.socket, "socket", return_value=FakeSocket()):
            ok = client.observe("backup.failed", "nightly", summary="tar exited 2")
        self.assertTrue(ok)
        self.assertEqual(captured["path"], self.socket_path)
        request = captured["data"].decode("utf-8")
        self.assertIn("X-Alertd-Token: secret", request)
        self.assertIn('"rule": "backup.failed"', request)
        self.assertIn("tar exited 2", request)
        # An event carries no active flag; the engine knows it happened.
        self.assertNotIn('"active"', request)


class PerSubjectPolicyTests(EngineTestCase):
    """Some policy belongs to the object, not to the rule."""

    def test_a_site_can_carry_its_own_delay(self):
        # websites.yml has alert_after per site; a single global delay would
        # be a regression against what healthd already offered.
        self.observe("site.down", trigger_delay=30)
        self.advance(31)
        self.observe("site.down", trigger_delay=30)
        self.assertEqual(len(self.channel.sent), 1)

    def test_the_rule_default_still_applies_without_one(self):
        self.observe("site.down")
        self.advance(31)
        self.observe("site.down")
        self.assertEqual(self.channel.sent, [])

    def test_an_event_ignores_a_delay(self):
        # It already happened; waiting would only delay the one notification.
        self.observe("backup.failed", subject="nightly", trigger_delay=3600)
        self.assertEqual(len(self.channel.sent), 1)

    def test_an_invalid_recipient_is_refused_at_the_door(self):
        with self.assertRaises(ValueError):
            self.observe("backup.failed", subject="nightly", recipient="nope")

    def test_the_recipient_reaches_the_channel(self):
        seen = {}

        class Watching(RecordingChannel):
            def send(self, config, subject, body):
                seen["recipient"] = config.recipient
                return super().send(config, subject, body)

        self.engine.channels = [Watching()]
        self.observe(
            "backup.failed", subject="nightly", recipient="ops@example.test"
        )
        self.assertEqual(seen["recipient"], "ops@example.test")

    def test_the_recovery_goes_to_whoever_got_the_alert(self):
        seen = []

        class Watching(RecordingChannel):
            def send(self, config, subject, body):
                seen.append(config.recipient)
                return super().send(config, subject, body)

        self.engine.channels = [Watching()]
        self.observe("site.down", trigger_delay=0, recipient="ops@example.test")
        self.observe(
            "site.down", active=False, trigger_delay=0, recipient="ops@example.test"
        )
        self.assertEqual(seen, ["ops@example.test", "ops@example.test"])

    def test_a_stale_recovery_also_reaches_the_right_address(self):
        # The sweep resolves it, and the sweep has only the stored row to
        # work from.
        seen = []

        class Watching(RecordingChannel):
            def send(self, config, subject, body):
                seen.append(config.recipient)
                return super().send(config, subject, body)

        self.engine.channels = [Watching()]
        self.observe("site.down", trigger_delay=0, recipient="ops@example.test")
        self.advance(901)
        self.engine.sweep()
        self.assertEqual(seen, ["ops@example.test", "ops@example.test"])

    def test_a_per_subject_recipient_is_not_written_into_the_settings(self):
        self.observe(
            "backup.failed", subject="nightly", recipient="ops@example.test"
        )
        self.assertEqual(self.engine.config.recipient, "")


class EscalationTests(EngineTestCase):
    def test_getting_worse_is_reported_without_waiting(self):
        # A partial outage becoming a total one is news on its own.
        self.observe("site.down", trigger_delay=0, severity="warning")
        self.assertEqual(len(self.channel.sent), 1)
        self.observe("site.down", trigger_delay=0, severity="critical")
        self.assertEqual(len(self.channel.sent), 2)
        self.assertIn("WORSE", self.channel.sent[1][0])

    def test_it_cannot_loop(self):
        self.observe("site.down", trigger_delay=0, severity="warning")
        for _ in range(5):
            self.observe("site.down", trigger_delay=0, severity="critical")
        self.assertEqual(len(self.channel.sent), 2)

    def test_getting_better_while_still_firing_says_nothing(self):
        self.observe("site.down", trigger_delay=0, severity="critical")
        self.observe("site.down", trigger_delay=0, severity="warning")
        self.assertEqual(len(self.channel.sent), 1)


class ProducerWiringTests(unittest.TestCase):
    """Every daemon that can fail has to be able to say so."""

    FILES = ROOT / "ansible/roles/haproxy-admin/files"

    EXPECTED = {
        "easy-ha-proxy-metricsd.py": ("monitoring.storage", "monitoring.paused"),
        "easy-ha-proxy-guardd.py": ("security.hostile_ip",),
        "easy-ha-proxy-backupd.py": ("backup.failed", "restore.failed"),
        "easy-ha-proxy-updated.py": ("update.failed",),
        "haproxy-controld.py": ("config.apply_failed",),
        "haproxy-certd.py": ("certificate.renewal_failed",),
        "haproxy-healthd.py": ("site.down",),
    }

    def test_each_producer_reports_its_own_conditions(self):
        for name, rules in sorted(self.EXPECTED.items()):
            source = (self.FILES / name).read_text(encoding="utf-8")
            for rule in rules:
                self.assertIn(f'"{rule}"', source, f"{name}: {rule}")

    def test_every_rule_a_producer_uses_exists_in_the_catalogue(self):
        for rules in self.EXPECTED.values():
            for rule in rules:
                self.assertIn(rule, alertd.RULES_BY_NAME, rule)

    def test_the_client_is_optional_everywhere(self):
        # A daemon must never fail to start because alertd is not installed.
        for name in self.EXPECTED:
            source = (self.FILES / name).read_text(encoding="utf-8")
            self.assertIn("AlertClient = None", source, name)

    def test_every_producer_unit_carries_the_socket_and_the_token(self):
        templates = ROOT / "ansible/roles/haproxy-admin/templates"
        for name in self.EXPECTED:
            unit = templates / (name.replace(".py", ".service.j2"))
            self.assertTrue(unit.exists(), unit.name)
            text = unit.read_text(encoding="utf-8")
            self.assertIn("ALERTD_TOKEN=", text, unit.name)
            self.assertIn("ALERTD_SOCKET_PATH=", text, unit.name)

    def test_reporting_never_uses_a_bare_call(self):
        # Every call site has to be inside something that swallows failure.
        for name in self.EXPECTED:
            source = (self.FILES / name).read_text(encoding="utf-8")
            self.assertTrue(
                "report_alert" in source
                or "_report_to_alerts" in source
                or "_report_ban" in source
                or "self._alerts.observe" in source,
                name,
            )


if __name__ == "__main__":
    unittest.main()
