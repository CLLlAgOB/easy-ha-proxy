"""Regression tests for the privileged monitoring daemon."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_healthd():
    path = ROOT / "ansible/roles/haproxy-admin/files/haproxy-healthd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_healthd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecentSystemdLogsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.healthd = load_healthd()

    def make_state(self):
        config = self.healthd.HealthdConfig(
            systemd_units=(
                "haproxy.service",
                "haproxy-healthd.service",
                "authelia-configd.service",
                "iptables-haproxy-ban.service",
            ),
            systemd_unit_globs=("haproxy-*.service",),
            docker_containers=(),
            poll_interval_seconds=5,
            events_max=200,
            cache_ttl_seconds=15,
            units_rescan_seconds=60,
            logs_default_tail=200,
            logs_max_tail=2000,
            logs_default_since_seconds=3600,
            logs_max_since_seconds=86400,
        )
        return self.healthd._State(config)

    def test_recent_feed_applies_default_exclusions_and_parses_json(self) -> None:
        state = self.make_state()
        journal = "\n".join((
            json.dumps({
                "__REALTIME_TIMESTAMP": "1720991114000000",
                "_SYSTEMD_UNIT": "authelia-configd.service",
                "MESSAGE": "Configuration daemon started",
                "PRIORITY": "6",
            }),
            json.dumps({
                "__REALTIME_TIMESTAMP": "1720991113000000",
                "UNIT": "iptables-haproxy-ban.service",
                "MESSAGE": "Finished loading ban rules",
                "PRIORITY": "4",
            }),
        ))

        with (
            mock.patch.object(
                state,
                "_expand_units",
                return_value=[
                    "authelia-configd.service",
                    "haproxy-healthd.service",
                    "haproxy.service",
                    "iptables-haproxy-ban.service",
                ],
            ),
            mock.patch.object(
                self.healthd,
                "_run_cmd",
                return_value=(0, journal, ""),
            ) as run_cmd,
        ):
            result = state.get_recent_systemd_logs(limit=10)

        command = run_cmd.call_args.args[0]
        self.assertNotIn("haproxy.service", command)
        self.assertNotIn("haproxy-healthd.service", command)
        self.assertIn("authelia-configd.service", command)
        self.assertIn("iptables-haproxy-ban.service", command)
        self.assertIn("--reverse", command)
        self.assertNotIn("--since", command)
        self.assertEqual(
            result["excluded_units"],
            ["haproxy-healthd.service", "haproxy.service"],
        )
        self.assertEqual(
            result["default_excluded_units"],
            ["haproxy-healthd.service", "haproxy.service"],
        )
        self.assertIsNone(result["requested_units"])
        self.assertEqual(result["limit"], 10)
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(result["items"][0]["unit"], "authelia-configd.service")
        self.assertEqual(result["items"][1]["priority"], 4)

    def test_explicit_selection_can_include_default_exclusions(self) -> None:
        state = self.make_state()
        raw_message = (
            'time="2026-07-15T01:18:52.473212050+03:00" '
            'level=warning msg="Security options are deprecated"'
        )
        journal = json.dumps({
            "__REALTIME_TIMESTAMP": "1720991114000000",
            "_SYSTEMD_UNIT": "haproxy-healthd.service",
            "MESSAGE": raw_message,
            "PRIORITY": "4",
        })

        with (
            mock.patch.object(
                state,
                "_expand_units",
                return_value=[
                    "authelia-configd.service",
                    "haproxy-healthd.service",
                    "haproxy.service",
                    "iptables-haproxy-ban.service",
                ],
            ),
            mock.patch.object(
                self.healthd,
                "_run_cmd",
                return_value=(0, journal, ""),
            ) as run_cmd,
        ):
            result = state.get_recent_systemd_logs(
                limit=9999,
                units=["haproxy-healthd.service", "haproxy.service"],
            )

        command = run_cmd.call_args.args[0]
        self.assertIn("haproxy-healthd.service", command)
        self.assertIn("haproxy.service", command)
        self.assertEqual(command[command.index("--lines") + 1], "500")
        self.assertEqual(
            result["units"],
            ["haproxy-healthd.service", "haproxy.service"],
        )
        self.assertEqual(
            result["items"][0]["raw_message"],
            raw_message,
        )
        self.assertNotIn("message", result["items"][0])

    def test_unknown_explicit_unit_is_rejected_before_journalctl(self) -> None:
        state = self.make_state()
        with (
            mock.patch.object(
                state,
                "_expand_units",
                return_value=["authelia-configd.service"],
            ),
            mock.patch.object(self.healthd, "_run_cmd") as run_cmd,
        ):
            result = state.get_recent_systemd_logs(
                units=["not-monitored.service"]
            )

        run_cmd.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(
            result["invalid_units"], ["not-monitored.service"]
        )
        self.assertEqual(
            result["available_units"], ["authelia-configd.service"]
        )

    def test_explicit_empty_selection_does_not_run_journalctl(self) -> None:
        state = self.make_state()
        with (
            mock.patch.object(
                state,
                "_expand_units",
                return_value=["authelia-configd.service"],
            ),
            mock.patch.object(self.healthd, "_run_cmd") as run_cmd,
        ):
            result = state.get_recent_systemd_logs(units=[])

        run_cmd.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertEqual(result["items"], [])
        self.assertEqual(result["units"], [])
        self.assertEqual(
            result["excluded_units"], ["authelia-configd.service"]
        )

    def test_query_parser_supports_repeated_comma_and_empty_selection(self) -> None:
        self.assertIsNone(self.healthd._parse_recent_systemd_units({}))
        self.assertEqual(
            self.healthd._parse_recent_systemd_units({
                "unit": ["one.service", "two.service, one.service"],
                "units": ["three.service"],
            }),
            ["one.service", "two.service", "three.service"],
        )
        self.assertEqual(
            self.healthd._parse_recent_systemd_units({"units": [""]}),
            [],
        )


class SystemdStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.healthd = load_healthd()

    def test_successful_inactive_oneshot_is_healthy(self) -> None:
        output = "\n".join((
            "LoadState=loaded",
            "ActiveState=inactive",
            "SubState=dead",
            "Type=oneshot",
            "Result=success",
            "ExecMainStatus=0",
            "InactiveExitTimestamp=Fri 2026-07-17 12:00:00 UTC",
        ))
        with mock.patch.object(
            self.healthd, "_run_cmd", return_value=(0, output, "")
        ):
            status = self.healthd._get_systemd_status(
                "easy-ha-proxy-geoip-update.service"
            )

        self.assertTrue(status["healthy"])
        self.assertEqual(status["display_state"], "completed")
        self.assertEqual(status["display_sub_state"], "success")
        self.assertEqual(status["active_state"], "inactive")
        self.assertEqual(status["sub_state"], "dead")
        self.assertEqual(status["exec_main_status"], 0)
        self.assertEqual(status["unit_type"], "oneshot")

    def test_failed_oneshot_is_unhealthy(self) -> None:
        output = "\n".join((
            "LoadState=loaded",
            "ActiveState=failed",
            "SubState=failed",
            "Type=oneshot",
            "Result=exit-code",
            "ExecMainStatus=2",
            "InactiveExitTimestamp=Fri 2026-07-17 12:00:00 UTC",
        ))
        with mock.patch.object(
            self.healthd, "_run_cmd", return_value=(0, output, "")
        ):
            status = self.healthd._get_systemd_status(
                "easy-ha-proxy-geoip-update.service"
            )

        self.assertFalse(status["healthy"])
        self.assertEqual(status["display_state"], "failed")
        self.assertEqual(status["display_sub_state"], "exit-code")
        self.assertEqual(status["active_state"], "failed")
        self.assertEqual(status["sub_state"], "failed")

    def test_never_run_inactive_oneshot_is_unknown(self) -> None:
        output = "\n".join((
            "LoadState=loaded",
            "ActiveState=inactive",
            "SubState=dead",
            "Type=oneshot",
            "Result=success",
            "ExecMainStatus=0",
            "InactiveExitTimestamp=",
        ))
        with mock.patch.object(
            self.healthd, "_run_cmd", return_value=(0, output, "")
        ):
            status = self.healthd._get_systemd_status(
                "easy-ha-proxy-geoip-update.service"
            )

        self.assertIsNone(status["healthy"])
        self.assertEqual(status["display_state"], "not-run")
        self.assertEqual(status["display_sub_state"], "—")
        self.assertEqual(status["active_state"], "inactive")
        self.assertEqual(status["sub_state"], "dead")

    def test_running_oneshot_has_running_presentation(self) -> None:
        output = "\n".join((
            "LoadState=loaded",
            "ActiveState=activating",
            "SubState=start",
            "Type=oneshot",
            "Result=success",
            "ExecMainStatus=0",
            "InactiveExitTimestamp=Fri 2026-07-17 12:00:00 UTC",
        ))
        with mock.patch.object(
            self.healthd, "_run_cmd", return_value=(0, output, "")
        ):
            status = self.healthd._get_systemd_status(
                "easy-ha-proxy-geoip-update.service"
            )

        self.assertIsNone(status["healthy"])
        self.assertEqual(status["display_state"], "running")
        self.assertEqual(status["display_sub_state"], "running")
        self.assertEqual(status["active_state"], "activating")
        self.assertEqual(status["sub_state"], "start")


class HealthJavascriptSourceTests(unittest.TestCase):
    def test_summaries_use_tri_state_health(self) -> None:
        source = (
            ROOT / "docker/app/haproxy_admin/static/js/health.js"
        ).read_text(encoding="utf-8")

        self.assertIn("function systemdHealthState(unit)", source)
        self.assertIn("if (unit.healthy === null) return null;", source)
        self.assertIn("function dockerHealthState(container)", source)
        self.assertIn('if (!health || health === "healthy") return true;', source)
        self.assertIn('if (health === "starting") return null;', source)
        self.assertIn("const hasFailed = states.some", source)
        self.assertIn('hasOwnProperty.call(u, "display_sub_state")', source)
        self.assertIn('titleParts.push(`result=${unit.result}`)', source)


class SiteAlertFormattingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.healthd = load_healthd()

    def test_duration_uses_days_hours_minutes(self):
        fd = self.healthd._format_duration
        self.assertEqual(fd(2885 * 60), "2d 0h 5m")
        self.assertEqual(fd(3661), "1h 1m")
        self.assertEqual(fd(65), "1m 5s")
        self.assertEqual(fd(30), "30s")

    def test_servers_block_lists_address_and_state(self):
        block = self.healthd._format_servers([
            {"name": "web1", "addr": "10.0.0.10:6690", "up": True},
            {"name": "web2", "addr": "10.0.0.11:6690", "up": False},
        ])
        self.assertIn("web1 (10.0.0.10:6690): UP", block)
        self.assertIn("web2 (10.0.0.11:6690): DOWN", block)

    def test_servers_block_falls_back_without_address(self):
        block = self.healthd._format_servers([{"name": "web1", "addr": "", "up": True}])
        self.assertEqual(block.strip(), "- web1: UP")

    def test_condition_reports_per_server_address(self):
        rows = [
            {"pxname": "be_rdg", "svname": "web1", "status": "UP",
             "addr": "10.0.0.10:6690"},
            {"pxname": "be_rdg", "svname": "web2", "status": "DOWN",
             "addr": "10.0.0.11:6690"},
            {"pxname": "be_rdg", "svname": "BACKEND", "status": "UP", "addr": ""},
        ]
        cond = self.healthd.SiteAlertEngine._site_condition("rdg", rows)
        self.assertEqual((cond["up"], cond["total"], cond["state"]), (1, 2, "degraded"))
        addrs = {s["name"]: s["addr"] for s in cond["servers"]}
        self.assertEqual(
            addrs, {"web1": "10.0.0.10:6690", "web2": "10.0.0.11:6690"}
        )


class SiteAlertStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.healthd = load_healthd()

    def setUp(self) -> None:
        # These tests script time.time() with a finite side_effect sequence
        # sized for the engine's own clock reads. Whenever the root logger has
        # a handler attached, LOG.info() inside the engine starts building real
        # LogRecords -- and LogRecord.__init__ calls time.time(), consuming a
        # scripted value. Silencing the logger keeps the scenario independent
        # of any global logging setup installed by the runner or other tests.
        patcher = mock.patch.object(self.healthd.LOG, "disabled", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_engine(self, state_path: Path):
        patcher = mock.patch.object(
            self.healthd, "SITE_ALERTS_STATE_PATH", state_path
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return self.healthd.SiteAlertEngine()

    @staticmethod
    def site():
        return {
            "name": "example.test",
            "alert_enabled": True,
            "alert_mode": "degraded",
            "alert_after": "5m",
        }

    @staticmethod
    def condition(state: str):
        up = 2 if state == "ok" else 1
        return {"state": state, "up": up, "total": 2, "servers": []}

    def test_transient_good_sample_after_reload_does_not_recover_incident(self):
        with tempfile.TemporaryDirectory() as temporary:
            engine = self.make_engine(Path(temporary) / "site-alerts.json")
            engine._incidents["example.test"] = {
                "bad_since": 100.0,
                "alerted_at": 400.0,
                "alerted_state": "degraded",
                "good_since": None,
            }
            with (
                mock.patch.object(engine, "_send_mail", return_value=True) as send,
                mock.patch.object(self.healthd.time, "time", side_effect=[500.0, 515.0]),
            ):
                first_changed = engine._evaluate(
                    self.site(), "example.test", self.condition("ok")
                )
                second_changed = engine._evaluate(
                    self.site(), "example.test", self.condition("degraded")
                )

            self.assertTrue(first_changed)
            self.assertTrue(second_changed)
            send.assert_not_called()
            record = engine._incidents["example.test"]
            self.assertEqual(record["alerted_at"], 400.0)
            self.assertIsNone(record["good_since"])

    def test_recovery_requires_the_full_stable_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            engine = self.make_engine(Path(temporary) / "site-alerts.json")
            engine._incidents["example.test"] = {
                "bad_since": 100.0,
                "alerted_at": 400.0,
                "alerted_state": "degraded",
                "good_since": None,
            }
            with (
                mock.patch.object(engine, "_send_mail", return_value=True) as send,
                mock.patch.object(
                    self.healthd.time, "time", side_effect=[500.0, 799.0, 800.0]
                ),
            ):
                engine._evaluate(self.site(), "example.test", self.condition("ok"))
                engine._evaluate(self.site(), "example.test", self.condition("ok"))
                engine._evaluate(self.site(), "example.test", self.condition("ok"))

            send.assert_called_once()
            self.assertIn("RECOVERED", send.call_args.args[1])
            self.assertEqual(
                engine._incidents["example.test"],
                {
                    "bad_since": None,
                    "alerted_at": None,
                    "alerted_state": "",
                    "good_since": None,
                },
            )

    def test_incident_and_repeat_deadline_survive_daemon_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "site-alerts.json"
            first = self.make_engine(state_path)
            first._incidents["example.test"] = {
                "bad_since": 100.0,
                "alerted_at": 400.0,
                "alerted_state": "degraded",
                "good_since": None,
            }
            self.assertTrue(first._persist_incidents())

            second = self.make_engine(state_path)

            self.assertEqual(second._incidents, first._incidents)
            self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
            with (
                mock.patch.object(second, "_send_mail", return_value=True) as send,
                mock.patch.object(self.healthd.time, "time", return_value=500.0),
            ):
                second._evaluate(
                    self.site(), "example.test", self.condition("degraded")
                )
            send.assert_not_called()
            self.assertEqual(
                second._incidents["example.test"]["alerted_at"], 400.0
            )

    def test_unsafe_symlink_state_is_ignored_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "operator-data.json"
            target.write_text("do not replace\n", encoding="utf-8")
            state_path = root / "site-alerts.json"
            state_path.symlink_to(target)

            engine = self.make_engine(state_path)
            engine._incidents["example.test"] = {
                "bad_since": 100.0,
                "alerted_at": None,
                "alerted_state": "",
                "good_since": None,
            }

            self.assertEqual(engine._incidents, {
                "example.test": {
                    "bad_since": 100.0,
                    "alerted_at": None,
                    "alerted_state": "",
                    "good_since": None,
                }
            })
            self.assertFalse(engine._persist_incidents())
            self.assertTrue(state_path.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "do not replace\n")

    def test_temporary_configuration_failure_preserves_incident_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            engine = self.make_engine(Path(temporary) / "site-alerts.json")
            engine._incidents["example.test"] = {
                "bad_since": 100.0,
                "alerted_at": 400.0,
                "alerted_state": "degraded",
                "good_since": None,
            }
            missing = Path(temporary) / "missing-websites.yml"
            with mock.patch.object(
                self.healthd, "SITE_ALERTS_WEBSITES", str(missing)
            ):
                self.assertIsNone(engine._load_sites())
            self.assertIn("example.test", engine._incidents)

    def test_systemd_unit_provisions_private_persistent_state_directory(self):
        unit = (
            ROOT
            / "ansible/roles/haproxy-admin/templates/haproxy-healthd.service.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("StateDirectory=easy-ha-proxy", unit)
        self.assertIn("StateDirectoryMode=0750", unit)


if __name__ == "__main__":
    unittest.main()
