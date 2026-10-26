"""Every alert rule on the alerts page is one something can raise.

Five rules were listed with nothing behind them: they could be switched on
and would never fire. backend.no_servers duplicated site.down, which healthd
already raises per site, and is gone. The other four have producers now:

- authelia.unavailable: metricsd, from HAProxy's view of Authelia's backend
  on every poll;
- http.error_ratio and response.slow: metricsd, per backend, on each
  minute's totals, with thresholds from its configuration and a request
  floor below which a minute says nothing either way;
- security.burst: guardd, when a wave of addresses is banned within minutes.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible/roles/haproxy-admin/files"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


alertd = load(FILES / "easy-ha-proxy-alertd.py", "alertd_producers_test")


class FakeAlerts:
    def __init__(self):
        self.seen = []

    def observe(self, rule, subject, **kwargs):
        self.seen.append((rule, subject, kwargs))
        return True

    def last(self, rule, subject):
        found = [item for item in self.seen if item[0] == rule and item[1] == subject]
        return found[-1][2] if found else None


class EveryRuleHasAProducer(unittest.TestCase):
    def test_no_rule_is_a_promise_nothing_keeps(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in (ROOT / "ansible", ROOT / "docker", ROOT / "installer")
            for path in directory.rglob("*.py")
            if path.name != "easy-ha-proxy-alertd.py"
        )
        for rule in alertd.RULES:
            with self.subTest(rule=rule.name):
                self.assertIn(f'"{rule.name}"', sources)

    def test_the_duplicate_of_site_down_is_gone(self):
        self.assertNotIn("backend.no_servers", alertd.RULES_BY_NAME)
        # An old configuration that still names it loads without complaint.
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"rules": {"backend.no_servers": {"enabled": False}}}, handle)
        self.addCleanup(Path(handle.name).unlink)
        self.assertIsNotNone(alertd.load_config(handle.name))


metricsd = load(FILES / "easy-ha-proxy-metricsd.py", "metricsd_producers_test")

HEADER = ("# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,chkfail,"
          "hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,req_tot,"
          "qtime,ctime,rtime,ttime")


def row(pxname, svname, *, status="UP", req_tot=0, hrsp_5xx=0, rtime=0):
    values = (pxname, svname, 0, 0, 0, 0, 0, 0, 0, 0, status, 0, 0, 0, 0, 0,
              hrsp_5xx, 0, req_tot, 0, 0, rtime, 0)
    return ",".join(str(value) for value in values)


class TheMetricsDaemon(unittest.TestCase):
    def setUp(self):
        from unittest import mock

        self.mock = mock
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = metricsd.MetricsDatabase(str(Path(temporary.name) / "metrics.db"))
        self.addCleanup(self.database.close)
        self.config = metricsd.load_config("/nonexistent/metricsd.json")
        self.alerts = FakeAlerts()
        guard = metricsd.StorageGuard(self.config, self.database, alerts=self.alerts)
        self.collector = metricsd.Collector(self.config, self.database, storage=guard)
        self.collector.cgroup_root = str(Path(temporary.name) / "no-cgroup")

    def poll(self, *rows, now):
        text = "\n".join((HEADER, *rows)) + "\n"
        with self.mock.patch.object(metricsd, "runtime_command", return_value=text), \
                self.mock.patch.object(metricsd, "_utc_now", return_value=now):
            self.collector.poll()

    def minute(self, *first, then):
        # Two polls in one minute give a delta; the flush judges the minute.
        self.poll(*first, now=1_000_020)
        self.poll(*then, now=1_000_040)
        with self.mock.patch.object(metricsd, "_utc_now", return_value=1_000_100):
            self.collector.flush(force=True)

    def test_server_errors_over_the_threshold_raise_and_a_quiet_minute_says_nothing(self):
        self.minute(
            row("be_busy", "BACKEND", req_tot=1000, hrsp_5xx=0),
            row("be_quiet", "BACKEND", req_tot=10, hrsp_5xx=0),
            then=(row("be_busy", "BACKEND", req_tot=1100, hrsp_5xx=30),
                  row("be_quiet", "BACKEND", req_tot=15, hrsp_5xx=5)),
        )
        busy = self.alerts.last("http.error_ratio", "be_busy")
        self.assertTrue(busy["active"])
        self.assertIn("30%", busy["summary"])
        # Five errors out of five requests is below the request floor.
        self.assertFalse(self.alerts.last("http.error_ratio", "be_quiet")["active"])

    def test_slow_responses_raise(self):
        self.minute(
            row("be_slow", "BACKEND", req_tot=100, rtime=4500),
            then=(row("be_slow", "BACKEND", req_tot=200, rtime=4500),),
        )
        self.assertTrue(self.alerts.last("response.slow", "be_slow")["active"])
        self.assertFalse(self.alerts.last("http.error_ratio", "be_slow")["active"])

    def test_authelia_down_and_back(self):
        self.poll(row("authelia_backend", "BACKEND", status="DOWN"), now=1_000_020)
        self.assertTrue(self.alerts.last("authelia.unavailable", "authelia")["active"])
        self.poll(row("authelia_backend", "BACKEND", status="UP"), now=1_000_030)
        self.assertFalse(self.alerts.last("authelia.unavailable", "authelia")["active"])
        # Its own numbers are the portal's, not a site's.
        self.assertIsNone(self.alerts.last("http.error_ratio", "authelia_backend"))

    def test_thresholds_come_from_the_configuration_and_zero_switches_off(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"alerts": {"error_ratio_percent": 0, "slow_response_ms": 250,
                                  "min_requests": 5}}, handle)
        self.addCleanup(Path(handle.name).unlink)
        config = metricsd.load_config(handle.name)
        self.assertEqual((config.alert_error_ratio_percent, config.alert_slow_response_ms,
                          config.alert_min_requests), (0, 250, 5))
        template = (ROOT / "ansible/roles/haproxy-admin/templates/metricsd.json.j2").read_text(encoding="utf-8")
        self.assertIn('"error_ratio_percent": {{ metricsd_alert_error_ratio_percent | default(10) | int }}', template)


guardd = load(FILES / "easy-ha-proxy-guardd.py", "guardd_producers_test")


class TheProtectionDaemon(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        log = root / "haproxy.log"
        log.write_text("", encoding="utf-8")
        config = guardd.GuardConfig(log_file=str(log), whitelist_files=())
        self.database = guardd.SecurityDatabase(str(root / "security.db"))
        self.addCleanup(self.database.close)
        self.alerts = FakeAlerts()
        self.engine = guardd.GuardEngine(config, self.database, alerts=self.alerts)

    def bursts(self):
        return [item for item in self.alerts.seen if item[0] == "security.burst"]

    def test_a_wave_of_bans_is_reported_once_per_hour(self):
        self.engine._check_burst(10, 1000)
        self.assertEqual(self.bursts(), [])
        self.engine._check_burst(5, 1100)
        self.assertEqual(len(self.bursts()), 1)
        self.assertIn("15 addresses banned", self.bursts()[0][2]["summary"])
        self.engine._check_burst(20, 1200)
        self.assertEqual(len(self.bursts()), 1)
        self.engine._check_burst(20, 1100 + guardd.BURST_REPORT_GAP_SECONDS)
        self.assertEqual(len(self.bursts()), 2)

    def test_bans_spread_over_time_are_not_a_wave(self):
        for minute in range(30):
            self.engine._check_burst(1, 1000 + minute * 60)
        self.assertEqual(self.bursts(), [])


if __name__ == "__main__":
    unittest.main()
