"""Monitors can be switched off, and what metricsd gathers itself stops.

The machine's load and its split per component are read by the collector
beside HAProxy's counters; switched off, they are no longer read. The
choices are kept in the collector's own state, survive a restart, and come
back with every summary so the page knows what to draw. On a virtual
machine, for one, there may be nothing worth watching about the machine.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"


def load():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_metricsd_monitors", DAEMON)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


metricsd = load()

STAT = (
    "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,"
    "wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,"
    "sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,"
    "check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,"
    "req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt\n"
    "be_site,BACKEND,0,0,1,1,,10,100,200,0,0,,0,0,0,0,UP,1,1,0,,0,0,0,,1,1,0,,0,,1,0,,0,,,,"
    "0,5,0,0,0,0,,0,0,10,0,0\n"
)


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = str(Path(temporary.name) / "metrics.db")
        self.database = metricsd.MetricsDatabase(self.path)
        self.addCleanup(self.database.close)
        self.collector = metricsd.Collector(
            metricsd.load_config("/nonexistent/metricsd.json"), self.database
        )
        self.collector.cgroup_root = str(Path(temporary.name) / "no-cgroup")

    def poll(self):
        with (
            mock.patch.object(metricsd, "runtime_command", return_value=STAT),
            mock.patch.object(self.collector, "_read_host_cpu", return_value=250) as cpu,
            mock.patch.object(self.collector, "_read_host_memory", return_value=(1000, 2000)),
            mock.patch.object(self.collector, "_read_haproxy_busy", return_value=None),
            mock.patch.object(self.collector, "_observe_components") as components,
        ):
            observed = self.collector.poll()
        return observed, cpu, components


class SwitchingThemOff(Fixture):
    def test_everything_runs_until_told_otherwise(self):
        self.collector.load_monitors()
        self.assertTrue(all(self.collector.monitors.values()))
        self.assertEqual(set(self.collector.monitors), set(metricsd.MONITOR_DEFAULTS))
        _, cpu, components = self.poll()
        cpu.assert_called_once()
        components.assert_called_once()

    def test_the_machine_switched_off_is_not_read_at_all(self):
        self.collector.set_monitors({"machine": False})
        observed, cpu, components = self.poll()
        # HAProxy's counters are read as ever.
        self.assertEqual(observed, 1)
        cpu.assert_not_called()
        components.assert_not_called()

    def test_components_switched_off_leave_the_machine_read(self):
        self.collector.set_monitors({"components": False})
        _, cpu, components = self.poll()
        cpu.assert_called_once()
        components.assert_not_called()

    def test_a_shown_only_monitor_changes_nothing_gathered(self):
        self.collector.set_monitors({"latency": False, "uplinks": False})
        _, cpu, components = self.poll()
        cpu.assert_called_once()
        components.assert_called_once()

    def test_the_choice_survives_a_restart(self):
        self.collector.set_monitors({"machine": False, "requests": False})
        restarted = metricsd.Collector(metricsd.load_config("/nonexistent/metricsd.json"), self.database)
        restarted.load_monitors()
        self.assertFalse(restarted.monitors["machine"])
        self.assertFalse(restarted.monitors["requests"])
        self.assertTrue(restarted.monitors["components"])

    def test_a_damaged_record_falls_back_to_everything_on(self):
        self.database.set_state(metricsd.MONITORS_KEY, "not json")
        self.collector.load_monitors()
        self.assertTrue(all(self.collector.monitors.values()))
        self.database.set_state(metricsd.MONITORS_KEY, json.dumps({"machine": "no", "bogus": False}))
        self.collector.load_monitors()
        self.assertTrue(self.collector.monitors["machine"])
        self.assertNotIn("bogus", self.collector.monitors)

    def test_switched_back_on_a_component_is_not_measured_across_the_pause(self):
        self.collector._component_previous["/sys/fs/cgroup/x"] = (1, 1.0)
        self.collector._cpu_previous = (10, 5)
        self.collector.set_monitors({"machine": False})
        self.assertEqual(self.collector._component_previous, {})
        self.assertIsNone(self.collector._cpu_previous)


class TheApi(Fixture):
    def handler(self, method, path, body=None):
        handler = metricsd.MetricsHandler.__new__(metricsd.MetricsHandler)
        handler.server = mock.Mock(collector=self.collector, database=self.database)
        raw = json.dumps(body).encode() if body is not None else b""
        handler.headers = {"Content-Length": str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        handler.path = path
        sent = {}

        def send_json(code, payload):
            sent["code"], sent["payload"] = code, payload

        handler._send_json = send_json
        getattr(handler, f"do_{method}")()
        return sent["code"], sent["payload"]

    def test_switching_answers_with_every_monitor(self):
        code, payload = self.handler("POST", "/api/v1/metrics/monitors", {"monitors": {"components": False}})
        self.assertEqual(code, 200)
        self.assertFalse(payload["monitors"]["components"])
        self.assertTrue(payload["monitors"]["machine"])
        code, payload = self.handler("GET", "/api/v1/metrics/monitors")
        self.assertEqual((code, payload["monitors"]["components"]), (200, False))

    def test_a_typo_or_a_non_boolean_switches_nothing(self):
        for body in ({"monitors": {"machnie": False}}, {"monitors": {"machine": "off"}},
                     {"monitors": {}}, {"something": 1}):
            with self.subTest(body=body):
                code, payload = self.handler("POST", "/api/v1/metrics/monitors", body)
                self.assertEqual(code, 400)
        self.assertTrue(all(self.collector.monitors.values()))


if __name__ == "__main__":
    unittest.main()
