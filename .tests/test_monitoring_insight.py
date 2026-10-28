"""What the monitoring page says beyond the lines: what happened, who stands out,
what is wrong now.

- Events: the changes from the change log and the alerts from the alert
  engine, marked on the charts. Only what changes what the gateway serves,
  only what succeeded, and only the period on show.
- Requests per backend: requests, errors and response time over the period,
  read from HAProxy's backend rows, to sort for the busiest, the failing and
  the slow backend.
- Needs attention: the alert engine's open alerts, firing first. The engine
  owns the thresholds; the page keeps no second set of rules.
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
APP = ROOT / "docker" / "app" / "haproxy_admin"
FILES = ROOT / "ansible" / "roles" / "haproxy-admin" / "files"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import audit  # noqa: E402
from haproxy_admin import services_monitoring as monitoring  # noqa: E402
from haproxy_admin.alertd_client import AlertdUnavailable  # noqa: E402


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, FILES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


metricsd = load("easy_ha_proxy_metricsd_insight", "easy-ha-proxy-metricsd.py")
alertd = load("easy_ha_proxy_alertd_insight", "easy-ha-proxy-alertd.py")


class TotalsPerBackend(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = metricsd.MetricsDatabase(str(Path(temporary.name) / "metrics.db"))
        self.addCleanup(self.database.close)

    def seed(self, kind, proxy, server, buckets, **columns):
        object_id = self.database.object_id(kind, proxy, server, 0)
        for bucket_ts in buckets:
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row["samples"] = 6
            row.update(columns)
            self.database.write_buckets(bucket_ts, {object_id: row})

    def totals(self, since=0, until=1200):
        return {
            entry["proxy"]: entry
            for entry in self.database.backend_totals(since=since, until=until)["backends"]
        }

    def test_counts_and_classes_are_summed_per_backend(self):
        self.seed("backend", "be_shop", "", [600, 660], requests=50, resp_2xx=40,
                  resp_4xx=6, resp_5xx=4, bytes_in=100, bytes_out=1000)
        totals = self.totals()
        self.assertEqual(totals["be_shop"]["requests"], 100)
        self.assertEqual(totals["be_shop"]["resp_5xx"], 8)
        self.assertEqual(totals["be_shop"]["resp_4xx"], 12)
        self.assertEqual(totals["be_shop"]["bytes_out"], 2000)

    def test_only_backend_rows_count(self):
        # The same requests pass a frontend and a server too; counting them
        # there as well would double every figure.
        self.seed("frontend", "fe_https", "", [600], requests=500)
        self.seed("server", "be_shop", "srv1", [600], requests=500)
        self.seed("backend", "be_shop", "", [600], requests=10)
        totals = self.totals()
        self.assertEqual(list(totals), ["be_shop"])
        self.assertEqual(totals["be_shop"]["requests"], 10)

    def test_response_time_is_weighed_by_the_requests_answered(self):
        self.seed("backend", "be_shop", "", [600], requests=90, response_ms_avg=100, response_ms_max=400)
        self.seed("backend", "be_shop", "", [660], requests=10, response_ms_avg=1000, response_ms_max=2000)
        # A quiet minute keeps HAProxy's last average; it must not count.
        self.seed("backend", "be_shop", "", [720], requests=0, response_ms_avg=9000, response_ms_max=9000)
        totals = self.totals()
        # (100 * 90 + 1000 * 10) / 100
        self.assertEqual(totals["be_shop"]["response_ms_avg"], 190)
        self.assertEqual(totals["be_shop"]["response_ms_max"], 2000)

    def test_a_backend_that_answered_nothing_has_no_response_time(self):
        self.seed("backend", "be_idle", "", [600], requests=0, response_ms_avg=50, response_ms_max=60)
        totals = self.totals()
        self.assertIsNone(totals["be_idle"]["response_ms_avg"])
        self.assertIsNone(totals["be_idle"]["response_ms_max"])

    def test_only_the_period_asked_for(self):
        self.seed("backend", "be_shop", "", [600], requests=5)
        self.seed("backend", "be_shop", "", [6000], requests=7)
        self.assertEqual(self.totals(0, 1200)["be_shop"]["requests"], 5)
        self.assertEqual(self.totals(1200, 7200)["be_shop"]["requests"], 7)

    def test_a_long_period_reads_the_hourly_rows(self):
        self.seed("backend", "be_shop", "", [0, 60], requests=10, response_ms_avg=100)
        self.database.rollup_hours(metricsd.HOUR_SECONDS)
        payload = self.database.backend_totals(since=0, until=30 * 86400)
        self.assertEqual(payload["source"], "metric_1h")
        self.assertEqual(payload["backends"][0]["requests"], 20)
        self.assertEqual(payload["backends"][0]["response_ms_avg"], 100)

    def test_the_daemon_answers_for_it(self):
        source = (FILES / "easy-ha-proxy-metricsd.py").read_text(encoding="utf-8")
        handler = source.split('if path == "/api/v1/metrics/backends":')[1].split("return\n\n")[0]
        self.assertIn("resolve_window(query)", handler)
        self.assertIn("database.backend_totals(since=since, until=until)", handler)


class AlertHistoryOfAPeriod(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = alertd.AlertDatabase(str(Path(temporary.name) / "alerts.db"))
        for ts in (100, 200, 300):
            self.database.add_event({
                "ts": ts, "rule": "site.down", "subject": "shop", "transition": "fired",
                "severity": "critical", "summary": "", "detail": "", "delivered": "",
                "delivery_error": "",
            })

    def test_a_period_that_ended_is_its_own_events(self):
        events = self.database.events(since=150, until=250)["events"]
        self.assertEqual([event["ts"] for event in events], [200])

    def test_without_an_end_it_reads_as_before(self):
        events = self.database.events(since=150)["events"]
        self.assertEqual(sorted(event["ts"] for event in events), [200, 300])

    def test_the_daemon_passes_the_end_on(self):
        source = (FILES / "easy-ha-proxy-alertd.py").read_text(encoding="utf-8")
        handler = source.split('if parsed.path == "/api/v1/alerts/history":')[1].split("return\n")[0]
        self.assertIn('until=_clamp_int(\n                        query.get("until"', handler)


class TheChangeLogAnswersForSeveralActions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.log = audit.AuditLog(str(Path(temporary.name) / "audit.db"))

    def test_any_of_the_actions_named(self):
        for ts, action in ((10, "site.update"), (20, "ban.place"), (30, "config.apply")):
            self.log.record(action, ts=ts)
        found = self.log.query(actions=("site.update", "config.apply"))
        self.assertEqual(sorted(row["action"] for row in found["events"]), ["config.apply", "site.update"])
        self.assertEqual(found["total"], 2)

    def test_no_actions_means_every_action(self):
        self.log.record("site.update", ts=10)
        self.log.record("ban.place", ts=20)
        self.assertEqual(self.log.query(actions=())["total"], 2)


class Events(unittest.TestCase):
    def changes(self, rows, total=None):
        log = mock.Mock()
        log.query.return_value = {"total": len(rows) if total is None else total, "events": rows}
        return mock.patch.object(monitoring, "audit_log", return_value=log)

    def alerts(self, rows=None, error=None):
        if error is not None:
            return mock.patch.object(monitoring, "alertd_history", side_effect=error)
        return mock.patch.object(monitoring, "alertd_history", return_value={"events": rows or []})

    def test_only_the_changes_a_chart_can_show_and_only_successes(self):
        with self.changes([]) as log, self.alerts():
            monitoring.events("24h", now=100000)
        query = log.return_value.query.call_args.kwargs
        self.assertEqual(set(query["actions"]), set(monitoring.EVENT_ACTIONS))
        self.assertEqual(query["result"], audit.RESULT_SUCCESS)
        self.assertEqual((query["since"], query["until"]), (100000 - 86400, 100000))
        # Reading a page or taking a backup changes nothing on a chart.
        for action in ("backup.start", "ban.place", "monitoring.monitors", "config.confirm"):
            self.assertNotIn(action, monitoring.EVENT_ACTIONS)

    def test_an_explicit_period_wins_over_the_preset(self):
        with self.changes([]) as log, self.alerts() as history:
            payload = monitoring.events("24h", {"since": 500, "until": 900}, now=100000)
        query = log.return_value.query.call_args.kwargs
        self.assertEqual((query["since"], query["until"]), (500, 900))
        self.assertEqual(history.call_args.args[0]["until"], 900)
        self.assertEqual((payload["since"], payload["until"]), (500, 900))

    def test_changes_and_alerts_come_back_oldest_first(self):
        rows = [{"ts": 300, "action": "site.update", "object_id": "shop", "actor": "anna",
                 "summary": "port: 80 → 8080"}]
        alerts = [
            {"ts": 400, "transition": "recovered", "subject": "shop", "summary": "up", "severity": "critical"},
            {"ts": 350, "transition": "repeated", "subject": "shop", "summary": "", "severity": "critical"},
            {"ts": 200, "transition": "fired", "subject": "shop", "summary": "down", "severity": "critical"},
        ]
        with self.changes(rows), self.alerts(alerts):
            payload = monitoring.events("24h", {"since": 100, "until": 1000})
        self.assertEqual([event["ts"] for event in payload["events"]], [200, 300, 400])
        self.assertEqual([event["kind"] for event in payload["events"]], ["alert", "change", "recovered"])
        change = payload["events"][1]
        self.assertEqual(change["label"], "Site changed")
        self.assertEqual((change["object"], change["actor"]), ("shop", "anna"))

    def test_an_alert_carries_its_rule_and_the_engines_name_for_it(self):
        alerts = [{"ts": 200, "transition": "fired", "rule": "response.slow", "subject": "be_shop",
                   "summary": "slow", "severity": "warning"}]
        state = {"catalogue": [{"name": "response.slow", "title": "Response time above the threshold"}]}
        with self.changes([]), self.alerts(alerts), \
                mock.patch.object(monitoring, "alertd_state", return_value=state):
            event = monitoring.events("24h", {"since": 100, "until": 1000})["events"][0]
        self.assertEqual(event["rule"], "response.slow")
        self.assertEqual(event["title"], "Response time above the threshold")
        # Without the catalogue the rule names itself.
        with self.changes([]), self.alerts(alerts), \
                mock.patch.object(monitoring, "alertd_state", side_effect=AlertdUnavailable("x")):
            event = monitoring.events("24h", {"since": 100, "until": 1000})["events"][0]
        self.assertEqual(event["title"], "response.slow")

    def test_an_older_engine_that_ignores_the_end_is_held_to_the_period(self):
        alerts = [{"ts": 5000, "transition": "fired", "subject": "x", "summary": "", "severity": "warning"}]
        with self.changes([]), self.alerts(alerts):
            payload = monitoring.events("24h", {"since": 100, "until": 1000})
        self.assertEqual(payload["events"], [])

    def test_without_the_alert_engine_the_changes_still_show(self):
        rows = [{"ts": 300, "action": "config.apply", "object_id": "", "actor": "", "summary": ""}]
        with self.changes(rows), self.alerts(error=AlertdUnavailable("down")):
            payload = monitoring.events("24h", {"since": 100, "until": 1000})
        self.assertEqual(len(payload["events"]), 1)
        self.assertFalse(payload["alerts_available"])

    def test_too_many_is_said_not_hidden(self):
        with self.changes([], total=monitoring.MAX_EVENTS + 1), self.alerts():
            self.assertTrue(monitoring.events("24h", now=100000)["truncated"])
        alerts = [
            {"ts": 100 + index, "transition": "fired", "subject": "x", "summary": "", "severity": "warning"}
            for index in range(monitoring.MAX_EVENTS + 5)
        ]
        with self.changes([]), self.alerts(alerts):
            payload = monitoring.events("24h", {"since": 1, "until": 100000})
        self.assertTrue(payload["truncated"])
        self.assertEqual(len(payload["events"]), monitoring.MAX_EVENTS)
        # The newest are kept.
        self.assertEqual(payload["events"][-1]["ts"], 100 + monitoring.MAX_EVENTS + 4)


class RequestsPerBackend(unittest.TestCase):
    def test_shares_labels_and_the_quiet_left_out(self):
        answer = {"range": "24h", "since": 1, "until": 2, "backends": [
            {"proxy": "be_shop", "requests": 200, "resp_2xx": 150, "resp_3xx": 10,
             "resp_4xx": 30, "resp_5xx": 10, "bytes_in": 5, "bytes_out": 6,
             "response_ms_avg": 120, "response_ms_max": 900},
            {"proxy": "be_idle", "requests": 0, "resp_2xx": 0, "response_ms_avg": None},
            {"proxy": "be_blog", "requests": 400, "resp_2xx": 400, "response_ms_avg": None,
             "response_ms_max": None},
        ]}
        with mock.patch.object(monitoring, "metricsd_backends", return_value=answer), \
                mock.patch.object(monitoring, "display_name", side_effect=lambda proxy: proxy[3:]):
            payload = monitoring.backend_requests("24h")
        self.assertEqual([entry["proxy"] for entry in payload["backends"]], ["be_blog", "be_shop"])
        shop = payload["backends"][1]
        self.assertEqual(shop["label"], "shop")
        self.assertEqual((shop["share_4xx"], shop["share_5xx"]), (15.0, 5.0))
        self.assertEqual(shop["bytes_total"], 11)
        self.assertIsNone(payload["backends"][0]["response_ms_avg"])
        self.assertEqual(payload["requests_total"], 600)


class NeedsAttention(unittest.TestCase):
    def state(self, active=(), pending=()):
        return {
            "active": list(active),
            "pending": list(pending),
            "catalogue": [{"name": "site.down", "title": "Site is down"}],
        }

    def row(self, rule, severity, since, subject="be_shop"):
        return {"rule": rule, "severity": severity, "since_ts": since, "subject": subject,
                "summary": f"{rule} {since}"}

    def test_firing_first_then_critical_then_newest(self):
        state = self.state(
            active=[self.row("http.error_ratio", "warning", 300), self.row("site.down", "critical", 100),
                    self.row("response.slow", "warning", 500)],
            pending=[self.row("site.down", "critical", 900)],
        )
        with mock.patch.object(monitoring, "alertd_state", return_value=state):
            payload = monitoring.attention()
        order = [(item["rule"], item["since"], item["pending"]) for item in payload["items"]]
        self.assertEqual(order, [
            ("site.down", 100, False),
            ("response.slow", 500, False),
            ("http.error_ratio", 300, False),
            ("site.down", 900, True),
        ])
        self.assertEqual(payload["items"][0]["title"], "Site is down")

    def test_information_is_not_a_problem(self):
        state = self.state(active=[self.row("update.available", "info", 100)])
        with mock.patch.object(monitoring, "alertd_state", return_value=state):
            self.assertEqual(monitoring.attention()["items"], [])

    def test_a_long_list_is_cut_and_says_so(self):
        rows = [self.row("response.slow", "warning", index) for index in range(monitoring.MAX_ATTENTION + 3)]
        with mock.patch.object(monitoring, "alertd_state", return_value=self.state(active=rows)):
            payload = monitoring.attention()
        self.assertEqual(len(payload["items"]), monitoring.MAX_ATTENTION)
        self.assertEqual(payload["more"], 3)

    def test_a_silent_engine_is_said(self):
        with mock.patch.object(monitoring, "alertd_state", side_effect=AlertdUnavailable("down")):
            payload = monitoring.attention()
        self.assertFalse(payload["available"])
        self.assertEqual(payload["items"], [])


class ThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (APP / "templates/monitoring.html").read_text(encoding="utf-8")
        cls.script = (APP / "static/js/monitoring.js").read_text(encoding="utf-8")
        cls.routes = (APP / "routes_monitoring.py").read_text(encoding="utf-8")
        cls.catalog = {}
        for path in (APP / "translations").rglob("*.json"):
            catalogue = json.loads(path.read_text(encoding="utf-8"))
            if catalogue.get("meta", {}).get("code") == "ru":
                cls.catalog.update(catalogue["messages"])

    def test_the_routes_only_read(self):
        for route in ("/api/monitoring/backend-requests", "/api/monitoring/events",
                      "/api/monitoring/attention"):
            self.assertIn(f'@bp.get("{route}")', self.routes)
            self.assertNotIn(f'@bp.post("{route}")', self.routes)

    def test_the_page_has_its_places(self):
        for marker in ('id="mon-attention" hidden', 'id="mon-attention-list"', 'id="mon-events"',
                       'data-view="requests"', 'id="mon-requests-sort-wrap" hidden',
                       'id="mon-backend-requests" class="mon-requests-wrap" hidden'):
            self.assertIn(marker, self.template)

    def test_events_are_off_until_a_viewer_turns_them_on(self):
        self.assertIn('<input type="checkbox" id="mon-events">', self.template)
        self.assertIn('remembered("mon-events", ["on", "off"], "off")', self.script)
        for marker in ('data-event-kind="change"', 'data-event-kind="alert"', 'data-event-kind="recovered"',
                       'data-event-severity="critical"', 'data-event-severity="warning"',
                       'data-event-severity="info"', 'id="mon-events-rules"'):
            self.assertIn(marker, self.template)
        # The marks are the filtered events, never the whole answer.
        draw = self.script.split("function drawChart(")[1].split("\n  }\n")[0]
        self.assertIn("core.eventMarks(points, step, shownEvents())", draw)

    def test_every_sort_order_is_offered(self):
        core = (APP / "static/js/monitoring_core.js").read_text(encoding="utf-8")
        orders = core.split("const REQUEST_SORTS = [")[1].split("]")[0]
        for order in [item.strip().strip('"') for item in orders.split(",")]:
            self.assertIn(f'<option value="{order}">', self.template)

    def test_events_follow_the_charts_and_ignore_the_site(self):
        load = self.script.split("async function loadAll(")[1].split("\n  }\n")[0]
        self.assertIn("showEvents && chartsDue", load)
        params = self.script.split("function eventsParams(")[1].split("\n  }\n")[0]
        self.assertNotIn("currentSite", params)
        self.assertIn("windowParams()", params)

    def test_every_word_is_in_russian(self):
        words = set(monitoring.EVENT_ACTIONS.values()) | {
            "Alert", "Recovered", "Events on charts", "Not all events of this period are shown",
            "Requests and errors", "Backend requests", "Most requests first",
            "Most server errors first", "Most client errors first", "Slowest first",
            "Client errors", "Show on charts", "Needs attention", "All alerts",
            "The alert engine is not answering", "ms", "waiting",
            "Filter", "Show", "Changes", "Alerts", "Recoveries", "Importance", "Critical",
            "Warning", "Info", "Alerts in this period", "No alerts in this period",
        }
        missing = sorted(word for word in words if word not in self.catalog)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
