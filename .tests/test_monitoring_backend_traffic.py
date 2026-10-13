"""The backend list can show traffic instead of availability.

The availability bars say whether a backend was up. They cannot say which of
twenty backends the traffic of a busy hour belonged to, and the total on the
overview card does not name anyone. The collector already keeps bytes per
server, so the same card now has a second view: traffic per backend over the
chosen period, busiest first, with the order left to the operator.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_monitoring as monitoring  # noqa: E402


MEASURED = {
    "range": "24h", "since": 100, "until": 200,
    "servers": [
        {"proxy": "be_quiet", "server": "srv1",
         "bytes_in": 10, "bytes_out": 90, "sessions": 2},
        # Two servers of one backend are one backend.
        {"proxy": "be_busy", "server": "main",
         "bytes_in": 1000, "bytes_out": 5000, "sessions": 40},
        {"proxy": "be_busy", "server": "bkp",
         "bytes_in": 100, "bytes_out": 300, "sessions": 3},
        # The machine's own interface is one of the answers here.
        {"proxy": "be_admin", "server": "ui",
         "bytes_in": 500, "bytes_out": 3000, "sessions": 7},
        {"proxy": "be_idle", "server": "srv1",
         "bytes_in": 0, "bytes_out": 0, "sessions": 0},
        {"proxy": "", "server": "orphan", "bytes_in": 5, "bytes_out": 5},
    ],
}


class TrafficPerBackend(unittest.TestCase):
    def traffic(self, payload=None, window=None):
        with mock.patch.object(
            monitoring, "metricsd_servers",
            return_value=MEASURED if payload is None else payload,
        ) as asked, mock.patch.object(
            monitoring, "display_name", side_effect=lambda proxy: proxy[3:]
        ):
            result = monitoring.backend_traffic("24h", window)
        self.asked = asked
        return result

    def test_the_busiest_backend_comes_first(self):
        result = self.traffic()
        self.assertEqual(
            [entry["label"] for entry in result["backends"]],
            ["busy", "admin", "quiet", "idle"],
        )

    def test_a_backend_is_the_sum_of_its_servers(self):
        busy = self.traffic()["backends"][0]
        self.assertEqual(busy["bytes_in"], 1100)
        self.assertEqual(busy["bytes_out"], 5300)
        self.assertEqual(busy["bytes_total"], 6400)
        self.assertEqual(busy["sessions"], 43)

    def test_shares_are_of_the_total_shown(self):
        result = self.traffic()
        self.assertEqual(result["bytes_total"], 10000)
        shares = {e["label"]: e["share"] for e in result["backends"]}
        self.assertEqual(shares, {"busy": 64.0, "admin": 35.0, "quiet": 1.0, "idle": 0.0})

    def test_no_traffic_at_all_is_not_a_division(self):
        result = self.traffic({"servers": [
            {"proxy": "be_idle", "server": "srv1", "bytes_in": 0, "bytes_out": 0},
        ]})
        self.assertEqual(result["backends"][0]["share"], 0.0)
        self.assertEqual(self.traffic({"servers": []})["backends"], [])

    def test_the_chosen_period_reaches_the_collector(self):
        window = {"since": 1000, "until": 2000}
        self.traffic(window=window)
        self.asked.assert_called_once_with("24h", window)


class ThePageOffersBothViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (APP_DIR / "static/js/monitoring.js").read_text(encoding="utf-8")
        cls.page = (APP_DIR / "templates/monitoring.html").read_text(encoding="utf-8")
        cls.routes = (APP_DIR / "routes_monitoring.py").read_text(encoding="utf-8")

    def test_there_is_a_route_and_it_only_reads(self):
        self.assertIn('@bp.get("/api/monitoring/backends")', self.routes)
        self.assertIn("monitoring.backend_traffic(range_key, _window())", self.routes)

    def test_the_card_has_a_switch_and_a_sort_order(self):
        for value in ('data-view="availability"', 'data-view="traffic"'):
            self.assertIn(value, self.page)
        for value in ("desc", "asc", "name"):
            self.assertIn(f'<option value="{value}">', self.page)
        self.assertIn('id="mon-backend-traffic" hidden', self.page)

    def test_traffic_is_only_fetched_when_it_is_shown(self):
        load = self.script.split("async function loadAll(")[1].split("\n  }\n")[0]
        self.assertIn('if (backendsView === "traffic") await loadBackendTraffic();', load)
        # After the timeline, so the note beside the heading is the right one.
        self.assertLess(
            load.index("renderTimeline(timeline)"), load.index("loadBackendTraffic()")
        )

    def test_it_follows_the_chosen_period(self):
        load = self.script.split("async function loadBackendTraffic(")[1].split("\n  }\n")[0]
        self.assertIn('"/api/monitoring/backends"', load)
        self.assertIn("windowParams()", load)

    def test_sorting_does_not_ask_the_server_again(self):
        bind = self.script.split("function bindBackendsView(")[1].split("\n  }\n")[0]
        change = bind.split('addEventListener("change"')[1].split("});")[0]
        self.assertIn("renderBackendTraffic();", change)
        self.assertNotIn("getJson", change)
        self.assertNotIn("loadAll", change)

    def test_the_choice_is_remembered_and_never_trusted(self):
        self.assertIn(
            'remembered("mon-backends-view", BACKEND_VIEWS, "availability")', self.script
        )
        self.assertIn('remembered("mon-backends-sort", BACKEND_SORTS, "desc")', self.script)
        remembered = self.script.split("function remembered(")[1].split("\n  }\n")[0]
        self.assertIn("allowed.includes(value) ? value : fallback", remembered)
        self.assertIn("catch (error)", remembered)

    def test_bars_are_measured_against_the_busiest_backend(self):
        render = self.script.split("function renderBackendTraffic(")[1].split("\n  }\n")[0]
        self.assertIn("/ busiest) * 100", render)
        # Names come from the configuration: written as text, not as markup.
        self.assertNotIn("innerHTML", render)

    def test_the_new_words_are_in_russian(self):
        catalogue = json.loads(
            (APP_DIR / "translations/ru/monitoring.json").read_text(encoding="utf-8")
        )["messages"]
        for phrase in (
            "Backend traffic", "Availability", "Sort", "Most traffic first",
            "Least traffic first", "By name", "Inbound", "Outbound",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, catalogue)


if __name__ == "__main__":
    unittest.main()
