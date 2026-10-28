"""The page's side of disk, network and temperature: a card per chart, a
switch per monitor, the daemon and the page naming the same charts, and no
temperature chart on a machine without a sensor."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))

from haproxy_admin import services_monitoring as monitoring  # noqa: E402


def daemon():
    spec = importlib.util.spec_from_file_location(
        "metricsd_host_charts", ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ThePage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (APP / "templates/monitoring.html").read_text(encoding="utf-8")
        cls.script = (APP / "static/js/monitoring.js").read_text(encoding="utf-8")
        cls.daemon = daemon()

    def test_the_panel_and_the_daemon_name_the_same_charts(self):
        self.assertEqual(set(monitoring.CHARTS), set(self.daemon.CHART_SERIES))

    def test_every_chart_has_a_card_a_plot_and_a_monitor(self):
        mapping = self.script.split("const CHART_MONITORS = {")[1].split("};")[0]
        for chart in monitoring.CHARTS:
            with self.subTest(chart=chart):
                self.assertIn(f'data-chart="{chart}"', self.template)
                self.assertIn(f'id="mon-plot-{chart}"', self.template)
                self.assertRegex(mapping, rf"\b{chart}: \"")

    def test_every_series_the_daemon_sends_is_drawn(self):
        for chart in ("disk", "diskio", "network", "temperature"):
            for column in self.daemon.CHART_SERIES[chart]:
                self.assertIn(f'key: "{column}"', self.script, (chart, column))

    def test_no_sensor_no_temperature_chart(self):
        chart_on = self.script.split("function chartOn(")[1].split("\n  }\n")[0]
        self.assertIn('name === "temperature" && sensors && sensors.temperature === false', chart_on)
        apply = self.script.split("function applyMonitors(")[1].split("\n  }\n")[0]
        self.assertIn('input.dataset.monitor === "temperature" && noSensor', apply)
        self.assertIn('id="mon-temperature-note" hidden', self.template)

    def test_degrees_are_written_as_degrees(self):
        for function in ("axisLabel", "legendValue"):
            body = self.script.split(f"function {function}(")[1].split("\n  }\n")[0]
            self.assertIn("if (spec.unit) return", body)
        self.assertIn('unit: "°C"', self.script)

    def test_every_word_is_in_russian(self):
        catalog = {}
        for path in (APP / "translations").rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("meta", {}).get("code") == "ru":
                catalog.update(data["messages"])
        section = self.template.split('data-chart="disk"')[1].split("</div>\n</div>")[0]
        words = {text.strip() for text in re.findall(r"<h3>([^<]+)</h3>", section)}
        words |= {"Root filesystem", "Read and written per second",
                  "Network cards of the machine, per second", "Warmest sensor of the machine",
                  "Read", "Written", "Received", "Sent", "Disk: space and activity",
                  "Network cards of the machine", "No sensor on this machine", "Temperature"}
        self.assertEqual(sorted(word for word in words if word not in catalog), [])


if __name__ == "__main__":
    unittest.main()
