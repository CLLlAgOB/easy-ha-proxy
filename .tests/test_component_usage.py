"""Who uses the machine: CPU and memory per part of the gateway.

The processor chart used to say how busy the machine was and how busy
HAProxy's event loop was, and nothing about the dozen helper services and
containers sharing two cores with it. metricsd now reads each one's cgroup --
CPU time and memory, the way `docker stats` counts it -- and the monitoring
page draws the helpers' total, the containers' total and, unfolded, each part
on its own, beside a memory chart that does the same. Any chart opens in full
screen.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "app" / "haproxy_admin"
sys.path.insert(0, str(ROOT / "docker" / "app"))


def load_metricsd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_metricsd_components", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


metricsd = load_metricsd()

PANEL_ID = "a" * 64
AUTH_ID = "b" * 64


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def cgroup(directory: Path, *, usage: int, current: int, inactive: int = 0) -> None:
    write(directory / "cpu.stat", f"usage_usec {usage}\nuser_usec 1\nsystem_usec 1\n")
    write(directory / "memory.current", f"{current}\n")
    write(directory / "memory.stat", f"anon 1\nfile 2\ninactive_file {inactive}\nactive_file 3\n")


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = metricsd.MetricsDatabase(str(self.root / "metrics.db"))
        self.addCleanup(self.database.close)
        self.collector = metricsd.Collector(
            metricsd.load_config("/nonexistent/metricsd.json"), self.database
        )
        self.collector.cgroup_root = str(self.root / "cgroup")
        self.collector.containers_dir = str(self.root / "containers")
        self.system = self.root / "cgroup" / "system.slice"

    def tree(self, usage=1_000_000):
        cgroup(self.system / "haproxy.service", usage=usage, current=40 * 1024 * 1024)
        cgroup(self.system / "haproxy-controld.service", usage=usage, current=20 * 1024 * 1024)
        cgroup(
            self.system / "easy-ha-proxy-guardd.service", usage=usage,
            current=300 * 1024 * 1024, inactive=270 * 1024 * 1024,
        )
        cgroup(self.system / "authelia-usersd.service", usage=usage, current=10 * 1024 * 1024)
        cgroup(self.system / "docker.service", usage=usage, current=60 * 1024 * 1024)
        cgroup(self.system / "sshd.service", usage=usage, current=5 * 1024 * 1024)
        cgroup(self.system / "cron.service", usage=usage, current=5 * 1024 * 1024)
        cgroup(self.system / f"docker-{PANEL_ID}.scope", usage=usage, current=90 * 1024 * 1024)
        cgroup(self.root / "cgroup" / "docker" / AUTH_ID, usage=usage, current=30 * 1024 * 1024)
        write(
            self.root / "containers" / PANEL_ID / "config.v2.json",
            json.dumps({"Name": "/haproxy-admin", "Config": {}}),
        )
        write(
            self.root / "containers" / AUTH_ID / "config.v2.json",
            json.dumps({"Name": "/authelia"}),
        )


class FindingTheParts(Fixture):
    def test_our_units_containers_and_the_engine_are_found_and_nothing_else(self):
        self.tree()
        found = {(name, group) for name, group, _ in self.collector._component_cgroups()}
        self.assertEqual(found, {
            ("haproxy", "service"),
            ("haproxy-controld", "service"),
            ("easy-ha-proxy-guardd", "service"),
            ("authelia-usersd", "service"),
            ("dockerd", "engine"),
            ("haproxy-admin", "container"),
            ("authelia", "container"),
        })

    def test_a_container_without_a_readable_record_keeps_its_short_id(self):
        self.tree()
        (self.root / "containers" / AUTH_ID / "config.v2.json").write_text("{broken")
        names = {name for name, group, _ in self.collector._component_cgroups()
                 if group == "container"}
        self.assertIn(AUTH_ID[:12], names)

    def test_a_strange_container_name_is_not_trusted(self):
        self.tree()
        write(
            self.root / "containers" / PANEL_ID / "config.v2.json",
            json.dumps({"Name": "/<script>"}),
        )
        names = {name for name, group, _ in self.collector._component_cgroups()
                 if group == "container"}
        self.assertIn(PANEL_ID[:12], names)

    def test_a_container_that_is_gone_is_forgotten(self):
        self.tree()
        self.collector._component_cgroups()
        self.assertIn(PANEL_ID, self.collector._container_names)
        import shutil
        shutil.rmtree(self.system / f"docker-{PANEL_ID}.scope")
        self.collector._component_cgroups()
        self.assertNotIn(PANEL_ID, self.collector._container_names)

    def test_no_cgroup_tree_means_no_parts_not_an_error(self):
        self.assertEqual(self.collector._component_cgroups(), [])


class ReadingOnePart(Fixture):
    def test_memory_leaves_out_the_cache_it_could_drop(self):
        self.tree()
        usage, memory = self.collector._read_cgroup(
            str(self.system / "easy-ha-proxy-guardd.service")
        )
        self.assertEqual(usage, 1_000_000)
        self.assertEqual(memory, 30 * 1024)  # KiB

    def test_cpu_is_a_share_of_the_whole_machine(self):
        self.tree(usage=1_000_000)
        with mock.patch.object(metricsd.os, "cpu_count", return_value=2), \
                mock.patch.object(metricsd.time, "monotonic", return_value=100.0):
            self.collector._observe_components(60)
        # Half a second of CPU over one second on two processors: 25%.
        self.tree(usage=1_500_000)
        with mock.patch.object(metricsd.os, "cpu_count", return_value=2), \
                mock.patch.object(metricsd.time, "monotonic", return_value=101.0):
            self.collector._observe_components(60)
        key = (metricsd.COMPONENT_KIND, "haproxy", "service")
        bucket = self.collector._buckets[self.collector._object_ids[key]]
        self.assertEqual(bucket.gauge_maxima["cpu"], 250)
        self.assertEqual(bucket.samples, 2)

    def test_a_restarted_unit_gives_no_cpu_reading_rather_than_a_negative_one(self):
        self.tree(usage=5_000_000)
        with mock.patch.object(metricsd.time, "monotonic", return_value=100.0):
            self.collector._observe_components(60)
        self.tree(usage=1_000)
        with mock.patch.object(metricsd.time, "monotonic", return_value=110.0):
            self.collector._observe_components(60)
        key = (metricsd.COMPONENT_KIND, "haproxy", "service")
        bucket = self.collector._buckets[self.collector._object_ids[key]]
        self.assertNotIn("cpu", bucket.gauge_maxima)
        self.assertIn("memory", bucket.gauge_maxima)

    def test_the_machines_memory_is_total_minus_available(self):
        meminfo = "MemTotal: 2000000 kB\nMemFree: 100000 kB\nMemAvailable: 1500000 kB\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=meminfo)):
            self.assertEqual(self.collector._read_host_memory(), (500000, 2000000))

    def test_an_unreadable_meminfo_costs_only_the_memory_reading(self):
        with mock.patch("builtins.open", side_effect=OSError("gone")):
            self.assertIsNone(self.collector._read_host_memory())

    def test_a_broken_component_read_never_costs_the_poll(self):
        with mock.patch.object(
            self.collector, "_observe_components", side_effect=RuntimeError("boom")
        ), mock.patch.object(self.collector, "_read_haproxy_busy", return_value=100):
            self.collector._observe_host(60)
        host = self.collector._object_ids[(metricsd.HOST_KIND, "", "")]
        self.assertEqual(self.collector._buckets[host].samples, 1)


class TheCharts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = metricsd.MetricsDatabase(str(Path(temporary.name) / "metrics.db"))
        self.addCleanup(self.database.close)

    def row(self, kind, proxy, server, bucket=3600, **values):
        object_id = self.database.object_id(kind, proxy, server, bucket)
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row.update(samples=1, **values)
        self.database.write_buckets(bucket, {object_id: row})

    def seed(self):
        self.row("host", "", "", cpu_avg=500, cpu_max=700,
                 memory_avg=1_000_000, memory_max=1_200_000, memory_total=2_000_000)
        self.row("component", "haproxy", "service", cpu_avg=200, cpu_max=300, memory_avg=40_000)
        self.row("component", "haproxy-controld", "service", cpu_avg=30, cpu_max=90, memory_avg=20_000)
        self.row("component", "easy-ha-proxy-guardd", "service", cpu_avg=20, cpu_max=40, memory_avg=30_000)
        self.row("component", "haproxy-admin", "container", cpu_avg=100, cpu_max=400, memory_avg=90_000)
        self.row("component", "dockerd", "engine", cpu_avg=10, cpu_max=10, memory_avg=60_000)

    def test_the_processor_chart_carries_the_helpers_and_each_part(self):
        self.seed()
        payload = self.database.series(chart="cpu", site="", since=0, until=7200)
        self.assertEqual(payload["series"]["cpu_avg"], [50.0])
        # HAProxy is not a helper; it has a line of its own.
        self.assertEqual(payload["series"]["helpers"], [5.0])
        self.assertEqual(payload["series"]["containers"], [10.0])
        self.assertEqual(payload["series"]["other"], [14.0])
        names = [entry["name"] for entry in payload["components"]]
        self.assertEqual(names[0], "haproxy")
        self.assertEqual(names[1], "haproxy-admin")
        admin = payload["components"][1]
        self.assertEqual(admin["values"], [10.0])
        self.assertEqual(admin["peak"], 40.0)
        self.assertEqual(admin["group"], "container")

    def test_the_memory_chart_is_in_bytes(self):
        self.seed()
        payload = self.database.series(chart="memory", site="", since=0, until=7200)
        self.assertEqual(payload["series"]["memory_avg"], [1_000_000 * 1024])
        self.assertEqual(payload["series"]["memory_total"], [2_000_000 * 1024])
        self.assertEqual(payload["series"]["helpers"], [50_000 * 1024])
        self.assertEqual(payload["series"]["other"], [(1_000_000 - 240_000) * 1024])
        self.assertEqual(payload["components"][0]["name"], "haproxy-admin")

    def test_a_part_missing_from_a_slot_reads_zero_there(self):
        self.row("host", "", "", bucket=3600, cpu_avg=100)
        self.row("host", "", "", bucket=3660, cpu_avg=100)
        self.row("component", "haproxy", "service", bucket=3660, cpu_avg=50)
        payload = self.database.series(chart="cpu", site="", since=0, until=7200)
        self.assertEqual(payload["components"][0]["values"], [0.0, 5.0])

    def test_the_overview_reports_memory(self):
        self.seed()
        load = self.database.host_load(since=0, until=7200)
        self.assertEqual(load["memory_avg"], 1_000_000 * 1024)
        self.assertEqual(load["memory_total"], 2_000_000 * 1024)
        self.assertEqual(load["cpu_avg"], 50.0)

    def test_the_parts_never_leak_into_traffic(self):
        self.seed()
        self.row("frontend", "fe_https", "", requests=500)
        self.assertEqual(self.database.totals(site="", since=0, until=7200)["requests"], 500)
        self.assertEqual(self.database.sites(), [])
        health = self.database.backend_health()
        self.assertEqual((health["backends"], health["servers"]), ([], []))
        traffic = self.database.series(chart="requests", site="", since=0, until=7200)
        self.assertNotIn("components", traffic)
        self.assertEqual(traffic["series"]["requests"], [500])

    def test_the_parts_survive_the_hourly_rollup(self):
        self.seed()
        self.database.rollup_hours(7200)
        connection = sqlite3.connect(str(self.database.path))
        try:
            row = connection.execute(
                "SELECT m.memory_avg, m.cpu_max FROM metric_1h m JOIN objects o "
                "ON o.id = m.object_id WHERE o.kind = 'component' AND o.proxy = 'haproxy-admin'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row, (90_000, 400))

    def test_every_stored_column_says_how_it_aggregates(self):
        missing = [
            column for column in metricsd.METRIC_COLUMNS
            if column != "samples" and column not in metricsd._AGGREGATIONS
        ]
        self.assertEqual(missing, [])


class TheCollectorMaySeeThem(unittest.TestCase):
    def test_the_sandbox_leaves_the_cgroup_tree_and_docker_records_readable(self):
        unit = (
            ROOT / "ansible/roles/haproxy-admin/templates/easy-ha-proxy-metricsd.service.j2"
        ).read_text(encoding="utf-8")
        # Read-only is enough; hiding either would leave the charts empty.
        self.assertNotIn("InaccessiblePaths", unit)
        self.assertNotIn("ProtectControlGroups=private", unit)
        self.assertIn("User=root", unit)


class ThePanel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (APP_DIR / "static/js/monitoring.js").read_text(encoding="utf-8")
        cls.page = (APP_DIR / "templates/monitoring.html").read_text(encoding="utf-8")
        cls.catalog = json.loads(
            (APP_DIR / "translations/ru/monitoring.json").read_text(encoding="utf-8")
        )["messages"]

    def section(self, name):
        return self.script.split(f"function {name}(")[1].split("\n  function ")[0]

    def test_the_service_layer_offers_the_memory_chart(self):
        source = (APP_DIR / "services_monitoring.py").read_text(encoding="utf-8")
        charts = re.search(r"CHARTS: Tuple\[str, \.\.\.\] = \((.*?)\)", source, re.S).group(1)
        self.assertIn('"memory"', charts)
        self.assertIn("memory", metricsd.CHART_SERIES)

    def test_helper_names_lose_the_prefix_everyone_shares(self):
        from haproxy_admin import services_monitoring

        label = services_monitoring.component_label
        self.assertEqual(label("easy-ha-proxy-guardd", "service"), "guardd")
        self.assertEqual(label("haproxy-controld", "service"), "controld")
        self.assertEqual(label("haproxy", "service"), "haproxy")
        self.assertEqual(label("authelia-usersd", "service"), "authelia-usersd")
        # A container is called what its owner called it.
        self.assertEqual(label("haproxy-admin", "container"), "haproxy-admin")

    def test_processor_and_memory_charts_have_group_lines_and_parts(self):
        charts = self.script.split("const CHARTS = [")[1].split("\n  ];")[0]
        for key in ('key: "helpers"', 'key: "containers"', 'key: "other"', 'key: "memory_total"'):
            self.assertIn(key, charts)
        self.assertEqual(charts.count("components: true"), 2)
        # Which lines a part adds, and how they are coloured, is tested by
        # behaviour in .tests/js/monitoring_core.test.js; here, that the
        # chart and its legend both take their lines from there.
        self.assertIn("core.chartData(chart, payload", self.section("drawChart"))
        self.assertIn("core.seriesFor(chart, payload)", self.section("renderLegend"))

    def test_a_line_can_be_hidden_and_the_choice_is_kept(self):
        legend = self.section("renderLegend")
        self.assertIn('item.type = "button"', legend)
        self.assertIn("setLineVisible(chart, spec, !lineVisible(chart, spec))", legend)
        self.assertIn("redrawChart(chart.name)", legend)
        self.assertIn("window.localStorage.setItem(VISIBILITY_KEY", self.section("setLineVisible"))
        # Hidden lines leave the scale, so the small ones can fill it (see
        # chartData in .tests/js/monitoring_core.test.js).
        self.assertIn(
            "core.chartData(chart, payload, (spec) => lineVisible(chart, spec))",
            self.section("drawChart"),
        )

    def test_part_names_are_machine_data(self):
        legend = self.section("renderLegend")
        self.assertIn("if (spec.component) {", legend)
        self.assertIn('label.setAttribute("data-i18n-skip", "")', legend)

    def test_every_chart_opens_in_full_screen(self):
        cards = re.findall(r'<div class="mon-chart" data-chart="([a-z]+)">', self.page)
        self.assertEqual(
            sorted(cards),
            sorted(["requests", "traffic", "responses", "latency", "connections", "cpu", "memory"]),
        )
        self.assertEqual(self.page.count("{{ expand_button() }}"), len(cards))
        self.assertIn('id="mon-overlay" hidden', self.page)
        expand = self.section("setExpanded")
        self.assertIn("overlay.appendChild(card)", expand)
        self.assertIn("replaceChild(card, expandedPlaceholder)", expand)
        bind = self.section("bindFullScreen")
        self.assertIn('event.key === "Escape"', bind)
        self.assertIn('"resize"', bind)
        self.assertIn("#chart=", bind)
        # Drawn at the size shown, not stretched from the card's frame.
        self.assertIn('svg.closest(".mon-chart-expanded")', self.section("drawChart"))

    def test_the_memory_card_and_chart_are_on_the_page(self):
        self.assertIn('id="mon-card-memory" hidden', self.page)
        self.assertIn('id="mon-plot-memory"', self.page)
        self.assertIn('id="mon-legend-memory"', self.page)
        for element_id in ("mon-memory", "mon-memory-detail"):
            tag = re.search(rf'<[^>]+id="{element_id}"[^>]*>', self.page).group(0)
            self.assertIn("data-i18n-skip", tag)

    def test_the_new_words_are_in_russian(self):
        for phrase, russian in (
            ("Memory", "Память"),
            ("Helper services", "Хелперы"),
            ("Containers", "Контейнеры"),
            ("Other processes", "Прочие процессы"),
            ("By component", "По компонентам"),
            ("Full screen", "На весь экран"),
            ("Exit full screen", "Свернуть"),
        ):
            self.assertEqual(self.catalog[phrase], russian)


if __name__ == "__main__":
    unittest.main()
