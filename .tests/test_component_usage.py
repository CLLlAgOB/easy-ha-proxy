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


UPDATE_JOB = "easy-ha-proxy-updated-job-0123456789ab"
BACKUP_JOB = "easy-ha-proxy-backupd-job-abcdef012345"


class JobsCountUnderTheirService(Fixture):
    """A unit started for one job is part of the service that started it.

    Every update check runs in a transient unit with a name of its own. Counted
    under that name, a day of checks on a test gateway left 98 components:
    the processor chart's answer grew to 780 KB and took nearly three seconds,
    and the page waited for it.
    """

    def test_a_job_unit_is_named_after_its_service(self):
        for unit, service in (
            (UPDATE_JOB, "easy-ha-proxy-updated"),
            (BACKUP_JOB, "easy-ha-proxy-backupd"),
            ("easy-ha-proxy-web-reboot-0123456789ab", "easy-ha-proxy-web-reboot"),
            ("easy-ha-proxy-reboot-20261027131500-4242-0a1b2c3d", "easy-ha-proxy-reboot"),
        ):
            self.assertEqual(metricsd.component_name(unit), service, unit)
        for name in ("haproxy", "haproxy-controld", "authelia-usersd",
                     "easy-ha-proxy-updated", "easy-ha-proxy-job-runner", "netdata"):
            self.assertEqual(metricsd.component_name(name), name)

    def test_the_collector_finds_no_job_by_its_own_name(self):
        self.tree()
        cgroup(self.system / "easy-ha-proxy-updated.service", usage=1, current=1024)
        cgroup(self.system / f"{UPDATE_JOB}.service", usage=1, current=1024)
        cgroup(self.system / f"{BACKUP_JOB}.service", usage=1, current=1024)
        names = [name for name, _, _ in self.collector._component_cgroups()]
        self.assertEqual(names.count("easy-ha-proxy-updated"), 2)
        self.assertIn("easy-ha-proxy-backupd", names)
        self.assertFalse([name for name in names if "-job-" in name])

    def test_a_service_and_its_running_job_are_added_up(self):
        updated = self.system / "easy-ha-proxy-updated.service"
        job = self.system / f"{UPDATE_JOB}.service"

        def poll(moment, broker, worker):
            cgroup(updated, usage=broker, current=20 * 1024 * 1024)
            cgroup(job, usage=worker, current=100 * 1024 * 1024)
            with mock.patch.object(metricsd.os, "cpu_count", return_value=2), \
                    mock.patch.object(metricsd.time, "monotonic", return_value=moment):
                self.collector._observe_components(60)

        poll(100.0, broker=1_000_000, worker=0)
        # One second later: the broker used 0.1 s, the job 0.9 s, on two CPUs.
        poll(101.0, broker=1_100_000, worker=900_000)
        key = (metricsd.COMPONENT_KIND, "easy-ha-proxy-updated", "service")
        bucket = self.collector._buckets[self.collector._object_ids[key]]
        self.assertEqual(bucket.gauge_maxima["cpu"], 500)
        self.assertEqual(bucket.gauge_maxima["memory"], 120 * 1024)
        self.assertNotIn(
            (metricsd.COMPONENT_KIND, UPDATE_JOB, "service"), self.collector._object_ids
        )

    def test_a_job_that_just_started_does_not_hide_its_service(self):
        updated = self.system / "easy-ha-proxy-updated.service"
        cgroup(updated, usage=1_000_000, current=1024)
        with mock.patch.object(metricsd.os, "cpu_count", return_value=1), \
                mock.patch.object(metricsd.time, "monotonic", return_value=100.0):
            self.collector._observe_components(60)
        cgroup(updated, usage=1_200_000, current=1024)
        # First seen now: no reading of its own yet, the service's still counts.
        cgroup(self.system / f"{UPDATE_JOB}.service", usage=5_000_000, current=1024)
        with mock.patch.object(metricsd.os, "cpu_count", return_value=1), \
                mock.patch.object(metricsd.time, "monotonic", return_value=101.0):
            self.collector._observe_components(60)
        key = (metricsd.COMPONENT_KIND, "easy-ha-proxy-updated", "service")
        bucket = self.collector._buckets[self.collector._object_ids[key]]
        self.assertEqual(bucket.gauge_maxima["cpu"], 200)

    def test_a_finished_job_is_forgotten(self):
        job = self.system / f"{UPDATE_JOB}.service"
        cgroup(job, usage=1, current=1024)
        self.collector._observe_components(60)
        self.assertIn(str(job), self.collector._component_previous)
        import shutil
        shutil.rmtree(job)
        self.collector._observe_components(120)
        self.assertNotIn(str(job), self.collector._component_previous)


class JobsRecordedBeforeAreFolded(unittest.TestCase):
    """Rows written under a job's own name read as part of its service."""

    setUp = TheCharts.setUp
    row = TheCharts.row

    def test_eighty_checks_are_one_line(self):
        self.row("host", "", "", cpu_avg=500)
        self.row("component", "easy-ha-proxy-updated", "service", cpu_avg=10, cpu_max=20)
        for index in range(80):
            self.row(
                "component", f"easy-ha-proxy-updated-job-{index:012x}", "service",
                cpu_avg=1, cpu_max=30 + index,
            )
        payload = self.database.series(chart="cpu", site="", since=0, until=7200)
        names = [entry["name"] for entry in payload["components"]]
        self.assertEqual(names, ["easy-ha-proxy-updated"])
        updated = payload["components"][0]
        self.assertEqual(updated["values"], [9.0])
        # The highest any of them reached, never below the line itself.
        self.assertEqual(updated["peak"], 10.9)
        # Helpers and "other" are the same with or without the fold.
        self.assertEqual(payload["series"]["helpers"], [9.0])
        self.assertEqual(payload["series"]["other"], [41.0])

    def test_a_day_read_row_by_row_agrees_with_months_read_grouped(self):
        # A day is read one stored row per slot; ninety days group hours by
        # two. The same data must come out the same either way.
        self.row("host", "", "", cpu_avg=500, cpu_max=700)
        self.row("component", "haproxy", "service", cpu_avg=200, cpu_max=300)
        self.row("component", "easy-ha-proxy-updated", "service", cpu_avg=10, cpu_max=20)
        self.row("component", UPDATE_JOB, "service", cpu_avg=30, cpu_max=90)
        self.database.rollup_hours(7200)
        day = self.database.series(chart="cpu", site="", since=0, until=7200)
        months = self.database.series(chart="cpu", site="", since=0, until=90 * 86400)
        self.assertEqual(months["resolution_seconds"], 7200)

        def lines(payload):
            return {entry["name"]: (entry["values"], entry["peak"]) for entry in payload["components"]}

        self.assertEqual(lines(day), lines(months))
        self.assertEqual(lines(day)["easy-ha-proxy-updated"], ([4.0], 9.0))
        self.assertEqual(day["series"]["helpers"], months["series"]["helpers"])

    def test_a_folded_line_is_never_below_its_busiest_slot(self):
        self.row("host", "", "", bucket=3600, cpu_avg=500)
        self.row("host", "", "", bucket=3660, cpu_avg=500)
        self.row("component", "easy-ha-proxy-updated", "service", bucket=3600, cpu_avg=5, cpu_max=6)
        # Neither peak reached 4.5%, the two together did.
        self.row("component", UPDATE_JOB, "service", bucket=3600, cpu_avg=40, cpu_max=30)
        self.row("component", BACKUP_JOB, "service", bucket=3660, cpu_avg=70, cpu_max=90)
        payload = self.database.series(chart="cpu", site="", since=0, until=7200)
        lines = {entry["name"]: entry for entry in payload["components"]}
        self.assertEqual(sorted(lines), ["easy-ha-proxy-backupd", "easy-ha-proxy-updated"])
        self.assertEqual(lines["easy-ha-proxy-updated"]["values"], [4.5, 0.0])
        self.assertEqual(lines["easy-ha-proxy-updated"]["peak"], 4.5)
        self.assertEqual(lines["easy-ha-proxy-backupd"]["values"], [0.0, 7.0])
        self.assertEqual(lines["easy-ha-proxy-backupd"]["peak"], 9.0)


class ThePartsAreSentOnlyWhenShown(unittest.TestCase):
    """Without the line per component, the chart keeps its group totals.

    The processor and memory charts' answer was mostly one line per
    component -- a day of minutes for each of 26 on the test gateway, 447 KiB
    and most of a second. The page now asks for them only when their list
    is open; the totals it draws by default must not change for that.
    """

    setUp = TheCharts.setUp
    row = TheCharts.row

    def seed(self):
        for bucket in (3600, 3660, 3720):
            self.row("host", "", "", bucket=bucket, cpu_avg=500, cpu_max=700,
                     memory_avg=1_000_000, memory_max=1_200_000, memory_total=2_000_000)
            self.row("component", "haproxy", "service", bucket=bucket, cpu_avg=200, memory_avg=40_000)
            self.row("component", "haproxy-controld", "service", bucket=bucket, cpu_avg=30, memory_avg=20_000)
            self.row("component", "haproxy-admin", "container", bucket=bucket, cpu_avg=100, memory_avg=90_000)
            self.row("component", "dockerd", "engine", bucket=bucket, cpu_avg=10, memory_avg=60_000)
        # A job folds into its service in both paths, and a part may be
        # missing from a slot.
        self.row("component", UPDATE_JOB, "service", bucket=3660, cpu_avg=40, memory_avg=7_000)
        # A slot whose row was written but holds no samples counts nothing.
        object_id = self.database.object_id("component", "easy-ha-proxy-guardd", "service", 3720)
        empty = {column: 0 for column in metricsd.METRIC_COLUMNS}
        empty.update(samples=0, cpu_avg=999, memory_avg=999_999)
        self.database.write_buckets(3720, {object_id: empty})

    def test_the_totals_are_the_same_without_the_parts(self):
        self.seed()
        self.database.rollup_hours(2 * 3600)
        for chart in ("cpu", "memory"):
            for until in (7200, 7 * 86400, 90 * 86400):
                with self.subTest(chart=chart, until=until):
                    full = self.database.series(chart=chart, site="", since=0, until=until)
                    light = self.database.series(chart=chart, site="", since=0, until=until,
                                                 components=False)
                    self.assertTrue(full["components"])
                    self.assertNotIn("components", light)
                    self.assertEqual(light["points"], full["points"])
                    self.assertEqual(light["series"], full["series"])

    def test_the_haproxy_line_is_not_a_helper_in_either(self):
        self.seed()
        light = self.database.series(chart="cpu", site="", since=0, until=7200, components=False)
        # controld 3.0 everywhere, plus the update job's 4.0 folded in at 3660.
        self.assertEqual(light["series"]["helpers"], [3.0, 7.0, 3.0])
        self.assertEqual(light["series"]["containers"], [10.0, 10.0, 10.0])

    def test_the_daemon_reads_the_flag(self):
        source = (ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py").read_text(encoding="utf-8")
        self.assertIn('wanted = (query.get("components", ["1"])[0] or "1").strip().lower()', source)
        self.assertIn('components=wanted not in ("0", "false", "no")', source)


class ASlowAnswerDoesNotHoldEveryPage(unittest.TestCase):
    def test_the_panel_serves_with_threads(self):
        # Two single-threaded workers: the processor and memory charts took
        # both, and any other page in any tab waited for them.
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        command = json.loads(dockerfile.split("CMD ", 1)[1].splitlines()[0])
        self.assertEqual(command[0], "gunicorn")
        threads = int(command[command.index("--threads") + 1])
        workers = int(command[command.index("--workers") + 1])
        self.assertGreaterEqual(workers * threads, 8)


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
