"""The machine beyond processor and memory: disk, network, temperature.

Read by the collector beside HAProxy's counters, each behind a switch of its
own, and stored on the machine's row. A virtual machine has no temperature
sensor: the summary says so, and nothing is drawn as 0 degrees.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"


def load():
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_metricsd_host", DAEMON)
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


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class AFakeMachine(unittest.TestCase):
    """A /sys and /proc of its own, with one of everything worth ignoring."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.block = self.root / "sys/block"
        self.net = self.root / "sys/class/net"
        self.thermal = self.root / "sys/class/thermal"
        self.diskstats = self.root / "proc/diskstats"
        # A disk, and views of disks that must not be counted again.
        (self.block / "mmcblk0" / "device").mkdir(parents=True)
        (self.block / "loop0").mkdir(parents=True)
        (self.block / "dm-0").mkdir(parents=True)
        self.set_disk(read_sectors=100, written_sectors=40)
        # A card, and interfaces that carry what the card already counted.
        self.set_card("eth0", 1000, 500, device=True)
        self.set_card("docker0", 99999, 99999, device=False)
        self.set_card("lo", 77777, 77777, device=False)
        self.set_card("veth1a2b", 55555, 55555, device=False)
        self.set_zone("thermal_zone0", "47250")
        self.set_zone("thermal_zone1", "52900")

    def set_disk(self, read_sectors, written_sectors, partition_read=999):
        write(self.diskstats, "\n".join((
            f" 179 0 mmcblk0 10 0 {read_sectors} 5 20 0 {written_sectors} 9 0 0 0",
            f" 179 1 mmcblk0p1 10 0 {partition_read} 5 20 0 {partition_read} 9 0 0 0",
            "   7 0 loop0 1 0 888 0 0 0 888 0 0 0 0",
            " 253 0 dm-0 1 0 777 0 0 0 777 0 0 0 0",
            "",
        )))

    def set_card(self, name, received, sent, device=True):
        base = self.net / name
        write(base / "statistics/rx_bytes", f"{received}\n")
        write(base / "statistics/tx_bytes", f"{sent}\n")
        if device:
            (base / "device").mkdir(exist_ok=True)

    def set_zone(self, name, value):
        write(self.thermal / name / "temp", f"{value}\n")


class Readers(AFakeMachine):
    def test_disks_are_counted_once(self):
        counters = metricsd.read_disk_counters(str(self.diskstats), str(self.block))
        self.assertEqual(counters, {"mmcblk0": (100 * 512, 40 * 512)})

    def test_only_cards_are_counted(self):
        self.assertEqual(metricsd.read_network_counters(str(self.net)), {"eth0": (1000, 500)})

    def test_the_warmest_zone_in_tenths_of_a_degree(self):
        self.assertEqual(metricsd.read_temperature(str(self.thermal)), 529)
        # A broken sensor is not a temperature.
        self.set_zone("thermal_zone2", "-273000")
        self.set_zone("thermal_zone3", "not a number")
        self.assertEqual(metricsd.read_temperature(str(self.thermal)), 529)

    def test_no_sensor_is_none(self):
        self.assertIsNone(metricsd.read_temperature(str(self.root / "nowhere")))
        empty = self.root / "empty-thermal"
        empty.mkdir()
        self.assertIsNone(metricsd.read_temperature(str(empty)))
        # cooling devices sit beside the zones and have no temperature
        (empty / "cooling_device0").mkdir()
        self.assertIsNone(metricsd.read_temperature(str(empty)))

    def test_disk_space_as_df_counts_it(self):
        used, total = metricsd.read_disk_space(str(self.root))
        self.assertGreater(total, 0)
        self.assertLessEqual(used, total)
        self.assertIsNone(metricsd.read_disk_space(str(self.root / "nowhere")))

    def test_nothing_to_read_is_none(self):
        self.assertIsNone(metricsd.read_network_counters(str(self.root / "nowhere")))
        self.assertIsNone(metricsd.read_disk_counters(str(self.root / "none"), str(self.block)))


class Collected(AFakeMachine):
    def setUp(self):
        super().setUp()
        self.database = metricsd.MetricsDatabase(str(self.root / "metrics.db"))
        self.addCleanup(self.database.close)
        self.collector = metricsd.Collector(
            metricsd.load_config("/nonexistent/metricsd.json"), self.database
        )
        self.collector.cgroup_root = str(self.root / "no-cgroup")
        self.collector.disk_path = str(self.root)
        self.collector.diskstats_path = str(self.diskstats)
        self.collector.sys_block_root = str(self.block)
        self.collector.sys_net_root = str(self.net)
        self.collector.thermal_root = str(self.thermal)
        self.now = 600

    def poll(self):
        with (
            mock.patch.object(metricsd, "runtime_command", return_value=STAT),
            mock.patch.object(self.collector, "_read_host_cpu", return_value=250),
            mock.patch.object(self.collector, "_read_host_memory", return_value=(1000, 2000)),
            mock.patch.object(self.collector, "_read_haproxy_busy", return_value=None),
            mock.patch.object(self.collector, "_observe_components"),
            mock.patch.object(metricsd, "_utc_now", return_value=self.now),
        ):
            self.collector.poll()
        self.now += 10

    def host_row(self):
        self.collector.flush()
        for row in self.database._conn.execute(
            "SELECT m.* FROM metric_1m m JOIN objects o ON o.id = m.object_id WHERE o.kind = 'host'"
        ):
            return dict(row)
        return None

    def test_rates_start_at_the_second_reading_and_count_what_grew(self):
        self.poll()
        self.set_disk(read_sectors=300, written_sectors=50)
        self.set_card("eth0", 4000, 900)
        self.poll()
        row = self.host_row()
        self.assertEqual((row["disk_read"], row["disk_write"]), (200 * 512, 10 * 512))
        self.assertEqual((row["net_rx"], row["net_tx"]), (3000, 400))
        self.assertEqual(row["temp_max"], 529)
        self.assertGreater(row["disk_total"], 0)

    def test_a_card_that_appears_or_restarts_adds_no_spike(self):
        self.poll()
        self.set_card("eth1", 10 ** 9, 10 ** 9, device=True)
        # eth0's driver reloaded: its counter went back.
        self.set_card("eth0", 10, 10)
        self.poll()
        row = self.host_row()
        self.assertEqual((row["net_rx"], row["net_tx"]), (0, 0))

    def test_a_switched_off_reading_is_not_taken(self):
        self.collector.set_monitors({"temperature": False, "network": False})
        with mock.patch.object(metricsd, "read_temperature") as temperature, \
                mock.patch.object(metricsd, "read_network_counters") as network:
            self.poll()
        temperature.assert_not_called()
        network.assert_not_called()

    def test_the_machine_off_and_the_disk_on_still_writes_the_row(self):
        self.collector.set_monitors({"machine": False, "network": False, "temperature": False})
        self.poll()
        row = self.host_row()
        self.assertIsNotNone(row)
        self.assertGreater(row["disk_total"], 0)
        self.assertEqual(row["cpu_avg"], 0)

    def test_everything_off_writes_no_row(self):
        self.collector.set_monitors({name: False for name in metricsd.HOST_MONITORS})
        self.poll()
        self.assertIsNone(self.host_row())

    def test_switched_back_on_a_counter_starts_afresh(self):
        self.poll()
        self.collector.set_monitors({"disk": False})
        self.assertNotIn("disk", self.collector._counter_previous)

    def test_the_summary_says_whether_there_is_a_sensor(self):
        self.assertEqual(self.collector.sensors(), {"temperature": True})
        self.collector.thermal_root = str(self.root / "nowhere")
        self.assertEqual(self.collector.sensors(), {"temperature": False})


class LeavingStorage(unittest.TestCase):
    def test_each_chart_in_its_own_units(self):
        self.assertEqual(metricsd._from_storage("temperature", 529), 52.9)
        self.assertEqual(metricsd._from_storage("disk", 2), 2 * metricsd.MEMORY_UNIT)
        self.assertEqual(metricsd._from_storage("network", 12345), 12345)
        self.assertEqual(metricsd._from_storage("diskio", 0), 0)

    def test_an_unread_minute_is_a_gap_not_a_zero(self):
        self.assertIsNone(metricsd._from_storage("temperature", 0))
        self.assertIsNone(metricsd._from_storage("disk", 0))

    def test_every_new_column_survives_the_rollup(self):
        for column in ("disk_used_avg", "disk_total", "disk_read", "disk_write",
                       "net_rx", "net_tx", "temp_avg", "temp_max"):
            self.assertIn(column, metricsd.METRIC_COLUMNS)
            self.assertIn(column, metricsd._AGGREGATIONS)
        for chart in ("disk", "diskio", "network", "temperature"):
            self.assertIn(chart, metricsd.HOST_CHARTS)
        for name in ("disk", "network", "temperature"):
            self.assertIn(name, metricsd.GATHERED_MONITORS)
            self.assertIn(name, metricsd.HOST_MONITORS)


class TheSeries(AFakeMachine):
    def test_temperature_reads_back_in_degrees_with_gaps(self):
        database = metricsd.MetricsDatabase(str(self.root / "metrics.db"))
        self.addCleanup(database.close)
        object_id = database.object_id("host", "", "", 0)
        for bucket, temp in ((600, 515), (660, 0), (720, 530)):
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row.update(samples=6, temp_avg=temp, temp_max=temp)
            database.write_buckets(bucket, {object_id: row})
        payload = database.series(chart="temperature", site="be_site", since=0, until=1200)
        self.assertEqual(payload["series"]["temp_avg"], [51.5, None, 53.0])


if __name__ == "__main__":
    unittest.main()
