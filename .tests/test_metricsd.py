"""Regression tests for the historical metrics collector."""

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


def load_metricsd():
    path = ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"
    spec = importlib.util.spec_from_file_location("easy_ha_proxy_metricsd", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


metricsd = load_metricsd()


HEADER = (
    "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,status,chkfail,"
    "hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,req_tot,"
    "qtime,ctime,rtime,ttime"
)


def stat_row(
    pxname,
    svname,
    *,
    stot=0,
    bin_=0,
    bout=0,
    status="UP",
    chkfail=0,
    hrsp_2xx=0,
    hrsp_5xx=0,
    hrsp_other=0,
    req_tot=0,
    scur=0,
    qcur=0,
    rtime=0,
    ttime=0,
):
    return ",".join(
        str(value)
        for value in (
            pxname, svname, qcur, 0, scur, 0, 0, stot, bin_, bout, status,
            chkfail, 0, hrsp_2xx, 0, 0, hrsp_5xx, hrsp_other, req_tot,
            0, 0, rtime, ttime,
        )
    )


def payload(*rows):
    return "\n".join((HEADER, *rows)) + "\n"


class ShowStatParserTests(unittest.TestCase):
    def test_parses_by_header_name(self):
        rows = metricsd.parse_show_stat(
            payload(stat_row("be_site", "srv01", stot=5, bin_=100))
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pxname"], "be_site")
        self.assertEqual(rows[0]["svname"], "srv01")
        self.assertEqual(rows[0]["stot"], "5")
        self.assertEqual(rows[0]["bin"], "100")

    def test_reordered_and_extra_columns_are_tolerated(self):
        text = "# svname,pxname,stot,brand_new_column\nsrv01,be_site,7,ignored\n"
        rows = metricsd.parse_show_stat(text)
        self.assertEqual(rows[0]["pxname"], "be_site")
        self.assertEqual(rows[0]["stot"], "7")

    def test_truncated_row_keeps_the_cells_it_has(self):
        text = "# pxname,svname,stot,bin,bout\nbe_site,srv01,3\n"
        rows = metricsd.parse_show_stat(text)
        self.assertEqual(rows[0]["stot"], "3")
        self.assertNotIn("bout", rows[0])

    def test_empty_and_headerless_output_yields_nothing(self):
        self.assertEqual(metricsd.parse_show_stat(""), [])
        self.assertEqual(metricsd.parse_show_stat("   \n\n"), [])
        self.assertEqual(metricsd.parse_show_stat("no header here\n"), [])
        self.assertEqual(metricsd.parse_show_stat("# unrelated,columns\n"), [])

    def test_blank_cells_parse_as_zero(self):
        self.assertEqual(metricsd._to_int(""), 0)
        self.assertEqual(metricsd._to_int(None), 0)
        self.assertEqual(metricsd._to_int("  "), 0)
        self.assertEqual(metricsd._to_int("nonsense"), 0)
        self.assertEqual(metricsd._to_int("12"), 12)
        self.assertEqual(metricsd._to_int("12.9"), 12)

    def test_classify_separates_frontends_backends_and_servers(self):
        self.assertEqual(
            metricsd.classify({"pxname": "fe_https", "svname": "FRONTEND"}),
            ("frontend", "fe_https", ""),
        )
        self.assertEqual(
            metricsd.classify({"pxname": "be_site", "svname": "BACKEND"}),
            ("backend", "be_site", ""),
        )
        self.assertEqual(
            metricsd.classify({"pxname": "be_site", "svname": "srv01"}),
            ("server", "be_site", "srv01"),
        )
        self.assertIsNone(metricsd.classify({"pxname": "", "svname": "srv01"}))


class ConfigTests(unittest.TestCase):
    def test_missing_file_falls_back_to_defaults(self):
        config = metricsd.load_config("/nonexistent/metricsd.json")
        self.assertTrue(config.enabled)
        self.assertEqual(config.poll_interval_seconds, 10)
        self.assertEqual(config.exclude_prefix, ("tbl_",))

    def test_out_of_range_values_are_clamped(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metricsd.json"
            path.write_text(
                json.dumps(
                    {
                        "poll_interval_seconds": 3600,
                        "retention": {"one_minute_days": 0},
                    }
                ),
                encoding="utf-8",
            )
            config = metricsd.load_config(str(path))
        self.assertEqual(config.poll_interval_seconds, 60)
        self.assertEqual(config.retention_one_minute_days, 1)

    def test_broken_file_does_not_raise(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metricsd.json"
            path.write_text("{ not json", encoding="utf-8")
            config = metricsd.load_config(str(path))
        self.assertEqual(config.poll_interval_seconds, 10)

    def test_service_proxies_are_excluded(self):
        config = metricsd.load_config("/nonexistent/metricsd.json")
        self.assertTrue(config.excluded("tbl_ban"))
        self.assertTrue(config.excluded("be_admin"))
        self.assertTrue(config.excluded(""))
        self.assertFalse(config.excluded("be_site"))


class CollectorTestCase(unittest.TestCase):
    """Shared fixture: a collector wired to a throwaway database."""

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.database = metricsd.MetricsDatabase(
            str(Path(self._temporary.name) / "metrics.db")
        )
        self.addCleanup(self.database.close)
        self.config = metricsd.load_config("/nonexistent/metricsd.json")
        self.collector = metricsd.Collector(self.config, self.database)
        self.collector._baselines = self.database.load_baselines()
        self.collector._last_states = self.database.load_last_states()

    def poll(self, text, *, now):
        with (
            mock.patch.object(metricsd, "runtime_command", return_value=text),
            mock.patch.object(metricsd, "_utc_now", return_value=now),
        ):
            return self.collector.poll()

    def flush(self, *, now):
        with mock.patch.object(metricsd, "_utc_now", return_value=now):
            return self.collector.flush(force=True)

    def rows(self, table="metric_1m", kind=None):
        """Stored rows for the proxy objects.

        Every poll also records the machine's own load as a synthetic 'host'
        object. That is a different question from the ones these tests ask,
        and counting it here would have every traffic assertion off by one,
        so it is excluded unless asked for by name.
        """

        connection = sqlite3.connect(str(self.database.path))
        connection.row_factory = sqlite3.Row
        try:
            if kind is None:
                predicate, parameters = "o.kind != ?", [metricsd.HOST_KIND]
            else:
                predicate, parameters = "o.kind = ?", [kind]
            return [
                dict(row)
                for row in connection.execute(
                    f"SELECT o.kind, o.proxy, o.server, m.* FROM {table} m "
                    "JOIN objects o ON o.id = m.object_id "
                    f"WHERE {predicate} "
                    "ORDER BY m.bucket_ts, o.proxy, o.server",
                    parameters,
                )
            ]
        finally:
            connection.close()

    def host_rows(self, table="metric_1m"):
        return self.rows(table=table, kind=metricsd.HOST_KIND)


class DeltaTests(CollectorTestCase):
    def test_first_sample_seeds_the_baseline_without_emitting_a_delta(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1000)), now=600)
        self.flush(now=660)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sessions"], 0)
        self.assertEqual(rows[0]["samples"], 1)

    def test_second_sample_emits_the_difference(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1000)), now=600)
        self.poll(payload(stat_row("be_site", "srv01", stot=1025)), now=610)
        self.flush(now=660)
        self.assertEqual(self.rows()[0]["sessions"], 25)

    def test_counter_reset_never_stores_a_negative_delta(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1000)), now=600)
        self.poll(payload(stat_row("be_site", "srv01", stot=1010)), now=610)
        # HAProxy restarted: counters start again from a small value.
        self.poll(payload(stat_row("be_site", "srv01", stot=3)), now=620)
        self.poll(payload(stat_row("be_site", "srv01", stot=8)), now=630)
        self.flush(now=660)
        row = self.rows()[0]
        self.assertEqual(row["sessions"], 15)
        self.assertGreaterEqual(row["sessions"], 0)

    def test_stale_baseline_is_reseeded_instead_of_credited(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1000)), now=600)
        self.poll(payload(stat_row("be_site", "srv01", stot=1010)), now=610)
        self.flush(now=660)
        # The daemon was away for an hour; that traffic must not land in the
        # minute it happens to come back in.
        self.poll(payload(stat_row("be_site", "srv01", stot=99000)), now=4210)
        self.poll(payload(stat_row("be_site", "srv01", stot=99020)), now=4220)
        self.flush(now=4260)
        rows = self.rows()
        self.assertEqual(rows[-1]["sessions"], 20)

    def test_baselines_survive_a_daemon_restart(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1000)), now=600)
        self.flush(now=660)

        restarted = metricsd.Collector(self.config, self.database)
        restarted._baselines = self.database.load_baselines()
        restarted._last_states = self.database.load_last_states()
        with (
            mock.patch.object(
                metricsd,
                "runtime_command",
                return_value=payload(stat_row("be_site", "srv01", stot=1012)),
            ),
            mock.patch.object(metricsd, "_utc_now", return_value=665),
        ):
            restarted.poll()
        with mock.patch.object(metricsd, "_utc_now", return_value=725):
            restarted.flush(force=True)

        rows = self.rows()
        self.assertEqual(rows[-1]["sessions"], 12)

    def test_response_classes_and_bytes_are_tracked_separately(self):
        self.poll(
            payload(
                stat_row(
                    "be_site", "srv01",
                    bin_=100, bout=200, hrsp_2xx=10, hrsp_5xx=1, hrsp_other=2,
                )
            ),
            now=600,
        )
        self.poll(
            payload(
                stat_row(
                    "be_site", "srv01",
                    bin_=180, bout=460, hrsp_2xx=17, hrsp_5xx=4, hrsp_other=2,
                )
            ),
            now=610,
        )
        self.flush(now=660)
        row = self.rows()[0]
        self.assertEqual(row["bytes_in"], 80)
        self.assertEqual(row["bytes_out"], 260)
        self.assertEqual(row["resp_2xx"], 7)
        self.assertEqual(row["resp_5xx"], 3)
        self.assertEqual(row["resp_other"], 0)


class AggregationTests(CollectorTestCase):
    def test_ten_second_samples_collapse_into_one_minute_row(self):
        for index, now in enumerate(range(600, 660, 10)):
            self.poll(
                payload(stat_row("be_site", "srv01", scur=index * 2)), now=now
            )
        self.flush(now=660)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bucket_ts"], 600)
        self.assertEqual(rows[0]["samples"], 6)
        # scur samples were 0,2,4,6,8,10.
        self.assertEqual(rows[0]["conn_cur_avg"], 5)
        self.assertEqual(rows[0]["conn_cur_max"], 10)

    def test_crossing_a_minute_boundary_starts_a_new_bucket(self):
        self.poll(payload(stat_row("be_site", "srv01", scur=1)), now=650)
        self.poll(payload(stat_row("be_site", "srv01", scur=9)), now=665)
        self.flush(now=725)
        rows = self.rows()
        self.assertEqual([row["bucket_ts"] for row in rows], [600, 660])
        self.assertEqual(rows[0]["conn_cur_max"], 1)
        self.assertEqual(rows[1]["conn_cur_max"], 9)

    def test_frontends_backends_and_servers_are_separate_objects(self):
        self.poll(
            payload(
                stat_row("fe_https", "FRONTEND", scur=3),
                stat_row("be_site", "BACKEND", scur=2),
                stat_row("be_site", "srv01", scur=1),
            ),
            now=600,
        )
        self.flush(now=660)
        rows = self.rows()
        self.assertEqual(
            {(row["kind"], row["proxy"], row["server"]) for row in rows},
            {
                ("frontend", "fe_https", ""),
                ("backend", "be_site", ""),
                ("server", "be_site", "srv01"),
            },
        )

    def test_service_proxies_are_never_stored(self):
        observed = self.poll(
            payload(
                stat_row("tbl_ban", "BACKEND"),
                stat_row("be_admin", "BACKEND"),
                stat_row("be_site", "BACKEND"),
            ),
            now=600,
        )
        self.flush(now=660)
        self.assertEqual(observed, 1)
        self.assertEqual([row["proxy"] for row in self.rows()], ["be_site"])

    def test_empty_runtime_output_raises_without_writing(self):
        with self.assertRaises(RuntimeError):
            self.poll("", now=600)
        self.assertEqual(self.rows(), [])

    def test_socket_failure_is_reported_but_not_fatal(self):
        with (
            mock.patch.object(
                metricsd, "runtime_command", side_effect=OSError("no socket")
            ),
            mock.patch.object(metricsd, "_utc_now", return_value=600),
        ):
            with self.assertRaises(OSError):
                self.collector.poll()
        self.assertEqual(self.rows(), [])


class StateEventTests(CollectorTestCase):
    def events(self):
        connection = sqlite3.connect(str(self.database.path))
        connection.row_factory = sqlite3.Row
        try:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT ts, previous_state, state FROM server_state_events "
                    "ORDER BY id"
                )
            ]
        finally:
            connection.close()

    def test_only_transitions_are_recorded(self):
        for now in (600, 610, 620):
            self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=now)
        self.poll(payload(stat_row("be_site", "srv01", status="DOWN")), now=630)
        self.poll(payload(stat_row("be_site", "srv01", status="DOWN")), now=640)
        self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=650)

        events = self.events()
        self.assertEqual(
            [(event["previous_state"], event["state"]) for event in events],
            [("", "UP"), ("UP", "DOWN"), ("DOWN", "UP")],
        )
        self.assertEqual([event["ts"] for event in events], [600, 630, 650])

    def test_transitional_status_text_is_normalised(self):
        self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=600)
        self.poll(
            payload(stat_row("be_site", "srv01", status="DOWN 1/3")), now=610
        )
        self.poll(
            payload(stat_row("be_site", "srv01", status="DOWN 2/3")), now=620
        )
        self.assertEqual(
            [event["state"] for event in self.events()], ["UP", "DOWN"]
        )

    def test_restart_does_not_replay_an_unchanged_state(self):
        self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=600)
        restarted = metricsd.Collector(self.config, self.database)
        restarted._baselines = self.database.load_baselines()
        restarted._last_states = self.database.load_last_states()
        with (
            mock.patch.object(
                metricsd,
                "runtime_command",
                return_value=payload(stat_row("be_site", "srv01", status="UP")),
            ),
            mock.patch.object(metricsd, "_utc_now", return_value=700),
        ):
            restarted.poll()
        self.assertEqual(len(self.events()), 1)


class RollupAndRetentionTests(CollectorTestCase):
    def write_minute(self, bucket_ts, object_id, **columns):
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row["samples"] = 6
        row.update(columns)
        self.database.write_buckets(bucket_ts, {object_id: row})

    def test_minutes_roll_up_into_weighted_hours(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        self.write_minute(3600, object_id, requests=10, conn_cur_avg=4, conn_cur_max=9)
        self.write_minute(3660, object_id, requests=20, conn_cur_avg=8, conn_cur_max=5)
        self.database.rollup_hours(7200)

        hours = self.rows("metric_1h")
        self.assertEqual(len(hours), 1)
        self.assertEqual(hours[0]["bucket_ts"], 3600)
        self.assertEqual(hours[0]["requests"], 30)
        self.assertEqual(hours[0]["samples"], 12)
        self.assertEqual(hours[0]["conn_cur_avg"], 6)
        self.assertEqual(hours[0]["conn_cur_max"], 9)

    def test_the_current_hour_is_left_alone(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        self.write_minute(7200, object_id, requests=5)
        self.database.rollup_hours(7200)
        self.assertEqual(self.rows("metric_1h"), [])

    def test_watermark_stops_a_second_pass_from_double_counting(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        self.write_minute(3600, object_id, requests=10)
        self.database.rollup_hours(7200)
        self.write_minute(3660, object_id, requests=20)
        # The hour is already behind the watermark, so a repeat pass is a no-op
        # rather than an accumulating overwrite.
        self.database.rollup_hours(7200)
        self.assertEqual(self.rows("metric_1h")[0]["requests"], 10)

    def test_retention_trims_server_minutes_first(self):
        backend = self.database.object_id("backend", "be_site", "", 0)
        server = self.database.object_id("server", "be_site", "srv01", 0)
        for bucket in (1000, 200000):
            self.write_minute(bucket, backend, requests=1)
            self.write_minute(bucket, server, requests=1)

        deleted = self.database.apply_retention(
            minute_cutoff=0,
            minute_server_cutoff=100000,
            hour_cutoff=0,
        )
        self.assertEqual(deleted["server_minutes"], 1)
        remaining = {
            (row["kind"], row["bucket_ts"]) for row in self.rows("metric_1m")
        }
        self.assertEqual(
            remaining,
            {("backend", 1000), ("backend", 200000), ("server", 200000)},
        )

    def test_maintenance_rolls_up_before_deleting(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        self.write_minute(3600, object_id, requests=42)
        with mock.patch.object(metricsd, "_utc_now", return_value=30 * 86400):
            self.collector.run_maintenance()
        # The minute is long past retention, but its hour survived the trim.
        self.assertEqual(self.rows("metric_1m"), [])
        self.assertEqual(self.rows("metric_1h")[0]["requests"], 42)


class DatabaseTests(CollectorTestCase):
    def test_schema_version_is_recorded_once(self):
        self.assertEqual(
            self.database.stats()["schema_version"], metricsd.SCHEMA_VERSION
        )
        reopened = metricsd.MetricsDatabase(str(self.database.path))
        self.addCleanup(reopened.close)
        connection = sqlite3.connect(str(self.database.path))
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM schema_version"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)

    def test_a_newer_schema_is_refused_rather_than_written_to(self):
        connection = sqlite3.connect(str(self.database.path))
        try:
            connection.execute(
                "UPDATE schema_version SET version = ?",
                (metricsd.SCHEMA_VERSION + 1,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeError):
            metricsd.MetricsDatabase(str(self.database.path))

    def test_wal_mode_and_incremental_autovacuum_are_enabled(self):
        connection = sqlite3.connect(str(self.database.path))
        try:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0].lower(),
                "wal",
            )
            self.assertEqual(
                connection.execute("PRAGMA auto_vacuum").fetchone()[0], 2
            )
        finally:
            connection.close()

    def test_storage_report_counts_wal_and_filesystem(self):
        self.poll(payload(stat_row("be_site", "srv01", stot=1)), now=600)
        self.flush(now=660)
        storage = self.database.storage()
        self.assertGreater(storage["database_bytes"], 0)
        self.assertEqual(
            storage["total_bytes"],
            storage["database_bytes"] + storage["wal_bytes"] + storage["shm_bytes"],
        )
        self.assertGreater(storage["filesystem"]["total_bytes"], 0)

    def test_health_reports_degraded_before_the_first_poll(self):
        self.assertTrue(self.collector.health()["degraded"])
        self.poll(payload(stat_row("be_site", "srv01")), now=600)
        with mock.patch.object(metricsd, "_utc_now", return_value=610):
            health = self.collector.health()
        self.assertFalse(health["degraded"])
        self.assertEqual(health["last_poll_ts"], 600)

    def test_health_goes_degraded_when_collection_stalls(self):
        self.poll(payload(stat_row("be_site", "srv01")), now=600)
        with mock.patch.object(metricsd, "_utc_now", return_value=600 + 1800):
            self.assertTrue(self.collector.health()["degraded"])


GIB = 1024 ** 3
MIB = 1024 ** 2


def storage_config(**storage):
    """Build a config with explicit storage limits."""

    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "metricsd.json"
        path.write_text(json.dumps({"storage": storage}), encoding="utf-8")
        return metricsd.load_config(str(path))


def fake_storage(*, database=0, wal=0, shm=0, fs_total=20 * GIB, fs_free=10 * GIB):
    return {
        "database_bytes": database,
        "wal_bytes": wal,
        "shm_bytes": shm,
        "total_bytes": database + wal + shm,
        "filesystem": {"total_bytes": fs_total, "free_bytes": fs_free},
    }


class SizeParsingTests(unittest.TestCase):
    def test_suffixes_and_plain_bytes(self):
        self.assertEqual(metricsd.parse_size(1024), 1024)
        self.assertEqual(metricsd.parse_size("1024"), 1024)
        self.assertEqual(metricsd.parse_size("5GiB"), 5 * GIB)
        self.assertEqual(metricsd.parse_size("512 MiB"), 512 * MIB)
        self.assertEqual(metricsd.parse_size("2gb"), 2 * 1000 ** 3)
        self.assertEqual(metricsd.parse_size("1.5GiB"), int(1.5 * GIB))

    def test_auto_and_nonsense_fall_back(self):
        self.assertIsNone(metricsd.parse_size("auto"))
        self.assertIsNone(metricsd.parse_size("unlimited"))
        self.assertIsNone(metricsd.parse_size(""))
        self.assertIsNone(metricsd.parse_size("later"))
        self.assertIsNone(metricsd.parse_size(-5))
        self.assertIsNone(metricsd.parse_size(True))
        self.assertEqual(metricsd.parse_size("nope", default=7), 7)


class StorageLimitTests(CollectorTestCase):
    def guard(self, **storage):
        return metricsd.StorageGuard(storage_config(**storage), self.database)

    def test_auto_limits_scale_with_the_filesystem(self):
        guard = self.guard()
        # A 100 GiB volume: the cap is capped, the reserve is a tenth.
        maximum, reserve = guard.resolve_limits(100 * GIB)
        self.assertEqual(maximum, 5 * GIB)
        self.assertEqual(reserve, 10 * GIB)

    def test_auto_limits_on_a_small_disk_keep_the_reserve_floor(self):
        guard = self.guard()
        maximum, reserve = guard.resolve_limits(8 * GIB)
        # 10% of 8 GiB is the binding cap, and the reserve never drops below
        # its floor no matter how small the disk is.
        self.assertEqual(maximum, int(8 * GIB * 0.10))
        self.assertEqual(reserve, 2 * GIB)

    def test_explicit_limits_win_over_auto(self):
        guard = self.guard(max_database_size="1GiB", reserved_free_space="256MiB")
        self.assertEqual(guard.resolve_limits(100 * GIB), (GIB, 256 * MIB))

    def test_unlimited_database_still_enforces_the_reserve(self):
        guard = self.guard(
            max_database_size="unlimited", reserved_free_space="1GiB"
        )
        maximum, reserve = guard.resolve_limits(100 * GIB)
        # "Unlimited" resolves through auto rather than to zero, and either way
        # the free-space reserve stays in force.
        self.assertEqual(reserve, GIB)
        with mock.patch.object(
            self.database,
            "storage",
            return_value=fake_storage(database=10 * GIB, fs_free=512 * MIB),
        ):
            self.assertEqual(guard.measure().state, metricsd.STATE_CRITICAL)
        del maximum


class StorageStateTests(CollectorTestCase):
    def setUp(self):
        super().setUp()
        self.guard = metricsd.StorageGuard(
            storage_config(max_database_size="1GiB", reserved_free_space="1GiB"),
            self.database,
        )

    def measure(self, **storage):
        with mock.patch.object(
            self.database, "storage", return_value=fake_storage(**storage)
        ):
            return self.guard.measure()

    def test_normal_below_every_threshold(self):
        status = self.measure(database=100 * MIB, fs_free=10 * GIB)
        self.assertEqual(status.state, metricsd.STATE_NORMAL)

    def test_warning_at_eighty_percent_of_the_cap(self):
        self.assertEqual(
            self.measure(database=820 * MIB, fs_free=10 * GIB).state,
            metricsd.STATE_WARNING,
        )

    def test_pressure_at_ninety_percent_of_the_cap(self):
        self.assertEqual(
            self.measure(database=930 * MIB, fs_free=10 * GIB).state,
            metricsd.STATE_PRESSURE,
        )

    def test_critical_when_the_cap_is_reached(self):
        status = self.measure(database=GIB, fs_free=10 * GIB)
        self.assertEqual(status.state, metricsd.STATE_CRITICAL)
        self.assertIn("size limit", status.reason)

    def test_free_space_alone_can_reach_every_state(self):
        self.assertEqual(
            self.measure(database=10 * MIB, fs_free=int(1.9 * GIB)).state,
            metricsd.STATE_WARNING,
        )
        self.assertEqual(
            self.measure(database=10 * MIB, fs_free=int(1.1 * GIB)).state,
            metricsd.STATE_PRESSURE,
        )
        status = self.measure(database=10 * MIB, fs_free=900 * MIB)
        self.assertEqual(status.state, metricsd.STATE_CRITICAL)
        self.assertIn("free-space reserve", status.reason)

    def test_wal_and_shm_count_towards_the_cap(self):
        # The database file alone is comfortable; with the WAL beside it the
        # budget is gone.
        self.assertEqual(
            self.measure(database=600 * MIB, fs_free=10 * GIB).state,
            metricsd.STATE_NORMAL,
        )
        status = self.measure(
            database=600 * MIB, wal=420 * MIB, shm=32 * MIB, fs_free=10 * GIB
        )
        self.assertEqual(status.state, metricsd.STATE_CRITICAL)
        self.assertEqual(status.total_bytes, (600 + 420 + 32) * MIB)

    def test_the_database_filesystem_is_measured_not_the_root(self):
        seen = []
        real_statvfs = metricsd.os.statvfs

        def spy(path):
            seen.append(str(path))
            return real_statvfs(path)

        with mock.patch.object(metricsd.os, "statvfs", side_effect=spy):
            self.database.storage()
        self.assertEqual(seen, [str(self.database.path.parent)])


class PauseAndResumeTests(CollectorTestCase):
    def setUp(self):
        super().setUp()
        self.config = storage_config(
            max_database_size="1GiB", reserved_free_space="1GiB"
        )
        self.guard = metricsd.StorageGuard(self.config, self.database)
        self.collector = metricsd.Collector(self.config, self.database, self.guard)
        self.collector._baselines = self.database.load_baselines()
        self.collector._last_states = self.database.load_last_states()

    def enforce(self, *, now, **storage):
        with mock.patch.object(
            self.database, "storage", return_value=fake_storage(**storage)
        ):
            return self.guard.enforce(now)

    def test_critical_pauses_writes_and_drops_the_bucket(self):
        self.enforce(now=600, database=GIB, fs_free=10 * GIB)
        self.assertTrue(self.guard.writes_paused)

        self.poll(payload(stat_row("be_site", "srv01", stot=10)), now=600)
        self.poll(payload(stat_row("be_site", "srv01", stot=20)), now=610)
        self.flush(now=660)
        self.assertEqual(self.rows(), [])
        self.assertGreater(self.collector.buckets_dropped, 0)

    def test_reserve_pauses_writes_even_with_a_tiny_database(self):
        self.enforce(now=600, database=1 * MIB, fs_free=500 * MIB)
        self.assertTrue(self.guard.writes_paused)
        self.assertEqual(self.guard.state, metricsd.STATE_CRITICAL)

    def test_state_events_are_not_written_while_paused(self):
        self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=600)
        self.enforce(now=610, database=GIB, fs_free=10 * GIB)
        self.poll(payload(stat_row("be_site", "srv01", status="DOWN")), now=620)
        connection = sqlite3.connect(str(self.database.path))
        try:
            states = [
                row[0]
                for row in connection.execute(
                    "SELECT state FROM server_state_events ORDER BY id"
                )
            ]
        finally:
            connection.close()
        self.assertEqual(states, ["UP"])

    def test_a_transition_missed_while_paused_is_recorded_after_resume(self):
        self.poll(payload(stat_row("be_site", "srv01", status="UP")), now=600)
        self.enforce(now=610, database=GIB, fs_free=10 * GIB)
        self.poll(payload(stat_row("be_site", "srv01", status="DOWN")), now=620)
        self.enforce(now=700, database=100 * MIB, fs_free=10 * GIB)
        self.assertFalse(self.guard.writes_paused)
        self.poll(payload(stat_row("be_site", "srv01", status="DOWN")), now=710)
        connection = sqlite3.connect(str(self.database.path))
        try:
            states = [
                row[0]
                for row in connection.execute(
                    "SELECT state FROM server_state_events ORDER BY id"
                )
            ]
        finally:
            connection.close()
        self.assertEqual(states, ["UP", "DOWN"])

    def test_resume_needs_real_headroom_not_just_crossing_back(self):
        self.enforce(now=600, database=10 * MIB, fs_free=500 * MIB)
        self.assertTrue(self.guard.writes_paused)

        # Just above the reserve is not enough: that is exactly the flapping
        # the hysteresis margin exists to prevent.
        self.enforce(now=700, database=10 * MIB, fs_free=GIB + MIB)
        self.assertTrue(self.guard.writes_paused)

        self.enforce(now=800, database=10 * MIB, fs_free=GIB + 600 * MIB)
        self.assertFalse(self.guard.writes_paused)

    def test_resume_margin_never_exceeds_what_the_volume_can_offer(self):
        # A dedicated 64 MiB mount: a fixed 512 MiB of extra headroom would be
        # more space than exists, so the collector could never come back.
        guard = metricsd.StorageGuard(
            storage_config(reserved_free_space="32MiB"), self.database
        )
        with mock.patch.object(
            self.database,
            "storage",
            return_value=fake_storage(
                database=MIB, fs_total=64 * MIB, fs_free=20 * MIB
            ),
        ):
            status = guard.measure()
            margin = guard.resume_margin(status)
        self.assertLess(margin, 64 * MIB)
        self.assertGreater(margin, 0)

    def test_a_small_volume_can_actually_recover(self):
        guard = metricsd.StorageGuard(
            storage_config(
                max_database_size="unlimited", reserved_free_space="32MiB"
            ),
            self.database,
        )
        small = {"fs_total": 64 * MIB}
        with mock.patch.object(
            self.database,
            "storage",
            return_value=fake_storage(database=MIB, fs_free=20 * MIB, **small),
        ):
            guard.enforce(600)
        self.assertTrue(guard.writes_paused)
        with mock.patch.object(
            self.database,
            "storage",
            return_value=fake_storage(database=MIB, fs_free=60 * MIB, **small),
        ):
            guard.enforce(700)
        self.assertFalse(guard.writes_paused)

    def test_resume_is_blocked_while_the_database_is_still_near_its_cap(self):
        self.enforce(now=600, database=GIB, fs_free=10 * GIB)
        self.assertTrue(self.guard.writes_paused)
        # Plenty of free space, but the database itself is still at 97%.
        self.enforce(now=700, database=int(0.97 * GIB), fs_free=10 * GIB)
        self.assertTrue(self.guard.writes_paused)
        self.enforce(now=800, database=int(0.90 * GIB), fs_free=10 * GIB)
        self.assertFalse(self.guard.writes_paused)

    def test_counting_continues_while_paused_so_nothing_is_double_counted(self):
        self.enforce(now=600, database=GIB, fs_free=10 * GIB)
        self.poll(payload(stat_row("be_site", "srv01", stot=100)), now=600)
        self.poll(payload(stat_row("be_site", "srv01", stot=150)), now=610)
        self.flush(now=660)
        self.assertEqual(self.rows(), [])

        self.enforce(now=665, database=10 * MIB, fs_free=10 * GIB)
        self.assertFalse(self.guard.writes_paused)
        self.poll(payload(stat_row("be_site", "srv01", stot=160)), now=670)
        self.flush(now=730)
        rows = self.rows()
        # Only the 10 sessions that happened after the resume are stored; the
        # paused minute is gone rather than replayed on top of the new one.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sessions"], 10)


class PressureCleanupTests(CollectorTestCase):
    def setUp(self):
        super().setUp()
        self.config = storage_config(
            max_database_size="1GiB", reserved_free_space="1GiB"
        )
        self.guard = metricsd.StorageGuard(self.config, self.database)

    def test_retention_ladder_only_ever_trims(self):
        level0 = self.guard.retention_for_level(0)
        self.assertEqual(level0["minute_days"], 7)
        self.assertEqual(level0["hour_days"], 365)
        previous = level0
        for level in range(1, len(metricsd.RETENTION_LADDER)):
            current = self.guard.retention_for_level(level)
            for key in ("minute_days", "minute_server_hours", "hour_days"):
                self.assertLessEqual(current[key], previous[key], (level, key))
            previous = current

    def test_a_shorter_configured_retention_is_never_extended(self):
        guard = metricsd.StorageGuard(
            storage_config(max_database_size="1GiB"), self.database
        )
        object.__setattr__(guard.config, "retention_one_hour_days", 14)
        self.assertEqual(guard.retention_for_level(3)["hour_days"], 14)

    def test_pressure_escalates_through_the_ladder_until_it_helps(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        now = 100 * 86400
        for age_days in (200, 100, 5, 2):
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row["samples"] = 6
            self.database.write_buckets(now - age_days * 86400, {object_id: row})

        sizes = iter(
            [
                fake_storage(database=950 * MIB),  # measure -> PRESSURE
                fake_storage(database=950 * MIB),  # after level 1 -> still bad
                fake_storage(database=400 * MIB),  # after level 2 -> recovered
            ]
        )
        with mock.patch.object(
            self.database, "storage", side_effect=lambda: next(sizes)
        ):
            result = self.guard.enforce(now)

        self.assertEqual(result["actions"], ["trim_level_1", "trim_level_2"])
        self.assertEqual(result["status"].state, metricsd.STATE_NORMAL)
        # Level 2 keeps one day of minutes, so only the two-day-old row went.
        remaining = {row["bucket_ts"] for row in self.rows()}
        self.assertEqual(remaining, set())

    def test_cleanup_reclaims_pages_without_a_full_vacuum(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        for index in range(500):
            row = {column: index for column in metricsd.METRIC_COLUMNS}
            self.database.write_buckets(index * 60, {object_id: row})
        self.database.checkpoint(truncate=True)
        before = self.database.path.stat().st_size

        with mock.patch.object(
            self.database, "storage", return_value=fake_storage(database=GIB)
        ):
            self.guard.enforce(1000 * 86400)
        self.database.checkpoint(truncate=True)

        after = self.database.path.stat().st_size
        self.assertLess(after, before)
        self.assertEqual(self.rows(), [])

    def test_the_daemon_never_issues_a_full_vacuum(self):
        source = (
            ROOT / "ansible/roles/haproxy-admin/files/easy-ha-proxy-metricsd.py"
        ).read_text(encoding="utf-8")
        # Look at SQL the daemon could actually execute -- quoted text -- and
        # ignore prose that merely mentions the word.
        # `auto_vacuum` has no word boundary before "vacuum", so match the bare
        # word and keep the search to single-line quoted text.
        statements = re.findall(r"""["']([^"'\n]*vacuum[^"'\n]*)["']""",
                                source, flags=re.IGNORECASE)
        self.assertTrue(statements, "expected the vacuum pragma to be present")
        for statement in statements:
            self.assertIn(
                "incremental",
                statement.lower(),
                f"full VACUUM would need room for a second copy: {statement}",
            )

    def test_auto_reduce_can_be_turned_off(self):
        guard = metricsd.StorageGuard(
            storage_config(
                max_database_size="1GiB", auto_reduce_retention=False
            ),
            self.database,
        )
        with mock.patch.object(
            self.database, "storage", return_value=fake_storage(database=950 * MIB)
        ):
            result = guard.enforce(1000)
        self.assertEqual(result["actions"], [])
        self.assertEqual(result["status"].state, metricsd.STATE_PRESSURE)


class WalManagementTests(CollectorTestCase):
    def test_an_oversized_wal_is_checkpointed(self):
        guard = metricsd.StorageGuard(
            storage_config(wal_soft_limit="1MiB"), self.database
        )
        with (
            mock.patch.object(
                self.database,
                "storage",
                return_value=fake_storage(database=MIB, wal=8 * MIB),
            ),
            mock.patch.object(
                self.database, "checkpoint", return_value=True
            ) as checkpoint,
        ):
            self.assertTrue(guard.manage_wal(guard.measure(), 600))
        checkpoint.assert_called_once_with(truncate=True)
        self.assertEqual(guard.last_checkpoint_ts, 600)

    def test_a_small_wal_is_left_alone(self):
        guard = metricsd.StorageGuard(
            storage_config(wal_soft_limit="64MiB"), self.database
        )
        with (
            mock.patch.object(
                self.database,
                "storage",
                return_value=fake_storage(database=MIB, wal=MIB),
            ),
            mock.patch.object(self.database, "checkpoint") as checkpoint,
        ):
            self.assertFalse(guard.manage_wal(guard.measure(), 600))
        checkpoint.assert_not_called()

    def test_a_busy_truncate_falls_back_to_a_passive_checkpoint(self):
        guard = metricsd.StorageGuard(
            storage_config(wal_soft_limit="1MiB"), self.database
        )
        with (
            mock.patch.object(
                self.database,
                "storage",
                return_value=fake_storage(database=MIB, wal=8 * MIB),
            ),
            mock.patch.object(
                self.database, "checkpoint", side_effect=[False, True]
            ) as checkpoint,
        ):
            guard.manage_wal(guard.measure(), 600)
        self.assertEqual(checkpoint.call_count, 2)


class StorageTelemetryTests(CollectorTestCase):
    def test_growth_is_reported_against_recorded_samples(self):
        now = 30 * 86400
        self.database.record_storage_sample(now - 8 * 86400, 100 * MIB)
        self.database.record_storage_sample(now - 2 * 86400, 150 * MIB)
        growth = self.database.storage_growth(now, 200 * MIB)
        # Each window compares against the newest sample at or before its edge:
        # 150 MiB two days ago, 100 MiB eight days ago.
        self.assertEqual(growth["last_24h_bytes"], 50 * MIB)
        self.assertEqual(growth["last_7d_bytes"], 100 * MIB)
        self.assertEqual(growth["trend"], "growing")

    def test_a_settled_database_reads_as_stable_not_as_a_forecast(self):
        now = 30 * 86400
        self.database.record_storage_sample(now - 8 * 86400, 500 * MIB)
        growth = self.database.storage_growth(now, 501 * MIB)
        self.assertEqual(growth["trend"], "stable")

    def test_trend_is_unknown_before_a_week_of_samples(self):
        now = 30 * 86400
        self.database.record_storage_sample(now - 3600, 500 * MIB)
        self.assertEqual(
            self.database.storage_growth(now, 500 * MIB)["trend"], "unknown"
        )

    def test_samples_are_hourly_and_expire(self):
        now = 40 * 86400
        self.database.record_storage_sample(now - 31 * 86400, 30)
        self.database.record_storage_sample(now, 10)
        self.database.record_storage_sample(now + 60, 20)
        connection = sqlite3.connect(str(self.database.path))
        try:
            rows = connection.execute(
                "SELECT ts, total_bytes FROM storage_samples ORDER BY ts"
            ).fetchall()
        finally:
            connection.close()
        # Two writes in the same hour collapse to one slot, and the month-old
        # sample is gone.
        self.assertEqual(rows, [(now - (now % 3600), 20)])

    def test_report_exposes_limits_state_and_effective_retention(self):
        guard = metricsd.StorageGuard(
            storage_config(max_database_size="1GiB", reserved_free_space="1GiB"),
            self.database,
        )
        with mock.patch.object(
            self.database,
            "storage",
            return_value=fake_storage(database=850 * MIB, wal=2 * MIB),
        ):
            report = guard.report(600)
        self.assertEqual(report["state"], metricsd.STATE_WARNING)
        self.assertEqual(report["max_database_bytes"], GIB)
        self.assertEqual(report["reserved_free_bytes"], GIB)
        self.assertFalse(report["writes_paused"])
        self.assertEqual(report["effective_retention"]["minute_days"], 7)
        self.assertIn("growth", report)


class ReadApiTests(CollectorTestCase):
    """The query surface the monitoring page reads from."""

    def seed(self, kind, proxy, server, buckets, table="metric_1m", **columns):
        object_id = self.database.object_id(kind, proxy, server, 0)
        for bucket_ts in buckets:
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row["samples"] = 6
            row.update(columns)
            if table == "metric_1m":
                self.database.write_buckets(bucket_ts, {object_id: row})
            else:
                self.database.write_buckets(bucket_ts, {object_id: row})
                self.database.rollup_hours(bucket_ts + metricsd.HOUR_SECONDS)
        return object_id

    def seed_host(self, buckets, **columns):
        """The machine's own row, so the cpu chart has something to return."""

        values = {"cpu_avg": 250, "cpu_max": 400, "haproxy_busy_avg": 100}
        values.update(columns)
        return self.seed(metricsd.HOST_KIND, "", "", buckets, **values)

    def test_range_and_resolution_are_chosen_from_an_allow_list(self):
        self.assertEqual(metricsd.resolve_range("24h"), ("24h", 86400))
        self.assertEqual(metricsd.resolve_range("bogus"), ("24h", 86400))
        self.assertEqual(metricsd.resolve_range(None), ("24h", 86400))
        self.assertEqual(metricsd.resolve_range("1y"), ("1y", 365 * 86400))

    def test_resolution_keeps_every_range_inside_the_point_budget(self):
        for key, seconds in metricsd.RANGES.items():
            table, step = metricsd.choose_resolution(seconds)
            points = seconds // step
            self.assertLessEqual(points, metricsd.MAX_CHART_POINTS, key)
            self.assertIn(table, ("metric_1m", "metric_1h"))
        self.assertEqual(metricsd.choose_resolution(3600), ("metric_1m", 60))
        self.assertEqual(metricsd.choose_resolution(86400), ("metric_1m", 60))
        self.assertEqual(metricsd.choose_resolution(7 * 86400)[0], "metric_1h")

    def test_without_a_site_the_frontends_are_the_scope(self):
        self.seed("frontend", "fe_https", "", [600, 660], requests=10)
        self.seed("backend", "be_shop", "", [600, 660], requests=99)
        payload = self.database.series(
            chart="requests", site="", since=0, until=1200
        )
        self.assertEqual(payload["series"]["requests"], [10, 10])

    def test_a_site_scopes_to_that_backend_only(self):
        self.seed("frontend", "fe_https", "", [600], requests=10)
        self.seed("backend", "be_shop", "", [600], requests=7)
        self.seed("backend", "be_blog", "", [600], requests=3)
        payload = self.database.series(
            chart="requests", site="be_shop", since=0, until=1200
        )
        self.assertEqual(payload["series"]["requests"], [7])

    def test_multiple_frontends_are_summed_not_duplicated(self):
        self.seed("frontend", "fe_https", "", [600], requests=10)
        self.seed("frontend", "fe_http80", "", [600], requests=5)
        payload = self.database.series(
            chart="requests", site="", since=0, until=1200
        )
        self.assertEqual(payload["series"]["requests"], [15])

    def test_each_chart_returns_its_declared_series(self):
        self.seed(
            "frontend", "fe_https", "", [600],
            requests=1, bytes_in=2, bytes_out=3,
            resp_2xx=4, resp_3xx=5, resp_4xx=6, resp_5xx=7,
            response_ms_avg=8, response_ms_max=9,
            conn_cur_avg=10, conn_cur_max=11,
        )
        # The machine's own row, on the same bucket: the cpu chart reads a
        # different object entirely, and without it this loop would pass
        # every chart and quietly skip the only one that is scoped
        # differently.
        self.seed_host([600])
        for chart, columns in metricsd.CHART_SERIES.items():
            payload = self.database.series(
                chart=chart, site="", since=0, until=1200
            )
            self.assertEqual(sorted(payload["series"]), sorted(columns), chart)
            for column in columns:
                self.assertEqual(len(payload["series"][column]), 1, chart)

    def test_maxima_stay_maxima_when_buckets_are_grouped(self):
        # A 7-day range reads hourly rows; the peak must survive the grouping.
        object_id = self.database.object_id("frontend", "fe_https", "", 0)
        for index in range(4):
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row["samples"] = 6
            row["conn_cur_max"] = 10 * (index + 1)
            row["conn_cur_avg"] = 5
            self.database.write_buckets(index * 60, {object_id: row})
        self.database.rollup_hours(metricsd.HOUR_SECONDS)
        payload = self.database.series(
            chart="connections", site="", since=0, until=30 * 86400
        )
        self.assertEqual(payload["source"], "metric_1h")
        self.assertEqual(max(payload["series"]["conn_cur_max"]), 40)
        self.assertEqual(payload["series"]["conn_cur_avg"], [5])

    def test_totals_cover_the_requested_window_only(self):
        self.seed("frontend", "fe_https", "", [600], requests=10)
        self.seed("frontend", "fe_https", "", [5000], requests=90)
        self.assertEqual(
            self.database.totals(site="", since=0, until=1200)["requests"], 10
        )
        self.assertEqual(
            self.database.totals(site="", since=0, until=6000)["requests"], 100
        )

    def test_sites_lists_backends_not_frontends(self):
        self.seed("frontend", "fe_https", "", [600])
        self.seed("backend", "be_shop", "", [600])
        self.seed("server", "be_shop", "srv1", [600])
        self.assertEqual(
            [entry["proxy"] for entry in self.database.sites()], ["be_shop"]
        )

    def test_backend_health_counts_the_latest_state(self):
        self.poll(
            payload(
                stat_row("be_shop", "BACKEND", status="UP"),
                stat_row("be_shop", "srv1", status="UP"),
                stat_row("be_blog", "BACKEND", status="DOWN"),
                stat_row("be_blog", "srv1", status="DOWN"),
            ),
            now=600,
        )
        health = self.database.backend_health()
        self.assertEqual(health["backends_total"], 2)
        self.assertEqual(health["backends_up"], 1)
        self.assertEqual(health["servers_total"], 2)
        self.assertEqual(health["servers_up"], 1)

    def test_latest_gauges_read_the_newest_bucket_with_data(self):
        self.seed("frontend", "fe_https", "", [600], conn_cur_avg=3, conn_cur_max=9)
        self.seed("frontend", "fe_https", "", [660], conn_cur_avg=5, conn_cur_max=12)
        gauges = self.database.latest_gauges(site="", until=100000)
        self.assertEqual(gauges["conn_cur_avg"], 5)
        self.assertEqual(gauges["conn_cur_max"], 12)

    def test_an_empty_window_returns_an_empty_series_not_an_error(self):
        payload = self.database.series(
            chart="requests", site="", since=0, until=1200
        )
        self.assertEqual(payload["points"], [])
        self.assertEqual(payload["series"]["requests"], [])
        self.assertEqual(
            self.database.totals(site="", since=0, until=1200)["requests"], 0
        )

    def test_every_chart_column_has_a_declared_aggregation(self):
        for chart, columns in metricsd.CHART_SERIES.items():
            for column in columns:
                self.assertIn(column, metricsd._AGGREGATIONS, f"{chart}.{column}")
                self.assertIn(column, metricsd.METRIC_COLUMNS, f"{chart}.{column}")
        for column in metricsd.SUMMARY_COLUMNS:
            self.assertIn(column, metricsd._AGGREGATIONS, column)

    def test_no_request_text_reaches_a_query(self):
        # Site names are matched against what exists; anything else scopes to
        # the frontends. The value never becomes SQL.
        self.seed("backend", "be_shop", "", [600], requests=5)
        payload = self.database.series(
            chart="requests",
            site="be_shop' OR '1'='1",
            since=0,
            until=1200,
        )
        self.assertEqual(payload["series"]["requests"], [])


class StateTimelineTests(CollectorTestCase):
    def event(self, kind, proxy, server, state, ts, previous=""):
        object_id = self.database.object_id(kind, proxy, server, ts)
        self.database.record_state_change(object_id, previous, state, ts)
        return object_id

    def test_a_server_up_for_the_whole_window_has_no_downtime(self):
        # The last transition is older than the window; the timeline still has
        # to show the state it left behind.
        self.event("server", "be_shop", "srv1", "UP", 100)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        entry = timeline["objects"][0]
        self.assertEqual(entry["current_state"], "UP")
        self.assertEqual(entry["downtime_seconds"], 0)
        self.assertEqual(entry["availability"], 1.0)
        self.assertEqual(len(entry["spans"]), 1)
        self.assertEqual(entry["spans"][0], {"state": "UP", "start": 10000, "end": 20000})

    def test_downtime_is_measured_between_transitions(self):
        self.event("server", "be_shop", "srv1", "UP", 100)
        self.event("server", "be_shop", "srv1", "DOWN", 12000, previous="UP")
        self.event("server", "be_shop", "srv1", "UP", 13000, previous="DOWN")
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        entry = timeline["objects"][0]
        self.assertEqual(entry["downtime_seconds"], 1000)
        self.assertEqual(entry["availability"], 0.9)
        self.assertEqual(entry["transitions"], 2)
        self.assertEqual(
            [span["state"] for span in entry["spans"]], ["UP", "DOWN", "UP"]
        )

    def test_spans_tile_the_window_without_gaps(self):
        self.event("server", "be_shop", "srv1", "UP", 100)
        self.event("server", "be_shop", "srv1", "DOWN", 11000, previous="UP")
        self.event("server", "be_shop", "srv1", "MAINT", 15000, previous="DOWN")
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        spans = timeline["objects"][0]["spans"]
        self.assertEqual(spans[0]["start"], 10000)
        self.assertEqual(spans[-1]["end"], 20000)
        for previous, following in zip(spans, spans[1:]):
            self.assertEqual(previous["end"], following["start"])

    def test_repeating_the_same_state_does_not_split_the_bar(self):
        # A restart re-observes the state it left behind; the timeline should
        # still read as one uninterrupted stretch.
        self.event("server", "be_shop", "srv1", "UP", 11000)
        self.event("server", "be_shop", "srv1", "UP", 14000)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        entry = timeline["objects"][0]
        self.assertEqual(len(entry["spans"]), 1)
        self.assertEqual(entry["spans"][0], {"state": "UP", "start": 10000, "end": 20000})
        self.assertEqual(entry["downtime_seconds"], 0)

    def test_anything_that_is_not_up_counts_against_availability(self):
        self.event("server", "be_shop", "srv1", "MAINT", 100)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        entry = timeline["objects"][0]
        self.assertEqual(entry["downtime_seconds"], 10000)
        self.assertEqual(entry["availability"], 0.0)

    def test_the_site_filter_scopes_to_one_backend(self):
        self.event("backend", "be_shop", "", "UP", 100)
        self.event("server", "be_shop", "srv1", "UP", 100)
        self.event("backend", "be_blog", "", "UP", 100)
        scoped = self.database.state_timeline(
            site="be_shop", since=10000, until=20000
        )
        self.assertEqual(
            {entry["proxy"] for entry in scoped["objects"]}, {"be_shop"}
        )
        self.assertEqual(len(scoped["objects"]), 2)

    def test_frontends_never_appear_in_the_timeline(self):
        self.event("frontend", "fe_https", "", "OPEN", 100)
        self.event("backend", "be_shop", "", "UP", 100)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        self.assertEqual(
            {entry["kind"] for entry in timeline["objects"]}, {"backend"}
        )

    def test_an_object_with_no_history_is_skipped(self):
        self.database.object_id("server", "be_shop", "srv1", 100)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        self.assertEqual(timeline["objects"], [])

    def test_a_flapping_server_is_truncated_rather_than_unbounded(self):
        object_id = self.database.object_id("server", "be_shop", "srv1", 0)
        for index in range(metricsd.MAX_TIMELINE_SPANS + 50):
            state = "UP" if index % 2 else "DOWN"
            self.database.record_state_change(object_id, "", state, 10001 + index)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        self.assertTrue(timeline["truncated"])
        self.assertLessEqual(
            len(timeline["objects"][0]["spans"]), metricsd.MAX_TIMELINE_SPANS + 1
        )

    def test_a_transition_recorded_by_the_collector_shows_up(self):
        self.poll(payload(stat_row("be_shop", "srv1", status="UP")), now=10100)
        self.poll(payload(stat_row("be_shop", "srv1", status="DOWN")), now=15000)
        timeline = self.database.state_timeline(
            site="", since=10000, until=20000
        )
        server = [
            entry for entry in timeline["objects"] if entry["kind"] == "server"
        ][0]
        self.assertEqual(server["current_state"], "DOWN")
        self.assertEqual(server["downtime_seconds"], 5000)


class MigrationTests(CollectorTestCase):
    def test_an_older_database_is_migrated_in_place(self):
        path = str(self.database.path)
        self.database.close()

        connection = sqlite3.connect(path)
        try:
            connection.execute("UPDATE schema_version SET version = 1")
            connection.execute("DROP TABLE storage_samples")
            connection.commit()
        finally:
            connection.close()

        migrated = metricsd.MetricsDatabase(path)
        self.addCleanup(migrated.close)
        self.assertEqual(migrated.stats()["schema_version"], metricsd.SCHEMA_VERSION)
        migrated.record_storage_sample(3600, 123)

    def test_existing_history_survives_the_migration(self):
        object_id = self.database.object_id("backend", "be_site", "", 0)
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row["samples"] = 6
        row["requests"] = 99
        self.database.write_buckets(3600, {object_id: row})
        path = str(self.database.path)
        self.database.close()

        connection = sqlite3.connect(path)
        try:
            connection.execute("UPDATE schema_version SET version = 1")
            connection.commit()
        finally:
            connection.close()

        migrated = metricsd.MetricsDatabase(path)
        self.addCleanup(migrated.close)
        self.assertEqual(migrated.stats()["metric_1m"]["rows"], 1)


class StorageAlertTests(unittest.TestCase):
    """Storage pressure used to be a journal line nobody read."""

    class Recorder:
        def __init__(self):
            self.calls = []

        def observe(self, rule, subject, **kwargs):
            self.calls.append((rule, kwargs))
            return True

    def guard(self, state, paused=False):
        recorder = self.Recorder()
        guard = metricsd.StorageGuard.__new__(metricsd.StorageGuard)
        guard.alerts = recorder
        guard.writes_paused = paused
        status = mock.Mock(state=state, reason=f"state is {state}")
        guard._report_to_alerts(status)
        return recorder

    def by_rule(self, recorder):
        return {rule: kwargs for rule, kwargs in recorder.calls}

    def test_a_healthy_disk_reports_both_conditions_as_inactive(self):
        # Reporting "false" is what lets the engine announce a recovery.
        reported = self.by_rule(self.guard(metricsd.STATE_NORMAL))
        self.assertFalse(reported["monitoring.storage"]["active"])
        self.assertFalse(reported["monitoring.paused"]["active"])

    def test_pressure_is_a_warning_and_critical_is_critical(self):
        reported = self.by_rule(self.guard(metricsd.STATE_PRESSURE))
        self.assertTrue(reported["monitoring.storage"]["active"])
        self.assertEqual(reported["monitoring.storage"]["severity"], "warning")
        reported = self.by_rule(self.guard(metricsd.STATE_CRITICAL))
        self.assertEqual(reported["monitoring.storage"]["severity"], "critical")

    def test_a_warning_state_is_not_yet_worth_an_alert(self):
        reported = self.by_rule(self.guard(metricsd.STATE_WARNING))
        self.assertFalse(reported["monitoring.storage"]["active"])

    def test_paused_writes_are_their_own_condition(self):
        reported = self.by_rule(
            self.guard(metricsd.STATE_CRITICAL, paused=True)
        )
        self.assertTrue(reported["monitoring.paused"]["active"])

    def test_a_broken_alert_client_cannot_stop_the_collector(self):
        class Exploding:
            def observe(self, *args, **kwargs):
                raise RuntimeError("alertd is on fire")

        guard = metricsd.StorageGuard.__new__(metricsd.StorageGuard)
        guard.alerts = Exploding()
        guard.writes_paused = False
        guard._report_to_alerts(mock.Mock(state="NORMAL", reason=""))

    def test_a_gateway_without_the_alert_daemon_still_works(self):
        guard = metricsd.StorageGuard.__new__(metricsd.StorageGuard)
        guard.alerts = None
        guard.writes_paused = False
        guard._report_to_alerts(mock.Mock(state="CRITICAL", reason=""))


class TheMachinesOwnLoad(unittest.TestCase):
    """CPU, which no `show stat` row reports.

    Stored as a synthetic object of kind 'host' so it inherits the existing
    bucketing, rollup and retention rather than growing a second system
    beside them. The whole design rests on nothing else selecting that kind,
    which the leak tests below pin down.
    """

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.database = metricsd.MetricsDatabase(
            str(Path(self._temporary.name) / "metrics.db")
        )
        self.addCleanup(self.database.close)
        self.config = metricsd.load_config("/nonexistent/metricsd.json")
        self.collector = metricsd.Collector(self.config, self.database)

    def read(self, *lines):
        """Drive _read_host_cpu off a fabricated /proc/stat."""

        data = "\n".join(lines)
        with mock.patch("builtins.open", mock.mock_open(read_data=data)):
            return self.collector._read_host_cpu()

    def test_the_first_reading_is_nothing_not_zero(self):
        # CPU is a rate. With nothing to subtract from, the honest answer is
        # "no reading yet"; a zero would draw a floor that never happened.
        self.assertIsNone(self.read("cpu 100 0 100 800 0 0 0 0"))

    def test_the_second_reading_is_the_share_that_was_busy(self):
        self.read("cpu 100 0 100 800 0 0 0 0")
        # 100 more busy jiffies, 100 more idle: half the interval was work.
        self.assertEqual(self.read("cpu 150 0 150 900 0 0 0 0"), 500)

    def test_iowait_counts_as_idle(self):
        # The processor was free; the disk was not. Calling that busy blames
        # the wrong component for a slow gateway.
        self.read("cpu 100 0 100 800 100 0 0 0")
        self.assertEqual(self.read("cpu 100 0 100 800 200 0 0 0"), 0)

    def test_a_counter_that_went_backwards_reports_nothing(self):
        self.read("cpu 500 0 500 5000 0 0 0 0")
        self.assertIsNone(self.read("cpu 10 0 10 100 0 0 0 0"))

    def test_an_unreadable_proc_costs_only_the_cpu_reading(self):
        with mock.patch("builtins.open", side_effect=OSError("nope")):
            self.assertIsNone(self.collector._read_host_cpu())

    def test_a_garbled_line_reports_nothing(self):
        self.assertIsNone(self.read("cpu bogus values here now ok fine"))

    def test_it_never_exceeds_the_whole_machine(self):
        self.read("cpu 0 0 0 0 0 0 0 0")
        self.assertLessEqual(self.read("cpu 900 0 100 0 0 0 0 0"), 1000)

    # -- HAProxy's own idle ------------------------------------------------

    def test_haproxy_busy_is_the_complement_of_idle(self):
        with mock.patch.object(
            metricsd, "runtime_command",
            return_value="Name: HAProxy\nIdle_pct: 93\n",
        ):
            self.assertEqual(self.collector._read_haproxy_busy(), 70)

    def test_a_missing_idle_line_reports_nothing(self):
        with mock.patch.object(
            metricsd, "runtime_command", return_value="Name: HAProxy\n"
        ):
            self.assertIsNone(self.collector._read_haproxy_busy())

    def test_a_failed_runtime_call_costs_only_this_reading(self):
        # It shares a poll with the traffic metrics and must never take them
        # down with it.
        with mock.patch.object(
            metricsd, "runtime_command", side_effect=OSError("socket gone")
        ):
            self.assertIsNone(self.collector._read_haproxy_busy())

    # -- it must not leak into anything else -------------------------------

    def host_row(self, cpu=250, busy=100, bucket=3600):
        object_id = self.database.object_id(metricsd.HOST_KIND, "", "", bucket)
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row.update(samples=1, cpu_avg=cpu, cpu_max=cpu, haproxy_busy_avg=busy)
        self.database.write_buckets(bucket, {object_id: row})

    def traffic_row(self, bucket=3600, requests=500):
        object_id = self.database.object_id("frontend", "fe_https", "", bucket)
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row.update(samples=1, requests=requests)
        self.database.write_buckets(bucket, {object_id: row})

    def test_the_host_row_is_not_counted_as_traffic(self):
        self.host_row()
        self.traffic_row(requests=500)
        totals = self.database.totals(site="", since=0, until=7200)
        self.assertEqual(totals["requests"], 500)

    def test_the_host_is_not_offered_as_a_site(self):
        self.host_row()
        self.assertEqual([entry["proxy"] for entry in self.database.sites()], [])

    def test_the_host_is_not_an_uplink(self):
        self.host_row()
        payload = self.database.server_totals(since=0, until=7200)
        self.assertEqual(payload["servers"], [])

    def test_the_chart_reads_percent_not_tenths(self):
        self.host_row(cpu=250)
        payload = self.database.series(chart="cpu", site="", since=0, until=7200)
        self.assertEqual(payload["series"]["cpu_avg"], [25.0])

    def test_choosing_a_site_does_not_filter_the_machine(self):
        # One machine's CPU is not divisible among the sites it serves, so a
        # site selection must leave the reading alone rather than empty it.
        self.host_row(cpu=250)
        payload = self.database.series(
            chart="cpu", site="be_something_else", since=0, until=7200
        )
        self.assertEqual(payload["series"]["cpu_avg"], [25.0])

    def test_the_summary_says_when_it_has_never_seen_the_machine(self):
        # A database written before the collector could read it has no rows
        # at all; a confident 0% would be a lie about an idle gateway.
        self.traffic_row()
        self.assertEqual(
            self.database.host_load(since=0, until=7200), {"observed": False}
        )

    def test_the_summary_reports_percent_once_it_has(self):
        self.host_row(cpu=250, busy=100)
        load = self.database.host_load(since=0, until=7200)
        self.assertTrue(load["observed"])
        self.assertEqual(load["cpu_avg"], 25.0)
        self.assertEqual(load["haproxy_busy_avg"], 10.0)


class EveryStoredColumnSurvivesTheRollup(unittest.TestCase):
    """The minute rows are deleted after a week; the hourly ones are the
    history. A column collected and charted but missing from the rollup
    lists would look perfect for seven days and then lose everything older
    -- silently, and only for that one metric. The lists are derived from
    the aggregation table for exactly that reason; this holds them to it.
    """

    def test_nothing_is_left_behind(self):
        covered = (
            set(metricsd._ROLLUP_SUM)
            | set(metricsd._ROLLUP_MAX)
            | set(metricsd._ROLLUP_WAVG)
        )
        forgotten = [
            column
            for column in metricsd.METRIC_COLUMNS
            if column != "samples" and column not in covered
        ]
        self.assertEqual(forgotten, [])

    def test_every_column_knows_how_it_aggregates(self):
        missing = [
            column
            for column in metricsd.METRIC_COLUMNS
            if column != "samples" and column not in metricsd._AGGREGATIONS
        ]
        self.assertEqual(missing, [])

    def test_the_load_actually_reaches_the_hourly_table(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = metricsd.MetricsDatabase(
            str(Path(temporary.name) / "metrics.db")
        )
        self.addCleanup(database.close)

        object_id = database.object_id(metricsd.HOST_KIND, "", "", 3600)
        for bucket in (3600, 3660):
            row = {column: 0 for column in metricsd.METRIC_COLUMNS}
            row.update(samples=1, cpu_avg=400, cpu_max=600)
            database.write_buckets(bucket, {object_id: row})

        database.rollup_hours(7200)
        connection = sqlite3.connect(str(database.path))
        try:
            row = connection.execute(
                "SELECT cpu_avg, cpu_max FROM metric_1h"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row, (400, 600))


class ANewColumnIsAddedToAnExistingDatabase(unittest.TestCase):
    """Upgrading must not cost the operator their history."""

    def test_a_table_missing_the_column_gets_it_without_losing_rows(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = str(Path(temporary.name) / "metrics.db")

        database = metricsd.MetricsDatabase(path)
        object_id = database.object_id("backend", "be_site", "", 0)
        row = {column: 0 for column in metricsd.METRIC_COLUMNS}
        row.update(samples=6, requests=99)
        database.write_buckets(3600, {object_id: row})
        database.close()

        # Put the table back the way a build without CPU columns left it.
        connection = sqlite3.connect(path)
        try:
            for column in (
                "cpu_avg", "cpu_max", "haproxy_busy_avg", "haproxy_busy_max",
            ):
                connection.execute(
                    f"ALTER TABLE metric_1m DROP COLUMN {column}"
                )
            connection.commit()
        except sqlite3.OperationalError:
            connection.close()
            self.skipTest("this sqlite cannot drop columns")
        else:
            connection.close()

        reopened = metricsd.MetricsDatabase(path)
        self.addCleanup(reopened.close)
        connection = sqlite3.connect(path)
        try:
            names = {
                str(entry[1])
                for entry in connection.execute("PRAGMA table_info(metric_1m)")
            }
            kept = connection.execute("SELECT requests FROM metric_1m").fetchone()
        finally:
            connection.close()
        self.assertIn("cpu_avg", names)
        self.assertEqual(kept[0], 99)

    def test_reopening_a_current_database_adds_nothing(self):
        # The ensure runs on every open, so it has to be a no-op the second
        # time rather than an error about a duplicate column.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = str(Path(temporary.name) / "metrics.db")
        first = metricsd.MetricsDatabase(path)
        first.close()
        second = metricsd.MetricsDatabase(path)
        self.addCleanup(second.close)
        self.assertEqual(
            second.stats()["schema_version"], metricsd.SCHEMA_VERSION
        )


if __name__ == "__main__":
    unittest.main()
