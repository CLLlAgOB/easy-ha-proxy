"""Explicit host time, read-only native timer discovery and cache freshness."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


clock = load('server_time_test', 'docker/app/haproxy_admin/server_time.py')
timers = load('timer_metadata_test', 'installer/timer_metadata.py')


class ServerTime(unittest.TestCase):
    def test_host_zone_wins_over_container_zone_and_formats_utc_instants(self):
        with patch.dict(os.environ, EHP_SERVER_TIMEZONE='Europe/Moscow', TZ='Europe/Warsaw'):
            self.assertEqual(clock.format_datetime('2026-11-07T00:20:25Z'), '2026-11-07 03:20 MSK')
            self.assertEqual(clock.context()['offset'], 'UTC+03:00')
            self.assertEqual(clock.context()['zone'], 'Europe/Moscow')

    def test_old_container_zone_is_a_rolling_upgrade_fallback(self):
        with patch.dict(os.environ, {'TZ': 'Europe/Warsaw'}, clear=True):
            self.assertEqual(clock.format_datetime('2026-11-07T00:20:25+00:00'), '2026-11-07 01:20 CET')

    def test_missing_or_invalid_zone_has_a_named_utc_fallback(self):
        for zone in ('', '../invalid'):
            with patch.dict(os.environ, {'EHP_SERVER_TIMEZONE': zone}, clear=True):
                self.assertEqual(clock.context()['zone'], 'UTC')
        self.assertEqual(clock.format_datetime('unknown'), '')


class NativeTimers(unittest.TestCase):
    def test_epoch_from_dbus_preserves_the_actual_randomized_next_run(self):
        props = ('ActiveState=active\nNextElapseUSecRealtime=Sun 2026-11-08 03:39:53 MSK\n'
                 'RandomizedDelayUSec=20min\nTimersCalendar={ OnCalendar=*-*-* 03:20:00 ; next_elapse=tomorrow }\n')
        with patch.object(timers, 'run', side_effect=[props, 't 1794098393515829']) as run:
            value = timers.timer('example-backup.timer')
        self.assertAlmostEqual(value['next_run_at'], 1794098393.515829)
        self.assertEqual(value['random_delay_seconds'], 1200)
        self.assertEqual(value['calendar'], ['*-*-* 03:20:00 '])
        self.assertIn('example_2dbackup_2etimer', run.call_args.args[0][3])

    def test_inactive_timer_does_not_report_a_scheduled_backup(self):
        with patch.object(timers, 'run', return_value='ActiveState=inactive\nNextElapseUSecRealtime=tomorrow') as run:
            value = timers.timer('example.timer')
        self.assertIsNone(value['next_run_at'])
        self.assertEqual(value['next_run'], '')
        self.assertEqual(run.call_count, 1)

    def test_other_backup_timers_are_discovered_without_installation_names(self):
        listed = '\n'.join([timers.MAIN_BACKUP_TIMER, 'dpkg-db-backup.timer', 'example-backup.timer', 'stopped-backup.timer'])
        def timer(name): return {'unit': name, 'active': name != 'stopped-backup.timer'}
        with patch.object(timers, 'run', return_value=listed), patch.object(timers, 'timer', side_effect=timer):
            self.assertEqual(timers.backups()['other_timers'], [{'unit': 'example-backup.timer', 'active': True}])

    def test_metadata_reads_never_enable_restart_or_modify_units(self):
        with patch.object(timers, 'run', return_value='') as run:
            timers.backups()
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ['show', 'list-units'])
        with self.assertRaises(ValueError): timers.timer('x;reboot.timer')
        for text, expected in [('1h 20min', 4800), ('500ms', .5), ('0', 0), ('unknown', None)]:
            self.assertEqual(timers.duration_seconds(text), expected)


class BackupMetadataCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = load('backupd_time_metadata_test', 'ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py')

    def test_polling_reuses_metadata_and_a_schedule_change_invalidates_it(self):
        b = self.broker
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'installer').mkdir(); (root / 'installer/timer_metadata.py').touch()
            metadata = json.dumps({'protocol': 1, 'timer': {'next_run_at': 123}, 'other_timers': [], 'checked_at': 12})
            def result(args, **kwargs):
                return SimpleNamespace(returncode=0, stdout=metadata if 'python3' in args[0] else '', stderr=b'')
            b._SCHEDULE_TIMER_CACHE.clear()
            with patch.object(b, 'SOURCE_DIR', root), patch.object(b, 'TIMER_DROPIN_DIR', root / 'timer'), \
                    patch.object(b, 'TIMER_DROPIN_PATH', root / 'timer/schedule.conf'), patch.object(b.subprocess, 'run', side_effect=result) as run:
                self.assertEqual(b.schedule_timer_metadata()['timer']['next_run_at'], 123)
                b.schedule_timer_metadata()
                self.assertEqual(run.call_count, 1)
                b.write_timer_time('03:20')
                self.assertEqual(b._SCHEDULE_TIMER_CACHE, {})
                b.schedule_timer_metadata()
                self.assertEqual(run.call_count, 4)

    def test_a_disabled_schedule_keeps_other_linux_timers_visible(self):
        b = self.broker
        with patch.object(b, 'load_schedule', return_value={'enabled': False}), patch.object(b, 'schedule_timer_metadata', return_value={'other_timers': [{'unit': 'example-backup.timer'}]}):
            value = b.schedule_status({})['schedule']
        self.assertFalse(value['enabled'])
        self.assertEqual(value['other_timers'][0]['unit'], 'example-backup.timer')
