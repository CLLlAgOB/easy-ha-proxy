"""Fail-closed boundaries of the explicit package migration, without host edits."""
from __future__ import annotations

import importlib.util
import contextlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if sys.platform == 'linux':
    spec = importlib.util.spec_from_file_location('migration_under_test', ROOT / 'installer/haproxy_package_migrate.py')
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
else:
    m = None

CONFIG = '''global
    localpeer ha-local
peers bancluster
    peer ha-local 127.0.0.1:10240
backend tbl_ban
    stick-table type ip size 200k expire 168h store gpc0,gpt0 peers bancluster
backend tbl_ip_auth
    stick-table type ip size 200k expire 9h store gpc0 peers bancluster
'''


@unittest.skipUnless(m, 'Linux migration command')
class Boundaries(unittest.TestCase):
    def test_only_known_single_node_peers_can_be_changed(self):
        layout = m.peer_layout(CONFIG)
        self.assertEqual(set(layout['tables']), {'tbl_ban', 'tbl_ip_auth'})
        for text in [CONFIG.replace('127.0.0.1', '192.0.2.1'),
                     CONFIG.replace('backend tbl_ban', '    peer other 127.0.0.1:10241\nbackend tbl_ban'),
                     CONFIG.replace('store gpc0,gpt0', 'store gpc0'),
                     CONFIG.replace('type ip', 'type ipv6'), CONFIG.replace('localpeer ha-local', 'localpeer other')]:
            with self.subTest(text=text), self.assertRaises(m.MigrationError):
                m.peer_layout(text)

    def test_seed_does_not_change_the_original_table_definitions(self):
        layout = m.peer_layout(CONFIG)
        candidate = m.add_seed(CONFIG, layout, 'migration-test', 12345)
        self.assertEqual(candidate.replace('    peer migration-test 127.0.0.1:12345\n', ''), CONFIG)
        seed = m.seed_config(layout, 'migration-test', 12345, Path('/private/seed.sock'))
        for declaration in layout['tables'].values():
            self.assertIn(declaration, seed)

    def test_apt_refuses_any_unrelated_install_remove_or_configure(self):
        for prefix in ['Inst', 'Remv', 'Conf']:
            with self.subTest(prefix=prefix), self.assertRaises(m.MigrationError):
                m.parse_apt_plan(prefix + ' libc6:arm64 (2.40)', {'haproxy'})
        self.assertEqual(m.parse_apt_plan('Remv haproxy [2.8]\nInst haproxy-awslc:arm64 (3.4)',
                                         {'haproxy', 'haproxy-awslc'}), {'haproxy', 'haproxy-awslc'})

    def test_preparation_cannot_be_applied_by_changed_migration_code(self):
        engine = m.Engine()
        engine.state = {'engine_digest': '0' * 64}
        with self.assertRaisesRegex(m.MigrationError, 'implementation changed'):
            engine.check_artifacts()

    def test_runtime_rejects_missing_table_wrong_type_or_missing_reason(self):
        for response in [[], ['Unknown table'], ['# table: tbl_ban, type: ipv6, size:10'],
                         ['# table: tbl_ban, type: ip, size:10', 'key=198.51.100.22 exp=1000 gpc0=1']]:
            with self.subTest(response=response), patch.object(m, 'lines_from_socket', return_value=iter(response)):
                with self.assertRaises(m.MigrationError):
                    list(m.table_rows(Path('/unused'), 'tbl_ban'))

    def compare(self, old, new, *, elapsed=5):
        tables = {'tbl_ban': '', 'tbl_ip_auth': ''}
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / 'tables.sqlite'
            with patch.object(m.time, 'time', return_value=100), patch.object(m, 'table_rows', side_effect=lambda _, table: iter(old.get(table, []))):
                m.snapshot_tables(Path('/unused'), snapshot, tables)
            with patch.object(m.time, 'time', return_value=100 + elapsed), patch.object(m, 'table_rows', side_effect=lambda _, table: iter(new.get(table, []))):
                return m.verify_tables(Path('/unused'), snapshot, tables)

    def test_expiries_are_preserved_instead_of_reset(self):
        entry = ('198.51.100.22', 30000, {'gpc0': 1, 'gpt0': 40})
        self.compare({'tbl_ban': [entry]}, {'tbl_ban': [(entry[0], 25000, entry[2])]})
        with self.assertRaisesRegex(m.MigrationError, 'extended=1'):
            self.compare({'tbl_ban': [entry]}, {'tbl_ban': [entry]})

    def test_missing_ban_changed_reason_and_lost_counter_are_rejected(self):
        old = {'tbl_ban': [('198.51.100.22', 30000, {'gpc0': 3, 'gpt0': 40})]}
        for new in [{}, {'tbl_ban': [('198.51.100.22', 25000, {'gpc0': 3, 'gpt0': 41})]},
                    {'tbl_ban': [('198.51.100.22', 25000, {'gpc0': 2, 'gpt0': 40})]}]:
            with self.subTest(new=new), self.assertRaises(m.MigrationError):
                self.compare(old, new)

    def test_natural_expiry_and_legitimate_auth_renewal_are_allowed(self):
        self.compare({'tbl_ban': [('198.51.100.22', 3000, {'gpc0': 1, 'gpt0': 40})]}, {})
        self.compare({'tbl_ip_auth': [('198.51.100.22', 30000, {'gpc0': 7})]},
                     {'tbl_ip_auth': [('198.51.100.22', 30000, {'gpc0': 8})]})
        with self.assertRaisesRegex(m.MigrationError, 'extended=1'):
            self.compare({'tbl_ip_auth': [('198.51.100.22', 30000, {'gpc0': 7})]},
                         {'tbl_ip_auth': [('198.51.100.22', 30000, {'gpc0': 7})]})

    def test_atomic_restore_refuses_external_changes_and_preserves_permissions(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned file qualification')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = m.Engine()
            engine.directory = root
            engine.state = {'files': {}}
            path = root / 'managed'
            m.atomic(path, b'original', 0o640)
            engine.backup(path)
            engine.put(path, b'owned replacement', 0o600)
            engine.restore(path)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            path.write_bytes(b'foreign edit')
            with self.assertRaisesRegex(m.MigrationError, 'outside'):
                engine.restore(path)

    def test_watchdog_recovery_does_not_undo_a_committed_migration(self):
        class Host:
            def __init__(self):
                self.cancelled = False

            def command(self, *args, **kwargs):
                pass

            def cancel_watchdog(self, unit):
                self.cancelled = True

        engine = m.Engine(host=Host())
        engine.state = {'id': 'a' * 32, 'phase': 'committed'}
        with patch.object(engine, 'locked', contextlib.nullcontext), patch.object(engine, 'load'), \
                patch.object(engine, 'resume'), patch.object(engine, 'rollback_locked') as rollback:
            self.assertEqual(engine.recover('a' * 32)['phase'], 'committed')
            rollback.assert_not_called()
            self.assertTrue(engine.host.cancelled)

    def test_reloading_same_version_must_wait_for_a_different_worker(self):
        engine = m.Engine()
        with patch.object(m, 'info', side_effect=[{'Version': '2.8.30', 'Pid': '10'},
                                                {'Version': '2.8.30', 'Pid': '11'}]) as read, \
                patch.object(engine.host, 'worker_digest', return_value='expected'), \
                patch.object(m, 'digest', return_value='expected'), patch.object(m.time, 'sleep'):
            self.assertEqual(engine.wait_worker('2.8.30', previous_worker='10')['Pid'], '11')
            self.assertEqual(read.call_count, 2)

    def test_interrupted_downgrade_without_a_ready_peer_keeps_the_committed_target(self):
        engine = m.Engine()
        engine.state = {'id': 'a' * 32, 'phase': 'bootstrapping_peer', 'operation': 'rollback', 'seed_ready': False}
        with patch.object(engine, 'locked', contextlib.nullcontext), patch.object(engine, 'load'), \
                patch.object(engine, 'save'), patch.object(engine, 'abort_downgrade') as abort, \
                patch.object(engine, 'rollback_locked') as rollback:
            engine.recover('a' * 32)
            abort.assert_called_once()
            rollback.assert_not_called()

    def test_persisted_guard_decisions_must_exist_with_the_same_reason_in_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = m.Engine()
            engine.directory = Path(directory)
            database = engine.directory / 'guard.sqlite'
            engine.state = {'guard_database': str(database)}
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE ip_state(ip TEXT, banned_until INTEGER)')
                connection.execute('CREATE TABLE manual_bans(ip TEXT, expires_at INTEGER)')
                connection.execute('INSERT INTO ip_state VALUES(?,?)', ('198.51.100.22', int(time.time()) + 60))
            for rows, accepted in [([], False), ([('198.51.100.22', 30000, {'gpc0': 1, 'gpt0': 50})], False),
                                   ([('198.51.100.22', 30000, {'gpc0': 1, 'gpt0': 40})], True)]:
                with patch.object(m, 'table_rows', return_value=iter(rows)):
                    m.snapshot_tables(Path('/unused'), engine.directory / 'tables.sqlite', {'tbl_ban': ''})
                if accepted:
                    engine.check_guard()
                else:
                    with self.assertRaisesRegex(m.MigrationError, 'Persisted guard decisions differ'):
                        engine.check_guard()


if __name__ == '__main__':
    unittest.main()
