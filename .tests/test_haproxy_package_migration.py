"""Fail-closed boundaries of the explicit package migration, without host edits."""
from __future__ import annotations

import importlib.util
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

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
    def test_combined_transition_holds_the_actual_lock_across_refresh_prepare_and_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'maintenance.lock'
            engine = m.Engine(m.Paths(lock=lock_path, source=ROOT), host=Mock(spec=m.Host))
            actual_fstat = os.fstat
            def root_owned(descriptor):
                metadata = list(actual_fstat(descriptor)); metadata[4] = 0
                return os.stat_result(metadata)
            calls = []
            def assert_locked(stage):
                with lock_path.open('a') as other:
                    with self.assertRaises(BlockingIOError):
                        m.fcntl.flock(other.fileno(), m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
                calls.append(stage)
            engine.host.command.side_effect = lambda *a, **k: (assert_locked('refresh') or Mock(stdout='{"fresh":true}'))
            with patch.object(m.os, 'fstat', side_effect=root_owned), \
                    patch.object(engine, 'prepare', side_effect=lambda: (assert_locked('prepare') or {'id': 'a'*32})), \
                    patch.object(engine, 'apply', side_effect=lambda identifier, **kwargs: (assert_locked('apply') or {'id': identifier, 'phase': 'committed'})) as apply:
                result = engine.migrate()
            self.assertEqual(calls, ['refresh', 'prepare', 'apply'])
            self.assertEqual(result['phase'], 'committed')
            apply.assert_called_once_with('a'*32, exercise_rollback=False)
            self.assertEqual(engine.host.command.call_args.args[0][-1], 'refresh')

    def test_failed_metadata_refresh_does_not_prepare_or_switch_the_running_service(self):
        engine = m.Engine(host=Mock(spec=m.Host))
        engine.host.command.return_value = Mock(stdout='{"fresh":false}')
        with patch.object(engine, 'locked', contextlib.nullcontext), patch.object(engine, 'prepare') as prepare, patch.object(engine, 'apply') as apply:
            with self.assertRaisesRegex(m.MigrationError, 'metadata refresh failed'):
                engine.migrate()
        prepare.assert_not_called(); apply.assert_not_called()

    def test_historical_master_socket_launch_is_qualified_without_allowing_arbitrary_exec(self):
        command = '/usr/sbin/haproxy -Ws -S /run/haproxy/master.sock,mode,660,user,root,group,haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid'
        text = '[Service]\nExecStart=\nExecStart=' + command + '\n'
        self.assertTrue(m.qualified_service_dropin(text, Path('/etc/haproxy/haproxy.cfg')))
        self.assertTrue(m.qualified_service_dropin(text.replace(' -S ', ' \\\n    -S '), Path('/etc/haproxy/haproxy.cfg')))
        for changed in (text.replace('660', '666'), text.replace('-Ws', '-W'), text.replace('/usr/sbin/haproxy', '/bin/sh'),
                        text.replace('/etc/haproxy/haproxy.cfg', '$CONFIG'), text + 'ExecStartPre=/bin/true\n',
                        text + 'User=another-user\n', text.replace('[Service]', '[Unit]'), text.replace('ExecStart=\n', '')):
            with self.subTest(changed=changed):
                self.assertFalse(m.qualified_service_dropin(changed, Path('/etc/haproxy/haproxy.cfg')))

    def test_service_override_drift_refuses_apply_before_arming_recovery(self):
        engine = m.Engine(host=Mock(spec=m.Host))
        engine.state = {'service_dropins': {'override.conf': 'original'}}
        with patch.object(engine, 'inspect_service_dropins', return_value={'override.conf': 'changed'}):
            with self.assertRaisesRegex(m.MigrationError, 'changed after preparation'):
                engine.unchanged_service_dropins()
        engine.host.command.assert_not_called()

    def test_only_the_fixed_state_start_guard_is_qualified(self):
        text = '[Service]\nExecStartPre=-/usr/local/sbin/haproxy-state-dump\n'
        self.assertTrue(m.qualified_service_dropin(text, Path('/etc/haproxy/haproxy.cfg')))
        for changed in (text.replace('haproxy-state-dump', 'another-script'), text + 'User=other\n',
                        text.replace('[Service]', '[Unit]'), text.replace('dump\n', 'dump --other\n')):
            with self.subTest(changed=changed):
                self.assertFalse(m.qualified_service_dropin(changed, Path('/etc/haproxy/haproxy.cfg')))

    def test_migration_and_rollback_normalize_even_a_legacy_raw_snapshot(self):
        from haproxy_server_state import FIELDS, OPTIONAL
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'haproxy.cfg'
            state = Path(directory) / 'state'
            config.write_text('backend target\n server main new.example.test:1026 check\n')
            engine = m.Engine(m.Paths(config=config, server_state=state), host=Mock(spec=m.Host))
            engine.state = {'files': {str(state): {}}, 'server_state':
                '1\n# ' + ' '.join(FIELDS + OPTIONAL) + '\n'
                '36 target 1 main 127.0.0.1 2 8 17 100 10 15 3 4 6 0 0 0 old.example.test 1025 - 0 0 - - 0\n'}
            with patch.object(m, 'atomic') as write:
                engine.store_servers()
            row = dict(zip(FIELDS, write.call_args.args[1].decode().splitlines()[2].split(), strict=True))
            self.assertEqual((row['srv_addr'], row['srv_fqdn'], row['srv_port']), ('-', 'new.example.test', '1026'))
            self.assertEqual((row['srv_admin_state'], row['srv_uweight']), ('8', '17'))

    def test_saved_recovery_command_is_self_contained_and_normalizer_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = m.Engine(host=Mock(spec=m.Host))
            engine.directory = root
            engine.state = {'engine_digest': m.digest(Path(m.__file__)),
                            'normalizer_digest': m.digest(m.STATE_NORMALIZER_SOURCE)}
            with patch.object(m, 'atomic', side_effect=lambda path, data, _mode: path.write_bytes(data)):
                engine.store_recovery_commands()
            result = subprocess.run([sys.executable, str(root / 'recover.py'), '--help'],
                cwd=root, env={**os.environ, 'PYTHONPATH': ''}, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / 'haproxy_server_state.py').write_text('tampered\n')
            with self.assertRaisesRegex(m.MigrationError, 'normalizer integrity'):
                engine.check_artifacts()

    def test_web_summary_is_durable_without_private_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = m.Engine(m.Paths(root=root))
            engine.directory = root / ('a' * 32)
            engine.state = {'id': 'a' * 32, 'kind': 'migration', 'created_at': time.time(),
                            'old_version': '2.8.30-1', 'target_runtime_version': '3.4.7',
                            'files': {'private-config': {'data': 'PRIVATE_CONFIGURATION_VALUE'}}}
            # The test runs without root; file contents and mode use the real
            # atomic writer, without changing ownership on the test machine.
            with patch.object(m.os, 'fchown'):
                engine.save('prepared')
                published = json.loads((root / 'last-migration.json').read_text())
                self.assertEqual(published['phase'], 'prepared')
                self.assertEqual(published['target_runtime_version'], '3.4.7')
                self.assertNotIn('PRIVATE_CONFIGURATION_VALUE', json.dumps(published))
                engine.state['target_verified'] = True
                engine.save('committed')
            self.assertTrue(json.loads((root / 'last-migration.json').read_text())['target_verified'])

    def test_manual_rollback_cannot_discard_a_later_package_revision_with_same_runtime_version(self):
        engine = m.Engine(host=Mock(spec=m.Host))
        engine.state = {'target_packages': [{'Package': 'haproxy-awslc', 'Version': '3.4.8-1'}]}
        engine.host.packages.return_value = {'haproxy-awslc': '3.4.8-2'}
        with self.assertRaisesRegex(m.MigrationError, 'target packages changed'):
            engine.committed_unchanged()
        engine.host.command.assert_not_called()

    def test_new_patch_cannot_overwrite_unfinished_recovery_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('last-update.json', 'last-migration.json'):
                previous = root / name
                previous.write_text('{"id":"' + 'a' * 32 + '","phase":"rollback_failed"}')
                for action in ('patch', 'migration'):
                    engine = m.Engine(m.Paths(root=root))
                    with self.subTest(name=name, action=action), patch.object(engine, 'locked', contextlib.nullcontext), patch.object(engine, 'native_preflight') as preflight:
                        with self.assertRaisesRegex(m.MigrationError, 'unfinished HAProxy update'):
                            engine.prepare_patch('3.4.8-1') if action == 'patch' else engine.prepare()
                        preflight.assert_not_called()
                previous.unlink()

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

    def test_ui_change_during_quiescence_is_preserved_before_any_package_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = m.Paths(**{name: root / name for name in
                              ('config', 'variables', 'policy', 'repository', 'priorities', 'signing_key', 'binary')})
            files = {}
            for path in (paths.config, paths.variables, paths.policy, paths.repository, paths.priorities, paths.signing_key, paths.binary):
                path.write_bytes(b'baseline')
                files[str(path)] = {'exists': True, 'digest': m.digest(path)}
            host = Mock(spec=m.Host)
            host.active.return_value = False
            engine = m.Engine(paths, host)
            engine.directory = root
            engine.state = {'id': 'a' * 32, 'phase': 'prepared', 'files': files, 'old_version': '2.8',
                            'old_binary_digest': m.digest(paths.binary), 'extra_baseline': {}, 'tls_baseline': None}

            def save(phase=None):
                if phase:
                    engine.state['phase'] = phase

            with patch.object(engine, 'locked', contextlib.nullcontext), patch.object(engine, 'load'), \
                    patch.object(engine, 'check_artifacts'), patch.object(engine, 'native_preflight', return_value=('amd64', {'haproxy': '2.8'})), \
                    patch.object(engine, 'health'), patch.object(engine, 'arm'), patch.object(engine, 'save', side_effect=save), \
                    patch.object(engine, 'pause', side_effect=lambda: paths.config.write_bytes(b'new UI configuration')), \
                    patch.object(engine, 'snapshot') as snapshot, patch.object(engine, 'resume'):
                with self.assertRaisesRegex(m.MigrationError, 'aborted before the package switch'):
                    engine.apply('a' * 32)
                self.assertEqual(paths.config.read_bytes(), b'new UI configuration')
                self.assertEqual(engine.state['phase'], 'aborted')
                snapshot.assert_not_called()
                host.command.assert_not_called()

    def test_aborting_an_unstarted_downgrade_does_not_restore_over_a_ui_change(self):
        engine = m.Engine()
        engine.state = {'config_modified': False}
        with patch.object(engine, 'restore') as restore, patch.object(engine, 'reload') as reload, \
                patch.object(engine, 'finish') as finish:
            engine.abort_downgrade()
            restore.assert_not_called()
            reload.assert_not_called()
            finish.assert_called_once_with('committed')

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
