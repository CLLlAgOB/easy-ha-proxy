"""One window admits stages; closing it never interrupts package recovery."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import stat
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer'))
import maintenance_window as windows  # noqa: E402
import os_upgrade_guard as guard  # noqa: E402

REVISION = 'a' * 32
IDENTITY = 'b' * 64


def settings(**extra):
    return {'auto_install': True, 'auto_install_unified': True, 'auto_install_runtime': True,
            'auto_install_os': True, 'auto_install_start': 1, 'auto_install_end': 2,
            'maintenance_revision': REVISION, 'maintenance_updated_at': 1, **extra}


class Windows(unittest.TestCase):
    def test_executor_lease_cannot_extend_the_saved_window_or_revive_revoked_consent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'os-security'
            file = Path(temporary) / 'settings.json'
            file.write_text(json.dumps(settings()))
            local = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
            deadline = local.replace(hour=2, minute=0).timestamp()
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_uid=0, st_size=100)), \
                 patch.object(guard.time, 'time', return_value=local.timestamp()):
                guard.runtime_consent(root, REVISION, deadline, local=local)
                with self.assertRaises(guard.UpgradeRefused):
                    guard.runtime_consent(root, REVISION, deadline+3600, local=local)
                with self.assertRaises(guard.UpgradeRefused):
                    guard.runtime_consent(root, REVISION, deadline, reserve=3600, local=local)
                file.write_text(json.dumps(settings(auto_install_runtime=False)))
                guard.runtime_consent(root, REVISION, deadline, require_runtime=False, local=local)
                with self.assertRaises(guard.UpgradeRefused):
                    guard.runtime_consent(root, REVISION, deadline, local=local)
                file.write_text(json.dumps(settings(auto_install=False)))
                with self.assertRaises(guard.UpgradeRefused):
                    guard.runtime_consent(root, REVISION, deadline, local=local)

    def test_exact_end_is_closed_and_cross_midnight_is_one_window(self):
        value = windows.policy(settings())
        now = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
        self.assertIsNotNone(windows.current(value, now))
        self.assertIsNone(windows.current(value, now.replace(hour=2, minute=0)))
        value.update(start=23, end=2)
        self.assertEqual(windows.current(value, now)['key'], '2026-11-14')
        self.assertEqual(windows.current(value, now.replace(day=14, hour=23))['key'], '2026-11-14')

    def test_a_new_consent_waits_for_the_next_full_window_and_disabled_means_no_admission(self):
        now = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
        value = windows.policy(settings(maintenance_updated_at=now.timestamp()))
        self.assertIsNone(windows.current(value, now))
        self.assertIsNotNone(windows.current(value, now + dt.timedelta(days=1)))
        value['enabled'] = False
        self.assertIsNone(windows.current(value, now + dt.timedelta(days=1)))

    def test_both_repeated_DST_hours_belong_to_a_single_window(self):
        value = windows.policy(settings(auto_install_start=1, auto_install_end=3))
        zone = ZoneInfo('Europe/Warsaw')
        first = dt.datetime(2026, 10, 25, 2, 30, tzinfo=zone, fold=0)
        second = first.replace(fold=1)
        self.assertEqual(windows.current(value, first), windows.current(value, second))

    def test_native_stage_rejects_a_revoked_or_replaced_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'os-security'
            file = root.parent / 'settings.json'
            local = dt.datetime(2026, 11, 15, 1, 30, tzinfo=dt.timezone.utc)
            reader = lambda path: json.loads(path.read_text())
            file.write_text(json.dumps(settings()))
            windows.require(root, reader, REVISION, local)
            for raw in (settings(auto_install=False), settings(maintenance_revision='c'*32),
                        settings(auto_install_unified=False)):
                file.write_text(json.dumps(raw))
                with self.assertRaisesRegex(ValueError, 'window has closed'):
                    windows.require(root, reader, REVISION, local)


@unittest.skipUnless(sys.platform == 'linux', 'Linux host broker')
class Coordinator(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('unified_maintenance_broker', ROOT / 'ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py')
        self.b = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.b
        spec.loader.exec_module(self.b)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.current = dt.datetime(2026, 11, 15, 1, 5, tzinfo=dt.timezone.utc)
        self.raw = settings()
        self.events = []
        self.addCleanup(patch.stopall)
        patch.object(self.b, 'STATE_ROOT', self.root).start()
        patch.object(self.b, 'OS_SECURITY_ROOT', self.root / 'os-security').start()
        patch.object(self.b, 'ACTIVE_MARKER', self.root / 'active').start()
        patch.object(self.b, 'read_settings', side_effect=lambda: dict(self.raw)).start()
        patch.object(self.b, 'maintenance_module', return_value=windows).start()
        patch.object(self.b, 'safe_json_file', side_effect=lambda path: json.loads(path.read_text())).start()
        patch.object(self.b, 'atomic_json', side_effect=lambda path, value: path.write_text(json.dumps(value))).start()
        patch.object(self.b, 'os_security_local_time', side_effect=lambda: self.current).start()
        patch.object(self.b, 'reboot_guard_present', return_value=False).start()
        patch.object(self.b, 'request_self_restart_if_needed').start()
        patch.object(self.b, 'record_auto_install').start()
        self.alert = patch.object(self.b, 'report_alert').start()
        self.updates = patch.object(self.b, 'auto_install_once', side_effect=self.update).start()
        self.actual_security = self.b.unified_security_stage
        self.security = patch.object(self.b, 'unified_security_stage', side_effect=lambda stage: self.events.append(stage)).start()
        patch.object(self.b, 'auto_check_once', side_effect=lambda: self.events.append('check-haproxy') or 'done').start()
        patch.object(self.b, 'load_latest_plan', return_value={'components': []}).start()
        self.actual_reboot = self.b.unified_reboot
        self.reboot = patch.object(self.b, 'unified_reboot', side_effect=lambda *_: self.events.append('reboot') or 'completed').start()

    def update(self):
        self.events.append('updates')
        return 'installed'

    def test_order_includes_application_and_only_one_cycle_survives_broker_restarts(self):
        self.assertEqual(self.b.unified_maintenance_tick(), 'completed')
        self.assertEqual(self.events, ['updates', 'install', 'check-haproxy', 'restart', 'reboot'])
        self.assertIsNone(self.b.unified_maintenance_tick())
        self.assertEqual(self.updates.call_count, 1)
        self.b.AUTO_INSTALL_STATE['night'] = None
        self.assertIsNone(self.b.unified_maintenance_tick())

    def test_overrun_finishes_the_current_stage_and_defers_all_new_mutations(self):
        def long_install():
            self.events.append('updates-completed')
            self.current = self.current.replace(hour=2, minute=5)
            return 'installed'
        self.updates.side_effect = long_install
        self.assertEqual(self.b.unified_maintenance_tick(), 'deferred')
        self.assertEqual(self.events, ['updates-completed'])
        self.security.assert_not_called()
        self.reboot.assert_not_called()

    def test_revocation_stops_new_stages_and_failures_do_not_start_reboot(self):
        def revoke():
            self.raw['auto_install'] = False
            return 'installed'
        self.updates.side_effect = revoke
        self.assertEqual(self.b.unified_maintenance_tick(), 'deferred')
        self.reboot.assert_not_called()
        self.raw['auto_install'] = True
        self.current += dt.timedelta(days=1)
        self.updates.side_effect = self.update
        self.security.side_effect = RuntimeError('package failure')
        self.assertEqual(self.b.unified_maintenance_tick(), 'failed')
        self.alert.assert_called_once()
        self.reboot.assert_not_called()

    def test_interrupted_cycle_is_reported_without_repeating_installation(self):
        (self.root / 'maintenance-cycle.json').write_text(json.dumps({'night':'2026-11-15', 'revision':REVISION, 'outcome':'running'}))
        self.assertIsNone(self.b.unified_maintenance_tick())
        self.alert.assert_called_once()
        self.updates.assert_not_called()

    def test_not_enough_time_for_the_countdown_defers_reboot_without_a_timer(self):
        value = windows.policy(self.raw)
        with patch.object(self.b.time, 'time', return_value=100), patch.object(self.b, 'request_reboot') as request:
            self.assertEqual(self.actual_reboot(value, {'closes_at':130}), 'deferred')
        request.assert_not_called()

    def test_native_stage_receives_the_common_revision_and_cannot_start_after_closing(self):
        with patch.object(self.b, 'acquire_operation', return_value=42), \
             patch.object(self.b, 'release_operation') as release, \
             patch.object(self.b, 'new_job', return_value={'id':'job'}), \
             patch.object(self.b, 'load_job', return_value={'status':'completed'}), \
             patch.object(self.b, 'os_security_worker') as worker:
            self.actual_security('install')
            worker.assert_called_once_with('job', 42, 'install', maintenance_revision=REVISION)
            self.current = self.current.replace(hour=2)
            with self.assertRaises(self.b.UpdatedError) as error:
                self.actual_security('restart')
            self.assertEqual(error.exception.code, 'window_closed')
            self.assertEqual(worker.call_count, 1)
            release.assert_called_once_with(42)

    def test_pending_runtime_recovery_blocks_the_entire_new_cycle(self):
        self.b.OS_SECURITY_ROOT.mkdir()
        (self.b.OS_SECURITY_ROOT / 'runtime-maintenance.json').write_text('{"phase":"recovery_required"}')
        self.assertEqual(self.b.unified_maintenance_tick(), 'failed')
        self.updates.assert_not_called()
        self.reboot.assert_not_called()

    def test_common_options_are_explicit_and_older_pages_keep_saved_consent(self):
        self.raw['auto_install_unified'] = False
        path = self.root / 'settings.json'
        patch.object(self.b, 'SETTINGS_PATH', path).start()
        patch.object(self.b, 'settings_payload', return_value={}).start()
        request = {'enabled':True, 'start':1, 'end':2, 'unified':True, 'runtime':True}
        with patch.object(self.b, 'os_security_snapshot', return_value={'policy':{'mode':'system'}}):
            with self.assertRaises(self.b.UpdatedError):
                self.b.set_auto_install(request)
        self.assertFalse(path.exists())
        with patch.object(self.b, 'os_security_snapshot', return_value={'policy':{'mode':'notify'}}):
            self.b.set_auto_install(request)
            self.raw = json.loads(path.read_text())
            self.b.set_auto_install({'enabled':True, 'start':2, 'end':3})
        saved = json.loads(path.read_text())
        self.assertTrue(saved['auto_install_unified'])
        self.assertTrue(saved['auto_install_runtime'])
        self.assertEqual(saved['auto_install_start'], 2)


@unittest.skipUnless(sys.platform == 'linux', 'Linux runtime maintenance journal')
class RuntimeMaintenance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'os-security'
        self.events = []
        self.simulation = 'Inst docker-ce [5:28.5.1] (5:29.0.0 repository [amd64])\n'
        self.containers = [{'id':IDENTITY, 'status':'running', 'paused':False, 'health':'healthy'}]
        self.addCleanup(patch.stopall)
        self.consent = patch.object(guard, 'runtime_consent').start()
        patch.object(guard, 'RUNTIME_CONFIG_FILES', ()).start()
        patch.object(guard, 'running_containers', return_value=self.containers).start()
        self.restore = patch.object(guard, 'restore_containers', side_effect=lambda items: self.events.append(('restore', items))).start()
        self.run = patch.object(guard, 'run', side_effect=self.command).start()
        self.upgrade = patch.object(guard, 'run_upgrade', side_effect=self.apt).start()

    def command(self, argv):
        if argv[0].endswith('dpkg'):
            return 'haproxy\thold\n'
        if argv[0].endswith('apt-get'):
            return self.simulation
        if 'info' in argv:
            return 'true\n' if '{{.LiveRestoreEnabled}}' in argv else 'inactive\n'
        if 'stop' in argv:
            self.events.append(('stop', argv))
        return ''

    def apt(self, argv):
        self.events.append(('download' if '--download-only' in argv else 'install', argv))

    def test_release_upgrade_downloads_before_downtime_and_restores_the_original_set(self):
        guard.perform_maintenance(self.root, REVISION, 123456)
        self.assertEqual([event[0] for event in self.events], ['download', 'stop', 'install', 'restore'])
        self.restore.assert_called_once_with(self.containers)
        record = json.loads((self.root / 'runtime-maintenance.json').read_text())
        self.assertEqual(record['phase'], 'completed')
        self.assertTrue(record['restored'])

    def test_window_without_runtime_consent_keeps_patch_only_policy(self):
        with self.assertRaisesRegex(guard.UpgradeRefused, 'manual review'):
            guard.perform_maintenance(self.root, REVISION, 123456, allow_runtime_change=False)
        self.upgrade.assert_not_called()
        self.simulation = self.simulation.replace('29.0.0', '28.5.2')
        guard.perform_maintenance(self.root, REVISION, 123456, allow_runtime_change=False)
        self.assertEqual([event[0] for event in self.events], ['download', 'install', 'restore'])
        self.assertTrue(all(call.kwargs.get('require_runtime') is False for call in self.consent.call_args_list))

    def test_install_failure_still_restores_and_requires_review_before_retry(self):
        def fail(argv):
            self.apt(argv)
            if '--download-only' not in argv:
                raise guard.UpgradeRefused('package failure')
        self.upgrade.side_effect = fail
        with self.assertRaisesRegex(guard.UpgradeRefused, 'package failure'):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.restore.assert_called_once_with(self.containers)
        with self.assertRaisesRegex(guard.UpgradeRefused, 'requires recovery'):
            guard.perform_maintenance(self.root, REVISION, 123456)

    def test_closed_window_before_installation_restores_without_installing(self):
        self.consent.side_effect = [None, None, guard.UpgradeRefused('window closed')]
        with self.assertRaisesRegex(guard.UpgradeRefused, 'window closed'):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.assertEqual([event[0] for event in self.events], ['download', 'stop', 'restore'])

    def test_download_failure_or_changed_candidates_never_stops_containers(self):
        self.upgrade.side_effect = guard.UpgradeRefused('download failed')
        with self.assertRaises(guard.UpgradeRefused):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.assertFalse(any(event[0] == 'stop' for event in self.events))
        self.upgrade.side_effect = self.apt
        seen = [0]
        original = self.command
        def changed(argv):
            if argv[0].endswith('apt-get'):
                seen[0] += 1
                if seen[0] == 2:
                    return self.simulation.replace('29.0.0', '29.0.1')
            return original(argv)
        self.run.side_effect = changed
        with self.assertRaisesRegex(guard.UpgradeRefused, 'candidates changed'):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.assertFalse(any(event[0] == 'stop' for event in self.events))

    def test_failed_restoration_is_durable_and_never_reported_as_success(self):
        self.restore.side_effect = RuntimeError('Docker did not return')
        with self.assertRaisesRegex(guard.UpgradeRefused, 'Docker did not return'):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.assertEqual(json.loads((self.root / 'runtime-maintenance.json').read_text())['phase'], 'recovery_required')

    def test_manual_recovery_respects_shared_custody_and_never_installs_packages(self):
        import fcntl
        self.root.mkdir()
        journal = self.root / 'runtime-maintenance.json'
        journal.write_text(json.dumps({'phase':'recovery_required', 'containers':self.containers}))
        lock = self.root / 'maintenance.lock'
        package_lock = self.root / 'dpkg.lock'
        package_lock.touch()
        with patch.object(guard, 'MAINTENANCE_LOCK', lock), patch.object(guard, 'DPKG_FRONTEND_LOCK', package_lock):
            with lock.open('w') as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                with self.assertRaisesRegex(guard.UpgradeRefused, 'Another maintenance'):
                    guard.recover_runtime(self.root)
                self.restore.assert_not_called()
            guard.recover_runtime(self.root)
        self.restore.assert_called_once_with(self.containers)
        self.upgrade.assert_not_called()
        self.assertEqual(json.loads(journal.read_text())['phase'], 'recovered')

    def test_restore_starts_only_previously_running_containers_and_waits_for_health(self):
        # Use the original implementation captured from the module source.
        spec = importlib.util.spec_from_file_location('runtime_restore_test', ROOT / 'installer/os_upgrade_guard.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        current = {**self.containers[0], 'status':'exited'}
        starting = {**self.containers[0], 'health':'starting'}
        with patch.object(module, 'container_state', side_effect=[current, starting, self.containers[0]]), \
             patch.object(module, 'run') as run, patch.object(module.time, 'sleep'), \
             patch.object(module.time, 'monotonic', side_effect=[0, 1]):
            module.restore_containers(self.containers)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/usr/bin/systemctl','start','docker.service'], ['/usr/bin/docker','start',IDENTITY]])


if __name__ == '__main__':
    unittest.main()
