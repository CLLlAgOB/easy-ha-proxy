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
        record = json.loads((self.root / 'runtime-maintenance.json').read_text())
        self.assertEqual(record['phase'], 'recovered')
        self.assertFalse(record['installation_started'])
        self.assertTrue(record['restored'])
        self.consent.side_effect = None
        with patch.object(guard.time, 'time', return_value=record['completed_at'] + 86400):
            guard.perform_maintenance(self.root, REVISION, 223456)
        self.assertEqual([event[0] for event in self.events],
                         ['download', 'stop', 'restore', 'download', 'stop', 'install', 'restore'])

    def test_closed_window_with_failed_restoration_still_requires_recovery(self):
        self.consent.side_effect = [None, None, guard.UpgradeRefused('window closed')]
        self.restore.side_effect = RuntimeError('container failed to start')
        with self.assertRaisesRegex(guard.UpgradeRefused, 'container failed to start'):
            guard.perform_maintenance(self.root, REVISION, 123456)
        self.consent.side_effect = None
        with self.assertRaisesRegex(guard.UpgradeRefused, 'requires recovery'):
            guard.perform_maintenance(self.root, REVISION, 223456)

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
