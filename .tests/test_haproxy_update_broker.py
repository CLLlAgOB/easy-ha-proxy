"""Controlled core updates cannot escape review or shared maintenance custody."""
from __future__ import annotations

import copy
import fcntl
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('haproxy_patch_broker', ROOT / 'ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py')
broker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = broker
spec.loader.exec_module(broker)


class Broker(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.installer = self.root / 'installer'
        self.installer.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(broker, 'SOURCE_DIR', self.root).start()
        patch.object(broker, 'HAPROXY_UPDATE_STATE', self.root / 'operation.json').start()
        patch.object(broker, 'LATEST_PLAN_PATH', self.root / 'plan.json').start()
        patch.object(broker, 'MAINTENANCE_LOCK_PATH', self.root / 'maintenance.lock').start()
        patch.object(broker, 'ACTIVE_MARKER', self.root / 'active').start()
        self.job_update = patch.object(broker, 'update_job').start()

    def operation(self, phase='committed', identifier='b' * 32, **fields):
        data = {'id': identifier, 'phase': phase, 'target_verified': True, **fields}
        broker.HAPROXY_UPDATE_STATE.write_text(json.dumps(data))
        return data

    def test_capability_negotiation_keeps_old_checker_bootstrappable(self):
        (self.installer / 'update_plan.py').touch()
        self.assertNotIn('--haproxy-status', broker.checker_command())
        (self.installer / 'haproxy_update_status.py').touch()
        self.assertIn('--haproxy-status', broker.checker_command())

    def test_only_reviewed_exact_version_is_sent_to_fixed_root_command(self):
        (self.installer / 'haproxy_package_migrate.py').touch()
        plan = {'components': [{'id': 'haproxy', 'available_version': '3.4.8-1', 'details': {'needs_reload': True}}]}

        def child(*args, **kwargs):
            self.operation()
            return 0, 'verified'

        with patch.object(broker, 'run_command', side_effect=child) as run:
            result, _ = broker.apply_haproxy_patch('a' * 32, plan, '')
        self.assertEqual(result['phase'], 'committed')
        command = run.call_args.args[1]
        self.assertEqual(command[1:], [str(self.installer / 'haproxy_package_migrate.py'), 'patch', '--expected-version', '3.4.8-1', '--reinstall'])
        plan['components'][0]['available_version'] = '3.4.8;unreviewed'
        with patch.object(broker, 'run_command') as run, self.assertRaises(broker.UpdatedError):
            broker.apply_haproxy_patch('a' * 32, plan, '')
        run.assert_not_called()

    def test_old_success_or_verified_rollback_cannot_report_update_success(self):
        (self.installer / 'haproxy_package_migrate.py').touch()
        plan = {'components': [{'id': 'haproxy', 'available': '3.4.8-1'}]}
        self.operation()
        with patch.object(broker, 'run_command', return_value=(0, '')), self.assertRaises(broker.UpdatedError):
            broker.apply_haproxy_patch('a' * 32, plan, '')
        for phase in ('rolled_back', 'rollback_failed', 'target_verified'):
            def child(*args, phase=phase, **kwargs):
                self.operation(phase, 'c' * 32)
                return 0, ''
            self.operation()
            with patch.object(broker, 'run_command', side_effect=child), self.assertRaises(broker.UpdatedError):
                broker.apply_haproxy_patch('a' * 32, plan, '')

    def test_automatic_installation_never_selects_core_or_os(self):
        plan = {'components': [{'id': name, 'state': 'available', 'actionable': True}
                               for name in ('haproxy', 'os', 'daemons')]}
        self.assertEqual(broker.auto_install_selection(plan), ['daemons'])

    def test_rechecking_timestamps_does_not_change_review_but_candidate_and_source_do(self):
        entry = {'id': 'haproxy', 'available': '3.4.8-1', 'details': {
            'apt': {'fresh': True, 'sources': 'same', 'last_success': 10}, 'last_operation': {'id': 'old'}}}
        original = broker.component_signature(entry)
        entry['details']['apt']['last_success'] = 20
        entry['details']['last_operation'] = {'id': 'new'}
        self.assertEqual(original, broker.component_signature(entry))
        for modified in (dict(entry, available='3.4.9-1'), copy.deepcopy(entry)):
            if modified['available'] == entry['available']:
                modified['details']['apt']['sources'] = 'changed'
            self.assertNotEqual(original, broker.component_signature(modified))

    def test_unfinished_recovery_blocks_other_host_maintenance(self):
        self.operation('rollback_failed')
        with self.assertRaises(broker.UpdatedError) as rejected:
            broker.acquire_operation()
        self.assertEqual(rejected.exception.code, 'conflict')
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())

    def test_damaged_or_unknown_recovery_state_is_not_treated_as_idle(self):
        for contents in ('{', json.dumps({'id': 'b' * 32, 'phase': 'new-unrecognized-phase'})):
            broker.HAPROXY_UPDATE_STATE.write_text(contents)
            self.assertTrue(broker.haproxy_patch_active())
        self.operation('rolled_back')
        self.assertFalse(broker.haproxy_patch_active())

    def test_failed_metadata_helper_invalidates_old_green_plan(self):
        (self.installer / 'apt_metadata.py').touch()
        broker.LATEST_PLAN_PATH.write_text('{}')
        with patch.object(broker, 'run_command', return_value=(1, '')), self.assertRaises(broker.UpdatedError):
            broker.refresh_apt_metadata('a' * 32)
        self.assertFalse(broker.LATEST_PLAN_PATH.exists())

    def test_background_metadata_refresh_respects_backup_lock(self):
        (self.installer / 'apt_metadata.py').touch()
        with broker.MAINTENANCE_LOCK_PATH.open('w') as backup:
            fcntl.flock(backup, fcntl.LOCK_EX | fcntl.LOCK_NB)
            broker.METADATA_CONTEXT.unlocked = True
            try:
                with patch.object(broker, 'run_command') as run, self.assertRaises(broker.UpdatedError):
                    broker.refresh_apt_metadata('a' * 32)
                run.assert_not_called()
            finally:
                broker.METADATA_CONTEXT.unlocked = False

    def test_child_receives_common_lock_and_parent_releases_it_after_verified_switch(self):
        descriptor = broker.acquire_operation()
        plan = {'source_channel': 'local', 'image_channel': 'alpha', 'components': []}

        def child(*args):
            # A separate process/file description must be able to take the
            # maintenance lock, and it keeps custody throughout the switch.
            with broker.MAINTENANCE_LOCK_PATH.open('r+') as independent:
                fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return {'phase': 'committed', 'target_verified': True}, 'verified'

        with patch.object(broker.time, 'sleep'), patch.object(broker, 'validate_selection'), \
                patch.object(broker, 'execute_checker', return_value=plan), \
                patch.object(broker, 'validate_fresh_candidates'), patch.object(broker, 'validate_reviewed_container_candidates'), \
                patch.object(broker, 'reviewed_source_revision', return_value=None), \
                patch.object(broker, 'apply_haproxy_patch', side_effect=child), \
                patch.object(broker, 'store_plan', return_value={'id': 'c' * 32}), \
                patch.object(broker, 'report_availability'), patch.object(broker, 'request_self_restart_if_needed'), \
                patch.object(broker, 'finish_failed') as failed:
            broker.apply_worker('a' * 32, descriptor, plan, ['haproxy'])
        failed.assert_not_called()
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.assertFalse(broker.ACTIVE_MARKER.exists())
        with broker.MAINTENANCE_LOCK_PATH.open('r+') as independent:
            fcntl.flock(independent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertTrue(any(call.kwargs.get('status') == 'completed' for call in self.job_update.call_args_list))


if __name__ == '__main__':
    unittest.main()
