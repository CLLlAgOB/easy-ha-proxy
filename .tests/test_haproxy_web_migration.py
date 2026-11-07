"""The web can review and apply only one fixed, current HAProxy migration."""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_haproxy_update_broker import broker  # noqa: E402
from test_update_web import ROUTES, REQUEST, CONFIG_STATE, AbortCalled  # noqa: E402


class WebMigrationBroker(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        (self.source / 'installer').mkdir(parents=True)
        self.tool = self.source / 'installer/haproxy_package_migrate.py'
        self.tool.write_text('WEB_MIGRATION_PROTOCOL = 1\nAUTOMATIC_MIGRATION_PROTOCOL = 1\n', encoding='utf-8')
        (self.source / 'installer/apt_metadata.py').touch()
        self.addCleanup(patch.stopall)
        for name, value in {
            'SOURCE_DIR': self.source, 'HAPROXY_UPDATE_STATE': self.root / 'patch.json',
            'HAPROXY_MIGRATION_STATE': self.root / 'migration.json',
            'HAPROXY_MIGRATION_PLAN': self.root / 'review.json', 'LATEST_PLAN_PATH': self.root / 'plan.json',
            'ACTIVE_MARKER': self.root / 'active', 'MAINTENANCE_LOCK_PATH': self.root / 'maintenance.lock',
            'OPERATION_THREAD_LOCK': threading.Lock(), 'SHUTDOWN_REQUESTED': threading.Event(),
        }.items():
            patch.object(broker, name, value).start()
        patch.object(broker, 'reboot_guard_present', return_value=False).start()
        patch.object(broker, 'haproxy_transaction_active', return_value=False).start()
        patch.object(broker, 'migration_platform_supported', return_value=True).start()
        # Production's root ownership and atomic-file checks have their own
        # tests; these fixtures exercise the state machine without root.
        patch.object(broker, 'safe_json_file', side_effect=lambda p: json.loads(p.read_text())).start()
        patch.object(broker, 'atomic_json', side_effect=lambda p, d: p.write_text(json.dumps(d))).start()
        self.updated = patch.object(broker, 'update_job').start()
        self.failed = patch.object(broker, 'finish_failed').start()
        self.thread = patch.object(broker, 'start_thread').start()
        patch.object(broker, 'new_job', side_effect=lambda op, **values: {
            'id': 'a' * 32, 'operation': op, 'status': 'queued', **values}).start()
        self.plan = {'id': 'd' * 32, 'expires_at': self.expiry(), 'components': [{'id': 'haproxy', 'details': {
            'qualified': True, 'package': 'haproxy', 'branch': '2.8',
            'installed_version': '2.8.30-1', 'running_version': '2.8.30', 'binary_matches': True}}]}
        broker.LATEST_PLAN_PATH.write_text(json.dumps(self.plan))

    def expiry(self, seconds=600):
        return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()

    def operation(self, phase='prepared', identifier='b' * 32, **values):
        data = {'id': identifier, 'kind': 'migration', 'phase': phase, 'architecture': 'amd64',
                'engine_digest': hashlib.sha256(self.tool.read_bytes()).hexdigest(), 'created_at': 1000,
                'old_version': '2.8.30-1', 'target_runtime_version': '3.4.7', 'updated_at': 1001,
                'target_packages': [{'Package': 'haproxy-awslc', 'Version': '3.4.7-1', 'SHA256': 'f' * 64},
                                    {'Package': 'libssl-awslc', 'Version': '1.2.3-1', 'SHA256': 'e' * 64}],
                'extra_packages': [], **values}
        broker.HAPROXY_MIGRATION_STATE.write_text(json.dumps(data))
        return data

    def review(self, **values):
        operation = self.operation()
        value = {'id': 'c' * 32, 'transaction_id': operation['id'], 'expires_at': self.expiry(),
                 'fingerprint': broker.migration_fingerprint(operation),
                 'source_digest': broker.migration_tool_digest(), **values}
        broker.HAPROXY_MIGRATION_PLAN.write_text(json.dumps(value))
        return value

    def queued_worker(self, child):
        args = self.thread.call_args.args
        with patch.object(broker, 'run_command', side_effect=child) as run:
            args[0](*args[1:])
        return run

    def test_offer_explains_unsupported_or_old_hosts(self):
        self.assertEqual(broker.migration_offer(self.plan)['state'], 'available')
        self.plan['components'][0]['details']['qualified'] = False
        self.assertIn('Ubuntu 24.04', broker.migration_offer(self.plan)['reason'])
        self.plan['components'][0]['details'].update(qualified=True, branch='3.4')
        self.assertEqual(broker.migration_offer(self.plan)['state'], 'current')
        self.assertEqual(broker.migration_offer(None)['state'], 'check_required')
        self.tool.write_text('old migrator', encoding='utf-8')
        self.assertIn('host services', broker.migration_offer(self.plan)['reason'])

    def test_automatic_offer_does_not_depend_on_expired_or_absent_plans(self):
        self.review(expires_at=self.expiry(-1))
        self.plan['expires_at'] = self.expiry(-1)
        snapshot = broker.migration_status(self.plan)
        self.assertTrue(snapshot['plan']['stale'])
        self.assertTrue(snapshot['automatic']['can_start'])
        self.assertTrue(broker.migration_status(None)['automatic']['can_start'])
        with patch.object(broker, 'migration_platform_supported', return_value=False):
            self.assertFalse(broker.migration_status(None)['automatic']['can_start'])
        self.operation('rollback_failed')
        self.assertFalse(broker.migration_status(None)['automatic']['can_start'])

    def test_one_confirmation_starts_a_fresh_combined_native_job_without_a_check_plan(self):
        self.review(expires_at=self.expiry(-1), consumed_by='f'*32)
        broker.LATEST_PLAN_PATH.unlink()
        response = broker.dispatch({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True})
        self.assertEqual(response['job']['operation'], 'haproxy-transition')

        def child(*args, **kwargs):
            with broker.MAINTENANCE_LOCK_PATH.open('a') as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.operation('committed', identifier='e'*32, target_verified=True)
            return 0, 'verified'

        run = self.queued_worker(child)
        self.assertEqual(run.call_args.args[1][1:], [str(self.tool), 'migrate', '--web-progress'])
        self.assertFalse(broker.HAPROXY_MIGRATION_PLAN.exists())
        self.assertEqual(self.updated.call_args.kwargs['status'], 'completed')
        self.failed.assert_not_called()

    def test_automatic_transition_requires_exact_confirmation_target_and_supported_tool(self):
        for fields in ({'confirmed': False}, {'confirmed': 'true'}, {'confirmed': 1}, {'target_branch': '3.5'}, {'command': 'id'}):
            with self.subTest(fields=fields), self.assertRaises(broker.UpdatedError):
                broker.dispatch({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True, **fields})
        self.tool.write_text('WEB_MIGRATION_PROTOCOL = 1\n')
        with self.assertRaises(broker.UpdatedError):
            broker.dispatch({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True})
        self.thread.assert_not_called()

    def test_automatic_transition_does_not_accept_old_success_or_a_verified_rollback(self):
        self.operation('committed', target_verified=True)
        broker.dispatch({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True})
        self.queued_worker(lambda *a, **k: (0, 'old result'))
        self.failed.assert_called_once()
        self.failed.reset_mock()
        self.operation('prepared')
        broker.dispatch({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True})
        self.queued_worker(lambda *a, **k: (self.operation('rolled_back', identifier='e'*32, rollback_verified=True) and 0, 'rolled back'))
        self.failed.assert_called_once()

    def test_protocol_only_accepts_fixed_target_and_confirmation(self):
        for data in ({'action': 'prepare_haproxy_migration', 'target_branch': '3.5'},
                     {'action': 'prepare_haproxy_migration', 'target_branch': '3.4', 'command': 'id'},
                     {'action': 'apply_haproxy_migration', 'plan_id': '../state', 'confirmation': 'MIGRATE 3.4'},
                     {'action': 'apply_haproxy_migration', 'plan_id': 'c' * 32, 'confirmation': 'UPDATE'}):
            with self.subTest(data=data), self.assertRaises(broker.UpdatedError):
                broker.dispatch(data)
        self.thread.assert_not_called()

    def test_prepare_is_async_and_never_applies(self):
        response = broker.dispatch({'action': 'prepare_haproxy_migration', 'target_branch': '3.4'})
        self.assertEqual(response['job']['operation'], 'haproxy-prepare')
        self.assertFalse(broker.HAPROXY_MIGRATION_PLAN.exists())

        def child(*args, **kwargs):
            # The child must be able to own the actual common flock.
            with broker.MAINTENANCE_LOCK_PATH.open('a') as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.operation()
            return 0, 'prepared'

        run = self.queued_worker(child)
        self.assertEqual(run.call_args.args[1][1:], [str(self.tool), 'prepare', '--web-progress'])
        self.assertEqual(broker.migration_review(require_fresh=True)['transaction_id'], 'b' * 32)
        self.assertFalse(broker.ACTIVE_MARKER.exists())
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.failed.assert_not_called()

    def test_prepare_cannot_reuse_old_success(self):
        self.operation()
        broker.start_haproxy_migration({'target_branch': '3.4'})
        self.queued_worker(lambda *a, **k: (0, 'old success'))
        self.failed.assert_called_once()
        self.assertFalse(broker.HAPROXY_MIGRATION_PLAN.exists())

    def test_apply_consumes_review_and_invokes_only_its_prepared_transaction(self):
        review = self.review()
        response = broker.start_haproxy_migration({'plan_id': review['id'], 'confirmation': 'MIGRATE 3.4'}, apply=True)
        self.assertEqual(response['job']['operation'], 'haproxy-migrate')
        self.assertEqual(json.loads(broker.HAPROXY_MIGRATION_PLAN.read_text())['consumed_by'], 'a' * 32)

        def child(*args, **kwargs):
            self.operation('committed', target_verified=True)
            return 0, 'verified'

        run = self.queued_worker(child)
        self.assertEqual(run.call_args.args[1][1:], [str(self.tool), 'apply', '--id', 'b' * 32, '--web-progress'])
        self.assertFalse(broker.LATEST_PLAN_PATH.exists())
        self.assertEqual(self.updated.call_args.kwargs['status'], 'completed')
        self.failed.assert_not_called()
        with self.assertRaises(broker.UpdatedError):
            broker.start_haproxy_migration({'plan_id': review['id'], 'confirmation': 'MIGRATE 3.4'}, apply=True)

    def test_expiry_source_changes_and_replaced_packages_invalidate_review(self):
        for change in ('expiry', 'source', 'package', 'transaction', 'kind'):
            with self.subTest(change=change):
                self.tool.write_text('WEB_MIGRATION_PROTOCOL = 1\n', encoding='utf-8')
                self.review(expires_at=self.expiry(-1) if change == 'expiry' else self.expiry())
                if change == 'source':
                    self.tool.write_text('WEB_MIGRATION_PROTOCOL = 1\n# changed\n', encoding='utf-8')
                elif change == 'package':
                    self.operation(target_packages=[{'Package': 'haproxy-awslc', 'Version': '3.4.8-1'}])
                elif change == 'transaction':
                    self.operation(identifier='e' * 32)
                elif change == 'kind':
                    self.operation(kind='patch')
                with self.assertRaises(broker.UpdatedError):
                    broker.migration_review(require_fresh=True)

    def test_queued_apply_rechecks_source_before_child_start(self):
        review = self.review()
        broker.start_haproxy_migration({'plan_id': review['id'], 'confirmation': 'MIGRATE 3.4'}, apply=True)
        self.tool.write_text('WEB_MIGRATION_PROTOCOL = 1\n# changed', encoding='utf-8')
        run = self.queued_worker(lambda *a, **k: (0, ''))
        run.assert_not_called()
        self.failed.assert_called_once()

    def test_verified_rollback_is_failure_and_unverified_recovery_blocks_maintenance(self):
        for phase in ('rolled_back', 'rollback_failed', 'target_verified'):
            with self.subTest(phase=phase):
                review = self.review()
                broker.start_haproxy_migration({'plan_id': review['id'], 'confirmation': 'MIGRATE 3.4'}, apply=True)
                self.queued_worker(lambda *a, phase=phase, **k: (self.operation(phase, rollback_verified=True) and 0, ''))
                self.assertTrue(self.failed.called)
                self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.operation('rollback_failed', updated_at=1)
        broker.HAPROXY_UPDATE_STATE.write_text(json.dumps({'id': 'f' * 32, 'phase': 'committed', 'updated_at': 9999}))
        self.assertTrue(broker.haproxy_patch_active())
        self.assertEqual(broker.haproxy_operation()['phase'], 'rollback_failed')
        status = broker.migration_status(self.plan)
        self.assertEqual(status['state'], 'blocked')
        self.assertIn('recovery', status['reason'])
        self.assertTrue(status['plan']['stale'])
        with self.assertRaises(broker.UpdatedError):
            broker.acquire_operation()

    def test_malformed_migration_record_blocks_other_maintenance(self):
        for raw in ('malformed', json.dumps({'id': 'a' * 32, 'phase': []}),
                    json.dumps({'id': 'a' * 32, 'phase': 'prepared', 'target_packages': {}})):
            broker.HAPROXY_MIGRATION_STATE.write_text(raw)
            self.assertTrue(broker.haproxy_patch_active())
        broker.HAPROXY_MIGRATION_STATE.unlink()
        broker.HAPROXY_MIGRATION_STATE.symlink_to(self.tool)
        self.assertTrue(broker.haproxy_patch_active())

    def test_public_review_does_not_expose_private_state_or_supply_paths(self):
        self.review()
        summary = broker.migration_status(self.plan)
        self.assertFalse(summary['plan']['stale'])
        text = json.dumps(summary)
        self.assertNotIn('engine_digest', text)
        self.assertNotIn('SHA256', text)
        self.assertNotIn(str(self.root), text)


class WebMigrationRoutes(unittest.TestCase):
    def setUp(self):
        CONFIG_STATE.reset_mock(return_value=True, side_effect=True)
        CONFIG_STATE.return_value = {'state': 'clean'}
        self.addCleanup(patch.stopall)
        self.rpc = patch.object(ROUTES, 'updated_request', return_value={'ok': True, 'job_id': 'a' * 32}).start()
        self.audit = patch.object(ROUTES, 'record_request').start()

    def body(self, value):
        REQUEST.get_json = lambda silent=True: value

    def test_prepare_has_its_own_audited_fixed_action(self):
        self.body({'target_branch': '3.4'})
        self.assertEqual(ROUTES.prepare_haproxy_migration()[1], 202)
        self.rpc.assert_called_once_with({'action': 'prepare_haproxy_migration', 'target_branch': '3.4'})
        self.assertEqual(self.audit.call_args.args[0], 'update.haproxy_prepare')

    def test_simple_transition_is_audited_and_accepts_only_one_explicit_boolean_confirmation(self):
        for values in ({'confirmed': False}, {'confirmed': 1}, {'confirmed': 'yes'}, {'target_branch': '3.5'}, {'plan_id': 'a'*32}):
            self.body({'target_branch': '3.4', 'confirmed': True, **values})
            with self.assertRaises(AbortCalled): ROUTES.start_haproxy_transition()
        self.rpc.assert_not_called()
        self.body({'target_branch': '3.4', 'confirmed': True})
        self.assertEqual(ROUTES.start_haproxy_transition()[1], 202)
        self.rpc.assert_called_once_with({'action': 'start_haproxy_transition', 'target_branch': '3.4', 'confirmed': True})
        self.assertEqual(self.audit.call_args.args[0], 'update.haproxy_transition')
        CONFIG_STATE.return_value = {'state': 'pending'}
        self.assertEqual(ROUTES.start_haproxy_transition()[1], 409)

    def test_apply_requires_exact_review_and_confirmation(self):
        for value in ({'plan_id': '../x', 'confirmation': 'MIGRATE 3.4'}, {'plan_id': 'a' * 32, 'confirmation': 'UPDATE'},
                      {'plan_id': 'a' * 32, 'confirmation': 'MIGRATE 3.4', 'version': '3.5'}):
            self.body(value)
            with self.assertRaises(AbortCalled):
                ROUTES.apply_haproxy_migration()
        self.rpc.assert_not_called()
        self.body({'plan_id': 'b' * 32, 'confirmation': 'MIGRATE 3.4'})
        self.assertEqual(ROUTES.apply_haproxy_migration()[1], 202)
        self.assertEqual(self.audit.call_args.args[0], 'update.haproxy_migrate')

    def test_both_steps_refuse_pending_or_unknown_config(self):
        for phase in ('pending', 'unknown'):
            CONFIG_STATE.return_value = {'state': phase}
            self.body({'target_branch': '3.4'})
            self.assertEqual(ROUTES.prepare_haproxy_migration()[1], 409)
            self.body({'plan_id': 'b' * 32, 'confirmation': 'MIGRATE 3.4'})
            self.assertEqual(ROUTES.apply_haproxy_migration()[1], 409)
        CONFIG_STATE.side_effect = OSError('unavailable')
        self.body({'target_branch': '3.4'})
        self.assertEqual(ROUTES.prepare_haproxy_migration()[1], 503)
        self.rpc.assert_not_called()
