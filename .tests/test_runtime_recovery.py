"""A stale maintenance snapshot cannot strand unrelated stopped services."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'installer'))
import os_upgrade_guard as guard  # noqa: E402


def state(identity, name, status='running', health='healthy'):
    return {'id': identity * 64, 'name': '/' + name, 'status': status,
            'health': health, 'paused': False}


class Recovery(unittest.TestCase):
    def test_missing_original_does_not_prevent_starting_later_dependencies(self):
        missing, redis = state('a', 'app'), state('b', 'redis')
        current = {redis['id']: {**redis, 'status': 'exited'}}
        def inspect(identity):
            if identity not in current:
                raise guard.UpgradeRefused('No such container: ' + identity)
            return current[identity]
        def run(argv):
            if 'ps' in argv:
                return redis['id']
            if argv[:2] == ['/usr/bin/docker', 'start']:
                current[redis['id']] = redis
            return ''
        with patch.object(guard, 'container_state', side_effect=inspect), \
                patch.object(guard, 'run', side_effect=run) as command, \
                patch.object(guard.time, 'monotonic', side_effect=[0, 181]):
            with self.assertRaisesRegex(guard.UpgradeRefused, '/app:.*No such container'):
                guard.restore_containers([missing, redis])
        self.assertIn(['/usr/bin/docker', 'start', redis['id']], [c.args[0] for c in command.call_args_list])
        self.assertEqual(current[redis['id']]['status'], 'running')

    def test_running_replacement_satisfies_recovery_without_mutating_it(self):
        original, replacement = state('a', 'app'), state('c', 'app')
        with patch.object(guard, 'container_state', side_effect=[guard.UpgradeRefused('gone'), replacement]), \
                patch.object(guard, 'run', return_value=replacement['id']) as command:
            guard.restore_containers([original])
        self.assertFalse(any(c.args[0][:2] == ['/usr/bin/docker', 'start'] for c in command.call_args_list))

    def test_replacement_must_be_running_with_the_exact_name_and_not_paused(self):
        original = state('a', 'app')
        for replacement in (state('c', 'other'), state('c', 'app', 'exited'),
                            {**state('c', 'app'), 'paused': True}):
            with self.subTest(replacement=replacement), \
                    patch.object(guard, 'container_state', side_effect=[guard.UpgradeRefused('gone'), replacement]), \
                    patch.object(guard, 'run', return_value=replacement['id']):
                with self.assertRaises(guard.UpgradeRefused):
                    guard.recovery_container_state(original)

    def test_inspect_failure_for_an_existing_id_never_falls_back_to_a_name(self):
        original = state('a', 'app')
        with patch.object(guard, 'container_state', side_effect=guard.UpgradeRefused('temporary')) as inspect, \
                patch.object(guard, 'run', return_value=original['id']):
            with self.assertRaisesRegex(guard.UpgradeRefused, 'temporary'):
                guard.recovery_container_state(original)
        inspect.assert_called_once_with(original['id'])

    def test_legacy_snapshot_without_name_still_restores_by_id(self):
        original = state('a', 'app')
        item = {k: v for k, v in original.items() if k != 'name'}
        with patch.object(guard, 'container_state', return_value=original), patch.object(guard, 'run'):
            guard.restore_containers([item])

    def test_malformed_names_are_never_used_for_lookup(self):
        for name in ('--help', '/', '/app/other', ['app']):
            with self.subTest(name=name), \
                    patch.object(guard, 'container_state', side_effect=guard.UpgradeRefused('gone')), \
                    patch.object(guard, 'run') as command:
                with self.assertRaises(guard.UpgradeRefused):
                    guard.recovery_container_state({**state('a', 'app'), 'name': name})
            command.assert_not_called()

    def test_transient_start_failure_retries_after_other_dependencies(self):
        first, second = state('a', 'app'), state('b', 'redis')
        current = {c['id']: {**c, 'status': 'exited'} for c in (first, second)}
        starts = []
        def run(argv):
            if argv[:2] == ['/usr/bin/docker', 'start']:
                identity = argv[-1]
                starts.append(identity)
                if starts == [first['id']]:
                    raise subprocess.TimeoutExpired(argv, 120)
                current[identity] = {**current[identity], 'status': 'running'}
            return ''
        with patch.object(guard, 'container_state', side_effect=lambda identity: current[identity]), \
                patch.object(guard, 'run', side_effect=run), patch.object(guard.time, 'sleep'), \
                patch.object(guard.time, 'monotonic', side_effect=[0, 1]):
            guard.restore_containers([first, second])
        self.assertEqual(starts, [first['id'], second['id'], first['id']])

    def test_start_retries_are_bounded_and_unhealthy_state_is_not_success(self):
        original = state('a', 'app', 'exited')
        with patch.object(guard, 'container_state', return_value=original), \
                patch.object(guard, 'run', return_value='') as command, patch.object(guard.time, 'sleep'), \
                patch.object(guard.time, 'monotonic', side_effect=[0, 1, 2, 3, 181]):
            with self.assertRaisesRegex(guard.UpgradeRefused, 'status=exited'):
                guard.restore_containers([original])
        self.assertEqual(sum(c.args[0][:2] == ['/usr/bin/docker', 'start'] for c in command.call_args_list), 3)
        for current in (state('a', 'app', health='unhealthy'), state('a', 'app', 'restarting')):
            with patch.object(guard, 'container_state', return_value=current), patch.object(guard, 'run') as command, \
                    patch.object(guard.time, 'monotonic', side_effect=[0, 181]):
                with self.assertRaises(guard.UpgradeRefused):
                    guard.restore_containers([current])
            self.assertFalse(any(c.args[0][:2] == ['/usr/bin/docker', 'start'] for c in command.call_args_list))

    def test_service_start_error_does_not_mask_a_working_daemon(self):
        with patch.object(guard, 'container_state', return_value=state('a', 'app')), \
                patch.object(guard, 'run', side_effect=guard.UpgradeRefused('unit restarting')):
            guard.restore_containers([state('a', 'app')])

    def test_last_start_failure_is_preserved_after_retries_are_exhausted(self):
        original = state('a', 'app', 'exited')
        def run(argv):
            if argv[:2] == ['/usr/bin/docker', 'start']:
                raise guard.UpgradeRefused('address already in use')
            return ''
        with patch.object(guard, 'container_state', return_value=original), \
                patch.object(guard, 'run', side_effect=run), patch.object(guard.time, 'sleep'), \
                patch.object(guard.time, 'monotonic', side_effect=[0, 1, 2, 3, 181]):
            with self.assertRaisesRegex(guard.UpgradeRefused, 'address already in use'):
                guard.restore_containers([original])


class Diagnostics(unittest.TestCase):
    def test_failure_retains_action_exit_and_bounded_redacted_stderr(self):
        result = subprocess.CompletedProcess([], 1, '', 'No such container: abc\nhttps://user:password@example.test ' + 'x' * 3000)
        with patch.object(guard.subprocess, 'run', return_value=result):
            with self.assertRaises(guard.UpgradeRefused) as caught:
                guard.run(['/usr/bin/docker', 'inspect', 'abc'])
        message = str(caught.exception)
        self.assertIn('docker inspect (exit 1)', message)
        self.assertIn('No such container: abc', message)
        self.assertNotIn('password', message)
        self.assertLess(len(message), 2100)


if __name__ == '__main__':
    unittest.main()
