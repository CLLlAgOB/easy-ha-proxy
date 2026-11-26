"""APT metadata freshness and the HAProxy protection order.

The HAProxy version status and the OS package isolation are part of the
update checker and are tested with it, in the host agent (updateplan)."""
from __future__ import annotations

import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

import apt_metadata


class Metadata(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.apt = self.root / 'apt'
        self.apt.mkdir()
        (self.apt / 'sources.list').write_text('deb https://example.test noble main\n')
        self.record = self.root / 'record.json'

    def write(self, **values):
        data = {'format': 1, 'success': True, 'last_success': 1000, 'sources': apt_metadata.source_fingerprint(self.apt)}
        data.update(values)
        self.record.write_text(json.dumps(data))

    def test_missing_failed_expired_and_future_metadata_are_never_current(self):
        self.assertFalse(apt_metadata.assess(self.record, root=self.apt, now=1000)['fresh'])
        for values, now in (({'success': False}, 1001), ({'last_success': 0}, 1000 + apt_metadata.MAX_AGE), ({'last_success': 2000}, 1000)):
            self.write(**values)
            self.assertFalse(apt_metadata.assess(self.record, root=self.apt, now=now)['fresh'])

    def test_sources_changed_after_a_success_make_it_stale(self):
        self.write()
        self.assertTrue(apt_metadata.assess(self.record, root=self.apt, now=1001)['fresh'])
        (self.apt / 'sources.list').write_text('deb https://other.example.test noble main\n')
        self.assertFalse(apt_metadata.assess(self.record, root=self.apt, now=1001)['fresh'])

    def execute(self, *, code=0, error='', communicate=None):
        class Process:
            pid = 100
            returncode = code

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def communicate(self, **kwargs):
                return communicate(**kwargs) if communicate else ('', error)

        with patch.object(apt_metadata.subprocess, 'Popen', return_value=Process()) as launch, \
                patch.object(apt_metadata.time, 'time', return_value=1000):
            result = apt_metadata.refresh(path=self.record, root=self.apt)
        args = launch.call_args.args[0]
        self.assertIn('update', args)
        self.assertIn('--error-on=any', args)
        self.assertNotIn('install', args)
        self.assertNotIn('upgrade', args)
        return result

    def test_success_is_recorded_only_after_the_command_finishes(self):
        result = self.execute()
        self.assertTrue(result['fresh'])
        self.assertEqual(self.record.stat().st_mode & 0o777, 0o600)
        self.assertTrue(apt_metadata.assess(self.record, root=self.apt, now=1001)['fresh'])

    def test_partial_failure_retains_last_success_but_not_current_status_or_credentials(self):
        self.write(last_success=900)
        result = self.execute(code=100, error='E: Cannot fetch https://user:do-not-leak@example.test/index\n')
        self.assertFalse(result['fresh'])
        self.assertEqual(result['last_success'], 900)
        self.assertNotIn('do-not-leak', self.record.read_text())
        self.assertFalse(apt_metadata.assess(self.record, root=self.apt, now=1001)['fresh'])

    def test_sources_changed_during_refresh_are_not_a_success(self):
        def communicate(**kwargs):
            (self.apt / 'sources.list').write_text('deb https://changed.example.test noble main')
            return '', ''
        self.assertFalse(self.execute(communicate=communicate)['fresh'])

    def test_timeout_terminates_the_whole_acquisition_process_group(self):
        calls = []

        def communicate(**kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired('apt-get', 100)
            return '', ''
        with patch.object(apt_metadata.os, 'killpg') as kill:
            self.assertFalse(self.execute(communicate=communicate)['fresh'])
            kill.assert_called_once_with(100, signal.SIGTERM)


class OsIsolation(unittest.TestCase):
    def test_existing_core_is_protected_before_the_first_package_install_and_status_stays_read_only(self):
        play = yaml.safe_load((Path(__file__).resolve().parents[1] / 'ansible/easy-ha-proxy.yml').read_text(encoding='utf-8'))[0]
        # The pre-task is the installer agent's haproxy/protection part.
        protection = next(task for task in play['pre_tasks'] if task.get('ansible.builtin.import_role', {}).get('tasks_from') == 'protection')
        self.assertEqual(protection['ansible.builtin.import_role']['name'], 'haproxy')
        self.assertEqual(set(protection['tags']), {'ha-install', 'upgrade'})


if __name__ == "__main__":
    unittest.main()
