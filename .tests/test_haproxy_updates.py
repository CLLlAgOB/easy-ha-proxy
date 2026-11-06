"""Version truth, metadata freshness and package-update isolation."""
from __future__ import annotations

import json
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import apt_metadata
import haproxy_update_status as status
from update_plan import CommandResult, _probe_os


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


class VersionStatus(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / 'haproxy'
        self.binary.write_bytes(b'fixture')
        self.protection = self.root / 'needrestart.conf'
        self.protection.write_text(r'$nrconf{override_rc}{qr(^haproxy\.service$)} = 0;')
        self.package = 'haproxy-awslc'
        self.installed = '3.4.7-0+ha34+ubuntu24.04u2'
        self.candidate = self.installed
        self.held = True
        self.remote = True
        self.runtime = {'running_version': self.installed, 'binary_matches': True, 'replaced_libraries': []}
        self.calls = []

    def command(self, argv, *, timeout):
        self.calls.append(argv)
        if argv[0] == 'dpkg-query':
            return CommandResult(0, 'installed\t' + self.installed) if argv[-1] == self.package else CommandResult(1)
        if argv[:2] == ('apt-cache', 'policy'):
            remote = ' 990 https://example.test noble/main amd64 Packages\n' if self.remote else ''
            return CommandResult(0, f'  Installed: {self.installed}\n  Candidate: {self.candidate}\n' + remote)
        if argv == ('dpkg', '--get-selections'):
            return CommandResult(0, (self.package + '\thold\nlibssl-awslc\thold') if self.held else '')
        if argv[:2] == ('dpkg', '--compare-versions'):
            return CommandResult(0 if self.candidate > self.installed else 1)
        raise AssertionError(argv)

    def probe(self, **kwargs):
        return status.probe(SimpleNamespace(run=self.command), binary=self.binary, metadata=kwargs.pop('metadata', {'fresh': True}),
                            reader=lambda _: dict(self.runtime), protection=self.protection,
                            last_update=self.root / 'absent', qualified=kwargs.pop('qualified', True), **kwargs)

    def test_installed_running_and_candidate_are_distinct_fields(self):
        result = self.probe()
        self.assertEqual(result['state'], 'current')
        self.assertEqual(result['details']['installed_version'], self.installed)
        self.assertEqual(result['details']['running_version'], self.installed)
        self.assertEqual(result['details']['candidate_version'], self.candidate)

    def test_a_patch_is_offered_but_a_branch_jump_and_downgrade_are_blocked(self):
        for version, expected in [('3.4.8-1', 'available'), ('3.5.0-1', 'blocked'), ('3.4.6-1', 'blocked')]:
            self.candidate = version
            self.assertEqual(self.probe()['state'], expected)

    def test_failed_metadata_does_not_claim_no_updates(self):
        self.assertEqual(self.probe(metadata={'fresh': False})['state'], 'unknown')

    def test_disk_runtime_mismatch_cannot_be_called_a_successful_update(self):
        self.runtime['binary_matches'] = False
        self.assertEqual(self.probe()['state'], 'blocked')

    def test_replaced_libraries_offer_a_state_preserving_reload_even_at_same_version(self):
        self.runtime['replaced_libraries'] = ['libc.so.6']
        result = self.probe()
        self.assertEqual(result['state'], 'available')
        self.assertTrue(result['details']['needs_reload'])
        self.assertEqual(result['current_version'], result['available_version'])

    def test_missing_hold_or_restart_guard_blocks_the_controlled_action(self):
        self.held = False
        self.assertEqual(self.probe()['state'], 'blocked')
        self.held = True
        self.protection.unlink()
        self.assertEqual(self.probe()['state'], 'blocked')

    def test_distribution_package_is_detected_without_assuming_vendor_name(self):
        self.package = 'haproxy'
        self.installed = self.candidate = '2.8.30-0ubuntu0.24.04.2'
        self.runtime['running_version'] = self.installed
        self.assertEqual(self.probe()['details']['branch'], '2.8')
        self.assertEqual(self.probe()['state'], 'current')

    def test_an_installed_package_without_a_repository_is_not_current(self):
        self.remote = False
        self.assertEqual(self.probe()['state'], 'unknown')

    def test_unsupported_platform_does_not_offer_a_controlled_install(self):
        self.assertEqual(self.probe(qualified=False)['state'], 'blocked')


class OsIsolation(unittest.TestCase):
    def test_managed_haproxy_and_tls_are_not_os_updates(self):
        class Runner:
            def run(self, *args, **kwargs):
                return CommandResult(0, 'Inst haproxy-awslc [3.4.7] (3.4.8 repo)\nInst libssl-awslc [4.2] (4.3 repo)\nInst libc6 [2.39] (2.39.1 repo)')
        result = _probe_os(Runner(), {'fresh': True}, status.PACKAGES)
        self.assertEqual(result['details']['packages'], ['libc6'])

    def test_failed_refresh_marks_os_unknown_even_when_simulation_is_empty(self):
        class Runner:
            def run(self, *args, **kwargs):
                return CommandResult(0, '')
        self.assertEqual(_probe_os(Runner(), {'fresh': False})['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()
