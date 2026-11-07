"""Security origins, native policy custody, scheduling and privileged API gates."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tests'))
if sys.platform == 'linux':
    spec = importlib.util.spec_from_file_location('os_security_test', ROOT / 'installer/os_security.py')
    s = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = s
    spec.loader.exec_module(s)
    from test_haproxy_update_broker import broker
else:
    s = broker = None


def origin(**values):
    return NS(trusted=True, origin='Ubuntu', archive='noble-security', codename='noble', label='Ubuntu', **values) if not values else NS(**{**vars(origin()), **values})


@unittest.skipUnless(s, 'Linux security worker')
class SecurityOrigins(unittest.TestCase):
    def test_needrestart_cannot_restart_the_active_update_executor(self):
        if not Path('/usr/bin/perl').is_file():
            self.skipTest('the native needrestart workflow supplies Perl')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'restart.conf'; path.write_text(s.RESTART_CONFIG)
            units = ['haproxy.service', 'docker.service', 'easy-ha-proxy-updated.service',
                     broker.transient_job_unit_name(), 'unrelated.service']
            code = 'our %nrconf; do $ARGV[0]; die $@ if $@; for my $unit (@ARGV[1..$#ARGV]) { my $blocked=0; for my $rx (keys %{$nrconf{override_rc}}) { $blocked=1 if $unit =~ $rx; } print "$blocked\\n"; }'
            result = subprocess.run(['/usr/bin/perl', '-e', code, str(path), *units], capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.splitlines(), ['1', '1', '1', '1', '0'])
    def test_configuration_reload_uses_the_actual_distribution_python_apt_api(self):
        available = subprocess.run(['/usr/bin/python3', '-c', 'import apt_pkg'], capture_output=True)
        if available.returncode:
            self.skipTest('python3-apt is exercised by the dedicated native security workflow')
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import apt_pkg; import os_security as s; '
                'apt_pkg.init_config(); apt_pkg.config.set("EHPFixture::Sentinel", "old"); '
                's.reload_apt_config(apt_pkg); assert not apt_pkg.config.find("EHPFixture::Sentinel"); '
                'assert apt_pkg.config.find("Dir::State::status")')
        subprocess.run(['/usr/bin/python3', '-c', code, str(ROOT / 'installer')], check=True, capture_output=True, text=True)

    def test_only_trusted_distribution_security_origins(self):
        self.assertTrue(s.security_origin(origin(), 'ubuntu', 'noble'))
        for fields in ({'trusted': False}, {'origin': 'LP-PPA-test'}, {'archive': 'noble-updates'}, {'archive': 'jammy-security'}):
            self.assertFalse(s.security_origin(origin(**fields), 'ubuntu', 'noble'))
        self.assertTrue(s.security_origin(origin(origin='UbuntuESMApps', archive='noble-apps-security'), 'ubuntu', 'noble'))
        debian = origin(origin='Debian', label='Debian-Security', codename='bookworm-security', archive='oldstable-security')
        self.assertTrue(s.security_origin(debian, 'debian', 'bookworm'))
        self.assertFalse(s.security_origin(debian, 'debian', 'trixie'))

    def test_security_version_selection_does_not_use_the_newest_nonsecurity_candidate(self):
        versions = [NS(version='3', origins=[origin(archive='noble-updates')]), NS(version='2', origins=[origin()])]
        package = NS(name='haproxy', fullname='haproxy:amd64', is_installed=True, installed=NS(version='1'), versions=versions, _pkg=NS(selected_state=2))
        rows = s.security_packages([package], 'ubuntu', 'noble', lambda a, b: int(a) - int(b))
        self.assertEqual(rows, [{'name': 'haproxy:amd64', 'installed': '1', 'candidate': '2', 'protected': True, 'held': True}])
        package.installed.version = '3'
        self.assertEqual(s.security_packages([package], 'ubuntu', 'noble', lambda a, b: int(a) - int(b)), [])

    def test_policy_bounds_reject_shell_fragments_booleans_and_extra_fields(self):
        value = {'mode': 'notify', 'interval': 4, 'start': 23, 'end': 2}
        self.assertEqual(s.validate_policy(value), value)
        for change in ({'mode': 'auto; reboot'}, {'interval': True}, {'interval': 3}, {'start': 24}, {'end': 23}, {'command': 'id'}):
            with self.subTest(change=change), self.assertRaises(s.SecurityError):
                s.validate_policy({**value, **change})
        self.assertTrue(s.window_open(value, dt.datetime(2026, 11, 7, 1)))
        self.assertFalse(s.window_open(value, dt.datetime(2026, 11, 7, 2)))

    def test_native_apt_config_clears_inherited_origins_and_reboot_policy(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(s.os, 'fchown'):
            root = Path(directory)
            parts = root / 'parts'; parts.mkdir()
            (parts / '99danger').write_text('Unattended-Upgrade::Allowed-Origins { "LP-PPA-test:noble"; };\nUnattended-Upgrade::Automatic-Reboot "true";\n')
            environment = s.apt_environment(root, 'ubuntu', 'noble')
            initial = root / 'initial.conf'
            initial.write_text(f'Dir::Etc::Parts "{parts}";\n' + initial.read_text())
            result = subprocess.run(['/usr/bin/apt-config', 'dump'], env={**os.environ, **environment}, capture_output=True, text=True, check=True)
            self.assertNotIn('LP-PPA-test', result.stdout)
            self.assertIn('Unattended-Upgrade::Automatic-Reboot "false"', result.stdout)
            self.assertIn('origin=Ubuntu,archive=noble-security', result.stdout)
            self.assertNotIn('archive=noble-updates', result.stdout)
            self.assertIn('^haproxy(:[a-z0-9]+)?$', result.stdout)
            self.assertIn('^docker[.]io(:[a-z0-9]+)?$', result.stdout)
            self.assertIn('APT::Get::AllowUnauthenticated "false"', result.stdout)

    def test_state_reader_refuses_symlinks_and_non_root_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            path.write_text('{}')
            if os.getuid() != 0:
                with self.assertRaises(s.SecurityError):
                    s.read_json(path)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(s.SecurityError):
                s.read_json(link)


@unittest.skipUnless(s, 'Linux security worker')
class NativePolicyCustody(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(s, 'RESTART_DROPIN', self.root / 'needrestart/security.conf').start()
        patch.object(s, 'APT_GUARD', self.root / 'apt/security.conf').start()
        patch.object(s.os, 'fchown').start()
        patch.object(s, 'read_json', side_effect=lambda p: json.loads(p.read_text())).start()
        self.timer = {'enabled': 'enabled', 'active': True}
        patch.object(s, 'native_timer', side_effect=lambda: dict(self.timer)).start()
        patch.object(s, 'assert_native_idle').start()
        self.bootstrap = patch.object(s, 'bootstrap').start()
        self.commands = patch.object(s, 'command', side_effect=self.command).start()
        self.policy = {'mode': 'notify', 'interval': 4, 'start': 3, 'end': 5}

    def command(self, args, **kwargs):
        if args[0] == '/usr/bin/apt-config': return 0, "PERIODIC='0'\nSHUTDOWN='false'\nREBOOT='false'\n"
        if 'stop' in args: self.timer['active'] = False
        if 'disable' in args: self.timer['enabled'] = 'disabled'
        if 'enable' in args: self.timer['enabled'] = 'enabled'
        if 'start' in args: self.timer['active'] = True
        return 0, ''

    def configure(self, **values):
        s.configure(self.root, {**self.policy, **values}, Mock(), 'ubuntu', 'noble')

    def test_explicit_management_takes_custody_and_system_mode_restores_exact_prior_timer(self):
        self.assertFalse((self.root / 'policy.json').exists())
        self.configure()
        self.assertEqual(self.timer, {'enabled': 'disabled', 'active': False})
        stored = json.loads((self.root / 'policy.json').read_text())
        self.assertEqual(stored['baseline'], {'enabled': 'enabled', 'active': True})
        self.configure(mode='auto')
        self.assertEqual(json.loads((self.root / 'policy.json').read_text())['baseline'], stored['baseline'])
        self.configure(mode='system')
        self.assertEqual(self.timer, stored['baseline'])
        self.assertFalse(s.RESTART_DROPIN.exists())

    def test_masked_timer_is_never_unmasked(self):
        self.timer.update(enabled='masked', active=False)
        self.configure(); self.configure(mode='system')
        self.assertFalse(any('unmask' in call.args[0] for call in self.commands.call_args_list))
        self.assertEqual(self.timer, {'enabled': 'masked', 'active': False})

    def test_failed_setup_restores_policy_and_failed_rollback_remains_recoverable(self):
        self.bootstrap.side_effect = s.SecurityError('dependency failed')
        with self.assertRaises(s.SecurityError): self.configure()
        self.assertEqual(self.timer, {'enabled': 'enabled', 'active': True})
        self.assertEqual(json.loads((self.root / 'policy.json').read_text())['policy']['mode'], 'system')
        with patch.object(s, 'restore_timer', side_effect=s.SecurityError('restore failed')):
            with self.assertRaises(s.SecurityError): self.configure()
        self.assertEqual(json.loads((self.root / 'policy.json').read_text())['phase'], 'recovery_required')
        with self.assertRaises(s.SecurityError): self.configure(mode='auto')
        self.configure(mode='system')
        self.assertEqual(self.timer, {'enabled': 'enabled', 'active': True})

    def test_external_timer_or_file_change_is_not_silently_overwritten(self):
        self.configure()
        self.timer.update(enabled='enabled', active=True)
        with self.assertRaises(s.SecurityError): self.configure(mode='auto')
        with self.assertRaises(s.SecurityError): self.configure(mode='system')
        self.timer.update(enabled='disabled', active=False)
        s.RESTART_DROPIN.write_text('externally changed')
        with self.assertRaises(s.SecurityError): self.configure(mode='system')

    def test_resaving_upgrades_the_known_previous_guard_but_install_does_not_use_it(self):
        self.configure()
        s.RESTART_DROPIN.write_text(s.PREVIOUS_RESTART_CONFIG)
        record = json.loads((self.root / 'policy.json').read_text())
        with self.assertRaises(s.SecurityError): s.assert_managed(record)
        self.configure(mode='auto')
        self.assertEqual(s.RESTART_DROPIN.read_text(), s.RESTART_CONFIG)


@unittest.skipUnless(s, 'Linux security broker')
class SecurityBroker(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.now = dt.datetime(2026, 11, 7, 3, 0).astimezone()
        self.snapshot = {'available': True, 'policy': {'mode': 'notify', 'interval': 4, 'start': 3, 'end': 5}, 'recovery_required': False, 'status': {}}
        patch.object(broker, 'os_security_snapshot', side_effect=lambda: self.snapshot).start()
        self.actual_start = broker.start_os_security
        self.start = patch.object(broker, 'start_os_security').start()

    def test_schedule_respects_system_mode_freshness_retry_and_night_window(self):
        self.assertEqual(broker.os_security_tick(self.now), 'started')
        self.assertEqual(self.start.call_args.args[0], {'action': 'os_security_cycle'})
        self.snapshot['policy']['mode'] = 'system'
        self.assertEqual(broker.os_security_tick(self.now), 'disabled')
        self.snapshot['policy']['mode'] = 'window'
        self.snapshot['status'] = {'last_success': self.now.timestamp() - 3600, 'last_attempt': self.now.timestamp() - 3600}
        self.assertEqual(broker.os_security_tick(self.now), 'started')
        self.snapshot['status']['last_install_at'] = self.now.timestamp() - 10
        self.assertEqual(broker.os_security_tick(self.now), 'waiting')
        self.snapshot['status']['last_attempt'] = self.now.timestamp() - 10
        self.assertEqual(broker.os_security_tick(self.now), 'waiting')
        self.snapshot['recovery_required'] = True
        self.assertEqual(broker.os_security_tick(self.now), 'disabled')

    def test_only_fixed_security_protocol_fields_and_types_are_accepted(self):
        for request in ({'action': 'os_security_check', 'command': 'id'}, {'action': 'os_security_install', 'confirmation': 'UPDATE'},
                        {'action': 'os_security_configure', 'mode': 'auto', 'interval': True, 'start': 3, 'end': 5, 'confirmation': 'SECURITY'}):
            # This test exercises dispatch validation rather than the patched
            # scheduler start helper.
            with patch.object(broker, 'start_os_security', self.actual_start):
                with self.assertRaises(broker.UpdatedError): broker.dispatch(request)

    def test_unknown_status_never_resolves_existing_security_or_restart_incident(self):
        alerts = Mock()
        with patch.object(broker, '_ALERTS', alerts):
            broker.os_security_notifications({'status': {'state': 'unknown', 'package_count': 0, 'error': 'network'}})
            self.assertEqual(alerts.observe.call_count, 1)
            self.assertEqual(alerts.observe.call_args.args[0], 'os.security_check_failed')
            self.assertTrue(alerts.observe.call_args.kwargs['active'])
            alerts.reset_mock()
            broker.os_security_notifications({'status': {'state': 'ready', 'package_count': 0, 'restart': {'error': 'unknown'}}})
            self.assertFalse(any(c.args[0] == 'os.security_restart' for c in alerts.observe.call_args_list))


@unittest.skipUnless(s, 'Linux APT executor')
class SecurityExecution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(s.os, 'fchown').start()
        patch.object(s, 'read_json', side_effect=lambda p: json.loads(p.read_text())).start()
        patch.object(s, 'platform', return_value=('ubuntu', 'noble')).start()
        patch.object(s, 'maintenance_guard').start()
        patch.object(s, 'assert_managed').start()
        patch.object(s, 'restart_status', return_value={'reboot_required': True, 'services': ['haproxy.service'], 'error': None}).start()
        patch.object(s, 'native_timer', return_value={'enabled': 'disabled', 'active': False}).start()
        self.command = patch.object(s, 'command', return_value=(0, 'native fixture')).start()
        self.installer = patch.object(s, 'installer_available', return_value=True).start()
        config = Mock()
        config.list.return_value = ['APT', 'Dir', 'DPkg']
        config.find.return_value = '0'; config.find_b.return_value = False
        self.cache = Mock()
        patch.dict(sys.modules, {'apt': NS(Cache=lambda: self.cache), 'apt_pkg': NS(config=config,
            init_config=Mock(), init_system=Mock(), version_compare=lambda a, b: int(a) - int(b))}).start()
        import apt_metadata
        self.metadata = patch.object(apt_metadata, 'refresh', return_value={'fresh': True}).start()
        self.row = {'name': 'fixture:amd64', 'installed': '1', 'candidate': '2', 'protected': False, 'held': False}
        self.packages = patch.object(s, 'security_packages', return_value=[self.row]).start()
        self.policy = {'mode': 'notify', 'interval': 4, 'start': 3, 'end': 5}
        (self.root / 'policy.json').write_text(json.dumps({'phase': 'ready', 'policy': self.policy}))

    def test_notify_cycle_checks_without_installing_and_preserves_activation_requirement(self):
        result = s.run('cycle', self.root)
        self.assertEqual(result['package_count'], 1)
        self.assertEqual(result['installed_count'], 0)
        self.assertTrue(result['restart']['reboot_required'])
        self.command.assert_not_called()
        self.assertEqual(result['state'], 'ready')

    def test_auto_cycle_uses_native_installer_and_recounts_remaining_packages(self):
        self.policy['mode'] = 'auto'
        (self.root / 'policy.json').write_text(json.dumps({'phase': 'ready', 'policy': self.policy}))
        self.packages.side_effect = [[self.row], []]
        result = s.run('cycle', self.root)
        self.assertEqual(result['installed_count'], 1)
        self.assertEqual(result['package_count'], 0)
        self.assertTrue(result['restart']['reboot_required'])
        argv = self.command.call_args.args[0]
        self.assertEqual(argv, ['/usr/bin/unattended-upgrade', '--verbose', '--minimal-upgrade-steps'])
        self.assertIn('APT_CONFIG', self.command.call_args.kwargs['env'])

    def test_metadata_failure_preserves_last_known_data_as_unknown(self):
        (self.root / 'status.json').write_text(json.dumps({'state': 'ready', 'last_success': 1000, 'package_count': 1, 'packages': [self.row]}))
        self.metadata.return_value = {'fresh': False, 'error': 'network unavailable'}
        with self.assertRaises(s.SecurityError): s.run('cycle', self.root)
        result = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['last_success'], 1000)
        self.assertEqual(result['package_count'], 1)
        self.command.assert_not_called()

    def test_missing_installer_never_reports_success_or_starts_an_install_command(self):
        self.installer.return_value = False
        with self.assertRaisesRegex(s.SecurityError, 'installer is not installed'):
            s.run('install', self.root)
        self.command.assert_not_called()
        self.assertEqual(json.loads((self.root / 'status.json').read_text())['state'], 'unknown')

    def test_a_configuration_change_refreshes_native_state_without_faking_a_security_check(self):
        with patch.object(s, 'configure'):
            s.run('configure', self.root, self.policy)
        state = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(state['state'], 'unverified')
        self.assertEqual(state['native_timer']['enabled'], 'disabled')
        self.assertNotIn('last_success', state)
        self.metadata.assert_not_called()


@unittest.skipUnless(s, 'Linux security jobs')
class SecurityJobs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        source = self.root / 'source/installer'; source.mkdir(parents=True)
        (source / 'os_security.py').write_text('PROTOCOL = 1\n')
        for name, value in {'SOURCE_DIR': source.parent, 'OS_SECURITY_ROOT': self.root / 'security',
                            'MAINTENANCE_LOCK_PATH': self.root / 'maintenance.lock', 'LATEST_PLAN_PATH': self.root / 'plan.json',
                            'ACTIVE_MARKER': self.root / 'active', 'HAPROXY_UPDATE_STATE': self.root / 'patch.json',
                            'HAPROXY_MIGRATION_STATE': self.root / 'migration.json', 'OPERATION_THREAD_LOCK': threading.Lock(),
                            'SHUTDOWN_REQUESTED': threading.Event()}.items():
            patch.object(broker, name, value).start()
        patch.object(broker, 'safe_json_file', side_effect=lambda p: json.loads(p.read_text())).start()
        patch.object(broker, 'reboot_guard_present', return_value=False).start()
        self.transaction = patch.object(broker, 'haproxy_transaction_active', return_value=False).start()
        self.updated = patch.object(broker, 'update_job').start()
        self.failed = patch.object(broker, 'finish_failed').start()
        patch.object(broker, 'os_security_notifications').start()
        patch.object(broker, 'new_job', side_effect=lambda operation, **values: {'id': 'a'*32, 'operation': operation, **values}).start()
        self.thread = patch.object(broker, 'start_thread').start()
        self.snapshot = patch.object(broker, 'os_security_snapshot', return_value={'policy': {'mode': 'notify'}, 'status': None}).start()

    def execute(self, response=None):
        def child(*args, **kwargs):
            with broker.MAINTENANCE_LOCK_PATH.open('a') as lock:
                # The parent unlocked its descriptor. A real native worker
                # can own the same lock while the broker's thread is busy.
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return response or (0, json.dumps({'ok': True, 'request_id': 'a'*32, 'message': 'verified'}))
        with patch.object(broker, 'run_command', side_effect=child) as run:
            args = self.thread.call_args.args
            args[0](*args[1:])
        return run

    def test_async_worker_uses_fixed_commands_and_gives_lock_custody_to_child(self):
        accepted = broker.dispatch({'action': 'os_security_check'})
        self.assertEqual(accepted['job']['operation'], 'security-check')
        run = self.execute()
        argv = run.call_args.args[1]
        self.assertEqual(argv[:3], ['/usr/bin/python3', str(broker.SOURCE_DIR / 'installer/os_security.py'), 'check'])
        self.assertIn('--maintenance-lock', argv)
        self.assertEqual(argv[-2:], ['--request-id', 'a'*32])
        self.failed.assert_not_called()
        self.assertEqual(self.updated.call_args.kwargs['status'], 'completed')
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.assertFalse(broker.ACTIVE_MARKER.exists())

    def test_wrong_job_success_and_nonzero_child_are_never_accepted(self):
        for response in ((0, '{}'), (0, '[]'), (0, json.dumps({'ok': True, 'request_id': 'b'*32})),
                         (1, json.dumps({'ok': True, 'request_id': 'a'*32}))):
            broker.dispatch({'action': 'os_security_check'})
            self.execute(response)
            self.assertTrue(self.failed.called)
            self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())

    def test_configuration_and_package_recovery_block_new_jobs(self):
        self.transaction.return_value = True
        with self.assertRaises(broker.UpdatedError): broker.dispatch({'action': 'os_security_check'})
        self.thread.assert_not_called()
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.transaction.return_value = False
        broker.OS_SECURITY_ROOT.mkdir()
        (broker.OS_SECURITY_ROOT / 'policy.json').write_text('{"phase":"configuring"}')
        with self.assertRaises(broker.UpdatedError): broker.acquire_operation()
        accepted = broker.dispatch({'action': 'os_security_configure', 'mode': 'system', 'interval': 4, 'start': 3, 'end': 5, 'confirmation': 'SECURITY'})
        self.assertEqual(accepted['job']['operation'], 'security-configure')
        self.execute()

    def test_install_requires_managed_policy_and_exact_confirmation(self):
        with self.assertRaises(broker.UpdatedError): broker.dispatch({'action': 'os_security_install', 'confirmation': 'UPDATE'})
        self.snapshot.return_value['policy']['mode'] = 'system'
        with self.assertRaises(broker.UpdatedError): broker.dispatch({'action': 'os_security_install', 'confirmation': 'SECURITY'})
        self.thread.assert_not_called()
        with self.assertRaises(broker.UpdatedError): broker.dispatch({'action': 'os_security_cycle'})


@unittest.skipUnless(s, 'Linux route/security fixtures')
class SecurityWebRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_update_web import ROUTES, REQUEST, CONFIG_STATE, FakeBlueprint, AbortCalled, load_security_module, load_module
        cls.base, cls.request, cls.config = ROUTES, REQUEST, CONFIG_STATE
        cls.abort_error = AbortCalled
        import types
        flask = types.ModuleType('flask')
        flask.Blueprint, flask.abort, flask.render_template, flask.request = FakeBlueprint, ROUTES.abort, ROUTES.render_template, REQUEST
        package = types.ModuleType('easy_ha_update_routes_test')
        package.__path__ = [str(ROOT / 'docker/app/haproxy_admin')]
        with patch.dict(sys.modules, {'flask': flask, 'easy_ha_update_routes_test': package,
                                      'easy_ha_update_routes_test.routes_updates': ROUTES}):
            cls.routes = load_module('easy_ha_update_routes_test.routes_os_security', ROOT / 'docker/app/haproxy_admin/routes_os_security.py')
        cls.security, cls.security_request, cls.identity = load_security_module()

    def setUp(self):
        self.addCleanup(patch.stopall)
        self.config.reset_mock(return_value=True, side_effect=True)
        self.config.return_value = {'state': 'clean'}
        self.rpc = patch.object(self.base, 'updated_request', return_value={'ok': True, 'job_id': 'a'*32}).start()
        self.audit = patch.object(self.base, 'record_request').start()
        self.request.args = {}

    def body(self, value):
        self.request.get_json = lambda silent=True: value

    def test_new_html_and_api_require_superadmin(self):
        self.assertIn('/system/os-security', self.security.SUPERADMIN_PREFIXES)
        for path in ('/system/os-security/', '/system/os-security/api/status', '/system/os-security/api/policy'):
            self.security_request.path, self.security_request.method = path, 'GET'
            self.security_request.is_json = '/api/' in path
            self.security_request.headers = {'X-Easy-HA-Proxy-Secret': 'fixture-secret', 'Remote-User': 'operator', 'Remote-Groups': 'admins'}
            with patch.dict(os.environ, {'HAPROXY_ADMIN_PROXY_SECRET': 'fixture-secret'}):
                if '/api/' in path:
                    self.assertEqual(self.security.enforce_proxy_and_role()[1], 403)
                else:
                    with self.assertRaises(self.abort_error): self.security.enforce_proxy_and_role()
                self.security_request.headers['Remote-Groups'] = 'superadmin'
                self.assertIsNone(self.security.enforce_proxy_and_role())

    def test_policy_is_audited_and_has_no_arbitrary_host_arguments(self):
        policy = {'mode': 'auto', 'interval': 2, 'start': 23, 'end': 2, 'confirmation': 'SECURITY'}
        for change in ({'mode': []}, {'interval': True}, {'end': 23}, {'command': 'id'}, {'confirmation': 'UPDATE'}):
            self.body({**policy, **change})
            with self.assertRaises(self.abort_error): self.routes.policy()
        self.rpc.assert_not_called()
        self.body(policy)
        self.assertEqual(self.routes.policy()[1], 202)
        self.assertEqual(self.rpc.call_args.args[0], {'action': 'os_security_configure', **policy})
        self.assertEqual(self.audit.call_args.args[0], 'os.security_policy')

    def test_pending_configuration_blocks_both_mutations(self):
        self.config.return_value = {'state': 'pending'}
        self.body({'mode': 'notify', 'interval': 4, 'start': 3, 'end': 5, 'confirmation': 'SECURITY'})
        self.assertEqual(self.routes.policy()[1], 409)
        self.body({'confirmation': 'SECURITY'})
        self.assertEqual(self.routes.install()[1], 409)
        self.rpc.assert_not_called()


if __name__ == '__main__':
    unittest.main()
