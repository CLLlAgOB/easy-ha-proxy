"""Independent restart scheduling, excluded services and verified reboot fallback."""
from __future__ import annotations

import datetime as dt
from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer'))
sys.path.insert(0, str(ROOT / '.tests'))
if sys.platform == 'linux':
    import service_restarts as s
    from test_haproxy_update_broker import broker
    import test_auto_reboot as reboot_tests
    import test_os_security as security_tests
else:
    s = broker = None

BOOT = '11111111-1111-1111-1111-111111111111'


@unittest.skipUnless(s, 'Linux service restart executor')
class ServiceRestarts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.addCleanup(patch.stopall)
        self.boot = self.root / 'boot'; self.boot.write_text(BOOT)
        self.now = dt.datetime(2026, 11, 8, 2, 20, tzinfo=dt.timezone.utc)
        self.policy = {'enabled': True, 'time': '02:15', 'id': 'a'*32, 'updated_at': self.now.timestamp()-7200}
        self.save_policy()
        (self.root / 'policy.json').write_text('{"phase":"ready","policy":{"mode":"daily"}}')
        patch.object(s, 'BOOT', self.boot).start()
        patch.object(s, 'platform').start()
        self.guard = patch.object(s, 'maintenance_guard').start()
        self.managed = patch.object(s, 'assert_managed').start()
        patch.object(s, 'package_locks', side_effect=nullcontext).start()
        patch.object(s.os, 'fchown').start()
        patch.object(s, 'read_json', side_effect=lambda p: json.loads(p.read_text())).start()
        patch.object(s.time, 'time', return_value=self.now.timestamp()).start()
        self.scan = patch.object(s, 'restart_status', return_value=self.restart()).start()
        self.command = patch.object(s, 'command', return_value=(0, 'active\n')).start()
        patch.object(broker, 'current_boot_id', return_value=BOOT).start()

    def save_policy(self):
        (self.root / 'restart-policy.json').write_text(json.dumps(self.policy))

    def restart(self, *units, error=None):
        return {'services': list(units), 'reboot_required': False, 'error': error, 'checked_at': self.now.timestamp()}

    def state(self):
        return json.loads((self.root / 'restart-status.json').read_text())

    def test_empty_package_day_still_restarts_services_and_preserves_exclusions(self):
        self.scan.side_effect = [self.restart('cron.service', 'dbus.service', 'haproxy.service'), self.restart('dbus.service', 'haproxy.service')]
        def command(argv, **kwargs):
            if argv[0] == '/usr/sbin/needrestart':
                config = Path(argv[-1]).read_text()
                self.assertIn('/etc/needrestart/needrestart.conf', config)
                for unit in ('systemd-networkd', 'haproxy', 'docker', 'containerd', 'easy-ha-proxy-updated-job-'):
                    self.assertIn(unit, config)
                self.assertEqual(argv[1:4], ['-r', 'a', '-c'])
            return 0, 'active\n'
        self.command.side_effect = command
        result = s.run('restart-cycle', self.root, now=self.now)
        self.assertEqual(result['restarted'], ['cron.service'])
        self.assertEqual(result['deferred'], ['dbus.service', 'haproxy.service'])
        self.assertTrue(result['verified'])
        self.assertEqual(self.command.call_count, 2)
        self.assertFalse(any('apt' in call.args[0][0] for call in self.command.call_args_list))
        self.assertFalse(s.due(self.policy, self.state(), self.now, BOOT)[0])

    def test_native_exclusion_config_keeps_existing_rules_and_protects_network_workers(self):
        if not Path('/usr/bin/perl').exists():
            self.skipTest('Perl is used by the native needrestart package')
        config = self.root / 'exclusions.conf'
        config.write_text(s.EXCLUSIONS)
        units = ['haproxy.service', 'docker.service', 'dnsmasq.service', 'systemd-networkd.service', 'systemd-resolved.service',
                 'easy-ha-proxy-updated-job-' + 'a'*12 + '.service', 'cron.service']
        code = 'our %nrconf; do $ARGV[0]; die $@ if $@; for my $unit (@ARGV[1..$#ARGV]) { print((grep { $unit =~ $_ } keys %{$nrconf{override_rc}}) ? "blocked\\n" : "allowed\\n"); }'
        result = subprocess.run(['/usr/bin/perl', '-e', code, str(config), *units], text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.splitlines(), ['blocked']*6 + ['allowed'])

    def test_check_does_not_consume_the_window_or_erase_application_evidence(self):
        s.run('restart-check', self.root, now=self.now)
        self.command.assert_not_called(); self.managed.assert_not_called()
        self.assertTrue(s.due(self.policy, self.state(), self.now, BOOT)[0])
        result = s.run('restart-cycle', self.root, now=self.now)
        self.assertTrue(result['applied'])
        s.run('restart-check', self.root, now=self.now)
        self.assertTrue(self.state()['applied'])
        self.assertFalse(s.due(self.policy, self.state(), self.now, BOOT)[0])

    def test_failures_never_supply_reboot_evidence(self):
        for failure in ('scan', 'command', 'health', 'unresolved'):
            with self.subTest(failure=failure):
                self.scan.side_effect = [self.restart('cron.service'), self.restart('cron.service') if failure == 'unresolved' else self.restart()]
                self.command.side_effect = None
                self.command.return_value = (0, 'inactive\n' if failure == 'health' else 'active\n')
                if failure == 'scan': self.scan.side_effect = [self.restart(error='unknown')]
                if failure == 'command': self.command.side_effect = s.SecurityError('restart failed')
                if failure == 'unresolved':
                    result = s.run('restart', self.root, now=self.now)
                    self.assertFalse(result['verified'])
                else:
                    with self.assertRaises(s.SecurityError): s.run('restart', self.root, now=self.now)
                    self.assertEqual(self.state()['state'], 'unknown')
                self.assertEqual(s.fallback_services(self.root, now=self.now), [])

    def test_unsupported_service_is_never_sent_to_systemctl(self):
        self.scan.return_value = self.restart('cron.service;reboot')
        with self.assertRaises(s.SecurityError): s.run('restart', self.root, now=self.now)
        self.command.assert_not_called()

    def test_package_lock_failure_is_recorded_and_throttles_both_schedulers(self):
        with patch.object(s, 'package_locks', side_effect=s.SecurityError('Unsafe package-manager lock')):
            with self.assertRaisesRegex(s.SecurityError, 'Unsafe package-manager lock'):
                s.run('restart-cycle', self.root, now=self.now)
        self.scan.assert_not_called()
        self.command.assert_not_called()
        state = self.state()
        self.assertEqual(state['state'], 'unknown')
        self.assertFalse(state['applied'])
        self.assertFalse(state['verified'])
        self.assertEqual(state['last_attempt'], self.now.timestamp())
        self.assertEqual(state['error'], 'Unsafe package-manager lock')
        self.assertEqual(s.fallback_services(self.root, now=self.now), [])
        for seconds, expected in ((60, False), (299, False), (300, True)):
            later = self.now + dt.timedelta(seconds=seconds)
            self.assertEqual(s.due(self.policy, state, later, BOOT)[0], expected)
            self.assertEqual(broker.service_restart_due(self.policy, state, later)[0], expected)

    def test_read_only_check_does_not_acquire_package_locks(self):
        with patch.object(s, 'package_locks') as locks:
            s.run('restart-check', self.root, now=self.now)
        locks.assert_not_called()

    def test_busy_apt_preflight_also_records_the_attempt(self):
        self.guard.side_effect = s.SecurityError('APT is busy; retry OS security maintenance later')
        with self.assertRaisesRegex(s.SecurityError, 'APT is busy'):
            s.run('restart-cycle', self.root, now=self.now)
        self.scan.assert_not_called()
        self.command.assert_not_called()
        state = self.state()
        self.assertEqual(state['state'], 'unknown')
        self.assertEqual(state['last_attempt'], self.now.timestamp())
        self.assertFalse(s.due(self.policy, state, self.now + dt.timedelta(seconds=60), BOOT)[0])

    def test_worker_rechecks_revoked_policy_and_window_before_mutation(self):
        for change in ({'enabled': False}, {'updated_at': self.now.timestamp()}, {'time': '04:00'}):
            with self.subTest(change=change):
                self.policy.update(change); self.save_policy()
                s.run('restart-cycle', self.root, now=self.now)
                self.scan.assert_not_called(); self.command.assert_not_called()
                self.policy.update(enabled=True, time='02:15', updated_at=self.now.timestamp()-7200)

    def test_fallback_only_uses_fresh_known_deferred_services_after_verified_application(self):
        self.scan.return_value = self.restart('dbus.service')
        s.run('restart-cycle', self.root, now=self.now)
        self.assertEqual(s.fallback_services(self.root, now=self.now), ['dbus.service'])
        self.command.assert_not_called()
        saved = self.state()
        for change in ({'state':'unknown'}, {'verified':False}, {'applied':False}, {'boot_id':'old'},
                       {'policy_id':'b'*32}, {'window':'old'}, {'failed_services':['cron.service']},
                       {'unresolved':['cron.service']}, {'completed_at':self.now.timestamp()-90000}):
            with self.subTest(change=change):
                (self.root/'restart-status.json').write_text(json.dumps({**saved, **change}))
                self.assertEqual(s.fallback_services(self.root, now=self.now), [])
        (self.root/'restart-status.json').write_text(json.dumps(saved))
        self.scan.return_value = self.restart('dbus.service', 'cron.service')
        self.assertEqual(s.fallback_services(self.root, now=self.now), [])
        self.scan.return_value = self.restart(error='unknown')
        with self.assertRaises(s.SecurityError): s.fallback_services(self.root, now=self.now)
        self.policy['enabled'] = False; self.save_policy()
        self.assertEqual(s.fallback_services(self.root, now=self.now), [])

    def test_broker_and_executor_agree_across_clock_changes_and_retries(self):
        from zoneinfo import ZoneInfo
        zone = ZoneInfo('Europe/Warsaw')
        for local in (self.now, dt.datetime(2026,10,25,2,20,tzinfo=zone,fold=0), dt.datetime(2026,10,25,2,20,tzinfo=zone,fold=1),
                      dt.datetime(2026,3,29,3,20,tzinfo=zone)):
            for status in ({}, {'state':'ready','applied':True,'policy_id':'a'*32,'boot_id':BOOT,'window':s.window(local,'02:15')[1]},
                           {'state':'running','policy_id':'a'*32,'boot_id':BOOT,'last_attempt':local.timestamp()-400}):
                self.assertEqual(s.due(self.policy,status,local,BOOT), broker.service_restart_due(self.policy,status,local))
        first=dt.datetime(2026,10,25,2,20,tzinfo=zone,fold=0)
        self.policy['updated_at']=first.timestamp()-7200
        status={'state':'ready','applied':True,'policy_id':'a'*32,'boot_id':BOOT,'window':s.window(first,'02:15')[1]}
        self.assertFalse(s.due(self.policy,status,first.replace(fold=1),BOOT)[0])
        self.assertFalse(s.due(self.policy,{**status,'boot_id':'previous-boot'},first,BOOT)[0])


@unittest.skipUnless(s, 'Linux restart broker')
class RestartBroker(reboot_tests.RebootBroker if s else unittest.TestCase):
    def setUp(self):
        super().setUp()
        (broker.SOURCE_DIR/'installer/service_restarts.py').write_text('SERVICE_RESTART_PROTOCOL = 1\n')
        (broker.SOURCE_DIR/'installer/auto_reboot.py').write_text('AUTO_REBOOT_PROTOCOL = 1\nSERVICE_REBOOT_PROTOCOL = 1\n')

    def save_restarts(self, **changes):
        return broker.dispatch({'action':'set_service_restarts','enabled':True,'time':'02:15','confirmation':'SECURITY',
                                'expected_boot_id':BOOT,'actor':'tester',**changes})

    def test_policy_is_off_by_default_and_does_not_start_a_job_when_saved(self):
        self.assertFalse(broker.service_restart_record()['enabled'])
        self.save_restarts()
        self.assertTrue(broker.service_restart_record()['enabled'])
        self.proc.assert_not_called()
        for change in ({'enabled':1},{'time':'24:00'},{'time':[]},{'confirmation':'UPDATE'},{'command':'reboot'}):
            with self.subTest(change=change), self.assertRaises(broker.UpdatedError): self.save_restarts(**change)
        self.mode.return_value['policy']['mode']='system'
        with self.assertRaises(broker.UpdatedError): self.save_restarts()

    def test_scheduler_runs_independently_of_package_freshness_and_retries_busy_work(self):
        self.save_restarts()
        self.mode.return_value.update(available=True,recovery_required=False,status={'last_success':self.now.timestamp()})
        local=self.now.replace(hour=2,minute=20)
        # The saved policy predates the window in this fixture.
        value=broker.service_restart_record(); value['updated_at']=local.timestamp()-7200
        broker.atomic_json(self.root/'restart-policy.json',value)
        with patch.object(broker,'start_os_security',side_effect=broker.UpdatedError('busy',code='busy')) as start:
            self.assertEqual(broker.service_restart_tick(local),'busy')
            self.assertFalse((self.root/'restart-status.json').exists())
            start.side_effect=None
            self.assertEqual(broker.service_restart_tick(local),'started')
            self.assertEqual(start.call_args.args[0],{'action':'os_security_restart_cycle'})

    def test_reboot_fallback_requires_explicit_consent_and_reverified_evidence(self):
        self.save_restarts(); self.save()
        with patch.object(broker,'service_reboot_reason',return_value=['dbus.service']) as evidence:
            self.assertEqual(broker.auto_reboot_tick(self.now),'disabled')
            evidence.assert_not_called()
            self.save(allow_service_reboot=True)
            self.assertEqual(broker.auto_reboot_tick(self.now),'scheduled')
            marker=json.loads(broker.REBOOT_MARKER.read_text())
            self.assertEqual(marker['automatic']['reason'],'services')
            self.assertEqual(marker['automatic']['restart_policy_revision'],broker.service_restart_record()['id'])
            self.save_restarts(enabled=False)
            self.assertFalse(broker.REBOOT_MARKER.exists())

    def test_empty_fallback_evidence_is_not_required_and_never_arms_a_reboot(self):
        self.save_restarts(); self.save(allow_service_reboot=True)
        with patch.object(broker,'service_reboot_reason',return_value=[]):
            self.assertEqual(broker.auto_reboot_tick(self.now), 'not_required')
        self.assertFalse(broker.REBOOT_MARKER.exists())
        self.proc.assert_not_called()
        self.assertEqual(broker.auto_reboot_record()['attempt']['state'], 'not_required')

    def test_unknown_fallback_evidence_is_a_verification_failure_and_never_arms_a_reboot(self):
        self.save_restarts(); self.save(allow_service_reboot=True)
        with patch.object(broker,'service_reboot_reason',side_effect=broker.UpdatedError('Unverified restart state',code='verification_failed')):
            self.assertEqual(broker.auto_reboot_tick(self.now), 'verification_failed')
        self.assertFalse(broker.REBOOT_MARKER.exists())
        self.proc.assert_not_called()
        attempt = broker.auto_reboot_record()['attempt']
        self.assertEqual(attempt['state'], 'deferred')
        self.assertIn('Unverified', attempt['error'])


@unittest.skipUnless(s, 'Linux reboot final executor')
class RestartRebootExecutor(reboot_tests.RebootExecutor if s else unittest.TestCase):
    def test_service_reason_needs_current_consent_and_current_service_policy_at_fire_time(self):
        self.required.unlink()
        self.policy['allow_service_reboot']=True; self.save()
        self.owned['automatic'].update(reason='services',restart_policy_revision='c'*32)
        self.marker.write_text(json.dumps(self.owned))
        with patch.object(s,'policy',return_value={'id':'c'*32}), patch.object(s,'fallback_services',return_value=['dbus.service']):
            self.assertEqual(self.fire(),'triggered')
        self.command.assert_called_once_with(['/usr/bin/systemctl','reboot'],timeout=30)

    def test_revoked_stale_or_unknown_service_reason_never_reboots(self):
        self.required.unlink()
        self.owned['automatic'].update(reason='services',restart_policy_revision='c'*32)
        for allowed, revision, services in ((False,'c'*32,['dbus.service']),(True,'d'*32,['dbus.service']),(True,'c'*32,[])):
            self.policy['allow_service_reboot']=allowed
            self.policy['attempt']['state']='scheduled'; self.save()
            self.marker.write_text(json.dumps(self.owned))
            with patch.object(s,'policy',return_value={'id':revision}), patch.object(s,'fallback_services',return_value=services):
                self.assertEqual(self.fire(),'not_required')
            self.command.assert_not_called()


@unittest.skipUnless(s, 'Linux asynchronous restart jobs')
class RestartJobs(security_tests.SecurityJobs if s else unittest.TestCase):
    def test_restart_worker_uses_the_fixed_native_executor_and_shared_lock(self):
        (broker.SOURCE_DIR/'installer/service_restarts.py').write_text('SERVICE_RESTART_PROTOCOL = 1\n')
        broker.dispatch({'action':'os_security_restart','confirmation':'SECURITY'})
        run=self.execute()
        self.assertEqual(run.call_args.args[1][:3],['/usr/bin/python3',str(broker.SOURCE_DIR/'installer/service_restarts.py'),'restart'])
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.failed.assert_not_called()


@unittest.skipUnless(s, 'Linux restart status')
class RestartStatus(unittest.TestCase):
    def test_failed_health_verification_never_resolves_the_previous_restart_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'status.json').write_text(json.dumps({'state':'ready','restart':{'services':['cron.service'],'checked_at':10}}))
            (root/'restart-status.json').write_text(json.dumps({'state':'unknown','boot_id':BOOT,'error':'inactive service',
                'last_attempt':20,'restart':{'services':[],'checked_at':30},'check':{'services':[],'checked_at':40},'check_boot_id':BOOT}))
            tool=root/'os_security.py';tool.write_text('SETTINGS_PROTOCOL = 1\n')
            with patch.object(broker,'OS_SECURITY_ROOT',root), patch.object(broker,'os_security_tool',return_value=tool), \
                    patch.object(broker,'safe_json_file',side_effect=lambda p:json.loads(p.read_text())), \
                    patch.object(broker,'current_boot_id',return_value=BOOT):
                snapshot=broker.os_security_snapshot()
                self.assertEqual(snapshot['status']['restart']['error'],'inactive service')
            self.assertEqual(json.loads((root/'status.json').read_text())['restart']['checked_at'],10)


@unittest.skipUnless(s, 'Linux web route fixtures')
class RestartWeb(security_tests.SecurityWebRoutes if s else unittest.TestCase):
    def test_restart_policy_and_manual_action_are_validated_and_audited(self):
        body={'enabled':True,'time':'02:15','confirmation':'SECURITY','expected_boot_id':BOOT}
        self.body(body); self.assertEqual(self.routes.restart_policy()[1],200)
        self.assertEqual(self.audit.call_args.args[0],'os.service_restart_policy')
        for change in ({'enabled':1},{'time':'24:00'},{'confirmation':'REBOOT'},{'command':'id'}):
            self.body({**body,**change})
            with self.assertRaises(self.abort_error): self.routes.restart_policy()
        self.body({'confirmation':'SECURITY'}); self.assertEqual(self.routes.restart_services()[1],202)
        self.assertEqual(self.audit.call_args.args[0],'os.service_restart')
        self.body({}); self.assertEqual(self.routes.restart_check()[1],202)

    def test_reboot_fallback_boolean_and_audit_preserve_existing_api_compatibility(self):
        body={'enabled':True,'time':'03:00','confirmation':'REBOOT','expected_boot_id':BOOT,'allow_service_reboot':True}
        self.body(body); self.assertEqual(self.routes.automatic_reboot()[1],200)
        self.assertTrue(self.rpc.call_args.args[0]['allow_service_reboot'])
        self.body({**body,'allow_service_reboot':1})
        with self.assertRaises(self.abort_error): self.routes.automatic_reboot()


if __name__ == '__main__':
    unittest.main()
