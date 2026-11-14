"""Scheduled reboot consent, cancellation and final package-manager custody."""
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tests'))
sys.path.insert(0, str(ROOT / 'installer'))
if sys.platform == 'linux':
    spec = importlib.util.spec_from_file_location('reboot_executor_test', ROOT / 'installer/auto_reboot.py')
    r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
    from test_haproxy_update_broker import broker
else:
    r = broker = None

BOOT = '11111111-1111-1111-1111-111111111111'
UNIT = 'easy-ha-proxy-web-reboot-' + 'a' * 12


@unittest.skipUnless(r, 'Linux reboot executor')
class RebootExecutor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.marker, self.required, self.lock = (self.root / name for name in ('reboot.json', 'required', 'maintenance.lock'))
        self.boot = self.root / 'boot'; self.boot.write_text(BOOT)
        self.now = dt.datetime(2026, 11, 8, 3, 5, tzinfo=dt.timezone.utc)
        self.policy = {'enabled': True, 'time': '03:00', 'id': 'b'*32, 'updated_at': self.now.timestamp()-3600,
                       'attempt': {'window': '2026-11-08 03:00', 'state': 'scheduled', 'at': self.now.timestamp()-60}}
        self.required.touch(); self.save()
        self.owned = {'unit': UNIT, 'boot_id': BOOT, 'automatic': {'policy_revision': 'b'*32, 'window': '2026-11-08 03:00'}}
        self.marker.write_text(json.dumps(self.owned))
        self.addCleanup(patch.stopall)
        patch.object(r, 'BOOT', self.boot).start()
        patch.object(r, 'read_json', side_effect=lambda p: json.loads(p.read_text())).start()
        patch.object(r.os, 'fchown').start()
        actual_fstat = os.fstat
        def root_stat(fd):
            values = list(actual_fstat(fd)); values[4] = 0
            return os.stat_result(values)
        patch.object(r.os, 'fstat', side_effect=root_stat).start()
        self.guard = patch.object(r, 'maintenance_guard').start()
        self.managed = patch.object(r, 'assert_managed').start()
        self.command = patch.object(r, 'command', return_value=(0, '')).start()
        apt_lock = self.root / 'dpkg.lock'; apt_lock.touch()
        patch.object(r, 'APT_LOCKS', (apt_lock,)).start()

    def save(self):
        (self.root / 'reboot-policy.json').write_text(json.dumps(self.policy))
        (self.root / 'policy.json').write_text('{"phase":"ready","policy":{"mode":"daily"}}')

    def fire(self, **kwargs):
        return r.fire(self.root, self.lock, self.marker, self.required, UNIT, now=kwargs.get('now', self.now))

    def test_only_verified_current_consent_can_request_the_fixed_reboot(self):
        self.assertEqual(self.fire(), 'triggered')
        self.command.assert_called_once_with(['/usr/bin/systemctl', 'reboot'], timeout=30)
        self.guard.assert_called_once_with(allow_web_reboot=True)
        self.assertTrue(self.marker.exists())
        self.assertEqual(json.loads((self.root / 'reboot-policy.json').read_text())['attempt']['state'], 'triggered')
        self.fire()
        self.assertEqual(self.command.call_count, 1)

    def test_disabled_replaced_or_canceled_policy_and_previous_boot_never_reboot(self):
        for change in ({'enabled': False}, {'id': 'c'*32}, {'attempt': {'window':'2026-11-08 03:00','state':'canceled'}}, {'old_boot':True}):
            with self.subTest(change=change):
                self.policy = {**self.policy, **change}; self.save()
                marker = {**self.owned, 'boot_id': 'old' if change.get('old_boot') else BOOT}
                self.marker.write_text(json.dumps(marker))
                self.assertEqual(self.fire(), 'canceled')
                self.assertFalse(self.marker.exists())
                self.command.assert_not_called()
                self.policy.update(enabled=True, id='b'*32, attempt={'window':'2026-11-08 03:00','state':'scheduled'})

    def test_unrelated_unit_marker_is_never_consumed(self):
        self.marker.write_text(json.dumps({**self.owned, 'unit': UNIT[:-1]+'f'}))
        self.assertEqual(self.fire(), 'obsolete')
        self.assertTrue(self.marker.exists()); self.command.assert_not_called()
        with self.assertRaises(r.SecurityError):
            r.fire(self.root, self.lock, self.marker, self.required, UNIT+';reboot', now=self.now)

    def test_no_required_reboot_or_missed_window_clears_only_its_own_guard(self):
        self.required.unlink()
        self.assertEqual(self.fire(), 'not_required')
        self.assertFalse(self.marker.exists()); self.command.assert_not_called()
        self.marker.write_text(json.dumps(self.owned)); self.required.touch()
        self.policy['attempt']['state'] = 'scheduled'; self.save()
        self.assertEqual(self.fire(now=self.now.replace(hour=4)), 'missed')
        self.assertFalse(self.marker.exists()); self.command.assert_not_called()

    def test_package_or_configuration_recovery_defers_without_rebooting(self):
        self.guard.side_effect = r.SecurityError('package recovery is pending')
        self.assertEqual(self.fire(), 'deferred')
        self.assertFalse(self.marker.exists()); self.command.assert_not_called()
        attempt = json.loads((self.root / 'reboot-policy.json').read_text())['attempt']
        self.assertEqual(attempt['state'], 'deferred'); self.assertIn('recovery', attempt['error'])

    def test_an_actual_posix_apt_lock_blocks_the_final_reboot(self):
        child = subprocess.Popen([sys.executable, '-c', 'import fcntl,sys; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read()', str(r.APT_LOCKS[0])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            self.assertEqual(self.fire(), 'deferred')
            self.command.assert_not_called(); self.assertFalse(self.marker.exists())
        finally:
            child.communicate(timeout=10)

    def test_non_root_package_lock_is_rejected_and_names_the_file(self):
        root_fstat = r.os.fstat
        def changed_owner(fd):
            values = list(root_fstat(fd))
            if os.readlink(f'/proc/self/fd/{fd}') == str(r.APT_LOCKS[0]):
                values[4] = 1020
            return os.stat_result(values)
        with patch.object(r.os, 'fstat', side_effect=changed_owner):
            self.assertEqual(self.fire(), 'deferred')
        self.command.assert_not_called()
        attempt = json.loads((self.root / 'reboot-policy.json').read_text())['attempt']
        self.assertIn('Unsafe package-manager lock', attempt['error'])
        self.assertIn(str(r.APT_LOCKS[0]), attempt['error'])

    def test_reboot_command_failure_is_retryable_and_releases_custody(self):
        self.command.side_effect = r.SecurityError('systemctl failed')
        self.assertEqual(self.fire(), 'deferred')
        self.assertFalse(self.marker.exists())
        import fcntl
        with self.lock.open('r+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_corrupt_consent_defers_without_rebooting(self):
        for change in ({'enabled':1},{'time':'24:00'},{'id':'invalid'},{'attempt':[]}):
            with self.subTest(change=change):
                (self.root/'reboot-policy.json').write_text(json.dumps({**self.policy,**change}))
                self.marker.write_text(json.dumps(self.owned))
                self.assertEqual(self.fire(),'deferred')
                self.command.assert_not_called()

    def test_final_guard_ignores_only_its_verified_web_marker(self):
        native = sys.modules['os_security']
        virtual = self.root / 'virtual'
        def mapped(path): return virtual / str(path).lstrip('/')
        marker = mapped('/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json')
        marker.parent.mkdir(parents=True); marker.touch()
        with patch.object(native,'Path',side_effect=mapped), patch.object(native,'command',return_value=(0,'')):
            with self.assertRaises(r.SecurityError): native.maintenance_guard()
            native.maintenance_guard(allow_web_reboot=True)
            for name in ('reboot-scheduled','easy-ha-proxy-backupd-restore.active'):
                other = marker.parent/name; other.touch()
                with self.assertRaises(r.SecurityError): native.maintenance_guard(allow_web_reboot=True)
                other.unlink()


@unittest.skipUnless(r, 'Linux reboot scheduler')
class RebootSchedule(unittest.TestCase):
    def test_exact_minute_grace_midnight_and_dst_use_the_same_contract(self):
        from zoneinfo import ZoneInfo
        zone = ZoneInfo('Europe/Warsaw')
        for local, text in ((dt.datetime(2026,11,8,3,5,tzinfo=zone),'03:00'),
                            (dt.datetime(2026,11,9,0,5,tzinfo=zone),'23:45'),
                            (dt.datetime(2026,10,25,2,45,tzinfo=zone,fold=1),'02:30'),
                            (dt.datetime(2026,3,29,3,35,tzinfo=zone),'02:30')):
            with self.subTest(local=local):
                self.assertEqual(r.window(local, text), broker.auto_reboot_window(local, text))
                anchor, key = r.window(local, text)
                value = {'enabled':True,'time':text,'updated_at':anchor.timestamp()-1}
                self.assertEqual(r.due(value,local), broker.auto_reboot_due(value,local))
                value['attempt'] = {'window':key,'state':'canceled','at':anchor.timestamp()}
                self.assertFalse(broker.auto_reboot_due(value,local)[0])
        local = dt.datetime(2026,11,8,3,5,tzinfo=zone)
        self.assertFalse(broker.auto_reboot_due({'enabled':True,'time':'03:00','updated_at':local.timestamp()},local)[0])


@unittest.skipUnless(r, 'Linux reboot broker')
class RebootBroker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.addCleanup(patch.stopall)
        source = self.root / 'source/installer'; source.mkdir(parents=True)
        (source / 'auto_reboot.py').write_text('AUTO_REBOOT_PROTOCOL = 1\n')
        for name, value in {'SOURCE_DIR':source.parent,'OS_SECURITY_ROOT':self.root,'MAINTENANCE_LOCK_PATH':self.root/'lock',
                            'ACTIVE_MARKER':self.root/'active','REBOOT_MARKER':self.root/'reboot.json','ASSISTANT_REBOOT_MARKER':self.root/'other-reboot',
                            'REBOOT_REQUIRED_PATH':self.root/'required','BACKUPD_RESTORE_ACTIVE_MARKER':self.root/'restore',
                            'HAPROXY_UPDATE_STATE':self.root/'patch.json','HAPROXY_MIGRATION_STATE':self.root/'migration.json',
                            'OPERATION_THREAD_LOCK':threading.Lock(),'SHUTDOWN_REQUESTED':threading.Event()}.items():
            patch.object(broker,name,value).start()
        patch.object(broker,'safe_json_file',side_effect=lambda p:json.loads(p.read_text())).start()
        patch.object(broker,'atomic_json',side_effect=lambda p,v:p.write_text(json.dumps(v))).start()
        patch.object(broker,'request_identity',return_value=(BOOT,'tester')).start()
        patch.object(broker,'current_boot_id',return_value=BOOT).start()
        self.mode = patch.object(broker,'os_security_snapshot',return_value={'policy':{'mode':'daily'}}).start()
        patch.object(broker,'haproxy_transaction_active',return_value=False).start()
        self.proc = patch.object(broker.subprocess,'run',return_value=NS(returncode=0,stdout='',stderr='')).start()
        self.stop = patch.object(broker,'stop_reboot_unit').start()
        self.now = dt.datetime(2026,11,8,3,5,tzinfo=dt.timezone.utc)
        patch.object(broker.time,'time',return_value=self.now.timestamp()-3600).start()

    def save(self, **changes):
        return broker.dispatch({'action':'set_auto_reboot','enabled':True,'time':'03:00','confirmation':'REBOOT','expected_boot_id':BOOT,'actor':'tester',**changes})

    def test_default_is_off_and_saving_does_not_arm_an_overnight_guard(self):
        self.assertFalse(broker.auto_reboot_record()['enabled'])
        self.save()
        self.assertTrue(broker.auto_reboot_record()['enabled'])
        self.assertFalse(broker.REBOOT_MARKER.exists()); self.proc.assert_not_called()
        self.assertEqual(broker.auto_reboot_tick(self.now),'disabled')
        for change in ({'enabled':1},{'time':'24:00'},{'time':'03:01;reboot'},{'confirmation':'UPDATE'},{'command':'id'}):
            with self.subTest(change=change), self.assertRaises(broker.UpdatedError): self.save(**change)
        self.mode.return_value['policy']['mode']='system'
        with self.assertRaises(broker.UpdatedError): self.save()

    def test_required_reboot_arms_a_fixed_final_executor_and_cancellation_is_durable(self):
        self.save(); broker.REBOOT_REQUIRED_PATH.touch()
        self.assertEqual(broker.auto_reboot_tick(self.now),'scheduled')
        command = self.proc.call_args.args[0]
        self.assertIn('--on-active=60s',command)
        self.assertIn(str(broker.SOURCE_DIR/'installer/auto_reboot.py'),command)
        self.assertNotEqual(command[-2:],[broker.SYSTEMCTL_PATH,'reboot'])
        self.assertFalse(broker.OPERATION_THREAD_LOCK.locked())
        self.assertEqual(broker.auto_reboot_tick(self.now),'waiting')
        broker.cancel_reboot({'expected_boot_id':BOOT,'actor':'tester'})
        self.assertFalse(broker.REBOOT_MARKER.exists())
        self.assertEqual(broker.auto_reboot_record()['attempt']['state'],'canceled')
        self.assertEqual(broker.auto_reboot_tick(self.now+dt.timedelta(minutes=1)),'waiting')
        self.assertEqual(self.proc.call_count,1)

    def test_disabling_cancels_its_timer_and_busy_maintenance_keeps_the_turn(self):
        self.save(); broker.REBOOT_REQUIRED_PATH.touch()
        import fcntl
        with broker.MAINTENANCE_LOCK_PATH.open('a') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(broker.auto_reboot_tick(self.now),'busy')
        self.assertEqual(broker.auto_reboot_tick(self.now),'scheduled')
        self.save(enabled=False)
        self.stop.assert_called_once(); self.assertFalse(broker.REBOOT_MARKER.exists())
        self.assertFalse(broker.auto_reboot_record()['enabled'])

    def test_a_manual_reboot_is_not_canceled_by_the_automatic_policy(self):
        self.save()
        broker.REBOOT_MARKER.write_text(json.dumps({'unit':UNIT,'boot_id':BOOT,'scheduled_at':self.now.isoformat(),'delay_seconds':60}))
        self.save(enabled=False)
        self.stop.assert_not_called(); self.assertTrue(broker.REBOOT_MARKER.exists())

    def test_revoked_consent_between_poll_and_lock_acquisition_is_respected(self):
        self.save(); broker.REBOOT_REQUIRED_PATH.touch()
        actual_acquire = broker.acquire_operation
        def revoke():
            descriptor = actual_acquire()
            value = broker.auto_reboot_record(); value['enabled']=False
            broker.atomic_json(self.root/'reboot-policy.json',value)
            return descriptor
        with patch.object(broker,'acquire_operation',side_effect=revoke):
            self.assertEqual(broker.auto_reboot_tick(self.now),'disabled')
        self.proc.assert_not_called(); self.assertFalse(broker.REBOOT_MARKER.exists())


@unittest.skipUnless(r, 'Linux route fixtures')
class RebootRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_os_security import SecurityWebRoutes
        SecurityWebRoutes.setUpClass.__func__(cls)

    def setUp(self):
        from test_os_security import SecurityWebRoutes
        SecurityWebRoutes.setUp(self)

    def test_route_validates_confirmation_boot_and_audits_the_policy(self):
        body = {'enabled':True,'time':'03:15','confirmation':'REBOOT','expected_boot_id':BOOT}
        self.request.get_json = lambda silent=True: body
        with patch.object(self.routes,'_actor',return_value='tester'):
            self.assertEqual(self.routes.automatic_reboot(), ({'ok':True,'job_id':'a'*32}, 200))
        self.assertEqual(self.rpc.call_args.args[0],{'action':'set_auto_reboot',**body,'actor':'tester'})
        self.assertEqual(self.audit.call_args.args[0],'os.automatic_reboot')
        for change in ({'enabled':1},{'time':'25:00'},{'time':[]},{'confirmation':'UPDATE'},{'actor':'forged'}):
            self.request.get_json = lambda silent=True, change=change: {**body,**change}
            with self.subTest(change=change), self.assertRaises(self.abort_error): self.routes.automatic_reboot()


if __name__ == '__main__':
    unittest.main()
