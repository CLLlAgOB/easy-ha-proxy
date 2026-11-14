"""Disposable reboot qualification. The reboot command is ALWAYS intercepted."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'installer'))
import auto_reboot as reboot  # noqa: E402


def harmless_worker(root, lock, marker, required, unit):
    calls = []
    def never_reboot(argv, **kwargs):
        assert argv == ['/usr/bin/systemctl', 'reboot'], argv
        calls.append(argv)
        return 0, 'No reboot was executed by this disposable fixture.'
    reboot.command = never_reboot  # No production reboot command can escape.
    result = reboot.fire(root, lock, marker, required, unit)
    return {'result':result, 'intercepted_reboots':len(calls)}


def exercise(root, base, *, systemd=False):
    if os.geteuid() != 0 or os.environ.get('EHP_SECURITY_DISPOSABLE') != '1':
        raise RuntimeError('Requires an explicitly disposable root test environment')
    lock, marker, required = (base / name for name in ('reboot.lock', 'reboot.json', 'reboot-required'))
    now = dt.datetime.now().astimezone()
    text = now.strftime('%H:%M')
    _, key = reboot.window(now, text)
    unit = 'easy-ha-proxy-web-reboot-' + uuid.uuid4().hex[:12]
    policy = {'enabled':True,'time':text,'id':uuid.uuid4().hex,'updated_at':now.timestamp()-60,
              'attempt':{'window':key,'state':'scheduled','at':now.timestamp()}}
    owned = {'unit':unit,'boot_id':reboot.BOOT.read_text().strip(),
             'automatic':{'policy_revision':policy['id'],'window':key}}
    def reset():
        reboot.atomic(root / 'reboot-policy.json', policy)
        reboot.atomic(marker, owned)
        required.touch()
    reset()
    result = harmless_worker(root, lock, marker, required, unit)
    assert result == {'result':'triggered','intercepted_reboots':1}, result
    marker.unlink()
    reset()
    child = subprocess.Popen(['/usr/bin/python3','-c',
        'import fcntl,sys; f=open("/var/lib/dpkg/lock-frontend","r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        result = harmless_worker(root, lock, marker, required, unit)
        assert result == {'result':'deferred','intercepted_reboots':0}, result
        assert not marker.exists()
    finally:
        child.communicate(timeout=10)
    if systemd:
        reset()
        output = base / 'reboot-worker.json'
        try:
            with lock.open('r+') as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                subprocess.run(['systemd-run','--quiet','--unit='+unit,'--on-active=1s',
                    '--timer-property=AccuracySec=1s','--timer-property=RemainAfterElapse=no',
                    '--property=TimeoutStartSec=30s','--property=StandardOutput=append:'+str(output),
                    '--setenv=EHP_SECURITY_DISPOSABLE=1','--','/usr/bin/python3',str(Path(__file__).resolve()),
                    '--worker',str(root),str(lock),str(marker),str(required),unit],check=True,capture_output=True,text=True)
                time.sleep(2)
                assert not output.exists() or not output.read_text().strip(), 'The worker escaped maintenance custody'
            for _ in range(100):
                if output.exists() and output.read_text().strip():
                    break
                time.sleep(0.1)
            result = json.loads(output.read_text().strip().splitlines()[-1])
            assert result == {'result':'triggered','intercepted_reboots':1}, result
        finally:
            subprocess.run(['systemctl','stop',unit+'.timer',unit+'.service'],capture_output=True)
            marker.unlink(missing_ok=True)
    else:
        marker.unlink(missing_ok=True)
    policy['enabled'] = False
    reboot.atomic(root / 'reboot-policy.json', policy)
    print(json.dumps({'reboot_fixture':True,'systemd_timer':systemd,'real_apt_lock_guard':True,'actual_reboots':0}),flush=True)


if __name__ == '__main__':
    if os.geteuid() != 0 or os.environ.get('EHP_SECURITY_DISPOSABLE') != '1' or len(sys.argv) != 7 or sys.argv[1] != '--worker':
        raise SystemExit('Disposable worker arguments required')
    print(json.dumps(harmless_worker(*(Path(value) for value in sys.argv[2:6]),sys.argv[6])),flush=True)
