"""Read-only systemd calendar metadata with unambiguous Unix timestamps."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time

PROTOCOL = 1
MAIN_BACKUP_TIMER = 'easy-ha-proxy-backup.timer'


def run(argv):
    try:
        reply = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=2)
        return reply.stdout[:128 * 1024].strip() if reply.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def duration_seconds(text):
    if text == '0': return 0
    units = {'us': 0.000001, 'ms': 0.001, 's': 1, 'min': 60, 'h': 3600, 'd': 86400}
    pattern = r'(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d)'
    if not text or re.sub(pattern, '', text).strip(): return None
    return sum(float(count) * units[unit] for count, unit in re.findall(pattern, text))


def timer(name):
    if not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,180}\.timer', name):
        raise ValueError('Invalid timer name')
    text = run(['/usr/bin/systemctl', 'show', name,
                '--property=ActiveState,TimersCalendar,NextElapseUSecRealtime,RandomizedDelayUSec,Description'])
    props = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    active = props.get('ActiveState') == 'active'
    result = {'unit': name, 'active': active, 'description': props.get('Description', ''),
              'next_run': props.get('NextElapseUSecRealtime', '') if active else '', 'next_run_at': None,
              'random_delay_seconds': duration_seconds(props.get('RandomizedDelayUSec', '')),
              'calendar': re.findall(r'OnCalendar=([^;}]*)', props.get('TimersCalendar', ''))}
    if active:
        # `systemctl show` keeps pretty timestamps even with --timestamp=unix.
        # D-Bus exposes the original microsecond integer, including DST folds.
        escaped = ''.join(char if char.isascii() and char.isalnum() else '_%02x' % ord(char) for char in name)
        value = run(['/usr/bin/busctl', 'get-property', 'org.freedesktop.systemd1',
                     '/org/freedesktop/systemd1/unit/' + escaped, 'org.freedesktop.systemd1.Timer', 'NextElapseUSecRealtime'])
        match = re.fullmatch(r't\s+([0-9]+)', value)
        if match and 0 < int(match[1]) < 10**18:
            result['next_run_at'] = int(match[1]) / 1000000
    return result


def backups():
    main = timer(MAIN_BACKUP_TIMER)
    text = run(['/usr/bin/systemctl', 'list-units', '--all', '--type=timer', '--plain', '--no-legend', '--no-pager', '*backup*.timer'])
    names = sorted(set(re.findall(r'\b([A-Za-z0-9_.:@-]*backup[A-Za-z0-9_.:@-]*\.timer)\b', text)))
    others = [timer(name) for name in names[:16] if name not in {MAIN_BACKUP_TIMER, 'dpkg-db-backup.timer'}]
    return {'protocol': PROTOCOL, 'checked_at': time.time(), 'timer': main,
            'other_timers': [value for value in others if value['active']][:8]}


if __name__ == '__main__':
    if sys.argv[1:] != ['backups']:
        raise SystemExit('Only read-only backup timer metadata is supported')
    print(json.dumps(backups()))
