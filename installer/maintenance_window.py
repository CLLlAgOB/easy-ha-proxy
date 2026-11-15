"""One consent record and one local-time window for software maintenance."""
from __future__ import annotations

import datetime as dt
import re


def policy(settings):
    if settings.get('auto_install_unified') is not True:
        return None
    start, end = settings.get('auto_install_start'), settings.get('auto_install_end')
    updated = settings.get('maintenance_updated_at')
    if (type(start) is not int or type(end) is not int or not 0 <= start < 24 or not 0 <= end < 24
            or start == end or not re.fullmatch('[0-9a-f]{32}', str(settings.get('maintenance_revision', '')))
            or type(updated) not in (int, float) or not 0 < updated < float('inf')):
        raise ValueError('The unified maintenance policy is invalid')
    return {'enabled': settings.get('auto_install') is True, 'start': start, 'end': end,
            'runtime': settings.get('auto_install_runtime') is True,
            'id': settings['maintenance_revision'], 'updated_at': settings.get('maintenance_updated_at', 0)}


def read(root, reader):
    path = root.parent / 'settings.json'
    return policy(reader(path)) if path.exists() else None


def window(local, start, end):
    day = local.date()
    if local.hour < start:
        day -= dt.timedelta(days=1)
    opened = dt.datetime.combine(day, dt.time(start), local.tzinfo)
    closed = dt.datetime.combine(day + dt.timedelta(days=end <= start), dt.time(end), local.tzinfo)
    return {'key': day.isoformat(), 'opens_at': opened.timestamp(), 'closes_at': closed.timestamp()}


def current(value, local):
    result = window(local, value['start'], value['end'])
    return result if (value['enabled'] and result['opens_at'] <= local.timestamp() < result['closes_at']
                      and value['updated_at'] <= result['opens_at']) else None


def restart_policy(value):
    return {'enabled': value['enabled'], 'time': f"{value['start']:02d}:00", 'id': value['id'],
            'updated_at': value['updated_at']}


def require(root, reader, revision, local):
    value = read(root, reader)
    if not value or value['id'] != revision or not current(value, local):
        raise ValueError('The unified maintenance window has closed or its consent changed')
