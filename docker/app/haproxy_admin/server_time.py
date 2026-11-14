"""One explicit gateway time zone for all human-facing panel timestamps."""
from __future__ import annotations

import datetime as dt
from functools import lru_cache
import os
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@lru_cache(maxsize=16)
def _zone(name):
    try:
        return ZoneInfo(name)
    except (ValueError, ZoneInfoNotFoundError):
        return ZoneInfo('UTC')


def timezone():
    # The host's explicit value wins over a container-only TZ override. The
    # old TZ remains a rolling-upgrade fallback for already deployed hosts.
    return _zone(os.environ.get('EHP_SERVER_TIMEZONE') or os.environ.get('TZ') or 'UTC')


def context():
    zone = timezone()
    now = dt.datetime.now(zone)
    offset = now.strftime('%z')
    return {'zone': zone.key, 'abbreviation': now.strftime('%Z'),
            'offset': 'UTC' + offset[:3] + ':' + offset[3:], 'now': now.timestamp() * 1000}


def format_datetime(value):
    try:
        moment = dt.datetime.fromisoformat(str(value or '').replace('Z', '+00:00'))
    except ValueError:
        return ''
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(timezone()).strftime('%Y-%m-%d %H:%M %Z')
