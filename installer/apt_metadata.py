"""Bounded metadata refresh for the broker; the plan reader stays read-only."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

STATE = Path('/var/lib/easy-ha-proxy/apt-metadata/status.json')
MAX_AGE = 24 * 3600


def source_fingerprint(root=Path('/etc/apt')):
    paths = [root / 'sources.list'] + sorted((root / 'sources.list.d').glob('*'))
    digest = hashlib.sha256()
    for path in paths:
        if path.suffix not in ('.list', '.sources') or not path.is_file():
            continue
        data = path.read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError('APT source file exceeds the metadata limit')
        digest.update(path.name.encode() + b'\0' + data + b'\0')
    return digest.hexdigest()


def assess(path=STATE, *, root=Path('/etc/apt'), now=None):
    moment = time.time() if now is None else now
    try:
        if path.is_symlink() or path.stat().st_size > 64 * 1024:
            raise ValueError('Unsafe metadata record')
        data = json.loads(path.read_text())
        if data.get('format') != 1:
            raise ValueError('Unknown metadata record')
        success = data.get('last_success')
        valid = (data.get('success') is True and isinstance(success, (int, float))
                 and 0 <= moment - success <= MAX_AGE and data.get('sources') == source_fingerprint(root))
        return {**data, 'fresh': valid}
    except (OSError, ValueError, TypeError):
        return {'fresh': False, 'success': False, 'last_success': None, 'error': 'APT metadata has not been verified'}


def refresh(*, path=STATE, root=Path('/etc/apt'), timeout=100):
    """Caller holds the shared maintenance lock. No packages are installed."""
    previous = assess(path, root=root)
    before = source_fingerprint(root)
    args = ['/usr/bin/apt-get', '--error-on=any', '-o', 'Acquire::Retries=1', '-o',
            'Acquire::http::Timeout=15', '-o', 'Acquire::https::Timeout=15', 'update']
    error = None
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          start_new_session=True, env=dict(os.environ, LC_ALL='C', DEBIAN_FRONTEND='noninteractive')) as child:
        try:
            _, diagnostic = child.communicate(timeout=timeout)
            if child.returncode:
                error = f'APT metadata refresh failed (exit {child.returncode})'
                # Keep a small useful error without URL credentials or tokens.
                lines = [line for line in diagnostic.splitlines() if line.startswith(('E:', 'W:'))]
                if lines:
                    detail = re.sub(r'https?://\S+', '[repository]', lines[-1])
                    error += ': ' + detail[:300]
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate()
            error = 'APT metadata refresh timed out'
    after = source_fingerprint(root)
    if before != after:
        error = 'APT sources changed during metadata refresh'
    data = {'format': 1, 'success': error is None, 'last_attempt': time.time(),
            'last_success': time.time() if error is None else previous.get('last_success'),
            'sources': after, 'error': error}
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**data, 'fresh': error is None}


def iso(timestamp):
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat() if isinstance(timestamp, (int, float)) else None


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('refresh',))
    parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Package metadata refresh must run as root')
    print(json.dumps(refresh()))
