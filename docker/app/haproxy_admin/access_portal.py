"""Disk-backed instructions and attachments for authenticated access gates."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 10
ID = re.compile(r'^[a-f0-9]{32}$')
LANGUAGES = frozenset({'auto', 'en', 'ru'})
# Where a deleted site's instructions and attachments wait before they are
# removed for good. Long enough to notice a site deleted by mistake and take
# its files back out of a backup or out of here; short enough that half a
# gigabyte per deleted site does not stay on the disk and in every backup.
TRASH = '.deleted'
TRASH_SECONDS = 30 * 86400
_TRASHED = re.compile(r'^[a-f0-9]{64}-(?P<at>[0-9]{1,12})-[a-f0-9]{8}$')


def root():
    return Path(os.environ.get('HAPROXY_ADMIN_PORTAL_DIR', '/var/lib/haproxy-admin/access-portals'))


def _directory(site):
    # Site names and uploaded filenames never become filesystem paths.
    directory = root() / hashlib.sha256(site.encode('utf-8')).hexdigest()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Invalid portal storage directory')
    return directory


def purge(now=None):
    """Remove what has waited in the trash for its whole term."""
    trash = root() / TRASH
    if trash.is_symlink() or not trash.is_dir():
        return 0
    now = time.time() if now is None else now
    removed = 0
    for entry in trash.iterdir():
        match = _TRASHED.fullmatch(entry.name)
        if match is None or entry.is_symlink() or not entry.is_dir():
            continue  # nothing this module put there
        if now - int(match.group('at')) >= TRASH_SECONDS:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    return removed


def discard(site, now=None):
    """Take a site's instructions and attachments out of service.

    Called when a site is deleted, and before one is created. The storage is
    found by the site's name, so without this a new site given the name of a
    deleted one was born with the old site's instructions and files, already
    published. The directory is moved aside rather than removed at once: a
    deletion can be a mistake, and a download in progress keeps its file.
    """
    now = time.time() if now is None else now
    purge(now)
    directory = root() / hashlib.sha256(site.encode('utf-8')).hexdigest()
    if directory.is_symlink() or not directory.is_dir():
        return False
    with _locked(site):
        trash = root() / TRASH
        trash.mkdir(mode=0o700, exist_ok=True)
        if trash.is_symlink() or not trash.is_dir():
            raise ValueError('Invalid portal storage directory')
        os.replace(directory, trash / f'{directory.name}-{int(now)}-{uuid.uuid4().hex[:8]}')
    return True


def download_turn(user):
    """One transfer at a time for one signed-in visitor, across the worker processes.

    Returns an open descriptor to close when the transfer ends, or None when
    this visitor already has one running. A lock on a file rather than a
    counter in memory: the panel runs more than one worker process, and the
    kernel drops the lock when a worker dies in the middle of a transfer.
    """
    directory = root() / '.downloads'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Invalid portal storage directory')
    fd = os.open(directory / hashlib.sha256(user.encode('utf-8')).hexdigest(),
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open(path, flags, mode=0o600):
    fd = os.open(path, flags | os.O_NOFOLLOW, mode)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('Portal storage must contain regular files')
    return fd


@contextmanager
def _locked(site):
    directory = _directory(site)
    with os.fdopen(_open(directory / '.lock', os.O_CREAT | os.O_RDWR), 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield directory


def _load(directory):
    try:
        with os.fdopen(_open(directory / 'settings.json', os.O_RDONLY), 'r') as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return {'enabled': False, 'language': 'auto', 'text': '', 'files': []}
    if not isinstance(value, dict) or not isinstance(value.get('files'), list):
        raise ValueError('Invalid portal settings')
    value.setdefault('language', 'auto')
    if not isinstance(value['language'], str) or value['language'] not in LANGUAGES:
        raise ValueError('Unsupported access-page language')
    return value


def _save(directory, value):
    fd, name = tempfile.mkstemp(prefix='.settings-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / 'settings.json')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _text(value, limit, label):
    if not isinstance(value, str) or len(value) > limit or re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', value):
        raise ValueError(f'Invalid {label}')
    return value.strip()


def _revision(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _view(value):
    return {**value, 'revision': _revision(value), 'max_file_bytes': MAX_FILE_BYTES,
            'max_total_bytes': MAX_TOTAL_BYTES, 'max_files': MAX_FILES}


def settings(site):
    # Atomic metadata replacement lets readers continue during a large upload.
    return _view(_load(_directory(site)))


def configure(site, payload, before_save=None):
    if not isinstance(payload, dict) or set(payload) - {'language'} != {'enabled', 'text', 'files', 'revision'}:
        raise ValueError('Invalid portal settings fields')
    if type(payload['enabled']) is not bool or not isinstance(payload['files'], list) or len(payload['files']) > MAX_FILES:
        raise ValueError('Invalid portal settings')
    if 'language' in payload and (not isinstance(payload['language'], str) or payload['language'] not in LANGUAGES):
        raise ValueError('Unsupported access-page language')
    text = _text(payload['text'], 12000, 'instructions')
    with _locked(site) as directory:
        old = _load(directory)
        if payload['revision'] != _revision(old):
            raise FileExistsError('Portal settings changed; reload before saving')
        existing = {item['id']: item for item in old['files']}
        files = []
        for item in payload['files']:
            if (not isinstance(item, dict) or set(item) != {'id', 'title', 'description'}
                    or not isinstance(item['id'], str) or item['id'] not in existing):
                raise ValueError('Invalid attachment settings')
            if any(f['id'] == item['id'] for f in files):
                raise ValueError('Duplicate attachment')
            files.append({**existing[item['id']], 'title': _text(item['title'], 160, 'attachment title'),
                          'description': _text(item['description'], 2000, 'attachment description')})
        if set(existing) != {item['id'] for item in files}:
            raise ValueError('Use the delete button to remove attachments')
        value = {'enabled': payload['enabled'], 'language': payload.get('language', old['language']),
                 'text': text, 'files': files}
        if before_save is not None:
            before_save(value['enabled'])
        _save(directory, value)
        return _view(value)


def upload(site, filename, stream):
    filename = _text(filename, 180, 'filename')
    if not filename or any(char in filename for char in '/\\') or re.search(r'[\x00-\x1f\x7f]', filename) or filename in {'.', '..'}:
        raise ValueError('Invalid filename')
    with _locked(site) as directory:
        value = _load(directory)
        if len(value['files']) >= MAX_FILES:
            raise ValueError('Too many attachments')
        purge()
        # Recover disk space after a worker/container was stopped mid-upload.
        # The lock guarantees these UUID files belong to no active writer.
        registered = {item['id'] + '.bin' for item in value['files']}
        for abandoned in directory.glob('*.bin'):
            if ID.fullmatch(abandoned.stem) and abandoned.name not in registered:
                abandoned.unlink(missing_ok=True)
        remaining = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - sum(item['size'] for item in value['files']))
        identifier = uuid.uuid4().hex
        target = directory / (identifier + '.bin')
        fd = _open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        size, digest = 0, hashlib.sha256()
        try:
            with os.fdopen(fd, 'wb') as output:
                while True:
                    chunk = stream.read(min(1024 * 1024, max(1, remaining - size + 1)))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > remaining:
                        raise ValueError('Attachment storage limit exceeded')
                    output.write(chunk)
                    digest.update(chunk)
                if not size:
                    raise ValueError('The attachment is empty')
                output.flush()
                os.fsync(output.fileno())
            value['files'].append({'id': identifier, 'filename': filename, 'title': filename,
                                   'description': '', 'size': size, 'sha256': digest.hexdigest()})
            _save(directory, value)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return _view(value)


def delete(site, identifier):
    if not ID.fullmatch(identifier):
        raise ValueError('Invalid attachment identifier')
    with _locked(site) as directory:
        value = _load(directory)
        value['files'] = [item for item in value['files'] if item['id'] != identifier]
        _save(directory, value)
        (directory / (identifier + '.bin')).unlink(missing_ok=True)
        return _view(value)


def open_download(site, identifier):
    if not ID.fullmatch(identifier):
        raise FileNotFoundError('Attachment not found')
    directory = _directory(site)
    value = _load(directory)
    item = next((item for item in value['files'] if item['id'] == identifier), None)
    if not value['enabled'] or item is None:
        raise FileNotFoundError('Attachment not found')
    stream = os.fdopen(_open(directory / (identifier + '.bin'), os.O_RDONLY), 'rb')
    if os.fstat(stream.fileno()).st_size != item['size']:
        stream.close()
        raise ValueError('Attachment size mismatch')
    return stream, item


# The page and every download ask which site a host name belongs to. The
# answer used to be read from the YAML sources each time: two files parsed per
# visitor request, in the administration panel's own few worker threads, for
# anyone who had signed in to an access page. It is now worked out once per
# version of the files.
_HOSTS_LOCK = threading.Lock()
_HOSTS = {}


def _signature(path):
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_ino, info.st_mtime_ns, info.st_size


def _gate_hosts(websites, variables, loader):
    """Host name -> site, for the enabled access-gate sites of one configuration."""
    data = loader(websites)
    defaults = loader(variables).get('site_defaults') or {}
    hosts = {}
    for site in data.get('sites') or []:
        if not isinstance(site, dict):
            continue
        effective = {**defaults, **site}
        if effective.get('access_gate') is not True or effective.get('enabled', True) is False:
            continue
        for name in [site.get('domain'), *(site.get('alt_names') or [])]:
            if isinstance(name, str) and name:
                hosts.setdefault(name.lower(), site)
    return hosts


def _hosts_of(websites, variables, loader):
    key = (_signature(websites), _signature(variables))
    if key[0] is None:
        # Nothing to tell versions apart by: read it each time, as before.
        return _gate_hosts(websites, variables, loader)
    kept = _HOSTS.get(str(websites))
    if kept is not None and kept[0] == key:
        return kept[1]
    with _HOSTS_LOCK:
        kept = _HOSTS.get(str(websites))
        if kept is None or kept[0] != key:
            kept = (key, _gate_hosts(websites, variables, loader))
            _HOSTS[str(websites)] = kept
        return kept[1]


def site_by_host(host):
    from . import services_haproxy_config as config
    from .validation import validate_domain
    hostname = validate_domain(host).lower()
    # What HAProxy routes is the applied configuration: a domain changed in
    # the draft keeps its page until the change is applied. The draft answers
    # for a gateway that has no applied copy yet.
    for websites, variables in ((config.HAPROXY_STATE_WEBSITES, config.HAPROXY_STATE_VARS),
                                (config.WEBSITES_YAML, config.CONFIG_YAML)):
        site = _hosts_of(websites, variables, config._load_yaml).get(hostname)
        if site is not None:
            return dict(site)
    raise FileNotFoundError('Access page not found')
