"""Deleted sites, TCP proxies and UDP forwards, kept so a deletion can be undone.

A deletion used to be final the moment websites.yml (or tcp.yml, udp.yml) was
written without the entry. Now the entry as it stood is set aside here first,
and the trash page can put it back -- through the same lock, the same
conflict checks and the same write path as an ordinary save, so a restored
entry is held to the rules a new one would be.

Certificates, authorities and their settings live on the host and are set
aside by certd in a trash of its own; the page shows both.

One JSON file per deleted entry, private to the panel. Nothing is ever kept
longer than KEEP_SECONDS: the access-page files of a deleted site wait in
access_portal's own trash for the same term, so a site restored within it
gets its page back too.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
import uuid

LOG = logging.getLogger("haproxy-admin")

KEEP_SECONDS = 30 * 86400
# A ceiling, not a working limit: an operator deleting hundreds of entries in
# a month is scripting something, and the oldest go first.
MAX_ITEMS = 500
KINDS = ("site", "tcp", "udp")
_ID = re.compile(r"^(?P<at>[0-9]{1,12})-[a-f0-9]{12}$")
CLAIM = ".restoring"
CLAIM_SECONDS = 600


class TrashError(ValueError):
    """An item that is not there, or cannot be put back."""


def root() -> Path:
    return Path(os.environ.get("HAPROXY_ADMIN_TRASH_DIR", "/var/lib/haproxy-admin/trash"))


def _directory() -> Path:
    directory = root()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise TrashError("Invalid trash directory")
    return directory


@contextmanager
def _locked() -> Iterator[Path]:
    """One writer at a time across the panel's worker processes."""
    directory = _directory()
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield directory
    finally:
        os.close(fd)


def _actor() -> str:
    try:
        from flask import g, has_request_context

        if has_request_context():
            return str(getattr(g, "remote_user", "") or "")
    except Exception:  # pylint: disable=broad-except
        pass
    return ""


def _path(directory: Path, item_id: str) -> Path:
    if not _ID.fullmatch(str(item_id or "")):
        raise TrashError("Unknown trash item")
    return directory / f"{item_id}.json"


def _read(path: Path) -> Optional[Dict[str, Any]]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("kind") not in KINDS:
        return None
    if not isinstance(value.get("entry"), dict):
        return None
    return value


def _write(path: Path, value: Dict[str, Any]) -> None:
    raw = json.dumps(value, ensure_ascii=False, indent=1).encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def _purge_locked(directory: Path, now: float) -> int:
    # A worker that died between claiming an item and putting it back left
    # the claim behind; after a while the item is offered again.
    for claim in directory.glob(f"*{CLAIM}"):
        try:
            stale = now - claim.stat().st_mtime > CLAIM_SECONDS
        except OSError:
            continue
        if stale and _ID.fullmatch(claim.stem) and not claim.is_symlink():
            os.replace(claim, claim.with_suffix(".json"))
    removed = 0
    kept: List[Tuple[int, Path]] = []
    for path in directory.glob("*.json"):
        match = _ID.fullmatch(path.stem)
        if match is None or path.is_symlink():
            continue  # nothing this module wrote
        at = int(match.group("at"))
        if now - at >= KEEP_SECONDS:
            path.unlink(missing_ok=True)
            removed += 1
        else:
            kept.append((at, path))
    kept.sort()
    for _, path in kept[: max(0, len(kept) - MAX_ITEMS)]:
        path.unlink(missing_ok=True)
        removed += 1
    return removed


def put(kind: str, name: str, entry: Dict[str, Any], extra: Optional[Dict[str, Any]] = None,
        now: Optional[float] = None) -> Optional[str]:
    """Set a deleted entry aside. Never a reason to fail the deletion itself."""
    if kind not in KINDS or not isinstance(entry, dict):
        return None
    now = time.time() if now is None else now
    item_id = f"{int(now)}-{uuid.uuid4().hex[:12]}"
    try:
        with _locked() as directory:
            _write(_path(directory, item_id), {
                "id": item_id,
                "kind": kind,
                "name": str(name),
                "deleted_at": int(now),
                "deleted_by": _actor(),
                "entry": entry,
                "extra": dict(extra or {}),
            })
            _purge_locked(directory, now)
    except Exception:  # pylint: disable=broad-except
        LOG.warning("The deleted %s %r could not be kept in the trash", kind, name, exc_info=True)
        return None
    return item_id


def _summary(item: Dict[str, Any]) -> Dict[str, Any]:
    entry = item["entry"]
    kind = item["kind"]
    if kind == "site":
        names = [str(entry.get("domain") or "")]
        names += [str(n) for n in (entry.get("alt_names") or []) if str(n).strip()]
        detail = ", ".join(n for n in names if n)
    elif kind == "tcp":
        detail = f"{entry.get('bind_ip') or '*'}:{entry.get('bind_port') or ''}"
    else:
        detail = f"udp {entry.get('listen_port') or ''} -> {entry.get('backend_ip') or ''}"
    return {
        "source": "panel",
        "id": item["id"],
        "kind": kind,
        "name": item.get("name") or "",
        "detail": detail,
        "deleted_at": item.get("deleted_at") or 0,
        "deleted_by": item.get("deleted_by") or "",
        "expires_at": int(item.get("deleted_at") or 0) + KEEP_SECONDS,
    }


def items(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """What can be put back, newest first. Expired entries go on the way."""
    now = time.time() if now is None else now
    with _locked() as directory:
        _purge_locked(directory, now)
        found = [_read(path) for path in directory.glob("*.json")]
    listed = [_summary(item) for item in found if item is not None]
    listed.sort(key=lambda item: (item["deleted_at"], item["id"]), reverse=True)
    return listed


def _restorers() -> Dict[str, Callable[[Dict[str, Any]], Tuple[bool, str]]]:
    from .services_haproxy_sites import restore_site
    from .services_haproxy_tcp import restore_tcp_proxy
    from .services_haproxy_udp import restore_udp_forward

    return {"site": restore_site, "tcp": restore_tcp_proxy, "udp": restore_udp_forward}


def restore(item_id: str) -> Dict[str, Any]:
    """Put an entry back where it was deleted from; drop it from the trash only then.

    The item is claimed under the trash lock and put back outside it: a
    deletion takes the source lock first and the trash lock second, so
    holding this one while waiting for that one could deadlock two workers.
    A claimed item is invisible to a second restore of the same entry.
    """
    with _locked() as directory:
        path = _path(directory, item_id)
        item = _read(path)
        if item is None:
            raise TrashError("Unknown trash item")
        claim = path.with_suffix(CLAIM)
        os.replace(path, claim)
    try:
        ok, message = _restorers()[item["kind"]](item["entry"])
    except Exception:
        with _locked():
            os.replace(claim, path)
        raise
    if not ok:
        with _locked():
            os.replace(claim, path)
        return {"ok": False, "error": message, "kind": item["kind"], "name": item["name"]}
    claim.unlink(missing_ok=True)
    result = {"ok": True, "message": message, "kind": item["kind"], "name": item["name"]}
    page = str((item.get("extra") or {}).get("access_page") or "")
    if item["kind"] == "site" and page:
        result["access_page"] = _restore_access_page(item["name"], page)
    return result


def _restore_access_page(name: str, stored: str) -> str:
    try:
        from . import access_portal

        return "restored" if access_portal.restore(name, stored) else "gone"
    except Exception:  # pylint: disable=broad-except
        LOG.warning("The access page of restored site %r could not be put back", name, exc_info=True)
        return "failed"


def remove(item_id: str) -> Dict[str, Any]:
    """Delete one item for good."""
    with _locked() as directory:
        path = _path(directory, item_id)
        item = _read(path)
        if item is None:
            raise TrashError("Unknown trash item")
        path.unlink(missing_ok=True)
    return {"ok": True, "kind": item["kind"], "name": item["name"]}


def empty() -> int:
    """Delete everything in this trash for good; how many items went."""
    removed = 0
    with _locked() as directory:
        for path in directory.glob("*.json"):
            if _ID.fullmatch(path.stem) and not path.is_symlink():
                path.unlink(missing_ok=True)
                removed += 1
    return removed
