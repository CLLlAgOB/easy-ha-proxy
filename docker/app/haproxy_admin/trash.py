"""Deleted sites, TCP proxies and UDP forwards, kept so a deletion can be undone.

A deletion used to be final the moment websites.yml (or tcp.yml, udp.yml) was
written without the entry. Now the entry as it stood is set aside here first,
and the trash page can put it back -- through the same lock, the same
conflict checks and the same write path as an ordinary save, so a restored
entry is held to the rules a new one would be.

Certificates, authorities and their settings live on the host and are set
aside by certd in a trash of its own; the page shows both.

One JSON file per deleted entry, private to the panel. The entry is written
here before the source is rewritten without it: when it cannot be kept,
nothing is deleted. Until the deletion has gone through it waits as
<id>.pending, which nothing lists, empties or purges -- so emptying the trash
in the middle of a deletion cannot take the only copy -- and commit() makes it
<id>.json. A deletion that failed drops it again, unless the entry turned
out to be gone from its source anyway. Items stay until the trash is emptied, unless the
operator set a term (keep_days); then an item older than that is gone, both
from the list and for a restore by its id. A deleted site's access page waits
in access_portal's own trash for as long as the site waits here, and goes
with it.
"""
from __future__ import annotations

from contextlib import contextmanager, suppress
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple
import uuid

LOG = logging.getLogger("haproxy-admin")

KINDS = ("site", "tcp", "udp")
_ID = re.compile(r"^(?P<at>[0-9]{1,12})-[a-f0-9]{12}$")
CLAIM = ".restoring"
CLAIM_SECONDS = 600
PENDING = ".pending"
# A worker that died in the middle of a deletion left its item pending; after
# this long it is listed, since the deletion may well have gone through.
PENDING_SECONDS = 3600
SETTINGS = "settings.json"
# 0 keeps items until someone empties the trash; otherwise the days they stay.
DEFAULT_KEEP_DAYS = 0
MAX_KEEP_DAYS = 3650
PURGE_INTERVAL_SECONDS = 3600


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
def settings_lock() -> Iterator[None]:
    """One change of the term at a time, across workers, for both keepers.

    The panel's file and certd's are written one after the other; two changes
    interleaved could each answer "saved" and leave the two on different
    terms. A lock of its own: certd is asked while it is held.
    """
    directory = _directory()
    fd = os.open(directory / ".settings.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@contextmanager
def _locked() -> Iterator[Path]:
    """One writer at a time across the panel's worker processes.

    Never call access_portal (or anything that reads the trash under this
    lock) while holding it: flock is per open file, so a second acquisition
    in the same process waits for itself.
    """
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


def _pending(directory: Path, item_id: str) -> Path:
    return _path(directory, item_id).with_suffix(PENDING)


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
            with suppress(FileNotFoundError):
                os.unlink(tmp)


# ───────────────────── the term ─────────────────────


def normalize_keep_days(value: Any) -> int:
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        raise TrashError("The term must be a whole number of days") from None
    if not 0 <= days <= MAX_KEEP_DAYS:
        raise TrashError("The term must be between 1 and 3650 days, or 0 to keep items until the trash is emptied")
    return days


def keep_days() -> int:
    """The operator's term in days; 0 keeps items until the trash is emptied."""
    path = root() / SETTINGS
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            value = json.load(stream)
        return normalize_keep_days(value.get("keep_days", DEFAULT_KEEP_DAYS))
    except (OSError, ValueError, AttributeError):
        return DEFAULT_KEEP_DAYS


def set_keep_days(value: Any, now: Optional[float] = None) -> int:
    """Store a new term and apply it at once: older items go now."""
    days = normalize_keep_days(value)
    now = time.time() if now is None else now
    with _locked() as directory:
        _write(directory / SETTINGS, {"keep_days": days})
        gone = _purge_locked(directory, now, days)
    _forget_pages(gone)
    return days


def _expired(at: int, now: float, days: int) -> bool:
    return days > 0 and now - at >= days * 86400


def _expires_at(at: int, days: int) -> int:
    return at + days * 86400 if days > 0 else 0


# ───────────────────── keeping and purging ─────────────────────


def _purge_locked(directory: Path, now: float, days: Optional[int] = None) -> List[Dict[str, Any]]:
    """Drop expired items; what went, so their access pages can follow outside the lock.

    The term is read here, under the lock that set_keep_days writes it under:
    one read before the lock could purge by a term already switched off.
    """
    days = keep_days() if days is None else days
    for pending in directory.glob(f"*{PENDING}"):
        try:
            stale = now - pending.stat().st_mtime > PENDING_SECONDS
        except OSError:
            continue
        if stale and _ID.fullmatch(pending.stem) and not pending.is_symlink():
            with suppress(FileNotFoundError):
                os.replace(pending, pending.with_suffix(".json"))
    # A worker that died between claiming an item and putting it back left
    # the claim behind; after a while the item is offered again. A claim is
    # touched when it is taken, so its age is the restore's, not the item's.
    for claim in directory.glob(f"*{CLAIM}"):
        try:
            stale = now - claim.stat().st_mtime > CLAIM_SECONDS
        except OSError:
            continue
        if stale and _ID.fullmatch(claim.stem) and not claim.is_symlink():
            with suppress(FileNotFoundError):
                os.replace(claim, claim.with_suffix(".json"))
    gone: List[Dict[str, Any]] = []
    if days <= 0:
        return gone
    for path in directory.glob("*.json"):
        match = _ID.fullmatch(path.stem)
        if match is None or path.is_symlink():
            continue  # nothing this module wrote
        if _expired(int(match.group("at")), now, days):
            item = _read(path)
            path.unlink(missing_ok=True)
            if item is not None:
                gone.append(item)
    return gone


def _page_of(item: Dict[str, Any]) -> str:
    if item.get("kind") != "site":
        return ""
    return str((item.get("extra") or {}).get("access_page") or "")


def _forget_pages(items: List[Dict[str, Any]]) -> None:
    """Remove for good the access pages of sites that left the trash for good."""
    for item in items:
        page = _page_of(item)
        if not page:
            continue
        try:
            from . import access_portal

            access_portal.forget(str(item.get("name") or ""), page)
        except Exception:  # pylint: disable=broad-except
            LOG.warning("The access page of deleted site %r could not be removed", item.get("name"), exc_info=True)


def referenced_pages() -> Set[str]:
    """The access pages that items in the trash still name; read without the lock.

    access_portal asks while it may hold its own lock or run inside a
    deletion that holds this one; items are written whole by a rename, so a
    plain read sees each one either before or after.
    """
    names: Set[str] = set()
    directory = root()
    if directory.is_symlink() or not directory.is_dir():
        return names
    found = list(directory.glob("*.json")) + list(directory.glob(f"*{CLAIM}"))
    for path in found + list(directory.glob(f"*{PENDING}")):
        if not _ID.fullmatch(path.stem):
            continue
        item = _read(path)
        if item is not None and _page_of(item):
            names.add(_page_of(item))
    return names


def keep(kind: str, name: str, entry: Dict[str, Any], extra: Optional[Dict[str, Any]] = None,
         now: Optional[float] = None) -> str:
    """Set an entry aside before it is deleted; its id. Raises when it cannot be kept.

    The item is pending: the caller deletes only after this returned, then
    calls commit(), or settle() when the deletion failed -- so the trash
    never lists an entry still in service, and a deletion never loses the
    only copy.
    """
    if kind not in KINDS or not isinstance(entry, dict):
        raise TrashError("Unknown trash kind")
    now = time.time() if now is None else now
    item_id = f"{int(now)}-{uuid.uuid4().hex[:12]}"
    try:
        with _locked() as directory:
            _write(_pending(directory, item_id), {
                "id": item_id,
                "kind": kind,
                "name": str(name),
                "deleted_at": int(now),
                "deleted_by": _actor(),
                "entry": entry,
                "extra": dict(extra or {}),
            })
            gone = _purge_locked(directory, now)
    except TrashError:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("The %s %r could not be kept in the trash", kind, name, exc_info=True)
        raise TrashError(str(exc) or exc.__class__.__name__) from exc
    _forget_pages(gone)
    return item_id


def annotate(item_id: str, **extra: Any) -> None:
    """Add to a pending item's extra (the access page it took along). Raises on failure."""
    try:
        with _locked() as directory:
            path = _pending(directory, item_id)
            item = _read(path)
            if item is None:
                raise TrashError("Unknown trash item")
            item["extra"] = dict(item.get("extra") or {}, **extra)
            _write(path, item)
    except TrashError:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("The trash item %s could not be updated", item_id, exc_info=True)
        raise TrashError(str(exc) or exc.__class__.__name__) from exc


def commit(item_id: str) -> bool:
    """The deletion went through: list the item."""
    try:
        with _locked() as directory:
            os.replace(_pending(directory, item_id), _path(directory, item_id))
        return True
    except Exception:  # pylint: disable=broad-except
        # Still on disk as pending; the purge lists it after PENDING_SECONDS.
        LOG.error("The trash item %s could not be listed yet", item_id, exc_info=True)
        return False


def drop(item_id: str) -> None:
    """Forget an item whose deletion did not go through."""
    try:
        with _locked() as directory:
            _pending(directory, item_id).unlink(missing_ok=True)
    except Exception:  # pylint: disable=broad-except
        LOG.warning("The trash item %s could not be dropped", item_id, exc_info=True)


def settle(item_id: str, still_in_source: bool) -> bool:
    """After a failed deletion: drop the copy only when the entry is still in its source.

    A write that failed can still have replaced the file -- the UDP apply
    whose rollback also failed left udp.yml without the forward -- and then
    the copy is all there is. True when the copy was kept.
    """
    if still_in_source:
        drop(item_id)
        return False
    commit(item_id)
    return True


def _summary(item: Dict[str, Any], days: int) -> Dict[str, Any]:
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
    deleted_at = int(item.get("deleted_at") or 0)
    return {
        "source": "panel",
        "id": item["id"],
        "kind": kind,
        "name": item.get("name") or "",
        "detail": detail,
        "deleted_at": deleted_at,
        "deleted_by": item.get("deleted_by") or "",
        "expires_at": _expires_at(deleted_at, days),
    }


def items(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """What can be put back, newest first. Expired entries go on the way."""
    now = time.time() if now is None else now
    with _locked() as directory:
        days = keep_days()
        gone = _purge_locked(directory, now, days)
        found = [_read(path) for path in directory.glob("*.json") if _ID.fullmatch(path.stem)]
    _forget_pages(gone)
    listed = [_summary(item, days) for item in found if item is not None]
    listed.sort(key=lambda item: (item["deleted_at"], item["id"]), reverse=True)
    return listed


def purge(now: Optional[float] = None) -> int:
    """Drop what has outlived the term; how many went."""
    now = time.time() if now is None else now
    with _locked() as directory:
        gone = _purge_locked(directory, now)
    _forget_pages(gone)
    return len(gone)


def _restorers() -> Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], Tuple[bool, str, Dict[str, Any]]]]:
    from .services_haproxy_sites import restore_site
    from .services_haproxy_tcp import restore_tcp_proxy
    from .services_haproxy_udp import restore_udp_forward

    return {"site": restore_site, "tcp": restore_tcp_proxy, "udp": restore_udp_forward}


def _take(directory: Path, item_id: str, now: float) -> Tuple[Path, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """The item and None, or None and the item it was when it has outlived the term.

    An expired item is removed here, under the lock; the caller removes its
    access page after the lock is released.
    """
    path = _path(directory, item_id)
    item = _read(path)
    if item is None:
        raise TrashError("Unknown trash item")
    if _expired(int(item.get("deleted_at") or 0), now, keep_days()):
        path.unlink(missing_ok=True)
        return path, None, item
    return path, item, None


def restore(item_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Put an entry back where it was deleted from; drop it from the trash only then.

    The item is claimed under the trash lock and put back outside it: a
    deletion takes the source lock first and the trash lock second, so
    holding this one while waiting for that one could deadlock two workers.
    A claimed item is invisible to a second restore of the same entry.
    """
    now = time.time() if now is None else now
    with _locked() as directory:
        path, item, expired = _take(directory, item_id, now)
        claim = path.with_suffix(CLAIM)
        if item is not None:
            os.replace(path, claim)
            # A rename keeps the old mtime: without this an item older than
            # CLAIM_SECONDS looked abandoned the moment it was claimed.
            os.utime(claim)
    if item is None:
        _forget_pages([expired] if expired else [])
        raise TrashError("Unknown trash item")

    def give_back() -> None:
        with _locked():
            with suppress(FileNotFoundError):
                os.replace(claim, path)

    # A site takes its access page back inside its own restore, under the
    # websites lock: done after it, the page could land on a new site of the
    # same name created in between. The claim is still there meanwhile, so
    # access_portal's purge sees the page as one a trash item names.
    try:
        ok, message, info = _restorers()[item["kind"]](item["entry"], dict(item.get("extra") or {}))
    except Exception:
        give_back()
        raise
    if not ok:
        give_back()
        return {"ok": False, "error": message, "kind": item["kind"], "name": item["name"]}
    result = {"ok": True, "message": message, "kind": item["kind"], "name": item["name"]}
    result.update({key: value for key, value in (info or {}).items() if value})
    claim.unlink(missing_ok=True)
    return result


def restore_access_page(name: str, stored: str) -> str:
    """Give a restored site the page it took into the trash: restored, gone or failed."""
    try:
        from . import access_portal

        return "restored" if access_portal.restore(name, stored) else "gone"
    except Exception:  # pylint: disable=broad-except
        LOG.warning("The access page of restored site %r could not be put back", name, exc_info=True)
        return "failed"


def remove(item_id: str) -> Dict[str, Any]:
    """Delete one item for good, with the access page a site took along."""
    with _locked() as directory:
        path = _path(directory, item_id)
        item = _read(path)
        if item is None:
            raise TrashError("Unknown trash item")
        path.unlink(missing_ok=True)
    _forget_pages([item])
    return {"ok": True, "kind": item["kind"], "name": item["name"]}


def empty() -> int:
    """Delete everything in this trash for good; how many items went."""
    gone: List[Dict[str, Any]] = []
    removed = 0
    with _locked() as directory:
        for path in directory.glob("*.json"):
            if _ID.fullmatch(path.stem) and not path.is_symlink():
                item = _read(path)
                path.unlink(missing_ok=True)
                removed += 1
                if item is not None:
                    gone.append(item)
    _forget_pages(gone)
    return removed


# ───────────────────── the term kept while nobody looks ─────────────────────

_purger_pid = 0
_purger_lock = threading.Lock()


def _purge_forever() -> None:
    while True:
        time.sleep(PURGE_INTERVAL_SECONDS)
        try:
            purge()
        except Exception:  # pylint: disable=broad-except
            LOG.warning("The trash could not be purged", exc_info=True)


def ensure_purger() -> None:
    """One purging thread per worker process, so a term is kept on an idle panel too.

    Started from the first request a worker serves, not at import: a
    preforking server would otherwise start it in the parent only. Workers
    share the files under the trash lock, so more than one is harmless.
    """
    global _purger_pid
    if _purger_pid == os.getpid():
        return
    with _purger_lock:
        if _purger_pid == os.getpid():
            return
        threading.Thread(target=_purge_forever, name="trash-purge", daemon=True).start()
        _purger_pid = os.getpid()
