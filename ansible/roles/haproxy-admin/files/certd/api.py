"""Certificate expiry watch, Unix-socket HTTP API, and CLI entrypoint."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import signal
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    CA_LOCK,
    CERTBOT_BIN,
    CERTD_DRY_RUN,
    CONFIG_YAML,
    DNS_CREDENTIALS_DIR,
    GROUP_NAME,
    LOG,
    MAX_REQUEST_BYTES,
    SOCKET_PATH,
    _ALERTS,
    _get_ca_root_dir,
    _get_cert_dns_names,
    _get_haproxy_certs_dir,
    _get_letsencrypt_root_dir,
    _load_cert_info,
    _load_first_cert_from_pem,
    _load_yaml,
    _normalize_dns_name,
    _prepare_ca_root,
    _prepare_ca_subdir,
    renew_certificates,
    report_alert_level,
)
from .issuance import (
    DELIVERY_DIR,
    _build_cert_item_for_list,
    handle_dns_provider_delete,
    handle_dns_provider_save,
    handle_dns_providers_list,
)
from .renewals import (
    _certs_available_root,
    _internal_ca_paths,
    handle_certs_issue,
    handle_certs_status,
    handle_deliveries_list,
    handle_delivery_delete,
    handle_delivery_save,
    handle_delivery_test,
    handle_renewal_pauses,
)
from .internal_ca import (
    MultipartForm,
    _STANDBY_SWITCH_LOCK,
    _ca_certificates,
    _load_client_auth_ids,
    _rebuild_client_auth_material,
    _standby_hint,
    handle_ca_client_auth,
    handle_ca_export,
    handle_ca_revoked,
    handle_external_ca_delete,
    handle_external_ca_upload_form,
    handle_internal_ca_delete,
    handle_internal_ca_ensure,
    handle_internal_ca_rotate,
    handle_internal_cert_issue,
    handle_standby_activate,
    handle_standby_adopt,
    handle_standby_delete,
    handle_standby_list,
    handle_standby_release,
    handle_standby_store,
    handle_standby_store_all,
)
from .inventory_trash import (
    TRASH_KINDS,
    TRASH_LOCK,
    TRASH_PURGE_INTERVAL_SECONDS,
    _TRASH_ID_RE,
    _copy_owned,
    _remove_path,
    _rename_noreplace,
    _trash_expired,
    _trash_fingerprints,
    _trash_item_dir,
    _trash_listing,
    _trash_root,
    handle_certs_backup,
    handle_certs_import_form,
    handle_certs_inspect_form,
    handle_certs_list,
    handle_certs_restore,
    handle_certs_upload_form,
    handle_delete_haproxy,
    handle_delete_le,
    set_trash_keep_days,
    trash_keep_days,
)

def _trash_meta(item_id: str, *, live: bool = False) -> Dict[str, Any]:
    """An item's metadata. With live, an item past the term is removed and refused."""

    directory = _trash_item_dir(item_id)
    meta_path = directory / "meta.json"
    if directory.is_symlink() or meta_path.is_symlink() or not meta_path.is_file():
        raise ValueError("unknown trash item")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or meta.get("kind") not in TRASH_KINDS:
        raise ValueError("unknown trash item")
    if not isinstance(meta.get("paths"), list):
        raise ValueError("unknown trash item")
    if live and _trash_expired(int(meta.get("deleted_at") or 0), time.time(), trash_keep_days()):
        shutil.rmtree(directory, ignore_errors=True)
        raise ValueError("unknown trash item")
    return meta


def _trash_purge_locked(now: Optional[float] = None) -> int:
    root = _trash_root()
    if not root.is_dir():
        return 0
    now = time.time() if now is None else now
    days = trash_keep_days()
    # First pass: clean abandoned staging dirs and promote stale pending copies
    # so any promoted copy that has also outlived the term is purged below.
    for entry in list(root.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            continue
        if entry.name.startswith(".tmp-") and now - entry.stat().st_mtime > 3600:
            # A copy cut short by a crash.
            shutil.rmtree(entry, ignore_errors=True)
        elif entry.name.startswith(".pending-") and now - entry.stat().st_mtime > 3600:
            # A deletion cut short by a crash may well have gone through.
            promoted_name = entry.name[len(".pending-"):]
            if _TRASH_ID_RE.fullmatch(promoted_name):
                with contextlib.suppress(OSError):
                    os.replace(entry, root / promoted_name)
    removed = 0
    if days <= 0:
        return 0
    for entry in list(root.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            continue
        match = _TRASH_ID_RE.fullmatch(entry.name)
        if match is not None and _trash_expired(int(match.group("at")), now, days):
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    return removed


def list_trash() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    with TRASH_LOCK:
        days = trash_keep_days()
        _trash_purge_locked()
        root = _trash_root()
        if root.is_dir():
            for entry in root.iterdir():
                if not _TRASH_ID_RE.fullmatch(entry.name):
                    continue
                try:
                    meta = _trash_meta(entry.name)
                except (OSError, ValueError):
                    continue
                items.append({
                    "id": meta["id"],
                    "kind": meta["kind"],
                    "name": meta.get("name") or "",
                    "details": meta.get("details") or {},
                    "deleted_at": int(meta.get("deleted_at") or 0),
                    "deleted_by": meta.get("deleted_by") or "",
                    "expires_at": (
                        int(meta.get("deleted_at") or 0) + days * 86400 if days > 0 else 0
                    ),
                })
    items.sort(key=lambda item: (item["deleted_at"], item["id"]), reverse=True)
    return {"items": items, "keep_days": days}


_TRASH_ROOTS = {
    "haproxy_cert": lambda: [_get_haproxy_certs_dir()],
    "letsencrypt": lambda: [_get_letsencrypt_root_dir()],
    "standby": lambda: [_certs_available_root()],
    "external_ca": lambda: [_get_ca_root_dir()],
    "internal_ca": lambda: [_get_ca_root_dir()],
    "dns_provider": lambda: [DNS_CREDENTIALS_DIR],
    "cert_delivery": lambda: [DELIVERY_DIR],
}


def _trash_targets(meta: Dict[str, Any]) -> List[Tuple[Path, Path, Dict[str, Any]]]:
    """Where each stored piece goes back to, refused outside its own home."""

    directory = _trash_item_dir(meta["id"])
    bases = [base.resolve() for base in _TRASH_ROOTS[meta["kind"]]()]
    targets = []
    for entry in meta["paths"]:
        if not isinstance(entry, dict):
            raise ValueError("damaged trash item")
        target = Path(str(entry.get("path") or ""))
        stored = str(entry.get("stored") or "")
        if not target.is_absolute() or target.name in ("", ".", "..") or not stored.isdigit():
            raise ValueError("damaged trash item")
        resolved_parent = target.parent.resolve()
        candidate = resolved_parent / target.name
        if not any(base in candidate.parents for base in bases):
            raise ValueError(f"refusing to restore outside the certificate directories: {target}")
        source = directory / stored
        if not os.path.lexists(source):
            raise ValueError("damaged trash item")
        targets.append((source, candidate, entry))
    return targets


def _trash_staging_dir(target_parent: Path, kind: str) -> Path:
    """Keep temporary files out of HAProxy's crt directory when on the same filesystem."""

    if kind == "haproxy_cert":
        trash_root = _trash_root(create=True)
        with contextlib.suppress(OSError):
            if trash_root.stat().st_dev == target_parent.stat().st_dev:
                return trash_root
    return target_parent


def restore_trash_item(item_id: str) -> Dict[str, Any]:
    with TRASH_LOCK:
        kind = _trash_meta(item_id, live=True)["kind"]
    # Taken in the order the deletions take them (see the section's head): a
    # CA restore that held TRASH_LOCK while waiting for CA_LOCK deadlocked
    # against a CA deletion holding CA_LOCK while waiting for TRASH_LOCK.
    with contextlib.ExitStack() as held:
        if kind in ("internal_ca", "external_ca"):
            # Not reentrant, and the client-trust rebuild below takes it
            # again: held only while the files go back.
            held.enter_context(CA_LOCK)
        held.enter_context(_STANDBY_SWITCH_LOCK)
        held.enter_context(TRASH_LOCK)
        meta = _trash_meta(item_id, live=True)
        if meta["kind"] != kind:
            raise ValueError("damaged trash item")
        targets = _trash_targets(meta)
        target_paths = [target for _, target, _ in targets]
        taken = [str(target) for target in target_paths if os.path.lexists(target)]
        # A deletion that stopped part-way (certbot removes the renewal
        # settings first) left pieces of the very thing in the trash. Exactly
        # those pieces, and nothing new, are moved aside and replaced by the
        # whole copy; anything else in the way is refused.
        extra = meta.get("extra") or {}
        leftovers = extra.get("leftovers")
        leftover_fingerprints = extra.get("leftover_fingerprints")
        replacing = (
            bool(taken)
            and isinstance(leftovers, list)
            and _trash_listing(target_paths) == sorted(str(value) for value in leftovers)
            and (
                not isinstance(leftover_fingerprints, list)
                or _trash_fingerprints(target_paths) == leftover_fingerprints
            )
        )
        if taken and not replacing:
            raise ValueError(
                "something of the same name is in place now; delete or rename it first: "
                + ", ".join(taken)
            )
        if meta["kind"] == "internal_ca" and not replacing:
            key_path, cert_path = _internal_ca_paths()
            if key_path.exists() or cert_path.exists():
                raise ValueError(
                    "a new internal certificate authority has been created since; "
                    "it has to be deleted before the old one can come back"
                )
        # Each piece is copied under a hidden temporary name (outside HAProxy's
        # crt directory when on the same filesystem) and renamed in only when
        # whole: a copy cut short never leaves a broken PEM where HAProxy or
        # certbot would read it, and never makes the place look taken.
        written: List[Path] = []
        staged: List[Path] = []
        aside: List[Tuple[Path, Path]] = []
        try:
            for source, target, entry in targets:
                if not target.parent.exists():
                    target.parent.mkdir(parents=True, mode=int(entry.get("parent_mode") or 0o700))
                    os.chmod(target.parent, int(entry.get("parent_mode") or 0o700))
                    with contextlib.suppress(OSError, TypeError):
                        os.chown(target.parent, int(entry["parent_uid"]), int(entry["parent_gid"]))
                    written.append(target.parent)
                stage_dir = _trash_staging_dir(target.parent, meta["kind"])
                if replacing and os.path.lexists(target):
                    moved = stage_dir / f".replaced-{os.urandom(6).hex()}"
                    os.rename(target, moved)
                    aside.append((moved, target))
                temporary = stage_dir / f".restore-{os.urandom(6).hex()}"
                staged.append(temporary)
                _copy_owned(source, temporary)
                try:
                    _rename_noreplace(temporary, target)
                except FileExistsError as exc:
                    raise ValueError(
                        f"{target} appeared while it was being restored; nothing was replaced"
                    ) from exc
                staged.remove(temporary)
                written.append(target)
        except BaseException:
            for path in staged + list(reversed(written)):
                with contextlib.suppress(OSError):
                    _remove_path(path)
            for moved, target in reversed(aside):
                with contextlib.suppress(OSError):
                    try:
                        _rename_noreplace(moved, target)
                    except FileExistsError:
                        # Something new appeared at target while rolling back:
                        # never replace it with the old leftover.
                        LOG.warning("cannot restore leftover %s: %s already exists", moved, target)
                        _remove_path(moved)
            raise
        for moved, _target in aside:
            with contextlib.suppress(OSError):
                _remove_path(moved)
        shutil.rmtree(_trash_item_dir(item_id), ignore_errors=True)
    notes: List[str] = []
    if meta["kind"] == "external_ca" and (meta.get("extra") or {}).get("client_auth"):
        ca_id = str(meta.get("name") or "")
        trusted = _load_client_auth_ids()
        if ca_id and ca_id not in trusted:
            status, response = handle_ca_client_auth({"ids": trusted + [ca_id]})
            if not response.get("ok"):
                notes.append(
                    "it was trusted for client certificates before; trust it again "
                    "on the certificates page (" + str(response.get("error") or status) + ")"
                )
    LOG.info("Restored %s %s from the trash", meta["kind"], meta.get("name"))
    return {
        "kind": meta["kind"],
        "name": meta.get("name") or "",
        "paths": [str(target) for _, target, _ in targets],
        "notes": notes,
    }


def purge_trash(item_id: Optional[str] = None) -> Dict[str, Any]:
    with TRASH_LOCK:
        if item_id:
            meta = _trash_meta(item_id)
            shutil.rmtree(_trash_item_dir(item_id))
            return {"removed": 1, "kind": meta["kind"], "name": meta.get("name") or ""}
        removed = 0
        failed: List[str] = []
        root = _trash_root()
        if root.is_dir():
            for entry in root.iterdir():
                if _TRASH_ID_RE.fullmatch(entry.name) and not entry.is_symlink() and entry.is_dir():
                    # Counted only when it is gone: a copy with a key left on
                    # the disk is not "deleted for good".
                    try:
                        shutil.rmtree(entry)
                    except OSError as exc:
                        failed.append(f"{entry.name}: {exc}")
                        continue
                    removed += 1
        return {"removed": removed, "failed": failed}


def _cert_details(path: Path) -> Dict[str, Any]:
    """What the trash page shows about a certificate: names and expiry."""

    with contextlib.suppress(Exception):
        item = _build_cert_item_for_list(path)
        if item:
            return {"domains": item.get("domains") or [], "not_after": item.get("not_after")}
    return {}


def handle_trash_list(_body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, {"ok": True, **list_trash()}
    except (OSError, ValueError) as exc:
        return 500, {"ok": False, "error": f"cannot read the trash: {exc}"}


def handle_trash_restore(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        restored = restore_trash_item(str(body.get("id") or ""))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot restore: {exc}"}
    return 200, {"ok": True, **restored}


def handle_trash_settings(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        if "keep_days" in body:
            return 200, {"ok": True, "keep_days": set_trash_keep_days(body.get("keep_days"))}
        return 200, {"ok": True, "keep_days": trash_keep_days()}
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot save the trash settings: {exc}"}


class TrashPurge(threading.Thread):
    """Keeps the term while nobody opens the trash page: keys do not outstay it."""

    def __init__(self) -> None:
        super().__init__(name="trash-purge", daemon=True)
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        while not self._halt.wait(TRASH_PURGE_INTERVAL_SECONDS):
            try:
                with TRASH_LOCK:
                    _trash_purge_locked()
            except Exception:  # pylint: disable=broad-except
                LOG.exception("trash purge failed")


def handle_trash_purge(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    item_id = str(body.get("id") or "")
    if not item_id and body.get("all") is not True:
        return 400, {"ok": False, "error": "id or all is required"}
    try:
        result = purge_trash(item_id or None)
        if result.get("failed"):
            return 500, {
                "ok": False,
                **result,
                "error": f"{len(result['failed'])} items could not be deleted: " + "; ".join(result["failed"]),
            }
        return 200, {"ok": True, **result}
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot delete: {exc}"}


# ───────────────────── an HTTP server over a Unix socket ─────────────────────


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


# How long one connection may keep a handler thread waiting on it: for the
# request, or for the caller to take the answer. Callers are local and send a
# whole request at once; one that connected and went quiet used to hold its
# thread for good. Processing time is not limited by this.
REQUEST_TIMEOUT_SECONDS = 30


class CertdHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT_SECONDS

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        """Overridden to write to the logger rather than stderr."""
        LOG.info("%s - %s", self.client_address, fmt % args)

    # helpers

    def _read_json_body(self) -> Dict[str, Any]:
        length_str = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_str)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body size is outside the allowed range")
        data = self.rfile.read(length) if length > 0 else b""
        if not data:
            return {}
        try:
            parsed = json.loads(data.decode("utf-8"))
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    # HTTP handlers

    def do_POST(self) -> None:  # noqa: N802
        path = self.path

        # Certificate and CA imports use multipart/form-data.
        if path in (
            "/api/v1/certs/upload",
            "/api/v1/certs/ca/upload",
            "/api/v1/certs/inspect",
            "/api/v1/certs/import",
        ):
            content_type = self.headers.get("Content-Type", "")
            media_type, boundary = MultipartForm.boundary(content_type)
            if media_type != "multipart/form-data":
                return self._send_json(
                    200,
                    {"ok": False, "error": "Content-Type must be multipart/form-data"},
                )

            if not boundary:
                return self._send_json(
                    200,
                    {"ok": False, "error": "multipart boundary missing"},
                )

            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_REQUEST_BYTES:
                return self._send_json(
                    413, {"ok": False, "error": "upload is too large"}
                )

            # Everything below is wrapped, unlike the JSON branch further
            # down, which always was. An exception escaping here does not
            # reach the caller as an error: it unwinds out of the handler and
            # the connection closes unanswered, so the browser is told only
            # that the remote end hung up. An upload that fails must say why.
            try:
                body = self.rfile.read(length)
                if len(body) < length:
                    return self._send_json(
                        400, {"ok": False, "error": "the upload was cut short"}
                    )
                form = MultipartForm.parse(content_type, body)

                if path == "/api/v1/certs/ca/upload":
                    status, resp = handle_external_ca_upload_form(form)
                elif path == "/api/v1/certs/inspect":
                    status, resp = handle_certs_inspect_form(form)
                elif path == "/api/v1/certs/import":
                    status, resp = handle_certs_import_form(form)
                else:
                    status, resp = handle_certs_upload_form(form)
            except Exception as exc:  # noqa: BLE001
                LOG.exception("certificate upload failed")
                status, resp = 500, {"ok": False, "error": str(exc)}
            return self._send_json(status, resp)

        try:
            body = self._read_json_body()
        except ValueError as exc:
            return self._send_json(413, {"ok": False, "error": str(exc)})

        try:
            if path == "/api/v1/certs/status":
                status, resp = handle_certs_status(body)
            elif path == "/api/v1/certs/renewal-pauses":
                status, resp = handle_renewal_pauses(body)
            elif path == "/api/v1/certs/issue":
                status, resp = handle_certs_issue(body)
            elif path == "/api/v1/certs/backup":
                status, resp = handle_certs_backup(body)
            elif path == "/api/v1/certs/restore":
                status, resp = handle_certs_restore(body)
            elif path == "/api/v1/certs/delete-haproxy":
                status, resp = handle_delete_haproxy(body)
            elif path == "/api/v1/certs/delete-le":
                status, resp = handle_delete_le(body)
            elif path == "/api/v1/certs/standby":
                status, resp = handle_standby_list(body)
            elif path == "/api/v1/certs/standby/store":
                status, resp = handle_standby_store(body)
            elif path == "/api/v1/certs/standby/adopt":
                status, resp = handle_standby_adopt(body)
            elif path == "/api/v1/certs/standby/store-all":
                status, resp = handle_standby_store_all(body)
            elif path == "/api/v1/certs/standby/activate":
                status, resp = handle_standby_activate(body)
            elif path == "/api/v1/certs/standby/release":
                status, resp = handle_standby_release(body)
            elif path == "/api/v1/certs/standby/delete":
                status, resp = handle_standby_delete(body)
            elif path == "/api/v1/certs/ca/internal/ensure":
                status, resp = handle_internal_ca_ensure(body)
            elif path == "/api/v1/certs/ca/internal/issue":
                status, resp = handle_internal_cert_issue(body)
            elif path == "/api/v1/certs/ca/internal/rotate":
                status, resp = handle_internal_ca_rotate(body)
            elif path == "/api/v1/certs/ca/internal/delete":
                status, resp = handle_internal_ca_delete(body)
            elif path == "/api/v1/certs/ca/export":
                status, resp = handle_ca_export(body)
            elif path == "/api/v1/certs/ca/delete-external":
                status, resp = handle_external_ca_delete(body)
            elif path == "/api/v1/certs/ca/client-auth":
                status, resp = handle_ca_client_auth(body)
            elif path == "/api/v1/certs/ca/revoked":
                status, resp = handle_ca_revoked(body)
            elif path == "/api/v1/certs/dns-providers":
                status, resp = handle_dns_providers_list(body)
            elif path == "/api/v1/certs/dns-providers/save":
                status, resp = handle_dns_provider_save(body)
            elif path == "/api/v1/certs/dns-providers/delete":
                status, resp = handle_dns_provider_delete(body)
            elif path == "/api/v1/certs/deliveries":
                status, resp = handle_deliveries_list(body)
            elif path == "/api/v1/certs/deliveries/save":
                status, resp = handle_delivery_save(body)
            elif path == "/api/v1/certs/deliveries/delete":
                status, resp = handle_delivery_delete(body)
            elif path == "/api/v1/certs/trash":
                status, resp = handle_trash_list(body)
            elif path == "/api/v1/certs/trash/restore":
                status, resp = handle_trash_restore(body)
            elif path == "/api/v1/certs/trash/purge":
                status, resp = handle_trash_purge(body)
            elif path == "/api/v1/certs/trash/settings":
                status, resp = handle_trash_settings(body)
            elif path == "/api/v1/certs/deliveries/test":
                status, resp = handle_delivery_test(body)
            else:
                status, resp = 404, {"ok": False, "error": "unknown path"}
        except Exception as exc:  # noqa: BLE001
            LOG.exception("certificate request failed")
            status, resp = 500, {"ok": False, "error": str(exc)}

        self._send_json(status, resp)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/v1/certs/list":
            status, resp = handle_certs_list()
        else:
            status, resp = 404, {"ok": False, "error": "unknown path"}
        self._send_json(status, resp)


# ───────────────────── main ─────────────────────


# --- Certificate expiry watch ----------------------------------------------
#
# Nothing else polls expiry: the status call is driven by someone opening the
# certificates page, so an alert built on it would only exist while a human is
# already looking. This thread is the timer that makes "expires in six days"
# something the gateway says on its own.
CERT_WATCH_INTERVAL_SECONDS = int(
    os.environ.get("CERTD_EXPIRY_WATCH_INTERVAL", str(6 * 3600))
)


# What the gateway serves now: the sites as last applied. The draft beside
# vars.yml is the fallback before anything has been applied.
APPLIED_WEBSITES = Path(
    os.environ.get(
        "HAPROXY_APPLIED_WEBSITES", "/opt/haproxy-admin/backups/haproxy/last_applied_websites.yml"
    )
)
# The settings as last applied, beside the sites: the admin and sign-in names
# the gateway serves now (R05).
APPLIED_VARS = Path(
    os.environ.get(
        "HAPROXY_APPLIED_VARS", "/opt/haproxy-admin/backups/haproxy/last_applied_vars.yml"
    )
)


def _site_names(site: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for key in ("domain", "alt_names", "aliases", "domains"):
        value = site.get(key)
        for item in value if isinstance(value, list) else [value]:
            if item:
                names.add(_normalize_dns_name(str(item)))
    return {name for name in names if name}


def certificate_users() -> Optional[Tuple[Set[str], Set[str]]]:
    """(names someone still uses, names only switched-off sites use).

    A site is switched off when it is both paused and has its renewal paused;
    its names stop counting only then. Everything else the gateway serves --
    other sites, the admin and sign-in hosts -- and every name a delivery
    target sends elsewhere counts as in use. None when the sites cannot be
    read: what cannot be known is checked, never skipped.
    """
    # What is served and what is saved but not applied yet, both: a name
    # counts as used if either uses it (R05). Applied sites with the draft's
    # admin and sign-in names used to be compared -- after a Save without
    # Apply the old admin name, still served, looked unused.
    site_files = [path for path in (CONFIG_YAML.parent / "websites.yml", APPLIED_WEBSITES)
                  if path.exists()]
    if not site_files:
        return None
    used: Set[str] = set()
    switched_off: Set[str] = set()
    for sites_path in site_files:
        sites = _load_yaml(sites_path).get("sites")
        if not isinstance(sites, list):
            return None
        for site in sites:
            if not isinstance(site, dict):
                continue
            if site.get("paused") is True and site.get("cert_renewal_paused") is True:
                switched_off |= _site_names(site)
            else:
                used |= _site_names(site)
    for vars_path in (CONFIG_YAML, APPLIED_VARS):
        settings = _load_yaml(vars_path)
        for key in ("admin_domain", "aut_domain"):
            if settings.get(key):
                used.add(_normalize_dns_name(str(settings[key])))
    if DELIVERY_DIR.is_dir():
        for record_path in sorted(DELIVERY_DIR.glob("*.json")):
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - an unreadable target may use anything
                return None
            for domain in record.get("domains") or []:
                used.add(_normalize_dns_name(str(domain)))
    return used, switched_off - used


def _name_covers(certificate_name: str, name: str) -> bool:
    if certificate_name == name:
        return True
    if certificate_name.startswith("*."):
        suffix = certificate_name[1:]
        return name.endswith(suffix) and "." not in name[: -len(suffix)]
    return False


def _only_switched_off(names: List[str], users: Optional[Tuple[Set[str], Set[str]]]) -> bool:
    """A certificate some switched-off site uses and nothing else does."""
    if users is None or not names:
        return False
    used, switched_off = users
    if any(_name_covers(cert_name, name) for cert_name in names for name in used):
        return False
    return any(_name_covers(cert_name, name) for cert_name in names for name in switched_off)


class CertificateExpiryWatch(threading.Thread):
    """One per daemon, started with it.

    It used to be started by every reading of the certificate authorities
    list -- which the certificates page does -- so a gateway nobody looked at
    never checked, and each visit added a thread and an immediate scan (and,
    on one gateway, another warning by email).
    """

    def __init__(self) -> None:
        super().__init__(name="cert-expiry-watch", daemon=True)
        # Not `_stop`: threading.Thread has a method of that name, which
        # join() calls.
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        if _ALERTS is None:
            return
        # A first pass right away, so a restart does not hide an expiry for
        # another six hours.
        while True:
            try:
                self.scan()
            except Exception:  # pylint: disable=broad-except
                LOG.exception("certificate expiry scan failed")
            if self._halt.wait(CERT_WATCH_INTERVAL_SECONDS):
                return

    def scan(self) -> int:
        """Report one observation per installed HAProxy certificate."""
        directory = _get_haproxy_certs_dir()
        reported = 0
        try:
            entries = sorted(directory.glob("*.pem"))
        except OSError as exc:
            LOG.warning("cannot list %s: %s", directory, exc)
            return 0
        users = certificate_users()
        for path in entries:
            info = _load_cert_info(path)
            if not info:
                continue
            days = int(info["days_left"])
            domain = path.stem
            cert = _load_first_cert_from_pem(path)
            names = sorted(_get_cert_dns_names(cert)) if cert is not None else []
            if _only_switched_off(names, users):
                # Paused, with its renewal paused: nobody is served by it and
                # nobody will renew it. Warning about its expiry, every six
                # hours, only taught the operator to ignore the mail.
                report_alert_level(
                    "certificate.expiring",
                    domain,
                    active=False,
                    retired=True,
                    summary=(
                        f"The certificate for {domain} is not checked: only switched-off "
                        "sites use it"
                    ),
                )
                reported += 1
                continue
            expiring = days <= int(info["warn_days"])
            report_alert_level(
                "certificate.expiring",
                domain,
                active=expiring,
                severity="critical" if days <= 7 else "warning",
                summary=(
                    f"The certificate for {domain} expires in {days} days"
                    if days >= 0
                    else f"The certificate for {domain} expired {-days} days ago"
                ),
                detail=(
                    f"Not after: {info['not_after']}"
                    + _standby_hint(domain)
                ),
            )
            reported += 1
        return reported


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    LOG.info(
        "Starting haproxy-certd: SOCKET_PATH=%s, CERTBOT_BIN=%s, DRY_RUN=%s",
        SOCKET_PATH,
        CERTBOT_BIN,
        CERTD_DRY_RUN,
    )

    ca_root = _prepare_ca_root()
    if ca_root.exists():
        _prepare_ca_subdir("internal")
        _prepare_ca_subdir("external")

    # The frontend may reference the bundle and the revocation list before
    # anyone has imported a certificate authority, and HAProxy will not start
    # if a file named in the configuration is missing.
    # A CA can disappear between restarts (a restore from an older backup, a
    # file removed by hand). One unresolvable entry must not cost the other
    # authorities their material.
    startup_ids: List[str] = []
    for ca_id in _load_client_auth_ids():
        try:
            _ca_certificates(ca_id)
        except (OSError, ValueError) as exc:
            LOG.warning("dropping %r from client authentication: %s", ca_id, exc)
            continue
        startup_ids.append(ca_id)
    try:
        _rebuild_client_auth_material(startup_ids)
    except (OSError, ValueError) as exc:
        LOG.error("cannot prepare client authentication material: %s", exc)

    # remove an old socket left behind
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except OSError as exc:
        LOG.error("Failed to unlink old socket %s: %s", SOCKET_PATH, exc)

    # create the server
    server = UnixHTTPServer(SOCKET_PATH, CertdHandler)

    # socket permissions: root:haproxy, 660
    try:
        import pwd
        import grp

        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(SOCKET_PATH, uid, gid)
    except Exception as exc:
        LOG.warning("Failed to set socket ownership on %s: %s", SOCKET_PATH, exc)
    try:
        os.chmod(SOCKET_PATH, 0o660)
    except Exception as exc:
        LOG.warning("Failed to set socket permissions on %s: %s", SOCKET_PATH, exc)

    # The expiry watch: one, for as long as the daemon runs.
    expiry_watch = CertificateExpiryWatch()
    expiry_watch.start()
    trash_purge = TrashPurge()
    trash_purge.start()

    shutdown_event = threading.Event()
    received_signal: List[int] = []

    def _shutdown_watcher() -> None:
        shutdown_event.wait()
        if received_signal:
            LOG.info("Received signal %s; shutting down", received_signal[0])
        server.shutdown()

    threading.Thread(target=_shutdown_watcher, daemon=True).start()

    def _handle_signal(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _handle_signal)

    try:
        LOG.info("haproxy-certd is listening on unix://%s", SOCKET_PATH)
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted by user")
    finally:
        expiry_watch.stop()
        trash_purge.stop()
        try:
            server.server_close()
        finally:
            try:
                if os.path.exists(SOCKET_PATH):
                    os.unlink(SOCKET_PATH)
            except OSError:
                pass


if __name__ == "__main__":
    if sys.argv[1:] == ["--renew"]:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        sys.exit(renew_certificates())
    main()
