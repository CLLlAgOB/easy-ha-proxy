"""Certificate inventory, import/upload/delete, and Trash retention."""

from __future__ import annotations

import base64
import ctypes
import errno
import io
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import zipfile
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .constants import (
    CERTBOT_BIN,
    CERTBOT_QUICK_TIMEOUT_SECONDS,
    CERTD_DRY_RUN,
    HAPROXY_PEMS_SCRIPT,
    LOG,
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_EXPANDED_BYTES,
    MAX_ARCHIVE_FILES,
    MAX_REQUEST_BYTES,
    PEM_REBUILD_TIMEOUT_SECONDS,
    _dns_binding_path,
    _ensure_within,
    _fmt_date,
    _get_cert_dns_names,
    _get_haproxy_certs_dir,
    _get_le_live_dir,
    _get_letsencrypt_root_dir,
    _load_cert_info,
    _normalize_dns_name,
    _prepare_ca_root,
    _prepare_ca_subdir,
    _run_bounded,
    _safe_slug,
    _validate_zip,
)
from .issuance import (
    _activate_server_pem,
    _build_cert_item_for_list,
    _certificate_label,
    _public_key_bytes,
    _set_cert_permissions,
    _validate_server_pem,
    _verify_external_chain,
)
from .renewals import _list_certificate_authorities
from .internal_ca import (
    MultipartForm,
    _certificate_is_authority,
    _chain_for_leaf,
    _decode_uploaded_material,
    _describe_certificate,
    _is_self_signed,
    _uploaded_file,
    _write_public_file,
)

# Bound across sibling submodules when the package finishes loading.
_cert_details: Any = None
_trash_purge_locked: Any = None

def _sort_uploaded_material(
    data: bytes, password: str, name: str, domain: str
) -> Dict[str, Any]:
    certificates, keys, detected = _decode_uploaded_material(data, password)

    authorities = [c for c in certificates if _certificate_is_authority(c)]
    leaves = [c for c in certificates if not _certificate_is_authority(c)]

    paired: Optional[Tuple[x509.Certificate, Any]] = None
    for leaf in leaves:
        for key in keys:
            if _public_key_bytes(leaf.public_key()) == _public_key_bytes(
                key.public_key()
            ):
                paired = (leaf, key)
                break
        if paired:
            break

    problems: List[str] = []
    actions: List[str] = []

    ca_id = ""
    if authorities:
        root = next((c for c in authorities if _is_self_signed(c)), authorities[0])
        ca_id = _safe_slug(name or _certificate_label(root)).lower()
        if ca_id == "internal":
            problems.append("the identifier 'internal' is reserved")
            ca_id = ""
        else:
            actions.append(
                f"import {len(authorities)} certificate authorities as {ca_id!r}"
                if len(authorities) > 1
                else f"import the certificate authority {ca_id!r}"
            )

    server: Optional[Dict[str, Any]] = None
    target = ""
    if paired:
        leaf, _key = paired
        names = sorted(_get_cert_dns_names(leaf))
        target = domain or (names[0] if names else "")
        if not target:
            problems.append(
                "the certificate carries no host name, so there is nothing to "
                "install it under; choose a domain"
            )
        else:
            chain = _chain_for_leaf(leaf, authorities)
            server = {
                **_describe_certificate(leaf),
                "domain": target,
                "chain_length": len(chain),
            }
            actions.append(f"install a server certificate for {target}")
            if not chain and not _is_self_signed(leaf):
                problems.append(
                    "no intermediate certificate came with it, so clients that "
                    "do not already hold the chain may reject this certificate"
                )
    elif leaves:
        problems.append(
            "a server certificate was found but not its private key, so it "
            "cannot be installed; upload both together"
        )
    elif keys and not authorities:
        problems.append("a private key was found but no certificate to go with it")

    return {
        "format": detected,
        "authorities": [_describe_certificate(c) for c in authorities],
        "server_certificate": server,
        "ca_id": ca_id,
        "domain": target,
        "actions": actions,
        "problems": problems,
        "_authorities": authorities,
        "_paired": paired,
    }


def _import_summary(plan: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value for key, value in plan.items() if not key.startswith("_")
    }


def handle_certs_inspect_form(form: MultipartForm) -> Tuple[int, Dict[str, Any]]:
    """Say what a file is, and change nothing."""
    file_item = _uploaded_file(form, "file")
    if file_item is None:
        return 400, {"ok": False, "error": "file is required"}
    data = file_item.file.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        return 413, {"ok": False, "error": "the upload is too large"}
    try:
        plan = _sort_uploaded_material(
            data,
            form.getfirst("password", "") or "",
            (form.getfirst("name", "") or "").strip(),
            (form.getfirst("domain", "") or "").strip(),
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    return 200, {"ok": True, **_import_summary(plan)}


def handle_certs_import_form(form: MultipartForm) -> Tuple[int, Dict[str, Any]]:
    """Do what the inspection described."""
    file_item = _uploaded_file(form, "file")
    if file_item is None:
        return 400, {"ok": False, "error": "file is required"}
    data = file_item.file.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        return 413, {"ok": False, "error": "the upload is too large"}
    replace = (form.getfirst("replace", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )

    try:
        plan = _sort_uploaded_material(
            data,
            form.getfirst("password", "") or "",
            (form.getfirst("name", "") or "").strip(),
            (form.getfirst("domain", "") or "").strip(),
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}

    if not plan["actions"]:
        return 400, {
            "ok": False,
            "error": "; ".join(plan["problems"])
            or "there is nothing in this file to install",
        }

    done: List[str] = []
    authorities: List[x509.Certificate] = plan["_authorities"]
    ca_path: Optional[Path] = None

    if authorities and plan["ca_id"]:
        canonical = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in authorities
        )
        external_dir = _prepare_ca_subdir("external", create=True)
        try:
            ca_path = _ensure_within(
                external_dir, external_dir / f"{plan['ca_id']}.pem"
            )
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        if ca_path.is_file() and ca_path.read_bytes() != canonical and not replace:
            return 409, {
                "ok": False,
                "error": (
                    f"a different certificate authority is already stored as "
                    f"{plan['ca_id']!r}. Choose another name, or confirm the "
                    "replacement."
                ),
                "needs_replace": True,
                **_import_summary(plan),
            }
        _write_public_file(ca_path, canonical)
        done.append(f"certificate authority {plan['ca_id']!r} imported")

    if plan["_paired"]:
        leaf, key = plan["_paired"]
        chain = _chain_for_leaf(leaf, authorities)
        pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in [leaf] + chain
        ) + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            certificates, _ = _validate_server_pem(pem, plan["domain"])
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc), "completed": done}

        # Only when the same upload also carried the authority: verifying
        # against an unrelated one already in the store would prove nothing.
        if ca_path is not None:
            verified, detail = _verify_external_chain(certificates, ca_path)
            if not verified:
                return 400, {
                    "ok": False,
                    "error": f"the chain does not verify against {plan['ca_id']!r}: {detail}",
                    "completed": done,
                }

        hap_dir = _get_haproxy_certs_dir()
        hap_dir.mkdir(parents=True, exist_ok=True)
        try:
            destination = _ensure_within(
                hap_dir, hap_dir / f"{_safe_slug(plan['domain'])}.pem"
            )
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc), "completed": done}
        ok, reload_rc, _out, reload_stderr = _activate_server_pem(destination, pem)
        if not ok:
            return 400, {
                "ok": False,
                "error": (
                    "HAProxy rejected the certificate and the previous one was "
                    f"restored: {reload_stderr.strip()[:300]}"
                ),
                "completed": done,
            }
        done.append(f"server certificate installed for {plan['domain']}")

    return 200, {
        "ok": True,
        "completed": done,
        "message": "; ".join(done),
        **_import_summary(plan),
    }


def handle_certs_backup(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    hap_dir = _get_haproxy_certs_dir()
    le_root = _get_letsencrypt_root_dir()
    ca_root = _prepare_ca_root()

    buf = io.BytesIO()
    total_files = 0
    hap_files = 0
    le_files = 0
    ca_files = 0

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        if hap_dir.is_dir():
            for path in sorted(hap_dir.rglob("*")):
                if not path.is_file():
                    continue
                try:
                    _ensure_within(hap_dir, path)
                except ValueError:
                    continue
                if total_files >= MAX_ARCHIVE_FILES:
                    raise ValueError("certificate backup contains too many files")
                if path.stat().st_size + buf.tell() > MAX_ARCHIVE_BYTES:
                    raise ValueError("certificate backup exceeds the configured limit")
                rel = path.relative_to(hap_dir)
                arcname = str(Path(hap_dir.name) / rel)
                zf.write(path, arcname=arcname)
                total_files += 1
                hap_files += 1

        if le_root.is_dir():
            for path in sorted(le_root.rglob("*")):
                if not path.is_file():
                    continue
                try:
                    _ensure_within(le_root, path)
                except ValueError:
                    continue
                if total_files >= MAX_ARCHIVE_FILES:
                    raise ValueError("certificate backup contains too many files")
                if path.stat().st_size + buf.tell() > MAX_ARCHIVE_BYTES:
                    raise ValueError("certificate backup exceeds the configured limit")
                rel = path.relative_to(le_root)
                arcname = str(Path(le_root.name) / rel)
                zf.write(path, arcname=arcname)
                total_files += 1
                le_files += 1

        if ca_root.is_dir():
            for path in sorted(ca_root.rglob("*")):
                if not path.is_file():
                    continue
                _ensure_within(ca_root, path)
                if total_files >= MAX_ARCHIVE_FILES:
                    raise ValueError("certificate backup contains too many files")
                if path.stat().st_size + buf.tell() > MAX_ARCHIVE_BYTES:
                    raise ValueError("certificate backup exceeds the configured limit")
                rel = path.relative_to(ca_root)
                zf.write(path, arcname=str(Path(ca_root.name) / rel))
                total_files += 1
                ca_files += 1

    raw = buf.getvalue()
    archive_b64 = base64.b64encode(raw).decode("ascii")

    msg = (
        f"Certificate backup created: {total_files} files total, "
        f"HAProxy: {hap_files}, Let's Encrypt: {le_files}, CA: {ca_files}. "
        f"Archive size: {len(raw)} bytes."
    )

    return 200, {
        "ok": True,
        "archive_b64": archive_b64,
        "haproxy_certs_dir": str(hap_dir),
        "letsencrypt_root_dir": str(le_root),
        "certificate_authorities_dir": str(ca_root),
        "message": msg,
    }


_CERTBOT_HOOK_KEY_RE = re.compile(
    r"^\s*(?:pre|post|deploy|renew|manual_auth|manual_cleanup)[_-]hook\s*=",
    re.IGNORECASE | re.MULTILINE,
)
_ALLOWED_LE_RESTORE_DIRS = frozenset({"accounts", "archive", "live", "renewal", "keys", "csr"})


def _is_allowed_le_restore_rel(rel: Path) -> bool:
    """Only restore certificate/account/renewal data under /etc/letsencrypt, never hooks or cli.ini."""
    parts = rel.parts
    if len(parts) < 2:
        return False
    top = parts[0]
    if top not in _ALLOWED_LE_RESTORE_DIRS:
        return False
    if top == "renewal":
        return len(parts) == 2 and parts[1].endswith(".conf") and not parts[1].startswith(".")
    return True


def _read_zip_member_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, remaining_budget: int) -> bytes:
    """Read a ZIP entry while strictly enforcing the total decompressed byte cap."""
    chunks: List[bytes] = []
    total = 0
    with zf.open(info, "r") as src:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > remaining_budget:
                raise ValueError("ZIP archive expands beyond the allowed size")
            chunks.append(chunk)
    return b"".join(chunks)


def handle_certs_restore(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    archive_b64 = (body.get("archive_b64") or "").strip()

    if not archive_b64:
        return 400, {"ok": False, "error": "archive_b64 is required"}

    try:
        raw = base64.b64decode(archive_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return 400, {"ok": False, "error": f"invalid base64: {exc}"}

    try:
        if len(raw) > MAX_ARCHIVE_BYTES:
            return 413, {"ok": False, "error": "ZIP archive is too large"}
        zf = zipfile.ZipFile(io.BytesIO(raw), "r")
        _validate_zip(zf)
    except Exception as exc:  # noqa: BLE001
        return 400, {"ok": False, "error": f"not a valid ZIP archive: {exc}"}

    hap_dir = _get_haproxy_certs_dir()
    le_root = _get_letsencrypt_root_dir()
    ca_root = _prepare_ca_root(create=True)
    hap_top = hap_dir.name
    le_top = le_root.name
    ca_top = ca_root.name

    written_files = 0
    skipped_entries = 0
    remaining_budget = MAX_ARCHIVE_EXPANDED_BYTES

    for info in zf.infolist():
        if info.is_dir():
            continue

        member_path = Path(info.filename)

        if member_path.is_absolute() or ".." in member_path.parts:
            skipped_entries += 1
            continue

        if len(member_path.parts) < 2:
            skipped_entries += 1
            continue

        top = member_path.parts[0]
        rel = Path(*member_path.parts[1:])

        if top == hap_top:
            if len(rel.parts) != 1 or not rel.name.endswith(".pem") or rel.name.startswith("."):
                skipped_entries += 1
                continue
            target_base = hap_dir
            is_haproxy_cert = True
        elif top == le_top:
            if not _is_allowed_le_restore_rel(rel):
                skipped_entries += 1
                continue
            target_base = le_root
            is_haproxy_cert = False
        elif top == ca_top:
            target_base = ca_root
            is_haproxy_cert = False
        else:
            skipped_entries += 1
            continue

        try:
            target = _ensure_within(target_base, target_base / rel)
        except ValueError:
            skipped_entries += 1
            continue

        try:
            data = _read_zip_member_bounded(zf, info, remaining_budget)
            remaining_budget -= len(data)
            if top == le_top and rel.parts[0] == "renewal":
                if _CERTBOT_HOOK_KEY_RE.search(data.decode("utf-8", errors="replace")):
                    LOG.warning("Refused certbot renewal config containing hook directive: %s", rel)
                    skipped_entries += 1
                    continue
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb") as dst:
                    fd = -1
                    dst.write(data)
                    dst.flush()
                    os.fsync(dst.fileno())
            finally:
                if fd != -1:
                    os.close(fd)

            if is_haproxy_cert:
                _set_cert_permissions(target)
            elif target_base == ca_root:
                os.chmod(target, 0o600 if target.name == "ca.key" else 0o644)
            else:
                os.chmod(target, 0o600)

            written_files += 1
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        except Exception:
            skipped_entries += 1
            continue

    pem_rc: Optional[int] = None
    pem_stdout = ""
    pem_stderr = ""

    if ca_root.is_dir():
        os.chmod(ca_root, 0o700)
        _prepare_ca_subdir("internal")
        _prepare_ca_subdir("external")

    if HAPROXY_PEMS_SCRIPT.exists() and not CERTD_DRY_RUN:
        LOG.info("Running PEM rebuild script after restore: %s",
                 HAPROXY_PEMS_SCRIPT)
        proc = _run_bounded(
            [str(HAPROXY_PEMS_SCRIPT)], timeout=PEM_REBUILD_TIMEOUT_SECONDS
        )
        pem_rc = proc.returncode
        pem_stdout = proc.stdout
        pem_stderr = proc.stderr

    ok = pem_rc in (None, 0)

    msg = (
        f"Certificate backup restored: {written_files} files written, "
        f"{skipped_entries} entries skipped."
    )
    if pem_rc is None:
        msg += " The PEM rebuild script was not run."
    elif pem_rc == 0:
        msg += " PEM rebuild and HAProxy reload completed successfully."
    else:
        msg += (
            f" PEM rebuild exited with code {pem_rc}; "
            "see pem_stdout and pem_stderr for details."
        )

    return 200, {
        "ok": ok,
        "message": msg,
        "haproxy_certs_dir": str(hap_dir),
        "letsencrypt_root_dir": str(le_root),
        "certificate_authorities_dir": str(ca_root),
        "written_files": written_files,
        "skipped_entries": skipped_entries,
        "pem_rc": pem_rc,
        "pem_stdout": pem_stdout,
        "pem_stderr": pem_stderr,
    }

def get_latest_account_id(accounts_dir: Path) -> Optional[str]:
    """Return the newest existing account, or None for first registration."""
    if not accounts_dir.is_dir():
        return None
    latest_account: Optional[str] = None
    latest_date: Optional[datetime] = None

    for account_dir in accounts_dir.iterdir():
        if account_dir.is_dir():
            creation_time = datetime.fromtimestamp(account_dir.stat().st_ctime)
            if latest_date is None or creation_time > latest_date:
                latest_date = creation_time
                latest_account = account_dir.name

    return latest_account

def handle_certs_upload_form(form: MultipartForm) -> Tuple[int, Dict[str, Any]]:
    """
    Handles a PEM upload over multipart/form-data.
    Expects the fields:
      - cert_file (a .pem file)
      - site_name (optional)
      - domain    (optional)
    """
    file_item = _uploaded_file(form, "cert_file")
    if file_item is None:
        return 200, {"ok": False, "error": "cert_file is required"}

    site_name = (form.getfirst("site_name", "") or "").strip()
    domain = (form.getfirst("domain", "") or "").strip()
    external_ca_id = (form.getfirst("external_ca_id", "") or "").strip()
    if domain:
        try:
            domain = _normalize_dns_name(domain)
        except ValueError as exc:
            return 400, {"ok": False, "error": f"invalid domain: {exc}"}

    hap_dir = _get_haproxy_certs_dir()
    hap_dir.mkdir(parents=True, exist_ok=True)

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=hap_dir, prefix=".upload-", suffix=".pem", delete=False
        ) as f:
            tmp_path = Path(f.name)
            shutil.copyfileobj(file_item.file, f)
    except Exception as exc:  # noqa: BLE001
        try:
            if tmp_path:
                tmp_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        return 200, {"ok": False, "error": f"failed to save uploaded file: {exc}"}

    if tmp_path is None or tmp_path.stat().st_size > MAX_REQUEST_BYTES:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
        return 413, {"ok": False, "error": "uploaded certificate is too large"}

    pem_data = tmp_path.read_bytes()
    try:
        certificates, _ = _validate_server_pem(pem_data, domain)
    except ValueError as exc:
        tmp_path.unlink(missing_ok=True)
        return 400, {"ok": False, "error": str(exc)}

    if external_ca_id:
        try:
            _prepare_ca_root()
            external_ca_id = _safe_slug(external_ca_id).lower()
            external_dir = _prepare_ca_subdir("external")
            ca_path = _ensure_within(
                external_dir, external_dir / f"{external_ca_id}.pem"
            )
        except ValueError as exc:
            tmp_path.unlink(missing_ok=True)
            return 400, {"ok": False, "error": str(exc)}
        if not ca_path.is_file():
            tmp_path.unlink(missing_ok=True)
            return 400, {"ok": False, "error": "selected external CA was not found"}
        verified, verification_error = _verify_external_chain(certificates, ca_path)
        if not verified:
            tmp_path.unlink(missing_ok=True)
            return 400, {
                "ok": False,
                "error": f"certificate chain is not trusted by {external_ca_id!r}: {verification_error}",
            }

    cert = certificates[0]

    cert_names = sorted(_get_cert_dns_names(cert))
    try:
        base_name = (
            domain
            or (_safe_slug(cert_names[0]) if cert_names else "")
            or _safe_slug(site_name)
        )
        dest_path = _ensure_within(hap_dir, hap_dir / f"{base_name}.pem")
    except (ValueError, IndexError) as exc:
        tmp_path.unlink(missing_ok=True)
        return 400, {"ok": False, "error": f"unsafe certificate name: {exc}"}

    tmp_path.unlink(missing_ok=True)
    ok, reload_rc, reload_stdout, reload_stderr = _activate_server_pem(
        dest_path, pem_data
    )
    info = _load_cert_info(dest_path) if ok else None
    not_after = _fmt_date(info["not_after"]) if info else None
    days_left = info["days_left"] if info else None

    return 200, {
        "ok": ok,
        "site_name": site_name or None,
        "domain": domain or None,
        "external_ca_id": external_ca_id or None,
        "path": str(dest_path),
        "not_after": not_after,
        "days_left": days_left,
        "reload_rc": reload_rc,
        "reload_stdout": reload_stdout,
        "reload_stderr": reload_stderr,
        "message": "Certificate uploaded successfully." if ok else "HAProxy rejected the certificate; the previous PEM was restored.",
    }


def handle_certs_list() -> Tuple[int, Dict[str, Any]]:
    hap_dir = _get_haproxy_certs_dir()
    haproxy_items: List[Dict[str, Any]] = []

    if hap_dir.is_dir():
        for pem_path in sorted(hap_dir.glob("*.pem")):
            item = _build_cert_item_for_list(pem_path)
            if item:
                item["kind"] = "haproxy"
                haproxy_items.append(item)

    le_live_dir = _get_le_live_dir()
    le_items: List[Dict[str, Any]] = []

    if le_live_dir.is_dir():
        for subdir in sorted(le_live_dir.iterdir()):
            if not subdir.is_dir():
                continue
            fullchain = subdir / "fullchain.pem"
            if not fullchain.is_file():
                continue

            item = _build_cert_item_for_list(fullchain)
            if not item:
                continue

            item["kind"] = "letsencrypt"
            item["lineage"] = subdir.name
            priv = subdir / "privkey.pem"
            if priv.is_file():
                item["privkey_path"] = str(priv)
            item["fullchain_path"] = str(fullchain)
            le_items.append(item)

    return 200, {
        "ok": True,
        "haproxy": haproxy_items,
        "letsencrypt": le_items,
        "certificate_authorities": _list_certificate_authorities(),
    }


def handle_delete_haproxy(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    path_str = (body.get("path") or "").strip()
    if not path_str:
        return 200, {"ok": False, "error": "path is required"}

    base_dir = _get_haproxy_certs_dir().resolve()
    try:
        target = Path(path_str).resolve()
    except Exception:
        return 200, {"ok": False, "error": "invalid path"}

    try:
        target.relative_to(base_dir)
    except ValueError:
        return 200, {
            "ok": False,
            "error": "refusing to delete file outside haproxy_certs_dir",
        }

    if not target.exists():
        return 200, {"ok": False, "error": f"file not found: {target}"}
    if target == base_dir or not target.is_file():
        return 200, {"ok": False, "error": f"refusing to delete non-file path: {target}"}

    try:
        kept = _trash_put(
            "haproxy_cert", target.name, [target],
            actor=str(body.get("actor") or ""), details=_cert_details(target),
        )
    except (OSError, ValueError) as exc:
        return 200, {"ok": False, "error": f"cannot keep a copy in the trash, nothing deleted: {exc}"}
    before = _trash_listing([target])
    try:
        target.unlink()
    except OSError as exc:
        _trash_settle(kept, before, [target])
        return 200, {"ok": False, "error": f"failed to delete {target}: {exc}"}
    _trash_commit(kept)

    return 200, {
        "ok": True,
        "message": f"HAProxy certificate moved to the trash: {target}",
        "path": str(target),
        "trash_id": kept,
    }


def handle_delete_le(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    lineage = (body.get("lineage") or "").strip()
    if not lineage:
        return 200, {"ok": False, "error": "lineage is required"}
    try:
        lineage = _safe_slug(lineage)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}

    cmd = [
        str(CERTBOT_BIN),
        "delete",
        "--cert-name",
        lineage,
        "--config-dir",
        str(_get_letsencrypt_root_dir()),
        "--non-interactive",
    ]

    # Everything certbot is about to remove: the lineage's live links, its
    # archive of every issued copy, its renewal settings, and the DNS profile
    # binding this daemon keeps beside them.
    le_root = _get_letsencrypt_root_dir()
    pieces = [
        le_root / "live" / lineage,
        le_root / "archive" / lineage,
        le_root / "renewal" / f"{lineage}.conf",
        _dns_binding_path(lineage),
    ]
    kept = None
    if any(os.path.lexists(piece) for piece in pieces[:3]):
        try:
            kept = _trash_put(
                "letsencrypt", lineage, pieces,
                actor=str(body.get("actor") or ""),
                details=_cert_details(le_root / "live" / lineage / "cert.pem"),
            )
        except (OSError, ValueError) as exc:
            return 200, {
                "ok": False,
                "error": f"cannot keep a copy in the trash, nothing deleted: {exc}",
            }

    LOG.info("Running certbot delete: %s", " ".join(cmd))

    before = _trash_listing(pieces)
    proc = _run_bounded(cmd, timeout=CERTBOT_QUICK_TIMEOUT_SECONDS)

    rc = proc.returncode
    ok = rc == 0
    partial = ""
    if ok:
        _dns_binding_path(lineage).unlink(missing_ok=True)
        _trash_commit(kept)
    else:
        kept = _trash_settle(kept, before, pieces)
        if kept:
            partial = (
                "certbot stopped part-way through the deletion; the copy taken "
                "before it started is in the trash, and restoring it puts the "
                "whole lineage back over what certbot left"
            )

    return 200, {
        "trash_id": kept,
        **({"error": partial} if partial else {}),
        "ok": ok,
        "rc": rc,
        "cmd": " ".join(cmd),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


# ───────────────────── the trash ─────────────────────
#
# A deletion here used to be final: a certificate unlinked, a lineage handed
# to `certbot delete`, an authority's directory removed. Now everything a
# deletion is about to remove is copied aside first, and the panel's trash
# page can put it back: until the trash is emptied, or for the term the
# operator set (settings.json, keep_days).
#
# The copy is taken before the deletion. It is dropped again only if a failed
# deletion removed nothing at all, so the trash never holds something that is
# still in service, and a half-done deletion never loses the only copy.
# Owners and modes go back as they were: HAProxy, certbot and the delivery
# worker each read these files under rules of their own.
#
# A copy waits as .pending-<id> until its deletion has gone through
# (_trash_commit): nothing lists, purges or empties it meanwhile, so emptying
# the trash during a deletion cannot take the only copy.
#
# Lock order, for every path that takes more than one: CA_LOCK, then
# _STANDBY_SWITCH_LOCK, then TRASH_LOCK. Deletions hold their own lock and
# take TRASH_LOCK inside it; a restore has to take them the same way round.
#
# Never inside the crt directory: HAProxy loads every file there, and one
# that is not a certificate is a fatal configuration error. Only metadata
# ever leaves this daemon -- never a key, never a credential.

TRASH_DIR = Path(
    os.environ.get("HAPROXY_CERTD_TRASH_DIR", "/var/lib/easy-ha-proxy/cert-trash")
)
TRASH_SETTINGS = "settings.json"
TRASH_MAX_KEEP_DAYS = 3650
TRASH_PURGE_INTERVAL_SECONDS = 3600
TRASH_KINDS = (
    "haproxy_cert",
    "letsencrypt",
    "standby",
    "external_ca",
    "internal_ca",
    "dns_provider",
    "cert_delivery",
)
_TRASH_ID_RE = re.compile(r"^(?P<at>[0-9]{1,12})-[a-f0-9]{12}$")
TRASH_LOCK = threading.RLock()


def _trash_root(create: bool = False) -> Path:
    if create:
        TRASH_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(TRASH_DIR, 0o700)
    if TRASH_DIR.is_symlink():
        raise ValueError("invalid trash directory")
    return TRASH_DIR


def _copy_file_owned(source: Path, destination: Path) -> None:
    """Copy a regular file without ever exposing it under a looser mode or group."""

    info = source.stat()
    fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as dst:
            fd = -1
            with source.open("rb") as src:
                shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
            os.fchown(dst.fileno(), info.st_uid, info.st_gid)
            os.fchmod(dst.fileno(), stat.S_IMODE(info.st_mode))
    finally:
        if fd != -1:
            os.close(fd)
    os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))


def _copy_owned(source: Path, destination: Path) -> None:
    """Copy a file, a symlink or a directory tree with its owners and modes."""

    if source.is_symlink():
        os.symlink(os.readlink(source), destination)
        os.lchown(destination, source.lstat().st_uid, source.lstat().st_gid)
        return
    if source.is_dir():
        dir_infos: List[Tuple[Path, os.stat_result]] = []
        os.mkdir(destination, 0o700)
        dir_infos.append((destination, source.lstat()))
        for walk_root, dirs, files in os.walk(source):
            root_path = Path(walk_root)
            relative = root_path.relative_to(source)
            dst_root = destination / relative if str(relative) != "." else destination
            for name in dirs:
                origin = root_path / name
                target = dst_root / name
                if origin.is_symlink():
                    os.symlink(os.readlink(origin), target)
                    info = origin.lstat()
                    os.lchown(target, info.st_uid, info.st_gid)
                else:
                    os.mkdir(target, 0o700)
                    dir_infos.append((target, origin.lstat()))
            for name in files:
                origin = root_path / name
                target = dst_root / name
                if origin.is_symlink():
                    os.symlink(os.readlink(origin), target)
                    info = origin.lstat()
                    os.lchown(target, info.st_uid, info.st_gid)
                else:
                    _copy_file_owned(origin, target)
        # Apply ownership before final modes, deepest directories first.
        for target, info in reversed(dir_infos):
            os.chown(target, info.st_uid, info.st_gid)
            os.chmod(target, stat.S_IMODE(info.st_mode))
            os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))
        return
    _copy_file_owned(source, destination)


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _trash_listing(paths: Sequence[Path]) -> List[str]:
    """Every file, link and directory under these paths: what a deletion could take."""

    found: List[str] = []
    for path in paths:
        if not os.path.lexists(path):
            continue
        found.append(str(path))
        if path.is_dir() and not path.is_symlink():
            for walk_root, dirs, files in os.walk(path):
                found.extend(str(Path(walk_root) / name) for name in dirs + files)
    return sorted(found)


def _trash_fingerprints(paths: Sequence[Path]) -> List[List[Any]]:
    """Path and lstat identity of every entry left under paths."""

    found: List[List[Any]] = []
    for item in _trash_listing(paths):
        try:
            info = os.lstat(item)
        except OSError:
            continue
        found.append([item, info.st_ino, info.st_size, info.st_mtime_ns])
    return found


def _trash_settle(kept: Optional[str], before: List[str], paths: Sequence[Path]) -> Optional[str]:
    """After a failed deletion: drop the copy only if nothing at all went.

    certbot removes the renewal settings before the lineage's files, and an
    rmtree can stop half-way; a copy dropped then would have been the only
    one left.
    """

    if not kept:
        return None
    left = _trash_listing(paths)
    if left == before:
        _trash_drop(kept)
        return None
    # What the failed deletion left behind, so a restore can tell those
    # leftovers from something created since and put the whole copy back
    # over them.
    _trash_update_extra(
        kept,
        leftovers=left,
        leftover_fingerprints=_trash_fingerprints(paths),
    )
    _trash_commit(kept)
    return kept


def _rename_noreplace(source: Path, target: Path) -> None:
    """Rename source to target, failing with FileExistsError if target exists.

    os.rename replaces a file that appeared at the target in the meantime --
    a certificate issued while a restore was copying would have been
    overwritten by the old one from the trash.
    """

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    except (OSError, AttributeError):
        renameat2 = None
    if renameat2 is not None:
        at_fdcwd, rename_noreplace = -100, 1
        if renameat2(at_fdcwd, os.fsencode(str(source)), at_fdcwd, os.fsencode(str(target)), rename_noreplace) == 0:
            return
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), str(target))
        if code not in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            raise OSError(code, os.strerror(code), str(target))
    # No renameat2 (or a filesystem without it): a hard link cannot replace
    # anything; a directory is checked first, which leaves a far narrower gap.
    if source.is_dir() and not source.is_symlink():
        if os.path.lexists(target):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(target))
        os.rename(source, target)
        return
    os.link(source, target, follow_symlinks=False)
    os.unlink(source)


def trash_keep_days() -> int:
    """The operator's term in days; 0 keeps items until the trash is emptied."""

    try:
        path = _trash_root() / TRASH_SETTINGS
        if path.is_symlink():
            return 0
        value = json.loads(path.read_text(encoding="utf-8")).get("keep_days", 0)
        days = int(value)
    except (OSError, ValueError, TypeError, AttributeError):
        return 0
    return days if 0 <= days <= TRASH_MAX_KEEP_DAYS else 0


def set_trash_keep_days(value: Any) -> int:
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("keep_days must be a whole number of days") from None
    if not 0 <= days <= TRASH_MAX_KEEP_DAYS:
        raise ValueError(f"keep_days must be between 0 and {TRASH_MAX_KEEP_DAYS}")
    with TRASH_LOCK:
        root = _trash_root(create=True)
        target = root / TRASH_SETTINGS
        temporary = root / f".tmp-settings-{os.urandom(4).hex()}"
        try:
            temporary.write_text(json.dumps({"keep_days": days}) + "\n", encoding="utf-8")
            os.chmod(temporary, 0o600)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        _trash_purge_locked()
    return days


def _trash_expired(at: int, now: float, days: int) -> bool:
    return days > 0 and now - at >= days * 86400


def _trash_put(
    kind: str,
    name: str,
    paths: Sequence[Path],
    *,
    actor: str = "",
    details: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """Copy what a deletion is about to remove; the item's id.

    Written under a temporary name and renamed into place, so the trash
    never lists half an item.
    """

    if kind not in TRASH_KINDS:
        raise ValueError("unknown trash kind")
    present = [path for path in paths if os.path.lexists(path)]
    if not present:
        raise ValueError("nothing to keep in the trash")
    now = int(time.time())
    item_id = f"{now}-{os.urandom(6).hex()}"
    with TRASH_LOCK:
        root = _trash_root(create=True)
        staging = Path(tempfile.mkdtemp(prefix=".tmp-", dir=root))
        try:
            entries = []
            for index, path in enumerate(present):
                stored = str(index)
                _copy_owned(path, staging / stored)
                parent = path.parent.stat()
                entries.append({
                    "path": str(path),
                    "stored": stored,
                    "parent_mode": stat.S_IMODE(parent.st_mode),
                    "parent_uid": parent.st_uid,
                    "parent_gid": parent.st_gid,
                })
            meta = {
                "id": item_id,
                "kind": kind,
                "name": str(name),
                "deleted_at": now,
                "deleted_by": str(actor or "")[:200],
                "details": details or {},
                "extra": extra or {},
                "paths": entries,
            }
            (staging / "meta.json").write_text(
                json.dumps(meta, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
            )
            staging.replace(_trash_pending_dir(item_id))
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        _trash_purge_locked(now)
    return item_id


def _trash_pending_dir(item_id: str) -> Path:
    if not _TRASH_ID_RE.fullmatch(str(item_id or "")):
        raise ValueError("unknown trash item")
    return _trash_root() / f".pending-{item_id}"


def _trash_commit(item_id: Optional[str]) -> None:
    """The deletion went through: list the copy."""

    if not item_id:
        return
    try:
        with TRASH_LOCK:
            os.replace(_trash_pending_dir(item_id), _trash_item_dir(item_id))
    except (OSError, ValueError):
        # Still on disk; the purge lists a pending copy after an hour.
        LOG.exception("cannot list trash item %s yet", item_id)


def _trash_update_extra(item_id: str, **extra: Any) -> bool:
    try:
        with TRASH_LOCK:
            meta_path = _trash_pending_dir(item_id) / "meta.json"
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta["extra"] = dict(meta.get("extra") or {}, **extra)
            raw = (json.dumps(meta, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
            temporary = meta_path.with_name(f".meta.json.{os.urandom(4).hex()}.tmp")
            fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.replace(meta_path)
            except BaseException:
                if fd != -1:
                    os.close(fd)
                temporary.unlink(missing_ok=True)
                raise
        return True
    except (OSError, ValueError):
        LOG.warning("cannot update metadata for pending trash item %s", item_id, exc_info=True)
        return False


def _trash_drop(item_id: str) -> None:
    """Forget a pending copy whose deletion did not go through."""

    with TRASH_LOCK:
        shutil.rmtree(_trash_pending_dir(item_id), ignore_errors=True)


def _trash_item_dir(item_id: str) -> Path:
    if not _TRASH_ID_RE.fullmatch(str(item_id or "")):
        raise ValueError("unknown trash item")
    return _trash_root() / str(item_id)
