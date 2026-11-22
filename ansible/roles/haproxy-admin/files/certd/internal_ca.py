"""Domain ownership checks, Internal CA, and mTLS client certificates."""

from __future__ import annotations

import base64
import contextlib
import email.policy
import io
import json
import os
import re
import shutil
import tempfile
import threading
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .constants import (
    CA_LOCK,
    CONFIG_YAML,
    HAPROXY_CFG,
    LOG,
    MAX_REQUEST_BYTES,
    MTLS_BUNDLE_NAME,
    MTLS_EMPTY_MARKER,
    MTLS_MAX_REVOKED,
    MTLS_REVOKED_NAME,
    MTLS_TRUST_FILE,
    SHA256_HEX_RE,
    _ensure_within,
    _get_cert_dns_names,
    _get_haproxy_certs_dir,
    _get_le_live_dir,
    _load_yaml,
    _normalize_dns_name,
    _prepare_ca_root,
    _prepare_ca_subdir,
    _safe_slug,
)
from .issuance import (
    _activate_server_pem,
    _cert_matches_domain,
    _cert_not_after,
    _cert_not_before,
    _certificate_label,
    _extract_pem_blocks,
    _load_pem_certificates,
    _put_back_pems,
    _reload_haproxy,
    _validate_ca_bundle,
    _validate_server_pem,
)
from .renewals import (
    _build_internal_server_pem,
    _ca_item,
    _clear_pin,
    _deployed_stems,
    _describe_pem,
    _ensure_internal_ca,
    _ensure_internal_ca_locked,
    _generate_internal_ca_material,
    _internal_ca_paths,
    _internal_leaf_certificates,
    _mtls_dir,
    _pin_path,
    _replace_server_pem_without_reload,
    _sibling_stem,
    _standby_entries,
    _standby_key,
    _standby_path,
    _standby_slot,
    _stem_domain,
    _write_internal_ca_material,
    _write_pin,
    list_standby_certificates,
    normalise_uploaded_pem,
    read_pin,
    store_standby_certificate,
)

# Bound across sibling submodules when the package finishes loading.
APPLIED_WEBSITES: Any = None
_cert_details: Any = None
_trash_commit: Any = None
_trash_listing: Any = None
_trash_put: Any = None
_trash_settle: Any = None

def store_standby_for_covered_names(
    slot: Any, pem: Any, exclude: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """Keep one certificate as the standby for every name it covers.

    A wildcard is bought precisely so it covers a dozen hostnames; filing it
    a dozen times by hand is the sort of chore that gets done nine times.
    Which names it lands on is decided by the certificate itself, checked
    against what is actually deployed, so it cannot be filed against a name
    it could not serve.
    """

    checked_slot = _standby_slot(slot)
    raw = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem or b"")
    if not raw.strip():
        raise ValueError("no certificate was supplied")
    data = normalise_uploaded_pem(raw)
    certificates = _load_pem_certificates(data)
    if not certificates:
        raise ValueError("PEM does not contain an X.509 certificate")

    left_out = {str(name) for name in (exclude or ())}
    covered: List[str] = []
    skipped: List[str] = []
    for stem in _deployed_stems():
        if stem in left_out:
            continue
        if _cert_matches_domain(certificates[0], _stem_domain(stem)):
            covered.append(stem)
        else:
            skipped.append(stem)

    if not covered:
        raise ValueError(
            "this certificate does not cover any name deployed on this gateway"
        )

    stored: List[Dict[str, Any]] = []
    for stem in covered:
        result = store_standby_certificate(stem, checked_slot, data)
        stored.append({"domain": stem, **result.get("standby", {})})

    LOG.info(
        "Stored standby %s for %d name(s): %s",
        checked_slot, len(covered), ", ".join(covered),
    )
    return {
        "ok": True,
        "slot": checked_slot,
        "domains": covered,
        "not_covered": skipped,
        "stored": stored,
    }


def _names_claimed_by(path: Path) -> List[str]:
    try:
        return _get_cert_dns_names(_load_pem_certificates(path.read_bytes())[0])
    except Exception:  # pylint: disable=broad-except
        return []


def adopt_deployed_as_standby(domain: Any, slot: Any) -> Dict[str, Any]:
    """Move a certificate out of service and keep it as a standby.

    The obvious thing to want after putting one in the wrong place: it is
    already on the gateway, with its key, and asking the operator to go and
    find the original files again to upload them a second time is a poor
    answer.

    It is only safe when nothing depends on it. Every ordinary name the
    certificate answers for has to still be answered by some other deployed
    file once this one is gone, or removing it would take that name down --
    so that is checked first and the whole thing is refused by name if it
    does not hold. Wildcard entries are not checked: a wildcard answers for
    hostnames that have no file of their own, and those had no certificate
    before this one arrived either.
    """

    stem = _standby_key(domain)
    checked_slot = _standby_slot(slot)
    certs_dir = _get_haproxy_certs_dir()
    source = _ensure_within(certs_dir, certs_dir / f"{_safe_slug(stem)}.pem")
    if not source.is_file():
        raise ValueError(f"no certificate is deployed as {stem}")

    data = source.read_bytes()
    # Without its key it is not a standby, it is half of one.
    _validate_server_pem(data)

    others = [p for p in certs_dir.glob("*.pem") if p.resolve() != source.resolve()]
    still_served = {name.lower() for path in others for name in _names_claimed_by(path)}
    orphaned = [
        name for name in _names_claimed_by(source)
        if not name.startswith("*.") and name.lower() not in still_served
    ]
    if orphaned:
        raise ValueError(
            "this certificate is the only one serving "
            + ", ".join(sorted(orphaned))
            + "; putting it away would leave "
            + ("that name" if len(orphaned) == 1 else "those names")
            + " without one"
        )

    stored = store_standby_for_covered_names(checked_slot, data, exclude=[stem])
    source.unlink()
    rc, _stdout, stderr = _reload_haproxy()
    LOG.warning(
        "Took %s out of service and kept it as standby %s for %s",
        stem, checked_slot, ", ".join(stored["domains"]),
    )
    return {
        "ok": rc in (None, 0),
        "removed": stem,
        "slot": checked_slot,
        "domains": stored["domains"],
        "reload_rc": rc,
        "reload_error": "" if rc in (None, 0) else stderr.strip()[:400],
    }


_STANDBY_SWITCH_LOCK = threading.RLock()


def _switch_certificate_files(
    changes: Sequence[Tuple[str, Optional[bytes]]], pin: Optional[str]
) -> Tuple[bool, Optional[int], str]:
    """Commit the PEMs and their holds together, restoring both on failure.

    Install holds before putting standbys in service so deploy hooks cannot
    replace them during the switch. Release holds only after every renewing
    PEM has been accepted. Snapshots are read before the first mutation; an
    unreadable hold must never be mistaken for an absent one.
    """
    certs_dir = _get_haproxy_certs_dir()
    pems: List[Tuple[str, Path, Optional[bytes]]] = []
    pins: List[Tuple[str, Path, Optional[bytes]]] = []
    for stem, _data in changes:
        destination = _ensure_within(certs_dir, certs_dir / f"{_safe_slug(stem)}.pem")
        pems.append((stem, destination, destination.read_bytes() if destination.exists() else None))
        path = _pin_path(stem)
        pins.append((stem, path, path.read_bytes() if path.exists() else None))

    rc: Optional[int] = None
    active_stem = changes[0][0]
    try:
        if pin is not None:
            for active_stem, _data in changes:
                _write_pin(active_stem, pin)
        for (name, data), (_stem, destination, _previous) in zip(changes, pems, strict=True):
            active_stem = name
            if data is None:
                continue
            ok, rc, _stdout, stderr = _activate_server_pem(
                destination, data, override_pin=True, allow_shadow=True
            )
            if not ok:
                raise RuntimeError((stderr or "HAProxy refused it").strip()[:200])
        if pin is None:
            for active_stem, _data in changes:
                _clear_pin(active_stem)
        return True, rc, ""
    except Exception as exc:  # pylint: disable=broad-except
        error = f"{active_stem}: {str(exc)[:200]}" + _put_back_pems(pems)
        pin_errors = []
        for stem, path, previous in pins:
            try:
                current = path.read_bytes() if path.exists() else None
                if current == previous:
                    continue
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    # Do not call _write_pin: restore the exact original
                    # bytes, including holds on another standby slot.
                    with tempfile.NamedTemporaryFile(
                        mode="wb", dir=path.parent, prefix=".pin-", delete=False
                    ) as handle:
                        temporary = Path(handle.name)
                        try:
                            handle.write(previous)
                            handle.flush()
                            os.fchmod(handle.fileno(), 0o644)
                        except Exception:
                            temporary.unlink(missing_ok=True)
                            raise
                    try:
                        temporary.replace(path)
                    finally:
                        temporary.unlink(missing_ok=True)
            except OSError as pin_exc:
                pin_errors.append(f"{stem} ({pin_exc})")
        if pin_errors:
            error += "; restoring holds failed for " + ", ".join(pin_errors)
        return False, rc, error


def activate_standby_certificate(domain: Any, slot: Any) -> Dict[str, Any]:
    """Put a standby and its dual-key sibling into service as one switch."""
    checked_domain = _standby_key(domain)
    checked_slot = _standby_slot(slot)
    with _STANDBY_SWITCH_LOCK:
        stems = [checked_domain]
        sibling = _sibling_stem(checked_domain)
        if sibling and _standby_path(sibling, checked_slot).is_file():
            stems.append(sibling)
        changes: List[Tuple[str, Optional[bytes]]] = []
        descriptions = []
        for stem in stems:
            path = _standby_path(stem, checked_slot)
            if not path.is_file():
                raise ValueError(f"no standby named {checked_slot!r} for this name")
            data = path.read_bytes()
            _validate_server_pem(data, _stem_domain(stem))
            described = _describe_pem(data)
            if not described["usable"]:
                raise ValueError(
                    "that standby is not valid today "
                    f"({described['not_before']} to {described['not_after']})"
                )
            changes.append((stem, data))
            descriptions.append(described)
        ok, rc, stderr = _switch_certificate_files(changes, checked_slot)
    described = descriptions[0]
    if ok:
        LOG.warning("Standby certificate %s put into service for %s (issuer %s)",
                    checked_slot, checked_domain, described["issuer"])
    else:
        LOG.error("Standby certificate %s not put into service for %s: %s",
                  checked_slot, checked_domain, stderr)
    return {
        "ok": ok,
        "domain": checked_domain,
        "slot": checked_slot,
        "also_switched": stems[1:] if ok else [],
        "issuer": described["issuer"],
        "not_after": described["not_after"],
        "reload_rc": rc,
        "reload_error": stderr,
    }


def release_to_letsencrypt(domain: Any) -> Dict[str, Any]:
    """Restore renewing PEMs before lifting any hold on the pair."""
    stem = _standby_key(domain)
    with _STANDBY_SWITCH_LOCK:
        if not read_pin(stem):
            raise ValueError("that name is not being held on a standby")
        stems = [stem]
        sibling = _sibling_stem(stem)
        if sibling and read_pin(sibling):
            stems.append(sibling)
        changes: List[Tuple[str, Optional[bytes]]] = []
        for name in stems:
            live = _get_le_live_dir() / name
            fullchain, privkey = live / "fullchain.pem", live / "privkey.pem"
            data = None
            if fullchain.is_file() and privkey.is_file():
                data = fullchain.read_bytes() + privkey.read_bytes()
                _validate_server_pem(data, _stem_domain(name))
            changes.append((name, data))
        available = [data is not None for _name, data in changes]
        if any(available) and not all(available):
            raise ValueError("both renewing certificates must be on disk to restore this pair")
        ok, rc, stderr = _switch_certificate_files(changes, None)
    result = {
        "ok": ok,
        "domain": stem,
        "restored": ok and all(available),
        "also_released": stems[1:] if ok else [],
        "reload_rc": rc,
        "reload_error": stderr,
    }
    if ok:
        LOG.warning("Released %s back to the renewing certificate", ", ".join(stems))
        if not all(available):
            result["message"] = "released; no Let's Encrypt certificate is on disk yet"
    else:
        LOG.error("Cannot release %s back to the renewing certificate: %s", ", ".join(stems), stderr)
    return result


def delete_standby_certificate(domain: Any, slot: Any, actor: str = "") -> Dict[str, Any]:
    checked_domain = _standby_key(domain)
    checked_slot = _standby_slot(slot)
    with _STANDBY_SWITCH_LOCK:
        if read_pin(checked_domain) == checked_slot:
            raise ValueError(
                "that standby is in service; hand the name back to Let's Encrypt "
                "before removing it"
            )
        path = _standby_path(checked_domain, checked_slot)
        kept = None
        if path.is_file():
            details = _cert_details(path)
            details["slot"] = checked_slot
            kept = _trash_put(
                "standby", f"{checked_domain} ({checked_slot})", [path],
                actor=actor, details=details,
            )
        before = _trash_listing([path])
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _trash_settle(kept, before, [path])
            raise
        _trash_commit(kept)
        holder = path.parent
        if holder.is_dir() and not any(holder.iterdir()):
            holder.rmdir()
    LOG.info("Deleted standby certificate %s for %s", checked_slot, checked_domain)
    return {"ok": True, "domain": checked_domain, "slot": checked_slot}


def _standby_hint(domain: str) -> str:
    """Whether a spare is ready, appended to the expiry warning.

    A warning that only says the certificate is dying leaves the operator to
    go and find out whether anything can be done about it. If a usable spare
    is already held, the warning is the right place to say so.
    """

    try:
        usable = [
            entry for entry in _standby_entries(domain) if entry.get("usable")
        ]
    except Exception:  # pylint: disable=broad-except
        return ""
    if not usable:
        return ""
    best = max(usable, key=lambda entry: entry.get("days_left", 0))
    return (
        f". A standby is ready: {best['slot']} from {best['issuer']}, "
        f"valid until {best['not_after']}"
    )


def _write_public_file(path: Path, data: bytes) -> None:
    """Replace a world-readable file in one step, never half-written."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _client_auth_trust_path() -> Path:
    return _prepare_ca_root() / MTLS_TRUST_FILE


def _load_client_auth_ids() -> List[str]:
    path = _client_auth_trust_path()
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOG.warning("cannot read the client authentication list: %s", exc)
        return []
    ids = payload.get("ids") if isinstance(payload, dict) else None
    if not isinstance(ids, list):
        return []
    return [str(value) for value in ids if isinstance(value, str)]


def _ca_certificates(ca_id: str) -> List[x509.Certificate]:
    """Load one CA bundle by identifier, internal or imported."""
    if ca_id == "internal":
        _, path = _internal_ca_paths()
        if not path.is_file():
            raise ValueError("the internal certificate authority does not exist")
        return _load_pem_certificates(path.read_bytes())
    safe = _safe_slug(ca_id).lower()
    external_dir = _prepare_ca_subdir("external")
    path = _ensure_within(external_dir, external_dir / f"{safe}.pem")
    if not path.is_file():
        raise ValueError(f"certificate authority {safe!r} was not found")
    return _validate_ca_bundle(path.read_bytes())


def _subject_cns(certificates: List[x509.Certificate]) -> List[str]:
    """Every name that could appear as the issuer of a client certificate.

    A bundle may hold a root and the intermediate that actually signs clients,
    and only the direct issuer shows up in ssl_c_i_dn -- so all of them count.
    """
    names: List[str] = []
    for cert in certificates:
        for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            value = str(attribute.value).strip()
            if value and value not in names:
                names.append(value)
    return names


def _issuer_list_path(ca_id: str) -> Path:
    return _mtls_dir() / f"issuers-{ca_id}.list"


def _rebuild_client_auth_material(ids: List[str]) -> Dict[str, List[str]]:
    """Derive everything HAProxy reads from the CAs marked for client auth."""
    directory = _mtls_dir(create=True)

    resolved: Dict[str, List[str]] = {}
    bundle: List[bytes] = []
    seen_cns: Dict[str, str] = {}
    for ca_id in ids:
        certificates = _ca_certificates(ca_id)
        names = _subject_cns(certificates)
        if not names:
            raise ValueError(
                f"certificate authority {ca_id!r} has no Common Name, so a "
                "certificate it signed cannot be told apart from another "
                "authority's"
            )
        for name in names:
            owner = seen_cns.get(name.lower())
            if owner and owner != ca_id:
                raise ValueError(
                    f"{ca_id!r} and {owner!r} both use the Common Name "
                    f"{name!r}; a site could not tell their certificates apart"
                )
            seen_cns[name.lower()] = ca_id
        resolved[ca_id] = names
        bundle.extend(
            cert.public_bytes(serialization.Encoding.PEM) for cert in certificates
        )

    for ca_id, names in resolved.items():
        _write_public_file(
            _issuer_list_path(ca_id),
            ("".join(f"{name}\n" for name in names)).encode("utf-8"),
        )
    # A CA that is no longer trusted must stop being an answer for any site
    # that still names it. Deleting the file would do that, but it would also
    # make the live configuration reference something that no longer exists,
    # so the next reload would fail and the change would not take effect at
    # all. Emptying it has the same effect on access -- the ACL matches
    # nothing, every request to that site is denied -- and leaves a
    # configuration that still loads.
    try:
        live_config = HAPROXY_CFG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        live_config = ""
    for path in directory.glob("issuers-*.list"):
        if path.stem[len("issuers-"):] in resolved:
            continue
        if path.name in live_config:
            _write_public_file(path, MTLS_EMPTY_MARKER.encode("utf-8"))
        else:
            with contextlib.suppress(OSError):
                path.unlink()

    _write_public_file(
        directory / MTLS_BUNDLE_NAME,
        b"".join(bundle) if bundle else MTLS_EMPTY_MARKER.encode("utf-8"),
    )
    revoked_path = directory / MTLS_REVOKED_NAME
    if not revoked_path.is_file():
        _write_public_file(revoked_path, MTLS_EMPTY_MARKER.encode("utf-8"))
    return resolved


def _load_revoked_fingerprints() -> List[str]:
    path = _mtls_dir() / MTLS_REVOKED_NAME
    if not path.is_file():
        return []
    values: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        candidate = line.strip().lower()
        if candidate and not candidate.startswith("#"):
            values.append(candidate)
    return values


def handle_ca_client_auth(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Replace the set of CAs trusted to authenticate clients."""
    raw = body.get("ids")
    if not isinstance(raw, list) or len(raw) > 64:
        return 400, {"ok": False, "error": "ids must be a list of CA identifiers"}
    ids: List[str] = []
    for value in raw:
        if not isinstance(value, str):
            return 400, {"ok": False, "error": "ids must be a list of CA identifiers"}
        candidate = value.strip().lower()
        if not candidate:
            continue
        try:
            candidate = "internal" if candidate == "internal" else _safe_slug(candidate).lower()
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        if candidate not in ids:
            ids.append(candidate)

    with CA_LOCK:
        try:
            resolved = _rebuild_client_auth_material(ids)
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        except OSError as exc:
            return 500, {"ok": False, "error": f"cannot write client authentication material: {exc}"}
        path = _client_auth_trust_path()
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps({"version": 1, "ids": ids}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    rc, _out, err = _reload_haproxy()
    return 200, {
        "ok": True,
        "ids": ids,
        "issuers": resolved,
        "reload_rc": rc,
        "reload_error": "" if rc == 0 else err.strip()[:400],
        "message": (
            f"Client authentication trusts {len(ids)} certificate authorities."
            if ids
            else "No certificate authority is trusted for client authentication."
        ),
    }


def handle_ca_revoked(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Replace the list of client certificates refused by fingerprint.

    Refusing one certificate should not mean discarding the authority that
    signed it, and a small gateway is unlikely to run a CRL distribution
    point -- so revocation here is a list of fingerprints the frontend
    matches directly.
    """
    raw = body.get("fingerprints")
    if not isinstance(raw, list) or len(raw) > MTLS_MAX_REVOKED:
        return 400, {
            "ok": False,
            "error": f"fingerprints must be a list of at most {MTLS_MAX_REVOKED} entries",
        }
    values: List[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            return 400, {"ok": False, "error": "each fingerprint must be a string"}
        # Accept what the tools print: colons, spaces, upper case.
        candidate = re.sub(r"[^0-9a-fA-F]", "", entry).lower()
        if not candidate:
            continue
        if not SHA256_HEX_RE.fullmatch(candidate):
            return 400, {
                "ok": False,
                "error": f"{entry.strip()!r} is not a SHA-256 fingerprint",
            }
        if candidate not in values:
            values.append(candidate)

    with CA_LOCK:
        try:
            directory = _mtls_dir(create=True)
            _write_public_file(
                directory / MTLS_REVOKED_NAME,
                (MTLS_EMPTY_MARKER + "".join(f"{value}\n" for value in values)).encode(
                    "utf-8"
                ),
            )
        except (OSError, ValueError) as exc:
            return 500, {"ok": False, "error": f"cannot write the revocation list: {exc}"}

    # HAProxy reads a pattern file when it loads the configuration, so the new
    # list is only in force after a reload. Revocation that takes effect at
    # some unspecified later time is not revocation.
    rc, _out, err = _reload_haproxy()
    return 200, {
        "ok": True,
        "fingerprints": values,
        "reload_rc": rc,
        "reload_error": "" if rc == 0 else err.strip()[:400],
        "message": f"{len(values)} client certificates are refused.",
    }


def handle_internal_ca_ensure(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    cert, _, created = _ensure_internal_ca()
    item = _ca_item("internal", "internal", [cert])
    return 200, {
        "ok": True,
        "created": created,
        "certificate_authority": item,
        "message": "Internal certificate authority created." if created else "Internal certificate authority already exists.",
    }


def handle_standby_list(_body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, list_standby_certificates()
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot list standby certificates")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_store(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, store_standby_certificate(
            body.get("domain"), body.get("slot"), body.get("pem")
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot store the standby certificate")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_store_all(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, store_standby_for_covered_names(
            body.get("slot"), body.get("pem")
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot store the standby certificate")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_adopt(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, adopt_deployed_as_standby(
            body.get("domain"), body.get("slot")
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot take the certificate out of service")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_activate(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, activate_standby_certificate(
            body.get("domain"), body.get("slot")
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot put the standby certificate into service")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_release(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, release_to_letsencrypt(body.get("domain"))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot release the name back to Let's Encrypt")
        return 500, {"ok": False, "error": str(exc)}


def handle_standby_delete(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        return 200, delete_standby_certificate(
            body.get("domain"), body.get("slot"), str(body.get("actor") or "")
        )
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.exception("cannot delete the standby certificate")
        return 500, {"ok": False, "error": str(exc)}


def handle_internal_cert_issue(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        domain = _normalize_dns_name(str(body.get("domain") or ""))
        raw_alt_names = body.get("alt_names") or []
        if not isinstance(raw_alt_names, list) or len(raw_alt_names) > 100:
            raise ValueError("alt_names must be a list of at most 100 items")
        names = [domain]
        for value in raw_alt_names:
            normalized = _normalize_dns_name(str(value))
            if normalized not in names:
                names.append(normalized)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}

    ca_cert, ca_key, ca_created = _ensure_internal_ca()
    leaf_cert, pem = _build_internal_server_pem(ca_cert, ca_key, names)
    destination = _ensure_within(
        _get_haproxy_certs_dir(),
        _get_haproxy_certs_dir() / f"{_safe_slug(domain)}.pem",
    )
    ok, reload_rc, reload_stdout, reload_stderr = _activate_server_pem(
        destination, pem
    )
    return 200, {
        "ok": ok,
        "domain": domain,
        "alt_names": names[1:],
        "source": "internal",
        "path": str(destination),
        "not_after": _cert_not_after(leaf_cert).strftime("%Y-%m-%d"),
        "internal_ca_created": ca_created,
        "reload_rc": reload_rc,
        "reload_stdout": reload_stdout,
        "reload_stderr": reload_stderr,
        "message": "Internal certificate issued successfully." if ok else "HAProxy rejected the certificate; the previous PEM was restored.",
    }


def _internal_ca_client_trust(authority: x509.Certificate) -> Optional[Dict[str, Any]]:
    """Where HAProxy trusts the internal CA to authenticate clients, or None.

    Rotating or deleting it does not yet carry that trust along: the bundle
    and issuers files would keep the old root, and the new one would not be
    in them. Until both move together the change is refused here. The trust
    list and the bundle HAProxy reads both count -- a site that is paused or
    not yet applied does not make the root unused -- and the sites that ask
    for its client certificates are named so the operator knows what to move.
    """

    listed = "internal" in _load_client_auth_ids()
    in_bundle = False
    try:
        held = _load_pem_certificates((_mtls_dir() / MTLS_BUNDLE_NAME).read_bytes())
        fingerprint = authority.fingerprint(hashes.SHA256())
        in_bundle = any(cert.fingerprint(hashes.SHA256()) == fingerprint for cert in held)
    except (OSError, ValueError):
        pass
    if not listed and not in_bundle:
        return None
    sites: Set[str] = set()
    for path in (APPLIED_WEBSITES, CONFIG_YAML.parent / "websites.yml"):
        entries = _load_yaml(path).get("sites") if path.exists() else None
        for site in entries if isinstance(entries, list) else []:
            if (
                isinstance(site, dict)
                and str(site.get("mtls_ca_id") or "").strip().lower() == "internal"
                and str(site.get("mtls_mode") or "disabled").strip().lower() != "disabled"
            ):
                sites.add(str(site.get("name") or site.get("domain") or "?"))
    return {"trust_list": listed, "bundle": in_bundle, "sites": sorted(sites)}


def handle_internal_ca_rotate(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Replace the internal root and atomically reissue all of its active PEMs."""
    if str(body.get("confirmation") or "") != "ROTATE":
        return 400, {
            "ok": False,
            "error": "type ROTATE to confirm internal root CA rotation",
        }

    with CA_LOCK:
        key_path, cert_path = _internal_ca_paths()
        if not key_path.is_file() or not cert_path.is_file():
            return 404, {"ok": False, "error": "internal certificate authority was not found"}
        old_cert, _, _ = _ensure_internal_ca_locked()
        trust = _internal_ca_client_trust(old_cert)
        if trust is not None:
            return 409, {
                "ok": False,
                "error": (
                    "The internal CA is trusted to authenticate client certificates, "
                    "and rotating it would leave HAProxy trusting the old root. Move the "
                    "sites that ask for its client certificates to another authority or "
                    "switch their client certificates off, take it off the client "
                    "certificate trust list, then rotate."
                ),
                "client_trust": trust,
            }
        affected = _internal_leaf_certificates(old_cert)
        new_cert, new_key = _generate_internal_ca_material()
        replacement_pems = {
            path: _build_internal_server_pem(new_cert, new_key, names)[1]
            for path, names in affected
        }
        previous_pems = {path: path.read_bytes() for path, _ in affected}
        ca_root = _prepare_ca_root(create=True)
        internal_dir = key_path.parent
        staged_dir = Path(tempfile.mkdtemp(prefix=".internal-ca-new-", dir=ca_root))
        rollback_dir = ca_root / f".internal-ca-rollback-{time.time_ns()}"
        old_moved = False
        try:
            _write_internal_ca_material(staged_dir, new_cert, new_key)
            internal_dir.replace(rollback_dir)
            old_moved = True
            staged_dir.replace(internal_dir)
            for path, pem in replacement_pems.items():
                _replace_server_pem_without_reload(path, pem)
            reload_rc, reload_stdout, reload_stderr = _reload_haproxy()
            if reload_rc not in (None, 0):
                raise RuntimeError(
                    reload_stderr or reload_stdout or "HAProxy rejected the rotated certificates"
                )
        except Exception as exc:  # noqa: BLE001
            for path, pem in previous_pems.items():
                try:
                    _replace_server_pem_without_reload(path, pem)
                except Exception:  # pragma: no cover - best-effort rollback logging
                    LOG.exception("Failed to restore certificate %s", path)
            if old_moved:
                try:
                    if internal_dir.exists():
                        shutil.rmtree(internal_dir)
                    rollback_dir.replace(internal_dir)
                except Exception:  # pragma: no cover - catastrophic filesystem failure
                    LOG.exception("Failed to restore the previous internal CA")
            _reload_haproxy()
            return 500, {
                "ok": False,
                "error": f"internal CA rotation failed and was rolled back: {exc}",
            }
        finally:
            if staged_dir.exists():
                shutil.rmtree(staged_dir)

        if rollback_dir.exists():
            shutil.rmtree(rollback_dir)
        return 200, {
            "ok": True,
            "certificate_authority": _ca_item("internal", "internal", [new_cert]),
            "previous_sha256": old_cert.fingerprint(hashes.SHA256()).hex(),
            "reissued": [
                {"path": str(path), "domains": names} for path, names in affected
            ],
            "message": (
                "Internal root CA rotated and all certificates issued by the previous root "
                "were reissued. Install the new public root certificate on client devices."
            ),
        }


def handle_internal_ca_delete(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Delete an unused internal CA, refusing to orphan active certificates."""
    if str(body.get("confirmation") or "") != "DELETE":
        return 400, {
            "ok": False,
            "error": "type DELETE to confirm internal root CA deletion",
        }
    with CA_LOCK:
        key_path, cert_path = _internal_ca_paths()
        if not key_path.is_file() or not cert_path.is_file():
            return 404, {"ok": False, "error": "internal certificate authority was not found"}
        authority, _, _ = _ensure_internal_ca_locked()
        trust = _internal_ca_client_trust(authority)
        if trust is not None:
            return 409, {
                "ok": False,
                "error": (
                    "The internal CA is trusted to authenticate client certificates, "
                    "and deleting it would leave HAProxy trusting it still. Move the "
                    "sites that ask for its client certificates to another authority or "
                    "switch their client certificates off, take it off the client "
                    "certificate trust list, then delete."
                ),
                "client_trust": trust,
            }
        affected = _internal_leaf_certificates(authority)
        if affected:
            return 409, {
                "ok": False,
                "error": (
                    "internal CA cannot be deleted while HAProxy certificates signed by it exist"
                ),
                "blocking_certificates": [
                    {"path": str(path), "domains": names} for path, names in affected
                ],
            }
        try:
            kept = _trash_put(
                "internal_ca", "internal", [key_path.parent],
                actor=str(body.get("actor") or ""), details=_cert_details(cert_path),
            )
        except (OSError, ValueError) as exc:
            return 500, {"ok": False, "error": f"cannot keep a copy in the trash, nothing deleted: {exc}"}
        before = _trash_listing([key_path.parent])
        try:
            shutil.rmtree(key_path.parent)
        except OSError as exc:
            if _trash_settle(kept, before, [key_path.parent]):
                return 500, {
                    "ok": False,
                    "trash_id": kept,
                    "error": (
                        f"the internal certificate authority was only partly deleted ({exc}); "
                        "the copy taken before is in the trash"
                    ),
                }
            return 500, {"ok": False, "error": f"cannot delete the internal certificate authority: {exc}"}
        _trash_commit(kept)
    return 200, {"ok": True, "message": "Internal certificate authority moved to the trash."}


class UploadedFile:
    """One file from a multipart form: the name it was sent under and its bytes."""

    def __init__(self, filename: str, content: bytes) -> None:
        self.filename = filename
        self.file = io.BytesIO(content)


class MultipartForm:
    """The fields and files of a multipart/form-data request body.

    The cgi module that used to parse these uploads is gone from Python 3.13,
    which Debian 13 ships; the email parser reads the same format. The
    handlers ask for two things only: the first value of a field, and the
    file attached under a name.
    """

    def __init__(
        self,
        fields: Optional[Dict[str, List[str]]] = None,
        files: Optional[Dict[str, UploadedFile]] = None,
    ) -> None:
        self.fields = fields or {}
        self.files = files or {}

    @staticmethod
    def boundary(content_type: str) -> Tuple[str, Optional[str]]:
        """The media type of a Content-Type header and its boundary, if any."""
        header = email.parser.HeaderParser(policy=email.policy.HTTP).parsestr(
            f"Content-Type: {content_type}\r\n\r\n"
        )
        return header.get_content_type(), header.get_param("boundary")

    @classmethod
    def parse(cls, content_type: str, body: bytes) -> "MultipartForm":
        media_type, boundary = cls.boundary(content_type)
        if media_type != "multipart/form-data" or not boundary:
            raise ValueError("not a multipart/form-data body")
        message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode("latin-1") + body
        )
        if not message.is_multipart():
            raise ValueError("the multipart body could not be read")
        fields: Dict[str, List[str]] = {}
        files: Dict[str, UploadedFile] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            content = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is None:
                fields.setdefault(name, []).append(content.decode("utf-8", "replace"))
            elif filename and name not in files:
                # An empty filename is the browser saying no file was chosen.
                files[name] = UploadedFile(filename, content)
        return cls(fields, files)

    def getfirst(self, name: str, default: Optional[str] = None) -> Optional[str]:
        values = self.fields.get(name)
        return values[0] if values else default


def _uploaded_file(form: MultipartForm, field: str) -> Optional[UploadedFile]:
    """Return the attached file for ``field``, or None."""
    return form.files.get(field)


def handle_external_ca_upload_form(
    form: MultipartForm,
) -> Tuple[int, Dict[str, Any]]:
    file_item = _uploaded_file(form, "ca_file")
    if file_item is None:
        return 400, {"ok": False, "error": "ca_file is required"}
    raw = file_item.file.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return 413, {"ok": False, "error": "CA bundle is too large"}
    try:
        certificates = _validate_ca_bundle(raw)
        supplied_name = (form.getfirst("name", "") or "").strip()
        ca_id = _safe_slug(supplied_name or _certificate_label(certificates[0])).lower()
        if ca_id == "internal":
            raise ValueError("the CA identifier 'internal' is reserved")
        external_dir = _prepare_ca_subdir("external", create=True)
        destination = _ensure_within(external_dir, external_dir / f"{ca_id}.pem")
        canonical = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in certificates
        )
        try:
            with destination.open("xb") as handle:
                handle.write(canonical)
        except FileExistsError:
            return 409, {"ok": False, "error": f"certificate authority {ca_id!r} already exists"}
        os.chmod(destination, 0o644)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    item = _ca_item(ca_id, "external", certificates)
    item["path"] = str(destination)
    return 200, {"ok": True, "certificate_authority": item, "message": "External certificate authority imported."}


def handle_ca_export(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    _prepare_ca_root()
    ca_id = (body.get("ca_id") or "").strip()
    if ca_id == "internal":
        _, path = _internal_ca_paths()
    else:
        try:
            ca_id = _safe_slug(ca_id).lower()
            external_dir = _prepare_ca_subdir("external")
            path = _ensure_within(external_dir, external_dir / f"{ca_id}.pem")
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
    if not path.is_file():
        return 404, {"ok": False, "error": "certificate authority was not found"}
    return 200, {
        "ok": True,
        "ca_id": ca_id,
        "filename": "easy-ha-proxy-root-ca.crt" if ca_id == "internal" else f"{ca_id}.pem",
        "certificate_b64": base64.b64encode(path.read_bytes()).decode("ascii"),
    }


def handle_external_ca_delete(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        _prepare_ca_root()
        ca_id = _safe_slug(str(body.get("ca_id") or "")).lower()
        external_dir = _prepare_ca_subdir("external")
        path = _ensure_within(external_dir, external_dir / f"{ca_id}.pem")
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    with CA_LOCK:
        if not path.is_file():
            return 404, {"ok": False, "error": "certificate authority was not found"}
        trusted_before = ca_id in _load_client_auth_ids()
        try:
            details = _cert_details(path)
            kept = _trash_put(
                "external_ca", ca_id, [path],
                actor=str(body.get("actor") or ""), details=details,
                extra={"client_auth": trusted_before},
            )
        except (OSError, ValueError) as exc:
            return 500, {"ok": False, "error": f"cannot keep a copy in the trash, nothing deleted: {exc}"}
        before = _trash_listing([path])
        try:
            path.unlink()
        except OSError as exc:
            _trash_settle(kept, before, [path])
            return 500, {"ok": False, "error": f"cannot delete the certificate authority: {exc}"}
        _trash_commit(kept)
    # Leaving a deleted authority in the client-auth list would keep its names
    # in an issuers file that nothing can regenerate.
    trusted = _load_client_auth_ids()
    if ca_id in trusted:
        remaining = [value for value in trusted if value != ca_id]
        status, response = handle_ca_client_auth({"ids": remaining})
        if not response.get("ok"):
            return status, response
    return 200, {"ok": True, "message": f"External certificate authority moved to the trash: {ca_id}"}


# ───────────────────── one upload, sorted by what it turns out to be ─────
#
# An operator holding a file from their certificate authority should not have
# to know whether it is PEM, DER or PKCS#12, nor which of the two forms on
# this page it belongs in, before they can upload it. So there is one field:
# read whatever arrives, work out what each piece is, and say so before
# touching anything.
#
# The sorting rule is the certificate's own Basic Constraints. CA:TRUE is an
# authority and goes to the trust store; anything else is an end-entity
# certificate and, if its private key came along, becomes a server
# certificate. Nothing is guessed from the file name or the extension.


def _certificate_is_authority(cert: x509.Certificate) -> bool:
    try:
        return bool(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
    except x509.ExtensionNotFound:
        return False


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _load_private_key_blocks(data: bytes, secret: Optional[bytes]) -> List[Any]:
    blocks: List[bytes] = []
    for label in (
        b"PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
    ):
        blocks.extend(_extract_pem_blocks(data, label))
    keys: List[Any] = []
    for block in blocks:
        for candidate in (secret, None):
            try:
                keys.append(
                    serialization.load_pem_private_key(
                        block, password=candidate, backend=default_backend()
                    )
                )
                break
            except (TypeError, ValueError):
                continue
        else:
            raise ValueError(
                "a private key in this file is encrypted; enter its password"
            )
    return keys


def _decode_uploaded_material(
    data: bytes, password: str = ""
) -> Tuple[List[x509.Certificate], List[Any], str]:
    """Return (certificates, private keys, detected format)."""
    secret = password.encode("utf-8") if password else None

    if b"-----BEGIN" in data:
        certificates = _load_pem_certificates(data)
        keys = _load_private_key_blocks(data, secret)
        if not certificates and not keys:
            raise ValueError("this PEM file holds no certificate and no private key")
        return certificates, keys, "PEM"

    # PKCS#12 before DER: a .p12 is also a binary blob, and trying to read it
    # as a certificate produces a misleading "not a certificate" instead of
    # "the password is wrong".
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12

        key, cert, extra = pkcs12.load_key_and_certificates(
            data, secret, default_backend()
        )
    except ValueError as exc:
        message = str(exc).lower()
        if "mac" in message or "password" in message or "invalid" in message:
            pkcs12_error: Optional[str] = (
                "this looks like a PKCS#12 file and the password is missing or wrong"
                if not password
                else "the PKCS#12 password is wrong"
            )
        else:
            pkcs12_error = None
    except Exception:  # noqa: BLE001
        pkcs12_error = None
    else:
        certificates = ([cert] if cert is not None else []) + list(extra or [])
        keys = [key] if key is not None else []
        if not certificates and not keys:
            raise ValueError("this PKCS#12 file is empty")
        return certificates, keys, "PKCS#12"

    try:
        return [x509.load_der_x509_certificate(data, default_backend())], [], "DER"
    except Exception:  # noqa: BLE001
        pass
    try:
        return [], [
            serialization.load_der_private_key(
                data, password=secret, backend=default_backend()
            )
        ], "DER"
    except Exception:  # noqa: BLE001
        pass

    if pkcs12_error:
        raise ValueError(pkcs12_error)
    raise ValueError(
        "unrecognised file: expected PEM, DER or PKCS#12 (.p12/.pfx)"
    )


def _chain_for_leaf(
    leaf: x509.Certificate, authorities: List[x509.Certificate]
) -> List[x509.Certificate]:
    """Order the intermediates from the leaf upwards.

    A self-signed root is left out: HAProxy sends the file as-is, and a client
    that does not already trust the root will not start trusting it because
    the server offered a copy.
    """
    chain: List[x509.Certificate] = []
    remaining = [ca for ca in authorities if not _is_self_signed(ca)]
    current = leaf
    while True:
        issuer = next(
            (ca for ca in remaining if ca.subject == current.issuer), None
        )
        if issuer is None:
            break
        chain.append(issuer)
        remaining.remove(issuer)
        current = issuer
    return chain


def _describe_certificate(cert: x509.Certificate) -> Dict[str, Any]:
    return {
        "subject": _certificate_label(cert),
        "issuer": (
            cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            else cert.issuer.rfc4514_string()
        ),
        "not_before": _cert_not_before(cert).strftime("%Y-%m-%d"),
        "not_after": _cert_not_after(cert).strftime("%Y-%m-%d"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        # Only for an end-entity certificate. _get_cert_dns_names falls back to
        # the Common Name when there is no SAN, which for an authority means
        # reporting "Corp Root CA" as though it were a host name.
        "dns_names": (
            [] if _certificate_is_authority(cert) else sorted(_get_cert_dns_names(cert))
        ),
        "self_signed": _is_self_signed(cert),
    }
