"""Certificate chain validation, PEM activation, and post-deploy delivery."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    CERTD_DRY_RUN,
    DELIVERY_TIMEOUT_SECONDS,
    HAPROXY_BIN,
    HAPROXY_CFG,
    HAPROXY_CHECK_TIMEOUT_SECONDS,
    HAPROXY_RELOAD_TIMEOUT_SECONDS,
    LOG,
    OPENSSL_TIMEOUT_SECONDS,
    _fmt_date,
    _get_cert_dns_names,
    _get_haproxy_certs_dir,
    _get_le_live_dir,
    _load_cert_info,
    _load_first_cert_from_pem,
    _normalize_dns_name,
    _run_bounded,
    delete_dns_provider,
    list_dns_providers,
    save_dns_provider,
)

# Bound across sibling submodules when the package finishes loading.
_trash_commit: Any = None
_trash_listing: Any = None
_trash_put: Any = None
_trash_settle: Any = None
read_pin: Any = None

def _hostname_matches_pattern(host: str, pattern: str) -> bool:
    """
    host:    dsm.domain.local
    pattern: dsm.domain.local  -> True
             *.domain.local    -> True
             domain.local      -> False
    """
    host = host.lower()
    pattern = pattern.lower()

    if host == pattern:
        return True

    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".domain.local"
        # A wildcard covers exactly one label, so the host must have the same
        # number of dots as the suffix -- a.domain.local against
        # .domain.local. This read `>` and was wrong in both directions at
        # once: it refused a.domain.local, the only thing the wildcard is
        # for, and accepted a.b.domain.local, which it does not cover.
        # endswith already rules out the bare domain, so nothing else needs
        # the comparison.
        if host.endswith(suffix) and host.count(".") == suffix.count("."):
            return True

    return False


def _cert_matches_domain(cert: x509.Certificate, domain: str) -> bool:
    domain = (domain or "").strip().lower()
    if not domain:
        return False

    for name in _get_cert_dns_names(cert):
        if _hostname_matches_pattern(domain, name):
            return True
    return False


def _extract_pem_blocks(data: bytes, label: bytes) -> List[bytes]:
    """Extract complete PEM blocks with an exact label."""
    begin = b"-----BEGIN " + label + b"-----"
    end = b"-----END " + label + b"-----"
    blocks: List[bytes] = []
    offset = 0
    while True:
        start = data.find(begin, offset)
        if start < 0:
            break
        finish = data.find(end, start + len(begin))
        if finish < 0:
            raise ValueError(f"incomplete PEM block: {label.decode('ascii')}")
        finish += len(end)
        blocks.append(data[start:finish] + b"\n")
        offset = finish
    return blocks


def _load_pem_certificates(data: bytes) -> List[x509.Certificate]:
    certificates: List[x509.Certificate] = []
    for block in _extract_pem_blocks(data, b"CERTIFICATE"):
        try:
            certificates.append(
                x509.load_pem_x509_certificate(block, default_backend())
            )
        except Exception as exc:  # noqa: BLE001
            raise ValueError("invalid X.509 certificate in PEM data") from exc
    return certificates


def _load_single_private_key(data: bytes) -> Any:
    key_blocks: List[bytes] = []
    for label in (b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY"):
        key_blocks.extend(_extract_pem_blocks(data, label))
    if len(key_blocks) != 1:
        raise ValueError("PEM must contain exactly one unencrypted private key")
    try:
        return serialization.load_pem_private_key(
            key_blocks[0], password=None, backend=default_backend()
        )
    except Exception as exc:  # noqa: BLE001
        raise ValueError("private key is encrypted or invalid") from exc


def _public_key_bytes(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _validate_server_pem(
    data: bytes, domain: str = ""
) -> Tuple[List[x509.Certificate], Any]:
    certificates = _load_pem_certificates(data)
    if not certificates:
        raise ValueError("PEM does not contain an X.509 certificate")
    private_key = _load_single_private_key(data)
    if _public_key_bytes(certificates[0].public_key()) != _public_key_bytes(
        private_key.public_key()
    ):
        raise ValueError("private key does not match the first certificate")
    if isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size < 2048:
        raise ValueError("RSA private key must be at least 2048 bits")
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and private_key.key_size < 256:
        raise ValueError("EC private key must be at least 256 bits")
    if domain and not _cert_matches_domain(certificates[0], domain):
        raise ValueError(f"certificate does not cover domain {domain!r}")
    return certificates, private_key


def _cert_not_before(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _cert_not_after(cert: x509.Certificate) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _certificate_label(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.subject.rfc4514_string()


def _validate_ca_bundle(data: bytes) -> List[x509.Certificate]:
    if any(
        marker in data
        for marker in (
            b"BEGIN PRIVATE KEY",
            b"BEGIN RSA PRIVATE KEY",
            b"BEGIN EC PRIVATE KEY",
        )
    ):
        raise ValueError("CA bundle must not contain a private key")
    certificates = _load_pem_certificates(data)
    if not certificates:
        raise ValueError("CA bundle does not contain certificates")
    for cert in certificates:
        try:
            constraints = cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise ValueError("every imported certificate must be a CA certificate") from exc
        if not constraints.ca:
            raise ValueError("every imported certificate must have CA=true")
    return certificates


def _set_cert_permissions(path: Path) -> None:
    try:
        import grp
        import pwd

        os.chown(path, pwd.getpwnam("root").pw_uid, grp.getgrnam("haproxy").gr_gid)
    except Exception:  # pragma: no cover - depends on system accounts
        pass
    os.chmod(path, 0o640)


def _reload_haproxy() -> Tuple[Optional[int], str, str]:
    if CERTD_DRY_RUN:
        return None, "", ""
    if HAPROXY_BIN.is_file() and HAPROXY_CFG.is_file():
        check = _run_bounded(
            [str(HAPROXY_BIN), "-c", "-f", str(HAPROXY_CFG)],
            timeout=HAPROXY_CHECK_TIMEOUT_SECONDS,
        )
        if check.returncode != 0:
            return check.returncode, check.stdout, check.stderr
    try:
        reload_result = _run_bounded(
            ["systemctl", "reload", "haproxy"],
            timeout=HAPROXY_RELOAD_TIMEOUT_SECONDS,
        )
        return reload_result.returncode, reload_result.stdout, reload_result.stderr
    except Exception as exc:  # noqa: BLE001
        return -1, "", f"systemctl reload haproxy failed: {exc}"


class PinnedCertificate(ValueError):
    """Raised when something would overwrite a name held on a standby."""


class ShadowedCertificate(ValueError):
    """Raised when installing would put two certificates on one name."""


def _key_family(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ecdsa"
    return type(key).__name__.lower()


def _shadow_conflicts(destination: Path, data: bytes) -> List[str]:
    """Names this certificate would end up fighting another file over.

    HAProxy resolves a name to one certificate per key type, picks by
    filename order, warns about nothing and never looks at the dates. Two
    files claiming a name is therefore not a spare and not a replacement --
    it is a coin toss decided by collation, and the loser is invisible.

    Measured on a live gateway after exactly this happened: a wildcard
    imported alongside the existing per-host certificates took over every
    hostname that had no certificate of its own, while the apex kept the old
    one purely because of how the names sorted. Nothing said a word.

    Different key types for one name are the legitimate dual-key pattern and
    are not a conflict; the same key type is.
    """

    try:
        incoming = _load_pem_certificates(data)[0]
    except Exception:  # pylint: disable=broad-except
        return []
    family = _key_family(incoming)
    names = {name.lower() for name in _get_cert_dns_names(incoming)}
    if not names:
        return []

    conflicts: List[str] = []
    for other in sorted(destination.parent.glob("*.pem")):
        if other.resolve() == destination.resolve():
            continue
        try:
            existing = _load_pem_certificates(other.read_bytes())[0]
        except Exception:  # pylint: disable=broad-except
            continue
        if _key_family(existing) != family:
            continue
        shared = names & {n.lower() for n in _get_cert_dns_names(existing)}
        for name in sorted(shared):
            conflicts.append(f"{name} (already in {other.name})")
    return conflicts


def _activate_server_pem(
    destination: Path,
    data: bytes,
    *,
    override_pin: bool = False,
    allow_shadow: bool = False,
) -> Tuple[bool, Optional[int], str, str]:
    """Install a PEM atomically and roll it back when HAProxy rejects it.

    Every path in this daemon that puts a certificate in front of HAProxy
    comes through here, which is why the hold is enforced here rather than at
    each of them. A name held on a standby is held against issuing, importing,
    uploading and renewing alike; there is no fifth caller that forgot.
    """

    if not allow_shadow:
        conflicts = _shadow_conflicts(destination, data)
        if conflicts:
            raise ShadowedCertificate(
                "another certificate already covers "
                + "; ".join(conflicts[:5])
                + ". HAProxy would pick one of them by file name and ignore "
                "the other. Keep this one as a standby instead, and put it "
                "into service when you want it."
            )
    if not override_pin:
        held = read_pin(destination.stem)
        if held:
            raise PinnedCertificate(
                f"{destination.stem} is being served by the standby "
                f"{held!r}; hand it back to Let's Encrypt first"
            )
    destination.parent.mkdir(parents=True, exist_ok=True)
    previous = destination.read_bytes() if destination.exists() else None
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=destination.parent, prefix=".cert-", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        _set_cert_permissions(temporary)
        temporary.replace(destination)
        rc, stdout, stderr = _reload_haproxy()
        if rc not in (None, 0):
            if previous is None:
                destination.unlink(missing_ok=True)
            else:
                destination.write_bytes(previous)
                _set_cert_permissions(destination)
            return False, rc, stdout, stderr
        return True, rc, stdout, stderr
    finally:
        temporary.unlink(missing_ok=True)


def _put_back_pems(touched: List[Tuple[str, Path, Optional[bytes]]]) -> str:
    """Put the files of a failed switch back as they were; what to add to the error.

    Only files that differ from before are written, and HAProxy is reloaded
    once if any was. When that fails the message names what still holds the
    new certificate, so nobody takes the old state for granted.
    """

    changed = []
    for stem, destination, previous in touched:
        try:
            current = destination.read_bytes() if destination.exists() else None
        except OSError:
            current = b""  # unreadable: write it back to be sure
        if current != previous:
            changed.append((stem, destination, previous))
    if not changed:
        return "; nothing had changed"
    failed = []
    for stem, destination, previous in changed:
        try:
            if previous is None:
                destination.unlink(missing_ok=True)
            else:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=destination.parent, prefix=".cert-", delete=False
                ) as handle:
                    temporary = Path(handle.name)
                    try:
                        handle.write(previous)
                        handle.flush()
                    except Exception:
                        temporary.unlink(missing_ok=True)
                        raise
                try:
                    _set_cert_permissions(temporary)
                    temporary.replace(destination)
                finally:
                    temporary.unlink(missing_ok=True)
        except OSError as exc:
            failed.append(f"{stem} ({exc})")
    try:
        rc, _stdout, reload_error = _reload_haproxy()
    except Exception as exc:  # pylint: disable=broad-except
        rc, reload_error = -1, str(exc)
    names = ", ".join(stem for stem, _destination, _previous in changed)
    if failed:
        message = f"; putting back failed for {', '.join(failed)}: these files still hold the new certificate"
        if rc not in (None, 0):
            message += f"; HAProxy rollback reload failed: {(reload_error or '').strip()[:300]}"
        return message
    if rc not in (None, 0):
        return (f"; {names} put back as they were, but HAProxy did not reload: "
                f"{(reload_error or '').strip()[:300]}")
    return f"; {names} put back as they were"


def _verify_external_chain(
    certificates: List[x509.Certificate], ca_path: Path
) -> Tuple[bool, str]:
    openssl = shutil.which("openssl")
    if not openssl:
        return False, "openssl is required to verify an external certificate chain"
    with tempfile.TemporaryDirectory(prefix="haproxy-cert-verify-") as raw_dir:
        work_dir = Path(raw_dir)
        leaf_path = work_dir / "leaf.pem"
        chain_path = work_dir / "chain.pem"
        leaf_path.write_bytes(
            certificates[0].public_bytes(serialization.Encoding.PEM)
        )
        command = [
            openssl,
            "verify",
            "-partial_chain",
            "-CAfile",
            str(ca_path),
        ]
        if len(certificates) > 1:
            chain_path.write_bytes(
                b"".join(
                    cert.public_bytes(serialization.Encoding.PEM)
                    for cert in certificates[1:]
                )
            )
            command.extend(["-untrusted", str(chain_path)])
        command.append(str(leaf_path))
        result = _run_bounded(command, timeout=OPENSSL_TIMEOUT_SECONDS)
    details = (result.stderr or result.stdout or "certificate chain verification failed").strip()
    return result.returncode == 0, details


# ───────────────────── finding certificate files ─────────────────────


def _find_cert_file_by_domain_in_dir(base_dir: Path, domain: str) -> Optional[Path]:
    """
    Finds a matching PEM in base_dir.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return None
    if not base_dir.is_dir():
        return None

    for pem_path in sorted(base_dir.glob("*.pem")):
        cert = _load_first_cert_from_pem(pem_path)
        if not cert:
            continue
        if _cert_matches_domain(cert, domain):
            return pem_path

    return None


def _find_le_fullchain_for_domain(domain: str) -> Optional[Path]:
    """
    The domain's fullchain.pem under live:
      1) <domain>/fullchain.pem
      2) <domain>-ecdsa/fullchain.pem
      3) <domain>-rsa/fullchain.pem
      4) a fallback by content.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return None

    le_live_dir = _get_le_live_dir()

    direct_candidates = [
        le_live_dir / domain / "fullchain.pem",
        le_live_dir / f"{domain}-ecdsa" / "fullchain.pem",
        le_live_dir / f"{domain}-rsa" / "fullchain.pem",
    ]

    for p in direct_candidates:
        if p.is_file():
            return p

    try:
        for subdir in sorted(le_live_dir.iterdir()):
            if not subdir.is_dir():
                continue
            candidate = subdir / "fullchain.pem"
            if not candidate.is_file():
                continue
            cert = _load_first_cert_from_pem(candidate)
            if cert and _cert_matches_domain(cert, domain):
                return candidate
    except FileNotFoundError:
        return None

    return None


# ───────────────────── certificate state by domain ─────────────────────


def get_cert_status_for_domain(domain: str) -> Dict[str, Any]:
    """
    The state of a domain's certificate.
    """
    domain = (domain or "").strip()
    if not domain:
        return {
            "state": "no_domain",
            "short": "no domain",
            "tooltip": "Cannot check the certificate because the domain is empty.",
            "haproxy_path": None,
            "haproxy_has": False,
            "haproxy_not_after": None,
            "haproxy_days_left": None,
            "le_path": None,
            "le_has": False,
            "le_not_after": None,
            "le_days_left": None,
        }

    hap_dir = _get_haproxy_certs_dir()
    hap_candidate = _find_cert_file_by_domain_in_dir(hap_dir, domain)
    le_candidate = _find_le_fullchain_for_domain(domain)

    hap_info = _load_cert_info(hap_candidate) if hap_candidate else None
    le_info = _load_cert_info(le_candidate) if le_candidate else None

    has_hap = hap_info is not None
    has_le = le_info is not None

    result: Dict[str, Any] = {
        "state": "",
        "short": "",
        "tooltip": "",
        "haproxy_path": str(hap_candidate) if hap_candidate else None,
        "haproxy_has": has_hap,
        "haproxy_not_after": _fmt_date(hap_info["not_after"]) if has_hap else None,
        "haproxy_days_left": hap_info["days_left"] if has_hap else None,
        "le_path": str(le_candidate) if le_candidate else None,
        "le_has": has_le,
        "le_not_after": _fmt_date(le_info["not_after"]) if has_le else None,
        "le_days_left": le_info["days_left"] if has_le else None,
    }

    # there is nothing
    if not has_hap and not has_le:
        result["state"] = "missing"
        result["short"] = "No certificate"
        result["tooltip"] = (
            "No HAProxy certificate and no Let's Encrypt certificate "
            "were found for this domain."
        )
        return result

    # there is LE, but no HAProxy file
    if has_le and not has_hap:
        result["state"] = "letsencrypt_only"
        if le_info["days_left"] < 0:
            result["short"] = "LE: expired"
        else:
            result["short"] = f"LE until {result['le_not_after']}"
        result["tooltip"] = (
            "A Let's Encrypt certificate exists, but the matching HAProxy PEM "
            "is missing. The deploy hook may not have completed."
        )
        return result

    # there is a HAProxy file, but no LE
    if has_hap and not has_le:
        days = hap_info["days_left"]
        if days < 0:
            state = "expired"
            short = "Expired"
        elif days <= hap_info["warn_days"]:
            state = "warning"
            short = f"Expires soon ({days} days)"
        else:
            state = "haproxy_only"
            short = f"OK until {result['haproxy_not_after']}"

        result["state"] = state
        result["short"] = short
        result["tooltip"] = (
            "An HAProxy certificate exists without a Let's Encrypt lineage. "
            "It may come from an external or internal certificate authority."
        )
        return result

    # there are both: take the earlier expiry
    days_left = min(hap_info["days_left"], le_info["days_left"])
    result["haproxy_days_left"] = hap_info["days_left"]
    result["le_days_left"] = le_info["days_left"]
    warn_days = min(hap_info["warn_days"], le_info["warn_days"])

    if days_left < 0:
        result["state"] = "expired"
        result["short"] = "Expired"
        result["tooltip"] = "The certificate has expired and must be renewed."
    elif days_left <= warn_days:
        result["state"] = "warning"
        result["short"] = f"Expires soon ({days_left} days)"
        result["tooltip"] = (
            "The certificate is approaching expiration. "
            f"Days remaining: {days_left}."
        )
    else:
        result["state"] = "ok"
        result["short"] = f"OK until {result['haproxy_not_after']}"
        result["tooltip"] = "The certificate is valid."

    return result


# ───────────────────── helper for the list ─────────────────────


def _build_cert_item_for_list(path: Path) -> Optional[Dict[str, Any]]:
    """
    The UI's structure for one PEM file.
    """
    cert = _load_first_cert_from_pem(path)
    if not cert:
        return None

    info = _load_cert_info(path)
    if not info:
        return None

    not_after_dt = info["not_after"]
    days_left = info["days_left"]
    not_after_str = _fmt_date(not_after_dt)

    if days_left is None:
        state = "unknown"
        short = "expiration date unavailable"
    elif days_left < 0:
        state = "expired"
        short = "Expired"
    elif days_left <= info["warn_days"]:
        state = "warning"
        short = f"Expires soon ({days_left} days)"
    else:
        state = "ok"
        short = f"OK until {not_after_str}"

    domains = _get_cert_dns_names(cert)

    return {
        "path": str(path),
        "not_after": not_after_str,
        "days_left": days_left,
        "state": state,
        "short": short,
        "domains": domains,
    }


# ───────────────────── the endpoints ─────────────────────


def handle_dns_providers_list(_body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    payload = list_dns_providers()
    payload["ok"] = True
    return 200, payload


def handle_dns_provider_save(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        saved = save_dns_provider(body)
    except ValueError as exc:
        # Never echo the payload back: it carries the credentials that were
        # just rejected.
        return 400, {"ok": False, "error": str(exc)}
    return 200, {"ok": True, **saved}


def handle_dns_provider_delete(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        removed = delete_dns_provider(body.get("name"), str(body.get("actor") or ""))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot delete the DNS profile: {exc}"}
    return 200, {"ok": True, **removed}


# ───────────────── certificate delivery targets ─────────────────
#
# Machines other than this gateway that hold the same certificate: a Remote
# Desktop Gateway wanting a PKCS#12, a web server wanting the PEM pair. The
# records live in a directory and the work is done by
# easy-ha-proxy-cert-deliver, which certbot's 906 hook also calls; certd only
# edits the records and can run one on demand so the operator can see it work
# before a renewal depends on it.
#
# Same storage shape as an off-host backup destination, and for the same
# reasons: one JSON per target, the private key and the pinned host key
# beside it, the whole directory root-only.

DELIVERY_DIR = Path(
    os.environ.get("CERT_DESTINATIONS_DIR", "/etc/easy-ha-proxy/cert-destinations")
)
DELIVERY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DELIVERY_FORMATS = ("pfx", "pem-pair", "pem-combined")
DELIVERY_TRANSPORTS = ("sftp", "scp")
DELIVERY_WORKER = "/usr/local/sbin/easy-ha-proxy-cert-deliver"
MAX_DELIVERY_TARGETS = 50


def _delivery_paths(name: str) -> Tuple[Path, Path, Path]:
    return (
        DELIVERY_DIR / f"{name}.json",
        DELIVERY_DIR / f"{name}.key",
        DELIVERY_DIR / f"{name}.known_hosts",
    )


def _delivery_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not DELIVERY_NAME_RE.fullmatch(text):
        raise ValueError(
            "name must be 1-40 characters of a-z, 0-9 and -, "
            "starting with a letter or digit"
        )
    return text


def _delivery_public(record: Dict[str, Any], name: str) -> Dict[str, Any]:
    """What the page is allowed to see. No key material, ever."""

    _, key, known = _delivery_paths(name)
    return {
        "name": name,
        "enabled": bool(record.get("enabled", True)),
        "domains": list(record.get("domains") or []),
        "transport": record.get("transport", "sftp"),
        "host": record.get("host", ""),
        "port": record.get("port", 22),
        "user": record.get("user", ""),
        "remote_path": record.get("remote_path", ""),
        "format": record.get("format", "pfx"),
        "post_command": record.get("post_command", ""),
        # Whether a password is set, never what it is.
        "pfx_password_set": bool(record.get("pfx_password")),
        "key_present": key.is_file(),
        "host_key_present": known.is_file(),
        "last_result": record.get("last_result", {}),
    }


def list_cert_deliveries() -> Dict[str, Any]:
    items = []
    if DELIVERY_DIR.is_dir():
        for path in sorted(DELIVERY_DIR.glob("*.json")):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    record = json.load(handle)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cannot read %s (%s)", path, exc)
                continue
            items.append(_delivery_public(record, path.stem))
    return {
        "ok": True,
        "targets": items,
        "formats": list(DELIVERY_FORMATS),
        "transports": list(DELIVERY_TRANSPORTS),
        "legacy_hooks": _unmanaged_delivery_hooks(),
    }


def _unmanaged_delivery_hooks() -> List[str]:
    """Hand-written hooks that also deliver certificates.

    A gateway upgraded from before this page has one, and it keeps working.
    Saying so is better than leaving the operator to wonder why a target
    they never configured is receiving files -- or, worse, deleting the
    hook that is doing the actual work.
    """

    found: List[str] = []
    hooks = Path("/etc/letsencrypt/renewal-hooks/deploy")
    if not hooks.is_dir():
        return found
    for path in sorted(hooks.glob("*.sh")):
        if path.name in ("905-haproxy-pems-reload.sh",
                         "906-deliver-certificates.sh",
                         "910-mail-notify.sh"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "sftp" in text or "scp " in text or "pkcs12" in text:
            found.append(path.name)
    return found


def save_cert_delivery(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = _delivery_name(payload.get("name"))
    record_path, key_file, known_file = _delivery_paths(name)

    DELIVERY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DELIVERY_DIR, 0o700)

    existing: Dict[str, Any] = {}
    if record_path.is_file():
        with record_path.open("r", encoding="utf-8") as handle:
            existing = json.load(handle)
    elif len(list(DELIVERY_DIR.glob("*.json"))) >= MAX_DELIVERY_TARGETS:
        raise ValueError(f"at most {MAX_DELIVERY_TARGETS} delivery targets")

    domains = [
        _normalize_dns_name(str(d)) for d in (payload.get("domains") or [])
        if str(d).strip()
    ]
    if not domains:
        raise ValueError("choose at least one certificate to deliver")
    if len(domains) > 1 and _resolve_lineage(domains[0]) is not None             and _lineage_covering(domains) is None:
        # Two certificates at one remote path: each renewal would overwrite
        # the other. Not yet issued means it cannot be judged, so it is kept.
        raise ValueError(
            "no one certificate covers all of " + ", ".join(domains)
            + "; a target receives one certificate, so give each certificate a target of its own"
        )

    transport = str(payload.get("transport") or "sftp").strip().lower()
    if transport not in DELIVERY_TRANSPORTS:
        raise ValueError("transport must be sftp or scp")

    fmt = str(payload.get("format") or "pfx").strip().lower()
    if fmt not in DELIVERY_FORMATS:
        raise ValueError("format must be pfx, pem-pair or pem-combined")

    host = str(payload.get("host") or "").strip()
    user = str(payload.get("user") or "").strip()
    remote_path = str(payload.get("remote_path") or "").strip()
    if not host or not user or not remote_path:
        raise ValueError("host, user and remote path are all required")
    if len(host) > 253 or host.startswith("-"):
        raise ValueError("host must be a valid hostname or IP address")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise ValueError("host must be a valid hostname or IP address") from None
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._@\\-]{0,127}", user):
        raise ValueError("user contains unsupported characters")
    if (
        len(remote_path) > 512
        or re.search(r"[\x00-\x1f\x7f]", remote_path)
        or ".." in re.split(r"[/\\]", remote_path)
    ):
        raise ValueError("remote_path is invalid")

    try:
        port = int(payload.get("port") or 22)
    except (TypeError, ValueError):
        raise ValueError("port must be a number") from None
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    post_command = str(payload.get("post_command") or "").strip()
    if len(post_command) > 2048 or "\x00" in post_command:
        raise ValueError("post_command is invalid")
    pfx_password = (
        str(payload.get("pfx_password"))
        if payload.get("pfx_password") is not None
        else existing.get("pfx_password", "")
    )
    if len(pfx_password) > 1024 or "\x00" in pfx_password:
        raise ValueError("pfx_password is invalid")

    record = {
        "enabled": bool(payload.get("enabled", True)),
        "domains": domains,
        "transport": transport,
        "host": host,
        "port": port,
        "user": user,
        "remote_path": remote_path,
        "format": fmt,
        "post_command": post_command,
        # Left as it was unless a new one is sent, so editing a target does
        # not silently clear its password.
        "pfx_password": pfx_password,
        "last_result": existing.get("last_result", {}),
    }

    material = payload.get("private_key")
    if material:
        _write_delivery_secret(key_file, str(material).strip() + chr(10))
    host_key = payload.get("host_key")
    if host_key:
        _write_delivery_secret(known_file, str(host_key).strip() + chr(10))

    tmp = record_path.with_suffix(".json.tmp")
    raw_record = json.dumps(record, indent=2, ensure_ascii=False).encode("utf-8")
    handle = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "wb") as stream:
            handle = -1
            stream.write(raw_record)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if handle != -1:
            os.close(handle)
    tmp.replace(record_path)
    return _delivery_public(record, name)


def _write_delivery_secret(path: Path, text: str) -> None:
    """Mode set before the content lands, not after."""

    tmp = path.with_suffix(path.suffix + ".tmp")
    handle = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "wb") as stream:
            handle = -1
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if handle != -1:
            os.close(handle)
    os.replace(tmp, path)


def delete_cert_delivery(name: Any, actor: str = "") -> Dict[str, Any]:
    checked = _delivery_name(name)
    paths = _delivery_paths(checked)
    kept = None
    if any(path.exists() for path in paths):
        details: Dict[str, Any] = {}
        with contextlib.suppress(OSError, ValueError, AttributeError):
            record = json.loads(paths[0].read_text(encoding="utf-8"))
            details = {
                key: record.get(key)
                for key in ("lineage", "host", "format", "transport")
                if isinstance(record.get(key), (str, int))
            }
        kept = _trash_put("cert_delivery", checked, list(paths), actor=actor, details=details)
    before = _trash_listing(paths)
    try:
        for path in paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    except OSError:
        # A half-removed target keeps its copy.
        _trash_settle(kept, before, paths)
        raise
    _trash_commit(kept)
    return {"name": checked, "deleted": True, "trash_id": kept}


def test_cert_delivery(name: Any) -> Dict[str, Any]:
    """Deliver right now, so a target can be proven before a renewal needs it."""

    checked = _delivery_name(name)
    record_path, _, _ = _delivery_paths(checked)
    if not record_path.is_file():
        raise ValueError(f"no delivery target named {checked}")
    with record_path.open("r", encoding="utf-8") as handle:
        record = json.load(handle)

    domains = list(record.get("domains") or [])
    if not domains:
        raise ValueError("this target has no certificate chosen")

    lineage = _lineage_covering(domains)
    if lineage is None:
        if _resolve_lineage(domains[0]) is None:
            raise ValueError(
                f"there is no issued certificate for {domains[0]} to send yet"
            )
        raise ValueError(
            "no one certificate covers all of " + ", ".join(domains)
            + "; a target receives one certificate, so give each certificate a target of its own"
        )

    # The worker copies over SSH: a hung ssh under it is stopped with it.
    # --target: this record alone, never every target sharing a name with it.
    result = _run_bounded(
        [
            DELIVERY_WORKER,
            "--lineage", str(lineage),
            "--target", checked,
        ],
        timeout=DELIVERY_TIMEOUT_SECONDS,
        text=False,
    )
    output = (result.stdout + result.stderr).decode("utf-8", "replace").strip()
    outcome = {
        "ok": result.returncode == 0,
        "output": output[-4000:],
        "lineage": lineage.name,
    }
    record["last_result"] = {
        "ok": outcome["ok"],
        "at": int(time.time()),
        "detail": output[-400:],
    }
    tmp = record_path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    tmp.replace(record_path)
    return outcome


def _resolve_lineage(domain: str) -> Optional[Path]:
    """Find the live directory holding a domain's certificate.

    During a renewal certbot hands the hook RENEWED_LINEAGE and there is
    nothing to work out. Sending on demand has to find it, and the directory
    is not simply the domain: this installation issues separate ECDSA and RSA
    lineages, so a site is example.com-ecdsa and example.com-rsa, and certbot
    itself appends -0001 when a name is reused.

    Tried in order, then a scan of every lineage for one whose certificate
    actually covers the name. Where a domain has both key types this picks
    one rather than sending twice to the same remote path, where the second
    would only overwrite the first. A real renewal still fires the hook once
    per lineage, as certbot decides; that is unchanged.
    """

    live = _get_le_live_dir()
    if not live.is_dir():
        return None

    for candidate in (domain, f"{domain}-ecdsa", f"{domain}-rsa"):
        path = live / candidate
        if (path / "fullchain.pem").is_file():
            return path

    for path in sorted(live.iterdir()):
        chain = path / "fullchain.pem"
        if not chain.is_file():
            continue
        cert = _load_first_cert_from_pem(chain)
        if cert is not None and _cert_matches_domain(cert, domain):
            return path
    return None


def _lineage_covering(domains: List[str]) -> Optional[Path]:
    """The lineage whose certificate covers every one of the names.

    The one _resolve_lineage picks for the first name is tried first, so a
    single-name target is sent what it always was.
    """

    first = _resolve_lineage(domains[0])
    candidates = [first] if first is not None else []
    live = _get_le_live_dir()
    if live.is_dir():
        candidates += [path for path in sorted(live.iterdir()) if path != first]
    for path in candidates:
        cert = _load_first_cert_from_pem(path / "fullchain.pem")
        if cert is not None and all(_cert_matches_domain(cert, d) for d in domains):
            return path
    return None
