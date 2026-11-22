"""Paused renewals, ACME HTTP-01/DNS-01 issuance, and standby certificates."""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import tempfile
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .constants import (
    CA_LOCK,
    CERTBOT_BIN,
    CERTD_DRY_RUN,
    HAPROXY_PEMS_SCRIPT,
    LOG,
    MTLS_DIR,
    PEM_REBUILD_TIMEOUT_SECONDS,
    _dns_challenge_flags,
    _ensure_within,
    _get_cert_dns_names,
    _get_certbot_settings,
    _get_haproxy_certs_dir,
    _get_letsencrypt_root_dir,
    _load_first_cert_from_pem,
    _normalize_dns_name,
    _prepare_ca_root,
    _prepare_ca_subdir,
    _run_bounded,
    _run_certbot_for_lineage,
    _safe_slug,
    report_alert,
)
from .issuance import (
    _cert_not_after,
    _cert_not_before,
    _certificate_label,
    _extract_pem_blocks,
    _load_pem_certificates,
    _public_key_bytes,
    _set_cert_permissions,
    _validate_ca_bundle,
    _validate_server_pem,
    delete_cert_delivery,
    get_cert_status_for_domain,
    list_cert_deliveries,
    save_cert_delivery,
    test_cert_delivery,
)

# Bound across sibling submodules when the package finishes loading.
_load_client_auth_ids: Any = None
_load_revoked_fingerprints: Any = None
_names_claimed_by: Any = None
_subject_cns: Any = None
get_latest_account_id: Any = None

# ---------------------------------------------------------------------------
# Paused renewals
# ---------------------------------------------------------------------------
#
# A site can be paused without being deleted -- its name pointed straight at
# its server for a while, say. Its certificate must then be left alone:
# renewing it would fail on a challenge that no longer reaches this gateway,
# and certbot would mail about the failure twice a day. certbot has its own
# switch for exactly this, "autorenew = False" in a lineage's renewalparams,
# which `certbot renew` honours. This keeps those switches in line with the
# sites the panel has paused, and touches only the lines it wrote itself: an
# autorenew an operator set by hand is theirs.

RENEWAL_PAUSE_MARKER = "# easy-ha-proxy: renewal paused from the panel"
_LINEAGE_SUFFIX_RE = re.compile(r"(?:-(?:rsa|ecdsa))?(?:-\d{4})?$")


def _lineage_domain(name: str) -> str:
    """example.com-ecdsa, example.com-0001 and example.com are all example.com."""

    return _LINEAGE_SUFFIX_RE.sub("", name, count=1).lower()


def _renewal_text_with_pause(text: str, paused: bool) -> str:
    lines = text.splitlines()
    kept: List[str] = []
    skip_next = False
    for line in lines:
        if skip_next:
            skip_next = False
            if line.strip().replace(" ", "").lower() == "autorenew=false":
                continue
        if line.strip() == RENEWAL_PAUSE_MARKER:
            skip_next = True
            continue
        kept.append(line)
    if paused:
        section = next(
            (i for i, line in enumerate(kept) if line.strip() == "[renewalparams]"),
            None,
        )
        if section is None:
            kept += ["[renewalparams]", RENEWAL_PAUSE_MARKER, "autorenew = False"]
        else:
            kept[section + 1:section + 1] = [RENEWAL_PAUSE_MARKER, "autorenew = False"]
    return "\n".join(kept) + "\n"


def sync_renewal_pauses(domains: Sequence[str]) -> Dict[str, Any]:
    paused = {_normalize_dns_name(str(domain)) for domain in domains}
    renewal_dir = _get_letsencrypt_root_dir() / "renewal"
    changed: List[str] = []
    lineages: Dict[str, bool] = {}
    if renewal_dir.is_dir():
        for conf in sorted(renewal_dir.glob("*.conf")):
            if conf.is_symlink() or not conf.is_file():
                continue
            name = conf.name[: -len(".conf")]
            want = _lineage_domain(name) in paused
            lineages[name] = want
            text = conf.read_text(encoding="utf-8")
            updated = _renewal_text_with_pause(text, want)
            if updated == text:
                continue
            info = conf.stat()
            fd, temporary = tempfile.mkstemp(dir=str(renewal_dir), prefix=".pause.")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(updated)
                os.chmod(temporary, stat.S_IMODE(info.st_mode))
                os.chown(temporary, info.st_uid, info.st_gid)
                os.replace(temporary, conf)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary)
                raise
            changed.append(name)
    if changed:
        LOG.info("renewal pauses updated for: %s", ", ".join(changed))
    return {
        "ok": True,
        "paused": sorted(name for name, want in lineages.items() if want),
        "changed": changed,
        # A paused domain with no lineage of its own -- covered by a wildcard,
        # or never issued here -- has nothing to pause, and pausing a shared
        # lineage would stop renewal for the other sites on it.
        "without_lineage": sorted(
            domain for domain in paused
            if not any(_lineage_domain(name) == domain for name in lineages)
        ),
    }


def handle_renewal_pauses(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    domains = body.get("domains")
    if not isinstance(domains, list) or len(domains) > 1000:
        return 400, {"ok": False, "error": "domains must be a list"}
    try:
        return 200, sync_renewal_pauses([str(domain) for domain in domains])
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}


def handle_deliveries_list(_body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    return 200, list_cert_deliveries()


def handle_delivery_save(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        saved = save_cert_delivery(body)
    except ValueError as exc:
        # Never echo the payload: it carries a private key.
        return 400, {"ok": False, "error": str(exc)}
    return 200, {"ok": True, "target": saved}


def handle_delivery_delete(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        removed = delete_cert_delivery(body.get("name"), str(body.get("actor") or ""))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 500, {"ok": False, "error": f"cannot delete the delivery target: {exc}"}
    return 200, {"ok": True, **removed}


def handle_delivery_test(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    try:
        outcome = test_cert_delivery(body.get("name"))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    return 200, outcome


def handle_certs_status(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    domains = body.get("domains") or []
    if not isinstance(domains, list) or len(domains) > 500:
        return 400, {"ok": False, "error": "domains must be a list of at most 500 items"}
    items: Dict[str, Any] = {}

    for d in domains:
        try:
            d_str = _normalize_dns_name(str(d))
        except ValueError:
            return 400, {"ok": False, "error": f"invalid domain: {d!r}"}
        items[d_str] = get_cert_status_for_domain(d_str)

    return 200, {"ok": True, "items": items}


def handle_certs_issue(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    domain = (body.get("domain") or "").strip()
    alt_names = body.get("alt_names") or []
    key_types = body.get("key_types") or []
    dns_profile = str(body.get("dns_profile") or "").strip().lower()
    dns_propagation = body.get("dns_propagation")
    # Wildcards are only accepted alongside a DNS profile, because only DNS-01
    # can validate them.
    allow_wildcard = bool(dns_profile)

    if not domain:
        return 200, {"ok": False, "error": "domain is required"}
    try:
        domain = _normalize_dns_name(domain, allow_wildcard=allow_wildcard)
    except ValueError as exc:
        return 400, {"ok": False, "error": f"invalid domain: {exc}"}

    if not isinstance(alt_names, list):
        alt_names = []
    try:
        alt_names = [
            _normalize_dns_name(str(x), allow_wildcard=allow_wildcard)
            for x in alt_names
            if x
        ]
    except ValueError as exc:
        return 400, {"ok": False, "error": f"invalid alternative domain: {exc}"}
    if len(alt_names) > 100:
        return 400, {"ok": False, "error": "too many alternative domains"}

    wildcard_names = [n for n in [domain, *alt_names] if n.startswith("*.")]
    if wildcard_names and not dns_profile:
        return 400, {
            "ok": False,
            "error": (
                "a wildcard certificate requires DNS-01; select a DNS provider "
                "profile for this site"
            ),
        }
    if dns_profile:
        # Resolve the profile and the plugin before issuing anything: a bad
        # profile should be a clear message, not a failed ACME attempt part way
        # through a loop over key types.
        try:
            _dns_challenge_flags(dns_profile, dns_propagation)
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}

    reserved_suffixes = (".test", ".example", ".invalid", ".localhost", ".local")
    reserved_names = [
        name
        for name in [domain, *alt_names]
        if name == "localhost" or name.endswith(reserved_suffixes)
    ]
    if reserved_names:
        return 200, {
            "ok": False,
            "domain": domain,
            "alt_names": alt_names,
            "source": "letsencrypt",
            "dry_run": CERTD_DRY_RUN,
            "error": (
                "Let's Encrypt cannot issue certificates for reserved/private domains: "
                + ", ".join(reserved_names)
                + ". Select Internal CA for this site."
            ),
        }

    if not CERTBOT_BIN.is_file():
        return 200, {
            "ok": False,
            "domain": domain,
            "alt_names": alt_names,
            "source": "letsencrypt",
            "dry_run": CERTD_DRY_RUN,
            "error": f"Certbot executable was not found: {CERTBOT_BIN}",
        }

    email, default_key_type, rsa_key_size, ecdsa_curve = _get_certbot_settings()

    if not isinstance(key_types, list) or not key_types:
        key_types = [default_key_type]

    key_types = [kt for kt in key_types if kt in ("rsa", "ecdsa")]
    if not key_types:
        key_types = [default_key_type]

    accounts_dir = (
        _get_letsencrypt_root_dir()
        / "accounts/acme-v02.api.letsencrypt.org/directory"
    )
    account_id = get_latest_account_id(accounts_dir)

    results: List[Dict[str, Any]] = []
    any_ok = False

    # The lineage becomes a directory name under /etc/letsencrypt/live and a
    # PEM file name in the HAProxy certificate directory, so a wildcard drops
    # its leftmost label — the same name Certbot would pick on its own.
    lineage_base = domain[2:] if domain.startswith("*.") else domain

    for kt in key_types:
        if len(key_types) == 1:
            lineage = lineage_base
        else:
            lineage = f"{lineage_base}-{kt}"

        res = _run_certbot_for_lineage(
            lineage=lineage,
            domain=domain,
            alt_names=alt_names,
            key_type=kt,
            email=email,
            rsa_key_size=rsa_key_size,
            ecdsa_curve=ecdsa_curve,
            account_id=account_id,
            dns_profile=dns_profile,
            dns_propagation=dns_propagation,
        )
        results.append(res)
        if res["rc"] == 0:
            any_ok = True

    pem_rc: Optional[int] = None
    pem_stdout = ""
    pem_stderr = ""

    if any_ok and HAPROXY_PEMS_SCRIPT.exists() and not CERTD_DRY_RUN:
        LOG.info("Running PEM rebuild script: %s", HAPROXY_PEMS_SCRIPT)
        proc = _run_bounded(
            [str(HAPROXY_PEMS_SCRIPT)], timeout=PEM_REBUILD_TIMEOUT_SECONDS
        )
        pem_rc = proc.returncode
        pem_stdout = proc.stdout
        pem_stderr = proc.stderr

    ok = any_ok and (pem_rc in (None, 0))

    error = ""
    if not any_ok:
        for result in results:
            error = (result.get("stderr") or result.get("stdout") or "").strip()
            if error:
                break
        if not error:
            error = "Certbot did not issue a certificate; inspect haproxy-certd logs."
    elif pem_rc not in (None, 0):
        error = (
            pem_stderr.strip()
            or pem_stdout.strip()
            or "The HAProxy PEM rebuild hook failed."
        )

    response = {
        "ok": ok,
        "domain": domain,
        "alt_names": alt_names,
        "key_types": key_types,
        "results": results,
        "dry_run": CERTD_DRY_RUN,
        "pem_rc": pem_rc,
        "pem_stdout": pem_stdout,
        "pem_stderr": pem_stderr,
    }
    if error:
        response["error"] = error
        # The browser sees this immediately, but issuance also runs before an
        # apply, where nobody is watching the certificate page.
        report_alert(
            "certificate.renewal_failed",
            domain,
            f"Certificate issuance failed for {domain}",
            error[:1000],
        )
    return 200, response


def _internal_ca_paths() -> Tuple[Path, Path]:
    internal_dir = _prepare_ca_subdir("internal")
    return internal_dir / "ca.key", internal_dir / "ca.crt"


def _ensure_internal_ca() -> Tuple[x509.Certificate, Any, bool]:
    with CA_LOCK:
        return _ensure_internal_ca_locked()


def _ensure_internal_ca_locked() -> Tuple[x509.Certificate, Any, bool]:
    _prepare_ca_root()
    key_path, cert_path = _internal_ca_paths()
    if key_path.is_file() and cert_path.is_file():
        key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None, backend=default_backend()
        )
        cert = x509.load_pem_x509_certificate(
            cert_path.read_bytes(), default_backend()
        )
        if _public_key_bytes(key.public_key()) != _public_key_bytes(
            cert.public_key()
        ):
            raise ValueError("internal CA certificate and private key do not match")
        return cert, key, False
    if key_path.exists() or cert_path.exists():
        raise ValueError("internal CA is incomplete; restore or remove its directory")

    ca_root = _prepare_ca_root(create=True)
    cert, key = _generate_internal_ca_material()
    temporary_dir = Path(tempfile.mkdtemp(prefix=".internal-ca-", dir=ca_root))
    try:
        _write_internal_ca_material(temporary_dir, cert, key)
        temporary_dir.replace(key_path.parent)
    finally:
        if temporary_dir.exists():
            shutil.rmtree(temporary_dir)
    return cert, key, True


def _generate_internal_ca_material() -> Tuple[x509.Certificate, Any]:
    """Create an in-memory root CA; callers decide when to activate it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Easy HA Proxy Local Root CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _write_internal_ca_material(
    directory: Path, cert: x509.Certificate, key: Any
) -> None:
    """Write root CA material to an already protected staging directory."""
    os.chmod(directory, 0o700)
    key_path = directory / "ca.key"
    cert_path = directory / "ca.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)


def _build_internal_server_pem(
    ca_cert: x509.Certificate, ca_key: Any, names: List[str]
) -> Tuple[x509.Certificate, bytes]:
    """Create a server certificate/key PEM signed by the supplied internal CA."""
    if not names:
        raise ValueError("at least one DNS name is required")
    domain = names[0]
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = b"".join(
        [
            leaf_cert.public_bytes(serialization.Encoding.PEM),
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ]
    )
    return leaf_cert, pem


def _certificate_is_issued_by(
    certificate: x509.Certificate, authority: x509.Certificate
) -> bool:
    """Return whether the certificate signature validates against the CA."""
    if certificate.issuer != authority.subject:
        return False
    public_key = authority.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _internal_leaf_certificates(
    authority: x509.Certificate,
) -> List[Tuple[Path, List[str]]]:
    """List active HAProxy PEMs signed by the current internal root."""
    certs_dir = _get_haproxy_certs_dir()
    if not certs_dir.is_dir():
        return []
    result: List[Tuple[Path, List[str]]] = []
    for path in sorted(certs_dir.glob("*.pem")):
        if path.is_symlink() or not path.is_file():
            continue
        _ensure_within(certs_dir, path)
        certificate = _load_first_cert_from_pem(path)
        if certificate is None or not _certificate_is_issued_by(certificate, authority):
            continue
        raw_names = _get_cert_dns_names(certificate)
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        primary = common_names[0].value.lower() if common_names else ""
        ordered = ([primary] if primary in raw_names else []) + sorted(
            name for name in raw_names if name != primary
        )
        if not ordered:
            raise ValueError(f"internal certificate has no DNS names: {path}")
        result.append((path, [_normalize_dns_name(name) for name in ordered]))
    return result


def _replace_server_pem_without_reload(destination: Path, data: bytes) -> None:
    """Atomically replace one PEM; a lifecycle transaction reloads HAProxy once."""
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=destination.parent, prefix=".cert-rotate-", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        _set_cert_permissions(temporary)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def _ca_item(ca_id: str, kind: str, certificates: List[x509.Certificate]) -> Dict[str, Any]:
    first = certificates[0]
    return {
        "id": ca_id,
        "kind": kind,
        "name": _certificate_label(first),
        "certificates": len(certificates),
        "not_before": _cert_not_before(first).strftime("%Y-%m-%d"),
        "not_after": _cert_not_after(first).strftime("%Y-%m-%d"),
        "sha256": first.fingerprint(hashes.SHA256()).hex(),
    }


def _list_certificate_authorities() -> Dict[str, Any]:
    _prepare_ca_root()
    client_auth_ids = set(_load_client_auth_ids())

    def _decorate(item: Dict[str, Any], certs: List[x509.Certificate]) -> Dict[str, Any]:
        # The names a site would match against. Shown so an operator can see
        # what "trusted for client authentication" actually turns into, and
        # so the site editor can refuse a CA that has nothing to match on.
        item["client_auth"] = item["id"] in client_auth_ids
        item["subject_cns"] = _subject_cns(certs)
        return item

    internal: Optional[Dict[str, Any]] = None
    _, internal_cert_path = _internal_ca_paths()
    if internal_cert_path.is_file():
        certs = _load_pem_certificates(internal_cert_path.read_bytes())
        if certs:
            internal = _decorate(_ca_item("internal", "internal", certs), certs)

    external: List[Dict[str, Any]] = []
    external_dir = _prepare_ca_subdir("external")
    if external_dir.is_dir():
        for path in sorted(external_dir.glob("*.pem")):
            try:
                certs = _validate_ca_bundle(path.read_bytes())
                item = _decorate(_ca_item(path.stem, "external", certs), certs)
                item["path"] = str(path)
                external.append(item)
            except (OSError, ValueError) as exc:
                LOG.warning("Skipping invalid CA bundle %s: %s", path, exc)
    return {
        "internal": internal,
        "external": external,
        "client_auth_ids": sorted(client_auth_ids),
        "revoked_client_certificates": _load_revoked_fingerprints(),
    }


# ───────────────────── client certificate authentication ─────────────────────
#
# Importing a CA does not make it a client-auth CA. A CA becomes one only when
# it is explicitly marked here, because the CA that signs this gateway's own
# server certificates has no business deciding who may connect to it.
#
# What gets written, and why the frontend needs exactly this:
#
#   clients-ca.pem       one bundle, because a bind takes one ca-file. It is
#                        also what the server advertises in CertificateRequest,
#                        so only these CA names reach a browser -- a visitor
#                        holding nothing from them is never prompted.
#   issuers-<id>.list    the subject CNs of one CA. The bundle is shared by the
#                        whole bind, so "verified" is not the same as "verified
#                        for this site"; the site matches the issuer against
#                        its own CA's names.
#   revoked.list         SHA-256 fingerprints, hex, lower case -- the exact
#                        form ssl_c_der,sha2(256),hex,lower produces.


def _mtls_dir(create: bool = False) -> Path:
    directory = MTLS_DIR
    if directory.is_symlink():
        raise ValueError("the client authentication directory must not be a symlink")
    if create:
        directory.mkdir(parents=True, mode=0o755, exist_ok=True)
    if directory.exists():
        if not directory.is_dir():
            raise ValueError("the client authentication path is not a directory")
        os.chmod(directory, 0o755)
    return directory


# Standby certificates live outside the directory HAProxy reads, and that
# separation is the entire point of it.
#
# HAProxy resolves a name to exactly one certificate per key type. Measured on
# 2.8: with two files claiming the same name it loads the first in alphabetical
# order, says nothing at all -- the configuration checks clean -- and serves
# that one. It never looks at the dates. Given an expired certificate and a
# perfectly good one side by side it serves the expired one and the site is
# down for everybody while the replacement sits unused in the same directory.
#
# So a spare cannot be left where HAProxy can see it. It waits here, and
# something has to deliberately put it in play.
CERTS_AVAILABLE_DIR = Path(
    os.environ.get("HAPROXY_CERTS_AVAILABLE_DIR", "/etc/haproxy/certs-available")
).resolve()

# Reserved for the certificate the ACME client renews on its own.
LETSENCRYPT_SLOT = "letsencrypt"


def _certs_available_root() -> Path:
    """Where standbys live. Reading must never create anything.

    Every certificate this daemon installs now passes the hold check on its
    way in, so if reading the hold created a directory then installing a
    certificate would depend on being able to create one -- and would start
    failing on any host where that was not possible, for a feature that host
    may not even use.
    """

    return CERTS_AVAILABLE_DIR


_PEM_LABELS = (
    b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY", b"CERTIFICATE",
)


def normalise_uploaded_pem(*parts: bytes) -> bytes:
    """Make one usable PEM out of whatever the operator actually had.

    A certificate authority hands over its material in whatever shape it
    likes: one file with the key first and the chain after it, one file the
    other way round, or a certificate and a key separately. The form used to
    insist on exactly two files, which meant the commonest case -- a single
    combined file -- was uploaded into both fields, arrived here as two
    copies, and was refused for containing two private keys. Being told that
    a file with one key in it has two keys is not a useful thing to be told.

    So: take every PEM block from everything given, drop exact duplicates,
    and put the certificates before the key. Order does not matter to
    HAProxy, but one shape is easier to reason about than four.
    """

    seen: set = set()
    certificates: List[bytes] = []
    keys: List[bytes] = []
    for part in parts:
        if not part:
            continue
        for label in _PEM_LABELS:
            for block in _extract_pem_blocks(part, label):
                normalised = block.strip()
                fingerprint = b"".join(normalised.split())
                if fingerprint in seen:
                    # The same file given twice, which is exactly what
                    # happens when one combined file meets two fields.
                    continue
                seen.add(fingerprint)
                if label == b"CERTIFICATE":
                    certificates.append(normalised)
                else:
                    keys.append(normalised)

    if not certificates:
        raise ValueError("no certificate was found in what was uploaded")
    if not keys:
        raise ValueError(
            "no private key was found; the certificate on its own cannot be "
            "used to serve a site"
        )
    if len(keys) > 1:
        raise ValueError(
            f"{len(keys)} different private keys were found; upload the one "
            "that belongs to this certificate"
        )
    separator = b"\n"
    return separator.join(certificates + keys) + separator


def _standby_slot(value: Any) -> str:
    """A slot name safe to use as a path component."""

    slug = _safe_slug(str(value or "").strip())
    if not slug:
        raise ValueError("the standby name must contain letters or digits")
    if len(slug) > 64:
        raise ValueError("the standby name is too long")
    return slug


def _standby_path(domain: str, slot: str) -> Path:
    """The file for one standby, checked to stay inside its own directory."""

    root = _certs_available_root()
    holder = _ensure_within(root, root / _safe_slug(domain))
    return _ensure_within(holder, holder / f"{slot}.pem")


# The marker that says a name is being held on a standby. It lives here and
# never in the crt directory: measured on HAProxy 2.8, one file there that is
# not a certificate is a fatal configuration error and the gateway will not
# start at all ("unable to load certificate ... no start line"). Only a
# leading dot is skipped, which is why this daemon's own temporary files are
# named .cert-* -- that prefix is load-bearing, not style.
PIN_FILE = ".pinned"


def _pin_path(stem: str) -> Path:
    root = _certs_available_root()
    holder = _ensure_within(root, root / _safe_slug(stem))
    return _ensure_within(holder, holder / PIN_FILE)


def _stem_domain(stem: str) -> str:
    """The name a file is really for.

    Dual-key sites are deployed as <domain>-ecdsa.pem and <domain>-rsa.pem,
    so the file stem is not a hostname and no certificate on earth covers it.
    Everything that addresses a file uses the stem; everything that checks
    what a certificate is good for uses this.
    """

    for suffix in ("-ecdsa", "-rsa"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def _standby_key(value: Any) -> str:
    """The stem of a deployed certificate file, checked and normalised.

    Not a hostname, deliberately. Dual-key sites deploy as <domain>-ecdsa.pem
    and <domain>-rsa.pem, and the stem is what every writer of that directory
    keys on, so it is what a hold and a standby are filed under. The hostname
    hiding inside it still has to be a real one.
    """

    raw = str(value or "").strip().lower()
    if not raw:
        raise ValueError("a certificate name is required")
    if len(raw) > 200:
        raise ValueError("that certificate name is too long")
    _normalize_dns_name(_stem_domain(raw))
    if _safe_slug(raw) != raw:
        raise ValueError("that certificate name cannot be used as a file name")
    return raw


def read_pin(stem: str) -> str:
    """Which standby a name is held on, or "" when it is not held."""

    try:
        path = _pin_path(stem)
    except ValueError:
        return ""
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()[:64]
    except OSError:
        return ""


def is_pinned(stem: str) -> bool:
    return bool(read_pin(stem))


def _write_pin(stem: str, slot: str) -> None:
    path = _pin_path(stem)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(f"{slot}\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _clear_pin(stem: str) -> None:
    # A failed removal is a failed switch, not a successfully released hold.
    _pin_path(stem).unlink(missing_ok=True)


def _describe_pem(data: bytes) -> Dict[str, Any]:
    """What a certificate is, in the terms the page needs to show it."""

    certificates = _load_pem_certificates(data)
    if not certificates:
        raise ValueError("PEM does not contain an X.509 certificate")
    leaf = certificates[0]
    not_after = _cert_not_after(leaf)
    not_before = _cert_not_before(leaf)
    now = datetime.now(timezone.utc)
    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type = f"EC {key.curve.name}"
    else:
        key_type = type(key).__name__
    return {
        "subject": _certificate_label(leaf),
        # Who signed it is the whole reason for keeping a second one: a
        # standby from a different authority is only useful if the operator
        # can see at a glance that it *is* from a different authority.
        "issuer": _issuer_label(leaf),
        "names": _get_cert_dns_names(leaf),
        "not_before": not_before.strftime("%Y-%m-%d"),
        "not_after": not_after.strftime("%Y-%m-%d"),
        "days_left": (not_after - now).days,
        "usable": not_before <= now < not_after,
        "key_type": key_type,
        "chain_length": len(certificates),
    }


def _issuer_label(cert: x509.Certificate) -> str:
    attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if attrs:
        return str(attrs[0].value)
    return cert.issuer.rfc4514_string()


def _standby_entries(domain: str) -> List[Dict[str, Any]]:
    """Every standby stored for one name, newest expiry first."""

    root = _certs_available_root()
    holder = root / _safe_slug(domain)
    if not holder.is_dir():
        return []
    entries: List[Dict[str, Any]] = []
    for path in sorted(holder.glob("*.pem")):
        try:
            described = _describe_pem(path.read_bytes())
        except Exception as exc:  # pylint: disable=broad-except
            # A file that cannot be read is reported, not hidden: a standby
            # nobody can see is broken is worse than no standby at all.
            entries.append({
                "slot": path.stem,
                "error": str(exc)[:200],
                "usable": False,
            })
            continue
        described["slot"] = path.stem
        entries.append(described)
    entries.sort(key=lambda item: (not item.get("usable"), item.get("slot", "")))
    return entries


def list_standby_certificates() -> Dict[str, Any]:
    """Every deployed certificate, with whatever spares are held for it."""

    certs_dir = _get_haproxy_certs_dir()
    domains: List[Dict[str, Any]] = []
    for path in sorted(certs_dir.glob("*.pem")):
        domain = path.stem
        try:
            active = _describe_pem(path.read_bytes())
        except Exception as exc:  # pylint: disable=broad-except
            active = {"error": str(exc)[:200], "usable": False}
        standbys = _standby_entries(domain)
        pinned = read_pin(domain)
        # Whether this one could be put away without leaving a name bare.
        # Offering the button on a certificate that is the only thing serving
        # its name would be offering an action that always refuses.
        claimed = _names_claimed_by(path)
        served_elsewhere = {
            name.lower()
            for other in certs_dir.glob("*.pem")
            if other.name != path.name
            for name in _names_claimed_by(other)
        }
        can_be_put_away = bool(claimed) and all(
            name.startswith("*.") or name.lower() in served_elsewhere
            for name in claimed
        )
        domains.append({
            "can_be_put_away": can_be_put_away,
            "domain": domain,
            "active": active,
            "standbys": standbys,
            "pinned": pinned,
            "renewal_paused": bool(pinned),
            # What the operator actually wants to know when the warning
            # arrives: is there something ready to put in.
            "has_usable_standby": any(
                entry.get("usable") for entry in standbys
            ),
        })
    return {"ok": True, "domains": domains}


def store_standby_certificate(
    domain: Any, slot: Any, pem: Any
) -> Dict[str, Any]:
    """Keep a certificate as a spare for one name.

    Refused rather than repaired if the key does not match the certificate or
    the certificate does not cover the name: a standby that cannot be put in
    is worse than none, because it will be discovered at the moment it is
    needed.
    """

    checked_domain = _standby_key(domain)
    checked_slot = _standby_slot(slot)
    if checked_slot == LETSENCRYPT_SLOT:
        raise ValueError(
            f"{LETSENCRYPT_SLOT!r} is reserved for the renewing certificate"
        )
    raw = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem or b"")
    if not raw.strip():
        raise ValueError("no certificate was supplied")
    if len(raw) > 1024 * 1024:
        raise ValueError("the certificate is implausibly large")

    data = normalise_uploaded_pem(raw)
    _validate_server_pem(data, _stem_domain(checked_domain))
    described = _describe_pem(data)

    path = _standby_path(checked_domain, checked_slot)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    handle = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, data)
    finally:
        os.close(handle)
    _set_cert_permissions(tmp)
    os.replace(tmp, path)
    LOG.info("Stored standby certificate %s for %s", checked_slot, checked_domain)
    described["slot"] = checked_slot
    return {"ok": True, "domain": checked_domain, "standby": described}


def _deployed_stems() -> List[str]:
    """Every name HAProxy currently has a certificate file for."""

    return sorted(path.stem for path in _get_haproxy_certs_dir().glob("*.pem"))


def _sibling_stem(stem: str) -> str:
    """The other half of a dual-key pair, or "" when there is not one.

    <domain>-ecdsa.pem and <domain>-rsa.pem are one site in two files. A
    standby put into only one of them would leave the other still claiming
    the same name -- which is the shadowing this whole feature exists to
    avoid, recreated by the act of avoiding it.
    """

    for suffix, other in (("-ecdsa", "-rsa"), ("-rsa", "-ecdsa")):
        if stem.endswith(suffix):
            return stem[: -len(suffix)] + other
    return ""
