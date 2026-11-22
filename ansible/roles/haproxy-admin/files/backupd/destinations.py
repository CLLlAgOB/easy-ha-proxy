"""Off-host SFTP/SSH and S3-compatible backup destinations."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import ipaddress
import os
import re
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from .constants import (
    ARCHIVE_SUFFIX,
    BackupdError,
    DESTINATION_UPLOAD_LOCKS,
    DESTINATION_UPLOAD_LOCKS_GUARD,
    LOG,
    atomic_json,
    identifier,
    report_alert,
    safe_json_file,
    utc_now,
)
from .jobs import (
    backup_archive_path,
    backup_checksum_path,
    backup_meta_path,
    private_file,
    read_checksum_file,
    sha256_file,
)

# ---------------------------------------------------------------------------
# Off-host copies
# ---------------------------------------------------------------------------
#
# The disaster-recovery archive is useless on the machine it protects. This
# sends the already-encrypted archive somewhere else and nothing more: no
# plaintext ever leaves, and the passphrase is not involved in the transfer at
# all -- the file is encrypted long before it gets here.
#
# Only SFTP is implemented. It uses the OpenSSH client that is already on the
# host, which means the host key handling, the ciphers and the key formats are
# somebody else's well-tested problem rather than ours.

DESTINATIONS_DIR = Path(
    os.environ.get(
        "BACKUPD_DESTINATIONS_DIR", "/etc/easy-ha-proxy/backup-destinations"
    )
)
DESTINATION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DESTINATION_TYPES = ("sftp", "s3")
SFTP_TIMEOUT_SECONDS = int(os.environ.get("BACKUPD_SFTP_TIMEOUT", "900"))
SCHEDULED_BACKUP_TIMEOUT = int(
    os.environ.get("BACKUPD_SCHEDULED_TIMEOUT", str(6 * 3600))
)
# Re-downloading to verify is exact but costs the transfer twice. Above this
# the daemon asks the far end to hash instead, and says which it used.
VERIFY_DOWNLOAD_MAX_BYTES = int(
    os.environ.get("BACKUPD_VERIFY_DOWNLOAD_MAX", str(2 * 1024 * 1024 * 1024))
)


def keep_count(value: Any, *, default: int, cap: int) -> int:
    """A retention count, where zero means zero rather than "unset"."""
    if value is None or value == "":
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise BackupdError("a retention count must be a number", code="invalid") from None
    return max(0, min(cap, number))


def destination_path(name: Any) -> Path:
    text = str(name or "").strip().lower()
    if not DESTINATION_NAME_RE.fullmatch(text):
        raise BackupdError(
            "the destination name may use a-z, 0-9 and dashes", code="invalid"
        )
    return DESTINATIONS_DIR / (text + ".json")


def destination_key_path(name: str) -> Path:
    return DESTINATIONS_DIR / (str(name).strip().lower() + ".key")


def destination_known_hosts(name: str) -> Path:
    return DESTINATIONS_DIR / (str(name).strip().lower() + ".known_hosts")


def destination_password_path(name: str) -> Path:
    return DESTINATIONS_DIR / (str(name).strip().lower() + ".password")


# How the gateway signs in to an SFTP destination.
DESTINATION_AUTH = ("key", "password")
SSH_KEYSCAN = "/usr/bin/ssh-keyscan"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
KEYSCAN_TIMEOUT_SECONDS = 15

# OpenSSH reads a password only from a terminal or from an askpass program,
# and an unattended backup has no terminal. This program prints the password
# file it is pointed at; the password itself stays in a root-only file and
# never reaches an argument list or the environment.
def askpass_path() -> Path:
    return DESTINATIONS_DIR / ".askpass"


ASKPASS_SCRIPT = b'#!/bin/sh\nexec cat -- "$EASY_HA_PROXY_SFTP_PASSWORD_FILE"\n'

# What OpenSSH prints when the far end is not the one that was pinned.
HOST_KEY_FAILURES = (
    "REMOTE HOST IDENTIFICATION HAS CHANGED",
    "Host key verification failed",
    "host key for",
    "No matching host key",
)


def destination_auth(record: dict[str, Any]) -> str:
    value = str(record.get("auth") or "key")
    return value if value in DESTINATION_AUTH else "key"


def scan_host_key(host: str, port: int) -> bytes:
    """Ask the far end for its host keys, as known_hosts lines.

    This is trust on first use: whatever answers now is what will be
    accepted from then on, and the fingerprints are shown so they can be
    compared with what the server itself reports. After that a different
    key stops every transfer until someone decides to trust it.
    """
    try:
        result = subprocess.run(
            [SSH_KEYSCAN, "-T", "10", "-p", str(port), "-t",
             "ed25519,ecdsa,rsa", "--", host],
            capture_output=True,
            timeout=KEYSCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupdError(f"cannot read the host key: {exc}", code="upstream") from exc
    lines = [
        line for line in (result.stdout or b"").decode("utf-8", "replace").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not lines:
        detail = (result.stderr or b"").decode("utf-8", "replace").strip()[:300]
        raise BackupdError(
            "the far end did not offer a host key"
            + (f": {detail}" if detail else ""),
            code="upstream",
        )
    return ("\n".join(sorted(lines)) + "\n").encode("utf-8")


def host_key_fingerprints(known_hosts: bytes) -> list[str]:
    """SHA256 fingerprints, the form `ssh-keygen -lf` and servers print."""
    with tempfile.NamedTemporaryFile(prefix="backupd-hostkey-") as handle:
        handle.write(known_hosts)
        handle.flush()
        try:
            result = subprocess.run(
                [SSH_KEYGEN, "-l", "-E", "sha256", "-f", handle.name],
                capture_output=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
    prints = []
    for line in (result.stdout or b"").decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("SHA256:"):
            kind = fields[-1].strip("()") if fields[-1].startswith("(") else ""
            prints.append(f"{kind} {fields[1]}".strip())
    return prints


def pin_host_key(name: str, known_hosts: bytes) -> list[str]:
    write_private(destination_known_hosts(name), known_hosts)
    return host_key_fingerprints(known_hosts)


def pinned_fingerprints(record: dict[str, Any]) -> list[str]:
    """Fingerprints of the pinned key, worked out for profiles saved before
    they were recorded, so every SFTP destination can show what it trusts."""
    stored = list(record.get("host_key_fingerprints") or [])
    if stored or record.get("type") != "sftp" or not record.get("name"):
        return stored
    try:
        return host_key_fingerprints(destination_known_hosts(record["name"]).read_bytes())
    except OSError:
        return []


def host_key_problem(stderr: bytes) -> bool:
    text = (stderr or b"").decode("utf-8", "replace")
    return any(marker.lower() in text.lower() for marker in HOST_KEY_FAILURES)


def note_host_key_change(record: dict[str, Any]) -> str:
    """Remember that the far end presented a different key, and say so.

    Nothing is trusted here: the transfer has already been refused. The new
    key's fingerprints are recorded so the page can show what would be
    trusted, and the operator decides.
    """
    offered: list[str] = []
    with contextlib.suppress(BackupdError):
        offered = host_key_fingerprints(
            scan_host_key(record["host"], int(record.get("port") or 22))
        )
    with contextlib.suppress(Exception):
        stored = load_destination(record["name"])
        stored["host_key_changed"] = {"at": utc_now(), "offered": offered}
        atomic_json(destination_path(record["name"]), stored, mode=0o600)
    return (
        "the far end presented a different host key than the one pinned, so "
        "nothing was sent. If the server was reinstalled or its key replaced "
        "on purpose, trust the new key on the backups page"
        + (f" (offered: {', '.join(offered)})" if offered else "")
        + "."
    )


def normalize_private_key(material: str) -> bytes:
    """Make a pasted key into a file OpenSSH will actually open.

    Two things a textarea gets wrong and OpenSSH will not forgive.

    The terminating newline: OpenSSH's own parser wants one after the
    footer, and without it falls back to the PEM reader, which reports
    `error in libcrypto` -- a message that describes a corrupt key and says
    nothing about the byte that is missing. The browser sends a trimmed
    field, so the newline is never there and no SFTP destination could ever
    authenticate. One production key was rejected for exactly this while
    being, in every other respect, perfectly valid.

    And CRLF: a key copied out of a Windows terminal carries carriage
    returns into the base64, which is the same failure wearing a different
    hat.
    """
    text = material.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    return (text + "\n").encode("utf-8")


def write_private(path: Path, content: bytes) -> None:
    """Replace a root-only file. private_file refuses to overwrite by design."""
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    private_file(path, content)


def ensure_destinations_dir() -> None:
    DESTINATIONS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DESTINATIONS_DIR, 0o700)


def load_destination(name: Any) -> dict[str, Any]:
    path = destination_path(name)
    try:
        record = safe_json_file(path)
    except BackupdError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise BackupdError(f"cannot read the destination: {exc}", code="invalid") from exc
    if not record:
        raise BackupdError("no such destination", code="not_found")
    return record


def public_destination(record: dict[str, Any]) -> dict[str, Any]:
    """What the browser may see. Never the key, never a fingerprint secret."""
    return {
        "name": record.get("name", ""),
        "type": record.get("type", ""),
        "host": record.get("host", ""),
        "port": record.get("port", 22),
        "user": record.get("user", ""),
        "path": record.get("path", ""),
        "has_key": bool(record.get("key_installed")),
        "auth": destination_auth(record),
        "has_password": bool(record.get("password_installed")),
        "host_key_pinned": bool(record.get("host_key_pinned")),
        "host_key_fingerprints": pinned_fingerprints(record),
        "host_key_source": record.get("host_key_source", ""),
        "host_key_changed": record.get("host_key_changed") or None,
        "verify": verify_mode(record.get("verify")),
        "endpoint": record.get("endpoint", ""),
        "region": record.get("region", ""),
        "bucket": record.get("bucket", ""),
        "prefix": record.get("prefix", ""),
        "access_key": record.get("access_key", ""),
        "has_secret": bool(record.get("secret_installed")),
        "allow_insecure": bool(record.get("allow_insecure")),
        "keep_daily": record.get("keep_daily", 7),
        "keep_weekly": record.get("keep_weekly", 4),
        "keep_monthly": record.get("keep_monthly", 6),
        "updated_at": record.get("updated_at", ""),
    }


def list_destinations(_request: dict[str, Any]) -> dict[str, Any]:
    ensure_destinations_dir()
    items = []
    for path in sorted(DESTINATIONS_DIR.glob("*.json")):
        with contextlib.suppress(Exception):
            items.append(public_destination(safe_json_file(path)))
    return {"ok": True, "destinations": items, "types": list(DESTINATION_TYPES)}


def save_destination(request: dict[str, Any]) -> dict[str, Any]:
    ensure_destinations_dir()
    name = str(request.get("name") or "").strip().lower()
    path_target = destination_path(name)
    kind = str(request.get("type") or "").strip().lower()
    if kind not in DESTINATION_TYPES:
        raise BackupdError("unsupported destination type", code="invalid")

    existing_probe: dict[str, Any] = {}
    with contextlib.suppress(BackupdError):
        existing_probe = load_destination(name)

    if kind == "s3":
        return save_s3_destination(request, name, path_target, existing_probe)

    host = str(request.get("host") or "").strip()
    if (
        not host
        or host.startswith("-")
        or len(host) > 253
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host)
        or not re.fullmatch(r"[A-Za-z0-9._:\[\]-]+", host)
    ):
        raise BackupdError("a host is required", code="invalid")
    user = str(request.get("user") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}", user):
        raise BackupdError("the user name is not valid", code="invalid")
    try:
        port = int(request.get("port") or 22)
    except (TypeError, ValueError):
        raise BackupdError("the port must be a number", code="invalid") from None
    if not 1 <= port <= 65535:
        raise BackupdError("the port is out of range", code="invalid")
    remote = normalize_remote_dir(request.get("path"))

    existing = existing_probe

    auth = str(request.get("auth") or existing.get("auth") or "key").strip().lower()
    if auth not in DESTINATION_AUTH:
        raise BackupdError("auth must be key or password", code="invalid")
    key_installed = bool(existing.get("key_installed"))
    password_installed = bool(existing.get("password_installed"))
    if auth == "key":
        key = str(request.get("private_key") or "")
        if key:
            if "PRIVATE KEY" not in key:
                raise BackupdError("that does not look like a private key", code="invalid")
            # The key never goes through the archive path and never leaves
            # this directory; the browser cannot read it back.
            write_private(destination_key_path(name), normalize_private_key(key))
            key_installed = True
        elif not key_installed:
            raise BackupdError("a private key is required", code="invalid")
    else:
        password = request.get("password")
        if password:
            if (
                not isinstance(password, str)
                or len(password) > 1024
                or any(ch in password for ch in "\x00\r\n")
            ):
                raise BackupdError("the password is not valid", code="invalid")
            # Root-only, like the key, and never returned to the browser.
            write_private(destination_password_path(name), password.encode("utf-8"))
            password_installed = True
        elif not password_installed:
            raise BackupdError("a password is required", code="invalid")

    # The host key: the one supplied, the one already pinned for this same
    # host and port, or -- trust on first use -- the one the far end offers
    # now. Typing it in used to be mandatory, and a key copied by hand was
    # one more thing to get wrong; what matters is that it cannot change
    # silently afterwards.
    host_key = str(request.get("host_key") or "").strip()
    same_endpoint = (
        existing.get("host") == host and int(existing.get("port") or 22) == port
    )
    fingerprints = list(existing.get("host_key_fingerprints") or [])
    source = existing.get("host_key_source") or "supplied"
    if host_key:
        fingerprints = pin_host_key(name, (host_key + "\n").encode("utf-8"))
        source = "supplied"
    elif not (existing.get("host_key_pinned") and same_endpoint):
        fingerprints = pin_host_key(name, scan_host_key(host, port))
        source = "first-use"

    record = {
        "name": name,
        "type": kind,
        "host": host,
        "port": port,
        "user": user,
        "path": remote,
        "auth": auth,
        "key_installed": key_installed,
        "password_installed": password_installed,
        "host_key_pinned": True,
        "host_key_fingerprints": fingerprints,
        "host_key_source": source,
        # "or" would read a deliberate zero as "not supplied" and quietly
        # restore the default, so an operator asking to keep no weeklies would
        # silently keep four of them.
        "keep_daily": keep_count(request.get("keep_daily"), default=7, cap=365),
        "keep_weekly": keep_count(request.get("keep_weekly"), default=4, cap=260),
        "keep_monthly": keep_count(request.get("keep_monthly"), default=6, cap=120),
        "verify": verify_mode(request.get("verify"), default=existing.get("verify")),
        "updated_at": utc_now(),
    }
    atomic_json(path_target, record, mode=0o600)
    return {"ok": True, "destination": public_destination(record)}


def _validate_s3_ip(candidate: str) -> None:
    """Reject loopback, link-local, multicast, unspecified and reserved IPs."""
    address = ipaddress.ip_address(candidate)
    unwrapped = getattr(address, "ipv4_mapped", None) or address
    if (
        unwrapped.is_loopback
        or unwrapped.is_link_local
        or unwrapped.is_multicast
        or unwrapped.is_unspecified
        or unwrapped.is_reserved
    ):
        raise BackupdError(
            "the S3 endpoint resolves to a forbidden address", code="invalid"
        )


def _validate_s3_endpoint_host(hostname: str) -> None:
    """Syntactic and literal-IP checks for an S3 endpoint host."""
    host = (hostname or "").strip().lower().rstrip(".")
    if (
        not host
        or len(host) > 253
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host)
    ):
        raise BackupdError("the endpoint host is not valid", code="invalid")
    if host == "localhost" or host.endswith(".localhost"):
        raise BackupdError(
            "the S3 endpoint cannot target localhost", code="invalid"
        )
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return
    _validate_s3_ip(host)


def resolve_s3_address(hostname: str, port: int) -> str:
    """Resolve and validate an S3 endpoint host, returning a pinned IP."""
    _validate_s3_endpoint_host(hostname)
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise BackupdError(
            f"the S3 endpoint host does not resolve: {exc}", code="invalid"
        ) from exc
    selected = ""
    for info in infos:
        candidate = info[4][0]
        try:
            _validate_s3_ip(candidate)
        except ValueError:
            continue
        if not selected:
            selected = candidate
    if not selected:
        raise BackupdError(
            "the S3 endpoint host did not resolve to a usable address",
            code="invalid",
        )
    return selected


def save_s3_destination(
    request: dict[str, Any],
    name: str,
    path_target: Path,
    existing: dict[str, Any],
) -> dict[str, Any]:
    import urllib.parse

    endpoint = str(request.get("endpoint") or "").strip().rstrip("/")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in endpoint):
        raise BackupdError("the endpoint URL is not valid", code="invalid")
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in ("https", "http") or not parsed.netloc or not parsed.hostname:
        raise BackupdError(
            "the endpoint must be a full https:// URL", code="invalid"
        )
    if parsed.username or parsed.password:
        raise BackupdError(
            "the endpoint URL must not include credentials", code="invalid"
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise BackupdError("the endpoint port is not valid", code="invalid") from None
    if not 1 <= port <= 65535:
        raise BackupdError("the endpoint port is out of range", code="invalid")
    _validate_s3_endpoint_host(parsed.hostname)
    allow_insecure = bool(request.get("allow_insecure"))
    if parsed.scheme == "http" and not allow_insecure:
        raise BackupdError(
            "the endpoint is plain http; tick 'allow insecure' only for a"
            " storage service on a trusted network",
            code="invalid",
        )

    bucket = str(request.get("bucket") or "").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,62}", bucket):
        raise BackupdError("the bucket name is not valid", code="invalid")
    prefix = str(request.get("prefix") or "").strip().strip("/")
    if ".." in prefix or len(prefix) > 256:
        raise BackupdError("the prefix is not valid", code="invalid")
    access_key = str(request.get("access_key") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9/+=_-]{3,128}", access_key):
        raise BackupdError("the access key is not valid", code="invalid")

    secret = str(request.get("secret_key") or "")
    if secret:
        write_private(destination_secret_path(name), secret.encode("utf-8"))
    elif not existing.get("secret_installed"):
        raise BackupdError("a secret key is required", code="invalid")

    record = {
        "name": name,
        "type": "s3",
        "endpoint": endpoint,
        "region": str(request.get("region") or "us-east-1").strip()[:64],
        "bucket": bucket,
        "prefix": prefix,
        "access_key": access_key,
        "secret_installed": True,
        "allow_insecure": allow_insecure,
        "keep_daily": keep_count(request.get("keep_daily"), default=7, cap=365),
        "keep_weekly": keep_count(request.get("keep_weekly"), default=4, cap=260),
        "keep_monthly": keep_count(request.get("keep_monthly"), default=6, cap=120),
        "verify": verify_mode(request.get("verify"), default=existing.get("verify")),
        "updated_at": utc_now(),
    }
    atomic_json(path_target, record, mode=0o600)
    return {"ok": True, "destination": public_destination(record)}


def delete_destination(request: dict[str, Any]) -> dict[str, Any]:
    name = str(request.get("name") or "").strip().lower()
    path_target = destination_path(name)
    removed = False
    for candidate in (
        path_target,
        destination_key_path(name),
        destination_known_hosts(name),
        destination_password_path(name),
        destination_secret_path(name),
    ):
        with contextlib.suppress(FileNotFoundError):
            candidate.unlink()
            removed = True
    return {"ok": True, "deleted": removed}


def sftp_base_command(record: dict[str, Any], binary: str) -> list[str]:
    """Options shared by every call to the OpenSSH client.

    The host key is pinned to what the operator saved. Accepting whatever
    answers would make an off-host copy a way to hand the archive to whoever
    can answer on that address -- encrypted, but still theirs to keep and
    attack offline.
    """
    name = record["name"]
    command = [
        binary,
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={destination_known_hosts(name)}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=20",
    ]
    if destination_auth(record) == "password":
        # BatchMode would forbid the askpass program, so the prompts are
        # bounded instead: one attempt, password methods only.
        command += [
            "-o", "BatchMode=no",
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1",
        ]
    else:
        command += ["-o", "BatchMode=yes", "-i", str(destination_key_path(name))]
    command += ["-P" if binary.endswith("sftp") else "-p", str(record.get("port") or 22)]
    return command


def ensure_askpass() -> None:
    path = askpass_path()
    with contextlib.suppress(FileNotFoundError):
        if path.read_bytes() == ASKPASS_SCRIPT:
            os.chmod(path, 0o700)
            return
    ensure_destinations_dir()
    write_private(path, ASKPASS_SCRIPT)
    os.chmod(path, 0o700)


def sftp_environment(record: dict[str, Any]) -> dict[str, str] | None:
    """The environment for a password login; None keeps the inherited one."""
    if destination_auth(record) != "password":
        return None
    ensure_askpass()
    environment = dict(os.environ)
    environment.update({
        "SSH_ASKPASS": str(askpass_path()),
        # OpenSSH 8.4+: use the askpass program even without a display or a
        # terminal, which is exactly an unattended backup.
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": environment.get("DISPLAY") or ":0",
        "EASY_HA_PROXY_SFTP_PASSWORD_FILE": str(destination_password_path(record["name"])),
    })
    return environment


def _checked(record: dict[str, Any], result: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    """Turn a refused host key into a statement anyone can act on."""
    if result.returncode != 0 and host_key_problem(result.stderr):
        message = note_host_key_change(record)
        result = subprocess.CompletedProcess(
            result.args, result.returncode, result.stdout, message.encode("utf-8")
        )
    return result


def run_sftp(record: dict[str, Any], batch: str) -> subprocess.CompletedProcess:
    command = sftp_base_command(record, "/usr/bin/sftp")
    command += ["-b", "-", "--", f"{record['user']}@{record['host']}"]
    return _checked(record, subprocess.run(
        command,
        input=batch.encode("utf-8"),
        capture_output=True,
        timeout=SFTP_TIMEOUT_SECONDS,
        check=False,
        env=sftp_environment(record),
    ))


def run_ssh(record: dict[str, Any], remote_command: list[str]) -> subprocess.CompletedProcess:
    command = sftp_base_command(record, "/usr/bin/ssh")
    command += ["--", f"{record['user']}@{record['host']}"] + remote_command
    return _checked(record, subprocess.run(
        command,
        capture_output=True,
        timeout=SFTP_TIMEOUT_SECONDS,
        check=False,
        env=sftp_environment(record),
        stdin=subprocess.DEVNULL,
    ))


def retrust_destination(request: dict[str, Any]) -> dict[str, Any]:
    """Pin whatever key the far end offers now, after a deliberate change."""
    record = load_destination(request.get("name"))
    if record.get("type") != "sftp":
        raise BackupdError("only an SFTP destination has a host key", code="invalid")
    known_hosts = scan_host_key(record["host"], int(record.get("port") or 22))
    record["host_key_fingerprints"] = pin_host_key(record["name"], known_hosts)
    record["host_key_pinned"] = True
    record["host_key_source"] = "trusted-after-change"
    record.pop("host_key_changed", None)
    record["updated_at"] = utc_now()
    atomic_json(destination_path(record["name"]), record, mode=0o600)
    return {"ok": True, "destination": public_destination(record)}


def normalize_remote_dir(value: Any) -> str:
    """The remote directory as stored: absolute, relative, or "." for home.

    Shared hosting confines an SFTP account to one directory and starts the
    session there, often deep inside the site -- and its "/" is not
    writable. Asking for an absolute path meant knowing the full path the
    host chose, and "/" failed the write test on "//.easy-ha-proxy-write-test".
    An empty field or "." now means the directory the session starts in,
    and a relative path is taken from there.
    """
    text = str(value or "").strip()
    if not text or text in (".", "./"):
        return "."
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts or len(text) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise BackupdError("the remote path must be free of '..'", code="invalid")
    joined = "/".join(parts)
    if text.startswith("/"):
        return "/" + joined
    return joined or "."


def remote_join(directory: str, name: str) -> str:
    """A file in the remote directory, without "//" or a leading "./"."""
    if directory in ("", "."):
        return name
    return directory.rstrip("/") + "/" + name


def remote_quote(value: str) -> str:
    """Quote a path for the sftp batch language, which splits on whitespace."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise BackupdError("the remote path contains control characters", code="invalid")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


_SHA256_RE = re.compile(r"[0-9a-f]{64}")

# How hard the gateway works to prove an off-host copy arrived intact.
#   auto     -- ask the far end to hash it; fall back to reading it back.
#   transfer -- trust that sftp accepted every byte, and do not read it back.
VERIFY_MODES = ("auto", "transfer")


def verify_mode(value: Any, *, default: Any = None) -> str:
    text = str(value or "").strip().lower()
    if text in VERIFY_MODES:
        return text
    if value is not None and text:
        raise BackupdError(
            "verify must be auto or transfer", code="invalid"
        )
    fallback = str(default or "").strip().lower()
    return fallback if fallback in VERIFY_MODES else "auto"



def verify_remote_copy(
    record: dict[str, Any], remote_file: str, expected: str, size: int
) -> tuple[bool, str, str]:
    """Prove the far end holds the same bytes. Returns (ok, method, detail).

    Three ways, in descending order of confidence.

    Asking the far end to hash is exact and costs nothing to send. A
    destination restricted to SFTP cannot do it, so re-reading the copy is
    the fallback: also exact, but it pays for the whole transfer a second
    time and needs room on this disk to land in, which on a small gateway
    with a large archive is the thing that fails.

    `verify: transfer` is for that case. sftp reports whether every byte it
    sent was accepted, and the checksum file is uploaded beside the archive,
    so a restore can still prove the contents later -- it just is not proved
    here and now. It is weaker, and it is chosen deliberately.
    """
    mode = str(record.get("verify") or "auto").strip().lower()
    if mode == "transfer":
        return True, "transfer", ""

    probe = run_ssh(record, ["sha256sum", "--", shlex.quote(remote_file)])
    if probe.returncode == 0:
        answer = (probe.stdout or b"").decode("utf-8", "replace").split()
        # A server restricted to SFTP answers every command with a banner and
        # exits 0 -- "This service allows sftp connections only." -- so a zero
        # exit is not evidence that anything was hashed. Taking the first word
        # of that as a digest reported a mismatch for a copy that was fine,
        # and, because an unproven copy is never pruned, would have let the
        # far end fill up while insisting the backup had failed.
        if answer and _SHA256_RE.fullmatch(answer[0]):
            if answer[0] == expected:
                return True, "remote-hash", ""
            return False, "remote-hash", "the far end reports different content"

    if size > VERIFY_DOWNLOAD_MAX_BYTES:
        return (
            False,
            "none",
            "the far end cannot hash and the archive is too large to re-read",
        )

    with tempfile.TemporaryDirectory(prefix="backupd-verify-") as work:
        local = Path(work) / "verify.bin"
        result = run_sftp(
            record, f"get {remote_quote(remote_file)} {remote_quote(str(local))}\n"
        )
        if result.returncode != 0 or not local.exists():
            return False, "download", "the copy could not be read back"
        if sha256_file(local) != expected:
            return False, "download", "the copy read back does not match"
    return True, "download", ""


REMOTE_PREFIX = "easy-ha-proxy-"


def remote_archive_name(backup_id: str, archive: Path) -> str:
    """The name a copy carries off-host: dated, so retention can group it.

    On the gateway an archive is named after its id alone, and that name used
    to be sent off-host unchanged. Retention groups copies by the date in
    their names and looks only at easy-ha-proxy-* files, so it recognised
    none of them: no destination was ever pruned, and one had a hundred files
    where the policy allowed seventeen archives. The date comes from the
    backup's own record, falling back to the archive's modification time.
    """
    created = None
    with contextlib.suppress(Exception):
        raw = str(safe_json_file(backup_meta_path(backup_id)).get("created_at") or "")
        created = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if created is None:
        created = dt.datetime.fromtimestamp(archive.stat().st_mtime, dt.timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=dt.timezone.utc)
    stamp = created.astimezone(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{REMOTE_PREFIX}{stamp}-{backup_id}{ARCHIVE_SUFFIX}"


def remote_checksum_body(expected: str, remote_name: str) -> bytes:
    # Names the remote file, so sha256sum -c works where the copy lands.
    return f"{expected}  {remote_name}\n".encode("ascii")


def remote_listing(record: dict[str, Any]) -> list[str]:
    """Archive names already on the far end, newest last."""
    result = run_sftp(record, f"ls -1 {remote_quote(record['path'])}\n")
    if result.returncode != 0:
        return []
    names = []
    for row in (result.stdout or b"").decode("utf-8", "replace").splitlines():
        candidate = row.strip().rsplit("/", 1)[-1]
        if candidate.startswith(REMOTE_PREFIX) and candidate.endswith(ARCHIVE_SUFFIX):
            names.append(candidate)
    return sorted(names)


def retention_victims(names: list[str], record: dict[str, Any]) -> list[str]:
    """Which remote archives fall outside the keep policy.

    Grouped by the date in the file name, which is how the archives are named
    anyway. One per day is kept as a daily, then one per ISO week, then one
    per month; anything else goes.
    """
    by_day: dict[str, str] = {}
    dated: set[str] = set()
    for name in sorted(names):
        # The date directly after the prefix, and nowhere else: an id is hex
        # and can hold eight digits in a row -- "...70977473..." read as a
        # date is month 74, which used to raise out of the whole upload.
        match = re.match(rf"{re.escape(REMOTE_PREFIX)}(\d{{4}})(\d{{2}})(\d{{2}})", name)
        if match is None:
            continue
        try:
            dt.date(*(int(part) for part in match.groups()))
        except ValueError:
            continue
        dated.add(name)
        # The last archive of a day represents that day.
        by_day["-".join(match.groups())] = name

    days = sorted(by_day, reverse=True)
    keep: set[str] = set()
    for day in days[: max(0, int(record.get("keep_daily") or 0))]:
        keep.add(by_day[day])

    seen_weeks: set[str] = set()
    for day in days:
        year, month, number = (int(part) for part in day.split("-"))
        week = dt.date(year, month, number).isocalendar()
        token = f"{week[0]}-{week[1]}"
        if token in seen_weeks:
            continue
        seen_weeks.add(token)
        if len(seen_weeks) <= int(record.get("keep_weekly") or 0):
            keep.add(by_day[day])

    seen_months: set[str] = set()
    for day in days:
        token = day[:7]
        if token in seen_months:
            continue
        seen_months.add(token)
        if len(seen_months) <= int(record.get("keep_monthly") or 0):
            keep.add(by_day[day])

    # Only copies recognised above can be victims. A file of any other name
    # in the folder -- an undated copy from before copies were dated, or
    # something that is not a backup at all -- is never retention's to remove.
    return [name for name in names if name in dated and name not in keep]


# ---------------------------------------------------------------------------
# S3-compatible destinations
# ---------------------------------------------------------------------------
#
# Signed with SigV4 against the standard library rather than by adding an SDK
# to the gateway. That is a deliberate trade: a hundred lines of HMAC here, or
# boto3 and its dependency tree on a two-core box that already runs HAProxy.
#
# The integrity proof falls out of the protocol. A signed PUT carries the
# payload's SHA-256 in x-amz-content-sha256, and the service refuses the
# request if the body does not hash to it -- so a 200 already means the far
# end holds exactly these bytes, with no second transfer to check.

S3_ALGORITHM = "AWS4-HMAC-SHA256"
S3_TIMEOUT_SECONDS = int(os.environ.get("BACKUPD_S3_TIMEOUT", "900"))
S3_SERVICE = "s3"
_S3_UNRESERVED = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def destination_secret_path(name: str) -> Path:
    return DESTINATIONS_DIR / (str(name).strip().lower() + ".secret")


def s3_quote(value: str, *, keep_slash: bool = True) -> str:
    """Percent-encode the way SigV4 requires, which is not urllib's default."""
    allowed = _S3_UNRESERVED + ("/" if keep_slash else "")
    out = []
    for byte in str(value).encode("utf-8"):
        char = chr(byte)
        out.append(char if char in allowed else f"%{byte:02X}")
    return "".join(out)


def s3_signing_key(secret: str, stamp: str, region: str) -> bytes:
    key = ("AWS4" + secret).encode("utf-8")
    for part in (stamp, region, S3_SERVICE, "aws4_request"):
        key = hmac.new(key, part.encode("utf-8"), hashlib.sha256).digest()
    return key


def s3_authorization(
    *,
    method: str,
    canonical_uri: str,
    canonical_query: str,
    headers: dict[str, str],
    payload_sha: str,
    access_key: str,
    secret_key: str,
    region: str,
    amz_date: str,
) -> str:
    """Build the Authorization header for one request.

    Header names are lower-cased and sorted, values collapsed -- SigV4 signs a
    canonical form, so anything that differs between what is signed and what
    is sent is a 403 that looks like bad credentials.
    """
    canonical_headers = "".join(
        f"{name}:{' '.join(str(value).split())}\n"
        for name, value in sorted(headers.items())
    )
    signed_headers = ";".join(sorted(headers))
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_sha,
        ]
    )
    stamp = amz_date[:8]
    scope = f"{stamp}/{region}/{S3_SERVICE}/aws4_request"
    to_sign = "\n".join(
        [
            S3_ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        s3_signing_key(secret_key, stamp, region),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return (
        f"{S3_ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


def s3_request(
    record: dict[str, Any],
    method: str,
    key: str = "",
    *,
    query: dict[str, str] | None = None,
    body: Any = None,
    body_sha: str = "",
    length: int = 0,
) -> tuple[int, dict[str, str], bytes]:
    """One signed request. Returns (status, headers, body)."""
    import http.client
    import urllib.parse

    endpoint = urllib.parse.urlparse(record["endpoint"])
    if endpoint.scheme not in ("https", "http") or not endpoint.hostname:
        raise BackupdError("the endpoint must be http or https", code="invalid")
    if endpoint.username or endpoint.password:
        raise BackupdError("the endpoint URL must not include credentials", code="invalid")
    _validate_s3_endpoint_host(endpoint.hostname)
    if endpoint.scheme == "http" and not record.get("allow_insecure"):
        raise BackupdError(
            "the endpoint is plain http; enable 'allow insecure' only for a"
            " storage service on a trusted network",
            code="invalid",
        )

    secret = destination_secret_path(record["name"]).read_text(encoding="utf-8").strip()
    # A bucket-level call addresses the bucket and carries the prefix in the
    # query; putting the prefix in the path too turns a listing into a request
    # for an object that does not exist.
    prefix = str(record.get("prefix") or "").strip("/")
    segments = [
        segment
        for segment in (record.get("bucket") or "", prefix if key else "", key)
        if segment
    ]
    canonical_uri = "/" + s3_quote("/".join(segments))

    items = sorted((query or {}).items())
    canonical_query = "&".join(
        f"{s3_quote(name, keep_slash=False)}={s3_quote(value, keep_slash=False)}"
        for name, value in items
    )

    amz_date = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload_sha = body_sha or hashlib.sha256(b"").hexdigest()
    host = endpoint.netloc
    headers = {
        "host": host,
        "x-amz-content-sha256": payload_sha,
        "x-amz-date": amz_date,
    }
    authorization = s3_authorization(
        method=method,
        canonical_uri=canonical_uri,
        canonical_query=canonical_query,
        headers=headers,
        payload_sha=payload_sha,
        access_key=record["access_key"],
        secret_key=secret,
        region=record.get("region") or "us-east-1",
        amz_date=amz_date,
    )
    secret = ""

    send_headers = dict(headers)
    send_headers["Authorization"] = authorization
    if length:
        send_headers["Content-Length"] = str(length)

    target = canonical_uri + (f"?{canonical_query}" if canonical_query else "")
    if endpoint.scheme == "https":
        class _PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self) -> None:
                pinned = resolve_s3_address(self.host, self.port)
                raw = socket.create_connection(
                    (pinned, self.port), self.timeout, self.source_address
                )
                try:
                    self.sock = self._context.wrap_socket(
                        raw, server_hostname=self.host
                    )
                except Exception:
                    raw.close()
                    raise

        connection = _PinnedHTTPSConnection(
            host, timeout=S3_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
    else:
        class _PinnedHTTPConnection(http.client.HTTPConnection):
            def connect(self) -> None:
                pinned = resolve_s3_address(self.host, self.port)
                self.sock = socket.create_connection(
                    (pinned, self.port), self.timeout, self.source_address
                )

        connection = _PinnedHTTPConnection(host, timeout=S3_TIMEOUT_SECONDS)
    try:
        connection.request(method, target, body=body, headers=send_headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024)
        return response.status, dict(response.getheaders()), payload
    finally:
        connection.close()


def s3_listing(record: dict[str, Any]) -> list[str]:
    """Archive names already in the bucket."""
    prefix = str(record.get("prefix") or "").strip("/")
    query = {"list-type": "2"}
    if prefix:
        query["prefix"] = prefix + "/"
    status, _headers, body = s3_request(record, "GET", query=query)
    if status != 200:
        return []
    text = body.decode("utf-8", "replace")
    names = []
    for match in re.finditer(r"<Key>([^<]+)</Key>", text):
        candidate = match.group(1).rsplit("/", 1)[-1]
        if candidate.startswith(REMOTE_PREFIX) and candidate.endswith(ARCHIVE_SUFFIX):
            names.append(candidate)
    return sorted(names)


def s3_upload(
    record: dict[str, Any], archive: Path, remote_name: str, expected: str
) -> dict[str, Any]:
    """PUT the archive, then the checksum beside it.

    No .part dance here: an S3 PUT is atomic, an object appears whole or not
    at all, so there is nothing half-written for a later prune to mistake for
    a finished backup.
    """
    size = archive.stat().st_size
    with archive.open("rb") as stream:
        status, _headers, body = s3_request(
            record, "PUT", remote_name, body=stream, body_sha=expected, length=size
        )
    if status not in (200, 201):
        detail = body.decode("utf-8", "replace").strip()[:400]
        raise BackupdError(f"the upload failed ({status}): {detail}", code="upstream")

    payload = remote_checksum_body(expected, remote_name)
    s3_request(
        record,
        "PUT",
        remote_name + ".sha256",
        body=payload,
        body_sha=hashlib.sha256(payload).hexdigest(),
        length=len(payload),
    )
    # The service verified the body against the hash carried in the signature,
    # so a success here is the integrity proof; re-reading would prove nothing
    # more and cost the transfer twice.
    return {"bytes": size, "verified": True, "verified_by": "signed-put"}


def s3_prune(record: dict[str, Any], victims: list[str]) -> list[str]:
    removed = []
    for name in victims:
        for key in (name, name + ".sha256"):
            status, _headers, _body = s3_request(record, "DELETE", key)
            if status in (200, 204) and key == name:
                removed.append(name)
    return removed


@contextlib.contextmanager
def sftp_upload_lock(record: dict[str, Any]):
    """Keep publication, verification and retention together for this folder.

    Use the remote identity, so two saved profiles pointing at the same
    destination share a lock. Waiting requests count as users too; the last
    request removes its entry rather than accumulating locks forever.
    """
    key = (
        str(record.get("host") or "").lower().rstrip("."),
        str(record.get("port") or 22),
        str(record.get("user") or ""),
        normalize_remote_dir(record["path"]),
    )
    with DESTINATION_UPLOAD_LOCKS_GUARD:
        lock, users = DESTINATION_UPLOAD_LOCKS.get(key, (threading.Lock(), 0))
        DESTINATION_UPLOAD_LOCKS[key] = (lock, users + 1)
    try:
        with lock:
            yield
    finally:
        with DESTINATION_UPLOAD_LOCKS_GUARD:
            _lock, users = DESTINATION_UPLOAD_LOCKS[key]
            if users == 1:
                del DESTINATION_UPLOAD_LOCKS[key]
            else:
                DESTINATION_UPLOAD_LOCKS[key] = (lock, users - 1)


def publish_sftp_file(
    record: dict[str, Any], staging: str, final: str, expected: str, size: int
) -> bool:
    """Publish without ever unlinking an existing copy; return whether moved.

    OpenSSH uses atomic replacement where the server supports it. A plain
    SFTP server can refuse a rename over an existing file. In that case an
    exact match makes a retry successful too, but transfer-only verification
    cannot prove that the *existing* file is the one we intended to send.
    """
    result = run_sftp(record, f"rename {remote_quote(staging)} {remote_quote(final)}\n")
    if result.returncode == 0:
        return True
    same, _method, _detail = verify_remote_copy(
        {**record, "verify": "auto"}, final, expected, size
    )
    if same:
        return False
    detail = (result.stderr or b"").decode("utf-8", "replace").strip()[:500]
    raise BackupdError(
        "the copy could not be published safely; an existing file was kept: " + detail,
        code="upstream",
    )


def upload_sftp_backup(
    record: dict[str, Any], backup_id: str, archive: Path,
    remote_name: str, expected: str, size: int,
) -> dict[str, Any]:
    remote_dir = record["path"]
    remote_file = remote_join(remote_dir, remote_name)
    token = uuid.uuid4().hex
    staging = f"{remote_file}.{token}.part"
    staging_checksum = f"{remote_file}.sha256.{token}.part"
    pending = [staging, staging_checksum]
    checksum_body = remote_checksum_body(expected, remote_name)
    response = {
        "ok": True,
        "backup_id": backup_id,
        "destination": record["name"],
        "bytes": size,
        "pruned": [],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="backupd-upload-") as work:
            checksum_copy = Path(work) / (remote_name + ".sha256")
            checksum_copy.write_bytes(checksum_body)
            batch = (
                f"-mkdir {remote_quote(remote_dir)}\n"
                f"put {remote_quote(str(archive))} {remote_quote(staging)}\n"
                f"put {remote_quote(str(checksum_copy))} {remote_quote(staging_checksum)}\n"
            )
            result = run_sftp(record, batch)
        if result.returncode != 0:
            detail = (result.stderr or b"").decode("utf-8", "replace").strip()[:500]
            raise BackupdError(f"the upload failed: {detail}", code="upstream")

        # Verify before publication: a bad retry cannot replace a good final
        # archive, even when the server offers atomic rename-overwrite.
        verified, method, detail = verify_remote_copy(record, staging, expected, size)
        response.update(verified=verified, verified_by=method)
        if not verified:
            response["ok"] = False
            response["error"] = detail or "the copy could not be verified"
            report_alert(
                "backup.failed",
                f"{backup_id}@{record['name']}",
                "The off-host copy could not be verified",
                response["error"],
            )
            return response

        if publish_sftp_file(record, staging, remote_file, expected, size):
            pending.remove(staging)
        if publish_sftp_file(
            record, staging_checksum, remote_file + ".sha256",
            hashlib.sha256(checksum_body).hexdigest(), len(checksum_body),
        ):
            pending.remove(staging_checksum)

        victims = retention_victims(remote_listing(record), record)
        if victims:
            prune = "".join(
                f"-rm {remote_quote(remote_join(remote_dir, name))}\n"
                f"-rm {remote_quote(remote_join(remote_dir, name + '.sha256'))}\n"
                for name in victims
            )
            run_sftp(record, prune)
            response["pruned"] = victims
        return response
    except (BackupdError, OSError, subprocess.TimeoutExpired) as exc:
        detail = str(exc)[:500]
        report_alert(
            "backup.failed",
            f"{backup_id}@{record['name']}",
            "The off-host copy of the backup failed",
            detail,
        )
        raise BackupdError(f"the upload failed: {detail}", code="upstream") from exc
    finally:
        if pending:
            # Only this request's temporary names are ours to clean up. Never
            # remove a final archive to recover from a refused rename.
            try:
                run_sftp(record, "".join(f"-rm {remote_quote(path)}\n" for path in pending))
            except (BackupdError, OSError, subprocess.TimeoutExpired):
                LOG.warning("Could not clean up temporary upload for %s", record["name"])


def upload_backup(request: dict[str, Any]) -> dict[str, Any]:
    """Copy one finished archive to one destination, then prune the far end."""
    backup_id = identifier(request.get("backup_id"), "backup id")
    record = load_destination(request.get("destination"))

    archive = backup_archive_path(backup_id)
    checksum = backup_checksum_path(backup_id)
    if not archive.is_file():
        raise BackupdError("no such backup", code="not_found")
    expected = read_checksum_file(checksum, checksum.stat()) if checksum.is_file() else ""
    if not expected:
        expected = sha256_file(archive)
    size = archive.stat().st_size
    remote_name = remote_archive_name(backup_id, archive)

    if record.get("type") == "s3":
        outcome = s3_upload(record, archive, remote_name, expected)
        response = {
            "ok": True,
            "backup_id": backup_id,
            "destination": record["name"],
            "pruned": [],
            **outcome,
        }
        victims = retention_victims(s3_listing(record), record)
        if victims:
            response["pruned"] = s3_prune(record, victims)
        return response

    with sftp_upload_lock(record):
        return upload_sftp_backup(
            record, backup_id, archive, remote_name, expected, size
        )


def test_destination(request: dict[str, Any]) -> dict[str, Any]:
    """Prove the credentials and the path work before a real backup needs them."""
    record = load_destination(request.get("name"))
    if record.get("type") == "s3":
        # A listing proves the credentials, the region and the bucket in one
        # call, without leaving anything behind to clean up.
        try:
            status, _headers, body = s3_request(
                record, "GET", query={"list-type": "2", "max-keys": "1"}
            )
        except BackupdError as exc:
            return {"ok": False, "error": str(exc)}
        if status != 200:
            return {
                "ok": False,
                "error": f"the storage service answered {status}: "
                + body.decode("utf-8", "replace").strip()[:300],
            }
        return {"ok": True, "destination": record["name"]}

    marker = remote_join(record["path"], ".easy-ha-proxy-write-test")
    with tempfile.TemporaryDirectory(prefix="backupd-test-") as work:
        probe = Path(work) / "probe"
        probe.write_text(utc_now() + "\n", encoding="utf-8")
        result = run_sftp(
            record,
            f"-mkdir {remote_quote(record['path'])}\n"
            f"put {remote_quote(str(probe))} {remote_quote(marker)}\n"
            f"rm {remote_quote(marker)}\n",
        )
    if result.returncode != 0:
        return {
            "ok": False,
            "error": (result.stderr or b"").decode("utf-8", "replace").strip()[:500],
        }
    if record.get("host_key_changed"):
        # The pinned key works again -- the change was transient, or put
        # back -- so the warning no longer describes anything.
        record.pop("host_key_changed", None)
        atomic_json(destination_path(record["name"]), record, mode=0o600)
    return {"ok": True, "destination": record["name"]}
