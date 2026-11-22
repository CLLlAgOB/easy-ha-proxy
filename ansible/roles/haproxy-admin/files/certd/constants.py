"""Constants, paths, locks, YAML helpers, and DNS-01 provider profiles."""

from __future__ import annotations

import configparser
import contextlib
import json
import logging
import os
import re
import signal
import ssl
import stat
import subprocess
import tempfile
import threading
import yaml
import zipfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Bound across sibling submodules when the package finishes loading.
_trash_commit: Any = None
_trash_listing: Any = None
_trash_put: Any = None
_trash_settle: Any = None

# ───────────────────── configuration ─────────────────────

LOG = logging.getLogger("haproxy-certd")

# Path to the control Unix socket
SOCKET_PATH = os.environ.get(
    "HAPROXY_CERTD_SOCKET", "/run/easy-ha-proxy/haproxy-certd.sock"
)
GROUP_NAME = os.environ.get("HAPROXY_CERTD_SOCKET_GROUP", "hadmin")

# Path to vars.yml (certbot_email, haproxy_certs_dir and the rest are read from it)
CONFIG_YAML = Path(
    os.environ.get("HAPROXY_VARS_YAML", "/opt/haproxy-admin/config/vars.yml")
)

# Where certbot is
CERTBOT_BIN = Path(os.environ.get("CERTBOT_BIN", "/snap/bin/certbot"))

# certbot's HTTP challenge
CERTBOT_HTTP_PORT = 8000
CERTBOT_HTTP_ADDR = "0.0.0.0"

# --- DNS-01 -----------------------------------------------------------------
#
# Certbot is installed here as a snap, so its plugins are snaps too, version
# for version with certbot itself: `snap install certbot-dns-<provider>`,
# `snap set certbot trust-plugin-with-root=ok`,
# `snap connect certbot:plugin certbot-dns-<provider>`. There are no apt packages.
#
# The providers and the names of their keys are a fixed set. The browser sends
# only the profile name and the values; neither the plugin's name nor certbot's
# arguments are ever taken from the request.
DNS_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "plugin": "dns-cloudflare",
        "snap": "certbot-dns-cloudflare",
        "keys": ("dns_cloudflare_api_token",),
    },
    "digitalocean": {
        "plugin": "dns-digitalocean",
        "snap": "certbot-dns-digitalocean",
        "keys": ("dns_digitalocean_token",),
    },
    "route53": {
        "plugin": "dns-route53",
        "snap": "certbot-dns-route53",
        "keys": ("aws_access_key_id", "aws_secret_access_key"),
    },
    "rfc2136": {
        "plugin": "dns-rfc2136",
        "snap": "certbot-dns-rfc2136",
        "keys": (
            "dns_rfc2136_server",
            "dns_rfc2136_port",
            "dns_rfc2136_name",
            "dns_rfc2136_secret",
            "dns_rfc2136_algorithm",
        ),
    },
}

DNS_CREDENTIALS_DIR = Path(
    os.environ.get("HAPROXY_DNS_CREDENTIALS_DIR", "/etc/easy-ha-proxy/dns-providers")
)
DNS_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DNS_VALUE_MAX = 4096
DNS_PROPAGATION_MIN = 10
DNS_PROPAGATION_MAX = 1800
DNS_PROPAGATION_DEFAULT = 60

# How long each command certd runs may take before it is stopped. Nothing
# used to bound them: a certbot that hung kept its request thread and its own
# lock for good, so every later issuance -- and the snap's renewal timer --
# failed with "another instance is already running" until certd restarted.
# certbot's own work around a challenge; a DNS-01 wait is added on top.
CERTBOT_TIMEOUT_SECONDS = 600
# certbot without a challenge: plugins, delete. The snap starts slowly on ARM.
CERTBOT_QUICK_TIMEOUT_SECONDS = 300
HAPROXY_CHECK_TIMEOUT_SECONDS = 60
HAPROXY_RELOAD_TIMEOUT_SECONDS = 120
OPENSSL_TIMEOUT_SECONDS = 30
PEM_REBUILD_TIMEOUT_SECONDS = 300
DELIVERY_TIMEOUT_SECONDS = 180
TIMED_OUT_RC = 124

# The script that rebuilds the PEM for HAProxy and reloads it
HAPROXY_PEMS_SCRIPT = Path(
    os.environ.get(
        "HAPROXY_PEMS_SCRIPT",
        "/etc/letsencrypt/renewal-hooks/deploy/905-haproxy-pems-reload.sh",
    )
)

# Default paths
DEFAULT_HAPROXY_CERTS_DIR = Path("/etc/haproxy/certs")
DEFAULT_LETSENCRYPT_ROOT_DIR = Path("/etc/letsencrypt")
DEFAULT_CA_ROOT_DIR = Path("/etc/haproxy/certificate-authorities")

# How long before expiry a certificate is reported, for one renewed by hand.
CERT_WARN_DAYS = 30
# A certificate that lives this long or less is renewed automatically.
AUTOMATED_LIFETIME_DAYS = 100


def cert_warn_days(lifetime_days: Optional[int]) -> int:
    """How many days before expiry this certificate deserves a warning.

    A fixed 30 warned about every Let's Encrypt certificate once per cycle.
    certbot renews when less than 30 days remain, the remaining time is
    counted in whole days rounded down, so "30 or fewer" fired a day before
    certbot even looked -- and certbot looks only twice a day besides. The
    warning has to mean that renewal is failing: for an automated
    certificate it comes at a quarter of its lifetime (22 days of a 90-day
    one, eight days of failed renewals later; 11 of a 45-day one). One
    renewed by hand keeps the full 30 days to act in.
    """
    if lifetime_days and 0 < lifetime_days <= AUTOMATED_LIFETIME_DAYS:
        return max(1, lifetime_days // 4)
    return CERT_WARN_DAYS


# The alert client lives beside this script in /usr/local/sbin, which is
# sys.path[0] for a daemon started by absolute path. Optional on purpose:
# certificates are issued the same way without the alert daemon.
try:
    from easy_ha_proxy_alert_client import AlertClient  # type: ignore[import]
except Exception:  # pragma: no cover - the daemon runs without it
    AlertClient = None  # type: ignore[assignment]

_ALERTS = None
if AlertClient is not None:
    _candidate = AlertClient(source="certd")
    _ALERTS = _candidate if _candidate.configured else None


def report_alert(rule: str, subject: str, summary: str, detail: str = "") -> None:
    """Tell the alert engine something failed. Never disturbs issuance."""
    if _ALERTS is None:
        return
    try:
        _ALERTS.observe(rule, subject, summary=summary, detail=detail)
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)


def report_alert_level(
    rule: str,
    subject: str,
    *,
    active: bool,
    severity: str = "",
    summary: str = "",
    detail: str = "",
    retired: bool = False,
) -> None:
    """Report a level condition. Never disturbs the daemon."""
    if _ALERTS is None:
        return
    try:
        _ALERTS.observe(
            rule,
            subject,
            active=active,
            severity=severity,
            summary=summary,
            detail=detail,
            retired=retired,
        )
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)

# Dry run: files are not touched, certbot runs with --dry-run
CERTD_DRY_RUN = os.environ.get("HAPROXY_CERTD_DRY_RUN", "0") == "1"
HAPROXY_CERTS_DIR = Path(
    os.environ.get("HAPROXY_CERTS_DIR", str(DEFAULT_HAPROXY_CERTS_DIR))
).resolve()
LETSENCRYPT_ROOT_DIR = Path(
    os.environ.get("LETSENCRYPT_ROOT_DIR", str(DEFAULT_LETSENCRYPT_ROOT_DIR))
).resolve()
CA_ROOT_DIR = Path(
    os.environ.get("HAPROXY_CA_ROOT_DIR", str(DEFAULT_CA_ROOT_DIR))
).absolute()
HAPROXY_BIN = Path(os.environ.get("HAPROXY_BIN", "/usr/sbin/haproxy"))
HAPROXY_CFG = Path(os.environ.get("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"))
MAX_REQUEST_BYTES = int(
    os.environ.get("HAPROXY_CERTD_MAX_REQUEST_BYTES", str(32 * 1024 * 1024))
)
MAX_ARCHIVE_BYTES = int(
    os.environ.get("HAPROXY_CERTD_MAX_ARCHIVE_BYTES", str(64 * 1024 * 1024))
)
MAX_ARCHIVE_FILES = int(os.environ.get("HAPROXY_CERTD_MAX_ARCHIVE_FILES", "4096"))
MAX_ARCHIVE_EXPANDED_BYTES = int(
    os.environ.get("HAPROXY_CERTD_MAX_ARCHIVE_EXPANDED_BYTES", str(256 * 1024 * 1024))
)
MAX_COMPRESSION_RATIO = int(
    os.environ.get("HAPROXY_CERTD_MAX_COMPRESSION_RATIO", "100")
)
CA_LOCK = threading.Lock()

# ── client authentication material ────────────────────────────────────────
#
# The CA root is 0700 root: HAProxy cannot read it, and neither can the web
# container. Everything the frontend needs for client certificates is derived
# into this directory instead, which holds only public certificates and the
# names taken out of them.
MTLS_DIR = Path(os.environ.get("HAPROXY_MTLS_DIR", "/etc/haproxy/mtls"))
MTLS_TRUST_FILE = "client-auth.json"
MTLS_BUNDLE_NAME = "clients-ca.pem"
MTLS_REVOKED_NAME = "revoked.list"
# A pattern file loads fine with nothing but a comment in it; an empty one
# earns a warning on every start. Both files exist from the first boot so the
# configuration can reference them before anyone has imported anything.
MTLS_EMPTY_MARKER = "# managed by easy-ha-proxy; edit through the web interface\n"
MTLS_MAX_REVOKED = 2000
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


# ───────────────────── YAML helpers ─────────────────────


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Reads a YAML file safely. A missing file gives {}.
    """
    try:
        if not path.exists():
            return {}
        # type: ignore[no-untyped-call]
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data is None:
            return {}
        if isinstance(data, dict):
            return data
        # if the root is not a dict, wrap it
        return {"_": data}
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Failed to load YAML %s: %s", path, exc)
        return {}


def _get_haproxy_certs_dir() -> Path:
    """Return the root-owned, service-configured certificate directory."""
    return HAPROXY_CERTS_DIR


def _get_letsencrypt_root_dir() -> Path:
    """Return the root-owned, service-configured Let's Encrypt directory."""
    return LETSENCRYPT_ROOT_DIR


def _get_ca_root_dir() -> Path:
    """Return the root-owned directory for internal and external CA data."""
    return CA_ROOT_DIR


def _prepare_ca_root(create: bool = False) -> Path:
    """Create/harden the CA root and refuse symlink-based path redirection."""
    root = _get_ca_root_dir()
    if root.is_symlink():
        raise ValueError("certificate authority root must not be a symlink")
    if create:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.exists():
        if not root.is_dir():
            raise ValueError("certificate authority root is not a directory")
        os.chmod(root, 0o700)
    return root


def _prepare_ca_subdir(name: str, create: bool = False) -> Path:
    if name not in ("internal", "external"):
        raise ValueError("invalid certificate authority directory")
    directory = _prepare_ca_root(create=create) / name
    if directory.is_symlink():
        raise ValueError(f"certificate authority directory {name!r} must not be a symlink")
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    if directory.exists():
        if not directory.is_dir():
            raise ValueError(f"certificate authority path {name!r} is not a directory")
        os.chmod(directory, 0o700)
    return directory


def _normalize_dns_name(value: str, *, allow_wildcard: bool = False) -> str:
    name = (value or "").strip().rstrip(".").lower()
    if not name or len(name) > 253 or any(ch in name for ch in "/\\\x00\r\n"):
        raise ValueError("invalid DNS name")

    if name.startswith("*."):
        # A wildcard is only ever the leftmost label, and only where the caller
        # said one is acceptable — everything else still refuses the character.
        if not allow_wildcard:
            raise ValueError("a wildcard name is not allowed here")
        remainder = name[2:]
        if "*" in remainder:
            raise ValueError("only one wildcard label is allowed")
        base = _normalize_dns_name(remainder)
        if len(base.split(".")) < 2:
            raise ValueError("a wildcard needs at least two labels beneath it")
        return "*." + base
    if "*" in name:
        raise ValueError("a wildcard is only allowed as the leftmost label")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized DNS name") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise ValueError("DNS name must contain at least two labels")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
        ):
            raise ValueError("invalid DNS label")
    return ascii_name


def _safe_slug(value: str) -> str:
    slug = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)
    slug = slug.strip(".-_")[:120]
    if not slug or slug in {".", ".."}:
        raise ValueError("invalid certificate name")
    return slug


def _ensure_within(base: Path, candidate: Path) -> Path:
    base_resolved = base.resolve()
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"path escapes protected directory: {candidate}") from exc
    return resolved


def _validate_zip(zf: zipfile.ZipFile) -> None:
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_FILES:
        raise ValueError("ZIP contains too many entries")
    expanded = 0
    for info in infos:
        if stat.S_ISLNK(info.external_attr >> 16):
            raise ValueError(f"ZIP symlink is not allowed: {info.filename}")
        expanded += int(info.file_size)
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ValueError("ZIP expanded size exceeds the configured limit")
        if info.file_size and info.compress_size == 0:
            raise ValueError("invalid ZIP compression metadata")
        if (
            info.compress_size
            and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise ValueError("ZIP compression ratio exceeds the configured limit")


def _get_le_live_dir() -> Path:
    """Return the live directory inside the configured Let's Encrypt root."""
    return _get_letsencrypt_root_dir() / "live"


def _get_certbot_settings() -> Tuple[str, str, int, str]:
    """Load Certbot settings from vars.yml."""
    cfg = _load_yaml(CONFIG_YAML)
    email = cfg.get("certbot_email") or "admin@example.com"
    cert_key_type = cfg.get("cert_key_type") or "ecdsa"
    try:
        rsa_key_size = int(cfg.get("rsa_key_size") or 3072)
    except (TypeError, ValueError):
        rsa_key_size = 3072
    ecdsa_curve = cfg.get("ecdsa_curve") or "secp256r1"
    return email, cert_key_type, rsa_key_size, ecdsa_curve


# ───────────────────── Certbot execution ─────────────────────


def _dns_profile_path(name: str) -> Path:
    """Path to a profile's credentials file.

    The name is checked against a pattern rather than joined to the path as
    it is: certbot reads this file as root.
    """

    if not DNS_PROFILE_RE.match(str(name or "")):
        raise ValueError("invalid DNS provider profile name")
    return DNS_CREDENTIALS_DIR / f"{name}.ini"


def _run_bounded(
    argv: Sequence[str], *, timeout: float, text: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Run a command; past ``timeout``, stop it and everything it started.

    certbot comes from a snap, and the process a plain subprocess timeout
    kills is `snap run`: the certbot under it lived on, holding its lock. The
    command gets a process group of its own and the whole group is killed. A
    timeout returns TIMED_OUT_RC with what the command printed so far and a
    line saying that it was stopped.
    """

    empty: Any = "" if text else b""
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # Something that left the group still holds the pipes: stop
            # reading rather than wait on it too.
            for stream in (process.stdout, process.stderr):
                with contextlib.suppress(Exception):
                    stream.close()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            stdout, stderr = empty, empty
        note = (
            f"{Path(str(argv[0])).name} did not finish within {int(timeout)} seconds "
            "and was stopped"
        )
        LOG.error("%s: %s", note, " ".join(str(part) for part in argv))
        stdout = stdout or empty
        stderr = stderr or empty
        if text:
            stderr = f"{stderr}\n{note}" if stderr else note
        else:
            stderr = stderr + b"\n" + note.encode() if stderr else note.encode()
        return subprocess.CompletedProcess(process.args, TIMED_OUT_RC, stdout, stderr)


def _propagation_seconds(propagation: Any) -> int:
    """The DNS-01 wait a request asked for, within the allowed range."""

    try:
        seconds = int(propagation) if propagation is not None else DNS_PROPAGATION_DEFAULT
    except (TypeError, ValueError):
        seconds = DNS_PROPAGATION_DEFAULT
    return max(DNS_PROPAGATION_MIN, min(seconds, DNS_PROPAGATION_MAX))


def _certbot_timeout(dns_profile: str, propagation: Any) -> int:
    """certbot's own work, plus the DNS-01 wait it was told to sit out."""

    if not dns_profile:
        return CERTBOT_TIMEOUT_SECONDS
    return CERTBOT_TIMEOUT_SECONDS + _propagation_seconds(propagation)


def _installed_dns_plugins() -> set[str]:
    """Which certbot DNS plugins are actually visible right now."""

    try:
        proc = _run_bounded(
            [str(CERTBOT_BIN), "plugins", "--non-interactive"],
            timeout=CERTBOT_QUICK_TIMEOUT_SECONDS,
        )
    except Exception:  # noqa: BLE001
        return set()
    found: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        entry = line.strip()
        if entry.startswith("* "):
            found.add(entry[2:].strip())
    return found


def list_dns_providers() -> Dict[str, Any]:
    """Profiles and plugin availability. Secrets are never returned."""

    available = _installed_dns_plugins()
    profiles: List[Dict[str, Any]] = []
    if DNS_CREDENTIALS_DIR.is_dir():
        for path in sorted(DNS_CREDENTIALS_DIR.glob("*.ini")):
            name = path.stem
            if not DNS_PROFILE_RE.match(name):
                continue
            provider = ""
            try:
                for line in path.read_text("utf-8").splitlines():
                    if line.startswith("# provider:"):
                        provider = line.split(":", 1)[1].strip()
                        break
            except OSError:
                continue
            profiles.append(
                {
                    "name": name,
                    "provider": provider,
                    "plugin_available": (
                        DNS_PROVIDERS.get(provider, {}).get("plugin") in available
                    ),
                    "updated_ts": int(path.stat().st_mtime),
                }
            )
    return {
        "profiles": profiles,
        "providers": {
            name: {
                "plugin": spec["plugin"],
                "snap": spec["snap"],
                "keys": list(spec["keys"]),
                "available": spec["plugin"] in available,
            }
            for name, spec in DNS_PROVIDERS.items()
        },
    }


def _read_dns_profile(path: Path) -> Dict[str, Any]:
    """A stored profile's provider and values; nothing when there is none."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return {"provider": "", "values": {}}
    provider = ""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("# provider:"):
            provider = line.split(":", 1)[1].strip()
        elif " = " in line and not line.startswith("#"):
            key, value = line.split(" = ", 1)
            values[key.strip()] = value
    return {"provider": provider, "values": values}


def _write_private_file(path: Path, data: bytes) -> None:
    """Replace root-owned credential/metadata files without an open-read gap."""
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _dns_binding_path(lineage: str) -> Path:
    if not lineage or lineage in (".", "..") or Path(lineage).name != lineage:
        raise ValueError("invalid Certbot lineage name")
    return _get_letsencrypt_root_dir() / "easy-ha-proxy-dns" / f"{lineage}.json"



def _renewal_authenticator(conf: Path) -> str:
    # Certbot uses ConfigObj, whose nested [[webroot_map]] sections cannot be
    # read by configparser. Only this scalar in renewalparams is needed.
    match = re.search(r"(?m)^\s*authenticator\s*=\s*([^\s#]+)", conf.read_text(encoding="utf-8"))
    return match[1] if match else ""


def _dns_profile_lineages(profile: str) -> List[str]:
    """Active lineages that need this profile during unattended renewal."""
    root = _get_letsencrypt_root_dir()
    used = []
    for path in sorted((root / "easy-ha-proxy-dns").glob("*.json")):
        conf = root / "renewal" / f"{path.stem}.conf"
        if not conf.is_file():
            continue
        try:
            if _renewal_authenticator(conf) != "dns-route53":
                continue
            binding = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(binding, dict):
                raise ValueError("invalid binding")
        except (OSError, ValueError) as exc:
            # Do not delete credentials while a broken binding makes their
            # ownership impossible to establish safely.
            raise ValueError(f"cannot read DNS renewal binding for {path.stem}") from exc
        if binding.get("profile") == profile:
            used.append(path.stem)
    return used


def _route53_environment(profile: str) -> Dict[str, str]:
    """Give boto one explicit, profile-specific AWS file, never ambient keys.

    Certbot is a classic snap. An absolute file under /etc is available even
    when its service hides /root with ProtectHome=tmpfs; ~/.aws is not. Do not
    put credentials in argv or rely on the snap's choice of HOME.
    """
    path = _dns_profile_path(profile)
    stored = _read_dns_profile(path)
    if stored["provider"] != "route53":
        raise ValueError(f"DNS profile {profile!r} is not a Route53 profile")
    values = stored["values"]
    keys = DNS_PROVIDERS["route53"]["keys"]
    if any(not values.get(key, "").strip() for key in keys):
        raise ValueError("Route53 requires both AWS access key and secret key")
    # Earlier profiles were sectionless Certbot-style INI, which AWS cannot
    # read. Migrate them atomically on first use, retaining their values.
    parser = configparser.RawConfigParser()
    try:
        parser.read_string(path.read_text(encoding="utf-8"))
        valid = parser.has_section("default") and all(
            parser.get("default", key, raw=True) == values[key] for key in keys
        )
    except configparser.Error:
        valid = False
    if not valid:
        lines = ["# provider: route53", "[default]"]
        lines.extend(f"{key} = {values[key]}" for key in keys)
        _write_private_file(path, ("\n".join(lines) + "\n").encode("utf-8"))
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
    env.update({
        "AWS_SHARED_CREDENTIALS_FILE": str(path.resolve()),
        "AWS_PROFILE": "default",
        "AWS_DEFAULT_PROFILE": "default",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_EC2_METADATA_DISABLED": "true",
        "BOTO_CONFIG": "/dev/null",
    })
    return env


def save_dns_provider(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Write a profile's credentials with mode 0600."""

    name = str(payload.get("name") or "").strip().lower()
    provider = str(payload.get("provider") or "").strip().lower()
    if provider not in DNS_PROVIDERS:
        raise ValueError("unsupported DNS provider")
    path = _dns_profile_path(name)

    spec = DNS_PROVIDERS[provider]
    supplied = payload.get("credentials")
    if not isinstance(supplied, dict):
        raise ValueError("credentials must be an object")
    if set(supplied) - set(spec["keys"]):
        raise ValueError("credentials contain an unsupported field")

    # The page sends only the fields that were filled in; an empty one means
    # "unchanged". Writing the file from the sent fields alone dropped every
    # other stored value -- changing an RFC 2136 server erased its TSIG key,
    # and the next renewal failed (F20, 30 October review). For the same
    # provider the stored values stay unless a new one is sent; a change of
    # provider starts afresh, so keys never mix.
    stored = _read_dns_profile(path)
    kept = stored["values"] if stored["provider"] == provider else {}

    if stored["provider"] != provider and _dns_profile_lineages(name):
        raise ValueError("this DNS profile is used for automatic renewal; reissue those lineages first")

    lines = [f"# provider: {provider}"]
    if provider == "route53":
        lines.append("[default]")
    for key in spec["keys"]:
        raw = supplied.get(key)
        if raw is None or str(raw) == "":
            raw = kept.get(key)
        if raw is None or str(raw) == "":
            continue
        value = str(raw)
        if len(value) > DNS_VALUE_MAX:
            raise ValueError(f"{key} exceeds the size limit")
        # A newline would let one value introduce another directive into the
        # credentials file certbot reads as root.
        if any(character in value for character in "\r\n\x00"):
            raise ValueError(f"{key} contains a line break")
        lines.append(f"{key} = {value}")
    if len(lines) == (2 if provider == "route53" else 1):
        raise ValueError("no credentials were supplied")
    if provider == "route53" and len(lines) != 4:
        raise ValueError("Route53 requires both AWS access key and secret key")

    _write_private_file(path, ("\n".join(lines) + "\n").encode("utf-8"))
    LOG.info("Saved DNS provider profile %s (%s)", name, provider)
    return {"name": name, "provider": provider}


def delete_dns_provider(name: str, actor: str = "") -> Dict[str, Any]:
    path = _dns_profile_path(str(name or "").strip().lower())
    used = _dns_profile_lineages(path.stem)
    if used:
        raise ValueError("this DNS profile is used for automatic renewal by " + ", ".join(used))
    existed = path.exists()
    kept = None
    if existed:
        provider = _read_dns_profile(path).get("provider") or ""
        kept = _trash_put(
            "dns_provider", path.stem, [path], actor=actor,
            details={"provider": provider},
        )
    before = _trash_listing([path])
    try:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    except OSError:
        _trash_settle(kept, before, [path])
        raise
    _trash_commit(kept)
    return {"name": path.stem, "deleted": existed, "trash_id": kept}


def _dns_provider_of(name: str) -> str:
    path = _dns_profile_path(name)
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"no DNS provider profile named {path.stem}") from exc
    except OSError as exc:
        # A profile that cannot be read is a configuration problem to report,
        # not an unhandled error to surface as a failed request.
        raise ValueError("the DNS provider profile cannot be read") from exc
    for line in text.splitlines():
        if line.startswith("# provider:"):
            provider = line.split(":", 1)[1].strip()
            if provider in DNS_PROVIDERS:
                return provider
            break
    raise ValueError("the DNS provider profile is unusable")


def _dns_challenge_flags(profile: str, propagation: Any = None) -> List[str]:
    """certbot's arguments for DNS-01. Everything comes from the table, nothing from the request."""

    provider = _dns_provider_of(profile)
    spec = DNS_PROVIDERS[provider]
    plugin = spec["plugin"]
    if plugin not in _installed_dns_plugins():
        raise ValueError(
            f"the {plugin} certbot plugin is not installed; "
            f"install and connect the {spec['snap']} snap first"
        )
    seconds = _propagation_seconds(propagation)

    flags = [f"--{plugin}", "--preferred-challenges", "dns-01"]
    if provider != "route53":
        # Route53 uses the AWS shared credentials file selected in the
        # child environment; its plugin has no credentials-file argument.
        flags.extend([f"--{plugin}-credentials", str(_dns_profile_path(profile))])
    flags.extend([f"--{plugin}-propagation-seconds", str(seconds)])
    return flags


def _run_certbot_for_lineage(
    lineage: str,
    domain: str,
    alt_names: List[str],
    key_type: str,
    email: str,
    rsa_key_size: int,
    ecdsa_curve: str,
    account_id: Optional[str] = None,
    dns_profile: str = "",
    dns_propagation: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue or renew one Certbot lineage.

    With a DNS profile the challenge is DNS-01, which is the only way to get a
    wildcard certificate; without one it stays the existing standalone HTTP-01
    path.
    """
    names = [domain] + [n for n in (alt_names or []) if n]
    san_flags: List[str] = []
    for n in names:
        san_flags.extend(["-d", n])

    wildcard = any(str(n).startswith("*.") for n in names)
    if wildcard and not dns_profile:
        raise ValueError(
            "a wildcard certificate requires DNS-01; select a DNS provider profile"
        )

    if dns_profile:
        challenge_flags = _dns_challenge_flags(dns_profile, dns_propagation)
    else:
        challenge_flags = [
            "--standalone",
            "--http-01-port",
            str(CERTBOT_HTTP_PORT),
            "--http-01-address",
            CERTBOT_HTTP_ADDR,
            "--preferred-challenges",
            "http-01",
        ]

    cmd: List[str] = [
        str(CERTBOT_BIN),
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        *challenge_flags,
        "--key-type",
        key_type,
        "--cert-name",
        lineage,
        "--config-dir",
        str(_get_letsencrypt_root_dir()),
        "--keep-until-expiring",
    ]

    # Certbot creates the first ACME account automatically. Pin an account only
    # when one already exists, which also keeps multi-account installations
    # deterministic.
    if account_id:
        cmd.extend(["--account", account_id])

    if key_type == "rsa":
        cmd.extend(["--rsa-key-size", str(rsa_key_size)])
    elif key_type == "ecdsa":
        cmd.extend(["--elliptic-curve", ecdsa_curve])

    cmd.extend(san_flags)

    if CERTD_DRY_RUN:
        cmd.append("--dry-run")

    LOG.info("Running certbot for lineage %s: %s", lineage, " ".join(cmd))

    env = None
    binding_path = _dns_binding_path(lineage)
    previous_binding = binding_path.read_bytes() if binding_path.exists() else None
    route53 = bool(dns_profile and _dns_provider_of(dns_profile) == "route53")
    if route53:
        env = _route53_environment(dns_profile)
        # Write before issuance so the first unattended renewal cannot run
        # between creation of the lineage and creation of its binding.
        if not CERTD_DRY_RUN:
            _write_private_file(binding_path, json.dumps({"profile": dns_profile}).encode("utf-8"))
    try:
        proc = _run_bounded(cmd, timeout=_certbot_timeout(dns_profile, dns_propagation), env=env)
    except Exception:
        if route53 and not CERTD_DRY_RUN:
            if previous_binding is None:
                binding_path.unlink(missing_ok=True)
            else:
                _write_private_file(binding_path, previous_binding)
        raise
    if not CERTD_DRY_RUN:
        if proc.returncode == 0:
            if not route53 and previous_binding is not None:
                conf = _get_letsencrypt_root_dir() / "renewal" / f"{lineage}.conf"
                # keep-until-expiring can succeed without reconfiguring an
                # existing lineage. Keep its credentials until the actual
                # authenticator has changed, not merely the requested one.
                if conf.is_file() and _renewal_authenticator(conf) not in ("", "dns-route53"):
                    binding_path.unlink(missing_ok=True)
        elif route53:
            if previous_binding is None:
                binding_path.unlink(missing_ok=True)
            else:
                _write_private_file(binding_path, previous_binding)

    return {
        "lineage": lineage,
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "cmd": " ".join(cmd),
    }


def renew_certificates() -> int:
    """The snap timer's runner, preserving each lineage's saved DNS profile.

    Certbot still decides whether each certificate is due and runs its normal
    hooks. Separate invocations are necessary: boto's environment is process
    wide, while two Route53 lineages can belong to different AWS accounts.
    Direct manual Certbot commands keep their normal AWS credential chain.
    """
    failed = False
    root = _get_letsencrypt_root_dir()
    for conf in sorted((root / "renewal").glob("*.conf")):
        try:
            env = None
            binding_path = _dns_binding_path(conf.stem)
            # A direct manual reconfiguration to HTTP/another DNS provider
            # supersedes an old binding without altering that provider's env.
            authenticator = _renewal_authenticator(conf)
            if binding_path.exists() and authenticator == "dns-route53":
                binding = json.loads(binding_path.read_text(encoding="utf-8"))
                env = _route53_environment(binding["profile"])
            command = [str(CERTBOT_BIN), "renew", "--non-interactive", "--quiet",
                       "--cert-name", conf.stem, "--config-dir", str(root),
                       "--no-random-sleep-on-renew"]
            proc = _run_bounded(
                command, timeout=CERTBOT_TIMEOUT_SECONDS + DNS_PROPAGATION_MAX, env=env
            )
            if proc.returncode:
                failed = True
                LOG.error("Certbot renewal failed for %s (rc=%s): %s",
                          conf.stem, proc.returncode, (proc.stderr or "").strip()[:400])
        except Exception as exc:  # pylint: disable=broad-except
            failed = True
            LOG.error("Cannot renew %s: %s", conf.stem, exc)
    return int(failed)


# ───────────────────── X.509 ─────────────────────


def _parse_not_after(not_after: str) -> Optional[datetime]:
    """
    Parses notAfter from ssl._ssl._test_decode_cert.
    Example: 'Jan 15 12:00:00 2026 GMT'
    """
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def _load_cert_info(path: Path) -> Optional[Dict[str, Any]]:
    """
    Reads a certificate and returns a dict:
      - path
      - not_after (datetime)
      - days_left (int)
    """
    try:
        if not path or not path.exists():
            return None
        info = ssl._ssl._test_decode_cert(str(path))
    except Exception:  # noqa: BLE001
        return None

    not_after_str = info.get("notAfter")
    not_after_dt = _parse_not_after(not_after_str)
    if not not_after_dt:
        return None

    now = datetime.now(timezone.utc)
    days_left = (not_after_dt - now).days
    not_before_dt = _parse_not_after(info.get("notBefore") or "")
    lifetime_days = (
        (not_after_dt - not_before_dt).days if not_before_dt else None
    )

    return {
        "path": str(path),
        "not_after": not_after_dt,
        "days_left": days_left,
        "lifetime_days": lifetime_days,
        "warn_days": cert_warn_days(lifetime_days),
    }


def _fmt_date(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _load_first_cert_from_pem(path: Path) -> Optional[x509.Certificate]:
    """
    Reads the first certificate of a PEM file.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None

    # the simple case: one certificate
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except Exception:
        pass

    # several PEM blocks: take the first BEGIN CERTIFICATE
    try:
        blocks: List[bytes] = []
        current: List[bytes] = []
        inside = False
        for line in data.splitlines(keepends=True):
            if b"BEGIN CERTIFICATE" in line:
                inside = True
                current = [line]
            elif b"END CERTIFICATE" in line and inside:
                current.append(line)
                blocks.append(b"".join(current))
                inside = False
            elif inside:
                current.append(line)

        if not blocks:
            return None

        return x509.load_pem_x509_certificate(blocks[0], default_backend())
    except Exception:
        return None


def _get_cert_dns_names(cert: x509.Certificate) -> List[str]:
    """
    Returns every DNS name in the certificate: the SANs and the CN.
    """
    names: set[str] = set()

    # SAN
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        for dns in san.value.get_values_for_type(x509.DNSName):
            names.add(dns.lower())
    except x509.ExtensionNotFound:
        pass

    # CN
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if attr.value:
                names.add(attr.value.lower())
    except Exception:
        pass

    return list(names)
