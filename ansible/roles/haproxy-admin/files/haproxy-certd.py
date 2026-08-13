#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
haproxy-certd.py — автономный root-сервис для работы с сертификатами
HAProxy и Let's Encrypt.

Отвечает по HTTP через Unix-сокет
и реализует API:

  POST /api/v1/certs/status
  POST /api/v1/certs/issue
  POST /api/v1/certs/backup
  POST /api/v1/certs/restore
  POST /api/v1/certs/upload   (multipart/form-data)
  POST /api/v1/certs/delete-haproxy
  POST /api/v1/certs/delete-le
  GET  /api/v1/certs/list

Форматы запросов/ответов совместимы с прежним Flask-приложением.
"""

from __future__ import annotations

import base64
import cgi
import contextlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import socketserver
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml  # type: ignore
from cryptography import x509  # type: ignore
from cryptography.exceptions import InvalidSignature  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # type: ignore
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # type: ignore

# ───────────────────── конфигурация ─────────────────────

LOG = logging.getLogger("haproxy-certd")

# Путь к Unix-сокету управления
SOCKET_PATH = os.environ.get(
    "HAPROXY_CERTD_SOCKET", "/run/easy-ha-proxy/haproxy-certd.sock"
)
GROUP_NAME = os.environ.get("HAPROXY_CERTD_SOCKET_GROUP", "hadmin")

# Путь к vars.yml (читаем certbot_email, haproxy_certs_dir и пр.)
CONFIG_YAML = Path(
    os.environ.get("HAPROXY_VARS_YAML", "/opt/haproxy-admin/config/vars.yml")
)

# Где лежит certbot
CERTBOT_BIN = Path(os.environ.get("CERTBOT_BIN", "/snap/bin/certbot"))

# HTTP–challenge от certbot
CERTBOT_HTTP_PORT = 8000
CERTBOT_HTTP_ADDR = "0.0.0.0"

# --- DNS-01 -----------------------------------------------------------------
#
# Certbot здесь ставится snap'ом, поэтому и плагины — тоже snap'ы, версия в
# версию с самим certbot: `snap install certbot-dns-<provider>`,
# `snap set certbot trust-plugin-with-root=ok`,
# `snap connect certbot:plugin certbot-dns-<provider>`. Пакетов apt тут нет.
#
# Провайдер и имена его ключей — фиксированный набор. Из браузера приходит
# только имя профиля и значения; ни имя плагина, ни аргументы certbot из
# запроса не берутся никогда.
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

# Скрипт, который пересобирает PEM для HAProxy и делает reload
HAPROXY_PEMS_SCRIPT = Path(
    os.environ.get(
        "HAPROXY_PEMS_SCRIPT",
        "/etc/letsencrypt/renewal-hooks/deploy/905-haproxy-pems-reload.sh",
    )
)

# Дефолтные пути
DEFAULT_HAPROXY_CERTS_DIR = Path("/etc/haproxy/certs")
DEFAULT_LETSENCRYPT_ROOT_DIR = Path("/etc/letsencrypt")
DEFAULT_CA_ROOT_DIR = Path("/etc/haproxy/certificate-authorities")

# Предупреждать, если до конца срока действия меньше N дней
CERT_WARN_DAYS = 30


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
        )
    except Exception:  # pylint: disable=broad-except
        LOG.debug("alert reporting failed", exc_info=True)

# Dry-run: не трогаем файлы, certbot запускаем с --dry-run
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


# ───────────────────── утилиты работы с YAML ─────────────────────


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Безопасно читаем YAML-файл. Если файла нет — {}.
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
        # если в корне не dict — оборачиваем
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
    """Путь к файлу учётных данных профиля.

    Имя сверяется с шаблоном, а не склеивается с путём как есть: этот файл
    отдаётся certbot от root.
    """

    if not DNS_PROFILE_RE.match(str(name or "")):
        raise ValueError("invalid DNS provider profile name")
    return DNS_CREDENTIALS_DIR / f"{name}.ini"


def _installed_dns_plugins() -> set[str]:
    """Какие DNS-плагины certbot реально видит прямо сейчас."""

    try:
        proc = subprocess.run(
            [str(CERTBOT_BIN), "plugins", "--non-interactive"],
            text=True,
            capture_output=True,
            timeout=60,
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
    """Профили и доступность плагинов. Секреты не возвращаются никогда."""

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


def save_dns_provider(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Записать учётные данные профиля с правами 0600."""

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

    lines = [f"# provider: {provider}"]
    for key in spec["keys"]:
        raw = supplied.get(key)
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
    if len(lines) == 1:
        raise ValueError("no credentials were supplied")

    DNS_CREDENTIALS_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(DNS_CREDENTIALS_DIR, 0o700)
    temporary = DNS_CREDENTIALS_DIR / f".{name}.{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    LOG.info("Saved DNS provider profile %s (%s)", name, provider)
    return {"name": name, "provider": provider}


def delete_dns_provider(name: str) -> Dict[str, Any]:
    path = _dns_profile_path(str(name or "").strip().lower())
    existed = path.exists()
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    return {"name": path.stem, "deleted": existed}


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
    """Аргументы certbot для DNS-01. Всё берётся из таблицы, не из запроса."""

    provider = _dns_provider_of(profile)
    spec = DNS_PROVIDERS[provider]
    plugin = spec["plugin"]
    if plugin not in _installed_dns_plugins():
        raise ValueError(
            f"the {plugin} certbot plugin is not installed; "
            f"install and connect the {spec['snap']} snap first"
        )
    try:
        seconds = int(propagation) if propagation is not None else DNS_PROPAGATION_DEFAULT
    except (TypeError, ValueError):
        seconds = DNS_PROPAGATION_DEFAULT
    seconds = max(DNS_PROPAGATION_MIN, min(seconds, DNS_PROPAGATION_MAX))

    flags = [f"--{plugin}", "--preferred-challenges", "dns-01"]
    if provider != "route53":
        # route53 reads the environment or the instance role; the others take
        # a credentials file.
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

    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    return {
        "lineage": lineage,
        "rc": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "cmd": " ".join(cmd),
    }


# ───────────────────── работа с X.509 ─────────────────────


def _parse_not_after(not_after: str) -> Optional[datetime]:
    """
    Парсит поле notAfter из ssl._ssl._test_decode_cert.
    Пример строки: 'Jan 15 12:00:00 2026 GMT'
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
    Читает сертификат и возвращает dict:
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

    return {
        "path": str(path),
        "not_after": not_after_dt,
        "days_left": days_left,
    }


def _fmt_date(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _load_first_cert_from_pem(path: Path) -> Optional[x509.Certificate]:
    """
    Читает первый сертификат из PEM-файла.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None

    # простой случай — один сертификат
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except Exception:
        pass

    # несколько PEM-блоков — берём первый BEGIN CERTIFICATE
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
    Возвращает все DNS-имена из сертификата: SAN + CN.
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
        if host.endswith(suffix) and host.count(".") > suffix.count("."):
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
    os.chmod(path, 0o640)
    try:
        import grp
        import pwd

        os.chown(path, pwd.getpwnam("root").pw_uid, grp.getgrnam("haproxy").gr_gid)
    except Exception:  # pragma: no cover - depends on system accounts
        pass


def _reload_haproxy() -> Tuple[Optional[int], str, str]:
    if CERTD_DRY_RUN:
        return None, "", ""
    if HAPROXY_BIN.is_file() and HAPROXY_CFG.is_file():
        check = subprocess.run(
            [str(HAPROXY_BIN), "-c", "-f", str(HAPROXY_CFG)],
            text=True,
            capture_output=True,
        )
        if check.returncode != 0:
            return check.returncode, check.stdout, check.stderr
    try:
        reload_result = subprocess.run(
            ["systemctl", "reload", "haproxy"],
            text=True,
            capture_output=True,
        )
        return reload_result.returncode, reload_result.stdout, reload_result.stderr
    except Exception as exc:  # noqa: BLE001
        return -1, "", f"systemctl reload haproxy failed: {exc}"


def _activate_server_pem(
    destination: Path, data: bytes
) -> Tuple[bool, Optional[int], str, str]:
    """Install a PEM atomically and roll it back when HAProxy rejects it."""
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
        result = subprocess.run(command, text=True, capture_output=True)
    details = (result.stderr or result.stdout or "certificate chain verification failed").strip()
    return result.returncode == 0, details


# ───────────────────── поиск файлов сертификатов ─────────────────────


def _find_cert_file_by_domain_in_dir(base_dir: Path, domain: str) -> Optional[Path]:
    """
    Ищет подходящий PEM в каталоге base_dir.
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
    fullchain.pem для домена в live:
      1) <domain>/fullchain.pem
      2) <domain>-ecdsa/fullchain.pem
      3) <domain>-rsa/fullchain.pem
      4) fallback по содержимому.
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


# ───────────────────── статус сертификата по домену ─────────────────────


def get_cert_status_for_domain(domain: str) -> Dict[str, Any]:
    """
    Статус сертификата по домену.
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

    # нет ничего
    if not has_hap and not has_le:
        result["state"] = "missing"
        result["short"] = "No certificate"
        result["tooltip"] = (
            "No HAProxy certificate and no Let's Encrypt certificate "
            "were found for this domain."
        )
        return result

    # есть LE, но нет HAProxy
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

    # есть HAProxy, но нет LE
    if has_hap and not has_le:
        days = hap_info["days_left"]
        if days < 0:
            state = "expired"
            short = "Expired"
        elif days <= CERT_WARN_DAYS:
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

    # есть оба — берём минимальный срок
    days_left = min(hap_info["days_left"], le_info["days_left"])
    result["haproxy_days_left"] = hap_info["days_left"]
    result["le_days_left"] = le_info["days_left"]

    if days_left < 0:
        result["state"] = "expired"
        result["short"] = "Expired"
        result["tooltip"] = "The certificate has expired and must be renewed."
    elif days_left <= CERT_WARN_DAYS:
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


# ───────────────────── helper для списка ─────────────────────


def _build_cert_item_for_list(path: Path) -> Optional[Dict[str, Any]]:
    """
    Структура для UI по одному PEM-файлу.
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
    elif days_left <= CERT_WARN_DAYS:
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


# ───────────────────── реализация эндпоинтов ─────────────────────


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
        removed = delete_dns_provider(body.get("name"))
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    return 200, {"ok": True, **removed}


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
        proc = subprocess.run(
            [str(HAPROXY_PEMS_SCRIPT)],
            text=True,
            capture_output=True,
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
    expiry_watch = CertificateExpiryWatch()
    expiry_watch.start()

    ca_root = _prepare_ca_root()
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
        swapped = False
        try:
            _write_internal_ca_material(staged_dir, new_cert, new_key)
            internal_dir.replace(rollback_dir)
            old_moved = True
            staged_dir.replace(internal_dir)
            swapped = True
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
        shutil.rmtree(key_path.parent)
    return 200, {"ok": True, "message": "Internal certificate authority deleted."}


def _uploaded_file(form: "cgi.FieldStorage", field: str) -> Any:
    """Return the attached file for ``field``, or None.

    A cgi.FieldStorage part that holds a file answers neither ``bool()`` nor
    ``in`` -- both raise TypeError, because its ``list`` is None. So the
    obvious way to ask whether the operator attached anything is the one way
    that cannot be used, and asking it crashed the request handler instead of
    returning an error.
    """
    try:
        item = form[field]
    except (KeyError, TypeError):
        return None
    if isinstance(item, list):
        item = item[0] if item else None
    if item is None or not getattr(item, "filename", ""):
        return None
    return item


def handle_external_ca_upload_form(
    form: "cgi.FieldStorage",
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
    ca_root = _prepare_ca_root()
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
        ca_root = _prepare_ca_root()
        ca_id = _safe_slug(str(body.get("ca_id") or "")).lower()
        external_dir = _prepare_ca_subdir("external")
        path = _ensure_within(external_dir, external_dir / f"{ca_id}.pem")
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    if not path.is_file():
        return 404, {"ok": False, "error": "certificate authority was not found"}
    path.unlink()
    # Leaving a deleted authority in the client-auth list would keep its names
    # in an issuers file that nothing can regenerate.
    trusted = _load_client_auth_ids()
    if ca_id in trusted:
        remaining = [value for value in trusted if value != ca_id]
        status, response = handle_ca_client_auth({"ids": remaining})
        if not response.get("ok"):
            return status, response
    return 200, {"ok": True, "message": f"External certificate authority deleted: {ca_id}"}


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


def handle_certs_inspect_form(form: "cgi.FieldStorage") -> Tuple[int, Dict[str, Any]]:
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


def handle_certs_import_form(form: "cgi.FieldStorage") -> Tuple[int, Dict[str, Any]]:
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
            target_base = hap_dir
            is_haproxy_cert = True
        elif top == le_top:
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
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

            if is_haproxy_cert:
                try:
                    os.chmod(target, 0o640)
                    try:
                        import pwd
                        import grp

                        uid = pwd.getpwnam("root").pw_uid
                        gid = grp.getgrnam("haproxy").gr_gid
                        os.chown(target, uid, gid)
                    except Exception:
                        pass
                except Exception:
                    pass
            elif target_base == ca_root:
                os.chmod(target, 0o600 if target.name == "ca.key" else 0o644)
            else:
                os.chmod(target, 0o600)

            written_files += 1
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
        proc = subprocess.run(
            [str(HAPROXY_PEMS_SCRIPT)],
            text=True,
            capture_output=True,
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

def handle_certs_upload_form(form: "cgi.FieldStorage") -> Tuple[int, Dict[str, Any]]:
    """
    Обработка загрузки PEM через multipart/form-data.
    Ожидает поля:
      - cert_file (файл .pem)
      - site_name (опц.)
      - domain    (опц.)
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
            ca_root = _prepare_ca_root()
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

    try:
        target.unlink()
    except OSError as exc:
        return 200, {"ok": False, "error": f"failed to delete {target}: {exc}"}

    return 200, {
        "ok": True,
        "message": f"HAProxy certificate deleted: {target}",
        "path": str(target),
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
        "--non-interactive",
    ]

    LOG.info("Running certbot delete: %s", " ".join(cmd))

    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    rc = proc.returncode
    ok = rc == 0

    return 200, {
        "ok": ok,
        "rc": rc,
        "cmd": " ".join(cmd),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


# ───────────────────── HTTP-сервер поверх Unix-сокета ─────────────────────


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


class CertdHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        """Переопределяем, чтобы писать в логгер, а не в stderr."""
        LOG.info("%s - %s", self.client_address, fmt % args)

    # служебные методы

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
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    # обработчики HTTP

    def do_POST(self) -> None:  # noqa: N802
        path = self.path

        # Certificate and CA imports use multipart/form-data.
        if path in (
            "/api/v1/certs/upload",
            "/api/v1/certs/ca/upload",
            "/api/v1/certs/inspect",
            "/api/v1/certs/import",
        ):
            ctype, pdict = cgi.parse_header(
                self.headers.get("Content-Type", ""))
            if ctype != "multipart/form-data":
                return self._send_json(
                    200,
                    {"ok": False, "error": "Content-Type must be multipart/form-data"},
                )

            if "boundary" not in pdict:
                return self._send_json(
                    200,
                    {"ok": False, "error": "multipart boundary missing"},
                )

            pdict["boundary"] = pdict["boundary"].encode("utf-8")
            length_str = self.headers.get("Content-Length") or "0"
            try:
                pdict["CONTENT-LENGTH"] = int(length_str)
            except ValueError:
                pdict["CONTENT-LENGTH"] = 0
            if (
                pdict["CONTENT-LENGTH"] <= 0
                or pdict["CONTENT-LENGTH"] > MAX_REQUEST_BYTES
            ):
                return self._send_json(
                    413, {"ok": False, "error": "upload is too large"}
                )

            # Everything below is wrapped, unlike the JSON branch further
            # down, which always was. An exception escaping here does not
            # reach the caller as an error: it unwinds out of the handler and
            # the connection closes unanswered, so the browser is told only
            # that the remote end hung up. An upload that fails must say why.
            try:
                form = cgi.FieldStorage(  # type: ignore[arg-type]
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        "REQUEST_METHOD": "POST",
                        "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    },
                    keep_blank_values=True,
                )

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


class CertificateExpiryWatch(threading.Thread):
    def __init__(self) -> None:
        super().__init__(name="cert-expiry-watch", daemon=True)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

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
            if self._stop.wait(CERT_WATCH_INTERVAL_SECONDS):
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
        for path in entries:
            info = _load_cert_info(path)
            if not info:
                continue
            days = int(info["days_left"])
            domain = path.stem
            expiring = days <= CERT_WARN_DAYS
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
                detail=f"Not after: {info['not_after']}",
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

    # удаляем старый сокет, если остался
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except OSError as exc:
        LOG.error("Failed to unlink old socket %s: %s", SOCKET_PATH, exc)

    # создаём сервер
    server = UnixHTTPServer(SOCKET_PATH, CertdHandler)

    # права на сокет: root:haproxy, 660
    try:
        import pwd
        import grp

        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(SOCKET_PATH, uid, gid)
    except Exception:
        pass
    try:
        os.chmod(SOCKET_PATH, 0o660)
    except Exception:
        pass

    try:
        LOG.info("haproxy-certd is listening on unix://%s", SOCKET_PATH)
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Interrupted by user")
    finally:
        try:
            server.server_close()
        finally:
            try:
                if os.path.exists(SOCKET_PATH):
                    os.unlink(SOCKET_PATH)
            except OSError:
                pass


if __name__ == "__main__":
    main()
