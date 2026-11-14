"""Local IP-to-country lookups backed by a DB-IP Country Lite MMDB file."""

from __future__ import annotations

import atexit
from ipaddress import ip_address
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any

import maxminddb


logger = logging.getLogger("haproxy-admin")

COUNTRY_DATABASE_FILE = Path(
    os.environ.get(
        "HAPROXY_ADMIN_GEOIP_DB",
        "/etc/haproxy/geoip/current/dbip-country-lite.mmdb",
    )
)
COUNTRY_DATABASE_STAT_INTERVAL = max(
    1.0,
    float(os.environ.get("HAPROXY_ADMIN_GEOIP_STAT_INTERVAL", "5")),
)

_READER_LOCK = threading.RLock()
_READER: Any | None = None
_READER_SIGNATURE: tuple[int, int, int, int] | None = None
_LAST_STAT_CHECK = 0.0
_LAST_PROBLEM: tuple[str, float] | None = None
_PROBLEM_LOG_INTERVAL = 60.0


def _file_signature(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _log_problem(message: str) -> None:
    global _LAST_PROBLEM
    now = time.monotonic()
    if _LAST_PROBLEM is None or (
        _LAST_PROBLEM[0] != message
        or now - _LAST_PROBLEM[1] >= _PROBLEM_LOG_INTERVAL
    ):
        logger.warning(message)
        _LAST_PROBLEM = (message, now)


def _reload_reader(*, force: bool = False):
    """Open a new reader after an atomic database replacement."""
    global _LAST_STAT_CHECK, _READER, _READER_SIGNATURE, _LAST_PROBLEM

    now = time.monotonic()
    with _READER_LOCK:
        if not force and now - _LAST_STAT_CHECK < COUNTRY_DATABASE_STAT_INTERVAL:
            return _READER
        _LAST_STAT_CHECK = now

        try:
            signature = _file_signature(COUNTRY_DATABASE_FILE)
        except OSError as exc:
            _log_problem(
                f"Local GeoIP database is unavailable at "
                f"{COUNTRY_DATABASE_FILE}: {exc}"
            )
            return _READER

        if _READER is not None and signature == _READER_SIGNATURE:
            return _READER

        try:
            candidate = maxminddb.open_database(str(COUNTRY_DATABASE_FILE))
            # Reading metadata forces format validation before replacing a
            # still-working reader.
            candidate.metadata()
        except Exception as exc:  # maxminddb exposes multiple reader errors
            _log_problem(
                f"Cannot open local GeoIP database {COUNTRY_DATABASE_FILE}: {exc}"
            )
            return _READER

        previous = _READER
        _READER = candidate
        _READER_SIGNATURE = signature
        _LAST_PROBLEM = None
        if previous is not None:
            try:
                previous.close()
            except Exception:
                logger.debug("Failed to close the previous GeoIP reader", exc_info=True)

        logger.info("Loaded local GeoIP database from %s", COUNTRY_DATABASE_FILE)
        return _READER


def init_cache() -> None:
    """Initialize the process-local MMDB reader.

    The historical function name is kept to avoid breaking callers while the
    former external-API JSON cache is intentionally no longer used.
    """
    _reload_reader(force=True)


def close_country_database() -> None:
    global _READER, _READER_SIGNATURE
    with _READER_LOCK:
        reader = _READER
        _READER = None
        _READER_SIGNATURE = None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                logger.debug("Failed to close the GeoIP reader", exc_info=True)


def get_country_code(ip: str) -> str:
    """Return an uppercase ISO 3166-1 alpha-2 code from the local database."""
    try:
        address = ip_address(str(ip).strip())
    except ValueError:
        return "??"

    if getattr(address, "ipv4_mapped", None) is not None:
        address = address.ipv4_mapped
    if not address.is_global:
        return "??"

    with _READER_LOCK:
        reader = _reload_reader()
        if reader is None:
            return "??"
        try:
            # Keep the lock while reading so another request cannot close the
            # old mmap reader during an atomic database replacement.
            record = reader.get(str(address)) or {}
            country = record.get("country") if isinstance(record, dict) else None
            code = country.get("iso_code", "") if isinstance(country, dict) else ""
            code = str(code).strip().upper()
            return code if len(code) == 2 and code.isalpha() else "??"
        except Exception as exc:
            _log_problem(f"Local GeoIP lookup failed for {address}: {exc}")
            return "??"


atexit.register(close_country_database)
