#!/usr/bin/env python3
"""Atomically update DB-IP Country Lite and derived HAProxy country ACLs."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterable
import urllib.error
import urllib.request

import maxminddb
import yaml


DATABASE_NAME = "dbip-country-lite.mmdb"
ALLOWED_NAME = "allowed.geo"
STATE_NAME = "state.json"
RELEASE_FORMAT_VERSION = 1
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_SELECTION_BYTES = 16 * 1024
MAX_CONFIG_TRANSACTION_BYTES = 20 * 1024 * 1024
MIN_DATABASE_NODES = 10_000
CONFIG_TRANSACTION_ACTIVE_STATES = {
    "prepared",
    "pending_confirmation",
    "rolling_back",
    "rollback_failed",
}
CONTROL_PLANE_ACL = re.compile(
    r"^\s*acl\s+(host_admin|host_authelia)\s+hdr\(host\)\s+-i\s+(.+?)\s*$",
    re.MULTILINE,
)
# A legacy HAProxy configuration can contain host_admin/host_authelia without
# the local-only authentication bypass used by the guarded reload probe. Do not
# send the readiness request unless all markers from the current template are
# present; otherwise an upgrade from an old image would fail before the new
# HAProxy configuration and application are deployed.
CONTROL_PLANE_PROBE_MARKERS = (
    re.compile(
        r"^\s*acl\s+local_control_plane_probe\s+src\s+127\.0\.0\.1\s*$",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*acl\s+admin_control_plane_probe_path\s+path\s+-i\s+"
        r"/api/control-plane-health\s*$",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*acl\s+admin_control_plane_probe\s+"
        r"var\(txn\.admin_control_plane_probe\)\s+-m\s+bool\s*$",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*http-request\s+set-header\s+Remote-User\s+"
        r"easy-ha-proxy-healthcheck\s+if\s+host_admin\s+"
        r"admin_control_plane_probe\s*$",
        re.MULTILINE,
    ),
)
CONTROL_PLANE_PATHS = {
    "host_admin": ("admin", "/api/control-plane-health"),
    "host_authelia": ("authelia", "/api/health"),
}


class GeoIPUpdateError(RuntimeError):
    """An expected failure that must leave the active release unchanged."""


def log(message: str) -> None:
    print(f"[easy-ha-proxy-geoip] {message}", flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_matches_sha256(path: Path, expected: Any) -> bool:
    value = str(expected or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        return False
    try:
        return sha256_file(path) == value
    except OSError:
        return False


def release_payload_matches(
    release: Path, database_sha256: str, allowed_sha256: str
) -> bool:
    state = read_state(release / STATE_NAME)
    return (
        state.get("release_format_version") == RELEASE_FORMAT_VERSION
        and str(state.get("database_sha256") or "").lower() == database_sha256
        and str(state.get("allowed_sha256") or "").lower() == allowed_sha256
        and file_matches_sha256(release / DATABASE_NAME, database_sha256)
        and file_matches_sha256(release / ALLOWED_NAME, allowed_sha256)
    )


def normalize_countries(values: Iterable[str]) -> tuple[str, ...]:
    countries: set[str] = set()
    for raw in values:
        for value in str(raw).split(","):
            code = value.strip().upper()
            if not code:
                continue
            if not re.fullmatch(r"[A-Z]{2}", code):
                raise GeoIPUpdateError(f"invalid ISO country code: {value!r}")
            countries.add(code)
    return tuple(sorted(countries))


def load_selection(path: Path) -> tuple[tuple[str, ...], bool]:
    """Load the root-managed runtime selection without following symlinks.

    The JSON file is intentionally much smaller and simpler than ``vars.yml``.
    It is the only mutable input accepted by the privileged periodic updater.
    """
    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise GeoIPUpdateError(f"GeoIP selection file is missing: {path}") from exc
    if path.is_symlink() or not path.is_file():
        raise GeoIPUpdateError("GeoIP selection must be a regular file")
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_SELECTION_BYTES:
        raise GeoIPUpdateError("GeoIP selection has an invalid size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GeoIPUpdateError(f"cannot read GeoIP selection: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "version",
        "countries",
        "access_filter_enabled",
    }:
        raise GeoIPUpdateError("GeoIP selection has an invalid format")
    if payload.get("version") != 1:
        raise GeoIPUpdateError("unsupported GeoIP selection version")
    countries = payload.get("countries")
    enabled = payload.get("access_filter_enabled")
    if not isinstance(countries, list) or not all(
        isinstance(value, str) for value in countries
    ):
        raise GeoIPUpdateError("GeoIP selection countries must be a list of strings")
    if not isinstance(enabled, bool):
        raise GeoIPUpdateError("GeoIP selection access_filter_enabled must be boolean")
    return normalize_countries(countries), enabled


def verify_config_transaction_access(
    state_path: Path | None,
    transaction_id: str,
) -> None:
    """Keep timer/manual updates out of a confirmable HAProxy transaction."""
    if state_path is None:
        return
    try:
        state_stat = state_path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
        raise GeoIPUpdateError("HAProxy config transaction state is unsafe")
    if state_stat.st_size <= 0 or state_stat.st_size > MAX_CONFIG_TRANSACTION_BYTES:
        raise GeoIPUpdateError("HAProxy config transaction state has an invalid size")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GeoIPUpdateError("HAProxy config transaction state is invalid") from exc
    if not isinstance(state, dict):
        raise GeoIPUpdateError("HAProxy config transaction state is invalid")
    if state.get("state") not in CONFIG_TRANSACTION_ACTIVE_STATES:
        return
    expected = str(state.get("transaction_id") or "")
    supplied = str(transaction_id or "")
    if expected and supplied and expected == supplied:
        return
    raise GeoIPUpdateError(
        "a HAProxy configuration transaction is active; GeoIP update deferred"
    )


def _read_regular_file(path: Path, maximum: int) -> bytes:
    directory_fd = _open_managed_directory(path.parent)
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            file_fd = os.open(path.name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return b""
        except OSError as exc:
            raise GeoIPUpdateError(f"cannot safely open managed file {path}: {exc}") from exc
        try:
            file_stat = os.fstat(file_fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise GeoIPUpdateError(f"managed file is not a regular file: {path}")
            if file_stat.st_size < 0 or file_stat.st_size > maximum:
                raise GeoIPUpdateError(f"managed file has an invalid size: {path}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise GeoIPUpdateError(f"managed file has an invalid size: {path}")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


def _open_managed_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise GeoIPUpdateError(f"managed directory is unavailable or unsafe: {path}") from exc


def _atomic_write_managed(path: Path, content: bytes, default_mode: int) -> None:
    directory_fd = _open_managed_directory(path.parent)
    current = None
    target_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        target_flags |= os.O_NOFOLLOW
    try:
        try:
            target_fd = os.open(path.name, target_flags, dir_fd=directory_fd)
        except FileNotFoundError:
            target_fd = None
        except OSError as exc:
            raise GeoIPUpdateError(f"managed file is unavailable or unsafe: {path}") from exc
        if target_fd is not None:
            try:
                current = os.fstat(target_fd)
                if not stat.S_ISREG(current.st_mode):
                    raise GeoIPUpdateError(f"managed file is not a regular file: {path}")
            finally:
                os.close(target_fd)

        temporary = f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temporary_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            view = memoryview(content)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
            os.fsync(temporary_fd)
            os.fchmod(
                temporary_fd,
                stat.S_IMODE(current.st_mode) if current is not None else default_mode,
            )
            if current is not None:
                try:
                    os.fchown(temporary_fd, current.st_uid, current.st_gid)
                except PermissionError:
                    if os.geteuid() == 0:
                        raise
        finally:
            os.close(temporary_fd)
        try:
            os.replace(
                temporary,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        except Exception:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            raise
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _restore_managed(path: Path, content: bytes, default_mode: int) -> None:
    if content:
        _atomic_write_managed(path, content, default_mode)
    else:
        directory_fd = _open_managed_directory(path.parent)
        try:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def configure_selection(args: argparse.Namespace) -> None:
    """Transactionally update the runtime country selection and ``vars.yml``.

    The HAProxy enable/mode switches are deliberately read-only here. They
    still require the guarded HAProxy configuration apply workflow.
    """
    selection_path = args.selection_file
    vars_path = args.vars_file
    if selection_path is None or vars_path is None:
        raise GeoIPUpdateError(
            "--selection-file and --vars-file are required for configuration"
        )
    countries = normalize_countries(args.country)
    vars_directory_fd = _open_managed_directory(vars_path.parent)
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    try:
        vars_lock_fd = os.open(
            ".vars.yml.lock", lock_flags, 0o640, dir_fd=vars_directory_fd
        )
    except OSError as exc:
        os.close(vars_directory_fd)
        raise GeoIPUpdateError("cannot safely open the vars.yml lock") from exc
    os.close(vars_directory_fd)

    with os.fdopen(vars_lock_fd, "a+b") as vars_lock:
        fcntl.flock(vars_lock.fileno(), fcntl.LOCK_EX)
        old_vars = _read_regular_file(vars_path, 2 * 1024 * 1024)
        old_selection = _read_regular_file(selection_path, MAX_SELECTION_BYTES)
        if not old_vars:
            raise GeoIPUpdateError(f"runtime vars.yml is missing or empty: {vars_path}")
        try:
            values = yaml.safe_load(old_vars.decode("utf-8")) or {}
        except (UnicodeError, yaml.YAMLError) as exc:
            raise GeoIPUpdateError(f"runtime vars.yml is invalid: {exc}") from exc
        if not isinstance(values, dict):
            raise GeoIPUpdateError("runtime vars.yml root must be a mapping")
        enabled = values.get("enable_geoip", False)
        if not isinstance(enabled, bool):
            raise GeoIPUpdateError("enable_geoip in runtime vars.yml must be boolean")
        previous_countries = values.get("geoip_country_codes") or []
        if not isinstance(previous_countries, list) or not all(
            isinstance(value, str) for value in previous_countries
        ):
            raise GeoIPUpdateError("geoip_country_codes in runtime vars.yml must be a list")
        previous_countries = list(normalize_countries(previous_countries))
        if not old_selection:
            old_selection = (
                json.dumps(
                    {
                        "version": 1,
                        "countries": previous_countries,
                        "access_filter_enabled": enabled,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        if enabled and not countries:
            raise GeoIPUpdateError(
                "at least one country is required while global GeoIP filtering is enabled"
            )

        values["geoip_country_codes"] = list(countries)
        new_vars = yaml.safe_dump(
            values,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=1000,
        ).encode("utf-8")
        selection = {
            "version": 1,
            "countries": list(countries),
            "access_filter_enabled": enabled,
        }
        new_selection = (
            json.dumps(selection, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        with update_lock(args.directory.resolve()):
            try:
                _atomic_write_managed(vars_path, new_vars, 0o640)
                _atomic_write_managed(selection_path, new_selection, 0o644)
                update(args, lock_held=True)
            except Exception as exc:  # noqa: BLE001
                rollback_errors: list[str] = []
                try:
                    _restore_managed(vars_path, old_vars, 0o640)
                except Exception as restore_exc:  # noqa: BLE001
                    rollback_errors.append(f"vars.yml restore failed: {restore_exc}")
                try:
                    _restore_managed(selection_path, old_selection, 0o644)
                except Exception as restore_exc:  # noqa: BLE001
                    rollback_errors.append(f"selection restore failed: {restore_exc}")
                if not rollback_errors and old_selection:
                    try:
                        update(args, lock_held=True)
                    except Exception as restore_exc:  # noqa: BLE001
                        rollback_errors.append(f"active ACL restore failed: {restore_exc}")
                detail = f"GeoIP selection update failed: {exc}"
                if rollback_errors:
                    detail += "; rollback incomplete: " + "; ".join(rollback_errors)
                else:
                    detail += "; previous selection and active ACL were restored"
                raise GeoIPUpdateError(detail) from exc


def month_candidates(now: datetime, count: int = 3) -> list[str]:
    year = now.year
    month = now.month
    result: list[str] = []
    for _ in range(max(1, count)):
        result.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return result


def read_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def active_release(directory: Path) -> Path | None:
    current = directory / "current"
    try:
        resolved = current.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    releases = (directory / "releases").resolve()
    try:
        resolved.relative_to(releases)
    except ValueError:
        raise GeoIPUpdateError("current GeoIP release points outside releases/")
    return resolved


def validate_database(path: Path):
    if not path.is_file() or path.stat().st_size <= 0:
        raise GeoIPUpdateError(f"GeoIP database is missing or empty: {path}")
    try:
        # MODE_AUTO uses the fast native reader when its wheel is available
        # and safely falls back to the pure mmap implementation otherwise.
        reader = maxminddb.open_database(str(path), mode=maxminddb.MODE_AUTO)
        metadata = reader.metadata()
    except Exception as exc:
        raise GeoIPUpdateError(f"invalid MMDB database {path}: {exc}") from exc
    database_type = str(getattr(metadata, "database_type", ""))
    node_count = int(getattr(metadata, "node_count", 0) or 0)
    if "country" not in database_type.lower() or node_count < MIN_DATABASE_NODES:
        reader.close()
        raise GeoIPUpdateError(
            f"unexpected MMDB metadata: type={database_type!r}, nodes={node_count}"
        )
    return reader, metadata


def download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "easy-ha-proxy-geoip-updater/1"},
    )
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                total = 0
                with destination.open("wb") as output:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_COMPRESSED_BYTES:
                            raise GeoIPUpdateError("compressed GeoIP download is too large")
                        output.write(chunk)
            if total == 0:
                raise GeoIPUpdateError("GeoIP download is empty")
            return
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code == 404:
                break
        except (OSError, urllib.error.URLError, GeoIPUpdateError) as exc:
            last_error = exc
        if attempt < 3:
            time.sleep(attempt)
    raise GeoIPUpdateError(f"download failed for {url}: {last_error}")


def decompress_database(source: Path, destination: Path) -> None:
    total = 0
    try:
        with gzip.open(source, "rb") as compressed, destination.open("wb") as output:
            while True:
                chunk = compressed.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DATABASE_BYTES:
                    raise GeoIPUpdateError("uncompressed GeoIP database is too large")
                output.write(chunk)
    except (OSError, EOFError) as exc:
        raise GeoIPUpdateError(f"cannot decompress GeoIP database: {exc}") from exc
    if total == 0:
        raise GeoIPUpdateError("uncompressed GeoIP database is empty")


def download_database(base_url: str, build_dir: Path, periods: list[str]):
    errors: list[str] = []
    for period in periods:
        url = f"{base_url.rstrip('/')}/dbip-country-lite-{period}.mmdb.gz"
        archive = build_dir / f"{period}.mmdb.gz"
        database = build_dir / f"{period}.mmdb"
        try:
            log(f"Downloading DB-IP Country Lite {period}")
            download_file(url, archive)
            decompress_database(archive, database)
            reader, metadata = validate_database(database)
            reader.close()
            return database, period, url, metadata
        except GeoIPUpdateError as exc:
            errors.append(str(exc))
        finally:
            archive.unlink(missing_ok=True)
    raise GeoIPUpdateError("; ".join(errors))


def _network_sort_key(network: ipaddress._BaseNetwork):
    return (network.version, int(network.network_address), network.prefixlen)


def _collapse(networks: set[ipaddress._BaseNetwork]):
    v4 = sorted((network for network in networks if network.version == 4), key=_network_sort_key)
    v6 = sorted((network for network in networks if network.version == 6), key=_network_sort_key)
    return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def derive_acl(database: Path, countries: tuple[str, ...]):
    selected: dict[str, set[ipaddress._BaseNetwork]] = {
        code: set() for code in countries
    }
    versions: set[int] = set()
    record_count = 0
    reader, metadata = validate_database(database)
    try:
        for raw_network, raw_record in reader:
            record_count += 1
            try:
                network = ipaddress.ip_network(str(raw_network), strict=False)
            except ValueError as exc:
                raise GeoIPUpdateError(f"invalid network in MMDB: {raw_network}") from exc
            versions.add(network.version)
            if not isinstance(raw_record, dict):
                continue
            country = raw_record.get("country")
            code = (
                str(country.get("iso_code", "")).strip().upper()
                if isinstance(country, dict)
                else ""
            )
            if code in selected:
                selected[code].add(network)
    finally:
        reader.close()

    if record_count < MIN_DATABASE_NODES or versions != {4, 6}:
        raise GeoIPUpdateError(
            f"MMDB coverage validation failed: records={record_count}, "
            f"IP versions={sorted(versions)}"
        )

    missing = [code for code, networks in selected.items() if not networks]
    if missing:
        raise GeoIPUpdateError(
            "selected countries are absent from the database: " + ", ".join(missing)
        )

    collapsed = {code: _collapse(networks) for code, networks in selected.items()}
    all_networks: set[ipaddress._BaseNetwork] = set()
    for networks in collapsed.values():
        all_networks.update(networks)
    allowed = sorted(all_networks, key=_network_sort_key)
    counts = {
        code: {
            "ipv4": sum(network.version == 4 for network in networks),
            "ipv6": sum(network.version == 6 for network in networks),
        }
        for code, networks in collapsed.items()
    }
    return allowed, collapsed, counts, metadata, record_count


def write_networks(path: Path, networks: Iterable[ipaddress._BaseNetwork]) -> None:
    values = [str(network) for network in networks]
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="ascii")


def set_release_permissions(path: Path) -> None:
    for entry in [path, *path.rglob("*")]:
        if entry.is_symlink():
            continue
        os.chmod(entry, 0o755 if entry.is_dir() else 0o644)
        try:
            shutil.chown(entry, user="root", group="haproxy")
        except LookupError:
            # Unit tests and source inspection may run without the service user.
            pass
        except PermissionError:
            if os.geteuid() == 0:
                raise


def atomic_symlink(target: str, link: Path) -> None:
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    os.symlink(target, temporary)
    os.replace(temporary, link)


def compatibility_snapshot(directory: Path) -> dict[str, tuple[str, Any] | None]:
    result: dict[str, tuple[str, Any] | None] = {}
    for name in (DATABASE_NAME, ALLOWED_NAME):
        path = directory / name
        if path.is_symlink():
            result[name] = ("symlink", os.readlink(path))
        elif path.is_file():
            result[name] = ("file", path.read_bytes())
        else:
            result[name] = None
    return result


def install_compatibility_links(directory: Path) -> None:
    for name in (DATABASE_NAME, ALLOWED_NAME):
        atomic_symlink(f"current/{name}", directory / name)


def remove_legacy_country_files(directory: Path) -> None:
    removed: list[str] = []
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        log(f"WARNING: cannot inspect legacy GeoIP country files: {exc}")
        return
    for path in entries:
        if not re.fullmatch(r"[A-Za-z]{2}\.cidr", path.name):
            continue
        # The historical updater created regular files in the GeoIP root. Do
        # not follow or remove a similarly named symlink created by an operator.
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError as exc:
            log(f"WARNING: cannot remove legacy GeoIP file {path}: {exc}")
    if removed:
        log("Removed legacy flat country files: " + ", ".join(sorted(removed)))


def restore_compatibility_snapshot(
    directory: Path, snapshot: dict[str, tuple[str, Any] | None]
) -> None:
    for name, value in snapshot.items():
        path = directory / name
        path.unlink(missing_ok=True)
        if value is None:
            continue
        kind, payload = value
        if kind == "symlink":
            os.symlink(str(payload), path)
        else:
            temporary = path.with_name(f".{name}.{os.getpid()}.restore")
            temporary.write_bytes(payload)
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)


def command(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = "\n".join(value.strip() for value in (result.stdout, result.stderr) if value.strip())
    return result.returncode == 0, output


def haproxy_is_active(systemctl: str) -> bool:
    ok, _ = command([systemctl, "is-active", "--quiet", "haproxy.service"])
    return ok


def control_plane_checks(config: Path) -> list[tuple[str, str, str]]:
    try:
        text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    if not all(marker.search(text) for marker in CONTROL_PLANE_PROBE_MARKERS):
        return []
    checks: list[tuple[str, str, str]] = []
    for match in CONTROL_PLANE_ACL.finditer(text):
        acl_name = match.group(1)
        service, path = CONTROL_PLANE_PATHS[acl_name]
        domains = [value.lower().rstrip(".") for value in match.group(2).split()]
        if len(domains) == 1 and re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            domains[0],
        ):
            checks.append((service, domains[0], path))
    return checks


def probe(service: str, domain: str, path: str, timeout: float = 5.0):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(("127.0.0.1", 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {domain}\r\n"
                    "User-Agent: easy-ha-proxy-geoip-guard/1\r\n"
                    "Accept: application/json\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(request.encode("ascii"))
                response = bytearray()
                while b"\r\n" not in response and len(response) < 8192:
                    chunk = tls.recv(2048)
                    if not chunk:
                        break
                    response.extend(chunk)
        status_line = bytes(response).split(b"\r\n", 1)[0].decode("ascii", "replace")
        match = re.fullmatch(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?", status_line)
        status = int(match.group(1)) if match else 0
        return status == 200, f"{service} ({domain}) returned HTTP {status or 'invalid'}"
    except Exception as exc:
        return False, f"{service} ({domain}) failed: {exc}"


def verify_control_plane(config: Path) -> tuple[bool, str]:
    checks = control_plane_checks(config)
    if not any(service == "admin" for service, _, _ in checks):
        return True, "guarded HAProxy Admin control-plane probe is unavailable; probe skipped"
    latest: list[str] = []
    for attempt in range(1, 6):
        results = [probe(*check) for check in checks]
        latest = [message for _, message in results]
        if all(ok for ok, _ in results):
            return True, "; ".join(latest)
        if attempt < 5:
            time.sleep(1.0)
    return False, "; ".join(latest)


def validate_reload_and_probe(
    haproxy: str,
    systemctl: str,
    config: Path,
) -> tuple[bool, str]:
    ok, output = command([haproxy, "-c", "-f", str(config)])
    if not ok:
        return False, f"HAProxy validation failed: {output}"
    ok, output = command([systemctl, "reload", "haproxy.service"])
    if not ok:
        return False, f"HAProxy reload failed: {output}"
    ok, probe_output = verify_control_plane(config)
    if not ok:
        return False, f"critical service probe failed: {probe_output}"
    return True, probe_output


def prune_releases(directory: Path, keep: int = 3) -> None:
    releases = directory / "releases"
    protected: set[Path] = set()
    for link_name in ("current", "previous"):
        try:
            protected.add((directory / link_name).resolve(strict=True))
        except (OSError, RuntimeError):
            pass
    candidates = sorted(
        (path for path in releases.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    retained = 0
    for path in candidates:
        if path in protected or retained < keep:
            retained += 1
            continue
        shutil.rmtree(path)


@contextmanager
def update_lock(directory: Path):
    lock_path = directory / ".update.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GeoIPUpdateError("another GeoIP update is already running") from exc
        yield


def update(args: argparse.Namespace, *, lock_held: bool = False) -> None:
    verify_config_transaction_access(
        getattr(args, "config_transaction_state", None),
        getattr(args, "config_transaction_id", ""),
    )
    directory = args.directory.resolve()
    releases = directory / "releases"
    directory.mkdir(parents=True, exist_ok=True)
    releases.mkdir(mode=0o755, exist_ok=True)
    for path in (directory, releases):
        os.chmod(path, 0o755)
        try:
            shutil.chown(path, user="root", group="haproxy")
        except LookupError:
            pass
        except PermissionError:
            if os.geteuid() == 0:
                raise
    lock_context = nullcontext() if lock_held else update_lock(directory)
    with lock_context:
        selection_file = getattr(args, "selection_file", None)
        if selection_file is not None:
            countries, access_filter_enabled = load_selection(selection_file)
        else:
            countries = normalize_countries(args.country)
            access_filter_enabled = bool(args.access_filter_enabled)
        if access_filter_enabled and not countries:
            raise GeoIPUpdateError(
                "GeoIP access filtering is enabled but no country codes are selected"
            )
        previous_release = active_release(directory)
        current_state = (
            read_state(previous_release / STATE_NAME) if previous_release else {}
        )
        current_database = (
            previous_release / DATABASE_NAME if previous_release else None
        )
        if current_database is None or not current_database.is_file():
            legacy_database = directory / DATABASE_NAME
            if legacy_database.is_file() and not legacy_database.is_symlink():
                current_database = legacy_database
        previous_allowed = (
            previous_release / ALLOWED_NAME if previous_release else directory / ALLOWED_NAME
        )
        try:
            previous_allowed_content = previous_allowed.read_bytes()
        except OSError:
            previous_allowed_content = None

        periods = month_candidates(datetime.now(timezone.utc))
        wanted_period = periods[0]
        database_hash_matches = bool(
            current_database is not None
            and current_database.is_file()
            and file_matches_sha256(
                current_database, current_state.get("database_sha256")
            )
        )
        allowed_hash_matches = bool(
            previous_release is not None
            and (previous_release / ALLOWED_NAME).is_file()
            and file_matches_sha256(
                previous_release / ALLOWED_NAME,
                current_state.get("allowed_sha256"),
            )
        )
        state_matches = (
            not args.force_download
            and previous_release is not None
            and current_database is not None
            and current_database.is_file()
            and (previous_release / ALLOWED_NAME).is_file()
            and current_state.get("release_format_version")
            == RELEASE_FORMAT_VERSION
            and current_state.get("source_period") == wanted_period
            and tuple(current_state.get("countries") or ()) == countries
            and bool(current_state.get("access_filter_enabled"))
            == access_filter_enabled
            and database_hash_matches
            and allowed_hash_matches
            and (
                not access_filter_enabled
                or (previous_release / ALLOWED_NAME).stat().st_size > 0
            )
        )
        if state_matches:
            reader, _ = validate_database(current_database)
            reader.close()
            install_compatibility_links(directory)
            remove_legacy_country_files(directory)
            log(
                f"GeoIP release {previous_release.name} is current; "
                "database and country selection are unchanged"
            )
            prune_releases(directory)
            return

        build_root = Path(tempfile.mkdtemp(prefix=".build-", dir=releases))
        try:
            reuse_current = (
                not args.force_download
                and current_database is not None
                and current_database.is_file()
                and database_hash_matches
                and current_state.get("source_period") == wanted_period
            )
            source_url = str(current_state.get("source_url") or "")
            source_period = str(current_state.get("source_period") or "unknown")
            if reuse_current:
                database = build_root / DATABASE_NAME
                shutil.copy2(current_database, database)
                validate_reader, metadata = validate_database(database)
                validate_reader.close()
                log(f"Reusing installed DB-IP Country Lite {source_period}")
            else:
                try:
                    database, source_period, source_url, metadata = download_database(
                        args.base_url, build_root, periods if current_database is None else [wanted_period]
                    )
                except GeoIPUpdateError:
                    if (
                        current_database is None
                        or not current_database.is_file()
                        or not database_hash_matches
                    ):
                        raise
                    database = build_root / DATABASE_NAME
                    shutil.copy2(current_database, database)
                    validate_reader, metadata = validate_database(database)
                    validate_reader.close()
                    log(
                        "WARNING: the newest database is unavailable; "
                        f"keeping installed release {source_period}"
                    )

            canonical_database = build_root / DATABASE_NAME
            if database != canonical_database:
                os.replace(database, canonical_database)
            database = canonical_database
            db_sha256 = sha256_file(database)
            allowed, per_country, counts, metadata, record_count = derive_acl(
                database, countries
            )
            write_networks(build_root / ALLOWED_NAME, allowed)
            # During an Ansible transition from enabled to disabled, the
            # running HAProxy process may still reference the old ACL until
            # its configuration role runs. Keep that known-good file in place
            # instead of briefly publishing an empty allow list.
            if (
                not access_filter_enabled
                and not countries
                and previous_allowed_content
            ):
                (build_root / ALLOWED_NAME).write_bytes(previous_allowed_content)
            allowed_content = (build_root / ALLOWED_NAME).read_bytes()
            acl_changed = previous_allowed_content != allowed_content
            allowed_sha256 = hashlib.sha256(allowed_content).hexdigest()
            published_allowed_count = sum(
                bool(line.strip()) and not line.lstrip().startswith(b"#")
                for line in allowed_content.splitlines()
            )
            for code, networks in per_country.items():
                write_networks(build_root / f"{code}.cidr", networks)

            config_hash = hashlib.sha256(
                json.dumps(
                    {
                        "release_format_version": RELEASE_FORMAT_VERSION,
                        "countries": countries,
                        "access_filter_enabled": access_filter_enabled,
                        "allowed_sha256": allowed_sha256,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            safe_period = re.sub(r"[^0-9A-Za-z_-]", "-", source_period)
            release_id = f"{safe_period}-{db_sha256[:12]}-{config_hash[:12]}"
            release = releases / release_id
            state = {
                "release_format_version": RELEASE_FORMAT_VERSION,
                "provider": "DB-IP Country Lite",
                "license": "CC BY 4.0",
                "source_url": source_url,
                "source_period": source_period,
                "activated_at": datetime.now(timezone.utc).isoformat(),
                "database_sha256": db_sha256,
                "database_type": str(getattr(metadata, "database_type", "")),
                "database_build_epoch": int(getattr(metadata, "build_epoch", 0) or 0),
                "database_records": record_count,
                "countries": list(countries),
                "country_networks": counts,
                "allowed_networks": published_allowed_count,
                "allowed_sha256": allowed_sha256,
                "access_filter_enabled": access_filter_enabled,
            }
            (build_root / STATE_NAME).write_text(
                json.dumps(state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            set_release_permissions(build_root)

            if release.exists():
                if release_payload_matches(release, db_sha256, allowed_sha256):
                    shutil.rmtree(build_root)
                    build_root = release
                else:
                    # Never delete a possibly active immutable release in
                    # place. Publish the repaired payload under a unique ID and
                    # switch `current` to it atomically below.
                    repair_base = f"{release_id}-repair-{os.getpid()}-{time.time_ns()}"
                    release_id = repair_base
                    release = releases / release_id
                    suffix = 0
                    while release.exists():
                        suffix += 1
                        release_id = f"{repair_base}-{suffix}"
                        release = releases / release_id
                    os.replace(build_root, release)
                    build_root = release
            else:
                os.replace(build_root, release)
                build_root = release

            old_target = (
                os.readlink(directory / "current")
                if (directory / "current").is_symlink()
                else None
            )
            new_target = f"releases/{release_id}"
            if old_target == new_target:
                install_compatibility_links(directory)
                remove_legacy_country_files(directory)
                log(f"GeoIP release {release_id} is already current")
                prune_releases(directory)
                return

            snapshot = compatibility_snapshot(directory)
            atomic_symlink(new_target, directory / "current")
            install_compatibility_links(directory)

            active = (
                acl_changed
                and access_filter_enabled
                and not args.skip_reload
                and haproxy_is_active(args.systemctl)
            )
            if active:
                ok, detail = validate_reload_and_probe(
                    args.haproxy, args.systemctl, args.haproxy_config
                )
                if not ok:
                    if old_target:
                        atomic_symlink(old_target, directory / "current")
                        install_compatibility_links(directory)
                    else:
                        (directory / "current").unlink(missing_ok=True)
                        restore_compatibility_snapshot(directory, snapshot)
                    rollback_ok, rollback_detail = validate_reload_and_probe(
                        args.haproxy, args.systemctl, args.haproxy_config
                    )
                    raise GeoIPUpdateError(
                        f"new release failed: {detail}; rollback "
                        f"{'succeeded' if rollback_ok else 'failed'}: {rollback_detail}"
                    )
                log(f"HAProxy reload and critical-service checks passed: {detail}")
            elif not acl_changed:
                log("HAProxy ACL is unchanged; reload is not required")

            if old_target and database_hash_matches and allowed_hash_matches:
                atomic_symlink(old_target, directory / "previous")
            remove_legacy_country_files(directory)
            log(
                f"Activated GeoIP release {release_id}: {published_allowed_count} networks "
                f"for {', '.join(countries) if countries else 'UI lookups only'}"
            )
            prune_releases(directory)
        finally:
            if build_root.exists() and build_root.name.startswith(".build-"):
                shutil.rmtree(build_root, ignore_errors=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("/etc/haproxy/geoip"))
    parser.add_argument("--base-url", default="https://download.db-ip.com/free")
    parser.add_argument("--selection-file", type=Path)
    parser.add_argument("--config-transaction-state", type=Path)
    parser.add_argument("--config-transaction-id", default="")
    parser.add_argument(
        "--vars-file",
        type=Path,
        default=Path("/opt/haproxy-admin/config/vars.yml"),
    )
    parser.add_argument("--configure-selection", action="store_true")
    parser.add_argument("--country", action="append", default=[])
    parser.add_argument("--access-filter-enabled", action="store_true")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--skip-reload", action="store_true")
    parser.add_argument("--haproxy", default="/usr/sbin/haproxy")
    parser.add_argument(
        "--haproxy-config", type=Path, default=Path("/etc/haproxy/haproxy.cfg")
    )
    parser.add_argument("--systemctl", default="/usr/bin/systemctl")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.configure_selection:
            configure_selection(args)
        else:
            update(args)
    except GeoIPUpdateError as exc:
        log(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
