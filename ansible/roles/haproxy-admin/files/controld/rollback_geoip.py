"""Transaction verification, rollback, and GeoIP database management."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    ADMIN_ALLOWLIST_PATH,
    CONFIG_SOURCE_FILENAMES,
    CONFIG_TRANSACTION_ACTIVE_STATES,
    CONFIG_TRANSACTION_MAX_TIMEOUT,
    CONFIG_TRANSACTION_MIN_TIMEOUT,
    CONFIG_TRANSACTION_VERSION,
    GEOIP_DIRECTORY,
    GEOIP_MAX_SELECTION_BYTES,
    GEOIP_MAX_STATE_BYTES,
    GEOIP_RELEASES_PATH,
    GEOIP_SELECTION_PATH,
    GEOIP_UPDATE_COMMAND,
    GEOIP_UPDATE_SERVICE,
    GEOIP_UPDATE_TIMER,
    HAPROXY_CFG_PATH,
    LOG,
    MAX_CONFIG_BYTES,
    _GEOIP_OPERATION_LOCK,
    _GUARDED_APPLY_LOCK,
)
from .transactions import (
    _canonical_admin_allowlist_raw,
    _create_guarded_config_backup,
    _decode_config_transaction_sources,
    _decode_control_plane_checks,
    _load_config_transaction,
    _open_admin_allowlist_directory,
    _persist_config_transaction,
    _read_admin_allowlist_raw,
    _restore_config_sources,
    _restore_guarded_config,
    _run_control_plane_checks,
    _validate_guarded_control_plane_transition,
    _verify_candidate_config_sources,
    _verify_live_transaction_candidate,
    _write_admin_allowlist_raw,
    cmd_reload,
    haproxy_write_config_from_b64,
    record_config_version,
)

# Bound across sibling submodules when the package finishes loading.
_run_geoip_command: Any = None

def _remove_admin_allowlist() -> None:
    directory_fd = _open_admin_allowlist_directory()
    try:
        try:
            target_stat = os.stat(
                ADMIN_ALLOWLIST_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise RuntimeError("admin allow list is not a regular file")
        os.unlink(ADMIN_ALLOWLIST_PATH.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _verify_transaction_admin_allowlist_candidate(state: dict[str, object]) -> None:
    admin_state = state.get("admin_allowlist")
    if admin_state is None:
        return
    if not isinstance(admin_state, dict):
        raise RuntimeError("persisted admin allow list state is invalid")
    expected = str(admin_state.get("candidate_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("persisted admin allow list candidate hash is invalid")
    present, raw = _read_admin_allowlist_raw()
    if not present or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
        raise RuntimeError("admin allow list changed before confirmation")


def _restore_transaction_admin_allowlist(state: dict[str, object]) -> None:
    admin_state = state.get("admin_allowlist")
    if admin_state is None:
        return
    if not isinstance(admin_state, dict):
        raise RuntimeError("persisted admin allow list state is invalid")
    previous_present = admin_state.get("previous_present") is True
    previous_encoded = admin_state.get("previous_b64")
    if not isinstance(previous_encoded, str):
        raise RuntimeError("persisted admin allow list snapshot is missing")
    previous_raw = base64.b64decode(previous_encoded, validate=True)
    if previous_present:
        _write_admin_allowlist_raw(previous_raw)
    else:
        _remove_admin_allowlist()
    present, current_raw = _read_admin_allowlist_raw()
    if present != previous_present or (previous_present and not secrets.compare_digest(
        current_raw, previous_raw
    )):
        raise RuntimeError("admin allow list rollback could not be verified")


def _canonical_config_geoip_selection(selection: dict[str, object]) -> bytes:
    return (
        json.dumps(selection, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _open_geoip_directory() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(GEOIP_DIRECTORY, flags)
    except OSError as exc:
        raise RuntimeError("GeoIP runtime directory is unavailable or unsafe") from exc


def _write_geoip_selection_raw(raw: bytes) -> None:
    """Atomically replace root-managed selection.json without following links."""
    if not raw or len(raw) > GEOIP_MAX_SELECTION_BYTES or b"\x00" in raw:
        raise ValueError("invalid GeoIP selection snapshot")
    raw.decode("utf-8")
    directory_fd = _open_geoip_directory()
    temporary = f".selection.json.transaction.{secrets.token_hex(8)}"
    temporary_created = False
    try:
        directory_stat = os.fstat(directory_fd)
        try:
            target_stat = os.stat(
                GEOIP_SELECTION_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
                raise RuntimeError("GeoIP selection is not a regular file")
            owner = target_stat.st_uid
            group = target_stat.st_gid
            mode = stat.S_IMODE(target_stat.st_mode)
        except FileNotFoundError:
            owner = directory_stat.st_uid
            group = directory_stat.st_gid
            mode = 0o644

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temporary_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        temporary_created = True
        try:
            view = memoryview(raw)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
            os.fsync(temporary_fd)
            os.fchmod(temporary_fd, mode)
            try:
                os.fchown(temporary_fd, owner, group)
            except PermissionError:
                if os.geteuid() == 0:
                    raise
        finally:
            os.close(temporary_fd)
        os.replace(
            temporary,
            GEOIP_SELECTION_PATH.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_created = False
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _remove_geoip_selection() -> None:
    directory_fd = _open_geoip_directory()
    try:
        try:
            target_stat = os.stat(
                GEOIP_SELECTION_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise RuntimeError("GeoIP selection is not a regular file")
        os.unlink(GEOIP_SELECTION_PATH.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _active_geoip_release_name() -> str:
    release = _geoip_current_release()
    return release.name if release is not None else ""


def _switch_geoip_release(release_name: str) -> None:
    """Restore the exact active release captured before the transaction."""
    if release_name:
        if (
            release_name in {".", ".."}
            or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,254}", release_name)
        ):
            raise RuntimeError("persisted GeoIP release name is invalid")
        try:
            releases_stat = GEOIP_RELEASES_PATH.lstat()
        except OSError as exc:
            raise RuntimeError("GeoIP releases directory is unavailable") from exc
        if stat.S_ISLNK(releases_stat.st_mode) or not stat.S_ISDIR(
            releases_stat.st_mode
        ):
            raise RuntimeError("GeoIP releases directory is unsafe")
        release = GEOIP_RELEASES_PATH / release_name
        try:
            release_stat = release.lstat()
            resolved = release.resolve(strict=True)
            resolved.relative_to(GEOIP_RELEASES_PATH.resolve(strict=True))
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError("persisted GeoIP release is unavailable") from exc
        if stat.S_ISLNK(release_stat.st_mode) or not stat.S_ISDIR(release_stat.st_mode):
            raise RuntimeError("persisted GeoIP release is unsafe")

    directory_fd = _open_geoip_directory()
    temporary = f".current.transaction.{secrets.token_hex(8)}"
    temporary_created = False
    try:
        try:
            current_stat = os.stat("current", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current_stat = None
        if current_stat is not None and not stat.S_ISLNK(current_stat.st_mode):
            raise RuntimeError("GeoIP current release pointer is not a symlink")
        if not release_name:
            if current_stat is not None:
                os.unlink("current", dir_fd=directory_fd)
                os.fsync(directory_fd)
            return
        os.symlink(f"releases/{release_name}", temporary, dir_fd=directory_fd)
        temporary_created = True
        os.replace(
            temporary,
            "current",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_created = False
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _geoip_runtime_fingerprint(
    expected_selection: dict[str, object],
) -> dict[str, str]:
    selection, selection_raw = _geoip_selection()
    if (
        selection.get("countries") != expected_selection.get("countries")
        or selection.get("access_filter_enabled")
        is not expected_selection.get("access_filter_enabled")
    ):
        raise RuntimeError("GeoIP runtime selection does not match the candidate")
    release = _geoip_current_release()
    if release is None:
        raise RuntimeError("GeoIP runtime has no active release")
    release_state = _read_geoip_state(release)
    database_path = release / "dbip-country-lite.mmdb"
    allowed_path = release / "allowed.geo"
    if (
        release_state.get("release_format_version") != 1
        or release_state.get("countries") != expected_selection.get("countries")
        or release_state.get("access_filter_enabled")
        is not expected_selection.get("access_filter_enabled")
        or not _sha256_matches(database_path, release_state.get("database_sha256"))
        or not _sha256_matches(allowed_path, release_state.get("allowed_sha256"))
    ):
        raise RuntimeError("GeoIP active release does not match the candidate")
    if expected_selection.get("access_filter_enabled"):
        try:
            if allowed_path.stat().st_size <= 0:
                raise RuntimeError("GeoIP candidate ACL is empty")
        except OSError as exc:
            raise RuntimeError("GeoIP candidate ACL is unavailable") from exc
    return {
        "selection_sha256": hashlib.sha256(selection_raw).hexdigest(),
        "release": release.name,
        "database_sha256": str(release_state.get("database_sha256") or "").lower(),
        "allowed_sha256": str(release_state.get("allowed_sha256") or "").lower(),
    }


def _verify_transaction_geoip_candidate(state: dict[str, object]) -> None:
    geoip = state.get("geoip")
    if geoip is None:
        return
    if not isinstance(geoip, dict):
        raise RuntimeError("persisted GeoIP transaction data is invalid")
    selection = geoip.get("candidate_selection")
    expected = geoip.get("candidate_fingerprint")
    if not isinstance(selection, dict) or not isinstance(expected, dict):
        raise RuntimeError("persisted GeoIP candidate data is incomplete")
    current = _geoip_runtime_fingerprint(selection)
    for key in ("selection_sha256", "release", "database_sha256", "allowed_sha256"):
        expected_value = str(expected.get(key) or "")
        current_value = str(current.get(key) or "")
        if not expected_value or not secrets.compare_digest(expected_value, current_value):
            raise RuntimeError("GeoIP runtime changed before confirmation")


def _restore_transaction_geoip(state: dict[str, object]) -> None:
    geoip = state.get("geoip")
    if geoip is None:
        return
    if not isinstance(geoip, dict):
        raise RuntimeError("persisted GeoIP rollback data is invalid")
    previous_present = geoip.get("previous_selection_present")
    previous_encoded = geoip.get("previous_selection_b64")
    previous_release = geoip.get("previous_release")
    if (
        not isinstance(previous_present, bool)
        or not isinstance(previous_encoded, str)
        or not isinstance(previous_release, str)
    ):
        raise RuntimeError("persisted GeoIP rollback data is incomplete")
    previous_raw = base64.b64decode(previous_encoded, validate=True)
    if previous_present:
        _write_geoip_selection_raw(previous_raw)
    else:
        _remove_geoip_selection()
    _switch_geoip_release(previous_release)

    selection_now, selection_raw_now = _geoip_selection()
    del selection_now
    if previous_present:
        if not secrets.compare_digest(selection_raw_now, previous_raw):
            raise RuntimeError("GeoIP selection rollback could not be verified")
    elif selection_raw_now:
        raise RuntimeError("GeoIP selection rollback could not be verified")
    if _active_geoip_release_name() != previous_release:
        raise RuntimeError("GeoIP release rollback could not be verified")


def _safe_check_status(item: object) -> dict[str, object]:
    if not isinstance(item, dict):
        return {}
    safe: dict[str, object] = {}
    for key in ("service", "domain", "path", "ok", "status", "attempt"):
        value = item.get(key)
        if isinstance(value, (str, int, bool)) or value is None:
            safe[key] = value
    failure = item.get("failure")
    if failure:
        safe["failure"] = str(failure)[:2000]
    return safe


def _sanitized_config_transaction_status(
    state: dict[str, object] | None,
) -> dict[str, object]:
    if state is None:
        return {"ok": True, "state": "none", "pending": False}
    status_name = str(state.get("state") or "unknown")
    deadline = float(state.get("deadline_epoch") or 0)
    remaining = max(0, int(deadline - time.time() + 0.999)) if deadline else 0
    confirm_by = (
        datetime.fromtimestamp(deadline, timezone.utc).isoformat()
        if deadline
        else None
    )
    result: dict[str, object] = {
        "ok": status_name in {"pending_confirmation", "confirmed", "rolled_back"},
        "state": status_name,
        "pending": status_name == "pending_confirmation",
        "transaction_id": str(state.get("transaction_id") or ""),
        "candidate_sha256": str(state.get("candidate_sha256") or ""),
        "previous_sha256": str(state.get("previous_sha256") or ""),
        "created_at": str(state.get("created_at") or ""),
        "deadline_epoch": deadline or None,
        "deadline": confirm_by,
        "confirm_by": confirm_by,
        "remaining_seconds": remaining,
        "source_files": sorted(
            str(name) for name in (state.get("candidate_source_sha256") or {})
        ),
        "checks": [
            _safe_check_status(item) for item in (state.get("checks") or [])
        ],
        "failure": str(state.get("failure") or "")[:4000],
        "rollback_reason": str(state.get("rollback_reason") or "")[:500],
    }
    rollback = state.get("rollback")
    if isinstance(rollback, dict):
        result["rollback"] = {
            "ok": bool(rollback.get("ok")),
            "reload_ok": bool(rollback.get("reload_ok")),
            "sources_ok": bool(rollback.get("sources_ok")),
            "geoip_ok": bool(rollback.get("geoip_ok", True)),
            "admin_allowlist_ok": bool(rollback.get("admin_allowlist_ok", True)),
            "restored_sources": [
                str(name) for name in (rollback.get("restored_sources") or [])
                if str(name) in CONFIG_SOURCE_FILENAMES
            ],
            "failure": str(rollback.get("failure") or "")[:4000],
            "checks": [
                _safe_check_status(item) for item in (rollback.get("checks") or [])
            ],
        }
    return result


def _transaction_matches(state: dict[str, object], transaction_id: str) -> bool:
    expected = str(state.get("transaction_id") or "")
    return bool(expected and transaction_id and secrets.compare_digest(expected, transaction_id))


def _rollback_config_transaction_locked(
    state: dict[str, object],
    reason: str,
) -> dict[str, object]:
    """Restore YAML and managed ACL state before restoring the HAProxy config."""
    state["state"] = "rolling_back"
    state["rollback_reason"] = reason
    state["failure"] = str(state.get("failure") or "")
    _persist_config_transaction(state)

    sources_ok = False
    restored_sources: list[str] = []
    source_failure = ""
    previous_sources_raw = state.get("previous_sources")
    try:
        if not isinstance(previous_sources_raw, dict):
            raise RuntimeError("persisted previous config sources are missing")
        previous_sources = {
            str(filename): base64.b64decode(str(encoded), validate=True)
            for filename, encoded in previous_sources_raw.items()
        }
        restored_sources = _restore_config_sources(previous_sources)
        sources_ok = True
    except Exception as exc:  # noqa: BLE001
        source_failure = f"config source rollback failed: {exc}"

    admin_allowlist_ok = False
    admin_allowlist_failure = ""
    try:
        _restore_transaction_admin_allowlist(state)
        admin_allowlist_ok = True
    except Exception as exc:  # noqa: BLE001
        admin_allowlist_failure = f"admin allow list rollback failed: {exc}"

    geoip_ok = False
    geoip_failure = ""
    try:
        _restore_transaction_geoip(state)
        geoip_ok = True
    except Exception as exc:  # noqa: BLE001
        geoip_failure = f"GeoIP rollback failed: {exc}"

    config_result: dict[str, object]
    previous_config = state.get("previous_config_b64")
    checks = state.get("control_plane_checks")
    if not isinstance(previous_config, str) or not isinstance(checks, list):
        config_result = {
            "ok": False,
            "reload_ok": False,
            "checks": [],
            "failure": "persisted rollback data is incomplete",
        }
    else:
        config_result = _restore_guarded_config(previous_config, checks)

    config_failure = str(config_result.get("failure") or "")
    failures = [
        value
        for value in (
            source_failure,
            admin_allowlist_failure,
            geoip_failure,
            config_failure,
        )
        if value
    ]
    rollback_ok = (
        bool(config_result.get("ok"))
        and sources_ok
        and admin_allowlist_ok
        and geoip_ok
    )
    state["state"] = "rolled_back" if rollback_ok else "rollback_failed"
    state["rollback"] = {
        "ok": rollback_ok,
        "reload_ok": bool(config_result.get("reload_ok")),
        "sources_ok": sources_ok,
        "admin_allowlist_ok": admin_allowlist_ok,
        "geoip_ok": geoip_ok,
        "restored_sources": restored_sources,
        "checks": config_result.get("checks") or [],
        "failure": "; ".join(failures),
    }
    if failures:
        state["failure"] = "; ".join(failures)
    if rollback_ok:
        state.pop("previous_config_b64", None)
        state.pop("previous_sources", None)
        state.pop("admin_allowlist", None)
        state.pop("geoip", None)
    _persist_config_transaction(state)
    return _sanitized_config_transaction_status(state)


def _expire_config_transaction_locked() -> dict[str, object] | None:
    state = _load_config_transaction()
    if state is None:
        return None
    if state.get("state") == "pending_confirmation":
        deadline = float(state.get("deadline_epoch") or 0)
        if deadline and time.time() >= deadline:
            return _rollback_config_transaction_locked(state, "confirmation timeout expired")
    return _sanitized_config_transaction_status(state)


def _config_transaction_watchdog(transaction_id: str, deadline_epoch: float) -> None:
    while True:
        remaining = deadline_epoch - time.time()
        if remaining > 0:
            time.sleep(min(remaining, 30.0))
            continue
        with _GUARDED_APPLY_LOCK:
            try:
                state = _load_config_transaction()
                if (
                    state is not None
                    and _transaction_matches(state, transaction_id)
                    and state.get("state") == "pending_confirmation"
                    and time.time() >= float(state.get("deadline_epoch") or 0)
                ):
                    _rollback_config_transaction_locked(
                        state, "confirmation timeout expired"
                    )
            except Exception:  # noqa: BLE001
                LOG.exception("HAProxy config transaction watchdog failed")
        return


def _schedule_config_transaction_watchdog(
    transaction_id: str,
    deadline_epoch: float,
) -> None:
    threading.Thread(
        target=_config_transaction_watchdog,
        args=(transaction_id, deadline_epoch),
        daemon=True,
        name=f"config-guard-{transaction_id[:8]}",
    ).start()


def begin_config_transaction(
    cfg_b64: str,
    checks_b64: str,
    sources_b64: str,
    timeout_text: str,
) -> dict[str, object]:
    """Apply a candidate and leave it pending until a browser confirms it."""
    try:
        timeout_seconds = int(timeout_text, 10)
    except ValueError as exc:
        raise ValueError("invalid config transaction timeout") from exc
    if not CONFIG_TRANSACTION_MIN_TIMEOUT <= timeout_seconds <= CONFIG_TRANSACTION_MAX_TIMEOUT:
        raise ValueError("config transaction timeout is outside the allowed range")
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration operation is running")
    geoip_lock_acquired = False
    try:
        existing = _load_config_transaction()
        if existing is not None:
            if existing.get("state") == "pending_confirmation":
                deadline = float(existing.get("deadline_epoch") or 0)
                if deadline and time.time() >= deadline:
                    _rollback_config_transaction_locked(
                        existing, "confirmation timeout expired"
                    )
                    existing = _load_config_transaction()
            if existing and existing.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES:
                raise RuntimeError("another HAProxy config transaction is still active")

        checks = _decode_control_plane_checks(checks_b64)
        candidate = base64.b64decode(cfg_b64, validate=True)
        if not candidate or len(candidate) > MAX_CONFIG_BYTES:
            raise ValueError("invalid HAProxy configuration size")
        (
            candidate_sources,
            previous_sources,
            candidate_geoip_selection,
            candidate_admin_allowlist,
        ) = _decode_config_transaction_sources(sources_b64)
        _verify_candidate_config_sources(candidate_sources)

        candidate_admin_allowlist_raw = b""
        previous_admin_allowlist_present = False
        previous_admin_allowlist_raw = b""
        if candidate_admin_allowlist is not None:
            candidate_admin_allowlist_raw = _canonical_admin_allowlist_raw(
                candidate_admin_allowlist
            )
            (
                previous_admin_allowlist_present,
                previous_admin_allowlist_raw,
            ) = _read_admin_allowlist_raw()

        previous_geoip_selection = b""
        previous_geoip_selection_present = False
        previous_geoip_release = ""
        if candidate_geoip_selection is not None:
            if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
                raise RuntimeError("another GeoIP operation is already running")
            geoip_lock_acquired = True
            service = _systemd_properties(
                GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
            )
            if service.get("ActiveState") in {"activating", "active", "reloading"}:
                raise RuntimeError("another GeoIP operation is already running")
            previous_selection_state, previous_geoip_selection = _geoip_selection()
            previous_geoip_selection_present = bool(
                previous_selection_state.get("available")
            )
            previous_geoip_release = _active_geoip_release_name()

        current_path = Path(HAPROXY_CFG_PATH)
        previous = current_path.read_bytes()
        if not previous or len(previous) > MAX_CONFIG_BYTES:
            raise ValueError("a valid current HAProxy configuration is required for rollback")
        _validate_guarded_control_plane_transition(previous, candidate, checks)

        candidate_sha256 = hashlib.sha256(candidate).hexdigest()
        previous_sha256 = hashlib.sha256(previous).hexdigest()
        transaction_id = secrets.token_urlsafe(24)
        backup_path = _create_guarded_config_backup(previous, candidate_sha256)
        state: dict[str, object] = {
            "version": CONFIG_TRANSACTION_VERSION,
            "transaction_id": transaction_id,
            "state": "prepared",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "candidate_sha256": candidate_sha256,
            "previous_sha256": previous_sha256,
            "candidate_source_sha256": {
                filename: hashlib.sha256(content).hexdigest()
                for filename, content in candidate_sources.items()
            },
            "previous_config_b64": base64.b64encode(previous).decode("ascii"),
            "previous_sources": {
                filename: base64.b64encode(content).decode("ascii")
                for filename, content in previous_sources.items()
            },
            "control_plane_checks": checks,
            "checks": [],
            "backup_path": backup_path,
            "deadline_epoch": 0,
            "failure": "",
            "rollback": None,
        }
        if candidate_admin_allowlist is not None:
            state["admin_allowlist"] = {
                "candidate_sha256": hashlib.sha256(
                    candidate_admin_allowlist_raw
                ).hexdigest(),
                "previous_present": previous_admin_allowlist_present,
                "previous_b64": base64.b64encode(
                    previous_admin_allowlist_raw
                ).decode("ascii"),
            }
        if candidate_geoip_selection is not None:
            candidate_selection_raw = _canonical_config_geoip_selection(
                candidate_geoip_selection
            )
            state["geoip"] = {
                "candidate_selection": candidate_geoip_selection,
                "candidate_selection_sha256": hashlib.sha256(
                    candidate_selection_raw
                ).hexdigest(),
                "candidate_fingerprint": None,
                "previous_selection_present": previous_geoip_selection_present,
                "previous_selection_b64": base64.b64encode(
                    previous_geoip_selection
                ).decode("ascii"),
                "previous_release": previous_geoip_release,
            }
        _persist_config_transaction(state)

        try:
            if candidate_geoip_selection is not None:
                _write_geoip_selection_raw(candidate_selection_raw)
                geoip_ok, geoip_output = _run_geoip_command(
                    [
                        GEOIP_UPDATE_COMMAND,
                        "--skip-reload",
                        "--config-transaction-id",
                        transaction_id,
                    ]
                )
                state["geoip_update_output"] = geoip_output
                if not geoip_ok:
                    raise RuntimeError(
                        "GeoIP candidate preparation failed: "
                        + (geoip_output or "updater failed")
                    )
                geoip_state = state.get("geoip")
                if not isinstance(geoip_state, dict):
                    raise RuntimeError("GeoIP transaction state is unavailable")
                geoip_state["candidate_fingerprint"] = _geoip_runtime_fingerprint(
                    candidate_geoip_selection
                )
                _persist_config_transaction(state)

            if candidate_admin_allowlist is not None:
                _write_admin_allowlist_raw(candidate_admin_allowlist_raw)
            haproxy_write_config_from_b64(cfg_b64)
            reload_ok, reload_output = cmd_reload()
            state["reload_output"] = reload_output
            if not reload_ok:
                state["failure"] = f"HAProxy reload failed: {reload_output}"
                return _rollback_config_transaction_locked(
                    state, "candidate reload failed"
                )
            check_results = _run_control_plane_checks(checks)
            state["checks"] = check_results
            if not all(bool(item.get("ok")) for item in check_results):
                failed = [
                    f"{item.get('service')} ({item.get('domain')}): {item.get('failure')}"
                    for item in check_results
                    if not item.get("ok")
                ]
                state["failure"] = "; ".join(failed) or "critical service check failed"
                return _rollback_config_transaction_locked(
                    state, "candidate health check failed"
                )
        except Exception as exc:  # noqa: BLE001
            state["failure"] = f"guarded transaction apply failed: {exc}"
            return _rollback_config_transaction_locked(state, "candidate apply failed")

        deadline = time.time() + timeout_seconds
        state["state"] = "pending_confirmation"
        state["deadline_epoch"] = deadline
        _persist_config_transaction(state)
        _schedule_config_transaction_watchdog(transaction_id, deadline)
        return _sanitized_config_transaction_status(state)
    finally:
        if geoip_lock_acquired:
            _GEOIP_OPERATION_LOCK.release()
        _GUARDED_APPLY_LOCK.release()


def config_transaction_status(transaction_id: str = "") -> dict[str, object]:
    # GeoIP selection changes deliberately share the guarded-apply lock while
    # they rebuild/reload ACLs. Status is read-only and transaction.json is
    # replaced atomically, so never make UI polling wait behind that work.
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        state = _load_config_transaction()
        if transaction_id:
            if state is None or not _transaction_matches(state, transaction_id):
                raise ValueError("HAProxy config transaction id does not match")
        result = _sanitized_config_transaction_status(state)
        result["busy"] = True
        return result
    try:
        status_result = _expire_config_transaction_locked()
        state = _load_config_transaction()
        if transaction_id:
            if state is None or not _transaction_matches(state, transaction_id):
                raise ValueError("HAProxy config transaction id does not match")
        return status_result or _sanitized_config_transaction_status(state)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _config_transaction_busy_result(
    transaction_id: str,
    action: str,
    candidate_sha256: str = "",
) -> dict[str, object]:
    """Return a retryable conflict instead of completing after client timeout."""
    state = _load_config_transaction()
    if state is None or not _transaction_matches(state, transaction_id):
        raise ValueError("HAProxy config transaction id does not match")
    result = _sanitized_config_transaction_status(state)
    if action == "confirmation":
        expected_sha256 = str(state.get("candidate_sha256") or "")
        if (
            not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256)
            or not secrets.compare_digest(expected_sha256, candidate_sha256)
        ):
            raise ValueError("HAProxy config transaction candidate hash does not match")
        if state.get("state") == "confirmed":
            return result
    elif action == "rollback" and state.get("state") == "rolled_back":
        return result
    state_name = str(state.get("state") or "")
    retryable_states = (
        {"prepared", "pending_confirmation"}
        if action == "confirmation"
        else {"prepared", "pending_confirmation", "rolling_back", "rollback_failed"}
    )
    retryable = state_name in retryable_states
    result.update({
        "ok": False,
        "busy": True,
        "conflict": True,
        "retryable": retryable,
        "error": (
            "Another HAProxy configuration operation is running; "
            f"retry {action} shortly"
            if retryable
            else f"HAProxy configuration transaction cannot perform {action} "
            f"while it is {state_name or 'unknown'}"
        ),
    })
    return result


def confirm_config_transaction(
    transaction_id: str,
    candidate_sha256: str,
) -> dict[str, object]:
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return _config_transaction_busy_result(
            transaction_id,
            "confirmation",
            candidate_sha256,
        )
    try:
        state = _load_config_transaction()
        if state is None or not _transaction_matches(state, transaction_id):
            raise ValueError("HAProxy config transaction id does not match")
        expected_sha256 = str(state.get("candidate_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) or not secrets.compare_digest(
            expected_sha256, candidate_sha256
        ):
            raise ValueError("HAProxy config transaction candidate hash does not match")
        if state.get("state") == "confirmed":
            return _sanitized_config_transaction_status(state)
        if state.get("state") != "pending_confirmation":
            raise RuntimeError("HAProxy config transaction is not awaiting confirmation")
        deadline = float(state.get("deadline_epoch") or 0)
        if not deadline or time.time() >= deadline:
            _rollback_config_transaction_locked(state, "confirmation timeout expired")
            raise RuntimeError("HAProxy config transaction confirmation arrived too late")
        try:
            _verify_live_transaction_candidate(state)
        except Exception as exc:  # noqa: BLE001
            state["failure"] = f"pending candidate verification failed: {exc}"
            rollback = _rollback_config_transaction_locked(
                state, "pending candidate changed before confirmation"
            )
            outcome = (
                "the previous configuration was restored"
                if rollback.get("state") == "rolled_back"
                else "automatic rollback failed"
            )
            raise RuntimeError(
                f"HAProxy config transaction candidate changed; {outcome}"
            ) from exc
        state["state"] = "confirmed"
        state["confirmed_at"] = datetime.now(timezone.utc).isoformat()
        # The files on disk are now the version that is running, so this is the
        # moment worth keeping. Recorded before the rollback material is
        # dropped, and never allowed to fail the confirmation.
        state["history_version"] = record_config_version(state)
        state.pop("previous_config_b64", None)
        state.pop("previous_sources", None)
        state.pop("admin_allowlist", None)
        state.pop("geoip", None)
        _persist_config_transaction(state)
        return _sanitized_config_transaction_status(state)
    finally:
        _GUARDED_APPLY_LOCK.release()


def rollback_config_transaction(transaction_id: str) -> dict[str, object]:
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return _config_transaction_busy_result(transaction_id, "rollback")
    try:
        state = _load_config_transaction()
        if state is None or not _transaction_matches(state, transaction_id):
            raise ValueError("HAProxy config transaction id does not match")
        if state.get("state") == "rolled_back":
            return _sanitized_config_transaction_status(state)
        if state.get("state") not in {
            "prepared", "pending_confirmation", "rolling_back", "rollback_failed"
        }:
            raise RuntimeError("HAProxy config transaction cannot be rolled back")
        return _rollback_config_transaction_locked(state, "manual rollback requested")
    finally:
        _GUARDED_APPLY_LOCK.release()


def recover_config_transaction() -> None:
    """Recover an interrupted or pending transaction before serving clients."""
    with _GUARDED_APPLY_LOCK:
        state = _load_config_transaction()
        if state is None:
            return
        state_name = state.get("state")
        if state_name in {"prepared", "rolling_back", "rollback_failed"}:
            _rollback_config_transaction_locked(state, "controld restart recovery")
        elif state_name == "pending_confirmation":
            deadline = float(state.get("deadline_epoch") or 0)
            if not deadline or time.time() >= deadline:
                _rollback_config_transaction_locked(
                    state, "confirmation timeout expired during restart"
                )
            else:
                _schedule_config_transaction_watchdog(
                    str(state["transaction_id"]), deadline
                )


def _decode_geoip_payload(encoded: str, expected_keys: set[str]) -> dict[str, object]:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid GeoIP request encoding") from exc
    if not raw or len(raw) > GEOIP_MAX_SELECTION_BYTES:
        raise ValueError("invalid GeoIP request size")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid GeoIP request JSON") from exc
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("invalid GeoIP request fields")
    return value


def _geoip_selection() -> tuple[dict[str, object], bytes]:
    try:
        selection_stat = GEOIP_SELECTION_PATH.lstat()
    except FileNotFoundError:
        return {
            "countries": [],
            "access_filter_enabled": False,
            "revision": hashlib.sha256(b"").hexdigest(),
            "available": False,
        }, b""
    if stat.S_ISLNK(selection_stat.st_mode) or not stat.S_ISREG(selection_stat.st_mode):
        raise RuntimeError("GeoIP selection is not a regular file")
    if selection_stat.st_size <= 0 or selection_stat.st_size > GEOIP_MAX_SELECTION_BYTES:
        raise RuntimeError("GeoIP selection has an invalid size")
    raw = GEOIP_SELECTION_PATH.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GeoIP selection is invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "version",
        "countries",
        "access_filter_enabled",
    }:
        raise RuntimeError("GeoIP selection has an invalid format")
    countries = value.get("countries")
    enabled = value.get("access_filter_enabled")
    if value.get("version") != 1 or not isinstance(countries, list) or not isinstance(enabled, bool):
        raise RuntimeError("GeoIP selection has an invalid format")
    normalized: set[str] = set()
    for code in countries:
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z]{2}", code):
            raise RuntimeError("GeoIP selection contains an invalid country code")
        normalized.add(code)
    if len(normalized) != len(countries) or list(countries) != sorted(normalized):
        raise RuntimeError("GeoIP selection countries are not canonical")
    return {
        "available": True,
        "countries": list(countries),
        "access_filter_enabled": enabled,
        "revision": hashlib.sha256(raw).hexdigest(),
    }, raw


def _geoip_current_release() -> Path | None:
    current = GEOIP_DIRECTORY / "current"
    try:
        target = current.resolve(strict=True)
        releases = GEOIP_RELEASES_PATH.resolve(strict=True)
        target.relative_to(releases)
        target_stat = target.lstat()
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return None
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISDIR(target_stat.st_mode):
        return None
    return target


def _read_geoip_state(release: Path) -> dict[str, object]:
    path = release / "state.json"
    try:
        state_stat = path.lstat()
    except FileNotFoundError:
        return {}
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
        return {}
    if state_stat.st_size <= 0 or state_stat.st_size > GEOIP_MAX_STATE_BYTES:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _sha256_matches(path: Path, expected: object) -> bool:
    expected_text = str(expected or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_text):
        return False
    try:
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return secrets.compare_digest(digest.hexdigest(), expected_text)
    except OSError:
        return False


def _systemd_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    if unit not in {GEOIP_UPDATE_SERVICE, GEOIP_UPDATE_TIMER}:
        raise ValueError("unsupported systemd unit")
    argv = ["/usr/bin/systemctl", "show", unit]
    for name in properties:
        argv.append(f"--property={name}")
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout or "systemctl failed").strip()[:2000]}
    output: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in properties:
            output[key] = value
    return output


def _geoip_journal_tail(lines: int = 20) -> list[str]:
    safe_lines = min(max(int(lines), 1), 100)
    try:
        result = subprocess.run(
            [
                "/usr/bin/journalctl",
                "-u",
                GEOIP_UPDATE_SERVICE,
                "--no-pager",
                "-q",
                "-o",
                "short-iso",
                "--lines",
                str(safe_lines),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"journal unavailable: {exc}"]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "journalctl failed").strip()
        return [f"journal unavailable: {detail[:1000]}"]
    return [line[:4000] for line in result.stdout.splitlines()[-safe_lines:]]
