"""UDP failover management, Unix-socket router, and CLI entrypoint."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socket
import subprocess
import threading
from datetime import datetime, timezone

from .constants import (
    ASSISTANT_REBOOT_MARKER,
    BAN_TABLE,
    CONFIG_TRANSACTION_ACTIVE_STATES,
    CONTROL_SOCKET,
    GEOIP_ALLOWED_SCHEDULES,
    GEOIP_FORCE_MARKER,
    GEOIP_MAX_COUNTRIES,
    GEOIP_TIMER_DROPIN,
    GEOIP_UPDATE_COMMAND,
    GEOIP_UPDATE_SERVICE,
    GEOIP_UPDATE_TIMEOUT,
    GEOIP_UPDATE_TIMER,
    INTERVAL,
    IPSET_NAME,
    LOG,
    LOG_LIMIT,
    MAINTENANCE_REBOOT_MARKER,
    MAX_COMMAND_BYTES,
    SOCKET_PATH,
    UDP_FAILOVER,
    UDP_MAX_PORT_RANGE,
    _GEOIP_OPERATION_LOCK,
    _GUARDED_APPLY_LOCK,
    _read_udp_forward_state,
    _send_control_json,
    _udp_ports_in_use,
    certs_backup_b64,
    certs_restore_b64,
    run_cmd,
    udp_failover_loop,
)
from .ipset_bans import (
    _LOGS_IP_CACHE_MAX_LIMIT,
    _sort_log_lines_by_time,
    bans_loop,
    grep_last_logs_for_ip,
    logs_attackers,
    sync_bans_once,
)
from .transactions import (
    _ensure_no_active_config_transaction_locked,
    _load_config_transaction,
    cmd_reload,
    get_config_version,
    haproxy_apply_config_guarded,
    haproxy_check_config_from_b64,
    haproxy_write_config_serialized,
    list_config_versions,
)
from .rollback_geoip import (
    _decode_geoip_payload,
    _geoip_current_release,
    _geoip_journal_tail,
    _geoip_selection,
    _read_geoip_state,
    _sha256_matches,
    _systemd_properties,
    begin_config_transaction,
    config_transaction_status,
    confirm_config_transaction,
    recover_config_transaction,
    rollback_config_transaction,
)

def geoip_status() -> dict[str, object]:
    selection_error = None
    try:
        selection, _ = _geoip_selection()
    except Exception as exc:  # noqa: BLE001
        selection_error = str(exc)
        selection = {
            "available": False,
            "countries": [],
            "access_filter_enabled": False,
            "revision": "",
        }

    database: dict[str, object] = {"available": False, "integrity_ok": False}
    release = _geoip_current_release()
    if release is not None:
        state = _read_geoip_state(release)
        database_path = release / "dbip-country-lite.mmdb"
        allowed_path = release / "allowed.geo"
        try:
            database_size = database_path.stat().st_size
        except OSError:
            database_size = 0
        try:
            allowed_size = allowed_path.stat().st_size
        except OSError:
            allowed_size = 0
        build_epoch = int(state.get("database_build_epoch") or 0)
        build_at = (
            datetime.fromtimestamp(build_epoch, timezone.utc).isoformat()
            if build_epoch > 0
            else None
        )
        integrity_ok = (
            state.get("release_format_version") == 1
            and _sha256_matches(database_path, state.get("database_sha256"))
            and _sha256_matches(allowed_path, state.get("allowed_sha256"))
        )
        database = {
            "available": bool(database_size and state),
            "release": release.name,
            "provider": str(state.get("provider") or ""),
            "source_period": str(state.get("source_period") or ""),
            "activated_at": state.get("activated_at"),
            "build_at": build_at,
            "records": int(state.get("database_records") or 0),
            "size_bytes": database_size,
            "allowed_size_bytes": allowed_size,
            "allowed_networks": int(state.get("allowed_networks") or 0),
            "country_networks": state.get("country_networks")
            if isinstance(state.get("country_networks"), dict)
            else {},
            "countries": state.get("countries")
            if isinstance(state.get("countries"), list)
            else [],
            "access_filter_enabled": bool(state.get("access_filter_enabled")),
            "integrity_ok": integrity_ok,
        }

    service_raw = _systemd_properties(
        GEOIP_UPDATE_SERVICE,
        (
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainStatus",
            "InactiveExitTimestamp",
        ),
    )
    timer_raw = _systemd_properties(
        GEOIP_UPDATE_TIMER,
        (
            "ActiveState",
            "SubState",
            "UnitFileState",
            "LastTriggerUSec",
            "NextElapseUSecRealtime",
        ),
    )
    service = {
        "active_state": service_raw.get("ActiveState", "unknown"),
        "sub_state": service_raw.get("SubState", "unknown"),
        "result": service_raw.get("Result", "unknown"),
        "exit_status": service_raw.get("ExecMainStatus", ""),
        "last_run_at": service_raw.get("InactiveExitTimestamp") or None,
    }
    if service_raw.get("error"):
        service["error"] = service_raw["error"]
    timer = {
        "active_state": timer_raw.get("ActiveState", "unknown"),
        "sub_state": timer_raw.get("SubState", "unknown"),
        "enabled": timer_raw.get("UnitFileState") == "enabled",
        "last_trigger_at": timer_raw.get("LastTriggerUSec") or None,
        "next_run_at": timer_raw.get("NextElapseUSecRealtime") or None,
        "schedule": _geoip_schedule_current(),
    }
    if timer_raw.get("error"):
        timer["error"] = timer_raw["error"]
    result: dict[str, object] = {
        "ok": selection_error is None,
        "database": database,
        "selection": selection,
        "service": service,
        "timer": timer,
        "update_running": service["active_state"] in {"activating", "active"}
        and service["sub_state"] not in {"dead", "exited"},
        "journal_tail": _geoip_journal_tail(),
    }
    if selection_error:
        result["error"] = selection_error
    active_countries = database.get("countries")
    result["selection_applied"] = (
        database.get("available")
        and active_countries == selection.get("countries")
        and database.get("access_filter_enabled")
        == selection.get("access_filter_enabled")
    )
    return result


def _geoip_schedule_current() -> str:
    """Return the effective OnCalendar keyword for the update timer.

    Reads the merged unit (base + drop-ins) via ``systemctl cat``; the last
    non-empty OnCalendar wins, matching systemd's override semantics.
    """
    try:
        out = subprocess.run(
            ["/usr/bin/systemctl", "cat", GEOIP_UPDATE_TIMER],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    value = ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("OnCalendar="):
            value = stripped.split("=", 1)[1].strip()
    return value


def geoip_set_schedule(schedule: object) -> dict[str, object]:
    """Override the update cadence via a systemd timer drop-in.

    Only daily/weekly/monthly are accepted, so the UI can never schedule a
    sub-daily run or inject an arbitrary systemd calendar expression.
    """
    value = str(schedule or "").strip().lower()
    if value not in GEOIP_ALLOWED_SCHEDULES:
        return {
            "ok": False,
            "error": "schedule must be one of: "
            + ", ".join(GEOIP_ALLOWED_SCHEDULES),
        }
    content = (
        "# Managed by the easy-ha-proxy web UI.\n"
        "[Timer]\n"
        "OnCalendar=\n"
        f"OnCalendar={value}\n"
    )
    try:
        GEOIP_TIMER_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        tmp = GEOIP_TIMER_DROPIN.with_name(GEOIP_TIMER_DROPIN.name + ".tmp")
        tmp.write_text(content, encoding="ascii")
        os.replace(tmp, GEOIP_TIMER_DROPIN)
    except OSError as exc:
        return {"ok": False, "error": f"cannot write timer override: {exc}"}
    reload_ok, reload_detail = _run_geoip_command(
        ["/usr/bin/systemctl", "daemon-reload"]
    )
    if not reload_ok:
        return {"ok": False, "error": f"daemon-reload failed: {reload_detail}"}
    restart_ok, restart_detail = _run_geoip_command(
        ["/usr/bin/systemctl", "restart", GEOIP_UPDATE_TIMER]
    )
    if not restart_ok:
        return {"ok": False, "error": f"timer restart failed: {restart_detail}"}
    LOG.info("geoip: update schedule set to %s", value)
    result = {
        "ok": True,
        "message": f"GeoIP update schedule set to {value}",
        "schedule": value,
    }
    result["status"] = geoip_status()
    return result


def _run_geoip_command(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=GEOIP_UPDATE_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = "\n".join(
        item.strip() for item in (result.stdout, result.stderr) if item.strip()
    )[-8000:]
    return result.returncode == 0, output


def geoip_update_now(force: bool) -> dict[str, object]:
    if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "another GeoIP operation is already running", "conflict": True}
    try:
        transaction = _load_config_transaction()
        if (
            transaction is not None
            and transaction.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES
        ):
            return {
                "ok": False,
                "error": "a HAProxy configuration transaction is still active",
                "conflict": True,
            }
        service = _systemd_properties(
            GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
        )
        if service.get("ActiveState") in {"activating", "active", "reloading"}:
            return {
                "ok": False,
                "error": "another GeoIP operation is already running",
                "conflict": True,
                "status": geoip_status(),
            }
        marker_created = False
        if force:
            marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                marker_flags |= os.O_NOFOLLOW
            try:
                marker_fd = os.open(GEOIP_FORCE_MARKER, marker_flags, 0o600)
            except FileExistsError:
                return {
                    "ok": False,
                    "error": "a forced GeoIP update is already queued",
                    "conflict": True,
                    "status": geoip_status(),
                }
            try:
                os.write(marker_fd, b"force\n")
                os.fsync(marker_fd)
            finally:
                os.close(marker_fd)
            marker_created = True
        ok, detail = _run_geoip_command(
            ["/usr/bin/systemctl", "start", "--no-block", GEOIP_UPDATE_SERVICE]
        )
        if not ok and marker_created:
            GEOIP_FORCE_MARKER.unlink(missing_ok=True)
        status = geoip_status()
        return {
            "ok": ok,
            "started": ok,
            "message": "GeoIP update started" if ok else "GeoIP update failed",
            "error": None if ok else "GeoIP update failed",
            "stdout": detail,
            "active_acl_preserved": bool(status.get("selection_applied")),
            "status": status,
        }
    finally:
        _GEOIP_OPERATION_LOCK.release()


def geoip_configure(countries: object, expected_revision: object) -> dict[str, object]:
    if not isinstance(countries, list) or len(countries) > GEOIP_MAX_COUNTRIES:
        raise ValueError("countries must be a list with at most 249 entries")
    normalized: set[str] = set()
    for raw in countries:
        if not isinstance(raw, str):
            raise ValueError("country codes must be strings")
        code = raw.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            raise ValueError(f"invalid ISO country code: {raw!r}")
        normalized.add(code)
    selected = sorted(normalized)
    revision = str(expected_revision or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ValueError("the GeoIP selection revision is missing or invalid")
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        return {
            "ok": False,
            "error": "another HAProxy configuration operation is already running",
            "conflict": True,
        }
    try:
        try:
            _ensure_no_active_config_transaction_locked()
        except RuntimeError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "conflict": True,
            }
        if not _GEOIP_OPERATION_LOCK.acquire(blocking=False):
            return {
                "ok": False,
                "error": "another GeoIP operation is already running",
                "conflict": True,
            }
        try:
            service = _systemd_properties(
                GEOIP_UPDATE_SERVICE, ("ActiveState", "SubState")
            )
            if service.get("ActiveState") in {"activating", "active", "reloading"}:
                return {
                    "ok": False,
                    "error": "another GeoIP operation is already running",
                    "conflict": True,
                    "status": geoip_status(),
                }
            _, current_raw = _geoip_selection()
            current_revision = hashlib.sha256(current_raw).hexdigest()
            if not secrets.compare_digest(current_revision, revision):
                return {
                    "ok": False,
                    "error": "GeoIP selection changed in another session; reload it before saving",
                    "conflict": True,
                    "current_revision": current_revision,
                    "status": geoip_status(),
                }
            argv = [GEOIP_UPDATE_COMMAND, "--configure-selection"]
            for code in selected:
                argv.extend(("--country", code))
            ok, detail = _run_geoip_command(argv)
            status = geoip_status()
            return {
                "ok": ok,
                "message": "GeoIP country selection updated"
                if ok
                else "GeoIP country selection update failed",
                "error": None if ok else "GeoIP country selection update failed",
                "stdout": detail,
                "active_acl_preserved": bool(status.get("selection_applied")),
                "status": status,
            }
        finally:
            _GEOIP_OPERATION_LOCK.release()
    finally:
        _GUARDED_APPLY_LOCK.release()


def handle_client(conn: socket.socket) -> None:
    try:
        conn.settimeout(30)
        # read the WHOLE command line (it matters for large base64)
        chunks: list[bytes] = []
        received = 0
        while True:
            data = conn.recv(4096)
            if not data:
                break
            received += len(data)
            if received > MAX_COMMAND_BYTES:
                conn.sendall(b"ERROR command is too large\n")
                return
            chunks.append(data)
            if b"\n" in data:
                break

        if not chunks:
            return

        raw = b"".join(chunks)
        line = raw.split(b"\n", 1)[0]
        cmd = line.decode("utf-8", "replace").strip()

        # Once the update broker has committed a reboot timer, do not admit a
        # new host mutation from another browser tab. Read-only inspection and
        # transaction confirmation/rollback stay available.
        reboot_blocked_exact = {"reload", "udp-apply", "udp-apply-json"}
        reboot_blocked_prefixes = (
            "certs-restore ",
            "write-config ",
            "apply-config ",
            "begin-config-transaction ",
            "geoip-update ",
            "geoip-configure ",
            "geoip-schedule ",
        )
        if (
            os.path.lexists(MAINTENANCE_REBOOT_MARKER)
            or os.path.lexists(ASSISTANT_REBOOT_MARKER)
        ) and (
            cmd in reboot_blocked_exact
            or cmd.startswith(reboot_blocked_prefixes)
        ):
            conn.sendall(b"ERROR a server reboot is scheduled\n")
            return

        # ---- reload ----
        if cmd == "reload":
            ok, msg = cmd_reload()
            if ok:
                conn.sendall(f"OK {msg}\n".encode("utf-8", "replace"))
            else:
                conn.sendall(f"ERROR {msg}\n".encode("utf-8", "replace"))
            return

        # ---- a one-off sync-bans ----
        if cmd == "sync-bans":
            try:
                sync_bans_once()
                conn.sendall(b"OK sync-bans done\n")
            except Exception as e:
                conn.sendall(
                    f"ERROR sync-bans: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- reload UDP forwarding rules (iptables DNAT) ----
        # Re-runs the loader unit synchronously. The JSON command returns the
        # generator's durable /run state, so the UI reports success only after
        # the complete ruleset has been installed.
        if cmd in {"udp-apply", "udp-apply-json"}:
            try:
                run_cmd(
                    ["systemctl", "restart", "iptables-haproxy-udp.service"],
                    timeout=60,
                )
                state = _read_udp_forward_state()
                if cmd == "udp-apply-json":
                    _send_control_json(conn, {"ok": True, **state})
                else:
                    conn.sendall(b"OK udp-apply done\n")
            except Exception as e:
                LOG.error("udp-apply error: %s", e)
                if cmd == "udp-apply-json":
                    _send_control_json(
                        conn,
                        {"ok": False, "error": f"UDP forwarding apply failed: {e}"},
                    )
                else:
                    conn.sendall(
                        f"ERROR udp-apply: {e}\n".encode("utf-8", "replace")
                    )
            return

        if cmd == "udp-status":
            try:
                _send_control_json(
                    conn,
                    {"ok": True, **_read_udp_forward_state(), "failover": UDP_FAILOVER.public_state()},
                )
            except Exception as exc:
                _send_control_json(
                    conn,
                    {"ok": False, "error": str(exc)[:4000]},
                )
            return

        # ---- check whether a host UDP listen port/range is already occupied ----
        if cmd.startswith("udp-port-check"):
            parts = cmd.split()
            try:
                start = int(parts[1])
                end = int(parts[2]) if len(parts) >= 3 else start
                if (
                    not 1 <= start <= end <= 65535
                    or end - start + 1 > UDP_MAX_PORT_RANGE
                ):
                    raise ValueError
            except (IndexError, ValueError):
                conn.sendall(b"ERROR udp-port-check: invalid port range\n")
                return
            busy = _udp_ports_in_use(start, end)
            if busy:
                conn.sendall(f"OK busy {min(busy)}\n".encode("ascii"))
            else:
                conn.sendall(f"OK free {start}-{end}\n".encode("ascii"))
            return

        # ---- certificate backup ----
        if cmd == "certs-backup":
            try:
                b64 = certs_backup_b64()
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                LOG.error("certs-backup error: %s", e)
                conn.sendall(
                    f"ERROR certs-backup: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- certificate restore ----
        if cmd.startswith("certs-restore "):
            try:
                _, b64 = cmd.split(" ", 1)
                msg = certs_restore_b64(b64)
                conn.sendall(f"OK {msg}\n".encode("utf-8", "replace"))
            except Exception as e:
                LOG.error("certs-restore error: %s", e)
                conn.sendall(
                    f"ERROR certs-restore: {e}\n".encode("utf-8", "replace")
                )
            return

        # ---- configuration check, haproxy -c ----
        if cmd.startswith("check-config "):
            try:
                _, cfg_b64 = cmd.split(" ", 1)
                rc, stdout, stderr = haproxy_check_config_from_b64(cfg_b64)

                stdout_b64 = base64.b64encode(
                    (stdout or "").encode("utf-8", "replace")
                ).decode("ascii")
                stderr_b64 = base64.b64encode(
                    (stderr or "").encode("utf-8", "replace")
                ).decode("ascii")

                resp = f"OK {rc}\n{stdout_b64}\n{stderr_b64}\n"
                conn.sendall(resp.encode("utf-8", "replace"))
            except Exception as e:
                msg = f"ERROR check-config: {e}"
                conn.sendall(msg.encode("utf-8", "replace"))
            return

        # ---- write the configuration /etc/haproxy/haproxy.cfg ----
        if cmd.startswith("write-config "):
            try:
                _, cfg_b64 = cmd.split(" ", 1)
                haproxy_write_config_serialized(cfg_b64)
                conn.sendall(b"OK wrote haproxy.cfg\n")
            except Exception as e:
                msg = f"ERROR write-config: {e}\n"
                conn.sendall(msg.encode("utf-8", "replace"))
            return

        # ---- transactional config apply with critical-service rollback ----
        if cmd.startswith("apply-config "):
            try:
                parts = cmd.split(" ", 2)
                if len(parts) != 3:
                    raise ValueError("apply-config requires config and checks payloads")
                result = haproxy_apply_config_guarded(parts[1], parts[2])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as e:
                result = {
                    "ok": False,
                    "applied": False,
                    "rolled_back": False,
                    "rollback_ok": None,
                    "failure": f"guarded apply request failed: {e}",
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- confirmable config transaction with a server-side deadline ----
        if cmd.startswith("begin-config-transaction "):
            try:
                parts = cmd.split(" ", 4)
                if len(parts) != 5:
                    raise ValueError(
                        "begin-config-transaction requires config, checks, "
                        "sources, and timeout payloads"
                    )
                result = begin_config_transaction(
                    parts[1], parts[2], parts[3], parts[4]
                )
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("pending") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd == "config-versions" or cmd.startswith("config-versions "):
            try:
                parts = cmd.split()
                if len(parts) > 2:
                    raise ValueError("config-versions accepts one optional limit")
                limit = int(parts[1]) if len(parts) == 2 else 50
                result = {"ok": True, "versions": list_config_versions(limit)}
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "failure": str(exc)[:4000]}
            payload = base64.b64encode(
                json.dumps(result, ensure_ascii=False).encode("utf-8")
            ).decode("ascii")
            conn.sendall(
                f"{'OK' if result.get('ok') else 'ERROR'} {payload}\n".encode("ascii")
            )
            return

        if cmd.startswith("config-version "):
            try:
                parts = cmd.split()
                if len(parts) != 2:
                    raise ValueError("config-version accepts exactly one id")
                result = {"ok": True, "version": get_config_version(parts[1])}
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "failure": str(exc)[:4000]}
            payload = base64.b64encode(
                json.dumps(result, ensure_ascii=False).encode("utf-8")
            ).decode("ascii")
            conn.sendall(
                f"{'OK' if result.get('ok') else 'ERROR'} {payload}\n".encode("ascii")
            )
            return

        if cmd == "config-transaction-status" or cmd.startswith(
            "config-transaction-status "
        ):
            try:
                parts = cmd.split()
                if len(parts) > 2:
                    raise ValueError("config-transaction-status accepts one optional id")
                result = config_transaction_status(parts[1] if len(parts) == 2 else "")
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"OK {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("confirm-config-transaction "):
            try:
                parts = cmd.split()
                if len(parts) != 3:
                    raise ValueError(
                        "confirm-config-transaction requires id and candidate hash"
                    )
                result = confirm_config_transaction(parts[1], parts[2])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("rollback-config-transaction "):
            try:
                parts = cmd.split()
                if len(parts) != 2:
                    raise ValueError("rollback-config-transaction requires an id")
                result = rollback_config_transaction(parts[1])
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("state") == "rolled_back" else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {
                    "ok": False,
                    "state": "error",
                    "pending": False,
                    "failure": str(exc)[:4000],
                }
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- local GeoIP database and runtime country selection ----
        if cmd == "geoip-status":
            try:
                result = geoip_status()
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-update "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(parts[1], {"force"})
                force = request_payload.get("force")
                if not isinstance(force, bool):
                    raise ValueError("force must be boolean")
                result = geoip_update_now(force)
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-configure "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(
                    parts[1], {"countries", "revision"}
                )
                result = geoip_configure(
                    request_payload.get("countries"),
                    request_payload.get("revision"),
                )
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        if cmd.startswith("geoip-schedule "):
            try:
                parts = cmd.split(" ", 1)
                request_payload = _decode_geoip_payload(parts[1], {"schedule"})
                result = geoip_set_schedule(request_payload.get("schedule"))
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                prefix = "OK" if result.get("ok") else "ERROR"
                conn.sendall(f"{prefix} {payload}\n".encode("ascii"))
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": str(exc)[:4000]}
                payload = base64.b64encode(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                ).decode("ascii")
                conn.sendall(f"ERROR {payload}\n".encode("ascii"))
            return

        # ---- logs-ip ----
        if cmd.startswith("logs-ip "):
            try:
                _, rest = cmd.split(" ", 1)
                parts = rest.split()
                if not parts:
                    conn.sendall(b"ERROR logs-ip: missing ip\n")
                    return

                ip = parts[0].strip()
                n = int(parts[1]) if len(parts) >= 2 else LOG_LIMIT
                n = max(1, min(n, _LOGS_IP_CACHE_MAX_LIMIT))

                # validate the IP
                ipaddress.ip_address(ip)

                lines = grep_last_logs_for_ip(ip, limit=n)
                lines = _sort_log_lines_by_time(lines)
                payload = "\n".join(lines).encode("utf-8", "replace")
                b64 = base64.b64encode(payload).decode("ascii")
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                conn.sendall(
                    f"ERROR logs-ip: {e}\n".encode("utf-8", "replace"))
            return

        # ---- logs-attackers ----
        if cmd == "logs-attackers":
            try:
                data = logs_attackers()
                payload = json.dumps(data, ensure_ascii=False).encode(
                    "utf-8", "replace")
                b64 = base64.b64encode(payload).decode("ascii")
                conn.sendall(f"OK {b64}\n".encode("utf-8", "replace"))
            except Exception as e:
                conn.sendall(
                    f"ERROR logs-attackers: {e}\n".encode("utf-8", "replace"))
            return

        # ---- ping ----
        if cmd == "ping":
            conn.sendall(b"OK pong\n")
            return

        conn.sendall(b"ERROR unknown command\n")
    except Exception as e:
        LOG.error("Error while handling client: %s", e)
        try:
            conn.sendall(f"ERROR exception: {e}\n".encode("utf-8", "replace"))
        except Exception:
            pass


def control_socket_loop() -> None:
    """
    The main loop: listen on the Unix socket and take commands.

    Each client is served in its own thread, so heavy commands (logs-ip, for
    example) do not hold up the next connections.
    """
    sock_path = CONTROL_SOCKET
    sock_dir = os.path.dirname(sock_path) or "/run"

    # remove an old socket left behind
    try:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    except OSError as e:
        LOG.error("Failed to unlink old socket %s: %s", sock_path, e)
        return

    os.makedirs(sock_dir, exist_ok=True)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(sock_path)
        os.chmod(sock_path, 0o660)
        srv.listen(5)
        LOG.info("haproxy-controld is listening on %s", sock_path)
    except Exception as e:
        LOG.error("Failed to bind/listen on %s: %s", sock_path, e)
        return

    shutdown_event = threading.Event()
    received_signal: list[int] = []

    def _handle_signal(signum: int, _frame: object) -> None:
        if not received_signal:
            received_signal.append(signum)
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _handle_signal)

    client_slots = threading.BoundedSemaphore(32)

    def _client_worker(c: socket.socket) -> None:
        try:
            with c:
                handle_client(c)
        finally:
            client_slots.release()

    srv.settimeout(1.0)
    try:
        while not shutdown_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                if shutdown_event.is_set():
                    break
                raise
            if not client_slots.acquire(blocking=False):
                with conn:
                    with contextlib.suppress(OSError):
                        conn.settimeout(1.0)
                        conn.sendall(b"ERROR busy\n")
                continue
            try:
                threading.Thread(
                    target=_client_worker,
                    args=(conn,),
                    daemon=True,
                    name="controld-client",
                ).start()
            except Exception:
                client_slots.release()
                conn.close()
                raise
    finally:
        if received_signal:
            LOG.info("Received signal %s; shutting down", received_signal[0])
        try:
            srv.close()
        finally:
            if os.path.exists(sock_path):
                os.unlink(sock_path)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    LOG.info(
        "Starting haproxy-controld: SOCKET_PATH=%s, BAN_TABLE=%s, "
        "IPSET_NAME=%s, INTERVAL=%ss, CONTROL_SOCKET=%s",
        SOCKET_PATH,
        BAN_TABLE,
        IPSET_NAME,
        INTERVAL,
        CONTROL_SOCKET,
    )

    try:
        recover_config_transaction()
    except Exception:  # noqa: BLE001
        # Do not silently discard an incomplete transaction. Keeping the
        # daemon available lets an authenticated administrator inspect and
        # retry a rollback through the control socket.
        LOG.exception("Could not recover the persisted HAProxy config transaction")

    # Start the background ban synchronisation thread
    threading.Thread(target=udp_failover_loop, daemon=True, name="udp-failover-loop").start()
    t = threading.Thread(target=bans_loop, daemon=True, name="ban-sync-loop")
    t.start()

    # The main thread loops over the control socket
    control_socket_loop()
