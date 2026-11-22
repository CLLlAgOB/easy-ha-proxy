"""HAProxy configuration validation and guarded apply transactions."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    ADMIN_ALLOWLIST_MAX_BYTES,
    ADMIN_ALLOWLIST_MAX_ENTRIES,
    ADMIN_ALLOWLIST_PATH,
    CONFIG_BACKUP_DIR,
    CONFIG_HISTORY_DIR,
    CONFIG_HISTORY_KEEP,
    CONFIG_HISTORY_META,
    CONFIG_SOURCE_DIR,
    CONFIG_SOURCE_FILENAMES,
    CONFIG_TRANSACTION_ACTIVE_STATES,
    CONFIG_TRANSACTION_DIR,
    CONFIG_TRANSACTION_STATE,
    CONFIG_TRANSACTION_VERSION,
    CONTROL_PLANE_CHECK_ATTEMPTS,
    CONTROL_PLANE_CHECK_INTERVAL,
    CONTROL_PLANE_CHECK_TIMEOUT,
    GEOIP_MAX_COUNTRIES,
    GUARDED_CONFIG_BACKUPS,
    HAPROXY_BIN,
    HAPROXY_CFG_PATH,
    HAPROXY_CHECK_TIMEOUT_SECONDS,
    HAPROXY_RELOAD_TIMEOUT_SECONDS,
    LOG,
    MAX_CONFIG_BYTES,
    MAX_TRANSACTION_SOURCES_PAYLOAD_BYTES,
    MAX_TRANSACTION_SOURCE_FILE_BYTES,
    MAX_TRANSACTION_STATE_BYTES,
    SYSTEMCTL_CMD,
    _GUARDED_APPLY_LOCK,
    report_alert,
)
from .ipset_bans import dump_server_state

# Bound across sibling submodules when the package finishes loading.
_rollback_config_transaction_locked: Any = None
_verify_transaction_admin_allowlist_candidate: Any = None
_verify_transaction_geoip_candidate: Any = None

def cmd_reload() -> tuple[bool, str]:
    """
    Run systemctl reload haproxy.
    """
    dump_server_state()
    try:
        LOG.info("Executing reload command: %s", SYSTEMCTL_CMD)
        proc = subprocess.run(
            SYSTEMCTL_CMD.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=HAPROXY_RELOAD_TIMEOUT_SECONDS,
        )
        if proc.returncode == 0:
            msg = (proc.stdout or "reloaded").strip()
            return True, msg
        err = (proc.stderr or f"systemctl exit code {proc.returncode}").strip()
        return False, err
    except subprocess.TimeoutExpired:
        return False, (
            f"the reload did not finish within {HAPROXY_RELOAD_TIMEOUT_SECONDS} "
            "seconds and was stopped"
        )
    except Exception as e:
        return False, f"reload exception: {e!r}"


def haproxy_check_config_from_b64(b64: str) -> tuple[int, str, str]:
    """
    Takes base64(cfg_text), writes it to a temporary file
    and runs `haproxy -c -f <tmpfile>` on the host.

    Returns (rc, stdout, stderr).
    """
    raw = base64.b64decode(b64, validate=True)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("HAProxy configuration exceeds the allowed size")
    _enforce_config_policy(raw)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, prefix="hapadm-check-", suffix=".cfg"
        ) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name

        try:
            proc = subprocess.run(
                [HAPROXY_BIN, "-c", "-f", tmp_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=HAPROXY_CHECK_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return 124, "", (
                f"haproxy -c did not finish within {HAPROXY_CHECK_TIMEOUT_SECONDS} "
                "seconds and was stopped"
            )
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _unfold_haproxy_lines(text: str) -> list[str]:
    """Join backslash-continued lines the way HAProxy parses them."""
    logical: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        if pending:
            combined = pending + raw_line
        else:
            combined = raw_line
        # Odd count of trailing backslashes means line continuation.
        stripped_r = combined.rstrip("\r")
        trailing = len(stripped_r) - len(stripped_r.rstrip("\\"))
        if trailing % 2 == 1:
            pending = stripped_r[:-1]
            continue
        logical.append(stripped_r)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def _normalized_prefix_path(raw_path: str, allowed_prefix: str) -> bool:
    """True when raw_path is an absolute normalized path strictly under allowed_prefix."""
    if not raw_path or not raw_path.startswith("/") or "\x00" in raw_path:
        return False
    if ".." in Path(raw_path).parts:
        return False
    normalized = os.path.normpath(raw_path)
    prefix = allowed_prefix.rstrip("/")
    return normalized.startswith(prefix + "/")


def _enforce_config_policy(raw: bytes) -> None:
    """Keep the config editor from turning HAProxy into a root command runner."""
    text = raw.decode("utf-8")
    forbidden = {
        "program", "pidfile", "module-load", "setuid", "setgid",
        "uid", "gid", "external-check", "external-check-path",
        "external-check-command", "lua-load-per-thread", "setenv",
        "presetenv", "ssl-engine", "insecure-fork-wanted",
        "insecure-setuid-wanted",
    }
    section_headers = {
        "defaults", "frontend", "backend", "listen", "resolvers",
        "mailers", "peers", "userlist", "cache", "program", "ring",
        "log-forward", "fcgi-app", "crt-store", "traces",
        "http-errors", "acme",
    }
    allowed_global = {
        "log", "nbthread", "maxconn", "chroot", "stats", "user", "group",
        "daemon", "ca-base", "crt-base", "ssl-default-bind-ciphersuites",
        "ssl-default-bind-ciphers", "ssl-default-bind-options", "localpeer",
        "lua-prepend-path", "lua-load", "server-state-file",
    }
    in_global = False
    saw_global = False
    required = {"user": False, "group": False, "chroot": False}
    # Never accept arbitrary preprocessing: it could make the privilege-drop
    # lines visible to this validator but invisible to the executing binary.
    # Only the two complete, fixed compatibility blocks emitted by our
    # template are accepted, and their bodies still pass the normal policy.
    compatibility_blocks = {
        ".if version_atleast(3.1)": "tune.lua.bool-sample-conversion normal",
        ".if !feature(OPENSSL_AWSLC)": "tune.ssl.default-dh-param 2048",
    }
    conditional_body = None
    conditional_body_seen = False

    for raw_line in _unfold_haproxy_lines(text):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        token = parts[0].lower()
        if conditional_body is not None:
            if not raw_line[:1].isspace():
                raise ValueError("HAProxy compatibility block must stay inside global")
            if conditional_body_seen:
                if line != ".endif":
                    raise ValueError("invalid HAProxy compatibility block ending")
                conditional_body = None
                conditional_body_seen = False
                continue
            if line != conditional_body:
                raise ValueError("invalid HAProxy compatibility block body")
            conditional_body_seen = True
        elif token.startswith("."):
            if not in_global or not raw_line[:1].isspace() or line not in compatibility_blocks:
                raise ValueError("unapproved HAProxy conditional directive")
            conditional_body = compatibility_blocks[line]
            continue
        if token in forbidden:
            raise ValueError(f"HAProxy directive '{token}' is not allowed")
        if token == "option" and len(parts) >= 2 and parts[1].lower() == "external-check":
            raise ValueError("HAProxy directive 'option external-check' is not allowed")
        if token == "global":
            if saw_global:
                raise ValueError("multiple global sections are not allowed")
            in_global = True
            saw_global = True
            continue
        if token in section_headers:
            in_global = False
            continue
        if not in_global:
            continue

        if token.startswith("tune."):
            pass
        elif token not in allowed_global:
            raise ValueError(f"global directive '{token}' is not allowed")

        if token == "user":
            required["user"] = len(parts) == 2 and parts[1] == "haproxy"
        elif token == "group":
            required["group"] = len(parts) == 2 and parts[1] == "haproxy"
        elif token == "chroot":
            required["chroot"] = len(parts) == 2 and parts[1] == "/var/lib/haproxy"
        elif token == "stats" and len(parts) >= 2 and parts[1].lower() == "socket":
            if len(parts) < 3 or not _normalized_prefix_path(parts[2], "/run/haproxy/"):
                raise ValueError("HAProxy stats socket must stay under /run/haproxy")
        elif token == "lua-load":
            if len(parts) != 2 or parts[1] != "/etc/haproxy/lua/auth-request.lua":
                raise ValueError("unapproved HAProxy Lua entry point")
        elif token == "lua-prepend-path":
            if len(parts) != 2 or not _normalized_prefix_path(parts[1], "/etc/haproxy/lua/"):
                raise ValueError("HAProxy Lua search path must stay under /etc/haproxy/lua")
        elif token == "server-state-file":
            # Pinned to the chroot this policy already requires, so a pasted
            # configuration cannot point HAProxy at an arbitrary file to read
            # as server state.
            if len(parts) != 2 or not _normalized_prefix_path(parts[1], "/var/lib/haproxy/"):
                raise ValueError(
                    "HAProxy server state file must stay under /var/lib/haproxy"
                )

    if conditional_body is not None:
        raise ValueError("unclosed HAProxy compatibility block")
    if not saw_global or not all(required.values()):
        raise ValueError("required HAProxy privilege-drop directives are missing")


def haproxy_write_config_from_b64(b64: str) -> None:
    """Validate and atomically replace the live HAProxy configuration."""
    raw = base64.b64decode(b64, validate=True)
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("invalid HAProxy configuration size")
    _enforce_config_policy(raw)

    cfg_path = Path(HAPROXY_CFG_PATH)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=cfg_path.parent,
            prefix=".haproxy.cfg.",
        ) as tmp:
            tmp.write(raw)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name

        proc = subprocess.run(
            [HAPROXY_BIN, "-c", "-f", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=HAPROXY_CHECK_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "validation failed").strip()
            raise ValueError(f"HAProxy rejected the configuration: {detail}")

        try:
            current = cfg_path.stat()
            os.chown(tmp_path, current.st_uid, current.st_gid)
            os.chmod(tmp_path, stat.S_IMODE(current.st_mode))
        except FileNotFoundError:
            os.chmod(tmp_path, 0o640)

        os.replace(tmp_path, cfg_path)
        tmp_path = None
        dir_fd = os.open(cfg_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


_CONTROL_PLANE_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_CONTROL_PLANE_ACL_RE = re.compile(
    r"^\s*acl\s+(host_admin|host_authelia)\s+"
    r"hdr\(host\)\s+-i\s+(.+?)\s*$",
    re.MULTILINE,
)
_CONTROL_PLANE_PATHS = {
    "admin": "/api/control-plane-health",
    "authelia": "/api/health",
}


def _decode_control_plane_checks(checks_b64: str) -> list[dict[str, str]]:
    """Decode and strictly validate guarded-apply HTTPS checks."""
    raw = base64.b64decode(checks_b64, validate=True)
    if not raw or len(raw) > 16 * 1024:
        raise ValueError("invalid control-plane check payload size")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, list) or not 1 <= len(payload) <= 2:
        raise ValueError("one or two control-plane checks are required")

    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("invalid control-plane check")
        service = str(item.get("service") or "").strip().lower()
        domain = str(item.get("domain") or "").strip().lower().rstrip(".")
        if service not in _CONTROL_PLANE_PATHS or service in seen:
            raise ValueError("invalid or duplicate control-plane service")
        if not _CONTROL_PLANE_DOMAIN_RE.fullmatch(domain):
            raise ValueError(f"invalid control-plane domain for {service}")
        seen.add(service)
        checks.append({
            "service": service,
            "domain": domain,
            "path": _CONTROL_PLANE_PATHS[service],
        })

    if "admin" not in seen:
        raise ValueError("the HAProxy Admin check is required")
    return checks


def _control_plane_domains_from_config(raw: bytes) -> dict[str, tuple[str, ...]]:
    """Extract protected host ACLs without importing the web application."""
    text = raw.decode("utf-8")
    domains: dict[str, tuple[str, ...]] = {}
    for match in _CONTROL_PLANE_ACL_RE.finditer(text):
        values = tuple(sorted({
            value.strip().lower().rstrip(".")
            for value in match.group(2).split()
            if value.strip()
        }))
        if values:
            domains[match.group(1)] = values
    return domains


def _validate_guarded_control_plane_transition(
    previous: bytes,
    candidate: bytes,
    checks: list[dict[str, str]],
) -> None:
    """Bind checks to unchanged protected ACLs before touching the live file."""
    active_domains = _control_plane_domains_from_config(previous)
    candidate_domains = _control_plane_domains_from_config(candidate)
    if not active_domains.get("host_admin"):
        raise ValueError("the current config has no protected HAProxy Admin domain")
    if active_domains != candidate_domains:
        raise ValueError(
            "protected HAProxy Admin/Authelia domains changed; "
            "use the domain migration workflow"
        )

    expected: dict[str, str] = {}
    mapping = {"host_admin": "admin", "host_authelia": "authelia"}
    for acl_name, service in mapping.items():
        domains = candidate_domains.get(acl_name) or ()
        if len(domains) > 1:
            raise ValueError(f"multiple protected domains found for {service}")
        if domains:
            expected[service] = domains[0]
    supplied = {check["service"]: check["domain"] for check in checks}
    if supplied != expected:
        raise ValueError("control-plane checks do not match the protected domains")


def _create_guarded_config_backup(raw: bytes, candidate_sha256: str) -> str:
    """Persist the known-good config before replacing it."""
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("the current HAProxy configuration cannot be backed up")
    CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = CONFIG_BACKUP_DIR / (
        f"haproxy.cfg.pre-apply.{timestamp}.{candidate_sha256[:12]}"
    )
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=CONFIG_BACKUP_DIR,
            prefix=".haproxy.cfg.pre-apply.",
        ) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_path = handle.name
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, backup)
        tmp_path = None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass

    backups = sorted(
        CONFIG_BACKUP_DIR.glob("haproxy.cfg.pre-apply.*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old_backup in backups[max(1, GUARDED_CONFIG_BACKUPS):]:
        try:
            old_backup.unlink()
        except OSError:
            LOG.warning("Could not remove old HAProxy config backup %s", old_backup)
    return str(backup)


def _probe_control_plane_service(check: dict[str, str]) -> dict[str, object]:
    """Reach a critical service through HAProxy on loopback with real SNI/Host."""
    service = check["service"]
    domain = check["domain"]
    path = check["path"]
    result: dict[str, object] = {
        "service": service,
        "domain": domain,
        "path": path,
        "ok": False,
        "status": None,
        "failure": "",
    }
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(
            ("127.0.0.1", 443), timeout=CONTROL_PLANE_CHECK_TIMEOUT
        ) as raw_socket:
            raw_socket.settimeout(CONTROL_PLANE_CHECK_TIMEOUT)
            with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    "User-Agent: easy-ha-proxy-config-guard/1\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                )
                tls_socket.sendall(request.encode("ascii"))
                response = bytearray()
                while b"\r\n" not in response and len(response) < 8192:
                    chunk = tls_socket.recv(2048)
                    if not chunk:
                        break
                    response.extend(chunk)

        status_line = bytes(response).split(b"\r\n", 1)[0].decode(
            "ascii", "replace"
        )
        match = re.fullmatch(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?", status_line)
        if not match:
            raise RuntimeError(f"invalid HTTP response: {status_line or 'empty'}")
        status = int(match.group(1))
        result["status"] = status
        result["ok"] = status == 200
        if status != 200:
            result["failure"] = f"expected HTTP 200, received HTTP {status}"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = str(exc)
    return result


def _run_control_plane_checks(
    checks: list[dict[str, str]],
) -> list[dict[str, object]]:
    """Retry the complete critical-service set while HAProxy settles."""
    latest: list[dict[str, object]] = []
    attempts = max(1, min(CONTROL_PLANE_CHECK_ATTEMPTS, 30))
    for attempt in range(1, attempts + 1):
        latest = [_probe_control_plane_service(check) for check in checks]
        for result in latest:
            result["attempt"] = attempt
        if all(bool(result.get("ok")) for result in latest):
            return latest
        if attempt < attempts:
            time.sleep(max(0.1, CONTROL_PLANE_CHECK_INTERVAL))
    return latest


def _restore_guarded_config(
    previous_b64: str,
    checks: list[dict[str, str]],
) -> dict[str, object]:
    """Restore, reload, and verify the last known-good HAProxy config."""
    result: dict[str, object] = {
        "ok": False,
        "reload_ok": False,
        "reload_output": "",
        "checks": [],
        "failure": "",
    }
    try:
        haproxy_write_config_from_b64(previous_b64)
        reload_ok, reload_output = cmd_reload()
        result["reload_ok"] = reload_ok
        result["reload_output"] = reload_output
        if not reload_ok:
            result["failure"] = f"rollback reload failed: {reload_output}"
            return result
        rollback_checks = _run_control_plane_checks(checks)
        result["checks"] = rollback_checks
        result["ok"] = all(bool(item.get("ok")) for item in rollback_checks)
        if not result["ok"]:
            result["failure"] = "critical services did not recover after rollback"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = f"rollback failed: {exc}"
    return result


def _haproxy_apply_config_guarded_locked(
    cfg_b64: str,
    checks_b64: str,
) -> dict[str, object]:
    """Apply a candidate config and automatically restore the previous one on failure."""
    checks = _decode_control_plane_checks(checks_b64)
    candidate = base64.b64decode(cfg_b64, validate=True)
    if not candidate or len(candidate) > MAX_CONFIG_BYTES:
        raise ValueError("invalid HAProxy configuration size")

    current_path = Path(HAPROXY_CFG_PATH)
    previous = current_path.read_bytes()
    if not previous or len(previous) > MAX_CONFIG_BYTES:
        raise ValueError("a valid current HAProxy configuration is required for rollback")
    _validate_guarded_control_plane_transition(previous, candidate, checks)

    candidate_sha256 = hashlib.sha256(candidate).hexdigest()
    previous_sha256 = hashlib.sha256(previous).hexdigest()
    backup_path = _create_guarded_config_backup(previous, candidate_sha256)
    previous_b64 = base64.b64encode(previous).decode("ascii")
    result: dict[str, object] = {
        "ok": False,
        "applied": False,
        "rolled_back": False,
        "rollback_ok": None,
        "candidate_sha256": candidate_sha256,
        "previous_sha256": previous_sha256,
        "backup_path": backup_path,
        "checks": [],
        "rollback": None,
        "reload_output": "",
        "failure": "",
    }

    try:
        haproxy_write_config_from_b64(cfg_b64)
        reload_ok, reload_output = cmd_reload()
        result["reload_output"] = reload_output
        if not reload_ok:
            result["failure"] = f"HAProxy reload failed: {reload_output}"
        else:
            check_results = _run_control_plane_checks(checks)
            result["checks"] = check_results
            if all(bool(item.get("ok")) for item in check_results):
                result["ok"] = True
                result["applied"] = True
                return result
            failed = [
                f"{item.get('service')} ({item.get('domain')}): {item.get('failure')}"
                for item in check_results
                if not item.get("ok")
            ]
            result["failure"] = "; ".join(failed) or "critical service check failed"
    except Exception as exc:  # noqa: BLE001
        result["failure"] = f"guarded apply failed: {exc}"

    rollback = _restore_guarded_config(previous_b64, checks)
    result["rolled_back"] = True
    result["rollback"] = rollback
    result["rollback_ok"] = bool(rollback.get("ok"))
    # The browser is told, but an apply can also be rolled back long after the
    # operator closed the tab, and a failed rollback is the worst case there is.
    report_alert(
        "config.apply_failed",
        "haproxy",
        (
            "HAProxy apply failed and was rolled back"
            if rollback.get("ok")
            else "HAProxy apply failed AND the rollback did not succeed"
        ),
        str(result.get("failure") or ""),
    )
    return result


def haproxy_apply_config_guarded(cfg_b64: str, checks_b64: str) -> dict[str, object]:
    """Serialize guarded config changes so backups and rollbacks cannot race."""
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration apply is running")
    try:
        _ensure_no_active_config_transaction_locked()
        return _haproxy_apply_config_guarded_locked(cfg_b64, checks_b64)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _transaction_state_path() -> Path:
    return CONFIG_TRANSACTION_DIR / CONFIG_TRANSACTION_STATE


def _ensure_transaction_dir() -> Path:
    """Create the root-owned transaction directory without accepting symlinks."""
    CONFIG_TRANSACTION_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory_stat = CONFIG_TRANSACTION_DIR.lstat()
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        raise RuntimeError("HAProxy config transaction path is not a safe directory")
    os.chmod(CONFIG_TRANSACTION_DIR, 0o700)
    return CONFIG_TRANSACTION_DIR


def _persist_config_transaction(state: dict[str, object]) -> None:
    """Atomically persist private transaction state for restart recovery."""
    directory = _ensure_transaction_dir()
    raw = json.dumps(
        state,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not raw or len(raw) > MAX_TRANSACTION_STATE_BYTES:
        raise RuntimeError("HAProxy config transaction state exceeds the size limit")

    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=directory,
            prefix=".transaction.",
        ) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = handle.name
        os.chmod(temporary, 0o600)
        os.replace(temporary, _transaction_state_path())
        temporary = None
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _load_config_transaction() -> dict[str, object] | None:
    path = _transaction_state_path()
    try:
        state_stat = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
        raise RuntimeError("HAProxy config transaction state is not a regular file")
    if state_stat.st_size <= 0 or state_stat.st_size > MAX_TRANSACTION_STATE_BYTES:
        raise RuntimeError("HAProxy config transaction state has an invalid size")
    raw = path.read_bytes()
    state = json.loads(raw.decode("utf-8"))
    if not isinstance(state, dict) or state.get("version") != CONFIG_TRANSACTION_VERSION:
        raise RuntimeError("HAProxy config transaction state has an invalid format")
    transaction_id = state.get("transaction_id")
    if not isinstance(transaction_id, str) or not transaction_id:
        raise RuntimeError("HAProxy config transaction state has no transaction id")
    return state


def _ensure_no_active_config_transaction_locked() -> None:
    """Keep legacy writes from bypassing a confirmable transaction."""
    state = _load_config_transaction()
    if state is None:
        return
    if state.get("state") == "pending_confirmation":
        deadline = float(state.get("deadline_epoch") or 0)
        if deadline and time.time() >= deadline:
            _rollback_config_transaction_locked(
                state, "confirmation timeout expired before another config write"
            )
            state = _load_config_transaction()
    if state is not None and state.get("state") in CONFIG_TRANSACTION_ACTIVE_STATES:
        raise RuntimeError(
            "another HAProxy config transaction is still active"
        )


def haproxy_write_config_serialized(cfg_b64: str) -> None:
    """Preserve legacy write-config while respecting pending transactions."""
    if not _GUARDED_APPLY_LOCK.acquire(blocking=False):
        raise RuntimeError("another guarded HAProxy configuration operation is running")
    try:
        _ensure_no_active_config_transaction_locked()
        haproxy_write_config_from_b64(cfg_b64)
    finally:
        _GUARDED_APPLY_LOCK.release()


def _canonical_admin_allowlist_entries(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > ADMIN_ALLOWLIST_MAX_ENTRIES:
        raise ValueError("admin allow list must contain at most 256 entries")
    result: list[str] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError("admin allow list entries must be strings")
        text = raw.strip()
        if not text:
            continue
        try:
            canonical = (
                str(ipaddress.ip_network(text, strict=False))
                if "/" in text
                else str(ipaddress.ip_address(text))
            )
        except ValueError as exc:
            raise ValueError(f"invalid admin allow list entry: {text!r}") from exc
        if canonical not in seen:
            result.append(canonical)
            seen.add(canonical)
    return result


def _decode_config_transaction_sources(
    sources_b64: str,
) -> tuple[
    dict[str, bytes],
    dict[str, bytes],
    dict[str, object] | None,
    list[str] | None,
]:
    """Decode the fixed-name YAML mappings and optional GeoIP selection."""
    raw = base64.b64decode(sources_b64, validate=True)
    if not raw or len(raw) > MAX_TRANSACTION_SOURCES_PAYLOAD_BYTES:
        raise ValueError("invalid config source payload size")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not {"candidate", "previous"}.issubset(payload):
        raise ValueError("config sources must contain candidate and previous mappings")
    if not set(payload).issubset({
        "candidate", "previous", "geoip_selection", "admin_allowlist"
    }):
        raise ValueError("config sources contain unsupported transaction fields")

    decoded: dict[str, dict[str, bytes]] = {}
    for group in ("candidate", "previous"):
        mapping = payload.get(group)
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError(f"config source {group} mapping is empty")
        if not set(mapping).issubset(CONFIG_SOURCE_FILENAMES):
            raise ValueError("config source payload contains an unsupported filename")
        group_decoded: dict[str, bytes] = {}
        for filename, encoded in mapping.items():
            if not isinstance(encoded, str):
                raise ValueError(f"invalid encoded content for {filename}")
            content = base64.b64decode(encoded, validate=True)
            if len(content) > MAX_TRANSACTION_SOURCE_FILE_BYTES:
                raise ValueError(f"config source {filename} exceeds the size limit")
            if b"\x00" in content:
                raise ValueError(f"config source {filename} contains a NUL byte")
            content.decode("utf-8")
            group_decoded[filename] = content
        decoded[group] = group_decoded

    if set(decoded["candidate"]) != set(decoded["previous"]):
        raise ValueError("candidate and previous config source filenames differ")

    geoip_selection_raw = payload.get("geoip_selection")
    geoip_selection: dict[str, object] | None = None
    if geoip_selection_raw is not None:
        if not isinstance(geoip_selection_raw, dict) or set(geoip_selection_raw) != {
            "version",
            "countries",
            "access_filter_enabled",
        }:
            raise ValueError("config GeoIP selection has an invalid format")
        countries_raw = geoip_selection_raw.get("countries")
        enabled = geoip_selection_raw.get("access_filter_enabled")
        if (
            geoip_selection_raw.get("version") != 1
            or not isinstance(countries_raw, list)
            or not isinstance(enabled, bool)
            or len(countries_raw) > GEOIP_MAX_COUNTRIES
        ):
            raise ValueError("config GeoIP selection has an invalid format")
        countries: list[str] = []
        for code in countries_raw:
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z]{2}", code):
                raise ValueError("config GeoIP selection contains an invalid country code")
            countries.append(code)
        if countries != sorted(set(countries)):
            raise ValueError("config GeoIP selection countries are not canonical")
        if enabled and not countries:
            raise ValueError(
                "GeoIP filtering cannot be enabled without selected countries"
            )
        geoip_selection = {
            "version": 1,
            "countries": countries,
            "access_filter_enabled": enabled,
        }
    admin_allowlist_raw = payload.get("admin_allowlist")
    admin_allowlist = (
        _canonical_admin_allowlist_entries(admin_allowlist_raw)
        if admin_allowlist_raw is not None
        else None
    )
    return (
        decoded["candidate"],
        decoded["previous"],
        geoip_selection,
        admin_allowlist,
    )


def _open_config_source_directory() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(CONFIG_SOURCE_DIR, flags)
    except OSError as exc:
        raise RuntimeError("HAProxy config source directory is unavailable or unsafe") from exc


def _read_config_source_at(directory_fd: int, filename: str) -> tuple[bytes, os.stat_result]:
    if filename not in CONFIG_SOURCE_FILENAMES:
        raise ValueError("unsupported config source filename")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RuntimeError(f"config source {filename} is unavailable or unsafe") from exc
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise RuntimeError(f"config source {filename} is not a regular file")
        if source_stat.st_size > MAX_TRANSACTION_SOURCE_FILE_BYTES:
            raise RuntimeError(f"config source {filename} exceeds the size limit")
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_TRANSACTION_SOURCE_FILE_BYTES:
                raise RuntimeError(f"config source {filename} exceeds the size limit")
            chunks.append(chunk)
        return b"".join(chunks), source_stat
    finally:
        os.close(source_fd)


def _verify_candidate_config_sources(candidate: dict[str, bytes]) -> None:
    directory_fd = _open_config_source_directory()
    try:
        for filename, expected in candidate.items():
            current, _ = _read_config_source_at(directory_fd, filename)
            if not secrets.compare_digest(current, expected):
                raise ValueError(
                    f"live config source {filename} changed before the transaction"
                )
    finally:
        os.close(directory_fd)


def _verify_live_transaction_candidate(state: dict[str, object]) -> None:
    """Verify that HAProxy and YAML still match the pending candidate."""
    expected_config_sha256 = str(state.get("candidate_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_config_sha256):
        raise RuntimeError("persisted candidate config hash is invalid")
    current_config = Path(HAPROXY_CFG_PATH).read_bytes()
    if not current_config or len(current_config) > MAX_CONFIG_BYTES:
        raise RuntimeError("live HAProxy configuration has an invalid size")
    current_config_sha256 = hashlib.sha256(current_config).hexdigest()
    if not secrets.compare_digest(current_config_sha256, expected_config_sha256):
        raise RuntimeError("live HAProxy configuration changed before confirmation")

    expected_sources = state.get("candidate_source_sha256")
    if (
        not isinstance(expected_sources, dict)
        or not expected_sources
        or not set(expected_sources).issubset(CONFIG_SOURCE_FILENAMES)
    ):
        raise RuntimeError("persisted candidate config source hashes are invalid")
    directory_fd = _open_config_source_directory()
    try:
        for filename, expected_hash_raw in expected_sources.items():
            expected_hash = str(expected_hash_raw)
            if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise RuntimeError(
                    f"persisted candidate hash for {filename} is invalid"
                )
            current_source, _ = _read_config_source_at(directory_fd, filename)
            current_hash = hashlib.sha256(current_source).hexdigest()
            if not secrets.compare_digest(current_hash, expected_hash):
                raise RuntimeError(
                    f"live config source {filename} changed before confirmation"
                )
    finally:
        os.close(directory_fd)
    _verify_transaction_admin_allowlist_candidate(state)
    _verify_transaction_geoip_candidate(state)


def _read_current_config_sources() -> dict[str, bytes]:
    """Read the managed YAML files as they are on disk right now."""

    directory_fd = _open_config_source_directory()
    sources: dict[str, bytes] = {}
    try:
        for filename in sorted(CONFIG_SOURCE_FILENAMES):
            try:
                content, _ = _read_config_source_at(directory_fd, filename)
            except (RuntimeError, OSError):
                continue
            sources[filename] = content
    finally:
        os.close(directory_fd)
    return sources


def _config_history_entries() -> list[Path]:
    if not CONFIG_HISTORY_DIR.is_dir():
        return []
    entries = [
        path
        for path in CONFIG_HISTORY_DIR.iterdir()
        if path.is_dir() and (path / CONFIG_HISTORY_META).is_file()
    ]
    return sorted(entries, key=lambda path: path.name, reverse=True)


def record_config_version(state: dict[str, object] | None = None) -> str:
    """Keep the managed sources of a confirmed configuration.

    Called after a transaction is confirmed, when the files on disk are the
    version that is actually running. Failing to record history must never
    undo a change that already succeeded, so every error is swallowed after
    being logged.
    """

    try:
        sources = _read_current_config_sources()
        if not sources:
            return ""
        digest = hashlib.sha256()
        for filename in sorted(sources):
            digest.update(filename.encode("utf-8"))
            digest.update(b"\0")
            digest.update(sources[filename])
        generation = digest.hexdigest()

        existing = _config_history_entries()
        if existing:
            try:
                latest = json.loads(
                    (existing[0] / CONFIG_HISTORY_META).read_text("utf-8")
                )
                if latest.get("generation") == generation:
                    # Confirming a transaction that changed nothing in the
                    # managed sources should not create a duplicate version.
                    return str(latest.get("id") or "")
            except (OSError, ValueError):
                pass

        timestamp = datetime.now(timezone.utc)
        version_id = f"{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}.{generation[:12]}"
        target = CONFIG_HISTORY_DIR / version_id
        staging = CONFIG_HISTORY_DIR / f".staging.{secrets.token_hex(8)}"
        CONFIG_HISTORY_DIR.mkdir(parents=True, mode=0o750, exist_ok=True)
        staging.mkdir(mode=0o750)
        try:
            for filename, content in sources.items():
                path = staging / filename
                path.write_bytes(content)
                os.chmod(path, 0o640)
            meta = {
                "id": version_id,
                "ts": int(timestamp.timestamp()),
                "generation": generation,
                "parent": existing[0].name if existing else "",
                "files": sorted(sources),
                "transaction_id": str((state or {}).get("id") or ""),
                "cfg_sha256": str((state or {}).get("candidate_sha256") or ""),
            }
            (staging / CONFIG_HISTORY_META).write_text(
                json.dumps(meta, ensure_ascii=False, sort_keys=True), "utf-8"
            )
            os.chmod(staging / CONFIG_HISTORY_META, 0o640)
            # Renaming a fully built directory means a reader never sees a
            # half-written version.
            os.replace(staging, target)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

        for stale in _config_history_entries()[max(1, CONFIG_HISTORY_KEEP):]:
            shutil.rmtree(stale, ignore_errors=True)
        LOG.info("Recorded configuration version %s", version_id)
        return version_id
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Could not record the configuration version: %r", exc)
        return ""


def list_config_versions(limit: int = 50) -> list[dict[str, object]]:
    versions: list[dict[str, object]] = []
    for path in _config_history_entries()[: max(1, min(int(limit), 200))]:
        try:
            meta = json.loads((path / CONFIG_HISTORY_META).read_text("utf-8"))
        except (OSError, ValueError):
            continue
        meta["bytes"] = sum(
            item.stat().st_size for item in path.iterdir() if item.is_file()
        )
        versions.append(meta)
    return versions


def get_config_version(version_id: str) -> dict[str, object]:
    """Return one stored version, with its sources base64 encoded."""

    name = str(version_id or "").strip()
    # The identifier indexes a directory, so it is matched against what exists
    # rather than joined onto a path.
    if not name or name not in {path.name for path in _config_history_entries()}:
        raise ValueError("unknown configuration version")
    path = CONFIG_HISTORY_DIR / name
    meta = json.loads((path / CONFIG_HISTORY_META).read_text("utf-8"))
    sources: dict[str, str] = {}
    for filename in sorted(CONFIG_SOURCE_FILENAMES):
        candidate = path / filename
        if candidate.is_file():
            sources[filename] = base64.b64encode(
                candidate.read_bytes()
            ).decode("ascii")
    meta["sources"] = sources
    return meta


def _restore_config_sources(previous: dict[str, bytes]) -> list[str]:
    """Atomically restore allow-listed YAML files using directory-relative I/O."""
    directory_fd = _open_config_source_directory()
    restored: list[str] = []
    try:
        directory_stat = os.fstat(directory_fd)
        for filename, content in previous.items():
            if filename not in CONFIG_SOURCE_FILENAMES:
                raise ValueError("unsupported rollback config source filename")
            try:
                _, target_stat = _read_config_source_at(directory_fd, filename)
                owner = target_stat.st_uid
                group = target_stat.st_gid
                mode = stat.S_IMODE(target_stat.st_mode)
            except RuntimeError:
                owner = directory_stat.st_uid
                group = directory_stat.st_gid
                mode = 0o644

            temporary = f".{filename}.transaction.{secrets.token_hex(8)}"
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
                os.fchmod(temporary_fd, mode)
                try:
                    os.fchown(temporary_fd, owner, group)
                except PermissionError:
                    if os.geteuid() == 0:
                        raise
            finally:
                os.close(temporary_fd)
            try:
                os.replace(
                    temporary,
                    filename,
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
            restored.append(filename)
    finally:
        os.close(directory_fd)
    return restored


def _canonical_admin_allowlist_raw(entries: list[str]) -> bytes:
    canonical = _canonical_admin_allowlist_entries(entries)
    raw = (("\n".join(canonical) + "\n") if canonical else "").encode("ascii")
    if len(raw) > ADMIN_ALLOWLIST_MAX_BYTES:
        raise ValueError("admin allow list exceeds the size limit")
    return raw


def _open_admin_allowlist_directory() -> int:
    path = ADMIN_ALLOWLIST_PATH
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise RuntimeError("admin allow list path is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path.parent, flags)
    except OSError as exc:
        raise RuntimeError("admin allow list directory is unavailable or unsafe") from exc


def _read_admin_allowlist_raw() -> tuple[bool, bytes]:
    directory_fd = _open_admin_allowlist_directory()
    try:
        try:
            target_stat = os.stat(
                ADMIN_ALLOWLIST_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False, b""
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise RuntimeError("admin allow list is not a regular file")
        if target_stat.st_size > ADMIN_ALLOWLIST_MAX_BYTES:
            raise RuntimeError("admin allow list exceeds the size limit")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_fd = os.open(ADMIN_ALLOWLIST_PATH.name, flags, dir_fd=directory_fd)
        try:
            current_stat = os.fstat(file_fd)
            if not stat.S_ISREG(current_stat.st_mode):
                raise RuntimeError("admin allow list is not a regular file")
            raw = b""
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > ADMIN_ALLOWLIST_MAX_BYTES:
                    raise RuntimeError("admin allow list exceeds the size limit")
        finally:
            os.close(file_fd)
        if b"\x00" in raw:
            raise RuntimeError("admin allow list contains a NUL byte")
        raw.decode("utf-8")
        return True, raw
    finally:
        os.close(directory_fd)


def _write_admin_allowlist_raw(raw: bytes) -> None:
    if len(raw) > ADMIN_ALLOWLIST_MAX_BYTES or b"\x00" in raw:
        raise ValueError("invalid admin allow list snapshot")
    raw.decode("utf-8")
    directory_fd = _open_admin_allowlist_directory()
    temporary = f".admin.allow.transaction.{secrets.token_hex(8)}"
    temporary_created = False
    try:
        directory_stat = os.fstat(directory_fd)
        try:
            target_stat = os.stat(
                ADMIN_ALLOWLIST_PATH.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
                raise RuntimeError("admin allow list is not a regular file")
            owner = target_stat.st_uid
            group = target_stat.st_gid
            mode = stat.S_IMODE(target_stat.st_mode)
        except FileNotFoundError:
            owner = directory_stat.st_uid
            group = directory_stat.st_gid
            mode = 0o640

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
            os.fchown(temporary_fd, owner, group)
        finally:
            os.close(temporary_fd)
        os.replace(
            temporary,
            ADMIN_ALLOWLIST_PATH.name,
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
