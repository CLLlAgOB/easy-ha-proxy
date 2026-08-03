# services_haproxy_config.py
# Логика генерации/проверки/применения haproxy.cfg
# + базовые операции с YAML (без логики сайтов)

import os
import base64
import re
import subprocess
import tempfile
import shutil
import time
import json
import socket
import hashlib
import ipaddress
import secrets
import difflib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple, Optional

from jinja2 import Environment, FileSystemLoader
import yaml  # можно заменить на ruamel.yaml при необходимости
from .validation import (
    control_plane_domains,
    validate_config_data,
    validate_control_plane_transition,
)
from .i18n import translate


# Пути относительно рабочего каталога приложения (/opt/haproxy-admin)
HAP_TEMPLATE = Path("./config/haproxy.cfg.j2")
HAPROXY_CFG_PATH = Path("/etc/haproxy/haproxy.cfg")

WEBSITES_YAML = Path("./config/websites.yml")
TCP_YAML = Path("./config/tcp.yml")
UDP_YAML = Path("./config/udp.yml")
CONFIG_YAML = Path("./config/vars.yml")

BASE_DIR = Path(__file__).resolve().parent.parent
HAPROXY_BACKUP_DIR = BASE_DIR / "backups" / "haproxy"
# --- снимки состояний и бэкапы YAML ---  ⬇⬇⬇
# добавь рядом с другими путями (где BASE_DIR / HAPROXY_BACKUP_DIR и т.д.)
YAML_BACKUP_DIR = BASE_DIR / "backups" / "haproxy" / "yaml"
HAPROXY_STATE_PATH = HAPROXY_BACKUP_DIR / "last_applied_state.json"
HAPROXY_STATE_WEBSITES = HAPROXY_BACKUP_DIR / "last_applied_websites.yml"
HAPROXY_STATE_TCP = HAPROXY_BACKUP_DIR / "last_applied_tcp.yml"
HAPROXY_STATE_VARS = HAPROXY_BACKUP_DIR / "last_applied_vars.yml"
HAPROXY_PENDING_TRANSACTION_PATH = (
    HAPROXY_BACKUP_DIR / "pending_ui_transaction.json"
)
CONFIG_GENERATION_HEADER = "X-Easy-HAProxy-Config-Generation"
CONFIG_GENERATION_PREFIX = "easy-ha-proxy-config-generation-v1|"
CONFIG_GENERATION_DIRECTIVE_RE = re.compile(
    r"^([ \t]*http-request[ \t]+set-header[ \t]+"
    r"X-Easy-HAProxy-Config-Generation[ \t]+)"
    r"[0-9a-f]{64}([ \t]+if[ \t]+host_admin[ \t]*)(\r?)$",
    re.IGNORECASE | re.MULTILINE,
)
CONFIG_SOURCE_ORDER = ("vars.yml", "websites.yml", "tcp.yml")
MAX_HAPROXY_CFG_BACKUPS = 14
MAX_YAML_BACKUPS = 14

HAPROXY_CONTROL_SOCKET = (
    os.environ.get("HAPROXY_CONTROL_SOCKET")
    or os.environ.get("HAPROXY_RELOAD_SOCKET")  # на всякий случай
    or "/run/easy-ha-proxy/haproxy-controld.sock"
)
HAPROXY_CONTROL_TIMEOUT = int(os.environ.get("HAPROXY_CONTROL_TIMEOUT", "10"))
HAPROXY_GUARDED_APPLY_TIMEOUT = int(
    os.environ.get("HAPROXY_GUARDED_APPLY_TIMEOUT", "420")
)
HAPROXY_CONFIG_CONFIRM_TIMEOUT = int(
    os.environ.get("HAPROXY_CONFIG_CONFIRM_TIMEOUT", "120")
)

HAP_CHECK_CMD = ["/usr/sbin/haproxy", "-c", "-f"]


class ConfigApplyPreparationError(ValueError):
    """A stable, machine-readable failure while preparing a safe apply."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.details = dict(details or {})


def _controld_json_request(
    command: str,
    *,
    timeout: int = HAPROXY_CONTROL_TIMEOUT,
) -> Dict[str, Any]:
    """Send a command whose response is ``OK|ERROR <base64-json>``."""
    sock_path = HAPROXY_CONTROL_SOCKET
    if not sock_path or not os.path.exists(sock_path):
        return {
            "ok": False,
            "error": "haproxy-controld is unavailable; no configuration was changed",
        }
    if "\n" in command or "\r" in command:
        return {"ok": False, "error": "invalid control command"}

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(sock_path)
            connection.sendall((command + "\n").encode("ascii"))
            chunks: list[bytes] = []
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                chunks.append(data)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"haproxy-controld request failed: {exc}"}

    response = b"".join(chunks).decode("utf-8", "replace").strip()
    try:
        prefix, payload_b64 = response.split(" ", 1)
        if prefix not in {"OK", "ERROR"}:
            raise ValueError("unexpected response prefix")
        payload = json.loads(
            base64.b64decode(payload_b64, validate=True).decode("utf-8")
        )
        if not isinstance(payload, dict):
            raise ValueError("response payload is not an object")
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": (
                "Invalid haproxy-controld response: "
                f"{response[:300] or 'empty'} ({exc})"
            ),
        }

    payload.setdefault("ok", prefix == "OK")
    if prefix == "ERROR":
        payload["ok"] = False
        payload.setdefault("error", payload.get("failure") or "control request failed")
    return payload


def _transaction_state(result: Dict[str, Any]) -> str:
    return str(result.get("state") or result.get("status") or "").strip().lower()


def _write_pending_transaction_marker(
    result: Dict[str, Any],
    config_generation: str,
) -> None:
    transaction_id = str(
        result.get("transaction_id") or result.get("id") or ""
    ).strip()
    if not transaction_id:
        return
    generation = str(config_generation or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", generation):
        raise ValueError("invalid HAProxy configuration generation")
    marker = {
        "transaction_id": transaction_id,
        "candidate_sha256": result.get("candidate_sha256"),
        "confirm_by": result.get("confirm_by") or result.get("deadline"),
        "config_generation": generation,
    }
    HAPROXY_PENDING_TRANSACTION_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=HAPROXY_PENDING_TRANSACTION_PATH.parent,
            prefix=".pending-ui-transaction.",
            encoding="utf-8",
        ) as handle:
            json.dump(marker, handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
            tmp_path = handle.name
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, HAPROXY_PENDING_TRANSACTION_PATH)
        tmp_path = None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


def _clear_pending_transaction_marker() -> None:
    try:
        HAPROXY_PENDING_TRANSACTION_PATH.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _read_pending_transaction_marker() -> Dict[str, Any]:
    try:
        value = json.loads(
            HAPROXY_PENDING_TRANSACTION_PATH.read_text(encoding="utf-8")
        )
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def candidate_request_reachable(
    transaction_id: str,
    request_generation: str,
) -> bool:
    """Prove that this request traversed the pending HAProxy generation.

    HAProxy deletes any client-supplied generation header and inserts its own
    value only for the protected administration host.  Comparing that value
    with the private pending marker prevents an old keep-alive connection from
    confirming a candidate that the browser has not reached through the new
    HAProxy process.
    """
    clean_id = str(transaction_id or "").strip()
    generation = str(request_generation or "").strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", clean_id):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", generation):
        return False
    marker = _read_pending_transaction_marker()
    marker_id = str(marker.get("transaction_id") or "").strip()
    marker_generation = str(marker.get("config_generation") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", marker_generation):
        return False
    return secrets.compare_digest(marker_id, clean_id) and secrets.compare_digest(
        marker_generation, generation
    )


def check_cfg_via_controld(cfg_text: str) -> Optional[Tuple[int, str, str]]:
    """
    Пытается проверить конфиг через root-демон haproxy-controld
    по Unix-сокету HAPROXY_CONTROL_SOCKET.

    Протокол:
      → "check-config <base64(cfg_text)>\\n"
      ← первая строка: "OK <rc>" или "ERROR ..."
         вторая: base64(stdout)
         третья: base64(stderr)

    Если сокет недоступен / ошибка протокола — возвращает None,
    чтобы вызвать локальный haproxy -c как фолбэк.
    """
    sock_path = HAPROXY_CONTROL_SOCKET
    if not sock_path or not os.path.exists(sock_path):
        return None

    try:
        payload_b64 = base64.b64encode(
            cfg_text.encode("utf-8")
        ).decode("ascii")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(HAPROXY_CONTROL_TIMEOUT)
            s.connect(sock_path)
            s.sendall(f"check-config {payload_b64}\n".encode("utf-8"))

            chunks: list[bytes] = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)

        raw = b"".join(chunks).decode("utf-8", "replace")
        lines = raw.splitlines()
        if not lines:
            return None

        first = lines[0].strip()
        if not first.startswith("OK "):
            # демон вернул ошибку — считаем, что проверка не удалась
            stderr = "\n".join(lines)
            return 1, "", stderr

        rc_str = first.split(" ", 1)[1].strip()
        try:
            rc = int(rc_str)
        except ValueError:
            rc = 1

        stdout_b64 = lines[1].strip() if len(lines) > 1 else ""
        stderr_b64 = lines[2].strip() if len(lines) > 2 else ""

        try:
            stdout = base64.b64decode(stdout_b64).decode(
                "utf-8", "replace"
            ) if stdout_b64 else ""
        except Exception:
            stdout = ""

        try:
            stderr = base64.b64decode(stderr_b64).decode(
                "utf-8", "replace"
            ) if stderr_b64 else ""
        except Exception:
            stderr = ""

        return rc, stdout, stderr

    except Exception as exc:  # noqa: BLE001
        # Логически здесь лучше залогировать, но не ломать UI —
        # пусть дальше отработает локальный haproxy -c
        return None


def write_cfg_via_controld(cfg_text: str) -> Optional[Tuple[bool, str, str]]:
    """
    Пытается записать /etc/haproxy/haproxy.cfg через root-демон haproxy-controld.

    Протокол:
      → "write-config <base64(cfg_text)>\\n"
      ← "OK ..." или "ERROR ..."

    Возвращает:
      * (True, stdout, stderr)  – запись успешна
      * (False, stdout, stderr) – запись не удалась
      * None                    – сокет недоступен (используем локальный режим)
    """
    sock_path = HAPROXY_CONTROL_SOCKET
    if not sock_path or not os.path.exists(sock_path):
        return None

    try:
        payload_b64 = base64.b64encode(
            cfg_text.encode("utf-8")
        ).decode("ascii")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(HAPROXY_CONTROL_TIMEOUT)
            s.connect(sock_path)
            s.sendall(f"write-config {payload_b64}\n".encode("utf-8"))

            chunks: list[bytes] = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)

        raw = b"".join(chunks).decode("utf-8", "replace")
        if not raw:
            return False, "", "empty response from haproxy-controld"

        lines = raw.splitlines()
        first = lines[0].strip()
        rest = "\n".join(lines[1:]).strip()

        if first.startswith("OK"):
            # stdout/ stderr тут по сути не нужны, но оставим интерфейс единым
            return True, rest, ""

        # ошибка
        err_msg = first
        if rest:
            err_msg = f"{first}\n{rest}"
        return False, "", err_msg

    except Exception as exc:  # noqa: BLE001
        return False, "", f"write-config via socket error: {exc!r}"


def _critical_control_plane_checks(cfg_text: str) -> list[dict[str, str]]:
    """Build the strict admin/Authelia check set from the rendered config."""
    domains = control_plane_domains(cfg_text)
    admin_domains = domains.get("host_admin") or ()
    if len(admin_domains) != 1:
        raise ValueError(
            "The rendered HAProxy configuration must contain exactly one "
            "protected HAProxy Admin domain"
        )

    checks = [{"service": "admin", "domain": admin_domains[0]}]
    authelia_domains = domains.get("host_authelia") or ()
    if len(authelia_domains) > 1:
        raise ValueError(
            "The rendered HAProxy configuration contains multiple Authelia domains"
        )
    if authelia_domains:
        checks.append({"service": "authelia", "domain": authelia_domains[0]})
    return checks


def _format_guard_diagnostics(result: Dict[str, Any]) -> str:
    """Return non-localized technical details for the apply result panel."""
    lines = [
        f"Candidate SHA256: {result.get('candidate_sha256') or 'unknown'}",
        f"Previous SHA256: {result.get('previous_sha256') or 'unknown'}",
    ]
    if result.get("backup_path"):
        lines.append(f"Pre-apply backup: {result['backup_path']}")

    for check in result.get("checks") or []:
        status = check.get("status")
        outcome = "OK" if check.get("ok") else "FAILED"
        suffix = f"HTTP {status}" if status is not None else (check.get("failure") or "no response")
        lines.append(
            f"Critical check {check.get('service')} ({check.get('domain')}): "
            f"{outcome} — {suffix}"
        )

    if result.get("failure"):
        lines.append(f"Apply failure: {result['failure']}")
    if result.get("rolled_back"):
        rollback = result.get("rollback") or {}
        rollback_outcome = "OK" if rollback.get("ok") else "FAILED"
        lines.append(f"Automatic rollback: {rollback_outcome}")
        if rollback.get("failure"):
            lines.append(f"Rollback failure: {rollback['failure']}")
        for check in rollback.get("checks") or []:
            status = check.get("status")
            outcome = "OK" if check.get("ok") else "FAILED"
            suffix = f"HTTP {status}" if status is not None else (check.get("failure") or "no response")
            lines.append(
                f"Rollback check {check.get('service')} ({check.get('domain')}): "
                f"{outcome} — {suffix}"
            )
    return "\n".join(lines)


def apply_cfg_guarded(cfg_text: str) -> Dict[str, Any]:
    """Apply through controld and require critical services to remain reachable."""
    rc, check_stdout, check_stderr = check_cfg(cfg_text)
    if rc != 0:
        return {
            "ok": False,
            "error": "HAProxy configuration validation failed",
            "stdout": check_stdout,
            "stderr": check_stderr,
            "safety": None,
        }

    try:
        checks = _critical_control_plane_checks(cfg_text)
    except ValueError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "stdout": "",
            "stderr": str(exc),
            "safety": None,
        }

    sock_path = HAPROXY_CONTROL_SOCKET
    if not sock_path or not os.path.exists(sock_path):
        error = (
            "Guarded HAProxy apply requires the haproxy-controld service; "
            "the configuration was not changed"
        )
        return {
            "ok": False,
            "error": error,
            "stdout": "",
            "stderr": error,
            "safety": None,
        }

    cfg_b64 = base64.b64encode(cfg_text.encode("utf-8")).decode("ascii")
    checks_b64 = base64.b64encode(
        json.dumps(checks, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(HAPROXY_GUARDED_APPLY_TIMEOUT)
            connection.connect(sock_path)
            connection.sendall(
                f"apply-config {cfg_b64} {checks_b64}\n".encode("ascii")
            )
            chunks: list[bytes] = []
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                chunks.append(data)
    except Exception as exc:  # noqa: BLE001
        error = f"Guarded apply request failed: {exc}"
        return {
            "ok": False,
            "error": error,
            "stdout": "",
            "stderr": error,
            "safety": None,
        }

    response = b"".join(chunks).decode("utf-8", "replace").strip()
    try:
        prefix, payload_b64 = response.split(" ", 1)
        if prefix not in {"OK", "ERROR"}:
            raise ValueError("unexpected response prefix")
        safety = json.loads(
            base64.b64decode(payload_b64, validate=True).decode("utf-8")
        )
        if not isinstance(safety, dict):
            raise ValueError("response payload is not an object")
    except Exception as exc:  # noqa: BLE001
        error = f"Invalid guarded apply response: {response[:300] or 'empty'} ({exc})"
        return {
            "ok": False,
            "error": error,
            "stdout": "",
            "stderr": error,
            "safety": None,
        }

    ok = prefix == "OK" and safety.get("ok") is True
    diagnostics = _format_guard_diagnostics(safety)
    if ok:
        error = ""
        stdout = diagnostics
        stderr = ""
    elif safety.get("rolled_back") and safety.get("rollback_ok"):
        error = (
            "Critical service check failed; the previous HAProxy "
            "configuration was restored automatically"
        )
        stdout = ""
        stderr = diagnostics
    elif safety.get("rolled_back"):
        error = (
            "Critical service check failed and automatic HAProxy rollback "
            "could not be verified"
        )
        stdout = ""
        stderr = diagnostics
    else:
        error = "Guarded HAProxy configuration apply failed before completion"
        stdout = ""
        stderr = diagnostics

    return {
        "ok": ok,
        "error": error,
        "stdout": stdout,
        "stderr": stderr,
        "safety": safety,
    }


def get_config_transaction_status(
    transaction_id: str = "",
) -> Dict[str, Any]:
    """Return the root daemon's server-authoritative transaction state."""
    clean_id = str(transaction_id or "").strip()
    if clean_id and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", clean_id):
        return {"ok": False, "error": "invalid configuration transaction id"}
    command = "config-transaction-status"
    if clean_id:
        command += f" {clean_id}"
    result = _controld_json_request(command)
    state = _transaction_state(result)
    if state in {
        "confirmed",
        "rolled_back",
        "none",
    }:
        marker = _read_pending_transaction_marker()
        marker_id = str(marker.get("transaction_id") or "")
        result_id = str(result.get("transaction_id") or result.get("id") or "")
        if not marker_id or not result_id or marker_id == result_id:
            _clear_pending_transaction_marker()
    return result


def config_transaction_is_pending() -> Tuple[bool, str]:
    """Fail closed while a marked confirmation transaction is unresolved."""
    marker = _read_pending_transaction_marker()
    marker_id = str(marker.get("transaction_id") or "").strip()
    result = get_config_transaction_status(marker_id)
    state = _transaction_state(result)
    if state in {"prepared", "pending", "pending_confirmation", "rolling_back"}:
        return True, "A configuration confirmation is pending"
    if state == "rollback_failed":
        return (
            True,
            "Automatic configuration rollback failed; inspect and restore "
            "HAProxy from the server console before editing again",
        )
    if marker_id and not result.get("ok"):
        return (
            True,
            "A configuration confirmation may still be pending; "
            "haproxy-controld status is unavailable",
        )
    return False, ""


def _current_config_source_paths() -> Dict[str, Path]:
    """Return paths dynamically so tests and alternate installations can patch them."""
    return {
        "vars.yml": CONFIG_YAML,
        "websites.yml": WEBSITES_YAML,
        "tcp.yml": TCP_YAML,
    }


def _applied_config_source_paths() -> Dict[str, Path]:
    return {
        "vars.yml": HAPROXY_STATE_VARS,
        "websites.yml": HAPROXY_STATE_WEBSITES,
        "tcp.yml": HAPROXY_STATE_TCP,
    }


def _read_config_source_bundle(
    paths: Dict[str, Path],
    *,
    label: str,
) -> Dict[str, bytes]:
    bundle: Dict[str, bytes] = {}
    for name, path in paths.items():
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            raise ValueError(
                f"The {label} {name} file is missing; no transaction was started"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"The {label} {name} file cannot be read; no transaction was started"
            ) from exc
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError(f"{name} exceeds the transaction size limit")
        if b"\x00" in raw:
            raise ValueError(f"{name} contains a NUL byte")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{name} is not valid UTF-8") from exc
        bundle[name] = raw
    return bundle


def config_source_generation(bundle: Dict[str, bytes]) -> str:
    """Hash an unambiguous framing of the three exact source-file bytes.

    The framing uses fixed filenames and the canonical base64 representation of
    each byte string.  Ansible receives those same base64 strings from
    ``slurp``, so host-side and application renders produce identical values
    without normalizing YAML, line endings, Unicode, or trailing whitespace.
    """
    if set(bundle) != set(CONFIG_SOURCE_ORDER):
        raise ValueError("The configuration source bundle is incomplete")
    fields: list[str] = []
    for name in CONFIG_SOURCE_ORDER:
        raw = bundle[name]
        if not isinstance(raw, bytes):
            raise ValueError(f"The configuration source {name} is not bytes")
        fields.append(f"{name}:{base64.b64encode(raw).decode('ascii')}")
    framed = CONFIG_GENERATION_PREFIX + "|".join(fields)
    return hashlib.sha256(framed.encode("ascii")).hexdigest()


def config_geoip_selection(bundle: Dict[str, bytes]) -> Dict[str, Any]:
    """Derive the root-managed GeoIP selection from candidate vars.yml."""
    if set(bundle) != set(CONFIG_SOURCE_ORDER):
        raise ValueError("The configuration source bundle is incomplete")
    try:
        variables = yaml.safe_load(bundle["vars.yml"].decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("The candidate vars.yml is invalid") from exc
    if not isinstance(variables, dict):
        raise ValueError("The candidate vars.yml root must be a mapping")
    enabled = variables.get("enable_geoip", False)
    if not isinstance(enabled, bool):
        raise ValueError("enable_geoip must be boolean")
    raw_countries = variables.get("geoip_country_codes") or []
    if not isinstance(raw_countries, list) or len(raw_countries) > 249:
        raise ValueError("geoip_country_codes must be a list of at most 249 codes")
    countries: set[str] = set()
    for raw in raw_countries:
        if not isinstance(raw, str):
            raise ValueError("GeoIP country codes must be strings")
        code = raw.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            raise ValueError(f"Invalid ISO GeoIP country code: {raw!r}")
        countries.add(code)
    selected = sorted(countries)
    if enabled and not selected:
        raise ValueError(
            "Select at least one GeoIP country before enabling GeoIP filtering"
        )

    try:
        websites = yaml.safe_load(bundle["websites.yml"].decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("The candidate websites.yml is invalid") from exc
    if not isinstance(websites, dict):
        raise ValueError("The candidate websites.yml root must be a mapping")
    sites = websites.get("sites") or []
    if not isinstance(sites, list):
        raise ValueError("The candidate websites.yml sites value must be a list")
    for index, site in enumerate(sites):
        if not isinstance(site, dict):
            raise ValueError(f"sites[{index}] must be an object")
        site_countries = site.get("geo_countries")
        if site_countries in (None, []):
            continue
        if not isinstance(site_countries, list) or len(site_countries) > 249:
            raise ValueError(
                f"sites[{index}].geo_countries must be a list of at most 249 ISO alpha-2 codes"
            )
        normalized_site_countries: set[str] = set()
        for country_index, raw in enumerate(site_countries):
            if not isinstance(raw, str):
                raise ValueError(
                    f"sites[{index}].geo_countries[{country_index}] must be a string"
                )
            code = raw.strip().upper()
            if not re.fullmatch(r"[A-Z]{2}", code):
                raise ValueError(
                    f"Invalid site GeoIP country code: {raw!r}"
                )
            normalized_site_countries.add(code)
        unavailable = sorted(normalized_site_countries - countries)
        if unavailable:
            label = str(site.get("domain") or site.get("name") or index)
            raise ValueError(
                f"Site {label!r} uses GeoIP countries not selected globally: "
                + ", ".join(unavailable)
            )
    return {
        "version": 1,
        "countries": selected,
        "access_filter_enabled": enabled,
    }


def config_admin_allowlist(bundle: Dict[str, bytes]) -> Optional[list[str]]:
    """Derive the root-managed admin.allow contents from candidate vars.yml."""
    if set(bundle) != set(CONFIG_SOURCE_ORDER):
        raise ValueError("The configuration source bundle is incomplete")
    try:
        variables = yaml.safe_load(bundle["vars.yml"].decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("The candidate vars.yml is invalid") from exc
    if not isinstance(variables, dict):
        raise ValueError("The candidate vars.yml root must be a mapping")
    if "admin_allowed_ips" not in variables:
        return None
    raw_entries = variables.get("admin_allowed_ips")
    if not isinstance(raw_entries, list) or len(raw_entries) > 256:
        raise ValueError("admin_allowed_ips must be a list of at most 256 entries")

    entries: list[str] = []
    seen: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, str):
            raise ValueError("admin_allowed_ips entries must be strings")
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
            raise ValueError(f"Invalid admin_allowed_ips entry: {text!r}") from exc
        if canonical not in seen:
            entries.append(canonical)
            seen.add(canonical)
    return entries


def _source_bundle_sha256(bundle: Dict[str, bytes]) -> Dict[str, str]:
    return {
        name: hashlib.sha256(raw).hexdigest()
        for name, raw in sorted(bundle.items())
    }


def _state_source_hashes_match(
    state: Dict[str, Any],
    bundle: Dict[str, bytes],
) -> bool:
    expected = state.get("source_sha256")
    if not isinstance(expected, dict):
        return False
    actual = _source_bundle_sha256(bundle)
    return expected == actual


def _state_spec_matches_source_bundle(
    state: Dict[str, Any],
    bundle: Dict[str, bytes],
) -> bool:
    """Validate legacy states that predate per-source SHA256 metadata."""
    try:
        spec = _spec_from_source_bundle(bundle)
    except (UnicodeDecodeError, yaml.YAMLError, ValueError, TypeError):
        return False
    return (
        state.get("sites", []) == spec["sites"]
        and state.get("tcp", []) == spec["tcp"]
        and (state.get("config_vars", {}) or {}) == spec["config_vars"]
    )


def _persist_applied_state_bundle(cfg_text: str, bundle: Dict[str, bytes]) -> None:
    """Atomically persist one exact rendered configuration/source bundle."""
    expected_names = set(_current_config_source_paths())
    if set(bundle) != expected_names:
        raise ValueError("The applied configuration source bundle is incomplete")
    rendered = _render_haproxy_cfg_from_source_bundle(bundle)
    if rendered != cfg_text:
        raise ValueError(
            "The configuration sources changed while the safe snapshot was being saved"
        )

    spec = _spec_from_source_bundle(bundle)
    cfg_raw = cfg_text.encode("utf-8")
    state = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "haproxy_cfg_sha256": hashlib.sha256(cfg_raw).hexdigest(),
        "haproxy_cfg_len": len(cfg_raw),
        "source_sha256": _source_bundle_sha256(bundle),
        "sites": spec["sites"],
        "tcp": spec["tcp"],
        "config_vars": spec["config_vars"],
    }

    snapshot_paths = _applied_config_source_paths()
    for name, raw in bundle.items():
        _atomic_write_snapshot(snapshot_paths[name], raw)
    state_raw = json.dumps(
        state, ensure_ascii=False, indent=2
    ).encode("utf-8") + b"\n"
    _atomic_write_snapshot(HAPROXY_STATE_PATH, state_raw)


def _reconcile_applied_state_for_candidate(
    cfg_text: str,
    current_bundle: Dict[str, bytes],
    previous_bundle: Optional[Dict[str, bytes]],
    *,
    allow_external_drift: bool = False,
    expected_active_sha256: str = "",
) -> Tuple[Dict[str, bytes], str]:
    """
    Return a proven rollback source bundle, repairing legacy metadata if safe.

    There are only three accepted trust paths:
      * the live config hash and saved source hashes match a confirmed state;
      * the live config is the exact render of the saved source bundle;
      * the live config is the exact render of the current source bundle.

    Anything else is unknown external drift and remains blocked unless the
    caller presents the exact live hash that the administrator just approved.
    """
    active = _read_file_text(HAPROXY_CFG_PATH)
    if not active:
        raise ValueError(
            "The active HAProxy configuration is unavailable; no transaction was started"
        )
    active_sha256 = hashlib.sha256(active.encode("utf-8")).hexdigest()
    state = _load_applied_state()

    if state and previous_bundle is not None:
        expected_sha256 = str(state.get("haproxy_cfg_sha256") or "")
        live_hash_matches = expected_sha256 == active_sha256
        sources_match = _state_source_hashes_match(state, previous_bundle)
        legacy_sources_match = _state_spec_matches_source_bundle(
            state, previous_bundle
        )
        if live_hash_matches and (sources_match or legacy_sources_match):
            if not sources_match:
                # Upgrade a legacy state without replacing its rollback sources.
                _persist_applied_state_bundle(active, previous_bundle)
                return previous_bundle, "legacy_snapshot_metadata"
            return previous_bundle, "trusted_snapshot"

        try:
            saved_render = _render_haproxy_cfg_from_source_bundle(previous_bundle)
        except (UnicodeDecodeError, yaml.YAMLError, ValueError, TypeError):
            saved_render = ""
        if saved_render == active:
            # A stale/legacy cfg hash is safe to repair when the saved sources
            # reproduce the running configuration byte-for-byte.
            _persist_applied_state_bundle(active, previous_bundle)
            return previous_bundle, "saved_render"

    current_render = _render_haproxy_cfg_from_source_bundle(current_bundle)
    if current_render == cfg_text and current_render == active:
        # This covers first use and installations updated outside the UI. The
        # current sources are safe to seed only because they already reproduce
        # the running configuration exactly.
        _persist_applied_state_bundle(active, current_bundle)
        return current_bundle, "current_render"

    drift_details = {
        "external_drift_confirmation_required": True,
        "active_cfg_sha256": active_sha256,
    }
    if allow_external_drift:
        expected_hash = str(expected_active_sha256 or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ConfigApplyPreparationError(
                "Explicit confirmation of the active HAProxy configuration is invalid.",
                error_code="haproxy_config_unknown_drift",
                details=drift_details,
            )
        if expected_hash != active_sha256:
            raise ConfigApplyPreparationError(
                "The active HAProxy configuration changed after it was reviewed. "
                "Review and confirm the new version before applying.",
                error_code="haproxy_config_unknown_drift",
                details=drift_details,
            )

        # The root transaction always captures the exact currently active
        # haproxy.cfg before replacing it. External edits cannot be represented
        # safely as YAML, so retain the current (still unapplied) YAML as its
        # pre-transaction state. A rollback therefore restores the exact live
        # config while keeping the user's pending editor changes available.
        return current_bundle, "external_drift_override"

    raise ConfigApplyPreparationError(
        "The active HAProxy configuration contains external changes. "
        "Explicit confirmation is required before overwriting it.",
        error_code="haproxy_config_unknown_drift",
        details=drift_details,
    )


def _config_source_payload(
    cfg_text: str,
    *,
    allow_external_drift: bool = False,
    expected_active_sha256: str = "",
) -> Tuple[Dict[str, Any], str]:
    """Freeze exact candidate and proven known-good YAML for root-side rollback."""
    current_bundle = _read_config_source_bundle(
        _current_config_source_paths(), label="current"
    )
    if _render_haproxy_cfg_from_source_bundle(current_bundle) != cfg_text:
        raise ConfigApplyPreparationError(
            "The configuration sources changed while the candidate was being "
            "prepared. Validate again before applying.",
            error_code="haproxy_config_sources_changed",
        )
    try:
        previous_bundle: Optional[Dict[str, bytes]] = _read_config_source_bundle(
            _applied_config_source_paths(), label="safe snapshot"
        )
    except ValueError:
        previous_bundle = None

    previous_bundle, baseline_source = _reconcile_applied_state_for_candidate(
        cfg_text,
        current_bundle,
        previous_bundle,
        allow_external_drift=allow_external_drift,
        expected_active_sha256=expected_active_sha256,
    )
    candidate = {
        name: base64.b64encode(raw).decode("ascii")
        for name, raw in current_bundle.items()
    }
    previous = {
        name: base64.b64encode(raw).decode("ascii")
        for name, raw in previous_bundle.items()
    }
    payload: Dict[str, Any] = {
        "candidate": candidate,
        "previous": previous,
        "geoip_selection": config_geoip_selection(current_bundle),
    }
    admin_allowlist = config_admin_allowlist(current_bundle)
    if admin_allowlist is not None:
        payload["admin_allowlist"] = admin_allowlist
    return payload, baseline_source


def _config_preparation_failure(exc: ValueError) -> Dict[str, Any]:
    failure = {
        "ok": False,
        "error": str(exc),
        "error_code": getattr(exc, "error_code", "config_snapshot_invalid"),
        "stdout": "",
        "stderr": str(exc),
    }
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        failure.update(details)
    return failure


def preflight_cfg_confirmation(
    cfg_text: str,
    *,
    allow_external_drift: bool = False,
    expected_active_sha256: str = "",
) -> Dict[str, Any]:
    """Check snapshot/drift safety without issuing certs or changing HAProxy."""
    try:
        _, baseline_source = _config_source_payload(
            cfg_text,
            allow_external_drift=allow_external_drift,
            expected_active_sha256=expected_active_sha256,
        )
    except ValueError as exc:
        return _config_preparation_failure(exc)
    return {
        "ok": True,
        "baseline_source": baseline_source,
        "external_drift_overridden": (
            baseline_source == "external_drift_override"
        ),
    }


def begin_cfg_confirmation(
    cfg_text: str,
    *,
    confirm_timeout: int | None = None,
    allow_external_drift: bool = False,
    expected_active_sha256: str = "",
) -> Dict[str, Any]:
    """Apply a candidate and leave it pending until the browser confirms it."""
    rc, check_stdout, check_stderr = check_cfg(cfg_text)
    if rc != 0:
        return {
            "ok": False,
            "error": "HAProxy configuration validation failed",
            "stdout": check_stdout,
            "stderr": check_stderr,
        }
    try:
        checks = _critical_control_plane_checks(cfg_text)
        sources, baseline_source = _config_source_payload(
            cfg_text,
            allow_external_drift=allow_external_drift,
            expected_active_sha256=expected_active_sha256,
        )
        if baseline_source == "external_drift_override":
            # Keep the hash confirmation as close as possible to the root-side
            # transaction. The daemon will independently snapshot the exact
            # live config that it replaces for rollback.
            active_now = _read_file_text(HAPROXY_CFG_PATH)
            active_now_sha256 = hashlib.sha256(
                active_now.encode("utf-8")
            ).hexdigest()
            if active_now_sha256 != expected_active_sha256:
                raise ConfigApplyPreparationError(
                    "The active HAProxy configuration changed after it was reviewed. "
                    "Review and confirm the new version before applying.",
                    error_code="haproxy_config_unknown_drift",
                    details={
                        "external_drift_confirmation_required": True,
                        "active_cfg_sha256": active_now_sha256,
                    },
                )
        candidate_encoded = sources.get("candidate")
        if not isinstance(candidate_encoded, dict):
            raise ValueError("The candidate configuration source bundle is missing")
        candidate_bundle = {
            str(name): base64.b64decode(str(encoded), validate=True)
            for name, encoded in candidate_encoded.items()
        }
        candidate_generation = config_source_generation(candidate_bundle)
    except ValueError as exc:
        return _config_preparation_failure(exc)

    timeout_seconds = max(
        30,
        min(int(confirm_timeout or HAPROXY_CONFIG_CONFIRM_TIMEOUT), 300),
    )
    cfg_b64 = base64.b64encode(cfg_text.encode("utf-8")).decode("ascii")
    checks_b64 = base64.b64encode(
        json.dumps(checks, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    sources_b64 = base64.b64encode(
        json.dumps(sources, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    result = _controld_json_request(
        "begin-config-transaction "
        f"{cfg_b64} {checks_b64} {sources_b64} {timeout_seconds}",
        timeout=HAPROXY_GUARDED_APPLY_TIMEOUT,
    )
    state = _transaction_state(result)
    if result.get("ok") and state in {"pending", "pending_confirmation"}:
        result["pending_confirmation"] = True
        _write_pending_transaction_marker(result, candidate_generation)
    result["baseline_source"] = baseline_source
    result["baseline_reconciled"] = baseline_source in {
        "legacy_snapshot_metadata",
        "saved_render",
        "current_render",
    }
    result["external_drift_overridden"] = (
        baseline_source == "external_drift_override"
    )
    diagnostics_source = result.get("safety")
    if not isinstance(diagnostics_source, dict):
        diagnostics_source = result
    diagnostics = _format_guard_diagnostics(diagnostics_source)
    result.setdefault("stdout", diagnostics if result.get("ok") else "")
    result.setdefault("stderr", "" if result.get("ok") else diagnostics)
    return result


def confirm_cfg_transaction(
    transaction_id: str,
    candidate_sha256: str,
) -> Dict[str, Any]:
    clean_id = str(transaction_id or "").strip()
    clean_sha = str(candidate_sha256 or "").strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", clean_id):
        return {"ok": False, "error": "invalid configuration transaction id"}
    if not re.fullmatch(r"[0-9a-f]{64}", clean_sha):
        return {"ok": False, "error": "invalid candidate SHA256"}
    result = _controld_json_request(
        f"confirm-config-transaction {clean_id} {clean_sha}",
        # A late/drifted confirmation performs the guarded rollback before it
        # replies, including reload and critical-service probes.
        timeout=HAPROXY_GUARDED_APPLY_TIMEOUT,
    )
    if result.get("ok") and _transaction_state(result) == "confirmed":
        _clear_pending_transaction_marker()
    return result


def rollback_cfg_transaction(transaction_id: str) -> Dict[str, Any]:
    clean_id = str(transaction_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", clean_id):
        return {"ok": False, "error": "invalid configuration transaction id"}
    result = _controld_json_request(
        f"rollback-config-transaction {clean_id}",
        timeout=HAPROXY_GUARDED_APPLY_TIMEOUT,
    )
    if _transaction_state(result) == "rolled_back":
        _clear_pending_transaction_marker()
    return result


def udp_listen_port_conflict(start: int, end: Optional[int] = None) -> Optional[str]:
    """Return an error when the host listens within an inclusive UDP range.

    The container cannot inspect host sockets, so it asks haproxy-controld.
    Fails open (returns None) when the check is unavailable — the apply step
    surfaces any controld problem anyway.
    """
    end = int(start if end is None else end)
    sock_path = HAPROXY_CONTROL_SOCKET
    if not sock_path or not os.path.exists(sock_path):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(HAPROXY_CONTROL_TIMEOUT)
            s.connect(sock_path)
            s.sendall(
                f"udp-port-check {int(start)} {end}\n".encode("ascii")
            )
            chunks: list[bytes] = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        resp = b"".join(chunks).decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        return None
    if resp.startswith("OK busy"):
        parts = resp.split()
        busy = parts[2] if len(parts) >= 3 else str(start)
        return f"Port {busy}/udp is already in use on the host"
    return None


def apply_udp_forwards() -> tuple[bool, Dict[str, Any], str]:
    """Ask haproxy-controld to reload the UDP forwarding (iptables DNAT) rules.

    UDP is not part of haproxy.cfg; the root loader unit regenerates the
    HP_UDP_* chains from the managed udp.yml. The root daemon returns the
    generator state only after systemd completed the synchronous reload.
    """
    result = _controld_json_request("udp-apply-json", timeout=70)
    if result.get("ok") is True:
        return True, result, ""
    return (
        False,
        {},
        str(result.get("error") or "UDP forwarding apply failed"),
    )


def get_udp_runtime_status() -> Dict[str, Any]:
    """Return the last successfully installed UDP ruleset state."""

    result = _controld_json_request("udp-status")
    if result.get("ok") is True:
        return result
    return {
        "ok": False,
        "error": str(
            result.get("error") or "UDP forwarding runtime status is unavailable"
        ),
    }


def reload_haproxy() -> tuple[bool, str, str]:
    """
    Перезагрузка HAProxy.

    1) Пытаемся через Unix-сокет HAPROXY_CONTROL_SOCKET → команда "reload".
    2) Если сокета нет → пробуем systemctl reload haproxy (для bare-metal).
    """
    sock_path = HAPROXY_CONTROL_SOCKET

    # 1. Через сокет haproxy-controld
    if sock_path and os.path.exists(sock_path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(HAPROXY_CONTROL_TIMEOUT)
                s.connect(sock_path)
                s.sendall(b"reload\n")

                chunks: list[bytes] = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)

            resp = b"".join(chunks).decode("utf-8", "replace").strip()

            if resp.startswith("OK"):
                return True, resp, ""
            return False, "", resp or "reload via socket failed"
        except Exception as exc:  # noqa: BLE001
            return False, "", f"reload via socket error: {exc!r}"

    # 2. Фолбэк: systemctl (для старого режима без Docker)
    try:
        proc = subprocess.run(
            ["systemctl", "reload", "haproxy"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ok = (proc.returncode == 0)
        return ok, proc.stdout, proc.stderr
    except FileNotFoundError:
        return False, "", (
            f"systemctl not found and control socket {sock_path!r} "
            "is not available"
        )


def jinja_regex_replace(value: Any, pattern: str, replacement: str) -> str:
    """
    Аналог ansible-фильтра regex_replace.
    """
    if value is None:
        return ""
    return re.sub(pattern, replacement, str(value))


def jinja_combine(value: Any, other: Any, recursive: bool = False) -> Dict[str, Any]:
    """
    Простейший аналог ansible-фильтра combine.
    """
    if value is None:
        base: Dict[str, Any] = {}
    else:
        base = dict(value)

    if other is None:
        return base

    other_dict = dict(other)

    for k, v in other_dict.items():
        if (
            recursive
            and k in base
            and isinstance(base[k], dict)
            and isinstance(v, dict)
        ):
            base[k] = jinja_combine(base[k], v, recursive=True)
        else:
            base[k] = v

    return base


# Jinja2-окружение для haproxy.cfg
JINJA_ENV = Environment(
    loader=FileSystemLoader(str(HAP_TEMPLATE.parent)),
    trim_blocks=True,
    lstrip_blocks=True,
)
JINJA_ENV.filters["regex_replace"] = jinja_regex_replace
JINJA_ENV.filters["combine"] = jinja_combine


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Безопасно грузим YAML: если файла нет или он пустой — возвращаем {}.
    """
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        if data is None:
            return {}
        if isinstance(data, dict):
            return data
        # если вдруг в корне не dict (например, список) — оборачиваем
        return {"_": data}


def _load_yaml_bytes(raw: bytes, filename: str) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"The saved {filename} snapshot is invalid") from exc
    if data is None:
        return {}
    if isinstance(data, dict):
        return data
    return {"_": data}


def _source_bundle_documents(
    bundle: Dict[str, bytes],
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    required = {"vars.yml", "websites.yml", "tcp.yml"}
    if set(bundle) != required:
        raise ValueError("The configuration source bundle is incomplete")
    return (
        _load_yaml_bytes(bundle["websites.yml"], "websites.yml"),
        _load_yaml_bytes(bundle["tcp.yml"], "tcp.yml"),
        _load_yaml_bytes(bundle["vars.yml"], "vars.yml"),
    )


def _spec_from_documents(
    data_sites: Dict[str, Any],
    data_tcp: Dict[str, Any],
    config_vars: Dict[str, Any],
) -> Dict[str, Any]:
    sites = data_sites.get("sites", [])
    if not isinstance(sites, list):
        sites = []
    tcp_items = data_tcp.get("tcp_proxies")
    if tcp_items is None:
        tcp_items = data_tcp.get("tcp")
    if not isinstance(tcp_items, list):
        tcp_items = []
    return {
        "sites": sites,
        "tcp": tcp_items,
        "config_vars": config_vars or {},
    }


def _spec_from_source_bundle(bundle: Dict[str, bytes]) -> Dict[str, Any]:
    return _spec_from_documents(*_source_bundle_documents(bundle))


def _render_haproxy_cfg_from_documents(
    data_sites: Dict[str, Any],
    data_tcp: Dict[str, Any],
    config_vars: Dict[str, Any],
    extra_context: Optional[Dict[str, Any]] = None,
) -> str:
    spec = _spec_from_documents(data_sites, data_tcp, config_vars)
    context: Dict[str, Any] = dict(config_vars)
    context.update(
        {
            "sites": spec["sites"],
            "tcp_proxies": spec["tcp"],
            "tcp": spec["tcp"],
            # These namespaces are populated only by the host-side Ansible
            # loader. A similarly named key in app-owned vars.yml must not
            # override the normal UI renderer context.
            "easy_ha_proxy_runtime_vars": {},
            "easy_ha_proxy_runtime_websites": {},
            "easy_ha_proxy_runtime_tcp": {},
        }
    )
    if extra_context:
        context.update(extra_context)
    template = JINJA_ENV.get_template(HAP_TEMPLATE.name)
    return template.render(**context)


def _render_haproxy_cfg_from_source_bundle(
    bundle: Dict[str, bytes],
    extra_context: Optional[Dict[str, Any]] = None,
) -> str:
    render_context = dict(extra_context or {})
    # This value is derived from the exact source bytes and must not be
    # overrideable by vars.yml or by a caller-provided context value.
    render_context["easy_ha_proxy_config_generation"] = (
        config_source_generation(bundle)
    )
    return _render_haproxy_cfg_from_documents(
        *_source_bundle_documents(bundle),
        extra_context=render_context,
    )


def render_haproxy_cfg(extra_context: Optional[Dict[str, Any]] = None) -> str:
    """
    Рендерит haproxy.cfg из шаблона и трёх YAML-файлов.

    Поддерживаются оба варианта структуры tcp.yml:
      - tcp_proxies: [...]
      - tcp: [...]
    В контекст шаблона передаём переменную tcp_proxies.
    """
    bundle = _read_config_source_bundle(
        _current_config_source_paths(), label="current"
    )
    return _render_haproxy_cfg_from_source_bundle(bundle, extra_context)


def _read_file_text(path: Path) -> str:
    """
    Безопасно читаем текстовый файл.
    Если файла нет или ошибка чтения — возвращаем пустую строку.
    """
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except OSError:
        return ""


def _get_current_spec() -> Dict[str, Any]:
    """
    Текущее состояние из YAML:
      - список sites (websites.yml)
      - список tcp (tcp.yml)
      - все переменные vars.yml
    """
    data_sites = _load_yaml(WEBSITES_YAML)
    data_tcp = _load_yaml(TCP_YAML)
    config_vars = _load_yaml(CONFIG_YAML)

    return _spec_from_documents(data_sites, data_tcp, config_vars)


def _atomic_write_snapshot(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, dir=path.parent, prefix=f".{path.name}."
        ) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_path = handle.name
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


def save_applied_state_strict(cfg_text: str) -> None:
    """
    Persist exact source snapshots after a confirmed configuration apply.

    Snapshot YAML is written first and the state JSON last, so readers never
    observe a new applied-state hash before all rollback sources are durable.
    """
    bundle = _read_config_source_bundle(
        _current_config_source_paths(), label="current"
    )
    _persist_applied_state_bundle(cfg_text, bundle)


def save_applied_state(cfg_text: str) -> None:
    """Compatibility wrapper used by older callers."""
    save_applied_state_strict(cfg_text)


def ensure_applied_state_baseline(cfg_text: str) -> bool:
    """Seed or safely reconcile a baseline when current sources equal live cfg.

    An existing baseline is refreshed only when the parsed source documents are
    semantically unchanged.  A source-only edit can legitimately render the
    same HAProxy configuration (for example, a default for sites that do not
    exist yet); such an edit must remain visible as unapplied instead of being
    accepted merely because the current render still matches the live file.
    No snapshot may be seeded or reconciled while a confirmable transaction is
    unresolved: its currently active candidate is not known-good until the
    root daemon records confirmation.
    """
    pending_transaction, _pending_reason = config_transaction_is_pending()
    if pending_transaction:
        return False

    active = _read_file_text(HAPROXY_CFG_PATH)
    if not active or active != cfg_text:
        return False
    state = _load_applied_state()
    if state:
        try:
            current_bundle = _read_config_source_bundle(
                _current_config_source_paths(), label="current"
            )
        except ValueError:
            return False
        if _state_source_hashes_match(state, current_bundle):
            return False
        if not _state_spec_matches_source_bundle(state, current_bundle):
            return False
    save_applied_state_strict(cfg_text)
    return True


def _load_applied_state() -> Optional[Dict[str, Any]]:
    """
    Читает JSON со снимком последнего успешно применённого состояния.
    """
    try:
        text = HAPROXY_STATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def check_cfg(cfg_text: str) -> Tuple[int, str, str]:
    """
    Проверка конфига.

    1) Если есть root-демон haproxy-controld и его сокет доступен —
       шлём текст конфига ему (check-config ...) и используем
       его haproxy (на хосте).
    2) Если сокета нет / ошибка — фолбэк: локальный haproxy -c -f <tmpfile>
       внутри процесса (старый режим без Docker).
    """
    active_cfg = _read_file_text(HAPROXY_CFG_PATH)
    if active_cfg:
        try:
            validate_control_plane_transition(active_cfg, cfg_text)
        except ValueError as exc:
            return 1, "", str(exc)

    # 1. Пытаемся через haproxy-controld
    res = check_cfg_via_controld(cfg_text)
    if res is not None:
        return res

    # 2. Фолбэк: локальный haproxy -c (как было раньше)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(cfg_text)
            tmp_path = tmp.name

        proc = subprocess.run(
            HAP_CHECK_CMD + [tmp_path],
            text=True,
            capture_output=True,
        )
        rc = proc.returncode
        return rc, proc.stdout, proc.stderr
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def apply_cfg(cfg_text: str) -> Tuple[bool, str, str]:
    """
    1) haproxy -c (валидация, по возможности через haproxy-controld на хосте)
    2) запись нового конфига:
       - если есть root-демон → write-config через Unix-сокет
       - иначе локально в /etc/haproxy/haproxy.cfg + бэкап
    3) reload HAProxy (через haproxy-controld или systemctl)
    """
    # 1. Валидация (через демон или локальный haproxy -c)
    rc, stdout, stderr = check_cfg(cfg_text)
    if rc != 0:
        # Конфиг не валиден — ничего не трогаем
        return False, stdout, stderr

    # 2a. Пытаемся записать конфиг через haproxy-controld
    res = write_cfg_via_controld(cfg_text)
    if res is not None:
        ok_write, w_stdout, w_stderr = res
        if not ok_write:
            # запись на хост не удалась — не перезагружаем
            return False, w_stdout, w_stderr

        # запись успешна → перезагружаем HAProxy как обычно
        ok, reload_stdout, reload_stderr = reload_haproxy()
        return ok, reload_stdout, reload_stderr

    # 2b. Фолбэк: локальный режим (старое поведение, без root-демона)
    # 2. Каталог бэкапов
    try:
        HAPROXY_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        stderr = (stderr or "") +\
            f"\n[apply_cfg] Failed to create backup directory {HAPROXY_BACKUP_DIR}: {e}"
        return False, stdout, stderr

    # 3. Бэкап текущего /etc/haproxy/haproxy.cfg
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = HAPROXY_BACKUP_DIR / f"haproxy.cfg.bak.{ts}"

    try:
        if HAPROXY_CFG_PATH.exists():
            shutil.copy2(HAPROXY_CFG_PATH, backup_path)
            _rotate_backups(
                HAPROXY_BACKUP_DIR,
                "haproxy.cfg.bak.*",
                MAX_HAPROXY_CFG_BACKUPS,
            )
    except OSError as e:
        stderr = (stderr or "") +\
            f"\n[apply_cfg] Failed to save backup {backup_path}: {e}"
        return False, stdout, stderr

    # 4. Записываем новый конфиг локально
    try:
        HAPROXY_CFG_PATH.write_text(cfg_text, encoding="utf-8")
    except OSError as e:
        stderr = (stderr or "") +\
            f"\n[apply_cfg] Failed to write {HAPROXY_CFG_PATH}: {e}"
        return False, stdout, stderr

    # 5. Релоад сервиса (через haproxy-controld или systemctl)
    ok, reload_stdout, reload_stderr = reload_haproxy()
    return ok, reload_stdout, reload_stderr


# добавь рядом с BASE_DIR / HAPROXY_BACKUP_DIR / MAX_YAML_BACKUPS
YAML_BACKUP_DIR = BASE_DIR / "backups" / "haproxy" / "yaml"


def update_yaml_file(kind: str, content: str) -> Tuple[bool, str]:
    """
    Обновляет один из YAML-файлов (websites/tcp/vars) целиком.
    Делает бэкап в ./backups/ (относительно BASE_DIR) и валидацию синтаксиса.
    """
    pending, pending_message = config_transaction_is_pending()
    if pending:
        return False, pending_message

    mapping = {
        "websites": WEBSITES_YAML,
        "tcp": TCP_YAML,
        "vars": CONFIG_YAML,
    }
    path = mapping.get(kind)
    if path is None:
        return False, f"Unknown file type: {kind!r}"
    if len(content.encode("utf-8")) > 2 * 1024 * 1024:
        return False, 'YAML file exceeds the 2 MB size limit'

    # Валидация YAML
    try:
        data = yaml.safe_load(content) or {}
        if not isinstance(data, dict):
            return False, 'The YAML root must be a mapping'
        validate_config_data(kind, data)
    except Exception as e:
        return False, f"YAML validation error: {e}"

    # Каталог бэкапов: ./backups/ (от BASE_DIR)
    backup_dir = BASE_DIR / "backups"
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, f"Failed to create backup directory {backup_dir}: {e}"

    # Бэкап -> в ./backups/
    if path.exists():
        ts = time.strftime("%Y%m%d%H%M%S")
        backup = backup_dir / f"{path.name}.bak.{ts}"
        try:
            shutil.copy2(path, backup)
        except OSError as e:
            return False, f"Failed to save backup {backup}: {e}"

        # Ротация: оставляем только N последних бэкапов для этого файла
        _rotate_backups(backup_dir, f"{path.name}.bak.*", MAX_YAML_BACKUPS)

    # Atomic replacement prevents two Gunicorn workers from exposing a
    # partially written YAML document to the renderer.
    try:
        raw = content.encode("utf-8")
        mode = (path.stat().st_mode & 0o777) if path.exists() else 0o640
        _atomic_write_snapshot(path, raw, mode=mode)
    except OSError as e:
        return False, f"Failed to write {path}: {e}"

    return True, f"File {path.name} updated successfully"


def add_site_minimal(
    name: str,
    domain: str,
    backend_ip: str,
    backend_port: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """
    Добавляет сайт:
      - обязательные поля: name, domain, backend_ip, backend_port
      - extra: доп. поля (backend_host, backend_ssl и т.п.), если заданы

    Остальные параметры тянутся из site_defaults в шаблоне.
    """
    try:
        port_int = int(backend_port)
    except ValueError:
        return False, 'backend_port must be a number'

    if not (1 <= port_int <= 65535):
        return False, 'backend_port must be between 1 and 65535'

    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        sites = []

    # Проверка на дубликаты по name
    for s in sites:
        if s.get("name") == name:
            return False, f"A site named {name!r} already exists"

    new_site: Dict[str, Any] = {
        "name": name,
        "domain": domain,
        "backend_ip": backend_ip,
        "backend_port": port_int,
    }

    # Добиваем доп. ключи, если переданы
    if extra:
        for k, v in extra.items():
            if v is not None:
                new_site[k] = v

    sites.append(new_site)
    data["sites"] = sites

    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("websites", content)
    return ok, msg


def _rotate_backups(directory: Path, pattern: str, keep: int) -> None:
    """
    Удаляет старые backup-файлы в каталоге `directory`,
    соответствующие glob-шаблону `pattern`, оставляя только `keep` самых новых.
    """
    try:
        files = sorted(
            directory.glob(pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return

    # Оставляем только первые `keep`, остальные удаляем
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            # не критично, просто пропускаем
            pass


def _list_to_dict_by_name(items: Any) -> Dict[str, Dict[str, Any]]:
    """
    Утилита: список объектов с полем name -> dict[name] = объект.
    Игнорируем элементы без name.
    """
    result: Dict[str, Dict[str, Any]] = {}
    if not items:
        return result
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        result[str(name)] = item
    return result


def get_config_diff_summary(rendered_cfg: Optional[str] = None) -> Dict[str, Any]:
    """
    Сводка:
      - server_differs: отличается ли /etc/haproxy/haproxy.cfg от текущего рендера
      - has_applied_state: есть ли сохранённый снимок последнего apply
      - has_changes: есть ли изменения в sites/tcp/vars относительно снимка
      - списки добавленных/удалённых/изменённых sites/tcp
      - список изменённых ключей vars.yml
    """
    if rendered_cfg is None:
        rendered_cfg = render_haproxy_cfg()

    # 1. Сравниваем живой /etc/haproxy/haproxy.cfg с текущим рендером.
    # The exact source-byte generation is a confirmation-channel marker, not
    # an operational HAProxy setting. Installer migrations may rewrite YAML
    # without changing its meaning, which legitimately changes that marker.
    # Keep all transaction hashes exact, but do not ask an administrator to
    # reload HAProxy when this one value is the only difference.
    server_cfg = _read_file_text(HAPROXY_CFG_PATH)
    server_differs = not configs_operationally_equal(server_cfg, rendered_cfg)

    # 2. Смотрим, есть ли вообще сохранённое состояние
    applied_state = _load_applied_state()
    spec = _get_current_spec()

    summary: Dict[str, Any] = {
        "server_differs": server_differs,
        "has_applied_state": applied_state is not None,
        "source_has_changes": False,
        "has_changes": False,
        "sites_added": [],
        "sites_removed": [],
        "sites_changed": {},  # name -> {changed_keys: [...]}
        "tcp_added": [],
        "tcp_removed": [],
        "tcp_changed": {},    # name -> {changed_keys: [...]}
        "global_changed_keys": [],
    }

    if not applied_state:
        # история ещё не велась — показываем только факт server_differs
        return summary

    # --- sites ---
    curr_sites = _list_to_dict_by_name(spec["sites"])
    old_sites = _list_to_dict_by_name(applied_state.get("sites", []))

    curr_names = set(curr_sites)
    old_names = set(old_sites)

    summary["sites_added"] = sorted(curr_names - old_names)
    summary["sites_removed"] = sorted(old_names - curr_names)

    changed_sites: Dict[str, Dict[str, Any]] = {}
    for name in sorted(curr_names & old_names):
        before = old_sites[name]
        after = curr_sites[name]
        if before == after:
            continue

        changed_keys = sorted(
            {
                k
                for k in set(before.keys()) | set(after.keys())
                if before.get(k) != after.get(k)
            }
        )
        if not changed_keys:
            continue

        changes: Dict[str, Dict[str, Any]] = {}
        for k in changed_keys:
            changes[k] = {
                "before": before.get(k),
                "after": after.get(k),
            }

        changed_sites[name] = {
            "changed_keys": changed_keys,
            "changes": changes,
        }
    summary["sites_changed"] = changed_sites

    # --- tcp ---
    curr_tcp = _list_to_dict_by_name(spec["tcp"])
    old_tcp = _list_to_dict_by_name(applied_state.get("tcp", []))

    curr_tcp_names = set(curr_tcp)
    old_tcp_names = set(old_tcp)

    summary["tcp_added"] = sorted(curr_tcp_names - old_tcp_names)
    summary["tcp_removed"] = sorted(old_tcp_names - curr_tcp_names)

    changed_tcp: Dict[str, Dict[str, Any]] = {}
    for name in sorted(curr_tcp_names & old_tcp_names):
        before = old_tcp[name]
        after = curr_tcp[name]
        if before == after:
            continue
        changed_keys = sorted(
            {
                k
                for k in set(before.keys()) | set(after.keys())
                if before.get(k) != after.get(k)
            }
        )
        if changed_keys:
            changed_tcp[name] = {"changed_keys": changed_keys}
    summary["tcp_changed"] = changed_tcp

    # --- vars.yml ---
    curr_vars = spec["config_vars"] or {}
    old_vars = applied_state.get("config_vars", {}) or {}

    global_changed_keys = []
    for k in sorted(set(curr_vars.keys()) | set(old_vars.keys())):
        if curr_vars.get(k) != old_vars.get(k):
            global_changed_keys.append(k)
    summary["global_changed_keys"] = global_changed_keys

    summary["source_has_changes"] = any(
        [
            summary["sites_added"],
            summary["sites_removed"],
            summary["sites_changed"],
            summary["tcp_added"],
            summary["tcp_removed"],
            summary["tcp_changed"],
            summary["global_changed_keys"],
        ]
    )
    # Keep the historical aggregate for API compatibility.  Callers that show
    # an "unapplied sources" indicator should use ``source_has_changes`` so an
    # unrelated edit to the live haproxy.cfg is not mislabeled as a pending UI
    # change.
    summary["has_changes"] = server_differs or summary["source_has_changes"]

    return summary


def get_haproxy_configuration_state() -> Dict[str, Any]:
    """Return a compact, server-authoritative configuration status.

    The public status deliberately exposes only aggregate semantic changes.
    Configuration values, object names, source hashes, and transaction
    identifiers stay on the server. YAML formatting-only edits therefore do
    not produce a false "apply required" warning.
    """
    rendered_cfg = render_haproxy_cfg()
    summary = get_config_diff_summary(rendered_cfg)
    transaction_result = get_config_transaction_status()
    transaction_state = _transaction_state(transaction_result)
    pending_transaction_states = {
        "prepared",
        "pending",
        "pending_confirmation",
        "rolling_back",
    }
    settled_transaction_states = {
        "none",
        "confirmed",
        "rolled_back",
        "expired",
        "failed",
        "cancelled",
    }

    # Older installations may not have a UI applied-state snapshot yet. Seed
    # one only when no confirmation transaction is active and the current
    # sources reproduce the live configuration byte-for-byte. The helper also
    # refuses to overwrite an existing semantic source-only change.
    if (
        not summary.get("has_applied_state")
        and not summary.get("server_differs")
        and transaction_state in settled_transaction_states
    ):
        ensure_applied_state_baseline(rendered_cfg)
        # Re-read even when the helper returned false: another worker may have
        # seeded a valid baseline between the first read and the guarded check.
        summary = get_config_diff_summary(rendered_cfg)

    site_changes = (
        len(summary["sites_added"])
        + len(summary["sites_removed"])
        + len(summary["sites_changed"])
    )
    tcp_changes = (
        len(summary["tcp_added"])
        + len(summary["tcp_removed"])
        + len(summary["tcp_changed"])
    )
    global_changes = len(summary["global_changed_keys"])
    source_has_changes = bool(summary.get("source_has_changes"))
    rendered_differs = bool(summary.get("server_differs"))

    if transaction_state in pending_transaction_states:
        public_transaction_state = "pending_confirmation"
        state = "pending_confirmation"
    elif transaction_state == "rollback_failed":
        public_transaction_state = "rollback_failed"
        state = "rollback_failed"
    elif transaction_state in settled_transaction_states:
        public_transaction_state = "idle"
        if source_has_changes:
            state = "unapplied"
        elif rendered_differs:
            state = "runtime_drift"
        elif summary.get("has_applied_state"):
            state = "clean"
        else:
            state = "unknown"
    else:
        # An unavailable control daemon means a confirmation transaction
        # cannot be ruled out. Never present that situation as clean.
        public_transaction_state = "unavailable"
        state = "unknown"

    return {
        "ok": True,
        "state": state,
        "status_available": state != "unknown",
        "pending": bool(
            source_has_changes
            or rendered_differs
            or public_transaction_state
            in {"pending_confirmation", "rollback_failed"}
        ),
        "has_applied_state": bool(summary.get("has_applied_state")),
        "source_has_changes": source_has_changes,
        "rendered_differs": rendered_differs,
        "transaction_state": public_transaction_state,
        "changes": {
            "sites": site_changes,
            "tcp": tcp_changes,
            "global": global_changes,
            "total": site_changes + tcp_changes + global_changes,
        },
    }


def revert_to_last_applied_state() -> Tuple[bool, str]:
    """
    Откатывает websites.yml/tcp.yml/vars.yml к последнему успешно
    применённому состоянию (копии из backups/haproxy/last_applied_*.yml).

    Сам /etc/haproxy/haproxy.cfg не трогаем — он уже соответствует
    последнему apply. Откат нужен именно для "я наковырялся в сайтах,
    но передумал применять".
    """
    pending, pending_message = config_transaction_is_pending()
    if pending:
        return False, pending_message

    # Если вообще ещё ни разу не применяли — откатывать нечего
    if not HAPROXY_STATE_PATH.exists():
        return False, 'No saved applied state; there is nothing to revert'

    any_restored = False
    errors = []

    mapping = [
        (HAPROXY_STATE_WEBSITES, WEBSITES_YAML, "websites.yml"),
        (HAPROXY_STATE_TCP, TCP_YAML, "tcp.yml"),
        (HAPROXY_STATE_VARS, CONFIG_YAML, "vars.yml"),
    ]

    for src, dst, label in mapping:
        if not src.exists():
            # конкретный файл не бэкапили — пропускаем
            continue
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            any_restored = True
        except OSError as e:
            errors.append(f"{label}: {e}")

    if errors:
        return False, "Failed to revert some files: " + "; ".join(errors)

    if not any_restored:
        return False, 'YAML backup files were not found'

    return True, 'YAML files reverted to the last applied state'


def get_server_cfg_text() -> str:
    """
    Возвращает текст текущего /etc/haproxy/haproxy.cfg (или "" если файла нет).
    """
    return _read_file_text(HAPROXY_CFG_PATH)


def _config_for_operational_comparison(cfg_text: str) -> str:
    """Mask only the exact, generated confirmation marker value.

    The surrounding directive and condition remain part of the comparison, so
    removing the header, changing its ACL, or inserting a malformed value is
    still reported as runtime drift.
    """
    return CONFIG_GENERATION_DIRECTIVE_RE.sub(
        r"\g<1><config-generation>\g<2>\g<3>", cfg_text or ""
    )


def configs_operationally_equal(server_cfg: str, rendered_cfg: str) -> bool:
    return _config_for_operational_comparison(
        server_cfg
    ) == _config_for_operational_comparison(rendered_cfg)


def make_cfg_html_diff(server_cfg: str, rendered_cfg: str) -> str:
    """
    Строит HTML-таблицу diff (side-by-side) между живым конфигом и рендером.
    Используем стандартный difflib.HtmlDiff.
    """
    # Present the same operational comparison used by the status indicator.
    # The private exact generation still participates in guarded apply and
    # candidate reachability checks; it is merely noise in an operator diff.
    server_lines = _config_for_operational_comparison(server_cfg).splitlines()
    rendered_lines = _config_for_operational_comparison(rendered_cfg).splitlines()

    if not server_lines and not rendered_lines:
        return (
            "<div class='mono notranslate' translate='no' data-i18n-skip>"
            f"{translate('Both configurations are empty.')}"
            "</div>"
        )

    hd = difflib.HtmlDiff(wrapcolumn=120)
    table = hd.make_table(
        server_lines,
        rendered_lines,
        fromdesc=translate("/etc/haproxy/haproxy.cfg (on server)"),
        todesc=translate("haproxy.cfg (rendered from templates)"),
        context=False,
        numlines=3,
    )
    return table.replace(
        '<table class="diff"',
        '<table class="diff notranslate" translate="no" data-i18n-skip',
        1,
    )
