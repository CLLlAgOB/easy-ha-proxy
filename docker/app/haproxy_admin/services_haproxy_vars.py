"""Schema-driven, revision-safe editor for the runtime ``vars.yml`` file."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from .services_haproxy_config import CONFIG_YAML, config_transaction_is_pending
from .validation import validate_config_data


MAX_VARS_BYTES = 2 * 1024 * 1024
INTERVAL_RE = re.compile(r"^[1-9][0-9]*(?:ms|s|m|h|d)$")
HSTS_DEFAULT_SECONDS = 15_552_000
HSTS_LEGACY_INTERVAL_RE = re.compile(r"^([0-9]+)([smhd])$")
HSTS_LEGACY_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _field(
    path: str,
    label: str,
    field_type: str = "string",
    *,
    help_text: str = "",
    readonly: bool = False,
    options: tuple[str, ...] = (),
    minimum: int | None = None,
    maximum: int | None = None,
    pattern: str = "",
    rows: int = 0,
    default: Any = None,
) -> dict[str, Any]:
    return {
        "path": path,
        "label": label,
        "type": field_type,
        "help": help_text,
        "readonly": readonly,
        "options": list(options),
        "minimum": minimum,
        "maximum": maximum,
        "pattern": pattern,
        "rows": rows,
        "default": default,
    }


# Only settings that take effect in the rendered HAProxy configuration are
# writable in the guided editor. Read-only reference values are listed last so
# the editable settings stay at the top of the page.
VARS_EDITOR_SECTIONS: tuple[dict[str, Any], ...] = (
    {
        "title": "Frontends and access",
        "description": "Global switches used directly by the HAProxy template.",
        "fields": (
            _field(
                "enable_http80",
                "Listen on HTTP port 80",
                "boolean",
                help_text="Keep enabled when HTTP redirects or ACME challenges are required.",
            ),
            _field(
                "admin_ips_enabled",
                "Restrict the admin frontend by IP list",
                "boolean",
                help_text="The actual addresses are managed by the installer and whitelist tools.",
            ),
            _field(
                "admin_authelia_enabled",
                "Protect HAProxy Admin with Authelia",
                "boolean",
            ),
            _field(
                "enable_geoip",
                "Enable GeoIP filtering subsystem",
                "boolean",
                default=False,
                help_text=(
                    "Master switch for configured HTTP sites; HAProxy Admin and Authelia "
                    "are not filtered. Sites are covered only when the default below or "
                    "their per-site override is enabled."
                ),
            ),
            _field(
                "site_defaults.enable_geoip",
                "Apply GeoIP filtering to sites by default",
                "boolean",
                default=True,
                help_text=(
                    "Affects every HTTP site without an explicit GeoIP override, not only "
                    "new sites. Warning: when the master switch is on and this default is "
                    "off, only sites explicitly enabled in their editor are filtered."
                ),
            ),
            _field(
                "geoip_mode",
                "GeoIP mode",
                "choice",
                options=("allow", "deny"),
                default="allow",
            ),
            _field(
                "haproxy_nbthread",
                "HAProxy worker threads",
                "integer",
                minimum=1,
                maximum=256,
                help_text="The installer may recalculate this value during a full stack update.",
            ),
        ),
    },
    {
        "title": "Default backend",
        "description": "Defaults inherited by newly created HTTP sites.",
        "fields": (
            _field(
                "site_defaults.balance",
                "Load-balancing algorithm",
                "choice",
                options=("roundrobin", "leastconn", "source", "first", "random"),
            ),
            _field(
                "site_defaults.sticky",
                "Sticky sessions",
                "choice",
                options=("none", "cookie", "source"),
            ),
            _field("site_defaults.backend_port", "Backend port", "integer", minimum=1, maximum=65535),
            _field("site_defaults.backend_ssl", "Use TLS to the backend", "boolean"),
            _field("site_defaults.backend_ssl_verify", "Verify backend TLS certificate", "boolean"),
            _field("site_defaults.redirect_to_https", "Redirect HTTP to HTTPS", "boolean"),
            _field("site_defaults.maintenance", "Maintenance mode by default", "boolean"),
            _field(
                "site_defaults.hsts",
                "HSTS max-age",
                "integer",
                minimum=0,
                maximum=63072000,
                default=HSTS_DEFAULT_SECONDS,
                help_text="Default: 15552000 seconds (180 days). Set to 0 to disable HSTS.",
            ),
            _field("site_defaults.compress", "Enable response compression", "boolean"),
            _field("site_defaults.enable_splice_global", "Enable TCP splicing", "boolean"),
            _field(
                "site_defaults.certificate_source",
                "Default certificate source",
                "choice",
                options=("letsencrypt", "internal", "external"),
            ),
            _field("site_defaults.le_managed", "Manage Let's Encrypt renewal", "boolean"),
        ),
    },
    {
        "title": "Health checks",
        "description": "Default checks and request timeout for HTTP sites.",
        "fields": (
            _field("site_defaults.tcp_check", "Enable backend health check", "boolean"),
            _field("site_defaults.health_uri", "Health-check URI"),
            _field("site_defaults.health_status", "Expected HTTP status", "integer", minimum=100, maximum=599),
            _field(
                "site_defaults.http_request_timeout",
                "HTTP request timeout",
                "interval",
                pattern=INTERVAL_RE.pattern,
                help_text="Examples: 500ms, 5s, 2m.",
            ),
        ),
    },
    {
        "title": "Rate and connection protection",
        "description": "Default limits inherited by HTTP sites.",
        "fields": (
            _field("site_defaults.max_req_rate", "Maximum request rate", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.rate_window", "Request-rate window", "interval", pattern=INTERVAL_RE.pattern),
            _field("site_defaults.rate_ban", "Ban clients that exceed the request rate", "boolean"),
            _field("site_defaults.rate_errors", "Request-rate strike threshold", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.waf", "WAF profile", "choice", options=("none", "strict", "balanced")),
            _field("site_defaults.conn_table_expire", "Connection table expiry", "interval", pattern=INTERVAL_RE.pattern),
            _field("site_defaults.conn_rate_window", "Connection-rate window", "interval", pattern=INTERVAL_RE.pattern),
            _field("site_defaults.conn_rate_burst", "Connection burst limit", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.conn_cur_limit", "Concurrent connection limit", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.err_limit", "Per-site error limit", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.err_window", "Per-site error window", "interval", pattern=INTERVAL_RE.pattern),
            _field("site_defaults.other_err_limit", "Other error limit", "integer", minimum=0, maximum=1000000),
            _field("site_defaults.other_err_window", "Other error window", "interval", pattern=INTERVAL_RE.pattern),
            _field("site_defaults.other_err_exclude_enabled", "Ignore selected harmless errors", "boolean"),
        ),
    },
    {
        "title": "Control plane (read-only)",
        "description": (
            "Protected domains and host paths are shown for reference. "
            "Use the installer migration workflow to change service domains."
        ),
        "fields": (
            _field("root_domain", "Root domain", readonly=True),
            _field("admin_domain", "HAProxy Admin domain", readonly=True),
            _field("aut_domain", "Authelia domain", readonly=True),
            _field("haproxy_certs_dir", "Certificate directory", readonly=True),
            _field("haproxy_socket", "HAProxy runtime socket", readonly=True),
            _field("haproxy_socket_group", "HAProxy socket group", readonly=True),
        ),
    },
)


def _schema_fields() -> dict[str, dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {}
    for section in VARS_EDITOR_SECTIONS:
        for field in section["fields"]:
            fields[field["path"]] = field
    return fields


SCHEMA_FIELDS = _schema_fields()
EDITABLE_FIELDS = {
    path: field for path, field in SCHEMA_FIELDS.items() if not field["readonly"]
}


def _read_vars_bytes() -> bytes:
    try:
        raw = CONFIG_YAML.read_bytes()
    except FileNotFoundError:
        return b"{}\n"
    if len(raw) > MAX_VARS_BYTES:
        raise ValueError("vars.yml exceeds the 2 MB size limit")
    return raw


def _revision(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parse_vars(raw: bytes) -> dict[str, Any]:
    try:
        data = yaml.safe_load(raw.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"vars.yml is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("The vars.yml root must be a mapping")
    validate_config_data("vars", data)
    return data


def _get_path(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _set_path(data: dict[str, Any], path: str, value: Any) -> None:
    keys = path.split(".")
    current = data
    for key in keys[:-1]:
        nested = current.get(key)
        if not isinstance(nested, dict):
            nested = {}
            current[key] = nested
        current = nested
    current[keys[-1]] = value


def _display_value(value: Any, field_type: str) -> Any:
    if field_type == "list":
        if not isinstance(value, list):
            return "" if value is None else str(value)
        return "\n".join(str(item) for item in value)
    return value


def _hsts_editor_value(value: Any) -> int:
    """Return seconds for the numeric editor, including legacy duration values."""
    if value is None:
        return HSTS_DEFAULT_SECONDS
    if value is True:
        return 31_536_000
    if value is False:
        return 0
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 10)
    except ValueError:
        match = HSTS_LEGACY_INTERVAL_RE.fullmatch(text)
        if match:
            return int(match.group(1)) * HSTS_LEGACY_UNIT_SECONDS[match.group(2)]
    return HSTS_DEFAULT_SECONDS


def get_vars_editor_model() -> dict[str, Any]:
    raw = _read_vars_bytes()
    data = _parse_vars(raw)
    sections = deepcopy(VARS_EDITOR_SECTIONS)
    for section in sections:
        section["fields"] = list(section["fields"])
        for field in section["fields"]:
            stored_value = _get_path(data, field["path"])
            value = stored_value
            if value is None and field.get("default") is not None:
                value = field["default"]
            if field["path"] == "site_defaults.hsts":
                value = _hsts_editor_value(value)
            field["value"] = _display_value(
                value, field["type"]
            )
            field["present"] = stored_value is not None
    return {
        "sections": sections,
        "yaml": raw.decode("utf-8"),
        "revision": _revision(raw),
    }


def _coerce_value(field: dict[str, Any], value: Any) -> Any:
    field_type = field["type"]
    label = field["label"]
    if field_type == "integer" and (value is None or str(value).strip() == ""):
        if field.get("default") is not None:
            value = field["default"]
    if field_type == "boolean":
        if isinstance(value, bool):
            return value
        text = str(value or "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
        raise ValueError(f"{label}: expected true or false")
    if field_type == "integer":
        try:
            parsed = int(str(value).strip(), 10)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}: expected an integer") from exc
        minimum = field.get("minimum")
        maximum = field.get("maximum")
        if minimum is not None and parsed < minimum:
            raise ValueError(f"{label}: minimum value is {minimum}")
        if maximum is not None and parsed > maximum:
            raise ValueError(f"{label}: maximum value is {maximum}")
        return parsed
    if field_type == "list":
        if isinstance(value, list):
            items = value
        else:
            items = re.split(r"[\n,]+", str(value or ""))
        return [str(item).strip() for item in items if str(item).strip()]

    text = str(value if value is not None else "").strip()
    if len(text) > 16384 or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label}: invalid text value")
    if field_type == "choice" and text not in field["options"]:
        raise ValueError(f"{label}: unsupported value {text!r}")
    if field_type == "interval" and not INTERVAL_RE.fullmatch(text):
        raise ValueError(f"{label}: use a value such as 500ms, 5s, 2m or 1h")
    return text


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current_stat = None
    try:
        current_stat = path.stat()
    except FileNotFoundError:
        pass
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, dir=path.parent, prefix=f".{path.name}."
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_path = handle.name
        if current_stat is not None:
            os.chmod(tmp_path, current_stat.st_mode & 0o777)
        else:
            os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
        tmp_path = None
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


def _save_with_revision(content: bytes, expected_revision: str) -> dict[str, Any]:
    pending, pending_message = config_transaction_is_pending()
    if pending:
        return {"ok": False, "pending": True, "error": pending_message}
    if not isinstance(expected_revision, str) or len(expected_revision) != 64:
        return {"ok": False, "conflict": True, "error": "The vars.yml revision is missing or invalid"}
    if not content or len(content) > MAX_VARS_BYTES:
        return {"ok": False, "error": "vars.yml must be between 1 byte and 2 MB"}

    lock_path = CONFIG_YAML.parent / ".vars.yml.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        current = _read_vars_bytes()
        current_revision = _revision(current)
        if current_revision != expected_revision:
            return {
                "ok": False,
                "conflict": True,
                "error": "vars.yml changed in another session; reload the page before saving",
                "revision": current_revision,
            }
        try:
            _parse_vars(content)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "revision": current_revision}
        if content == current:
            return {
                "ok": True,
                "unchanged": True,
                "message": "No vars.yml changes were detected",
                "revision": current_revision,
                "vars_yaml": current.decode("utf-8"),
            }
        _atomic_write(CONFIG_YAML, content)
        return {
            "ok": True,
            "message": "vars.yml was saved. Validate and apply the pending configuration.",
            "revision": _revision(content),
            "vars_yaml": content.decode("utf-8"),
        }


def save_guided_vars(values: Any, expected_revision: str) -> dict[str, Any]:
    if not isinstance(values, dict):
        return {"ok": False, "error": "The values payload must be an object"}
    unknown = sorted(set(values) - set(EDITABLE_FIELDS))
    if unknown:
        return {
            "ok": False,
            "error": "Unsupported or read-only vars.yml fields: " + ", ".join(unknown),
        }

    raw = _read_vars_bytes()
    if _revision(raw) != expected_revision:
        return {
            "ok": False,
            "conflict": True,
            "error": "vars.yml changed in another session; reload the page before saving",
            "revision": _revision(raw),
        }
    data = _parse_vars(raw)
    changed: list[str] = []
    try:
        for path, supplied in values.items():
            parsed = _coerce_value(EDITABLE_FIELDS[path], supplied)
            if _get_path(data, path) != parsed:
                _set_path(data, path, parsed)
                changed.append(path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc), "revision": _revision(raw)}

    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=1000,
    ).encode("utf-8")
    result = _save_with_revision(content, expected_revision)
    result["changed_fields"] = changed
    return result


def save_raw_vars(content: Any, expected_revision: str) -> dict[str, Any]:
    if not isinstance(content, str):
        return {"ok": False, "error": "The YAML content must be text"}
    return _save_with_revision(content.encode("utf-8"), expected_revision)


ACME_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$")


def get_acme_email() -> dict[str, Any]:
    """Return the Let's Encrypt account email with an optimistic revision."""

    raw = _read_vars_bytes()
    data = _parse_vars(raw)
    return {
        "ok": True,
        "email": str(data.get("certbot_email") or ""),
        "revision": _revision(raw),
    }


def save_acme_email(email: Any, expected_revision: str) -> dict[str, Any]:
    """Persist certbot_email in vars.yml under the shared revision guard."""

    text = str(email if email is not None else "").strip()
    if len(text) > 254 or not ACME_EMAIL_RE.fullmatch(text):
        return {
            "ok": False,
            "validation_error": True,
            "error": "Enter a valid Let's Encrypt account email address",
        }
    raw = _read_vars_bytes()
    if _revision(raw) != expected_revision:
        return {
            "ok": False,
            "conflict": True,
            "error": "vars.yml changed in another session; reload the page before saving",
            "revision": _revision(raw),
        }
    data = _parse_vars(raw)
    if str(data.get("certbot_email") or "") == text:
        return {
            "ok": True,
            "unchanged": True,
            "message": "The Let's Encrypt email is already up to date",
            "email": text,
            "revision": _revision(raw),
        }
    data["certbot_email"] = text
    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=1000,
    ).encode("utf-8")
    result = _save_with_revision(content, expected_revision)
    if result.get("ok"):
        result["email"] = text
        result["message"] = (
            "The Let's Encrypt email was saved. It applies to future "
            "certificate registrations and renewals."
        )
    result.pop("vars_yaml", None)
    return result
