#!/usr/bin/env python3
"""Prepare easy-ha-proxy control-plane config from a protected legacy snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import secrets
from pathlib import Path
import shutil
import sys
from typing import Any

import yaml


class PreparationError(RuntimeError):
    pass


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PreparationError(f"Cannot read YAML {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise PreparationError(f"Expected a YAML mapping in {path}")
    return loaded


def nested(data: dict[str, Any], *keys: Any, default: Any = None) -> Any:
    value: Any = data
    for key in keys:
        if isinstance(key, int):
            if not isinstance(value, list) or len(value) <= key:
                return default
            value = value[key]
        else:
            if not isinstance(value, dict) or key not in value:
                return default
            value = value[key]
    return value


def set_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PreparationError(f"Cannot read environment file {path}: {exc}") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value
    return values


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def build_authelia(
    fallback: dict[str, Any],
    live: dict[str, Any],
    live_vars: dict[str, Any],
) -> dict[str, Any]:
    result = dict(fallback)
    session = live.get("session") or {}
    cookie = nested(live, "session", "cookies", 0, default={}) or {}
    redis = session.get("redis") or {}
    authentication_file = nested(
        live, "authentication_backend", "file", default={}
    ) or {}
    regulation = live.get("regulation") or {}
    notifier = live.get("notifier") or {}
    notifier_smtp = notifier.get("smtp") or {}
    notifier_filesystem = notifier.get("filesystem") or {}
    totp = live.get("totp") or {}
    access = live.get("access_control") or {}

    result["authelia_enabled"] = bool(live_vars.get("authelia_enabled", True))
    result["admin_authelia_enabled"] = result["authelia_enabled"]
    set_if_present(result, "aut_domain", live_vars.get("aut_domain"))
    set_if_present(result, "authelia_server_address", nested(live, "server", "address"))
    set_if_present(result, "authelia_log_level", nested(live, "log", "level"))
    set_if_present(result, "authelia_log_file_path", nested(live, "log", "file_path"))
    set_if_present(result, "authelia_session_name", session.get("name"))
    set_if_present(result, "authelia_session_same_site", session.get("same_site"))
    set_if_present(result, "authelia_session_expiration", session.get("expiration"))
    set_if_present(result, "authelia_session_inactivity", session.get("inactivity"))
    set_if_present(result, "authelia_session_remember_me", session.get("remember_me"))
    set_if_present(result, "authelia_cookie_domain", cookie.get("domain"))
    set_if_present(result, "authelia_portal_url", cookie.get("authelia_url"))
    set_if_present(
        result,
        "authelia_default_redirection_url",
        cookie.get("default_redirection_url"),
    )

    result["authelia_session_redis_enabled"] = bool(redis)
    set_if_present(result, "authelia_session_redis_host", redis.get("host"))
    set_if_present(result, "authelia_session_redis_port", redis.get("port"))
    set_if_present(
        result, "authelia_session_redis_database", redis.get("database_index")
    )
    set_if_present(
        result,
        "authelia_session_redis_max_active",
        redis.get("maximum_active_connections"),
    )
    set_if_present(
        result,
        "authelia_session_redis_max_idle",
        redis.get("minimum_idle_connections"),
    )
    set_if_present(result, "authelia_session_redis_timeout", redis.get("timeout"))

    set_if_present(
        result, "authelia_storage_local_path", nested(live, "storage", "local", "path")
    )
    set_if_present(
        result,
        "authelia_auth_refresh_interval",
        nested(live, "authentication_backend", "refresh_interval"),
    )
    set_if_present(result, "authelia_users_file_path", authentication_file.get("path"))
    set_if_present(result, "authelia_users_watch", authentication_file.get("watch"))
    set_if_present(
        result,
        "authelia_password_algorithm",
        nested(authentication_file, "password", "algorithm"),
    )

    set_if_present(result, "authelia_regulation_modes", regulation.get("modes"))
    set_if_present(
        result, "authelia_regulation_max_retries", regulation.get("max_retries")
    )
    set_if_present(result, "authelia_regulation_find_time", regulation.get("find_time"))
    set_if_present(result, "authelia_regulation_ban_time", regulation.get("ban_time"))

    if "filesystem" in notifier:
        result["authelia_notifier_type"] = "filesystem"
        set_if_present(
            result,
            "authelia_notifier_filesystem_filename",
            notifier_filesystem.get("filename"),
        )
    elif "smtp" in notifier:
        result["authelia_notifier_type"] = "smtp"
        # All SMTP notifications in the managed stack now use mail_relay.
        # A legacy direct address is surfaced in the UI until Save and apply,
        # but the upgraded Compose stack must still make the relay available.
        result["mail_relay_server"] = True
        set_if_present(result, "mail_smtp_timeout", notifier_smtp.get("timeout"))
        set_if_present(result, "mail_subject", notifier_smtp.get("subject"))
        set_if_present(
            result,
            "mail_smtp_disable_starttls",
            notifier_smtp.get("disable_starttls"),
        )
        set_if_present(
            result,
            "mail_smtp_disable_require_tls",
            notifier_smtp.get("disable_require_tls"),
        )
        set_if_present(
            result,
            "mail_smtp_tls_skip_verify",
            nested(notifier_smtp, "tls", "skip_verify"),
        )

    set_if_present(result, "authelia_totp_issuer", totp.get("issuer"))
    set_if_present(result, "authelia_totp_period", totp.get("period"))
    set_if_present(result, "authelia_totp_skew", totp.get("skew"))
    set_if_present(result, "authelia_default_policy", access.get("default_policy"))
    set_if_present(result, "authelia_access_control_rules", access.get("rules"))
    result["authelia_users_mode"] = "selfservice"
    return result


def prepare(live_dir: Path, controller_dir: Path, output_dir: Path) -> None:
    live_dir = live_dir.resolve()
    controller_dir = controller_dir.resolve()
    output_dir = output_dir.resolve()

    required = {
        "live_vars": live_dir / "opt/haproxy-admin/config/vars.yml",
        "live_sites": live_dir / "opt/haproxy-admin/config/websites.yml",
        "live_tcp": live_dir / "opt/haproxy-admin/config/tcp.yml",
        "live_authelia": live_dir / "opt/authelia/configuration.yml",
        "live_users": live_dir / "opt/authelia/users_database.yml",
        "live_env": live_dir / "opt/authelia/.env",
        "controller_authelia": controller_dir / "ansible/authelia.yml",
    }
    missing = [str(path) for path in required.values() if not path.is_file()]
    if missing:
        raise PreparationError("Required snapshot files are missing: " + ", ".join(missing))
    if output_dir.exists():
        raise PreparationError(f"Output directory already exists: {output_dir}")

    live_vars = load_yaml(required["live_vars"])
    live_sites = load_yaml(required["live_sites"])
    live_tcp = load_yaml(required["live_tcp"])
    live_authelia = load_yaml(required["live_authelia"])
    live_users = load_yaml(required["live_users"])
    fallback_authelia = load_yaml(required["controller_authelia"])
    live_env = read_env(required["live_env"])

    users = live_users.get("users") or {}
    if not isinstance(users, dict) or not users:
        raise PreparationError("The live Authelia users database is empty or invalid.")

    secrets_data = {
        "authelia_session_secret": nested(live_authelia, "session", "secret"),
        "authelia_jwt_secret": nested(
            live_authelia, "identity_validation", "reset_password", "jwt_secret"
        ),
        "authelia_storage_key": nested(live_authelia, "storage", "encryption_key"),
        "mail_smtp_pass": (
            live_env.get("MAIL_SMTP_PASSWORD")
            or live_env.get("SMTP_PASSWORD")
            or nested(live_authelia, "notifier", "smtp", "password", default="")
        ),
        "haproxy_admin_proxy_secret": secrets.token_urlsafe(48),
    }
    missing_secrets = [
        key
        for key in (
            "authelia_session_secret",
            "authelia_jwt_secret",
            "authelia_storage_key",
        )
        if not secrets_data.get(key)
    ]
    if missing_secrets:
        raise PreparationError(
            "Required live secrets are missing: " + ", ".join(missing_secrets)
        )

    authelia_data = build_authelia(
        fallback_authelia,
        live_authelia,
        live_vars,
    )
    root_domain = str(live_vars.get("root_domain") or "")
    admin_domain = str(live_vars.get("admin_domain") or "")
    authelia_domain = str(
        live_vars.get("aut_domain") or authelia_data.get("aut_domain") or ""
    )
    if not root_domain or not admin_domain or not authelia_domain:
        raise PreparationError("Cannot determine root/admin/Authelia domains.")

    metadata = {
        "product": "easy-ha-proxy",
        "configured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": "https://github.com/CLLlAgOB/easy-ha-proxy.git",
        "test_mode": False,
        "test_server_ip": "",
        "admin_domain": admin_domain,
        "authelia_domain": authelia_domain,
        "migration_source": str(live_dir),
        "migration_mode": "legacy_snapshot",
    }

    temporary = output_dir.parent / f".{output_dir.name}.tmp-{os.getpid()}"
    temporary.mkdir(parents=True, mode=0o700)
    os.chmod(temporary, 0o700)
    try:
        write_yaml(temporary / "vars.yml", live_vars)
        write_yaml(temporary / "authelia.yml", authelia_data)
        write_yaml(
            temporary / "authelia_users_initial.yml",
            {"authelia_users": users},
        )
        write_yaml(temporary / "websites.yml", live_sites)
        write_yaml(temporary / "tcp.yml", live_tcp)
        write_yaml(temporary / "secrets.yml", secrets_data)
        write_yaml(temporary / "metadata.yml", metadata)
        inventory = temporary / "inventory.ini"
        inventory.write_text(
            "[easy_ha_proxy]\n"
            "localhost ansible_connection=local "
            "ansible_python_interpreter=/usr/bin/python3\n",
            encoding="utf-8",
        )
        os.chmod(inventory, 0o600)
        temporary.rename(output_dir)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    site_count = len(live_sites.get("sites") or [])
    tcp_count = len(
        live_tcp.get("tcp_proxies", live_tcp.get("tcp", [])) or []
    )
    print(f"Prepared config: {output_dir}")
    print(f"Sites preserved: {site_count}")
    print(f"TCP proxies preserved: {tcp_count}")
    print(f"Authelia users preserved: {len(users)}")
    print("Secrets copied from the protected live snapshot; values were not printed.")
    print("No files were uploaded to the server and no services were changed.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live-dir", required=True, type=Path)
    parser.add_argument("--controller-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        prepare(args.live_dir, args.controller_dir, args.output_dir)
    except PreparationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
