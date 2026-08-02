#!/usr/bin/env python3
"""Single-server installer and updater for easy-ha-proxy."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import getpass
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat as stat_module
import subprocess
import sys
import tempfile
from typing import Any

import yaml


PRODUCT = "easy-ha-proxy"
DEFAULT_HOME = Path("/opt/easy-ha-proxy")
DEFAULT_CONFIG_DIR = Path("/etc/easy-ha-proxy")
DEFAULT_REPOSITORY = "https://github.com/CLLlAgOB/easy-ha-proxy.git"
DEFAULT_ADMIN_IMAGE_REPOSITORY = "clllagob/haproxy-admin-ui"

# A "release channel" is the single user-facing choice that binds the git branch
# (host source/daemon updates) to the matching Docker image tag (the UI
# container). "local" is the maintainer mode: deploy the on-server synced source
# and leave branch/image untouched.
RELEASE_CHANNELS: dict[str, dict[str, str]] = {
    "stable": {"source_channel": "github", "branch": "main", "image_channel": "latest"},
    "alpha": {"source_channel": "github", "branch": "alpha", "image_channel": "alpha"},
    "local": {"source_channel": "local"},
}


_GIT_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")


def _valid_git_branch(branch: str) -> bool:
    return bool(
        _GIT_BRANCH_RE.fullmatch(branch)
        and ".." not in branch
        and not branch.startswith("/")
        and not branch.endswith("/")
        and not branch.endswith(".lock")
        and "//" not in branch
    )


def release_channel_from_settings(
    *, source_channel: str, branch: str, image_channel: str
) -> str:
    """Derive the release-channel name for display.

    Keyed off the image tag (and the source) so existing installs that predate
    the stored branch still map cleanly. Saving a named channel realigns the
    branch, so the pair stays consistent going forward.
    """

    if (source_channel or "github") == "local":
        return "local"
    if (image_channel or "latest") == "alpha":
        return "alpha"
    return "stable"
REBOOT_REQUIRED_PATH = Path("/var/run/reboot-required")
REBOOT_SCHEDULE_MARKER = Path("/run/easy-ha-proxy/reboot-scheduled")
WEB_REBOOT_SCHEDULE_MARKER = Path(
    "/run/easy-ha-proxy/easy-ha-proxy-web-reboot.json"
)
REBOOT_DELAY_SECONDS = 30
REBOOT_SYSTEMD_UNIT_PREFIX = "easy-ha-proxy-reboot"
UPDATE_SOURCE_REFRESHED_ENV = "EASY_HA_PROXY_UPDATE_SOURCE_REFRESHED"
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUNTIME_HAPROXY_CONFIG_DIR = Path("/opt/haproxy-admin/config")
RUNTIME_CONFIG_MAX_BYTES = 2 * 1024 * 1024
# Only values consumed directly by haproxy.cfg may flow from the app-owned
# runtime vars.yml back into root-managed installer configuration. Stack
# controls (image/channel, domains, certificates, language and secrets) remain
# installer-owned even if a stale copy is present in runtime vars.yml.
RUNTIME_HAPROXY_VAR_KEYS = frozenset(
    {
        "admin_allowed_ips",
        "admin_ips_enabled",
        "admin_password",
        "enable_geoip",
        "enable_http80",
        "export_prometheus",
        "geoip_country_codes",
        "geoip_mode",
        "haproxy_nbthread",
        "haproxy_nbthread_max",
        "haproxy_socket",
        "haproxy_socket_group",
        "localpeer",
        "peers_bind",
        "peers_enabled",
        "peers_name",
        "prometheus_port",
        "site_defaults",
    }
)
INSTALLER_LANGUAGE = os.environ.get("EASY_HA_PROXY_LANGUAGE", "en").strip().lower()
if INSTALLER_LANGUAGE not in {"en", "ru"}:
    INSTALLER_LANGUAGE = "en"

RU_MESSAGES = {
    "Value is required.": "Значение обязательно.",
    "Enter yes or no.": "Введите yes/да или no/нет.",
    "Enter a full DNS name, for example example.com.": "Введите полное DNS-имя, например example.com.",
    "Enter a valid email address.": "Введите корректный адрес электронной почты.",
    "Use only letters, digits and . _ @ - (maximum 64 characters).": "Используйте только буквы, цифры и . _ @ - (не более 64 символов).",
    "Port must be an integer.": "Порт должен быть целым числом.",
    "Port must be between 1 and 65535.": "Порт должен быть в диапазоне 1–65535.",
    "Enter a valid IPv4 or IPv6 address.": "Введите корректный IPv4- или IPv6-адрес.",
    "First Authelia administrator password: ": "Пароль первого администратора Authelia: ",
    "Use at least 12 characters.": "Используйте не менее 12 символов.",
    "Repeat password: ": "Повторите пароль: ",
    "Passwords do not match.": "Пароли не совпадают.",
    "Root domain": "Корневой домен",
    "Administration domain": "Домен панели управления",
    "Authelia portal domain": "Домен портала Authelia",
    "Administrator email": "Email администратора",
    "Let's Encrypt email": "Email для Let's Encrypt",
    "Let's Encrypt / administrator email": "Email для Let's Encrypt / администратора",
    "Certificate source": "Источник сертификатов",
    "Initial certificate source": "Начальный источник сертификата",
    "Docker image channel": "Канал Docker-образа",
    "Enter latest or alpha.": "Введите latest или alpha.",
    "Enter letsencrypt or internal.": "Введите letsencrypt или internal.",
    "Timezone": "Часовой пояс",
    "Server LAN/host-only IP": "LAN/host-only IP сервера",
    "Admin allowed IP/CIDR list, comma-separated [all authenticated users]: ": "Разрешённые IP/CIDR админки через запятую [все аутентифицированные пользователи]: ",
    "GeoIP allowed country codes, comma-separated [disabled; examples: RU,PL,BY]: ": "Разрешённые коды стран GeoIP через запятую [выключено; примеры: RU,PL,BY]: ",
    "Existing initial Authelia users are preserved. Manage active users through the web UI.": "Существующие начальные пользователи Authelia сохранены. Управляйте активными пользователями через веб-интерфейс.",
    "First administrator login": "Логин первого администратора",
    "Administrator display name": "Отображаемое имя администратора",
    "Configure email notifications through the internal relay": "Настроить почтовые уведомления через внутренний relay",
    "SMTP server": "SMTP-сервер",
    "SMTP port": "SMTP-порт",
    "SMTP username": "Пользователь SMTP",
    "SMTP password [leave empty to preserve current]: ": "Пароль SMTP [оставьте пустым, чтобы сохранить текущий]: ",
    "SMTP password: ": "Пароль SMTP: ",
    "Mail sender": "Отправитель писем",
    "Notification recipient": "Получатель уведомлений",
    "The LAN/host-only IP and hosts-file setup are ready. Continue": "LAN/host-only IP и файл hosts настроены. Продолжить",
    "Private DNS/hosts are configured and the internal CA trust plan is ready. Continue": "Приватный DNS/hosts настроен, план добавления внутреннего CA в доверенные готов. Продолжить",
    "DNS is configured and TCP ports 80/443 are reachable. Continue": "DNS настроен, TCP-порты 80/443 доступны. Продолжить",
    "DNS is not ready. Continue installation and skip initial Let's Encrypt issuance for unresolved names": "DNS ещё не готов. Продолжить установку и пропустить первоначальный выпуск Let's Encrypt для неразрешённых имён",
    "DNS preflight was skipped. Continue installation": "Предварительная проверка DNS пропущена. Продолжить установку",
    "easy-ha-proxy installation completed.": "Установка easy-ha-proxy завершена.",
    "The operating system requires a reboot to finish applying updates.": "Для завершения применения обновлений требуется перезагрузка сервера.",
    "Reboot the server now": "Перезагрузить сервер сейчас",
    "Reboot deferred. Run 'sudo systemctl reboot' manually or choose 'Reboot server' in the assistant.": "Перезагрузка отложена. Выполните 'sudo systemctl reboot' вручную или выберите «Перезагрузить сервер» в помощнике.",
    "A server reboot has been scheduled in {seconds} seconds. The current session will close cleanly.": "Перезагрузка сервера запланирована через {seconds} секунд. Текущая сессия будет завершена корректно.",
    "A reboot is already scheduled; the current session will close.": "Перезагрузка уже запланирована; текущая сессия будет завершена.",
    "No reboot is currently required.": "В данный момент перезагрузка не требуется.",
    "Security notification": "Уведомление безопасности",
}


def _(message: str) -> str:
    """Translate an installer message while keeping English as source."""

    if INSTALLER_LANGUAGE == "ru":
        return RU_MESSAGES.get(message, message)
    return message

INSTALL_TAGS = ",".join(
    (
        "crt-install",
        "crt-notify",
        "crt-hooks",
        "crt-renew",
        "ha-install",
        "apparmor",
        "geo",
        "ha-cfg",
        "docker",
        "aut-install",
        "ha-adm-install",
        "ha-adm-healthd",
        "ha-adm-cfg",
        "ha-adm-controld",
        "ha-adm-backupd",
        "ha-adm-updated",
        "ha-adm-journald",
        "ha-adm-start",
        "status",
    )
)

UPDATE_TAGS = ",".join(
    (
        "crt-install",
        "crt-hooks",
        "crt-notify",
        "ha-install",
        "apparmor",
        "geo",
        "ha-cfg",
        "docker",
        "aut-install",
        "aut-update",
        "ha-adm-install",
        "ha-adm-healthd",
        "ha-adm-cfg",
        "ha-adm-controld",
        "ha-adm-backupd",
        "ha-adm-updated",
        "ha-adm-journald",
        "ha-adm-update",
        "ha-adm-start",
        "status",
    )
)

UI_TAGS = ",".join(
    (
        "ha-cfg",
        "aut-daemons",
        "ha-adm-daemons",
        "ha-adm-healthd",
        "ha-adm-cfg",
        "ha-adm-controld",
        "ha-adm-backupd",
        "ha-adm-updated",
        "ha-adm-update",
        "ha-adm-start",
        "status",
    )
)
DAEMON_TAGS = "aut-daemons,ha-adm-daemons,status"
HOST_SERVICE_TAGS = ",".join(
    (
        "crt-install",
        "crt-hooks",
        "crt-notify",
        "ha-install",
        "apparmor",
        "geo",
        "ha-cfg",
        "ha-adm-install",
        "ha-adm-healthd",
        "ha-adm-backupd",
        "ha-adm-updated",
        "ha-adm-journald",
        "aut-install",
        "status",
    )
)
UPDATE_COMPONENT_TAGS = {
    "all": UPDATE_TAGS,
    "ui": UI_TAGS,
    "daemons": DAEMON_TAGS,
    "services": HOST_SERVICE_TAGS,
    "containers": "aut-update,ha-adm-update,status",
    # Render Compose before pulling so an explicit latest/alpha channel switch
    # actually changes the image reference used by the targeted update.
    "admin-container": "ha-adm-cfg,ha-adm-update,status",
    "authelia-container": "aut-update,status",
    "os": "upgrade,status",
}
CONFIGURE_TAGS = f"crt-renew,{UPDATE_TAGS}"
LANGUAGE_TAGS = "aut-install,ha-adm-cfg,ha-adm-start,status"
DOMAIN_MIGRATION_TAGS = ",".join(
    (
        "crt-hooks",
        "crt-renew",
        "ha-cfg",
        "aut-cfg",
        "ha-adm-cfg",
        "ha-adm-start",
        "status",
    )
)
INTERNAL_CA_DOMAIN_MIGRATION_TAGS = ",".join(
    tag
    for tag in DOMAIN_MIGRATION_TAGS.split(",")
    if tag != "crt-renew"
)
INTERNAL_CA_INSTALL_TAGS = ",".join(
    tag for tag in INSTALL_TAGS.split(",") if tag != "crt-renew"
)
RESTORE_TAGS = ",".join(
    tag for tag in INSTALL_TAGS.split(",") if tag != "crt-renew"
)
# Configuration-scope restore only re-renders and reloads HAProxy from the
# restored site configs and certificates; host services stay untouched.
RESTORE_CONFIG_TAGS = "ha-adm-cfg,ha-cfg,status"
RESTORE_SKIP_TAGS = "restore-network"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class InstallerError(RuntimeError):
    """Expected installer failure with a user-facing message."""


def source_dir() -> Path:
    configured = os.environ.get("EASY_HA_PROXY_SOURCE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def config_dir() -> Path:
    return Path(
        os.environ.get("EASY_HA_PROXY_CONFIG_DIR", str(DEFAULT_CONFIG_DIR))
    ).expanduser()


def install_home() -> Path:
    return Path(os.environ.get("EASY_HA_PROXY_HOME", str(DEFAULT_HOME))).expanduser()


def require_root() -> None:
    if os.geteuid() != 0 and os.environ.get("EASY_HA_PROXY_ALLOW_NON_ROOT") != "1":
        raise InstallerError("Run this command as root (sudo easy-ha-proxy ...).")


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"\n+ {printable}", flush=True)
    return subprocess.run(command, text=True, env=env, check=check)


def prompt(
    label: str,
    *,
    default: str | None = None,
    validator: Any | None = None,
) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        value = input(f"{_(label)}{suffix}: ").strip()
        if not value and default is not None:
            value = default
        if not value:
            print(_("Value is required."))
            continue
        if validator is not None:
            error = validator(value)
            if error:
                print(error)
                continue
        return value


def prompt_bool(label: str, *, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{_(label)} [{hint}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "д", "да"}:
            return True
        if value in {"n", "no", "н", "нет"}:
            return False
        print(_("Enter yes or no."))


def reboot_required() -> bool:
    """Return whether the operating system requests a reboot."""

    return REBOOT_REQUIRED_PATH.exists()


def reboot_schedule_is_active() -> bool:
    """Validate that the runtime marker still has an active systemd unit."""

    # A web-scheduled timer is owned and canceled by the update broker. Treat
    # it as active here so the CLI cannot schedule a competing reboot.
    if os.path.lexists(WEB_REBOOT_SCHEDULE_MARKER):
        return True

    if not REBOOT_SCHEDULE_MARKER.exists():
        return False

    try:
        marker_values = dict(
            line.split("=", 1)
            for line in REBOOT_SCHEDULE_MARKER.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
    except OSError:
        marker_values = {}
    unit_name = marker_values.get("unit", "")
    if not re.fullmatch(
        rf"{re.escape(REBOOT_SYSTEMD_UNIT_PREFIX)}-[0-9]{{14}}-[0-9]+-[0-9a-f]{{8}}",
        unit_name,
    ):
        REBOOT_SCHEDULE_MARKER.unlink(missing_ok=True)
        return False

    systemctl = shutil.which("systemctl")
    if systemctl:
        for suffix in ("timer", "service"):
            try:
                result = subprocess.run(
                    [
                        systemctl,
                        "is-active",
                        "--quiet",
                        f"{unit_name}.{suffix}",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except OSError:
                break
            if result.returncode == 0:
                return True

    REBOOT_SCHEDULE_MARKER.unlink(missing_ok=True)
    return False


def schedule_server_reboot() -> None:
    """Schedule reboot after the assistant and SSH session can exit cleanly."""

    if reboot_schedule_is_active():
        print(_("A reboot is already scheduled; the current session will close."))
        print("EASY_HA_PROXY_REBOOT_SCHEDULED=1", flush=True)
        return

    systemd_run = shutil.which("systemd-run")
    systemctl = shutil.which("systemctl")
    if not systemd_run or not systemctl:
        raise InstallerError(
            "Cannot schedule a controlled reboot: systemd-run or systemctl is missing."
        )

    unit_name = (
        f"{REBOOT_SYSTEMD_UNIT_PREFIX}-"
        f"{dt.datetime.now(dt.timezone.utc):%Y%m%d%H%M%S}-"
        f"{os.getpid()}-{secrets.token_hex(4)}"
    )
    REBOOT_SCHEDULE_MARKER.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    REBOOT_SCHEDULE_MARKER.write_text(
        f"unit={unit_name}\n"
        f"scheduled_at={dt.datetime.now(dt.timezone.utc).isoformat()}\n",
        encoding="utf-8",
    )
    os.chmod(REBOOT_SCHEDULE_MARKER, 0o644)
    try:
        run(
            [
                systemd_run,
                f"--unit={unit_name}",
                "--description=easy-ha-proxy controlled reboot",
                f"--on-active={REBOOT_DELAY_SECONDS}s",
                "--timer-property=AccuracySec=1s",
                systemctl,
                "reboot",
            ]
        )
    except Exception:
        REBOOT_SCHEDULE_MARKER.unlink(missing_ok=True)
        raise
    message = _(
        "A server reboot has been scheduled in {seconds} seconds. "
        "The current session will close cleanly."
    ).format(seconds=REBOOT_DELAY_SECONDS)
    print(f"\n{message}")
    print("EASY_HA_PROXY_REBOOT_SCHEDULED=1", flush=True)


def offer_pending_reboot(*, assume_yes: bool = False) -> bool:
    """Prompt for a required reboot, defaulting safely to defer."""

    if not reboot_required():
        return False

    print(f"\n{_('The operating system requires a reboot to finish applying updates.')}")
    decision = os.environ.get("EASY_HA_PROXY_REBOOT_DECISION", "").strip().lower()
    if assume_yes or decision in {"y", "yes", "1", "true", "д", "да"}:
        reboot_now = True
    elif decision in {"n", "no", "0", "false", "н", "нет"}:
        reboot_now = False
    elif sys.stdin.isatty():
        reboot_now = prompt_bool("Reboot the server now", default=False)
    else:
        reboot_now = False

    if reboot_now:
        schedule_server_reboot()
        return True

    print(
        _(
            "Reboot deferred. Run 'sudo systemctl reboot' manually or choose "
            "'Reboot server' in the assistant."
        )
    )
    return False


def validate_domain(value: str) -> str | None:
    if not DOMAIN_RE.fullmatch(value.lower()):
        return _("Enter a full DNS name, for example example.com.")
    return None


def validate_email(value: str) -> str | None:
    if value.count("@") != 1 or "." not in value.rsplit("@", 1)[-1]:
        return _("Enter a valid email address.")
    return None


def validate_username(value: str) -> str | None:
    if not USERNAME_RE.fullmatch(value):
        return _("Use only letters, digits and . _ @ - (maximum 64 characters).")
    return None


def validate_port(value: str) -> str | None:
    try:
        port = int(value)
    except ValueError:
        return _("Port must be an integer.")
    if not 1 <= port <= 65535:
        return _("Port must be between 1 and 65535.")
    return None


def validate_ip(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return _("Enter a valid IPv4 or IPv6 address.")
    return None


def validate_certificate_source(value: str) -> str | None:
    if value.strip().lower() not in {"letsencrypt", "internal"}:
        return _("Enter letsencrypt or internal.")
    return None


def prompt_password() -> str:
    while True:
        first = getpass.getpass(_("First Authelia administrator password: "))
        if len(first) < 12:
            print(_("Use at least 12 characters."))
            continue
        second = getpass.getpass(_("Repeat password: "))
        if first != second:
            print(_("Passwords do not match."))
            continue
        return first


def parse_networks(value: str) -> list[str]:
    networks: list[str] = []
    for item in (part.strip() for part in value.split(",")):
        if not item:
            continue
        try:
            if "/" in item:
                networks.append(str(ipaddress.ip_network(item, strict=False)))
            else:
                networks.append(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise InstallerError(f"Invalid IP/network {item!r}: {exc}") from exc
    return networks


def parse_countries(value: str) -> list[str]:
    countries = [part.strip().upper() for part in value.split(",") if part.strip()]
    invalid = [country for country in countries if not re.fullmatch(r"[A-Z]{2}", country)]
    if invalid:
        raise InstallerError(
            "Country codes must use ISO alpha-2 format: " + ", ".join(invalid)
        )
    return countries


def detect_timezone() -> str:
    timezone_file = Path("/etc/timezone")
    try:
        value = timezone_file.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    return value or "UTC"


def detect_local_ip() -> str:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 53))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        if sock is not None:
            sock.close()


def write_yaml(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(
                data,
                stream,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def write_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def backup_configuration(directory: Path) -> Path | None:
    if not directory.exists() or not any(directory.iterdir()):
        return None
    backup_root = directory / "backups"
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = backup_root / timestamp
    destination.mkdir(parents=True, mode=0o700)
    for item in directory.iterdir():
        if item.name == "backups":
            continue
        if item.is_file():
            shutil.copy2(item, destination / item.name)
    print(f"Configuration backup: {destination}")
    return destination


def build_site_defaults(*, geoip_enabled: bool) -> dict[str, Any]:
    # The top-level enable_geoip value is the subsystem master switch. Keep the
    # per-site default enabled even when a fresh installation initially leaves
    # the subsystem off, so enabling it later actually covers existing sites.
    # Existing installations preserve their complete site_defaults mapping.
    return {
        "balance": "roundrobin",
        "sticky": "none",
        "backend_port": 80,
        "backend_ssl": False,
        "backend_ssl_verify": False,
        "redirect_to_https": True,
        "maintenance": False,
        "hsts": 15_552_000,
        "compress": False,
        "add_headers": {},
        "max_req_rate": 200,
        "rate_window": "20s",
        "rate_ban": True,
        "rate_errors": 20,
        "enable_geoip": True,
        "waf": "none",
        "tcp_check": False,
        "health_uri": "/",
        "health_status": 200,
        "http_request_timeout": "5s",
        "conn_table_expire": "30s",
        "conn_rate_window": "10s",
        "conn_rate_burst": 40,
        "conn_cur_limit": 100,
        "err_limit": 8,
        "err_window": "20s",
        "other_err_window": "20s",
        "other_err_limit": 12,
        "other_err_exclude_enabled": True,
        "other_err_exclude_exact": [{"path": "/", "methods": ["GET"]}],
        "enable_splice_global": False,
    }


def configure_interactively(
    *,
    overwrite: bool = False,
    test_mode: bool | None = None,
    certificate_source: str | None = None,
    image_channel: str | None = None,
    source_channel: str | None = None,
) -> Path:
    directory = config_dir()
    marker = directory / "metadata.yml"
    has_existing_configuration = marker.exists()
    existing_users: dict[str, Any] | None = None
    existing_variables: dict[str, Any] = {}
    existing_authelia: dict[str, Any] = {}
    existing_secrets: dict[str, Any] = {}
    existing_metadata: dict[str, Any] = {}
    existing_websites: dict[str, Any] = {"sites": []}
    existing_tcp: dict[str, Any] = {"tcp_proxies": []}
    if has_existing_configuration and not overwrite:
        return directory

    if (
        not sys.stdin.isatty()
        and os.environ.get("EASY_HA_PROXY_ALLOW_STDIN") != "1"
    ):
        try:
            sys.stdin = open("/dev/tty", "r", encoding="utf-8")  # noqa: SIM115
        except OSError as exc:
            raise InstallerError(
                "Interactive configuration needs a terminal. "
                "Download install-local.sh and run it from a terminal."
            ) from exc

    if has_existing_configuration:
        def load_existing_mapping(path: Path) -> dict[str, Any]:
            try:
                loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                raise InstallerError(
                    f"Cannot safely read existing {path.name}; "
                    "refusing to overwrite the current configuration."
                ) from None
            if not isinstance(loaded, dict):
                raise InstallerError(
                    f"Existing {path.name} must contain a YAML mapping; "
                    "refusing to overwrite the current configuration."
                )
            return loaded

        existing_metadata = load_existing_mapping(marker)
        existing_variables = load_existing_mapping(directory / "vars.yml")
        existing_authelia = load_existing_mapping(directory / "authelia.yml")
        existing_secrets = load_existing_mapping(directory / "secrets.yml")

        try:
            users_path = directory / "authelia_users_initial.yml"
            loaded_users = load_existing_mapping(users_path)
            if isinstance(loaded_users, dict) and loaded_users.get("authelia_users"):
                existing_users = loaded_users
        except InstallerError:
            if users_path.exists():
                raise
            existing_users = None
        runtime_documents = None
        if not bool(existing_metadata.get("configuration_pending", False)):
            runtime_documents = _load_runtime_haproxy_documents(
                RUNTIME_HAPROXY_CONFIG_DIR
            )
        if runtime_documents is not None:
            runtime_vars, runtime_websites, runtime_tcp = runtime_documents
            for key in RUNTIME_HAPROXY_VAR_KEYS:
                if key in runtime_vars:
                    existing_variables[key] = copy.deepcopy(runtime_vars[key])
                else:
                    existing_variables.pop(key, None)
            existing_websites = copy.deepcopy(runtime_websites)
            existing_tcp = copy.deepcopy(runtime_tcp)
        else:
            for name, default_value in (
                ("websites.yml", {"sites": []}),
                ("tcp.yml", {"tcp_proxies": []}),
            ):
                source = directory / name
                loaded = (
                    load_existing_mapping(source)
                    if source.is_file()
                    else copy.deepcopy(default_value)
                )
                if name == "websites.yml":
                    existing_websites = loaded
                else:
                    existing_tcp = loaded

    if test_mode is None:
        test_mode = bool(existing_metadata.get("test_mode", False))

    if certificate_source is not None:
        certificate_source = certificate_source.strip().lower()
        error = validate_certificate_source(certificate_source)
        if error:
            raise InstallerError(error)
    if test_mode and certificate_source not in {None, "internal"}:
        raise InstallerError("Test mode requires the internal certificate authority.")
    if test_mode:
        certificate_source = "internal"

    if image_channel is not None:
        image_channel = image_channel.strip().lower()
        if image_channel not in {"latest", "alpha"}:
            raise InstallerError("Docker image channel must be latest or alpha.")
    if source_channel is None:
        source_channel = str(
            os.environ.get("EASY_HA_PROXY_SOURCE_CHANNEL")
            or existing_metadata.get("source_channel")
            or "github"
        ).strip().lower()
    if source_channel not in {"github", "local"}:
        raise InstallerError("Source channel must be github or local.")

    if test_mode:
        print(
            "\nТестовая конфигурация easy-ha-proxy\n"
            if INSTALLER_LANGUAGE == "ru"
            else "\neasy-ha-proxy test configuration\n"
        )
    else:
        print(
            "\nПервоначальная конфигурация easy-ha-proxy\n"
            if INSTALLER_LANGUAGE == "ru"
            else "\nInitial easy-ha-proxy configuration\n"
        )

    if image_channel is None:
        existing_image_channel = str(
            existing_metadata.get("image_channel")
            or ("alpha" if test_mode else "latest")
        ).strip().lower()
        if existing_image_channel not in {"latest", "alpha"}:
            existing_image_channel = "latest"
        print(
            "  1) latest (релиз)\n  2) alpha (тестовая сборка)"
            if INSTALLER_LANGUAGE == "ru"
            else "  1) latest (release)\n  2) alpha (test build)"
        )
        default_image_choice = "2" if existing_image_channel == "alpha" else "1"
        image_choice = prompt(
            "Docker image channel",
            default=default_image_choice,
            validator=lambda value: None
            if value.strip().lower() in {"1", "2", "latest", "alpha", "release", "test"}
            else _("Enter latest or alpha."),
        ).strip().lower()
        image_channel = "alpha" if image_choice in {"2", "alpha", "test"} else "latest"

    if certificate_source is None:
        existing_source = str(
            existing_metadata.get("certificate_source")
            or existing_variables.get("easy_ha_proxy_certificate_source")
            or "letsencrypt"
        ).lower()
        if existing_source not in {"letsencrypt", "internal"}:
            existing_source = "letsencrypt"
        print(
            "  1) Let's Encrypt\n  2) Внутренний CA (self-signed root)"
            if INSTALLER_LANGUAGE == "ru"
            else "  1) Let's Encrypt\n  2) Internal CA (self-signed root)"
        )
        default_source = "1" if existing_source == "letsencrypt" else "2"
        source_choice = prompt(
            "Initial certificate source",
            default=default_source,
            validator=lambda value: None
            if value.strip().lower()
            in {"1", "2", "letsencrypt", "internal", "le", "ca"}
            else _("Enter letsencrypt or internal."),
        ).strip().lower()
        certificate_source = (
            "internal" if source_choice in {"2", "internal", "ca"} else "letsencrypt"
        )

    if certificate_source == "letsencrypt":
        print(
            "DNS-записи A/AAAA доменов админки и Authelia должны указывать на сервер;\n"
            "входящие TCP-порты 80 и 443 должны быть доступны.\n"
            if INSTALLER_LANGUAGE == "ru"
            else "DNS A/AAAA records for the admin and Authelia domains must point to this server;\n"
            "incoming TCP ports 80 and 443 must be reachable.\n"
        )
    else:
        print(
            "Для панели и Authelia будет создан сертификат внутреннего корневого CA.\n"
            "Его публичный сертификат нужно добавить в доверенные на клиентских устройствах.\n"
            if INSTALLER_LANGUAGE == "ru"
            else "The administration UI and Authelia will initially use the internal root CA.\n"
            "Install its public certificate as trusted on client devices.\n"
        )
    print(
        "Certbot устанавливается в обоих вариантах. После установки каждый сайт может независимо\n"
        "использовать Let's Encrypt, внутренний CA или импортированный внешний CA на /haproxy/certs.\n"
        if INSTALLER_LANGUAGE == "ru"
        else "Certbot is installed in both modes. After installation, each site can independently\n"
        "use Let's Encrypt, the internal CA, or an imported external CA from /haproxy/certs.\n"
    )

    existing_root_domain = str(existing_variables.get("root_domain") or "").strip()
    root_domain = prompt(
        "Root domain",
        default=(
            existing_root_domain
            or ("easy-ha-proxy.test" if test_mode else None)
        ),
        validator=validate_domain,
    ).lower()
    existing_admin_domain = str(
        existing_variables.get("admin_domain")
        or existing_metadata.get("admin_domain")
        or ""
    ).strip()
    admin_domain = prompt(
        "Administration domain",
        default=existing_admin_domain or f"ha.{root_domain}",
        validator=validate_domain,
    ).lower()
    existing_authelia_domain = str(
        existing_authelia.get("aut_domain")
        or existing_variables.get("aut_domain")
        or existing_metadata.get("authelia_domain")
        or ""
    ).strip()
    authelia_domain = prompt(
        "Authelia portal domain",
        default=existing_authelia_domain or f"aut.{root_domain}",
        validator=validate_domain,
    ).lower()
    if admin_domain == authelia_domain:
        raise InstallerError(
            "Administration and Authelia portal domains must be different."
        )
    if has_existing_configuration and (
        root_domain != existing_root_domain.lower()
        or admin_domain != existing_admin_domain.lower()
        or authelia_domain != existing_authelia_domain.lower()
    ):
        raise InstallerError(
            "Existing installation domains cannot be changed by configure. "
            "Use 'easy-ha-proxy migrate-domain --new-domain <domain>' for a "
            "reviewed domain migration."
        )
    # Optional zero-trust access gate: an Authelia-protected site with no
    # upstream. After a visitor signs in, HAProxy records their IP in
    # tbl_ip_auth, unlocking every zero-trust site and TCP proxy. Any
    # Authelia-protected site can do this, so the gate is entirely optional.
    # Only offered during a fresh install; a reconfigure never re-asks (add or
    # edit the gate later in the web UI instead).
    _existing_sites = existing_websites.get("sites")
    if not isinstance(_existing_sites, list):
        _existing_sites = []
        existing_websites["sites"] = _existing_sites
    _has_gate = any(
        isinstance(s, dict) and s.get("access_gate") for s in _existing_sites
    )
    if not has_existing_configuration and not _has_gate and prompt_bool(
        "Create a zero-trust access-gate login site now?", default=True
    ):
        gate_domain = prompt(
            "Access-gate domain",
            default=f"a.{root_domain}",
            validator=validate_domain,
        ).lower()
        if any(
            isinstance(s, dict)
            and str(s.get("domain") or s.get("name") or "").lower() == gate_domain
            for s in _existing_sites
        ):
            raise InstallerError(
                f"A site for {gate_domain} already exists; edit it in the web UI "
                "to turn it into an access gate."
            )
        _existing_sites.append(
            {
                "name": gate_domain,
                "domain": gate_domain,
                "access_gate": True,
                "authelia_enabled": True,
            }
        )

    certbot_email = prompt(
        "Let's Encrypt / administrator email",
        default=(
            str(existing_variables.get("certbot_email") or "").strip()
            or ("admin@example.test" if test_mode else None)
        ),
        validator=validate_email,
    )
    timezone = prompt(
        "Timezone",
        default=(
            str(
                existing_variables.get("haproxy_admin_timezone")
                or existing_authelia.get("authelia_timezone")
                or ""
            ).strip()
            or detect_timezone()
        ),
    )
    test_server_ip = ""
    if test_mode:
        test_server_ip = prompt(
            "Server LAN/host-only IP",
            default=(
                str(
                    existing_variables.get("easy_ha_proxy_test_ip")
                    or existing_metadata.get("test_server_ip")
                    or ""
                ).strip()
                or detect_local_ip()
            ),
            validator=validate_ip,
        )

    allowed_raw = input(_(
        "Admin allowed IP/CIDR list, comma-separated [all authenticated users]: "
    )).strip()
    if not allowed_raw and has_existing_configuration:
        existing_allowed = existing_variables.get("admin_allowed_ips")
        allowed_networks = (
            copy.deepcopy(existing_allowed)
            if isinstance(existing_allowed, list)
            else []
        )
        admin_ips_enabled = bool(
            existing_variables.get("admin_ips_enabled", bool(allowed_networks))
        )
    else:
        allowed_networks = parse_networks(allowed_raw)
        admin_ips_enabled = bool(allowed_networks)

    countries_raw = input(_(
        "GeoIP allowed country codes, comma-separated [disabled; examples: RU,PL,BY]: "
    )).strip()
    if not countries_raw and has_existing_configuration:
        existing_countries = existing_variables.get("geoip_country_codes")
        countries = (
            copy.deepcopy(existing_countries)
            if isinstance(existing_countries, list)
            else []
        )
        geoip_enabled = bool(
            existing_variables.get("enable_geoip", bool(countries))
        )
    else:
        countries = parse_countries(countries_raw)
        geoip_enabled = bool(countries)

    if existing_users is not None:
        users = existing_users
        print(_(
            "Existing initial Authelia users are preserved. "
            "Manage active users through the web UI."
        ))
    else:
        from argon2 import PasswordHasher

        admin_username = prompt(
            "First administrator login",
            default="admin",
            validator=validate_username,
        )
        admin_display_name = prompt(
            "Administrator display name", default="Administrator"
        )
        admin_email = prompt(
            "Administrator email",
            default=certbot_email,
            validator=validate_email,
        )
        admin_password = prompt_password()
        password_hash = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
        ).hash(admin_password)
        del admin_password
        users = {
            "authelia_users": {
                admin_username: {
                    "displayname": admin_display_name,
                    "password": password_hash,
                    "email": admin_email,
                    "groups": ["admins", "superadmin", "users"],
                }
            }
        }

    if has_existing_configuration:
        smtp_enabled = bool(
            existing_variables.get(
                "mail_notify_enabled",
                existing_authelia.get("mail_relay_server")
                or existing_authelia.get("authelia_notifier_type") == "smtp",
            )
        )
        smtp_host = str(existing_variables.get("mail_smtp_host") or "localhost")
        try:
            smtp_port = int(existing_variables.get("mail_smtp_port") or 25)
        except (TypeError, ValueError):
            smtp_port = 25
        smtp_user = str(existing_variables.get("mail_smtp_user") or "")
        smtp_password = str(existing_secrets.get("mail_smtp_pass") or "")
        mail_from = str(
            existing_variables.get("mail_notify_from") or certbot_email
        )
        mail_to = str(existing_variables.get("mail_notify_to") or certbot_email)
    else:
        smtp_enabled = prompt_bool(
            "Configure email notifications through the internal relay", default=False
        )
        smtp_host = "localhost"
        smtp_port = 25
        smtp_user = ""
        smtp_password = ""
        mail_from = certbot_email
        mail_to = certbot_email
        if smtp_enabled:
            smtp_host = prompt("SMTP server")
            smtp_port = int(
                prompt("SMTP port", default="587", validator=validate_port)
            )
            smtp_user = prompt("SMTP username")
            smtp_password = getpass.getpass(_("SMTP password: "))
            mail_from = prompt(
                "Mail sender", default=certbot_email, validator=validate_email
            )
            mail_to = prompt(
                "Notification recipient",
                default=certbot_email,
                validator=validate_email,
            )

    existing_site_defaults = existing_variables.get("site_defaults")
    if has_existing_configuration:
        site_defaults = (
            copy.deepcopy(existing_site_defaults)
            if isinstance(existing_site_defaults, dict)
            else {}
        )
    else:
        site_defaults = build_site_defaults(geoip_enabled=geoip_enabled)
        site_defaults["certificate_source"] = certificate_source
        site_defaults["le_managed"] = certificate_source == "letsencrypt"

    variable_defaults = {
        "haproxy_socket": "/run/haproxy/admin.sock",
        "haproxy_socket_group": "hadmin",
        "haproxy_certs_dir": "/etc/haproxy/certs",
        "root_domain": root_domain,
        "admin_ips_file": "/etc/haproxy/admin.allow",
        "admin_domain": admin_domain,
        "aut_domain": authelia_domain,
        "authelia_enabled": True,
        "admin_authelia_enabled": True,
        "admin_ips_enabled": admin_ips_enabled,
        "admin_allowed_ips": allowed_networks or ["127.0.0.1"],
        "admin_dyn_enabled": False,
        "admin_dyn_hostname": root_domain,
        "enable_http80": True,
        "zero_trust": False,
        "enable_geoip": geoip_enabled,
        "geoip_mode": "allow",
        "geoip_country_codes": countries,
        "admin_password": False,
        "certbot_email": certbot_email,
        "site_defaults": site_defaults,
        "mail_notify_enabled": smtp_enabled,
        "mail_notify_only_for": [],
        "mail_notify_to": mail_to,
        "mail_notify_from": mail_from,
        "mail_smtp_host": smtp_host,
        "mail_smtp_port": smtp_port,
        "mail_smtp_user": smtp_user,
        "mail_smtp_auth": "on" if smtp_enabled else "off",
        "mail_smtp_ssl_mode": "smtps" if smtp_port == 465 else "starttls",
        "mail_smtp_tls_trust_file": "/etc/ssl/certs/ca-certificates.crt",
        "haproxy_admin_timezone": timezone,
        "haproxy_admin_default_language": INSTALLER_LANGUAGE,
        "haproxy_admin_image": (
            f"{os.environ.get('EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY', DEFAULT_ADMIN_IMAGE_REPOSITORY)}:"
            f"{image_channel}"
        ),
        "haproxy_admin_debug_routes": False,
        "authelia_timezone": timezone,
        "easy_ha_proxy_test_mode": bool(test_mode),
        "easy_ha_proxy_test_ip": test_server_ip,
        "easy_ha_proxy_certificate_source": certificate_source,
    }

    if has_existing_configuration:
        variables = copy.deepcopy(existing_variables)
        variables.update(
            {
                "root_domain": root_domain,
                "admin_domain": admin_domain,
                "aut_domain": authelia_domain,
                "admin_ips_enabled": admin_ips_enabled,
                "admin_allowed_ips": copy.deepcopy(allowed_networks),
                "enable_geoip": geoip_enabled,
                "geoip_country_codes": copy.deepcopy(countries),
                "certbot_email": certbot_email,
                "haproxy_admin_timezone": timezone,
                "haproxy_admin_image": (
                    f"{os.environ.get('EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY', DEFAULT_ADMIN_IMAGE_REPOSITORY)}:"
                    f"{image_channel}"
                ),
                "authelia_timezone": timezone,
                "easy_ha_proxy_test_mode": bool(test_mode),
                "easy_ha_proxy_test_ip": test_server_ip,
                "easy_ha_proxy_certificate_source": certificate_source,
            }
        )
    else:
        variables = variable_defaults

    authelia_defaults = {
        "authelia_enabled": True,
        "mail_relay_server": smtp_enabled,
        "admin_authelia_enabled": True,
        "aut_domain": authelia_domain,
        "aut_geoip_enabled": False,
        "aut_geoip_mode": "allow",
        "authelia_server_address": "tcp://0.0.0.0:9091",
        "authelia_log_level": "warn",
        "authelia_session_name": "authelia_session",
        "authelia_session_same_site": "lax",
        "authelia_session_expiration": "12h",
        "authelia_session_inactivity": "30m",
        "authelia_session_remember_me": "3M",
        "authelia_cookie_domain": root_domain,
        "authelia_portal_url": f"https://{authelia_domain}",
        "authelia_default_redirection_url": (
            f"https://{authelia_domain}/access_granted"
        ),
        "authelia_storage_local_path": "/config/db.sqlite3",
        "authelia_users_file_path": "/config/users_database.yml",
        "authelia_password_algorithm": "argon2id",
        "authelia_regulation_modes": ["ip"],
        "authelia_regulation_max_retries": 5,
        "authelia_regulation_find_time": "2m",
        "authelia_regulation_ban_time": "1h",
        "authelia_notifier_type": "smtp" if smtp_enabled else "filesystem",
        "mail_subject": f"[{root_domain}] {_('Security notification')}",
        "authelia_notification_language": INSTALLER_LANGUAGE,
        "authelia_notifier_filesystem_filename": "/config/notification.log",
        "mail_smtp_ssl_authelia": "submissions" if smtp_port == 465 else "smtp",
        "mail_smtp_disable_starttls": False,
        "mail_smtp_disable_require_tls": False,
        "mail_smtp_tls_skip_verify": False,
        "mail_smtp_timeout": "10s",
        "authelia_totp_issuer": root_domain,
        "authelia_totp_period": 30,
        "authelia_totp_skew": 1,
        "authelia_default_policy": "deny",
        "authelia_log_file_path": "/config/logs/authelia.log",
        "authelia_access_control_rules": [
            {
                "domain": admin_domain,
                "subject": ["group:superadmin"],
                "policy": "one_factor",
            },
            {
                "domain": admin_domain,
                "resources": [
                    "^/authelia(/.*)?$",
                    "^/stats(/.*)?$",
                    "^/haproxy(/.*)?$",
                ],
                "policy": "deny",
            },
            {
                "domain": admin_domain,
                "subject": ["group:admins"],
                "policy": "one_factor",
            },
            {
                "domain": authelia_domain,
                "resources": ["^/access_granted/?$"],
                "policy": "one_factor",
            },
        ],
    }

    if has_existing_configuration:
        authelia = copy.deepcopy(existing_authelia)
        offered_authelia_values = {
            "aut_domain": authelia_domain,
            "authelia_timezone": timezone,
            "authelia_cookie_domain": root_domain,
            "authelia_portal_url": f"https://{authelia_domain}",
            "authelia_default_redirection_url": (
                f"https://{authelia_domain}/access_granted"
            ),
        }
        for key, value in offered_authelia_values.items():
            if key in authelia:
                authelia[key] = value
    else:
        authelia = authelia_defaults

    if has_existing_configuration:
        secret_values = copy.deepcopy(existing_secrets)
    else:
        secret_values = {
            "authelia_session_secret": secrets.token_hex(64),
            "authelia_jwt_secret": secrets.token_hex(64),
            "authelia_storage_key": secrets.token_hex(64),
            "mail_smtp_pass": smtp_password,
            "haproxy_admin_proxy_secret": secrets.token_urlsafe(48),
        }

    if has_existing_configuration:
        metadata = copy.deepcopy(existing_metadata)
        metadata.update(
            {
                "configured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "test_mode": bool(test_mode),
                "certificate_source": certificate_source,
                "source_channel": source_channel,
                "image_channel": image_channel,
                "test_server_ip": test_server_ip,
                "admin_domain": admin_domain,
                "authelia_domain": authelia_domain,
                "configuration_pending": True,
            }
        )
    else:
        metadata = {
            "product": PRODUCT,
            "configured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "repository": os.environ.get(
                "EASY_HA_PROXY_REPOSITORY", DEFAULT_REPOSITORY
            ),
            "test_mode": bool(test_mode),
            "certificate_source": certificate_source,
            "source_channel": source_channel,
            "image_channel": image_channel,
            "test_server_ip": test_server_ip,
            "admin_domain": admin_domain,
            "authelia_domain": authelia_domain,
            "installer_language": INSTALLER_LANGUAGE,
            "installation_complete": False,
            "configuration_pending": True,
        }

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    if has_existing_configuration:
        backup_configuration(directory)
    write_yaml(directory / "vars.yml", variables)
    write_yaml(directory / "authelia.yml", authelia)
    write_yaml(directory / "authelia_users_initial.yml", users)
    write_yaml(directory / "websites.yml", existing_websites)
    write_yaml(directory / "tcp.yml", existing_tcp)
    write_yaml(directory / "secrets.yml", secret_values)
    write_yaml(marker, metadata)
    write_text(
        directory / "inventory.ini",
        "[easy_ha_proxy]\n"
        "localhost ansible_connection=local "
        "ansible_python_interpreter=/usr/bin/python3\n",
        mode=0o600,
    )

    if INSTALLER_LANGUAGE == "ru":
        print(f"\nКонфигурация записана в {directory}")
    else:
        print(f"\nConfiguration written to {directory}")
    return directory


def load_metadata(directory: Path | None = None) -> dict[str, Any]:
    directory = directory or config_dir()
    try:
        loaded = yaml.safe_load(
            (directory / "metadata.yml").read_text(encoding="utf-8")
        )
    except (OSError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def mark_installation_complete(directory: Path | None = None) -> None:
    """Mark managed configuration as successfully applied."""

    directory = directory or config_dir()
    metadata_path = directory / "metadata.yml"
    metadata = load_yaml_mapping(metadata_path)
    metadata["installation_complete"] = True
    metadata["configuration_pending"] = False
    metadata["installation_completed_at"] = dt.datetime.now(
        dt.timezone.utc
    ).isoformat()
    write_yaml(metadata_path, metadata)


def is_test_mode(directory: Path | None = None) -> bool:
    return bool(load_metadata(directory).get("test_mode", False))


def configured_certificate_source(directory: Path | None = None) -> str:
    metadata = load_metadata(directory)
    source = str(metadata.get("certificate_source") or "").strip().lower()
    if source in {"letsencrypt", "internal"}:
        return source
    return "internal" if bool(metadata.get("test_mode", False)) else "letsencrypt"


def uses_internal_ca(directory: Path | None = None) -> bool:
    return configured_certificate_source(directory) == "internal"


def generate_internal_certificate(directory: Path) -> Path:
    openssl = shutil.which("openssl")
    if not openssl:
        raise InstallerError("openssl is required for the internal certificate authority.")

    metadata = load_metadata(directory)
    admin_domain = str(metadata.get("admin_domain") or "").strip()
    authelia_domain = str(metadata.get("authelia_domain") or "").strip()
    if not admin_domain or not authelia_domain:
        raise InstallerError("Admin or Authelia domains are missing from metadata.yml.")

    certificate_dir = directory / "internal-pki"
    certificate_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(certificate_dir, 0o700)
    ca_root = Path(
        os.environ.get(
            "HAPROXY_CA_ROOT_DIR", "/etc/haproxy/certificate-authorities"
        )
    )
    if ca_root.is_symlink():
        raise InstallerError("The certificate authority root must not be a symlink.")
    ca_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not ca_root.is_dir():
        raise InstallerError("The certificate authority root is not a directory.")
    os.chmod(ca_root, 0o700)
    internal_ca_dir = ca_root / "internal"
    if internal_ca_dir.is_symlink():
        raise InstallerError("The internal certificate authority path must not be a symlink.")
    internal_ca_dir.mkdir(exist_ok=True, mode=0o700)
    if not internal_ca_dir.is_dir():
        raise InstallerError("The internal certificate authority path is not a directory.")
    os.chmod(internal_ca_dir, 0o700)
    ca_key = internal_ca_dir / "ca.key"
    ca_cert = internal_ca_dir / "ca.crt"
    leaf_key = certificate_dir / "server.key"
    leaf_request = certificate_dir / "server.csr"
    leaf_cert = certificate_dir / "server.crt"
    extensions = certificate_dir / "server.ext"
    combined = certificate_dir / "easy-ha-proxy-internal.pem"

    legacy_dir = directory / "test-pki"
    legacy_ca_key = legacy_dir / "ca.key"
    legacy_ca_cert = legacy_dir / "ca.crt"
    if (
        not ca_key.exists()
        and not ca_cert.exists()
        and legacy_ca_key.is_file()
        and legacy_ca_cert.is_file()
    ):
        shutil.copyfile(legacy_ca_key, ca_key)
        shutil.copyfile(legacy_ca_cert, ca_cert)

    if not ca_key.exists() or not ca_cert.exists():
        if ca_key.exists() or ca_cert.exists():
            raise InstallerError(
                "The internal CA is incomplete; restore both ca.key and ca.crt."
            )
        run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=Easy HA Proxy Local Root CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:1",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_cert),
            ]
        )

    run(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-subj",
            f"/CN={admin_domain}",
            "-keyout",
            str(leaf_key),
            "-out",
            str(leaf_request),
        ]
    )
    write_text(
        extensions,
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{admin_domain},DNS:{authelia_domain}\n",
    )
    run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(leaf_request),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "397",
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(leaf_cert),
        ]
    )
    write_text(
        combined,
        leaf_cert.read_text(encoding="utf-8")
        + leaf_key.read_text(encoding="utf-8"),
    )
    os.chmod(ca_key, 0o600)
    os.chmod(ca_cert, 0o644)
    os.chmod(leaf_key, 0o600)
    os.chmod(combined, 0o600)

    target_dir = Path(
        os.environ.get("EASY_HA_PROXY_CERT_DIR", "/etc/haproxy/certs")
    )
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    target = target_dir / "easy-ha-proxy-internal.pem"
    shutil.copyfile(combined, target)
    os.chmod(target, 0o600)
    exported_ca = Path(
        os.environ.get(
            "EASY_HA_PROXY_CA_EXPORT", "/tmp/easy-ha-proxy-internal-ca.crt"
        )
    )
    shutil.copyfile(ca_cert, exported_ca)
    os.chmod(exported_ca, 0o644)
    if INSTALLER_LANGUAGE == "ru":
        print(f"TLS-сертификат внутреннего CA установлен: {target}")
        print(f"Сертификат внутреннего CA: {ca_cert}")
        print(f"Публичный CA для копирования на рабочую станцию: {exported_ca}")
    else:
        print(f"Internal-CA TLS certificate installed: {target}")
        print(f"Internal CA certificate: {ca_cert}")
        print(f"Public CA export for copying to a workstation: {exported_ca}")
    return ca_cert


def generate_test_certificate(directory: Path) -> Path:
    """Backward-compatible alias for callers using the old test-mode name."""

    return generate_internal_certificate(directory)


def print_internal_ca_instructions(directory: Path) -> None:
    metadata = load_metadata(directory)
    server_ip = str(metadata.get("test_server_ip") or "").strip()
    admin_domain = str(metadata.get("admin_domain") or "")
    authelia_domain = str(metadata.get("authelia_domain") or "")
    if server_ip:
        if INSTALLER_LANGUAGE == "ru":
            print(
                "\nДобавьте эту строку в файл hosts на рабочем компьютере:\n\n"
                f"{server_ip} {admin_domain} {authelia_domain}\n\n"
                "Windows: C:\\Windows\\System32\\drivers\\etc\\hosts\n"
                "Linux/macOS: /etc/hosts\n"
            )
        else:
            print(
                "\nAdd this line to the hosts file on your workstation:\n\n"
                f"{server_ip} {admin_domain} {authelia_domain}\n\n"
                "Windows: C:\\Windows\\System32\\drivers\\etc\\hosts\n"
                "Linux/macOS: /etc/hosts\n"
            )
    if INSTALLER_LANGUAGE == "ru":
        print(
            f"\nОткройте https://{admin_domain}/\n"
            "Скопируйте /tmp/easy-ha-proxy-internal-ca.crt на рабочий компьютер "
            "и импортируйте его как доверенный корневой CA. Никогда не копируйте "
            "закрытый ключ CA."
        )
    else:
        print(
            f"\nOpen https://{admin_domain}/\n"
            "Copy /tmp/easy-ha-proxy-internal-ca.crt to your workstation and import it "
            "as a trusted root CA. Never copy the CA private key."
        )


def print_test_access_instructions(directory: Path) -> None:
    """Backward-compatible alias for the old test-mode instruction function."""

    print_internal_ca_instructions(directory)


def dns_preflight(directory: Path) -> bool:
    """Report DNS readiness without blocking installation."""

    try:
        variables = yaml.safe_load(
            (directory / "vars.yml").read_text(encoding="utf-8")
        ) or {}
        authelia = yaml.safe_load(
            (directory / "authelia.yml").read_text(encoding="utf-8")
        ) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InstallerError(f"Cannot read generated configuration: {exc}") from exc

    domains = [
        str(variables.get("admin_domain") or "").strip(),
        str(authelia.get("aut_domain") or "").strip(),
    ]
    ready = True
    for domain in domains:
        if not domain:
            raise InstallerError("Admin or Authelia domain is missing.")
        try:
            records = socket.getaddrinfo(
                domain,
                443,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            ready = False
            if INSTALLER_LANGUAGE == "ru":
                print(
                    f"WARNING: DNS-имя {domain} пока не разрешается: {exc}. "
                    "Установка может продолжиться, но первоначальный сертификат "
                    "Let's Encrypt для этого имени выпущен не будет."
                )
            else:
                print(
                    f"WARNING: DNS lookup failed for {domain}: {exc}. "
                    "Installation can continue, but the initial Let's Encrypt "
                    "certificate for this name will not be issued."
                )
            continue
        addresses = sorted({record[4][0] for record in records})
        print(f"DNS {domain}: {', '.join(addresses)}")
    return ready


def ansible_playbook_path() -> str:
    managed = install_home() / "venv/bin/ansible-playbook"
    if managed.exists():
        return str(managed)
    discovered = shutil.which("ansible-playbook")
    if discovered:
        return discovered
    raise InstallerError("ansible-playbook not found; run install-local.sh first.")


def ansible_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(source_dir() / "ansible/ansible.cfg")
    environment["ANSIBLE_VARS_ENABLED"] = ""
    environment["ANSIBLE_NOCOWS"] = "1"
    environment.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/easy-ha-proxy-ansible")
    return environment


def playbook_command(
    tags: str,
    *,
    check_mode: bool = False,
    directory: Path | None = None,
    extra_vars: dict[str, str] | None = None,
    skip_tags: str | None = None,
) -> list[str]:
    directory = directory or config_dir()
    required = (
        directory / "inventory.ini",
        directory / "vars.yml",
        directory / "secrets.yml",
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise InstallerError(
            "Configuration is incomplete. Run easy-ha-proxy install first. Missing: "
            + ", ".join(missing)
        )

    playbook = source_dir() / "ansible/easy-ha-proxy.yml"
    if not playbook.exists():
        raise InstallerError(f"Playbook not found: {playbook}")

    command = [
        ansible_playbook_path(),
        "-i",
        str(directory / "inventory.ini"),
        str(playbook),
        "--extra-vars",
        f"easy_ha_proxy_config_dir={directory}",
        "--extra-vars",
        "easy_ha_proxy_target=easy_ha_proxy",
    ]
    for key, value in (extra_vars or {}).items():
        command.extend(("--extra-vars", f"{key}={value}"))
    command.extend(("--tags", tags))
    if skip_tags:
        command.extend(("--skip-tags", skip_tags))
    if check_mode:
        command.append("--check")
    return command


def ensure_security_secrets(directory: Path) -> None:
    """Idempotently migrate older managed configurations to new secrets."""
    path = directory / "secrets.yml"
    if not path.is_file():
        return
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InstallerError(f"Cannot migrate security secrets in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InstallerError(f"Expected a YAML mapping in {path}.")
    if data.get("haproxy_admin_proxy_secret"):
        return
    data["haproxy_admin_proxy_secret"] = secrets.token_urlsafe(48)
    write_yaml(path, data)
    print(f"Generated the missing internal proxy secret in {path}.")


def syntax_check(directory: Path | None = None) -> None:
    command = playbook_command("always", directory=directory)
    command.append("--syntax-check")
    run(command, env=ansible_environment())


def offline_restore_required_images(
    *,
    directory: Path | None = None,
    controller_source: Path | None = None,
) -> set[str]:
    """Resolve images that the current recovery source will render.

    A backup may contain an older Compose file, while reconciliation renders a
    new file from the trusted recovery source.  Derive the preflight set from
    that source's defaults plus restored managed variables, not from the stale
    Compose snapshot.  The template shape check fails closed if a future role
    adds another image without extending this resolver.
    """

    directory = directory or config_dir()
    controller_source = controller_source or source_dir()
    variables = load_yaml_mapping(directory / "vars.yml")
    authelia = load_yaml_mapping(directory / "authelia.yml")
    admin_defaults = load_yaml_mapping(
        controller_source / "ansible/roles/haproxy-admin/defaults/main.yml"
    )
    authelia_defaults = load_yaml_mapping(
        controller_source / "ansible/roles/authelia/defaults/main.yml"
    )
    effective: dict[str, Any] = {}
    effective.update(admin_defaults)
    effective.update(authelia_defaults)
    effective.update(variables)
    effective.update(authelia)

    templates = {
        controller_source
        / "ansible/roles/haproxy-admin/templates/docker-compose.yml.j2": (
            "haproxy_admin_image",
        ),
        controller_source
        / "ansible/roles/authelia/templates/docker-compose.yml.j2": (
            "authelia_redis_image",
            "mail_relay_image",
            "authelia_version",
        ),
    }
    for template, supported_variables in templates.items():
        try:
            image_lines = [
                line.strip()
                for line in template.read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("image:")
            ]
        except OSError as exc:
            raise InstallerError(
                f"Offline restore preflight cannot read image template {template}: {exc}"
            ) from exc
        if len(image_lines) != len(supported_variables) or any(
            sum(variable in line for line in image_lines) != 1
            for variable in supported_variables
        ):
            raise InstallerError(
                "Offline restore preflight does not recognize every image in "
                f"the current recovery template: {template}."
            )

    images: set[str] = set()
    if bool(effective.get("haproxy_admin_use_docker", True)):
        images.add(str(effective.get("haproxy_admin_image", "")).strip())
    if bool(effective.get("authelia_enabled", False)):
        images.add(
            "authelia/authelia:"
            + str(effective.get("authelia_version", "")).strip()
        )
        if bool(effective.get("authelia_session_redis_enabled", True)):
            images.add(str(effective.get("authelia_redis_image", "")).strip())
        # The relay service is always rendered (possibly behind a profile),
        # and the spool migration may recreate an existing legacy relay even
        # when notifications are currently disabled.
        images.add(str(effective.get("mail_relay_image", "")).strip())

    invalid = sorted(
        image
        for image in images
        if not image or len(image) > 512 or any(character.isspace() for character in image)
    )
    if invalid:
        raise InstallerError(
            "Offline restore preflight found invalid managed image references: "
            + ", ".join(repr(image) for image in invalid)
        )
    return images


def offline_restore_image_preflight(
    *,
    directory: Path | None = None,
    controller_source: Path | None = None,
    required_images: set[str] | None = None,
) -> None:
    """Require every image rendered by an offline reconciliation locally."""

    docker = shutil.which("docker")
    if not docker:
        raise InstallerError(
            "Offline restore preflight failed: Docker is not installed. "
            "Prepare the target with the normal installer before restoring."
        )

    images = (
        required_images
        if required_images is not None
        else offline_restore_required_images(
            directory=directory,
            controller_source=controller_source,
        )
    )

    missing: list[str] = []
    for image in sorted(images):
        try:
            result = subprocess.run(
                [docker, "image", "inspect", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as exc:
            raise InstallerError(
                f"Offline restore preflight failed while inspecting {image}: {exc}"
            ) from exc
        if result.returncode != 0:
            missing.append(image)

    if missing:
        raise InstallerError(
            "Offline restore preflight failed: required Docker images are not "
            "available locally: "
            + ", ".join(missing)
            + ". Run a normal managed install/update to cache them before "
            "restoring; the restore broker will not contact registries."
        )


def run_playbook(
    tags: str,
    *,
    check_mode: bool = False,
    directory: Path | None = None,
    extra_vars: dict[str, str] | None = None,
    skip_tags: str | None = None,
) -> None:
    effective_extra_vars = dict(extra_vars or {})
    if not check_mode and "status" in tags.split(","):
        # Install/update must not report success while a managed service is
        # restarting or unhealthy. Plans remain non-blocking diagnostics.
        effective_extra_vars.setdefault("status_check_fail_on_error", "true")
    run(
        playbook_command(
            tags,
            check_mode=check_mode,
            directory=directory,
            extra_vars=effective_extra_vars,
            skip_tags=skip_tags,
        ),
        env=ansible_environment(),
    )
    selected_tags = {tag.strip() for tag in tags.split(",") if tag.strip()}
    if not check_mode and "upgrade" in selected_tags:
        offer_pending_reboot()


def sync_runtime_dependencies() -> None:
    home = install_home()
    pip = home / "venv/bin/pip"
    galaxy = home / "venv/bin/ansible-galaxy"
    requirements = source_dir() / "installer/requirements.txt"
    collections = source_dir() / "ansible/requirements.yml"
    if pip.exists() and requirements.exists():
        run([str(pip), "install", "--disable-pip-version-check", "-r", str(requirements)])
    if galaxy.exists() and collections.exists():
        run([str(galaxy), "collection", "install", "-r", str(collections)])


def ensure_source_executables(directory: Path | None = None) -> None:
    root = directory or source_dir()
    for relative in (
        "install.sh",
        "install-local.sh",
        "install-remote.sh",
        "easy-ha-proxy-helper.sh",
        "installer/easy-ha-proxy",
    ):
        path = root / relative
        if path.is_file():
            os.chmod(path, 0o755)


def normalize_source_revision(value: str | None) -> str | None:
    """Return a validated lowercase Git object id used to pin web updates."""

    if value is None:
        return None
    revision = value.strip().lower()
    if not SOURCE_REVISION_RE.fullmatch(revision):
        raise InstallerError("Expected source revision must be a full Git object ID.")
    return revision


def git_revision(directory: Path, ref: str) -> str:
    """Resolve one exact Git revision without accepting abbreviated output."""

    completed = subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "--verify", ref],
        check=False,
        capture_output=True,
        text=True,
    )
    revision = completed.stdout.strip().lower()
    if completed.returncode != 0 or not SOURCE_REVISION_RE.fullmatch(revision):
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        suffix = f": {detail[0]}" if detail else ""
        raise InstallerError(f"Could not resolve fetched source revision{suffix}")
    return revision


def update_managed_source(expected_revision: str | None = None) -> bool:
    """Refresh the installer-managed source and report whether it was replaced.

    Callers must re-exec the CLI after a successful refresh.  Continuing in
    the current Python process would combine old migration logic with the new
    playbook that has just appeared on disk.
    """

    expected_revision = normalize_source_revision(expected_revision)
    managed_source = (install_home() / "source").resolve()
    current_source = source_dir().resolve()
    if current_source != managed_source:
        print("Source update skipped: this is not the installer-managed source path.")
        return False
    branch = str(
        os.environ.get("EASY_HA_PROXY_BRANCH")
        or load_metadata().get("branch")
        or "main"
    ).strip()
    if not _valid_git_branch(branch):
        raise InstallerError(f"Invalid git branch recorded in metadata: {branch!r}")
    if (current_source / ".git").is_dir():
        run(["git", "-C", str(current_source), "fetch", "--depth=1", "origin", branch])
        fetched_revision = git_revision(current_source, "FETCH_HEAD")
        if expected_revision and fetched_revision != expected_revision:
            raise InstallerError(
                "The fetched source revision changed after the update check; "
                "run the check again before applying."
            )
        run(["git", "-C", str(current_source), "reset", "--hard", fetched_revision])
        ensure_source_executables(current_source)
        return True

    metadata = load_metadata()
    repository = str(
        os.environ.get("EASY_HA_PROXY_REPOSITORY")
        or metadata.get("repository")
        or DEFAULT_REPOSITORY
    )
    home = install_home()
    home.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=".source-update.", dir=home))
    checkout = staging_root / "source"
    backup = home / (
        "source.before-update."
        + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    try:
        print(
            "The installed source is a staged bundle; "
            f"cloning {repository} ({branch}) atomically."
        )
        run(
            [
                "git",
                "clone",
                "--depth=1",
                "--branch",
                branch,
                repository,
                str(checkout),
            ]
        )
        for required in (
            "installer/easy_ha_proxy.py",
            "installer/requirements.txt",
            "ansible/easy-ha-proxy.yml",
            "ansible/requirements.yml",
        ):
            if not (checkout / required).is_file():
                raise InstallerError(
                    f"Downloaded source is incomplete: {required}"
                )
        fetched_revision = git_revision(checkout, "HEAD")
        if expected_revision and fetched_revision != expected_revision:
            raise InstallerError(
                "The downloaded source revision changed after the update check; "
                "run the check again before applying."
            )
        current_source.rename(backup)
        try:
            checkout.rename(current_source)
        except Exception:
            backup.rename(current_source)
            raise
        ensure_source_executables(current_source)
        print(f"Previous source backup: {backup}")
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    return True


def reexec_after_source_update() -> None:
    """Start the refreshed installer once, preserving the original arguments."""

    entrypoint = source_dir() / "installer/easy-ha-proxy"
    if not entrypoint.is_file():
        raise InstallerError(
            f"Refreshed installer entrypoint is missing: {entrypoint}"
        )
    environment = os.environ.copy()
    environment[UPDATE_SOURCE_REFRESHED_ENV] = "1"
    print("Restarting the updater with the refreshed installer source.", flush=True)
    os.execve(
        str(entrypoint),
        [str(entrypoint), *sys.argv[1:]],
        environment,
    )
    raise InstallerError("Could not restart the refreshed installer.")


def persist_deployment_channels(
    *,
    source_channel: str | None = None,
    image_channel: str | None = None,
    branch: str | None = None,
    release_channel: str | None = None,
    directory: Path | None = None,
) -> None:
    """Persist explicit source/branch/image choices without rewriting config.

    ``release_channel`` is the unified choice; when given it derives the other
    three (a github branch bound to its Docker image tag, or the local mode).
    Explicit source/branch/image arguments still work and take precedence for
    the fields they set.
    """
    if release_channel is not None:
        release_channel = release_channel.strip().lower()
        mapping = RELEASE_CHANNELS.get(release_channel)
        if mapping is None:
            raise InstallerError(
                "Release channel must be stable, alpha or local."
            )
        # Named channels set the fields the caller did not override explicitly.
        source_channel = source_channel or mapping.get("source_channel")
        if release_channel != "local":
            branch = branch or mapping.get("branch")
            image_channel = image_channel or mapping.get("image_channel")

    directory = directory or config_dir()
    variables_path = directory / "vars.yml"
    metadata_path = directory / "metadata.yml"
    variables = load_yaml_mapping(variables_path)
    metadata = load_yaml_mapping(metadata_path)
    changed = False

    if branch is not None:
        branch = branch.strip()
        if not _valid_git_branch(branch):
            raise InstallerError("Invalid git branch name.")
        if metadata.get("branch") != branch:
            metadata["branch"] = branch
            changed = True

    if source_channel is not None:
        source_channel = source_channel.strip().lower()
        if source_channel not in {"github", "local"}:
            raise InstallerError("Source channel must be github or local.")
        if metadata.get("source_channel") != source_channel:
            metadata["source_channel"] = source_channel
            changed = True

    if image_channel is not None:
        image_channel = image_channel.strip().lower()
        if image_channel not in {"latest", "alpha"}:
            raise InstallerError("Docker image channel must be latest or alpha.")
        repository = os.environ.get(
            "EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY", DEFAULT_ADMIN_IMAGE_REPOSITORY
        )
        image = f"{repository}:{image_channel}"
        if variables.get("haproxy_admin_image") != image:
            variables["haproxy_admin_image"] = image
            changed = True
        if metadata.get("image_channel") != image_channel:
            metadata["image_channel"] = image_channel
            changed = True

    if not changed:
        return
    backup_configuration(directory)
    write_yaml(variables_path, variables)
    write_yaml(metadata_path, metadata)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InstallerError(f"Cannot read YAML file {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise InstallerError(f"Expected a YAML mapping in {path}.")
    return loaded


def managed_configuration_is_pending(directory: Path | None = None) -> bool:
    """Return whether installer-owned configuration still needs a full apply."""

    return bool(load_metadata(directory).get("configuration_pending", False))


def _load_bounded_runtime_yaml(path: Path) -> dict[str, Any]:
    """Read one app-owned YAML file without following a replacement symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallerError(f"Cannot safely open runtime YAML {path}: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat_module.S_ISREG(file_stat.st_mode):
            raise InstallerError(f"Runtime YAML is not a regular file: {path}")
        if not 0 < file_stat.st_size <= RUNTIME_CONFIG_MAX_BYTES:
            raise InstallerError(
                f"Runtime YAML must be between 1 byte and 2 MiB: {path}"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            text = stream.read(RUNTIME_CONFIG_MAX_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise InstallerError(f"Cannot read runtime YAML {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(text.encode("utf-8")) > RUNTIME_CONFIG_MAX_BYTES:
        raise InstallerError(f"Runtime YAML exceeds 2 MiB: {path}")
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InstallerError(f"Invalid runtime YAML {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise InstallerError(f"Expected a YAML mapping in runtime file {path}.")
    return loaded


def _reject_unsafe_runtime_scalars(value: Any, *, path: str) -> None:
    if isinstance(value, str):
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise InstallerError(f"Unsafe control character in runtime configuration: {path}")
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise InstallerError(f"Runtime mapping keys must be strings: {path}")
            _reject_unsafe_runtime_scalars(key, path=f"{path}.<key>")
            _reject_unsafe_runtime_scalars(nested, path=f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_unsafe_runtime_scalars(nested, path=f"{path}[{index}]")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise InstallerError(f"Unsupported YAML value in runtime configuration: {path}")


def _validate_runtime_document_roots(
    document: dict[str, Any],
    *,
    filename: str,
    allowed: frozenset[str],
) -> None:
    """Keep auxiliary vars files from acquiring arbitrary Ansible authority."""

    unexpected = sorted(set(document) - allowed)
    if unexpected:
        raise InstallerError(
            f"Unsupported top-level key(s) in {filename}: "
            + ", ".join(unexpected)
            + ". Preserve the file and upgrade with a version that explicitly "
            "supports this schema before applying changes."
        )


def _load_runtime_haproxy_documents(
    runtime_directory: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Load and validate the complete app-owned HAProxy source, if present."""

    runtime_paths = {
        name: runtime_directory / name
        for name in ("vars.yml", "websites.yml", "tcp.yml")
    }
    available = [path.exists() for path in runtime_paths.values()]
    if not any(available):
        return None
    if not all(available):
        raise InstallerError(
            "The HAProxy Admin runtime configuration is incomplete; expected "
            "vars.yml, websites.yml, and tcp.yml together."
        )

    runtime_vars = _load_bounded_runtime_yaml(runtime_paths["vars.yml"])
    runtime_websites = _load_bounded_runtime_yaml(runtime_paths["websites.yml"])
    runtime_tcp = _load_bounded_runtime_yaml(runtime_paths["tcp.yml"])
    for name, data in (
        ("vars.yml", runtime_vars),
        ("websites.yml", runtime_websites),
        ("tcp.yml", runtime_tcp),
    ):
        _reject_unsafe_runtime_scalars(data, path=name)
    _validate_runtime_document_roots(
        runtime_websites,
        filename="runtime websites.yml",
        allowed=frozenset({"sites"}),
    )
    _validate_runtime_document_roots(
        runtime_tcp,
        filename="runtime tcp.yml",
        allowed=frozenset({"tcp_proxies", "tcp"}),
    )
    if "tcp_proxies" in runtime_tcp and "tcp" in runtime_tcp:
        raise InstallerError(
            "Runtime tcp.yml cannot contain both tcp_proxies and the legacy tcp key."
        )

    sites = runtime_websites.get("sites", [])
    tcp_proxies = runtime_tcp.get("tcp_proxies", runtime_tcp.get("tcp", []))
    if (
        not isinstance(sites, list)
        or len(sites) > 500
        or not all(isinstance(site, dict) for site in sites)
    ):
        raise InstallerError("Runtime websites.yml must contain at most 500 sites.")
    if (
        not isinstance(tcp_proxies, list)
        or len(tcp_proxies) > 500
        or not all(isinstance(proxy, dict) for proxy in tcp_proxies)
    ):
        raise InstallerError("Runtime tcp.yml must contain at most 500 TCP proxies.")
    if "site_defaults" in runtime_vars and not isinstance(
        runtime_vars["site_defaults"], dict
    ):
        raise InstallerError("Runtime vars.yml site_defaults must be a mapping.")
    runtime_geoip_countries: set[str] = set()
    if "geoip_country_codes" in runtime_vars:
        countries = runtime_vars["geoip_country_codes"]
        if not isinstance(countries, list) or any(
            not isinstance(country, str)
            or not re.fullmatch(r"[A-Za-z]{2}", country)
            for country in countries
        ):
            raise InstallerError(
                "Runtime vars.yml geoip_country_codes must contain ISO alpha-2 codes."
            )
        runtime_geoip_countries = {country.upper() for country in countries}
    for index, site in enumerate(sites):
        site_countries = site.get("geo_countries")
        if site_countries in (None, []):
            continue
        if (
            not isinstance(site_countries, list)
            or len(site_countries) > 249
            or any(
                not isinstance(country, str)
                or not re.fullmatch(r"[A-Z]{2}", country.strip())
                for country in site_countries
            )
        ):
            raise InstallerError(
                f"Runtime websites.yml sites[{index}].geo_countries must contain "
                "at most 249 uppercase ISO alpha-2 codes."
            )
        unavailable = sorted(set(site_countries) - runtime_geoip_countries)
        if unavailable:
            raise InstallerError(
                f"Runtime websites.yml sites[{index}] uses GeoIP countries not "
                "selected globally: " + ", ".join(unavailable)
            )
    return runtime_vars, runtime_websites, runtime_tcp


def sync_runtime_haproxy_config_to_managed(
    directory: Path | None = None,
    *,
    runtime_directory: Path | None = None,
) -> bool:
    """Persist the UI-owned HAProxy subset for all roles in a normal update.

    A pending installer reconfiguration reverses authority: managed files must
    be applied to runtime by a full update, so runtime is deliberately ignored.
    """

    directory = directory or config_dir()
    runtime_directory = runtime_directory or RUNTIME_HAPROXY_CONFIG_DIR
    if managed_configuration_is_pending(directory):
        return False

    runtime_documents = _load_runtime_haproxy_documents(runtime_directory)
    if runtime_documents is None:
        return False
    runtime_vars, runtime_websites, runtime_tcp = runtime_documents
    sites = runtime_websites.get("sites", [])
    tcp_proxies = runtime_tcp.get("tcp_proxies", runtime_tcp.get("tcp", []))

    managed_vars_path = directory / "vars.yml"
    managed_websites_path = directory / "websites.yml"
    managed_tcp_path = directory / "tcp.yml"
    managed_vars = load_yaml_mapping(managed_vars_path)
    managed_websites = load_yaml_mapping(managed_websites_path)
    managed_tcp = load_yaml_mapping(managed_tcp_path)
    _validate_runtime_document_roots(
        managed_websites,
        filename="managed websites.yml",
        allowed=frozenset({"sites"}),
    )
    _validate_runtime_document_roots(
        managed_tcp,
        filename="managed tcp.yml",
        allowed=frozenset({"tcp_proxies", "tcp"}),
    )
    if "tcp_proxies" in managed_tcp and "tcp" in managed_tcp:
        raise InstallerError(
            "Managed tcp.yml cannot contain both tcp_proxies and the legacy tcp key."
        )
    effective_vars = copy.deepcopy(managed_vars)
    for key in RUNTIME_HAPROXY_VAR_KEYS:
        if key in runtime_vars:
            effective_vars[key] = copy.deepcopy(runtime_vars[key])
        else:
            # Absence is meaningful in the advanced runtime editor: it must
            # fall back to the role/template default instead of reviving a
            # stale managed value during the next update.
            effective_vars.pop(key, None)
    effective_websites = {"sites": copy.deepcopy(sites)}
    effective_tcp = {"tcp_proxies": copy.deepcopy(tcp_proxies)}

    if (
        effective_vars == managed_vars
        and effective_websites == managed_websites
        and effective_tcp == managed_tcp
    ):
        return False
    backup_configuration(directory)
    write_yaml(managed_vars_path, effective_vars)
    write_yaml(managed_websites_path, effective_websites)
    write_yaml(managed_tcp_path, effective_tcp)
    print(
        "Synchronized UI-owned HAProxy sites, TCP proxies, and render settings "
        "into the managed update source."
    )
    return True


def replace_domain_text(
    value: str,
    old_domain: str,
    new_domain: str,
) -> str:
    pattern = re.compile(
        rf"(?<![A-Za-z0-9-]){re.escape(old_domain)}(?![A-Za-z0-9-])"
    )
    return pattern.sub(new_domain, value)


def replace_domain_in_data(
    value: Any,
    old_domain: str,
    new_domain: str,
    *,
    path: str,
    changes: list[tuple[str, str, str]],
) -> Any:
    if isinstance(value, dict):
        return {
            key: replace_domain_in_data(
                item,
                old_domain,
                new_domain,
                path=f"{path}.{key}" if path else str(key),
                changes=changes,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            replace_domain_in_data(
                item,
                old_domain,
                new_domain,
                path=f"{path}[{index}]",
                changes=changes,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and old_domain in value:
        replaced = replace_domain_text(value, old_domain, new_domain)
        if replaced != value:
            changes.append((path, value, replaced))
        return replaced
    return copy.deepcopy(value)


def domain_migration_dns_names(
    variables: dict[str, Any],
    authelia: dict[str, Any],
    websites: dict[str, Any],
    new_domain: str,
) -> list[str]:
    names: set[str] = set()
    for candidate in (
        variables.get("admin_domain"),
        authelia.get("aut_domain"),
    ):
        value = str(candidate or "").strip().lower()
        if value == new_domain or value.endswith(f".{new_domain}"):
            names.add(value)

    sites = websites.get("sites")
    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue
            candidates = [site.get("domain")]
            alt_names = site.get("alt_names")
            if isinstance(alt_names, list):
                candidates.extend(alt_names)
            for candidate in candidates:
                value = str(candidate or "").strip().lower()
                if value == new_domain or value.endswith(f".{new_domain}"):
                    names.add(value)
    return sorted(names)


def verify_public_dns(domains: list[str]) -> bool:
    if not domains:
        print("WARNING: No managed domains were found for public DNS validation.")
        return False

    dig = shutil.which("dig")
    failures: list[str] = []
    for domain in domains:
        addresses: set[str] = set()
        if dig:
            for resolver in ("1.1.1.1", "8.8.8.8"):
                resolver_addresses: set[str] = set()
                for record_type in ("A", "AAAA"):
                    result = subprocess.run(
                        [
                            dig,
                            "+time=3",
                            "+tries=1",
                            "+short",
                            record_type,
                            domain,
                            f"@{resolver}",
                        ],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    for line in result.stdout.splitlines():
                        candidate = line.strip()
                        try:
                            ipaddress.ip_address(candidate)
                        except ValueError:
                            continue
                        resolver_addresses.add(candidate)
                if not resolver_addresses:
                    failures.append(f"{domain} via {resolver}")
                addresses.update(resolver_addresses)
        else:
            try:
                records = socket.getaddrinfo(
                    domain,
                    443,
                    type=socket.SOCK_STREAM,
                )
                addresses.update(record[4][0] for record in records)
            except socket.gaierror:
                failures.append(domain)

        if addresses:
            print(f"DNS {domain}: {', '.join(sorted(addresses))}")

    if failures:
        print(
            "WARNING: Public DNS is not ready for: "
            + ", ".join(failures)
            + ". The change can continue, but Let's Encrypt issuance for "
            "unresolved names will be skipped."
        )
        return False
    return True


def backup_runtime_ui_config(destination: Path) -> None:
    runtime_dir = Path("/opt/haproxy-admin/config")
    if not runtime_dir.is_dir():
        return
    target = destination / "runtime-haproxy-admin"
    target.mkdir(parents=True, mode=0o700)
    os.chmod(target, 0o700)
    for name in ("vars.yml", "websites.yml", "tcp.yml", "haproxy.cfg.j2"):
        source = runtime_dir / name
        if source.is_file():
            shutil.copy2(source, target / name)
            os.chmod(target / name, 0o600)


def restore_domain_migration_backup(
    directory: Path,
    backup: Path,
) -> None:
    runtime_backup = backup / "runtime-haproxy-admin"
    for name in (
        "vars.yml",
        "websites.yml",
        "tcp.yml",
        "authelia.yml",
        "metadata.yml",
    ):
        source = (
            runtime_backup / name
            if name in {"vars.yml", "websites.yml", "tcp.yml"}
            and (runtime_backup / name).is_file()
            else backup / name
        )
        if not source.is_file():
            raise InstallerError(f"Rollback file is missing: {source}")
        shutil.copy2(source, directory / name)
        os.chmod(directory / name, 0o600)


def set_migration_value(
    mapping: dict[str, Any],
    key: str,
    value: Any,
    *,
    path: str,
    changes: list[tuple[str, str, str]],
) -> None:
    """Set one migration value and include it in the human-readable preview."""

    previous = mapping.get(key)
    if previous == value:
        return
    changes.append((f"{path}.{key}", str(previous), str(value)))
    mapping[key] = value


def command_migrate_domain(args: argparse.Namespace) -> None:
    require_root()
    directory = config_dir()
    promote_production = bool(getattr(args, "promote_production", False))
    if promote_production and not is_test_mode(directory):
        raise InstallerError(
            "Production promotion is available only for a test-mode installation."
        )
    required_names = (
        "vars.yml",
        "authelia.yml",
        "websites.yml",
        "tcp.yml",
        "metadata.yml",
        "inventory.ini",
        "secrets.yml",
        "authelia_users_initial.yml",
    )
    missing = [name for name in required_names if not (directory / name).is_file()]
    if missing:
        raise InstallerError(
            "Managed configuration is incomplete: " + ", ".join(missing)
        )

    runtime_dir = Path("/opt/haproxy-admin/config")
    source_paths = {
        "vars.yml": (
            runtime_dir / "vars.yml"
            if (runtime_dir / "vars.yml").is_file()
            else directory / "vars.yml"
        ),
        "websites.yml": (
            runtime_dir / "websites.yml"
            if (runtime_dir / "websites.yml").is_file()
            else directory / "websites.yml"
        ),
        "tcp.yml": (
            runtime_dir / "tcp.yml"
            if (runtime_dir / "tcp.yml").is_file()
            else directory / "tcp.yml"
        ),
        "authelia.yml": directory / "authelia.yml",
        "metadata.yml": directory / "metadata.yml",
    }
    current = {
        name: load_yaml_mapping(path) for name, path in source_paths.items()
    }
    old_domain = str(current["vars.yml"].get("root_domain") or "").lower().strip()
    if validate_domain(old_domain):
        raise InstallerError(
            f"Current root_domain is missing or invalid: {old_domain!r}"
        )

    new_domain = str(args.new_domain or "").lower().strip()
    if not new_domain:
        new_domain = prompt(
            "Production root domain" if promote_production else "New root domain",
            validator=validate_domain,
        ).lower()
    validation_error = validate_domain(new_domain)
    if validation_error:
        raise InstallerError(validation_error)
    if old_domain == new_domain and not promote_production:
        raise InstallerError("The new root domain is identical to the current one.")

    changes: list[tuple[str, str, str]] = []
    if old_domain == new_domain:
        migrated = copy.deepcopy(current)
    else:
        migrated = {
            name: replace_domain_in_data(
                data,
                old_domain,
                new_domain,
                path=name,
                changes=changes,
            )
            for name, data in current.items()
        }
    migrated_text = {} if promote_production else {
        name: replace_domain_text(
            source_paths[name].read_text(encoding="utf-8"),
            old_domain,
            new_domain,
        )
        for name in ("vars.yml", "websites.yml", "tcp.yml", "authelia.yml")
    }
    for name, text in migrated_text.items():
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise InstallerError(
                f"Domain replacement produced invalid YAML in {name}: {exc}"
            ) from exc
        if parsed != migrated[name]:
            raise InstallerError(
                f"Text-preserving and structural domain replacements differ in {name}."
            )
    migrated["vars.yml"]["root_domain"] = new_domain
    if old_domain != new_domain:
        migrated["metadata.yml"]["previous_root_domain"] = old_domain
    migrated["metadata.yml"]["domain_migrated_at"] = dt.datetime.now(
        dt.timezone.utc
    ).isoformat()

    target_internal_ca = uses_internal_ca(directory)
    if promote_production:
        certificate_source = str(
            getattr(args, "certificate_source", None) or ""
        ).strip().lower()
        if not certificate_source:
            print(
                "  1) Let's Encrypt\n  2) Внутренний CA (self-signed root)"
                if INSTALLER_LANGUAGE == "ru"
                else "  1) Let's Encrypt\n  2) Internal CA (self-signed root)"
            )
            source_choice = prompt(
                "Initial certificate source",
                default="2",
                validator=lambda value: None
                if value.strip().lower()
                in {"1", "2", "letsencrypt", "internal", "le", "ca"}
                else _("Enter letsencrypt or internal."),
            ).strip().lower()
            certificate_source = (
                "internal"
                if source_choice in {"2", "internal", "ca"}
                else "letsencrypt"
            )
        error = validate_certificate_source(certificate_source)
        if error:
            raise InstallerError(error)

        image_channel = str(
            getattr(args, "image_channel", None) or ""
        ).strip().lower()
        if not image_channel:
            print(
                "  1) latest (релиз)\n  2) alpha (тестовая сборка)"
                if INSTALLER_LANGUAGE == "ru"
                else "  1) latest (release)\n  2) alpha (test build)"
            )
            image_choice = prompt(
                "Docker image channel",
                default="1",
                validator=lambda value: None
                if value.strip().lower()
                in {"1", "2", "latest", "alpha", "release", "test"}
                else _("Enter latest or alpha."),
            ).strip().lower()
            image_channel = (
                "alpha" if image_choice in {"2", "alpha", "test"} else "latest"
            )
        if image_channel not in {"latest", "alpha"}:
            raise InstallerError("Docker image channel must be latest or alpha.")

        variables = migrated["vars.yml"]
        metadata = migrated["metadata.yml"]
        set_migration_value(
            variables,
            "easy_ha_proxy_test_mode",
            False,
            path="vars.yml",
            changes=changes,
        )
        set_migration_value(
            variables,
            "easy_ha_proxy_test_ip",
            "",
            path="vars.yml",
            changes=changes,
        )
        set_migration_value(
            variables,
            "easy_ha_proxy_certificate_source",
            certificate_source,
            path="vars.yml",
            changes=changes,
        )
        site_defaults = variables.get("site_defaults")
        if not isinstance(site_defaults, dict):
            site_defaults = {}
            variables["site_defaults"] = site_defaults
        set_migration_value(
            site_defaults,
            "certificate_source",
            certificate_source,
            path="vars.yml.site_defaults",
            changes=changes,
        )
        set_migration_value(
            site_defaults,
            "le_managed",
            certificate_source == "letsencrypt",
            path="vars.yml.site_defaults",
            changes=changes,
        )
        image_repository = os.environ.get(
            "EASY_HA_PROXY_ADMIN_IMAGE_REPOSITORY",
            DEFAULT_ADMIN_IMAGE_REPOSITORY,
        )
        set_migration_value(
            variables,
            "haproxy_admin_image",
            f"{image_repository}:{image_channel}",
            path="vars.yml",
            changes=changes,
        )
        for key, value in (
            ("test_mode", False),
            ("test_server_ip", ""),
            ("certificate_source", certificate_source),
            ("image_channel", image_channel),
            ("configuration_pending", True),
        ):
            set_migration_value(
                metadata,
                key,
                value,
                path="metadata.yml",
                changes=changes,
            )
        metadata["promoted_to_production_at"] = dt.datetime.now(
            dt.timezone.utc
        ).isoformat()
        target_internal_ca = certificate_source == "internal"
    if not changes:
        raise InstallerError(
            f"No references to {old_domain} were found in managed configuration."
        )

    title = "Test-to-production promotion" if promote_production else "Domain migration"
    print(f"\n{title} preview: {old_domain} -> {new_domain}")
    print("Runtime UI vars/sites/TCP are used as the current source of truth.")
    for path, before, after in changes:
        print(f"  {path}: {before} -> {after}")
    print(f"\nChanged values: {len(changes)}")

    with tempfile.TemporaryDirectory(
        prefix="easy-ha-proxy-domain-preview.",
        dir="/tmp",
    ) as temporary:
        preview_dir = Path(temporary)
        os.chmod(preview_dir, 0o700)
        for source in directory.iterdir():
            if source.is_file():
                shutil.copy2(source, preview_dir / source.name)
                os.chmod(preview_dir / source.name, 0o600)
        for name, data in migrated.items():
            if name in migrated_text:
                write_text(preview_dir / name, migrated_text[name])
            else:
                write_yaml(preview_dir / name, data)

        if not args.skip_dns_check and not target_internal_ca:
            verify_public_dns(
                domain_migration_dns_names(
                    migrated["vars.yml"],
                    migrated["authelia.yml"],
                    migrated["websites.yml"],
                    new_domain,
                )
            )

        migration_extra_vars = {
            "haproxy_admin_sync_managed_config": "true",
        }
        if promote_production:
            migration_tags = (
                INTERNAL_CA_INSTALL_TAGS if target_internal_ca else INSTALL_TAGS
            )
        else:
            migration_tags = (
                INTERNAL_CA_DOMAIN_MIGRATION_TAGS
                if target_internal_ca
                else DOMAIN_MIGRATION_TAGS
            )
        print("\nRunning syntax-check and domain migration plan...")
        syntax_check(preview_dir)
        run_playbook(
            migration_tags,
            check_mode=True,
            directory=preview_dir,
            extra_vars=migration_extra_vars,
        )

        if args.plan_only:
            print("\nPlan completed. No configuration was changed.")
            return

        confirmation_word = "PROMOTE" if promote_production else "MIGRATE"
        confirmation = input(
            f"\nType {confirmation_word} to switch {old_domain} to {new_domain}: "
        ).strip()
        if confirmation != confirmation_word:
            raise InstallerError("Domain migration cancelled; no files were changed.")

        backup = backup_configuration(directory)
        if backup is None:
            raise InstallerError("Could not create the configuration backup.")
        backup_runtime_ui_config(backup)
        for name, data in migrated.items():
            if name in migrated_text:
                write_text(directory / name, migrated_text[name])
            else:
                write_yaml(directory / name, data)

        if target_internal_ca:
            generate_internal_certificate(directory)
        try:
            run_playbook(
                migration_tags,
                directory=directory,
                extra_vars=migration_extra_vars,
            )
        except Exception:
            print(
                "\nDomain migration apply failed. "
                "Restoring the previous managed configuration...",
                file=sys.stderr,
            )
            restore_domain_migration_backup(directory, backup)
            try:
                rollback_internal_ca = uses_internal_ca(directory)
                if rollback_internal_ca:
                    generate_internal_certificate(directory)
                run_playbook(
                    (
                        INTERNAL_CA_INSTALL_TAGS
                        if promote_production and rollback_internal_ca
                        else (
                            INSTALL_TAGS
                            if promote_production
                            else (
                                INTERNAL_CA_DOMAIN_MIGRATION_TAGS
                                if rollback_internal_ca
                                else DOMAIN_MIGRATION_TAGS
                            )
                        )
                    ),
                    directory=directory,
                    extra_vars=migration_extra_vars,
                )
                print("Previous domain configuration restored.", file=sys.stderr)
            except Exception as rollback_error:
                print(
                    "Automatic rollback also failed. "
                    f"Protected backup: {backup}. Error: {rollback_error}",
                    file=sys.stderr,
                )
            raise

        mark_installation_complete(directory)

    if promote_production:
        print(f"\nProduction promotion completed: {old_domain} -> {new_domain}")
    else:
        print(f"\nDomain migration completed: {old_domain} -> {new_domain}")
    print("Existing Authelia sessions for the previous cookie domain may need login again.")


def command_install(args: argparse.Namespace) -> None:
    require_root()
    directory = configure_interactively(
        overwrite=args.reconfigure,
        test_mode=args.test_mode,
        certificate_source=args.certificate_source,
        image_channel=args.image_channel,
        source_channel=args.source_channel,
    )
    persist_deployment_channels(
        source_channel=args.source_channel,
        image_channel=args.image_channel,
        directory=directory,
    )
    test_mode = is_test_mode(directory)
    internal_ca = uses_internal_ca(directory)
    dns_ready = True
    if internal_ca:
        generate_internal_certificate(directory)
        print_internal_ca_instructions(directory)
    elif not args.skip_dns_check:
        dns_ready = dns_preflight(directory)
    else:
        dns_ready = False
    if not prompt_bool(
        (
            "The LAN/host-only IP and hosts-file setup are ready. Continue"
            if test_mode
            else (
                "Private DNS/hosts are configured and the internal CA trust plan is ready. Continue"
                if internal_ca
                else (
                    "DNS is configured and TCP ports 80/443 are reachable. Continue"
                    if dns_ready
                    else (
                        "DNS preflight was skipped. Continue installation"
                        if args.skip_dns_check
                        else "DNS is not ready. Continue installation and skip initial Let's Encrypt issuance for unresolved names"
                    )
                )
            )
        ),
        default=False,
    ):
        raise InstallerError(
            f"Installation cancelled. Configuration remains in {directory}."
        )
    syntax_check()
    managed_pending = managed_configuration_is_pending(directory)
    run_playbook(
        INTERNAL_CA_INSTALL_TAGS if internal_ca else INSTALL_TAGS,
        extra_vars=(
            {"haproxy_admin_sync_managed_config": "true"}
            if args.reconfigure or managed_pending
            else None
        ),
    )
    mark_installation_complete(directory)
    print(f"\n{_('easy-ha-proxy installation completed.')}")
    if internal_ca:
        print_internal_ca_instructions(directory)


def command_plan(args: argparse.Namespace) -> None:
    require_root()
    directory = config_dir()
    component = "ui" if getattr(args, "ui_only", False) else args.component
    managed_pending = managed_configuration_is_pending(directory)
    syntax_check()
    tags = update_tags_for_args(args, check_mode=True)
    run_playbook(
        tags,
        check_mode=True,
        extra_vars=(
            {"haproxy_admin_sync_managed_config": "true"}
            if managed_pending and component == "all"
            else None
        ),
    )
    if managed_pending and component != "all":
        print(
            "Managed configuration is still pending and was not included in "
            "this targeted plan. Run 'easy-ha-proxy plan --component all'."
        )


def update_tags_for_args(args: argparse.Namespace, *, check_mode: bool = False) -> str:
    component = getattr(args, "component", "all")
    if getattr(args, "ui_only", False):
        if component != "all":
            raise SystemExit("--ui-only cannot be combined with --component")
        component = "ui"
    try:
        return UPDATE_COMPONENT_TAGS[component]
    except KeyError as exc:
        mode = "plan" if check_mode else "update"
        raise SystemExit(f"Unsupported {mode} component: {component}") from exc


def command_update(args: argparse.Namespace) -> None:
    require_root()
    component = "ui" if args.ui_only else args.component
    expected_source_revision = normalize_source_revision(
        getattr(args, "expected_source_revision", None)
    )
    source_channel = args.source_channel
    if source_channel is None:
        configured_channel = str(load_metadata().get("source_channel") or "").strip()
        source_channel = (
            configured_channel
            if args.no_fetch and configured_channel in {"github", "local"}
            else "github"
        )
    # --no-fetch means "use the installed source for this run".  It must not
    # silently rewrite a GitHub-managed installation as a local-source one.
    fetch_source = source_channel == "github" and not args.no_fetch
    refresh_source = fetch_source and component in {"all", "daemons", "services"}
    source_was_refreshed = os.environ.pop(UPDATE_SOURCE_REFRESHED_ENV, "") == "1"
    if expected_source_revision and source_channel != "github":
        raise InstallerError(
            "An expected source revision can only be used with the GitHub source channel."
        )
    if expected_source_revision and component not in {"all", "daemons", "services"}:
        raise InstallerError(
            "An expected source revision is only valid for a source update component."
        )

    # A GitHub update is deliberately two-stage.  The old CLI may download
    # the new tree, but only the CLI from that tree is allowed to run config
    # migrations and apply its playbook.
    if refresh_source and not source_was_refreshed:
        if component in {"daemons", "services"}:
            print("Updating managed source before the targeted host-service update.")
        if update_managed_source(expected_source_revision):
            reexec_after_source_update()
    if source_was_refreshed and expected_source_revision:
        active_revision = git_revision(source_dir(), "HEAD")
        if active_revision != expected_source_revision:
            raise InstallerError(
                "The active source does not match the revision approved by the update plan."
            )

    directory = config_dir()
    ensure_security_secrets(directory)
    persist_deployment_channels(
        source_channel=(source_channel if not args.no_fetch or args.source_channel else None),
        image_channel=args.image_channel,
    )
    managed_pending = managed_configuration_is_pending(directory)
    if not managed_pending:
        sync_runtime_haproxy_config_to_managed(directory)
    if component == "all":
        if source_was_refreshed:
            print("Continuing with the refreshed GitHub source.")
        elif fetch_source:
            print("Using the current source because managed source refresh was skipped.")
        else:
            print("Using the currently installed local source; GitHub fetch skipped.")
        sync_runtime_dependencies()
    elif component in {"daemons", "services"} and refresh_source:
        sync_runtime_dependencies()
    elif component != "all" and fetch_source:
        print("Source fetch skipped for targeted component update.")
    syntax_check()
    tags = update_tags_for_args(args)
    run_playbook(
        tags,
        extra_vars=(
            {"haproxy_admin_sync_managed_config": "true"}
            if managed_pending and component == "all"
            else None
        ),
    )
    if managed_pending and component != "all":
        print(
            "Managed configuration remains pending because a targeted update "
            "cannot safely apply the complete stack. Run "
            "'easy-ha-proxy update --component all'."
        )
    else:
        mark_installation_complete(directory)


def command_set_channels(args: argparse.Namespace) -> None:
    """Persist the deployment channels without running an update."""

    require_root()
    release_channel = getattr(args, "release_channel", None)
    if (
        release_channel is not None
        or args.source_channel is not None
        or args.image_channel is not None
        or getattr(args, "branch", None) is not None
    ):
        persist_deployment_channels(
            release_channel=release_channel,
            source_channel=args.source_channel,
            image_channel=args.image_channel,
            branch=getattr(args, "branch", None),
        )
    metadata = load_metadata()
    source = str(metadata.get("source_channel") or "github")
    branch = str(metadata.get("branch") or "main")
    image = str(metadata.get("image_channel") or "latest")
    print(
        "release_channel="
        + release_channel_from_settings(
            source_channel=source, branch=branch, image_channel=image
        )
    )
    print(f"source_channel={source}")
    print(f"branch={branch}")
    print(f"image_channel={image}")


def command_status(_args: argparse.Namespace) -> None:
    require_root()
    run_playbook("status")


def command_reboot(args: argparse.Namespace) -> None:
    """Schedule a previously deferred operating-system reboot."""

    require_root()
    if reboot_schedule_is_active():
        print(_("A reboot is already scheduled; the current session will close."))
        print("EASY_HA_PROXY_REBOOT_SCHEDULED=1", flush=True)
        return
    if not reboot_required():
        print(_("No reboot is currently required."))
        return
    offer_pending_reboot(assume_yes=args.yes)


def command_language(args: argparse.Namespace) -> None:
    """Persist the assistant, UI, and Authelia notification language."""

    require_root()
    directory = config_dir()
    variables_path = directory / "vars.yml"
    authelia_path = directory / "authelia.yml"
    metadata_path = directory / "metadata.yml"
    for path in (variables_path, authelia_path, metadata_path):
        if not path.is_file():
            raise InstallerError(f"Managed configuration file is missing: {path}")

    metadata = load_yaml_mapping(metadata_path)
    current = str(metadata.get("installer_language", "en")).lower()
    language = args.language
    if language is None:
        print(f"Current language / Текущий язык: {current}")
        print("  1) English\n  2) Русский")
        choice = input("Language / Язык [1]: ").strip().lower()
        language = "ru" if choice in {"2", "ru", "rus", "рус", "русский"} else "en"

    variables = load_yaml_mapping(variables_path)
    authelia = load_yaml_mapping(authelia_path)
    backup_configuration(directory)

    variables["haproxy_admin_default_language"] = language
    authelia["authelia_notification_language"] = language
    root_domain = str(variables.get("root_domain", "Authelia"))
    authelia["mail_subject"] = (
        f"[{root_domain}] Уведомление безопасности"
        if language == "ru"
        else f"[{root_domain}] Security notification"
    )
    metadata["installer_language"] = language
    metadata["language_updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    write_yaml(variables_path, variables)
    write_yaml(authelia_path, authelia)
    write_yaml(metadata_path, metadata)
    print(
        f"Language saved: {language}. This setting controls the assistant, "
        "the default web UI language, and Authelia notification templates."
    )
    if args.apply:
        syntax_check(directory)
        run_playbook(
            LANGUAGE_TAGS,
            directory=directory,
            extra_vars={"haproxy_admin_force_recreate": "true"},
        )
        print("Language applied to the complete stack.")
    else:
        print("Run 'easy-ha-proxy language --language %s --apply' to apply it." % language)


def full_backup_script() -> Path:
    script = source_dir() / "installer/full_backup.py"
    if not script.is_file():
        raise InstallerError(f"Full backup helper is missing: {script}")
    return script


def command_backup_full(args: argparse.Namespace) -> None:
    require_root()
    command = [sys.executable, str(full_backup_script()), "backup"]
    if args.output_dir:
        command.extend(["--output-dir", args.output_dir])
    include_ssh = args.include_ssh
    if include_ssh is None:
        include_ssh = prompt_bool(
            "Include SSH host/private/authorized keys in the encrypted backup",
            default=False,
        )
    if include_ssh:
        command.append("--include-ssh")
    if args.no_quiesce:
        command.append("--no-quiesce")
    run(command)


def command_restore_full(args: argparse.Namespace) -> None:
    require_root()
    command = [
        sys.executable,
        str(full_backup_script()),
        "restore",
        args.archive,
        "--mode",
        args.mode,
        "--replace-managed",
    ]
    if args.restore_ssh:
        command.append("--restore-ssh")
    if args.skip_ssh:
        command.append("--skip-ssh")
    if args.apply:
        command.append("--apply")
    run(command)


def command_apply_restored(args: argparse.Namespace) -> None:
    require_root()
    directory = config_dir()
    offline = bool(getattr(args, "offline", False))
    scope = str(getattr(args, "scope", "full") or "full")
    ensure_security_secrets(directory)
    syntax_check(directory)
    if scope == "config":
        # A configuration-scope restore replaced only site configs and
        # certificates; re-render and reload HAProxy without touching host
        # services, containers, or Authelia.
        extra_vars = {"haproxy_admin_sync_managed_config": "true"}
        if offline:
            extra_vars["easy_ha_proxy_offline_restore"] = "true"
        run_playbook(
            RESTORE_CONFIG_TAGS,
            directory=directory,
            extra_vars=extra_vars,
            skip_tags=RESTORE_SKIP_TAGS if offline else None,
        )
        print("\nRestored site configuration reconciled successfully.")
        return
    if offline:
        offline_restore_image_preflight(directory=directory)
    extra_vars = {
        "authelia_force_restart": "true",
        "haproxy_admin_force_recreate": "true",
        "haproxy_admin_sync_managed_config": "true",
    }
    if offline:
        extra_vars["easy_ha_proxy_offline_restore"] = "true"
    run_playbook(
        RESTORE_TAGS,
        directory=directory,
        extra_vars=extra_vars,
        skip_tags=RESTORE_SKIP_TAGS if offline else None,
    )
    print("\nRestored easy-ha-proxy installation reconciled successfully.")


def command_configure(args: argparse.Namespace) -> None:
    require_root()
    directory = configure_interactively(
        overwrite=True,
        test_mode=None,
        certificate_source=args.certificate_source,
        image_channel=args.image_channel,
        source_channel=None,
    )
    print("Configuration updated. Run 'easy-ha-proxy plan' and then 'easy-ha-proxy update'.")
    if args.apply:
        internal_ca = uses_internal_ca(directory)
        if internal_ca:
            generate_internal_certificate(directory)
        else:
            dns_preflight(directory)
        syntax_check()
        run_playbook(
            UPDATE_TAGS if internal_ca else CONFIGURE_TAGS,
            extra_vars={"haproxy_admin_sync_managed_config": "true"},
        )
        mark_installation_complete(directory)
        if internal_ca:
            print_internal_ca_instructions(directory)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRODUCT,
        description="Install and update easy-ha-proxy on one Debian/Ubuntu server.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="run first installation")
    install_parser.add_argument(
        "--reconfigure",
        action="store_true",
        help=(
            "rerun the wizard after a backup while preserving settings that "
            "are not explicitly changed"
        ),
    )
    install_parser.add_argument(
        "--skip-dns-check",
        action="store_true",
        help="continue without resolving the admin and Authelia domains",
    )
    install_parser.add_argument(
        "--test-mode",
        action="store_true",
        help="use .test domains and a local CA instead of Let's Encrypt",
    )
    install_parser.add_argument(
        "--certificate-source",
        choices=("letsencrypt", "internal"),
        help="use Let's Encrypt or the built-in internal certificate authority",
    )
    install_parser.add_argument(
        "--image-channel", "--image",
        choices=("latest", "alpha"),
        help="deploy the release or test HAProxy Admin image",
    )
    install_parser.add_argument(
        "--source-channel", "--source",
        choices=("github", "local"),
        default=os.environ.get("EASY_HA_PROXY_SOURCE_CHANNEL"),
        help="record whether this deployment uses GitHub or staged local source",
    )
    install_parser.set_defaults(func=command_install)

    plan_parser = subparsers.add_parser("plan", help="preview an update")
    plan_parser.add_argument("--ui-only", action="store_true")
    plan_parser.add_argument(
        "--component",
        choices=sorted(UPDATE_COMPONENT_TAGS),
        default="all",
        help="preview only one update component",
    )
    plan_parser.set_defaults(func=command_plan)

    update_parser = subparsers.add_parser("update", help="update source and apply changes")
    update_parser.add_argument("--ui-only", action="store_true")
    update_parser.add_argument(
        "--component",
        choices=sorted(UPDATE_COMPONENT_TAGS),
        default="all",
        help="update only one component",
    )
    update_parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="apply the currently installed source without fetching GitHub",
    )
    update_parser.add_argument(
        "--source-channel", "--source",
        choices=("github", "local"),
        help="fetch GitHub or apply the currently synchronized local source",
    )
    update_parser.add_argument(
        "--image-channel", "--image",
        choices=("latest", "alpha"),
        help="switch HAProxy Admin to the release or test image",
    )
    update_parser.add_argument(
        "--expected-source-revision",
        help=argparse.SUPPRESS,
    )
    update_parser.set_defaults(func=command_update)

    set_channels_parser = subparsers.add_parser(
        "set-channels",
        help="persist the deployment channels without updating",
    )
    set_channels_parser.add_argument(
        "--release-channel", "--channel",
        choices=("stable", "alpha", "local"),
        help="unified channel binding branch + image (stable=main/latest, "
        "alpha=alpha/alpha, local=synced source)",
    )
    set_channels_parser.add_argument(
        "--source-channel", "--source",
        choices=("github", "local"),
        help="follow GitHub or the locally synchronized source for updates",
    )
    set_channels_parser.add_argument(
        "--branch",
        help="git branch to track on the github source channel",
    )
    set_channels_parser.add_argument(
        "--image-channel", "--image",
        choices=("latest", "alpha"),
        help="use the release or test HAProxy Admin image on the next update",
    )
    set_channels_parser.set_defaults(func=command_set_channels)

    status_parser = subparsers.add_parser("status", help="show service status")
    status_parser.set_defaults(func=command_status)

    reboot_parser = subparsers.add_parser(
        "reboot",
        help="schedule a reboot previously requested by operating-system updates",
    )
    reboot_parser.add_argument(
        "--yes",
        action="store_true",
        help="schedule the reboot without an additional confirmation prompt",
    )
    reboot_parser.set_defaults(func=command_reboot)

    language_parser = subparsers.add_parser(
        "language", help="change the assistant, UI, and notification language"
    )
    language_parser.add_argument("--language", choices=("en", "ru"))
    language_parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the language immediately and recreate affected services",
    )
    language_parser.set_defaults(func=command_language)

    backup_full_parser = subparsers.add_parser(
        "backup-full",
        help="create an encrypted disaster-recovery backup",
    )
    backup_full_parser.add_argument("--output-dir")
    backup_ssh_group = backup_full_parser.add_mutually_exclusive_group()
    backup_ssh_group.add_argument(
        "--include-ssh",
        dest="include_ssh",
        action="store_true",
    )
    backup_ssh_group.add_argument(
        "--exclude-ssh",
        dest="include_ssh",
        action="store_false",
    )
    backup_full_parser.add_argument("--no-quiesce", action="store_true")
    backup_full_parser.set_defaults(func=command_backup_full, include_ssh=None)

    restore_full_parser = subparsers.add_parser(
        "restore-full",
        help="restore an encrypted disaster-recovery backup",
    )
    restore_full_parser.add_argument("archive")
    restore_full_parser.add_argument(
        "--mode",
        choices=("auto", "fresh", "overlay"),
        default="auto",
    )
    restore_full_parser.add_argument("--restore-ssh", action="store_true")
    restore_full_parser.add_argument("--skip-ssh", action="store_true")
    restore_full_parser.add_argument("--apply", action="store_true")
    restore_full_parser.set_defaults(func=command_restore_full)

    apply_restored_parser = subparsers.add_parser(
        "apply-restored",
        help=argparse.SUPPRESS,
    )
    apply_restored_parser.add_argument(
        "--offline",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    apply_restored_parser.add_argument(
        "--scope",
        choices=("full", "config"),
        default="full",
        help=argparse.SUPPRESS,
    )
    apply_restored_parser.set_defaults(func=command_apply_restored)

    configure_parser = subparsers.add_parser(
        "configure", help="run the configuration wizard again"
    )
    configure_parser.add_argument("--apply", action="store_true")
    configure_parser.add_argument(
        "--certificate-source",
        choices=("letsencrypt", "internal"),
        help="change the source used for automatically managed certificates",
    )
    configure_parser.add_argument(
        "--image-channel", "--image",
        choices=("latest", "alpha"),
        help="switch HAProxy Admin to the release or test image",
    )
    configure_parser.set_defaults(func=command_configure)

    migrate_domain_parser = subparsers.add_parser(
        "migrate-domain",
        help="safely replace the managed root domain",
    )
    migrate_domain_parser.add_argument(
        "--new-domain",
        help="new root domain, for example new.example.net",
    )
    migrate_domain_parser.add_argument(
        "--skip-dns-check",
        action="store_true",
        help="skip public DNS validation (unsafe for production)",
    )
    migrate_domain_parser.add_argument(
        "--plan-only",
        action="store_true",
        help="show replacements and run check mode without changing files",
    )
    migrate_domain_parser.set_defaults(
        func=command_migrate_domain,
        promote_production=False,
    )

    promote_parser = subparsers.add_parser(
        "promote-production",
        help="promote a test installation to production without reinstalling",
    )
    promote_parser.add_argument(
        "--new-domain",
        help="production root domain; existing managed subdomains are migrated",
    )
    promote_parser.add_argument(
        "--certificate-source",
        choices=("letsencrypt", "internal"),
        help="use public ACME or keep the built-in CA after promotion",
    )
    promote_parser.add_argument(
        "--image-channel", "--image",
        choices=("latest", "alpha"),
        help="use the release or test HAProxy Admin image",
    )
    promote_parser.add_argument(
        "--skip-dns-check",
        action="store_true",
        help="skip public DNS readiness diagnostics",
    )
    promote_parser.add_argument(
        "--plan-only",
        action="store_true",
        help="preview promotion and run check mode without changing files",
    )
    promote_parser.set_defaults(
        func=command_migrate_domain,
        promote_production=True,
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except InstallerError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(
            f"\nERROR: command failed with exit code {exc.returncode}.",
            file=sys.stderr,
        )
        return exc.returncode or 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
