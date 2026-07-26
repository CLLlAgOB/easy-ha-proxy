#!/usr/bin/env python3
"""Encrypted full backup and disaster recovery for easy-ha-proxy."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import getpass
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


FORMAT_VERSION = 1
OFFLINE_RESTORE_ENV = "EASY_HA_PROXY_OFFLINE_RESTORE"
DEFAULT_BACKUP_ROOT = Path("/var/backups/easy-ha-proxy")
CORE_PATHS = (
    "/etc/easy-ha-proxy",
    "/opt/easy-ha-proxy/source",
    "/etc/haproxy",
    "/etc/letsencrypt",
    "/etc/iptables/haproxy_ban.rules",
    "/etc/msmtprc",
    "/etc/apparmor.d/local/usr.sbin.rsyslogd",
    "/etc/logrotate.d/authelia",
    "/etc/sysctl.d/99-authelia-redis.conf",
    "/etc/systemd/journald.conf.d/80-retention.conf",
    "/opt/authelia",
    "/opt/haproxy-admin",
    "/var/lib/haproxy",
    "/var/log/haproxy",
    "/var/log/haproxy.log",
    "/var/log/letsencrypt",
    "/usr/local/bin/update-geoip.sh",
    "/usr/local/lib/easy-ha-proxy/update_geoip.py",
)
CORE_GLOBS = (
    "/etc/systemd/system/haproxy*",
    "/etc/systemd/system/authelia*",
    "/etc/systemd/system/iptables-haproxy*",
    "/etc/systemd/system/update-admin-rt*",
    "/etc/systemd/system/journal-vacuum*",
    "/etc/systemd/system/easy-ha-proxy-geoip-update*",
    "/usr/local/sbin/haproxy-*",
    "/usr/local/sbin/authelia-*",
    "/etc/rsyslog.d/*haproxy*",
)

# CORE_PATHS intentionally mixes directory trees and individual files. Keep
# the directory semantics explicit so an archive cannot turn a managed file
# path such as /etc/msmtprc into an authorization for arbitrary descendants.
CORE_DIRECTORY_PATHS = frozenset(
    {
        "/etc/easy-ha-proxy",
        "/opt/easy-ha-proxy/source",
        "/etc/haproxy",
        "/etc/letsencrypt",
        "/opt/authelia",
        "/opt/haproxy-admin",
        "/var/lib/haproxy",
        "/var/log/haproxy",
        "/var/log/letsencrypt",
    }
)

# Runtime notification material contains short-lived password-reset links and
# one-time codes. It must not survive inside disaster-recovery archives.
BACKUP_EXCLUDES = (
    "opt/authelia/notification.log",
    "var/lib/easy-ha-proxy/authelia-notification-state.json",
    "var/lib/easy-ha-proxy/authelia-notifications",
)
SSH_GLOBS = (
    "/etc/ssh/ssh_host_*",
    "/root/.ssh",
    "/home/*/.ssh",
)
QUIESCE_UNITS = (
    "easy-ha-proxy-geoip-update.timer",
    "easy-ha-proxy-geoip-update.service",
    "haproxy-certd.service",
    "haproxy-controld.service",
    "haproxy-healthd.service",
    "authelia-configd.service",
    "authelia-usersd.service",
    "authelia-bansd.service",
    "snap.certbot.renew.timer",
    "certbot.timer",
)
QUIESCE_CONTAINERS = (
    "haproxy-admin",
    "authelia",
    "authelia-redis",
    "mail_relay",
)


class BackupError(RuntimeError):
    """Expected backup/restore failure."""


def _configured_positive_limit(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise BackupError(f"{name} must be a positive integer.") from exc
    if value <= 0:
        raise BackupError(f"{name} must be a positive integer.")
    return value


MAX_OUTER_MEMBERS = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_OUTER_MEMBERS", 8
)
MAX_OUTER_EXPANDED_BYTES = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_OUTER_BYTES", 8 * 1024 * 1024 * 1024
)
MAX_CORE_MEMBERS = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_CORE_MEMBERS", 250_000
)
MAX_CORE_EXPANDED_BYTES = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_CORE_BYTES", 64 * 1024 * 1024 * 1024
)
MAX_SSH_MEMBERS = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_SSH_MEMBERS", 10_000
)
MAX_SSH_EXPANDED_BYTES = _configured_positive_limit(
    "EASY_HA_PROXY_BACKUP_MAX_SSH_BYTES", 1024 * 1024 * 1024
)
RESTORE_MIN_FREE_BYTES = _configured_positive_limit(
    "EASY_HA_PROXY_RESTORE_MIN_FREE_BYTES", 512 * 1024 * 1024
)
ROLLBACK_BASE_OVERHEAD_BYTES = 16 * 1024 * 1024
ROLLBACK_MEMBER_OVERHEAD_BYTES = 4096

OUTER_REQUIRED_MEMBERS = frozenset(
    {"manifest.json", "system-state.txt", "payload.tar.gz"}
)
OUTER_OPTIONAL_MEMBERS = frozenset({"ssh.tar.gz"})


def run(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=capture,
        input=input_text,
        env=env,
    )


def require_root() -> None:
    if os.geteuid() != 0 and os.environ.get("EASY_HA_PROXY_ALLOW_NON_ROOT") != "1":
        raise BackupError("Run as root (sudo).")


def managed_config_dir() -> Path:
    return Path(os.environ.get("EASY_HA_PROXY_CONFIG_DIR", "/etc/easy-ha-proxy"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def existing_paths(paths: tuple[str, ...], patterns: tuple[str, ...]) -> list[str]:
    found: set[str] = set()
    for value in paths:
        if os.path.lexists(value):
            found.add(value)
    for pattern in patterns:
        for value in glob.glob(pattern):
            if os.path.lexists(value):
                found.add(value)
    return sorted(found)


def _normalized_absolute_path(value: str) -> str | None:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        return None
    normalized = posixpath.normpath(value)
    if not normalized.startswith("/"):
        return None
    return normalized


def _posix_pattern_matches(path: str, pattern: str) -> bool:
    candidate_parts = PurePosixPath(path).parts
    pattern_parts = PurePosixPath(pattern).parts
    return len(candidate_parts) == len(pattern_parts) and all(
        fnmatch.fnmatchcase(candidate, expected)
        for candidate, expected in zip(candidate_parts, pattern_parts)
    )


def _is_same_or_below(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _static_pattern_prefix(pattern: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(pattern).parts:
        if any(character in part for character in "*?["):
            break
        parts.append(part)
    if not parts:
        return "/"
    return str(PurePosixPath(*parts))


def _manifest_core_path_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    if normalized is None:
        return False
    return normalized in CORE_PATHS or any(
        _posix_pattern_matches(normalized, pattern) for pattern in CORE_GLOBS
    )


def _core_payload_path_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    if normalized is None:
        return False
    if any(
        _is_same_or_below(normalized, root) for root in CORE_DIRECTORY_PATHS
    ):
        return True
    if normalized in CORE_PATHS:
        return True
    for pattern in CORE_GLOBS:
        if _posix_pattern_matches(normalized, pattern):
            return True
        # A glob can legitimately select a managed directory such as
        # haproxy.service.d. Tar then contains that directory's children as
        # well; authorize only descendants of the exact glob match.
        for parent in PurePosixPath(normalized).parents:
            parent_value = str(parent)
            if _posix_pattern_matches(parent_value, pattern):
                return True
    return False


def _core_ancestor_directory_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    if normalized is None:
        return False
    targets = list(CORE_PATHS)
    targets.extend(_static_pattern_prefix(pattern) for pattern in CORE_GLOBS)
    return any(
        target == normalized or target.startswith(normalized.rstrip("/") + "/")
        for target in targets
    )


def _manifest_ssh_path_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    return normalized is not None and any(
        _posix_pattern_matches(normalized, pattern) for pattern in SSH_GLOBS
    )


def _ssh_payload_path_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    if normalized is None:
        return False
    if _posix_pattern_matches(normalized, "/etc/ssh/ssh_host_*"):
        return True
    if _is_same_or_below(normalized, "/root/.ssh"):
        return True
    parts = PurePosixPath(normalized).parts
    return len(parts) >= 4 and parts[1] == "home" and parts[3] == ".ssh"


def _ssh_ancestor_directory_allowed(path: str) -> bool:
    normalized = _normalized_absolute_path(path)
    if normalized is None:
        return False
    if normalized in {"/etc", "/etc/ssh", "/root", "/home"}:
        return True
    parts = PurePosixPath(normalized).parts
    return len(parts) == 3 and parts[1] == "home" and bool(parts[2])


def ssh_paths() -> list[str]:
    paths = existing_paths((), SSH_GLOBS)
    config = managed_config_dir() / "vars.yml"
    if config.is_file():
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("rdg_ssh_key:"):
                candidate = line.split(":", 1)[1].strip().strip("\"'")
                if (
                    _manifest_ssh_path_allowed(candidate)
                    and os.path.isfile(candidate)
                ):
                    paths.append(candidate)
                break
    return sorted(set(paths))


def relative_paths(paths: list[str]) -> list[str]:
    return [value.lstrip("/") for value in paths]


def create_payload(
    destination: Path,
    paths: list[str],
    *,
    excludes: tuple[str, ...] = BACKUP_EXCLUDES,
) -> None:
    if not paths:
        raise BackupError("No files were found for the backup payload.")
    run(
        [
            "tar",
            "--acls",
            "--xattrs",
            "--numeric-owner",
            "-czpf",
            str(destination),
            "-C",
            "/",
            *(f"--exclude={value}" for value in excludes),
            *relative_paths(paths),
        ]
    )
    os.chmod(destination, 0o600)


def command_output(argv: list[str]) -> str:
    try:
        return run(argv, check=False, capture=True).stdout
    except OSError:
        return ""


class Quiesce:
    def __init__(self, enabled: bool, *, stop_containers: bool = False):
        self.enabled = enabled
        self.stop_containers = stop_containers
        self.units: list[str] = []
        self.containers: list[str] = []

    def __enter__(self) -> "Quiesce":
        if not self.enabled:
            return self
        try:
            if shutil.which("systemctl"):
                for unit in QUIESCE_UNITS:
                    active = run(
                        ["systemctl", "is-active", "--quiet", unit],
                        check=False,
                    ).returncode == 0
                    if active:
                        run(["systemctl", "stop", unit])
                        self.units.append(unit)
            if shutil.which("docker"):
                run(
                    ["docker", "exec", "authelia-redis", "redis-cli", "SAVE"],
                    check=False,
                )
                for container in QUIESCE_CONTAINERS:
                    running = (
                        command_output(
                            [
                                "docker",
                                "inspect",
                                "-f",
                                "{{.State.Running}}",
                                container,
                            ]
                        ).strip()
                        == "true"
                    )
                    if running:
                        run(
                            [
                                "docker",
                                "stop" if self.stop_containers else "pause",
                                container,
                            ]
                        )
                        self.containers.append(container)
        except BaseException:
            # A failure half-way through quiescing must not leave the original
            # installation stopped when no backup/restore work has begun.
            self._resume()
            raise
        return self

    def resume_units(self) -> None:
        """Restart quiesced systemd units before their state is inspected.

        Restore reconciliation runs its status check while the surrounding
        quiesce context is still open; timers this class stopped (for example
        snap.certbot.renew.timer) must be active again by then or the check
        fails on damage the quiesce itself caused.
        """

        units = list(reversed(self.units))
        self.units.clear()
        for unit in units:
            try:
                run(["systemctl", "start", unit], check=False)
            except OSError:
                pass

    def _resume(self) -> None:
        containers = list(reversed(self.containers))
        self.containers.clear()
        for container in containers:
            try:
                run(
                    [
                        "docker",
                        "start" if self.stop_containers else "unpause",
                        container,
                    ],
                    check=False,
                )
            except OSError:
                pass
        self.resume_units()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._resume()


def read_passphrase(*, confirm: bool, from_stdin: bool = False) -> str:
    if from_stdin:
        first = sys.stdin.readline()
        if first == "":
            raise BackupError("No backup passphrase was supplied on stdin.")
        first = first.rstrip("\r\n")
    else:
        testing = os.environ.get("EASY_HA_PROXY_TEST_PASSPHRASE")
        if (
            testing is not None
            and os.environ.get("EASY_HA_PROXY_ALLOW_NON_ROOT") == "1"
        ):
            return testing
        first = getpass.getpass("Backup passphrase: ")
    if len(first) < 12:
        raise BackupError("Use a backup passphrase of at least 12 characters.")
    if confirm and not from_stdin:
        second = getpass.getpass("Repeat backup passphrase: ")
        if first != second:
            raise BackupError("Backup passphrases do not match.")
    return first


def openssl_crypt(source: Path, destination: Path, password: str, *, decrypt: bool) -> None:
    argv = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        "600000",
        "-md",
        "sha256",
    ]
    if decrypt:
        argv.append("-d")
    else:
        argv.append("-salt")
    argv.extend(["-in", str(source), "-out", str(destination), "-pass", "stdin"])
    try:
        run(argv, input_text=password + "\n")
    except subprocess.CalledProcessError as exc:
        raise BackupError("Cannot decrypt backup: wrong passphrase or damaged file.") from exc
    os.chmod(destination, 0o600)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def compact_manifest_json(manifest: dict[str, Any]) -> str:
    return json.dumps(
        manifest,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def create_backup(args: argparse.Namespace) -> Path:
    require_root()
    if not shutil.which("openssl") or not shutil.which("tar"):
        raise BackupError("openssl and tar are required.")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = Path(args.output_dir or DEFAULT_BACKUP_ROOT) / f"full-{timestamp}"
    backup_dir.mkdir(parents=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    encrypted = backup_dir / f"easy-ha-proxy-full-{timestamp}.tar.gz.enc"
    core = existing_paths(CORE_PATHS, CORE_GLOBS)
    included_ssh = bool(args.include_ssh)
    ssh = ssh_paths() if included_ssh else []
    if not (managed_config_dir() / "metadata.yml").is_file():
        raise BackupError("A managed easy-ha-proxy installation was not found.")

    password = read_passphrase(
        confirm=True,
        from_stdin=bool(getattr(args, "passphrase_stdin", False)),
    )
    with tempfile.TemporaryDirectory(prefix="easy-ha-proxy-backup.") as temporary:
        work = Path(temporary)
        payload = work / "payload.tar.gz"
        ssh_payload = work / "ssh.tar.gz"
        with Quiesce(args.quiesce):
            create_payload(payload, core)
            if included_ssh and ssh:
                create_payload(ssh_payload, ssh)

        payload_expanded_bytes = validate_payload(payload)
        ssh_payload_expanded_bytes = (
            validate_payload(ssh_payload, ssh=True)
            if ssh_payload.exists()
            else None
        )

        manifest = {
            "format": "easy-ha-proxy-full-backup",
            "format_version": FORMAT_VERSION,
            "created_at": timestamp,
            "hostname": socket.getfqdn(),
            "machine": os.uname().machine,
            "core_paths": core,
            "runtime_excludes": list(BACKUP_EXCLUDES),
            "ssh_included": bool(included_ssh and ssh),
            "ssh_paths": ssh,
            "quiesced": bool(args.quiesce),
            "payload_sha256": sha256_file(payload),
            "ssh_payload_sha256": sha256_file(ssh_payload) if ssh_payload.exists() else None,
            "payload_expanded_bytes": payload_expanded_bytes,
            "ssh_payload_expanded_bytes": ssh_payload_expanded_bytes,
        }
        write_json(work / "manifest.json", manifest)
        (work / "system-state.txt").write_text(
            "=== OS ===\n"
            + command_output(["uname", "-a"])
            + "\n=== PACKAGES ===\n"
            + command_output(["dpkg-query", "-W"])
            + "\n=== SYSTEMD ===\n"
            + command_output(["systemctl", "list-unit-files", "--no-pager"])
            + "\n=== DOCKER ===\n"
            + command_output(["docker", "ps", "-a", "--no-trunc"])
            + "\n=== IMAGES ===\n"
            + command_output(["docker", "image", "ls", "--digests", "--no-trunc"]),
            encoding="utf-8",
        )
        bundle = work / "bundle.tar.gz"
        names = ["manifest.json", "system-state.txt", "payload.tar.gz"]
        if ssh_payload.exists():
            names.append("ssh.tar.gz")
        run(["tar", "-czf", str(bundle), "-C", str(work), *names])
        openssl_crypt(bundle, encrypted, password, decrypt=False)

    checksum = sha256_file(encrypted)
    sidecar = Path(str(encrypted) + ".sha256")
    sidecar.write_text(f"{checksum}  {encrypted.name}\n", encoding="ascii")
    os.chmod(sidecar, 0o600)
    print(f"\nFull encrypted backup created: {encrypted}")
    print(f"Checksum: {sidecar}")
    print(f"SSH keys included: {'yes' if manifest['ssh_included'] else 'no'}")
    print(f"EASY_HA_PROXY_FULL_BACKUP_FILE={encrypted}")
    print(
        "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
        + compact_manifest_json(manifest)
    )
    return encrypted


def validate_bundle_member(member: tarfile.TarInfo) -> None:
    name = PurePosixPath(member.name)
    if name.is_absolute() or ".." in name.parts:
        raise BackupError(f"Unsafe bundle entry: {member.name}")
    normalized_name = posixpath.normpath(member.name)
    if normalized_name in {"", "."}:
        raise BackupError(f"Unsafe bundle entry: {member.name}")
    if not (
        member.isfile()
        or member.isdir()
        or member.issym()
        or member.islnk()
    ):
        raise BackupError(f"Unsafe special bundle entry: {member.name}")
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        if not member.linkname or link.is_absolute():
            raise BackupError(f"Unsafe bundle link: {member.name}")
        if member.issym():
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(normalized_name), member.linkname)
            )
        else:
            # Tar hard-link names are relative to the archive root, unlike
            # symbolic-link targets which are relative to the link directory.
            resolved = posixpath.normpath(member.linkname)
        if resolved == ".." or resolved.startswith("../"):
            raise BackupError(f"Unsafe bundle link: {member.name}")


def _normalized_member_name(member: tarfile.TarInfo) -> str:
    return posixpath.normpath(member.name)


def _resolved_link_name(member: tarfile.TarInfo) -> str | None:
    if not (member.issym() or member.islnk()):
        return None
    name = _normalized_member_name(member)
    if member.issym():
        return posixpath.normpath(
            posixpath.join(posixpath.dirname(name), member.linkname)
        )
    return posixpath.normpath(member.linkname)


def _validate_archive_members(
    path: Path,
    *,
    label: str,
    max_members: int,
    max_expanded_bytes: int,
    member_policy: Any,
) -> tuple[set[str], int]:
    seen: set[str] = set()
    count = 0
    expanded_bytes = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            validate_bundle_member(member)
            name = _normalized_member_name(member)
            if name in seen:
                raise BackupError(f"Duplicate {label} archive member: {name}")
            seen.add(name)

            count += 1
            if count > max_members:
                raise BackupError(
                    f"{label} archive exceeds the member-count limit "
                    f"({max_members})."
                )
            if member.size < 0:
                raise BackupError(f"Invalid {label} archive member size: {name}")
            expanded_bytes += member.size
            if expanded_bytes > max_expanded_bytes:
                raise BackupError(
                    f"{label} archive exceeds the expanded-size limit "
                    f"({max_expanded_bytes} bytes)."
                )
            member_policy(member, name)
    return seen, expanded_bytes


def _outer_member_policy(member: tarfile.TarInfo, name: str) -> None:
    allowed = OUTER_REQUIRED_MEMBERS | OUTER_OPTIONAL_MEMBERS
    if name not in allowed:
        raise BackupError(f"Unexpected outer backup member: {name}")
    if not member.isfile():
        raise BackupError(f"Outer backup member is not a regular file: {name}")


def _core_member_policy(member: tarfile.TarInfo, name: str) -> None:
    path = "/" + name.lstrip("/")
    allowed = _core_payload_path_allowed(path)
    if member.isdir():
        allowed = allowed or _core_ancestor_directory_allowed(path)
    if not allowed:
        raise BackupError(f"Core payload member is outside managed paths: {name}")

    link_target = _resolved_link_name(member)
    if link_target is not None and not _core_payload_path_allowed(
        "/" + link_target.lstrip("/")
    ):
        raise BackupError(
            f"Core payload link target is outside managed paths: {name}"
        )


def _ssh_member_policy(member: tarfile.TarInfo, name: str) -> None:
    path = "/" + name.lstrip("/")
    allowed = _ssh_payload_path_allowed(path)
    if member.isdir():
        allowed = allowed or _ssh_ancestor_directory_allowed(path)
    if not allowed:
        raise BackupError(f"SSH payload member is outside allowed paths: {name}")

    link_target = _resolved_link_name(member)
    if link_target is not None and not _ssh_payload_path_allowed(
        "/" + link_target.lstrip("/")
    ):
        raise BackupError(f"SSH payload link target is outside allowed paths: {name}")


def extract_bundle(bundle: Path, destination: Path) -> None:
    members, expanded_bytes = _validate_archive_members(
        bundle,
        label="outer backup",
        max_members=MAX_OUTER_MEMBERS,
        max_expanded_bytes=MAX_OUTER_EXPANDED_BYTES,
        member_policy=_outer_member_policy,
    )
    missing = OUTER_REQUIRED_MEMBERS - members
    if missing:
        raise BackupError(
            "Outer backup is missing required members: " + ", ".join(sorted(missing))
        )
    free_bytes = shutil.disk_usage(destination).free
    required_bytes = expanded_bytes + RESTORE_MIN_FREE_BYTES
    if free_bytes < required_bytes:
        raise BackupError(
            "Not enough temporary disk space to inspect the backup: need "
            f"{_format_bytes(required_bytes)}, have {_format_bytes(free_bytes)}."
        )
    with tarfile.open(bundle, "r:gz") as archive:
        archive.extractall(destination)


def validate_payload(path: Path, *, ssh: bool = False) -> int:
    """Validate a payload and return its total expanded member size."""

    _members, expanded_bytes = _validate_archive_members(
        path,
        label="SSH payload" if ssh else "core payload",
        max_members=MAX_SSH_MEMBERS if ssh else MAX_CORE_MEMBERS,
        max_expanded_bytes=(
            MAX_SSH_EXPANDED_BYTES if ssh else MAX_CORE_EXPANDED_BYTES
        ),
        member_policy=_ssh_member_policy if ssh else _core_member_policy,
    )
    return expanded_bytes


def validate_rollback_payload(path: Path, *, include_ssh: bool) -> None:
    """Validate a local safety snapshot that may contain core and SSH state."""

    if not include_ssh:
        validate_payload(path)
        return

    def rollback_policy(member: tarfile.TarInfo, name: str) -> None:
        try:
            _core_member_policy(member, name)
            return
        except BackupError as core_error:
            try:
                _ssh_member_policy(member, name)
                return
            except BackupError:
                raise core_error

    _validate_archive_members(
        path,
        label="rollback payload",
        max_members=MAX_CORE_MEMBERS + MAX_SSH_MEMBERS,
        max_expanded_bytes=MAX_CORE_EXPANDED_BYTES + MAX_SSH_EXPANDED_BYTES,
        member_policy=rollback_policy,
    )


def verify_encrypted_archive(archive: Path) -> None:
    if not archive.is_file():
        raise BackupError(f"Backup file not found: {archive}")
    sidecar = Path(str(archive) + ".sha256")
    if not sidecar.is_file():
        return
    fields = sidecar.read_text(encoding="ascii").split()
    if not fields:
        raise BackupError("Encrypted backup checksum file is empty.")
    expected = fields[0].lower()
    if len(expected) != 64 or any(
        value not in "0123456789abcdef" for value in expected
    ):
        raise BackupError("Encrypted backup checksum file is invalid.")
    if expected != sha256_file(archive):
        raise BackupError("Encrypted backup checksum verification failed.")


def _validated_manifest(raw_manifest: Any) -> dict[str, Any]:
    if not isinstance(raw_manifest, dict):
        raise BackupError("Full-backup manifest must be a JSON object.")
    manifest = dict(raw_manifest)
    if (
        manifest.get("format") != "easy-ha-proxy-full-backup"
        or manifest.get("format_version") != FORMAT_VERSION
    ):
        raise BackupError("Unsupported full-backup format.")

    for field in ("created_at", "hostname", "machine"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            raise BackupError(f"Full-backup manifest field is invalid: {field}")
    for field in ("core_paths", "ssh_paths"):
        values = manifest.get(field)
        if not isinstance(values, list) or not all(
            isinstance(value, str)
            and PurePosixPath(value).is_absolute()
            and ".." not in PurePosixPath(value).parts
            for value in values
        ):
            raise BackupError(f"Full-backup manifest field is invalid: {field}")
    if not manifest["core_paths"]:
        raise BackupError("Full-backup manifest field is invalid: core_paths")
    if not all(
        _manifest_core_path_allowed(value) for value in manifest["core_paths"]
    ):
        raise BackupError("Full-backup manifest contains unmanaged core_paths.")
    if not all(
        _manifest_ssh_path_allowed(value) for value in manifest["ssh_paths"]
    ):
        raise BackupError("Full-backup manifest contains disallowed ssh_paths.")
    if not isinstance(manifest.get("ssh_included"), bool):
        raise BackupError("Full-backup manifest field is invalid: ssh_included")
    if not isinstance(manifest.get("quiesced"), bool):
        raise BackupError("Full-backup manifest field is invalid: quiesced")

    payload_sha256 = manifest.get("payload_sha256")
    if not isinstance(payload_sha256, str) or len(payload_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in payload_sha256.lower()
    ):
        raise BackupError("Full-backup manifest field is invalid: payload_sha256")
    ssh_sha256 = manifest.get("ssh_payload_sha256")
    if ssh_sha256 is not None and (
        not isinstance(ssh_sha256, str)
        or len(ssh_sha256) != 64
        or any(value not in "0123456789abcdef" for value in ssh_sha256.lower())
    ):
        raise BackupError(
            "Full-backup manifest field is invalid: ssh_payload_sha256"
        )
    if manifest["ssh_included"] != bool(ssh_sha256):
        raise BackupError("Full-backup manifest SSH metadata is inconsistent.")
    if manifest["ssh_included"] != bool(manifest["ssh_paths"]):
        raise BackupError("Full-backup manifest SSH path metadata is inconsistent.")

    payload_expanded_bytes = manifest.get("payload_expanded_bytes")
    if payload_expanded_bytes is not None and (
        isinstance(payload_expanded_bytes, bool)
        or not isinstance(payload_expanded_bytes, int)
        or payload_expanded_bytes < 0
        or payload_expanded_bytes > MAX_CORE_EXPANDED_BYTES
    ):
        raise BackupError(
            "Full-backup manifest field is invalid: payload_expanded_bytes"
        )
    ssh_expanded_bytes = manifest.get("ssh_payload_expanded_bytes")
    if ssh_expanded_bytes is not None and (
        isinstance(ssh_expanded_bytes, bool)
        or not isinstance(ssh_expanded_bytes, int)
        or ssh_expanded_bytes < 0
        or ssh_expanded_bytes > MAX_SSH_EXPANDED_BYTES
    ):
        raise BackupError(
            "Full-backup manifest field is invalid: ssh_payload_expanded_bytes"
        )
    if not manifest["ssh_included"] and ssh_expanded_bytes is not None:
        raise BackupError(
            "Full-backup manifest SSH expanded-size metadata is inconsistent."
        )

    runtime_excludes = manifest.get("runtime_excludes")
    if runtime_excludes is not None and (
        not isinstance(runtime_excludes, list)
        or not all(isinstance(value, str) for value in runtime_excludes)
    ):
        raise BackupError("Full-backup manifest field is invalid: runtime_excludes")
    return manifest


def validate_backup_archive(
    archive: Path,
    password: str,
    work: Path,
    *,
    outer_checksum_verified: bool = False,
) -> tuple[dict[str, Any], Path, Path | None]:
    """Decrypt and fully validate an archive without changing the host state."""
    if not outer_checksum_verified:
        verify_encrypted_archive(archive)
    bundle = work / "bundle.tar.gz"
    openssl_crypt(archive, bundle, password, decrypt=True)
    extract_bundle(bundle, work)

    manifest_path = work / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BackupError("Full-backup manifest is missing or is not a regular file.")
    manifest = _validated_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8"))
    )

    payload = work / "payload.tar.gz"
    if payload.is_symlink() or not payload.is_file():
        raise BackupError("Core payload is missing or is not a regular file.")
    if sha256_file(payload).lower() != manifest["payload_sha256"].lower():
        raise BackupError("Core payload checksum verification failed.")
    payload_expanded_bytes = validate_payload(payload)
    declared_payload_size = manifest.get("payload_expanded_bytes")
    if (
        declared_payload_size is not None
        and declared_payload_size != payload_expanded_bytes
    ):
        raise BackupError("Core payload expanded-size verification failed.")
    # Version 1 archives created before expanded-size metadata remain readable.
    # Inspection enriches their in-memory manifest with the measured values so
    # every restore path can perform the same disk-space preflight.
    manifest["payload_expanded_bytes"] = payload_expanded_bytes

    ssh_payload_path = work / "ssh.tar.gz"
    ssh_payload: Path | None = None
    if manifest["ssh_included"]:
        if ssh_payload_path.is_symlink() or not ssh_payload_path.is_file():
            raise BackupError("SSH payload is missing or is not a regular file.")
        if (
            sha256_file(ssh_payload_path).lower()
            != manifest["ssh_payload_sha256"].lower()
        ):
            raise BackupError("SSH payload checksum verification failed.")
        ssh_payload_expanded_bytes = validate_payload(ssh_payload_path, ssh=True)
        declared_ssh_size = manifest.get("ssh_payload_expanded_bytes")
        if (
            declared_ssh_size is not None
            and declared_ssh_size != ssh_payload_expanded_bytes
        ):
            raise BackupError("SSH payload expanded-size verification failed.")
        manifest["ssh_payload_expanded_bytes"] = ssh_payload_expanded_bytes
        ssh_payload = ssh_payload_path
    elif os.path.lexists(ssh_payload_path):
        raise BackupError("Unexpected SSH payload is present in the backup.")
    else:
        manifest["ssh_payload_expanded_bytes"] = None
    return manifest, payload, ssh_payload


def inspect_backup(args: argparse.Namespace) -> dict[str, Any]:
    archive = Path(args.archive).expanduser().resolve()
    verify_encrypted_archive(archive)
    password = read_passphrase(
        confirm=False,
        from_stdin=bool(getattr(args, "passphrase_stdin", False)),
    )
    with tempfile.TemporaryDirectory(prefix="easy-ha-proxy-inspect.") as temporary:
        manifest, _payload, _ssh_payload = validate_backup_archive(
            archive,
            password,
            Path(temporary),
            outer_checksum_verified=True,
        )
    print(
        "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
        + compact_manifest_json(manifest)
    )
    return manifest


def current_authorized_keys() -> dict[Path, tuple[list[str], int, int]]:
    saved: dict[Path, tuple[list[str], int, int]] = {}
    candidates = [Path("/root/.ssh/authorized_keys")]
    candidates.extend(Path(value) for value in glob.glob("/home/*/.ssh/authorized_keys"))
    for path in candidates:
        if not path.is_file():
            continue
        stat = path.stat()
        lines = [
            line
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        saved[path] = (lines, stat.st_uid, stat.st_gid)
    return saved


def merge_authorized_keys(saved: dict[Path, tuple[list[str], int, int]]) -> None:
    for path, (old_lines, uid, gid) in saved.items():
        new_lines: list[str] = []
        if path.is_file():
            new_lines = [
                line
                for line in path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if line.strip()
            ]
        merged = list(dict.fromkeys(new_lines + old_lines))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        os.chown(path, uid, gid)


def extract_payload(payload: Path, members: list[str] | None = None) -> None:
    command = [
        "tar",
        "--acls",
        "--xattrs",
        "--numeric-owner",
        "-xzpf",
        str(payload),
        "-C",
        "/",
    ]
    if members:
        # Selective extraction: tar extracts each named member and, for
        # directories, everything below it.
        command.extend(members)
    run(command)


# Configuration-scope restore: only HTTP/TCP sites, their runtime settings and
# certificates. The managed source, systemd units, secrets, Authelia state and
# SSH identity of the target server are deliberately left untouched, so even a
# backup taken on an older software revision cannot downgrade host services.
CONFIG_SCOPE_PATHS = (
    "/etc/haproxy",
    "/etc/letsencrypt",
    "/opt/haproxy-admin/config",
)


def list_payload_members(payload: Path) -> list[str]:
    result = run(["tar", "-tzf", str(payload)], capture=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def config_scope_members(payload: Path) -> list[str]:
    """Return archive member prefixes covered by the configuration scope."""

    prefixes = tuple(path.lstrip("/") for path in CONFIG_SCOPE_PATHS)
    selected: set[str] = set()
    for member in list_payload_members(payload):
        name = member.lstrip("./").rstrip("/")
        for prefix in prefixes:
            if name == prefix or name.startswith(prefix + "/"):
                selected.add(prefix)
    return sorted(selected)


def reconcile_restored_configuration() -> None:
    command = [
        "/usr/local/bin/easy-ha-proxy",
        "apply-restored",
        "--scope",
        "config",
    ]
    if os.environ.get(OFFLINE_RESTORE_ENV) == "1":
        command.append("--offline")
    _restore_stage("Restored site configuration reconciliation", command)


def restore_config_scope(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    payload: Path,
) -> None:
    """Restore only sites, their settings and certificates from the archive."""

    print("\nConfiguration restore plan (sites and certificates only):")
    print(f"  archive host: {manifest.get('hostname', 'unknown')}")
    print(f"  created:      {manifest.get('created_at', 'unknown')}")
    print("  paths:        " + ", ".join(CONFIG_SCOPE_PATHS))
    print("  untouched:    managed source, systemd units, secrets, Authelia, SSH")
    if not bool(getattr(args, "yes", False)):
        confirmation = input("Type RESTORE to continue: ").strip()
        if confirmation != "RESTORE":
            raise BackupError("Restore cancelled.")

    members = config_scope_members(payload)
    if not members:
        raise BackupError(
            "The archive contains no site or certificate payload for a "
            "configuration-scope restore."
        )
    if args.apply:
        preflight_restore_control_plane()
    rollback_paths = [
        path for path in CONFIG_SCOPE_PATHS if os.path.lexists(path)
    ]
    rollback = create_pre_restore_backup(rollback_paths)
    if rollback:
        print(f"Pre-restore rollback archive: {rollback}")
    try:
        extract_payload(payload, members=members)
        normalize_restored_config_permissions()
        if args.apply:
            reconcile_restored_configuration()
    except (Exception, KeyboardInterrupt) as restore_error:
        if rollback is None:
            raise BackupError(
                "Configuration restore failed and no previous state was "
                f"available for automatic rollback: {restore_error}"
            ) from restore_error
        try:
            validate_rollback_payload(rollback, include_ssh=False)
            remove_paths(rollback_paths)
            extract_payload(rollback)
            normalize_restored_config_permissions()
            if args.apply:
                reconcile_restored_configuration()
        except (Exception, KeyboardInterrupt) as rollback_error:
            raise BackupError(
                "Configuration restore failed and automatic rollback also "
                f"failed. Restore error: {restore_error}. "
                f"Rollback archive: {rollback}. "
                f"Rollback error: {rollback_error}"
            ) from rollback_error
        cleanup_pre_restore_backup(rollback)
        raise BackupError(
            "Configuration restore failed; the previous configuration was "
            f"restored automatically. Restore error: {restore_error}"
        ) from restore_error
    cleanup_pre_restore_backup(rollback)
    print("\nSite configuration and certificates restored successfully.")
    if args.apply:
        print("The restored configuration was applied successfully.")
    else:
        print(
            "Run 'sudo easy-ha-proxy apply-restored --scope config' "
            "to apply it."
        )


def disable_restored_runtime_firewall_state(root: Path | None = None) -> list[Path]:
    """Preserve but disable host-specific iptables-persistent snapshots.

    /etc/iptables/rules.v4 and rules.v6 are not portable application config: on
    Docker hosts they often contain live DOCKER chains, bridge names and subnet
    addresses from the source machine. Restoring them on a fresh target can wipe
    the target Docker NAT chains and make published container ports fail.
    """
    base = root or Path("/")
    iptables_dir = base / "etc/iptables"
    disabled: list[Path] = []
    if not iptables_dir.exists():
        return disabled
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for name in ("rules.v4", "rules.v6"):
        source = iptables_dir / name
        if not os.path.lexists(source):
            continue
        suffix = 0
        target = iptables_dir / f"{name}.restored-disabled.{timestamp}"
        while os.path.lexists(target):
            suffix += 1
            target = iptables_dir / f"{name}.restored-disabled.{timestamp}.{suffix}"
        os.replace(source, target)
        disabled.append(target)
        print(f"Disabled restored runtime firewall state: {source} -> {target}")
    return disabled


def create_pre_restore_backup(paths: list[str]) -> Path | None:
    existing = [path for path in paths if os.path.lexists(path)]
    if not existing:
        return None
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = DEFAULT_BACKUP_ROOT / f"pre-restore-{timestamp}-{os.getpid()}"
    destination.mkdir(parents=True, mode=0o700)
    archive = destination / "previous-state.tar.gz"
    # Unlike exported DR archives, this short-lived root-only snapshot keeps
    # runtime state so a failed restore can be reversed exactly. It is deleted
    # after either a successful restore or a successful automatic rollback.
    create_payload(archive, existing, excludes=())
    return archive


def cleanup_pre_restore_backup(archive: Path | None) -> None:
    if archive is None:
        return
    try:
        archive.unlink()
    except FileNotFoundError:
        pass
    try:
        archive.parent.rmdir()
    except OSError:
        pass


def managed_state_paths(*, include_ssh: bool = False) -> list[str]:
    """Return only paths authorized by the controller's built-in allowlist."""

    paths = existing_paths(CORE_PATHS, CORE_GLOBS)
    if include_ssh:
        paths.extend(ssh_paths())
    return sorted(set(paths))


def managed_paths_apparent_usage(paths: list[str]) -> tuple[int, int, set[int]]:
    """Return apparent bytes, unique members, and filesystems without links.

    The result is used only for a conservative capacity check. Missing paths
    are harmless because managed services can rotate files while the plan is
    being prepared; every other filesystem error aborts before quiescing.
    """

    expanded_bytes = 0
    member_count = 0
    devices: set[int] = set()
    seen: set[tuple[int, int]] = set()

    def visit(value: str) -> None:
        nonlocal expanded_bytes, member_count
        try:
            metadata = os.lstat(value)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BackupError(
                f"Cannot inspect managed path before restore: {value}: {exc}"
            ) from exc

        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            return
        seen.add(identity)
        devices.add(metadata.st_dev)
        member_count += 1
        if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            expanded_bytes += max(0, metadata.st_size)

        if not stat.S_ISDIR(metadata.st_mode):
            return
        try:
            with os.scandir(value) as entries:
                children = [entry.path for entry in entries]
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BackupError(
                f"Cannot inspect managed directory before restore: {value}: {exc}"
            ) from exc
        for child in children:
            visit(child)

    for path in sorted(set(paths)):
        visit(path)
    return expanded_bytes, member_count, devices


def _existing_ancestor(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            raise BackupError(f"Cannot find a filesystem for restore path: {path}")
        candidate = parent
    return candidate


def _format_bytes(value: int) -> str:
    size = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or suffix == "TiB":
            return f"{size:.1f} {suffix}"
        size /= 1024
    return f"{value} B"


def preflight_restore_space(
    manifest: dict[str, Any],
    rollback_paths: list[str],
    *,
    replace_managed: bool,
    restore_ssh: bool,
) -> None:
    """Verify space for candidate extraction and an automatic rollback copy."""

    payload_bytes = manifest.get("payload_expanded_bytes")
    ssh_bytes = manifest.get("ssh_payload_expanded_bytes")
    if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int):
        raise BackupError("Backup inspection did not report core expanded size.")
    if restore_ssh and (
        isinstance(ssh_bytes, bool) or not isinstance(ssh_bytes, int)
    ):
        raise BackupError("Backup inspection did not report SSH expanded size.")
    candidate_bytes = payload_bytes + (ssh_bytes if restore_ssh else 0)

    current_bytes, current_members, current_devices = managed_paths_apparent_usage(
        rollback_paths
    )
    rollback_bytes = 0
    if current_members:
        rollback_bytes = (
            current_bytes
            + current_members * ROLLBACK_MEMBER_OVERHEAD_BYTES
            + ROLLBACK_BASE_OVERHEAD_BYTES
        )

    root_path = _existing_ancestor(Path("/"))
    backup_path = _existing_ancestor(DEFAULT_BACKUP_ROOT)
    root_device = os.stat(root_path).st_dev
    backup_device = os.stat(backup_path).st_dev
    root_free = shutil.disk_usage(root_path).free
    backup_free = shutil.disk_usage(backup_path).free

    # Exact replacement can reclaim the current managed bytes before payload
    # extraction, but only when every observed path lives on the root
    # filesystem. Otherwise keep the estimate conservative.
    reclaimable = (
        current_bytes
        if replace_managed
        and current_devices
        and current_devices == {root_device}
        else 0
    )
    candidate_growth = max(0, candidate_bytes - reclaimable)

    if root_device == backup_device:
        required = rollback_bytes + candidate_growth + RESTORE_MIN_FREE_BYTES
        if root_free < required:
            raise BackupError(
                "Not enough free space for restore and automatic rollback on "
                f"{root_path}: need {_format_bytes(required)}, "
                f"have {_format_bytes(root_free)}."
            )
        return

    root_required = candidate_growth + RESTORE_MIN_FREE_BYTES
    if root_free < root_required:
        raise BackupError(
            f"Not enough free space for restore on {root_path}: need "
            f"{_format_bytes(root_required)}, have {_format_bytes(root_free)}."
        )
    if rollback_bytes:
        backup_required = rollback_bytes + RESTORE_MIN_FREE_BYTES
        if backup_free < backup_required:
            raise BackupError(
                "Not enough free space for the automatic rollback archive on "
                f"{backup_path}: need {_format_bytes(backup_required)}, "
                f"have {_format_bytes(backup_free)}."
            )


def remove_paths(paths: list[str]) -> None:
    """Remove exact, already-authorized paths without following symlinks."""

    for value in sorted(set(paths), key=lambda item: item.count("/"), reverse=True):
        if not os.path.lexists(value):
            continue
        path = Path(value)
        if path.is_symlink() or not path.is_dir():
            path.unlink()
        else:
            shutil.rmtree(path)


def remove_managed_state(*, include_ssh: bool = False) -> None:
    """Delete current managed state using code-owned paths, never manifest paths."""

    remove_paths(managed_state_paths(include_ssh=include_ssh))


def normalize_restored_config_permissions() -> None:
    config = managed_config_dir()
    if not config.is_dir():
        return
    os.chmod(config, 0o700)
    for child in config.iterdir():
        if child.is_file():
            os.chmod(child, 0o600)


def _restore_stage(
    name: str,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run one restore stage and keep its name in the terminal error."""

    try:
        return run(argv, env=env, capture=capture)
    except subprocess.CalledProcessError as exc:
        detail = ""
        if capture:
            output = (exc.stderr or exc.stdout or "").strip()
            if output:
                detail = f": {output[-2000:]}"
        raise BackupError(
            f"{name} failed with exit code {exc.returncode}{detail}"
        ) from exc


def restore_control_plane_source() -> Path:
    configured = os.environ.get("EASY_HA_PROXY_SOURCE_DIR")
    return Path(configured or "/opt/easy-ha-proxy/source").resolve()


def preflight_restore_control_plane() -> None:
    """Verify the already-installed offline restore controller before mutation."""

    source = restore_control_plane_source()
    required_sources = (
        source / "install.sh",
        source / "install-local.sh",
        source / "install-remote.sh",
        source / "easy-ha-proxy-helper.sh",
        source / "installer/easy-ha-proxy",
        source / "installer/easy_ha_proxy.py",
        source / "installer/requirements.txt",
        source / "ansible/easy-ha-proxy.yml",
        source / "ansible/requirements.yml",
    )
    missing_sources = [str(path) for path in required_sources if not path.is_file()]
    if missing_sources:
        raise BackupError(
            "Restore control-plane preflight failed: missing trusted source files: "
            + ", ".join(missing_sources)
        )

    home = Path(os.environ.get("EASY_HA_PROXY_HOME", "/opt/easy-ha-proxy"))
    python = home / "venv/bin/python"
    ansible_playbook = home / "venv/bin/ansible-playbook"
    missing_executables = [
        str(path) for path in (python, ansible_playbook) if not os.access(path, os.X_OK)
    ]
    if missing_executables:
        raise BackupError(
            "Restore control-plane preflight failed: missing prepared executables: "
            + ", ".join(missing_executables)
        )

    _restore_stage(
        "Restore control-plane Python dependency check",
        [str(python), "-c", "import ansible, yaml"],
        capture=True,
    )
    _restore_stage(
        "Restore control-plane Ansible check",
        [str(ansible_playbook), "--version"],
        capture=True,
    )


def reconcile_restored_host(*, prepare_entrypoints: bool = True) -> None:
    source = activate_recovery_source()
    if prepare_entrypoints:
        installer = source / "install-local.sh"
        if not installer.is_file():
            raise BackupError("Restored source does not contain install-local.sh.")
        environment = os.environ.copy()
        environment["EASY_HA_PROXY_USE_EXISTING_SOURCE"] = "true"
        _restore_stage(
            "Offline restore entrypoint preparation",
            [
                "bash",
                str(installer),
                "--prepare-only",
                "--skip-bootstrap-dependencies",
            ],
            env=environment,
        )
    reconcile_command = ["/usr/local/bin/easy-ha-proxy", "apply-restored"]
    if os.environ.get(OFFLINE_RESTORE_ENV) == "1":
        reconcile_command.append("--offline")
    _restore_stage("Restored host reconciliation", reconcile_command)


def restore_previous_state(
    rollback: Path,
    *,
    restore_ssh: bool,
    apply: bool,
) -> None:
    """Exactly restore the pre-restore snapshot after a candidate failure."""

    validate_rollback_payload(rollback, include_ssh=restore_ssh)
    remove_managed_state(include_ssh=restore_ssh)
    extract_payload(rollback)
    run(["systemctl", "try-restart", "rsyslog.service"], check=False)
    normalize_restored_config_permissions()
    if apply:
        # The candidate path already validated the installed controller and
        # repaired stable entrypoints. Re-running installer preparation here
        # could turn one environmental failure into a false rollback failure.
        reconcile_restored_host(prepare_entrypoints=False)


def recovery_source_archive_path(
    managed: Path,
    *,
    timestamp: str | None = None,
    pid: int | None = None,
) -> Path:
    """Return a collision-safe diagnostic path beside the managed source."""

    timestamp = timestamp or dt.datetime.now(dt.timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )
    pid = os.getpid() if pid is None else pid
    base = managed.parent / f"source.from-backup.{timestamp}.{pid}"
    for counter in range(10_000):
        candidate = base if counter == 0 else Path(f"{base}.{counter}")
        if not os.path.lexists(candidate):
            return candidate
    raise BackupError(
        f"Cannot allocate a diagnostic source archive path beside {managed}."
    )


def activate_recovery_source() -> Path:
    """Promote the controller's recovery source over source from the archive."""
    managed = Path("/opt/easy-ha-proxy/source")
    configured = os.environ.get("EASY_HA_PROXY_SOURCE_DIR")
    if not configured:
        return managed

    recovery = Path(configured).resolve()
    if recovery == managed.resolve():
        return managed
    required = (
        recovery / "install-local.sh",
        recovery / "installer/easy_ha_proxy.py",
        recovery / "ansible/easy-ha-proxy.yml",
        recovery / "ansible/requirements.yml",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise BackupError(
            "Recovery source is incomplete: " + ", ".join(missing)
        )

    managed.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    staged = managed.parent / f".source.restore.next.{os.getpid()}"
    archived = recovery_source_archive_path(managed)
    if staged.exists():
        raise BackupError(f"Recovery source staging path already exists: {staged}")
    shutil.copytree(recovery, staged, symlinks=True)
    run(["chown", "-R", "root:root", str(staged)])
    os.chmod(staged, 0o755)

    previous_moved = False
    try:
        if managed.exists():
            os.replace(managed, archived)
            previous_moved = True
        os.replace(staged, managed)
    except Exception:
        if staged.exists():
            shutil.rmtree(staged)
        if previous_moved and archived.exists() and not managed.exists():
            os.replace(archived, managed)
        raise

    os.environ["EASY_HA_PROXY_SOURCE_DIR"] = str(managed)
    print(f"Recovery source activated: {managed}")
    if previous_moved:
        print(f"Source restored from backup preserved at: {archived}")
    return managed


def restore_backup(args: argparse.Namespace) -> None:
    require_root()
    archive = Path(args.archive).expanduser().resolve()
    verify_encrypted_archive(archive)
    password = read_passphrase(
        confirm=False,
        from_stdin=bool(getattr(args, "passphrase_stdin", False)),
    )
    with tempfile.TemporaryDirectory(prefix="easy-ha-proxy-restore.") as temporary:
        work = Path(temporary)
        manifest, payload, ssh_payload = validate_backup_archive(
            archive,
            password,
            work,
            outer_checksum_verified=True,
        )

        installed = (managed_config_dir() / "metadata.yml").is_file()
        mode = args.mode
        if mode == "auto":
            mode = "overlay" if installed else "fresh"
        if mode == "fresh" and installed:
            raise BackupError("Fresh restore refuses to overwrite an installed server.")
        if mode == "overlay" and not installed:
            raise BackupError("Overlay restore requires an existing managed installation.")

        scope = str(getattr(args, "scope", "full") or "full")
        if scope == "config":
            if not installed:
                raise BackupError(
                    "Configuration-scope restore requires an installed server."
                )
            if bool(getattr(args, "restore_ssh", False)):
                raise BackupError(
                    "SSH keys are not part of a configuration-scope restore."
                )
            restore_config_scope(args, manifest, payload)
            return

        restore_ssh = False
        if ssh_payload is not None and not args.skip_ssh:
            restore_ssh = args.restore_ssh
            if not restore_ssh:
                answer = input(
                    "Restore archived SSH host/private/authorized keys? [y/N]: "
                ).strip().lower()
                restore_ssh = answer in {"y", "yes", "д", "да"}

        print("\nFull restore plan:")
        print(f"  archive host: {manifest.get('hostname', 'unknown')}")
        print(f"  created:      {manifest.get('created_at', 'unknown')}")
        print(f"  mode:         {mode}")
        print(
            "  managed state: "
            + (
                "replace exactly"
                if bool(getattr(args, "replace_managed", False))
                else "overlay"
            )
        )
        print(f"  SSH keys:     {'restore' if restore_ssh else 'keep current'}")
        if not bool(getattr(args, "yes", False)):
            confirmation = input("Type RESTORE to continue: ").strip()
            if confirmation != "RESTORE":
                raise BackupError("Restore cancelled.")

        if args.apply:
            # A web restore runs inside the hardened backup broker, where APT
            # is intentionally unable to switch to the _apt uid. Verify that
            # the already-installed Python/Ansible controller is complete
            # before stopping services, taking a rollback snapshot, or
            # replacing any managed path. The destructive phase then remains
            # fully offline with respect to dependency managers.
            preflight_restore_control_plane()

        saved_keys = current_authorized_keys() if restore_ssh else {}
        rollback: Path | None = None
        # Resolve the rollback set from the controller's code-owned allowlist
        # and verify capacity before any service is stopped or file is changed.
        rollback_paths = managed_state_paths(include_ssh=restore_ssh)
        preflight_restore_space(
            manifest,
            rollback_paths,
            replace_managed=bool(getattr(args, "replace_managed", False)),
            restore_ssh=restore_ssh,
        )
        with Quiesce(True, stop_containers=True) as quiesce:
            # Snapshot all currently managed paths from the trusted code
            # allowlist. The archive's manifest never authorizes what can be
            # read, removed, or restored on this host.
            rollback = create_pre_restore_backup(rollback_paths)
            if rollback:
                print(f"Pre-restore rollback archive: {rollback}")
            try:
                if bool(getattr(args, "replace_managed", False)):
                    remove_paths(rollback_paths)
                extract_payload(payload)
                # Extraction replaced /var/log/haproxy.log with the archived
                # copy; rsyslog still writes to the old inode until restarted,
                # which would leave the banned-IP log viewer without fresh
                # lines.
                run(["systemctl", "try-restart", "rsyslog.service"], check=False)
                disable_restored_runtime_firewall_state()
                if restore_ssh:
                    extract_payload(ssh_payload)
                    merge_authorized_keys(saved_keys)
                normalize_restored_config_permissions()
                if args.apply:
                    # Reconciliation ends with a status check that expects the
                    # quiesced timers to be active again.
                    quiesce.resume_units()
                    reconcile_restored_host()
            except (Exception, KeyboardInterrupt) as restore_error:
                if rollback is None:
                    raise BackupError(
                        "Restore failed and no previous managed state was available "
                        f"for automatic rollback: {restore_error}"
                    ) from restore_error
                try:
                    quiesce.resume_units()
                    restore_previous_state(
                        rollback,
                        restore_ssh=restore_ssh,
                        apply=bool(args.apply and installed),
                    )
                except (Exception, KeyboardInterrupt) as rollback_error:
                    raise BackupError(
                        "Restore failed and automatic rollback also failed. "
                        f"Restore error: {restore_error}. "
                        f"Rollback archive: {rollback}. "
                        f"Rollback error: {rollback_error}"
                    ) from rollback_error
                cleanup_pre_restore_backup(rollback)
                raise BackupError(
                    "Restore failed; the previous managed state was restored "
                    "automatically. "
                    f"Restore error: {restore_error}"
                ) from restore_error

    cleanup_pre_restore_backup(rollback)
    print("\nFiles restored successfully.")
    if args.apply:
        print("The restored host was reconciled successfully.")
    else:
        print("Run 'sudo easy-ha-proxy apply-restored' to reconcile the restored host.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="easy-ha-proxy-full-backup")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup = subparsers.add_parser("backup")
    backup.add_argument("--output-dir")
    backup.add_argument("--include-ssh", action="store_true")
    backup.add_argument("--no-quiesce", dest="quiesce", action="store_false")
    backup.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read one passphrase line from stdin instead of prompting",
    )
    backup.set_defaults(func=create_backup, quiesce=True)
    restore = subparsers.add_parser("restore")
    restore.add_argument("archive")
    restore.add_argument("--mode", choices=("auto", "fresh", "overlay"), default="auto")
    restore.add_argument(
        "--scope",
        choices=("full", "config"),
        default="full",
        help=(
            "full restores every managed path; config restores only sites, "
            "their settings and certificates on an installed server"
        ),
    )
    restore.add_argument("--restore-ssh", action="store_true")
    restore.add_argument("--skip-ssh", action="store_true")
    restore.add_argument("--apply", action="store_true")
    restore.add_argument(
        "--replace-managed",
        action="store_true",
        help=(
            "remove current allowlisted easy-ha-proxy state before extraction; "
            "automatic rollback restores the previous managed snapshot on failure"
        ),
    )
    restore.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read one passphrase line from stdin instead of prompting",
    )
    restore.add_argument(
        "--yes",
        action="store_true",
        help="skip the RESTORE confirmation prompt",
    )
    restore.set_defaults(func=restore_backup)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("archive")
    inspect.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read one passphrase line from stdin instead of prompting",
    )
    inspect.set_defaults(func=inspect_backup)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except (
        BackupError,
        OSError,
        json.JSONDecodeError,
        tarfile.TarError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
