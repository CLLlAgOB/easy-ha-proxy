#!/usr/bin/env python3
"""Build a read-only, machine-readable easy-ha-proxy update plan.

The checker intentionally does not mutate APT state, fetch Git objects into the
managed checkout, or pull Docker images.  It is suitable for use by the local
maintenance CLI and by a narrowly privileged host broker.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable, Protocol, Sequence


SCHEMA_VERSION = 1
VALID_STATES = frozenset({"available", "current", "unknown", "blocked"})
VALID_SOURCE_CHANNELS = frozenset({"github", "local"})
VALID_IMAGE_CHANNELS = frozenset({"latest", "alpha"})

DEFAULT_SOURCE_DIR = Path("/opt/easy-ha-proxy/source")
DEFAULT_CONFIG_DIR = Path("/etc/easy-ha-proxy")
DEFAULT_AUTHELIA_COMPOSE = Path("/opt/authelia/docker-compose.yml")
DEFAULT_ADMIN_COMPOSE = Path("/opt/haproxy-admin/docker-compose.yml")
DEFAULT_REPOSITORY = "https://github.com/CLLlAgOB/easy-ha-proxy.git"
DEFAULT_BRANCH = "main"

GIT_TIMEOUT = 20.0
APT_TIMEOUT = 45.0
COMPOSE_TIMEOUT = 15.0
REGISTRY_TIMEOUT = 30.0
CLONE_TIMEOUT = 60.0

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40,64}")
_BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_URI_USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_?token|api_?key|key|password|passwd|secret|token)=)[^&#\s]+"
)

SERVICE_SOURCE_PATHS: tuple[Path, ...] = (
    Path("ansible/easy-ha-proxy.yml"),
    Path("ansible/roles/authelia"),
    Path("ansible/roles/cert"),
    Path("ansible/roles/docker"),
    Path("ansible/roles/geoip_acl"),
    Path("ansible/roles/haproxy"),
    Path("ansible/roles/haproxy-admin"),
    Path("ansible/roles/healthcheck"),
    Path("ansible/roles/update_packages"),
)


@dataclass(frozen=True)
class CommandResult:
    """A bounded subprocess result which never raises for probe failures."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        """Run one fixed argv without a shell."""


class SubprocessRunner:
    """Production command runner with deterministic locale and hard timeouts."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        command = tuple(str(value) for value in argv)
        environment = os.environ.copy()
        environment.update(
            {
                "LC_ALL": "C",
                "LANG": "C",
                "GIT_TERMINAL_PROMPT": "0",
                "DEBIAN_FRONTEND": "noninteractive",
            }
        )
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            return CommandResult(127, stderr=str(exc), error="not-found")
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return CommandResult(124, stdout, stderr, error="timeout")
        except OSError as exc:
            return CommandResult(126, stderr=str(exc), error="os-error")
        return CommandResult(
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )


DAEMON_ARTIFACTS: tuple[tuple[str, str, Path, Path], ...] = (
    (
        "haproxy-certd",
        "HAProxy certificate daemon",
        Path("/usr/local/sbin/haproxy-certd.py"),
        Path("ansible/roles/haproxy-admin/files/haproxy-certd.py"),
    ),
    (
        "haproxy-controld",
        "HAProxy control daemon",
        Path("/usr/local/sbin/haproxy-controld.py"),
        Path("ansible/roles/haproxy-admin/files/haproxy-controld.py"),
    ),
    (
        "haproxy-healthd",
        "HAProxy health daemon",
        Path("/usr/local/sbin/haproxy-healthd.py"),
        Path("ansible/roles/haproxy-admin/files/haproxy-healthd.py"),
    ),
    (
        "easy-ha-proxy-backupd",
        "Encrypted backup and restore broker",
        Path("/usr/local/sbin/easy-ha-proxy-backupd.py"),
        Path("ansible/roles/haproxy-admin/files/easy-ha-proxy-backupd.py"),
    ),
    (
        "easy-ha-proxy-updated",
        "Software update broker",
        Path("/usr/local/sbin/easy-ha-proxy-updated.py"),
        Path("ansible/roles/haproxy-admin/files/easy-ha-proxy-updated.py"),
    ),
    (
        "authelia-configd",
        "Authelia configuration daemon",
        Path("/usr/local/sbin/authelia-configd.py"),
        Path("ansible/roles/authelia/files/authelia-configd.py"),
    ),
    (
        "authelia-usersd",
        "Authelia users daemon",
        Path("/usr/local/sbin/authelia-usersd.py"),
        Path("ansible/roles/authelia/files/authelia-usersd.py"),
    ),
    (
        "authelia-bansd",
        "Authelia bans daemon",
        Path("/usr/local/sbin/authelia-bansd.py"),
        Path("ansible/roles/authelia/files/authelia-bansd.py"),
    ),
)


def _component(
    component_id: str,
    state: str,
    summary: str,
    *,
    current_version: str | int | None = None,
    available_version: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if state not in VALID_STATES:
        raise ValueError(f"Unsupported update state: {state}")
    return {
        "id": component_id,
        "state": state,
        "actionable": state == "available",
        "summary": summary,
        "current_version": current_version,
        "available_version": available_version,
        # Stable aliases used by the host broker when signing a checked plan.
        "installed": current_version,
        "available": available_version,
        "candidate": available_version,
        "details": details or {},
    }


def _read_mapping(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.is_file():
        return {}, None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {}, f"Could not read {path}: {exc}"
    try:
        import yaml  # type: ignore[import-untyped]

        loaded = yaml.safe_load(text)
    except ImportError:
        # The installer venv includes PyYAML.  This small fallback keeps the
        # standalone checker useful with system Python for scalar metadata.
        loaded = _parse_scalar_yaml(text)
    except Exception as exc:  # PyYAML reports several parser exception types.
        return {}, f"Could not parse {path}: {exc}"
    if loaded is None:
        return {}, None
    if not isinstance(loaded, dict):
        return {}, f"Expected a YAML mapping in {path}"
    return loaded, None


def _parse_scalar_yaml(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line or raw_line[0].isspace() or raw_line.lstrip().startswith("#"):
            continue
        key, separator, raw_value = raw_line.partition(":")
        if not separator or not re.fullmatch(r"[A-Za-z0-9_]+", key):
            continue
        value = raw_value.strip()
        if not value:
            continue
        if value[0:1] == value[-1:] and value[0:1] in {"'", '"'}:
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        values[key] = value
    return values


def _redact_sensitive_text(value: str) -> str:
    value = _URI_USERINFO_RE.sub(r"\1***@", value)
    return _SECRET_QUERY_RE.sub(r"\1***", value)


def _short_error(result: CommandResult) -> str:
    if result.error == "timeout":
        return "probe timed out"
    if result.error == "not-found":
        return "required command is not installed"
    message = (result.stderr or result.stdout).strip().splitlines()
    if not message:
        return f"command exited with {result.returncode}"
    return _redact_sensitive_text(message[0])[:240]


def _valid_branch(branch: str) -> bool:
    return bool(
        _BRANCH_RE.fullmatch(branch)
        and ".." not in branch
        and not branch.endswith("/")
        and "//" not in branch
    )


SOURCE_REVISION_MARKER = ".easy-ha-proxy-source-revision"


def _git_checkout_revision(
    *, source_dir: Path, branch: str, runner: Runner
) -> tuple[str | None, dict[str, Any] | None]:
    """Return (revision, None) or (None, blocking-component) for a git checkout."""

    revision_result = runner.run(
        ("git", "-C", str(source_dir), "rev-parse", "HEAD"),
        timeout=GIT_TIMEOUT,
    )
    if revision_result.returncode != 0:
        return None, _component(
            "all",
            "unknown",
            "The installed Git revision could not be read.",
            details={"reason": "git-revision-failed", "error": _short_error(revision_result)},
        )
    revision_match = _REVISION_RE.search(revision_result.stdout.lower())
    if not revision_match:
        return None, _component(
            "all",
            "unknown",
            "The installed Git revision was not valid.",
            details={"reason": "invalid-local-revision"},
        )
    local_revision = revision_match.group(0)

    # core.fileMode=false suppresses permission-only drift introduced by
    # controller-to-server source synchronization while retaining content and
    # untracked-file changes.
    status_result = runner.run(
        (
            "git",
            "-C",
            str(source_dir),
            "-c",
            "core.fileMode=false",
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ),
        timeout=GIT_TIMEOUT,
    )
    if status_result.returncode != 0:
        return None, _component(
            "all",
            "unknown",
            "Local source changes could not be inspected.",
            current_version=local_revision,
            details={"reason": "git-status-failed", "error": _short_error(status_result)},
        )
    changes = [line for line in status_result.stdout.splitlines() if line.strip()]
    if changes:
        return None, _component(
            "all",
            "blocked",
            "The managed source has local content changes and will not be replaced automatically.",
            current_version=local_revision,
            details={
                "reason": "local-source-changes",
                "branch": branch,
                "changed_paths": len(changes),
                "network_checked": False,
            },
        )
    return local_revision, None


def _recorded_source_revision(
    *, source_dir: Path, branch: str
) -> tuple[str | None, dict[str, Any] | None]:
    """Read the revision marker written when the source tarball was packaged.

    Returns (revision, None) when a clean recorded commit is available, or
    (None, component) describing why the remote revision cannot be compared.
    """

    marker = source_dir / SOURCE_REVISION_MARKER
    if not marker.is_file():
        return None, _component(
            "all",
            "unknown",
            "The managed source is not a Git checkout and carries no recorded "
            "revision, so its remote revision cannot be compared safely.",
            details={"reason": "not-a-git-checkout"},
        )
    fields: dict[str, str] = {}
    try:
        for line in marker.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                fields[key.strip()] = value.strip()
    except OSError as exc:
        return None, _component(
            "all",
            "unknown",
            "The recorded source revision could not be read.",
            details={"reason": "revision-marker-unreadable", "error": str(exc)},
        )
    revision_match = _REVISION_RE.search((fields.get("revision") or "").lower())
    if not revision_match:
        return None, _component(
            "all",
            "unknown",
            "The recorded source revision is missing or invalid; reinstall or "
            "re-synchronize the source to record it.",
            details={"reason": "invalid-recorded-revision"},
        )
    if (fields.get("dirty") or "").strip().lower() == "true":
        return None, _component(
            "all",
            "blocked",
            "The source was synchronized from a working tree with uncommitted "
            "changes, so it cannot be compared to the remote branch. Commit and "
            "push the changes, then re-synchronize.",
            current_version=revision_match.group(0),
            details={
                "reason": "recorded-source-dirty",
                "branch": branch,
                "network_checked": False,
            },
        )
    return revision_match.group(0), None


def _probe_source(
    *,
    source_dir: Path,
    channel: str,
    branch: str,
    repository: str,
    runner: Runner,
) -> dict[str, Any]:
    if channel == "local":
        return _component(
            "all",
            "blocked",
            "Git source checks are disabled for the local source channel.",
            details={"reason": "local-source-channel", "network_checked": False},
        )
    if not source_dir.is_dir():
        return _component(
            "all",
            "blocked",
            "The managed source directory is missing.",
            details={"reason": "source-directory-missing"},
        )

    if (source_dir / ".git").is_dir():
        # A real git checkout (direct on-box install): read HEAD and the working
        # tree state from git itself.
        local_revision, dirty_component = _git_checkout_revision(
            source_dir=source_dir, branch=branch, runner=runner
        )
        if dirty_component is not None:
            return dirty_component
        origin_result = runner.run(
            ("git", "-C", str(source_dir), "remote", "get-url", "origin"),
            timeout=GIT_TIMEOUT,
        )
        origin = (
            origin_result.stdout.strip()
            if origin_result.returncode == 0
            else repository
        )
    else:
        # A synced/tarball install keeps no .git. The packaging step records the
        # exact commit in a marker file so the remote branch can still be
        # compared without a checkout (option B). The candidate clone below uses
        # the configured repository URL.
        local_revision, marker_component = _recorded_source_revision(
            source_dir=source_dir, branch=branch
        )
        if marker_component is not None:
            return marker_component
        origin = repository

    if not origin or any(character in origin for character in "\r\n\x00"):
        return _component(
            "all",
            "unknown",
            "The source repository is not configured.",
            current_version=local_revision,
            details={"reason": "repository-missing"},
        )
    remote_result = runner.run(
        (
            "git",
            "ls-remote",
            "--heads",
            "--",
            origin,
            f"refs/heads/{branch}",
        ),
        timeout=GIT_TIMEOUT,
    )
    remote_match = _REVISION_RE.search(remote_result.stdout.lower())
    if remote_result.returncode != 0 or not remote_match:
        return _component(
            "all",
            "unknown",
            "The remote source revision could not be checked.",
            current_version=local_revision,
            details={
                "reason": "remote-revision-unavailable",
                "branch": branch,
                "error": _short_error(remote_result),
            },
        )
    remote_revision = remote_match.group(0)
    if local_revision == remote_revision:
        return _component(
            "all",
            "current",
            "The managed source is current.",
            current_version=local_revision,
            available_version=remote_revision,
            details={"branch": branch},
        )
    return _component(
            "all",
        "available",
        "A different remote managed source revision is available.",
        current_version=local_revision,
        available_version=remote_revision,
        details={"branch": branch},
    )


def _remote_candidate(
    *,
    source_dir: Path,
    repository: str,
    branch: str,
    expected_revision: str,
    destination: Path,
    runner: Runner,
) -> tuple[Path | None, str | None]:
    # A tarball install has no checkout to read the origin from; use the
    # configured repository URL directly. Only a real checkout is asked for its
    # own origin (which may legitimately differ from the metadata default).
    if (source_dir / ".git").is_dir():
        origin_result = runner.run(
            ("git", "-C", str(source_dir), "remote", "get-url", "origin"),
            timeout=GIT_TIMEOUT,
        )
        origin = (
            origin_result.stdout.strip()
            if origin_result.returncode == 0
            else repository
        )
    else:
        origin = repository
    if not origin or any(character in origin for character in "\r\n\x00"):
        return None, "repository-missing"
    clone_result = runner.run(
        (
            "git",
            "clone",
            "--quiet",
            "--depth=1",
            "--single-branch",
            "--branch",
            branch,
            "--",
            origin,
            str(destination),
        ),
        timeout=CLONE_TIMEOUT,
    )
    if clone_result.returncode != 0:
        return None, f"candidate-clone-failed: {_short_error(clone_result)}"
    revision_result = runner.run(
        ("git", "-C", str(destination), "rev-parse", "HEAD"),
        timeout=GIT_TIMEOUT,
    )
    revision_match = _REVISION_RE.search(revision_result.stdout.lower())
    if revision_result.returncode != 0 or not revision_match:
        return None, "candidate-revision-unavailable"
    if revision_match.group(0) != expected_revision:
        return None, "candidate-revision-changed-during-check"
    return destination, None


def _service_fingerprint(root: Path) -> str | None:
    excluded = {relative.as_posix() for _, _, _, relative in DAEMON_ARTIFACTS}
    files: dict[str, Path] = {}
    for selected in SERVICE_SOURCE_PATHS:
        path = root / selected
        if path.is_file():
            files[selected.as_posix()] = path
            continue
        if not path.is_dir():
            continue
        for candidate in path.rglob("*"):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(root).as_posix()
            if (
                relative in excluded
                or "/__pycache__/" in f"/{relative}/"
                or relative.endswith(".pyc")
                or relative.endswith("haproxy-admin.zip")
            ):
                continue
            files[relative] = candidate
    if not files:
        return None
    digest = hashlib.sha256()
    try:
        for relative, path in sorted(files.items()):
            digest.update(relative.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(_sha256(path).encode("ascii"))
            digest.update(b"\x00")
    except OSError:
        return None
    return digest.hexdigest()


def _probe_services(
    source: dict[str, Any],
    channel: str,
    *,
    installed_source: Path,
    candidate_source: Path | None,
    candidate_error: str | None,
) -> dict[str, Any]:
    if channel == "local":
        return _component(
            "services",
            "blocked",
            "Remote host-service checks are disabled for the local source channel.",
            details={"reason": "local-source-channel", "network_checked": False},
        )
    state = str(source["state"])
    if state == "available":
        if candidate_source is None:
            return _component(
                "services",
                "unknown",
                "The remote source changed, but its host-service files could not be classified.",
                current_version=source.get("current_version"),
                available_version=source.get("available_version"),
                details={
                    "reason": "source-diff-unclassified",
                    "candidate_error": candidate_error,
                    "depends_on": "all",
                },
            )
        installed_fingerprint = _service_fingerprint(installed_source)
        candidate_fingerprint = _service_fingerprint(candidate_source)
        if installed_fingerprint is None or candidate_fingerprint is None:
            return _component(
                "services",
                "unknown",
                "Host-service source files could not be fingerprinted.",
                current_version=installed_fingerprint,
                available_version=candidate_fingerprint,
                details={"reason": "service-fingerprint-unavailable", "depends_on": "all"},
            )
        if installed_fingerprint == candidate_fingerprint:
            return _component(
                "services",
                "current",
                "The remote source does not change host-service files.",
                current_version=installed_fingerprint,
                available_version=candidate_fingerprint,
                details={"depends_on": "all"},
            )
        return _component(
            "services",
            "available",
            "The remote source contains different host-service files.",
            current_version=installed_fingerprint,
            available_version=candidate_fingerprint,
            details={"reason": "source-update", "depends_on": "all"},
        )
    if state == "current":
        return _component(
            "services",
            "current",
            "Host services are based on the current managed source revision.",
            current_version=source.get("current_version"),
            available_version=source.get("available_version"),
            details={"depends_on": "all"},
        )
    if state == "blocked":
        return _component(
            "services",
            "blocked",
            "Host-service updates are blocked until the source issue is resolved.",
            current_version=source.get("current_version"),
            available_version=source.get("available_version"),
            details={"reason": "source-blocked", "depends_on": "all"},
        )
    return _component(
        "services",
        "unknown",
        "Host-service updates could not be determined because the source state is unknown.",
        current_version=source.get("current_version"),
        available_version=source.get("available_version"),
        details={"reason": "source-unknown", "depends_on": "all"},
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_daemons(
    source_dir: Path,
    *,
    artifact_path: Callable[[Path], Path] | None = None,
    remote_candidate_required: bool = False,
    candidate_error: str | None = None,
) -> dict[str, Any]:
    resolve_installed = artifact_path or (lambda path: path)
    artifacts: list[dict[str, Any]] = []
    available = False
    unknown = False
    checked = 0
    for artifact_id, label, installed_path, relative_source in DAEMON_ARTIFACTS:
        source_path = source_dir / relative_source
        installed = resolve_installed(installed_path)
        item: dict[str, Any] = {"id": artifact_id, "label": label}
        if not source_path.is_file():
            item.update({"state": "unknown", "reason": "source-file-missing"})
            unknown = True
            artifacts.append(item)
            continue
        try:
            source_digest = _sha256(source_path)
            installed_digest = _sha256(installed) if installed.is_file() else None
        except OSError as exc:
            item.update({"state": "unknown", "reason": "read-failed", "error": str(exc)})
            unknown = True
            artifacts.append(item)
            continue
        checked += 1
        item["current_digest"] = installed_digest
        item["available_digest"] = source_digest
        if installed_digest == source_digest:
            item["state"] = "current"
        else:
            item["state"] = "available"
            item["reason"] = (
                "installed-file-missing"
                if installed_digest is None
                else "digest-mismatch"
            )
            available = True
        artifacts.append(item)

    details = {
        "comparison": "installed-files-to-managed-source",
        "artifacts": artifacts,
    }
    if remote_candidate_required:
        return _component(
            "daemons",
            "unknown",
            "The remote source changed, but its helper daemon files could not "
            "be compared safely.",
            current_version=f"{checked}/{len(artifacts)} checked locally",
            details={
                **details,
                "reason": "remote-candidate-unavailable",
                "candidate_error": candidate_error,
            },
        )
    if available:
        return _component(
            "daemons",
            "available",
            "One or more helper daemons differ from the managed source.",
            current_version=(
                f"{sum(item['state'] == 'current' for item in artifacts)}"
                f"/{len(artifacts)}"
            ),
            available_version=f"{sum(item['state'] == 'available' for item in artifacts)} updates",
            details=details,
        )
    if checked == 0:
        return _component(
            "daemons",
            "blocked",
            "Helper daemon source files are unavailable.",
            details={**details, "reason": "daemon-sources-missing"},
        )
    if unknown:
        return _component(
            "daemons",
            "unknown",
            "Some helper daemon versions could not be checked.",
            current_version=f"{checked}/{len(artifacts)} checked",
            details=details,
        )
    return _component(
        "daemons",
        "current",
        "Installed helper daemons match the managed source.",
        current_version=f"{checked}/{len(artifacts)} current",
        available_version=f"{checked}/{len(artifacts)} current",
        details=details,
    )


def _probe_os(runner: Runner) -> dict[str, Any]:
    result = runner.run(("apt-get", "-s", "upgrade"), timeout=APT_TIMEOUT)
    if result.returncode != 0:
        state = "blocked" if result.error == "not-found" else "unknown"
        return _component(
            "os",
            state,
            "Upgradeable operating-system packages could not be checked.",
            details={"reason": "apt-simulation-failed", "error": _short_error(result)},
        )
    packages: list[str] = []
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("Inst "):
            continue
        match = re.match(
            r"^Inst\s+(?P<name>\S+)(?:\s+\[[^\]]*\])?\s+"
            r"\((?P<version>\S+)(?:\s|\))",
            line,
        )
        if match is None:
            return _component(
                "os",
                "unknown",
                "An operating-system package candidate could not be parsed "
                "safely from the APT simulation.",
                details={
                    "reason": "apt-candidate-unparseable",
                    "line": _redact_sensitive_text(line)[:512],
                },
            )
        name = match.group("name")
        version = match.group("version")
        if name not in seen:
            packages.append(name)
            candidates.append({"name": name, "version": version})
            seen.add(name)
    if packages:
        return _component(
            "os",
            "available",
            f"{len(packages)} operating-system package update(s) are available.",
            current_version=None,
            available_version=len(packages),
            details={
                "package_count": len(packages),
                "packages": packages,
                "candidates": candidates,
            },
        )
    return _component(
        "os",
        "current",
        "No operating-system package updates are present in the current APT cache.",
        current_version=0,
        available_version=0,
        details={"package_count": 0, "packages": [], "candidates": []},
    )


def _local_digest(stdout: str) -> str | None:
    try:
        loaded = json.loads(stdout.strip())
    except (TypeError, ValueError):
        loaded = None
    if isinstance(loaded, list):
        for value in loaded:
            if isinstance(value, str) and "@" in value:
                match = _DIGEST_RE.search(value.lower())
                if match:
                    return match.group(0)
    match = _DIGEST_RE.search(stdout.lower())
    return match.group(0) if match else None


def _remote_digest(stdout: str) -> str | None:
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "Digest:" and _DIGEST_RE.fullmatch(fields[1].lower()):
            return fields[1].lower()
    return None


def _image_repository(image: str) -> str | None:
    if not image or image.startswith("-") or "://" in image or any(
        character.isspace() or ord(character) < 32 for character in image
    ):
        return None
    without_digest = image.split("@", 1)[0]
    last_slash = without_digest.rfind("/")
    last_colon = without_digest.rfind(":")
    repository = (
        without_digest[:last_colon]
        if last_colon > last_slash
        else without_digest
    )
    return repository or None


def _tagged_image(image: str, channel: str) -> str | None:
    repository = _image_repository(image)
    return f"{repository}:{channel}" if repository else None


def _normalized_tagged_image(image: str) -> str | None:
    repository = _image_repository(image)
    if not repository or "@" in image:
        return None
    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    tag = image[last_colon + 1 :] if last_colon > last_slash else "latest"
    return f"{repository}:{tag}"


def _probe_image(image: str, runner: Runner) -> dict[str, Any]:
    if (
        not image
        or len(image) > 512
        or image.startswith("-")
        or any(character.isspace() or ord(character) < 32 for character in image)
        or "://" in image
        or "?" in image
        or "&" in image
        or ("@" in image and "@sha256:" not in image)
    ):
        return {
            "image": "<invalid>",
            "state": "unknown",
            "reason": "invalid-image-reference",
        }
    if "@sha256:" in image:
        digest = _DIGEST_RE.search(image.lower())
        return {
            "image": image,
            "state": "current",
            "reason": "digest-pinned",
            "current_digest": digest.group(0) if digest else None,
            "available_digest": digest.group(0) if digest else None,
        }
    if image.startswith("sha256:") or re.fullmatch(r"[0-9a-f]{12,64}", image.lower()):
        return {"image": image, "state": "unknown", "reason": "non-registry-reference"}

    local_result = runner.run(
        ("docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"),
        timeout=COMPOSE_TIMEOUT,
    )
    remote_result = runner.run(
        ("docker", "buildx", "imagetools", "inspect", image),
        timeout=REGISTRY_TIMEOUT,
    )
    local = _local_digest(local_result.stdout) if local_result.returncode == 0 else None
    remote = _remote_digest(remote_result.stdout) if remote_result.returncode == 0 else None
    details: dict[str, Any] = {
        "image": image,
        "current_digest": local,
        "available_digest": remote,
    }
    if local is None:
        details.update(
            {
                "state": "unknown",
                "reason": "local-digest-unavailable",
                "error": _short_error(local_result),
            }
        )
    elif remote is None:
        details.update(
            {
                "state": "unknown",
                "reason": "registry-digest-unavailable",
                "error": _short_error(remote_result),
            }
        )
    elif local == remote:
        details["state"] = "current"
    else:
        details["state"] = "available"
    return details


def _probe_compose(
    component_id: str,
    compose_file: Path,
    runner: Runner,
) -> dict[str, Any]:
    if not compose_file.is_file():
        return _component(
            component_id,
            "blocked",
            "The managed Docker Compose file is missing.",
            details={"reason": "compose-file-missing", "compose_file": str(compose_file)},
        )
    compose_result = runner.run(
        ("docker", "compose", "-f", str(compose_file), "config", "--images"),
        timeout=COMPOSE_TIMEOUT,
    )
    if compose_result.returncode != 0:
        state = "blocked" if compose_result.error == "not-found" else "unknown"
        return _component(
            component_id,
            state,
            "The managed Docker image list could not be read.",
            details={
                "reason": "compose-config-failed",
                "compose_file": str(compose_file),
                "error": _short_error(compose_result),
            },
        )
    images = list(
        dict.fromkeys(
            line.strip()
            for line in compose_result.stdout.splitlines()
            if line.strip()
        )
    )
    if not images:
        return _component(
            component_id,
            "unknown",
            "The managed Docker Compose file contains no images.",
            details={"reason": "no-compose-images", "compose_file": str(compose_file)},
        )
    image_results = [_probe_image(image, runner) for image in images]
    available = [item for item in image_results if item["state"] == "available"]
    unknown = [item for item in image_results if item["state"] == "unknown"]
    details = {"compose_file": str(compose_file), "images": image_results}
    if unknown:
        return _component(
            component_id,
            "unknown",
            "One or more managed Docker image versions could not be checked; "
            "the stack cannot be updated partially.",
            details=details,
        )
    if available:
        return _component(
            component_id,
            "available",
            f"{len(available)} managed Docker image update(s) are available.",
            current_version=None,
            available_version=len(available),
            details=details,
        )
    return _component(
        component_id,
        "current",
        "All managed Docker images are current or digest-pinned.",
        current_version=len(image_results),
        available_version=0,
        details=details,
    )


def _probe_admin_compose(
    compose_file: Path,
    runner: Runner,
    *,
    configured_image: str | None,
    configured_channel: str,
    target_channel: str,
) -> dict[str, Any]:
    if not compose_file.is_file():
        return _component(
            "admin-container",
            "blocked",
            "The managed Docker Compose file is missing.",
            details={
                "reason": "compose-file-missing",
                "compose_file": str(compose_file),
            },
        )
    compose_result = runner.run(
        ("docker", "compose", "-f", str(compose_file), "config", "--images"),
        timeout=COMPOSE_TIMEOUT,
    )
    if compose_result.returncode != 0:
        state = "blocked" if compose_result.error == "not-found" else "unknown"
        return _component(
            "admin-container",
            state,
            "The managed HAProxy Admin image could not be read.",
            details={
                "reason": "compose-config-failed",
                "compose_file": str(compose_file),
                "error": _short_error(compose_result),
            },
        )
    images = list(
        dict.fromkeys(
            line.strip()
            for line in compose_result.stdout.splitlines()
            if line.strip()
        )
    )
    configured_repository = (
        _image_repository(configured_image) if configured_image else None
    )
    matching = [
        image
        for image in images
        if configured_repository
        and _image_repository(image) == configured_repository
    ]
    if len(matching) == 1:
        current_image = matching[0]
    elif len(images) == 1:
        current_image = images[0]
    else:
        return _component(
            "admin-container",
            "unknown",
            "The HAProxy Admin image is missing or ambiguous in its Compose file.",
            details={
                "reason": "admin-image-ambiguous",
                "compose_file": str(compose_file),
                "image_count": len(images),
            },
        )
    base_image = configured_image or current_image
    target_image = _tagged_image(base_image, target_channel)
    normalized_current = _normalized_tagged_image(current_image)
    if not target_image or not normalized_current:
        return _component(
            "admin-container",
            "unknown",
            "The HAProxy Admin image reference is invalid.",
            details={
                "reason": "invalid-image-reference",
                "compose_file": str(compose_file),
            },
        )

    local_result = runner.run(
        (
            "docker",
            "image",
            "inspect",
            current_image,
            "--format",
            "{{json .RepoDigests}}",
        ),
        timeout=COMPOSE_TIMEOUT,
    )
    target_result = runner.run(
        ("docker", "buildx", "imagetools", "inspect", target_image),
        timeout=REGISTRY_TIMEOUT,
    )
    local = _local_digest(local_result.stdout) if local_result.returncode == 0 else None
    candidate = (
        _remote_digest(target_result.stdout)
        if target_result.returncode == 0
        else None
    )
    image_detail: dict[str, Any] = {
        "image": target_image,
        "current_image": current_image,
        "target_image": target_image,
        "current_digest": local,
        "available_digest": candidate,
    }
    details = {
        "compose_file": str(compose_file),
        "configured_channel": configured_channel,
        "target_channel": target_channel,
        "images": [image_detail],
    }
    if local is None:
        image_detail.update(
            {
                "state": "unknown",
                "reason": "local-digest-unavailable",
                "error": _short_error(local_result),
            }
        )
        return _component(
            "admin-container",
            "unknown",
            "The installed HAProxy Admin image digest could not be read.",
            details=details,
        )
    if candidate is None:
        image_detail.update(
            {
                "state": "unknown",
                "reason": "registry-digest-unavailable",
                "error": _short_error(target_result),
            }
        )
        return _component(
            "admin-container",
            "unknown",
            "The requested HAProxy Admin channel could not be verified.",
            current_version=local,
            details=details,
        )

    configured_reference = (
        _normalized_tagged_image(configured_image)
        if configured_image
        else target_image
    )
    channel_change = (
        configured_channel != target_channel
        or normalized_current != target_image
        or configured_reference != target_image
    )
    if channel_change:
        image_detail["state"] = "available"
        image_detail["reason"] = "image-channel-change"
        return _component(
            "admin-container",
            "available",
            "The requested HAProxy Admin image channel differs from the deployed channel.",
            current_version=f"{current_image}@{local}",
            available_version=f"{target_image}@{candidate}",
            details=details,
        )
    if local != candidate:
        image_detail["state"] = "available"
        return _component(
            "admin-container",
            "available",
            "A HAProxy Admin image update is available in the selected channel.",
            current_version=local,
            available_version=candidate,
            details=details,
        )
    image_detail["state"] = "current"
    return _component(
        "admin-container",
        "current",
        "The HAProxy Admin image is current in the selected channel.",
        current_version=local,
        available_version=candidate,
        details=details,
    )


def build_update_plan(
    *,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    config_dir: Path = DEFAULT_CONFIG_DIR,
    authelia_compose: Path = DEFAULT_AUTHELIA_COMPOSE,
    admin_compose: Path = DEFAULT_ADMIN_COMPOSE,
    source_channel: str | None = None,
    image_channel: str | None = None,
    branch: str | None = None,
    runner: Runner | None = None,
    now: dt.datetime | None = None,
    artifact_path: Callable[[Path], Path] | None = None,
) -> dict[str, Any]:
    """Return a JSON-serializable, read-only update plan.

    ``artifact_path`` exists for isolated tests; production callers should not
    override it.  Command arguments and managed Compose paths remain fixed in
    the CLI interface.
    """

    metadata, metadata_error = _read_mapping(Path(config_dir) / "metadata.yml")
    variables, variables_error = _read_mapping(Path(config_dir) / "vars.yml")
    configured_image_value = variables.get("haproxy_admin_image")
    configured_image = (
        str(configured_image_value).strip()
        if isinstance(configured_image_value, str)
        else None
    )
    configured_image_reference = (
        _normalized_tagged_image(configured_image) if configured_image else None
    )
    inferred_image_channel = (
        configured_image_reference.rsplit(":", 1)[1]
        if configured_image_reference
        else "latest"
    )
    if inferred_image_channel not in VALID_IMAGE_CHANNELS:
        inferred_image_channel = "latest"
    configured_image_channel = str(
        metadata.get("image_channel") or inferred_image_channel
    ).strip().lower()
    resolved_source_channel = str(
        source_channel or metadata.get("source_channel") or "github"
    ).strip().lower()
    resolved_image_channel = str(
        image_channel or configured_image_channel
    ).strip().lower()
    resolved_branch = str(
        branch
        or metadata.get("branch")
        or os.environ.get("EASY_HA_PROXY_BRANCH")
        or DEFAULT_BRANCH
    ).strip()
    if resolved_source_channel not in VALID_SOURCE_CHANNELS:
        raise ValueError("source_channel must be github or local")
    if resolved_image_channel not in VALID_IMAGE_CHANNELS:
        raise ValueError("image_channel must be latest or alpha")
    if not _valid_branch(resolved_branch):
        raise ValueError("branch contains unsupported characters")

    repository = str(
        os.environ.get("EASY_HA_PROXY_REPOSITORY")
        or metadata.get("repository")
        or DEFAULT_REPOSITORY
    ).strip()
    command_runner = runner or SubprocessRunner()
    source = _probe_source(
        source_dir=Path(source_dir),
        channel=resolved_source_channel,
        branch=resolved_branch,
        repository=repository,
        runner=command_runner,
    )
    with tempfile.TemporaryDirectory(prefix="easy-ha-proxy-update-plan.") as temporary:
        candidate_source: Path | None = None
        candidate_error: str | None = None
        if source["state"] == "available":
            candidate_source, candidate_error = _remote_candidate(
                source_dir=Path(source_dir),
                repository=repository,
                branch=resolved_branch,
                expected_revision=str(source["available_version"]),
                destination=Path(temporary) / "source",
                runner=command_runner,
            )
        comparison_source = candidate_source or Path(source_dir)
        components = [
            source,
            _probe_services(
                source,
                resolved_source_channel,
                installed_source=Path(source_dir),
                candidate_source=candidate_source,
                candidate_error=candidate_error,
            ),
            _probe_daemons(
                comparison_source,
                artifact_path=artifact_path,
                remote_candidate_required=(
                    source["state"] == "available" and candidate_source is None
                ),
                candidate_error=candidate_error,
            ),
            _probe_os(command_runner),
            _probe_compose(
                "authelia-container", Path(authelia_compose), command_runner
            ),
            _probe_admin_compose(
                Path(admin_compose),
                command_runner,
                configured_image=configured_image,
                configured_channel=configured_image_channel,
                target_channel=resolved_image_channel,
            ),
        ]

    if (
        resolved_source_channel == "github"
        and source.get("state") in {"blocked", "unknown"}
    ):
        source_state = str(source.get("state"))
        components[2] = _component(
            "daemons",
            source_state,
            "Helper daemon updates cannot be trusted until the managed Git "
            "source state is resolved.",
            current_version=source.get("current_version"),
            available_version=source.get("available_version"),
            details={
                "reason": (
                    "source-blocked"
                    if source_state == "blocked"
                    else "source-unknown"
                ),
                "depends_on": "all",
            },
        )

    if components[0].get("actionable") is True:
        unavailable_containers = [
            item["id"]
            for item in components
            if item.get("id") in {"authelia-container", "admin-container"}
            and item.get("state") not in {"current", "available"}
        ]
        if unavailable_containers:
            checked_source = components[0]
            components[0] = _component(
                "all",
                "blocked",
                "The complete stack update is blocked until every managed image "
                "candidate can be verified.",
                current_version=checked_source.get("current_version"),
                available_version=checked_source.get("available_version"),
                details={
                    **(checked_source.get("details") or {}),
                    "reason": "container-candidate-unavailable",
                    "blocked_components": unavailable_containers,
                },
            )

    generated_at = now or dt.datetime.now(dt.timezone.utc)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=dt.timezone.utc)
    generated_at = generated_at.astimezone(dt.timezone.utc)
    warnings = [
        _redact_sensitive_text(error)
        for error in (metadata_error, variables_error)
        if error
    ]
    actionable = [item["id"] for item in components if item["actionable"]]
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_channel": resolved_source_channel,
        "image_channel": resolved_image_channel,
        "components": components,
        "has_updates": bool(actionable),
        "actionable_components": actionable,
        "warnings": warnings,
    }
    # Fail here during development if a new field accidentally stops being
    # serializable; callers can safely pass the returned mapping to json.dump.
    json.dumps(plan, ensure_ascii=False)
    return plan


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--source-channel", choices=tuple(sorted(VALID_SOURCE_CHANNELS)))
    parser.add_argument("--image-channel", choices=tuple(sorted(VALID_IMAGE_CHANNELS)))
    parser.add_argument("--branch")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    if args.branch is not None and not _valid_branch(args.branch):
        _argument_parser().error("invalid --branch")
    try:
        plan = build_update_plan(
            source_channel=args.source_channel,
            image_channel=args.image_channel,
            branch=args.branch,
        )
    except (OSError, ValueError) as exc:
        _argument_parser().error(str(exc))
    print(json.dumps(plan, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
