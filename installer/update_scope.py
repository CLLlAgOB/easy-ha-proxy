#!/usr/bin/env python3
"""Which playbook steps a source change actually needs.

A full update runs every stage of the playbook -- certificates, the HAProxy
package, AppArmor, GeoIP, Docker, Authelia, every daemon -- to deliver what is
often one changed daemon and a template. This module compares the source tree
an update would install with the tree the last complete update applied, and
maps each changed file to the stage that deploys it.

The map is deliberately narrow and conservative. A file it does not know --
the playbook itself, a role's defaults or handlers, the Python requirements,
anything new -- means "run the full stack", never "skip it". A file that
deploys nothing (tests, documentation, the web application's source, which
ships as a container image) needs no stage at all.

The comparison is against a record of the last complete update, not against
whatever was on disk before the download. An update that stopped half way, or
a narrower update that refreshed the source without running every stage,
therefore cannot make the next "changes only" run skip what it missed.
"""

from __future__ import annotations

import datetime as dt
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Iterable, Mapping, Sequence


APPLIED_SOURCE_FILE = "applied-source.json"
MANIFEST_SCHEMA = 1
# Directories and files that are never part of the shipped source, even in a
# staged bundle that was not a Git checkout.
_SKIPPED_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules"})
_SKIPPED_PATTERNS = (
    "*.pyc",
    "*.retry",
    ".easy-ha-proxy-source-revision",
    "ansible/cache/*",
    "ansible/tcp.yml",
    "ansible/authelia_users_initial.yml",
    "ansible/roles/cert/files/*.pem",
    "ansible/roles/haproxy-admin.zip",
)
_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
GIT_TIMEOUT = 20.0

FULL = "full"
STATUS_TAG = "status"

# First match wins. A rule maps a source path pattern to the tags that deploy
# it; an empty tuple means the file deploys nothing on the host. Every rule
# naming a stage is checked by a test against the stage's own task file, so
# the map cannot quietly drift from the roles.
_ADMIN = "ansible/roles/haproxy-admin"
_HAPROXY = "ansible/roles/haproxy"
_CERT = "ansible/roles/cert"
_AUTHELIA = "ansible/roles/authelia"
RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Nothing to deploy.
    (".tests/*", ()),
    (".github/*", ()),
    ("LICENSES/*", ()),
    ("LICENSE", ()),
    ("*.md", ()),
    (".gitignore", ()),
    (".gitattributes", ()),
    (".dockerignore", ()),
    # The web application ships as a container image built from these; the
    # "web application" update pulls it. Nothing on the host changes.
    ("Dockerfile", ()),
    ("docker/*", ()),
    # Install entry points and the menu helper run from the source directory
    # itself, and the refreshed source is already in place.
    ("install.sh", ()),
    ("install-local.sh", ()),
    ("install-remote.sh", ()),
    ("easy-ha-proxy-helper.sh", ()),
    # The installer runs from the refreshed source too -- except for its
    # Python dependencies, which only the full update reinstalls.
    ("installer/requirements.txt", (FULL,)),
    ("installer/*", ()),
    # Always run, and the OS packages have their own update.
    ("ansible/roles/healthcheck/*", ()),
    ("ansible/roles/update_packages/*", ()),

    # Adaptive protection.
    (f"{_ADMIN}/files/easy-ha-proxy-guardd.py", ("ha-adm-guardd",)),
    (f"{_ADMIN}/files/scanner-signatures.json", ("ha-adm-guardd",)),
    (f"{_ADMIN}/templates/guardd.json.j2", ("ha-adm-guardd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-guardd.service.j2", ("ha-adm-guardd",)),
    (f"{_ADMIN}/tasks/guardd.yml", ("ha-adm-guardd",)),
    # Metrics.
    (f"{_ADMIN}/files/easy-ha-proxy-metricsd.py", ("ha-adm-metricsd",)),
    (f"{_ADMIN}/templates/metricsd.json.j2", ("ha-adm-metricsd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-metricsd.service.j2", ("ha-adm-metricsd",)),
    (f"{_ADMIN}/tasks/metricsd.yml", ("ha-adm-metricsd",)),
    # Alerts, and the client the other daemons import.
    (f"{_ADMIN}/files/easy-ha-proxy-alertd.py", ("ha-adm-alertd",)),
    (f"{_ADMIN}/files/easy_ha_proxy_alert_client.py", ("ha-adm-alertd",)),
    (f"{_ADMIN}/templates/alertd.json.j2", ("ha-adm-alertd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-alertd.service.j2", ("ha-adm-alertd",)),
    (f"{_ADMIN}/tasks/alertd.yml", ("ha-adm-alertd",)),
    # Health.
    (f"{_ADMIN}/files/haproxy-healthd.py", ("ha-adm-healthd",)),
    (f"{_ADMIN}/templates/healthd.json.j2", ("ha-adm-healthd",)),
    (f"{_ADMIN}/templates/haproxy-healthd.service.j2", ("ha-adm-healthd",)),
    (f"{_ADMIN}/tasks/healthd.yml", ("ha-adm-healthd",)),
    # Control.
    (f"{_ADMIN}/files/haproxy-controld.py", ("ha-adm-controld",)),
    (f"{_ADMIN}/templates/haproxy-controld.service.j2", ("ha-adm-controld",)),
    (f"{_ADMIN}/tasks/controld.yml", ("ha-adm-controld",)),
    # Backups.
    (f"{_ADMIN}/files/easy-ha-proxy-backupd.py", ("ha-adm-backupd",)),
    (f"{_ADMIN}/files/easy-ha-proxy-backup-run.py", ("ha-adm-backupd",)),
    (f"{_ADMIN}/files/easy-ha-proxy-unit-failed.py", ("ha-adm-backupd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-backup.service.j2", ("ha-adm-backupd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-backup.timer.j2", ("ha-adm-backupd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-backupd.service.j2", ("ha-adm-backupd",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-unit-failed@.service.j2", ("ha-adm-backupd",)),
    (f"{_ADMIN}/tasks/backupd.yml", ("ha-adm-backupd",)),
    # The update broker.
    (f"{_ADMIN}/files/easy-ha-proxy-updated.py", ("ha-adm-updated",)),
    (f"{_ADMIN}/templates/easy-ha-proxy-updated.service.j2", ("ha-adm-updated",)),
    (f"{_ADMIN}/tasks/updated.yml", ("ha-adm-updated",)),
    # Certificates: certd is only deployed by the install and daemons stages.
    (f"{_ADMIN}/files/haproxy-certd.py", ("ha-adm-daemons",)),
    (f"{_ADMIN}/files/easy-ha-proxy-cert-deliver.py", ("ha-adm-daemons",)),
    (f"{_ADMIN}/templates/haproxy-certd.service.j2", ("ha-adm-daemons",)),
    (f"{_ADMIN}/tasks/certd.yml", ("ha-adm-daemons",)),
    (f"{_ADMIN}/tasks/dns-plugins.yml", ("ha-adm-daemons",)),
    (f"{_ADMIN}/tasks/daemons.yml", ("ha-adm-daemons",)),
    # Journal retention.
    (f"{_ADMIN}/templates/journal-vacuum.service.j2", ("ha-adm-journald",)),
    (f"{_ADMIN}/templates/journal-vacuum.timer.j2", ("ha-adm-journald",)),
    (f"{_ADMIN}/tasks/journald-retention.yml", ("ha-adm-journald",)),
    # Firewall helpers and the admin host setup.
    (f"{_ADMIN}/files/haproxy_ban.rules", ("ha-adm-install",)),
    (f"{_ADMIN}/files/haproxy-udp-forward.py", ("ha-adm-install",)),
    (f"{_ADMIN}/templates/iptables-haproxy-ban.service.j2", ("ha-adm-install",)),
    (f"{_ADMIN}/templates/iptables-haproxy-udp.service.j2", ("ha-adm-install",)),
    (f"{_ADMIN}/tasks/iptables-ban.yml", ("ha-adm-install",)),
    (f"{_ADMIN}/tasks/iptables-udp.yml", ("ha-adm-install",)),
    (f"{_ADMIN}/tasks/install.yml", ("ha-adm-install",)),
    (f"{_ADMIN}/tasks/fs.yml", ("ha-adm-install",)),
    # The web application's Compose file, environment and start stage are
    # left to the full stack on purpose: starting it also pulls the image,
    # which would update the container without the digest review the "web
    # application" update does.
    # Pulling the image is the web application update's job.
    (f"{_ADMIN}/tasks/update_haproxy_admin.yml", ()),

    # HAProxy.
    # The web application renders the configuration from its own copy of the
    # template, which the admin settings stage refreshes.
    (f"{_HAPROXY}/templates/haproxy.cfg.j2", ("ha-cfg", "ha-adm-cfg")),
    (f"{_HAPROXY}/templates/haproxy-state-dump.*", ("ha-cfg",)),
    (f"{_HAPROXY}/tasks/config.yml", ("ha-cfg",)),
    (f"{_HAPROXY}/files/default-favicon.ico", ("ha-install",)),
    (f"{_HAPROXY}/templates/access_granted.http.j2", ("ha-install",)),
    (f"{_HAPROXY}/templates/maintenance.http.j2", ("ha-install",)),
    (f"{_HAPROXY}/templates/update-admin-rt.*", ("ha-install",)),
    (f"{_HAPROXY}/tasks/install.yml", ("ha-install",)),
    (f"{_HAPROXY}/tasks/fs.yml", ("ha-install",)),
    (f"{_HAPROXY}/tasks/apparmor.yml", ("apparmor",)),
    # A default can change the rendered configuration and what install lays down.
    (f"{_HAPROXY}/defaults/*", ("ha-install", "ha-cfg")),
    (f"{_HAPROXY}/handlers/*", ("ha-install", "ha-cfg")),
    # Run by hand, never by an update.
    (f"{_HAPROXY}/tasks/addadmin.yml", ()),

    # GeoIP: one stage owns the whole role.
    ("ansible/roles/geoip_acl/*", ("geo",)),
    # Docker: likewise.
    ("ansible/roles/docker/*", ("docker",)),

    # Certificate hooks and notifications. Issuance and renewal are not part
    # of any update, full or not.
    (f"{_CERT}/templates/905-haproxy-pems-reload.sh.j2", ("crt-hooks",)),
    (f"{_CERT}/templates/906-deliver-certificates.sh.j2", ("crt-hooks",)),
    (f"{_CERT}/tasks/hooks.yml", ("crt-hooks",)),
    (f"{_CERT}/templates/910-mail-notify.sh.j2", ("crt-notify",)),
    (f"{_CERT}/templates/mail-notify.json.j2", ("crt-notify",)),
    (f"{_CERT}/tasks/notify.yml", ("crt-notify",)),
    (f"{_CERT}/tasks/install.yml", ("crt-install",)),
    (f"{_CERT}/tasks/renew*.yml", ()),
    (f"{_CERT}/templates/_san_flags.j2", ()),
    (f"{_CERT}/tasks/rdg.yml", ()),
    (f"{_CERT}/tasks/test.yml", ()),
    (f"{_CERT}/tasks/backup.yml", ()),
    (f"{_CERT}/tasks/remove_orphans.yml", ()),

    # Authelia's host daemons. Its configuration and container are not
    # mapped: those go through the full stack.
    (f"{_AUTHELIA}/files/authelia-bansd.py", ("aut-daemons",)),
    (f"{_AUTHELIA}/files/authelia-configd.py", ("aut-daemons",)),
    (f"{_AUTHELIA}/files/authelia-usersd.py", ("aut-daemons",)),
    (f"{_AUTHELIA}/templates/authelia-bans.sh.j2", ("aut-daemons",)),
    (f"{_AUTHELIA}/templates/authelia-bansd.service.j2", ("aut-daemons",)),
    (f"{_AUTHELIA}/templates/authelia-configd.service.j2", ("aut-daemons",)),
    (f"{_AUTHELIA}/templates/authelia-usersd.service.j2", ("aut-daemons",)),
    (f"{_AUTHELIA}/tasks/bansd.yml", ("aut-daemons",)),
    (f"{_AUTHELIA}/tasks/configd.yml", ("aut-daemons",)),
    (f"{_AUTHELIA}/tasks/usersd.yml", ("aut-daemons",)),
    (f"{_AUTHELIA}/tasks/daemons.yml", ("aut-daemons",)),
)

# What each step is called on the page and in the log.
TAG_LABELS: dict[str, str] = {
    "ha-cfg": "HAProxy configuration",
    "ha-install": "HAProxy files",
    "apparmor": "AppArmor profile",
    "geo": "GeoIP",
    "docker": "Docker",
    "crt-install": "Certbot",
    "crt-hooks": "Certificate hooks",
    "crt-notify": "Certificate notifications",
    "ha-adm-guardd": "Adaptive protection",
    "ha-adm-metricsd": "Metrics",
    "ha-adm-alertd": "Alerts",
    "ha-adm-healthd": "Health monitor",
    "ha-adm-controld": "HAProxy control service",
    "ha-adm-backupd": "Backups",
    "ha-adm-updated": "Update service",
    "ha-adm-daemons": "Helper daemons",
    "ha-adm-journald": "Journal retention",
    "ha-adm-install": "Admin host setup",
    "ha-adm-cfg": "Web application's copy of the HAProxy template",
    "aut-daemons": "Authelia helper daemons",
}
MAX_LISTED_PATHS = 20


def _skipped(relative: str) -> bool:
    parts = relative.split("/")
    if any(part in _SKIPPED_DIRS for part in parts[:-1]):
        return True
    return any(fnmatchcase(relative, pattern) for pattern in _SKIPPED_PATTERNS)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def _tracked_files(root: Path) -> list[str] | None:
    """The files Git tracks, or None when the tree is not a usable checkout."""
    if not (root / ".git").exists():
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return [name for name in completed.stdout.decode("utf-8", "replace").split("\0") if name]


def source_manifest(root: Path) -> dict[str, str]:
    """{relative path: sha256} for the shipped files under ``root``.

    In a Git checkout only tracked files count, so files the installation
    writes into its own source directory at run time never look like a
    change. A staged bundle has no Git; it is walked, minus the known
    run-time files.
    """
    root = Path(root)
    names = _tracked_files(root)
    if names is None:
        names = [
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
    manifest: dict[str, str] = {}
    for relative in names:
        if _skipped(relative):
            continue
        path = root / relative
        if not path.is_file() or path.is_symlink():
            continue
        manifest[relative] = _file_digest(path)
    return manifest


def changed_paths(applied: Mapping[str, str], candidate: Mapping[str, str]) -> list[str]:
    """Paths the candidate adds or changes.

    A removed file deploys nothing by itself: whatever used to install it is
    a task file, and that task file changes with it.
    """
    return sorted(path for path, digest in candidate.items() if applied.get(path) != digest)


def tags_for_path(relative: str) -> tuple[str, ...] | None:
    """The tags that deploy one path; () for nothing; None when unknown."""
    for pattern, tags in RULES:
        if fnmatchcase(relative, pattern):
            return tags
    return None


def scope_for(paths: Iterable[str]) -> dict[str, Any]:
    """Decide what a set of changed paths needs.

    ``full`` is True when any path is unknown or explicitly needs the whole
    stack; ``tags`` is then empty. Otherwise ``tags`` lists the stages to run
    (always with the status check when anything runs at all).
    """
    changed = sorted(set(paths))
    tags: set[str] = set()
    unmapped: list[str] = []
    full_paths: list[str] = []
    for relative in changed:
        found = tags_for_path(relative)
        if found is None:
            unmapped.append(relative)
        elif FULL in found:
            full_paths.append(relative)
        else:
            tags.update(found)
    needs_full = bool(unmapped or full_paths)
    ordered = [] if needs_full else sorted(tags)
    if ordered:
        ordered.append(STATUS_TAG)
    return {
        "full": needs_full,
        "tags": ordered,
        "steps": [TAG_LABELS.get(tag, tag) for tag in ordered if tag != STATUS_TAG],
        "changed": len(changed),
        "unmapped": (unmapped + full_paths)[:MAX_LISTED_PATHS],
        "paths": changed[:MAX_LISTED_PATHS],
    }


def read_applied(config_dir: Path) -> dict[str, Any] | None:
    """The record of the last complete update, or None when there is none."""
    path = Path(config_dir) / APPLIED_SOURCE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(data, dict)
        or data.get("schema") != MANIFEST_SCHEMA
        or not isinstance(data.get("files"), dict)
        or not data["files"]
    ):
        return None
    files = {
        str(name): str(digest)
        for name, digest in data["files"].items()
        if isinstance(name, str) and isinstance(digest, str)
    }
    return {"revision": str(data.get("revision") or ""), "files": files,
            "recorded_at": str(data.get("recorded_at") or "")}


def write_applied(config_dir: Path, source_root: Path, revision: str | None = None) -> Path:
    """Record ``source_root`` as the tree the last complete update applied."""
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    clean_revision = (revision or "").strip().lower()
    payload = {
        "schema": MANIFEST_SCHEMA,
        "revision": clean_revision if _REVISION_RE.fullmatch(clean_revision) else "",
        "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "files": source_manifest(source_root),
    }
    target = config_dir / APPLIED_SOURCE_FILE
    descriptor, temporary = tempfile.mkstemp(prefix=f".{APPLIED_SOURCE_FILE}.", dir=config_dir)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        os.chmod(temporary, 0o640)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return target


def plan_scope(config_dir: Path, candidate_root: Path) -> dict[str, Any]:
    """What applying ``candidate_root`` needs, for the update plan and the CLI."""
    applied = read_applied(config_dir)
    if applied is None:
        return {
            "ready": False,
            "reason": "no-applied-record",
            "full": True,
            "tags": [],
            "steps": [],
            "changed": 0,
            "unmapped": [],
            "paths": [],
        }
    scope = scope_for(changed_paths(applied["files"], source_manifest(candidate_root)))
    scope["ready"] = not scope["full"]
    scope["reason"] = "unmapped-paths" if scope["full"] else ""
    scope["applied_revision"] = applied["revision"]
    return scope


def tags_text(tags: Sequence[str]) -> str:
    return ",".join(tags)
