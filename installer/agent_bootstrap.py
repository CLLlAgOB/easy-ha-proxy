"""Fetch the host agent built for the installed source revision.

A fresh host has no agent, and the one an earlier version installed may not
run the playbook yet. CI publishes the native binaries as a scratch image
(``clllagob/haproxy-admin-ui:native-<channel>-<sha12>``) on Docker Hub; this
reads it straight from the registry over HTTPS -- Docker is not installed
yet on a fresh host -- checks the revision label against the source and the
binary against the image's SHA256SUMS, as the native stage does, and
installs the agent. The native stage installs both binaries properly later
in the run.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))
AGENT_MEMBER = "sbin/easy-ha-proxy-agent"
MAX_BLOB = 256 * 1024 * 1024


class BootstrapError(RuntimeError):
    pass


def architecture() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise BootstrapError(f"unsupported architecture {machine}")


def image_reference(variables: dict, revision: str) -> str | None:
    """The pinned native image for these settings, or None when the binaries
    come from somewhere else (a local bundle, an HTTPS release)."""

    if variables.get("native_local_bundle_dir") or variables.get("native_release_base_url"):
        return None
    image = str(variables.get("haproxy_admin_image") or "clllagob/haproxy-admin-ui:latest")
    channel = "alpha" if image.endswith((":alpha", ":go-alpha")) else "latest"
    reference = str(variables.get("native_release_image") or f"clllagob/haproxy-admin-ui:native-{channel}")
    if "{{" in reference:
        reference = f"clllagob/haproxy-admin-ui:native-{channel}"
    if str(variables.get("native_release_pin_revision", True)).lower() not in ("false", "0", "no"):
        reference += "-" + revision[:12]
    return reference


def _get(url: str, token: str, accept: str = "") -> tuple[bytes, str]:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "User-Agent": "easy-ha-proxy"})
    if accept:
        request.add_header("Accept", accept)
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read(MAX_BLOB + 1)
        if len(body) > MAX_BLOB:
            raise BootstrapError(f"{url}: larger than {MAX_BLOB} bytes")
        return body, response.headers.get("Content-Type", "")


def fetch_agent(reference: str, revision: str, arch: str | None = None) -> bytes:
    """The agent binary from the pinned image, verified."""

    name, _, tag = reference.partition(":")
    repo = name if "/" in name else f"library/{name}"
    arch = arch or architecture()
    with urllib.request.urlopen(urllib.request.Request(AUTH.format(repo=repo), headers={"User-Agent": "easy-ha-proxy"}), timeout=60) as r:
        token = json.load(r)["token"]
    body, kind = _get(f"{REGISTRY}/v2/{repo}/manifests/{tag}", token, ACCEPT)
    manifest = json.loads(body)
    if "manifests" in manifest:
        chosen = [m for m in manifest["manifests"]
                  if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == arch]
        if not chosen:
            raise BootstrapError(f"{reference} has no linux/{arch} image")
        body, _ = _get(f"{REGISTRY}/v2/{repo}/manifests/{chosen[0]['digest']}", token, ACCEPT)
        manifest = json.loads(body)
    config, _ = _get(f"{REGISTRY}/v2/{repo}/blobs/{manifest['config']['digest']}", token)
    labels = (json.loads(config).get("config") or {}).get("Labels") or {}
    built = labels.get("org.opencontainers.image.revision", "")
    if revision and built != revision:
        raise BootstrapError(f"{reference} was built from {built or 'an unknown revision'}, not {revision}")
    files: dict[str, bytes] = {}
    for layer in manifest.get("layers", []):
        blob, _ = _get(f"{REGISTRY}/v2/{repo}/blobs/{layer['digest']}", token)
        if hashlib.sha256(blob).hexdigest() != layer["digest"].split(":", 1)[1]:
            raise BootstrapError(f"layer {layer['digest']} does not match its digest")
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
            for member in archive.getmembers():
                path = member.name.lstrip("./")
                if member.isfile() and path in (AGENT_MEMBER, "SHA256SUMS"):
                    files[path] = archive.extractfile(member).read()
    if AGENT_MEMBER not in files or "SHA256SUMS" not in files:
        raise BootstrapError(f"{reference} holds no {AGENT_MEMBER} with SHA256SUMS")
    expected = {}
    for line in files["SHA256SUMS"].decode().splitlines():
        parts = line.split()
        if len(parts) == 2:
            expected[parts[1].lstrip("*").lstrip("./")] = parts[0]
    if hashlib.sha256(files[AGENT_MEMBER]).hexdigest() != expected.get(AGENT_MEMBER):
        raise BootstrapError(f"{AGENT_MEMBER} does not match SHA256SUMS in {reference}")
    return files[AGENT_MEMBER]


def install_agent(binary: bytes, destination: Path) -> None:
    """Replace the agent atomically (a running one keeps its old file)."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".easy-ha-proxy-agent.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(binary)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
