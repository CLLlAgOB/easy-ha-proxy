"""Which build the panel and the host run, for the footer.

The operator keeps several gateways and needs to see, on any page, what each
one runs. Two builds meet here: the panel image's, baked in when CI built it,
and the host source's, which the update broker reads from the managed
checkout. Each is a commit -- its time orders builds, its short hash names
one -- and each carries the fingerprint of the web files it holds, so the
footer can say when the panel was built from other web files than the host
has. A panel image reused for later commits (its web files unchanged) keeps
the commit it was first built from; the fingerprints still match.

The release number (the VERSION file) comes from the host's source, since a
reused image would name an older one, and the HAProxy version from HAProxy
itself, over the runtime socket the panel already uses.
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Optional

from . import updates_badge
from .server_time import format_datetime

_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$")
_TREE_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,24})?$")
_HAPROXY_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+~][0-9A-Za-z.+~-]{0,60})?$")
HAPROXY_VERSION_TTL_SECONDS = 300.0
_HAPROXY_VERSION: dict[str, Any] = {"at": None, "value": None}
_HAPROXY_VERSION_LOCK = threading.Lock()


def _version(value: Any) -> str:
    text = str(value or "").strip()
    return text if _VERSION_RE.fullmatch(text) else ""


def _read_haproxy_version() -> Optional[dict[str, str]]:
    """{"short": "3.4.7", "full": "3.4.7-0+ha34+ubuntu24.04u2"} from `show info`."""
    from .utils import SOCKET, haproxy_runtime_command

    try:
        reply = haproxy_runtime_command("show info", SOCKET, timeout=2) or ""
    except (OSError, ValueError):
        return None
    for line in reply.splitlines():
        name, _, value = line.partition(":")
        if name.strip() == "Version":
            full = value.strip()
            if not _HAPROXY_VERSION_RE.fullmatch(full):
                return None
            return {"short": re.split(r"[-+~]", full, maxsplit=1)[0], "full": full}
    return None


def haproxy_version() -> Optional[dict[str, str]]:
    """The running HAProxy's version, asked at most every five minutes."""
    with _HAPROXY_VERSION_LOCK:
        at = _HAPROXY_VERSION["at"]
        if at is not None and time.monotonic() - at < HAPROXY_VERSION_TTL_SECONDS:
            return _HAPROXY_VERSION["value"]
        value = _read_haproxy_version()
        _HAPROXY_VERSION.update(at=time.monotonic(), value=value)
        return value


def _when(value: Any) -> str:
    """The same immutable commit instant, displayed in the gateway's zone."""
    return format_datetime(value)


def _build(revision: Any, committed_at: Any, web_tree: Any) -> Optional[dict[str, str]]:
    revision = str(revision or "").strip().lower()
    if not _REVISION_RE.fullmatch(revision):
        return None
    tree = str(web_tree or "").strip().lower()
    return {
        "revision": revision[:7],
        "when": _when(committed_at),
        "web_tree": tree if _TREE_RE.fullmatch(tree) else "",
    }


def panel_build() -> Optional[dict[str, str]]:
    """The image's own build, from what CI passed when it built it."""

    return _build(
        os.environ.get("EHP_BUILD_REVISION"),
        os.environ.get("EHP_BUILD_DATE"),
        os.environ.get("EHP_SOURCE_TREE"),
    )


def footer() -> dict[str, Any]:
    """Both builds, and whether the panel holds the host's web files.

    match is None when either fingerprint is missing -- an image built by
    hand, or a host the broker could not read -- because then nobody knows.
    """

    panel = panel_build()
    reported = updates_badge.host_build()
    host = (
        _build(reported.get("revision"), reported.get("committed_at"), reported.get("web_tree"))
        if isinstance(reported, dict)
        else None
    )
    match = None
    if panel and host and panel["web_tree"] and host["web_tree"]:
        match = panel["web_tree"] == host["web_tree"]
    version = _version(reported.get("version")) if isinstance(reported, dict) else ""
    return {"panel": panel, "host": host, "match": match,
            "version": version, "haproxy": haproxy_version()}
