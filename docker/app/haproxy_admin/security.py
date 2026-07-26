"""Security boundary for requests forwarded by the trusted HAProxy frontend."""

from __future__ import annotations

import hmac
import os
from typing import FrozenSet

from flask import abort, g, jsonify, request

from .i18n import translate


PROXY_SECRET_HEADER = "X-Easy-HA-Proxy-Secret"
ADMIN_GROUPS: FrozenSet[str] = frozenset({"admins", "superadmin"})
SUPERADMIN_PREFIXES = (
    "/haproxy",
    "/authelia",
    "/system/backups",
    "/system/updates",
)
SUPERADMIN_EXACT = frozenset({"/api/health/control"})
CONTROL_PLANE_HEALTHCHECK_PATH = "/api/control-plane-health"
CONTROL_PLANE_HEALTHCHECK_USER = "easy-ha-proxy-healthcheck"
CONTROL_PLANE_HEALTHCHECK_GROUPS: FrozenSet[str] = frozenset({"healthcheck"})


def normalized_groups(value: str) -> FrozenSet[str]:
    groups: set[str] = set()
    for raw in (value or "").replace(";", ",").split(","):
        group = raw.strip()
        if not group:
            continue
        if group.startswith("group:"):
            group = group.split(":", 1)[1]
        groups.add(group)
    return frozenset(groups)


def _json_error(message: str, status: int):
    message = translate(message)
    if request.path.startswith(
        ("/api/", "/system/backups/api/", "/system/updates/api/")
    ) or request.is_json:
        return jsonify({"ok": False, "error": message}), status
    abort(status, description=message)


def enforce_proxy_and_role():
    """Reject direct access and enforce application-side RBAC.

    HAProxy removes any client supplied identity headers and adds a shared
    secret only for the administration virtual host. The application still
    validates both the secret and the authenticated Authelia identity so a
    direct request to the loopback Docker port cannot bypass authentication.
    The guarded HAProxy reload probe has a separate least-privilege identity
    which is accepted only for its exact GET readiness endpoint.
    """

    expected = os.environ.get("HAPROXY_ADMIN_PROXY_SECRET", "").strip()
    supplied = request.headers.get(PROXY_SECRET_HEADER, "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return _json_error("trusted proxy authentication required", 403)

    username = (request.headers.get("Remote-User") or "").strip()
    groups = normalized_groups(request.headers.get("Remote-Groups", ""))
    is_control_plane_healthcheck = (
        request.method == "GET"
        and request.path == CONTROL_PLANE_HEALTHCHECK_PATH
        and username == CONTROL_PLANE_HEALTHCHECK_USER
        and groups == CONTROL_PLANE_HEALTHCHECK_GROUPS
    )
    if is_control_plane_healthcheck:
        g.remote_user = username
        g.remote_groups = groups
        g.is_superadmin = False
        return None

    if (
        username == CONTROL_PLANE_HEALTHCHECK_USER
        or groups.intersection(CONTROL_PLANE_HEALTHCHECK_GROUPS)
    ):
        return _json_error("authenticated administrator required", 403)

    if not username or not groups.intersection(ADMIN_GROUPS):
        return _json_error("authenticated administrator required", 403)

    needs_superadmin = request.path in SUPERADMIN_EXACT or request.path.startswith(
        SUPERADMIN_PREFIXES
    )
    if needs_superadmin and "superadmin" not in groups:
        return _json_error("superadmin role required", 403)

    g.remote_user = username
    g.remote_groups = groups
    g.is_superadmin = "superadmin" in groups
    return None


def apply_security_headers(response):
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Pragma", "no-cache")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'",
    )
    return response
