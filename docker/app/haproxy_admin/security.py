"""Security boundary for requests forwarded by the trusted HAProxy frontend."""

from __future__ import annotations

import hmac
import os
from typing import FrozenSet
from urllib.parse import urlsplit, urlunsplit

from flask import abort, g, jsonify, request

from .i18n import translate


PROXY_SECRET_HEADER = "X-Easy-HA-Proxy-Secret"
# Kept in sync with the app factory's SEND_FILE_MAX_AGE_DEFAULT.
STATIC_CACHE_SECONDS = 31536000
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

# A Prometheus scraper cannot complete an Authelia login, so HAProxy lets this
# one path through for an allow-listed source and marks it with an identity of
# its own. That identity is accepted here for exactly that GET and nothing
# else, and the endpoint itself still demands a bearer token: being on the
# allow-list is one gate, holding the token is the other.
METRICS_SCRAPE_PATH = "/metrics"
METRICS_SCRAPE_USER = "easy-ha-proxy-metrics"
METRICS_SCRAPE_GROUPS: FrozenSet[str] = frozenset({"metrics"})


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

    is_metrics_scrape = (
        request.method == "GET"
        and request.path == METRICS_SCRAPE_PATH
        and username == METRICS_SCRAPE_USER
        and groups == METRICS_SCRAPE_GROUPS
    )
    if is_metrics_scrape:
        g.remote_user = username
        g.remote_groups = groups
        g.is_superadmin = False
        return None

    if (
        username == CONTROL_PLANE_HEALTHCHECK_USER
        or groups.intersection(CONTROL_PLANE_HEALTHCHECK_GROUPS)
        or username == METRICS_SCRAPE_USER
        or groups.intersection(METRICS_SCRAPE_GROUPS)
    ):
        # Either identity anywhere else is a forged header, not a mistake.
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
    # Static files are versioned in their URL, so a released asset never
    # changes under a given URL and the browser can keep it without the
    # revalidation round-trip that every navigation used to pay.
    # 304 must carry it too: the browser refreshes the stored policy from the
    # revalidation response, so omitting it there keeps the entry revalidating
    # on every navigation.
    if request.endpoint == "static" and response.status_code in (200, 304):
        response.headers["Cache-Control"] = (
            f"public, max-age={STATIC_CACHE_SECONDS}, immutable"
        )
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Pragma", "no-cache")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    # Inline scripts carry the per-request nonce, so 'unsafe-inline' is not
    # needed for script-src. style-src keeps it on purpose: the templates rely
    # on inline style attributes, which cannot execute code.
    nonce = getattr(g, "csp_nonce", "")
    script_src = f"'self' 'nonce-{nonce}'" if nonce else "'self'"
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'; "
        f"script-src {script_src}; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'",
    )
    return response


def init_csrf(app, csrf) -> None:
    """Switch on CSRF protection with a token that lasts as long as its session.

    Flask-WTF's default gives a token one hour. A page reads its token once,
    when it loads, so every write from a page left open longer -- "check for
    updates" on a page opened in the morning -- failed with "CSRF validation
    failed" until the page was reloaded. The token stays bound to the session
    cookie (HttpOnly, Secure, SameSite=Strict), and a new session gets a new
    one; how long a login lasts is Authelia's decision, not the token's.
    """

    app.config["WTF_CSRF_TIME_LIMIT"] = None
    csrf.init_app(app)


def keep_redirects_on_this_origin(response):
    """Send the panel's redirects to its own pages as a path, not a full URL.

    Flask answers /system/updates with a redirect to /system/updates/ and
    writes it as an absolute URL from what it sees: plain http, because TLS
    ends at HAProxy. The browser then leaves https for an address the gateway
    does not serve. A path keeps the scheme and host the browser came with.
    Telling Flask the request was https would do it too, but would also switch
    on the CSRF check's strict Referer rules for every form.
    """

    location = response.headers.get("Location")
    if not location or not 300 <= response.status_code < 400:
        return response
    parts = urlsplit(location)
    if parts.scheme not in ("http", "https") or parts.netloc != request.host:
        return response
    # One leading slash: "//elsewhere/x" would be read as another host.
    path = "/" + parts.path.lstrip("/")
    response.headers["Location"] = urlunsplit(("", "", path, parts.query, parts.fragment))
    return response
