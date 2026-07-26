# haproxy_admin/__init__.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import secrets

from flask import Flask, abort, g, jsonify, redirect, request, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect

from .cache import init_cache
from .i18n import (
    DEFAULT_LANGUAGE,
    LANGUAGE_COOKIE,
    get_messages,
    init_request_language,
    localize_json_response,
    normalize_language,
    safe_local_redirect,
    supported_languages,
    translate,
)
from .utils import ensure_whitelist_file
from .security import apply_security_headers, enforce_proxy_and_role

# Import routes so they register themselves on their blueprints.
from . import routes
from . import routes_haproxy_config
from . import routes_haproxy_sites
from . import routes_haproxy_tcp
from . import routes_haproxy_udp
from . import routes_health
from . import routes_geoip

from .routes_authelia_settings import bp_authelia_settings
from .authelia_acl import bp_authelia_acl
from .routes_backup import bp_system_backups
from .routes_updates import bp_system_updates

logger = logging.getLogger("haproxy-admin")
csrf = CSRFProtect()

_DEFAULT_SECRET_FILE = "/opt/haproxy-admin/config/secret.key"

# Per-language cache of the translation catalog served as a standalone,
# browser-cacheable JavaScript asset. Previously the whole catalog (~200 KB,
# and ~400 KB once tojson escaped Cyrillic to \uXXXX) was inlined into every
# page, so it was re-sent and re-parsed on every navigation. Serving it once
# from a hashed, immutable URL removes it from the per-page HTML entirely.
# The catalog is static for the life of the process (loaded from bundled
# files), so building the asset once per worker is safe.
_I18N_ASSET_CACHE: dict[str, dict[str, object]] = {}


def _i18n_messages_asset(language: str) -> dict[str, object]:
    cached = _I18N_ASSET_CACHE.get(language)
    if cached is not None:
        return cached
    # ensure_ascii=False keeps Cyrillic as compact UTF-8 (~180 KB) instead of
    # \uXXXX escapes (~400 KB); the payload is gzipped once (~40 KB on the wire).
    payload = json.dumps(
        get_messages(language),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    body = (
        "window.HAPROXY_ADMIN_I18N=window.HAPROXY_ADMIN_I18N||{};"
        f"window.HAPROXY_ADMIN_I18N.messages={payload};"
    ).encode("utf-8")
    asset = {
        "body": body,
        "gzip": gzip.compress(body, 6),
        "etag": hashlib.sha256(body).hexdigest()[:16],
    }
    _I18N_ASSET_CACHE[language] = asset
    return asset


def _get_or_create_secret_key() -> str:
    # 1) ENV
    env_key = os.environ.get("HAPROXY_ADMIN_SECRET_KEY", "").strip()
    if env_key:
        logger.info("Using Flask secret key from env HAPROXY_ADMIN_SECRET_KEY")
        return env_key

    # 2) Secret file.
    secret_file = os.environ.get("HAPROXY_ADMIN_SECRET_FILE", _DEFAULT_SECRET_FILE)

    try:
        if os.path.exists(secret_file):
            with open(secret_file, "r", encoding="utf-8") as f:
                existing = f.read().strip()
            if existing:
                logger.info("Using Flask secret key from %s", secret_file)
                return existing
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("Cannot read secret file %s: %s", secret_file, e)

    # 3) Generate a new secret.
    new_key = secrets.token_hex(32)

    try:
        os.makedirs(os.path.dirname(secret_file), exist_ok=True)
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(new_key)
        os.chmod(secret_file, 0o600)
        logger.info("Generated new Flask secret key and saved to %s", secret_file)
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("Cannot write secret file %s: %s", secret_file, e)

    return new_key


def create_app() -> Flask:
    # Configure logging before any logger.info()/warning() calls.
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app = Flask(__name__)
    app.secret_key = _get_or_create_secret_key()
    app.config.update(
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=2 * 1024 * 1024,
        MAX_FORM_PARTS=100,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )

    @app.before_request
    def configure_request_body_limit():
        """Allow large raw DR archives only on the exact superadmin upload route."""

        if request.path == "/system/backups/api/uploads":
            request.max_content_length = int(
                os.environ.get(
                    "EASY_HA_PROXY_BACKUP_MAX_UPLOAD_BYTES",
                    str(8 * 1024**3),
                )
            )

    csrf.init_app(app)
    app.before_request(init_request_language)
    app.before_request(enforce_proxy_and_role)
    app.after_request(apply_security_headers)
    app.after_request(localize_json_response)

    @app.context_processor
    def inject_i18n_context():
        language = getattr(g, "language", "en")
        languages = supported_languages()
        # The catalog itself is delivered by the cacheable /i18n/messages.js
        # asset (see below); the inline config only carries the tiny language
        # metadata so the page HTML stays small.
        return {
            "_": translate,
            "current_language": language,
            "supported_languages": languages,
            "i18n_config": {
                "language": language,
                "languages": languages,
            },
            "i18n_messages_url": url_for(
                "i18n_messages",
                lang=language,
                v=_i18n_messages_asset(language)["etag"],
            ),
        }

    @app.get("/i18n/messages.js", endpoint="i18n_messages")
    def i18n_messages():
        language = normalize_language(request.args.get("lang")) or DEFAULT_LANGUAGE
        asset = _i18n_messages_asset(language)
        accepts_gzip = "gzip" in request.headers.get("Accept-Encoding", "").lower()
        data = asset["gzip"] if accepts_gzip else asset["body"]
        response = app.response_class(
            data, content_type="application/javascript; charset=utf-8"
        )
        if accepts_gzip:
            response.headers["Content-Encoding"] = "gzip"
        response.headers["Vary"] = "Accept-Encoding"
        response.headers["Content-Length"] = str(len(data))
        response.set_etag(str(asset["etag"]))
        # The URL carries a content hash (?v=), so a changed catalog produces a
        # new URL; mark it immutable. Set Cache-Control explicitly because the
        # global security header applies "no-store" only via setdefault.
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response

    @app.post("/language", endpoint="set_language")
    def set_language():
        language = normalize_language(request.form.get("language"))
        if not language:
            abort(400, description=translate("Unsupported interface language"))

        target = safe_local_redirect(request.form.get("next"))
        response = redirect(target, code=303)
        response.set_cookie(
            LANGUAGE_COOKIE,
            language,
            max_age=365 * 24 * 60 * 60,
            secure=app.config["SESSION_COOKIE_SECURE"],
            httponly=True,
            samesite=app.config["SESSION_COOKIE_SAMESITE"],
        )
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(exc: CSRFError):
        message = translate("CSRF validation failed")
        if request.path.startswith(
            ("/api/", "/system/backups/api/", "/system/updates/api/")
        ) or request.is_json:
            return jsonify({"ok": False, "error": message}), 400
        return f"{message}: {exc.description}", 400

    # Open the local MMDB reader. Each Gunicorn worker reopens it after an
    # atomic on-disk database update.
    init_cache()

    ensure_whitelist_file()

    # Main blueprint.
    app.register_blueprint(routes.bp)

    # Authelia blueprints.
    app.register_blueprint(bp_authelia_settings)
    app.register_blueprint(bp_authelia_acl)
    app.register_blueprint(bp_system_backups)
    app.register_blueprint(bp_system_updates)

    return app
