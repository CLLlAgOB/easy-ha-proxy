# routes_dns_providers.py
#
# Профили DNS-провайдеров для DNS-01. Сохранённые учётные данные лежат у root
# и обратно в браузер не возвращаются никогда: их не отдаёт даже сам демон.

from __future__ import annotations

import logging
import re

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .certd_client import (
    CertdUnavailable,
    dns_provider_delete,
    dns_provider_save,
    dns_providers_list,
)
from .routes import bp

LOG = logging.getLogger("haproxy-admin")

# Держим синхронно с DNS_PROVIDERS в haproxy-certd.py.
PROVIDERS = ("cloudflare", "digitalocean", "route53", "rfc2136")
PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
MAX_CREDENTIAL_LENGTH = 4096


def _superadmin() -> bool:
    return bool(getattr(g, "is_superadmin", False))


@bp.get("/haproxy/certs/dns-providers")
def dns_providers_page():
    return render_template("dns_providers.html", providers=PROVIDERS)


@bp.get("/api/haproxy/dns-providers")
def api_dns_providers():
    try:
        return jsonify(dns_providers_list())
    except CertdUnavailable as exc:
        LOG.warning("certd unavailable: %s", exc)
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503


@bp.post("/api/haproxy/dns-providers/save")
def api_dns_provider_save():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip().lower()
    provider = str(payload.get("provider") or "").strip().lower()

    if not _superadmin():
        record_request(
            "dns_provider.save",
            object_type="dns_provider",
            object_id=name,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    if not PROFILE_RE.match(name):
        return jsonify(
            {"ok": False, "error": "the profile name may use a-z, 0-9 and dashes"}
        ), 400
    if provider not in PROVIDERS:
        return jsonify({"ok": False, "error": "unsupported provider"}), 400

    supplied = payload.get("credentials")
    if not isinstance(supplied, dict) or not supplied:
        return jsonify({"ok": False, "error": "credentials are required"}), 400
    credentials = {}
    for key, value in supplied.items():
        text = str(value or "")
        if not text:
            continue
        if len(text) > MAX_CREDENTIAL_LENGTH:
            return jsonify({"ok": False, "error": f"{key} is too long"}), 400
        credentials[str(key)] = text
    if not credentials:
        return jsonify({"ok": False, "error": "credentials are required"}), 400

    try:
        result = dns_provider_save(name, provider, credentials)
    except CertdUnavailable as exc:
        record_request(
            "dns_provider.save",
            object_type="dns_provider",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503
    if not result.get("ok"):
        record_request(
            "dns_provider.save",
            object_type="dns_provider",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(result.get("error") or ""),
        )
        return jsonify(result), 400

    # The credential values are deliberately absent from the record: only that
    # the profile was written, and for which provider.
    record_request(
        "dns_provider.save",
        object_type="dns_provider",
        object_id=name,
        summary=f"provider: {provider}, credentials: changed",
    )
    return jsonify(result)


@bp.post("/api/haproxy/dns-providers/delete")
def api_dns_provider_delete():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip().lower()

    if not _superadmin():
        record_request(
            "dns_provider.delete",
            object_type="dns_provider",
            object_id=name,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403
    if not PROFILE_RE.match(name):
        return jsonify({"ok": False, "error": "invalid profile name"}), 400

    try:
        result = dns_provider_delete(name)
    except CertdUnavailable as exc:
        record_request(
            "dns_provider.delete",
            object_type="dns_provider",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503
    if not result.get("ok"):
        return jsonify(result), 400

    record_request(
        "dns_provider.delete", object_type="dns_provider", object_id=name
    )
    return jsonify(result)
