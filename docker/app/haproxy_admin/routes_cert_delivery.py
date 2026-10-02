# routes_cert_delivery.py
#
# Доставка сертификата на другие машины, которым нужен тот же самый.
#
# Приватный ключ и закреплённый ключ хоста уходят к certd и обратно не
# возвращаются никогда: демон их не отдаёт, страница видит только «задан» или
# «не задан». Тот же контракт, что у DNS-провайдеров и у назначений бэкапа.

from __future__ import annotations

import logging

from flask import g, jsonify, render_template, request

from .audit import RESULT_DENIED, RESULT_FAILURE, record_request
from .certd_client import (
    CertdUnavailable,
    cert_deliveries_list,
    cert_delivery_delete,
    cert_delivery_save,
    cert_delivery_test,
    list_all_certs,
)
from .routes import bp

LOG = logging.getLogger("haproxy-admin")

# Держим синхронно с haproxy-certd.py и easy-ha-proxy-cert-deliver.py.
FORMATS = ("pfx", "pem-pair", "pem-combined")
TRANSPORTS = ("sftp", "scp")
MAX_KEY_LENGTH = 16384


def _superadmin() -> bool:
    return bool(getattr(g, "is_superadmin", False))


def _unavailable(exc: CertdUnavailable):
    LOG.warning("certd unavailable: %s", exc)
    return jsonify({"ok": False, "unavailable": True, "error": str(exc)}), 503


@bp.get("/haproxy/certs/delivery")
def cert_delivery_page():
    return render_template(
        "cert_delivery.html", formats=FORMATS, transports=TRANSPORTS
    )


@bp.get("/api/haproxy/cert-delivery")
def api_cert_delivery_list():
    try:
        payload = cert_deliveries_list()
    except CertdUnavailable as exc:
        return _unavailable(exc)

    # The lineages the page offers to choose from, in the same answer: a
    # target names a certificate, and typing the name by hand is how a
    # target ends up silently never firing.
    available = []
    try:
        for item in (list_all_certs().get("letsencrypt") or []):
            name = str(item.get("lineage") or "").strip()
            if name:
                available.append({"name": name, "expires": item.get("not_after", "")})
    except Exception as exc:  # pylint: disable=broad-except
        LOG.warning("cannot list certificates for the delivery page: %s", exc)
    payload["available"] = available
    return jsonify(payload)


@bp.post("/api/haproxy/cert-delivery/save")
def api_cert_delivery_save():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip().lower()

    if not _superadmin():
        record_request(
            "cert_delivery.save",
            object_type="cert_delivery",
            object_id=name,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    # Only the obvious size guard here. Everything else certd validates,
    # because certd has to refuse a bad record whoever sends it and two
    # copies of the same rules are two things to drift.
    for field in ("private_key", "host_key"):
        if len(str(payload.get(field) or "")) > MAX_KEY_LENGTH:
            return jsonify({"ok": False, "error": f"{field} is too long"}), 400

    try:
        result = cert_delivery_save(payload)
    except CertdUnavailable as exc:
        record_request(
            "cert_delivery.save",
            object_type="cert_delivery",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(exc),
        )
        return _unavailable(exc)

    if not result.get("ok"):
        record_request(
            "cert_delivery.save",
            object_type="cert_delivery",
            object_id=name,
            result=RESULT_FAILURE,
            detail=str(result.get("error", "")),
        )
        return jsonify(result), 400

    # The record without its secrets: certd already stripped them, and what
    # is left is exactly what belongs in the change log.
    record_request(
        "cert_delivery.save",
        object_type="cert_delivery",
        object_id=name,
        after=result.get("target"),
        detail="certificate delivery target saved",
    )
    return jsonify(result)


@bp.post("/api/haproxy/cert-delivery/delete")
def api_cert_delivery_delete():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip().lower()

    if not _superadmin():
        record_request(
            "cert_delivery.delete",
            object_type="cert_delivery",
            object_id=name,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    try:
        result = cert_delivery_delete(name)
    except CertdUnavailable as exc:
        return _unavailable(exc)

    if not result.get("ok"):
        return jsonify(result), 400
    record_request(
        "cert_delivery.delete",
        object_type="cert_delivery",
        object_id=name,
        detail="certificate delivery target removed",
    )
    return jsonify(result)


@bp.post("/api/haproxy/cert-delivery/test")
def api_cert_delivery_test():
    """Send the certificate now, so a target is proven before a renewal.

    Mutating -- it really does write a file on another machine -- so it is
    guarded like the rest.
    """

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip().lower()

    if not _superadmin():
        record_request(
            "cert_delivery.test",
            object_type="cert_delivery",
            object_id=name,
            result=RESULT_DENIED,
            detail="superadmin required",
        )
        return jsonify({"ok": False, "error": "superadmin required"}), 403

    try:
        result = cert_delivery_test(name)
    except CertdUnavailable as exc:
        return _unavailable(exc)

    entry = {
        "object_type": "cert_delivery",
        "object_id": name,
        "detail": str(result.get("output", ""))[:400],
    }
    if not result.get("ok"):
        entry["result"] = RESULT_FAILURE
    record_request("cert_delivery.test", **entry)
    return jsonify(result)
