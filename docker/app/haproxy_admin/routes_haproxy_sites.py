# haproxy_admin/routes_haproxy_sites.py

import traceback
import os
from flask import jsonify, request

from .routes import bp
from .services_haproxy_sites import (
    delete_site,
    get_site_raw_and_effective,
    save_site_from_json,
)
from .certd_client import upload_cert_for_site


@bp.post("/haproxy/sites/save")
def haproxy_site_save():
    """
    Сохранение сайта (создание/редактирование) через JSON.

    Ожидает тело запроса:
      {
        "site": { ... },
        "original_name": "старое_имя_или_пусто"
      }

    Возвращает JSON:
      { "ok": true,  "message": "..." }
      { "ok": false, "error": "..." }
    """
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        traceback.print_exc()
        return jsonify(
            {"ok": False, "error": 'Invalid JSON in request'}
        ), 400

    if not isinstance(payload, dict):
        return jsonify(
            {"ok": False, "error": 'Invalid request format'}
        ), 400

    site = payload.get("site") or {}
    original_name = payload.get("original_name") or None

    ok, msg = save_site_from_json(site, original_name=original_name)
    status = 200 if ok else 400
    return jsonify({"ok": ok, ("message" if ok else "error"): msg}), status

@bp.route("/haproxy/sites/<site_name>/upload-cert", methods=["POST"])
def haproxy_site_upload_cert(site_name):
    from flask import request, jsonify, current_app

    file = request.files.get("cert_file")
    if not file or file.filename == "":
        return jsonify(ok=False, error='No file supplied'), 400

    _, raw, effective = get_site_raw_and_effective(site_name)
    if raw is None:
        return jsonify(ok=False, error="Site was not found"), 404
    domain = (effective.get("domain") or effective.get("name") or "").strip()
    source = raw.get("certificate_source")
    if source not in ("letsencrypt", "external", "internal"):
        source = "letsencrypt" if raw.get("le_managed", True) else "external"
    if source != "external":
        return jsonify(
            ok=False,
            error="Select the external certificate authority mode before uploading a certificate.",
        ), 400
    external_ca_id = str(raw.get("external_ca_id") or "").strip()
    if not external_ca_id:
        return jsonify(ok=False, error="Select an imported external certificate authority."), 400

    try:
        pem_bytes = file.read()
    except Exception as exc:  # pylint: disable=broad-except
        current_app.logger.exception("Failed to read uploaded cert file")
        return jsonify(ok=False, error=f"Failed to read uploaded file: {exc}"), 400

    if not pem_bytes:
        return jsonify(ok=False, error='The file is empty'), 400

    res = upload_cert_for_site(
        site_name=site_name,
        domain=domain,
        pem_bytes=pem_bytes,
        filename=file.filename,
        external_ca_id=external_ca_id,
    )

    # upload_cert_for_site всегда возвращает dict с ok/message|error
    return jsonify(res), 200


@bp.post("/haproxy/sites/<name>/delete")
def haproxy_site_delete(name):
    """
    Удаление сайта по имени (JSON-эндпоинт).
    Пока фронт этим не пользуется, но можно будет подвязать delete по AJAX.
    """
    ok, msg = delete_site(name)
    return jsonify({"ok": ok, ("message" if ok else "error"): msg})
