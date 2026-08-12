# haproxy_admin/routes_haproxy_sites.py

import traceback
import os
from flask import jsonify, request

from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request, summarize
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

    # The stored site is read before the write so the record can say what
    # moved rather than dump the whole object. An unknown name means a create.
    name = str(site.get("name") or original_name or "").strip()
    before = {}
    if original_name:
        _defaults, previous, _effective = get_site_raw_and_effective(original_name)
        before = previous or {}

    ok, msg = save_site_from_json(site, original_name=original_name)
    record_request(
        "site.update" if before else "site.create",
        object_type="site",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=summarize(before, site) if ok else "",
        detail="" if ok else str(msg)[:500],
    )
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

    # The uploaded bytes hold a private key, so only the shape of the upload is
    # recorded: which site, which authority, and how large the file was.
    record_request(
        "certificate.upload",
        object_type="site",
        object_id=site_name,
        result=RESULT_SUCCESS if res.get("ok") else RESULT_FAILURE,
        summary=f"authority: {external_ca_id}, bytes: {len(pem_bytes)}",
        detail="" if res.get("ok") else str(res.get("error") or "")[:500],
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
    record_request(
        "site.delete",
        object_type="site",
        object_id=name,
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        detail="" if ok else str(msg)[:500],
    )
    return jsonify({"ok": ok, ("message" if ok else "error"): msg})
