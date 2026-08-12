# routes_haproxy_config.py

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    url_for,
    Response,
    send_file,
    abort,
    redirect,
)

from pathlib import Path
import traceback
import io
import base64
import hashlib
import ipaddress
import re
import zipfile
from datetime import datetime
from .audit import RESULT_FAILURE, RESULT_SUCCESS, record_request, summarize
from .routes import bp
from .services_haproxy_config import (
    render_haproxy_cfg,
    check_cfg,
    preflight_cfg_confirmation,
    begin_cfg_confirmation,
    confirm_cfg_transaction,
    rollback_cfg_transaction,
    get_config_transaction_status,
    candidate_request_reachable,
    CONFIG_GENERATION_HEADER,
    update_yaml_file,
    WEBSITES_YAML,
    TCP_YAML,
    CONFIG_YAML,
    _load_yaml,
    #add_site_full,
    get_config_diff_summary,
    get_haproxy_configuration_state,
    save_applied_state_strict,
    ensure_applied_state_baseline,
    get_server_cfg_text,
    make_cfg_html_diff,
    HAP_TEMPLATE,
    HAPROXY_CFG_PATH,
    HAPROXY_STATE_PATH,
    HAPROXY_STATE_WEBSITES,
    HAPROXY_STATE_TCP,
    HAPROXY_STATE_VARS,
    revert_to_last_applied_state,
)
from .services_haproxy_vars import (
    get_acme_email,
    get_vars_editor_model,
    save_acme_email,
    save_guided_vars,
    save_raw_vars,
    validate_admin_access_for_client,
)

from .services_haproxy_sites import (
    get_websites_list,
    add_site_minimal,
    delete_site_by_name,
    get_sites_and_defaults_for_ui,
    get_site_raw_and_effective,
    get_configured_geoip_countries,
    save_site_raw,
    ensure_certs_before_apply,
)

from .services_haproxy_tcp import (
    get_tcp_proxies_list,
    save_tcp_from_json,
    delete_tcp_proxy,
)


# The site editor normally saves through JavaScript, which posts the whole site
# as JSON. Without JavaScript the browser posts only the form controls, and a
# site holds far more than the form can express — the backend server table and
# the error-exclusion rules are built by script and have no form control at
# all. So these are the only keys a plain submit is allowed to speak for;
# everything else is carried over from the stored site untouched.
FORM_TEXT_FIELDS = ("backend_host", "health_uri", "hsts", "waf")
FORM_NUMBER_FIELDS = ("max_req_rate", "health_status")
FORM_TRISTATE_FIELDS = (
    "redirect_to_https",
    "authelia_enabled",
    "zero_trust",
    "backend_ssl",
    "backend_ssl_verify",
    "maintenance",
    "rate_ban",
    "compress",
)
# Everything above is a select, a text/number input, a textarea or a radio, so
# the browser submits it whether or not it has a value. That is what makes
# "the control is present" a usable signal. A checkbox is absent when it is
# unchecked, which would be indistinguishable from a form that never carried
# it, so no checkbox-backed key (key_types, and the tables) is handled here.


def merge_site_from_edit_form(name, existing, form):
    """Overlay a plain HTML form submission onto the stored site.

    Returns ``(site, error)``. The stored site is the base: a form control that
    was submitted wins, and an empty one clears its key so the site_defaults
    value applies again. A key with no control in the submission is left alone
    rather than dropped, which is what keeps a non-JavaScript save from
    silently reverting the certificate source, the key types or the backend
    server list.
    """
    domain = (form.get("domain") or "").strip()
    backend_ip = (form.get("backend_ip") or "").strip()
    backend_port_str = (form.get("backend_port") or "").strip()

    if not domain or not backend_ip or not backend_port_str:
        return {}, 'The domain, backend_ip, and backend_port fields are required'
    try:
        backend_port = int(backend_port_str)
    except ValueError:
        return {}, 'backend_port must be a number'
    if not (1 <= backend_port <= 65535):
        return {}, 'backend_port must be between 1 and 65535'

    site = dict(existing or {})
    site["name"] = name
    site["domain"] = domain
    site["backend_ip"] = backend_ip
    site["backend_port"] = backend_port

    if "alt_names" in form:
        alt_names = [
            line.strip()
            for line in (form.get("alt_names") or "").splitlines()
            if line.strip()
        ]
        if alt_names:
            site["alt_names"] = alt_names
        else:
            site.pop("alt_names", None)

    # A saved profile is the only switch for DNS-01, so choosing HTTP-01 has to
    # drop it — and with it the wildcard names that only DNS-01 could validate.
    if "acme_challenge" in form:
        profile = ""
        if (form.get("acme_challenge") or "").strip() == "dns-01":
            profile = (form.get("dns_profile") or "").strip()
        if profile:
            site["dns_profile"] = profile
            extra = [
                line.strip()
                for line in (form.get("cert_alt_names") or "").splitlines()
                if line.strip()
            ]
            if extra:
                site["cert_alt_names"] = extra
            else:
                site.pop("cert_alt_names", None)
        else:
            site.pop("dns_profile", None)
            site.pop("cert_alt_names", None)

    for field in FORM_TRISTATE_FIELDS:
        if field not in form:
            continue
        value = (form.get(field) or "").strip()
        if value == "true":
            site[field] = True
        elif value == "false":
            site[field] = False
        else:
            site.pop(field, None)

    for field in FORM_NUMBER_FIELDS:
        if field not in form:
            continue
        value = (form.get(field) or "").strip()
        if not value:
            site.pop(field, None)
            continue
        try:
            site[field] = int(value)
        except ValueError:
            return {}, f"{field} must be a number"

    for field in FORM_TEXT_FIELDS:
        if field not in form:
            continue
        value = (form.get(field) or "").strip()
        if value:
            site[field] = value
        else:
            site.pop(field, None)

    return site, ""


def _available_dns_profiles():
    """DNS-01 profiles offered by the site editor.

    certd being unreachable must not break the editor, so the list degrades to
    empty and the site keeps whatever profile it already references.
    """
    from .certd_client import CertdUnavailable, dns_providers_list

    try:
        data = dns_providers_list()
    except CertdUnavailable:
        return []
    profiles = data.get("profiles")
    if not isinstance(profiles, list):
        return []
    return [
        entry
        for entry in profiles
        if isinstance(entry, dict) and entry.get("name")
    ]


def _trusted_client_ip() -> str:
    """Return the edge client IP after the trusted HAProxy header rewrite."""
    raw = str(request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


@bp.get("/haproxy/config/preview")
def haproxy_config_preview():
    """
    Старый эндпоинт — оставляем как есть:
    возвращает сгенерированный haproxy.cfg в plain-text.
    """
    cfg_text = render_haproxy_cfg()
    return Response(cfg_text, mimetype="text/plain")


@bp.get("/haproxy/config/download-cfg/<source>")
def haproxy_download_cfg(source):
    """
    Скачать haproxy.cfg:
      - source="rendered" — рендер из шаблонов (то, что сейчас будет применено)
      - source="server"   — живой /etc/haproxy/haproxy.cfg
    """
    if source == "rendered":
        try:
            cfg_text = render_haproxy_cfg()
        except Exception as e:  # pylint: disable=broad-except
            traceback.print_exc()
            return Response(
                f"Failed to generate configuration: {e}",
                status=500,
                mimetype="text/plain",
            )
        filename = "haproxy-rendered.cfg"

    elif source == "server":
        try:
            cfg_text = HAPROXY_CFG_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            return Response(
                f"File {HAPROXY_CFG_PATH} was not found on the server",
                status=404,
                mimetype="text/plain",
            )
        except OSError as e:  # pylint: disable=broad-except
            traceback.print_exc()
            return Response(
                f"Failed to read {HAPROXY_CFG_PATH}: {e}",
                status=500,
                mimetype="text/plain",
            )
        filename = "haproxy-server.cfg"

    else:
        abort(404)

    resp = Response(cfg_text, mimetype="text/plain")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.get("/haproxy/config/download-all")
def haproxy_download_all_configs():
    """
    Архивирует основные файлы конфигурации HAProxy и отдаёт zip:
      - /etc/haproxy/haproxy.cfg
      - шаблон haproxy.cfg.j2
      - websites.yml / tcp.yml / vars.yml
      - снимки последнего apply, если есть
    """
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        def add(path: Path, arcname: str) -> None:
            try:
                if path.exists():
                    zf.write(path, arcname)
            except OSError:
                # если не получилось прочитать один файл — остальные все равно отдадим
                pass

        # Основные конфиги
        add(HAPROXY_CFG_PATH, "haproxy/haproxy.cfg")
        add(HAP_TEMPLATE, "haproxy/haproxy.cfg.j2")

        add(WEBSITES_YAML, "haproxy/websites.yml")
        add(TCP_YAML, "haproxy/tcp.yml")
        add(CONFIG_YAML, "haproxy/vars.yml")

        # Снимки последнего применённого состояния
        add(HAPROXY_STATE_PATH, "haproxy/last_applied_state.json")
        add(HAPROXY_STATE_WEBSITES, "haproxy/last_applied_websites.yml")
        add(HAPROXY_STATE_TCP, "haproxy/last_applied_tcp.yml")
        add(HAPROXY_STATE_VARS, "haproxy/last_applied_vars.yml")

    buf.seek(0)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"haproxy-configs-{ts}.zip"

    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/zip",
        max_age=0,
    )


@bp.get("/haproxy/config/diff")
def haproxy_config_diff():
    """
    JSON с diff:
      - rendered_cfg: текущий рендер из шаблонов
      - server_cfg: реальный /etc/haproxy/haproxy.cfg
      - html_diff: HTML-таблица diff (side-by-side)
      - diff_summary: сводка изменений (для полоски статуса)
    """
    try:
        rendered = render_haproxy_cfg()
        server_cfg = get_server_cfg_text()
        html_diff = make_cfg_html_diff(server_cfg, rendered)
        summary = get_config_diff_summary(rendered)

        return jsonify(
            {
                "ok": True,
                "rendered_cfg": rendered,
                "server_cfg": server_cfg,
                "html_diff": html_diff,
                "diff_summary": summary,
            }
        )
    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"Failed to build diff: {e}",
                }
            ),
            500,
        )


@bp.get("/haproxy/config/state")
def haproxy_configuration_state():
    """Return an aggregate status for the shared superadmin indicator."""
    try:
        return jsonify(get_haproxy_configuration_state())
    except Exception:  # pylint: disable=broad-except
        # Configuration contents and daemon diagnostics must not be reflected
        # into a page-wide polling endpoint.
        traceback.print_exc()
        return (
            jsonify(
                {
                    "ok": False,
                    "state": "unknown",
                    "status_available": False,
                    "pending": False,
                    "error": "Configuration status is unavailable",
                }
            ),
            503,
        )


@bp.route("/haproxy/config", methods=["GET"])
def haproxy_config_page():
    """
    Страница:
      - статус "конфиг на сервере совпадает / отличается"
      - сводка изменений sites/tcp/vars относительно последнего apply
      - превью/diff haproxy.cfg (по кнопке, скрыто по умолчанию)
      - кнопки "Проверить" / "Применить"
      - формы загрузки YAML
    """
    error = None
    cfg_text = ""
    diff_summary = None
    vars_sections = []
    vars_yaml = ""
    vars_revision = ""

    try:
        cfg_text = render_haproxy_cfg()
        try:
            ensure_applied_state_baseline(cfg_text)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
        try:
            diff_summary = get_config_diff_summary(cfg_text)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            diff_summary = None
    except Exception as e:  # pylint: disable=broad-except
        error = f"Configuration generation error: {e}"

    try:
        vars_model = get_vars_editor_model()
        vars_sections = vars_model["sections"]
        vars_yaml = vars_model["yaml"]
        vars_revision = vars_model["revision"]
    except Exception as exc:  # pylint: disable=broad-except
        traceback.print_exc()
        if error:
            error = f"{error}\nvars.yml editor error: {exc}"
        else:
            error = f"vars.yml editor error: {exc}"

    return render_template(
        "haproxy_config.html",
        cfg_text=cfg_text,
        error=error,
        diff_summary=diff_summary,
        vars_sections=vars_sections,
        vars_yaml=vars_yaml,
        vars_revision=vars_revision,
        admin_client_ip=_trusted_client_ip(),
    )


@bp.route("/haproxy/config/check", methods=["POST"])
def haproxy_config_check():
    """
    Проверка текущей сгенерированной конфигурации через haproxy -c.
    Возвращает JSON.
    """
    try:
        cfg_text = render_haproxy_cfg()
    except Exception as e:  # pylint: disable=broad-except
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"Failed to generate configuration: {e}",
                    "stdout": "",
                    "stderr": "",
                    "rc": None,
                }
            ),
            500,
        )

    try:
        config_vars = _load_yaml(CONFIG_YAML)
        if not isinstance(config_vars, dict):
            raise ValueError("The candidate vars.yml root must be a mapping")
        validate_admin_access_for_client(config_vars, _trusted_client_ip())
    except ValueError as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "rc": None,
                "stdout": "",
                "stderr": str(exc),
            }
        ), 400

    rc, stdout, stderr = check_cfg(cfg_text)
    ok = rc == 0

    return (
        jsonify(
            {
                "ok": ok,
                "rc": rc,
                "stdout": stdout,
                "stderr": stderr,
            }
        ),
        200 if ok else 400,
    )


@bp.route("/haproxy/config/apply", methods=["POST"])
def haproxy_config_apply():
    """
    Begin a confirmable HAProxy/YAML transaction.

    The root daemon performs validation, reload and immediate critical-service
    probes, then keeps the candidate pending. The browser must confirm through
    the normal frontend before the server-side deadline or everything is
    restored automatically.
    """
    try:
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            return jsonify(
                {
                    "ok": False,
                    "error": "The apply request must be a JSON object",
                    "error_code": "invalid_apply_request",
                }
            ), 400
        allow_external_drift = payload.get("allow_external_drift") is True
        expected_active_sha256 = str(
            payload.get("active_cfg_sha256") or ""
        ).strip().lower()
        if allow_external_drift and not re.fullmatch(
            r"[0-9a-f]{64}", expected_active_sha256
        ):
            return jsonify(
                {
                    "ok": False,
                    "error": "A valid active HAProxy configuration hash is required",
                    "error_code": "invalid_apply_request",
                }
            ), 400

        cfg_text = render_haproxy_cfg()
        config_vars = _load_yaml(CONFIG_YAML)
        if not isinstance(config_vars, dict):
            raise ValueError("The candidate vars.yml root must be a mapping")
        try:
            validate_admin_access_for_client(config_vars, _trusted_client_ip())
        except ValueError as exc:
            return jsonify(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_code": "admin_ip_lockout_risk",
                    "stdout": "",
                    "stderr": "",
                }
            ), 400
        preflight_result = preflight_cfg_confirmation(
            cfg_text,
            allow_external_drift=allow_external_drift,
            expected_active_sha256=expected_active_sha256,
        )
        if not preflight_result.get("ok"):
            drift_confirmation_required = bool(
                preflight_result.get("external_drift_confirmation_required")
            )
            return jsonify(
                {
                    "ok": False,
                    "error": preflight_result.get("error"),
                    "error_code": preflight_result.get("error_code"),
                    "stdout": preflight_result.get("stdout") or "",
                    "stderr": preflight_result.get("stderr") or "",
                    "external_drift_confirmation_required": (
                        drift_confirmation_required
                    ),
                    "active_cfg_sha256": preflight_result.get(
                        "active_cfg_sha256"
                    ),
                }
            ), 409 if drift_confirmation_required else 400

        cert_res = ensure_certs_before_apply()
        if not cert_res.get("ok"):
            return jsonify(
                {
                    "ok": False,
                    "error": 'Failed to issue certificates for some sites',
                    "cert_details": cert_res,
                    "stdout": "",
                    "stderr": "",
                }
            ), 200

        apply_result = begin_cfg_confirmation(
            cfg_text,
            allow_external_drift=allow_external_drift,
            expected_active_sha256=expected_active_sha256,
        )
        ok = bool(apply_result.get("ok"))
        stdout = str(apply_result.get("stdout") or "")
        stderr = str(apply_result.get("stderr") or "")
        state = str(
            apply_result.get("state") or apply_result.get("status") or ""
        ).lower()
        pending_confirmation = ok and state in {
            "pending",
            "pending_confirmation",
        }

        try:
            diff_summary = get_config_diff_summary(cfg_text)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            diff_summary = None

        # An apply is the moment the running gateway changes, so it is recorded
        # even while it is only pending: the confirmation and the automatic
        # rollback are separate events with their own records.
        record_request(
            "config.apply",
            object_type="haproxy",
            object_id=str(
                apply_result.get("transaction_id") or apply_result.get("id") or ""
            ),
            result=RESULT_SUCCESS if ok else RESULT_FAILURE,
            summary=(
                f"state: {state or 'applied'}"
                + (", external drift overridden"
                   if apply_result.get("external_drift_overridden") else "")
            ),
            detail="" if ok else str(
                apply_result.get("error") or stderr or ""
            )[:500],
        )

        return (
            jsonify(
                {
                    "ok": ok,
                    "stdout": stdout,
                    "stderr": stderr,
                    "error": "" if ok else (
                        apply_result.get("error")
                        or 'HAProxy confirmable apply failed (see stderr)'
                    ),
                    "error_code": apply_result.get("error_code"),
                    "baseline_source": apply_result.get("baseline_source"),
                    "baseline_reconciled": bool(
                        apply_result.get("baseline_reconciled")
                    ),
                    "external_drift_confirmation_required": bool(
                        apply_result.get("external_drift_confirmation_required")
                    ),
                    "active_cfg_sha256": apply_result.get("active_cfg_sha256"),
                    "external_drift_overridden": bool(
                        apply_result.get("external_drift_overridden")
                    ),
                    "safety": apply_result.get("safety") or apply_result,
                    "state": state,
                    "pending_confirmation": pending_confirmation,
                    "transaction_id": (
                        apply_result.get("transaction_id")
                        or apply_result.get("id")
                    ),
                    "candidate_sha256": apply_result.get("candidate_sha256"),
                    "confirm_by": (
                        apply_result.get("confirm_by")
                        or apply_result.get("deadline")
                    ),
                    "remaining_seconds": apply_result.get("remaining_seconds"),
                    "diff_summary": diff_summary,
                }
            ),
            202 if pending_confirmation else (
                200 if ok else (
                    409
                    if apply_result.get("external_drift_confirmation_required")
                    else 400
                )
            ),
        )

    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        record_request(
            "config.apply",
            object_type="haproxy",
            result=RESULT_FAILURE,
            detail=str(e)[:500],
        )
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"Failed to apply configuration: {e}",
                    "stdout": "",
                    "stderr": "",
                }
            ),
            500,
        )


@bp.get("/haproxy/config/apply-status")
def haproxy_config_apply_status():
    transaction_id = str(request.args.get("transaction_id") or "").strip()
    result = get_config_transaction_status(transaction_id)
    state = str(result.get("state") or result.get("status") or "").lower()
    result["candidate_reachable"] = bool(
        state in {"pending", "pending_confirmation"}
        and candidate_request_reachable(
            transaction_id,
            request.headers.get(CONFIG_GENERATION_HEADER, ""),
        )
    )
    return jsonify(result), 200 if result.get("ok") else 409


@bp.post("/haproxy/config/confirm")
def haproxy_config_confirm():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "Invalid confirmation request"}), 400
    transaction_id = str(payload.get("transaction_id") or "").strip()
    candidate_sha256 = str(payload.get("candidate_sha256") or "").strip()
    if not candidate_request_reachable(
        transaction_id,
        request.headers.get(CONFIG_GENERATION_HEADER, ""),
    ):
        return jsonify(
            {
                "ok": False,
                "state": "pending_confirmation",
                "pending": True,
                "conflict": True,
                "retryable": True,
                "candidate_reachable": False,
                "error": (
                    "Waiting for a fresh connection through the candidate "
                    "HAProxy configuration"
                ),
            }
        ), 409
    result = confirm_cfg_transaction(transaction_id, candidate_sha256)
    state = str(result.get("state") or result.get("status") or "").lower()
    if not result.get("ok") or state != "confirmed":
        record_request(
            "config.confirm",
            object_type="haproxy",
            object_id=transaction_id,
            result=RESULT_FAILURE,
            summary=f"state: {state or 'unknown'}",
            detail=str(result.get("error") or "")[:500],
        )
        return jsonify(result), 409

    warnings = []
    try:
        cfg_text = render_haproxy_cfg()
        rendered_sha256 = hashlib.sha256(cfg_text.encode("utf-8")).hexdigest()
        if rendered_sha256 != candidate_sha256.lower():
            raise RuntimeError(
                "The confirmed HAProxy config no longer matches the runtime YAML"
            )

        # GeoIP selection/ACL activation, the HAProxy reload, and critical
        # probes all completed inside the root transaction before the browser
        # received the confirmation prompt. Confirmation is deliberately a
        # commit-only operation and must never trigger another reload.
        save_applied_state_strict(cfg_text)
    except Exception as exc:  # pylint: disable=broad-except
        traceback.print_exc()
        warnings.append(
            "The configuration is confirmed and remains active, but its "
            f"applied-state snapshot could not be saved: {exc}"
        )

    record_request(
        "config.confirm",
        object_type="haproxy",
        object_id=transaction_id,
        summary="; ".join(warnings) if warnings else "",
    )

    response = dict(result)
    response["ok"] = True
    response["state"] = "confirmed"
    response["message"] = "Configuration confirmed and kept"
    if warnings:
        response["warnings"] = warnings
        response["warning"] = warnings[0]
    return jsonify(response), 200


@bp.post("/haproxy/config/rollback-pending")
def haproxy_config_rollback_pending():
    payload = request.get_json(silent=True) or {}
    transaction_id = str(payload.get("transaction_id") or "").strip()
    result = rollback_cfg_transaction(transaction_id)
    state = str(result.get("state") or result.get("status") or "").lower()
    rolled_back = state == "rolled_back" and bool(result.get("ok"))
    record_request(
        "config.rollback",
        object_type="haproxy",
        object_id=transaction_id,
        result=RESULT_SUCCESS if rolled_back else RESULT_FAILURE,
        summary=f"state: {state or 'unknown'}",
        detail="" if rolled_back else str(result.get("error") or "")[:500],
    )
    return jsonify(result), 200 if rolled_back else 409


@bp.route("/haproxy/config/upload", methods=["POST"])
def haproxy_config_upload():
    """
    Загрузка одного из YAML-файлов:
      kind ∈ {websites, tcp, vars}
      file — .yml/.yaml

    Ответ: JSON {ok: bool, message|error: str}
    (всегда 200, чтобы HAProxy не подменял тело ответа)
    """
    kind = request.form.get("kind")
    file = request.files.get("file")

    if not kind:
        return jsonify({"ok": False, "error": "The kind parameter is required"}), 200
    if not file or file.filename == "":
        return jsonify({"ok": False, "error": 'No file supplied'}), 200

    content = file.read().decode("utf-8", errors="replace")

    try:
        ok, msg = update_yaml_file(kind, content)
    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        record_request(
            "config.upload",
            object_type="yaml",
            object_id=str(kind),
            result=RESULT_FAILURE,
            detail=str(e)[:500],
        )
        return jsonify(
            {
                "ok": False,
                "error": f"File update error: {e}",
            }
        ), 200

    # A whole-file replacement can change every site at once, so the record
    # notes the size rather than the contents.
    record_request(
        "config.upload",
        object_type="yaml",
        object_id=str(kind),
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary=f"bytes: {len(content.encode('utf-8'))}",
        detail="" if ok else str(msg)[:500],
    )

    return (
        jsonify(
            {
                "ok": ok,
                ("message" if ok else "error"): msg,
            }
        ),
        200,
    )


@bp.post("/haproxy/config/vars")
def haproxy_config_save_vars():
    payload = request.get_json(silent=True) or {}
    values = payload.get("values")
    result = save_guided_vars(
        values,
        str(payload.get("revision") or ""),
        client_ip=_trusted_client_ip(),
    )
    record_request(
        "vars.update",
        object_type="haproxy",
        object_id="vars.yml",
        result=RESULT_SUCCESS if result.get("ok") else RESULT_FAILURE,
        summary=(
            "fields: " + ", ".join(sorted(str(k) for k in values))
            if isinstance(values, dict)
            else "guided editor"
        ),
        detail="" if result.get("ok") else str(result.get("error") or "")[:500],
    )
    status = 200 if result.get("ok") else (409 if result.get("conflict") or result.get("pending") else 400)
    return jsonify(result), status


@bp.post("/haproxy/config/vars/raw")
def haproxy_config_save_vars_raw():
    payload = request.get_json(silent=True) or {}
    content = payload.get("content")
    result = save_raw_vars(
        content,
        str(payload.get("revision") or ""),
    )
    # vars.yml holds the ACME email and other settings but no secrets of its
    # own; even so only the size is recorded, never the text.
    record_request(
        "vars.update",
        object_type="haproxy",
        object_id="vars.yml",
        result=RESULT_SUCCESS if result.get("ok") else RESULT_FAILURE,
        summary="raw editor, bytes: %d" % len(str(content or "").encode("utf-8")),
        detail="" if result.get("ok") else str(result.get("error") or "")[:500],
    )
    status = 200 if result.get("ok") else (409 if result.get("conflict") or result.get("pending") else 400)
    return jsonify(result), status


@bp.post("/haproxy/config/revert")
def haproxy_config_revert():
    """
    Откатывает websites.yml/tcp.yml/vars.yml к последнему применённому состоянию.
    Использует файлы last_applied_*.yml, которые сохраняет save_applied_state.
    """
    try:
        ok, msg = revert_to_last_applied_state()
    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        record_request(
            "config.revert",
            object_type="haproxy",
            result=RESULT_FAILURE,
            detail=str(e)[:500],
        )
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"Revert error: {e}",
                }
            ),
            500,
        )

    record_request(
        "config.revert",
        object_type="haproxy",
        result=RESULT_SUCCESS if ok else RESULT_FAILURE,
        summary="restored the last applied websites/tcp/vars",
        detail="" if ok else str(msg)[:500],
    )

    return (
        jsonify(
            {
                "ok": ok,
                ("message" if ok else "error"): msg,
            }
        ),
        200,
    )


@bp.get("/haproxy/config/download/<kind>")
def haproxy_config_download(kind):
    """
    Скачать один из YAML-файлов:
      kind: websites | tcp | vars
    Берём пути из services_haproxy_config, чтобы не дублировать логику.
    """
    mapping = {
        "websites": WEBSITES_YAML,
        "tcp": TCP_YAML,
        "vars": CONFIG_YAML,
    }

    path = mapping.get(kind)
    if path is None:
        abort(404)

    path = path.resolve()

    if not path.exists():
        # Лучше понятная ошибка, чем 500 с трейсбеком
        return Response(
            f"File {path} was not found on the server",
            status=404,
            mimetype="text/plain",
        )

    return send_file(
        path,
        as_attachment=True,
        download_name=path.name,
        mimetype="text/yaml",
        max_age=0,
    )


# ───── Страница со списком сайтов (HTTP) ─────────────────────────────
@bp.route("/haproxy/sites", methods=["GET", "POST"])
def haproxy_sites_page():
    """
    Список HTTP-сайтов + простая форма добавления:

    - только поля: domain, backend_ip, backend_port;
    - после успешного добавления сразу редирект на /haproxy/sites/<domain>/edit.
    - support action=delete для старых форм (если где-то ещё используется).
    """
    error = None
    message = None

    if request.method == "POST":
        action = (request.form.get("action") or "add").strip()

        # ─── Удаление сайта (если откуда-то ещё прилетает) ───────────────────
        if action == "delete":
            name = (request.form.get("name") or "").strip()
            if not name:
                error = 'Site name is required for deletion'
            else:
                ok, msg = delete_site_by_name(name)
                record_request(
                    "site.delete",
                    object_type="site",
                    object_id=name,
                    result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                    detail="" if ok else str(msg)[:500],
                )
                if ok:
                    message = msg
                else:
                    error = msg

        # ─── Добавление сайта (упрощённая форма) ─────────────────────────────
        else:
            domain = (request.form.get("domain") or "").strip()
            site_type = (request.form.get("site_type") or "normal").strip()
            backend_ip = (request.form.get("backend_ip") or "").strip()
            backend_port_str = (request.form.get("backend_port") or "").strip()

            # An access gate is an Authelia-protected site with no upstream that
            # authorizes the visitor IP and serves a static welcome page. It is
            # chosen explicitly (site_type=gate) or implicitly by leaving the
            # backend empty. A gate ignores any backend fields.
            is_gate = site_type == "gate" or (not backend_ip and not backend_port_str)
            if is_gate:
                backend_ip = ""
                backend_port_str = ""
            if not domain:
                error = 'The Domain field is required'
            elif is_gate:
                pass
            elif not backend_ip or not backend_port_str:
                error = 'Provide both backend_ip and Port, or choose the access-gate site type'
            else:
                # Валидируем порт тут, чтобы сообщение было человеческое
                try:
                    backend_port = int(backend_port_str)
                except ValueError:
                    error = 'Port must be a number'
                else:
                    if not (1 <= backend_port <= 65535):
                        error = 'Port must be between 1 and 65535'

            if not error:
                # ВАЖНО: add_site_minimal ожидает (name, domain, backend_ip, backend_port)
                # name = domain
                ok, msg = add_site_minimal(
                    domain,           # name
                    domain,           # domain
                    backend_ip,
                    backend_port_str  # строка, как и ожидает add_site_minimal
                )
                record_request(
                    "site.create",
                    object_type="site",
                    object_id=domain,
                    result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                    summary=(
                        "access gate"
                        if is_gate
                        else f"backend: {backend_ip}:{backend_port_str}"
                    ),
                    detail="" if ok else str(msg)[:500],
                )
                if ok:
                    # сразу переходим на редактирование этого сайта
                    return redirect(url_for("routes.haproxy_site_edit", name=domain))
                else:
                    error = msg

    # GET или ошибка на POST — показать список и форму
    config_vars = _load_yaml(CONFIG_YAML)
    if not isinstance(config_vars, dict):
        config_vars = {}

    site_defaults, sites = get_sites_and_defaults_for_ui()
    return render_template(
        "haproxy_sites.html",
        sites=sites,
        site_defaults=site_defaults,
        config_vars=config_vars,
        error=error,
        message=message,
    )


@bp.get("/haproxy/mail")
def mail_settings_page():
    """Email delivery settings shared by Authelia and certificate hooks."""
    return render_template("mail_settings.html")


@bp.get("/haproxy/certs/api/acme-email")
def acme_email_view():
    try:
        return jsonify(get_acme_email())
    except Exception as exc:  # pylint: disable=broad-except
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.post("/haproxy/certs/api/acme-email")
def acme_email_save():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"email", "revision"}:
        return jsonify(
            {
                "ok": False,
                "validation_error": True,
                "error": "email and revision are required",
            }
        ), 400
    try:
        result = save_acme_email(payload.get("email"), payload.get("revision"))
    except Exception as exc:  # pylint: disable=broad-except
        traceback.print_exc()
        record_request(
            "acme_email.update",
            object_type="haproxy",
            object_id="acme_email",
            result=RESULT_FAILURE,
            detail=str(exc)[:500],
        )
        return jsonify({"ok": False, "error": str(exc)}), 500
    # The address itself is operator-supplied contact data, so the record notes
    # that it changed rather than to what.
    record_request(
        "acme_email.update",
        object_type="haproxy",
        object_id="acme_email",
        result=RESULT_SUCCESS if result.get("ok") else RESULT_FAILURE,
        summary="address: changed" if result.get("ok") else "",
        detail="" if result.get("ok") else str(result.get("error") or "")[:500],
    )
    if result.get("ok"):
        status = 200
    elif result.get("conflict") or result.get("pending"):
        status = 409
    elif result.get("validation_error"):
        status = 400
    else:
        status = 500
    return jsonify(result), status


@bp.route("/haproxy/certs", methods=["GET", "POST"])
def haproxy_certs_page():
    """
    HTML-страница со списком сертификатов и кнопками удаления.

    Все операции (чтение каталогов, удаление файлов, certbot delete)
    выполняет root-сервис haproxy-certd.
    """
    from .certd_client import (
        list_all_certs,
        delete_haproxy_cert,
        delete_le_cert,
        delete_external_ca,
        delete_internal_ca,
        ensure_internal_ca,
        issue_internal_cert_for_domain,
        rotate_internal_ca,
        upload_external_ca,
    )

    message = None
    error = None

    # Every certificate action below ends in one audit record. Uploaded bytes,
    # CA private keys and confirmation phrases never reach it — only which
    # action ran, against what, and whether it worked.
    CERT_AUDIT_ACTIONS = {
        "delete_haproxy": ("certificate.delete", "certificate"),
        "delete_le": ("certificate.delete", "letsencrypt"),
        "create_internal_ca": ("ca.create", "internal_ca"),
        "issue_internal_cert": ("certificate.issue", "certificate"),
        "rotate_internal_ca": ("ca.rotate", "internal_ca"),
        "delete_internal_ca": ("ca.delete", "internal_ca"),
        "import_external_ca": ("ca.import", "external_ca"),
        "delete_external_ca": ("ca.delete", "external_ca"),
    }

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        audit_target = ""

        if action == "delete_haproxy":
            path = (request.form.get("path") or "").strip()
            audit_target = path
            res = delete_haproxy_cert(path)
            if res.get("ok"):
                message = res.get(
                    "message") or f"HAProxy certificate deleted: {path}"
            else:
                error = (
                    res.get("message")
                    or res.get("error")
                    or 'Failed to delete the HAProxy certificate'
                )

        elif action == "delete_le":
            lineage = (request.form.get("lineage") or "").strip()
            audit_target = lineage
            res = delete_le_cert(lineage)
            if res.get("ok"):
                message = res.get(
                    "message") or f"Let's Encrypt certificate deleted: {lineage}"
            else:
                error = (
                    res.get("message")
                    or res.get("error")
                    or "Failed to delete the Let's Encrypt certificate"
                )

        elif action == "create_internal_ca":
            res = ensure_internal_ca()
            if res.get("ok"):
                message = res.get("message") or "Internal certificate authority is ready."
            else:
                error = res.get("error") or "Failed to create the internal certificate authority"

        elif action == "issue_internal_cert":
            domain = (request.form.get("domain") or "").strip()
            alt_names = [
                value.strip()
                for value in re.split(r"[,\s]+", request.form.get("alt_names") or "")
                if value.strip()
            ]
            audit_target = domain
            res = issue_internal_cert_for_domain(domain, alt_names)
            if res.get("ok"):
                message = res.get("message") or "Internal certificate issued successfully."
            else:
                error = res.get("error") or "Failed to issue the internal certificate"

        elif action == "rotate_internal_ca":
            res = rotate_internal_ca(request.form.get("confirmation") or "")
            if res.get("ok"):
                reissued = len(res.get("reissued") or [])
                message = (
                    res.get("message")
                    or f"Internal certificate authority rotated; certificates reissued: {reissued}."
                )
            else:
                error = res.get("error") or "Failed to rotate the internal certificate authority"

        elif action == "delete_internal_ca":
            res = delete_internal_ca(request.form.get("confirmation") or "")
            if res.get("ok"):
                message = res.get("message") or "Internal certificate authority deleted."
            else:
                error = res.get("error") or "Failed to delete the internal certificate authority"
                blockers = res.get("blocking_certificates") or []
                if blockers:
                    error += ": " + ", ".join(
                        ", ".join(item.get("domains") or []) or str(item.get("path") or "")
                        for item in blockers
                    )

        elif action == "import_external_ca":
            ca_file = request.files.get("ca_file")
            if not ca_file or not ca_file.filename:
                error = "Select a root or intermediate CA certificate bundle"
            else:
                audit_target = str(request.form.get("ca_name") or "").strip()
                res = upload_external_ca(
                    audit_target,
                    ca_file.read(),
                    ca_file.filename,
                )
                if res.get("ok"):
                    message = res.get("message") or "External certificate authority imported."
                else:
                    error = res.get("error") or "Failed to import the certificate authority"

        elif action == "delete_external_ca":
            audit_target = str(request.form.get("ca_id") or "").strip()
            res = delete_external_ca(audit_target)
            if res.get("ok"):
                message = res.get("message") or "External certificate authority deleted."
            else:
                error = res.get("error") or "Failed to delete the certificate authority"

        else:
            error = "Unknown action"

        if action in CERT_AUDIT_ACTIONS:
            audit_action, audit_object_type = CERT_AUDIT_ACTIONS[action]
            record_request(
                audit_action,
                object_type=audit_object_type,
                object_id=audit_target,
                result=RESULT_FAILURE if error else RESULT_SUCCESS,
                summary=f"action: {action}",
                detail=str(error or "")[:500],
            )

    data = list_all_certs()
    haproxy_certs = data.get("haproxy") or []
    le_certs = data.get("letsencrypt") or []
    authorities = data.get("certificate_authorities") or {}

    if not error and not data.get("ok"):
        error = data.get(
            "error") or 'Failed to get the certificate list from haproxy-certd'

    return render_template(
        "haproxy_certs.html",
        haproxy_certs=haproxy_certs,
        le_certs=le_certs,
        internal_ca=authorities.get("internal"),
        external_cas=authorities.get("external") or [],
        message=message,
        error=error,
    )


@bp.get("/haproxy/certs/ca/<ca_id>/download")
def haproxy_ca_download(ca_id):
    """Download public CA certificates; private CA keys never leave certd."""
    from .certd_client import export_ca_certificate

    result = export_ca_certificate(ca_id)
    if not result.get("ok"):
        abort(404)
    try:
        content = base64.b64decode(result.get("certificate_b64") or "", validate=True)
    except (ValueError, TypeError):
        abort(502)
    return send_file(
        io.BytesIO(content),
        as_attachment=True,
        download_name=result.get("filename") or f"{ca_id}.pem",
        mimetype="application/x-pem-file",
        max_age=0,
    )

# ───── Редактирование одного сайта ───────────────────────────────────


@bp.route("/haproxy/sites/<name>/edit", methods=["GET", "POST"])
def haproxy_site_edit(name):
    """
    Страница редактирования одного сайта:
      - отображаем текущие значения (raw + effective)
      - даём править поля
      - с этой же страницы можно удалить сайт (action=delete)

    ВАЖНО:
      * Сохранение параметров теперь идёт через JS (fetch на /haproxy/sites/save),
        поэтому POST здесь нужен только для action=delete (старый HTML-ф low).
    """
    error = None
    message = None

    site_defaults, site_raw, site_effective = get_site_raw_and_effective(name)
    if site_raw is None:
        abort(404)

    if request.method == "POST":
        action = request.form.get("action", "save")

        # ─── Удаление сайта ──────────────────────────────────────
        if action == "delete":
            ok, msg = delete_site_by_name(name)
            if ok:
                # после успешного удаления → назад к списку сайтов
                return redirect(url_for("routes.haproxy_sites_page"))
            else:
                error = msg

        # Сохранение через классическую HTML-форму мы оставляем на всякий случай,
        # но в нормальном сценарии его перехватывает JS и шлёт JSON на /haproxy/sites/save.
        elif action == "save":
            new_site, error = merge_site_from_edit_form(
                name, site_raw, request.form
            )
            if not error:
                ok, msg = save_site_raw(name, new_site)
                record_request(
                    "site.update",
                    object_type="site",
                    object_id=name,
                    result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                    summary=summarize(site_raw or {}, new_site) if ok else "",
                    detail="" if ok else str(msg)[:500],
                )
                if ok:
                    message = (
                        f"{msg} JavaScript was unavailable, so only the fields "
                        "this form carries were saved; the backend servers, "
                        "certificate source, key types and error-exclusion "
                        "rules were kept as they were."
                    )
                    # перечитаем сайт после сохранения
                    site_defaults, site_raw, site_effective = get_site_raw_and_effective(
                        name
                    )
                else:
                    error = msg

    # ВАЖНО: передаём original_name и is_new, чтобы JS знал, что редактируем существующий сайт
    from .certd_client import list_all_certs

    cert_data = list_all_certs()
    authorities = cert_data.get("certificate_authorities") or {}
    return render_template(
        "haproxy_site_edit.html",
        site=site_raw,
        eff=site_effective,
        site_defaults=site_defaults,
        error=error,
        message=message,
        original_name=name,
        is_new=False,
        external_cas=authorities.get("external") or [],
        dns_profiles=_available_dns_profiles(),
        geoip_country_codes=get_configured_geoip_countries(),
    )


@bp.post("/haproxy/sites/<name>/issue-cert")
def haproxy_site_issue_cert(name):
    from .certd_client import issue_cert_for_domain, issue_internal_cert_for_domain

    try:
        site_defaults, raw, eff = get_site_raw_and_effective(name)
        if raw is None:
            res = {
                "ok": False,
                "status": "ERROR",
                "message": f"Site {name!r} not found",
            }
            return jsonify(res), 200

        domain = eff.get("domain") or eff.get("name")
        if not domain:
            res = {
                "ok": False,
                "status": "ERROR",
                "message": 'The site has no domain',
            }
            return jsonify(res), 200

        alt_names = eff.get("alt_names") or []
        key_types = eff.get("key_types") or []

        payload = request.get_json(silent=True) or {}
        requested_source = str(payload.get("source") or "").strip().lower()
        source = requested_source or raw.get("certificate_source")
        if source not in ("letsencrypt", "external", "internal"):
            source = "letsencrypt" if raw.get("le_managed", True) else "external"
        if source == "external":
            raw_res = {
                "ok": False,
                "error": "External CA certificates must be uploaded with their private key.",
            }
        elif source == "internal":
            raw_res = issue_internal_cert_for_domain(domain, alt_names) or {}
        else:
            # Extra certificate names never take part in routing, so they are
            # added to the SAN list only, and only for a Let's Encrypt lineage.
            raw_res = issue_cert_for_domain(
                domain,
                list(alt_names) + list(eff.get("cert_alt_names") or []),
                key_types,
                dns_profile=str(eff.get("dns_profile") or ""),
            ) or {}
        res = dict(raw_res)  # Do not mutate the certificate client response.
        res.setdefault("source", source)

        # Normalize the status for the browser.
        if "ok" in res:
            res["status"] = "OK" if res["ok"] else "ERROR"
        elif "status" not in res:
            # Fallback for older certificate daemon responses.
            res["status"] = "UNKNOWN"

        # Normalize a useful user-facing message.
        if not res.get("message"):
            msg = (
                res.get("error")
                or res.get("details")
                or res.get("detail")
                or res.get("stderr")
                or res.get("stdout")
            )
            if msg:
                res["message"] = str(msg)
            else:
                res["message"] = 'no details'

        # An issuance attempt is worth recording either way. The summary names
        # the challenge and the profile, never a credential: certd does not
        # return one and the message is truncated regardless.
        challenge = "dns-01" if eff.get("dns_profile") else "http-01"
        summary = f"source: {source}, challenge: {challenge}"
        if eff.get("dns_profile"):
            summary += f", profile: {eff.get('dns_profile')}"
        record_request(
            "certificate.issue",
            object_type="site",
            object_id=name,
            result=RESULT_SUCCESS if res.get("ok") else RESULT_FAILURE,
            summary=summary,
            detail="" if res.get("ok") else str(res.get("message") or "")[:500],
        )

        return jsonify(res), 200

    except Exception as e:  # pylint: disable=broad-except
        traceback.print_exc()
        res = {
            "ok": False,
            "status": "ERROR",
            "message": f"Certificate issuance error: {e}",
        }
        # Preserve a real HTTP error for unexpected application failures.
        return jsonify(res), 500


@bp.route("/haproxy/certs/backup", methods=["GET"])
def haproxy_certs_backup():
    """
    Скачивание ZIP-архива с сертификатами (HAProxy + Let's Encrypt)
    через haproxy-certd.
    """
    import base64
    from datetime import datetime
    from flask import current_app, Response
    from .certd_client import backup_certs

    try:
        res = backup_certs()
    except Exception as exc:  # pylint: disable=broad-except
        current_app.logger.exception("Backup certs failed: %s", exc)
        return Response(
            'Certificate backup failed (see the haproxy-certd service log).',
            status=500,
            mimetype="text/plain",
        )

    if not res.get("ok"):
        msg = res.get("message") or res.get(
            "error") or 'Unknown backup error.'
        current_app.logger.warning("Backup certs returned error: %s", msg)
        return Response(
            f"Certificate backup error:\n{msg}",
            status=500,
            mimetype="text/plain",
        )

    # Exporting every certificate and private key off the gateway is one of
    # the most sensitive actions here, so the export itself is the record.
    record_request("certificate.export", object_type="certificate", object_id="all")

    archive_b64 = res.get("archive_b64")
    if not archive_b64:
        return Response(
            'The backup service did not return an archive (archive_b64 is empty).',
            status=500,
            mimetype="text/plain",
        )

    try:
        binary = base64.b64decode(archive_b64)
    except Exception as exc:  # pylint: disable=broad-except
        current_app.logger.exception("Decode archive_b64 failed: %s", exc)
        return Response(
            'Failed to decode the archive (base64 error).',
            status=500,
            mimetype="text/plain",
        )

    filename = f"haproxy_certs_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"

    resp = Response(binary, mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@bp.route("/haproxy/certs/restore", methods=["POST"])
def haproxy_certs_restore():
    """
    Восстановление сертификатов из загруженного ZIP-архива через haproxy-certd.

    Форма на /haproxy/certs должна выглядеть примерно так:

      <form action="{{ url_for('routes.haproxy_certs_restore') }}"
            method="post"
            enctype="multipart/form-data">
        <input type="file" name="archive" accept=".zip" required>
        <button type="submit" class="btn">Восстановить из бэкапа</button>
      </form>
    """
    from flask import current_app, request, redirect, url_for
    from .certd_client import restore_certs_from_archive

    file = request.files.get("archive")
    if not file or file.filename == "":
        current_app.logger.warning('haproxy_certs_restore: no file selected')
        return redirect(url_for("routes.haproxy_certs_page"))

    data = file.read()
    if not data:
        current_app.logger.warning('haproxy_certs_restore: empty file')
        return redirect(url_for("routes.haproxy_certs_page"))

    try:
        res = restore_certs_from_archive(data)
    except Exception as exc:  # pylint: disable=broad-except
        current_app.logger.exception(
            'haproxy_certs_restore: exception while calling certd')
        record_request(
            "certificate.restore",
            object_type="certificate",
            object_id="all",
            result=RESULT_FAILURE,
            summary=f"bytes: {len(data)}",
            detail=str(exc)[:500],
        )
        return redirect(url_for("routes.haproxy_certs_page"))

    if not res.get("ok"):
        msg = (res.get("message") or res.get("error") or "").strip()
        current_app.logger.warning(
            'haproxy_certs_restore: restore failed: %s',
            msg[:300],
        )
    record_request(
        "certificate.restore",
        object_type="certificate",
        object_id="all",
        result=RESULT_SUCCESS if res.get("ok") else RESULT_FAILURE,
        summary=f"bytes: {len(data)}",
        detail="" if res.get("ok") else (res.get("message") or res.get("error") or "")[:500],
    )

    # Пока без flash-сообщений — просто возвращаемся на страницу сертификатов.
    return redirect(url_for("routes.haproxy_certs_page"))


@bp.route("/haproxy/tcp", methods=["GET", "POST"])
def haproxy_tcp_page():
    """
    Список TCP-прокси + упрощённая форма добавления.

    Данные берутся из config/tcp.yml (ключ tcp_proxies).
    """
    error = None
    message = None

    if request.method == "POST":
        action = (request.form.get("action") or "add").strip()

        # ─── Удаление TCP-прокси (классический POST) ────────────────────────
        if action == "delete":
            name = (request.form.get("name") or "").strip()
            if not name:
                error = 'TCP proxy name is required for deletion'
            else:
                ok, msg = delete_tcp_proxy(name)
                record_request(
                    "tcp_proxy.delete",
                    object_type="tcp_proxy",
                    object_id=name,
                    result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                    detail="" if ok else str(msg)[:500],
                )
                if ok:
                    message = msg
                else:
                    error = msg

        # ─── Добавление TCP-прокси (упрощённая форма) ──────────────────────
        else:
            name = (request.form.get("name") or "").strip()
            bind_ip = (request.form.get("bind_ip") or "").strip() or "0.0.0.0"
            bind_port_str = (request.form.get("bind_port") or "").strip()
            backend_host = (request.form.get("backend_host") or "").strip()
            backend_port_str = (request.form.get("backend_port") or "").strip()
            balance = (request.form.get("balance") or "").strip() or "source"
            zero_trust = bool(request.form.get("zero_trust"))
            ban_check = bool(request.form.get("ban_check"))

            if not name:
                error = 'The TCP proxy Name field is required'
            elif not bind_port_str:
                error = 'The Bind port field is required'
            elif not backend_host or not backend_port_str:
                error = 'The backend_host and backend_port fields are required'
            else:
                try:
                    bind_port = int(bind_port_str)
                    backend_port = int(backend_port_str)
                except ValueError:
                    error = 'bind_port and backend_port must be numbers'
                else:
                    if not (1 <= bind_port <= 65535 and 1 <= backend_port <= 65535):
                        error = 'Ports must be between 1 and 65535'

            if not error:
                tcp_obj = {
                    "name": name,
                    "bind_ip": bind_ip,
                    "bind_port": bind_port,
                    "backend_host": backend_host,
                    "backend_port": backend_port,
                    "balance": balance,
                    "zero_trust": zero_trust,
                    "ban_check": ban_check,
                }
                ok, msg = save_tcp_from_json(tcp_obj, original_name=None)
                record_request(
                    "tcp_proxy.create",
                    object_type="tcp_proxy",
                    object_id=name,
                    result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                    summary=f"bind: {bind_ip}:{bind_port}, backend: {backend_host}:{backend_port}",
                    detail="" if ok else str(msg)[:500],
                )
                if ok:
                    # после успешного добавления → сразу на страницу редактирования
                    return redirect(url_for("routes.haproxy_tcp_edit", name=name))
                else:
                    error = msg

    tcp_proxies = get_tcp_proxies_list()
    return render_template(
        "haproxy_tcp.html",
        tcp_proxies=tcp_proxies,
        error=error,
        message=message,
    )


@bp.route("/haproxy/tcp/<name>/edit", methods=["GET", "POST"])
def haproxy_tcp_edit(name):
    """
    Страница редактирования одного TCP-прокси.

    Сохранение параметров происходит через JS (fetch на /haproxy/tcp/save),
    поэтому POST здесь нужен только для action=delete в fallback-режиме.
    """
    error = None
    message = None

    tcp_list = get_tcp_proxies_list()
    tcp_obj = None
    for t in tcp_list:
        if t.get("name") == name:
            tcp_obj = t
            break

    if tcp_obj is None:
        return render_template(
            "haproxy_tcp_edit.html",
            tcp={"name": name},
            error=f"TCP proxy with name={name!r} not found",
            message=None,
        ), 404

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()
        if action == "delete":
            ok, msg = delete_tcp_proxy(name)
            record_request(
                "tcp_proxy.delete",
                object_type="tcp_proxy",
                object_id=name,
                result=RESULT_SUCCESS if ok else RESULT_FAILURE,
                detail="" if ok else str(msg)[:500],
            )
            if ok:
                return redirect(url_for("routes.haproxy_tcp_page"))
            else:
                error = msg

    return render_template(
        "haproxy_tcp_edit.html",
        tcp=tcp_obj,
        error=error,
        message=message,
    )
