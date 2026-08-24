# -*- coding: utf-8 -*-
"""Клиент для общения с root-сервисом haproxy-certd.

По умолчанию работает через выделенный Unix-сокет easy-ha-proxy.
с использованием схемы http+unix:// (requests-unixsocket).

Если:
  - не установлен requests-unixsocket ИЛИ
  - переменная окружения CERTD_SOCKET_PATH пустая,

клиент откатывается на TCP (http://127.0.0.1:5001/api/v1), чтобы
можно было временно поднимать certd через встроенный Flask.
"""

import logging
from typing import Any, Dict, List, Optional
import base64
import os
from urllib.parse import quote_plus


import requests

try:
    import requests_unixsocket  # type: ignore[import]
except Exception:  # pragma: no cover - опциональная зависимость
    requests_unixsocket = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# ----- Транспорт: Unix-сокет по умолчанию -----

# Путь к сокету certd. Можно переопределить через CERTD_SOCKET_PATH,
# но по умолчанию он такой же, как в unit-файле haproxy-certd.service.
CERTD_SOCKET_PATH = os.environ.get(
    "CERTD_SOCKET_PATH", "/run/easy-ha-proxy/haproxy-certd.sock"
)

if requests_unixsocket is not None and CERTD_SOCKET_PATH:
    # Основной режим: HTTP через Unix-сокет
    encoded = quote_plus(CERTD_SOCKET_PATH)
    CERTD_API_BASE = f"http+unix://{encoded}/api/v1"
    _session: requests.Session = requests_unixsocket.Session()  # type: ignore[assignment]
    log.debug("haproxy-certd: using UNIX socket %s", CERTD_SOCKET_PATH)
else:
    # Fallback на TCP — только если нет requests-unixsocket или нет пути к сокету.
    CERTD_API_BASE = os.environ.get(
        "CERTD_HTTP_BASE",
        "http://127.0.0.1:5001/api/v1",
    )
    _session = requests.Session()
    if requests_unixsocket is None:
        log.warning(
            "requests-unixsocket is not installed; using TCP %s",
            CERTD_API_BASE,
        )
    elif not CERTD_SOCKET_PATH:
        log.warning(
            "CERTD_SOCKET_PATH is empty; using TCP %s",
            CERTD_API_BASE,
        )


def _post(url: str, **kwargs) -> requests.Response:
    """Обёртка вокруг session.post для единообразия."""
    return _session.post(url, **kwargs)


def _get(url: str, **kwargs) -> requests.Response:
    """Обёртка вокруг session.get для единообразия."""
    return _session.get(url, **kwargs)


class CertdUnavailable(RuntimeError):
    """certd не отвечает."""


def _dns_request(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Запрос к certd по разделу DNS-провайдеров.

    Ответ никогда не содержит сохранённых секретов: их не отдаёт сам демон.
    """

    url = f"{CERTD_API_BASE}/certs/{path}"
    try:
        resp = _post(url, json=payload, timeout=70.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd unreachable (%s): %s", url, exc)
        raise CertdUnavailable(str(exc)) from exc
    try:
        data = resp.json()
    except ValueError as exc:
        raise CertdUnavailable("certd returned a non-JSON response") from exc
    if not isinstance(data, dict):
        raise CertdUnavailable("certd returned an unexpected payload")
    return data


def dns_providers_list() -> Dict[str, Any]:
    return _dns_request("dns-providers", {})


def dns_provider_save(
    name: str, provider: str, credentials: Dict[str, str]
) -> Dict[str, Any]:
    return _dns_request(
        "dns-providers/save",
        {"name": name, "provider": provider, "credentials": credentials},
    )


def dns_provider_delete(name: str) -> Dict[str, Any]:
    return _dns_request("dns-providers/delete", {"name": name})


def _delivery_request(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Запрос к certd по разделу доставки сертификатов.

    Тот же контракт, что и у DNS-провайдеров: секреты уходят к демону и
    никогда не возвращаются -- он их не отдаёт.
    """

    url = f"{CERTD_API_BASE}/certs/{path}"
    try:
        # A test delivery talks to another machine over the network, so it
        # gets longer than an edit does.
        timeout = 200.0 if path.endswith("test") else 70.0
        resp = _post(url, json=payload, timeout=timeout)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd unreachable (%s): %s", url, exc)
        raise CertdUnavailable(str(exc)) from exc
    try:
        data = resp.json()
    except ValueError as exc:
        raise CertdUnavailable("certd returned a non-JSON response") from exc
    if not isinstance(data, dict):
        raise CertdUnavailable("certd returned an unexpected payload")
    return data


def cert_deliveries_list() -> Dict[str, Any]:
    return _delivery_request("deliveries", {})


def cert_delivery_save(payload: Dict[str, Any]) -> Dict[str, Any]:
    return _delivery_request("deliveries/save", payload)


def cert_delivery_delete(name: str) -> Dict[str, Any]:
    return _delivery_request("deliveries/delete", {"name": name})


def cert_delivery_test(name: str) -> Dict[str, Any]:
    return _delivery_request("deliveries/test", {"name": name})


def get_certs_status_for_domains(domains: List[str]) -> Dict[str, Dict[str, Any]]:
    """Запрашивает статусы сертификатов для списка доменов.

    Возвращает dict[domain] = status_dict.
    При ошибке возвращает {}.
    """
    if not domains:
        return {}

    uniq = sorted({(d or "").strip() for d in domains if d})
    if not uniq:
        return {}

    url = f"{CERTD_API_BASE}/certs/status"

    try:
        resp = _post(
            url,
            json={"domains": uniq},
            timeout=2.0,
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd unreachable (%s): %s", url, exc)
        return {}

    if not resp.ok:
        log.warning(
            "haproxy-certd HTTP %s for %s: %s",
            resp.status_code,
            resp.url,
            resp.text[:200],
        )
        return {}

    try:
        data = resp.json()
    except ValueError:
        log.warning(
            "haproxy-certd non-JSON response from %s: %s",
            resp.url,
            resp.text[:200],
        )
        return {}

    # !!! ВАЖНО: сохраняю твою семантику: certd возвращает {"items": {...}}
    items = data.get("items") or {}
    if not isinstance(items, dict):
        return {}

    return items


def _normalize_cert_issue_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Приводит ответ certd к виду, удобному для UI:
      - гарантирует поля ok, status, message
      - аккумулирует ошибки из results[*].stderr/stdout и pem_*
      - отдельно вытаскивает строки Detail:/Hint: из вывода certbot
    """
    res: Dict[str, Any] = dict(data or {})

    # ---- ok / status ----
    ok = bool(res.get("ok"))
    res["ok"] = ok
    if "status" not in res:
        res["status"] = "OK" if ok else "ERROR"

    # Если уже есть message — не переопределяем
    if res.get("message"):
        return res

    # Если есть error — поднимаем его в message
    if res.get("error"):
        res["message"] = str(res["error"])
        return res

    detail_blocks: list[str] = []
    generic_blocks: list[str] = []

    results = res.get("results") or []
    for entry in results:
        if not isinstance(entry, dict):
            continue

        rc = entry.get("rc")
        if rc is None:
            continue

        lineage = entry.get("lineage") or ""

        stderr_text = (entry.get("stderr") or "")
        stdout_text = (entry.get("stdout") or "")
        combined = (stderr_text + "\n" + stdout_text).strip()

        header = f"[{lineage or 'certbot'}]"

        if not combined:
            generic_blocks.append(
                f"{header} exit code {rc} (no output)."
            )
            continue

        lines = combined.splitlines()

        # Вытаскиваем человекочитаемые строки: Detail:/Hint:
        detail_lines: list[str] = []
        hint_lines: list[str] = []
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith("Detail:"):
                detail_lines.append(stripped)
            elif stripped.startswith("Hint:"):
                hint_lines.append(stripped)

        if detail_lines or hint_lines:
            block_lines = [header]
            block_lines.extend(detail_lines)
            block_lines.extend(hint_lines)
            detail_blocks.append("\n".join(block_lines))

        # Полный вывод на случай, если нужно копнуть глубже
        # (ограничим, чтобы не заливать весь UI)
        trimmed = lines
        if len(trimmed) > 20:
            trimmed = trimmed[:20] + ["... (truncated)"]

        generic_blocks.append(
            f"{header} exit code {rc}\n" + "\n".join(trimmed)
        )

    # Ошибки при сборке PEM / reload HAProxy
    pem_rc = res.get("pem_rc")
    if pem_rc not in (None, 0):
        pem_err = (res.get("pem_stderr") or res.get("pem_stdout") or "").strip()
        header = "[haproxy-pems-reload]"
        if pem_err:
            pem_lines = pem_err.splitlines()
            if len(pem_lines) > 20:
                pem_lines = pem_lines[:20] + ["... (truncated)"]
            generic_blocks.append(
                f"{header} exit code {pem_rc}\n" + "\n".join(pem_lines)
            )
        else:
            generic_blocks.append(
                f"{header} exit code {pem_rc} (no output)."
            )

    msg_parts: list[str] = []

    if detail_blocks:
        msg_parts.append("ACME rejection reason:\n" + "\n\n".join(detail_blocks))

    if generic_blocks:
        if detail_blocks:
            msg_parts.append('\n--- Full certbot output ---\n')
        msg_parts.append("\n\n".join(generic_blocks))

    if not msg_parts:
        if ok:
            res["message"] = 'Request completed successfully with no errors.'
        else:
            res["message"] = (
                'The request failed, but certd returned no details. '
                "Check the haproxy-certd service log."
            )
    else:
        res["message"] = "\n".join(msg_parts)

    return res


def upload_cert_for_site(
    site_name: str,
    domain: str,
    pem_bytes: bytes,
    filename: str = "cert.pem",
    external_ca_id: str = "",
) -> Dict[str, Any]:
    """Отправляет PEM-сертификат в haproxy-certd для сохранения от имени сайта.

    Используется HTTP multipart/form-data:
      - cert_file (файл)
      - site_name
      - domain
    """
    site_name = (site_name or "").strip()
    domain = (domain or "").strip()

    url = f"{CERTD_API_BASE}/certs/upload"

    files = {
        "cert_file": (filename or "cert.pem", pem_bytes, "application/x-pem-file"),
    }
    data = {
        "site_name": site_name,
        "domain": domain,
        "external_ca_id": (external_ca_id or "").strip(),
    }

    try:
        resp = _post(
            url,
            data=data,
            files=files,
            timeout=60.0,
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd upload failed (%s): %s", url, exc)
        return {
            "ok": False,
            "error": f"haproxy-certd unreachable: {exc}",
        }

    try:
        data = resp.json()
    except ValueError:
        return {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    # Гарантируем флаг ok и человекочитаемое message для UI
    res: Dict[str, Any] = dict(data)
    ok = bool(res.get("ok"))
    res["ok"] = ok
    if not ok and not res.get("message"):
        if res.get("error"):
            res["message"] = str(res["error"])
        else:
            res["message"] = 'Certificate upload failed through haproxy-certd'
    return res


def get_cert_status_for_domain(domain: str) -> Dict[str, Any]:
    """Упрощённая обёртка: статус для одного домена."""
    domain = (domain or "").strip()
    if not domain:
        return {}

    statuses = get_certs_status_for_domains([domain])
    return statuses.get(domain, {})


def backup_certs() -> Dict[str, Any]:
    """
    Просит haproxy-certd сделать ZIP-бэкап сертификатов и вернуть его в base64.

    Возвращает dict с полями:
      - ok: bool
      - archive_b64: str (если ok)
      - message, error, ...
    """
    url = f"{CERTD_API_BASE}/certs/backup"

    try:
        resp = _post(url, json={}, timeout=600.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd backup failed (%s): %s", url, exc)
        res = {"ok": False, "error": f"haproxy-certd unreachable: {exc}"}
        return _normalize_cert_issue_response(res)

    try:
        data = resp.json()
    except ValueError:
        res = {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }
        return _normalize_cert_issue_response(res)

    if not isinstance(data, dict):
        data = {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    return _normalize_cert_issue_response(data)


def restore_certs_from_archive(archive_bytes: bytes) -> Dict[str, Any]:
    """
    Отправляет ZIP-бэкап (bytes) в haproxy-certd для восстановления.

    Возвращает dict с ok, message, error, pem_rc и т.п.
    """
    if not archive_bytes:
        res = {"ok": False, "error": "archive_bytes is empty"}
        return _normalize_cert_issue_response(res)

    archive_b64 = base64.b64encode(archive_bytes).decode("ascii")

    payload = {"archive_b64": archive_b64}
    url = f"{CERTD_API_BASE}/certs/restore"

    try:
        resp = _post(url, json=payload, timeout=600.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd restore failed (%s): %s", url, exc)
        res = {"ok": False, "error": f"haproxy-certd unreachable: {exc}"}
        return _normalize_cert_issue_response(res)

    try:
        data = resp.json()
    except ValueError:
        res = {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }
        return _normalize_cert_issue_response(res)

    if not isinstance(data, dict):
        data = {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    return _normalize_cert_issue_response(data)


def issue_cert_for_domain(
    domain: str,
    alt_names: List[str],
    key_types: List[str],
    dns_profile: str = "",
    dns_propagation: Optional[int] = None,
) -> Dict[str, Any]:
    """Просит haproxy-certd выпустить/обновить сертификат для домена.

    Используется в routes_haproxy_sites (кнопка "Выпустить сертификат").
    С профилем DNS-провайдера challenge будет DNS-01 — единственный способ
    получить wildcard.
    """
    domain = (domain or "").strip()
    if not domain:
        res = {"ok": False, "error": "domain is empty"}
        return _normalize_cert_issue_response(res)

    payload: Dict[str, Any] = {
        "domain": domain,
        "alt_names": [str(x).strip() for x in (alt_names or []) if x],
        "key_types": key_types or [],
    }
    if dns_profile:
        payload["dns_profile"] = str(dns_profile).strip().lower()
        if dns_propagation is not None:
            payload["dns_propagation"] = dns_propagation

    url = f"{CERTD_API_BASE}/certs/issue"

    try:
        resp = _post(
            url,
            json=payload,
            timeout=600.0,  # certbot может работать довольно долго
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd issue failed (%s): %s", url, exc)
        res = {"ok": False, "error": f"haproxy-certd unreachable: {exc}"}
        return _normalize_cert_issue_response(res)

    try:
        data = resp.json()
    except ValueError:
        res = {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }
        return _normalize_cert_issue_response(res)

    if not isinstance(data, dict):
        data = {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    return _normalize_cert_issue_response(data)


def issue_internal_cert_for_domain(
    domain: str, alt_names: List[str]
) -> Dict[str, Any]:
    """Issue a server certificate with the local root CA."""
    url = f"{CERTD_API_BASE}/certs/ca/internal/issue"
    payload = {
        "domain": (domain or "").strip(),
        "alt_names": [str(value).strip() for value in (alt_names or []) if value],
    }
    try:
        response = _post(url, json=payload, timeout=120.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def ensure_internal_ca() -> Dict[str, Any]:
    """Create the local root CA once, without returning its private key."""
    url = f"{CERTD_API_BASE}/certs/ca/internal/ensure"
    try:
        response = _post(url, json={}, timeout=120.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def rotate_internal_ca(confirmation: str) -> Dict[str, Any]:
    """Rotate the local root CA and reissue every active certificate it signed."""
    url = f"{CERTD_API_BASE}/certs/ca/internal/rotate"
    try:
        response = _post(
            url,
            json={"confirmation": (confirmation or "").strip()},
            timeout=180.0,
        )
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def delete_internal_ca(confirmation: str) -> Dict[str, Any]:
    """Delete the local root CA only when no active certificate depends on it."""
    url = f"{CERTD_API_BASE}/certs/ca/internal/delete"
    try:
        response = _post(
            url,
            json={"confirmation": (confirmation or "").strip()},
            timeout=30.0,
        )
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def upload_external_ca(name: str, pem_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Import a public root/intermediate CA bundle."""
    url = f"{CERTD_API_BASE}/certs/ca/upload"
    try:
        response = _post(
            url,
            data={"name": (name or "").strip()},
            files={"ca_file": (filename or "ca.pem", pem_bytes, "application/x-pem-file")},
            timeout=60.0,
        )
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def inspect_certificate_material(
    payload: bytes, filename: str, password: str = "", name: str = "", domain: str = ""
) -> Dict[str, Any]:
    """Ask what a file is. Changes nothing on the gateway."""
    return _material_request("inspect", payload, filename, password, name, domain)


def import_certificate_material(
    payload: bytes,
    filename: str,
    password: str = "",
    name: str = "",
    domain: str = "",
    replace: bool = False,
) -> Dict[str, Any]:
    """Import whatever the file turned out to contain."""
    return _material_request(
        "import", payload, filename, password, name, domain, replace=replace
    )


def _material_request(
    action: str,
    payload: bytes,
    filename: str,
    password: str,
    name: str,
    domain: str,
    replace: bool = False,
) -> Dict[str, Any]:
    url = f"{CERTD_API_BASE}/certs/{action}"
    data = {"password": password, "name": name, "domain": domain}
    if replace:
        data["replace"] = "true"
    try:
        response = _post(
            url,
            data=data,
            files={
                "file": (
                    filename or "upload.pem",
                    payload,
                    "application/octet-stream",
                )
            },
            timeout=60.0,
        )
        result = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return result if isinstance(result, dict) else {
        "ok": False,
        "error": "unexpected response from haproxy-certd",
    }


def export_ca_certificate(ca_id: str) -> Dict[str, Any]:
    """Return a public CA certificate bundle encoded by certd."""
    url = f"{CERTD_API_BASE}/certs/ca/export"
    try:
        response = _post(url, json={"ca_id": ca_id}, timeout=10.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def delete_external_ca(ca_id: str) -> Dict[str, Any]:
    """Delete an imported public CA bundle."""
    url = f"{CERTD_API_BASE}/certs/ca/delete-external"
    try:
        response = _post(url, json={"ca_id": ca_id}, timeout=10.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def set_client_auth_cas(ca_ids: List[str]) -> Dict[str, Any]:
    """Replace the set of authorities trusted to authenticate clients.

    The whole list is sent, not a single toggle: two requests racing over one
    file would otherwise decide the trust set by arrival order.
    """
    url = f"{CERTD_API_BASE}/certs/ca/client-auth"
    try:
        response = _post(url, json={"ids": ca_ids}, timeout=30.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def set_revoked_client_certificates(fingerprints: List[str]) -> Dict[str, Any]:
    """Replace the list of client certificates refused by fingerprint."""
    url = f"{CERTD_API_BASE}/certs/ca/revoked"
    try:
        response = _post(url, json={"fingerprints": fingerprints}, timeout=30.0)
        data = response.json()
    except Exception as exc:  # pylint: disable=broad-except
        return {"ok": False, "error": f"haproxy-certd request failed: {exc}"}
    return data if isinstance(data, dict) else {"ok": False, "error": "unexpected response from haproxy-certd"}


def list_all_certs() -> Dict[str, Any]:
    """Запрашивает у haproxy-certd полный список сертификатов."""

    url = f"{CERTD_API_BASE}/certs/list"

    try:
        resp = _get(url, timeout=5.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd list failed (%s): %s", url, exc)
        return {
            "ok": False,
            "error": f"haproxy-certd unreachable: {exc}",
            "haproxy": [],
            "letsencrypt": [],
            "certificate_authorities": {"internal": None, "external": []},
        }

    if not resp.ok:
        log.warning(
            "haproxy-certd HTTP %s for %s: %s",
            resp.status_code,
            resp.url,
            resp.text[:200],
        )
        return {
            "ok": False,
            "error": f"haproxy-certd HTTP {resp.status_code}",
            "haproxy": [],
            "letsencrypt": [],
            "certificate_authorities": {"internal": None, "external": []},
        }

    try:
        data = resp.json()
    except ValueError:
        log.warning(
            "haproxy-certd non-JSON response from %s: %s",
            resp.url,
            resp.text[:200],
        )
        return {
            "ok": False,
            "error": "haproxy-certd non-JSON response",
            "haproxy": [],
            "letsencrypt": [],
            "certificate_authorities": {"internal": None, "external": []},
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
            "haproxy": [],
            "letsencrypt": [],
            "certificate_authorities": {"internal": None, "external": []},
        }

    data.setdefault("haproxy", [])
    data.setdefault("letsencrypt", [])
    data.setdefault("certificate_authorities", {"internal": None, "external": []})
    data.setdefault("ok", True)
    return data


def delete_haproxy_cert(path: str) -> Dict[str, Any]:
    """Удаляет PEM из каталога HAProxy через haproxy-certd."""
    path = (path or "").strip()
    if not path:
        return {"ok": False, "error": "empty path"}

    url = f"{CERTD_API_BASE}/certs/delete-haproxy"
    payload = {"path": path}

    try:
        resp = _post(url, json=payload, timeout=10.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd delete-haproxy failed (%s): %s", url, exc)
        return {"ok": False, "error": f"haproxy-certd unreachable: {exc}"}

    try:
        data = resp.json()
    except ValueError:
        return {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    data.setdefault("ok", False)
    return data


def delete_le_cert(lineage: str) -> Dict[str, Any]:
    """Удаляет lineage Let's Encrypt через certbot delete."""
    lineage = (lineage or "").strip()
    if not lineage:
        return {"ok": False, "error": "empty lineage"}

    url = f"{CERTD_API_BASE}/certs/delete-le"
    payload = {"lineage": lineage}

    try:
        resp = _post(url, json=payload, timeout=60.0)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("haproxy-certd delete-le failed (%s): %s", url, exc)
        return {"ok": False, "error": f"haproxy-certd unreachable: {exc}"}

    try:
        data = resp.json()
    except ValueError:
        return {
            "ok": False,
            "error": (
                f"haproxy-certd non-JSON response (HTTP {resp.status_code}) "
                f"from {resp.url}: {resp.text[:200]}"
            ),
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "error": f"unexpected JSON from certd: {data!r}",
        }

    data.setdefault("ok", False)
    return data
