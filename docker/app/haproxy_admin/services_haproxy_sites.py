# services_haproxy_sites.py
# Вспомогательные функции для работы с websites.yml:
# - список сайтов
# - добавление/удаление
# - получение effective-настроек с учётом site_defaults
# - сохранение изменений одного сайта
from .certd_client import (
    get_cert_status_for_domain,
    issue_cert_for_domain,
    issue_internal_cert_for_domain,
)
from typing import Any, Dict, List, Tuple, Optional
import re
import yaml
from pathlib import Path
import ssl
from datetime import datetime, timezone
from .services_haproxy_config import (
    WEBSITES_YAML,
    CONFIG_YAML,
    _load_yaml,
    update_yaml_file,
    jinja_combine,
)
from .validation import (
    CA_ID_RE,
    validate_cidr,
    validate_domain,
    validate_host,
    validate_identifier,
    validate_port,
)

DEFAULT_HAPROXY_CERTS_DIR = Path("/etc/haproxy/certs")
# certd derives one issuers file per authority that is trusted to authenticate
# clients. The directory is mounted read-only into the container, so this is
# the same evidence HAProxy itself will use rather than a second opinion.
MTLS_DIR = Path("/etc/haproxy/mtls")
ISO_ALPHA2_RE = re.compile(r"^[A-Z]{2}$")
# Must stay in step with DNS_PROFILE_RE in haproxy-certd.py: the profile name
# is a file name in a root-owned directory on the other side.
DNS_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
#LE_LIVE_DIR = Path("/etc/letsencrypt/live")
#CERT_WARN_DAYS = 30  # за сколько дней до истечения показывать предупреждение


def _normalize_allow_ips(value: Any) -> List[str]:
    """Canonicalise the per-site access list, keeping the operator's order.

    Order is kept because the operator reads this list back; duplicates are
    dropped because two identical entries in a src ACL are noise, not intent.
    """
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        value = [part for part in re.split(r"[,;\s]+", value) if part]
    if not isinstance(value, list):
        raise ValueError("The access list must be a list of addresses or networks")
    if len(value) > 64:
        raise ValueError("The access list may hold at most 64 addresses")
    seen: List[str] = []
    for index, entry in enumerate(value):
        canonical = validate_cidr(entry, f"allow_ips[{index}]")
        if canonical not in seen:
            seen.append(canonical)
    return seen


def client_auth_ca_ids() -> Optional[set]:
    """Authorities a site may name for client certificates.

    ``None`` means the answer is unknown -- the directory does not exist,
    which is the case on a gateway where nobody has ever opened the feature
    and in every test that does not set one up. An unknown answer must not
    block a save; a known one must.
    """
    try:
        if not MTLS_DIR.is_dir():
            return None
        return {
            path.stem[len("issuers-"):]
            for path in MTLS_DIR.glob("issuers-*.list")
        }
    except OSError:
        return None


def _get_haproxy_certs_dir() -> Path:
    """
    Берём haproxy_certs_dir из vars.yml (CONFIG_YAML),
    по умолчанию /etc/haproxy/certs.
    """
    cfg = _load_yaml(CONFIG_YAML)
    path_str = cfg.get("haproxy_certs_dir") or str(DEFAULT_HAPROXY_CERTS_DIR)
    try:
        return Path(path_str)
    except TypeError:
        return DEFAULT_HAPROXY_CERTS_DIR


def _parse_not_after(not_after: str) -> Optional[datetime]:
    """
    Парсим строку notAfter из сертификата OpenSSL.
    Обычно формат: 'Nov 30 12:00:00 2025 GMT'
    """
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(not_after, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _load_cert_info(path: Path) -> Optional[Dict[str, Any]]:
    """
    Читает сертификат с диска и возвращает:
      - not_after (datetime)
      - days_left (int)
    Если файл not found, нет прав или не удаётся прочитать — None.
    """
    try:
        # path.exists() внутри себя делает stat() и может выбросить PermissionError
        if not path.exists():
            return None

        # _test_decode_cert тоже может упасть с PermissionError / OSError / др. ошибкой
        info = ssl._ssl._test_decode_cert(str(path))
    except Exception:
        # Любая ошибка чтения сертификата = "сертификат для нас недоступен"
        return None

    not_after_str = info.get("notAfter")
    not_after_dt = _parse_not_after(not_after_str)
    if not not_after_dt:
        return None

    now = datetime.now(timezone.utc)
    days_left = (not_after_dt - now).days

    return {
        "path": str(path),
        "not_after": not_after_dt,
        "days_left": days_left,
    }


def get_cert_status_for_site(eff: Dict[str, Any]) -> Dict[str, Any]:
    """
    Теперь этот код не трогает файловую систему.
    Вся работа с сертификатами вынесена в root-сервис haproxy-certd.
    """
    domain = eff.get("domain") or eff.get("name")
    domain = (domain or "").strip()

    if not domain:
        return {
            "state": "no_domain",
            "short": 'no domain',
            "tooltip": 'Cannot check certificate: the site has no domain.',
            "haproxy_path": None,
            "haproxy_has": False,
            "haproxy_not_after": None,
            "haproxy_days_left": None,
            "le_path": None,
            "le_has": False,
            "le_not_after": None,
            "le_days_left": None,
        }

    status = get_cert_status_for_domain(domain)

    # Если сервис недоступен / вернул пусто — не ломаем UI
    if not status:
        return {
            "state": "unknown",
            "short": "unknown",
            "tooltip": 'Certificate checking service is unavailable.',
            "haproxy_path": None,
            "haproxy_has": False,
            "haproxy_not_after": None,
            "haproxy_days_left": None,
            "le_path": None,
            "le_has": False,
            "le_not_after": None,
            "le_days_left": None,
        }

    return status


def _fmt_date(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    # Можно поменять формат отображения при желании
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def get_websites_list() -> List[Dict[str, Any]]:
    """
    Возвращает список сайтов из websites.yml (как есть).
    """
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return []
    return sites


def get_configured_geoip_countries() -> List[str]:
    """Return the canonical country set materialized by the GeoIP updater."""
    config_vars = _load_yaml(CONFIG_YAML)
    raw_countries = config_vars.get("geoip_country_codes") or []
    if not isinstance(raw_countries, list):
        return []
    countries = {
        str(value).strip().upper()
        for value in raw_countries
        if isinstance(value, str)
        and ISO_ALPHA2_RE.fullmatch(str(value).strip().upper())
    }
    return sorted(countries)


def _normalize_site_geo_countries(value: Any) -> List[str]:
    """Validate a per-site country override against the active global set."""
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("geo_countries must be a list of ISO alpha-2 country codes")
    if len(value) > 249:
        raise ValueError("geo_countries must contain at most 249 country codes")

    countries: set[str] = set()
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError("geo_countries must contain only strings")
        code = raw.strip().upper()
        if not ISO_ALPHA2_RE.fullmatch(code):
            raise ValueError(f"Invalid GeoIP country code: {raw!r}")
        countries.add(code)

    normalized = sorted(countries)
    available = set(get_configured_geoip_countries())
    unavailable = sorted(set(normalized) - available)
    if unavailable:
        raise ValueError(
            "Select these countries on the global GeoIP page first: "
            + ", ".join(unavailable)
        )
    return normalized


def _normalize_name_list(value: Any, label: str, limit: int) -> List[str]:
    """Accept a list, or a textarea/comma separated string, of DNS names."""
    if value in (None, ""):
        return []
    if isinstance(value, str):
        items = [part for part in re.split(r"[,\s]+", value) if part]
    elif isinstance(value, list):
        items = []
        for raw in value:
            if not isinstance(raw, str):
                raise ValueError(f"{label} must contain only strings")
            text = raw.strip()
            if text:
                items.append(text)
    else:
        raise ValueError(f"{label} must be a list of DNS names")
    if len(items) > limit:
        raise ValueError(f"{label} must contain at most {limit} names")
    return items


def _normalize_site_alt_names(value: Any, domain: str) -> List[str]:
    """Validate the additional routing names of a site.

    These land in ``hdr(host) -i`` and ``ssl_fc_sni -i`` ACLs, so they are
    matched literally and a wildcard among them would silently route nothing.
    """
    seen: List[str] = []
    for raw in _normalize_name_list(value, "alt_names", 100):
        name = validate_domain(raw, "alt_names")
        if name == domain or name in seen:
            continue
        seen.append(name)
    return seen


def _normalize_site_cert_alt_names(
    value: Any, *, allow_wildcard: bool, taken: List[str]
) -> List[str]:
    """Validate names that exist only to widen the certificate's SAN list."""
    already = {name for name in taken if name}
    seen: List[str] = []
    for raw in _normalize_name_list(value, "cert_alt_names", 100):
        name = validate_domain(
            raw, "cert_alt_names", allow_wildcard=allow_wildcard
        )
        if name in already or name in seen:
            continue
        seen.append(name)
    return seen


def add_site_minimal(
    name: str,
    domain: str,
    backend_ip: str,
    backend_port: str,
) -> Tuple[bool, str]:
    """
    Добавляет минимальный сайт:
      - name, domain, backend_ip, backend_port
    Остальные параметры тянутся из site_defaults в шаблоне.

    Пустые backend_ip и backend_port создают шлюз доступа (access_gate):
    сайт без бекенда, который после входа через Authelia отдаёт статичную
    страницу и авторизует IP посетителя.
    """
    backend_ip = (backend_ip or "").strip()
    backend_port = str(backend_port or "").strip()
    if not backend_ip and not backend_port:
        data = _load_yaml(WEBSITES_YAML)
        sites = data.get("sites") or []
        if not isinstance(sites, list):
            sites = []
        for s in sites:
            if s.get("name") == name:
                return False, f"A site named {name!r} already exists"
        sites.append(
            {
                "name": name,
                "domain": domain,
                "access_gate": True,
                "authelia_enabled": True,
            }
        )
        data["sites"] = sites
        content = yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
        ok, msg = update_yaml_file("websites", content)
        if ok:
            rule_ok, rule_msg = _ensure_access_gate_authelia_rule([domain])
            if not rule_ok:
                return True, (
                    f"{msg} Note: add a one_factor Authelia rule for {domain} "
                    f"on the access rules page ({rule_msg})."
                )
        return ok, msg

    try:
        port_int = int(backend_port)
    except ValueError:
        return False, 'backend_port must be a number'

    if not (1 <= port_int <= 65535):
        return False, 'backend_port must be between 1 and 65535'

    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        sites = []

    # Проверка на дубликаты по name
    for s in sites:
        if s.get("name") == name:
            return False, f"A site named {name!r} already exists"

    new_site = {
        "name": name,
        "domain": domain,
        "backend_ip": backend_ip,
        "backend_port": port_int,
    }
    sites.append(new_site)
    data["sites"] = sites

    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("websites", content)
    return ok, msg


def delete_site_by_name(name: str) -> Tuple[bool, str]:
    """
    Удаляет сайт по name из websites.yml.
    """
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return False, 'Invalid websites.yml structure (expected a sites list)'

    new_sites: List[Dict[str, Any]] = []
    removed = False
    for s in sites:
        if s.get("name") == name:
            removed = True
            continue
        new_sites.append(s)

    if not removed:
        return False, f"Site {name!r} was not found"

    data["sites"] = new_sites
    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("websites", content)
    return ok, msg


def delete_site(name: str) -> Tuple[bool, str]:
    """
    Совместимость для routes_haproxy_sites:
    просто вызывает delete_site_by_name(name).
    """
    return delete_site_by_name(name)


def get_sites_and_defaults_for_ui() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Для страницы списка:
      - возвращает site_defaults из vars.yml
      - и список сайтов вида:
          {
            "raw": {...},        # как в websites.yml
            "effective": {...},  # site_defaults + site (как в шаблоне)
            "cert": {...},       # статус сертификата
          }
    """
    config_vars = _load_yaml(CONFIG_YAML)
    site_defaults = config_vars.get("site_defaults") or {}
    if not isinstance(site_defaults, dict):
        site_defaults = {}

    sites_raw = get_websites_list()
    sites_ui: List[Dict[str, Any]] = []

    for s in sites_raw:
        # effective-настройки сайта (как использует шаблон)
        eff = jinja_combine(site_defaults, s, recursive=True)

        # статус сертификата (может быть только HAProxy, LE, оба или ничего)
        cert = get_cert_status_for_site(eff)

        sites_ui.append(
            {
                "raw": s,
                "effective": eff,
                "cert": cert,
            }
        )

    return site_defaults, sites_ui


def get_site_raw_and_effective(
    name: str,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Для страницы редактирования:
      - возвращает site_defaults
      - сайт в "сыром" виде (как в websites.yml)
      - сайт в виде effective (site_defaults + site)
    """
    config_vars = _load_yaml(CONFIG_YAML)
    site_defaults = config_vars.get("site_defaults") or {}
    if not isinstance(site_defaults, dict):
        site_defaults = {}

    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        sites = []

    for s in sites:
        if s.get("name") == name:
            eff = jinja_combine(site_defaults, s, recursive=True)
            return site_defaults, s, eff

    return site_defaults, None, None

def save_site_from_json(site: Dict[str, Any], original_name: Optional[str] = None) -> Tuple[bool, str]:
    """
    Сохранение сайта из JSON (форма редактирования/создания).

    site — то, что пришло с фронта (как есть).
    original_name:
      - пусто/None  -> создаём новый сайт
      - непустая    -> редактируем существующий (под этим name), можно переименовать
    """
    if not isinstance(site, dict):
        return False, 'Invalid site format (expected a JSON object)'

    # --- базовые поля name / domain -----------------------------------------
    try:
        name = validate_identifier(
            site.get("name") or site.get("domain"), "name"
        )
        domain = validate_domain(site.get("domain") or name)
    except ValueError as exc:
        return False, str(exc)

    # Работаем с копией, чтобы не портить исходный словарь
    site_out: Dict[str, Any] = dict(site)
    site_out["name"] = name
    site_out["domain"] = domain

    # An absent or empty override deliberately keeps the legacy global
    # ``allowed.geo`` behavior. Non-empty overrides may only reference country
    # ACLs that the root-managed GeoIP updater has materialized.
    try:
        geo_countries = _normalize_site_geo_countries(
            site_out.get("geo_countries")
        )
    except ValueError as exc:
        return False, str(exc)
    if geo_countries:
        site_out["geo_countries"] = geo_countries
    else:
        site_out.pop("geo_countries", None)

    # New installations store an explicit certificate source. Preserve the
    # previous le_managed flag so older templates remain compatible.
    certificate_source = str(site_out.get("certificate_source") or "").strip()
    if certificate_source not in ("letsencrypt", "external", "internal"):
        certificate_source = (
            "letsencrypt" if site_out.get("le_managed", True) else "external"
        )
    site_out["certificate_source"] = certificate_source
    site_out["le_managed"] = certificate_source == "letsencrypt"

    # Routing names go into HAProxy ACLs verbatim, so they must be real names.
    # They were never validated here, which let a stray value reach the
    # generated configuration.
    try:
        alt_names = _normalize_site_alt_names(site_out.get("alt_names"), domain)
    except ValueError as exc:
        return False, str(exc)
    if alt_names:
        site_out["alt_names"] = alt_names
    else:
        site_out.pop("alt_names", None)

    # DNS-01 validation, and with it wildcard certificates, only exists for
    # Let's Encrypt lineages.
    dns_profile = ""
    if certificate_source == "letsencrypt":
        dns_profile = str(site_out.get("dns_profile") or "").strip().lower()
        if dns_profile and not DNS_PROFILE_RE.fullmatch(dns_profile):
            return False, "Invalid DNS provider profile name"
    if dns_profile:
        site_out["dns_profile"] = dns_profile
    else:
        site_out.pop("dns_profile", None)

    # Extra certificate names never reach an ACL: they only widen the SAN list,
    # which is what makes a wildcard useful here — new subdomains can be routed
    # later without touching the certificate.
    try:
        cert_alt_names = _normalize_site_cert_alt_names(
            site_out.get("cert_alt_names"),
            allow_wildcard=bool(dns_profile),
            taken=[domain] + alt_names,
        )
    except ValueError as exc:
        return False, str(exc)
    if cert_alt_names:
        if certificate_source == "external":
            return False, (
                "Extra certificate names do not apply to an external "
                "certificate authority"
            )
        site_out["cert_alt_names"] = cert_alt_names
    else:
        site_out.pop("cert_alt_names", None)

    # A site restricted to named addresses. Everything else about the site
    # still works -- the backend, the certificate -- but nobody outside this
    # list ever reaches it, and for those inside it the sorting gates are off.
    try:
        allow_ips = _normalize_allow_ips(site_out.get("allow_ips"))
    except ValueError as exc:
        return False, str(exc)
    if allow_ips:
        site_out["allow_ips"] = allow_ips
    else:
        site_out.pop("allow_ips", None)

    # Client certificates. Deliberately independent of certificate_source: the
    # authority that signs this site's server certificate has no bearing on
    # which authority may vouch for a visitor, and reusing one for the other
    # by default is exactly the accident worth preventing.
    mtls_mode = str(site_out.get("mtls_mode") or "disabled").strip().lower()
    if mtls_mode not in ("disabled", "optional", "required"):
        return False, "Client certificate mode must be disabled, optional or required"
    if mtls_mode == "disabled":
        site_out.pop("mtls_mode", None)
        site_out.pop("mtls_ca_id", None)
    else:
        mtls_ca_id = str(site_out.get("mtls_ca_id") or "").strip().lower()
        if not mtls_ca_id:
            return False, "Select a certificate authority for client certificates"
        if not CA_ID_RE.fullmatch(mtls_ca_id):
            return False, "Invalid client certificate authority identifier"
        trusted = client_auth_ca_ids()
        # An authority that was never marked for client authentication has no
        # issuers file, and the configuration would name a file that does not
        # exist. Refuse here, where it can be explained, rather than at reload.
        if trusted is not None and mtls_ca_id not in trusted:
            return False, (
                f"The certificate authority {mtls_ca_id!r} is not trusted for "
                "client authentication. Enable it on the Certificates page first."
            )
        site_out["mtls_mode"] = mtls_mode
        site_out["mtls_ca_id"] = mtls_ca_id

    if certificate_source == "external":
        external_ca_id = str(site_out.get("external_ca_id") or "").strip().lower()
        if not external_ca_id:
            return False, "Select an imported external certificate authority"
        if (
            len(external_ca_id) > 120
            or external_ca_id in (".", "..")
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in external_ca_id)
        ):
            return False, "Invalid external certificate authority identifier"
        site_out["external_ca_id"] = external_ca_id
    else:
        site_out.pop("external_ca_id", None)

    # --- backend servers -----------------------------------------------------
    cleaned_servers: List[Dict[str, Any]] = []
    servers = site_out.get("servers")

    if isinstance(servers, list):
        for idx, srv in enumerate(servers, start=1):
            if not isinstance(srv, dict):
                continue

            host = str(srv.get("host") or "").strip()
            port = srv.get("port")

            if not host:
                # backend без host нам не нужен
                continue

            try:
                host = validate_host(host, f"servers[{idx}].host")
                port_int = validate_port(port, f"servers[{idx}].port")
            except ValueError as exc:
                return False, str(exc)

            srv_out: Dict[str, Any] = {}

            # backup-флаг
            backup_flag = bool(srv.get("backup"))

            # Гарантируем имя бэкенда
            name_srv = str(srv.get("name") or "").strip()
            if not name_srv:
                name_srv = f"backup{idx}" if backup_flag else f"srv{idx}"
            try:
                name_srv = validate_identifier(name_srv, f"servers[{idx}].name")
            except ValueError as exc:
                return False, str(exc)

            srv_out["name"] = name_srv
            srv_out["host"] = host
            srv_out["port"] = port_int

            if backup_flag:
                srv_out["backup"] = True

            # Вес (опционально)
            if "weight" in srv and srv["weight"] not in (None, ""):
                try:
                    srv_out["weight"] = int(srv["weight"])
                except (TypeError, ValueError):
                    # если не получилось преобразовать — просто не пишем
                    pass

            cleaned_servers.append(srv_out)

    if cleaned_servers:
        site_out["servers"] = cleaned_servers

        # ВАЖНО: если backend'ов больше одного — backend_ip/backend_port считаем
        # устаревшими и убираем их, чтобы не было противоречивой информации.
        if len(cleaned_servers) > 1:
            site_out.pop("backend_ip", None)
            site_out.pop("backend_port", None)

    # --- backend_ip / backend_port для одиночного бэкенда -------------------
    backend_ip = str(site_out.get("backend_ip") or "").strip()
    backend_port = site_out.get("backend_port")

    if backend_ip and backend_port is not None:
        try:
            backend_ip = validate_host(backend_ip, "backend_ip")
            backend_port_int = validate_port(backend_port, "backend_port")
        except ValueError as exc:
            return False, str(exc)
        else:
            site_out["backend_ip"] = backend_ip
            site_out["backend_port"] = backend_port_int
    else:
        # Если один из них пустой — убираем оба, чтобы не хранить мусор
        site_out.pop("backend_ip", None)
        site_out.pop("backend_port", None)

    # --- читаем текущий websites.yml ----------------------------------------
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return False, 'Invalid websites.yml structure (expected a sites list)'

    # --- создаём новый или обновляем существующий ---------------------------
    name_norm = name
    orig_norm = (original_name or "").strip() or None

    if orig_norm is None:
        # Создание нового сайта
        for s in sites:
            if (s.get("name") or "").strip() == name_norm:
                return False, f"A site named {name_norm!r} already exists"

        sites.append(site_out)
    else:
        # Редактирование существующего (возможен rename)
        replaced = False
        for idx, s in enumerate(sites):
            if (s.get("name") or "").strip() == orig_norm:
                sites[idx] = site_out
                replaced = True
                break

        if not replaced:
            return False, f"Site {orig_norm!r} was not found"

    data["sites"] = sites

    # --- сохраняем YAML ------------------------------------------------------
    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("websites", content)
    if not ok:
        return ok, msg

    # An access gate is useless while Authelia's default_policy=deny rejects its
    # domain, so make sure a login rule exists. Best-effort: never fail the save
    # over it, but tell the operator when the rule could not be ensured.
    if site_out.get("access_gate") is True:
        gate_domains = [domain] + [
            str(a).strip()
            for a in (site_out.get("alt_names") or [])
            if str(a).strip()
        ]
        rule_ok, rule_msg = _ensure_access_gate_authelia_rule(gate_domains)
        if not rule_ok:
            return True, (
                f"{msg} Note: the Authelia login rule for the gate could not be "
                f"added automatically ({rule_msg}); add a one_factor rule for "
                f"{domain} on the Authelia access rules page."
            )
    return ok, msg


def _ensure_access_gate_authelia_rule(domains: List[str]) -> Tuple[bool, str]:
    """Ensure Authelia has a login rule for each access-gate domain.

    Idempotent: a domain that already appears in any rule is left untouched so
    an operator's manual policy (e.g. two_factor) is never overwritten.
    """
    try:
        from .authelia_acl import (
            load_rules_yaml,
            save_rules_from_yaml,
            _configd_request,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"authelia rules helper unavailable: {exc}"

    try:
        rules = yaml.safe_load(load_rules_yaml()) or []
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot read current rules: {exc}"
    if not isinstance(rules, list):
        rules = []

    def _covered(dom: str) -> bool:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rdomain = rule.get("domain")
            names = rdomain if isinstance(rdomain, list) else [rdomain]
            if any(str(n).strip().lower() == dom.lower() for n in names):
                return True
        return False

    missing = [d for d in domains if d and not _covered(d)]
    if not missing:
        return True, "already present"

    for dom in missing:
        rules.append({"domain": dom, "policy": "one_factor"})

    try:
        rules_yaml = yaml.safe_dump(
            rules, allow_unicode=True, default_flow_style=False, sort_keys=False
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot serialize rules: {exc}"

    ok, msg = save_rules_from_yaml(rules_yaml)
    if not ok:
        return ok, msg

    # A saved rule only becomes active after Authelia reloads its configuration,
    # so restart it (the manual access-rules editor does the same). Best-effort:
    # the rule is already persisted and will also load on the next apply.
    try:
        restart = _configd_request({"action": "restart"})
        if not restart.get("ok"):
            return True, (
                "rule saved; restart Authelia to activate it "
                f"({restart.get('error') or 'restart failed'})"
            )
    except Exception as exc:  # noqa: BLE001
        return True, f"rule saved; restart Authelia to activate it ({exc})"
    return True, "rule added"


def save_site_raw(name: str, new_site: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Заменяет сайт с данным name на new_site в websites.yml.
    new_site — это уже "сырой" объект (только те ключи, которые должны быть
    в YAML). Не добавляем сюда site_defaults, чтобы дефолты продолжали
    работать централизованно.
    """
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return False, 'Invalid websites.yml structure (expected a sites list)'

    new_sites: List[Dict[str, Any]] = []
    found = False
    for s in sites:
        if s.get("name") == name:
            new_sites.append(new_site)
            found = True
        else:
            new_sites.append(s)

    if not found:
        return False, f"Site {name!r} was not found"

    data["sites"] = new_sites
    content = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    ok, msg = update_yaml_file("websites", content)
    return ok, msg


def ensure_certs_before_apply() -> Dict[str, Any]:
    """
    Ensure the certificate required by each TLS-terminating site exists.

    Let's Encrypt and internal certificates can be issued automatically.
    External CA certificates must be uploaded by an administrator.
    """
    site_defaults, sites_ui = get_sites_and_defaults_for_ui()
    actions = []

    for item in sites_ui:
        eff = item.get("effective") or {}
        raw = item.get("raw") or {}
        if eff.get("tcp_passthrough"):
            continue
        source = raw.get("certificate_source")
        if source not in ("letsencrypt", "external", "internal"):
            source = "letsencrypt" if raw.get("le_managed", True) else "external"

        status = get_cert_status_for_site(eff)
        state = status.get("state")

        # Issue missing/expired certificates. Renew internal certificates when
        # they enter the warning window; external certificates remain manual.
        if state in ("missing", "expired") or (
            source == "internal" and state == "warning"
        ):
            domain = eff.get("domain") or eff.get("name")
            alt_names = eff.get("alt_names") or []
            key_types = eff.get("key_types") or []

            if source == "letsencrypt":
                res = issue_cert_for_domain(
                    domain,
                    list(alt_names) + list(eff.get("cert_alt_names") or []),
                    key_types,
                    dns_profile=str(eff.get("dns_profile") or ""),
                )
            elif source == "internal":
                res = issue_internal_cert_for_domain(domain, alt_names)
            else:
                res = {
                    "ok": False,
                    "error": (
                        "The site uses an external certificate authority, but no valid "
                        "server certificate is installed. Upload its certificate, chain, "
                        "and matching private key before applying HAProxy."
                    ),
                }
            actions.append({"domain": domain, "result": res})

            if not res.get("ok"):
                return {"ok": False, "actions": actions}

    return {"ok": True, "actions": actions}


# def create_empty_site() -> Tuple[Dict[str, Any], Dict[str, Any]]:
#     """
#     Возвращает заготовку пустого сайта и site_defaults для формы createdия.

#     Возвращаем кортеж:
#       (site, site_defaults)

#     site — то, что попадает в шаблон как `site`:
#       - поля либо пустые, либо с безопасными дефолтами
#       - все остальные значения будут подхватываться через site_defaults
#         в шаблоне HAProxy.
#     """
#     # Тянем site_defaults из vars.yml (CONFIG_YAML)
#     config_vars = _load_yaml(CONFIG_YAML)
#     site_defaults = config_vars.get("site_defaults") or {}
#     if not isinstance(site_defaults, dict):
#         site_defaults = {}

#     # Базовая заготовка сайта для формы
#     site: Dict[str, Any] = {
#         "name": "",
#         "domain": "",
#         "maintenance": False,

#         # HTTP backend по умолчанию (как в примерах)
#         "backend_ip": "",
#         "backend_port": site_defaults.get("backend_port") or 80,
#         "backend_host": "",

#         # SSL к бэкенду: по умолчанию как в site_defaults, если есть
#         "backend_ssl": site_defaults.get("backend_ssl", False),
#         "backend_ssl_verify": site_defaults.get("backend_ssl_verify", True),
#         "backend_alpn": site_defaults.get("backend_alpn", "http/1.1"),

#         # Дополнительные фичи
#         "authelia_enabled": False,
#         "zero_trust": False,
#         "redirect_to_https": True,
#         "tcp_passthrough": False,

#         # Сертификаты
#         "key_types": site_defaults.get("key_types", ["rsa"]),
#         "alt_names": [],

#         # Backend-серверы: изначально пустой список
#         # (форма сама добавит main/backup по необходимости)
#         "servers": [],

#         # Логические штуки, которые часто нужны на форме:
#         "max_req_rate": None,
#         "rate_ban": None,
#         "rate_errors": None,
#         "err_ignore_rules": None,
#     }

#     return site, site_defaults
