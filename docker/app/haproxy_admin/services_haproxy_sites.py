# services_haproxy_sites.py
# Helpers for websites.yml:
# - the list of sites
# - adding and removing
# - the effective settings, with site_defaults applied
# - saving the changes to one site
from .certd_client import (
    get_cert_status_for_domain,
    issue_cert_for_domain,
    issue_internal_cert_for_domain,
)
from typing import Any, Dict, List, Tuple, Optional
import logging
import re
import yaml
from pathlib import Path
import ssl
from datetime import datetime, timezone
from .services_haproxy_config import (
    WEBSITES_YAML,
    CONFIG_YAML,
    _load_yaml,
    check_entry_revision,
    entry_revision,
    source_lock,
    update_yaml_file,
    jinja_combine,
)
from .validation import (
    CA_ID_RE,
    site_identity_conflict,
    validate_cidr,
    validate_domain,
    validate_host,
    validate_identifier,
    validate_port,
)

logger = logging.getLogger("haproxy-admin")

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
#CERT_WARN_DAYS = 30  # how many days before expiry to show a warning


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
    haproxy_certs_dir from vars.yml (CONFIG_YAML),
    /etc/haproxy/certs by default.
    """
    cfg = _load_yaml(CONFIG_YAML)
    path_str = cfg.get("haproxy_certs_dir") or str(DEFAULT_HAPROXY_CERTS_DIR)
    try:
        return Path(path_str)
    except TypeError:
        return DEFAULT_HAPROXY_CERTS_DIR


def _parse_not_after(not_after: str) -> Optional[datetime]:
    """
    Parses an OpenSSL notAfter string.
    Usually in the form 'Nov 30 12:00:00 2025 GMT'.
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
    Reads a certificate from disk and returns:
      - not_after (datetime)
      - days_left (int)
    None if the file is missing, unreadable or cannot be parsed.
    """
    try:
        # path.exists() calls stat() and may raise PermissionError
        if not path.exists():
            return None

        # _test_decode_cert may fail too, with PermissionError, OSError or another error
        info = ssl._ssl._test_decode_cert(str(path))
    except Exception:
        # Any error reading the certificate means "this certificate is not available to us"
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
    This code no longer touches the filesystem: all certificate work is
    done by the root service haproxy-certd.
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

    # If the service is unavailable or answers empty, do not break the UI
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
    # The display format can be changed here if wanted
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def get_websites_list() -> List[Dict[str, Any]]:
    """
    Returns the list of sites from websites.yml, as it is.
    """
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return []
    return sites


# Two independent pauses, for a site that should go quiet for a while without
# its configuration being deleted -- say, a domain pointed straight at its
# server for now. "paused" takes it out of HAProxy; "cert_renewal_paused"
# stops its certificate being renewed or reissued. Only an explicit true
# pauses, so a site written before these keys existed is unaffected.
PAUSE_KEYS = ("paused", "cert_renewal_paused")


def site_is_paused(site: Dict[str, Any]) -> bool:
    return isinstance(site, dict) and site.get("paused") is True


def renewal_is_paused(site: Dict[str, Any]) -> bool:
    return isinstance(site, dict) and site.get("cert_renewal_paused") is True


def renewal_paused_domains() -> List[str]:
    """The domains whose certificates must not be renewed, for certd."""

    domains = []
    for site in get_websites_list():
        if renewal_is_paused(site) and site.get("domain"):
            domains.append(str(site["domain"]).strip().lower())
    return sorted(set(domains))


def set_site_pause(name: str, key: str, paused: bool) -> Tuple[bool, str]:
    """Pause or resume one aspect of a site, leaving the rest as it is."""

    if key not in PAUSE_KEYS:
        return False, f"Unknown pause setting {key!r}"
    with source_lock("websites"):
        for site in get_websites_list():
            if isinstance(site, dict) and site.get("name") == name:
                updated = dict(site)
                if paused:
                    updated[key] = True
                else:
                    updated.pop(key, None)
                if key == "paused" and not paused:
                    # Back in HAProxy: its names must be free again.
                    others = [s for s in get_websites_list()
                              if not (isinstance(s, dict) and s.get("name") == name)]
                    conflict = site_identity_conflict(updated, others)
                    if conflict:
                        return False, conflict
                return save_site_raw(name, updated)
    return False, f"Site {name!r} was not found"


def site_revision(name: str) -> Optional[str]:
    """The fingerprint of a stored site, for its edit form; None when absent."""

    for site in get_websites_list():
        if isinstance(site, dict) and (site.get("name") or "").strip() == name:
            return entry_revision(site)
    return None


def sync_renewal_pauses() -> Dict[str, Any]:
    """Tell certd which certificates certbot must leave alone.

    Best effort: a gateway whose certd predates this feature keeps renewing
    as before, and saying so is better than failing the save it follows.
    """

    from . import certd_client

    try:
        return certd_client.set_renewal_pauses(renewal_paused_domains())
    except Exception as exc:  # noqa: BLE001 - never fail the caller over it
        return {"ok": False, "error": str(exc)}


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
    with source_lock("websites"):
        return _add_site_minimal(name, domain, backend_ip, backend_port)


def _add_site_minimal(
    name: str,
    domain: str,
    backend_ip: str,
    backend_port: str,
) -> Tuple[bool, str]:
    """
    Adds a minimal site:
      - name, domain, backend_ip, backend_port
    Everything else comes from site_defaults in the template.

    An empty backend_ip and backend_port make an access gate (access_gate):
    a site without a backend that, after an Authelia sign-in, serves a static
    page and authorises the visitor's IP.
    """
    backend_ip = (backend_ip or "").strip()
    backend_port = str(backend_port or "").strip()
    if not backend_ip and not backend_port:
        if _load_yaml(CONFIG_YAML).get('authelia_enabled', True) is False:
            return False, 'Enable Authelia before creating a service site'
        data = _load_yaml(WEBSITES_YAML)
        sites = data.get("sites") or []
        if not isinstance(sites, list):
            sites = []
        gate = {
            "name": name,
            "domain": domain,
            "access_gate": True,
            "authelia_enabled": True,
            "allow_ips": [],
            "tcp_passthrough": False,
            "zero_trust": False,
            "redirect_to_https": True,
            "access_portal_enabled": True,
        }
        conflict = site_identity_conflict(gate, sites)
        if conflict:
            return False, conflict
        # No site has this name now, so whatever is stored under it was left
        # by an earlier one: a new site starts with nothing published.
        _discard_access_page(name)
        sites.append(gate)
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
            return True, _with_gate_rule_outcome(msg, domain, rule_ok, rule_msg)
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

    new_site = {
        "name": name,
        "domain": domain,
        "backend_ip": backend_ip,
        "backend_port": port_int,
    }
    conflict = site_identity_conflict(new_site, sites)
    if conflict:
        return False, conflict
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
    Deletes the site with this name from websites.yml.
    """
    with source_lock("websites"):
        return _delete_site_by_name(name)


def _delete_site_by_name(name: str) -> Tuple[bool, str]:
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
    if ok:
        _discard_access_page(name)
    return ok, msg


def _discard_access_page(name: str) -> None:
    """Take a site's access-page instructions and files out of service.

    They are stored under the site's name, so a site created later with the
    same name would otherwise publish them again. Never a reason to fail the
    change to the site itself.
    """
    try:
        from . import access_portal

        access_portal.discard(name)
    except Exception:  # pylint: disable=broad-except
        logger.warning("The access-page storage of site %r could not be set aside", name, exc_info=True)


def delete_site(name: str) -> Tuple[bool, str]:
    """
    Compatibility for routes_haproxy_sites:
    simply calls delete_site_by_name(name).
    """
    return delete_site_by_name(name)


def get_sites_and_defaults_for_ui() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    For the list page:
      - returns site_defaults from vars.yml
      - and the list of sites, each as:
          {
            "raw": {...},        # as in websites.yml
            "effective": {...},  # site_defaults + site (as the template sees it)
            "cert": {...},       # the certificate's state
          }
    """
    config_vars = _load_yaml(CONFIG_YAML)
    site_defaults = config_vars.get("site_defaults") or {}
    if not isinstance(site_defaults, dict):
        site_defaults = {}

    sites_raw = get_websites_list()
    sites_ui: List[Dict[str, Any]] = []

    for s in sites_raw:
        # the site's effective settings (as the template uses them)
        eff = jinja_combine(site_defaults, s, recursive=True)

        # the certificate's state (HAProxy only, LE only, both or none)
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
    For the edit page:
      - returns site_defaults
      - the site as it is (as in websites.yml)
      - the site as effective (site_defaults + site)
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

def save_site_from_json(
    site: Dict[str, Any],
    original_name: Optional[str] = None,
    expected_revision: Optional[str] = None,
) -> Tuple[bool, str]:
    """Save a site from its form; raises StaleEntry when expected_revision
    no longer matches the stored site. See _save_site_from_json."""

    with source_lock("websites"):
        return _save_site_from_json(site, original_name, expected_revision)


def _save_site_from_json(
    site: Dict[str, Any],
    original_name: Optional[str] = None,
    expected_revision: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Saves a site from JSON (the edit or create form).

    site is what the front end sent, as it is.
    original_name:
      - empty/None  -> create a new site
      - non-empty   -> edit the existing site of this name; it may be renamed
    """
    if not isinstance(site, dict):
        return False, 'Invalid site format (expected a JSON object)'

    # --- the basic fields name / domain -----------------------------------------
    try:
        name = validate_identifier(
            site.get("name") or site.get("domain"), "name"
        )
        domain = validate_domain(site.get("domain") or name)
    except ValueError as exc:
        return False, str(exc)

    # Work on a copy so the original dict is not spoiled
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
                # a backend without a host is of no use
                continue

            try:
                host = validate_host(host, f"servers[{idx}].host")
                port_int = validate_port(port, f"servers[{idx}].port")
            except ValueError as exc:
                return False, str(exc)

            srv_out: Dict[str, Any] = {}

            # the backup flag
            backup_flag = bool(srv.get("backup"))

            # Make sure the backend has a name
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

            # Weight (optional)
            if "weight" in srv and srv["weight"] not in (None, ""):
                try:
                    srv_out["weight"] = int(srv["weight"])
                except (TypeError, ValueError):
                    # if it cannot be converted, simply leave it out
                    pass

            cleaned_servers.append(srv_out)

    if cleaned_servers:
        site_out["servers"] = cleaned_servers

        # IMPORTANT: with more than one backend, backend_ip/backend_port are
        # obsolete and removed, so the information cannot contradict itself.
        if len(cleaned_servers) > 1:
            site_out.pop("backend_ip", None)
            site_out.pop("backend_port", None)

    # --- backend_ip / backend_port for a single backend -------------------
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
        # If one of them is empty, drop both, so no junk is kept
        site_out.pop("backend_ip", None)
        site_out.pop("backend_port", None)

    # --- read the current websites.yml ----------------------------------------
    data = _load_yaml(WEBSITES_YAML)
    sites = data.get("sites") or []
    if not isinstance(sites, list):
        return False, 'Invalid websites.yml structure (expected a sites list)'

    # --- create a new site or update the existing one ---------------------------
    orig_norm = (original_name or "").strip() or None

    # The editor rebuilds the whole site from its form, so a key it does not
    # mention would be dropped. A page loaded before the pauses existed must
    # not resume a paused site by saving something else.
    previous = next(
        (s for s in sites if isinstance(s, dict)
         and (s.get("name") or "").strip() == (orig_norm or "")),
        {},
    )
    if orig_norm is not None:
        # The form was loaded with this site as it was then; another
        # session's save since would be lost under this one.
        check_entry_revision(previous or None, expected_revision, "This site")
    for key in PAUSE_KEYS:
        if key not in site:
            if previous.get(key) is True:
                site_out[key] = True
        elif site.get(key) is True:
            site_out[key] = True
        else:
            site_out.pop(key, None)

    # This setting belongs to the access-page editor, not the site form.
    if 'access_portal_enabled' not in site and previous.get('access_portal_enabled') is True:
        site_out['access_portal_enabled'] = True

    # The site being edited is not its own rival; every other one is.
    others = [
        s for s in sites
        if orig_norm is None or not isinstance(s, dict)
        or (s.get("name") or "").strip() != orig_norm
    ]
    conflict = site_identity_conflict(site_out, others)
    if conflict:
        return False, conflict

    if orig_norm is None:
        # Creating a new site
        sites.append(site_out)
    else:
        # Editing an existing one (it may be renamed)
        replaced = False
        for idx, s in enumerate(sites):
            if (s.get("name") or "").strip() == orig_norm:
                sites[idx] = site_out
                replaced = True
                break

        if not replaced:
            return False, f"Site {orig_norm!r} was not found"

    data["sites"] = sites

    # --- save the YAML ------------------------------------------------------
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
        return True, _with_gate_rule_outcome(msg, domain, rule_ok, rule_msg)
    return ok, msg


def _with_gate_rule_outcome(msg: str, domain: str, rule_ok: bool, rule_msg: str) -> str:
    """The save's message, plus what it did to Authelia.

    Unlike the rest of a site save, which waits for the HAProxy apply, the
    gate's Authelia rule and restart are live at once -- so the operator is
    told, whichever way it went.
    """

    if not rule_ok:
        return (
            f"{msg} Note: the Authelia login rule for the gate could not be "
            f"added automatically ({rule_msg}); add a one_factor rule for "
            f"{domain} on the Authelia access rules page."
        )
    if rule_msg == "rule added":
        return (
            f"{msg} Authelia now has a one_factor access rule for this gate "
            "and was restarted to load it; that took effect at once, before "
            "the HAProxy apply."
        )
    if rule_msg.startswith("rule saved"):
        return (
            f"{msg} The Authelia access rule for this gate was saved, but "
            "Authelia could not be restarted to load it; restart it on the "
            f"Authelia page ({rule_msg})."
        )
    return msg


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
    Replaces the site of this name with new_site in websites.yml.
    new_site is the raw object (only the keys that belong in the YAML).
    site_defaults are not added here, so the defaults keep working from
    one place.
    """
    with source_lock("websites"):
        return _save_site_raw(name, new_site)


def save_access_site_identity(name, domain, paused, expected_revision, *, delete=False, backend=None):
    """The service-site editor changes identity/publication only, never proxy options.

    One exception, for a site that predates the split: a gate that already
    proxies to a single backend of its own. The proxy editor no longer opens
    gates, so without this the address of that backend could not be changed
    from the panel at all. `backend` is its (address, port); a service site
    with no backend cannot be given one here.
    """
    with source_lock('websites'):
        _, raw, effective = get_site_raw_and_effective(name)
        if raw is None or effective.get('access_gate') is not True:
            return False, 'Access page not found'
        if not expected_revision:
            return False, 'Reload the service site before saving'
        check_entry_revision(raw, expected_revision, 'This site')
        if delete:
            return _delete_site_by_name(name)
        try:
            domain = validate_domain(domain)
        except ValueError as exc:
            return False, str(exc)
        updated = {**raw, 'domain': domain}
        if paused:
            updated['paused'] = True
        else:
            updated.pop('paused', None)
        if backend is not None:
            if not raw.get('backend_ip') or raw.get('servers'):
                return False, 'This service site has no single backend of its own to change'
            try:
                updated['backend_ip'] = validate_host(str(backend[0] or '').strip(), 'backend_ip')
                updated['backend_port'] = validate_port(backend[1], 'backend_port')
            except ValueError as exc:
                return False, str(exc)
        others = [site for site in get_websites_list() if site.get('name') != name]
        conflict = site_identity_conflict(updated, others)
        if conflict:
            return False, conflict
        ok, message = _save_site_raw(name, updated)
        if ok and domain != raw.get('domain'):
            rule_ok, rule_msg = _ensure_access_gate_authelia_rule([domain])
            message = _with_gate_rule_outcome(message, domain, rule_ok, rule_msg)
        return ok, message


def _save_site_raw(name: str, new_site: Dict[str, Any]) -> Tuple[bool, str]:
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
        # A paused site is not published, and a paused renewal is exactly the
        # instruction not to issue: its name may well point elsewhere by now,
        # and a challenge that cannot succeed would block every apply.
        if site_is_paused(raw) or renewal_is_paused(raw):
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
