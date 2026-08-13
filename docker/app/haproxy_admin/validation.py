"""Validation shared by the UI editors and whole-file YAML uploads."""
from __future__ import annotations

import ipaddress
import re
from typing import Any


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
HOST_RE = re.compile(r"^[A-Za-z0-9_.:%-]{1,253}$")
# A single hostname label such as a container or LAN short name.
HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$")
ISO_ALPHA2_RE = re.compile(r"^[A-Z]{2}$")
# A DNS-01 profile name is a file name in a root-owned directory on the certd
# side; keep this in step with DNS_PROFILE_RE in haproxy-certd.py.
DNS_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
# A CA identifier becomes a file name under /etc/haproxy/mtls and a token in
# the generated configuration, so it stays to what _safe_slug already allows.
CA_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}$")
INTERVAL_RE = re.compile(r"^[1-9][0-9]*(?:ms|s|m|h|d)$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z0-9-]{2,63}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
BALANCE_VALUES = {
    "roundrobin", "static-rr", "leastconn", "first", "source",
    "uri", "url_param", "hdr", "random", "rdp-cookie",
}
CONTROL_PLANE_ACL_RE = re.compile(
    r"^\s*acl\s+(host_admin|host_authelia)\s+"
    r"hdr\(host\)\s+-i\s+(.+?)\s*$",
    re.MULTILINE,
)


def validate_identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not IDENTIFIER_RE.fullmatch(text):
        raise ValueError(
            f"{label}: only Latin letters, digits, '.', '_', and '-' are allowed (up to 128 characters)"
        )
    return text


def validate_domain(
    value: Any, label: str = "domain", *, allow_wildcard: bool = False
) -> str:
    """Validate a DNS name.

    A wildcard is refused by default. HAProxy matches routing names literally
    (``hdr(host) -i``, ``ssl_fc_sni -i``), so a ``*.example.com`` used as a
    routing name would build a configuration that passes ``haproxy -c`` and
    then never matches a request. Only names that exist purely to appear on a
    certificate may be wildcards.
    """
    text = str(value or "").strip().lower()
    if not DOMAIN_RE.fullmatch(text):
        raise ValueError(f"{label}: invalid DNS name")
    text = text.rstrip(".")
    if text.startswith("*."):
        if not allow_wildcard:
            raise ValueError(
                f"{label}: a wildcard is only allowed among the extra "
                f"certificate names, and only with DNS-01 validation"
            )
        if len(text.split(".")) < 3:
            raise ValueError(
                f"{label}: a wildcard needs at least two labels beneath it"
            )
    return text


def validate_host(value: Any, label: str) -> str:
    """Accept an IPv4/IPv6 literal or a DNS name.

    The character class alone would pass structurally impossible values such
    as "1.2.3.4.5" or "---", which only fail later during the HAProxy
    configuration check with a message that does not point at the field.
    """
    text = str(value or "").strip()
    if not HOST_RE.fullmatch(text) or CONTROL_RE.search(text):
        raise ValueError(f"{label}: invalid IP address or hostname")
    literal = text
    if literal.startswith("[") and literal.endswith("]"):
        literal = literal[1:-1]
    # An IPv6 literal may carry a zone index (fe80::1%eth0).
    literal = literal.split("%", 1)[0]
    try:
        ipaddress.ip_address(literal)
        return text
    except ValueError:
        pass
    if ":" in text:
        # Only an IP literal may contain a colon; a DNS name may not.
        raise ValueError(f"{label}: invalid IP address or hostname")
    labels = text.split(".")
    if all(part.isdigit() for part in labels):
        # Looks like an IP address but did not parse as one (1.2.3.4.5).
        raise ValueError(f"{label}: invalid IP address or hostname")
    if not DOMAIN_RE.fullmatch(text) and not HOSTNAME_LABEL_RE.fullmatch(text):
        raise ValueError(f"{label}: invalid IP address or hostname")
    return text


def validate_cidr(value: Any, label: str) -> str:
    """Accept one address or network, and return it in canonical form.

    HAProxy takes both on a ``src`` ACL. Canonicalising here means the
    generated configuration cannot contain "10.0.0.5/24", which HAProxy reads
    as the whole network while the operator plainly meant one host.
    """
    text = str(value or "").strip()
    if not text or CONTROL_RE.search(text) or len(text) > 64:
        raise ValueError(f"{label}: invalid IP address or network")
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            if network.num_addresses == 1:
                return str(network.network_address)
            return str(network)
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError(
            f"{label}: invalid IP address or network ({text!r})"
        ) from exc


def validate_port(value: Any, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return port


def control_plane_domains(config_text: str) -> dict[str, tuple[str, ...]]:
    """Return the admin/Authelia host ACL values from rendered HAProxy config."""
    domains: dict[str, tuple[str, ...]] = {}
    for match in CONTROL_PLANE_ACL_RE.finditer(config_text or ""):
        values = tuple(
            sorted(
                {
                    value.strip().lower().rstrip(".")
                    for value in match.group(2).split()
                    if value.strip()
                }
            )
        )
        if values:
            domains[match.group(1)] = values
    return domains


def validate_control_plane_transition(
    active_config: str,
    candidate_config: str,
) -> None:
    """Prevent UI-generated configs from replacing protected service domains."""
    active = control_plane_domains(active_config)
    if not active:
        return

    candidate = control_plane_domains(candidate_config)
    labels = {
        "host_admin": "HAProxy Admin",
        "host_authelia": "Authelia",
    }
    for acl_name, active_domains in active.items():
        candidate_domains = candidate.get(acl_name)
        if candidate_domains == active_domains:
            continue
        current = ", ".join(active_domains)
        proposed = (
            ", ".join(candidate_domains)
            if candidate_domains
            else "missing"
        )
        raise ValueError(
            f"Protected domain {labels[acl_name]} changed: "
            f"{current} -> {proposed}. "
            'The change was blocked. Service domains can only be changed '
            'with easy-ha-proxy migrate-domain.'
        )


def reject_unsafe_scalars(
    value: Any,
    path: str = "root",
    depth: int = 0,
    seen: set[int] | None = None,
) -> int:
    """Reject control characters and excessively complex expanded YAML."""
    if seen is None:
        seen = set()
    if depth > 20:
        raise ValueError(f"{path}: structure is too deeply nested")
    if isinstance(value, str):
        if len(value) > 16384:
            raise ValueError(f"{path}: string is too long")
        if CONTROL_RE.search(value):
            raise ValueError(f"{path}: control characters and line breaks are forbidden")
        return 1
    if isinstance(value, dict):
        if id(value) in seen:
            raise ValueError(f"{path}: YAML aliases are not allowed")
        seen.add(id(value))
        count = 1
        for key, item in value.items():
            if not isinstance(key, str) or CONTROL_RE.search(key) or len(key) > 128:
                raise ValueError(f"{path}: invalid key")
            count += reject_unsafe_scalars(item, f"{path}.{key}", depth + 1, seen)
            if count > 10000:
                raise ValueError('YAML contains too many items')
        return count
    if isinstance(value, list):
        if id(value) in seen:
            raise ValueError(f"{path}: YAML aliases are not allowed")
        seen.add(id(value))
        count = 1
        for index, item in enumerate(value):
            count += reject_unsafe_scalars(
                item, f"{path}[{index}]", depth + 1, seen
            )
            if count > 10000:
                raise ValueError('YAML contains too many items')
        return count
    if value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError(f"{path}: unsupported value type")
    return 1


def _validate_site(site: Any, index: int) -> None:
    if not isinstance(site, dict):
        raise ValueError(f"sites[{index}] must be an object")
    validate_identifier(site.get("name") or site.get("domain"), f"sites[{index}].name")
    validate_domain(site.get("domain") or site.get("name"), f"sites[{index}].domain")
    if site.get("backend_ip"):
        validate_host(site["backend_ip"], f"sites[{index}].backend_ip")
    if site.get("backend_port") is not None:
        validate_port(site["backend_port"], f"sites[{index}].backend_port")
    geo_countries = site.get("geo_countries")
    if geo_countries is not None:
        if not isinstance(geo_countries, list) or len(geo_countries) > 249:
            raise ValueError(
                f"sites[{index}].geo_countries must be a list of at most 249 ISO alpha-2 codes"
            )
        for country_index, country in enumerate(geo_countries):
            if (
                not isinstance(country, str)
                or not ISO_ALPHA2_RE.fullmatch(country.strip())
            ):
                raise ValueError(
                    f"sites[{index}].geo_countries[{country_index}] must be an uppercase ISO alpha-2 code"
                )
    # Routing names are matched literally by HAProxy; only the certificate-only
    # names may carry a wildcard, and then only with DNS-01.
    dns_profile = site.get("dns_profile")
    if dns_profile is not None:
        if not DNS_PROFILE_RE.fullmatch(str(dns_profile).strip().lower()):
            raise ValueError(
                f"sites[{index}].dns_profile: may use a-z, 0-9 and dashes"
            )
    for key, allow_wildcard in (("alt_names", False), ("cert_alt_names", True)):
        names = site.get(key)
        if names is None:
            continue
        if not isinstance(names, list) or len(names) > 100:
            raise ValueError(
                f"sites[{index}].{key} must be a list of at most 100 DNS names"
            )
        for name_index, name in enumerate(names):
            validate_domain(
                name,
                f"sites[{index}].{key}[{name_index}]",
                allow_wildcard=allow_wildcard and bool(dns_profile),
            )
    # A site restricted to named addresses. Non-empty means the site answers
    # nobody else, and the gates that exist to sort strangers out -- GeoIP,
    # Authelia, zero-trust, the adaptive counters -- stop applying to it.
    allow_ips = site.get("allow_ips")
    if allow_ips is not None:
        if not isinstance(allow_ips, list) or len(allow_ips) > 64:
            raise ValueError(
                f"sites[{index}].allow_ips must be a list of at most 64 "
                "addresses or networks"
            )
        for entry_index, entry in enumerate(allow_ips):
            validate_cidr(entry, f"sites[{index}].allow_ips[{entry_index}]")
    # Client certificates are a separate layer from Authelia: a site may use
    # either, both, or neither, so nothing here consults authelia_enabled.
    mtls_mode = site.get("mtls_mode")
    if mtls_mode is not None and mtls_mode not in ("disabled", "optional", "required"):
        raise ValueError(
            f"sites[{index}].mtls_mode must be disabled, optional or required"
        )
    if mtls_mode in ("optional", "required"):
        ca_id = str(site.get("mtls_ca_id") or "").strip()
        if not ca_id:
            raise ValueError(
                f"sites[{index}].mtls_ca_id is required when client "
                "certificates are enabled"
            )
        if not CA_ID_RE.fullmatch(ca_id):
            raise ValueError(f"sites[{index}].mtls_ca_id: invalid identifier")
    if site.get("access_gate") is not None and not isinstance(
        site["access_gate"], bool
    ):
        raise ValueError(f"sites[{index}].access_gate must be true or false")
    if site.get("alert_enabled") is not None and not isinstance(
        site["alert_enabled"], bool
    ):
        raise ValueError(f"sites[{index}].alert_enabled must be true or false")
    if site.get("alert_mode") is not None and site["alert_mode"] not in (
        "down",
        "degraded",
    ):
        raise ValueError(f"sites[{index}].alert_mode must be down or degraded")
    if site.get("alert_after") is not None and not INTERVAL_RE.fullmatch(
        str(site["alert_after"])
    ):
        raise ValueError(
            f"sites[{index}].alert_after must be an interval such as 5m or 300s"
        )
    if site.get("alert_email") is not None:
        email = str(site["alert_email"]).strip()
        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            raise ValueError(f"sites[{index}].alert_email must be a valid email")
    for srv_index, server in enumerate(site.get("servers") or []):
        if not isinstance(server, dict):
            raise ValueError(f"sites[{index}].servers[{srv_index}] must be an object")
        validate_identifier(
            server.get("name") or f"srv{srv_index + 1}",
            f"sites[{index}].servers[{srv_index}].name",
        )
        validate_host(server.get("host"), f"sites[{index}].servers[{srv_index}].host")
        validate_port(server.get("port"), f"sites[{index}].servers[{srv_index}].port")


def _validate_tcp(proxy: Any, index: int) -> None:
    if not isinstance(proxy, dict):
        raise ValueError(f"tcp_proxies[{index}] must be an object")
    validate_identifier(proxy.get("name"), f"tcp_proxies[{index}].name")
    validate_host(proxy.get("bind_ip") or "0.0.0.0", f"tcp_proxies[{index}].bind_ip")
    validate_port(proxy.get("bind_port"), f"tcp_proxies[{index}].bind_port")
    balance = str(proxy.get("balance") or "source").strip()
    if balance not in BALANCE_VALUES:
        raise ValueError(f"tcp_proxies[{index}].balance: unsupported algorithm")
    if proxy.get("inter") and not INTERVAL_RE.fullmatch(str(proxy["inter"])):
        raise ValueError(f"tcp_proxies[{index}].inter: invalid interval")
    if proxy.get("backend_host"):
        validate_host(proxy["backend_host"], f"tcp_proxies[{index}].backend_host")
        validate_port(proxy.get("backend_port"), f"tcp_proxies[{index}].backend_port")
    for srv_index, server in enumerate(proxy.get("servers") or []):
        if not isinstance(server, dict):
            raise ValueError(f"tcp_proxies[{index}].servers[{srv_index}] must be an object")
        validate_identifier(
            server.get("name") or f"srv{srv_index + 1}",
            f"tcp_proxies[{index}].servers[{srv_index}].name",
        )
        validate_host(server.get("host"), f"tcp_proxies[{index}].servers[{srv_index}].host")
        validate_port(server.get("port"), f"tcp_proxies[{index}].servers[{srv_index}].port")


def validate_config_data(kind: str, data: dict[str, Any]) -> None:
    reject_unsafe_scalars(data)
    if kind == "websites":
        sites = data.get("sites", [])
        if not isinstance(sites, list) or len(sites) > 500:
            raise ValueError('sites must be a list of at most 500 items')
        for index, site in enumerate(sites):
            _validate_site(site, index)
    elif kind == "tcp":
        proxies = data.get("tcp_proxies", data.get("tcp", []))
        if not isinstance(proxies, list) or len(proxies) > 500:
            raise ValueError('tcp_proxies must be a list of at most 500 items')
        for index, proxy in enumerate(proxies):
            _validate_tcp(proxy, index)
